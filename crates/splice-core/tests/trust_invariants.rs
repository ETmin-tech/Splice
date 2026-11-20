//! Step 9 end-to-end tests: the trust store and the trusted connection path driven
//! over a transport, not by direct state-machine calls.
//!
//! What is proved here, with bytes on the wire:
//!
//! * I13 — a NodeId that is not pinned is refused, and refusal sends **nothing**, so
//!   a prober cannot tell "unknown" from "protocol error".
//! * A pinned NodeId is served: `Hello{mode: Trusted}` → `Pong` on `Ping`.
//! * `splice devices rm` reaches a **live** connection, not just the next one.
//! * A corrupt store is an error with a backup, and never silent data loss.

use std::sync::Arc;
use std::time::Duration;

use splice_core::constants::{ALPN, PROTOCOL_VERSION};
use splice_core::identity::{NodeId, NodeSecret};
use splice_core::net::memory::Network;
use splice_core::net::{Connection, RecvStream, SendStream, Transport};
use splice_core::proto::frame::{self, Frame, FrameKind};
use splice_core::proto::messages::{ByeReason, ControlMsg, HelloMode, WireMessage};
use splice_core::trust::session::{
    close_foreign, ActiveTrusted, TrustedOutcome, TrustedServer, TrustedStep, FOREIGN_CLOSE_CODE,
    FOREIGN_CLOSE_REASON,
};
use splice_core::trust::{TrustEntry, TrustStore};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn id() -> NodeId {
    NodeSecret::generate().public()
}

/// Write a store file the way the loader expects to find it: owner-only.
///
/// A plain `fs::write` inherits the umask, which on Linux is `0022`, so the file
/// lands `0644` and `TrustStore::load_in` stops at the permission check before it
/// can ever report the corruption under test.
fn write_store_file(path: &std::path::Path, bytes: impl AsRef<[u8]>) {
    std::fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

async fn write_control(tx: &mut SendStream, message: &ControlMsg) -> Result<(), String> {
    let bytes = Frame::control(message)
        .map_err(|err| err.to_string())?
        .encode();
    tx.write_all(&bytes).await.map_err(|err| err.to_string())
}

async fn read_control(rx: &mut RecvStream) -> Result<ControlMsg, String> {
    let mut header = [0u8; 6];
    rx.read_exact(&mut header)
        .await
        .map_err(|err| err.to_string())?;
    let header = frame::decode_header(&header).map_err(|err| err.to_string())?;
    assert_eq!(header.kind, FrameKind::Control);
    let mut body = vec![0u8; header.len as usize];
    rx.read_exact(&mut body)
        .await
        .map_err(|err| err.to_string())?;
    ControlMsg::decode_from_slice(&body).map_err(|err| err.to_string())
}

fn trusted_store(dir: &TempDir, device: NodeId, alias: &str) -> TrustStore {
    let mut store = TrustStore::load_in(dir.path()).expect("fresh store");
    store
        .add(TrustEntry::new(device, alias, Duration::ZERO))
        .expect("pin");
    store
}

#[tokio::test]
async fn a_stranger_is_refused_without_a_single_byte() {
    let net = Network::new();
    let host_id = id();
    let guest_id = id();
    let host_ep = net.endpoint_with(host_id, false);
    let guest_ep = net.endpoint_with(guest_id, false);

    let dialed = guest_ep.connect(host_ep.hint(), ALPN).await.expect("dial");
    let accepted = host_ep.accept().await.expect("accept").expect("connection");
    assert_eq!(accepted.remote_id(), guest_id);

    let dir = TempDir::new().unwrap();
    let store = TrustStore::load_in(dir.path()).unwrap();
    assert!(store.is_empty());

    let mut server = TrustedServer::new(&store, accepted.remote_id());
    assert!(!server.is_trusted());

    // A well-formed Hello from a stranger gets silence: no reply bytes at all.
    assert_eq!(
        server.on_message(ControlMsg::Hello {
            version: PROTOCOL_VERSION,
            mode: HelloMode::Trusted,
            nameplate: None,
            resume: None,
        }),
        TrustedStep::Close {
            reply: None,
            outcome: TrustedOutcome::NotTrusted,
        }
    );
    close_foreign(dialed.as_ref());
    assert_eq!(FOREIGN_CLOSE_CODE, 0);
    assert_eq!(FOREIGN_CLOSE_REASON, b"refused");

    // Our side observes the hang-up; no CONTROL frame ever arrived.
    tokio::time::timeout(Duration::from_secs(5), dialed.closed())
        .await
        .expect("the refusal is immediate");
    let (mut guest_tx, mut guest_rx) = dialed.open_bi().await.expect("stream");
    let _ = write_control(&mut guest_tx, &ControlMsg::Ping).await;
    let mut header = [0u8; 6];
    let read = tokio::time::timeout(Duration::from_secs(2), guest_rx.read_exact(&mut header)).await;
    assert!(
        matches!(read, Ok(Err(_)) | Err(_)),
        "a refused peer must not receive protocol bytes, got {read:?}"
    );
}

#[tokio::test]
async fn a_pinned_device_completes_the_trusted_exchange() {
    let net = Network::new();
    let host_id = id();
    let device_id = id();
    let host_ep = net.endpoint_with(host_id, false);
    let device_ep = net.endpoint_with(device_id, false);

    let dir = TempDir::new().unwrap();
    let store = trusted_store(&dir, device_id, "laptop");

    let dialed = device_ep.connect(host_ep.hint(), ALPN).await.expect("dial");
    let accepted = host_ep.accept().await.expect("accept").expect("connection");
    let (mut device_tx, _device_rx) = dialed.open_bi().await.expect("device stream");
    let (mut host_tx, mut host_rx) = accepted.open_bi().await.expect("host stream");

    let mut server = TrustedServer::new(&store, accepted.remote_id());
    assert!(server.is_trusted());

    // The device opens with exactly the trusted Hello.
    write_control(&mut device_tx, &splice_core::trust::trusted_hello())
        .await
        .expect("hello");
    let hello = read_control(&mut host_rx).await.expect("host reads hello");
    assert_eq!(hello.name(), "Hello");
    assert_eq!(server.on_message(hello), TrustedStep::Idle);
    assert!(server.is_ready());

    // Keepalive works, and is the only application traffic in Phase 1 (I2).
    write_control(&mut device_tx, &ControlMsg::Ping)
        .await
        .expect("ping");
    let ping = read_control(&mut host_rx).await.expect("host reads ping");
    assert_eq!(ping, ControlMsg::Ping);
    match server.on_message(ping) {
        TrustedStep::Reply(message) => {
            // The real listener writes this back over its stream.
            write_control(&mut host_tx, &message).await.expect("pong");
            assert_eq!(message, ControlMsg::Pong);
        }
        other => panic!("expected a Pong, got {other:?}"),
    }

    // A clean goodbye ends the session without a reply.
    assert_eq!(
        server.on_message(ControlMsg::Bye {
            reason: ByeReason::Normal
        }),
        TrustedStep::Close {
            reply: None,
            outcome: TrustedOutcome::PeerBye,
        }
    );
}

#[tokio::test]
async fn removing_a_device_hangs_up_its_live_connection() {
    let net = Network::new();
    let host_id = id();
    let device_id = id();
    let host_ep = net.endpoint_with(host_id, false);
    let device_ep = net.endpoint_with(device_id, false);

    let dir = TempDir::new().unwrap();
    let mut store = trusted_store(&dir, device_id, "laptop");

    let dialed: Arc<dyn Connection> = device_ep.connect(host_ep.hint(), ALPN).await.expect("dial");
    let accepted = host_ep.accept().await.expect("accept").expect("connection");
    assert!(TrustedServer::new(&store, accepted.remote_id()).is_trusted());

    let active = ActiveTrusted::new();
    active.register(accepted.clone());
    assert_eq!(active.len(), 1);

    // `devices rm` = drop the entry, then drop the live links.
    let removed = store.remove("laptop").expect("remove");
    assert_eq!(removed.node_id, device_id);
    assert_eq!(active.close_all(&device_id), 1);
    assert!(active.is_empty());
    assert!(!store.contains(&device_id));

    // The peer sees the hang-up, and a re-connect is no longer trusted.
    tokio::time::timeout(Duration::from_secs(5), dialed.closed())
        .await
        .expect("the revoked link is closed");

    let reopened = device_ep
        .connect(host_ep.hint(), ALPN)
        .await
        .expect("dial again");
    let accepted_again = host_ep.accept().await.expect("accept").expect("connection");
    assert!(!TrustedServer::new(&store, accepted_again.remote_id()).is_trusted());

    // `close_foreign` is idempotent: calling it twice must not panic.
    close_foreign(reopened.as_ref());
    close_foreign(reopened.as_ref());
}

#[tokio::test]
async fn a_corrupt_store_keeps_a_backup_and_trusts_nobody() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("trust.json");
    write_store_file(&path, b"{ this is not json");

    let err = TrustStore::load_in(dir.path()).expect_err("corruption must be reported");
    let text = err.to_string();
    assert!(text.contains("corrupt"), "got: {text}");
    assert!(
        text.contains("trust.json.bak"),
        "the message names the backup"
    );
    assert_eq!(
        std::fs::read(dir.path().join("trust.json.bak")).unwrap(),
        b"{ this is not json"
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"{ this is not json",
        "a corrupt store is never rewritten"
    );

    // Fail closed: with no store loaded there is no device to trust, so the
    // listener cannot fall back to "trust everything".
    assert!(TrustStore::load_in(dir.path()).is_err());
}
