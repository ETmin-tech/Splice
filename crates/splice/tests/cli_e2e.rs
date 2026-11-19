//! End-to-end tests for the CLI wiring (Step 10 of the Phase 1 brief).
//!
//! These drive the same public functions the binary drives — [`dev::host_once`],
//! [`dev::host_accept_once`], [`dev::guest_once`] and [`dev::run`] — so the
//! command layer is covered without spawning a process.
//!
//! Scope note: **the real two-process tests belong to Step 11** (`tests/offline/`
//! with two network namespaces). What is checked here is (a) exchanges over the
//! in-memory transport, which prove the frame helpers and both state machines
//! agree, and (b) exchanges over a real loopback/LAN QUIC endpoint, which also
//! prove transport-level identity binding and ALPN negotiation.
//!
//! The byte-level helpers used here are [`splice::cli::write_control`] and
//! [`splice::cli::read_control`], **not** the ones in `crates/splice-core/tests/`.
//! The CLI helpers write the stream-type byte (`0x01`) before every frame and
//! consume one before every frame; the core test helpers omit it. Mixing the two
//! families desynchronises the stream by one byte, which is exactly the class of
//! bug these tests exist to catch.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use splice_core::code::Code;
use splice_core::discovery::Ticket;
use splice_core::identity::{NodeId, NodeSecret};
use splice_core::net::memory::Network;
use splice_core::net::{Connection, NodeAddr, RelaySetting, Transport, REQUIRED_ALPN};
use splice_core::pairing::{GuestSession, HostSession, Outcome, PairingPhase};
use splice_core::proto::messages::{ByeReason, ControlMsg, HelloMode};
use splice_core::trust::{
    close_foreign, TrustEntry, TrustStore, TrustedOutcome, TrustedServer, TrustedStep,
};
use tempfile::TempDir;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

use splice::cli::cmd::dev::{self, GuestPassword};
use splice::cli::{
    apply_step, await_peer_hangup, build_endpoint, read_control, write_control, Cli, Command,
    DevCommand,
};

/// The code the fixtures pair with. Two words, fixed, so no test depends on an RNG.
const CODE: &str = "42-torch-crystal";
/// Same nameplate, one different word: a well-formed wrong guess.
const WRONG_CODE: &str = "42-torch-zebra";

/// A CONTROL message may not take longer than this in a test.
const STEP_TIMEOUT: Duration = Duration::from_secs(10);

fn code(text: &str) -> Code {
    Code::parse(text).expect("test code must parse")
}

fn id(seed: u8) -> NodeId {
    NodeId::from_bytes([seed; 32])
}

/// Wrap every read, so a wiring bug shows up as a clear failure instead of a hang.
async fn read_frame(rx: &mut splice_core::net::RecvStream) -> ControlMsg {
    timeout(STEP_TIMEOUT, read_control(rx))
        .await
        .expect("timed out waiting for a CONTROL frame")
        .expect("failed to read a CONTROL frame")
}

/// Read one frame if one arrives, and `None` once the stream ends.
///
/// The "stream ended" case is a normal ending for the refusing side: it sends its
/// last frame and closes. Panicking there would hide the frame that was sent.
async fn maybe_frame(rx: &mut splice_core::net::RecvStream) -> Option<ControlMsg> {
    timeout(STEP_TIMEOUT, read_control(rx)).await.ok()?.ok()
}

/// Dial with a deadline. The real transport can spend ~30 s on a peer that does
/// not speak our ALPN, so no test may call `connect` bare.
async fn dial(from: &dyn Transport, addr: NodeAddr) -> Arc<dyn Connection> {
    let conn = timeout(STEP_TIMEOUT, from.connect(addr, REQUIRED_ALPN))
        .await
        .expect("dial timed out")
        .expect("dial failed");
    assert_eq!(conn.alpn(), REQUIRED_ALPN.to_vec(), "ALPN must match");
    conn
}

/// An address a peer in this process can dial, for a real endpoint.
///
/// iroh reports whatever it bound; a wildcard bind has no routable address of its
/// own, so fall back to loopback on the same port.
fn dialable(transport: &dyn Transport) -> SocketAddr {
    let addrs = transport.local_addrs();
    if let Some(addr) = addrs
        .iter()
        .find(|addr| !addr.ip().is_unspecified() && !addr.ip().is_loopback())
    {
        return *addr;
    }
    let port = addrs.first().expect("endpoint has a bound socket").port();
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

/// A LAN-only endpoint, which binds in milliseconds and needs no internet.
async fn lan_endpoint(secret: NodeSecret) -> Arc<dyn Transport> {
    build_endpoint(secret, RelaySetting::Disabled)
        .await
        .expect("bind a LAN-only endpoint")
}

fn cli(command: Command) -> Cli {
    Cli {
        command,
        relay_mode: "disabled".to_string(),
        relay_url: None,
        addr: None,
        words: 2,
        yes: true,
    }
}

// ---------------------------------------------------------------------------
// 1. One-shot pairing over the in-memory transport
// ---------------------------------------------------------------------------

/// The happy path, with both halves of the CLI driven through the memory
/// transport: the frame helpers, the wire order and both state machines must
/// agree, and the host must see `Paired` *and* answer the keepalive.
#[tokio::test]
async fn one_shot_pairing_completes_over_the_memory_transport() {
    let net = Network::new();
    let (guest_id, host_id) = (id(0x31), id(0x32));
    let host_ep = net.endpoint_with(host_id, false);
    let guest_ep = net.endpoint_with(guest_id, false);

    let mut host = HostSession::new(host_id, HelloMode::OneShot, code(CODE), Instant::now())
        .expect("host session");

    let host_half = dev::host_once(&mut host, &host_ep);
    let guest_half = async {
        let conn = dial(&guest_ep, host_ep.hint()).await;
        dev::guest_once(
            guest_id,
            conn.as_ref(),
            HelloMode::OneShot,
            GuestPassword::Code(&code(CODE)),
        )
        .await
    };

    let (paired_peer, guest_result) = tokio::join!(host_half, guest_half);

    assert_eq!(
        paired_peer.expect("host must complete the pairing"),
        guest_id,
        "the host must report the guest's transport-authenticated identity"
    );
    guest_result.expect("guest must complete the pairing and the keepalive");

    assert_eq!(
        host.phase(),
        PairingPhase::Paired,
        "the CLI must leave the session paired, not merely connected"
    );
    assert_eq!(host.attempts_left(), 3, "a correct code spends no attempt");
}

// ---------------------------------------------------------------------------
// 2. Ticket pairing over a real endpoint
// ---------------------------------------------------------------------------

/// Ticket mode on a real QUIC endpoint: no nameplate, no mDNS, no code — the
/// ticket's 128-bit secret is the SPAKE2 password on both sides.
#[tokio::test(flavor = "multi_thread")]
async fn ticket_pairing_completes_over_a_real_endpoint() {
    let host_ep = lan_endpoint(NodeSecret::generate()).await;
    let host_id = host_ep.node_id();

    // The ticket is built from the address the guest can actually dial, which is
    // the same choice `dev host-ticket` makes.
    let addr = NodeAddr::new(host_id).with_ip(dialable(host_ep.as_ref()));
    let ticket = Ticket::generate(&addr).expect("ticket");
    let password = ticket.password_string();

    let guest_ep = lan_endpoint(NodeSecret::generate()).await;
    let guest_id = guest_ep.node_id();

    let mut host =
        HostSession::new_with_password(host_id, HelloMode::OneShot, &password, Instant::now())
            .expect("host session");

    let host_half = dev::host_once(&mut host, host_ep.as_ref());
    let guest_half = async {
        let target = ticket.to_node_addr();
        assert!(target.has_hint(), "a ticket must carry a dialable address");
        let conn = dial(guest_ep.as_ref(), target).await;
        dev::guest_once(
            guest_id,
            conn.as_ref(),
            HelloMode::OneShot,
            GuestPassword::Ticket(password.duplicate()),
        )
        .await
    };

    let (paired_peer, guest_result) = tokio::join!(host_half, guest_half);

    assert_eq!(
        paired_peer.expect("host must complete the ticket pairing"),
        guest_id
    );
    guest_result.expect("guest must complete the ticket pairing");
    assert_eq!(host.phase(), PairingPhase::Paired);
}

// ---------------------------------------------------------------------------
// 3. Pair, then `dev ping`
// ---------------------------------------------------------------------------

/// The trusted-server half of `splice listen`, minus presence and Ctrl+C.
///
/// `listen::run` cannot be called from a test: it binds the multicast presence
/// port and loops until a signal. The part that matters for `dev ping` — the
/// store check before any stream, then `Hello{mode: Trusted}` / `Ping` / `Pong` —
/// is reproduced here with the same public pieces `listen` uses.
async fn serve_one_trusted(transport: &dyn Transport, store: &TrustStore) -> NodeId {
    let conn = timeout(STEP_TIMEOUT, transport.accept())
        .await
        .expect("timed out accepting a trusted connection")
        .expect("accept failed")
        .expect("a connection");
    let peer = conn.remote_id();

    // I13, exactly as `listen` does it: the store decides before any stream opens.
    if !store.contains(&peer) {
        close_foreign(conn.as_ref());
        return peer;
    }

    // The CONTROL stream is opened by the caller (`Architecture.md` §7), so the
    // accepting side takes it — exactly as `listen::serve_trusted` does.
    let (mut tx, mut rx) = conn.accept_bi().await.expect("host stream");
    let mut server = TrustedServer::new(store, peer);
    loop {
        let msg = match timeout(STEP_TIMEOUT, read_control(&mut rx)).await {
            Ok(Ok(msg)) => msg,
            Ok(Err(_)) => return peer,
            // `listen` treats silence as the end of the session, not an error.
            Err(_) => return peer,
        };
        match server.on_message(msg) {
            TrustedStep::Idle => {}
            TrustedStep::Reply(reply) => {
                write_control(&mut tx, &reply).await.expect("write reply");
                if reply == ControlMsg::Pong {
                    // The keepalive round trip is the whole check here. The real
                    // `listen` stays in the loop for further keepalives; this
                    // stand-in ends once the round trip is proven, because the test
                    // has nothing else to send and no Ctrl+C to wait for. Lingering
                    // first keeps our close from overtaking the `Pong`.
                    await_peer_hangup(&mut rx).await;
                    return peer;
                }
            }
            TrustedStep::Close { reply, outcome } => {
                if let Some(reply) = reply {
                    let _ = write_control(&mut tx, &reply).await;
                }
                assert_ne!(
                    outcome,
                    TrustedOutcome::NotTrusted,
                    "the trusted path must not refuse a pinned peer"
                );
                return peer;
            }
        }
    }
}

/// `splice pair` records the peer, `splice dev ping <alias>` then reaches it with
/// no code, no PAKE, and no presence lookup (`--addr` supplies the hint).
///
/// Two config dirs, because the two sides keep *different* stores: the dialer's
/// store names the device it pings (the listener), and the listener's store names
/// the device allowed to connect (the dialer). Sharing one dir would pin the wrong
/// `NodeId` and make the dialer try to connect to itself.
#[tokio::test(flavor = "multi_thread")]
async fn pair_then_dev_ping_reaches_the_trusted_device() {
    // `dev ping` loads its store and its identity from `SPLICE_CONFIG_DIR`.
    let dialer_dir = TempDir::new().expect("dialer dir");
    std::env::set_var("SPLICE_CONFIG_DIR", dialer_dir.path());

    // The identity `dev ping` will dial with, created here so the listener can pin it.
    let (secret, _source) = splice_core::identity::load_or_create_persistent()
        .expect("create the persistent identity the CLI will use");
    let guest_id = secret.public();

    let host_ep = lan_endpoint(NodeSecret::generate()).await;
    let host_id = host_ep.node_id();
    let addr = dialable(host_ep.as_ref());

    // The dialer's store: "laptop" is the host we paired with.
    let mut dialer_store = TrustStore::load_in(dialer_dir.path()).expect("load store");
    dialer_store
        .add(TrustEntry::new(host_id, "laptop", Duration::ZERO))
        .expect("record the host");
    dialer_store.save().expect("save the dialer store");

    // The listener's store: the dialer's persistent id is the pinned peer (I13).
    let host_dir = TempDir::new().expect("listener dir");
    let mut host_store = TrustStore::load_in(host_dir.path()).expect("load store");
    host_store
        .add(TrustEntry::new(guest_id, "laptop", Duration::ZERO))
        .expect("record the guest");
    host_store.save().expect("save the listener store");

    // `splice listen` would already be running here; stand in for it.
    let server = tokio::spawn({
        let store = TrustStore::load_in(host_dir.path()).expect("load store");
        let transport = host_ep.clone();
        async move { serve_one_trusted(transport.as_ref(), &store).await }
    });

    let mut ping = cli(Command::Dev(DevCommand::Ping {
        alias: "laptop".to_string(),
    }));
    ping.addr = Some(addr.to_string());

    // `dev ping` ignores `--yes`; it is a trusted connection, not a prompt.
    dev::run(
        &ping,
        &DevCommand::Ping {
            alias: "laptop".to_string(),
        },
    )
    .await
    .expect("dev ping must reach the paired host");

    // The listener saw the pinned peer, which is the identity `dev ping` dialed with.
    assert_eq!(server.await.expect("server task"), guest_id);
}

// ---------------------------------------------------------------------------
// 4. Wrong code
// ---------------------------------------------------------------------------

/// A well-formed wrong guess costs exactly one attempt, and both sides learn the
/// same generic outcome: the guest gets `Bye{Protocol}` and stops, the host goes
/// back to waiting with one attempt spent.
#[tokio::test]
async fn a_wrong_code_spends_one_attempt_and_keeps_the_code() {
    let net = Network::new();
    let (guest_id, host_id) = (id(0x41), id(0x42));
    let host_ep = net.endpoint_with(host_id, false);
    let guest_ep = net.endpoint_with(guest_id, false);

    let mut host = HostSession::new(host_id, HelloMode::OneShot, code(CODE), Instant::now())
        .expect("host session");
    assert_eq!(host.attempts_left(), 3);

    let host_half = dev::host_accept_once(&mut host, &host_ep);
    let guest_half = async {
        let conn = dial(&guest_ep, host_ep.hint()).await;
        dev::guest_once(
            guest_id,
            conn.as_ref(),
            HelloMode::OneShot,
            GuestPassword::Code(&code(WRONG_CODE)),
        )
        .await
    };

    let (paired, guest_result) = tokio::join!(host_half, guest_half);

    assert!(
        paired
            .expect("a wrong guess is a clean end, not an error")
            .is_none(),
        "a wrong code must not report a paired peer"
    );
    let guest_error = guest_result.expect_err("the guest must not believe it paired");
    assert!(
        guest_error.to_string().contains("failed"),
        "the guest must see the generic `failed` outcome, got: {guest_error}"
    );

    assert_eq!(host.phase(), PairingPhase::WaitingForGuest);
    assert_eq!(
        host.attempts_left(),
        2,
        "one wrong guess must cost exactly one attempt (I3)"
    );
}

/// The same exchange at the wire level, so the refusal reason is checked rather
/// than inferred from an error string: the host sends `Bye{Protocol}` and the
/// code is *not* burned.
#[tokio::test]
async fn a_wrong_code_gets_bye_protocol_not_bye_burned() {
    let net = Network::new();
    let (guest_id, host_id) = (id(0x43), id(0x44));
    let host_ep = net.endpoint_with(host_id, false);
    let guest_ep = net.endpoint_with(guest_id, false);

    let mut host = HostSession::new(host_id, HelloMode::OneShot, code(CODE), Instant::now())
        .expect("host session");

    let host_half = dev::host_accept_once(&mut host, &host_ep);
    let guest_half = async {
        let conn = dial(&guest_ep, host_ep.hint()).await;
        let (mut tx, mut rx) = conn.open_bi().await.expect("guest stream");
        let (mut guest, opening) = GuestSession::begin(
            guest_id,
            host_id,
            HelloMode::OneShot,
            code(WRONG_CODE),
            Instant::now(),
        )
        .expect("guest session");
        for message in &opening {
            write_control(&mut tx, message).await.expect("opening");
        }

        // Host share, then its confirmation attempt fails and it says Bye.
        for _ in 0..2 {
            let message = read_frame(&mut rx).await;
            let step = guest
                .on_message(host_id, message, Instant::now())
                .expect("guest step");
            if let Some(outcome) = apply_step(&mut tx, step).await.expect("apply") {
                return outcome;
            }
        }
        panic!("the host must refuse a wrong confirmation");
    };

    let (paired, outcome) = tokio::join!(host_half, guest_half);

    assert!(paired.expect("host").is_none(), "no peer paired");
    assert_eq!(
        outcome,
        Outcome::Failed,
        "a wrong guess maps to `Failed`, never to `Burned` on the first try"
    );
    assert_eq!(host.attempts_left(), 2);
}

// ---------------------------------------------------------------------------
// 5. BURNED
// ---------------------------------------------------------------------------

/// Three wrong guesses burn the code, and the third refusal says so on the wire.
#[tokio::test]
async fn three_wrong_codes_burn_the_code() {
    let net = Network::new();
    let host_id = id(0x51);
    let host_ep = net.endpoint_with(host_id, false);

    let mut host = HostSession::new(host_id, HelloMode::OneShot, code(CODE), Instant::now())
        .expect("host session");

    let mut reasons = Vec::new();
    for round in 0..3u8 {
        let guest_ep = net.endpoint_with(id(0x60 + round), false);
        let guest_id = guest_ep.node_id();

        let host_half = dev::host_accept_once(&mut host, &host_ep);
        let guest_half = async {
            let conn = dial(&guest_ep, host_ep.hint()).await;
            let (mut tx, mut rx) = conn.open_bi().await.expect("guest stream");
            let (mut guest, opening) = GuestSession::begin(
                guest_id,
                host_id,
                HelloMode::OneShot,
                code(WRONG_CODE),
                Instant::now(),
            )
            .expect("guest session");
            for message in &opening {
                write_control(&mut tx, message).await.expect("opening");
            }

            // The guest fails key confirmation one message *before* the host's
            // `Bye` arrives: `PakeConfirm` from the host already fails the MAC on
            // our side, so the local verdict is always `Failed`. The host's own
            // verdict — which distinguishes `Protocol` from `Burned` — is only on
            // the wire, so read one more frame rather than trusting our own.
            let mut local = None;
            for _ in 0..3 {
                let Some(message) = maybe_frame(&mut rx).await else {
                    break;
                };
                if let ControlMsg::Bye { reason } = message {
                    return reason;
                }
                let step = guest
                    .on_message(host_id, message, Instant::now())
                    .expect("guest step");
                if let Some(outcome) = apply_step(&mut tx, step).await.expect("apply") {
                    local = Some(outcome);
                    // Our `Bye` went out; the host's refusal is still unread.
                }
            }
            // Fallback for a peer that closes without saying why.
            match local {
                Some(Outcome::Burned) => ByeReason::Burned,
                _ => ByeReason::Protocol,
            }
        };

        let (paired, reason) = tokio::join!(host_half, guest_half);
        assert!(paired.expect("host").is_none(), "no peer may pair");
        reasons.push(reason);
    }

    assert_eq!(
        reasons,
        vec![ByeReason::Protocol, ByeReason::Protocol, ByeReason::Burned],
        "only the last refusal may admit that the code is dead"
    );
    assert_eq!(host.phase(), PairingPhase::Burned);
    assert_eq!(host.attempts_left(), 0);

    // A burned code stays burned: no fourth guest can spend anything, and it gets
    // the generic refusal — a burned code does not announce itself to a new peer,
    // only the third guess that caused it hears `Burned` (`HostSession` treats any
    // `Hello` outside `WaitingForGuest` as a plain protocol violation).
    let late = net.endpoint_with(id(0x71), false);
    let late_host = dev::host_accept_once(&mut host, &host_ep);
    let late_guest = async {
        let conn = dial(&late, host_ep.hint()).await;
        let (mut tx, mut rx) = conn.open_bi().await.expect("guest stream");
        write_control(
            &mut tx,
            &ControlMsg::Hello {
                version: splice_core::constants::PROTOCOL_VERSION,
                mode: HelloMode::OneShot,
                nameplate: Some(code(CODE).nameplate().get()),
                resume: None,
            },
        )
        .await
        .expect("hello");
        read_frame(&mut rx).await
    };
    let (paired, answer) = tokio::join!(late_host, late_guest);
    assert!(
        paired.expect("host").is_none(),
        "a burned code may not pair a fourth guest"
    );
    match answer {
        ControlMsg::Bye { reason } => assert_eq!(reason, ByeReason::Protocol),
        other => panic!(
            "a burned code must be refused with Bye, got {}",
            other.name()
        ),
    }
    assert_eq!(host.attempts_left(), 0, "a burned code has nothing left");
}

// ---------------------------------------------------------------------------
// 6. Foreign NodeId
// ---------------------------------------------------------------------------

/// A peer whose `NodeId` is not pinned is closed without a single byte of
/// protocol traffic (I13). Reproduces the `listen` accept path exactly.
#[tokio::test(flavor = "multi_thread")]
async fn a_foreign_node_id_is_closed_without_a_protocol_message() {
    let dir = TempDir::new().expect("temp dir");
    let store = TrustStore::load_in(dir.path()).expect("empty store");
    assert!(store.is_empty());

    let host_ep = lan_endpoint(NodeSecret::generate()).await;
    let guest_ep = lan_endpoint(NodeSecret::generate()).await;
    let guest_id = guest_ep.node_id();

    // The listener half: store check first, then `close_foreign`.
    let listener = tokio::spawn({
        let host_ep = host_ep.clone();
        async move {
            let conn = timeout(STEP_TIMEOUT, host_ep.accept())
                .await
                .expect("accept timed out")
                .expect("accept failed")
                .expect("a connection");
            assert_eq!(conn.remote_id(), guest_id);
            close_foreign(conn.as_ref());
        }
    });

    let conn = dial(
        guest_ep.as_ref(),
        NodeAddr::direct(host_ep.node_id(), dialable(host_ep.as_ref())),
    )
    .await;
    listener.await.expect("listener task");

    // The peer observes only a close: no frame, no reason string beyond the
    // generic one the transport carries.
    timeout(STEP_TIMEOUT, conn.closed())
        .await
        .expect("a refused peer must be disconnected promptly");

    if let Ok(Ok((mut tx, mut rx))) = timeout(STEP_TIMEOUT, conn.open_bi()).await {
        // If the transport still hands out the stream, it must be empty.
        use tokio::io::AsyncWriteExt as _;
        let _ = tx.write_all(&[0u8; 1]).await;
        let mut buffer = Vec::new();
        // An error is equally acceptable: the connection is already gone.
        if let Ok(Ok(_)) = timeout(STEP_TIMEOUT, rx.read_to_end(&mut buffer)).await {
            assert!(
                buffer.is_empty(),
                "a foreign peer must receive no protocol bytes, got {buffer:?}"
            );
        }
    }
}
