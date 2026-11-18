//! Custom ALPN + bi-directional stream with a leading type byte (`Architecture.md` §7.1/§7.2).
//!
//! Also checks the negative cases we depend on: an endpoint that does not advertise our ALPN
//! must fail the handshake, and a peer that opens a stream with an unknown type byte must be
//! rejected by us rather than silently accepted.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use iroh::{endpoint::presets, Endpoint, EndpointAddr, RelayMode, TransportAddr};

use crate::{emit, ms, ALPN, STREAM_TYPE_CONTROL};

/// A type byte no version of the protocol defines.
const STREAM_TYPE_UNKNOWN: u8 = 0x7f;

pub async fn run() -> Result<()> {
    // Server: advertises only `splice/1`, and rejects unknown stream type bytes.
    let server = Endpoint::builder(presets::Minimal)
        .secret_key(iroh::SecretKey::generate())
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .context("bind server")?;

    // A second server that advertises a *different* ALPN, to prove negotiation is enforced.
    let other = Endpoint::builder(presets::Minimal)
        .secret_key(iroh::SecretKey::generate())
        .alpns(vec![b"other/1".to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .context("bind other-alpn server")?;

    let client = Endpoint::builder(presets::Minimal)
        .secret_key(iroh::SecretKey::generate())
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .context("bind client")?;

    let server_addr = pick_addr(&server).context("server has no bound socket")?;
    let other_addr = pick_addr(&other).context("other server has no bound socket")?;

    // --- positive: correct ALPN, CONTROL stream type, echo ---
    let server_task = tokio::spawn(serve_one(server.clone()));
    let target = EndpointAddr::from_parts(server.id(), [TransportAddr::Ip(server_addr)]);
    let t0 = Instant::now();
    let conn = tokio::time::timeout(Duration::from_secs(10), client.connect(target, ALPN))
        .await
        .context("connect timed out")?
        .context("connect with splice/1")?;
    let connect_ms = ms(t0.elapsed());
    let negotiated = conn.alpn();

    let (mut send, mut recv) = conn.open_bi().await.context("open bi")?;
    let payload = b"hello-splice";
    send.write_all(&[STREAM_TYPE_CONTROL])
        .await
        .context("write type")?;
    send.write_all(payload).await.context("write payload")?;
    send.finish().context("finish")?;
    let client_res: Result<(u8, Vec<u8>)> = async {
        let mut ty = [0u8; 1];
        recv.read_exact(&mut ty).await.context("read type")?;
        let echoed = recv.read_to_end(1024).await.context("read echo")?;
        Ok((ty[0], echoed))
    }
    .await;
    conn.close(0u8.into(), b"done");

    let server_saw = server_task.await.context("server task panicked")?;
    let (ty, echoed) = match client_res {
        Ok(v) => v,
        Err(e) => {
            let side = match &server_saw {
                Ok(_) => "server ok".to_string(),
                Err(err) => format!("server err: {err:#}"),
            };
            bail!("{e:#}; {side}");
        }
    };

    emit(serde_json::json!({
        "event": "alpn_positive",
        "connect_ms": connect_ms,
        "negotiated_alpn": String::from_utf8_lossy(&negotiated).to_string(),
        "alpn_is_splice_1": negotiated == ALPN,
        "stream_type_roundtrip": ty,
        "type_byte_preserved": ty == STREAM_TYPE_CONTROL,
        "echo_matches": echoed == payload,
        "server_saw": match &server_saw {
            Ok(v) => format!("ok 0x{v:02x}"),
            Err(e) => format!("err: {e:#}"),
        },
    }));

    // --- negative 1: wrong ALPN must fail, and must not hang ---
    let other_target = EndpointAddr::from_parts(other.id(), [TransportAddr::Ip(other_addr)]);
    let neg_timeout = std::env::var("ALPN_NEG_TIMEOUT_S")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(10);
    let t0 = Instant::now();
    let wrong = tokio::time::timeout(
        Duration::from_secs(neg_timeout),
        client.connect(other_target, ALPN),
    )
    .await;
    emit(serde_json::json!({
        "event": "alpn_wrong",
        "elapsed_ms": ms(t0.elapsed()),
        "rejected": matches!(wrong, Ok(Err(_))),
        "hung": wrong.is_err(),
        "error": match &wrong {
            Ok(Err(e)) => Some(format!("{e:#}")),
            Err(_) => Some("timeout".to_string()),
            Ok(Ok(_)) => None,
        },
    }));

    // --- negative 2: unknown stream type byte must be refused by our accept path ---
    let server_task = tokio::spawn(serve_one(server.clone()));
    let target = EndpointAddr::from_parts(server.id(), [TransportAddr::Ip(server_addr)]);
    let conn = client
        .connect(target, ALPN)
        .await
        .context("connect for bad type")?;
    let (mut send, _recv) = conn.open_bi().await.context("open bi")?;
    send.write_all(&[STREAM_TYPE_UNKNOWN])
        .await
        .context("write type")?;
    send.finish().context("finish")?;
    let bad_type_result = server_task.await.context("server task panicked")?;
    emit(serde_json::json!({
        "event": "alpn_unknown_stream_type",
        "rejected": bad_type_result.is_err(),
        "detail": bad_type_result.err().map(|e| format!("{e:#}")),
    }));

    server.close().await;
    other.close().await;
    client.close().await;
    Ok(())
}

fn pick_addr(ep: &Endpoint) -> Option<SocketAddr> {
    // The endpoint binds `0.0.0.0` / `[::]`, which is not a dialable destination. This
    // subcommand only exercises ALPN negotiation and stream framing, both of which are
    // transport-agnostic, so loopback is a valid and deterministic target. (The direct-LAN
    // path is measured separately in `direct.rs` with the real veth address.)
    let sockets = ep.bound_sockets();
    let port = sockets
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| sockets.first())
        .map(|a| a.port())?;
    Some(SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)))
}

/// Accept exactly one connection, read one CONTROL stream, echo it.
async fn serve_one(endpoint: Endpoint) -> Result<u8> {
    let incoming = tokio::time::timeout(Duration::from_secs(20), endpoint.accept())
        .await
        .context("accept timed out")?
        .context("endpoint closed")?;
    let conn = incoming.await.context("incoming handshake")?;
    let (mut send, mut recv) = conn.accept_bi().await.context("accept bi")?;
    let mut ty = [0u8; 1];
    recv.read_exact(&mut ty).await.context("read type")?;
    if ty[0] != STREAM_TYPE_CONTROL {
        conn.close(2u8.into(), b"unknown stream type");
        bail!("unknown stream type byte 0x{:02x}", ty[0]);
    }
    let body = recv.read_to_end(4096).await.context("read body")?;
    send.write_all(&[ty[0]]).await.context("write type")?;
    send.write_all(&body).await.context("write body")?;
    send.finish().context("finish")?;
    // Do *not* return straight away: dropping the connection here resets it before the
    // peer has acknowledged the echo (measured: "read type: connection lost: closed by
    // peer: 0; server ok"). Wait for the peer to close, like `direct.rs` does.
    let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
    Ok(ty[0])
}
