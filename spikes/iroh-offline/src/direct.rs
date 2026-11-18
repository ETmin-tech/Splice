//! Direct LAN connection with relays disabled: the core S1 question.
//!
//! Both sides use `presets::Minimal` (crypto provider only) plus
//! `RelayMode::Disabled`, so no relay transport exists at all and no DNS is consulted.
//! The dialer is given the peer's `EndpointId` and one direct UDP address — nothing else.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use iroh::{endpoint::presets, Endpoint, EndpointAddr, EndpointId, RelayMode, TransportAddr};

use crate::{emit, ms, ALPN, STREAM_TYPE_CONTROL};

/// Accept-side timeout per connection.
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);
/// Read a whole request but never buffer more than this.
const READ_LIMIT: usize = 1024 * 1024;

/// Bind with relay disabled and echo one request per bi-directional stream.
pub async fn serve(key: Option<PathBuf>, rounds: usize) -> Result<()> {
    let secret = match key {
        Some(path) => crate::keys::load_or_create(&path)?,
        None => secret_or_random(),
    };

    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(secret)
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .context("bind endpoint (relay disabled)")?;

    let sockets: Vec<SocketAddr> = endpoint.bound_sockets();
    emit(serde_json::json!({
        "event": "listening",
        "id": endpoint.id().to_string(),
        "sockets": sockets.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
    }));

    for _ in 0..rounds {
        let incoming = match tokio::time::timeout(ACCEPT_TIMEOUT, endpoint.accept()).await {
            Err(_) => bail!("no incoming connection within {ACCEPT_TIMEOUT:?}"),
            Ok(None) => bail!("endpoint closed while accepting"),
            Ok(Some(incoming)) => incoming,
        };
        let conn = incoming.await.context("finish incoming handshake")?;
        let remote = conn.remote_id();

        let (mut send, mut recv) = conn.accept_bi().await.context("accept bi stream")?;
        let mut ty = [0u8; 1];
        recv.read_exact(&mut ty)
            .await
            .context("read stream type byte")?;
        let body = recv.read_to_end(READ_LIMIT).await.context("read body")?;

        // Echo the type byte plus the payload, so the dialer can verify fidelity.
        send.write_all(&ty).await.context("write type byte")?;
        send.write_all(&body).await.context("write body")?;
        send.finish().context("finish send")?;

        emit(serde_json::json!({
            "event": "served",
            "remote": remote.to_string(),
            "stream_type": ty[0],
            "body_len": body.len(),
        }));
        conn.closed().await;
    }

    endpoint.close().await;
    Ok(())
}

/// Dial `id` at `addr` `rounds` times and report connect + round-trip timings.
pub async fn dial(id: EndpointId, addr: SocketAddr, rounds: usize) -> Result<()> {
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(secret_or_random())
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .context("bind endpoint (relay disabled)")?;

    let target = EndpointAddr::from_parts(id, [TransportAddr::Ip(addr)]);

    for round in 0..rounds {
        let t0 = Instant::now();
        let conn = endpoint
            .connect(target.clone(), ALPN)
            .await
            .with_context(|| format!("connect to {addr} (round {round})"))?;
        let connect_ms = ms(t0.elapsed());

        if conn.remote_id() != id {
            bail!("peer id mismatch: expected {id}, got {}", conn.remote_id());
        }

        let (mut send, mut recv) = conn.open_bi().await.context("open bi stream")?;
        let payload = format!("round-{round}").into_bytes();
        let t1 = Instant::now();
        send.write_all(&[STREAM_TYPE_CONTROL])
            .await
            .context("write type byte")?;
        send.write_all(&payload).await.context("write payload")?;
        send.finish().context("finish send")?;

        let mut ty = [0u8; 1];
        recv.read_exact(&mut ty)
            .await
            .context("read echoed type byte")?;
        let echoed = recv.read_to_end(READ_LIMIT).await.context("read echo")?;
        let rtt_ms = ms(t1.elapsed());

        if ty[0] != STREAM_TYPE_CONTROL || echoed != payload {
            bail!("echo mismatch: type {} payload {:?}", ty[0], echoed);
        }

        emit(serde_json::json!({
            "event": "dial",
            "round": round,
            "connect_ms": connect_ms,
            "rtt_ms": rtt_ms,
            "path": "direct",
        }));

        conn.close(0u8.into(), b"done");
    }

    endpoint.close().await;
    Ok(())
}

/// A random secret key, reported so the run is reproducible.
fn secret_or_random() -> iroh::SecretKey {
    let key = iroh::SecretKey::generate();
    emit(serde_json::json!({ "event": "identity", "id": key.public().to_string() }));
    key
}
