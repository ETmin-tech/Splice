//! Relay enabled (n0 default preset) with no internet: does it hang, slow down, or work?

use std::time::{Duration, Instant};

use anyhow::Result;
use iroh::{endpoint::presets, Endpoint, EndpointAddr, RelayMode};

use crate::{emit, ms, ALPN};

/// Bind with relay enabled, then try to dial an id that has no address hints at all.
///
/// Two separate measurements:
/// 1. `bind` — how long `Endpoint::bind` takes when the relay/DNS endpoints are unreachable.
/// 2. `connect_*` — what a lookup-escaping connect attempt does: error, or hang until we
///    cut it off. A hang is a real finding: `splice` must never rely on a default timeout.
pub async fn probe(timeout_secs: u64) -> Result<()> {
    let t0 = Instant::now();
    let bound = Endpoint::builder(presets::N0)
        .secret_key(iroh::SecretKey::generate())
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Default)
        .bind()
        .await;
    let bind_ms = ms(t0.elapsed());

    let endpoint = match bound {
        Ok(ep) => {
            emit(serde_json::json!({
                "event": "relay_bind",
                "ok": true,
                "bind_ms": bind_ms,
            }));
            ep
        }
        Err(err) => {
            emit(serde_json::json!({
                "event": "relay_bind",
                "ok": false,
                "bind_ms": bind_ms,
                "error": format!("{err:#}"),
            }));
            return Ok(());
        }
    };

    // No lookup service can answer for this id: it is a fresh key and the dial target has no
    // addresses, so only the relay path could ever work.
    let orphan = EndpointAddr::from_parts(iroh::SecretKey::generate().public(), []);

    let t0 = Instant::now();
    let attempt = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        endpoint.connect(orphan, ALPN),
    )
    .await;
    let elapsed = ms(t0.elapsed());

    match attempt {
        Ok(Ok(_conn)) => emit(serde_json::json!({
            "event": "relay_connect",
            "outcome": "connected",
            "elapsed_ms": elapsed,
            "note": "unexpected: connected to an addressless id with no internet",
        })),
        Ok(Err(err)) => emit(serde_json::json!({
            "event": "relay_connect",
            "outcome": "error",
            "elapsed_ms": elapsed,
            "error": format!("{err:#}"),
        })),
        Err(_) => emit(serde_json::json!({
            "event": "relay_connect",
            "outcome": "hung_past_timeout",
            "elapsed_ms": elapsed,
            "timeout_secs": timeout_secs,
            "note": "connect did not resolve within the timeout; a caller must impose its own",
        })),
    }

    // `online()` waits for a relay, so it can never complete without internet. Prove it rather
    // than assume: this is the trap that would freeze `splice listen`.
    let t0 = Instant::now();
    let online = tokio::time::timeout(Duration::from_secs(timeout_secs), endpoint.online()).await;
    emit(serde_json::json!({
        "event": "relay_online",
        "completed": online.is_ok(),
        "elapsed_ms": ms(t0.elapsed()),
        "note": if online.is_ok() { "relay reachable" } else { "online() never resolved: must not be awaited before serving" },
    }));

    endpoint.close().await;
    Ok(())
}
