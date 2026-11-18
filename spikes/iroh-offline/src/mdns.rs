//! Local discovery: is there mDNS in iroh, how fast is a peer visible, and what leaks?
//!
//! iroh 1.4.1 has no built-in mDNS. `iroh-mdns-address-lookup` wraps `swarm-discovery`, which
//! announces an instance name of the form `<base32(endpoint_id)>._<service>._udp.local`. This
//! module measures the appear latency and prints the base32 label so a packet capture can be
//! checked for it — the NodeId-leak question from `Architecture.md` §5.3 / I17.

use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use iroh::{endpoint::presets, Endpoint, EndpointId, RelayMode};
use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};
use n0_future::StreamExt;

use crate::{emit, ms};

/// Advertise a peer on the mDNS-like service and stay up until killed.
pub async fn serve(service: String) -> Result<()> {
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(iroh::SecretKey::generate())
        .relay_mode(RelayMode::Disabled)
        // No relay transport means nothing but IP addresses get advertised.
        .bind()
        .await
        .context("bind mdns server")?;

    let mdns = MdnsAddressLookup::builder()
        .service_name(service.clone())
        .advertise(true)
        .build(endpoint.id())
        .context("build mdns lookup")?;
    endpoint
        .address_lookup()
        .context("endpoint address lookup")?
        .add(mdns.clone());

    let sockets: Vec<String> = endpoint
        .bound_sockets()
        .iter()
        .map(|s| s.to_string())
        .collect();

    emit(serde_json::json!({
        "event": "mdns_listening",
        "id": endpoint.id().to_string(),
        "base32_label": base32_lower(&endpoint.id()),
        "instance_name": format!(
            "{}._{}._udp.local",
            base32_lower(&endpoint.id()),
            service
        ),
        "sockets": sockets,
        "service": service,
    }));

    // Hold the endpoint open; the discoverer advertises on its own cadence.
    tokio::signal::ctrl_c().await.ok();
    endpoint.close().await;
    Ok(())
}

/// Measure how long the target peer takes to appear, once, and exit.
///
/// Run repeatedly as separate processes to get a distribution: each run starts with an empty
/// discovery cache, which is exactly the cold-start case `splice` cares about.
pub async fn probe(id: EndpointId, service: String, timeout_secs: u64) -> Result<()> {
    let t_start = Instant::now();
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(iroh::SecretKey::generate())
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .context("bind mdns probe")?;

    let mdns = MdnsAddressLookup::builder()
        .service_name(service)
        .advertise(false)
        .build(endpoint.id())
        .context("build mdns lookup")?;
    endpoint
        .address_lookup()
        .context("endpoint address lookup")?
        .add(mdns.clone());

    // Start counting after registration, so the number means "subscriber registered -> seen".
    let t0 = Instant::now();
    let mut events = mdns.subscribe().await;

    let deadline = Duration::from_secs(timeout_secs);
    let found = tokio::time::timeout(deadline, async {
        while let Some(event) = events.next().await {
            if let DiscoveryEvent::Discovered { endpoint_info, .. } = event {
                if endpoint_info.endpoint_id == id {
                    return Some(endpoint_info);
                }
            }
        }
        None
    })
    .await;

    let setup_ms = ms(t0.duration_since(t_start));
    let mut discovered = false;
    match found {
        Ok(Some(info)) => {
            discovered = true;
            let addrs: Vec<String> = info.addrs().map(|a| format!("{a:?}")).collect();
            emit(serde_json::json!({
                "event": "mdns_appear",
                "found": true,
                "appear_ms": ms(t0.elapsed()),
                "setup_ms": setup_ms,
                "target": id.to_string(),
                "target_base32": base32_lower(&id),
                "addrs": addrs,
            }));
        }
        Ok(None) => emit(serde_json::json!({
            "event": "mdns_appear",
            "found": false,
            "appear_ms": ms(t0.elapsed()),
            "setup_ms": setup_ms,
            "target": id.to_string(),
            "reason": "event stream closed",
        })),
        Err(_) => emit(serde_json::json!({
            "event": "mdns_appear",
            "found": false,
            "appear_ms": ms(t0.elapsed()),
            "setup_ms": setup_ms,
            "target": id.to_string(),
            "reason": "timeout",
            "timeout_secs": timeout_secs,
        })),
    }

    endpoint.close().await;
    if !discovered {
        bail!("target not discovered within {timeout_secs}s");
    }
    Ok(())
}

/// Lowercase RFC 4648 base32 without padding — the label `swarm-discovery` publishes.
fn base32_lower(id: &EndpointId) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let bytes = id.as_bytes();
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::base32_lower;

    /// Cross-checks against the doc example in `iroh-mdns-address-lookup`.
    #[test]
    fn base32_matches_known_label_length() {
        // 32 bytes -> 52 chars for base32 without padding.
        let id: [u8; 32] = [0u8; 32];
        let label = base32_lower(&iroh::EndpointId::from_bytes(&id).unwrap());
        assert_eq!(label.len(), 52, "got {label}");
        assert!(label
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        assert_eq!(label, "a".repeat(52));
    }
}
