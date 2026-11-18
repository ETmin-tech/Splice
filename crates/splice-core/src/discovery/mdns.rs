//! mDNS advertisement and lookup for pairing codes (§5.3).
//!
//! Service type `_splice._udp.local.`, TXT `np=<nameplate>`, `id=<ephemeral
//! NodeId in hex>`, `v=1`. The service is registered when a code is created and
//! withdrawn as soon as the session reaches PAIRED or BURNED, so the advertisement
//! only ever exposes a *live* code's nameplate.
//!
//! # Why our own schema instead of iroh's built-in mDNS
//!
//! Spike S1 measured both. The built-in discovery announces an instance label
//! that is `base32(endpoint_id)`, which any LAN observer decodes back to the real
//! NodeId (confirmed by packet capture, `LABEL_IS_NODEID: True`), and its
//! implementation returned `Network is unreachable (os error 101)` inside an
//! isolated network namespace with no default route — the exact venue the offline
//! test uses. So the decision (recorded in `Laporan-1.md` §4) was: own service
//! type, own TXT schema, own lifecycle, still on top of `mdns-sd` for the DNS
//! wire format.
//!
//! The published NodeId is the *ephemeral* key of the pairing session, never the
//! persistent identity (§5.1): after pairing the advertisement is gone and the
//! ephemeral key is dropped.

use std::collections::HashMap;
use std::time::Duration;

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

use crate::constants::PROTOCOL_VERSION;
use crate::error::{DiscoveryError, Result};
use crate::identity::NodeId;

/// The DNS-SD service type. Part of the protocol (§5.3).
pub const SERVICE_TYPE: &str = "_splice._udp.local.";

/// TXT key for the nameplate (public, only selects a host).
pub const TXT_NAMEPLATE: &str = "np";

/// TXT key for the session's ephemeral NodeId, hex encoded.
pub const TXT_NODE_ID: &str = "id";

/// TXT key for the advertisement format version.
pub const TXT_VERSION: &str = "v";

/// How long a lookup waits for a matching advertisement before giving up.
///
/// One presence interval plus a margin: mDNS answers are usually immediate on the
/// same link (S1: cold start p95 755 ms), but a lost packet costs a retry.
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// A nameplate advertised on the LAN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvertisedHost {
    /// Nameplate from the code; the only field a guest searches with.
    pub nameplate: u16,
    /// Ephemeral NodeId of the pairing session.
    pub node: NodeId,
    /// Where to dial. Port comes from the SRV record, IPs from A/AAAA records.
    pub addrs: Vec<std::net::SocketAddr>,
    /// The instance fullname, needed to withdraw the record.
    pub fullname: String,
}

impl AdvertisedHost {
    /// A [`crate::net::NodeAddr`] with every address the advertiser published.
    pub fn to_node_addr(&self) -> Option<crate::net::NodeAddr> {
        let first = *self.addrs.first()?;
        let mut addr = crate::net::NodeAddr::direct(self.node, first);
        for extra in &self.addrs[1..] {
            addr = addr.with_ip(*extra);
        }
        Some(addr)
    }
}

/// Owns a [`ServiceDaemon`] for the lifetime of the process' discovery use.
///
/// `mdns-sd` runs its own thread pool; `ServiceDaemon::new()` returns an error
/// only when *both* the IPv4 and IPv6 multicast sockets fail to bind, which is the
/// case we translate into [`DiscoveryError::MulticastUnavailable`] so the caller
/// can suggest a ticket or `--addr` instead of hanging.
pub struct Mdns {
    daemon: ServiceDaemon,
}

impl std::fmt::Debug for Mdns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mdns").finish_non_exhaustive()
    }
}

impl Mdns {
    /// Start the daemon, or explain why multicast is unusable.
    pub fn start() -> Result<Self> {
        let daemon = ServiceDaemon::new().map_err(|err| {
            DiscoveryError::MulticastUnavailable(format!("cannot open mDNS sockets: {err}"))
        })?;
        Ok(Self { daemon })
    }

    /// Check that at least one interface actually joined the mDNS group.
    ///
    /// `ServiceDaemon::new()` succeeding only means a socket bound; a host with
    /// client isolation or an isolated network namespace has a socket but no
    /// membership, and every lookup would then time out. Reading the daemon's own
    /// status is cheap and answers the question immediately.
    pub fn check_multicast(&self) -> Result<()> {
        let receiver = self
            .daemon
            .status()
            .map_err(|err| DiscoveryError::Mdns(err.to_string()))?;
        let status = receiver
            .recv_timeout(Duration::from_secs(2))
            .map_err(|err| DiscoveryError::Mdns(format!("no daemon status: {err}")))?;
        let mdns_sd::DaemonStatus::Running(running) = status else {
            return Err(DiscoveryError::MulticastUnavailable(
                "the mDNS daemon is not running".to_string(),
            )
            .into());
        };
        if !running.ipv4_socket().is_bound() && !running.ipv6_socket().is_bound() {
            return Err(DiscoveryError::MulticastUnavailable(format!(
                "no multicast socket: {}",
                running
                    .ipv4_socket()
                    .bind_error()
                    .unwrap_or("unknown reason")
            ))
            .into());
        }
        let joined = running.enabled_intfs().iter().any(|intf| {
            intf.ipv4().is_some_and(|m| m.is_joined()) || intf.ipv6().is_some_and(|m| m.is_joined())
        });
        if !joined {
            return Err(DiscoveryError::MulticastUnavailable(
                "no interface joined the mDNS multicast group".to_string(),
            )
            .into());
        }
        Ok(())
    }

    /// Advertise a live pairing code.
    ///
    /// `port` is the iroh UDP port the guest should dial; the address records are
    /// filled in by the daemon from the host's interfaces (`enable_addr_auto`), so
    /// a DHCP-renewed address does not require re-registering.
    pub fn advertise(&self, nameplate: u16, node: NodeId, port: u16) -> Result<AdvertisedHost> {
        let instance = instance_label(nameplate, node);
        let properties = HashMap::from([
            (TXT_NAMEPLATE.to_string(), nameplate.to_string()),
            (TXT_NODE_ID.to_string(), node.to_string()),
            (TXT_VERSION.to_string(), PROTOCOL_VERSION.to_string()),
        ]);
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            &instance,
            &hostname(),
            (),
            port,
            Some(properties),
        )
        .map_err(|err| DiscoveryError::Mdns(err.to_string()))?
        // The address set is maintained by the daemon as interfaces change.
        .enable_addr_auto();
        // Probing would let another host rename our instance on a name conflict,
        // and the guest searches by TXT, not by instance name, so a rename is
        // harmless; disabling the probe keeps the first advertisement fast.
        let mut info = info;
        info.set_requires_probe(false);

        let fullname = info.get_fullname().to_string();
        self.daemon
            .register(info)
            .map_err(|err| DiscoveryError::Mdns(err.to_string()))?;
        Ok(AdvertisedHost {
            nameplate,
            node,
            addrs: Vec::new(),
            fullname,
        })
    }

    /// Withdraw an advertisement. Idempotent: a record that is already gone is
    /// reported as `NotFound`, which is not an error for us (§5.4 step 8).
    pub fn withdraw(&self, fullname: &str) -> Result<()> {
        let receiver = self
            .daemon
            .unregister(fullname)
            .map_err(|err| DiscoveryError::Mdns(err.to_string()))?;
        match receiver.recv_timeout(Duration::from_secs(2)) {
            Ok(mdns_sd::UnregisterStatus::OK | mdns_sd::UnregisterStatus::NotFound) => Ok(()),
            Err(err) => Err(DiscoveryError::Mdns(format!("withdrawing {fullname}: {err}")).into()),
        }
    }

    /// Find the host advertising `nameplate`, waiting at most [`LOOKUP_TIMEOUT`].
    ///
    /// Only `ServiceResolved` carries TXT records and addresses, so the nameplate
    /// filter is applied there. Advertisements with a version we do not speak, or
    /// with an unparseable NodeId, are skipped rather than failing the lookup: a
    /// newer peer on the same LAN must not make an older `splice` unusable.
    pub async fn lookup(&self, nameplate: u16, timeout: Duration) -> Result<AdvertisedHost> {
        let receiver = self
            .daemon
            .browse(SERVICE_TYPE)
            .map_err(|err| DiscoveryError::Mdns(err.to_string()))?;
        let deadline = tokio::time::Instant::now() + timeout;
        let result = loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break None;
            }
            let event = tokio::time::timeout(remaining, receiver.recv_async()).await;
            match event {
                Err(_) => break None,
                Ok(Err(_)) => break None,
                Ok(Ok(ServiceEvent::ServiceResolved(resolved))) => {
                    if let Some(host) = from_resolved(&resolved, nameplate) {
                        break Some(host);
                    }
                }
                Ok(Ok(_)) => {}
            }
        };
        let _ = self.daemon.stop_browse(SERVICE_TYPE);
        result.ok_or_else(|| DiscoveryError::NameplateNotFound { nameplate }.into())
    }

    /// Stop the daemon. Called on shutdown; dropping the struct is not enough
    /// because `mdns-sd`'s threads outlive a plain drop.
    pub fn shutdown(&self) {
        let _ = self.daemon.shutdown();
    }
}

/// Instance label: nameplate plus the NodeId prefix, so two hosts that picked the
/// same nameplate still get distinct instance names.
///
/// `mdns-sd` escapes dots and limits the service *type* to 30 bytes; the instance
/// label is shorter than that here (`999-xxxxxxxx` = 12).
fn instance_label(nameplate: u16, node: NodeId) -> String {
    format!("{nameplate}-{}", node.prefix8())
}

/// A hostname is required by the SRV record. It is only meaningful inside the
/// local link, and deliberately does not reveal the NodeId.
fn hostname() -> String {
    format!("splice-{}.local.", std::process::id() % 100_000)
}

fn from_resolved(resolved: &mdns_sd::ResolvedService, nameplate: u16) -> Option<AdvertisedHost> {
    let properties = &resolved.txt_properties;
    let advertised: u16 = properties
        .get_property_val_str(TXT_NAMEPLATE)?
        .parse()
        .ok()?;
    if advertised != nameplate {
        return None;
    }
    let version: u16 = properties.get_property_val_str(TXT_VERSION)?.parse().ok()?;
    if version != PROTOCOL_VERSION {
        return None;
    }
    let node: NodeId = properties.get_property_val_str(TXT_NODE_ID)?.parse().ok()?;
    let port = resolved.port;
    let mut addrs: Vec<std::net::SocketAddr> = resolved
        .addresses
        .iter()
        .map(|ip| std::net::SocketAddr::new(ip.to_ip_addr(), port))
        .collect();
    addrs.sort();
    Some(AdvertisedHost {
        nameplate,
        node,
        addrs,
        fullname: resolved.fullname.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_label_is_short_and_distinct() {
        let a = NodeId::from_bytes([1; 32]);
        let b = NodeId::from_bytes([2; 32]);
        assert_eq!(instance_label(7, a), "7-01010101");
        assert_ne!(instance_label(7, a), instance_label(7, b));
        assert!(instance_label(999, b).len() <= 30);
    }

    #[test]
    fn service_type_is_the_architecture_value() {
        assert_eq!(SERVICE_TYPE, "_splice._udp.local.");
        assert!(SERVICE_TYPE.ends_with("._udp.local."));
    }

    #[test]
    fn txt_keys_match_the_architecture() {
        assert_eq!(TXT_NAMEPLATE, "np");
        assert_eq!(TXT_NODE_ID, "id");
        assert_eq!(TXT_VERSION, "v");
    }

    #[test]
    fn hostname_never_contains_the_node_id() {
        let node = NodeId::from_bytes([0xab; 32]);
        let name = hostname();
        assert!(!name.contains(&node.prefix8()));
        assert!(name.ends_with(".local."));
    }

    #[test]
    fn to_node_addr_keeps_every_published_address() {
        let node = NodeId::from_bytes([3; 32]);
        let host = AdvertisedHost {
            nameplate: 5,
            node,
            addrs: vec![
                "10.0.0.5:4242".parse().unwrap(),
                "10.0.0.6:4242".parse().unwrap(),
            ],
            fullname: "5-03030303._splice._udp.local.".to_string(),
        };
        let addr = host.to_node_addr().expect("has addresses");
        assert_eq!(addr.id(), node);
        assert_eq!(addr.ip_addrs().len(), 2);
        assert!(AdvertisedHost {
            addrs: Vec::new(),
            ..host
        }
        .to_node_addr()
        .is_none());
    }
}
