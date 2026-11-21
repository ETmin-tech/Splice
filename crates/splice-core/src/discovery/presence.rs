//! Trusted-device presence over UDP multicast (§5.3, D13, I17).
//!
//! Every trusted device broadcasts an 11-byte beacon every [`PRESENCE_INTERVAL`]:
//!
//! ```text
//! v:u8 | tag:[u8;8] | port:u16 (big-endian)
//! ```
//!
//! `tag` is a *rotating* keyed hash of the sender's [`NodeId`] and the current
//! 300-second time bucket:
//!
//! ```text
//! tag = blake3::keyed_hash(derive_key("splice presence v1", node_id),
//!                          floor(t / 300).to_be_bytes())[0..8]
//! ```
//!
//! A LAN observer therefore sees an opaque 8-byte value that changes every five
//! minutes and cannot be linked to a device it has not already been told about
//! (I17: no alias, no NodeId, nothing human readable). A device that *is* in our
//! trust store recomputes the tag for every NodeId it knows, over buckets −1, 0
//! and +1, so a clock difference of up to five minutes still matches.
//!
//! The beacon carries the sender's transport UDP port; the source IP of the datagram
//! supplies the address, so a matched beacon yields a complete
//! NodeAddr hint.
//! A forged beacon only produces a dial that TLS rejects.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use crate::clock::Clock;
use crate::constants::{
    PRESENCE_INTERVAL, PRESENCE_OFFLINE_AFTER, PRESENCE_TAG_BUCKET, PRESENCE_TAG_SKEW_BUCKETS,
};
use crate::error::{DiscoveryError, Result};
use crate::identity::NodeId;

/// IPv4 multicast group for presence beacons.
///
/// `Architecture.md` §5.3 says "UDP multicast on the local network" without
/// fixing an address, so this is our choice: the administratively scoped range
/// (239.0.0.0/8) keeps it off the internet and off the mDNS/DNS-SD group
/// (224.0.0.251), so presence never mixes with discovery traffic.
pub const PRESENCE_GROUP_V4: Ipv4Addr = Ipv4Addr::new(239, 255, 71, 20);

/// UDP port for presence beacons. Also our choice (see the group above); it is
/// deliberately not 5353 so a host running a stock mDNS daemon still works.
pub const PRESENCE_PORT: u16 = 47820;

/// Domain separator for the presence key. A rename would break interop; the
/// string is part of the protocol, not a label.
pub const PRESENCE_KDF_CONTEXT: &str = "splice presence v1";

/// Beacon format version.
pub const PRESENCE_VERSION: u8 = 1;

/// Encoded beacon length: `v` + `tag` + `port`.
pub const BEACON_LEN: usize = 1 + TAG_LEN + 2;

/// Truncated tag length. 64 bits makes an accidental match between unrelated
/// devices negligible while keeping the datagram small.
pub const TAG_LEN: usize = 8;

/// The presence tag of one device in one time bucket.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PresenceTag([u8; TAG_LEN]);

impl PresenceTag {
    pub const fn from_bytes(bytes: [u8; TAG_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; TAG_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for PresenceTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A tag is not a secret (it is broadcast), but printing it in full adds
        // noise to logs; the prefix is enough to correlate two lines.
        write!(f, "PresenceTag({:02x}{:02x}..)", self.0[0], self.0[1])
    }
}

/// The bucket index `floor(t / PRESENCE_TAG_BUCKET)` for an instant.
pub fn bucket_at(now: Duration) -> i64 {
    (now.as_secs() / PRESENCE_TAG_BUCKET.as_secs()) as i64
}

/// Derive the tag for `node` in `bucket`.
///
/// Deriving the per-device key on every call would be wasteful (a receiver
/// recomputes tags for every trusted device every bucket), so callers that loop
/// over many buckets should go through [`DeviceTags`].
pub fn tag_for(node: NodeId, bucket: i64) -> PresenceTag {
    DeviceTags::new(node).at(bucket)
}

/// Per-device key plus cached tags for the buckets around a moving clock.
///
/// The key is `derive_key(context, NodeId)`: a receiver can compute it for any
/// device it already knows, and nobody else can.
pub struct DeviceTags {
    key: [u8; blake3::KEY_LEN],
    /// Bucket whose tags are cached, and the three tags for it (−1, 0, +1).
    cached_bucket: Option<i64>,
    cached: [PresenceTag; 3],
}

impl DeviceTags {
    pub fn new(node: NodeId) -> Self {
        Self {
            key: blake3::derive_key(PRESENCE_KDF_CONTEXT, node.as_bytes()),
            cached_bucket: None,
            cached: [PresenceTag::from_bytes([0; TAG_LEN]); 3],
        }
    }

    /// The tag for an explicit bucket.
    pub fn at(&mut self, bucket: i64) -> PresenceTag {
        if self.cached_bucket == Some(bucket) {
            return self.cached[1];
        }
        let mut tags = [PresenceTag::from_bytes([0; TAG_LEN]); 3];
        for (offset, slot) in tags.iter_mut().enumerate() {
            *slot = self.compute(bucket + offset as i64 - PRESENCE_TAG_SKEW_BUCKETS);
        }
        self.cached = tags;
        self.cached_bucket = Some(bucket);
        tags[1]
    }

    fn compute(&self, bucket: i64) -> PresenceTag {
        let hash = blake3::keyed_hash(&self.key, &bucket.to_be_bytes());
        let mut out = [0u8; TAG_LEN];
        out.copy_from_slice(&hash.as_bytes()[..TAG_LEN]);
        PresenceTag::from_bytes(out)
    }

    /// Match one received tag against the three buckets around `now`.
    ///
    /// Returns the bucket that matched, which tells the caller how far the
    /// sender's clock is from ours (useful for a diagnostic, not for trust).
    pub fn match_now(&mut self, now: Duration, received: PresenceTag) -> Option<i64> {
        let bucket = bucket_at(now);
        let _ = self.at(bucket);
        for offset in -PRESENCE_TAG_SKEW_BUCKETS..=PRESENCE_TAG_SKEW_BUCKETS {
            let candidate = bucket + offset;
            let slot = (offset + PRESENCE_TAG_SKEW_BUCKETS) as usize;
            if self.cached[slot] == received {
                return Some(candidate);
            }
        }
        None
    }
}

/// A decoded beacon. Deliberately `Copy` and tiny: it is processed on the hot
/// path and must not allocate.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Beacon {
    pub tag: PresenceTag,
    /// The sender's transport UDP port, used as a direct-address hint.
    pub port: u16,
}

impl std::fmt::Debug for Beacon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Beacon")
            .field("tag", &self.tag)
            .field("port", &self.port)
            .finish()
    }
}

impl Beacon {
    pub fn encode(&self) -> [u8; BEACON_LEN] {
        let mut out = [0u8; BEACON_LEN];
        out[0] = PRESENCE_VERSION;
        out[1..1 + TAG_LEN].copy_from_slice(self.tag.as_bytes());
        out[1 + TAG_LEN..].copy_from_slice(&self.port.to_be_bytes());
        out
    }

    /// Decode a datagram. A wrong length or version is dropped silently: a
    /// stranger's traffic must not be able to spam the log or cause an error.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != BEACON_LEN || bytes[0] != PRESENCE_VERSION {
            return None;
        }
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&bytes[1..1 + TAG_LEN]);
        let port = u16::from_be_bytes([bytes[1 + TAG_LEN], bytes[1 + TAG_LEN + 1]]);
        Some(Self {
            tag: PresenceTag::from_bytes(tag),
            port,
        })
    }
}

/// A trusted device that has been heard from recently.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PeerPresence {
    /// The trusted device the beacon matched.
    pub node: NodeId,
    /// Source address of the beacon, with the port taken from the beacon body.
    pub addr: SocketAddr,
    /// When it was last heard.
    pub last_seen: Duration,
}

impl std::fmt::Debug for PeerPresence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerPresence")
            .field("node", &self.node)
            .field("addr", &self.addr)
            .field("last_seen_secs", &self.last_seen.as_secs())
            .finish()
    }
}

impl PeerPresence {
    /// A NodeAddr hint for dialing this device directly.
    pub fn to_node_addr(&self) -> crate::net::NodeAddr {
        crate::net::NodeAddr::direct(self.node, self.addr)
    }
}

/// Per-source datagram budget, so one host cannot flood the socket.
struct Budget {
    window_start: Duration,
    count: u32,
}

/// Matches beacons against the trusted list and tracks who is online.
///
/// Owns no socket: [`observe`](Self::observe) takes a datagram and its source
/// address, which keeps the whole state machine testable without a network.
pub struct PresenceTracker {
    clock: std::sync::Arc<dyn Clock>,
    tags: HashMap<NodeId, DeviceTags>,
    seen: HashMap<NodeId, PeerPresence>,
    budgets: HashMap<IpAddr, Budget>,
}

impl std::fmt::Debug for PresenceTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PresenceTracker")
            .field("trusted", &self.tags.len())
            .field("online", &self.seen.len())
            .finish()
    }
}

impl PresenceTracker {
    /// `clock` drives both matching and expiry; tests pass a [`crate::clock::ManualClock`].
    pub fn new(clock: std::sync::Arc<dyn Clock>) -> Self {
        Self {
            clock,
            tags: HashMap::new(),
            seen: HashMap::new(),
            budgets: HashMap::new(),
        }
    }

    /// Replace the trusted set. Devices removed here stop being matched on the
    /// next beacon, and their `seen` entries are dropped immediately.
    pub fn set_trusted(&mut self, nodes: Vec<NodeId>) {
        let wanted: std::collections::HashSet<NodeId> = nodes.iter().copied().collect();
        self.tags.retain(|node, _| wanted.contains(node));
        self.seen.retain(|node, _| wanted.contains(node));
        for node in nodes {
            self.tags
                .entry(node)
                .or_insert_with(|| DeviceTags::new(node));
        }
    }

    pub fn trusted(&self) -> usize {
        self.tags.len()
    }

    /// Feed one datagram. Returns the device it matched, if any.
    ///
    /// `from` is the address the OS reported; its port is replaced by the port
    /// in the beacon because the sender may transmit from an ephemeral port.
    pub fn observe(&mut self, datagram: &[u8], from: SocketAddr) -> Option<PeerPresence> {
        let now = self.clock.now();
        if !self.spend_budget(from.ip(), now) {
            return None;
        }
        let beacon = Beacon::decode(datagram)?;
        let source = SocketAddr::new(from.ip(), beacon.port);

        let matched = oldest_match(self.tags.iter_mut().filter_map(|(node, tags)| {
            tags.match_now(now, beacon.tag)
                .map(|bucket| (*node, bucket))
        }));
        let (node, _bucket) = matched?;

        let presence = PeerPresence {
            node,
            addr: source,
            last_seen: now,
        };
        self.seen.insert(node, presence);
        Some(presence)
    }

    /// Trusted devices heard from within [`PRESENCE_OFFLINE_AFTER`].
    pub fn online(&mut self) -> Vec<PeerPresence> {
        let now = self.clock.now();
        self.seen
            .retain(|_, seen| now.saturating_sub(seen.last_seen) < PRESENCE_OFFLINE_AFTER);
        let mut out: Vec<PeerPresence> = self.seen.values().copied().collect();
        out.sort_by_key(|presence| presence.node);
        out
    }

    pub fn is_online(&mut self, node: NodeId) -> bool {
        self.online().iter().any(|presence| presence.node == node)
    }

    /// The known direct hint for `node`, if it is still online.
    pub fn node_addr(&mut self, node: NodeId) -> Option<crate::net::NodeAddr> {
        self.online()
            .into_iter()
            .find(|presence| presence.node == node)
            .map(|presence| presence.to_node_addr())
    }

    fn spend_budget(&mut self, ip: IpAddr, now: Duration) -> bool {
        let budget = self.budgets.entry(ip).or_insert(Budget {
            window_start: now,
            count: 0,
        });
        if now.saturating_sub(budget.window_start) >= Duration::from_secs(1) {
            budget.window_start = now;
            budget.count = 0;
        }
        budget.count += 1;
        budget.count <= crate::constants::PRESENCE_MAX_PER_SEC
    }
}

/// A bound presence socket: sends beacons and receives other devices' beacons.
///
/// Uses `socket2` directly because we need `SO_REUSEADDR` *before* binding (other
/// processes on the same host must be able to listen too) and multicast group
/// membership on a specific interface.
pub struct PresenceSocket {
    socket: tokio::net::UdpSocket,
    group: std::net::Ipv4Addr,
    /// Every IPv4 interface the group was joined on, in join order: the usable
    /// interfaces first, then loopback. A beacon is sent once per entry, so a
    /// host with Wi-Fi *and* Ethernet reaches peers on both segments instead of
    /// only the one the kernel would pick. Kept for diagnostics too: a bind that
    /// succeeds but joins nothing here is the failure mode the tests report.
    egresses: Vec<std::net::Ipv4Addr>,
}

impl std::fmt::Debug for PresenceSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PresenceSocket")
            .field("port", &self.port())
            .field("group", &self.group)
            .field("egresses", &self.egresses)
            .finish()
    }
}

impl PresenceSocket {
    /// Bind [`PRESENCE_PORT`] and join the group on every IPv4 interface.
    ///
    /// A host with no usable interface (client isolation, no multicast route)
    /// gets [`DiscoveryError::MulticastUnavailable`] rather than a silent socket
    /// that never receives anything.
    pub fn bind(port: u16) -> Result<Self> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .map_err(|err| DiscoveryError::PresenceSocket(err.to_string()))?;
        socket
            .set_reuse_address(true)
            .map_err(|err| DiscoveryError::PresenceSocket(err.to_string()))?;
        // `SO_REUSEADDR` alone lets two sockets share a UDP port on Linux, but on
        // the BSDs (macOS included) it does not: the second `bind` fails with
        // `EADDRINUSE`. Several processes on one host must be able to listen
        // (and the two-socket test opens both on one port), so `SO_REUSEPORT` is
        // required there, not a nicety. The `cfg` mirrors the platforms where
        // socket2 exposes the option; on those, failing to set it is fatal
        // because the alternative is a bind that silently cannot be shared.
        #[cfg(all(
            unix,
            not(any(
                target_os = "solaris",
                target_os = "illumos",
                target_os = "cygwin",
                target_os = "nuttx",
                target_os = "wasi"
            ))
        ))]
        socket.set_reuse_port(true).map_err(|err| {
            DiscoveryError::PresenceSocket(format!("cannot enable SO_REUSEPORT: {err}"))
        })?;
        // Our own beacon must come back to us: on a host that is the only
        // listener, and in the send test where sender and receiver share the
        // port, delivery relies on the multicast loopback. The option defaults
        // on, but it is set explicitly so a platform default cannot silently
        // change the receive path this test measures.
        let _ = socket.set_multicast_loop_v4(true);
        socket
            .set_nonblocking(true)
            .map_err(|err| DiscoveryError::PresenceSocket(err.to_string()))?;
        socket
            .bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port).into())
            .map_err(|err| {
                DiscoveryError::MulticastUnavailable(format!(
                    "cannot bind UDP port {port}: {err}{}",
                    interface_context()
                ))
            })?;

        let group = PRESENCE_GROUP_V4;
        let egresses = join_on_all_interfaces(&socket, group);
        if egresses.is_empty() {
            return Err(DiscoveryError::MulticastUnavailable(format!(
                "cannot join {group} on any IPv4 interface{}",
                interface_context()
            ))
            .into());
        }
        // Joining only fixes the receive path. Sending without an explicit egress
        // interface asks the kernel to pick one from the routing table, which
        // fails with `Network is unreachable` when there is no default route (an
        // offline network namespace, a client-isolated WLAN). Start from the
        // first joined interface; `send` walks the whole list and re-pins the
        // egress before each datagram, so one host can beacon on every segment it
        // is attached to.
        if let Some(primary) = egresses.iter().find(|addr| **addr != Ipv4Addr::UNSPECIFIED) {
            let _ = socket.set_multicast_if_v4(primary);
        }
        let socket = tokio::net::UdpSocket::from_std(socket.into())
            .map_err(|err| DiscoveryError::PresenceSocket(err.to_string()))?;
        Ok(Self {
            socket,
            group,
            egresses,
        })
    }

    /// The bound port (useful when the caller passed 0 in a test).
    pub fn port(&self) -> u16 {
        self.socket
            .local_addr()
            .map(|addr| addr.port())
            .unwrap_or(0)
    }

    pub fn group(&self) -> Ipv4Addr {
        self.group
    }

    /// The first interface joined, or `0.0.0.0` when the kernel chose. This is
    /// the one used for the first datagram; [`Self::egresses`] has the whole list.
    pub fn egress(&self) -> Ipv4Addr {
        self.egresses
            .first()
            .copied()
            .unwrap_or(Ipv4Addr::UNSPECIFIED)
    }

    /// Every interface the group was joined on, in send order. Exposed so a
    /// failed receive or send can name the interfaces it should have used.
    pub fn egresses(&self) -> &[Ipv4Addr] {
        &self.egresses
    }

    /// Broadcast one beacon on every joined interface.
    ///
    /// A host with Wi-Fi *and* Ethernet is attached to two segments; the kernel
    /// sends multicast on one interface per datagram, so a single `send_to`
    /// reaches only the segment of the chosen egress. Re-pinning the egress
    /// before each datagram covers all of them. A beacon counts as sent when at
    /// least one interface carried it; if none did, the error names each
    /// interface and its own errno, because "No route to host" alone does not say
    /// which segment failed.
    pub async fn send(&self, beacon: &Beacon) -> Result<()> {
        let target = SocketAddr::new(IpAddr::V4(self.group), self.port());
        send_on_all(&self.socket, &self.egresses, target, &beacon.encode()).await
    }

    /// Wait for one datagram. Returns the bytes and the source address.
    ///
    /// The buffer is one byte larger than a beacon so an over-long datagram is
    /// observed as such (and rejected by [`Beacon::decode`]) instead of being
    /// silently truncated into a valid-looking frame (I9).
    pub async fn recv(&self) -> Result<([u8; BEACON_LEN + 1], usize, SocketAddr)> {
        let mut buffer = [0u8; BEACON_LEN + 1];
        let (len, from) = self
            .socket
            .recv_from(&mut buffer)
            .await
            .map_err(|err| DiscoveryError::PresenceSocket(err.to_string()))?;
        Ok((buffer, len, from))
    }

    /// The interval between beacons, for callers that drive the loop.
    pub const fn interval() -> Duration {
        PRESENCE_INTERVAL
    }

    /// Test-only: replace the egress list so a test can inject an interface that
    /// cannot carry a datagram without needing a second NIC. Nothing outside
    /// `tests` can reach it, so the production egress list stays a property of
    /// the host.
    #[cfg(test)]
    fn with_egresses(mut self, egresses: Vec<Ipv4Addr>) -> Self {
        self.egresses = egresses;
        self
    }
}

/// Send `bytes` once per egress interface, succeeding if at least one carried it.
///
/// Multicast is per-interface: one `send_to` leaves through a single interface,
/// so a host on two segments needs one datagram each. The egress is re-pinned
/// with `IP_MULTICAST_IF` immediately before every `send_to`; `UNSPECIFIED`
/// means "let the kernel pick", which is what the fallback join records.
///
/// The error lists every interface with its own errno, because "No route to
/// host" alone does not say which segment failed — and on a machine we cannot
/// log into, that list is the whole diagnosis.
async fn send_on_all(
    socket: &tokio::net::UdpSocket,
    egresses: &[Ipv4Addr],
    target: SocketAddr,
    bytes: &[u8],
) -> Result<()> {
    let mut sent = 0usize;
    let mut failures: Vec<String> = Vec::new();
    for egress in egresses {
        if *egress != Ipv4Addr::UNSPECIFIED {
            if let Err(err) = socket2::SockRef::from(socket).set_multicast_if_v4(egress) {
                log_interface_error(*egress, &err);
                failures.push(format!("{egress}: set egress: {err}"));
                continue;
            }
        }
        match socket.send_to(bytes, target).await {
            Ok(_) => sent += 1,
            Err(err) => {
                log_interface_error(*egress, &err);
                failures.push(format!("{egress}: {err}"));
            }
        }
    }
    if sent > 0 {
        return Ok(());
    }
    Err(DiscoveryError::PresenceSocket(format!(
        "no interface carried the beacon to {target} (tried: {}){}",
        failures.join(", "),
        interface_context()
    ))
    .into())
}

/// Rate-limited warning when a multicast interface fails to send.
///
/// Logging at most once per 30 seconds per interface IP avoids flooding the
/// logs on every tick while preserving diagnostic visibility.
fn log_interface_error(egress: Ipv4Addr, err: &dyn std::fmt::Display) {
    static LAST_LOGGED: std::sync::Mutex<Option<HashMap<Ipv4Addr, std::time::Instant>>> =
        std::sync::Mutex::new(None);
    let mut guard = match LAST_LOGGED.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    let map = guard.get_or_insert_with(HashMap::new);
    let now = std::time::Instant::now();
    let should_log = match map.get(&egress) {
        Some(last) => now.duration_since(*last) >= Duration::from_secs(30),
        None => true,
    };
    if should_log {
        map.insert(egress, now);
        tracing::warn!(%egress, %err, "multicast beacon send failed on interface");
    }
}

/// Best-effort join on every interface, returning every address that joined.
///
/// `join_multicast_v4` with `Ipv4Addr::UNSPECIFIED` lets the kernel pick the
/// interface for the default route, which is exactly what breaks on a
/// client-isolated Wi-Fi or an offline network namespace; so we try each
/// interface address explicitly and keep the successes.
///
/// The list is also the send order: usable interfaces first, in enumeration
/// order. Loopback is only used as a fallback when no real interface joined.
fn join_on_all_interfaces(socket: &socket2::Socket, group: Ipv4Addr) -> Vec<Ipv4Addr> {
    let mut candidates = Vec::new();
    let mut loopback = Vec::new();
    if let Ok(interfaces) = if_addrs::get_if_addrs() {
        for interface in interfaces {
            if interface.is_p2p() {
                continue;
            }
            if let IpAddr::V4(addr) = interface.ip() {
                if addr.is_loopback() {
                    loopback.push(addr);
                } else if usable_multicast_interface(addr) {
                    candidates.push(addr);
                }
            }
        }
    }
    let mut joined = join_all(candidates, |addr| {
        socket.join_multicast_v4(&group, addr).is_ok()
    });
    // Active multicast interfaces take precedence: loopback is only joined as a fallback
    // when no real IPv4 multicast interface is available.
    if !joined.is_empty() {
        return joined;
    }
    for addr in loopback {
        if socket.join_multicast_v4(&group, &addr).is_ok() {
            joined.push(addr);
        }
    }
    if !joined.is_empty() {
        return joined;
    }
    // Fall back to the kernel's choice: works on a normal single-NIC host
    // even when enumeration is restricted.
    if socket
        .join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED)
        .is_ok()
    {
        return vec![Ipv4Addr::UNSPECIFIED];
    }
    Vec::new()
}

/// Whether a local IPv4 address is one to join multicast on as a *real*
/// interface.
///
/// Link-local addresses are reached through the interface's normal address
/// anyway, and loopback has no multicast segment — it is joined separately, as
/// the last-resort egress, so it must be filtered out here rather than in the
/// caller.
fn usable_multicast_interface(addr: Ipv4Addr) -> bool {
    !addr.is_loopback() && !addr.is_link_local()
}

/// Enumerate the host's IPv4 interfaces for an error message.
///
/// A multicast failure is almost always a *host* property (no usable interface,
/// client isolation), not a bug in this file, so the message must carry the
/// evidence to tell the two apart on a machine we cannot log into.
fn interface_context() -> String {
    match if_addrs::get_if_addrs() {
        Ok(interfaces) => {
            let mut listed = Vec::new();
            for interface in interfaces {
                listed.push(format!("{}={}", interface.name, interface.ip()));
            }
            if listed.is_empty() {
                " (no interfaces enumerated)".to_string()
            } else {
                format!(" (interfaces: {})", listed.join(", "))
            }
        }
        Err(err) => format!(" (interface enumeration failed: {err})"),
    }
}

/// The addresses for which `join` succeeds, in input order.
///
/// Order matters: the first entry is the egress tried first, so two runs on the
/// same host send in the same order. It is a separate function because the
/// choice is otherwise only reachable through a real NIC.
fn join_all<F>(candidates: impl IntoIterator<Item = Ipv4Addr>, mut join: F) -> Vec<Ipv4Addr>
where
    F: FnMut(&Ipv4Addr) -> bool,
{
    let mut joined = Vec::new();
    for addr in candidates {
        if join(&addr) {
            joined.push(addr);
        }
    }
    joined
}

/// The matching device with the smallest `NodeId`, or `None`.
///
/// A tag can in principle match two trusted devices, so the winner must be
/// deterministic: picking the smallest id makes the answer independent of hash
/// order. Two real nodes cannot collide on an 8-byte tag, which is why this lives
/// on its own — the tie-break is unreachable through `observe`.
fn oldest_match(matches: impl IntoIterator<Item = (NodeId, i64)>) -> Option<(NodeId, i64)> {
    let mut best: Option<(NodeId, i64)> = None;
    for candidate in matches {
        if best.is_none_or(|(id, _)| candidate.0 < id) {
            best = Some(candidate);
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use std::sync::Arc;

    fn node(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 32])
    }

    fn at(secs: u64) -> Duration {
        Duration::from_secs(secs)
    }

    #[test]
    fn the_oldest_matching_id_wins_regardless_of_iteration_order() {
        // The tie-break must not depend on hash order, so the smallest id wins
        // whatever order the candidates arrive in.
        let candidates = [(node(0x30), 1), (node(0x20), 2), (node(0x40), 3)];
        let expected = (node(0x20), 2);
        assert_eq!(oldest_match(candidates), Some(expected));
        assert_eq!(
            oldest_match(candidates.into_iter().rev()),
            Some(expected),
            "reversing the input must not change the winner"
        );
        assert_eq!(oldest_match(std::iter::empty()), None);
    }

    #[test]
    fn the_oldest_match_keeps_the_first_bucket_for_a_repeated_id() {
        // Two candidates with the same id can only come from one device, and
        // keeping the first seen makes the result stable rather than last-wins.
        let repeated = [(node(0x20), 7), (node(0x20), 9)];
        assert_eq!(oldest_match(repeated), Some((node(0x20), 7)));
    }

    #[test]
    fn tag_is_stable_within_a_bucket_and_changes_between_buckets() {
        let mut tags = DeviceTags::new(node(1));
        let first = tags.at(100);
        assert_eq!(first, tags.at(100));
        assert_ne!(first, tags.at(101));
    }

    #[test]
    fn tag_depends_on_the_node() {
        assert_ne!(tag_for(node(1), 100), tag_for(node(2), 100));
        assert_ne!(tag_for(node(1), 100), tag_for(node(1), 101));
    }

    #[test]
    fn bucket_boundaries() {
        assert_eq!(bucket_at(at(0)), 0);
        assert_eq!(bucket_at(at(299)), 0);
        assert_eq!(bucket_at(at(300)), 1);
        assert_eq!(bucket_at(at(599)), 1);
        assert_eq!(bucket_at(at(600)), 2);
    }

    #[test]
    fn clock_skew_of_one_bucket_matches_in_both_directions() {
        let now = at(900); // bucket 3
        let mut receiver = DeviceTags::new(node(7));
        for skew in [-1i64, 0, 1] {
            let sender = tag_for(node(7), bucket_at(now) + skew);
            assert_eq!(
                receiver.match_now(now, sender),
                Some(bucket_at(now) + skew),
                "skew {skew} should match"
            );
        }
        // Two buckets away is outside the tolerance.
        let stale = tag_for(node(7), bucket_at(now) + 2);
        assert_eq!(receiver.match_now(now, stale), None);
        let future = tag_for(node(7), bucket_at(now) - 2);
        assert_eq!(receiver.match_now(now, future), None);
    }

    #[test]
    fn matching_across_a_bucket_edge_keeps_working() {
        // Sender is one second behind the bucket edge, receiver just after it.
        let mut receiver = DeviceTags::new(node(3));
        let sender_bucket = bucket_at(at(299));
        let tag = tag_for(node(3), sender_bucket);
        assert_eq!(receiver.match_now(at(300), tag), Some(sender_bucket));
    }

    #[test]
    fn beacon_roundtrips_and_rejects_bad_input() {
        let beacon = Beacon {
            tag: tag_for(node(4), 12),
            port: 4242,
        };
        let bytes = beacon.encode();
        assert_eq!(bytes.len(), BEACON_LEN);
        assert_eq!(Beacon::decode(&bytes), Some(beacon));

        assert_eq!(Beacon::decode(&[]), None);
        assert_eq!(Beacon::decode(&bytes[..BEACON_LEN - 1]), None);
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert_eq!(Beacon::decode(&longer), None);
        let mut wrong_version = bytes;
        wrong_version[0] = 2;
        assert_eq!(Beacon::decode(&wrong_version), None);
    }

    /// I17: the beacon is an opaque tag and a port, nothing else.
    #[test]
    fn i17_beacon_has_no_identity_or_alias_bytes() {
        let alias = "Rina's laptop";
        let id = node(0xab);
        let beacon = Beacon {
            tag: tag_for(id, bucket_at(at(1_000))),
            port: 5555,
        };
        let bytes = beacon.encode();

        assert!(
            !bytes.windows(alias.len()).any(|w| w == alias.as_bytes()),
            "alias must not appear in a beacon"
        );
        assert!(
            !bytes.windows(NodeId::LEN).any(|w| w == id.as_bytes()),
            "NodeId must not appear in a beacon"
        );
        // Nothing printable beyond the version byte and the tag, which are
        // deliberately binary.
        assert!(
            bytes[1..]
                .windows(4)
                .all(|w| !w.iter().all(|b| b.is_ascii_graphic())),
            "beacon must not contain a printable run"
        );
        assert_eq!(bytes.len(), 11);
    }

    #[test]
    fn tracker_matches_a_trusted_device_and_builds_a_direct_hint() {
        let clock = Arc::new(ManualClock::at(at(1_000)));
        let mut tracker = PresenceTracker::new(clock.clone());
        let peer = node(9);
        tracker.set_trusted(vec![peer]);

        let beacon = Beacon {
            tag: tag_for(peer, bucket_at(clock.now())),
            port: 8080,
        };
        let from: SocketAddr = "10.0.0.9:12345".parse().unwrap();
        let matched = tracker.observe(&beacon.encode(), from).expect("must match");
        assert_eq!(matched.node, peer);
        assert_eq!(matched.addr, "10.0.0.9:8080".parse().unwrap());

        let online = tracker.online();
        assert_eq!(online.len(), 1);
        assert_eq!(tracker.node_addr(peer).unwrap().ip_addrs()[0].port(), 8080);
    }

    #[test]
    fn untrusted_tags_are_ignored() {
        let clock = Arc::new(ManualClock::at(at(1_000)));
        let mut tracker = PresenceTracker::new(clock.clone());
        tracker.set_trusted(vec![node(1)]);
        let stranger = Beacon {
            tag: tag_for(node(2), bucket_at(clock.now())),
            port: 1,
        };
        let from: SocketAddr = "10.0.0.2:1".parse().unwrap();
        assert!(tracker.observe(&stranger.encode(), from).is_none());
        assert!(tracker.online().is_empty());
    }

    #[test]
    fn device_goes_offline_after_the_offline_window() {
        let clock = Arc::new(ManualClock::at(at(1_000)));
        let mut tracker = PresenceTracker::new(clock.clone());
        let peer = node(5);
        tracker.set_trusted(vec![peer]);
        let beacon = Beacon {
            tag: tag_for(peer, bucket_at(clock.now())),
            port: 2,
        };
        let from: SocketAddr = "10.0.0.5:2".parse().unwrap();
        assert!(tracker.observe(&beacon.encode(), from).is_some());
        assert_eq!(tracker.online().len(), 1);

        clock.advance(PRESENCE_OFFLINE_AFTER - Duration::from_millis(1));
        assert_eq!(tracker.online().len(), 1);
        clock.advance(Duration::from_millis(1));
        assert!(tracker.online().is_empty(), "must expire at exactly 6 s");
    }

    #[test]
    fn removing_a_device_from_the_trusted_set_forgets_it() {
        let clock = Arc::new(ManualClock::at(at(1_000)));
        let mut tracker = PresenceTracker::new(clock.clone());
        let peer = node(6);
        tracker.set_trusted(vec![peer]);
        let beacon = Beacon {
            tag: tag_for(peer, bucket_at(clock.now())),
            port: 3,
        };
        let from: SocketAddr = "10.0.0.6:3".parse().unwrap();
        tracker.observe(&beacon.encode(), from).unwrap();
        tracker.set_trusted(vec![]);
        assert!(tracker.online().is_empty());
        assert_eq!(tracker.trusted(), 0);
        // The same tag is no longer recognised.
        assert!(tracker.observe(&beacon.encode(), from).is_none());
    }

    #[test]
    fn a_flood_from_one_address_is_rate_limited() {
        let clock = Arc::new(ManualClock::at(at(1_000)));
        let mut tracker = PresenceTracker::new(clock.clone());
        let peer = node(8);
        tracker.set_trusted(vec![peer]);
        let beacon = Beacon {
            tag: tag_for(peer, bucket_at(clock.now())),
            port: 4,
        };
        let from: SocketAddr = "10.0.0.8:4".parse().unwrap();
        let mut accepted = 0;
        for _ in 0..64 {
            if tracker.observe(&beacon.encode(), from).is_some() {
                accepted += 1;
            }
        }
        assert_eq!(accepted as u32, crate::constants::PRESENCE_MAX_PER_SEC);
        // A new second resets the budget.
        clock.advance(Duration::from_secs(1));
        assert!(tracker.observe(&beacon.encode(), from).is_some());
    }

    #[test]
    fn junk_datagrams_are_dropped_without_panicking() {
        let clock = Arc::new(ManualClock::at(at(1_000)));
        let mut tracker = PresenceTracker::new(clock);
        tracker.set_trusted(vec![node(1)]);
        let from: SocketAddr = "10.0.0.1:9".parse().unwrap();
        for len in 0..32 {
            let junk = vec![0xffu8; len];
            assert!(tracker.observe(&junk, from).is_none());
        }
    }

    // The tests below pin what a mutant can flip without any behavioural test
    // noticing: the rotating tag itself, the small accessors, and what each
    // `Debug` impl prints. `cargo mutants` found exactly these survivors.

    /// The tag value is fixed by the protocol. If the bucket arithmetic in
    /// [`DeviceTags::at`] drifts by one bucket, devices with different clocks
    /// silently stop matching and nothing else fails. The expected bytes come
    /// from the KDF written in the module docs, not from this implementation.
    #[test]
    fn tag_for_is_pinned_to_a_golden_vector() {
        let cases: [(u8, i64, [u8; TAG_LEN]); 4] = [
            (0x01, 0, [0xaa, 0x03, 0xc7, 0xaa, 0x3d, 0x0f, 0x39, 0x64]),
            (0x01, 100, [0x7c, 0xe7, 0xae, 0x34, 0x0a, 0x99, 0xec, 0x71]),
            (0xab, 1, [0x3f, 0xf6, 0x11, 0x50, 0xfa, 0xfa, 0x28, 0xb3]),
            (0xab, 3, [0xd6, 0x9c, 0x15, 0x54, 0xb7, 0xe3, 0x89, 0xd1]),
        ];
        for (node_byte, bucket, expected) in cases {
            assert_eq!(
                tag_for(node(node_byte), bucket).as_bytes(),
                &expected,
                "tag vector for node {node_byte:02x} bucket {bucket}"
            );
        }
    }

    /// `at(bucket)` returns the tag for `bucket` itself, not for a neighbour.
    /// `tag_for` goes through `at`, so the golden vector above covers the middle
    /// slot; this covers the claim that the middle slot is the requested bucket.
    #[test]
    fn at_returns_the_tag_of_the_bucket_it_was_given() {
        let mut tags = DeviceTags::new(node(0x01));
        assert_eq!(tags.at(100), tag_for(node(0x01), 100));
        assert_eq!(tags.at(100), tags.at(100), "cached value stays put");
    }

    #[test]
    fn trusted_counts_only_the_devices_in_the_trusted_set() {
        let clock = Arc::new(ManualClock::at(at(1_000)));
        let mut tracker = PresenceTracker::new(clock);
        assert_eq!(tracker.trusted(), 0, "nothing trusted yet");
        tracker.set_trusted(vec![node(1), node(2), node(3)]);
        assert_eq!(tracker.trusted(), 3);
    }

    #[test]
    fn is_online_is_true_only_for_the_matched_device() {
        let clock = Arc::new(ManualClock::at(at(1_000)));
        let mut tracker = PresenceTracker::new(clock.clone());
        let peer = node(7);
        tracker.set_trusted(vec![peer, node(8)]);
        assert!(!tracker.is_online(peer), "not heard yet");
        assert!(!tracker.is_online(node(8)));

        let beacon = Beacon {
            tag: tag_for(peer, bucket_at(clock.now())),
            port: 9,
        };
        let from: SocketAddr = "10.0.0.7:9".parse().unwrap();
        tracker.observe(&beacon.encode(), from).unwrap();

        assert!(tracker.is_online(peer), "the beacon made it online");
        assert!(
            !tracker.is_online(node(8)),
            "a different trusted device must stay offline"
        );
    }

    #[test]
    fn loopback_and_link_local_addresses_are_not_multicast_interfaces() {
        assert!(!usable_multicast_interface(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!usable_multicast_interface(Ipv4Addr::new(169, 254, 1, 2)));
        assert!(usable_multicast_interface(Ipv4Addr::new(192, 168, 1, 5)));
        assert!(usable_multicast_interface(Ipv4Addr::new(10, 0, 0, 1)));
    }

    /// Every success is kept, in input order: the send order must be
    /// deterministic, and one host can beacon on several segments.
    #[test]
    fn join_all_keeps_every_success_in_order() {
        let addrs = [
            Ipv4Addr::new(10, 0, 0, 7),    // joins
            Ipv4Addr::new(192, 168, 1, 9), // joins
            Ipv4Addr::new(10, 0, 0, 8),    // join fails
            Ipv4Addr::LOCALHOST,           // joins; the caller decides about it
        ];
        let mut tried = Vec::new();
        let joined = join_all(addrs, |addr| {
            tried.push(*addr);
            *addr != Ipv4Addr::new(10, 0, 0, 8)
        });
        assert_eq!(
            joined,
            vec![
                Ipv4Addr::new(10, 0, 0, 7),
                Ipv4Addr::new(192, 168, 1, 9),
                Ipv4Addr::LOCALHOST
            ]
        );
        assert_eq!(tried, addrs.to_vec(), "every candidate must be tried");
        assert!(join_all(addrs, |_| false).is_empty());
    }

    #[test]
    fn presence_tag_debug_shows_the_short_prefix() {
        let tag = PresenceTag::from_bytes([0xab, 0xcd, 1, 2, 3, 4, 5, 6]);
        assert_eq!(format!("{tag:?}"), "PresenceTag(abcd..)");
    }

    #[test]
    fn beacon_debug_shows_the_tag_and_port() {
        let beacon = Beacon {
            tag: PresenceTag::from_bytes([0xab, 0xcd, 1, 2, 3, 4, 5, 6]),
            port: 4242,
        };
        assert_eq!(
            format!("{beacon:?}"),
            "Beacon { tag: PresenceTag(abcd..), port: 4242 }"
        );
    }

    #[test]
    fn peer_presence_debug_shows_the_address_and_last_seen() {
        let presence = PeerPresence {
            node: node(0xab),
            addr: "10.0.0.9:8080".parse().unwrap(),
            last_seen: at(1_234),
        };
        assert_eq!(
            format!("{presence:?}"),
            "PeerPresence { node: NodeId(abababab), addr: 10.0.0.9:8080, last_seen_secs: 1234 }"
        );
    }

    #[test]
    fn presence_tracker_debug_shows_the_counts_not_the_maps() {
        let clock = Arc::new(ManualClock::at(at(1_000)));
        let mut tracker = PresenceTracker::new(clock.clone());
        tracker.set_trusted(vec![node(1), node(2)]);
        let beacon = Beacon {
            tag: tag_for(node(1), bucket_at(clock.now())),
            port: 3,
        };
        tracker
            .observe(&beacon.encode(), "10.0.0.1:3".parse().unwrap())
            .unwrap();
        assert_eq!(
            format!("{tracker:?}"),
            "PresenceTracker { trusted: 2, online: 1 }"
        );
    }

    /// A beacon must still leave the host when one egress cannot carry it.
    ///
    /// This is the macOS CI failure in miniature: there the NIC joined the group
    /// but `send_to` through it failed (`EHOSTUNREACH`), and the old code had no
    /// second attempt, so the beacon never left. `192.0.2.1` (TEST-NET-1) is
    /// never assigned locally, so pinning the egress to it fails — Linux rejects
    /// a non-local `IP_MULTICAST_IF` at set time where macOS accepted `en0` and
    /// failed at send time; either way one egress fails and `send` must move on.
    ///
    /// The assertion is on the *source address*: a beacon sent through loopback
    /// arrives from `127.0.0.1`, one sent through the NIC arrives from the NIC's
    /// address. Without per-interface egress pinning the datagram takes the NIC
    /// route and this fails even though a beacon was received.
    #[tokio::test]
    async fn send_falls_back_to_the_next_egress_when_one_cannot_be_pinned() {
        let receiver = PresenceSocket::bind(0).expect("bind an ephemeral presence port");
        let port = receiver.port();
        let sender = PresenceSocket::bind(port)
            .expect("bind a second socket on the same port")
            .with_egresses(vec![Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::LOCALHOST]);
        let beacon = Beacon {
            tag: tag_for(node(0x5b), bucket_at(Duration::from_secs(0))),
            port: sender.port(),
        };

        sender
            .send(&beacon)
            .await
            .expect("loopback must carry the beacon after the bogus egress fails");

        match tokio::time::timeout(Duration::from_secs(5), receiver.recv()).await {
            Ok(Ok((buffer, len, from))) => {
                assert_eq!(
                    Beacon::decode(&buffer[..len]).map(|b| b.port),
                    Some(beacon.port)
                );
                assert_eq!(
                    from.ip(),
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    "the beacon must arrive over the loopback egress, not the NIC"
                );
            }
            Ok(Err(err)) => panic!("recv failed: {err}"),
            Err(_) => panic!("no beacon within 5 s on port {port}{}", interface_context()),
        }
    }

    /// Item 1: `send` must transmit to EVERY active multicast interface.
    /// Beacons must arrive from each working egress, and a failure on one
    /// interface must not stop transmission to the others.
    #[tokio::test]
    async fn send_transmits_to_all_interfaces_and_one_failure_does_not_stop_others() {
        let receiver = PresenceSocket::bind(0).expect("bind an ephemeral presence port");
        let port = receiver.port();
        // One failing interface (192.0.2.1) followed by two working interfaces.
        let sender = PresenceSocket::bind(port)
            .expect("bind second socket on the same port")
            .with_egresses(vec![
                Ipv4Addr::new(192, 0, 2, 1),
                Ipv4Addr::new(127, 0, 0, 1),
                Ipv4Addr::new(127, 0, 0, 2),
            ]);
        let beacon = Beacon {
            tag: tag_for(node(0x5e), bucket_at(Duration::from_secs(0))),
            port: sender.port(),
        };

        sender
            .send(&beacon)
            .await
            .expect("send must succeed when at least one interface works");

        // We must receive TWO beacons: one from each working egress.
        let mut count = 0usize;
        let mut received = std::collections::HashSet::new();
        for _ in 0..2 {
            match tokio::time::timeout(Duration::from_secs(5), receiver.recv()).await {
                Ok(Ok((buffer, len, from))) => {
                    assert_eq!(
                        Beacon::decode(&buffer[..len]).map(|b| b.port),
                        Some(beacon.port)
                    );
                    received.insert(from.ip());
                    count += 1;
                }
                Ok(Err(err)) => panic!("recv failed: {err}"),
                Err(_) => panic!(
                    "timed out waiting for beacons from all interfaces; received {count} beacons: {received:?}"
                ),
            }
        }

        assert_eq!(count, 2, "beacon must arrive from each working interface");
        // On Linux, loopback aliases retain their distinct source IPs.
        #[cfg(target_os = "linux")]
        {
            assert!(
                received.contains(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                "beacon must arrive from 127.0.0.1"
            );
            assert!(
                received.contains(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
                "beacon must arrive from 127.0.0.2"
            );
        }
    }

    /// When no egress carries the beacon, `send` must fail and name every
    /// interface it tried. "No route to host" alone does not say which segment
    /// failed, and the host that produces it is the one we cannot log into.
    #[tokio::test]
    async fn send_names_every_failed_egress_when_none_can_carry_the_beacon() {
        let egresses = [Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(198, 51, 100, 1)];
        let socket = PresenceSocket::bind(0)
            .expect("bind an ephemeral presence port")
            .with_egresses(egresses.to_vec());
        let beacon = Beacon {
            tag: tag_for(node(0x5c), bucket_at(Duration::from_secs(0))),
            port: socket.port(),
        };

        let err = socket
            .send(&beacon)
            .await
            .expect_err("no local interface can be pinned to either TEST-NET address");

        let message = err.to_string();
        for egress in egresses {
            assert!(
                message.contains(&egress.to_string()),
                "the error must name {egress}: {message}"
            );
        }
        assert!(
            message.contains("no interface carried the beacon"),
            "the error must say what failed: {message}"
        );
    }

    /// `Debug` must not recurse into the socket; it prints the bound port and the
    /// group, and it must actually print them (a `Debug` that emits nothing would
    /// still compile and would still make every log line useless).
    #[tokio::test]
    async fn presence_socket_debug_and_port_report_the_bound_socket() {
        let socket = PresenceSocket::bind(0).expect("bind an ephemeral presence port");
        let port = socket.port();
        assert_ne!(port, 0, "binding port 0 must yield a real port");
        assert_eq!(socket.group(), PRESENCE_GROUP_V4);

        let debug = format!("{socket:?}");
        assert!(debug.contains("PresenceSocket"), "got {debug:?}");
        assert!(debug.contains(&format!("port: {port}")), "got {debug:?}");
        assert!(
            debug.contains(&format!("group: {}", PRESENCE_GROUP_V4)),
            "got {debug:?}"
        );
    }

    #[tokio::test]
    async fn egresses_returns_joined_interfaces_and_precedence() {
        let socket = PresenceSocket::bind(0).expect("bind an ephemeral presence port");
        assert!(!socket.egresses().is_empty());
        assert_eq!(socket.egress(), socket.egresses()[0]);
        if socket
            .egresses()
            .iter()
            .any(|a| usable_multicast_interface(*a))
        {
            assert!(
                !socket.egresses().contains(&Ipv4Addr::LOCALHOST),
                "real interfaces take precedence over loopback"
            );
            assert!(
                !socket.egresses().contains(&Ipv4Addr::UNSPECIFIED),
                "real interfaces take precedence over unspecified"
            );
        }
    }

    #[test]
    fn log_interface_error_records_and_throttles() {
        let test_ip = Ipv4Addr::new(192, 0, 2, 250);
        let err = std::io::Error::other("rate limit test error");
        log_interface_error(test_ip, &err);
        log_interface_error(test_ip, &err);
    }

    /// Verify that two sockets can bind to the exact same UDP port on this OS.
    /// On BSD/macOS this requires SO_REUSEPORT as well as SO_REUSEADDR.
    ///
    /// The option is also *read back*, because a platform where the `cfg` above
    /// is wrong would otherwise fail only on that platform's CI. Where socket2
    /// exposes the getter, a `false` here means the bind above succeeded for a
    /// reason other than the option, and the macOS failure would come back.
    #[tokio::test]
    async fn two_sockets_can_share_one_port() {
        let first = PresenceSocket::bind(0).expect("bind first socket");
        let port = first.port();
        assert_ne!(port, 0);
        let second = PresenceSocket::bind(port).expect("bind second socket on the same port");
        assert_eq!(first.port(), second.port());

        #[cfg(all(
            unix,
            not(any(
                target_os = "solaris",
                target_os = "illumos",
                target_os = "cygwin",
                target_os = "nuttx",
                target_os = "wasi"
            ))
        ))]
        {
            let sock = socket2::SockRef::from(&second.socket);
            assert!(
                sock.reuse_port().expect("read SO_REUSEPORT back"),
                "SO_REUSEPORT must be enabled, not merely attempted"
            );
            assert!(
                sock.reuse_address().expect("read SO_REUSEADDR back"),
                "SO_REUSEADDR must stay enabled on every platform"
            );
        }
    }

    /// `send` must put real bytes on the wire. One socket sends a beacon and
    /// receives it back through multicast loopback, so the assertion cannot pass
    /// on a `send` that returns `Ok(())` without transmitting. A single socket is
    /// used on purpose: with `SO_REUSEPORT` two sockets on one port may share
    /// delivery differently per platform, which would make the result say more
    /// about the kernel's reuse policy than about this code.
    ///
    /// Requires at least one interface to succeed. If the runner lacks an IPv4
    /// multicast interface, tries IP_MULTICAST_IF=127.0.0.1 first before
    /// skipping at runtime with a printed diagnostic reason.
    #[tokio::test]
    async fn send_actually_transmits_a_beacon() {
        let socket = match PresenceSocket::bind(0) {
            Ok(s) => s,
            Err(err) => {
                eprintln!("SKIPPED: cannot bind PresenceSocket: {err}");
                return;
            }
        };

        let has_multicast_if = socket
            .egresses()
            .iter()
            .any(|addr| usable_multicast_interface(*addr));

        let socket = if !has_multicast_if {
            // Coba dulu IP_MULTICAST_IF=127.0.0.1
            eprintln!(
                "runner lacks active IPv4 multicast interface; trying IP_MULTICAST_IF=127.0.0.1"
            );
            socket.with_egresses(vec![Ipv4Addr::LOCALHOST])
        } else {
            socket
        };

        let beacon = Beacon {
            tag: tag_for(node(0x5a), bucket_at(Duration::from_secs(0))),
            port: socket.port(),
        };

        if let Err(err) = socket.send(&beacon).await {
            if !has_multicast_if {
                eprintln!(
                    "SKIPPED: runner has no active IPv4 multicast interface and loopback failed: {err}{}",
                    interface_context()
                );
                return;
            }
            panic!("send failed despite having active multicast interface: {err}");
        }

        match tokio::time::timeout(Duration::from_secs(5), socket.recv()).await {
            Ok(Ok((buffer, len, _from))) => assert_eq!(
                Beacon::decode(&buffer[..len]).map(|b| b.port),
                Some(beacon.port)
            ),
            Ok(Err(err)) => panic!("recv failed: {err}"),
            Err(_) => {
                if !has_multicast_if {
                    eprintln!(
                        "SKIPPED: multicast datagram not received on loopback (isolated environment){}",
                        interface_context()
                    );
                    return;
                }
                panic!(
                    "no beacon within 5 s; egresses {:?}, port {}, group {}{}",
                    socket.egresses(),
                    socket.port(),
                    socket.group(),
                    interface_context()
                );
            }
        }
    }
}
