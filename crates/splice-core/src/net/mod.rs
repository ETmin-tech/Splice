//! Transport boundary (§6, §7.1).
//!
//! Everything above this module speaks [`Transport`] and [`Connection`]; only
//! [`iroh_impl`] mentions iroh. That keeps the S1 decision reversible: a different
//! QUIC stack would be a new module, not a rewrite.
//!
//! Three things are deliberately *not* hidden here: the peer [`NodeId`] (authenticated
//! by TLS, never by application data), the negotiated ALPN, and the path kind
//! (direct or relay), because the UI has to tell the user which path is in use.

mod iroh_impl;

pub use iroh_impl::REQUIRED_ALPN;
pub mod memory;

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{NetError, Result};
use crate::identity::{NodeId, NodeSecret};

/// A boxed future used by the object-safe transport traits.
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Bytes going to the peer. `poll_shutdown` finishes the QUIC stream.
pub type SendStream = Box<dyn AsyncWrite + Send + Unpin>;
/// Bytes coming from the peer.
pub type RecvStream = Box<dyn AsyncRead + Send + Unpin>;

/// Which kind of path a connection currently uses (§6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    /// Direct UDP path, the only one that works with no internet.
    Direct,
    /// Third-party relay. Encrypted end to end; the relay sees addresses and sizes.
    Relay,
    /// The transport did not report a path (in-memory fake, or a stack without paths).
    Unknown,
}

impl PathKind {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Relay => "relay",
            Self::Unknown => "unknown",
        }
    }
}

/// How to treat relays. Mirrors the CLI `--relay-mode` / `--relay-url` flags.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum RelaySetting {
    /// No relay transport at all: LAN-only, works offline.
    Disabled,
    /// iroh's default third-party relays.
    #[default]
    Default,
    /// A single user-supplied relay URL.
    Custom(String),
}

impl RelaySetting {
    /// Parse the CLI value: `default` or `disabled`.
    pub fn parse_mode(value: &str) -> Result<Self> {
        match value {
            "default" => Ok(Self::Default),
            "disabled" => Ok(Self::Disabled),
            other => Err(NetError::Transport(format!(
                "unknown relay mode {other:?}; expected default or disabled"
            ))
            .into()),
        }
    }

    pub const fn name(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Default => "default",
            Self::Custom(_) => "custom",
        }
    }
}

/// Everything needed to build an endpoint.
#[derive(Debug)]
pub struct EndpointConfig {
    /// Persistent or ephemeral key; the caller decides (§5.1).
    pub secret: NodeSecret,
    pub relay: RelaySetting,
    /// Extra UDP bind address. `None` binds the transport defaults.
    pub bind: Option<SocketAddr>,
    /// ALPNs to advertise. Always contains [`crate::constants::ALPN`] in practice.
    pub alpns: Vec<Vec<u8>>,
}

impl EndpointConfig {
    /// A LAN-only endpoint that advertises only the splice ALPN.
    pub fn lan_only(secret: NodeSecret) -> Self {
        Self {
            secret,
            relay: RelaySetting::Disabled,
            bind: None,
            alpns: vec![crate::constants::ALPN.to_vec()],
        }
    }
}

/// A peer address: the identity we authenticate, plus hints for reaching it.
///
/// Hints are untrusted. TLS decides whether the peer really is [`NodeId`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeAddr {
    id: NodeId,
    ip_addrs: Vec<SocketAddr>,
    relay: Option<String>,
}

impl NodeAddr {
    pub fn new(id: NodeId) -> Self {
        Self {
            id,
            ip_addrs: Vec::new(),
            relay: None,
        }
    }

    /// A direct address hint only.
    pub fn direct(id: NodeId, addr: SocketAddr) -> Self {
        Self::new(id).with_ip(addr)
    }

    pub fn with_ip(mut self, addr: SocketAddr) -> Self {
        if !self.ip_addrs.contains(&addr) {
            self.ip_addrs.push(addr);
        }
        self
    }

    pub fn with_relay(mut self, relay: impl Into<String>) -> Self {
        self.relay = Some(relay.into());
        self
    }

    pub const fn id(&self) -> NodeId {
        self.id
    }

    pub fn ip_addrs(&self) -> &[SocketAddr] {
        &self.ip_addrs
    }

    pub fn relay(&self) -> Option<&str> {
        self.relay.as_deref()
    }

    /// Whether any transport hint at all is present. Dialing by bare NodeId only
    /// works with an address-lookup service, which this build does not use.
    pub fn has_hint(&self) -> bool {
        !self.ip_addrs.is_empty() || self.relay.is_some()
    }
}

/// One accepted or dialed connection.
///
/// Object-safe on purpose: [`Transport`] hands back `Arc<dyn Connection>` so the
/// pairing state machine and the listener can share one connection without
/// generics spreading through the crate.
pub trait Connection: Send + Sync {
    /// The peer identity, as authenticated by the transport handshake.
    fn remote_id(&self) -> NodeId;

    /// The negotiated ALPN. A peer that picked anything else is a bug.
    fn alpn(&self) -> Vec<u8>;

    /// Current path kind, best effort (§6).
    fn path_kind(&self) -> PathKind;

    /// Round-trip time of the selected path, if the transport reports one.
    fn rtt(&self) -> Option<std::time::Duration>;

    /// Open a bidirectional stream. The caller writes the stream type byte first.
    fn open_bi(&self) -> BoxFuture<Result<(SendStream, RecvStream)>>;

    /// Accept a bidirectional stream opened by the peer.
    fn accept_bi(&self) -> BoxFuture<Result<(SendStream, RecvStream)>>;

    /// Start a graceful close. Idempotent.
    fn close(&self, code: u32, reason: &'static [u8]);

    /// Resolve when the connection is gone, for any reason.
    fn closed(&self) -> BoxFuture<()>;
}

/// A bound endpoint: accept, dial, and report our own identity.
pub trait Transport: Send + Sync {
    /// Our [`NodeId`]. Public key, safe to log.
    fn node_id(&self) -> NodeId;

    /// Addresses we are listening on. Unspecified (`0.0.0.0`) entries are not
    /// dialable and are filtered out by the caller that needs them.
    fn local_addrs(&self) -> Vec<SocketAddr>;

    /// Dial a peer. Fails fast when the transport has no way to reach it.
    fn connect(&self, addr: NodeAddr, alpn: &[u8]) -> BoxFuture<Result<Arc<dyn Connection>>>;

    /// Accept the next incoming connection. `Ok(None)` means the endpoint closed.
    fn accept(&self) -> BoxFuture<Result<Option<Arc<dyn Connection>>>>;

    /// Close the endpoint and all its connections.
    fn close(&self) -> BoxFuture<()>;
}

/// Bind a real (iroh-backed) endpoint.
pub async fn bind(config: EndpointConfig) -> Result<Arc<dyn Transport>> {
    iroh_impl::bind(config).await
}

/// Reject a peer that negotiated something other than the recorded ALPN.
pub fn expect_alpn(conn: &dyn Connection, expected: &[u8]) -> Result<()> {
    if conn.alpn() != expected {
        return Err(NetError::Rejected(format!(
            "peer negotiated ALPN {:?}, expected {:?}",
            String::from_utf8_lossy(&conn.alpn()),
            String::from_utf8_lossy(expected)
        ))
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_addr_dedupes_and_reports_hints() {
        let id = NodeSecret::generate().public();
        let addr: SocketAddr = "10.0.0.5:4242".parse().unwrap();
        let target = NodeAddr::new(id).with_ip(addr).with_ip(addr);
        assert_eq!(target.ip_addrs(), &[addr]);
        assert!(target.has_hint());
        assert!(!NodeAddr::new(id).has_hint());
    }

    #[test]
    fn relay_mode_parsing_is_strict() {
        assert_eq!(
            RelaySetting::parse_mode("disabled").unwrap(),
            RelaySetting::Disabled
        );
        assert!(RelaySetting::parse_mode("Disabled").is_err());
        assert!(RelaySetting::parse_mode("").is_err());
    }
}
