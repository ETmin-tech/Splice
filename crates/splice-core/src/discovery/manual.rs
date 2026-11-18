//! Manual address: `--addr` skips every discovery path (§5.3).
//!
//! Two shapes are accepted:
//!
//! * `ip:port` — only a hint. Usable when the peer's [`NodeId`] is already known
//!   from the trust store, because QUIC cannot be dialed without knowing the
//!   server's public key.
//! * `nodeid@ip:port` — id plus hint, which is what a code-mode pairing over
//!   `--addr` needs.
//!
//! The second form is an addition to the architecture text, which only shows
//! `--addr 192.168.x.x:port`. It exists because iroh authenticates the responder
//! by public key: there is no dial-by-IP-without-identity call. The deviation is
//! recorded in `Laporan-1.md` §10 (ambiguities).

use std::net::SocketAddr;

use crate::error::{DiscoveryError, Result};
use crate::identity::NodeId;
use crate::net::NodeAddr;

/// A parsed `--addr` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualTarget {
    pub addr: SocketAddr,
    /// Present when the user supplied `nodeid@ip:port`.
    pub node: Option<NodeId>,
}

impl ManualTarget {
    /// Parse `ip:port` or `nodeid@ip:port`.
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(DiscoveryError::BadAddress {
                addr: input.to_string(),
            }
            .into());
        }
        let (node, address) = match trimmed.split_once('@') {
            Some((id, address)) => {
                let node: NodeId = id.parse().map_err(|_| DiscoveryError::BadAddress {
                    addr: input.to_string(),
                })?;
                (Some(node), address)
            }
            None => (None, trimmed),
        };
        let addr: SocketAddr = address.parse().map_err(|_| DiscoveryError::BadAddress {
            addr: input.to_string(),
        })?;
        if addr.port() == 0 {
            return Err(DiscoveryError::BadAddress {
                addr: input.to_string(),
            }
            .into());
        }
        Ok(Self { addr, node })
    }

    /// Build a dial target. Fails when the id is unknown and no fallback exists.
    pub fn to_node_addr(&self) -> Result<NodeAddr> {
        match self.node {
            Some(node) => Ok(NodeAddr::direct(node, self.addr)),
            None => Err(DiscoveryError::BadAddress {
                addr: self.addr.to_string(),
            }
            .into()),
        }
    }

    /// Build a dial target for a peer whose id is known from elsewhere.
    pub fn with_id(&self, node: NodeId) -> NodeAddr {
        NodeAddr::direct(node, self.addr)
    }
}

impl std::str::FromStr for ManualTarget {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_bare_address() {
        let target = ManualTarget::parse("192.168.1.9:4242").unwrap();
        assert_eq!(target.addr, "192.168.1.9:4242".parse().unwrap());
        assert_eq!(target.node, None);
    }

    #[test]
    fn parses_an_address_with_an_id() {
        let id = NodeId::from_bytes([0x12; 32]);
        let target = ManualTarget::parse(&format!("{id}@192.168.1.9:4242")).unwrap();
        assert_eq!(target.node, Some(id));
        let addr = target.to_node_addr().unwrap();
        assert_eq!(addr.id(), id);
        assert_eq!(addr.ip_addrs(), &["192.168.1.9:4242".parse().unwrap()]);
    }

    #[test]
    fn parses_ipv6() {
        let target = ManualTarget::parse("[fe80::1]:4242").unwrap();
        assert_eq!(target.addr.port(), 4242);
    }

    #[test]
    fn rejects_junk() {
        for input in [
            "",
            "   ",
            "192.168.1.9",
            "192.168.1.9:0",
            "nope:1",
            "@1.2.3.4:5",
        ] {
            assert!(
                ManualTarget::parse(input).is_err(),
                "{input:?} must be rejected"
            );
        }
    }

    #[test]
    fn a_bare_address_cannot_be_dialed_without_an_id() {
        assert!(ManualTarget::parse("10.0.0.1:5")
            .unwrap()
            .to_node_addr()
            .is_err());
    }

    #[test]
    fn a_known_id_completes_the_target() {
        let id = NodeId::from_bytes([3; 32]);
        let addr = ManualTarget::parse("10.0.0.1:5").unwrap().with_id(id);
        assert_eq!(addr.id(), id);
        assert!(addr.has_hint());
    }
}
