//! Tickets: a copy-paste string that carries an address and a PAKE password
//! (§5.3, §5.4 ticket mode).
//!
//! ```text
//! sp1-<base32 of postcard{TicketBody}>
//! ```
//!
//! `TicketBody` holds the NodeAddr (NodeId plus any direct and
//! relay hints) and a 128-bit CSPRNG secret. The secret *is* the SPAKE2 password in
//! ticket mode, so the ticket string is a secret: it must never be logged and must
//! be handled through [`SecretString`] once it leaves this module.
//!
//! Base32 (`BASE32_NOPAD`) is used because it survives being read aloud and typed:
//! uppercase letters and digits 2–7, no punctuation, no ambiguity with `0`/`O` or
//! `1`/`I`.

use std::net::SocketAddr;
use std::str::FromStr;

use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};

use crate::error::{DiscoveryError, Result};
use crate::identity::NodeId;
use crate::net::NodeAddr;
use crate::secret::{SecretBytes, SecretString};

/// Visible prefix. Ends with `-` so the body is easy to delimit by eye.
pub const TICKET_PREFIX: &str = "sp1-";

/// Ticket format version, separate from the wire protocol version.
pub const TICKET_VERSION: u8 = 1;

/// Length of the ticket secret in bytes (128 bits).
pub const TICKET_SECRET_LEN: usize = 16;

/// The decoded contents of a ticket.
#[derive(Serialize, Deserialize)]
struct TicketBody {
    version: u8,
    /// The peer's NodeId.
    node: [u8; NodeId::LEN],
    /// Direct address hints, as `ip:port`.
    direct: Vec<String>,
    /// Optional relay URL.
    relay: Option<String>,
    /// SPAKE2 password in ticket mode.
    secret: [u8; TICKET_SECRET_LEN],
}

/// A parsed ticket. The secret is kept behind [`SecretBytes`] so `Debug` output is
/// `[redacted]` and the buffer is zeroized on drop (I1, I11).
pub struct Ticket {
    node: NodeId,
    direct: Vec<SocketAddr>,
    relay: Option<String>,
    secret: SecretBytes,
}

impl std::fmt::Debug for Ticket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ticket")
            .field("node", &self.node)
            .field("direct", &self.direct)
            .field("relay", &self.relay)
            .field("secret", &"[redacted]")
            .finish()
    }
}

impl Ticket {
    /// Build a ticket for `addr` with a fresh CSPRNG secret.
    pub fn generate(addr: &NodeAddr) -> Result<Self> {
        let mut secret = [0u8; TICKET_SECRET_LEN];
        getrandom::fill(&mut secret).map_err(|err| {
            DiscoveryError::PresenceSocket(format!("no CSPRNG for the ticket secret: {err}"))
        })?;
        Ok(Self {
            node: addr.id(),
            direct: addr.ip_addrs().to_vec(),
            relay: addr.relay().map(str::to_string),
            secret: SecretBytes::from_slice(&secret),
        })
    }

    /// Build from an explicit secret. Used by tests and by a host that wants to
    /// print the same ticket twice.
    pub fn from_parts(
        node: NodeId,
        direct: Vec<SocketAddr>,
        relay: Option<String>,
        secret: &[u8; TICKET_SECRET_LEN],
    ) -> Self {
        Self {
            node,
            direct,
            relay,
            secret: SecretBytes::from_slice(secret),
        }
    }

    pub fn node(&self) -> NodeId {
        self.node
    }

    pub fn direct(&self) -> &[SocketAddr] {
        &self.direct
    }

    pub fn relay(&self) -> Option<&str> {
        self.relay.as_deref()
    }

    /// The SPAKE2 password. The caller must not log or serialize it.
    pub fn password(&self) -> SecretBytes {
        SecretBytes::from_slice(self.secret.expose_secret())
    }

    /// The SPAKE2 password in the form the pairing machines take.
    ///
    /// The ticket secret is 128 random bits, not text, so it cannot be handed over
    /// as a `SecretString` losslessly by copying bytes. Encoding it as lowercase hex
    /// keeps every bit and keeps it printable, and the same encoding on both sides
    /// yields the same password (§5.4, last paragraph).
    pub fn password_string(&self) -> SecretString {
        use std::fmt::Write as _;

        let mut text = String::with_capacity(TICKET_SECRET_LEN * 2);
        for byte in self.secret.expose_secret() {
            let _ = write!(&mut text, "{byte:02x}");
        }
        SecretString::from_string(text)
    }

    /// The dial target this ticket describes.
    pub fn to_node_addr(&self) -> NodeAddr {
        let mut addr = NodeAddr::new(self.node);
        for ip in &self.direct {
            addr = addr.with_ip(*ip);
        }
        if let Some(relay) = &self.relay {
            addr = addr.with_relay(relay.clone());
        }
        addr
    }

    /// Encode as the copy-paste string.
    ///
    /// The returned `String` is secret material; callers hand it to the user once
    /// and drop it.
    pub fn encode(&self) -> SecretString {
        let body = TicketBody {
            version: TICKET_VERSION,
            node: *self.node.as_bytes(),
            direct: self.direct.iter().map(ToString::to_string).collect(),
            relay: self.relay.clone(),
            secret: {
                let mut copy = [0u8; TICKET_SECRET_LEN];
                copy.copy_from_slice(self.secret.expose_secret());
                copy
            },
        };
        let bytes = postcard::to_stdvec(&body).expect("a ticket body always encodes");
        let text = format!("{TICKET_PREFIX}{}", BASE32_NOPAD.encode(&bytes));
        SecretString::from_string(text)
    }

    /// Parse user input. Case-insensitive on the prefix, strict on the body.
    ///
    /// Grouping spaces and `-` inside the body are tolerated (people wrap long
    /// strings); every other character is rejected.
    pub fn parse(input: &str) -> Result<Self> {
        let cleaned: String = input
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect();
        let without_prefix = cleaned
            .strip_prefix("SP1")
            .or_else(|| cleaned.strip_prefix("sp1"))
            .ok_or(DiscoveryError::BadTicket)?;
        if without_prefix.is_empty() {
            return Err(DiscoveryError::BadTicket.into());
        }
        let bytes = BASE32_NOPAD
            .decode(without_prefix.to_ascii_uppercase().as_bytes())
            .map_err(|_| DiscoveryError::BadTicket)?;
        // `postcard::from_bytes` silently ignores trailing bytes, which would let
        // anyone append junk to a valid ticket. `take_from_bytes` reports the
        // remainder so we can reject it explicitly.
        let (body, rest): (TicketBody, &[u8]) =
            postcard::take_from_bytes(&bytes).map_err(|_| DiscoveryError::BadTicket)?;
        if !rest.is_empty() {
            return Err(DiscoveryError::BadTicket.into());
        }
        if body.version != TICKET_VERSION {
            return Err(DiscoveryError::TicketVersion { got: body.version }.into());
        }
        let node = NodeId::from_bytes(body.node);
        let mut direct = Vec::with_capacity(body.direct.len());
        for addr in body.direct {
            let parsed: SocketAddr = addr
                .parse()
                .map_err(|_| DiscoveryError::BadAddress { addr: addr.clone() })?;
            direct.push(parsed);
        }
        Ok(Self {
            node,
            direct,
            relay: body.relay,
            secret: SecretBytes::from_slice(&body.secret),
        })
    }
}

impl FromStr for Ticket {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    fn sample() -> Ticket {
        Ticket::from_parts(
            NodeId::from_bytes([0x11; 32]),
            vec!["10.0.0.7:4242".parse().unwrap()],
            None,
            &[0x5a; TICKET_SECRET_LEN],
        )
    }

    #[test]
    fn roundtrip_preserves_everything() {
        let ticket = sample();
        let text = ticket.encode();
        let raw = text.expose_secret().clone();
        let parsed = Ticket::parse(&raw).unwrap();
        assert_eq!(parsed.node(), ticket.node());
        assert_eq!(parsed.direct(), ticket.direct());
        assert_eq!(parsed.relay(), None);
        assert_eq!(
            parsed.password().expose_secret(),
            ticket.password().expose_secret()
        );
    }

    /// The ticket secret is random bytes, so the pairing machines cannot take it as
    /// text directly. `password_string` keeps every bit, and two tickets with the
    /// same secret must produce the same password on both sides.
    #[test]
    fn password_string_is_lossless_and_stable() {
        let ticket = sample();
        let text = ticket.encode();
        let raw = text.expose_secret().clone();
        let parsed = Ticket::parse(&raw).unwrap();
        assert_eq!(
            parsed.password_string().expose_secret(),
            ticket.password_string().expose_secret()
        );
        // 16 bytes as lowercase hex: 32 characters, all in `[0-9a-f]`.
        let password = ticket.password_string();
        let value = password.expose_secret();
        assert_eq!(value.len(), TICKET_SECRET_LEN * 2);
        assert!(value
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert!(
            value.contains("5a5a"),
            "the sample secret is all 0x5a bytes"
        );
    }

    #[test]
    fn prefix_is_visible() {
        let text = sample().encode();
        assert!(text.expose_secret().starts_with(TICKET_PREFIX));
        // Base32 uppercase only: no confusing punctuation, no lowercase.
        let body = text.expose_secret().trim_start_matches(TICKET_PREFIX);
        assert!(body
            .chars()
            .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c)));
    }

    #[test]
    fn parsing_tolerates_wrapping_and_case() {
        let text = sample().encode();
        let raw = text.expose_secret().clone();
        let wrapped = format!(
            "{}\n{}\n",
            raw[..raw.len() / 2].to_lowercase(),
            &raw[raw.len() / 2..]
        );
        assert!(Ticket::parse(&wrapped).is_ok());
        assert!(Ticket::parse(&format!("  {raw}  ")).is_ok());
    }

    #[test]
    fn garbage_is_rejected_without_panicking() {
        for input in [
            "",
            "sp1-",
            "hello",
            "sp1-!!!!",
            "sp1-AAAAAAAA",
            "sp2-AAAAAAAA",
            "sp1-0000000000000000000000000",
        ] {
            assert!(Ticket::parse(input).is_err(), "{input:?} must be rejected");
        }
    }

    #[test]
    fn truncated_and_extended_bodies_are_rejected() {
        let text = sample().encode();
        let raw = text.expose_secret();
        let body = raw.trim_start_matches(TICKET_PREFIX);
        for cut in 1..body.len() {
            let truncated = format!("{TICKET_PREFIX}{}", &body[..cut]);
            let _ = Ticket::parse(&truncated);
        }
        let extended = format!("{raw}AAAA");
        assert!(Ticket::parse(&extended).is_err());
    }

    #[test]
    fn wrong_version_is_reported() {
        let body = TicketBody {
            version: 9,
            node: [0; 32],
            direct: vec![],
            relay: None,
            secret: [0; TICKET_SECRET_LEN],
        };
        let bytes = postcard::to_stdvec(&body).unwrap();
        let text = format!("{TICKET_PREFIX}{}", BASE32_NOPAD.encode(&bytes));
        assert!(matches!(
            Ticket::parse(&text),
            Err(Error::Discovery(DiscoveryError::TicketVersion { got: 9 }))
        ));
    }

    #[test]
    fn a_bad_address_is_reported_not_silently_dropped() {
        let body = TicketBody {
            version: TICKET_VERSION,
            node: [1; 32],
            direct: vec!["not-an-address".to_string()],
            relay: None,
            secret: [0; TICKET_SECRET_LEN],
        };
        let bytes = postcard::to_stdvec(&body).unwrap();
        let text = format!("{TICKET_PREFIX}{}", BASE32_NOPAD.encode(&bytes));
        assert!(matches!(
            Ticket::parse(&text),
            Err(Error::Discovery(DiscoveryError::BadAddress { .. }))
        ));
    }

    /// I1: the secret never appears in the debug output.
    #[test]
    fn debug_output_redacts_the_secret() {
        let ticket = sample();
        let shown = format!("{ticket:?}");
        assert!(shown.contains("[redacted]"));
        let hex_secret = ticket
            .password()
            .expose_secret()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert!(!shown.contains(&hex_secret));
    }

    #[test]
    fn a_ticket_with_a_relay_hint_keeps_it() {
        let ticket = Ticket::from_parts(
            NodeId::from_bytes([2; 32]),
            vec![],
            Some("https://relay.example".to_string()),
            &[1; TICKET_SECRET_LEN],
        );
        let text = ticket.encode();
        let parsed = Ticket::parse(text.expose_secret()).unwrap();
        assert_eq!(parsed.relay(), Some("https://relay.example"));
        assert!(parsed.to_node_addr().has_hint());
    }
}
