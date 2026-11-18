//! Key types: our own `NodeId` / `NodeSecret` around iroh's ed25519 keys.

use std::fmt;
use std::str::FromStr;

use iroh::SecretKey;

use crate::error::{IdentityError, Result};

/// Public node identifier (32 bytes, ed25519 public key).
///
/// Rendered as lowercase hex: 64 characters. `shorthand()` gives the last 8
/// characters, which is what the pairing prompt shows (§5.4 step 9).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId([u8; 32]);

impl NodeId {
    pub const LEN: usize = 32;

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Last 8 hex characters, used in prompts ("id: 1a2b3c4d").
    pub fn shorthand(&self) -> String {
        let mut hex = self.to_string();
        hex.split_off(hex.len() - 8)
    }

    /// First 8 hex characters, for log correlation. Never a secret.
    pub fn prefix8(&self) -> String {
        self.to_string()[..8].to_string()
    }

    pub(crate) fn to_iroh(self) -> iroh::EndpointId {
        iroh::PublicKey::from_bytes(&self.0).expect("NodeId always holds a valid public key")
    }

    pub(crate) fn from_iroh(key: iroh::EndpointId) -> Self {
        Self(*key.as_bytes())
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", self.prefix8())
    }
}

impl FromStr for NodeId {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.len() != 64 {
            return Err(IdentityError::InvalidKey.into());
        }
        let mut out = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let text = std::str::from_utf8(chunk).map_err(|_| IdentityError::InvalidKey)?;
            out[i] = u8::from_str_radix(text, 16).map_err(|_| IdentityError::InvalidKey)?;
        }
        Ok(Self(out))
    }
}

/// Private node key. Redacted in `Debug`, zeroized on drop.
pub struct NodeSecret {
    inner: SecretKey,
}

impl NodeSecret {
    /// Generate from the OS CSPRNG.
    pub fn generate() -> Self {
        Self {
            inner: SecretKey::generate(),
        }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            inner: SecretKey::from_bytes(&bytes),
        }
    }

    /// Raw key bytes. Callers must zeroize their copy (use [`crate::SecretBytes`]).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    pub fn public(&self) -> NodeId {
        NodeId::from_iroh(self.inner.public())
    }

    pub(crate) fn to_iroh(&self) -> SecretKey {
        // iroh's SecretKey is Clone + ZeroizeOnDrop, and the copy handed to the
        // endpoint lives as long as the endpoint does.
        self.inner.clone()
    }
}

// `iroh::SecretKey` is `ZeroizeOnDrop`, so no manual `Drop` is needed here. A
// manual impl would also prevent moving the key out in `to_iroh`.

impl fmt::Debug for NodeSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_is_redacted() {
        let secret = NodeSecret::generate();
        let text = format!("{secret:?}");
        assert_eq!(text, "[redacted]");
        assert!(!text.contains(&secret.public().to_string()));
    }

    #[test]
    fn public_id_is_hex_and_roundtrips() {
        let secret = NodeSecret::generate();
        let id = secret.public();
        let text = id.to_string();
        assert_eq!(text.len(), 64);
        assert!(text.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(NodeId::from_str(&text).unwrap(), id);
        assert_eq!(id.shorthand(), &text[56..]);
    }

    #[test]
    fn key_bytes_roundtrip_is_stable() {
        let secret = NodeSecret::generate();
        let bytes = secret.to_bytes();
        let restored = NodeSecret::from_bytes(bytes);
        assert_eq!(secret.public(), restored.public());
    }

    #[test]
    fn distinct_keys_produce_distinct_ids() {
        let a = NodeSecret::generate();
        let b = NodeSecret::generate();
        assert_ne!(a.public(), b.public());
    }

    #[test]
    fn bad_node_id_is_rejected() {
        assert!(NodeId::from_str("nothex").is_err());
        assert!(NodeId::from_str(&"z".repeat(64)).is_err());
    }
}