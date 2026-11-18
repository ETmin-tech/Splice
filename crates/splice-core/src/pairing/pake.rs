//! SPAKE2 wrapper (§5.4 step 5).
//!
//! This is the only file that mentions the `spake2` crate. Everything above it
//! passes a password in and gets a session key out.
//!
//! Roles are fixed by the architecture: the **guest** is side A and the **host** is
//! side B, and both identities are `NodeId`s. The identity binding matters: SPAKE2
//! hashes `id_a` and `id_b` into the final key, so a relay that swaps in its own
//! `NodeId` derives a different key and cannot forge the confirmation MAC.
//!
//! ### What is *not* zeroized
//!
//! `spake2` 0.4.0 keeps its own copies of the password (a `Vec<u8>` and a scalar)
//! inside the state object, and offers no way to clear them: the crate is `no_std`
//! and has no `zeroize` dependency. Our copy is a [`SecretString`] that clears on
//! drop, and the key we return clears on drop, but the crate's internal copy is
//! freed by the allocator without being overwritten. This limit is recorded in
//! `Laporan-1.md` §11 (I11) rather than papered over.

use std::fmt;

use spake2::{Ed25519Group, Identity, Password, Spake2};

use crate::error::{PairingError, Result};
use crate::identity::NodeId;
use crate::secret::{Secret, SecretString};

/// Length of a SPAKE2 public share: a one-byte side tag plus a compressed point.
///
/// Fixed by the group (Edwards25519), so it is checked before the crate sees the
/// message and we never do work on a peer's arbitrary buffer.
pub const PAKE_MSG_LEN: usize = 1 + 32;

/// Side tag bytes the crate emits. We check them ourselves so the error is ours.
const SIDE_A: u8 = 0x41; // 'A', guest
const SIDE_B: u8 = 0x42; // 'B', host

/// Which side of the exchange this party plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Code holder's counterpart: side A in SPAKE2.
    Guest,
    /// Code holder: side B in SPAKE2.
    Host,
}

impl Role {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Guest => "guest",
            Self::Host => "host",
        }
    }

    const fn side_tag(self) -> u8 {
        match self {
            Self::Guest => SIDE_A,
            Self::Host => SIDE_B,
        }
    }

    /// The side tag we expect to *receive*.
    const fn peer_side_tag(self) -> u8 {
        match self {
            Self::Guest => SIDE_B,
            Self::Host => SIDE_A,
        }
    }
}

/// A SPAKE2 exchange in progress. Never prints the password or the key.
pub struct PakeState {
    inner: Spake2<Ed25519Group>,
    role: Role,
}

impl fmt::Debug for PakeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `Spake2` holds `PartialEq`, not `Debug`, and must not be dumped anyway.
        f.debug_struct("PakeState")
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

impl PakeState {
    /// Begin an exchange. Returns the state and the bytes to send to the peer.
    ///
    /// `password` is the lowercase word list joined by `-` (code mode) or the
    /// ticket secret (ticket mode). It is copied into the crate's own buffer and
    /// the local `Password` is dropped immediately.
    pub fn start(
        role: Role,
        password: &SecretString,
        guest: NodeId,
        host: NodeId,
    ) -> (Self, Vec<u8>) {
        let id_a = Identity::new(guest.as_bytes());
        let id_b = Identity::new(host.as_bytes());
        let pake_password = Password::new(password.expose_secret());
        let (inner, outbound) = match role {
            Role::Guest => Spake2::<Ed25519Group>::start_a(&pake_password, &id_a, &id_b),
            Role::Host => Spake2::<Ed25519Group>::start_b(&pake_password, &id_a, &id_b),
        };
        drop(pake_password);
        (Self { inner, role }, outbound)
    }

    /// Validate a public share without doing any group arithmetic.
    ///
    /// A wrong length or the wrong side tag is a protocol error, not a bad guess,
    /// so it must not increment the failure counter (I3): otherwise any LAN host
    /// could burn codes by sending garbage.
    pub fn check_message(role: Role, message: &[u8]) -> Result<()> {
        if message.len() != PAKE_MSG_LEN {
            return Err(PairingError::BadMessage.into());
        }
        if message[0] != role.peer_side_tag() {
            return Err(PairingError::WrongRole.into());
        }
        Ok(())
    }

    /// The side tag of our own share, for tests and diagnostics.
    pub const fn side_tag(&self) -> u8 {
        self.role.side_tag()
    }

    /// Consume the peer's share and derive the shared key.
    ///
    /// The key doubles as the SPAKE2 session key `K` of §5.4 step 6. It is returned
    /// in a [`Secret`] so every read goes through `expose_secret`.
    pub fn finish(self, peer_message: &[u8]) -> Result<Secret<[u8; 32]>> {
        Self::check_message(self.role, peer_message)?;
        // `finish` consumes `self`, and its internal password copy goes with it.
        let raw = self
            .inner
            .finish(peer_message)
            .map_err(|_| PairingError::BadMessage)?;
        let mut key = [0u8; 32];
        if raw.len() != key.len() {
            return Err(PairingError::BadMessage.into());
        }
        key.copy_from_slice(&raw);
        Ok(Secret::new(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeSecret;

    fn ids() -> (NodeId, NodeId) {
        (
            NodeSecret::generate().public(),
            NodeSecret::generate().public(),
        )
    }

    fn password() -> SecretString {
        SecretString::from_string("torch-crystal".to_string())
    }

    #[test]
    fn both_sides_derive_the_same_key() {
        let (guest_id, host_id) = ids();
        let (guest, guest_msg) = PakeState::start(Role::Guest, &password(), guest_id, host_id);
        let (host, host_msg) = PakeState::start(Role::Host, &password(), guest_id, host_id);

        assert_eq!(guest_msg.len(), PAKE_MSG_LEN);
        assert_eq!(host_msg.len(), PAKE_MSG_LEN);
        assert_eq!(guest_msg[0], SIDE_A);
        assert_eq!(host_msg[0], SIDE_B);

        let guest_key = guest.finish(&host_msg).unwrap();
        let host_key = host.finish(&guest_msg).unwrap();
        assert_eq!(
            guest_key.expose_secret(),
            host_key.expose_secret(),
            "SPAKE2 must agree on one key"
        );
    }

    #[test]
    fn wrong_password_gives_different_keys() {
        let (guest_id, host_id) = ids();
        let (guest, guest_msg) = PakeState::start(
            Role::Guest,
            &SecretString::from_string("torch-crystal".to_string()),
            guest_id,
            host_id,
        );
        let (host, host_msg) = PakeState::start(
            Role::Host,
            &SecretString::from_string("torch-zebra".to_string()),
            guest_id,
            host_id,
        );
        let guest_key = guest.finish(&host_msg).unwrap();
        let host_key = host.finish(&guest_msg).unwrap();
        assert_ne!(guest_key.expose_secret(), host_key.expose_secret());
    }

    #[test]
    fn swapping_an_identity_changes_the_key() {
        let (guest_id, host_id) = ids();
        let (impostor, _) = ids();
        let (guest, guest_msg) = PakeState::start(Role::Guest, &password(), guest_id, host_id);
        // The host believes it speaks to someone else.
        let (host, host_msg) = PakeState::start(Role::Host, &password(), impostor, host_id);
        let guest_key = guest.finish(&host_msg).unwrap();
        let host_key = host.finish(&guest_msg).unwrap();
        assert_ne!(
            guest_key.expose_secret(),
            host_key.expose_secret(),
            "identity binding must be part of the key"
        );
    }

    #[test]
    fn a_message_from_the_same_side_is_rejected() {
        let (guest_id, host_id) = ids();
        let (guest, guest_msg) = PakeState::start(Role::Guest, &password(), guest_id, host_id);
        // Echoing our own share back must not be accepted as the peer's.
        assert!(matches!(
            guest.finish(&guest_msg),
            Err(crate::error::Error::Pairing(PairingError::WrongRole))
        ));
    }

    #[test]
    fn a_truncated_or_padded_message_is_rejected_before_the_crate() {
        let (guest_id, host_id) = ids();
        let (_guest, _) = PakeState::start(Role::Guest, &password(), guest_id, host_id);
        for len in [0usize, 1, 32, 34, 64] {
            let mut message = vec![SIDE_B; len];
            if len > 0 {
                message[0] = SIDE_B;
            }
            assert!(
                matches!(
                    guest_check(&message),
                    Err(crate::error::Error::Pairing(PairingError::BadMessage))
                ),
                "length {len} must be rejected"
            );
        }
    }

    fn guest_check(message: &[u8]) -> Result<()> {
        PakeState::check_message(Role::Guest, message)?;
        Ok(())
    }

    #[test]
    fn debug_does_not_expose_the_key() {
        let (guest_id, host_id) = ids();
        let (guest, guest_msg) = PakeState::start(Role::Guest, &password(), guest_id, host_id);
        let (host, _host_msg) = PakeState::start(Role::Host, &password(), guest_id, host_id);
        let text = format!("{guest:?}");
        assert!(text.contains("Guest"));
        assert!(!text.contains("torch"));
        let key = host.finish(&guest_msg).unwrap();
        assert_eq!(format!("{key:?}"), "[redacted]");
    }
}
