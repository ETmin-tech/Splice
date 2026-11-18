//! Transcript hashing and key confirmation (§5.4 step 6).
//!
//! `transcript = H(version ‖ mode ‖ guest NodeId ‖ host NodeId ‖ PakeMsg_guest ‖ PakeMsg_host)`
//!
//! Each side then sends `PakeConfirm{mac}` where
//! `mac = blake3::keyed_hash(derive_key("splice v1 confirm <role>", K), transcript)`.
//!
//! The transcript binds both identities and both public shares to the key. That is
//! what makes a man in the middle fail even with a correct guess: it would have to
//! produce a MAC that verifies against a transcript naming *our* peer, and it does
//! not hold that peer's identity in its own SPAKE2 run.
//!
//! Field order is fixed and every length is implicit (two `u16`s and four
//! fixed-length buffers), so there is no ambiguity to exploit: no attacker-chosen
//! separator can shift the boundaries.

use blake3;

use crate::constants::PROTOCOL_VERSION;
use crate::error::{PairingError, Result};
use crate::identity::NodeId;
use crate::proto::messages::HelloMode;
use crate::secret::{Secret, SecretString};

use super::pake::PAKE_MSG_LEN;

/// KDF contexts. These strings are part of the protocol; changing one is a wire
/// break. The old project name is replaced by `splice` (architecture §5.4 uses the
/// previous spelling).
pub const CONFIRM_GUEST: &str = "splice v1 confirm guest";
pub const CONFIRM_HOST: &str = "splice v1 confirm host";
pub const RESUME_KEY_CONTEXT: &str = "splice v1 resume";

/// The four things both sides must agree on before a MAC can verify.
#[derive(Debug, Clone)]
pub struct Transcript {
    version: u16,
    mode: HelloMode,
    guest: NodeId,
    host: NodeId,
    guest_msg: Vec<u8>,
    host_msg: Vec<u8>,
}

impl Transcript {
    /// Build a transcript for one exchange.
    ///
    /// Returns `None`-like errors rather than panicking when a share has the wrong
    /// length: this runs on peer-controlled data.
    pub fn new(
        mode: HelloMode,
        guest: NodeId,
        host: NodeId,
        guest_msg: &[u8],
        host_msg: &[u8],
    ) -> Result<Self> {
        if guest_msg.len() != PAKE_MSG_LEN || host_msg.len() != PAKE_MSG_LEN {
            return Err(PairingError::BadMessage.into());
        }
        Ok(Self {
            version: PROTOCOL_VERSION,
            mode,
            guest,
            host,
            guest_msg: guest_msg.to_vec(),
            host_msg: host_msg.to_vec(),
        })
    }

    /// The unambiguous pre-image `version ‖ mode ‖ guest ‖ host ‖ msgs`.
    pub fn preimage(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 1 + 64 + 2 * PAKE_MSG_LEN);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(mode_byte(self.mode));
        out.extend_from_slice(self.guest.as_bytes());
        out.extend_from_slice(self.host.as_bytes());
        out.extend_from_slice(&self.guest_msg);
        out.extend_from_slice(&self.host_msg);
        out
    }

    /// `H(pre-image)`, the transcript value the MAC is computed over.
    pub fn digest(&self) -> [u8; 32] {
        *blake3::hash(&self.preimage()).as_bytes()
    }
}

const fn mode_byte(mode: HelloMode) -> u8 {
    match mode {
        HelloMode::OneShot => 1,
        HelloMode::Pair => 2,
        HelloMode::Trusted => 3,
    }
}

/// Derive a labelled subkey from the SPAKE2 session key.
///
/// `blake3::derive_key` is the keyed KDF the architecture names; the context string
/// is the label, so two labels can never produce the same subkey.
pub fn subkey(label: &str, session_key: &Secret<[u8; 32]>) -> Secret<[u8; 32]> {
    Secret::new(blake3::derive_key(label, session_key.expose_secret()))
}

/// Compute the confirmation MAC for one role.
pub fn confirm_mac(
    role: super::pake::Role,
    session_key: &Secret<[u8; 32]>,
    transcript: &Transcript,
) -> [u8; 32] {
    let label = match role {
        super::pake::Role::Guest => CONFIRM_GUEST,
        super::pake::Role::Host => CONFIRM_HOST,
    };
    let key = subkey(label, session_key);
    let digest = transcript.digest();
    *blake3::keyed_hash(key.expose_secret(), &digest).as_bytes()
}

/// Verify a peer's MAC in constant time.
///
/// `spake2`/`blake3` comparisons here must not leak a matching prefix, hence
/// `subtle`. A failure is [`PairingError::ConfirmFailed`], which is exactly the
/// signal the host counts as a failed attempt (I3).
pub fn verify_mac(
    role: super::pake::Role,
    session_key: &Secret<[u8; 32]>,
    transcript: &Transcript,
    received: &[u8; 32],
) -> Result<()> {
    let expected = confirm_mac(role, session_key, transcript);
    use subtle::ConstantTimeEq;
    if expected.ct_eq(received).into() {
        Ok(())
    } else {
        Err(PairingError::ConfirmFailed.into())
    }
}

/// The resume key of §5.4 step 8 and §5.7 (declared here, used in Phase 2/3).
pub fn resume_key(session_key: &Secret<[u8; 32]>) -> Secret<[u8; 32]> {
    subkey(RESUME_KEY_CONTEXT, session_key)
}

/// A password built from words and a ticket secret, kept in one place so the
/// "never log it" rule has a single chokepoint.
pub fn password_from_words(words: &[&str]) -> SecretString {
    SecretString::from_string(words.join("-"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeSecret;
    use crate::pairing::pake::{PakeState, Role};

    fn setup() -> (Secret<[u8; 32]>, Transcript) {
        let guest_id = NodeSecret::generate().public();
        let host_id = NodeSecret::generate().public();
        let password = SecretString::from_string("torch-crystal".to_string());
        let (g, g_msg) = PakeState::start(Role::Guest, &password, guest_id, host_id);
        let (h, h_msg) = PakeState::start(Role::Host, &password, guest_id, host_id);
        let key = g.finish(&h_msg).unwrap();
        let transcript =
            Transcript::new(HelloMode::Pair, guest_id, host_id, &g_msg, &h_msg).unwrap();
        // Host must derive the same key.
        let host_key = h.finish(&g_msg).unwrap();
        assert_eq!(key.expose_secret(), host_key.expose_secret());
        (key, transcript)
    }

    #[test]
    fn both_roles_compute_a_verifiable_mac() {
        let (key, transcript) = setup();
        let guest_mac = confirm_mac(Role::Guest, &key, &transcript);
        let host_mac = confirm_mac(Role::Host, &key, &transcript);
        assert_ne!(guest_mac, host_mac, "the two labels must differ");
        assert!(verify_mac(Role::Guest, &key, &transcript, &guest_mac).is_ok());
        assert!(verify_mac(Role::Host, &key, &transcript, &host_mac).is_ok());
    }

    #[test]
    fn a_flipped_bit_fails_confirmation() {
        let (key, transcript) = setup();
        let mut mac = confirm_mac(Role::Guest, &key, &transcript);
        mac[0] ^= 1;
        assert!(matches!(
            verify_mac(Role::Guest, &key, &transcript, &mac),
            Err(crate::error::Error::Pairing(PairingError::ConfirmFailed))
        ));
    }

    #[test]
    fn changing_any_single_identity_breaks_the_mac() {
        let (key, transcript) = setup();
        let mac = confirm_mac(Role::Guest, &key, &transcript);

        // Every field change must invalidate the MAC: this is the anti-MITM
        // property the architecture asks for, tested field by field.
        let forged_guest = Transcript {
            guest: NodeSecret::generate().public(),
            ..transcript.clone()
        };
        let forged_host = Transcript {
            host: NodeSecret::generate().public(),
            ..transcript.clone()
        };
        let forged_mode = Transcript {
            mode: HelloMode::OneShot,
            ..transcript.clone()
        };
        let forged_version = Transcript {
            version: PROTOCOL_VERSION + 1,
            ..transcript.clone()
        };
        let mut forged_msg = transcript.clone();
        forged_msg.guest_msg[1] ^= 0xff;

        for forged in [
            forged_guest,
            forged_host,
            forged_mode,
            forged_version,
            forged_msg,
        ] {
            assert!(
                verify_mac(Role::Guest, &key, &forged, &mac).is_err(),
                "a changed transcript field must break confirmation"
            );
        }
    }

    #[test]
    fn a_transcript_with_a_short_share_is_rejected() {
        let (guest, host) = (
            NodeSecret::generate().public(),
            NodeSecret::generate().public(),
        );
        assert!(Transcript::new(HelloMode::Pair, guest, host, &[0u8; 32], &[0u8; 33]).is_err());
        assert!(Transcript::new(HelloMode::Pair, guest, host, &[0u8; 33], &[0u8; 32]).is_err());
    }

    #[test]
    fn resume_key_is_label_separated() {
        let (key, _) = setup();
        let resume = resume_key(&key);
        assert_ne!(resume.expose_secret(), key.expose_secret());
        assert_ne!(
            *resume.expose_secret(),
            blake3::derive_key(CONFIRM_GUEST, key.expose_secret())
        );
        assert_eq!(format!("{resume:?}"), "[redacted]");
    }
}
