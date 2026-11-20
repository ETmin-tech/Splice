//! CONTROL messages (§7.3), `postcard`-encoded inside [`crate::proto::frame`] bodies.
//!
//! Two rules shape these types:
//!
//! * Nothing here carries a secret. The SPAKE2 message is a *public* share, the MAC
//!   is derived from the session key, and no variant has a plaintext password field.
//! * Every `String` from the peer is bounded by the frame limit and validated on
//!   arrival (`alias` in particular) rather than trusted.

use serde::{Deserialize, Serialize};

use crate::constants::{ALIAS_MAX_LEN, PROTOCOL_VERSION};
use crate::error::{Error, ProtoError};

/// How the caller intends to use the connection (§5.4, §5.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HelloMode {
    /// One-shot code: a session, nothing persisted.
    OneShot,
    /// Code plus a trust entry if both sides agree (§5.4 step 9).
    Pair,
    /// Persistent-identity device already in the trust store (§5.6).
    Trusted,
}

impl HelloMode {
    pub const fn name(self) -> &'static str {
        match self {
            Self::OneShot => "one-shot",
            Self::Pair => "pair",
            Self::Trusted => "trusted",
        }
    }

    /// Ticket and code pairing share the PAKE path; trusted mode must never reach it.
    pub const fn uses_pake(self) -> bool {
        matches!(self, Self::OneShot | Self::Pair)
    }
}

/// Features the two sides agree on after PAIRED. Phase 1 advertises nothing, but
/// the field exists on the wire so a later phase does not need a version bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Caps(pub u32);

impl Caps {
    pub const NONE: Self = Self(0);

    pub const fn has(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// Why the sender is closing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ByeReason {
    /// Normal end of session.
    Normal,
    /// The peer is not trusted and this is not a pairing connection (I13).
    NotTrusted,
    /// The code was burned by too many failures (I3).
    Burned,
    /// The pairing took too long.
    Timeout,
    /// Protocol violation; a generic reason so probing gets no detail.
    Protocol,
    /// The user declined.
    Declined,
    /// The device was revoked from the trust store.
    Revoked,
}

impl ByeReason {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::NotTrusted => "not trusted",
            Self::Burned => "burned",
            Self::Timeout => "timeout",
            Self::Protocol => "protocol",
            Self::Declined => "declined",
            Self::Revoked => "revoked",
        }
    }
}

/// A CONTROL message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMsg {
    /// First message from the guest. `nameplate` is present in code modes only;
    /// `resume` is a session id for the (Phase 2/3) resume path.
    Hello {
        version: u16,
        mode: HelloMode,
        nameplate: Option<u16>,
        resume: Option<Vec<u8>>,
    },
    /// SPAKE2 public share for the sending side. Public value, not a secret.
    PakeMsg { payload: Vec<u8> },
    /// Key-confirmation MAC over the transcript (§5.4 step 6).
    PakeConfirm { mac: [u8; 32] },
    /// Proposed alias, sent in Pair mode only. Sanitized on arrival.
    TrustExchange { alias: String },
    /// "I agree to store your entry." Both sides must send it (I18).
    TrustAck,
    /// "We are PAIRED." Sent after successful key confirmation.
    Paired { caps: Caps },
    /// Phase 3 host-consent result; present so the state machine is complete.
    ConsentResult { granted: bool },
    /// Phase 3 read-only ↔ interactive switch.
    ModeChange { interactive: bool },
    /// Phase 3/2 resume challenge.
    ResumeChallenge { nonce: [u8; 32] },
    /// Phase 3/2 resume proof.
    ResumeProof { proof: [u8; 32] },
    /// Keepalive.
    Ping,
    /// Keepalive reply.
    Pong,
    /// Going away.
    Bye { reason: ByeReason },
}

impl ControlMsg {
    /// Version check for a `Hello`. Returns the message unchanged on success.
    pub fn check_version(&self) -> Result<(), Error> {
        match self {
            Self::Hello { version, .. } if *version != PROTOCOL_VERSION => {
                Err(ProtoError::VersionMismatch {
                    got: *version,
                    expected: PROTOCOL_VERSION,
                }
                .into())
            }
            _ => Ok(()),
        }
    }

    /// The wire name, used in `tracing` fields. Never includes a payload.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Hello { .. } => "Hello",
            Self::PakeMsg { .. } => "PakeMsg",
            Self::PakeConfirm { .. } => "PakeConfirm",
            Self::TrustExchange { .. } => "TrustExchange",
            Self::TrustAck => "TrustAck",
            Self::Paired { .. } => "Paired",
            Self::ConsentResult { .. } => "ConsentResult",
            Self::ModeChange { .. } => "ModeChange",
            Self::ResumeChallenge { .. } => "ResumeChallenge",
            Self::ResumeProof { .. } => "ResumeProof",
            Self::Ping => "Ping",
            Self::Pong => "Pong",
            Self::Bye { .. } => "Bye",
        }
    }

    /// I2: which messages a connection may carry before it is authenticated.
    ///
    /// Only the pairing exchange and keepalives. Anything else arriving early is a
    /// protocol violation and closes the connection.
    pub const fn allowed_before_auth(&self) -> bool {
        matches!(
            self,
            Self::Hello { .. }
                | Self::PakeMsg { .. }
                | Self::PakeConfirm { .. }
                | Self::TrustExchange { .. }
                | Self::TrustAck
                | Self::Paired { .. }
                | Self::Ping
                | Self::Pong
                | Self::Bye { .. }
        )
    }
}

/// Alias sanitization (§5.4 step 9, `ALIAS_MAX_LEN`).
///
/// Strips control characters (which could otherwise rewrite the prompt line),
/// strips invisible bidi and format characters (which could reorder it or hide
/// part of an alias), trims, collapses internal whitespace, and truncates on a
/// character boundary. An empty result is an error: the prompt needs something to
/// print.
pub fn sanitize_alias(raw: &str) -> Result<String, Error> {
    let mut out = String::with_capacity(raw.len().min(ALIAS_MAX_LEN));
    let mut last_was_space = false;
    for ch in raw.chars() {
        if is_invisible_format(ch) {
            continue;
        }
        let ch = if ch.is_control() { ' ' } else { ch };
        if ch == ' ' || ch == '\u{00a0}' || ch == '\u{200b}' {
            if last_was_space || out.is_empty() {
                continue;
            }
            out.push(' ');
            last_was_space = true;
            continue;
        }
        last_was_space = false;
        out.push(ch);
        if out.chars().count() >= ALIAS_MAX_LEN {
            break;
        }
    }
    let trimmed = out.trim_end().to_string();
    if trimmed.is_empty() {
        return Err(crate::error::TrustError::EmptyAlias.into());
    }
    Ok(trimmed)
}

/// Whether `ch` is an invisible formatting character that has no place in an alias.
///
/// These are not `char::is_control` (they are in category `Cf`), so the control
/// filter misses them, yet they can reorder a rendered line or make text
/// disappear: a guest could otherwise choose an alias that makes the `[y/N]`
/// prompt read as a different device's name. Format characters (U+200B..U+200F,
/// U+2060..U+206F, U+FEFF, soft hyphen) and the bidi controls (U+061C,
/// U+202A..U+202E) are all refused.
///
/// Shared with [`crate::trust::store`], which re-validates a hand-edited file.
pub const fn is_invisible_format(ch: char) -> bool {
    matches!(ch,
        '\u{00ad}'                  // soft hyphen
        | '\u{061c}'                // arabic letter mark
        | '\u{200b}'..='\u{200f}'   // zero width space .. right-to-left mark
        | '\u{202a}'..='\u{202e}'   // bidi embeddings and overrides
        | '\u{2060}'..='\u{2064}'   // word joiner .. invisible plus
        | '\u{2066}'..='\u{206f}'   // bidi isolates .. deprecated format chars
        | '\u{feff}'                // zero width no-break space
    )
}

/// A message that can travel in a CONTROL frame body.
///
/// The supertraits carry the `postcard` bounds, so a generic `M: WireMessage`
/// can encode and decode without restating them at every call site.
pub trait WireMessage: Serialize + for<'de> Deserialize<'de> + Sized + std::fmt::Debug {
    /// Encode into a CONTROL body. Never allocates more than the message needs.
    fn encode_to_vec(&self) -> Result<Vec<u8>, Error> {
        postcard::to_stdvec(self).map_err(|err| ProtoError::Encode(err.to_string()).into())
    }

    /// Decode a CONTROL body. The caller has already bounded its length.
    ///
    /// Trailing bytes are an error: `postcard::from_bytes` would accept them, and
    /// a body with slack is either a mismatch between the declared length and the
    /// message or an attempt to smuggle data past the decoder (I9).
    fn decode_from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let (message, rest) =
            postcard::take_from_bytes(bytes).map_err(|err| ProtoError::Decode(err.to_string()))?;
        if !rest.is_empty() {
            return Err(ProtoError::Decode(format!(
                "{} trailing byte(s) after the message",
                rest.len()
            ))
            .into());
        }
        Ok(message)
    }
}

impl WireMessage for ControlMsg {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{Error, TrustError};

    fn sample_messages() -> Vec<ControlMsg> {
        vec![
            ControlMsg::Hello {
                version: PROTOCOL_VERSION,
                mode: HelloMode::OneShot,
                nameplate: Some(7),
                resume: None,
            },
            ControlMsg::Hello {
                version: PROTOCOL_VERSION,
                mode: HelloMode::Pair,
                nameplate: Some(999),
                resume: Some(vec![1, 2, 3]),
            },
            ControlMsg::PakeMsg {
                payload: vec![0x41; 33],
            },
            ControlMsg::PakeConfirm { mac: [7u8; 32] },
            ControlMsg::TrustExchange {
                alias: "Rina's laptop".to_string(),
            },
            ControlMsg::TrustAck,
            ControlMsg::Paired { caps: Caps::NONE },
            ControlMsg::ConsentResult { granted: true },
            ControlMsg::ModeChange { interactive: false },
            ControlMsg::ResumeChallenge { nonce: [9u8; 32] },
            ControlMsg::ResumeProof { proof: [3u8; 32] },
            ControlMsg::Ping,
            ControlMsg::Pong,
            ControlMsg::Bye {
                reason: ByeReason::NotTrusted,
            },
        ]
    }

    #[test]
    fn every_message_roundtrips() {
        for message in sample_messages() {
            let bytes = message.encode_to_vec().unwrap();
            let decoded = ControlMsg::decode_from_slice(&bytes).unwrap();
            assert_eq!(decoded, message, "{} did not roundtrip", message.name());
        }
    }

    #[test]
    fn hello_reports_a_version_mismatch() {
        let hello = ControlMsg::Hello {
            version: PROTOCOL_VERSION + 1,
            mode: HelloMode::OneShot,
            nameplate: Some(3),
            resume: None,
        };
        assert!(matches!(
            hello.check_version(),
            Err(Error::Proto(ProtoError::VersionMismatch {
                got: 2,
                expected: 1
            }))
        ));
        assert!(ControlMsg::Ping.check_version().is_ok());
    }

    #[test]
    fn garbage_does_not_panic() {
        for len in 0..64 {
            let bytes = vec![0xffu8; len];
            let _ = ControlMsg::decode_from_slice(&bytes);
        }
        // Truncated valid encoding.
        let bytes = ControlMsg::Paired { caps: Caps::NONE }
            .encode_to_vec()
            .unwrap();
        for cut in 0..bytes.len() {
            let _ = ControlMsg::decode_from_slice(&bytes[..cut]);
        }
    }

    #[test]
    fn trailing_bytes_after_a_message_are_rejected() {
        let mut bytes = ControlMsg::Ping.encode_to_vec().unwrap();
        bytes.push(0);
        assert!(ControlMsg::decode_from_slice(&bytes).is_err());
    }

    #[test]
    fn pre_auth_allowlist_matches_i2() {
        assert!(ControlMsg::Ping.allowed_before_auth());
        assert!(ControlMsg::TrustAck.allowed_before_auth());
        assert!(ControlMsg::PakeConfirm { mac: [0; 32] }.allowed_before_auth());
        assert!(!ControlMsg::ConsentResult { granted: true }.allowed_before_auth());
        assert!(!ControlMsg::ModeChange { interactive: true }.allowed_before_auth());
        assert!(!ControlMsg::ResumeProof { proof: [0; 32] }.allowed_before_auth());
    }

    #[test]
    fn only_code_modes_use_pake() {
        assert!(HelloMode::OneShot.uses_pake());
        assert!(HelloMode::Pair.uses_pake());
        assert!(!HelloMode::Trusted.uses_pake());
    }

    #[test]
    fn alias_sanitizing_strips_control_characters() {
        let alias = sanitize_alias("  Rina\u{1b}[2J's  \t laptop \n").unwrap();
        assert_eq!(alias, "Rina [2J's laptop");
        assert!(!alias.contains('\u{1b}'));
        assert!(!alias.contains('\n'));
    }

    #[test]
    fn alias_is_truncated_to_the_limit() {
        let long = "a".repeat(200);
        let alias = sanitize_alias(&long).unwrap();
        assert_eq!(alias.chars().count(), ALIAS_MAX_LEN);
    }

    #[test]
    fn alias_truncation_respects_character_boundaries() {
        let long = "é".repeat(100);
        let alias = sanitize_alias(&long).unwrap();
        assert_eq!(alias.chars().count(), ALIAS_MAX_LEN);
    }

    #[test]
    fn empty_alias_is_rejected() {
        for raw in ["", "   ", "\u{1b}\u{7}", "\n\t"] {
            assert!(matches!(
                sanitize_alias(raw),
                Err(Error::Trust(TrustError::EmptyAlias))
            ));
        }
    }

    /// Bidi overrides and invisible formatting characters are not char::is_control,
    /// so the control-character filter lets them through and they can reorder the
    /// [y/N] prompt or hide part of an alias from the human reading it.
    #[test]
    fn alias_strips_invisible_bidi_and_format_characters() {
        for hidden in [
            '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', // LRE RLE PDF LRO RLO
            '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', // LRI RLI FSI PDI
            '\u{200e}', '\u{200f}', '\u{061c}', '\u{feff}', '\u{00ad}',
        ] {
            let raw = format!("a{hidden}b");
            let alias = sanitize_alias(&raw).expect("not empty");
            assert!(
                !alias.contains(hidden),
                "U+{:04X} survived sanitizing: {alias:?}",
                hidden as u32
            );
        }
    }

    #[test]
    fn alias_keeps_inner_spacing_but_collapses_runs() {
        assert_eq!(sanitize_alias("a    b").unwrap(), "a b");
    }
}
