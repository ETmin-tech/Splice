//! The one question a pairing asks a human (§5.4 step 9, I18).
//!
//! The trait exists so the state machine can be tested without a terminal: the
//! tests supply [`Prompter`] implementations that answer deterministically, and the
//! CLI supplies one that reads `stdin`. Nothing in this module prints anything
//! itself, which keeps `splice-core` free of terminal assumptions.

use std::fmt;

use crate::error::{Error, TrustError};
use crate::proto::messages::sanitize_alias;

/// What one side proposes about the peer it just authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasConsent {
    /// The peer's proposed name for *us*, already sanitized.
    pub alias: String,
    /// The peer's `NodeId`, in hex. The prompt shows its last eight characters so a
    /// human can compare both screens.
    pub peer_id: String,
}

impl AliasConsent {
    /// Build from a peer's raw `TrustExchange` alias and its `NodeId`.
    ///
    /// Sanitizing happens here, before the string can reach a terminal, and an
    /// empty result is refused rather than shown as a blank prompt.
    pub fn new(raw_alias: &str, peer_id: impl fmt::Display) -> Result<Self, Error> {
        let alias = sanitize_alias(raw_alias)?;
        Ok(Self {
            alias,
            peer_id: peer_id.to_string(),
        })
    }

    /// The prompt text, fixed so a test can assert it verbatim.
    ///
    /// The `[y/N]` form means a bare Enter is "no": consent must be explicit.
    pub fn prompt(&self) -> String {
        format!(
            "Pasangkan dengan {} (id: {})? [y/N] ",
            self.alias,
            self.short_id()
        )
    }

    /// The last eight characters of the peer id, as the architecture specifies.
    pub fn short_id(&self) -> &str {
        let len = self.peer_id.chars().count();
        if len <= 8 {
            return &self.peer_id;
        }
        let skip = len - 8;
        // `peer_id` is hex from `NodeId`, so this slice is on an ASCII boundary.
        &self.peer_id[skip..]
    }
}

/// Asks a human whether to trust the device on the other end.
///
/// The default answer is *no*: an implementation that cannot ask must return
/// `false`, because silently trusting is the failure mode I18 exists to prevent.
pub trait Prompter: Send + Sync {
    /// `true` only on an explicit yes.
    fn confirm(&self, consent: &AliasConsent) -> bool;
}

/// A prompter that always says no. Used when the process has no terminal, and as
/// the safe default in tests that are not about consent.
#[derive(Debug, Default, Clone, Copy)]
pub struct AlwaysNo;

impl Prompter for AlwaysNo {
    fn confirm(&self, _consent: &AliasConsent) -> bool {
        false
    }
}

/// A prompter that always says yes. Only for tests: shipping this would defeat I18.
#[derive(Debug, Default, Clone, Copy)]
pub struct AlwaysYes;

impl Prompter for AlwaysYes {
    fn confirm(&self, _consent: &AliasConsent) -> bool {
        true
    }
}

/// A prompter with a scripted answer, recording every question it was asked.
#[derive(Debug, Default)]
pub struct Canned {
    answer: bool,
    asked: std::sync::Mutex<Vec<String>>,
}

impl Canned {
    pub fn new(answer: bool) -> Self {
        Self {
            answer,
            asked: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Every prompt shown so far, in order.
    pub fn asked(&self) -> Vec<String> {
        self.asked.lock().map(|v| v.clone()).unwrap_or_default()
    }
}

impl Prompter for Canned {
    fn confirm(&self, consent: &AliasConsent) -> bool {
        if let Ok(mut asked) = self.asked.lock() {
            asked.push(consent.prompt());
        }
        self.answer
    }
}

/// Both sides must answer yes before either writes an entry (I18).
///
/// Pure so it can be tested directly: this is the whole of the invariant.
pub const fn both_agree(ours: bool, theirs: bool) -> bool {
    ours && theirs
}

/// An alias that is refused for a reason other than being empty is still a refusal
/// to prompt: the caller reports [`TrustError::EmptyAlias`] instead of asking.
pub fn consent_or_refuse(
    raw_alias: &str,
    peer_id: impl fmt::Display,
) -> Result<AliasConsent, Error> {
    AliasConsent::new(raw_alias, peer_id).map_err(|err| match err {
        Error::Trust(TrustError::EmptyAlias) => Error::Trust(TrustError::EmptyAlias),
        other => other,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeId;

    fn id() -> NodeId {
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = i as u8;
        }
        NodeId::from_bytes(bytes)
    }

    #[test]
    fn consent_sanitizes_the_peer_alias() {
        let consent = AliasConsent::new("  Rina\u{1b}[2J's\tlaptop  ", id()).unwrap();
        assert_eq!(consent.alias, "Rina [2J's laptop");
        assert!(!consent.alias.contains('\u{1b}'));
    }

    #[test]
    fn consent_refuses_an_empty_alias() {
        assert!(matches!(
            AliasConsent::new("   ", id()),
            Err(Error::Trust(TrustError::EmptyAlias))
        ));
    }

    #[test]
    fn the_prompt_shows_the_last_eight_characters() {
        let consent = AliasConsent::new("laptop", id()).unwrap();
        assert_eq!(consent.short_id(), "1c1d1e1f");
        assert_eq!(
            consent.prompt(),
            "Pasangkan dengan laptop (id: 1c1d1e1f)? [y/N] "
        );
        assert!(consent.prompt().ends_with("[y/N] "));
    }

    #[test]
    fn a_short_id_is_shown_whole() {
        let consent = AliasConsent {
            alias: "x".to_string(),
            peer_id: "abc".to_string(),
        };
        assert_eq!(consent.short_id(), "abc");
    }

    #[test]
    fn a_prompter_that_cannot_ask_says_no() {
        let consent = AliasConsent::new("laptop", id()).unwrap();
        assert!(!AlwaysNo.confirm(&consent));
    }

    #[test]
    fn a_prompter_that_answers_yes_says_yes() {
        // `AlwaysYes` is the test-only counterpart of `AlwaysNo`. If it ever
        // returned `false`, every test that relies on it to grant consent would
        // silently exercise the refusal path instead of the one it names.
        let consent = AliasConsent::new("laptop", id()).unwrap();
        assert!(AlwaysYes.confirm(&consent));
        assert_ne!(
            AlwaysNo.confirm(&consent),
            AlwaysYes.confirm(&consent),
            "the two built-in prompters must not agree"
        );
    }

    #[test]
    fn both_sides_must_agree() {
        assert!(both_agree(true, true));
        assert!(!both_agree(true, false));
        assert!(!both_agree(false, true));
        assert!(!both_agree(false, false));
    }

    #[test]
    fn canned_records_what_it_was_asked() {
        let canned = Canned::new(true);
        let consent = AliasConsent::new("laptop", id()).unwrap();
        assert!(canned.confirm(&consent));
        assert_eq!(canned.asked(), vec![consent.prompt()]);
    }
}
