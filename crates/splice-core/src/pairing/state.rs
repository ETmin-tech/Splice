//! Vocabulary shared by both halves of the pairing state machine.
//!
//! The guest and the host differ in what they *do*, not in how they report it, so
//! the phase, the outcome, and the "what to send next" step live here once.

use crate::proto::messages::{ByeReason, ControlMsg};

/// Where the pairing stands. Mirrors §5.8's diagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingPhase {
    /// An advertisement is up, no guest has said hello.
    WaitingForGuest,
    /// A guest is authenticated as far as TLS goes and the PAKE is running.
    Pairing,
    /// Key confirmation succeeded. The code is spent.
    Paired,
    /// Three failures, or the code expired. Terminal.
    ///
    /// This is a statement about the *code*, not about this connection: only the
    /// host can reach it, because only the host counts attempts and holds the
    /// expiry. A guest adopts it when the host says so (`Bye{Burned}`).
    Burned,
    /// This exchange ended and nothing vouched for the code's fate.
    ///
    /// A protocol violation, a handshake timeout, a refused attempt, or a
    /// guest-side token mismatch in ticket mode. The host may be perfectly
    /// healthy and the code may still pair someone else, so reporting `Burned`
    /// here would tell the caller a device is dead when it is not. Terminal for
    /// this session, and never advertises.
    Aborted,
}

impl PairingPhase {
    pub const fn name(self) -> &'static str {
        match self {
            Self::WaitingForGuest => "waiting",
            Self::Pairing => "pairing",
            Self::Paired => "paired",
            Self::Burned => "burned",
            Self::Aborted => "aborted",
        }
    }

    /// Whether the advertisement should still be on the network.
    ///
    /// Withdrawn the moment the code is spent, in any direction (I4): leaving it up
    /// would invite a second guest to a code that can no longer work.
    pub const fn advertises(self) -> bool {
        matches!(self, Self::WaitingForGuest | Self::Pairing)
    }
}

/// Why the session ended, for the caller's cleanup and its one log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Key confirmation passed and the transcript matches.
    Paired,
    /// The peer guessed wrong. The code survives until the counter hits the limit.
    Failed,
    /// The counter hit the limit, or the code expired; the code is dead.
    Burned,
    /// The peer violated the protocol; the code is untouched.
    ProtocolViolation,
    /// The handshake deadline passed with no progress.
    TimedOut,
    /// A second guest tried to pair while the first was active.
    Busy,
}

impl Outcome {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Paired => "paired",
            Self::Failed => "failed",
            Self::Burned => "burned",
            Self::ProtocolViolation => "protocol",
            Self::TimedOut => "timed out",
            Self::Busy => "busy",
        }
    }

    /// The `Bye` reason to show the peer, if any.
    ///
    /// A wrong guess gets `Protocol`, not `Declined`: telling a guesser how it
    /// failed would turn the counter into an oracle.
    pub const fn bye_reason(self) -> ByeReason {
        match self {
            Self::Burned => ByeReason::Burned,
            Self::TimedOut => ByeReason::Timeout,
            Self::Busy | Self::ProtocolViolation | Self::Failed => ByeReason::Protocol,
            Self::Paired => ByeReason::Normal,
        }
    }

    /// Whether the session is over, whatever the caller does next.
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Paired)
    }
}

/// What the caller does with a message after feeding it in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Send this reply on the CONTROL stream.
    Reply(ControlMsg),
    /// Send this reply and then close the session with the given outcome.
    ReplyThenClose {
        reply: Option<ControlMsg>,
        outcome: Outcome,
    },
    /// Send nothing; wait for the peer's next message.
    Idle,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_paired_is_not_terminal() {
        assert!(!Outcome::Paired.is_terminal());
        for outcome in [
            Outcome::Failed,
            Outcome::Burned,
            Outcome::ProtocolViolation,
            Outcome::TimedOut,
            Outcome::Busy,
        ] {
            assert!(
                outcome.is_terminal(),
                "{} must end the session",
                outcome.name()
            );
        }
    }

    #[test]
    fn a_wrong_guess_is_not_reported_as_a_decline() {
        assert_eq!(Outcome::Failed.bye_reason(), ByeReason::Protocol);
        assert_ne!(Outcome::Failed.bye_reason(), ByeReason::Declined);
        assert_eq!(Outcome::Burned.bye_reason(), ByeReason::Burned);
    }

    #[test]
    fn a_spent_code_stops_advertising() {
        assert!(PairingPhase::WaitingForGuest.advertises());
        assert!(PairingPhase::Pairing.advertises());
        assert!(!PairingPhase::Paired.advertises());
        assert!(!PairingPhase::Burned.advertises());
        assert!(!PairingPhase::Aborted.advertises());
    }

    #[test]
    fn every_outcome_names_itself_for_the_log_line() {
        // `Outcome::name` is what the CLI prints and what `is_terminal`'s
        // assertion messages show. A mutant that returns "" or "xyzzy" makes
        // every terminal outcome look identical in the log.
        assert_eq!(Outcome::Paired.name(), "paired");
        assert_eq!(Outcome::Failed.name(), "failed");
        assert_eq!(Outcome::Burned.name(), "burned");
        assert_eq!(Outcome::ProtocolViolation.name(), "protocol");
        assert_eq!(Outcome::TimedOut.name(), "timed out");
        assert_eq!(Outcome::Busy.name(), "busy");

        // All six must be distinct, which is the property the caller relies on.
        let names = [
            Outcome::Paired,
            Outcome::Failed,
            Outcome::Burned,
            Outcome::ProtocolViolation,
            Outcome::TimedOut,
            Outcome::Busy,
        ]
        .map(Outcome::name);
        let mut sorted = names;
        sorted.sort_unstable();
        let mut deduped = sorted.to_vec();
        deduped.dedup();
        assert_eq!(
            deduped.len(),
            names.len(),
            "outcome names collide: {names:?}"
        );
    }

    #[test]
    fn only_the_host_claims_the_code_burned() {
        // `Burned` is a claim about the code; `Aborted` says only that this
        // exchange stopped. Both names are distinct so a log line or a caller
        // cannot confuse them.
        assert_eq!(PairingPhase::Burned.name(), "burned");
        assert_eq!(PairingPhase::Aborted.name(), "aborted");
        assert_ne!(PairingPhase::Burned, PairingPhase::Aborted);
    }
}
