//! Guest-side state machine for a code pairing (§5.4, §5.8).
//!
//! The mirror of [`super::host::HostSession`], with one deliberate asymmetry: the
//! guest holds no attempt counter, because the counter must live where the code
//! lives (the host). A guest that guesses wrong learns only that the exchange
//! failed — [`crate::error::PairingError::ConfirmFailed`] with a neutral message —
//! and never retries on its own. Retrying automatically would turn three guesses
//! into an unbounded number of guesses.
//!
//! Ordering on the wire (fixed by the host's handler):
//!
//! ```text
//! guest                       host
//!   Hello          --------->
//!   PakeMsg        --------->
//!                  <---------  PakeMsg
//!   PakeConfirm    --------->
//!                  <---------  PakeConfirm
//!                  <---------  Paired
//! ```

use std::fmt;
use std::time::{Duration, Instant};

use crate::code::Code;
use crate::constants::HANDSHAKE_TIMEOUT;
use crate::error::{PairingError, Result};
use crate::identity::NodeId;
use crate::proto::messages::{ByeReason, ControlMsg, HelloMode};
use crate::secret::{Secret, SecretString};

use super::confirm::{confirm_mac, verify_mac, Transcript};
use super::pake::{PakeState, Role, PAKE_MSG_LEN};
use super::state::{Outcome, PairingPhase, Step};

/// The guest's view of one pairing.
pub struct GuestSession {
    /// Our own persistent (Pair mode) or ephemeral (OneShot) identity.
    self_id: NodeId,
    /// The host's identity, learned from mDNS/`--addr`/ticket and then authenticated
    /// by TLS. The transcript names this value, so a relay with a different
    /// `NodeId` cannot complete the exchange.
    host_id: NodeId,
    mode: HelloMode,
    /// The code this session belongs to. `None` in ticket mode.
    code: Option<Code>,
    phase: PairingPhase,
    pake: Option<PakeState>,
    our_pake_msg: Vec<u8>,
    peer_pake_msg: Vec<u8>,
    sent_confirm: bool,
    session_key: Option<Secret<[u8; 32]>>,
    deadline: Option<Instant>,
}

impl fmt::Debug for GuestSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // No code, no key, no PAKE bytes.
        f.debug_struct("GuestSession")
            .field("host", &self.host_id.prefix8())
            .field("mode", &self.mode)
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

impl GuestSession {
    /// Start a pairing: builds the session and the two messages that open it.
    ///
    /// Two messages, not one, because the guest's PAKE share follows `Hello`
    /// immediately and is *not* a reply to anything. Returning them together keeps
    /// that ordering in one place instead of asking the caller to remember it.
    pub fn begin(
        self_id: NodeId,
        host_id: NodeId,
        mode: HelloMode,
        code: Code,
        now: Instant,
    ) -> Result<(Self, Vec<ControlMsg>)> {
        let password = code.password();
        let nameplate = code.nameplate().get();
        Self::build(
            self_id,
            host_id,
            mode,
            Some(code),
            password,
            Some(nameplate),
            now,
        )
    }

    /// Start a pairing for a ticket: same exchange, no nameplate, and the ticket's
    /// 128-bit secret as the SPAKE2 password (§5.4, last paragraph).
    pub fn begin_with_password(
        self_id: NodeId,
        host_id: NodeId,
        mode: HelloMode,
        password: &SecretString,
        now: Instant,
    ) -> Result<(Self, Vec<ControlMsg>)> {
        Self::build(
            self_id,
            host_id,
            mode,
            None,
            password.duplicate(),
            None,
            now,
        )
    }

    fn build(
        self_id: NodeId,
        host_id: NodeId,
        mode: HelloMode,
        code: Option<Code>,
        password: SecretString,
        nameplate: Option<u16>,
        now: Instant,
    ) -> Result<(Self, Vec<ControlMsg>)> {
        if !mode.uses_pake() {
            // Trusted mode has no PAKE and no code (§5.6); it is not a pairing.
            return Err(PairingError::NotAllowed.into());
        }
        if code.is_some() != nameplate.is_some() {
            // A code always carries a nameplate, and ticket mode carries neither.
            return Err(PairingError::NotAllowed.into());
        }
        let (pake, our_msg) = PakeState::start(Role::Guest, &password, self_id, host_id);

        let hello = ControlMsg::Hello {
            version: crate::constants::PROTOCOL_VERSION,
            mode,
            nameplate,
            resume: None,
        };
        let session = Self {
            self_id,
            host_id,
            mode,
            code,
            phase: PairingPhase::Pairing,
            pake: Some(pake),
            our_pake_msg: our_msg.clone(),
            peer_pake_msg: Vec::new(),
            sent_confirm: false,
            session_key: None,
            deadline: Some(now + HANDSHAKE_TIMEOUT),
        };
        Ok((
            session,
            vec![hello, ControlMsg::PakeMsg { payload: our_msg }],
        ))
    }

    pub fn phase(&self) -> PairingPhase {
        self.phase
    }

    pub fn mode(&self) -> HelloMode {
        self.mode
    }

    pub fn host_id(&self) -> NodeId {
        self.host_id
    }

    /// The code this session is paired with, if any. For printing through
    /// [`Code::reveal_for_user`] (one-shot) or not at all (after pairing). Nothing
    /// here prints it.
    pub fn code(&self) -> Option<&Code> {
        self.code.as_ref()
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    pub fn is_handshake_expired(&self, now: Instant) -> bool {
        self.deadline.is_some_and(|deadline| now >= deadline)
    }

    /// The session key, valid only after the host's MAC verified.
    ///
    /// The SPAKE2 output exists as soon as the host's share arrives, because our own
    /// confirmation MAC is computed from it (see the private `session_key_ref`). It
    /// is not *readable* until then: a wrong guess derives a different key, and a
    /// man in the middle relaying two SPAKE2 runs has a key of its own that the
    /// host's MAC has not yet vouched for.
    pub fn session_key(&self) -> Option<&Secret<[u8; 32]>> {
        if self.phase != PairingPhase::Paired {
            return None;
        }
        self.session_key.as_ref()
    }

    /// Handle a decoded CONTROL message from the host.
    pub fn on_message(&mut self, from: NodeId, message: ControlMsg, now: Instant) -> Result<Step> {
        if !message.allowed_before_auth() {
            self.abort();
            return Ok(self.bye(Outcome::ProtocolViolation));
        }
        if from != self.host_id {
            // The transport authenticated a different node than the one discovery
            // pointed at. Nothing in the transcript would match it.
            self.abort();
            return Ok(self.bye(Outcome::ProtocolViolation));
        }
        if self.phase == PairingPhase::Pairing && self.is_handshake_expired(now) {
            // The deadline passed while this message was in flight. Answering it
            // would keep a stalled exchange alive past `HANDSHAKE_TIMEOUT`.
            self.abort();
            return Ok(self.bye(Outcome::TimedOut));
        }

        match &message {
            ControlMsg::PakeMsg { payload } => {
                if self.phase != PairingPhase::Pairing || self.pake.is_none() {
                    return Ok(self.bye(Outcome::ProtocolViolation));
                }
                if !self.peer_pake_msg.is_empty() || payload.len() != PAKE_MSG_LEN {
                    return Ok(self.bye(Outcome::ProtocolViolation));
                }
                let Some(pake) = self.pake.take() else {
                    return Ok(self.bye(Outcome::ProtocolViolation));
                };
                let key = match pake.finish(payload) {
                    Ok(key) => key,
                    Err(_) => return Ok(self.bye(Outcome::ProtocolViolation)),
                };
                self.peer_pake_msg = payload.clone();
                self.session_key = Some(key);
                let transcript = Transcript::new(
                    self.mode,
                    self.self_id,
                    self.host_id,
                    &self.our_pake_msg,
                    &self.peer_pake_msg,
                )?;
                let mac = confirm_mac(Role::Guest, self.session_key_ref()?, &transcript);
                self.sent_confirm = true;
                Ok(Step::Reply(ControlMsg::PakeConfirm { mac }))
            }

            ControlMsg::PakeConfirm { mac } => {
                if self.phase != PairingPhase::Pairing || !self.sent_confirm {
                    return Ok(self.bye(Outcome::ProtocolViolation));
                }
                let transcript = Transcript::new(
                    self.mode,
                    self.self_id,
                    self.host_id,
                    &self.our_pake_msg,
                    &self.peer_pake_msg,
                )?;
                let key = self.session_key_ref()?;
                if verify_mac(Role::Host, key, &transcript, mac).is_err() {
                    // Wrong words, or a man in the middle. The guest cannot tell
                    // which, and must not try again (I3 is enforced on the host).
                    return Ok(self.bye(Outcome::Failed));
                }
                self.phase = PairingPhase::Paired;
                self.deadline = None;
                Ok(Step::Idle)
            }

            ControlMsg::Paired { .. } => {
                // The host's confirmation of the same event. Waiting for the MAC
                // already moved us to `Paired`; a duplicate is harmless.
                if self.phase == PairingPhase::Paired {
                    Ok(Step::Idle)
                } else {
                    Ok(self.bye(Outcome::ProtocolViolation))
                }
            }

            ControlMsg::Ping => Ok(Step::Reply(ControlMsg::Pong)),

            ControlMsg::Bye { reason } => {
                let outcome = match reason {
                    ByeReason::Burned => Outcome::Burned,
                    ByeReason::Timeout => Outcome::TimedOut,
                    ByeReason::Declined => Outcome::ProtocolViolation,
                    _ => Outcome::Failed,
                };
                self.abort();
                if *reason == ByeReason::Burned {
                    // The host is the only authority on the counter and the expiry,
                    // and this is it saying the code is gone. Adopt that verdict;
                    // every other reason leaves the code's fate unknown.
                    self.phase = PairingPhase::Burned;
                }
                Ok(Step::ReplyThenClose {
                    reply: None,
                    outcome,
                })
            }

            // I2: nothing else is legal before confirmation.
            _ => {
                self.abort();
                Ok(self.bye(Outcome::ProtocolViolation))
            }
        }
    }

    /// Called when the handshake timer fires. The guest does not count attempts;
    /// it only stops waiting.
    pub fn on_timeout(&mut self, now: Instant) -> Option<Outcome> {
        if self.phase == PairingPhase::Pairing && self.is_handshake_expired(now) {
            self.abort();
            return Some(Outcome::TimedOut);
        }
        None
    }

    /// How long until the caller should call [`Self::on_timeout`] again.
    pub fn next_timer(&self, now: Instant) -> Option<Duration> {
        self.deadline
            .map(|deadline| deadline.saturating_duration_since(now))
    }

    fn session_key_ref(&self) -> Result<&Secret<[u8; 32]>> {
        self.session_key
            .as_ref()
            .ok_or_else(|| PairingError::BadMessage.into())
    }

    fn bye(&mut self, outcome: Outcome) -> Step {
        self.abort();
        Step::ReplyThenClose {
            reply: Some(ControlMsg::Bye {
                reason: outcome.bye_reason(),
            }),
            outcome,
        }
    }

    fn abort(&mut self) {
        if self.phase == PairingPhase::Paired {
            return;
        }
        // Terminal, but *not* `Burned`: this side stopped and learned nothing about
        // the code. The caller reads the phase to decide what to tell the user, so
        // claiming the device is dead here would be a lie. The one path that does
        // know is a `Bye{Burned}` from the host, which sets it explicitly below.
        self.phase = PairingPhase::Aborted;
        self.deadline = None;
        self.pake = None;
        // The shares are as sensitive as the key: they are half of the transcript
        // the MAC covers, and the host's `abort_handshake` clears its own for the
        // same reason. Leaving them behind would keep a dead exchange alive in
        // memory after `session_key` is dropped.
        self.our_pake_msg.clear();
        self.peer_pake_msg.clear();
        self.sent_confirm = false;
        self.session_key = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code::{Nameplate, WordCount};
    use crate::proto::messages::Caps;
    use rand::SeedableRng;

    fn code() -> Code {
        let mut rng = rand::rngs::StdRng::seed_from_u64(3);
        Code::generate(&mut rng, WordCount::Two, Nameplate::new(77).unwrap()).unwrap()
    }

    fn ids() -> (NodeId, NodeId) {
        (
            NodeId::from_bytes([0x21; 32]),
            NodeId::from_bytes([0x42; 32]),
        )
    }

    fn guest() -> (GuestSession, Vec<ControlMsg>) {
        let (g, h) = ids();
        GuestSession::begin(g, h, HelloMode::Pair, code(), Instant::now()).unwrap()
    }

    fn host_message(message: ControlMsg) -> ControlMsg {
        message
    }

    #[test]
    fn begin_sends_hello_then_the_pake_share() {
        let (_s, messages) = guest();
        assert_eq!(messages.len(), 2);
        match &messages[0] {
            ControlMsg::Hello {
                version,
                mode,
                nameplate,
                resume,
            } => {
                assert_eq!(*version, crate::constants::PROTOCOL_VERSION);
                assert_eq!(*mode, HelloMode::Pair);
                assert_eq!(*nameplate, Some(77));
                assert!(resume.is_none());
            }
            other => panic!("expected Hello, got {}", other.name()),
        }
        match &messages[1] {
            ControlMsg::PakeMsg { payload } => assert_eq!(payload.len(), PAKE_MSG_LEN),
            other => panic!("expected PakeMsg, got {}", other.name()),
        }
    }

    #[test]
    fn a_trusted_mode_begins_no_pairing() {
        let (g, h) = ids();
        let result = GuestSession::begin(g, h, HelloMode::Trusted, code(), Instant::now());
        assert!(matches!(
            result,
            Err(crate::error::Error::Pairing(PairingError::NotAllowed))
        ));
    }

    #[test]
    fn a_message_from_a_foreign_node_is_refused() {
        let (mut s, _) = guest();
        let intruder = NodeId::from_bytes([0x99; 32]);
        let step = s
            .on_message(
                intruder,
                host_message(ControlMsg::PakeMsg {
                    payload: vec![0x42; PAKE_MSG_LEN],
                }),
                Instant::now(),
            )
            .unwrap();
        assert!(matches!(
            step,
            Step::ReplyThenClose {
                outcome: Outcome::ProtocolViolation,
                ..
            }
        ));
        assert!(s.session_key().is_none());
    }

    #[test]
    fn a_short_share_is_a_protocol_error_not_a_failed_guess() {
        let (mut s, _) = guest();
        let step = s
            .on_message(
                ids().1,
                ControlMsg::PakeMsg {
                    payload: vec![0x42; 8],
                },
                Instant::now(),
            )
            .unwrap();
        assert!(matches!(
            step,
            Step::ReplyThenClose {
                outcome: Outcome::ProtocolViolation,
                ..
            }
        ));
    }

    #[test]
    fn an_early_confirm_without_a_share_is_refused() {
        let (mut s, _) = guest();
        let step = s
            .on_message(
                ids().1,
                ControlMsg::PakeConfirm { mac: [0; 32] },
                Instant::now(),
            )
            .unwrap();
        assert!(matches!(
            step,
            Step::ReplyThenClose {
                outcome: Outcome::ProtocolViolation,
                ..
            }
        ));
    }

    #[test]
    fn the_key_is_held_back_until_the_host_mac_verifies() {
        let (mut s, _opening) = guest();
        let (self_id, host_id) = ids();
        let (_host_pake, host_share) =
            PakeState::start(Role::Host, &code().password(), self_id, host_id);

        let step = s
            .on_message(
                host_id,
                ControlMsg::PakeMsg {
                    payload: host_share,
                },
                Instant::now(),
            )
            .unwrap();
        assert!(
            matches!(step, Step::Reply(ControlMsg::PakeConfirm { .. })),
            "the guest answers with its own confirmation, got {step:?}"
        );
        // We needed the key to compute that MAC, but the host's MAC has not been
        // seen yet, so the exchange is still unauthenticated: a man in the middle
        // who relayed two independent SPAKE2 runs would look exactly like this.
        assert!(
            s.session_key().is_none(),
            "the key must not be readable before the host's MAC verified"
        );
        assert_eq!(s.phase(), PairingPhase::Pairing);
    }

    #[test]
    fn a_forbidden_message_before_auth_is_refused() {
        let (mut s, _) = guest();
        let step = s
            .on_message(
                ids().1,
                ControlMsg::ConsentResult { granted: true },
                Instant::now(),
            )
            .unwrap();
        assert!(matches!(
            step,
            Step::ReplyThenClose {
                outcome: Outcome::ProtocolViolation,
                ..
            }
        ));
    }

    #[test]
    fn a_handshake_that_fails_does_not_claim_the_code_burned() {
        // `Burned` means the *host* counted three wrong guesses (or the code
        // expired). A guest that was refused, or that timed out, learned nothing
        // about the code's fate: the host may be perfectly healthy. Reporting
        // `Burned` here would tell the caller the device is dead when it is not.
        let (mut s, _) = guest();
        let step = s
            .on_message(
                ids().1,
                ControlMsg::ConsentResult { granted: true },
                Instant::now(),
            )
            .unwrap();
        assert!(matches!(step, Step::ReplyThenClose { .. }));
        assert_ne!(
            s.phase(),
            PairingPhase::Burned,
            "a protocol violation says nothing about the code"
        );
        assert!(!s.phase().advertises());

        let (mut timed_out, _) = guest();
        let start = Instant::now();
        assert_eq!(
            timed_out.on_timeout(start + HANDSHAKE_TIMEOUT),
            Some(Outcome::TimedOut)
        );
        assert_ne!(timed_out.phase(), PairingPhase::Burned);
    }

    #[test]
    fn a_burned_host_ends_the_guest_without_retrying() {
        let (mut s, _) = guest();
        let step = s
            .on_message(
                ids().1,
                ControlMsg::Bye {
                    reason: ByeReason::Burned,
                },
                Instant::now(),
            )
            .unwrap();
        assert!(matches!(
            step,
            Step::ReplyThenClose {
                outcome: Outcome::Burned,
                reply: None
            }
        ));
        assert_eq!(s.phase(), PairingPhase::Burned);
        // A second message gets nowhere: the session is terminal.
        let step = s
            .on_message(
                ids().1,
                ControlMsg::Paired { caps: Caps::NONE },
                Instant::now(),
            )
            .unwrap();
        assert!(matches!(step, Step::ReplyThenClose { .. }));
    }

    #[test]
    fn an_expired_handshake_ends_the_session() {
        let (mut s, _) = guest();
        let start = Instant::now();
        assert!(s.on_timeout(start).is_none());
        assert_eq!(
            s.on_timeout(start + HANDSHAKE_TIMEOUT),
            Some(Outcome::TimedOut)
        );
        assert_eq!(s.phase(), PairingPhase::Aborted, "a timeout burns nothing");
    }

    #[test]
    fn debug_never_prints_the_words() {
        let (s, _) = guest();
        let text = format!("{s:?}");
        let words = s
            .code()
            .expect("code mode")
            .password()
            .expose_secret()
            .clone();
        for word in words.split('-') {
            assert!(!text.contains(word), "Debug leaked a word");
        }
        // Redaction is only worth anything if the line still says something, so
        // the fields a log reader needs must survive. A `Debug` that prints
        // nothing at all would pass the loop above.
        assert!(text.contains("GuestSession"), "Debug lost the type: {text}");
        assert!(
            text.contains("phase: Pairing"),
            "Debug lost the phase: {text}"
        );
        assert!(
            text.contains(&ids().1.prefix8()),
            "Debug lost the peer: {text}"
        );
    }

    #[test]
    fn the_deadline_and_timer_are_armed_then_cleared() {
        // The caller arms its timer from `next_timer` and prints `deadline`; a
        // `None` here would let a stalled exchange wait forever, and a zero
        // duration would fire immediately on every poll.
        let (g, h) = ids();
        let start = Instant::now();
        let (s, _) = GuestSession::begin(g, h, HelloMode::Pair, code(), start).unwrap();
        assert_eq!(s.deadline(), Some(start + HANDSHAKE_TIMEOUT));
        assert_eq!(s.next_timer(start), Some(HANDSHAKE_TIMEOUT));
        assert_eq!(
            s.next_timer(start + Duration::from_secs(4)),
            Some(HANDSHAKE_TIMEOUT - Duration::from_secs(4))
        );

        let mut s = s;
        s.on_timeout(start + HANDSHAKE_TIMEOUT);
        assert_eq!(s.deadline(), None);
        assert_eq!(s.next_timer(start + HANDSHAKE_TIMEOUT), None);
    }

    #[test]
    fn a_message_after_the_deadline_is_timed_out() {
        // A reply that was already in flight when the deadline passed must not
        // keep the exchange alive (the same rule the host applies).
        let (mut s, _) = guest();
        let start = Instant::now();
        let step = s
            .on_message(ids().1, ControlMsg::Ping, start + HANDSHAKE_TIMEOUT)
            .unwrap();
        assert!(matches!(
            step,
            Step::ReplyThenClose {
                outcome: Outcome::TimedOut,
                ..
            }
        ));
        assert_eq!(
            s.phase(),
            PairingPhase::Aborted,
            "a late reply burns nothing"
        );
    }

    #[test]
    fn a_ping_is_answered_before_confirmation() {
        // `Ping`/`Pong` is the liveness check the caller uses on a CONTROL
        // stream that has no application traffic yet.
        let (mut s, _) = guest();
        let step = s
            .on_message(ids().1, ControlMsg::Ping, Instant::now())
            .unwrap();
        assert_eq!(step, Step::Reply(ControlMsg::Pong));
        assert_eq!(s.phase(), PairingPhase::Pairing);
    }

    #[test]
    fn every_bye_reason_maps_to_its_outcome() {
        // A `Bye` is the peer's verdict, and the caller shows it to the user.
        // Collapsing any arm into the `_ => Failed` catch-all would tell someone
        // whose code was burned, or whose handshake timed out, that the guess
        // was merely wrong.
        for (reason, expected) in [
            (ByeReason::Burned, Outcome::Burned),
            (ByeReason::Timeout, Outcome::TimedOut),
            (ByeReason::Declined, Outcome::ProtocolViolation),
            (ByeReason::Protocol, Outcome::Failed),
            (ByeReason::Revoked, Outcome::Failed),
            (ByeReason::NotTrusted, Outcome::Failed),
            (ByeReason::Normal, Outcome::Failed),
        ] {
            let (mut s, _) = guest();
            let step = s
                .on_message(ids().1, ControlMsg::Bye { reason }, Instant::now())
                .unwrap();
            match step {
                Step::ReplyThenClose { reply, outcome } => {
                    assert_eq!(outcome, expected, "wrong outcome for {reason:?}");
                    assert!(reply.is_none(), "a Bye must not be answered with a Bye");
                }
                other => panic!("expected close for {reason:?}, got {other:?}"),
            }
            let expected_phase = if reason == ByeReason::Burned {
                // The host's verdict: the code is gone.
                PairingPhase::Burned
            } else {
                // Any other `Bye` says nothing about the code itself.
                PairingPhase::Aborted
            };
            assert_eq!(s.phase(), expected_phase, "for {reason:?}");
        }
    }
}
