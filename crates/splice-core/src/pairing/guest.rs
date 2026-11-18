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
use crate::secret::Secret;

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
    code: Code,
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
        if !mode.uses_pake() {
            // Trusted mode has no PAKE and no code (§5.6); it is not a pairing.
            return Err(PairingError::NotAllowed.into());
        }
        let password = code.password();
        let (pake, our_msg) = PakeState::start(Role::Guest, &password, self_id, host_id);
        drop(password);

        let hello = ControlMsg::Hello {
            version: crate::constants::PROTOCOL_VERSION,
            mode,
            nameplate: Some(code.nameplate().get()),
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

    /// The code, for printing through [`Code::reveal_for_user`] (one-shot) or not at
    /// all (after pairing). Nothing here prints it.
    pub fn code(&self) -> &Code {
        &self.code
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    pub fn is_handshake_expired(&self, now: Instant) -> bool {
        self.deadline.is_some_and(|deadline| now >= deadline)
    }

    /// The session key, valid only after the host's MAC verified.
    pub fn session_key(&self) -> Option<&Secret<[u8; 32]>> {
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
                    self.abort();
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
        self.phase = PairingPhase::Burned;
        self.deadline = None;
        self.pake = None;
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
        assert_eq!(s.phase(), PairingPhase::Burned);
    }

    #[test]
    fn debug_never_prints_the_words() {
        let (s, _) = guest();
        let text = format!("{s:?}");
        let words = s.code().password().expose_secret().clone();
        for word in words.split('-') {
            assert!(!text.contains(word), "Debug leaked a word");
        }
    }
}
