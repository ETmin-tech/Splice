//! Host-side state machine for a code pairing (§5.4, §5.8).
//!
//! This type holds no I/O. It is a pure function of the messages it is given, so
//! every invariant below is testable without a network:
//!
//! * **I3** — three failed attempts burn the code, a fourth attempt is refused even
//!   with the right words, and the counter is a property of the *code*, not of the
//!   connection, so reconnecting does not reset it.
//! * **I4** — after `Paired` the same code can never pair again.
//! * **I2** — messages that are not part of the pairing exchange are refused before
//!   confirmation.
//! * One active guest at a time: a second `Hello` gets [`PairingError::Busy`] and
//!   does not disturb the first.
//!
//! Time is passed in, never read here, so the 10 s handshake deadline and the
//! 600 s code TTL can be tested exactly.

use std::fmt;
use std::time::{Duration, Instant};

use crate::code::Code;
use crate::constants::{HANDSHAKE_TIMEOUT, PAIRING_ATTEMPTS_MAX, PAIRING_CODE_TTL};
use crate::error::{PairingError, Result};
use crate::identity::NodeId;
use crate::proto::messages::{ByeReason, ControlMsg, HelloMode};
use crate::secret::SecretString;

use super::confirm::{confirm_mac, verify_mac, Transcript};
use super::pake::{PakeState, Role, PAKE_MSG_LEN};
use super::state::{Outcome, PairingPhase, Step};

/// The host's view of one code.
///
/// One code, one pairing. A caller that wants a new code builds a new value; there
/// is no `reset` on purpose, because a counter that can be reset is a counter an
/// attacker can reset.
pub struct HostSession {
    /// Persistent identity of this host (ephemeral in one-shot mode, but still the
    /// identity the transcript must name).
    host_id: NodeId,
    mode: HelloMode,
    /// The guest's authenticated `NodeId`, learned from `Hello`'s connection.
    guest_id: Option<NodeId>,
    /// The code this session belongs to. `None` in ticket mode, which carries no
    /// code and no nameplate (§5.4, last paragraph).
    code: Option<Code>,
    /// The SPAKE2 password: the code's words, or the ticket's 128-bit secret.
    password: SecretString,
    /// The nameplate a `Hello` must carry. `None` in ticket mode.
    nameplate: Option<u16>,
    phase: PairingPhase,
    failures: u32,
    created: Instant,
    deadline: Option<Instant>,
    pake: Option<PakeState>,
    our_pake_msg: Vec<u8>,
    peer_pake_msg: Vec<u8>,
    /// Set once this side has sent its own MAC, so the peer's is only accepted after.
    sent_confirm: bool,
    /// Set once both MACs verified.
    session_key: Option<crate::secret::Secret<[u8; 32]>>,
}

impl fmt::Debug for HostSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately omits the code, the key, and the SPAKE2 messages.
        f.debug_struct("HostSession")
            .field("host", &self.host_id.prefix8())
            .field("mode", &self.mode)
            .field("phase", &self.phase)
            .field("failures", &self.failures)
            .finish_non_exhaustive()
    }
}

impl HostSession {
    /// Create a session for `code`, owned by `host_id`, in the given mode.
    pub fn new(host_id: NodeId, mode: HelloMode, code: Code, now: Instant) -> Result<Self> {
        let password = code.password();
        let nameplate = code.nameplate().get();
        Self::build(host_id, mode, Some(code), password, Some(nameplate), now)
    }

    /// Create a session for a ticket, which carries a password but no code and no
    /// nameplate (§5.4, last paragraph: "Mode tiket memakai langkah yang sama,
    /// tanpa nameplate").
    ///
    /// The caller is responsible for the ticket secret's provenance; this type
    /// never logs it and zeroizes its own copy on drop.
    pub fn new_with_password(
        host_id: NodeId,
        mode: HelloMode,
        password: &SecretString,
        now: Instant,
    ) -> Result<Self> {
        Self::build(host_id, mode, None, password.duplicate(), None, now)
    }

    fn build(
        host_id: NodeId,
        mode: HelloMode,
        code: Option<Code>,
        password: SecretString,
        nameplate: Option<u16>,
        now: Instant,
    ) -> Result<Self> {
        if !mode.uses_pake() {
            // Trusted mode has no code and no PAKE (§5.6).
            return Err(PairingError::NotAllowed.into());
        }
        if code.is_some() != nameplate.is_some() {
            // A code always carries a nameplate, and ticket mode carries neither.
            return Err(PairingError::NotAllowed.into());
        }
        Ok(Self {
            host_id,
            mode,
            guest_id: None,
            code,
            password,
            nameplate,
            phase: PairingPhase::WaitingForGuest,
            failures: 0,
            created: now,
            deadline: None,
            pake: None,
            our_pake_msg: Vec::new(),
            peer_pake_msg: Vec::new(),
            sent_confirm: false,
            session_key: None,
        })
    }

    pub fn phase(&self) -> PairingPhase {
        self.phase
    }

    /// Remaining failed-attempt budget, for the UI.
    pub fn attempts_left(&self) -> u32 {
        PAIRING_ATTEMPTS_MAX.saturating_sub(self.failures)
    }

    /// The code this session is paired with, if any. Callers that print it must go
    /// through [`Code::reveal_for_user`]; nothing here prints it.
    pub fn code(&self) -> Option<&Code> {
        self.code.as_ref()
    }

    pub fn mode(&self) -> HelloMode {
        self.mode
    }

    /// Whether the code's unused-code TTL has passed at `now`.
    pub fn is_expired(&self, now: Instant) -> bool {
        now.duration_since(self.created) >= PAIRING_CODE_TTL
    }

    /// Whether the active handshake deadline has passed at `now`.
    ///
    /// Only meaningful while a guest is connected; the timer starts at `Hello`, not
    /// at advertisement, so a code that sits unused is not penalised.
    pub fn is_handshake_expired(&self, now: Instant) -> bool {
        self.deadline.is_some_and(|deadline| now >= deadline)
    }

    /// The deadline the caller should arm a timer for, if any.
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Expire an unused code. Returns the outcome when this call changed anything.
    pub fn expire(&mut self, now: Instant) -> Option<Outcome> {
        if self.phase == PairingPhase::WaitingForGuest && self.is_expired(now) {
            self.phase = PairingPhase::Burned;
            return Some(Outcome::Burned);
        }
        None
    }

    /// Handle a decoded CONTROL message from the guest.
    ///
    /// `now` drives both timers. `from` is the transport-authenticated peer
    /// identity; that is the only source of a `NodeId` we trust.
    pub fn on_message(&mut self, from: NodeId, message: ControlMsg, now: Instant) -> Result<Step> {
        if !message.allowed_before_auth() {
            // A forbidden message costs the peer nothing, so it must cost the code
            // nothing either: burning here would let any LAN host kill a code by
            // sending garbage, without even knowing the words.
            self.abort_handshake();
            return Ok(Step::ReplyThenClose {
                reply: Some(ControlMsg::Bye {
                    reason: ByeReason::Protocol,
                }),
                outcome: Outcome::ProtocolViolation,
            });
        }

        match &message {
            ControlMsg::Hello {
                version,
                mode,
                nameplate,
                ..
            } => {
                let hello_mode = *mode;
                let hello_nameplate = *nameplate;
                let hello_version = *version;
                // `Hello` is only legal as the first message.
                if self.phase != PairingPhase::WaitingForGuest {
                    return Ok(self.reject(if self.phase == PairingPhase::Pairing {
                        Outcome::Busy
                    } else {
                        Outcome::ProtocolViolation
                    }));
                }
                if hello_version != crate::constants::PROTOCOL_VERSION {
                    return Ok(self.reject(Outcome::ProtocolViolation));
                }
                if hello_mode != self.mode {
                    return Ok(self.reject(Outcome::ProtocolViolation));
                }
                if let Some(plate) = self.nameplate {
                    // §5.4 step 4: the nameplate must match. `self.nameplate` is
                    // `Some` exactly in code mode (`build` refuses `Trusted` and ties
                    // the field to the code), so a missing nameplate is a mismatch
                    // too — not a "mode without nameplates", which is ticket mode and
                    // has `self.nameplate == None`.
                    if hello_nameplate != Some(plate) {
                        // A wrong nameplate is not a guess: it is a misdial or a
                        // probe, and must not spend an attempt.
                        return Ok(self.reject(Outcome::ProtocolViolation));
                    }
                } else if hello_nameplate.is_some() {
                    // Ticket mode has no nameplate to compare against.
                    return Ok(self.reject(Outcome::ProtocolViolation));
                }
                if let Some(expiry) = self.expire(now) {
                    return Ok(Step::ReplyThenClose {
                        reply: Some(ControlMsg::Bye {
                            reason: expiry.bye_reason(),
                        }),
                        outcome: expiry,
                    });
                }

                self.guest_id = Some(from);
                self.phase = PairingPhase::Pairing;
                self.deadline = Some(now + HANDSHAKE_TIMEOUT);

                let password = &self.password;
                let (state, ours) = PakeState::start(Role::Host, password, from, self.host_id);
                self.our_pake_msg = ours.clone();
                self.pake = Some(state);
                Ok(Step::Reply(ControlMsg::PakeMsg { payload: ours }))
            }

            ControlMsg::PakeMsg { payload } => {
                if self.phase != PairingPhase::Pairing {
                    return Ok(self.violate());
                }
                if self.guest_id != Some(from) {
                    // A different NodeId mid-handshake. Do not abort: that would let
                    // any LAN host cancel a handshake it is not part of.
                    return Ok(self.reject(Outcome::ProtocolViolation));
                }
                if !self.peer_pake_msg.is_empty() || payload.len() != PAKE_MSG_LEN {
                    return Ok(self.violate());
                }
                let Some(pake) = self.pake.take() else {
                    return Ok(self.violate());
                };
                let key = match pake.finish(payload) {
                    Ok(key) => key,
                    Err(_) => {
                        // Malformed public share: a protocol violation, not a guess.
                        return Ok(self.violate());
                    }
                };
                self.peer_pake_msg = payload.clone();
                self.session_key = Some(key);
                // Send our confirmation first; the peer's is only accepted after.
                let transcript = Transcript::new(
                    self.mode,
                    from,
                    self.host_id,
                    &self.peer_pake_msg,
                    &self.our_pake_msg,
                )?;
                let mac = confirm_mac(Role::Host, self.session_key_ref()?, &transcript);
                self.sent_confirm = true;
                Ok(Step::Reply(ControlMsg::PakeConfirm { mac }))
            }

            ControlMsg::PakeConfirm { mac } => {
                if self.phase != PairingPhase::Pairing || !self.sent_confirm {
                    return Ok(self.reject(Outcome::ProtocolViolation));
                }
                let Some(guest) = self.guest_id else {
                    return Ok(self.reject(Outcome::ProtocolViolation));
                };
                if guest != from {
                    return Ok(self.reject(Outcome::ProtocolViolation));
                }
                let transcript = Transcript::new(
                    self.mode,
                    guest,
                    self.host_id,
                    &self.peer_pake_msg,
                    &self.our_pake_msg,
                )?;
                let key = self.session_key_ref()?;
                if verify_mac(Role::Guest, key, &transcript, mac).is_err() {
                    return Ok(self.fail_attempt());
                }
                self.phase = PairingPhase::Paired;
                self.deadline = None;
                // `Paired` only. The trust exchange of §5.4 step 9 is driven by the
                // caller (and its `Prompter`), not by this state machine: a MAC that
                // verifies is not yet consent to store anything (I18).
                Ok(Step::Reply(ControlMsg::Paired {
                    caps: crate::proto::messages::Caps::NONE,
                }))
            }

            ControlMsg::Ping => Ok(Step::Reply(ControlMsg::Pong)),

            ControlMsg::Bye { .. } => Ok(Step::ReplyThenClose {
                reply: None,
                outcome: Outcome::ProtocolViolation,
            }),

            // Everything else is refused: I2.
            _ => {
                self.abort_handshake();
                Ok(Step::ReplyThenClose {
                    reply: Some(ControlMsg::Bye {
                        reason: ByeReason::Protocol,
                    }),
                    outcome: Outcome::ProtocolViolation,
                })
            }
        }
    }

    /// Undo an in-progress handshake without spending an attempt.
    ///
    /// Used for every rejection that is *not* a wrong guess: a bad nameplate, a
    /// malformed share, a forbidden message. The peer may dial again and the code
    /// is still valid.
    fn abort_handshake(&mut self) {
        if self.phase == PairingPhase::Paired {
            // A finished pairing keeps its key; the caller decides the connection's
            // fate. Nothing here may roll that back.
            return;
        }
        if self.phase == PairingPhase::Pairing {
            self.phase = PairingPhase::WaitingForGuest;
        }
        self.deadline = None;
        self.pake = None;
        self.guest_id = None;
        self.our_pake_msg.clear();
        self.peer_pake_msg.clear();
        self.sent_confirm = false;
        self.session_key = None;
    }

    fn session_key_ref(&self) -> Result<&crate::secret::Secret<[u8; 32]>> {
        self.session_key
            .as_ref()
            .ok_or_else(|| PairingError::BadMessage.into())
    }

    fn reject(&mut self, outcome: Outcome) -> Step {
        Step::ReplyThenClose {
            reply: Some(ControlMsg::Bye {
                reason: outcome.bye_reason(),
            }),
            outcome,
        }
    }

    /// Refuse *and* discard the in-progress handshake.
    ///
    /// Distinct from [`Self::reject`]: a second `Hello` must leave the first guest
    /// untouched, but a malformed message from the guest we are already talking to
    /// ends that exchange. Without this, one bad frame could park the code in
    /// `Pairing` forever and a legitimate guest could never start.
    fn violate(&mut self) -> Step {
        self.abort_handshake();
        self.reject(Outcome::ProtocolViolation)
    }

    /// Count one failed guess, burning the code on the last one.
    fn fail_attempt(&mut self) -> Step {
        self.failures += 1;
        if self.failures >= PAIRING_ATTEMPTS_MAX {
            self.phase = PairingPhase::Burned;
            self.abort_handshake();
            Step::ReplyThenClose {
                reply: Some(ControlMsg::Bye {
                    reason: ByeReason::Burned,
                }),
                outcome: Outcome::Burned,
            }
        } else {
            // The counter lives on this object, which outlives the connection:
            // reconnecting cannot reset it (I3).
            self.abort_handshake();
            Step::ReplyThenClose {
                reply: Some(ControlMsg::Bye {
                    reason: ByeReason::Protocol,
                }),
                outcome: Outcome::Failed,
            }
        }
    }

    /// Called by the caller when its timer fires. Distinguishes "the guest never
    /// showed up" (no attempt spent) from "the guest went silent after starting".
    pub fn on_timeout(&mut self, now: Instant) -> Option<Outcome> {
        match self.phase {
            PairingPhase::Pairing => {
                // A silent guest after Hello is *not* a guess: it spent no words.
                // Policy recorded in the report: it does not consume an attempt.
                self.abort_handshake();
                Some(Outcome::TimedOut)
            }
            PairingPhase::WaitingForGuest => {
                if self.is_expired(now) {
                    self.phase = PairingPhase::Burned;
                    Some(Outcome::Burned)
                } else {
                    None
                }
            }
            PairingPhase::Paired | PairingPhase::Burned | PairingPhase::Aborted => None,
        }
    }

    /// The session key, valid only after the guest's MAC verified.
    ///
    /// The SPAKE2 output exists as soon as the guest's share arrives, because our
    /// own confirmation MAC is computed from it (see the private `session_key_ref`).
    /// It is not *readable* until then: before the peer's MAC verifies it proves
    /// nothing — a man in the middle relaying two independent SPAKE2 runs holds a
    /// perfectly good key of its own, and a wrong guess derives a different one.
    pub fn session_key(&self) -> Option<&crate::secret::Secret<[u8; 32]>> {
        if self.phase != PairingPhase::Paired {
            return None;
        }
        self.session_key.as_ref()
    }

    /// How long until the caller should call [`Self::on_timeout`] again.
    pub fn next_timer(&self, now: Instant) -> Option<Duration> {
        if let Some(deadline) = self.deadline {
            return Some(deadline.saturating_duration_since(now));
        }
        if self.phase == PairingPhase::WaitingForGuest {
            let expires = self.created + PAIRING_CODE_TTL;
            return Some(expires.saturating_duration_since(now));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code::Nameplate;
    use crate::code::{Code, WordCount};
    use crate::secret::SecretString;
    use rand::SeedableRng;

    fn session_on(mode: HelloMode) -> (HostSession, Code, NodeId, NodeId) {
        session_at(mode, Instant::now())
    }

    /// Same, but pinned to a caller-supplied start time so the timers are exact.
    fn session_at(mode: HelloMode, now: Instant) -> (HostSession, Code, NodeId, NodeId) {
        let host_id = NodeId::from_bytes([7u8; 32]);
        let guest_id = NodeId::from_bytes([9u8; 32]);
        let plate = Nameplate::new(42).unwrap();
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let code = Code::generate(&mut rng, WordCount::Two, plate).unwrap();
        let session = HostSession::new(host_id, mode, code.clone(), now).unwrap();
        (session, code, host_id, guest_id)
    }

    fn hello(mode: HelloMode, plate: u16) -> ControlMsg {
        ControlMsg::Hello {
            version: crate::constants::PROTOCOL_VERSION,
            mode,
            nameplate: Some(plate),
            resume: None,
        }
    }

    #[test]
    fn a_valid_hello_starts_the_pake_and_arms_the_deadline() {
        let (mut s, _code, _h, guest) = session_on(HelloMode::OneShot);
        let now = Instant::now();
        let step = s
            .on_message(guest, hello(HelloMode::OneShot, 42), now)
            .unwrap();
        match step {
            Step::Reply(ControlMsg::PakeMsg { payload }) => {
                assert_eq!(payload.len(), PAKE_MSG_LEN)
            }
            other => panic!("expected PakeMsg, got {other:?}"),
        }
        assert_eq!(s.phase(), PairingPhase::Pairing);
        assert_eq!(s.deadline(), Some(now + HANDSHAKE_TIMEOUT));
        assert!(s.phase().advertises());
    }

    #[test]
    fn a_wrong_nameplate_is_refused_without_spending_an_attempt() {
        let (mut s, _code, _h, guest) = session_on(HelloMode::OneShot);
        let step = s
            .on_message(guest, hello(HelloMode::OneShot, 43), Instant::now())
            .unwrap();
        assert!(matches!(
            step,
            Step::ReplyThenClose {
                outcome: Outcome::ProtocolViolation,
                ..
            }
        ));
        assert_eq!(s.attempts_left(), PAIRING_ATTEMPTS_MAX);
    }

    #[test]
    fn a_code_host_refuses_a_hello_without_a_nameplate() {
        // §5.4 step 4: the host checks the nameplate matches. A `Hello` that omits
        // it cannot match, so it must be refused. The old `else if ... != OneShot
        // && ... != Pair` guard could never fire: `build` refuses `Trusted`, so
        // `nameplate.is_some()` implies one of the two code modes. The effect was
        // that a code-mode guest could skip the check altogether.
        let (mut s, _code, _h, guest) = session_on(HelloMode::OneShot);
        let step = s
            .on_message(
                guest,
                ControlMsg::Hello {
                    version: crate::constants::PROTOCOL_VERSION,
                    mode: HelloMode::OneShot,
                    nameplate: None,
                    resume: None,
                },
                Instant::now(),
            )
            .unwrap();
        assert!(
            matches!(
                step,
                Step::ReplyThenClose {
                    outcome: Outcome::ProtocolViolation,
                    ..
                }
            ),
            "a Hello without a nameplate must be refused, got {step:?}"
        );
        assert_eq!(s.phase(), PairingPhase::WaitingForGuest);
        assert_eq!(s.attempts_left(), PAIRING_ATTEMPTS_MAX);
    }

    #[test]
    fn a_second_guest_is_rejected_and_the_first_survives() {
        let (mut s, _code, _h, guest) = session_on(HelloMode::OneShot);
        let now = Instant::now();
        s.on_message(guest, hello(HelloMode::OneShot, 42), now)
            .unwrap();
        let other = NodeId::from_bytes([11u8; 32]);
        let step = s
            .on_message(other, hello(HelloMode::OneShot, 42), now)
            .unwrap();
        assert!(matches!(
            step,
            Step::ReplyThenClose {
                outcome: Outcome::Busy,
                ..
            }
        ));
        assert_eq!(s.phase(), PairingPhase::Pairing);
        assert_eq!(s.attempts_left(), PAIRING_ATTEMPTS_MAX);
    }

    #[test]
    fn a_forbidden_message_before_auth_closes_the_session() {
        let (mut s, _code, _h, guest) = session_on(HelloMode::OneShot);
        let step = s
            .on_message(
                guest,
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
    fn a_silent_guest_does_not_consume_an_attempt() {
        let (mut s, _code, _h, guest) = session_on(HelloMode::OneShot);
        s.on_message(guest, hello(HelloMode::OneShot, 42), Instant::now())
            .unwrap();
        let outcome = s.on_timeout(Instant::now() + HANDSHAKE_TIMEOUT).unwrap();
        assert_eq!(outcome, Outcome::TimedOut);
        assert_eq!(s.attempts_left(), PAIRING_ATTEMPTS_MAX);
        assert_eq!(s.phase(), PairingPhase::WaitingForGuest);
    }

    #[test]
    fn debug_never_prints_the_words() {
        let (s, code, host_id, _g) = session_on(HelloMode::Pair);
        let text = format!("{s:?}");
        let words = code.password().expose_secret().clone();
        for word in words.split('-') {
            assert!(!text.contains(word), "Debug leaked a word");
        }
        // Redaction must not turn into silence: with all the fields dropped this
        // text would still pass the loop above while telling a reader nothing.
        assert!(text.contains("HostSession"), "Debug lost the type: {text}");
        assert!(text.contains("phase"), "Debug lost the phase: {text}");
        assert!(
            text.contains(&host_id.prefix8()),
            "Debug lost the host id: {text}"
        );
    }

    #[test]
    fn a_trusted_mode_session_cannot_be_constructed() {
        let plate = Nameplate::new(5).unwrap();
        let mut rng = rand::rngs::StdRng::seed_from_u64(2);
        let code = Code::generate(&mut rng, WordCount::Two, plate).unwrap();
        assert!(HostSession::new(
            NodeId::from_bytes([1u8; 32]),
            HelloMode::Trusted,
            code,
            Instant::now()
        )
        .is_err());
    }

    #[test]
    fn unused_codes_expire_and_burn() {
        let (mut s, _code, _h, _g) = session_on(HelloMode::OneShot);
        let later = Instant::now() + PAIRING_CODE_TTL;
        assert_eq!(s.expire(later), Some(Outcome::Burned));
        assert_eq!(s.phase(), PairingPhase::Burned);
        assert!(!s.phase().advertises());
    }

    #[test]
    fn session_key_is_absent_until_confirmed() {
        let (mut s, _code, _h, guest) = session_on(HelloMode::OneShot);
        s.on_message(guest, hello(HelloMode::OneShot, 42), Instant::now())
            .unwrap();
        assert!(s.session_key().is_none());
    }

    #[test]
    fn the_key_is_held_back_until_the_guest_mac_verifies() {
        let (mut s, code, host_id, guest) = session_on(HelloMode::OneShot);
        let now = Instant::now();
        let step = s
            .on_message(guest, hello(HelloMode::OneShot, 42), now)
            .unwrap();
        assert!(matches!(step, Step::Reply(ControlMsg::PakeMsg { .. })));

        // The guest's share arrives: SPAKE2 yields a key, which the host needs for
        // its own MAC. That is not yet proof of anything — a guest who guessed
        // wrong derives a *different* key and its MAC will not verify.
        let (_pake, guest_share) = PakeState::start(Role::Guest, &code.password(), guest, host_id);
        let step = s
            .on_message(
                guest,
                ControlMsg::PakeMsg {
                    payload: guest_share,
                },
                now,
            )
            .unwrap();
        assert!(
            matches!(step, Step::Reply(ControlMsg::PakeConfirm { .. })),
            "the unverified stage still produces our confirmation, got {step:?}"
        );
        assert!(
            s.session_key().is_none(),
            "the key must not be readable before the guest's MAC verified"
        );

        assert_eq!(s.phase(), PairingPhase::Pairing);
    }

    #[test]
    fn an_empty_password_type_is_still_redacted() {
        let s = SecretString::from_string("x".to_string());
        assert_eq!(format!("{s:?}"), "[redacted]");
    }

    #[test]
    fn a_code_session_exposes_its_code_and_a_ticket_session_does_not() {
        // `code()` gates every caller that prints or stores the code, so a `None`
        // that never becomes `Some` would silently hide the one value the user needs.
        let (s, code, _h, _g) = session_on(HelloMode::OneShot);
        let held = s.code().expect("a code session holds its code");
        assert_eq!(
            held.password().expose_secret(),
            code.password().expose_secret()
        );

        let password = SecretString::from_string("ticket-secret".to_string());
        let ticket = HostSession::new_with_password(
            NodeId::from_bytes([3u8; 32]),
            HelloMode::OneShot,
            &password,
            Instant::now(),
        )
        .unwrap();
        assert!(ticket.code().is_none(), "ticket mode carries no code");
    }

    #[test]
    fn next_timer_follows_the_deadline_then_the_ttl_then_stops() {
        let now = Instant::now();
        let (mut s, _code, _h, guest) = session_at(HelloMode::OneShot, now);

        // Idle: the only thing pending is the code's own TTL.
        assert_eq!(s.next_timer(now), Some(PAIRING_CODE_TTL));

        // Mid-handshake the handshake deadline takes over, and it is shorter.
        s.on_message(guest, hello(HelloMode::OneShot, 42), now)
            .unwrap();
        assert_eq!(
            s.next_timer(now),
            Some(HANDSHAKE_TIMEOUT),
            "the armed deadline must win over the TTL"
        );
        assert_eq!(s.next_timer(now + HANDSHAKE_TIMEOUT), Some(Duration::ZERO));

        // A burned code is terminal with no deadline armed: nothing is left to
        // wait for, and reporting a TTL here would keep the caller's timer alive
        // forever.
        let (mut burned, _code, _h, _g) = session_at(HelloMode::OneShot, now);
        assert_eq!(burned.expire(now + PAIRING_CODE_TTL), Some(Outcome::Burned));
        assert_eq!(burned.phase(), PairingPhase::Burned);
        assert_eq!(burned.deadline(), None, "expiry arms no deadline");
        assert_eq!(burned.next_timer(now), None);
    }

    #[test]
    fn the_ttl_timer_is_measured_from_creation_not_from_now() {
        // A `created + TTL` that was really `now + TTL` would keep pushing the
        // expiry back, and an unused code would never burn.
        let now = Instant::now();
        let (s, _code, _h, _g) = session_at(HelloMode::OneShot, now);
        let later = now + Duration::from_secs(60);
        assert_eq!(
            s.next_timer(later),
            Some(PAIRING_CODE_TTL - Duration::from_secs(60))
        );
        assert_eq!(
            s.next_timer(now + PAIRING_CODE_TTL),
            Some(Duration::ZERO),
            "the timer must not go negative at the TTL"
        );
    }

    #[test]
    fn a_bye_from_the_guest_finishes_the_step_without_echoing_one() {
        // The host never answers a `Bye` with a `Bye`: the peer already left, and
        // replying would turn one clean shutdown into a message the peer cannot read.
        let (mut s, _code, _h, guest) = session_on(HelloMode::OneShot);
        let step = s
            .on_message(
                guest,
                ControlMsg::Bye {
                    reason: ByeReason::Normal,
                },
                Instant::now(),
            )
            .unwrap();
        assert_eq!(
            step,
            Step::ReplyThenClose {
                reply: None,
                outcome: Outcome::ProtocolViolation,
            }
        );
    }

    #[test]
    fn a_replayed_guest_share_is_refused() {
        // `peer_pake_msg` must already hold the first share: without that guard a
        // second `PakeMsg` would try to drive a consumed SPAKE2 state.
        let (mut s, code, host_id, guest) = session_on(HelloMode::OneShot);
        let now = Instant::now();
        s.on_message(guest, hello(HelloMode::OneShot, 42), now)
            .unwrap();
        let (_pake, guest_share) = PakeState::start(Role::Guest, &code.password(), guest, host_id);
        let first = s
            .on_message(
                guest,
                ControlMsg::PakeMsg {
                    payload: guest_share.clone(),
                },
                now,
            )
            .unwrap();
        assert!(matches!(first, Step::Reply(ControlMsg::PakeConfirm { .. })));

        let replay = s
            .on_message(
                guest,
                ControlMsg::PakeMsg {
                    payload: guest_share,
                },
                now,
            )
            .unwrap();
        assert!(
            matches!(
                replay,
                Step::ReplyThenClose {
                    outcome: Outcome::ProtocolViolation,
                    ..
                }
            ),
            "a second share on one handshake must be refused, got {replay:?}"
        );
    }

    #[test]
    fn a_guest_mac_before_our_confirmation_is_refused() {
        // `sent_confirm` guards the MAC check: accepting the peer's MAC first would
        // let the guest learn whether its own MAC matched before proving anything.
        let (mut s, code, host_id, guest) = session_on(HelloMode::OneShot);
        let now = Instant::now();
        s.on_message(guest, hello(HelloMode::OneShot, 42), now)
            .unwrap();

        let step = s
            .on_message(guest, ControlMsg::PakeConfirm { mac: [0u8; 32] }, now)
            .unwrap();
        assert!(
            matches!(
                step,
                Step::ReplyThenClose {
                    outcome: Outcome::ProtocolViolation,
                    ..
                }
            ),
            "a MAC before we sent ours must be refused, got {step:?}"
        );
        assert_eq!(s.attempts_left(), PAIRING_ATTEMPTS_MAX);
        let _ = (code, host_id);
    }
}
