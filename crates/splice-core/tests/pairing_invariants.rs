//! Cross-module pairing invariants (§13, Step 8 of the Phase 1 brief).
//!
//! The per-module tests in `src/pairing/` cover the state machines in isolation.
//! This file checks the properties that only appear once the pieces are combined:
//! the crate's public API, the wire bytes, the real SPAKE2 primitives, and — for
//! the happy path — two sessions talking over the in-memory transport.
//!
//! Nothing here touches a socket, a clock, or the filesystem. The one test that
//! needs a transport uses [`splice_core::net::memory`], so it runs offline and on
//! every platform.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use splice_core::code::Code;
use splice_core::constants::{HANDSHAKE_TIMEOUT, PAIRING_ATTEMPTS_MAX};
use splice_core::identity::NodeId;
use splice_core::net::memory::Network;
use splice_core::net::{RecvStream, SendStream, Transport};
use splice_core::pairing::pake::Role;
use splice_core::pairing::{
    confirm_mac, verify_mac, GuestSession, HostSession, Outcome, PairingPhase, Step, Transcript,
};
use splice_core::proto::frame::{self, Frame, FrameKind};
use splice_core::proto::messages::WireMessage;
use splice_core::proto::{ControlMsg, HelloMode};
use splice_core::secret::Secret;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroize;

/// A fixed code, so no test depends on an RNG. `Code::parse` also re-validates the
/// words against the vendored list, so a typo here fails loudly.
const CODE: &str = "42-torch-crystal";
/// Same nameplate, one different word: a wrong guess that is still a *well-formed*
/// guess, which is the only kind that may spend an attempt.
const WRONG_CODE: &str = "42-torch-zebra";

fn code(text: &str) -> Code {
    Code::parse(text).expect("test code must parse")
}

fn id(seed: u8) -> NodeId {
    NodeId::from_bytes([seed; 32])
}

/// The two identities every test uses. Distinct bytes so a swap is detectable.
fn ids() -> (NodeId, NodeId) {
    (id(0x11), id(0x22))
}

fn hello(mode: HelloMode, nameplate: u16) -> ControlMsg {
    ControlMsg::Hello {
        version: splice_core::constants::PROTOCOL_VERSION,
        mode,
        nameplate: Some(nameplate),
        resume: None,
    }
}

/// Every CONTROL message a peer might send before it is authenticated.
fn early_messages() -> Vec<ControlMsg> {
    vec![
        ControlMsg::ConsentResult { granted: true },
        ControlMsg::ModeChange { interactive: true },
        ControlMsg::ResumeChallenge { nonce: [1u8; 32] },
        ControlMsg::ResumeProof { proof: [2u8; 32] },
    ]
}

/// Wire bytes for a sequence of CONTROL messages, as they would appear on the
/// CONTROL stream: a frame header plus a postcard body, one frame per message.
fn wire_bytes(messages: &[ControlMsg]) -> Vec<u8> {
    let mut out = Vec::new();
    for message in messages {
        out.extend_from_slice(&Frame::control(message).expect("frame").encode());
    }
    out
}

/// A byte needle that is unlikely to occur by accident in a 33-byte public share.
/// The words are checked as ASCII, exactly as they would appear if leaked.
fn contains_ascii(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

/// Pull the message out of a `Step::Reply`, failing with the actual step otherwise.
fn expect_reply(step: Step) -> ControlMsg {
    match step {
        Step::Reply(message) => message,
        other => panic!("expected a reply, got {other:?}"),
    }
}

/// Drive one code exchange to `Paired` and return both sides plus every message
/// that crossed the wire.
///
/// The order mirrors the wire: the guest opens with `Hello` + its share, the host
/// answers with its share, and the two `PakeConfirm`s cross.
fn run_to_paired(mode: HelloMode) -> (HostSession, GuestSession, Vec<ControlMsg>) {
    let (guest_id, host_id) = ids();
    let now = Instant::now();
    let mut host = HostSession::new(host_id, mode, code(CODE), now).expect("host session");
    let (mut guest, opening) =
        GuestSession::begin(guest_id, host_id, mode, code(CODE), now).expect("guest session");

    let hello_message = opening[0].clone();
    let guest_share = opening[1].clone();
    let mut sent = opening.clone();

    // Host: Hello -> our share.
    let host_share = expect_reply(
        host.on_message(guest_id, hello_message, now)
            .expect("hello"),
    );
    sent.push(host_share.clone());

    // Host: guest share -> host confirmation MAC.
    let host_mac = expect_reply(
        host.on_message(guest_id, guest_share, now)
            .expect("guest share"),
    );
    sent.push(host_mac.clone());

    // Guest: host share -> guest confirmation MAC.
    let guest_mac = expect_reply(
        guest
            .on_message(host_id, host_share, now)
            .expect("host share"),
    );
    sent.push(guest_mac.clone());

    // Guest: host MAC -> Paired locally.
    assert_eq!(
        guest.on_message(host_id, host_mac, now).expect("host mac"),
        Step::Idle
    );
    assert_eq!(guest.phase(), PairingPhase::Paired);

    // Host: guest MAC -> Paired and the `Paired` announcement.
    let announcement = expect_reply(
        host.on_message(guest_id, guest_mac, now)
            .expect("guest mac"),
    );
    sent.push(announcement.clone());
    assert_eq!(host.phase(), PairingPhase::Paired);
    assert!(matches!(announcement, ControlMsg::Paired { .. }));

    // Guest: the announcement is a duplicate of what its own MAC check proved.
    assert_eq!(
        guest
            .on_message(host_id, announcement, now)
            .expect("announcement"),
        Step::Idle
    );

    (host, guest, sent)
}

// ---------------------------------------------------------------------------
// I1 — the words never leave the process in readable form.
// ---------------------------------------------------------------------------

/// Every word of the test code, as it would appear in a leak.
fn secret_words() -> Vec<String> {
    code(CODE)
        .password()
        .expose_secret()
        .split('-')
        .map(str::to_owned)
        .collect()
}

#[test]
fn i1_no_secret_words_in_debug_output() {
    let (host, guest, _sent) = run_to_paired(HelloMode::Pair);
    let rendered = format!(
        "{host:?}\n{guest:?}\n{:?}\n{:?}",
        code(CODE),
        guest.session_key().expect("key after pairing")
    );
    for word in secret_words() {
        assert!(
            !rendered.contains(word.as_str()),
            "Debug output leaked the word {word:?}"
        );
    }
    // The redaction marker is present, so the test above is not passing by
    // rendering nothing at all.
    assert!(rendered.contains("[redacted]"));
}

#[test]
fn i1_no_secret_words_on_the_wire() {
    let (_host, _guest, sent) = run_to_paired(HelloMode::Pair);
    let bytes = wire_bytes(&sent);
    assert!(!bytes.is_empty());
    for word in secret_words() {
        assert!(
            !contains_ascii(&bytes, word.as_str()),
            "a CONTROL frame carried the word {word:?} in cleartext"
        );
    }
}

#[test]
fn i1_no_secret_words_in_error_strings() {
    let (guest_id, host_id) = ids();
    let now = Instant::now();
    let mut host = HostSession::new(host_id, HelloMode::OneShot, code(CODE), now).expect("host");
    let (mut guest, opening) =
        GuestSession::begin(guest_id, host_id, HelloMode::OneShot, code(WRONG_CODE), now)
            .expect("guest");

    let host_share = expect_reply(
        host.on_message(guest_id, opening[0].clone(), now)
            .expect("hello"),
    );
    let _host_mac = expect_reply(
        host.on_message(guest_id, opening[1].clone(), now)
            .expect("share"),
    );
    let guest_mac = expect_reply(
        guest
            .on_message(host_id, host_share, now)
            .expect("host share"),
    );
    let step = host
        .on_message(guest_id, guest_mac, now)
        .expect("confirmation");
    let text = format!("{step:?}");

    // A wrong guess reports a generic protocol failure, not which word was wrong.
    assert!(matches!(
        step,
        Step::ReplyThenClose {
            outcome: Outcome::Failed,
            ..
        }
    ));
    for word in secret_words() {
        assert!(!text.contains(word.as_str()), "error path leaked {word:?}");
    }
    assert!(
        !text.contains("zebra"),
        "the guess itself must not be echoed"
    );
}

// ---------------------------------------------------------------------------
// I2 — nothing but the pairing exchange is processed before authentication.
// ---------------------------------------------------------------------------

#[test]
fn i2_a_host_refuses_every_early_application_message() {
    let (guest_id, host_id) = ids();
    let now = Instant::now();

    for message in early_messages() {
        // Before `Hello`.
        let mut waiting =
            HostSession::new(host_id, HelloMode::OneShot, code(CODE), now).expect("host");
        let step = waiting
            .on_message(guest_id, message.clone(), now)
            .expect("message");
        assert!(
            matches!(
                step,
                Step::ReplyThenClose {
                    outcome: Outcome::ProtocolViolation,
                    ..
                }
            ),
            "{} was accepted before Hello",
            message.name()
        );
        assert_eq!(waiting.phase(), PairingPhase::WaitingForGuest);
        assert_eq!(
            waiting.attempts_left(),
            PAIRING_ATTEMPTS_MAX,
            "an early message must not spend an attempt"
        );

        // Mid-handshake, from the guest we are already talking to.
        let mut pairing =
            HostSession::new(host_id, HelloMode::OneShot, code(CODE), now).expect("host");
        pairing
            .on_message(guest_id, hello(HelloMode::OneShot, 42), now)
            .expect("hello");
        let step = pairing
            .on_message(guest_id, message.clone(), now)
            .expect("message");
        assert!(
            matches!(
                step,
                Step::ReplyThenClose {
                    outcome: Outcome::ProtocolViolation,
                    ..
                }
            ),
            "{} was accepted mid-handshake",
            message.name()
        );
        assert_eq!(pairing.attempts_left(), PAIRING_ATTEMPTS_MAX);
    }
}

#[test]
fn i2_a_guest_refuses_every_early_application_message() {
    let (guest_id, host_id) = ids();
    let now = Instant::now();

    for message in early_messages() {
        let (mut guest, _opening) =
            GuestSession::begin(guest_id, host_id, HelloMode::OneShot, code(CODE), now)
                .expect("guest");
        let step = guest
            .on_message(host_id, message.clone(), now)
            .expect("message");
        assert!(
            matches!(
                step,
                Step::ReplyThenClose {
                    outcome: Outcome::ProtocolViolation,
                    ..
                }
            ),
            "{} was accepted before confirmation",
            message.name()
        );
        assert_eq!(guest.phase(), PairingPhase::Burned);
    }
}

// ---------------------------------------------------------------------------
// I3 — the attempt counter lives on the host and survives reconnects.
// ---------------------------------------------------------------------------

/// One full guess against `host`, as a reconnecting guest would make it
/// (`Hello` + share + both confirmations, on a fresh session).
///
/// Each call uses a fresh [`GuestSession`], which is what "reconnect" means on the
/// wire: the attacker never gets to keep state between attempts.
fn attempt(
    host: &mut HostSession,
    host_id: NodeId,
    guest_id: NodeId,
    guess: &str,
    now: Instant,
) -> Step {
    let (mut guest, opening) =
        GuestSession::begin(guest_id, host_id, host.mode(), code(guess), now).expect("guest");
    // A burned or already-paired host refuses at `Hello`, before any PAKE work.
    let host_share = match host
        .on_message(guest_id, opening[0].clone(), now)
        .expect("hello")
    {
        Step::Reply(message) => message,
        closing => return closing,
    };
    let _host_mac = expect_reply(
        host.on_message(guest_id, opening[1].clone(), now)
            .expect("guest share"),
    );
    let guest_mac = expect_reply(
        guest
            .on_message(host_id, host_share, now)
            .expect("host share"),
    );
    host.on_message(guest_id, guest_mac, now)
        .expect("guest mac")
}

#[test]
fn i3_three_wrong_guesses_burn_the_code_and_the_counter_survives_reconnects() {
    let (guest_id, host_id) = ids();
    let now = Instant::now();
    let mut host = HostSession::new(host_id, HelloMode::OneShot, code(CODE), now).expect("host");
    assert_eq!(host.attempts_left(), PAIRING_ATTEMPTS_MAX);

    for spent in 1..=PAIRING_ATTEMPTS_MAX {
        let step = attempt(&mut host, host_id, guest_id, WRONG_CODE, now);
        let expected = if spent == PAIRING_ATTEMPTS_MAX {
            Outcome::Burned
        } else {
            Outcome::Failed
        };
        match step {
            Step::ReplyThenClose { outcome, .. } => assert_eq!(
                outcome, expected,
                "attempt {spent} of {PAIRING_ATTEMPTS_MAX} reported the wrong outcome"
            ),
            other => panic!("attempt {spent}: expected close, got {other:?}"),
        }
        // The counter never goes back up: the reconnects above each built a new
        // guest session, and each one cost exactly one attempt.
        assert_eq!(
            host.attempts_left(),
            PAIRING_ATTEMPTS_MAX - spent,
            "the counter must be a property of the code, not of the connection"
        );
    }

    assert_eq!(host.phase(), PairingPhase::Burned);
    assert!(
        !host.phase().advertises(),
        "a burned code must stop advertising"
    );
    assert!(host.session_key().is_none());
}

#[test]
fn i3_a_fourth_attempt_with_the_correct_words_is_refused() {
    let (guest_id, host_id) = ids();
    let now = Instant::now();
    let mut host = HostSession::new(host_id, HelloMode::OneShot, code(CODE), now).expect("host");
    for _ in 0..PAIRING_ATTEMPTS_MAX {
        let _ = attempt(&mut host, host_id, guest_id, WRONG_CODE, now);
    }
    assert_eq!(host.phase(), PairingPhase::Burned);

    let step = attempt(&mut host, host_id, guest_id, CODE, now);
    match step {
        Step::ReplyThenClose { outcome, .. } => {
            assert_eq!(
                outcome,
                Outcome::ProtocolViolation,
                "a burned code must refuse even the right words"
            );
        }
        other => panic!("the fourth attempt must be refused, got {other:?}"),
    }
    assert!(host.session_key().is_none(), "no key may be derived");
    assert_eq!(host.phase(), PairingPhase::Burned);
}

// ---------------------------------------------------------------------------
// I4 — a paired code never pairs a second time.
// ---------------------------------------------------------------------------

#[test]
fn i4_a_paired_code_cannot_pair_again() {
    let (guest_id, host_id) = ids();
    let now = Instant::now();
    let mut host = HostSession::new(host_id, HelloMode::OneShot, code(CODE), now).expect("host");
    let step = attempt(&mut host, host_id, guest_id, CODE, now);
    match step {
        Step::Reply(ControlMsg::Paired { .. }) => {}
        other => panic!("the first attempt must pair, got {other:?}"),
    }
    assert_eq!(host.phase(), PairingPhase::Paired);
    assert!(
        !host.phase().advertises(),
        "the code is spent, so it stops advertising"
    );

    let key_before = host
        .session_key()
        .expect("key after pairing")
        .expose_secret()
        .to_owned();

    // A second guest with the right words, on a fresh connection.
    let step = attempt(&mut host, host_id, guest_id, CODE, now);
    match step {
        Step::ReplyThenClose { outcome, .. } => assert_eq!(outcome, Outcome::ProtocolViolation),
        other => panic!("a paired code must refuse a second pairing, got {other:?}"),
    }
    assert_eq!(host.phase(), PairingPhase::Paired);
    assert_eq!(
        host.session_key().expect("key").expose_secret(),
        &key_before,
        "a refused second guest must not replace the first guest's key"
    );
}

// ---------------------------------------------------------------------------
// I11 — the secrets are held in zeroizing, unprintable types.
// ---------------------------------------------------------------------------

#[test]
fn i11_dropping_a_secret_zeroizes_its_contents() {
    struct Watched {
        buffer: Arc<Mutex<Vec<u8>>>,
        zeroized: Arc<AtomicUsize>,
    }

    impl Zeroize for Watched {
        fn zeroize(&mut self) {
            self.buffer.lock().expect("probe").fill(0);
            self.zeroized.fetch_add(1, Ordering::SeqCst);
        }
    }

    let buffer = Arc::new(Mutex::new(code(CODE).password().into_inner().into_bytes()));
    let zeroized = Arc::new(AtomicUsize::new(0));
    {
        let secret = Secret::new(Watched {
            buffer: Arc::clone(&buffer),
            zeroized: Arc::clone(&zeroized),
        });
        assert!(!secret.expose_secret().buffer.lock().unwrap().is_empty());
    }
    assert_eq!(zeroized.load(Ordering::SeqCst), 1);
    assert!(
        buffer.lock().unwrap().iter().all(|byte| *byte == 0),
        "the passphrase bytes must be overwritten on drop"
    );
}

#[test]
fn i11_an_explicit_zeroize_clears_a_live_secret() {
    let mut secret = Secret::new(b"torch-crystal".to_vec());
    assert_eq!(secret.expose_secret().len(), 13);
    secret.zeroize();
    assert!(
        secret.expose_secret().is_empty(),
        "a zeroized buffer must not keep its contents"
    );
}

#[test]
fn i11_the_password_and_key_are_unprintable() {
    let (host, guest, _sent) = run_to_paired(HelloMode::Pair);
    let password = code(CODE).password();
    let key = guest.session_key().expect("key after pairing");

    // I1 and I11 meet here: the type that zeroizes is also the type that redacts.
    assert_eq!(format!("{password:?}"), "[redacted]");
    assert_eq!(format!("{key:?}"), "[redacted]");
    assert!(
        host.session_key().is_some(),
        "the host keeps the same kind of secret"
    );
    assert_eq!(
        format!("{:?}", host.session_key().expect("key")),
        "[redacted]"
    );
}

// ---------------------------------------------------------------------------
// MITM: two shapes of attacker, both must fail key confirmation.
// ---------------------------------------------------------------------------

/// Shape (a): the attacker sits on the wire and forwards every byte unchanged,
/// but the transport authenticated *its* NodeId, not the peers'.
///
/// Nothing the attacker sends is modified. It still fails, twice over: the keys
/// differ because SPAKE2 is bound to the NodeIds, and the transcripts differ
/// because the MAC covers those same NodeIds.
#[test]
fn mitm_a_a_verbatim_relay_between_two_node_ids_fails_both_confirmations() {
    let me = NodeId::from_bytes([0x33; 32]);
    let (guest_id, host_id) = ids();
    let now = Instant::now();

    let mut host = HostSession::new(host_id, HelloMode::OneShot, code(CODE), now).expect("host");
    // The guest believes it is talking to the attacker.
    let (mut guest, opening) =
        GuestSession::begin(guest_id, me, HelloMode::OneShot, code(CODE), now).expect("guest");

    // The attacker forwards the bytes. The host only ever sees the attacker's id.
    let host_share = expect_reply(host.on_message(me, opening[0].clone(), now).expect("hello"));
    let host_mac = expect_reply(host.on_message(me, opening[1].clone(), now).expect("share"));
    let guest_mac = expect_reply(guest.on_message(me, host_share, now).expect("host share"));

    // The host's own confirmation must not verify at the guest, and vice versa.
    match host.on_message(me, guest_mac, now).expect("guest mac") {
        Step::ReplyThenClose { outcome, .. } => assert_eq!(
            outcome,
            Outcome::Failed,
            "a relayed share must not pair the real host"
        ),
        other => panic!("expected the host to reject, got {other:?}"),
    }
    match guest.on_message(me, host_mac, now).expect("host mac") {
        Step::ReplyThenClose { outcome, .. } => assert_eq!(
            outcome,
            Outcome::Failed,
            "a relayed share must not pair the real guest"
        ),
        other => panic!("expected the guest to reject, got {other:?}"),
    }

    assert_eq!(host.phase(), PairingPhase::WaitingForGuest);
    assert_eq!(guest.phase(), PairingPhase::Burned);
    assert!(host.session_key().is_none());
    assert!(guest.session_key().is_none());
    // The code survives: a wrong guess costs one attempt, not the code.
    assert_eq!(host.attempts_left(), PAIRING_ATTEMPTS_MAX - 1);
}

/// Shape (b): the attacker runs its own SPAKE2 against each side, guessing the
/// words. A wrong guess fails key confirmation on the side it guesses against.
#[test]
fn mitm_b_own_spake2_with_a_wrong_guess_fails_key_confirmation() {
    let me = NodeId::from_bytes([0x44; 32]);
    let (guest_id, host_id) = ids();
    let now = Instant::now();

    // Attacker guesses the words, and plays host towards the real guest.
    let mut attacker_as_host =
        HostSession::new(me, HelloMode::OneShot, code(WRONG_CODE), now).expect("attacker host");
    let (mut guest, opening) =
        GuestSession::begin(guest_id, me, HelloMode::OneShot, code(CODE), now).expect("guest");

    let attacker_share = expect_reply(
        attacker_as_host
            .on_message(guest_id, opening[0].clone(), now)
            .expect("hello"),
    );
    let attacker_mac = expect_reply(
        attacker_as_host
            .on_message(guest_id, opening[1].clone(), now)
            .expect("share"),
    );
    let guest_mac = expect_reply(
        guest
            .on_message(me, attacker_share, now)
            .expect("attacker share"),
    );

    // The guess was wrong, so neither side confirms.
    match guest
        .on_message(me, attacker_mac, now)
        .expect("attacker mac")
    {
        Step::ReplyThenClose { outcome, .. } => assert_eq!(outcome, Outcome::Failed),
        other => panic!("expected the guest to reject a wrong guess, got {other:?}"),
    }
    match attacker_as_host
        .on_message(guest_id, guest_mac, now)
        .expect("guest mac")
    {
        Step::ReplyThenClose { outcome, .. } => assert_eq!(outcome, Outcome::Failed),
        other => panic!("expected the attacker to fail, got {other:?}"),
    }

    // And the real host is untouched by all of this.
    let real_host =
        HostSession::new(host_id, HelloMode::OneShot, code(CODE), now).expect("real host");
    assert_eq!(real_host.phase(), PairingPhase::WaitingForGuest);
    assert_eq!(real_host.attempts_left(), PAIRING_ATTEMPTS_MAX);
}

/// Pull the two `PakeMsg` payloads out of a captured exchange, in wire order.
fn pake_shares(sent: &[ControlMsg]) -> (Vec<u8>, Vec<u8>) {
    let mut shares = sent.iter().filter_map(|message| match message {
        ControlMsg::PakeMsg { payload } => Some(payload.clone()),
        _ => None,
    });
    let guest = shares.next().expect("guest share");
    let host = shares.next().expect("host share");
    (guest, host)
}

/// The transcript is what binds the key to *these* two peers. Change any single
/// field and the confirmation MAC stops verifying.
#[test]
fn mitm_c_changing_any_transcript_field_breaks_the_confirmation_mac() {
    let (host, _guest, sent) = run_to_paired(HelloMode::Pair);
    let (guest_share, host_share) = pake_shares(&sent);
    let (guest_id, host_id) = ids();
    let key = host.session_key().expect("key after pairing");

    let honest = Transcript::new(
        HelloMode::Pair,
        guest_id,
        host_id,
        &guest_share,
        &host_share,
    )
    .expect("transcript");
    let mac = confirm_mac(Role::Guest, key, &honest);
    verify_mac(Role::Guest, key, &honest, &mac).expect("the honest transcript must verify");

    // A different guest identity.
    let swapped_guest = Transcript::new(
        HelloMode::Pair,
        id(0x77),
        host_id,
        &guest_share,
        &host_share,
    )
    .expect("transcript");
    assert!(
        verify_mac(Role::Guest, key, &swapped_guest, &mac).is_err(),
        "a MAC must not verify against a transcript naming a different guest"
    );

    // A different host identity.
    let swapped_host = Transcript::new(
        HelloMode::Pair,
        guest_id,
        id(0x88),
        &guest_share,
        &host_share,
    )
    .expect("transcript");
    assert!(
        verify_mac(Role::Guest, key, &swapped_host, &mac).is_err(),
        "a MAC must not verify against a transcript naming a different host"
    );

    // The two peers swapped: a relay that reorders the shares must fail too.
    let swapped_order = Transcript::new(
        HelloMode::Pair,
        guest_id,
        host_id,
        &host_share,
        &guest_share,
    )
    .expect("transcript");
    assert!(
        verify_mac(Role::Guest, key, &swapped_order, &mac).is_err(),
        "a MAC must not verify when the shares are attributed to the wrong side"
    );

    // A different mode, i.e. a downgrade attempt.
    let downgraded = Transcript::new(
        HelloMode::OneShot,
        guest_id,
        host_id,
        &guest_share,
        &host_share,
    )
    .expect("transcript");
    assert!(
        verify_mac(Role::Guest, key, &downgraded, &mac).is_err(),
        "a MAC must not verify across a mode change"
    );

    // The role labels are distinct, so a host's MAC is not a guest's MAC.
    let as_host = confirm_mac(Role::Host, key, &honest);
    assert_ne!(as_host, mac, "the two roles must not derive the same MAC");
    assert!(verify_mac(Role::Guest, key, &honest, &as_host).is_err());
}

// ---------------------------------------------------------------------------
// Guessing simulation: 10 000 wrong words buy nothing.
// ---------------------------------------------------------------------------

/// A deterministic stand-in for "some other well-formed code": same nameplate, a
/// different pair of words from the vendored list.
fn wrong_codes(count: usize) -> Vec<String> {
    let plate = code(CODE).nameplate().get();
    let mut guesses = Vec::with_capacity(count);
    let mut index = 0;
    while guesses.len() < count {
        // Walk the list with two different strides so the pairs repeat slowly.
        let first = splice_core::code::WORDS[index % splice_core::code::WORDS.len()];
        let second = splice_core::code::WORDS[(index * 7 + 1) % splice_core::code::WORDS.len()];
        guesses.push(format!("{plate}-{first}-{second}"));
        index += 1;
    }
    guesses
}

#[test]
fn guessing_10_000_wrong_words_never_pairs() {
    const GUESSES: usize = 10_000;
    let (guest_id, host_id) = ids();
    let now = Instant::now();
    let mut host = HostSession::new(host_id, HelloMode::OneShot, code(CODE), now).expect("host");
    let mut codes_spent = 0usize;
    let mut successes = 0usize;
    let mut attempts_made = 0usize;

    for guess in wrong_codes(GUESSES) {
        if host.phase() == PairingPhase::Burned {
            // The real product mints a fresh code here. Each new code is a fresh
            // `HostSession` with a fresh counter and the same secret words.
            codes_spent += 1;
            host = HostSession::new(host_id, HelloMode::OneShot, code(CODE), now).expect("host");
        }
        // A guess equal to the real code would be a "success" that proves nothing
        // about the crypto, so it is filtered out rather than counted.
        if code(&guess) == code(CODE) {
            continue;
        }
        attempts_made += 1;
        match attempt(&mut host, host_id, guest_id, &guess, now) {
            Step::Reply(ControlMsg::Paired { .. }) => successes += 1,
            Step::ReplyThenClose { outcome, .. } => assert!(
                matches!(outcome, Outcome::Failed | Outcome::Burned),
                "a wrong guess must fail, not {outcome:?}"
            ),
            other => panic!("unexpected step for a wrong guess: {other:?}"),
        }
    }

    assert_eq!(
        successes, 0,
        "no wrong word may ever produce a paired session"
    );
    assert!(attempts_made > 9_000, "the simulation must actually run");
    // Three attempts per code, so 10 000 attempts spend about 3 334 codes.
    assert!(
        (3_000..=3_400).contains(&codes_spent),
        "expected roughly one code per {PAIRING_ATTEMPTS_MAX} attempts, spent {codes_spent}"
    );
}

// ---------------------------------------------------------------------------
// Timeout and concurrency policy (§5.4 step 4, Step 8 brief).
// ---------------------------------------------------------------------------

#[test]
fn a_silent_guest_times_out_without_spending_an_attempt() {
    let (guest_id, host_id) = ids();
    let now = Instant::now();
    let mut host = HostSession::new(host_id, HelloMode::OneShot, code(CODE), now).expect("host");
    host.on_message(guest_id, hello(HelloMode::OneShot, 42), now)
        .expect("hello");
    assert_eq!(host.phase(), PairingPhase::Pairing);

    // Nothing further arrives. The caller's timer fires at the deadline.
    let deadline = host.deadline().expect("an armed deadline");
    assert_eq!(deadline, now + HANDSHAKE_TIMEOUT);
    assert!(!host.is_handshake_expired(deadline - Duration::from_millis(1)));
    assert!(host.is_handshake_expired(deadline));

    assert_eq!(host.on_timeout(deadline), Some(Outcome::TimedOut));
    assert_eq!(
        host.attempts_left(),
        PAIRING_ATTEMPTS_MAX,
        "silence spent no words, so it must not cost an attempt"
    );
    // The code is still usable: this was not a guess, just a dead connection.
    assert_eq!(host.phase(), PairingPhase::WaitingForGuest);
    assert!(host.phase().advertises());
}

#[test]
fn a_second_guest_is_rejected_and_the_first_guest_still_pairs() {
    let (first, host_id) = ids();
    let second = id(0x99);
    let now = Instant::now();
    let mut host = HostSession::new(host_id, HelloMode::OneShot, code(CODE), now).expect("host");

    // First guest opens the handshake but does not finish it.
    let (mut guest, opening) =
        GuestSession::begin(first, host_id, HelloMode::OneShot, code(CODE), now).expect("guest");
    let host_share = expect_reply(
        host.on_message(first, opening[0].clone(), now)
            .expect("hello"),
    );
    host.on_message(first, opening[1].clone(), now)
        .expect("first share");

    // Second guest, mid-handshake: refused, and the first is undisturbed.
    match host
        .on_message(second, hello(HelloMode::OneShot, 42), now)
        .expect("second hello")
    {
        Step::ReplyThenClose { outcome, .. } => assert_eq!(outcome, Outcome::Busy),
        other => panic!("a second guest must be refused, got {other:?}"),
    }
    assert_eq!(host.phase(), PairingPhase::Pairing);
    assert_eq!(host.attempts_left(), PAIRING_ATTEMPTS_MAX);

    // The first guest still finishes normally.
    let guest_mac = expect_reply(
        guest
            .on_message(host_id, host_share, now)
            .expect("host share"),
    );
    match host.on_message(first, guest_mac, now).expect("guest mac") {
        Step::Reply(ControlMsg::Paired { .. }) => {}
        other => panic!("the first guest must still pair, got {other:?}"),
    }
    assert_eq!(host.phase(), PairingPhase::Paired);
}

// ---------------------------------------------------------------------------
// Rejection policy: which failures discard the handshake, and which do not.
// ---------------------------------------------------------------------------

#[test]
fn a_malformed_share_from_the_active_guest_releases_the_code() {
    let (guest_id, host_id) = ids();
    let now = Instant::now();
    let mut host = HostSession::new(host_id, HelloMode::OneShot, code(CODE), now).expect("host");
    host.on_message(guest_id, hello(HelloMode::OneShot, 42), now)
        .expect("hello");
    assert_eq!(host.phase(), PairingPhase::Pairing);

    // A share of the wrong length: a protocol violation, not a guess.
    let step = host
        .on_message(
            guest_id,
            ControlMsg::PakeMsg {
                payload: vec![0u8; 4],
            },
            now,
        )
        .expect("short share");
    assert!(matches!(
        step,
        Step::ReplyThenClose {
            outcome: Outcome::ProtocolViolation,
            ..
        }
    ));
    assert_eq!(
        host.phase(),
        PairingPhase::WaitingForGuest,
        "a garbage frame must not park the code in Pairing forever"
    );
    assert_eq!(host.attempts_left(), PAIRING_ATTEMPTS_MAX);

    // The code is still usable by a real guest.
    let (mut guest, opening) =
        GuestSession::begin(guest_id, host_id, HelloMode::OneShot, code(CODE), now).expect("guest");
    let host_share = expect_reply(
        host.on_message(guest_id, opening[0].clone(), now)
            .expect("hello"),
    );
    host.on_message(guest_id, opening[1].clone(), now)
        .expect("guest share");
    let guest_mac = expect_reply(
        guest
            .on_message(host_id, host_share, now)
            .expect("host share"),
    );
    match host
        .on_message(guest_id, guest_mac, now)
        .expect("guest mac")
    {
        Step::Reply(ControlMsg::Paired { .. }) => {}
        other => panic!("the code must still work, got {other:?}"),
    }
}

#[test]
fn a_foreign_node_cannot_cancel_an_active_handshake() {
    let (guest_id, host_id) = ids();
    let outsider = id(0x55);
    let now = Instant::now();
    let mut host = HostSession::new(host_id, HelloMode::OneShot, code(CODE), now).expect("host");
    let (mut guest, opening) =
        GuestSession::begin(guest_id, host_id, HelloMode::OneShot, code(CODE), now).expect("guest");
    let host_share = expect_reply(
        host.on_message(guest_id, opening[0].clone(), now)
            .expect("hello"),
    );
    host.on_message(guest_id, opening[1].clone(), now)
        .expect("guest share");

    // An outsider that never guessed anything tries to interrupt by sending a share.
    let step = host
        .on_message(
            outsider,
            ControlMsg::PakeMsg {
                payload: vec![0u8; 33],
            },
            now,
        )
        .expect("outsider share");
    assert!(matches!(
        step,
        Step::ReplyThenClose {
            outcome: Outcome::ProtocolViolation,
            ..
        }
    ));
    assert_eq!(
        host.phase(),
        PairingPhase::Pairing,
        "the outsider gets a refusal, not a cancellation"
    );

    // The invited guest is unaffected.
    let guest_mac = expect_reply(
        guest
            .on_message(host_id, host_share, now)
            .expect("host share"),
    );
    match host
        .on_message(guest_id, guest_mac, now)
        .expect("guest mac")
    {
        Step::Reply(ControlMsg::Paired { .. }) => {}
        other => panic!("the invited guest must still pair, got {other:?}"),
    }
}

#[test]
fn a_bye_from_the_host_ends_the_guest_for_good() {
    let (guest_id, host_id) = ids();
    let now = Instant::now();
    let (mut guest, _opening) =
        GuestSession::begin(guest_id, host_id, HelloMode::OneShot, code(CODE), now).expect("guest");

    let step = guest
        .on_message(
            host_id,
            ControlMsg::Bye {
                reason: splice_core::proto::ByeReason::Protocol,
            },
            now,
        )
        .expect("bye");
    assert!(matches!(
        step,
        Step::ReplyThenClose {
            reply: None,
            outcome: Outcome::Failed
        }
    ));
    assert_eq!(
        guest.phase(),
        PairingPhase::Burned,
        "a refused guest must not be reusable"
    );
    // A late message cannot revive it.
    let step = guest
        .on_message(host_id, ControlMsg::Pong, now)
        .expect("late message");
    assert!(matches!(
        step,
        Step::ReplyThenClose {
            outcome: Outcome::ProtocolViolation,
            ..
        }
    ));
    assert!(guest.session_key().is_none());
}

// ---------------------------------------------------------------------------
// End to end over the in-memory transport: real frames, real state machines.
// ---------------------------------------------------------------------------

/// Write one CONTROL message as a frame, exactly as `splice listen` would.
async fn write_control(tx: &mut SendStream, message: &ControlMsg) -> Result<(), String> {
    let bytes = Frame::control(message)
        .map_err(|err| err.to_string())?
        .encode();
    tx.write_all(&bytes).await.map_err(|err| err.to_string())
}

/// Read one CONTROL frame, honouring the header before allocating.
async fn read_control(rx: &mut RecvStream) -> Result<ControlMsg, String> {
    let mut header = [0u8; 6];
    rx.read_exact(&mut header)
        .await
        .map_err(|err| err.to_string())?;
    let header = frame::decode_header(&header).map_err(|err| err.to_string())?;
    assert_eq!(header.kind, FrameKind::Control);
    let mut body = vec![0u8; header.len as usize];
    rx.read_exact(&mut body)
        .await
        .map_err(|err| err.to_string())?;
    ControlMsg::decode_from_slice(&body).map_err(|err| err.to_string())
}

/// Perform whatever the state machine asked for, then report the outcome.
async fn apply(tx: &mut SendStream, step: Step) -> Option<Outcome> {
    match step {
        Step::Reply(message) => {
            write_control(tx, &message).await.expect("write");
            None
        }
        Step::ReplyThenClose { reply, outcome } => {
            if let Some(message) = reply {
                write_control(tx, &message).await.expect("write");
            }
            Some(outcome)
        }
        Step::Idle => None,
    }
}

/// The whole protocol, with the state machines driven by bytes on a transport
/// instead of by direct calls: the guest's messages are decoded by the host and
/// vice versa, so a codec bug cannot hide behind the unit tests.
#[tokio::test]
async fn pairing_completes_over_the_in_memory_transport() {
    let net = Network::new();
    let (guest_id, host_id) = ids();
    let host_ep = net.endpoint_with(host_id, false);
    let guest_ep = net.endpoint_with(guest_id, false);

    let dialed = guest_ep
        .connect(host_ep.hint(), splice_core::constants::ALPN)
        .await
        .expect("dial");
    let accepted = host_ep
        .accept()
        .await
        .expect("accept")
        .expect("a connection");
    assert_eq!(dialed.remote_id(), host_id);
    assert_eq!(accepted.remote_id(), guest_id);
    splice_core::net::expect_alpn(accepted.as_ref(), splice_core::constants::ALPN).expect("ALPN");

    let (mut guest_tx, mut guest_rx) = dialed.open_bi().await.expect("guest stream");
    let (mut host_tx, mut host_rx) = accepted.accept_bi().await.expect("host stream");

    let now = Instant::now();
    let mut host = HostSession::new(host_id, HelloMode::Pair, code(CODE), now).expect("host");
    let (mut guest, opening) =
        GuestSession::begin(guest_id, host_id, HelloMode::Pair, code(CODE), now).expect("guest");
    for message in opening {
        write_control(&mut guest_tx, &message).await.expect("open");
    }

    // Guest's share arrives at the host.
    let hello_message = read_control(&mut host_rx).await.expect("read hello");
    assert_eq!(hello_message.name(), "Hello");
    if let Some(outcome) = apply(
        &mut host_tx,
        host.on_message(guest_id, hello_message, now)
            .expect("hello"),
    )
    .await
    {
        panic!("a valid hello must not end the session: {outcome:?}");
    }

    let guest_share = read_control(&mut host_rx).await.expect("read share");
    if let Some(outcome) = apply(
        &mut host_tx,
        host.on_message(guest_id, guest_share, now).expect("share"),
    )
    .await
    {
        panic!("a valid share must not end the session: {outcome:?}");
    }

    // Guest confirms. The host already queued its own `PakeConfirm` right behind
    // its share, so the guest must consume both before it is satisfied.
    let host_share = read_control(&mut guest_rx).await.expect("read host share");
    if let Some(outcome) = apply(
        &mut guest_tx,
        guest
            .on_message(host_id, host_share, now)
            .expect("host share"),
    )
    .await
    {
        panic!("the guest must not fail on a correct share: {outcome:?}");
    }
    let host_mac = read_control(&mut guest_rx).await.expect("read host mac");
    assert_eq!(
        guest.on_message(host_id, host_mac, now).expect("host mac"),
        Step::Idle
    );
    assert_eq!(guest.phase(), PairingPhase::Paired);

    // Host verifies the guest's MAC and announces Paired.
    let guest_mac = read_control(&mut host_rx).await.expect("read guest mac");
    if let Some(outcome) = apply(
        &mut host_tx,
        host.on_message(guest_id, guest_mac, now)
            .expect("guest mac"),
    )
    .await
    {
        panic!("the host must pair: {outcome:?}");
    }
    assert_eq!(host.phase(), PairingPhase::Paired);

    // Guest accepts the announcement and settles.
    let announcement = read_control(&mut guest_rx).await.expect("read paired");
    assert!(matches!(announcement, ControlMsg::Paired { .. }));
    assert_eq!(
        guest
            .on_message(host_id, announcement, now)
            .expect("announcement"),
        Step::Idle
    );
    assert_eq!(guest.phase(), PairingPhase::Paired);

    // Both halves derived the same key, byte for byte, over the wire.
    assert_eq!(
        host.session_key().expect("host key").expose_secret(),
        guest.session_key().expect("guest key").expose_secret(),
        "the two sides must agree on the session key"
    );

    // And keepalives still work once paired.
    write_control(&mut guest_tx, &ControlMsg::Ping)
        .await
        .expect("ping");
    assert_eq!(
        read_control(&mut host_rx).await.expect("read ping"),
        ControlMsg::Ping
    );
    apply(
        &mut host_tx,
        host.on_message(guest_id, ControlMsg::Ping, now)
            .expect("ping"),
    )
    .await;
    assert_eq!(
        read_control(&mut guest_rx).await.expect("read pong"),
        ControlMsg::Pong
    );
}

// ---------------------------------------------------------------------------
// Ticket mode — the same exchange, no code and no nameplate (§5.4 last line)
// ---------------------------------------------------------------------------

/// A host and a guest built from a ticket's secret must pair, and the `Hello` must
/// carry no nameplate. This is the path `splice dev host-ticket/guest-ticket` use.
#[test]
fn a_ticket_secret_pairs_without_a_nameplate() {
    use splice_core::discovery::Ticket;

    let (guest_id, host_id) = ids();
    let now = Instant::now();
    // The host mints a ticket for itself; the guest holds only the encoded string.
    let addr = splice_core::net::NodeAddr::new(host_id).with_ip("127.0.0.1:7000".parse().unwrap());
    let ticket = Ticket::generate(&addr).expect("ticket");
    let text = ticket.encode();
    let parsed = Ticket::parse(text.expose_secret()).expect("parsed ticket");
    assert_eq!(parsed.node(), host_id);

    let host_password = ticket.password_string();
    let guest_password = parsed.password_string();
    let mut host = HostSession::new_with_password(host_id, HelloMode::Pair, &host_password, now)
        .expect("host session");
    let (mut guest, opening) =
        GuestSession::begin_with_password(guest_id, host_id, HelloMode::Pair, &guest_password, now)
            .expect("guest session");
    assert_eq!(host.code(), None, "ticket mode carries no code");

    // The guest's opening `Hello` must have no nameplate, or the host would refuse
    // it as a probe (see `HostSession::on_message`).
    match &opening[0] {
        ControlMsg::Hello {
            nameplate, mode, ..
        } => {
            assert_eq!(*nameplate, None);
            assert_eq!(*mode, HelloMode::Pair);
        }
        other => panic!("expected Hello, got {}", other.name()),
    }

    let announcement = {
        let host_share = expect_reply(
            host.on_message(guest_id, opening[0].clone(), now)
                .expect("hello"),
        );
        let host_mac = expect_reply(
            host.on_message(guest_id, opening[1].clone(), now)
                .expect("guest share"),
        );
        let guest_mac = expect_reply(
            guest
                .on_message(host_id, host_share, now)
                .expect("host share"),
        );
        assert_eq!(
            guest.on_message(host_id, host_mac, now).expect("host mac"),
            Step::Idle
        );
        expect_reply(
            host.on_message(guest_id, guest_mac, now)
                .expect("guest mac"),
        )
    };

    assert_eq!(host.phase(), PairingPhase::Paired);
    assert_eq!(guest.phase(), PairingPhase::Paired);
    assert!(matches!(announcement, ControlMsg::Paired { .. }));
    assert_eq!(
        host.session_key().expect("host key").expose_secret(),
        guest.session_key().expect("guest key").expose_secret(),
        "both sides must derive the same ticket key"
    );
}

/// A ticket-mode host must refuse a `Hello` that carries a nameplate: the ticket
/// names no code, so a plate is either a misdial or a probe, and spending an
/// attempt on it would let a stranger burn the ticket.
#[test]
fn a_ticket_host_refuses_a_nameplate_without_spending_an_attempt() {
    use splice_core::discovery::Ticket;

    let (_guest_id, host_id) = ids();
    let now = Instant::now();
    let addr = splice_core::net::NodeAddr::new(host_id);
    let ticket = Ticket::generate(&addr).expect("ticket");
    let password = ticket.password_string();
    let mut host =
        HostSession::new_with_password(host_id, HelloMode::Pair, &password, now).expect("host");

    let probe = NodeId::from_bytes([0x33; 32]);
    let step = host
        .on_message(
            probe,
            ControlMsg::Hello {
                version: splice_core::constants::PROTOCOL_VERSION,
                mode: HelloMode::Pair,
                nameplate: Some(42),
                resume: None,
            },
            now,
        )
        .expect("hello");
    assert!(matches!(
        step,
        Step::ReplyThenClose {
            outcome: Outcome::ProtocolViolation,
            ..
        }
    ));
    assert_eq!(host.attempts_left(), PAIRING_ATTEMPTS_MAX);
}

/// A wrong ticket secret is a wrong password: the host spends an attempt, exactly
/// like a wrong code, so ticket mode is not a guessing oracle.
#[test]
fn a_wrong_ticket_secret_spends_an_attempt() {
    use splice_core::discovery::Ticket;

    let (guest_id, host_id) = ids();
    let now = Instant::now();
    let host_ticket = Ticket::from_parts(host_id, Vec::new(), None, &[1u8; 16]);
    let guest_ticket = Ticket::from_parts(host_id, Vec::new(), None, &[2u8; 16]);
    let mut host = HostSession::new_with_password(
        host_id,
        HelloMode::Pair,
        &host_ticket.password_string(),
        now,
    )
    .expect("host");
    let (guest, opening) = GuestSession::begin_with_password(
        guest_id,
        host_id,
        HelloMode::Pair,
        &guest_ticket.password_string(),
        now,
    )
    .expect("guest");
    let _ = guest;

    expect_reply(
        host.on_message(guest_id, opening[0].clone(), now)
            .expect("hello"),
    );
    expect_reply(
        host.on_message(guest_id, opening[1].clone(), now)
            .expect("share"),
    );
    let step = host
        .on_message(guest_id, ControlMsg::PakeConfirm { mac: [0u8; 32] }, now)
        .expect("confirm");
    assert!(matches!(
        step,
        Step::ReplyThenClose {
            outcome: Outcome::Failed,
            ..
        }
    ));
    assert_eq!(host.attempts_left(), PAIRING_ATTEMPTS_MAX - 1);
}
