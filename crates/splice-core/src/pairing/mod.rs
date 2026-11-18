//! SPAKE2 pairing (A5.4).
//!
//! Two halves, one protocol:
//!
//! - [`host`] holds the code. It advertises, accepts one guest, and counts wrong
//!   guesses against `PAIRING_ATTEMPTS_MAX`.
//! - [`guest`] types the code. It follows the host through HELLO, the PAKE, and key
//!   confirmation.
//!
//! Both are pure state machines: they take a message and a timestamp and return the
//! bytes to send. They never touch a socket, a clock, or the trust store, so the
//! whole protocol is testable without a network and without a TTY.
//!
//! What the machines deliberately do **not** do is store the device. A verified
//! confirmation MAC proves the peer knew the code; it is not consent to write a
//! permanent trust record. That decision belongs to whoever is at the keyboard, and
//! arrives through [`Prompter`].
//!
//! The password never leaves this module: it is a [`crate::SecretString`], and the
//! session key is a [`crate::Secret`] that clears itself on drop.

pub mod confirm;
pub mod guest;
pub mod host;
pub mod pake;
pub mod prompter;
pub mod state;

pub use confirm::{
    confirm_mac, password_from_words, resume_key, verify_mac, Transcript, CONFIRM_GUEST,
    CONFIRM_HOST, RESUME_KEY_CONTEXT,
};
pub use guest::GuestSession;
pub use host::HostSession;
pub use pake::{PakeState, Role, PAKE_MSG_LEN};
pub use prompter::{
    both_agree, consent_or_refuse, AliasConsent, AlwaysNo, AlwaysYes, Canned, Prompter,
};
pub use state::{Outcome, PairingPhase, Step};
