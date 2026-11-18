//! Wire protocol, CONTROL stream only (§7).
//!
//! * Every new QUIC stream starts with one type byte ([`StreamType`]).
//! * Inside a stream, every message is a frame ([`frame`]) with a 6-byte header.
//! * CONTROL bodies are `postcard` ([`messages`]).

pub mod frame;
pub mod kinds;
pub mod messages;

pub use frame::{Frame, FrameFlags, FrameKind};
pub use kinds::StreamType;
pub use messages::{ByeReason, Caps, ControlMsg, HelloMode};