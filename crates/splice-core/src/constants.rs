//! All protocol constants in one place.
//!
//! Values are fixed by `Architecture.md` §5.5 / §7 and the Phase 1 brief. Do not
//! change them locally; a different value is a protocol change.

use std::time::Duration;

/// ALPN identifier negotiated by iroh/QUIC. Bumped only on a wire break.
pub const ALPN: &[u8] = b"splice/1";

/// Wire protocol version advertised in `Hello`.
pub const PROTOCOL_VERSION: u16 = 1;

/// Frame header: `type: u8 | flags: u8 | len: u32 (big-endian)`.
pub const FRAME_HEADER_LEN: usize = 6;

/// Hard upper bound for a single frame body (1 MiB). Checked *before* allocating.
pub const MAX_FRAME_LEN: usize = 1024 * 1024;

/// Failed PAKE attempts per code, counted on the host. The next state is BURNED.
pub const PAIRING_ATTEMPTS_MAX: u32 = 3;

/// Lifetime of an unused code.
pub const PAIRING_CODE_TTL: Duration = Duration::from_secs(600);

/// Handshake (Hello through key confirmation) deadline.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Size of the wordlist (2 words = 22 bits, 3 words = 33 bits).
pub const WORDLIST_LEN: usize = 2048;

/// Words in a generated code by default; `--words 3` may be requested.
pub const CODE_WORDS_DEFAULT: usize = 2;

/// Presence beacon period.
pub const PRESENCE_INTERVAL: Duration = Duration::from_millis(1500);

/// A trusted device is offline after this long without a beacon.
pub const PRESENCE_OFFLINE_AFTER: Duration = Duration::from_secs(6);

/// Rotating presence tag bucket width.
pub const PRESENCE_TAG_BUCKET: Duration = Duration::from_secs(300);

/// Accepted clock skew, in buckets, when matching presence tags (−1, 0, +1).
pub const PRESENCE_TAG_SKEW_BUCKETS: i64 = 1;

/// Maximum alias length in characters, after control characters are stripped.
pub const ALIAS_MAX_LEN: usize = 32;

/// Maximum resume attempts per session (declared here; resume lands in Phase 2/3).
pub const RESUME_ATTEMPTS_MAX: u32 = 5;

/// Sender-side inactivity TTL used in Phase 2/3 (declared here, not enforced yet).
pub const SESSION_IDLE_TTL: Duration = Duration::from_secs(30 * 60);

/// Default size cap for `auto_accept` transfers (1 GiB).
pub const AUTO_ACCEPT_MAX_BYTES: u64 = 1024 * 1024 * 1024;

/// Presence beacons per second at most, per peer, used to drop floods.
pub const PRESENCE_MAX_PER_SEC: u32 = 4;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_architecture() {
        assert_eq!(MAX_FRAME_LEN, 1024 * 1024);
        assert_eq!(PAIRING_ATTEMPTS_MAX, 3);
        assert_eq!(PAIRING_CODE_TTL.as_secs(), 600);
        assert_eq!(HANDSHAKE_TIMEOUT.as_secs(), 10);
        assert_eq!(WORDLIST_LEN, 2048);
        assert_eq!(PRESENCE_INTERVAL, Duration::from_millis(1500));
        assert_eq!(PRESENCE_OFFLINE_AFTER.as_secs(), 6);
        assert_eq!(PRESENCE_TAG_BUCKET.as_secs(), 300);
        assert_eq!(ALIAS_MAX_LEN, 32);
        assert_eq!(RESUME_ATTEMPTS_MAX, 5);
        assert_eq!(SESSION_IDLE_TTL.as_secs(), 30 * 60);
        assert_eq!(ALPN, b"splice/1");
    }
}