//! One error type for the whole library.
//!
//! Two rules apply to everything here:
//!
//! * Never interpolate secret material (words, SPAKE2 keys, resume keys) into a
//!   message. Errors travel to logs and to the terminal.
//! * Every peer-controlled value that is echoed back is truncated or described by
//!   its class, not dumped verbatim (a hostile peer must not be able to inject
//!   terminal escapes through our own error text).

use std::path::PathBuf;

/// Convenient alias used across the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Unified library error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("platform config directory is unavailable")]
    ConfigDirUnavailable,

    #[error("identity: {0}")]
    Identity(#[from] IdentityError),

    #[error("code: {0}")]
    Code(#[from] CodeError),

    #[error("frame: {0}")]
    Frame(#[from] FrameError),

    #[error("protocol: {0}")]
    Proto(#[from] ProtoError),

    #[error("discovery: {0}")]
    Discovery(#[from] DiscoveryError),

    #[error("pairing: {0}")]
    Pairing(#[from] PairingError),

    #[error("trust store: {0}")]
    Trust(#[from] TrustError),

    #[error("network: {0}")]
    Net(#[from] NetError),

    #[error("operation timed out: {0}")]
    Timeout(&'static str),

    #[error("{0}")]
    Other(String),
}

/// Key material, key files, and identity storage.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("key file {path} is missing")]
    Missing { path: PathBuf },
    #[error("key file {path} has insecure permissions {mode:o}; expected owner-only (0600)")]
    InsecurePermissions { path: PathBuf, mode: u32 },
    #[error("key file {path} has the wrong length ({len} bytes, expected {expected})")]
    WrongLength {
        path: PathBuf,
        len: usize,
        expected: usize,
    },
    #[error("key file {path} exists but is not a regular file")]
    NotRegularFile { path: PathBuf },
    #[error("key file {path} could not be written atomically: {source}")]
    AtomicWrite {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("key material is invalid")]
    InvalidKey,
}

/// Code parsing/formatting. Deliberately contains no user input.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CodeError {
    #[error("code is empty")]
    Empty,
    #[error("code is too long")]
    TooLong,
    #[error("code has the wrong shape; expected <nameplate>-<word>-<word>")]
    Shape,
    #[error("nameplate is not a number")]
    NameplateNotNumeric,
    #[error("nameplate is out of range")]
    NameplateOutOfRange,
    #[error("a word is not in the wordlist")]
    UnknownWord,
    #[error("word count is out of range")]
    WordCountOutOfRange,
    #[error("code contains characters outside a-z, 0-9 and '-'")]
    InvalidCharacter,
}

/// Frame codec errors (I9: every length is bounded).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("frame body length {len} exceeds the {max} byte limit")]
    TooLarge { len: u64, max: usize },
    #[error("frame is shorter than the {header} byte header")]
    ShortHeader { header: usize },
    #[error("unknown frame type {kind:#04x}")]
    UnknownType { kind: u8 },
    #[error("unsupported frame flags {flags:#04x}")]
    UnsupportedFlags { flags: u8 },
    #[error("frame body is truncated: declared {declared}, received {received}")]
    Truncated { declared: u32, received: usize },
    #[error("frame body could not be decoded: {0}")]
    Decode(String),
}

/// Message-level protocol errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtoError {
    #[error("unsupported protocol version {got} (this build speaks {expected})")]
    VersionMismatch { got: u16, expected: u16 },
    #[error("message is not allowed in the current state")]
    UnexpectedMessage,
    #[error("message could not be decoded: {0}")]
    Decode(String),
    #[error("message could not be encoded: {0}")]
    Encode(String),
    #[error("unknown stream type byte {kind:#04x}")]
    UnknownStreamType { kind: u8 },
    #[error("message belongs to another stream type")]
    WrongStreamType,
}

/// Discovery (mDNS, presence, ticket, manual address).
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("multicast is unavailable: {0}. Use a ticket or --addr instead")]
    MulticastUnavailable(String),
    #[error("mDNS error: {0}")]
    Mdns(String),
    #[error("no host is advertising nameplate {nameplate}")]
    NameplateNotFound { nameplate: u16 },
    #[error("ticket is malformed")]
    BadTicket,
    #[error("ticket has the wrong version {got}")]
    TicketVersion { got: u8 },
    #[error("address {addr:?} is not a valid ip:port")]
    BadAddress { addr: String },
    #[error("presence socket error: {0}")]
    PresenceSocket(String),
}

/// Pairing state machine and SPAKE2.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PairingError {
    #[error("code is burned; no further attempts are allowed")]
    Burned,
    #[error("already pairing with another guest")]
    Busy,
    #[error("nameplate does not match the advertised code")]
    NameplateMismatch,
    #[error("key confirmation failed")]
    ConfirmFailed,
    #[error("peer sent an unexpected pairing role")]
    WrongRole,
    #[error("pairing message could not be decoded")]
    BadMessage,
    #[error("the peer declined the exchange")]
    Declined,
    #[error("pairing handshake timed out")]
    Timeout,
    #[error("pairing is not allowed in this mode")]
    NotAllowed,
}

/// Trust store errors.
#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("trust store {path} is corrupt: {detail}. A backup was kept at {backup}")]
    Corrupt {
        path: PathBuf,
        detail: String,
        backup: PathBuf,
    },
    #[error("trust store {path} could not be saved: {source}")]
    Save {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("a device with node id {id} is already trusted under alias {alias}")]
    DuplicateNodeId { id: String, alias: String },
    #[error("a device with alias {alias:?} already exists")]
    DuplicateAlias { alias: String },
    #[error("no trusted device matches {0:?}")]
    NotFound(String),
    #[error("alias is empty after sanitizing")]
    EmptyAlias,
}

/// Transport boundary errors (iroh is hidden behind these).
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("endpoint could not be created: {0}")]
    EndpointCreate(String),
    #[error("could not reach the peer: {0}")]
    Dial(String),
    #[error("connection closed by the peer")]
    PeerClosed,
    #[error("no forwarded address is known for this node")]
    NoAddress,
    #[error("stream closed before a complete message arrived")]
    StreamClosed,
    #[error("transport error: {0}")]
    Transport(String),
    #[error("connection was rejected: {0}")]
    Rejected(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_error_mentions_the_limit_not_the_payload() {
        let err = FrameError::TooLarge {
            len: 99_999_999,
            max: 1024 * 1024,
        };
        let text = err.to_string();
        assert!(text.contains("1048576"));
        assert!(text.contains("99999999"));
    }

    #[test]
    fn identity_error_does_not_carry_key_bytes() {
        let err = IdentityError::WrongLength {
            path: PathBuf::from("C:/tmp/identity.key"),
            len: 12,
            expected: 32,
        };
        assert!(!err.to_string().contains("0x"));
    }
}
