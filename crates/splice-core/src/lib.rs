//! `splice-core` — identity, codes, discovery, pairing, trust store, wire protocol.
//!
//! Phase 1 scope (see `Architecture.md` §15): identity, code/wordlist, mDNS +
//! presence + ticket + manual address discovery, SPAKE2 pairing, trust store, the
//! CONTROL frame codec, and a minimal listener. PTY, file transfer, daemon/IPC and
//! the basket GUI are deliberately absent.
//!
//! iroh types are confined to [`net`] and [`identity`]; everything else speaks our
//! own `NodeId`, `NodeAddr`, and `Connection`.

#![forbid(unsafe_code)]

pub mod code;
pub mod constants;
pub mod discovery;
pub mod error;
pub mod identity;
pub mod net;
pub mod pairing;
pub mod proto;
pub mod secret;
pub mod trust;

pub use error::{Error, Result};
pub use identity::{NodeId, NodeSecret};
pub use net::{Connection, NodeAddr};
pub use secret::{Secret, SecretBytes, SecretString};

/// Initialise `tracing` once. Logs go to stderr and never include secret material.
///
/// `RUST_LOG` overrides the default (`info`); use `RUST_LOG=splice_core=debug`.
pub fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(true)
        .try_init();
}

/// The crate version, reported by `splice --version` and `splice dev info`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");