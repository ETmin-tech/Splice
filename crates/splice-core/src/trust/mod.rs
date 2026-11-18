//! Trust store and trusted-connection policy (§5.6, I13, I18).
//!
//! Two pieces, deliberately separate:
//!
//! * [`store`] — the pinned list of devices (`trust.json`), the only thing that
//!   answers "is this NodeId trusted?".
//! * [`session`] — the trusted-mode conversation on the wire: `Hello{mode:
//!   Trusted}`, no PAKE, then keepalives, and nothing else in Phase 1.
//!
//! The distinction matters for I13: authentication is done by TLS, the decision is
//! done by the store, and neither is allowed to infer the other. A peer never
//! *becomes* trusted by what it sends.

pub mod session;
pub mod store;

pub use session::{
    close_foreign, trusted_hello, ActiveTrusted, TrustedOutcome, TrustedServer, TrustedStep,
    FOREIGN_CLOSE_CODE, FOREIGN_CLOSE_REASON,
};
pub use store::{TrustEntry, TrustStore, TRUST_BACKUP_SUFFIX, TRUST_FILE, TRUST_FORMAT_VERSION};
