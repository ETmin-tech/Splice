//! Identity: ephemeral and persistent node keys (§5.1).
//!
//! A *persistent* key is created once and stored in the user config directory; it
//! is used by `pair`, `devices`, `listen` and (later) the daemon and basket. An
//! *ephemeral* key is created per session for one-shot codes and shell sessions and
//! is never written to disk.
//!
//! iroh's key type is confined to this module (plus [`crate::net`]); the rest of the
//! crate sees [`NodeId`] and [`NodeSecret`].

mod keys;
mod store;

pub use keys::{NodeId, NodeSecret};
pub use store::{
    config_dir, load_or_create_persistent, load_persistent, reset_persistent, IdentitySource,
    IDENTITY_FILE,
};
