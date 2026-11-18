//! Finding a peer without a server (§5.3).
//!
//! Four paths, in the order the CLI tries them:
//!
//! 1. [`mdns`] — a host with a live code advertises the nameplate in DNS-SD.
//! 2. [`ticket`] — a copy-paste string carrying the NodeId, address hints and the
//!    SPAKE2 password, for when multicast is unusable.
//! 3. [`manual`] — `--addr`, which skips discovery entirely.
//! 4. [`presence`] — rotating keyed tags that tell us which *already trusted*
//!    devices are online, without revealing who they are to the rest of the LAN.
//!
//! Nothing here talks to iroh: each module produces a [`crate::net::NodeAddr`]
//! hint and calls `splice-core`'s own transport.

pub mod manual;
pub mod mdns;
pub mod presence;
pub mod ticket;

pub use manual::ManualTarget;
pub use mdns::{AdvertisedHost, Mdns, SERVICE_TYPE};
pub use presence::{
    Beacon, DeviceTags, PeerPresence, PresenceSocket, PresenceTag, PresenceTracker, BEACON_LEN,
    PRESENCE_KDF_CONTEXT, PRESENCE_VERSION, TAG_LEN,
};
pub use ticket::{Ticket, TICKET_PREFIX, TICKET_SECRET_LEN, TICKET_VERSION};
