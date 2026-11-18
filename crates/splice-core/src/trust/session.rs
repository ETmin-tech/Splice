//! Trusted-mode conversation (`Hello{mode: Trusted}` → Ping/Pong only).
//!
//! §5.6 fixes the whole exchange: no PAKE, no code, one `Hello`, then keepalives
//! and nothing else in Phase 1. The trust decision itself is not made here — it is
//! [`TrustStore::contains`](super::store::TrustStore::contains) against the
//! `NodeId` the transport already authenticated. This module only encodes what may
//! follow that decision.
//!
//! Two invariants are enforced on purpose:
//!
//! * **I13** — a peer whose NodeId is not pinned gets a generic close and no
//!   protocol message at all, so probing cannot tell "unknown node" from "protocol
//!   error".
//! * **I2** — in trusted mode no message other than [`Ping`](ControlMsg::Ping) and
//!   [`Pong`](ControlMsg::Pong) is processed, before *or* after the trust match.
//!   The `allowed_before_auth` list in [`crate::proto::messages`] is the code-pairing
//!   list; it deliberately allows `PakeMsg`, which must stay a violation here.

use std::sync::{Arc, Mutex};

use crate::constants::PROTOCOL_VERSION;
use crate::identity::NodeId;
use crate::net::Connection;
use crate::proto::messages::{ByeReason, ControlMsg, HelloMode};

use super::store::TrustStore;

/// Application close code used for every refusal on the trusted path.
///
/// Deliberately the same value for "not trusted" and "protocol violation": the
/// reason string is generic for the same reason (I13).
pub const FOREIGN_CLOSE_CODE: u32 = 0;

/// Generic close reason. Not `b"not trusted"`: that would confirm the prober's
/// NodeId is absent from the store.
pub const FOREIGN_CLOSE_REASON: &[u8] = b"refused";

/// Why a trusted-mode connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedOutcome {
    /// The peer's NodeId is not in the trust store (I13).
    NotTrusted,
    /// The peer asked for a code pairing on the trusted path, or sent no `Hello`.
    WrongMode,
    /// A message the trusted path does not serve in Phase 1 (I2).
    Protocol,
    /// The peer closed normally.
    PeerBye,
    /// `on_message` was called after the session already ended.
    AlreadyClosed,
}

impl TrustedOutcome {
    pub const fn name(self) -> &'static str {
        match self {
            Self::NotTrusted => "not trusted",
            Self::WrongMode => "wrong mode",
            Self::Protocol => "protocol",
            Self::PeerBye => "peer bye",
            Self::AlreadyClosed => "already closed",
        }
    }

    /// Whether the caller must close the connection after this step.
    pub const fn closes(self) -> bool {
        true
    }
}

/// What the caller should do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustedStep {
    /// Send nothing.
    Idle,
    /// Send this message and keep the session open.
    Reply(ControlMsg),
    /// End the session. A `reply` is only present when the peer is trusted (a
    /// `Bye` explaining a protocol violation); a foreign peer gets silence.
    Close {
        reply: Option<ControlMsg>,
        outcome: TrustedOutcome,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    ExpectHello,
    Ready,
    Closed,
}

/// Listener side of one trusted connection.
#[derive(Debug)]
pub struct TrustedServer {
    peer: NodeId,
    /// The trust-store answer, frozen at connection time. A device removed while
    /// this connection is live is handled by [`ActiveTrusted::close_all`].
    trusted: bool,
    state: State,
}

impl TrustedServer {
    /// Build the session. This call is the trust-store match (I13).
    pub fn new(store: &TrustStore, peer: NodeId) -> Self {
        Self {
            peer,
            trusted: store.contains(&peer),
            state: State::ExpectHello,
        }
    }

    /// Build without consulting a store. Only for tests that exercise the state
    /// machine; production code goes through [`Self::new`].
    #[doc(hidden)]
    pub fn with_trust_decision(peer: NodeId, trusted: bool) -> Self {
        Self {
            peer,
            trusted,
            state: State::ExpectHello,
        }
    }

    pub const fn peer(&self) -> NodeId {
        self.peer
    }

    /// Whether this peer is pinned. The listener uses it to decide whether to open
    /// a CONTROL stream at all.
    pub const fn is_trusted(&self) -> bool {
        self.trusted
    }

    pub const fn is_ready(&self) -> bool {
        matches!(self.state, State::Ready)
    }

    pub fn on_message(&mut self, message: ControlMsg) -> TrustedStep {
        if self.state == State::Closed {
            return TrustedStep::Close {
                reply: None,
                outcome: TrustedOutcome::AlreadyClosed,
            };
        }

        // I13 first: a foreign NodeId never reaches the message match, so no
        // behaviour of this state machine is observable to it beyond "closed".
        if !self.trusted {
            self.state = State::Closed;
            return TrustedStep::Close {
                reply: None,
                outcome: TrustedOutcome::NotTrusted,
            };
        }

        match self.state {
            State::ExpectHello => self.expect_hello(message),
            State::Ready => self.serve(message),
            State::Closed => unreachable!("checked above"),
        }
    }

    fn expect_hello(&mut self, message: ControlMsg) -> TrustedStep {
        match message {
            ControlMsg::Hello { version, mode, .. } => {
                if version != PROTOCOL_VERSION {
                    return self.violate(TrustedOutcome::Protocol);
                }
                if mode != HelloMode::Trusted {
                    return self.violate(TrustedOutcome::WrongMode);
                }
                self.state = State::Ready;
                TrustedStep::Idle
            }
            // Anything before `Hello` is a violation, including `Ping`: the peer
            // has not said what it wants yet.
            _ => self.violate(TrustedOutcome::Protocol),
        }
    }

    fn serve(&mut self, message: ControlMsg) -> TrustedStep {
        match message {
            ControlMsg::Ping => TrustedStep::Reply(ControlMsg::Pong),
            ControlMsg::Pong => TrustedStep::Idle,
            ControlMsg::Bye { .. } => {
                self.state = State::Closed;
                TrustedStep::Close {
                    reply: None,
                    outcome: TrustedOutcome::PeerBye,
                }
            }
            // I2: Phase 1 has no application stream on the trusted path. `PakeMsg`,
            // `Paired`, `TrustExchange`, `ConsentResult`, … all land here.
            _ => self.violate(TrustedOutcome::Protocol),
        }
    }

    fn violate(&mut self, outcome: TrustedOutcome) -> TrustedStep {
        self.state = State::Closed;
        TrustedStep::Close {
            reply: Some(ControlMsg::Bye {
                reason: ByeReason::Protocol,
            }),
            outcome,
        }
    }
}

/// The dialer's opening message: trusted mode, no nameplate, no resume.
pub fn trusted_hello() -> ControlMsg {
    ControlMsg::Hello {
        version: PROTOCOL_VERSION,
        mode: HelloMode::Trusted,
        nameplate: None,
        resume: None,
    }
}

/// Hang up on a connection that is not allowed to be here (I13).
///
/// One place for the generic code and reason, so no future call site can leak a
/// more specific reason by accident.
pub fn close_foreign(conn: &dyn Connection) {
    conn.close(FOREIGN_CLOSE_CODE, FOREIGN_CLOSE_REASON);
}

/// Live trusted connections, so a removal can hang up on a device that is
/// connected right now (§5.6 "Pencabutan").
///
/// Cheap to clone; the listener and the command that removes a device share one.
/// Removal is by `Arc` identity, because the same peer can hold several
/// connections and only the registered ones should be closed.
#[derive(Clone, Default)]
pub struct ActiveTrusted {
    inner: Arc<Mutex<Vec<Arc<dyn Connection>>>>,
}

impl std::fmt::Debug for ActiveTrusted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActiveTrusted")
            .field("count", &self.len())
            .finish()
    }
}

impl ActiveTrusted {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .map(|guard| guard.len())
            .unwrap_or_default()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remember a connection so a later revocation can close it.
    pub fn register(&self, conn: Arc<dyn Connection>) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.push(conn);
        }
    }

    /// Forget a connection that ended on its own. Safe to call twice.
    pub fn unregister(&self, conn: &Arc<dyn Connection>) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.retain(|other| !Arc::ptr_eq(other, conn));
        }
    }

    /// Close every live connection to `peer`, and forget them. Returns how many
    /// were closed, which is what `splice devices rm` reports.
    pub fn close_all(&self, peer: &NodeId) -> usize {
        let closed: Vec<Arc<dyn Connection>> = match self.inner.lock() {
            Ok(mut guard) => {
                let (matching, rest): (Vec<_>, Vec<_>) =
                    guard.drain(..).partition(|conn| conn.remote_id() == *peer);
                *guard = rest;
                matching
            }
            Err(_) => return 0,
        };
        let count = closed.len();
        for conn in closed {
            close_foreign(conn.as_ref());
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::ALPN;
    use crate::identity::NodeSecret;
    use crate::net::memory::Network;
    use crate::net::Transport;
    use crate::trust::store::{TrustEntry, TrustStore};
    use std::time::Duration;
    use tempfile::TempDir;

    fn node() -> NodeId {
        NodeSecret::generate().public()
    }

    fn code_pair_hello() -> ControlMsg {
        ControlMsg::Hello {
            version: PROTOCOL_VERSION,
            mode: HelloMode::Pair,
            nameplate: Some(42),
            resume: None,
        }
    }

    fn store_with(dir: &TempDir, ids: &[NodeId]) -> TrustStore {
        let mut store = TrustStore::load_in(dir.path()).unwrap();
        for (index, id) in ids.iter().enumerate() {
            store
                .add(TrustEntry::new(*id, format!("dev{index}"), Duration::ZERO))
                .unwrap();
        }
        store
    }

    #[test]
    fn trusted_hello_is_trusted_mode_without_nameplate() {
        match trusted_hello() {
            ControlMsg::Hello {
                version,
                mode,
                nameplate,
                resume,
            } => {
                assert_eq!(version, PROTOCOL_VERSION);
                assert_eq!(mode, HelloMode::Trusted);
                assert_eq!(nameplate, None);
                assert_eq!(resume, None);
            }
            other => panic!("expected Hello, got {}", other.name()),
        }
    }

    #[test]
    fn a_foreign_peer_gets_silence_and_no_state() {
        let dir = TempDir::new().unwrap();
        let store = store_with(&dir, &[]);
        let peer = node();
        let mut server = TrustedServer::new(&store, peer);
        assert_eq!(server.peer(), peer);
        assert!(!server.is_trusted());

        // Even a well-formed Hello produces no reply: probing learns nothing.
        assert_eq!(
            server.on_message(trusted_hello()),
            TrustedStep::Close {
                reply: None,
                outcome: TrustedOutcome::NotTrusted,
            }
        );
        // And it stays closed, whatever arrives next.
        assert_eq!(
            server.on_message(ControlMsg::Ping),
            TrustedStep::Close {
                reply: None,
                outcome: TrustedOutcome::AlreadyClosed,
            }
        );
    }

    #[test]
    fn a_pinned_peer_completes_the_trusted_handshake() {
        let dir = TempDir::new().unwrap();
        let peer = node();
        let store = store_with(&dir, &[peer]);
        let mut server = TrustedServer::new(&store, peer);
        assert!(server.is_trusted());

        assert_eq!(server.on_message(trusted_hello()), TrustedStep::Idle);
        assert!(server.is_ready());
        assert_eq!(
            server.on_message(ControlMsg::Ping),
            TrustedStep::Reply(ControlMsg::Pong)
        );
        assert_eq!(server.on_message(ControlMsg::Pong), TrustedStep::Idle);
        assert_eq!(
            server.on_message(ControlMsg::Bye {
                reason: ByeReason::Normal
            }),
            TrustedStep::Close {
                reply: None,
                outcome: TrustedOutcome::PeerBye,
            }
        );
    }

    #[test]
    fn the_trusted_path_refuses_the_pairing_mode() {
        let dir = TempDir::new().unwrap();
        let peer = node();
        let mut server = TrustedServer::new(&store_with(&dir, &[peer]), peer);
        let step = server.on_message(code_pair_hello());
        assert_eq!(
            step,
            TrustedStep::Close {
                reply: Some(ControlMsg::Bye {
                    reason: ByeReason::Protocol
                }),
                outcome: TrustedOutcome::WrongMode,
            }
        );
    }

    #[test]
    fn the_trusted_path_refuses_other_versions() {
        let dir = TempDir::new().unwrap();
        let peer = node();
        let mut server = TrustedServer::new(&store_with(&dir, &[peer]), peer);
        let step = server.on_message(ControlMsg::Hello {
            version: PROTOCOL_VERSION + 1,
            mode: HelloMode::Trusted,
            nameplate: None,
            resume: None,
        });
        assert_eq!(
            step,
            TrustedStep::Close {
                reply: Some(ControlMsg::Bye {
                    reason: ByeReason::Protocol
                }),
                outcome: TrustedOutcome::Protocol,
            }
        );
    }

    #[test]
    fn nothing_may_precede_hello_on_the_trusted_path() {
        let dir = TempDir::new().unwrap();
        let peer = node();
        for early in [
            ControlMsg::Ping,
            ControlMsg::TrustAck,
            ControlMsg::Paired {
                caps: crate::proto::messages::Caps::NONE,
            },
        ] {
            let mut server = TrustedServer::new(&store_with(&dir, &[peer]), peer);
            let step = server.on_message(early.clone());
            assert!(
                matches!(
                    step,
                    TrustedStep::Close {
                        outcome: TrustedOutcome::Protocol,
                        ..
                    }
                ),
                "{} before Hello must be a protocol violation, got {step:?}",
                early.name()
            );
        }
    }

    #[test]
    fn i2_allows_only_ping_pong_after_hello() {
        let dir = TempDir::new().unwrap();
        let peer = node();
        let forbidden = [
            ControlMsg::PakeMsg {
                payload: vec![1, 2, 3],
            },
            ControlMsg::PakeConfirm { mac: [7u8; 32] },
            ControlMsg::TrustExchange {
                alias: "sneaky".into(),
            },
            ControlMsg::TrustAck,
            ControlMsg::Paired {
                caps: crate::proto::messages::Caps::NONE,
            },
            ControlMsg::ModeChange { interactive: true },
            code_pair_hello(),
        ];
        for message in forbidden {
            let mut server = TrustedServer::new(&store_with(&dir, &[peer]), peer);
            assert_eq!(server.on_message(trusted_hello()), TrustedStep::Idle);
            let step = server.on_message(message.clone());
            assert_eq!(
                step,
                TrustedStep::Close {
                    reply: Some(ControlMsg::Bye {
                        reason: ByeReason::Protocol
                    }),
                    outcome: TrustedOutcome::Protocol,
                },
                "{} must be an I2 violation",
                message.name()
            );
        }
    }

    #[test]
    fn a_closed_session_stays_closed() {
        let dir = TempDir::new().unwrap();
        let peer = node();
        let mut server = TrustedServer::new(&store_with(&dir, &[peer]), peer);
        assert_eq!(server.on_message(trusted_hello()), TrustedStep::Idle);
        assert!(matches!(
            server.on_message(ControlMsg::TrustAck),
            TrustedStep::Close { .. }
        ));
        assert_eq!(
            server.on_message(ControlMsg::Ping),
            TrustedStep::Close {
                reply: None,
                outcome: TrustedOutcome::AlreadyClosed,
            }
        );
    }

    #[test]
    fn outcomes_all_close_and_have_names() {
        for outcome in [
            TrustedOutcome::NotTrusted,
            TrustedOutcome::WrongMode,
            TrustedOutcome::Protocol,
            TrustedOutcome::PeerBye,
            TrustedOutcome::AlreadyClosed,
        ] {
            assert!(outcome.closes());
            assert!(!outcome.name().is_empty());
        }
    }

    #[test]
    fn the_trust_decision_is_frozen_at_connection_time() {
        let dir = TempDir::new().unwrap();
        let peer = node();
        let mut store = store_with(&dir, &[peer]);
        let mut server = TrustedServer::new(&store, peer);
        assert_eq!(server.on_message(trusted_hello()), TrustedStep::Idle);

        // Removing the device does not retroactively change this session; the
        // listener closes it explicitly through `ActiveTrusted::close_all`.
        store.remove("dev0").unwrap();
        assert!(!store.contains(&peer));
        assert_eq!(
            server.on_message(ControlMsg::Ping),
            TrustedStep::Reply(ControlMsg::Pong)
        );
    }

    #[tokio::test]
    async fn active_trusted_closes_only_the_matching_peer() {
        let net = Network::new();
        let gone = node();
        let kept = node();
        let local = node();

        let gone_ep = net.endpoint_with(gone, false);
        let kept_ep = net.endpoint_with(kept, false);
        let local_ep = net.endpoint_with(local, false);

        let gone_conn = local_ep
            .connect(gone_ep.hint(), ALPN)
            .await
            .expect("dial gone");
        let kept_conn = local_ep
            .connect(kept_ep.hint(), ALPN)
            .await
            .expect("dial kept");

        let active = ActiveTrusted::new();
        active.register(gone_conn.clone());
        active.register(kept_conn.clone());
        active.register(gone_conn.clone());
        assert_eq!(active.len(), 3);

        assert_eq!(active.close_all(&gone), 2);
        assert_eq!(active.len(), 1, "only the removed peer's links are dropped");

        // The closed flag is observable: the peer's side reports closure.
        tokio::time::timeout(Duration::from_secs(5), gone_conn.closed())
            .await
            .expect("closing is immediate");
        assert!(
            tokio::time::timeout(Duration::from_millis(50), kept_conn.closed())
                .await
                .is_err()
        );

        // Removing a peer with no live connection is a no-op, not an error.
        assert_eq!(active.close_all(&node()), 0);
    }

    #[tokio::test]
    async fn unregister_forgets_a_connection_idempotently() {
        let net = Network::new();
        let peer = node();
        let local = node();
        let peer_ep = net.endpoint_with(peer, false);
        let local_ep = net.endpoint_with(local, false);

        let conn = local_ep.connect(peer_ep.hint(), ALPN).await.expect("dial");
        let active = ActiveTrusted::new();
        assert!(active.is_empty());
        active.register(conn.clone());
        assert_eq!(active.len(), 1);
        active.unregister(&conn);
        active.unregister(&conn);
        assert!(active.is_empty());

        // A connection that was forgotten is not closed by a later removal.
        assert_eq!(active.close_all(&peer), 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), conn.closed())
                .await
                .is_err()
        );
    }
}
