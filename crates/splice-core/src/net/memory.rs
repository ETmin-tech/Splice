//! In-memory transport used by unit tests.
//!
//! Two endpoints live in one process and are wired together by [`Network`]. No
//! sockets, no QUIC, no timing: the fake exists to test the pairing state machine
//! and the trust checks, which must not depend on a real network being available.
//!
//! Deliberate limitation: one bidirectional stream per connection, which is all a
//! Phase 1 CONTROL exchange needs. A test that wants a second stream gets a clear
//! error rather than a silently different pipe.
//!
//! What the fake does **not** prove: TLS identity binding, ALPN negotiation, path
//! selection, or that a hostile peer cannot forge an identity. Tests that need
//! those use the real transport on loopback.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{duplex, DuplexStream};
use tokio::sync::{mpsc, watch};

use super::{BoxFuture, Connection, NodeAddr, PathKind, RecvStream, Result, SendStream, Transport};
use crate::error::NetError;
use crate::identity::{NodeId, NodeSecret};

/// A dial attempt waiting in the acceptor's queue.
///
/// The dialer's identity and the negotiated ALPN travel beside the byte pipe,
/// because a real transport gets both from the handshake, not from the bytes.
struct Arrival {
    from: NodeId,
    alpn: Vec<u8>,
    pipe: DuplexStream,
}

/// A one-way "closed" broadcast. `watch` is used rather than a bare `Notify`
/// because a waiter that subscribes after the close must still see `true`.
struct Flag {
    tx: watch::Sender<bool>,
}

impl Flag {
    fn new() -> Self {
        let (tx, _rx) = watch::channel(false);
        Self { tx }
    }

    fn close(&self) {
        // `send_replace` always updates the value and never fails; `send` would
        // fail when no receiver currently exists, silently dropping the close.
        self.tx.send_replace(true);
    }

    fn subscribe(&self) -> watch::Receiver<bool> {
        self.tx.subscribe()
    }
}

async fn wait_closed(mut rx: watch::Receiver<bool>) {
    // `wait_for` returns as soon as the value is already `true`, so no ordering
    // problem between "subscribe" and "close".
    let _ = rx.wait_for(|closed| *closed).await;
}

/// In-process network. Cheap to clone; all endpoints share one registry.
#[derive(Clone, Default)]
pub struct Network {
    senders: Arc<Mutex<HashMap<NodeId, mpsc::Sender<Arrival>>>>,
}

impl Network {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new endpoint with a fresh ephemeral identity.
    pub fn endpoint(&self, relay: bool) -> MemoryTransport {
        self.endpoint_with(NodeSecret::generate().public(), relay)
    }

    /// Register an endpoint with a caller-chosen identity (useful for trust tests).
    pub fn endpoint_with(&self, id: NodeId, relay: bool) -> MemoryTransport {
        let (sender, receiver) = mpsc::channel(8);
        self.senders
            .lock()
            .expect("network registry poisoned")
            .insert(id, sender);
        MemoryTransport {
            id,
            senders: self.senders.clone(),
            incoming: Arc::new(Mutex::new(Some(receiver))),
            relay,
            closed: Flag::new(),
        }
    }

    /// Remove an endpoint. Later dials to `id` fail with "unknown node", and a
    /// pending `accept` on that endpoint returns `None`.
    pub fn remove(&self, id: NodeId) {
        self.senders
            .lock()
            .expect("network registry poisoned")
            .remove(&id);
    }
}

/// A fake endpoint bound to a [`Network`].
pub struct MemoryTransport {
    id: NodeId,
    senders: Arc<Mutex<HashMap<NodeId, mpsc::Sender<Arrival>>>>,
    /// Taken out of the mutex for the duration of one `accept` call, then put
    /// back, so a `std` guard is never held across an await point.
    incoming: Arc<Mutex<Option<mpsc::Receiver<Arrival>>>>,
    relay: bool,
    closed: Flag,
}

impl MemoryTransport {
    /// A hint that dials this endpoint, shaped like a real `NodeAddr`.
    pub fn hint(&self) -> NodeAddr {
        NodeAddr::direct(self.id, fake_addr())
    }

    /// Simulate a network-level close from the remote side.
    pub fn force_close(&self) {
        self.closed.close();
    }
}

fn fake_addr() -> SocketAddr {
    ([127, 0, 0, 1], 1).into()
}

impl Transport for MemoryTransport {
    fn node_id(&self) -> NodeId {
        self.id
    }

    fn local_addrs(&self) -> Vec<SocketAddr> {
        vec![fake_addr()]
    }

    fn connect(&self, addr: NodeAddr, alpn: &[u8]) -> BoxFuture<Result<Arc<dyn Connection>>> {
        let from = self.id;
        let to = addr.id();
        let senders = self.senders.clone();
        let relay = self.relay;
        let alpn = alpn.to_vec();
        Box::pin(async move {
            if from == to {
                return Err(NetError::Dial("cannot dial self".to_string()).into());
            }
            let sender = senders
                .lock()
                .expect("network registry poisoned")
                .get(&to)
                .cloned()
                .ok_or_else(|| NetError::Dial("unknown node".to_string()))?;

            // `duplex` hands back the two ends of one bidirectional pipe.
            let (dialer_pipe, acceptor_pipe) = duplex(256 * 1024);
            sender
                .try_send(Arrival {
                    from,
                    alpn: alpn.clone(),
                    pipe: acceptor_pipe,
                })
                .map_err(|_| NetError::Dial("peer is not accepting".to_string()))?;

            Ok(Arc::new(End {
                peer: to,
                relay,
                alpn,
                pipe: Mutex::new(Some(dialer_pipe)),
                closed: Flag::new(),
            }) as Arc<dyn Connection>)
        })
    }

    fn accept(&self) -> BoxFuture<Result<Option<Arc<dyn Connection>>>> {
        let relay = self.relay;
        let incoming = self.incoming.clone();
        let endpoint_closed = self.closed.subscribe();
        Box::pin(async move {
            let receiver = {
                let mut guard = incoming.lock().expect("accept queue poisoned");
                guard.take().ok_or_else(|| {
                    NetError::Transport(
                        "accept is already in progress for this endpoint".to_string(),
                    )
                })?
            };

            // Honour `Transport::close` while waiting: a closed endpoint stops
            // accepting instead of blocking forever.
            let mut receiver = receiver;
            let mut closed = endpoint_closed;
            let received = tokio::select! {
                received = receiver.recv() => received,
                _ = closed.wait_for(|closed| *closed) => None,
            };

            // Always restore the queue, even after a close, so the error message
            // for a second concurrent `accept` stays correct.
            *incoming.lock().expect("accept queue poisoned") = Some(receiver);

            match received {
                None => Ok(None),
                Some(Arrival { from, alpn, pipe }) => Ok(Some(Arc::new(End {
                    peer: from,
                    relay,
                    alpn,
                    pipe: Mutex::new(Some(pipe)),
                    closed: Flag::new(),
                })
                    as Arc<dyn Connection>)),
            }
        })
    }

    fn close(&self) -> BoxFuture<()> {
        self.closed.close();
        Box::pin(async {})
    }
}

struct End {
    /// The peer identity: on the dialer side the callee, on the acceptor side the
    /// caller. This is what a real transport takes from TLS.
    peer: NodeId,
    relay: bool,
    alpn: Vec<u8>,
    /// Both ends start with their own half of the pipe and hand it out exactly once.
    pipe: Mutex<Option<DuplexStream>>,
    closed: Flag,
}

impl End {
    fn take_pipe(&self) -> Result<(SendStream, RecvStream)> {
        let pipe = self
            .pipe
            .lock()
            .expect("pipe mutex poisoned")
            .take()
            .ok_or_else(|| {
                NetError::Transport("fake connection supports a single stream".to_string())
            })?;
        let (read, write) = tokio::io::split(pipe);
        Ok((Box::new(write) as SendStream, Box::new(read) as RecvStream))
    }
}

impl Connection for End {
    fn remote_id(&self) -> NodeId {
        self.peer
    }

    fn alpn(&self) -> Vec<u8> {
        self.alpn.clone()
    }

    fn path_kind(&self) -> PathKind {
        if self.relay {
            PathKind::Relay
        } else {
            PathKind::Direct
        }
    }

    fn rtt(&self) -> Option<Duration> {
        Some(Duration::from_millis(1))
    }

    fn open_bi(&self) -> BoxFuture<Result<(SendStream, RecvStream)>> {
        let taken = self.take_pipe();
        Box::pin(async move { taken })
    }

    fn accept_bi(&self) -> BoxFuture<Result<(SendStream, RecvStream)>> {
        // The fake pipe is symmetric: both sides "open" their own half.
        self.open_bi()
    }

    fn close(&self, _code: u32, _reason: &'static [u8]) {
        self.closed.close();
    }

    fn closed(&self) -> BoxFuture<()> {
        let rx = self.closed.subscribe();
        Box::pin(wait_closed(rx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn dial_and_accept_exchange_identity_and_bytes() {
        let net = Network::new();
        let a = net.endpoint(false);
        let b = net.endpoint(false);
        let (a_id, b_id) = (a.node_id(), b.node_id());

        let dial = a.connect(b.hint(), crate::constants::ALPN).await.unwrap();

        let mut accepted = None;
        while accepted.is_none() {
            accepted = b.accept().await.unwrap();
        }
        let accepted = accepted.unwrap();

        // Identity is per side, not self-reported by the peer's bytes.
        assert_eq!(dial.remote_id(), b_id);
        assert_eq!(accepted.remote_id(), a_id);

        // Both see the same ALPN, and the acceptor reports the requested one.
        assert_eq!(dial.alpn(), crate::constants::ALPN.to_vec());
        assert_eq!(accepted.alpn(), crate::constants::ALPN.to_vec());
        assert_eq!(dial.path_kind(), PathKind::Direct);

        let (mut dial_tx, mut dial_rx) = dial.open_bi().await.unwrap();
        let (mut acc_tx, mut acc_rx) = accepted.open_bi().await.unwrap();

        dial_tx.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        acc_rx.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        acc_tx.write_all(b"world").await.unwrap();
        let mut buf = [0u8; 5];
        dial_rx.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");

        // A second stream is refused loudly instead of silently aliasing the first.
        assert!(dial.open_bi().await.is_err());
    }

    #[tokio::test]
    async fn closing_a_connection_resolves_closed() {
        let net = Network::new();
        let a = net.endpoint(false);
        let b = net.endpoint(false);
        let dial = a.connect(b.hint(), crate::constants::ALPN).await.unwrap();

        dial.close(0, b"bye");
        // Must observe an already-closed connection, not wait for a notification.
        tokio::time::timeout(Duration::from_millis(50), dial.closed())
            .await
            .expect("closed() should resolve immediately");
    }

    #[tokio::test]
    async fn closing_the_endpoint_stops_accept() {
        let net = Network::new();
        let b = net.endpoint(false);
        b.close().await;
        assert!(b.accept().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn dialing_an_unknown_node_fails() {
        let net = Network::new();
        let a = net.endpoint(false);
        let err = match a
            .connect(
                NodeAddr::direct(NodeSecret::generate().public(), fake_addr()),
                crate::constants::ALPN,
            )
            .await
        {
            Ok(_) => panic!("dial to an unknown node should fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("unknown node"));
    }

    #[tokio::test]
    async fn a_second_concurrent_accept_is_an_error_not_a_hang() {
        let net = Network::new();
        let b = Arc::new(net.endpoint(false));
        let first = {
            let b = b.clone();
            tokio::spawn(async move { b.accept().await })
        };
        // Give the first accept a chance to take the queue.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let second = b.accept().await;
        assert!(second.is_err());
        first.abort();
    }
}
