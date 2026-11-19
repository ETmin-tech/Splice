//! iroh implementation of [`Transport`] / [`Connection`].
//!
//! This is the only module (besides `identity`) that names an iroh type. The
//! choices encoded here come straight from spike S1:
//!
//! * `presets::Minimal` + `RelayMode::Disabled` for LAN-only: no DNS, no relay
//!   transport, bind succeeds offline in ~6 ms.
//! * Address lookup is only attached when a relay is configured; the default
//!   `N0` preset would otherwise publish our address to a third party.
//! * We never await `Endpoint::online()`: measured at 20 s+ with no route.
//! * Dialing a peer that does not speak `splice/1` costs a ~30 s timeout rather
//!   than a fast error, so callers must wrap `connect` in their own deadline.

use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, RelayMode};

use super::{
    BoxFuture, Connection, EndpointConfig, NodeAddr, PathKind, RecvStream, RelaySetting, Result,
    SendStream, Transport,
};
use crate::constants::ALPN;
use crate::error::NetError;
use crate::identity::NodeId;

/// Bind an iroh endpoint from our own configuration type.
pub async fn bind(config: EndpointConfig) -> Result<Arc<dyn Transport>> {
    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(config.secret.to_iroh())
        .alpns(config.alpns.clone());

    builder = match &config.relay {
        RelaySetting::Disabled => builder.relay_mode(RelayMode::Disabled),
        RelaySetting::Default => builder.relay_mode(RelayMode::Default),
        RelaySetting::Custom(url) => builder.relay_mode(RelayMode::custom([url
            .parse::<iroh::RelayUrl>()
            .map_err(|err| NetError::Transport(format!("relay url {url:?}: {err}")))?])),
    };

    if let Some(addr) = config.bind {
        builder = builder
            .bind_addr(addr)
            .map_err(|err| NetError::Transport(format!("bind address {addr}: {err}")))?;
    }

    let endpoint = builder
        .bind()
        .await
        .map_err(|err| NetError::EndpointCreate(err.to_string()))?;

    Ok(Arc::new(IrohTransport { endpoint }))
}

struct IrohTransport {
    endpoint: Endpoint,
}

impl IrohTransport {
    fn to_endpoint_addr(&self, addr: &NodeAddr) -> EndpointAddr {
        let mut out = EndpointAddr::new(addr.id().to_iroh());
        for ip in addr.ip_addrs() {
            out = out.with_ip_addr(*ip);
        }
        if let Some(relay) = addr.relay() {
            if let Ok(url) = relay.parse::<iroh::RelayUrl>() {
                out = out.with_relay_url(url);
            }
        }
        out
    }
}

impl Transport for IrohTransport {
    fn node_id(&self) -> NodeId {
        NodeId::from_iroh(self.endpoint.id())
    }

    fn local_addrs(&self) -> Vec<std::net::SocketAddr> {
        // `bound_sockets` only reports what the socket was bound to, which for the
        // default configuration is `0.0.0.0:port` and `[::]:port`; the interface
        // addresses are what iroh derives from those binds plus netmon. Callers
        // need the latter (they filter out unspecified and loopback), otherwise a
        // host on a LAN or in a network namespace has no dialable address at all.
        self.endpoint.addr().ip_addrs().copied().collect()
    }

    fn connect(&self, addr: NodeAddr, alpn: &[u8]) -> BoxFuture<Result<Arc<dyn Connection>>> {
        let target = self.to_endpoint_addr(&addr);
        let expected = addr.id();
        let endpoint = self.endpoint.clone();
        let alpn = alpn.to_vec();
        Box::pin(async move {
            let conn = endpoint
                .connect(target, &alpn)
                .await
                .map_err(|err| NetError::Dial(err.to_string()))?;
            // Defence in depth: TLS already proved the peer id, and we check it again
            // so a transport bug cannot silently connect us to the wrong node.
            let remote = NodeId::from_iroh(conn.remote_id());
            if remote != expected {
                conn.close(0u32.into(), b"identity mismatch");
                return Err(NetError::Rejected(
                    "peer identity does not match the requested node".to_string(),
                )
                .into());
            }
            Ok(Arc::new(IrohConnection { inner: conn }) as Arc<dyn Connection>)
        })
    }

    fn accept(&self) -> BoxFuture<Result<Option<Arc<dyn Connection>>>> {
        let endpoint = self.endpoint.clone();
        Box::pin(async move {
            match endpoint.accept().await {
                None => Ok(None),
                Some(incoming) => {
                    let conn = incoming
                        .await
                        .map_err(|err| NetError::Transport(err.to_string()))?;
                    Ok(Some(
                        Arc::new(IrohConnection { inner: conn }) as Arc<dyn Connection>
                    ))
                }
            }
        })
    }

    fn close(&self) -> BoxFuture<()> {
        let endpoint = self.endpoint.clone();
        Box::pin(async move { endpoint.close().await })
    }
}

struct IrohConnection {
    inner: iroh::endpoint::Connection,
}

impl Connection for IrohConnection {
    fn remote_id(&self) -> NodeId {
        NodeId::from_iroh(self.inner.remote_id())
    }

    fn alpn(&self) -> Vec<u8> {
        self.inner.alpn().to_vec()
    }

    fn path_kind(&self) -> PathKind {
        // `Path` borrows the connection, so read it and drop it immediately.
        let paths = self.inner.paths();
        let selected = paths.iter().find(|path| path.is_selected());
        match selected {
            Some(path) if path.is_relay() => PathKind::Relay,
            Some(path) if path.is_ip() => PathKind::Direct,
            Some(_) => PathKind::Unknown,
            None => PathKind::Unknown,
        }
    }

    fn rtt(&self) -> Option<Duration> {
        let paths = self.inner.paths();
        let selected = paths.iter().find(|path| path.is_selected())?;
        Some(selected.rtt())
    }

    fn open_bi(&self) -> BoxFuture<Result<(SendStream, RecvStream)>> {
        let conn = self.inner.clone();
        Box::pin(async move {
            let (send, recv) = conn
                .open_bi()
                .await
                .map_err(|err| NetError::Transport(err.to_string()))?;
            Ok((Box::new(send) as SendStream, Box::new(recv) as RecvStream))
        })
    }

    fn accept_bi(&self) -> BoxFuture<Result<(SendStream, RecvStream)>> {
        let conn = self.inner.clone();
        Box::pin(async move {
            let (send, recv) = conn
                .accept_bi()
                .await
                .map_err(|err| NetError::Transport(err.to_string()))?;
            Ok((Box::new(send) as SendStream, Box::new(recv) as RecvStream))
        })
    }

    fn close(&self, code: u32, reason: &'static [u8]) {
        self.inner.close(code.into(), reason);
    }

    fn closed(&self) -> BoxFuture<()> {
        let conn = self.inner.clone();
        Box::pin(async move {
            conn.closed().await;
        })
    }
}

/// The ALPN every real connection must have negotiated.
pub const REQUIRED_ALPN: &[u8] = ALPN;
