//! `splice listen` — the minimal Phase 1 form (D9).
//!
//! Announces this device's presence, accepts connections, and answers `Ping` with
//! `Pong` only for NodeIds in the trust store. File transfer is Phase 2; this
//! minimal form exists so trusted-device discovery can be tested in Phase 1.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use tokio::time::{interval, timeout, MissedTickBehavior};
use tracing::{debug, info, warn};

use splice_core::clock::{Clock, SystemClock};
use splice_core::constants::HANDSHAKE_TIMEOUT;
use splice_core::discovery::presence::{bucket_at, tag_for, Beacon, PresenceSocket, PRESENCE_PORT};
use splice_core::identity::NodeId;
use splice_core::net::{Connection, REQUIRED_ALPN};
use splice_core::trust::{close_foreign, ActiveTrusted, TrustStore, TrustedServer, TrustedStep};

use crate::cli::{
    build_endpoint, load_persistent_identity, read_control, resolve_relay, write_control, Cli,
};

/// Run the listen command. Only `Ctrl+C` or a fatal error ends it.
pub async fn run(cli: &Cli) -> Result<()> {
    let (secret, source) = load_persistent_identity()?;
    let relay = resolve_relay(cli)?;
    let transport = build_endpoint(secret, relay).await?;
    let node_id = transport.node_id();
    info!(%node_id, source=?source, "listen siap");

    let store = Arc::new(TrustStore::load()?);
    let presence = PresenceSocket::bind(PRESENCE_PORT)
        .context("gagal membuka soket presence (multicast tidak tersedia)")?;
    let beacon_port = transport
        .local_addrs()
        .iter()
        .find(|addr| !addr.ip().is_unspecified() && !addr.ip().is_loopback())
        .map(|addr| addr.port())
        .ok_or_else(|| anyhow!("endpoint tidak mengiklankan alamat lokal yang dapat dihubungi"))?;

    println!("👂 Mendengarkan. NodeId: {node_id}");
    if store.is_empty() {
        println!("   Belum ada perangkat tepercaya; hanya koneksi tercatat yang dilayani.");
    } else {
        println!("   {} perangkat tepercaya.", store.len());
    }

    let active = ActiveTrusted::new();
    let mut beacon_timer = interval(PresenceSocket::interval());
    beacon_timer.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = beacon_timer.tick() => {
                let now = SystemClock.now();
                let beacon = Beacon {
                    tag: tag_for(node_id, bucket_at(now)),
                    port: beacon_port,
                };
                if let Err(err) = presence.send(&beacon).await {
                    warn!(error=?err, "beacon gagal dikirim; mencoba lagi di tick berikutnya");
                }
            }
            datagram = presence.recv() => {
                match datagram {
                    Ok((buffer, len, from)) => {
                        // Other devices' beacons say nothing about what to do here:
                        // this command's job is to be seen, not to dial.
                        if let Some(beacon) = Beacon::decode(&buffer[..len.min(buffer.len())]) {
                            debug!(%from, port=beacon.port, "beacon dari perangkat lain");
                        }
                    }
                    Err(err) => warn!(error=?err, "presence recv gagal"),
                }
            }
            accepted = transport.accept() => {
                let conn = match accepted {
                    Ok(Some(conn)) => conn,
                    Ok(None) => {
                        warn!("transport ditutup");
                        return Err(anyhow!("transport ditutup"));
                    }
                    Err(err) => {
                        warn!(error=?err, "accept gagal");
                        continue;
                    }
                };
                let peer = conn.remote_id();

                // I13: the store decides, before any stream is opened. A foreign
                // peer learns nothing; it is simply closed.
                if !store.contains(&peer) {
                    info!(%peer, "NodeId asing ditolak");
                    close_foreign(conn.as_ref());
                    continue;
                }
                if conn.alpn() != REQUIRED_ALPN {
                    warn!(alpn=?conn.alpn(), "ALPN tidak cocok");
                    close_foreign(conn.as_ref());
                    continue;
                }

                let active = active.clone();
                let store = Arc::clone(&store);
                tokio::spawn(async move {
                    active.register(Arc::clone(&conn));
                    if let Err(err) = serve_trusted(conn.as_ref(), &store, peer).await {
                        debug!(%peer, error=?err, "sesi tepercaya berakhir");
                    }
                    active.unregister(&conn);
                });
            }
            _ = tokio::signal::ctrl_c() => {
                println!();
                println!("Berhenti.");
                return Ok(());
            }
        }
    }
}

/// One trusted connection: `Hello{mode: Trusted}`, then only keepalives (I2).
async fn serve_trusted(conn: &dyn Connection, store: &TrustStore, peer: NodeId) -> Result<()> {
    // The CONTROL stream is opened by the caller (`Architecture.md` §7), so the
    // accepting side takes it rather than opening a stream of its own.
    let (mut tx, mut rx) = conn
        .accept_bi()
        .await
        .map_err(|e| anyhow!("gagal accept_bi: {e}"))?;
    let mut server = TrustedServer::new(store, peer);
    debug!(%peer, "sesi tepercaya dimulai");

    loop {
        let msg = match timeout(HANDSHAKE_TIMEOUT, read_control(&mut rx)).await {
            Ok(Ok(msg)) => msg,
            Ok(Err(err)) => {
                debug!(%peer, error=?err, "stream ditutup");
                return Ok(());
            }
            Err(_) => {
                debug!(%peer, "tidak ada pesan, menutup");
                return Ok(());
            }
        };
        debug!(%peer, msg=?msg.name(), "terima");

        match server.on_message(msg) {
            TrustedStep::Idle => {}
            TrustedStep::Reply(reply) => write_control(&mut tx, &reply).await?,
            TrustedStep::Close { reply, outcome } => {
                if let Some(reply) = reply {
                    // Best effort: the session is ending either way.
                    let _ = write_control(&mut tx, &reply).await;
                }
                debug!(%peer, outcome=outcome.name(), "sesi tepercaya ditutup");
                return Ok(());
            }
        }
    }
}
