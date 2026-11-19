//! Hidden `splice dev …` commands (D10).
//!
//! These exist so every discovery and pairing path can be driven end to end from
//! a terminal. They use an **ephemeral** identity and never write the trust store:
//! a dev session must not leave state that a later run would depend on.
//!
//! * `host-oneshot` / `guest-oneshot <code>` — code + mDNS (or `--addr`).
//! * `host-ticket` / `guest-ticket <ticket>` — ticket, no nameplate, no mDNS.
//! * `ping <alias>` — trusted connection to an already-paired device.
//!
//! Every pairing here runs in [`HelloMode::OneShot`], so the trust exchange of
//! §5.4 step 9 is skipped; the handshake ends with a `Ping`/`Pong` pair, which is
//! what proves the CONTROL stream works in both directions.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use splice_core::clock::SystemClock;
use splice_core::code::{Code, Nameplate};
use splice_core::constants::{HANDSHAKE_TIMEOUT, PAIRING_CODE_TTL};
use splice_core::discovery::mdns::LOOKUP_TIMEOUT;
use splice_core::discovery::presence::{PresenceSocket, PresenceTracker, PRESENCE_PORT};
use splice_core::discovery::{Mdns, Ticket};
use splice_core::identity::{NodeId, NodeSecret};
use splice_core::net::{Connection, NodeAddr, RelaySetting, Transport, REQUIRED_ALPN};
use splice_core::pairing::{GuestSession, HostSession, PairingPhase};
use splice_core::proto::messages::{ControlMsg, HelloMode};
use splice_core::secret::SecretString;
use splice_core::trust::{trusted_hello, TrustStore};

use crate::cli::{
    apply_step, await_peer_hangup, build_endpoint, load_persistent_identity, read_control,
    resolve_addr, resolve_relay, resolve_word_count, write_control, Cli, DevCommand,
};

/// One CONTROL message may not take longer than the handshake budget.
const READ_TIMEOUT: Duration = HANDSHAKE_TIMEOUT;

/// Run one dev subcommand.
pub async fn run(cli: &Cli, cmd: &DevCommand) -> Result<()> {
    match cmd {
        DevCommand::HostOneshot => host_oneshot(cli).await,
        DevCommand::GuestOneshot { code } => guest_oneshot(cli, code).await,
        DevCommand::HostTicket => host_ticket(cli).await,
        DevCommand::GuestTicket { ticket } => guest_ticket(cli, ticket).await,
        DevCommand::Ping { alias } => ping(cli, alias).await,
    }
}

// ---------------------------------------------------------------------------
// Pairing halves (kept public so tests can drive them over the memory transport)
// ---------------------------------------------------------------------------

/// Host: accept one guest, run the PAKE to `Paired`, then answer one `Ping`.
///
/// Returns the peer `NodeId` once the exchange is complete.
pub async fn host_once(host: &mut HostSession, transport: &dyn Transport) -> Result<NodeId> {
    loop {
        let now = Instant::now();
        if host.is_expired(now) {
            if let Some(outcome) = host.expire(now) {
                return Err(anyhow!("kode kedaluwarsa ({})", outcome.name()));
            }
        }

        // Never block longer than one second, so an expiring code is noticed.
        let wait = host
            .next_timer(now)
            .unwrap_or(PAIRING_CODE_TTL)
            .min(Duration::from_secs(1));

        let conn = match timeout(wait, accept_one(transport)).await {
            Ok(Ok(Some(conn))) => conn,
            Ok(Ok(None)) => continue,
            Ok(Err(err)) => return Err(err),
            Err(_) => continue,
        };
        if conn.alpn() != REQUIRED_ALPN {
            warn!(alpn=?conn.alpn(), "ALPN tidak cocok");
            continue;
        }
        let peer = conn.remote_id();
        info!(%peer, "koneksi masuk");
        if let Some(peer) = serve_pairing(host, conn.as_ref(), peer).await? {
            return Ok(peer);
        }
    }
}

/// Accept one connection and serve at most one pairing attempt.
///
/// `Ok(Some(peer))` means the exchange reached `Paired` and the keepalive
/// answered; `Ok(None)` means this connection ended without pairing (the code is
/// still live unless the host burned it). Exposed so tests can hold the
/// [`HostSession`] and inspect its phase and attempt count afterwards.
pub async fn host_accept_once(
    host: &mut HostSession,
    transport: &dyn Transport,
) -> Result<Option<NodeId>> {
    let conn = match accept_one(transport).await? {
        Some(conn) => conn,
        None => return Ok(None),
    };
    if conn.alpn() != REQUIRED_ALPN {
        warn!(alpn=?conn.alpn(), "ALPN tidak cocok");
        return Ok(None);
    }
    let peer = conn.remote_id();
    info!(%peer, "koneksi masuk");
    serve_pairing(host, conn.as_ref(), peer).await
}

/// Wait for one incoming connection. `Ok(None)` is a recoverable accept error
/// (already logged); `Err` means the endpoint is gone.
async fn accept_one(transport: &dyn Transport) -> Result<Option<Arc<dyn Connection>>> {
    match transport.accept().await {
        Ok(Some(conn)) => Ok(Some(conn)),
        Ok(None) => Err(anyhow!("transport ditutup")),
        Err(err) => {
            warn!(error=?err, "accept gagal, lanjut");
            Ok(None)
        }
    }
}

/// Drive one guest through the three-message handshake, then `Ping`/`Pong`.
async fn serve_pairing(
    host: &mut HostSession,
    conn: &dyn Connection,
    peer: NodeId,
) -> Result<Option<NodeId>> {
    // The CONTROL stream is opened by the caller (`Architecture.md` §7), so the
    // accepting side takes it rather than opening a stream of its own.
    let (mut tx, mut rx) = conn
        .accept_bi()
        .await
        .map_err(|e| anyhow!("gagal accept_bi: {e}"))?;

    for step in ["hello", "pake msg", "pake confirm"] {
        let msg = read_with_deadline(&mut rx, step).await?;
        debug!(msg=?msg.name(), "host menerima");
        let reply = host
            .on_message(peer, msg, Instant::now())
            .map_err(|e| anyhow!("host on_message ({step}): {e}"))?;
        if let Some(outcome) = apply_step(&mut tx, reply).await? {
            warn!(outcome=?outcome.name(), "pairing berhenti di {step}");
            // Let the guest read the `Bye` before this connection is dropped.
            await_peer_hangup(&mut rx).await;
            return Ok(None);
        }
    }

    if host.phase() != PairingPhase::Paired {
        warn!(phase=?host.phase(), "pairing tidak selesai");
        return Ok(None);
    }
    info!(%peer, "PAIRED");

    match read_with_deadline(&mut rx, "Ping").await? {
        ControlMsg::Ping => {
            write_control(&mut tx, &ControlMsg::Pong).await?;
            info!(%peer, "Pong terkirim");
            // Dropping the connection here would close it before the guest can
            // read the `Pong`, so wait for the guest to hang up instead.
            await_peer_hangup(&mut rx).await;
            Ok(Some(peer))
        }
        other => {
            warn!(msg=?other.name(), "diharapkan Ping");
            Ok(None)
        }
    }
}

/// How the guest learns its SPAKE2 password.
pub enum GuestPassword<'a> {
    /// Code pairing: the password is derived from the words.
    Code(&'a Code),
    /// Ticket pairing: the password is the ticket secret.
    Ticket(SecretString),
}

/// Guest: connect, run the PAKE, then `Ping`/`Pong`.
pub async fn guest_once(
    self_id: NodeId,
    conn: &dyn Connection,
    mode: HelloMode,
    password: GuestPassword<'_>,
) -> Result<()> {
    let host_id = conn.remote_id();
    let (mut guest, opening) = match password {
        GuestPassword::Code(code) => {
            GuestSession::begin(self_id, host_id, mode, code.clone(), Instant::now())?
        }
        GuestPassword::Ticket(password) => {
            GuestSession::begin_with_password(self_id, host_id, mode, &password, Instant::now())?
        }
    };

    let (mut tx, mut rx) = conn
        .open_bi()
        .await
        .map_err(|e| anyhow!("gagal open_bi: {e}"))?;
    for msg in &opening {
        write_control(&mut tx, msg).await?;
    }

    // Host's PAKE share, then its key confirmation.
    for step in ["pake msg", "pake confirm"] {
        let msg = read_with_deadline(&mut rx, step).await?;
        debug!(msg=?msg.name(), "tamu menerima");
        let reply = guest
            .on_message(host_id, msg, Instant::now())
            .map_err(|e| anyhow!("guest on_message ({step}): {e}"))?;
        if let Some(outcome) = apply_step(&mut tx, reply).await? {
            return Err(anyhow!("pairing gagal: {}", outcome.name()));
        }
    }
    if guest.phase() != PairingPhase::Paired {
        return Err(anyhow!("host tidak membuktikan pengetahuan kode"));
    }

    // The host repeats the same event as `Paired`; a duplicate is harmless.
    match read_with_deadline(&mut rx, "Paired").await? {
        ControlMsg::Paired { .. } => {}
        other => return Err(anyhow!("diharapkan Paired, dapat {:?}", other.name())),
    }

    write_control(&mut tx, &ControlMsg::Ping).await?;
    match read_with_deadline(&mut rx, "Pong").await? {
        ControlMsg::Pong => {
            info!(%host_id, "Pong diterima");
            Ok(())
        }
        other => Err(anyhow!("diharapkan Pong, dapat {:?}", other.name())),
    }
}

/// Read one CONTROL message, mapping a stalled stream to a readable error.
async fn read_with_deadline(
    rx: &mut splice_core::net::RecvStream,
    what: &str,
) -> Result<ControlMsg> {
    timeout(READ_TIMEOUT, read_control(rx))
        .await
        .map_err(|_| anyhow!("batas waktu menunggu {what}"))?
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Host a one-shot code pairing over a fresh ephemeral identity.
async fn host_oneshot(cli: &Cli) -> Result<()> {
    let transport = ephemeral_transport(cli).await?;
    let node_id = transport.node_id();

    let code = generate_code(cli)?;
    println!("🔑 Kode: {}", code.reveal_for_user());
    println!("⏳ Menunggu tamu... (Ctrl+C untuk berhenti)");

    let port = dialable_port(transport.as_ref())?;
    let mdns = Mdns::start()?;
    let advertised = mdns.advertise(code.nameplate().get(), node_id, port)?;

    let mut host = HostSession::new(node_id, HelloMode::OneShot, code, Instant::now())?;
    let result = host_once(&mut host, transport.as_ref()).await;

    mdns.withdraw(&advertised.fullname).ok();
    let peer = result?;
    println!("✅ Terhubung dengan {}", peer.shorthand());
    Ok(())
}

/// Guest side of a one-shot code pairing.
async fn guest_oneshot(cli: &Cli, raw: &str) -> Result<()> {
    let code = Code::parse(raw).map_err(|e| anyhow!("kode tidak valid: {e}"))?;
    let addr = discover_host(cli, code.nameplate().get()).await?;

    let transport = ephemeral_transport(cli).await?;
    let node_id = transport.node_id();
    info!(%node_id, target=%addr.id(), "menghubungi host");

    let conn = dial(transport.as_ref(), addr).await?;
    guest_once(
        node_id,
        conn.as_ref(),
        HelloMode::OneShot,
        GuestPassword::Code(&code),
    )
    .await?;
    println!("✅ Selesai: pairing one-shot berhasil.");
    Ok(())
}

/// Host a ticket pairing. The ticket is the only out-of-band channel.
async fn host_ticket(cli: &Cli) -> Result<()> {
    let transport = ephemeral_transport(cli).await?;
    let node_id = transport.node_id();

    let mut addr = NodeAddr::new(node_id);
    for local in transport.local_addrs() {
        if !local.ip().is_unspecified() && !local.ip().is_loopback() {
            addr = addr.with_ip(local);
        }
    }
    if !addr.has_hint() {
        return Err(anyhow!(
            "endpoint tidak mengiklankan alamat lokal yang dapat dihubungi"
        ));
    }

    let ticket = Ticket::generate(&addr)?;
    println!("🎫 Tiket: {}", ticket.encode().expose_secret());
    println!("⏳ Menunggu tamu... (Ctrl+C untuk berhenti)");

    let mut host = HostSession::new_with_password(
        node_id,
        HelloMode::OneShot,
        &ticket.password_string(),
        Instant::now(),
    )?;
    let peer = host_once(&mut host, transport.as_ref()).await?;
    println!("✅ Terhubung dengan {}", peer.shorthand());
    Ok(())
}

/// Guest side of a ticket pairing.
async fn guest_ticket(cli: &Cli, raw: &str) -> Result<()> {
    let ticket = Ticket::parse(raw).map_err(|e| anyhow!("tiket tidak valid: {e}"))?;
    let addr = ticket.to_node_addr();
    if !addr.has_hint() {
        return Err(anyhow!("tiket tidak memuat alamat; minta tiket baru"));
    }

    let transport = ephemeral_transport(cli).await?;
    let node_id = transport.node_id();
    info!(%node_id, target=%addr.id(), "menghubungi host");

    let conn = dial(transport.as_ref(), addr).await?;
    let password = ticket.password_string();
    guest_once(
        node_id,
        conn.as_ref(),
        HelloMode::OneShot,
        GuestPassword::Ticket(password),
    )
    .await?;
    println!("✅ Selesai: pairing tiket berhasil.");
    Ok(())
}

/// Ping a trusted device by alias, using the persistent identity.
async fn ping(cli: &Cli, alias: &str) -> Result<()> {
    let store = TrustStore::load()?;
    let entry = store
        .find_by_alias(alias)
        .ok_or_else(|| anyhow!("alias `{alias}` tidak ada di daftar tepercaya"))?;
    let target = entry.node_id;

    let (secret, _source) = load_persistent_identity()?;
    let transport = build_endpoint(secret, resolve_relay(cli)?).await?;

    let addr = match resolve_addr(cli)? {
        Some(manual) => manual.with_id(target),
        None => presence_hint(target).await?,
    };

    let conn = dial(transport.as_ref(), addr).await?;
    let (mut tx, mut rx) = conn
        .open_bi()
        .await
        .map_err(|e| anyhow!("gagal open_bi: {e}"))?;

    write_control(&mut tx, &trusted_hello()).await?;
    write_control(&mut tx, &ControlMsg::Ping).await?;

    match read_with_deadline(&mut rx, "Pong").await? {
        ControlMsg::Pong => {
            println!("✅ Pong dari {alias} ({})", target.shorthand());
            Ok(())
        }
        other => Err(anyhow!("diharapkan Pong, dapat {:?}", other.name())),
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Build an endpoint on a fresh ephemeral identity, per the dev commands' promise
/// that they touch nothing on disk.
async fn ephemeral_transport(cli: &Cli) -> Result<Arc<dyn Transport>> {
    let relay: RelaySetting = resolve_relay(cli)?;
    build_endpoint(NodeSecret::generate(), relay).await
}

/// Generate a code with a free nameplate.
fn generate_code(cli: &Cli) -> Result<Code> {
    let nameplate = Nameplate::random_avoiding(&[], &mut rand::rng())
        .ok_or_else(|| anyhow!("tidak ada nameplate tersedia"))?;
    Ok(Code::generate(
        &mut rand::rng(),
        resolve_word_count(cli)?,
        nameplate,
    )?)
}

/// The port mDNS should advertise: the first address a peer could actually dial.
fn dialable_port(transport: &dyn Transport) -> Result<u16> {
    transport
        .local_addrs()
        .iter()
        .find(|addr| !addr.ip().is_unspecified() && !addr.ip().is_loopback())
        .map(|addr| addr.port())
        .ok_or_else(|| anyhow!("endpoint tidak mengiklankan alamat lokal yang dapat dihubungi"))
}

/// Dial with a deadline, so a peer that never answers cannot hang the command.
async fn dial(transport: &dyn Transport, addr: NodeAddr) -> Result<Arc<dyn Connection>> {
    let conn = timeout(HANDSHAKE_TIMEOUT, transport.connect(addr, REQUIRED_ALPN))
        .await
        .map_err(|_| anyhow!("batas waktu dial"))?
        .map_err(|e| anyhow!("gagal dial: {e}"))?;
    if conn.alpn() != REQUIRED_ALPN {
        return Err(anyhow!("ALPN tidak cocok: {:?}", conn.alpn()));
    }
    Ok(conn)
}

/// Find the host: mDNS first, then `--addr`.
async fn discover_host(cli: &Cli, nameplate: u16) -> Result<NodeAddr> {
    match Mdns::start() {
        Ok(mdns) => match mdns.lookup(nameplate, LOOKUP_TIMEOUT).await {
            Ok(host) => {
                if let Some(addr) = host.to_node_addr() {
                    return Ok(addr);
                }
            }
            Err(err) => debug!(error=?err, "mDNS lookup gagal"),
        },
        Err(err) => debug!(error=?err, "mDNS tidak tersedia"),
    }

    if let Some(manual) = resolve_addr(cli)? {
        return manual
            .to_node_addr()
            .map_err(|e| anyhow!("alamat tidak lengkap: {e}"));
    }

    Err(anyhow!(
        "host tidak ditemukan. Coba --addr nodeid@ip:port atau pakai tiket"
    ))
}

/// Wait for one presence beacon from `target`, per §5.3 path 4.
async fn presence_hint(target: NodeId) -> Result<NodeAddr> {
    let socket = PresenceSocket::bind(PRESENCE_PORT)?;
    let mut tracker = PresenceTracker::new(Arc::new(SystemClock));
    tracker.set_trusted(vec![target]);

    let deadline = Instant::now() + LOOKUP_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, socket.recv()).await {
            Ok(Ok((buffer, len, from))) => {
                if let Some(presence) = tracker.observe(&buffer[..len.min(buffer.len())], from) {
                    return Ok(presence.to_node_addr());
                }
            }
            Ok(Err(err)) => return Err(anyhow!("presence: {err}")),
            Err(_) => break,
        }
    }

    Err(anyhow!(
        "perangkat tidak terlihat di LAN; jalankan `splice listen` di sana atau pakai --addr nodeid@ip:port"
    ))
}
