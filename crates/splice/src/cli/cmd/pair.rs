//! `splice pair` and `splice pair --join [CODE]`
//!
//! Host path: generate code, advertise via mDNS, accept guest, run PAKE,
//! trust exchange, save to trust store.
//!
//! Guest path: parse code (or prompt hidden), discover host via mDNS or
//! `--addr`, dial, run PAKE, trust exchange.

use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use splice_core::clock::{Clock, SystemClock};
use splice_core::code::{Code, Nameplate};
use splice_core::constants::{HANDSHAKE_TIMEOUT, PAIRING_CODE_TTL};
use splice_core::discovery::mdns::LOOKUP_TIMEOUT;
use splice_core::discovery::Mdns;
use splice_core::identity::NodeId;
use splice_core::net::{Connection, NodeAddr, REQUIRED_ALPN};
use splice_core::pairing::{consent_or_refuse, GuestSession, HostSession, PairingPhase};
use splice_core::proto::messages::{sanitize_alias, ByeReason, ControlMsg, HelloMode};
use splice_core::trust::{TrustEntry, TrustStore};

use crate::cli::{
    apply_step, await_peer_hangup, build_endpoint, load_persistent_identity, make_prompter,
    read_control, resolve_addr, resolve_relay, resolve_word_count, write_control, Cli, PairArgs,
};

/// How long one CONTROL message may take during the handshake.
const READ_TIMEOUT: Duration = HANDSHAKE_TIMEOUT;

/// Run the pair command.
pub async fn run(cli: &Cli, args: &PairArgs) -> Result<()> {
    match &args.join {
        Some(code_opt) => join(cli, code_opt.as_deref()).await,
        None => host(cli).await,
    }
}

// ---------------------------------------------------------------------------
// Host
// ---------------------------------------------------------------------------

async fn host(cli: &Cli) -> Result<()> {
    let (secret, source) = load_persistent_identity()?;
    let relay = resolve_relay(cli)?;
    let transport = build_endpoint(secret, relay).await?;
    let node_id = transport.node_id();

    info!(%node_id, source=?source, "host mode siap");

    // Generate the code and the state machine that owns it.
    let wc = resolve_word_count(cli)?;
    let nameplate = Nameplate::random_avoiding(&[], &mut rand::rng())
        .ok_or_else(|| anyhow!("tidak ada nameplate tersedia"))?;
    let code = Code::generate(&mut rand::rng(), wc, nameplate)?;
    let mut host = HostSession::new(node_id, HelloMode::Pair, code, Instant::now())?;

    let reveal = host
        .code()
        .ok_or_else(|| anyhow!("sesi pair tanpa kode"))?
        .reveal_for_user();
    println!("🔑 Kode: {reveal}");
    println!("⏳ Menunggu perangkat lain...");

    // Advertise on the LAN. The port comes from the endpoint, because mDNS is the
    // only channel that carries it.
    let local_port = transport
        .local_addrs()
        .iter()
        .find(|addr| !addr.ip().is_unspecified() && !addr.ip().is_loopback())
        .map(|addr| addr.port())
        .ok_or_else(|| anyhow!("endpoint tidak mengiklankan alamat lokal yang dapat dihubungi"))?;

    let mdns = Mdns::start().map_err(|e| anyhow!("mDNS gagal: {e}"))?;
    let np = host
        .code()
        .ok_or_else(|| anyhow!("sesi pair tanpa kode"))?
        .nameplate()
        .get();
    let advertised = mdns
        .advertise(np, node_id, local_port)
        .map_err(|e| anyhow!("mDNS advertise gagal: {e}"))?;

    let prompter = make_prompter(cli);
    let mut trust_store = TrustStore::load()?;

    let result = accept_loop(
        &mut host,
        transport.as_ref(),
        prompter.as_ref(),
        &mut trust_store,
        node_id,
    )
    .await;

    mdns.withdraw(&advertised.fullname).ok();
    result
}

/// Accept connections until one pairing completes or the code expires.
async fn accept_loop(
    host: &mut HostSession,
    transport: &dyn splice_core::net::Transport,
    prompter: &dyn splice_core::pairing::Prompter,
    trust_store: &mut TrustStore,
    node_id: NodeId,
) -> Result<()> {
    loop {
        let now = Instant::now();
        if host.is_expired(now) {
            if let Some(outcome) = host.expire(now) {
                println!("⏰ Kode kedaluwarsa: {}", outcome.name());
                return Err(anyhow!("kode kedaluwarsa"));
            }
        }

        // Wake up at the next state-machine deadline, but never longer than the
        // code TTL, so expiry is noticed promptly.
        let timer = host.next_timer(now).unwrap_or(PAIRING_CODE_TTL);
        let accept_timeout = timer.min(Duration::from_secs(1));

        let accepted = match timeout(accept_timeout, transport.accept()).await {
            Ok(Ok(Some(conn))) => conn,
            Ok(Ok(None)) => {
                warn!("transport ditutup");
                return Err(anyhow!("transport ditutup"));
            }
            Ok(Err(e)) => {
                warn!(error=?e, "accept gagal, lanjut");
                continue;
            }
            Err(_) => continue,
        };

        if accepted.alpn() != REQUIRED_ALPN {
            warn!(alpn=?accepted.alpn(), "ALPN tidak cocok");
            continue;
        }
        let peer = accepted.remote_id();
        info!(%peer, "koneksi masuk");

        match serve_guest(
            host,
            accepted.as_ref(),
            peer,
            prompter,
            trust_store,
            node_id,
        )
        .await
        {
            Ok(Some(())) => return Ok(()),
            Ok(None) => continue,
            Err(err) => {
                warn!(error=?err, "pairing dengan tamu gagal");
                continue;
            }
        }
    }
}

/// Run one guest through the handshake. `Ok(Some(()))` means pairing finished,
/// `Ok(None)` means this connection is done but the code is still live.
async fn serve_guest(
    host: &mut HostSession,
    conn: &dyn Connection,
    peer: NodeId,
    prompter: &dyn splice_core::pairing::Prompter,
    trust_store: &mut TrustStore,
    node_id: NodeId,
) -> Result<Option<()>> {
    // The CONTROL stream is opened by the caller (`Architecture.md` §7), so the
    // accepting side takes it rather than opening a stream of its own.
    let (mut tx, mut rx) = conn
        .accept_bi()
        .await
        .map_err(|e| anyhow!("gagal accept_bi: {e}"))?;

    // Hello, PakeMsg, PakeConfirm: one message in, at most one reply out.
    for step_name in ["hello", "pake msg", "pake confirm"] {
        let msg = timeout(READ_TIMEOUT, read_control(&mut rx))
            .await
            .map_err(|_| anyhow!("batas waktu menunggu {step_name}"))??;
        debug!(msg=?msg.name(), "terima dari tamu");
        let step = host
            .on_message(peer, msg, Instant::now())
            .with_context(|| format!("host on_message ({step_name})"))?;
        if let Some(outcome) = apply_step(&mut tx, step).await? {
            debug!(outcome=?outcome.name(), "pairing berakhir di {step_name}");
            // Let the guest read the `Bye` before this connection is dropped.
            await_peer_hangup(&mut rx).await;
            return Ok(None);
        }
        if step_name == "pake confirm" {
            // `Step::Reply(Paired)` was just written by `apply_step`.
        }
    }

    if host.phase() != PairingPhase::Paired {
        warn!(phase=?host.phase(), "pairing gagal sebelum paired");
        return Ok(None);
    }
    info!(%peer, "PAIRED");

    // Trust exchange (§5.4 step 9). A verified MAC is not consent (I18): the entry
    // is stored only if both humans say yes.
    let our_alias = sanitize_alias(&format!("device-{}", peer.prefix8()))?;
    write_control(&mut tx, &ControlMsg::TrustExchange { alias: our_alias }).await?;

    let their_msg = timeout(READ_TIMEOUT, read_control(&mut rx))
        .await
        .map_err(|_| anyhow!("batas waktu menunggu TrustExchange"))??;
    let their_alias = match their_msg {
        ControlMsg::TrustExchange { alias } => alias,
        other => {
            warn!(msg=?other.name(), "diharapkan TrustExchange");
            return decline(&mut tx, &mut rx, ByeReason::Protocol).await;
        }
    };

    let consent = match consent_or_refuse(&their_alias, peer) {
        Ok(consent) => consent,
        Err(err) => {
            warn!(error=?err, "alias dari tamu tidak dapat dipakai");
            return decline(&mut tx, &mut rx, ByeReason::Protocol).await;
        }
    };

    if !prompter.confirm(&consent) {
        println!("❌ Ditolak");
        return decline(&mut tx, &mut rx, ByeReason::Declined).await;
    }

    write_control(&mut tx, &ControlMsg::TrustAck).await?;
    let ack = timeout(READ_TIMEOUT, read_control(&mut rx))
        .await
        .map_err(|_| anyhow!("batas waktu menunggu TrustAck"))??;
    match ack {
        ControlMsg::TrustAck => {
            trust_store.add(TrustEntry::new(
                peer,
                consent.alias.clone(),
                SystemClock.now(),
            ))?;
            trust_store.save()?;
            println!("✅ {} tersimpan", consent.alias);
            info!(%node_id, %peer, alias=%consent.alias, "perangkat tepercaya ditambahkan");
        }
        other => warn!(msg=?other.name(), "diharapkan TrustAck"),
    }

    Ok(Some(()))
}

/// Close a pairing politely: send `Bye`, then wait for the guest to hang up so the
/// frame is not cut off by our own close.
async fn decline(
    tx: &mut splice_core::net::SendStream,
    rx: &mut splice_core::net::RecvStream,
    reason: ByeReason,
) -> Result<Option<()>> {
    write_control(tx, &ControlMsg::Bye { reason }).await?;
    await_peer_hangup(rx).await;
    Ok(None)
}

// ---------------------------------------------------------------------------
// Join (guest)
// ---------------------------------------------------------------------------

async fn join(cli: &Cli, code_str: Option<&str>) -> Result<()> {
    let code_str = match code_str {
        Some(code) => code.to_string(),
        None => {
            use console::Term;
            let term = Term::stdout();
            eprint!("Masukkan kode: ");
            term.read_secure_line()?
        }
    };
    let code = Code::parse(&code_str).map_err(|e| anyhow!("kode tidak valid: {e}"))?;

    let relay = resolve_relay(cli)?;
    let (secret, _source) = load_persistent_identity()?;
    let transport = build_endpoint(secret, relay).await?;
    let node_id = transport.node_id();

    let host_addr = resolve_host(cli, &code).await?;
    info!(%node_id, target=?host_addr.id(), "menghubungi host");

    let conn = transport
        .connect(host_addr, REQUIRED_ALPN)
        .await
        .map_err(|e| anyhow!("gagal dial host: {e}"))?;
    if conn.alpn() != REQUIRED_ALPN {
        anyhow::bail!("ALPN tidak cocok: {:?}", conn.alpn());
    }
    let peer = conn.remote_id();
    info!(%peer, "tersambung");

    let (mut tx, mut rx) = conn
        .open_bi()
        .await
        .map_err(|e| anyhow!("gagal open_bi: {e}"))?;

    let (mut guest, opening) =
        GuestSession::begin(node_id, peer, HelloMode::Pair, code, Instant::now())?;
    for msg in &opening {
        write_control(&mut tx, msg).await?;
    }

    // Host's PAKE share, answered with our confirmation.
    let host_share = timeout(READ_TIMEOUT, read_control(&mut rx))
        .await
        .map_err(|_| anyhow!("batas waktu menunggu PakeMsg host"))??;
    let step = guest
        .on_message(peer, host_share, Instant::now())
        .context("guest on_message (pake msg)")?;
    if let Some(outcome) = apply_step(&mut tx, step).await? {
        anyhow::bail!("pairing gagal: {}", outcome.name());
    }

    // Host's confirmation: the guest verifies it here and becomes Paired.
    let host_confirm = timeout(READ_TIMEOUT, read_control(&mut rx))
        .await
        .map_err(|_| anyhow!("batas waktu menunggu PakeConfirm host"))??;
    let step = guest
        .on_message(peer, host_confirm, Instant::now())
        .context("guest on_message (pake confirm)")?;
    if let Some(outcome) = apply_step(&mut tx, step).await? {
        anyhow::bail!("pairing gagal: {}", outcome.name());
    }
    if guest.phase() != PairingPhase::Paired {
        anyhow::bail!("konfirmasi host tidak memverifikasi kode");
    }

    // The host repeats the same event as `Paired`.
    let paired = timeout(READ_TIMEOUT, read_control(&mut rx))
        .await
        .map_err(|_| anyhow!("batas waktu menunggu Paired"))??;
    match paired {
        ControlMsg::Paired { .. } => info!(%peer, "PAIRED"),
        other => anyhow::bail!("diharapkan Paired, dapat: {:?}", other.name()),
    }

    // Trust exchange: host proposes our alias first.
    let host_msg = timeout(READ_TIMEOUT, read_control(&mut rx))
        .await
        .map_err(|_| anyhow!("batas waktu menunggu TrustExchange host"))??;
    let host_alias = match host_msg {
        ControlMsg::TrustExchange { alias } => alias,
        other => anyhow::bail!("diharapkan TrustExchange, dapat: {:?}", other.name()),
    };

    let our_alias = sanitize_alias(&format!("device-{}", peer.prefix8()))?;
    write_control(
        &mut tx,
        &ControlMsg::TrustExchange {
            alias: our_alias.clone(),
        },
    )
    .await?;

    let consent = consent_or_refuse(&host_alias, peer)?;
    if !make_prompter(cli).confirm(&consent) {
        write_control(
            &mut tx,
            &ControlMsg::Bye {
                reason: ByeReason::Declined,
            },
        )
        .await?;
        println!("❌ Ditolak");
        return Ok(());
    }

    write_control(&mut tx, &ControlMsg::TrustAck).await?;
    let ack = timeout(READ_TIMEOUT, read_control(&mut rx))
        .await
        .map_err(|_| anyhow!("batas waktu menunggu TrustAck host"))??;
    match ack {
        ControlMsg::TrustAck => {
            let mut trust_store = TrustStore::load()?;
            trust_store.add(TrustEntry::new(peer, our_alias.clone(), SystemClock.now()))?;
            trust_store.save()?;
            println!("✅ {our_alias} tersimpan");
        }
        other => warn!(msg=?other.name(), "diharapkan TrustAck"),
    }

    info!("pairing selesai");
    Ok(())
}

/// Resolve the host address: mDNS, then `--addr`.
async fn resolve_host(cli: &Cli, code: &Code) -> Result<NodeAddr> {
    if let Ok(mdns) = Mdns::start() {
        match mdns.lookup(code.nameplate().get(), LOOKUP_TIMEOUT).await {
            Ok(host) => {
                if let Some(addr) = host.to_node_addr() {
                    return Ok(addr);
                }
            }
            Err(e) => debug!(error=?e, "mDNS lookup gagal"),
        }
    }

    if let Some(target) = resolve_addr(cli)? {
        return target
            .to_node_addr()
            .map_err(|e| anyhow!("alamat tidak lengkap: {e}"));
    }

    anyhow::bail!("tidak dapat menemukan host. Coba --addr nodeid@ip:port atau gunakan tiket")
}
