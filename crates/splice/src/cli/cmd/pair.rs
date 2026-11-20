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
    // The SRV record carries one port for every address record, so this log is
    // what tells a failed guest dial whether it was handed the right one.
    debug!(
        nameplate = np,
        port = local_port,
        addrs = ?transport.local_addrs(),
        "mengiklankan host di LAN"
    );

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

        // §5.4 step 7: a burned code is terminal. The advertisement must come down
        // and no further guest may be asked for it — the state machine refuses them
        // anyway, but looping would keep the socket answering for the rest of the
        // TTL and keep the mDNS record up.
        if host.phase() == PairingPhase::Burned {
            println!("🚫 Kode hangus");
            return Err(anyhow!("kode hangus"));
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
    //
    // `TrustExchange` carries the sender's *own* display name; the receiver stores
    // it as the alias for the sender. So each side stores the name the peer chose
    // for itself, and the prompt it shows names the peer, not the local device.
    let our_alias = exchange_alias(node_id)?;
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
            record_peer(trust_store, peer, &consent, SystemClock.now())?;
            println!("✅ {} tersimpan", consent.alias);
            info!(%node_id, %peer, alias=%consent.alias, "perangkat tepercaya ditambahkan");
        }
        other => {
            // §5.4 step 9: only a `TrustAck` is consent. Anything else means the
            // peer never agreed, so nothing is stored and this is not a success:
            // reporting `Ok(Some(()))` here would exit 0 on a device that is
            // absent from the trust store.
            warn!(msg=?other.name(), "diharapkan TrustAck");
            return decline(&mut tx, &mut rx, ByeReason::Protocol).await;
        }
    }

    Ok(Some(()))
}

/// The name this device offers to its peer.
///
/// `TrustExchange` carries the sender's **own** name, so this is built from our
/// `NodeId`. Building it from the peer's id instead makes each side store its own
/// name under the peer's id, which is why this lives in one place with a test.
fn exchange_alias(our_id: NodeId) -> Result<String> {
    Ok(sanitize_alias(&format!("device-{}", our_id.prefix8()))?)
}

/// Record the peer after both humans agreed: the peer's `NodeId` under the name the
/// peer chose for itself (the alias we received, not the one we sent).
fn record_peer(
    store: &mut TrustStore,
    peer: NodeId,
    consent: &splice_core::pairing::AliasConsent,
    now: Duration,
) -> Result<()> {
    store.add(TrustEntry::new(peer, consent.alias.clone(), now))?;
    store.save()?;
    Ok(())
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

    // Trust exchange: each side sends the name it wants to be called by, then
    // stores the name it receives as the peer's alias (see the host comment).
    let host_msg = timeout(READ_TIMEOUT, read_control(&mut rx))
        .await
        .map_err(|_| anyhow!("batas waktu menunggu TrustExchange host"))??;
    let host_alias = match host_msg {
        ControlMsg::TrustExchange { alias } => alias,
        other => anyhow::bail!("diharapkan TrustExchange, dapat: {:?}", other.name()),
    };

    let our_alias = exchange_alias(node_id)?;
    write_control(&mut tx, &ControlMsg::TrustExchange { alias: our_alias }).await?;

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

    confirm_trust_ack(&mut tx, &mut rx).await?;
    record_peer(&mut TrustStore::load()?, peer, &consent, SystemClock.now())?;
    println!("✅ {} tersimpan", consent.alias);

    info!("pairing selesai");
    Ok(())
}

/// §5.4 step 9, guest side: only a `TrustAck` means the host agreed.
///
/// A prompt answered with anything else is not consent, so this fails instead of
/// letting `join` print "pairing selesai" for a device that was never stored.
async fn confirm_trust_ack(
    tx: &mut splice_core::net::SendStream,
    rx: &mut splice_core::net::RecvStream,
) -> Result<()> {
    let ack = timeout(READ_TIMEOUT, read_control(rx))
        .await
        .map_err(|_| anyhow!("batas waktu menunggu TrustAck host"))??;
    match ack {
        ControlMsg::TrustAck => Ok(()),
        other => {
            warn!(msg=?other.name(), "diharapkan TrustAck");
            write_control(
                tx,
                &ControlMsg::Bye {
                    reason: ByeReason::Protocol,
                },
            )
            .await?;
            await_peer_hangup(rx).await;
            anyhow::bail!("host tidak menyetujui pertukaran kepercayaan")
        }
    }
}

/// Resolve the host address: mDNS, then `--addr`.
async fn resolve_host(cli: &Cli, code: &Code) -> Result<NodeAddr> {
    if let Ok(mdns) = Mdns::start() {
        match mdns.lookup(code.nameplate().get(), LOOKUP_TIMEOUT).await {
            Ok(host) => {
                debug!(
                    nameplate = code.nameplate().get(),
                    node = %host.node,
                    addrs = ?host.addrs,
                    "mDNS menemukan host"
                );
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

#[cfg(test)]
mod tests {
    use super::*;
    use splice_core::net::memory::Network;
    use splice_core::pairing::{AliasConsent, AlwaysYes};
    use tempfile::TempDir;

    fn id(seed: u8) -> NodeId {
        // A patterned id, so `prefix8()` and `shorthand()` differ: a test that
        // cannot tell them apart would not catch an alias built from the wrong end.
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = seed.wrapping_add(i as u8);
        }
        NodeId::from_bytes(bytes)
    }

    /// §5.4 step 7: once the code is BURNED, no further guest may reach it.
    ///
    /// The loop, not the state machine, keeps accepting connections, so a burned
    /// host that keeps looping still advertises and still answers `Hello`s for the
    /// rest of the TTL. This drives the real `accept_loop` with a burned session
    /// and asserts it stops instead of looping.
    #[tokio::test]
    async fn a_burned_code_stops_the_accept_loop() {
        let net = Network::new();
        let host_id = id(0x71);
        let host_ep = net.endpoint_with(host_id, false);

        let nameplate = splice_core::code::Nameplate::new(9).expect("nameplate");
        let mut rng = rand::rng();
        let the_code =
            Code::generate(&mut rng, splice_core::code::WordCount::Two, nameplate).expect("code");
        let mut host = HostSession::new(host_id, HelloMode::Pair, the_code.clone(), Instant::now())
            .expect("host session");

        // Drive it to BURNED exactly the way a guest with the wrong code does,
        // without the network: a wrong guess must reach key confirmation, so the
        // round is `Hello` -> `PakeMsg` -> a `PakeConfirm` that cannot verify. The
        // point under test is what `accept_loop` does *next*.
        let wrong = splice_core::secret::SecretString::from_string("not-the-real-code".to_string());
        for _ in 0..3 {
            let guest = id(0x80);
            let (pake, our_msg) = splice_core::pairing::PakeState::start(
                splice_core::pairing::Role::Guest,
                &wrong,
                guest,
                host_id,
            );
            let step = host
                .on_message(
                    guest,
                    ControlMsg::Hello {
                        version: splice_core::constants::PROTOCOL_VERSION,
                        mode: HelloMode::Pair,
                        nameplate: Some(nameplate.get()),
                        resume: None,
                    },
                    Instant::now(),
                )
                .expect("hello");
            // The host shares its PAKE message as soon as it accepts the `Hello`.
            let host_msg = match step {
                splice_core::pairing::Step::Reply(ControlMsg::PakeMsg { payload }) => payload,
                other => panic!("expected the host share, got {other:?}"),
            };
            let step = host
                .on_message(
                    guest,
                    ControlMsg::PakeMsg { payload: our_msg },
                    Instant::now(),
                )
                .expect("pake msg");
            assert!(
                matches!(
                    step,
                    splice_core::pairing::Step::Reply(ControlMsg::PakeConfirm { .. })
                ),
                "the host confirms first, got {step:?}"
            );
            // The two sides derive different keys, so this MAC cannot verify.
            let _ = pake.finish(&host_msg);
            let step = host
                .on_message(
                    guest,
                    ControlMsg::PakeConfirm { mac: [0u8; 32] },
                    Instant::now(),
                )
                .expect("confirm");
            assert!(
                matches!(step, splice_core::pairing::Step::ReplyThenClose { .. }),
                "a wrong MAC must end the attempt"
            );
        }
        assert_eq!(host.phase(), PairingPhase::Burned, "precondition");

        let dir = TempDir::new().expect("temp dir");
        let mut store = TrustStore::load_in(dir.path()).expect("store");
        let prompter = AlwaysYes;

        // No guest is ever dialed: if the loop is still accepting, this await
        // blocks until the test times out. A passing run returns promptly.
        let loop_result = timeout(
            Duration::from_millis(400),
            accept_loop(&mut host, &host_ep, &prompter, &mut store, host_id),
        )
        .await;

        let returned = loop_result.expect("a burned code must end the accept loop");
        assert!(
            returned.is_err(),
            "a burned code is a terminal failure, not a success"
        );
    }

    /// `TrustExchange` names the *sender*. The name must come from our own id, so
    /// the peer stores it against us and not against itself.
    #[test]
    fn the_offered_alias_names_this_device_not_the_peer() {
        let ours = id(0xa1);
        let peer = id(0xb2);

        let offered = exchange_alias(ours).expect("alias");
        assert_eq!(offered, format!("device-{}", ours.prefix8()));
        assert_ne!(
            offered,
            format!("device-{}", peer.prefix8()),
            "the alias we send must not be built from the peer's id"
        );
    }

    /// §5.4 step 9: only a `TrustAck` means the peer agreed.
    ///
    /// Neither side may treat any other final message as consent. Before this was
    /// fixed, a peer that answered the prompt with something else was never
    /// recorded, yet the host still returned success, so `splice pair` printed
    /// nothing and exited 0 while the device was missing from the trust store.
    /// This drives the real `serve_guest` with a guest that runs the whole
    /// handshake and then says `Paired` instead of `TrustAck`.
    #[tokio::test]
    async fn a_missing_trust_ack_is_a_protocol_failure() {
        use splice_core::code::WordCount;
        use splice_core::net::Transport;

        let net = Network::new();
        let (guest_id, host_id) = (id(0xd1), id(0xd2));
        let host_ep = net.endpoint_with(host_id, false);
        let guest_ep = net.endpoint_with(guest_id, false);

        let nameplate = Nameplate::new(11).expect("nameplate");
        let mut rng = rand::rng();
        let the_code = Code::generate(&mut rng, WordCount::Two, nameplate).expect("code");
        let mut host = HostSession::new(host_id, HelloMode::Pair, the_code.clone(), Instant::now())
            .expect("host session");

        let dir = TempDir::new().expect("temp dir");
        let mut store = TrustStore::load_in(dir.path()).expect("store");
        let prompter = AlwaysYes;
        let code_for_guest = the_code.clone();

        let host_half = async {
            let conn = host_ep
                .accept()
                .await
                .expect("accept")
                .expect("the guest dials");
            assert_eq!(conn.remote_id(), guest_id);
            let result = serve_guest(
                &mut host,
                conn.as_ref(),
                guest_id,
                &prompter,
                &mut store,
                host_id,
            )
            .await;
            (result, conn)
        };

        let guest_half = async {
            let conn = guest_ep
                .connect(host_ep.hint(), REQUIRED_ALPN)
                .await
                .expect("dial the host");
            let (mut tx, mut rx) = conn.open_bi().await.expect("open the CONTROL stream");

            let (mut guest, opening) = GuestSession::begin(
                guest_id,
                host_id,
                HelloMode::Pair,
                code_for_guest,
                Instant::now(),
            )
            .expect("guest session");
            for msg in &opening {
                write_control(&mut tx, msg).await.expect("write opening");
            }

            // PAKE: the host shares first, then we answer and verify its confirm.
            for step_name in ["pake msg", "pake confirm"] {
                let msg = read_control(&mut rx).await.expect(step_name);
                let step = guest
                    .on_message(host_id, msg, Instant::now())
                    .expect("guest on_message");
                if let Some(outcome) = apply_step(&mut tx, step).await.expect("apply step") {
                    panic!("the guest ended early at {step_name}: {}", outcome.name());
                }
            }
            assert_eq!(guest.phase(), PairingPhase::Paired, "precondition");

            // Trust exchange, in the wire order the host expects: it sends first.
            assert_eq!(
                read_control(&mut rx).await.expect("Paired"),
                ControlMsg::Paired {
                    caps: splice_core::proto::messages::Caps::NONE
                }
            );
            assert!(matches!(
                read_control(&mut rx).await.expect("TrustExchange"),
                ControlMsg::TrustExchange { .. }
            ));
            write_control(
                &mut tx,
                &ControlMsg::TrustExchange {
                    alias: "dapur".to_string(),
                },
            )
            .await
            .expect("write our name");
            assert_eq!(
                read_control(&mut rx).await.expect("TrustAck"),
                ControlMsg::TrustAck,
                "the host must ask before it stores anything"
            );

            // The misbehaviour: answer the prompt with the wrong message.
            write_control(
                &mut tx,
                &ControlMsg::Paired {
                    caps: splice_core::proto::messages::Caps::NONE,
                },
            )
            .await
            .expect("write the wrong frame");

            let reply = timeout(Duration::from_secs(3), read_control(&mut rx))
                .await
                .expect("the host must answer, not leave the guest waiting")
                .expect("read the host's answer");
            assert_eq!(
                reply,
                ControlMsg::Bye {
                    reason: ByeReason::Protocol
                },
                "a missing TrustAck is a protocol failure, not silence"
            );
            // Hang up so the host's linger does not have to wait out its timeout.
            conn.close(0, b"");
        };

        let ((result, _conn), ()) = tokio::join!(host_half, guest_half);

        assert!(
            matches!(result, Ok(None)),
            "no ack means this guest did not pair, got {result:?}"
        );
        assert!(
            store.get(&guest_id).is_none(),
            "a peer that never acknowledged must not be in the trust store"
        );
    }

    /// The guest half of the same rule: a host that answers the prompt with anything
    /// but `TrustAck` has not agreed, so the guest must fail (and say `Bye`) rather
    /// than report a finished pairing.
    #[tokio::test]
    async fn the_guest_refuses_a_host_that_never_acks() {
        use splice_core::net::Transport;

        let net = Network::new();
        let (guest_id, host_id) = (id(0xe1), id(0xe2));
        let host_ep = net.endpoint_with(host_id, false);
        let guest_ep = net.endpoint_with(guest_id, false);

        let host_half = async {
            let conn = host_ep
                .accept()
                .await
                .expect("accept")
                .expect("the guest dials");
            let (mut tx, mut rx) = conn.accept_bi().await.expect("host stream");
            // The prompt was answered with the wrong message.
            write_control(
                &mut tx,
                &ControlMsg::Paired {
                    caps: splice_core::proto::messages::Caps::NONE,
                },
            )
            .await
            .expect("write the wrong frame");
            // The guest must answer with `Bye{Protocol}`, not silence.
            let reply = timeout(Duration::from_secs(3), read_control(&mut rx))
                .await
                .expect("the guest must answer, not hang up silently")
                .expect("read the guest's answer");
            assert_eq!(
                reply,
                ControlMsg::Bye {
                    reason: ByeReason::Protocol
                }
            );
        };

        let guest_half = async {
            let conn = guest_ep
                .connect(host_ep.hint(), REQUIRED_ALPN)
                .await
                .expect("dial");
            let (mut tx, mut rx) = conn.open_bi().await.expect("guest stream");
            let result = confirm_trust_ack(&mut tx, &mut rx).await;
            assert!(
                result.is_err(),
                "a host that never acked has not agreed; got {result:?}"
            );
            conn.close(0, b"");
        };

        tokio::join!(host_half, guest_half);
    }

    /// The control: a real `TrustAck` is accepted, so the test above is failing for
    /// the right reason and not because every read errors.
    #[tokio::test]
    async fn the_guest_accepts_a_real_trust_ack() {
        use splice_core::net::Transport;

        let net = Network::new();
        let (guest_id, host_id) = (id(0xf1), id(0xf2));
        let host_ep = net.endpoint_with(host_id, false);
        let guest_ep = net.endpoint_with(guest_id, false);

        let host_half = async {
            let conn = host_ep
                .accept()
                .await
                .expect("accept")
                .expect("the guest dials");
            let (mut tx, _rx) = conn.accept_bi().await.expect("host stream");
            write_control(&mut tx, &ControlMsg::TrustAck)
                .await
                .expect("write the ack");
        };

        let guest_half = async {
            let conn = guest_ep
                .connect(host_ep.hint(), REQUIRED_ALPN)
                .await
                .expect("dial");
            let (mut tx, mut rx) = conn.open_bi().await.expect("guest stream");
            confirm_trust_ack(&mut tx, &mut rx)
                .await
                .expect("a real TrustAck must be accepted");
        };

        tokio::join!(host_half, guest_half);
    }

    /// The entry stored for the peer carries the name the peer sent, under the
    /// peer's `NodeId` — the direction `splice devices` reads back.
    #[test]
    fn the_stored_entry_uses_the_alias_the_peer_sent() {
        let dir = TempDir::new().expect("temp dir");
        let mut store = TrustStore::load_in(dir.path()).expect("empty store");

        let peer = id(0xc3);
        // Not derivable from any NodeId, so a store that regenerates the name from
        // an id (ours or the peer's) cannot pass by coincidence.
        let their_alias = "dapur".to_string();
        let consent = AliasConsent::new(&their_alias, peer).expect("consent");

        record_peer(&mut store, peer, &consent, Duration::from_secs(1)).expect("record");

        let saved = TrustStore::load_in(dir.path()).expect("reload");
        let entry = saved.get(&peer).expect("the peer must be recorded");
        assert_eq!(entry.alias, their_alias);

        // The listing is by alias, so this is what a human sees.
        let found = saved
            .find_by_alias(&their_alias)
            .expect("the peer is reachable by the name it chose");
        assert_eq!(found.node_id, peer);
    }
}
