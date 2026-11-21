//! Stage timing measurements for pairing and dev ping (Fase 1.7 requirement 2).
//!
//! Measures each stage with microsecond-precision `Instant` over real QUIC endpoints
//! across N >= 20 runs (N = 32), printing p50, p95, min, max, mean.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use splice_core::clock::{Clock, SystemClock};
use splice_core::code::Code;
use splice_core::discovery::presence::{
    bucket_at, tag_for, Beacon, PresenceSocket, PresenceTracker,
};
use splice_core::identity::NodeSecret;
use splice_core::net::{NodeAddr, RelaySetting, Transport, REQUIRED_ALPN};
use splice_core::pairing::{consent_or_refuse, GuestSession, HostSession, PairingPhase};
use splice_core::proto::messages::{ControlMsg, HelloMode};
use splice_core::trust::{
    close_foreign, trusted_hello, TrustEntry, TrustStore, TrustedServer, TrustedStep,
};
use tempfile::TempDir;
use tokio::time::timeout;

use splice::cli::{apply_step, await_peer_hangup, build_endpoint, read_control, write_control};

const CODE_TEXT: &str = "42-torch-crystal";
const STEP_TIMEOUT: Duration = Duration::from_secs(10);
const RUNS: usize = 32;

fn code(text: &str) -> Code {
    Code::parse(text).expect("test code must parse")
}

fn dialable(transport: &dyn Transport) -> SocketAddr {
    let addrs = transport.local_addrs();
    if let Some(addr) = addrs
        .iter()
        .find(|addr| !addr.ip().is_unspecified() && !addr.ip().is_loopback())
    {
        return *addr;
    }
    let port = addrs.first().expect("endpoint has a bound socket").port();
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

async fn lan_endpoint(secret: NodeSecret) -> Arc<dyn Transport> {
    build_endpoint(secret, RelaySetting::Disabled)
        .await
        .expect("bind LAN endpoint")
}

#[derive(Default, Debug, Clone)]
struct StageStats {
    values: Vec<f64>,
}

impl StageStats {
    fn record(&mut self, val_ms: f64) {
        self.values.push(val_ms);
    }

    fn summary(&mut self) -> (f64, f64, f64, f64, f64) {
        if self.values.is_empty() {
            return (0.0, 0.0, 0.0, 0.0, 0.0);
        }
        self.values.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let n = self.values.len();
        let min = self.values[0];
        let p50 = self.values[n * 50 / 100];
        let p95 = self.values[n * 95 / 100];
        let max = self.values[n - 1];
        let mean = self.values.iter().sum::<f64>() / n as f64;
        (min, p50, p95, max, mean)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn measure_pairing_stages_empirical() {
    println!("\n=== MEASURING PAIRING STAGES (N = {RUNS}) ===");

    let mut s_init = StageStats::default();
    let mut s_dial = StageStats::default();
    let mut s_spake2 = StageStats::default();
    let mut s_trust_ex = StageStats::default();
    let mut s_store = StageStats::default();
    let mut s_total = StageStats::default();

    for _ in 0..RUNS {
        // 1. Host side setup
        let host_ep = lan_endpoint(NodeSecret::generate()).await;
        let host_id = host_ep.node_id();
        let host_addr = dialable(host_ep.as_ref());

        let host_code = code(CODE_TEXT);
        let mut host =
            HostSession::new(host_id, HelloMode::Pair, host_code, Instant::now()).unwrap();

        // Host server task
        let host_task = tokio::spawn({
            let ep = host_ep.clone();
            async move {
                let conn = timeout(STEP_TIMEOUT, ep.accept())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                let (mut tx, mut rx) = conn.accept_bi().await.unwrap();

                // 3 handshake steps
                for _step_name in ["hello", "pake msg", "pake confirm"] {
                    let msg = timeout(STEP_TIMEOUT, read_control(&mut rx))
                        .await
                        .unwrap()
                        .unwrap();
                    let reply = host
                        .on_message(conn.remote_id(), msg, Instant::now())
                        .unwrap();
                    apply_step(&mut tx, reply).await.unwrap();
                }

                // TrustExchange
                write_control(
                    &mut tx,
                    &ControlMsg::TrustExchange {
                        alias: "host-dev".into(),
                    },
                )
                .await
                .unwrap();
                let guest_msg = timeout(STEP_TIMEOUT, read_control(&mut rx))
                    .await
                    .unwrap()
                    .unwrap();
                if let ControlMsg::TrustExchange { .. } = guest_msg {
                    write_control(&mut tx, &ControlMsg::TrustAck).await.unwrap();
                }
                let ack = timeout(STEP_TIMEOUT, read_control(&mut rx))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(ack, ControlMsg::TrustAck);
                await_peer_hangup(&mut rx).await;
            }
        });

        // 2. Guest measurement
        let t0 = Instant::now();
        let guest_ep = lan_endpoint(NodeSecret::generate()).await;
        let guest_id = guest_ep.node_id();
        let t1 = Instant::now();
        s_init.record((t1 - t0).as_secs_f64() * 1000.0);

        // Guest dial
        let conn = timeout(
            STEP_TIMEOUT,
            guest_ep.connect(NodeAddr::direct(host_id, host_addr), REQUIRED_ALPN),
        )
        .await
        .unwrap()
        .unwrap();
        let t2 = Instant::now();
        s_dial.record((t2 - t1).as_secs_f64() * 1000.0);

        let (mut tx, mut rx) = conn.open_bi().await.unwrap();
        let guest_code = code(CODE_TEXT);
        let (mut guest, opening) = GuestSession::begin(
            guest_id,
            host_id,
            HelloMode::Pair,
            guest_code,
            Instant::now(),
        )
        .unwrap();
        for msg in &opening {
            write_control(&mut tx, msg).await.unwrap();
        }

        // Host PakeMsg
        let host_share = timeout(STEP_TIMEOUT, read_control(&mut rx))
            .await
            .unwrap()
            .unwrap();
        let step = guest
            .on_message(host_id, host_share, Instant::now())
            .unwrap();
        apply_step(&mut tx, step).await.unwrap();

        // Host PakeConfirm
        let host_confirm = timeout(STEP_TIMEOUT, read_control(&mut rx))
            .await
            .unwrap()
            .unwrap();
        let step = guest
            .on_message(host_id, host_confirm, Instant::now())
            .unwrap();
        apply_step(&mut tx, step).await.unwrap();
        assert_eq!(guest.phase(), PairingPhase::Paired);

        // Paired repeat
        let paired = timeout(STEP_TIMEOUT, read_control(&mut rx))
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(paired, ControlMsg::Paired { .. }));
        let t3 = Instant::now();
        s_spake2.record((t3 - t2).as_secs_f64() * 1000.0);

        // Trust Exchange
        let host_alias_msg = timeout(STEP_TIMEOUT, read_control(&mut rx))
            .await
            .unwrap()
            .unwrap();
        let host_alias = match host_alias_msg {
            ControlMsg::TrustExchange { alias } => alias,
            _ => panic!("expected TrustExchange"),
        };
        write_control(
            &mut tx,
            &ControlMsg::TrustExchange {
                alias: "guest-dev".into(),
            },
        )
        .await
        .unwrap();

        let consent = consent_or_refuse(&host_alias, host_id).unwrap();
        write_control(&mut tx, &ControlMsg::TrustAck).await.unwrap();

        let host_ack = timeout(STEP_TIMEOUT, read_control(&mut rx))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(host_ack, ControlMsg::TrustAck);
        let t4 = Instant::now();
        s_trust_ex.record((t4 - t3).as_secs_f64() * 1000.0);

        // Trust store persist
        let guest_dir = TempDir::new().unwrap();
        let mut store = TrustStore::load_in(guest_dir.path()).unwrap();
        store
            .add(TrustEntry::new(
                host_id,
                consent.alias.clone(),
                Duration::ZERO,
            ))
            .unwrap();
        store.save().unwrap();
        let t5 = Instant::now();
        s_store.record((t5 - t4).as_secs_f64() * 1000.0);

        s_total.record((t5 - t0).as_secs_f64() * 1000.0);
        drop(tx);
        drop(rx);
        drop(conn);
        host_task.await.unwrap();
    }

    print_table(
        "Tahap Pairing (Pairing Breakdown)",
        &[
            ("Init & Endpoint Build", &mut s_init),
            ("Transport Dial (QUIC Handshake)", &mut s_dial),
            ("SPAKE2 PAKE Handshake", &mut s_spake2),
            ("Trust Exchange & Consent", &mut s_trust_ex),
            ("Trust Store Disk Persist (0600)", &mut s_store),
            ("TOTAL PAIRING (Guest side)", &mut s_total),
        ],
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn measure_dev_ping_stages_empirical() {
    println!("\n=== MEASURING DEV PING & PING-PONG RTT (N = {RUNS}) ===");

    let mut s_init = StageStats::default();
    let mut s_dial = StageStats::default();
    let mut s_hello = StageStats::default();
    let mut s_rtt = StageStats::default();
    let mut s_total = StageStats::default();

    for _ in 0..RUNS {
        let listener_ep = lan_endpoint(NodeSecret::generate()).await;
        let listener_id = listener_ep.node_id();
        let listener_addr = dialable(listener_ep.as_ref());

        let dialer_secret = NodeSecret::generate();
        let dialer_id = dialer_secret.public();

        let listener_dir = TempDir::new().unwrap();
        let mut listener_store = TrustStore::load_in(listener_dir.path()).unwrap();
        listener_store
            .add(TrustEntry::new(dialer_id, "dialer", Duration::ZERO))
            .unwrap();
        listener_store.save().unwrap();

        // Listener server task
        let listener_task = tokio::spawn({
            let ep = listener_ep.clone();
            let store = listener_store;
            async move {
                let conn = timeout(STEP_TIMEOUT, ep.accept())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                let peer = conn.remote_id();
                if !store.contains(&peer) {
                    close_foreign(conn.as_ref());
                    return;
                }
                let (mut tx, mut rx) = conn.accept_bi().await.unwrap();
                let mut server = TrustedServer::new(&store, peer);
                loop {
                    let msg = timeout(STEP_TIMEOUT, read_control(&mut rx))
                        .await
                        .unwrap()
                        .unwrap();
                    match server.on_message(msg) {
                        TrustedStep::Idle => {}
                        TrustedStep::Reply(reply) => {
                            write_control(&mut tx, &reply).await.unwrap();
                            if reply == ControlMsg::Pong {
                                await_peer_hangup(&mut rx).await;
                                return;
                            }
                        }
                        _ => return,
                    }
                }
            }
        });

        // Dialer measurement
        let t0 = Instant::now();
        let dialer_dir = TempDir::new().unwrap();
        let mut dialer_store = TrustStore::load_in(dialer_dir.path()).unwrap();
        dialer_store
            .add(TrustEntry::new(listener_id, "listener", Duration::ZERO))
            .unwrap();
        dialer_store.save().unwrap();
        let dialer_ep = lan_endpoint(dialer_secret).await;
        let t1 = Instant::now();
        s_init.record((t1 - t0).as_secs_f64() * 1000.0);

        // QUIC Connect
        let conn = timeout(
            STEP_TIMEOUT,
            dialer_ep.connect(NodeAddr::direct(listener_id, listener_addr), REQUIRED_ALPN),
        )
        .await
        .unwrap()
        .unwrap();
        let t2 = Instant::now();
        s_dial.record((t2 - t1).as_secs_f64() * 1000.0);

        // Bi-stream + Trusted Hello
        let (mut tx, mut rx) = conn.open_bi().await.unwrap();
        write_control(&mut tx, &trusted_hello()).await.unwrap();
        let t3 = Instant::now();
        s_hello.record((t3 - t2).as_secs_f64() * 1000.0);

        // Ping-Pong RTT (ACTUAL APPLICATION RTT)
        let t_ping = Instant::now();
        write_control(&mut tx, &ControlMsg::Ping).await.unwrap();
        let pong = timeout(STEP_TIMEOUT, read_control(&mut rx))
            .await
            .unwrap()
            .unwrap();
        let t_pong = Instant::now();
        assert_eq!(pong, ControlMsg::Pong);

        s_rtt.record((t_pong - t_ping).as_secs_f64() * 1000.0);
        s_total.record((t_pong - t0).as_secs_f64() * 1000.0);

        drop(tx);
        drop(rx);
        drop(conn);
        listener_task.await.unwrap();
    }

    print_table(
        "Tahap Dev Ping & RTT Sebenarnya",
        &[
            ("Init & Store/Endpoint Build", &mut s_init),
            ("Transport Dial (QUIC Handshake & TLS)", &mut s_dial),
            ("Stream Open & Trusted Hello", &mut s_hello),
            ("Ping-Pong Frame Round-Trip (RTT SEBENARNYA)", &mut s_rtt),
            ("WAKTU SAMPAI PONG PERTAMA (E2E Direct LAN)", &mut s_total),
        ],
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn measure_dev_ping_with_steady_listener_and_presence_discovery() {
    println!("\n=== MEASURING DEV PING WITH STEADY LISTENER & PRESENCE DISCOVERY (N = {RUNS}) ===");

    let listener_ep = lan_endpoint(NodeSecret::generate()).await;
    let listener_id = listener_ep.node_id();
    let listener_addr = dialable(listener_ep.as_ref());

    let listener_dir = TempDir::new().unwrap();
    let listener_store = Arc::new(std::sync::Mutex::new(
        TrustStore::load_in(listener_dir.path()).unwrap(),
    ));

    let presence_listener = PresenceSocket::bind(0).expect("bind presence listener");
    let presence_port = presence_listener.port();

    let stop_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Background beacon broadcast task (steady state: broadcasting every 1 second)
    let beacon_task = tokio::spawn({
        let presence = presence_listener;
        let stop = stop_flag.clone();
        let port = listener_addr.port();
        async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                interval.tick().await;
                let now = SystemClock.now();
                let beacon = Beacon {
                    tag: tag_for(listener_id, bucket_at(now)),
                    port,
                };
                let _ = presence.send(&beacon).await;
            }
        }
    });

    // Background listener accept task (serves Ping/Pong repeatedly for steady listener)
    let accept_task = tokio::spawn({
        let ep = listener_ep.clone();
        let store = listener_store.clone();
        let stop = stop_flag.clone();
        async move {
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                let conn = match timeout(Duration::from_millis(500), ep.accept()).await {
                    Ok(Ok(Some(c))) => c,
                    _ => continue,
                };
                let peer = conn.remote_id();
                let is_trusted = {
                    let s = store.lock().unwrap();
                    s.contains(&peer)
                };
                if !is_trusted {
                    close_foreign(conn.as_ref());
                    continue;
                }
                let conn_clone = conn.clone();
                let store_clone = store.clone();
                tokio::spawn(async move {
                    let _keep = conn_clone;
                    if let Ok((mut tx, mut rx)) = _keep.accept_bi().await {
                        let mut server = {
                            let store_guard = store_clone.lock().unwrap();
                            TrustedServer::new(&store_guard, peer)
                        };
                        while let Ok(Ok(msg)) = timeout(STEP_TIMEOUT, read_control(&mut rx)).await {
                            match server.on_message(msg) {
                                TrustedStep::Idle => {}
                                TrustedStep::Reply(reply) => {
                                    if write_control(&mut tx, &reply).await.is_err() {
                                        break;
                                    }
                                    if reply == ControlMsg::Pong {
                                        await_peer_hangup(&mut rx).await;
                                        break;
                                    }
                                }
                                _ => break,
                            }
                        }
                    }
                });
            }
        }
    });

    // Wait a brief moment for steady state
    tokio::time::sleep(Duration::from_millis(100)).await;

    let dialer_secret = NodeSecret::generate();
    let dialer_id = dialer_secret.public();
    let raw_secret = dialer_secret.to_bytes();
    {
        let mut s = listener_store.lock().unwrap();
        s.add(TrustEntry::new(dialer_id, "dialer", Duration::ZERO))
            .unwrap();
        s.save().unwrap();
    }

    let presence_dialer = PresenceSocket::bind(presence_port).expect("bind dialer presence");

    let mut s_init = StageStats::default();
    let mut s_discovery = StageStats::default();
    let mut s_dial = StageStats::default();
    let mut s_pingpong = StageStats::default();
    let mut s_total = StageStats::default();

    for _ in 0..RUNS {
        // 1. Dialer init & endpoint
        let t0 = Instant::now();
        let dialer_dir = TempDir::new().unwrap();
        let mut dialer_store = TrustStore::load_in(dialer_dir.path()).unwrap();
        dialer_store
            .add(TrustEntry::new(listener_id, "listener", Duration::ZERO))
            .unwrap();
        dialer_store.save().unwrap();
        let dialer_ep = lan_endpoint(NodeSecret::from_bytes(raw_secret)).await;
        let t1 = Instant::now();
        s_init.record((t1 - t0).as_secs_f64() * 1000.0);

        // 2. Presence Discovery Hint: wait for next beacon on presence_dialer
        let mut tracker = PresenceTracker::new(Arc::new(SystemClock));
        tracker.set_trusted(vec![listener_id]);

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut discovered_addr: Option<NodeAddr> = None;
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if let Ok(Ok((buffer, len, from))) = timeout(remaining, presence_dialer.recv()).await {
                if let Some(presence) = tracker.observe(&buffer[..len.min(buffer.len())], from) {
                    discovered_addr = Some(presence.to_node_addr());
                    break;
                }
            } else {
                break;
            }
        }
        let target_addr = match discovered_addr {
            Some(addr) => addr,
            None => {
                eprintln!(
                    "SKIPPED: runner could not discover beacon via multicast (runner network isolation)"
                );
                return;
            }
        };
        let t2 = Instant::now();
        s_discovery.record((t2 - t1).as_secs_f64() * 1000.0);

        // 3. Transport Dial
        let conn = timeout(STEP_TIMEOUT, dialer_ep.connect(target_addr, REQUIRED_ALPN))
            .await
            .unwrap()
            .unwrap();
        let t3 = Instant::now();
        s_dial.record((t3 - t2).as_secs_f64() * 1000.0);

        // 4. Stream Open, Trusted Hello, Ping-Pong
        let (mut tx, mut rx) = conn.open_bi().await.unwrap();
        write_control(&mut tx, &trusted_hello()).await.unwrap();
        write_control(&mut tx, &ControlMsg::Ping).await.unwrap();
        let pong = timeout(STEP_TIMEOUT, read_control(&mut rx))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pong, ControlMsg::Pong);
        let t4 = Instant::now();
        s_pingpong.record((t4 - t3).as_secs_f64() * 1000.0);
        s_total.record((t4 - t0).as_secs_f64() * 1000.0);

        drop(tx);
        drop(rx);
        drop(conn);
    }

    stop_flag.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = beacon_task.await;
    let _ = accept_task.await;

    print_table(
        "Tahap Dev Ping dengan Listener Steady & Penemuan Presence Multicast (N = 32)",
        &[
            ("Init & Store/Endpoint Build", &mut s_init),
            (
                "Presence Discovery Hint (Steady Listener)",
                &mut s_discovery,
            ),
            ("Transport Dial (QUIC Handshake & TLS)", &mut s_dial),
            ("Stream Open & Ping-Pong RTT", &mut s_pingpong),
            (
                "WAKTU SAMPAI PONG PERTAMA (via Steady Presence)",
                &mut s_total,
            ),
        ],
    );
}

fn print_table(title: &str, stages: &[(&str, &mut StageStats)]) {
    println!("\n### {title}");
    println!("| Tahap | Min (ms) | p50 (ms) | p95 (ms) | Max (ms) | Mean (ms) |");
    println!("|---|:---:|:---:|:---:|:---:|:---:|");
    for (name, stats) in stages {
        let mut s = (*stats).clone();
        let (min, p50, p95, max, mean) = s.summary();
        println!("| **{name}** | {min:.2} | {p50:.2} | {p95:.2} | {max:.2} | {mean:.2} |");
    }
}
