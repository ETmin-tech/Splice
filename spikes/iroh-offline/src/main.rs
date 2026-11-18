//! Spike S1 — does iroh 1.4.1 work on a LAN with **no internet and no relay**?
//!
//! Throwaway measurement harness for `MasterPrompt-Fase1.md` §4 Step 1.
//! Every subcommand prints newline-delimited JSON on stdout so the driver script can
//! aggregate it. Nothing here is meant to be reused by the real crates.

mod alpn;
mod direct;
mod keys;
mod mdns;
mod relay;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use iroh::EndpointId;

/// ALPN from `Architecture.md` §7.1 (renamed `tether/1` -> `splice/1`).
const ALPN: &[u8] = b"splice/1";

/// Stream type byte for the CONTROL stream, `Architecture.md` §7.2.
const STREAM_TYPE_CONTROL: u8 = 0x01;

#[derive(Parser, Debug)]
#[command(about = "Spike S1: iroh on a LAN with no internet and no relay")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Bind with relay disabled, announce id + sockets, accept and echo bi-streams.
    Serve {
        /// Use a persistent secret key stored at this path (created if missing).
        #[arg(long)]
        key: Option<PathBuf>,
        /// Number of connections to accept before exiting.
        #[arg(long, default_value_t = 1)]
        rounds: usize,
    },
    /// Dial id + direct socket address `--rounds` times and measure connect latency.
    Dial {
        #[arg(long)]
        id: EndpointId,
        #[arg(long)]
        addr: std::net::SocketAddr,
        #[arg(long, default_value_t = 1)]
        rounds: usize,
    },
    /// Bind with the n0 relay preset while offline; report bind + connect behaviour.
    RelayProbe {
        /// How long to wait for a connect attempt before giving up, in seconds.
        #[arg(long, default_value_t = 20)]
        timeout_secs: u64,
    },
    /// Persistent + ephemeral secret key side by side in one process.
    Keys {
        /// Directory for the persistent key file.
        #[arg(long)]
        dir: PathBuf,
    },
    /// ALPN + leading-type-byte check, including wrong-ALPN rejection.
    Alpn,
    /// Advertise on mDNS-like discovery and stay up.
    MdnsServe {
        #[arg(long, default_value = "splice-s1")]
        service: String,
    },
    /// Measure how long a specific peer takes to appear via mDNS-like discovery.
    MdnsProbe {
        #[arg(long)]
        id: EndpointId,
        #[arg(long, default_value = "splice-s1")]
        service: String,
        #[arg(long, default_value_t = 30)]
        timeout_secs: u64,
    },
}

/// Print one JSON object and flush, so a dying process never eats a measurement.
fn emit(v: serde_json::Value) {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{v}");
    let _ = out.flush();
}

/// Lossy milliseconds, rounded to 3 decimals.
fn ms(d: std::time::Duration) -> f64 {
    (d.as_secs_f64() * 1000.0 * 1000.0).round() / 1000.0
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    match Cli::parse().cmd {
        Cmd::Serve { key, rounds } => direct::serve(key, rounds).await,
        Cmd::Dial { id, addr, rounds } => direct::dial(id, addr, rounds).await,
        Cmd::RelayProbe { timeout_secs } => relay::probe(timeout_secs).await,
        Cmd::Keys { dir } => keys::run(&dir).await,
        Cmd::Alpn => alpn::run().await,
        Cmd::MdnsServe { service } => mdns::serve(service).await,
        Cmd::MdnsProbe {
            id,
            service,
            timeout_secs,
        } => mdns::probe(id, service, timeout_secs).await,
    }
}