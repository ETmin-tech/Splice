//! CLI surface for splice (Phase 1). See `MasterPrompt-Fase1.md` §3.2 and D9/D10.
//!
//! Command tree:
//! - `pair` / `pair --join [CODE]`
//! - `devices` / `devices rm <alias>`
//! - `listen`
//! - `identity show|reset`
//! - `dev <sub>` (hidden, D10)

pub mod cmd;

use std::sync::Arc;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use splice_core::code::WordCount;
use splice_core::discovery::ManualTarget;
use splice_core::net::RelaySetting;

use crate::cli::cmd::{dev, devices, identity, listen, pair};

// ---------------------------------------------------------------------------
// Top-level clap types
// ---------------------------------------------------------------------------

/// Top-level CLI.
#[derive(Parser, Debug)]
#[command(name = "splice", version, about = "Pair and manage trusted devices")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Relay mode: `default` (auto) or `disabled`.
    #[arg(long = "relay-mode", global = true, default_value = "default")]
    pub relay_mode: String,

    /// Custom relay URL (overrides the default).
    #[arg(long = "relay-url", global = true)]
    pub relay_url: Option<String>,

    /// Direct address hint: `ip:port` or `nodeid@ip:port`.
    #[arg(long = "addr", global = true)]
    pub addr: Option<String>,

    /// Word count for pairing codes: 2 or 3.
    #[arg(long = "words", global = true, default_value = "2")]
    pub words: u8,

    /// Skip confirmation prompts (test-only).
    #[arg(long = "yes", global = true, default_value_t = false)]
    pub yes: bool,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Host a pairing session (prints a code and waits).
    Pair(PairArgs),

    /// List trusted devices, or remove one.
    Devices(DevicesArgs),

    /// Announce presence and accept trusted connections.
    Listen,

    /// Show or reset the local identity.
    Identity(IdentityArgs),

    /// Dev subcommands (hidden, D10).
    #[command(subcommand, hide = true)]
    Dev(DevCommand),
}

#[derive(Parser, Debug)]
pub struct PairArgs {
    /// Join an existing pairing. CODE may be omitted (hidden prompt).
    #[arg(long = "join", short = 'j')]
    pub join: Option<Option<String>>,
}

#[derive(Parser, Debug)]
pub struct DevicesArgs {
    /// Remove a trusted device by alias, shorthand, or NodeId.
    #[arg(long = "rm")]
    pub rm: Option<String>,
}

#[derive(Parser, Debug)]
pub struct IdentityArgs {
    /// Subcommand: show or reset.
    #[command(subcommand)]
    pub action: IdentityAction,
}

#[derive(Subcommand, Debug)]
pub enum IdentityAction {
    /// Show the local NodeId and identity file path.
    Show,
    /// Reset (delete) the persistent identity.
    Reset,
}

/// Dev subcommands (D10).
#[derive(Subcommand, Debug)]
pub enum DevCommand {
    /// Host a one-shot pairing (ephemeral key).
    HostOneshot,
    /// Join a one-shot pairing.
    GuestOneshot { code: String },
    /// Host a ticket-mode pairing.
    HostTicket,
    /// Join a ticket-mode pairing.
    GuestTicket { ticket: String },
    /// Ping a trusted device by alias.
    Ping { alias: String },
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Resolve the relay setting from CLI flags.
pub fn resolve_relay(cli: &Cli) -> Result<RelaySetting> {
    if let Some(url) = &cli.relay_url {
        return Ok(RelaySetting::Custom(url.clone()));
    }
    RelaySetting::parse_mode(&cli.relay_mode).map_err(|e| anyhow!("{e}"))
}

/// Resolve word count from CLI flags.
pub fn resolve_word_count(cli: &Cli) -> Result<WordCount> {
    WordCount::from_count(cli.words as usize).map_err(|e| anyhow!("{e}"))
}

/// Resolve address hint, if any.
pub fn resolve_addr(cli: &Cli) -> Result<Option<ManualTarget>> {
    match &cli.addr {
        Some(raw) => Ok(Some(ManualTarget::parse(raw)?)),
        None => Ok(None),
    }
}

/// Load or create a persistent identity.
pub fn load_persistent_identity() -> Result<(
    splice_core::identity::NodeSecret,
    splice_core::identity::IdentitySource,
)> {
    splice_core::identity::load_or_create_persistent()
        .map_err(|e| anyhow!("gagal memuat identitas: {e}"))
}

/// Build an endpoint from an identity + relay setting.
pub async fn build_endpoint(
    secret: splice_core::identity::NodeSecret,
    relay: RelaySetting,
) -> Result<Arc<dyn splice_core::net::Transport>> {
    use splice_core::net::{bind, EndpointConfig, REQUIRED_ALPN};
    let config = EndpointConfig {
        secret,
        relay,
        bind: None,
        alpns: vec![REQUIRED_ALPN.to_vec()],
    };
    bind(config)
        .await
        .map_err(|e| anyhow!("gagal bind endpoint: {e}"))
}

/// Write a CONTROL frame to a stream.
///
/// The stream type byte belongs to the stream, not to the frame: it is written
/// once by whoever opened the stream, before the first frame.
pub async fn write_control(
    tx: &mut splice_core::net::SendStream,
    msg: &splice_core::proto::ControlMsg,
) -> Result<()> {
    use splice_core::proto::{Frame, StreamType};
    use tokio::io::AsyncWriteExt;
    let bytes = Frame::control(msg)?.encode();
    tx.write_all(&[StreamType::Control.as_byte()])
        .await
        .map_err(|e| anyhow!("write stream type: {e}"))?;
    tx.write_all(&bytes)
        .await
        .map_err(|e| anyhow!("write: {e}"))
}

/// Read one CONTROL frame from a stream.
///
/// On the first call the stream type byte is still unread, so it is consumed and
/// checked here; later calls re-read it, which fails loudly instead of silently
/// desynchronising if a caller reads twice.
pub async fn read_control(
    rx: &mut splice_core::net::RecvStream,
) -> Result<splice_core::proto::ControlMsg> {
    use splice_core::proto::messages::WireMessage as _;
    use splice_core::proto::{frame, FrameKind, StreamType};
    use tokio::io::AsyncReadExt;

    let mut stream_type = [0u8; 1];
    rx.read_exact(&mut stream_type)
        .await
        .map_err(|e| anyhow!("read stream type: {e}"))?;
    match StreamType::from_byte(stream_type[0])? {
        StreamType::Control => {}
        other => return Err(anyhow!("stream type {:?} is not served in Phase 1", other)),
    }

    let mut header = [0u8; 6];
    rx.read_exact(&mut header)
        .await
        .map_err(|e| anyhow!("read header: {e}"))?;
    let hdr = frame::decode_header(&header)?;
    if hdr.kind != FrameKind::Control {
        return Err(anyhow!("expected CONTROL frame, got {:?}", hdr.kind));
    }
    let mut body = vec![0u8; hdr.len as usize];
    rx.read_exact(&mut body)
        .await
        .map_err(|e| anyhow!("read body: {e}"))?;
    splice_core::proto::ControlMsg::decode_from_slice(&body).map_err(|e| anyhow!("decode: {e}"))
}

/// How long a finished exchange keeps its connection alive while the peer reads
/// the last frame.
///
/// A real transport closes the connection as soon as its last handle is dropped,
/// and that close can overtake the final stream bytes. Waiting for the peer to
/// hang up first makes the last frame delivery deterministic.
const LINGER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Read (and discard) until the peer hangs up, so our own close cannot cut off
/// the frame we just wrote. Bounded by [`LINGER_TIMEOUT`], and never an error:
/// a peer that lingers or vanishes both end the wait.
pub async fn await_peer_hangup(rx: &mut splice_core::net::RecvStream) {
    use tokio::io::AsyncReadExt;
    let mut scratch = [0u8; 64];
    let _ = tokio::time::timeout(LINGER_TIMEOUT, async {
        loop {
            match rx.read(&mut scratch).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await;
}

/// Perform one step of the state machine, writing if needed. Returns the
/// terminal outcome if the step closes the stream.
pub async fn apply_step(
    tx: &mut splice_core::net::SendStream,
    step: splice_core::pairing::Step,
) -> Result<Option<splice_core::pairing::Outcome>> {
    match step {
        splice_core::pairing::Step::Reply(msg) => {
            write_control(tx, &msg).await?;
            Ok(None)
        }
        splice_core::pairing::Step::ReplyThenClose { reply, outcome } => {
            if let Some(msg) = reply {
                // Best effort: the peer usually stops reading (or hangs up) right
                // after its own terminal step, so a failed farewell is not a fault.
                if let Err(err) = write_control(tx, &msg).await {
                    tracing::debug!(error = ?err, "gagal mengirim pesan penutup");
                }
            }
            Ok(Some(outcome))
        }
        splice_core::pairing::Step::Idle => Ok(None),
    }
}

/// Prompt the user for trust consent. Returns `Canned` or interactive.
pub fn make_prompter(cli: &Cli) -> Arc<dyn splice_core::pairing::Prompter> {
    if cli.yes {
        Arc::new(splice_core::pairing::Canned::new(true))
    } else {
        Arc::new(CliPrompter)
    }
}

/// Interactive prompter that reads from stdin.
struct CliPrompter;

impl splice_core::pairing::Prompter for CliPrompter {
    fn confirm(&self, consent: &splice_core::pairing::AliasConsent) -> bool {
        eprint!("{}", consent.prompt());
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap_or_default();
        let trimmed = input.trim().to_lowercase();
        trimmed == "y" || trimmed == "yes"
    }
}

// ---------------------------------------------------------------------------
// Top-level dispatch
// ---------------------------------------------------------------------------

/// Run the parsed CLI command.
pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Pair(ref args) => pair::run(&cli, args).await,
        Command::Devices(ref args) => devices::run(&cli, args).await,
        Command::Listen => listen::run(&cli).await,
        Command::Identity(ref args) => identity::run(&cli, args).await,
        Command::Dev(ref cmd) => dev::run(&cli, cmd).await,
    }
}
