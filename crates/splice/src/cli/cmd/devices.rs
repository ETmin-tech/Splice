//! `splice devices` and `splice devices --rm <alias>`.
//!
//! Listing is read-only: the trust store is the single source of truth, so the
//! command never infers trust from a live connection. With no daemon in Phase 1
//! there is no live session to revoke, so `--rm` only edits the store.

use anyhow::{anyhow, Result};

use splice_core::clock::{Clock, SystemClock};
use splice_core::trust::TrustStore;

use crate::cli::{Cli, DevicesArgs};

/// How long ago `last_seen` was, in words a human reads quickly.
fn seen_ago(last_seen: u64, now: u64) -> String {
    if last_seen == 0 {
        return "belum pernah".to_string();
    }
    let secs = now.saturating_sub(last_seen);
    match secs {
        0..=59 => "baru saja".to_string(),
        60..=3_599 => format!("{} menit lalu", secs / 60),
        3_600..=86_399 => format!("{} jam lalu", secs / 3_600),
        _ => format!("{} hari lalu", secs / 86_400),
    }
}

/// Run the devices command.
pub async fn run(_cli: &Cli, args: &DevicesArgs) -> Result<()> {
    let mut store = TrustStore::load()?;
    let path = store.display_path();

    if let Some(target) = &args.rm {
        let entry = store
            .remove(target)
            .map_err(|e| anyhow!("gagal menghapus `{target}`: {e}"))?;
        println!(
            "🗑️  {} ({}) dihapus",
            entry.alias,
            entry.node_id.shorthand()
        );
        println!("   {path}");
        return Ok(());
    }

    if store.is_empty() {
        println!("Belum ada perangkat tepercaya.");
        println!("Jalankan `splice pair` di dua perangkat untuk memasangkan.");
        println!("Berkas: {path}");
        return Ok(());
    }

    let now = SystemClock.now().as_secs();
    println!("Perangkat tepercaya ({}):", store.len());
    for entry in store.entries() {
        println!(
            "  {:<24} {}  terakhir: {}",
            entry.alias,
            entry.node_id.shorthand(),
            seen_ago(entry.last_seen, now)
        );
    }
    println!();
    println!("Berkas: {path}");
    Ok(())
}
