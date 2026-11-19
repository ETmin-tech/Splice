//! `splice identity show|reset`.
//!
//! The persistent key is the device's identity: it is what a peer pins in its
//! trust store, so resetting it makes every existing pairing unknown to both
//! sides. The command says so before it does it.

use anyhow::{anyhow, Result};

use splice_core::identity;

use crate::cli::{Cli, IdentityAction, IdentityArgs};

/// Run the identity command.
pub async fn run(_cli: &Cli, args: &IdentityArgs) -> Result<()> {
    match args.action {
        IdentityAction::Show => show().await,
        IdentityAction::Reset => reset().await,
    }
}

async fn show() -> Result<()> {
    let dir = identity::config_dir()
        .map_err(|e| anyhow!("gagal menemukan direktori konfigurasi: {e}"))?;
    let path = identity::display_path(&dir);

    match identity::peek_node_id(&dir).map_err(|e| anyhow!("gagal membaca identitas: {e}"))? {
        Some(node_id) => {
            println!("NodeId: {node_id}");
            println!("Berkas: {path}");
            println!("Status: persisten");
        }
        None => {
            println!("Belum ada identitas persisten.");
            println!("Berkas: {path} (belum dibuat)");
            println!("Identitas dibuat otomatis oleh `splice pair` dan `splice listen`.");
        }
    }
    Ok(())
}

async fn reset() -> Result<()> {
    match identity::reset_persistent().map_err(|e| anyhow!("gagal menghapus identitas: {e}"))? {
        true => {
            println!("🗑️  Identitas dihapus. Pairing yang ada tidak lagi mengenali perangkat ini.");
            if let Ok(dir) = identity::config_dir() {
                println!("   {}", identity::display_path(&dir));
            }
            println!("Perangkat lain perlu `splice devices --rm` lalu pairing ulang.");
        }
        false => println!("Tidak ada identitas persisten untuk dihapus."),
    }
    Ok(())
}
