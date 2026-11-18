//! Persistent vs ephemeral secret key in a single process, plus proof that both work.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use iroh::{endpoint::presets, Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey, TransportAddr};

use crate::{emit, ms, ALPN, STREAM_TYPE_CONTROL};

/// Create the key file if it is missing; return the key either way.
pub fn load_or_create(path: &Path) -> Result<SecretKey> {
    if path.exists() {
        let hex = std::fs::read_to_string(path).context("read key file")?;
        let bytes = hex_bytes(hex.trim())?;
        return Ok(SecretKey::from_bytes(&bytes));
    }
    let key = SecretKey::generate();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("create key dir")?;
    }
    let mut f = std::fs::File::create(path).context("create key file")?;
    f.write_all(hex_string(&key.to_bytes()).as_bytes())
        .context("write key file")?;
    f.sync_all().context("fsync key file")?;
    Ok(key)
}

fn hex_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_bytes(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 {
        bail!("key file must hold 64 hex chars, found {}", s.len());
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(chunk).context("key file is not ASCII")?;
        out[i] = u8::from_str_radix(text, 16).context("key file is not hex")?;
    }
    Ok(out)
}

/// Proves: a persistent key survives a reload, an ephemeral key differs, and the two
/// identities can talk to each other over the same transport in one process.
pub async fn run(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).context("create keys dir")?;
    let path: PathBuf = dir.join("identity.key");

    let t0 = std::time::Instant::now();
    let persistent = load_or_create(&path)?;
    let first_load_ms = ms(t0.elapsed());
    let persistent_id = persistent.public();

    let t0 = std::time::Instant::now();
    let reloaded = load_or_create(&path)?;
    let reload_ms = ms(t0.elapsed());
    let reloaded_id = reloaded.public();

    let ephemeral = SecretKey::generate();
    let ephemeral_id = ephemeral.public();

    // The reload must be byte-identical, or the "persistent" key is not persistent.
    if persistent.to_bytes() != reloaded.to_bytes() {
        bail!("persistent key changed across reload");
    }
    if persistent_id == ephemeral_id {
        bail!("ephemeral key collided with the persistent key");
    }

    let perms = describe_permissions(&path);

    // Two live endpoints in one process: persistent identity accepts, ephemeral dials.
    let server = Endpoint::builder(presets::Minimal)
        .secret_key(reloaded)
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .context("bind persistent-identity endpoint")?;
    let addr = server_addr(&server);
    let client = Endpoint::builder(presets::Minimal)
        .secret_key(ephemeral)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .context("bind ephemeral-identity endpoint")?;

    if addr.is_none() {
        bail!("server reported no bound socket");
    }
    let (connect_ms, remote_seen) =
        dual_identity_probe(&client, &server, addr.unwrap(), persistent_id).await?;

    server.close().await;
    client.close().await;

    let leftover: Vec<String> = std::fs::read_dir(dir)
        .context("list keys dir")?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();

    emit(serde_json::json!({
        "event": "keys",
        "persistent_id": persistent_id.to_string(),
        "reloaded_id": reloaded_id.to_string(),
        "ephemeral_id": ephemeral_id.to_string(),
        "same_after_reload": true,
        "distinct_ids": true,
        "first_load_ms": first_load_ms,
        "reload_ms": reload_ms,
        "permissions": perms,
        "files_in_dir": leftover,
        "both_alive_in_one_process": true,
        "connect_ms": connect_ms,
        "server_saw_client": remote_seen.map(|i| i.to_string()),
        "key_bytes_in_json": false,
    }));
    Ok(())
}

fn server_addr(ep: &Endpoint) -> Option<std::net::SocketAddr> {
    ep.bound_sockets()
        .into_iter()
        .find(|a| a.is_ipv4() && !a.ip().is_unspecified())
        .or_else(|| ep.bound_sockets().into_iter().next())
}

async fn dual_identity_probe(
    client: &Endpoint,
    server: &Endpoint,
    addr: std::net::SocketAddr,
    expect_id: EndpointId,
) -> Result<(f64, Option<EndpointId>)> {
    let server_id = server.id();
    if server_id != expect_id {
        bail!("persistent endpoint id differs from the stored key's public key");
    }
    let target = EndpointAddr::from_parts(server_id, [TransportAddr::Ip(addr)]);
    let (tx, rx) = tokio::sync::oneshot::channel();

    // Accept task: record who dialled, then answer one stream.
    let server2 = server.clone();
    tokio::spawn(async move {
        let seen = async {
            let incoming = server2.accept().await?;
            let conn = incoming.await.ok()?;
            let remote = conn.remote_id();
            let (_send, mut recv) = conn.accept_bi().await.ok()?;
            let mut ty = [0u8; 1];
            recv.read_exact(&mut ty).await.ok()?;
            let _ = recv.read_to_end(64).await.ok()?;
            conn.close(0u8.into(), b"ok");
            Some(remote)
        };
        let _ = tx.send(seen.await);
    });

    let t0 = std::time::Instant::now();
    let conn = tokio::time::timeout(Duration::from_secs(10), client.connect(target, ALPN))
        .await
        .context("dual-identity connect timed out")?
        .context("dual-identity connect")?;
    let connect_ms = ms(t0.elapsed());
    let (mut send, _recv) = conn.open_bi().await.context("open bi")?;
    send.write_all(&[STREAM_TYPE_CONTROL]).await.context("write type")?;
    send.finish().context("finish")?;
    let seen = tokio::time::timeout(Duration::from_secs(10), rx)
        .await
        .context("accept task timed out")?
        .context("accept task dropped")?;
    Ok((connect_ms, seen))
}

#[cfg(windows)]
fn describe_permissions(path: &Path) -> serde_json::Value {
    let readonly = std::fs::metadata(path)
        .map(|m| m.permissions().readonly())
        .unwrap_or(false);
    serde_json::json!({
        "platform": "windows",
        "unix_mode": serde_json::Value::Null,
        "readonly": readonly,
        "note": "ACL inherited from the user profile; not verified by this spike",
    })
}

#[cfg(unix)]
fn describe_permissions(path: &Path) -> serde_json::Value {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path).map(|m| m.permissions().mode() & 0o777);
    serde_json::json!({
        "platform": "unix",
        "unix_mode": mode.as_ref().map(|m| format!("{m:04o}")).ok(),
        "readonly": false,
    })
}

#[cfg(not(any(windows, unix)))]
fn describe_permissions(_path: &Path) -> serde_json::Value {
    serde_json::json!({ "platform": "unknown" })
}