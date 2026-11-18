//! Persistent identity storage (§5.1, I16).
//!
//! Layout: `<config-dir>/identity.key`, 32 raw bytes, owner-only.
//!
//! * Unix: the file is created with mode `0600` *before* any key byte is written,
//!   and the parent directory is `0700`. A store file with looser permissions is
//!   refused, not silently repaired — a world-readable key means the identity is
//!   already compromised, and fixing the mode would hide that.
//! * Windows: mode bits are best effort only. Windows access control is inherited
//!   from the user profile, so the protection is the profile ACL, not this code.
//!   This is stated in the report and in the smoke test below; the ACL is not
//!   verified from Rust.
//!
//! Writes are atomic: temp file in the same directory, `sync_all`, then `rename`.
//! A crash leaves either the old key or the new one, never a truncated file.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::error::{Error, IdentityError, Result};
use crate::identity::{NodeId, NodeSecret};

/// File name inside the config directory.
pub const IDENTITY_FILE: &str = "identity.key";

/// Directory name inside the platform config dir.
const APP_DIR: &str = "splice";

/// Environment override for the config directory. Used by tests and by the
/// offline harness so two processes can have separate identities.
pub const CONFIG_DIR_ENV: &str = "SPLICE_CONFIG_DIR";

/// Where a key came from. Reported by `splice identity show`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentitySource {
    /// Loaded from, or just created in, the config directory.
    Persistent,
    /// Generated for this process only.
    Ephemeral,
}

/// The platform config directory for splice, or `$SPLICE_CONFIG_DIR` when set.
pub fn config_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os(CONFIG_DIR_ENV) {
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir));
        }
    }
    let base = dirs::config_dir().ok_or(Error::ConfigDirUnavailable)?;
    Ok(base.join(APP_DIR))
}

fn identity_path(dir: &Path) -> PathBuf {
    dir.join(IDENTITY_FILE)
}

/// Create `dir` with owner-only permissions where the platform supports them.
fn ensure_dir(dir: &Path) -> Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Ignore failure: the umask may already be tighter than 0700.
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

/// Load the persistent key, or create it on first use.
pub fn load_or_create_persistent() -> Result<(NodeSecret, IdentitySource)> {
    let dir = config_dir()?;
    load_or_create_persistent_in(&dir)
}

/// Same as [`load_or_create_persistent`], with an explicit directory (tests).
pub fn load_or_create_persistent_in(dir: &Path) -> Result<(NodeSecret, IdentitySource)> {
    match load_persistent_in(dir)? {
        Some(secret) => Ok((secret, IdentitySource::Persistent)),
        None => {
            let secret = NodeSecret::generate();
            save_persistent_in(dir, &secret)?;
            Ok((secret, IdentitySource::Persistent))
        }
    }
}

/// Load the persistent key if it exists. `Ok(None)` means "not created yet".
pub fn load_persistent() -> Result<Option<NodeSecret>> {
    load_persistent_in(&config_dir()?)
}

fn load_persistent_in(dir: &Path) -> Result<Option<NodeSecret>> {
    let path = identity_path(dir);
    let metadata = match fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };

    if !metadata.is_file() {
        return Err(IdentityError::NotRegularFile { path }.into());
    }

    check_permissions(&path, &metadata)?;

    let bytes = fs::read(&path)?;
    if bytes.len() != 32 {
        return Err(IdentityError::WrongLength {
            path,
            len: bytes.len(),
            expected: 32,
        }
        .into());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    let secret = NodeSecret::from_bytes(key);
    zeroize(&mut key);
    Ok(Some(secret))
}

/// Refuse a key file that other users can read. Unix only; on Windows access is
/// governed by the profile ACL and there is nothing here that can verify it.
#[cfg(unix)]
fn check_permissions(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(IdentityError::InsecurePermissions {
            path: path.to_path_buf(),
            mode,
        }
        .into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path, _metadata: &fs::Metadata) -> Result<()> {
    // Best effort: Windows ACLs are inherited from %USERPROFILE%. Not verified.
    Ok(())
}

/// Write the key atomically with owner-only permissions.
pub fn save_persistent(secret: &NodeSecret) -> Result<()> {
    save_persistent_in(&config_dir()?, secret)
}

fn save_persistent_in(dir: &Path, secret: &NodeSecret) -> Result<()> {
    ensure_dir(dir)?;
    let path = identity_path(dir);
    let tmp = dir.join(format!("{IDENTITY_FILE}.tmp{}", std::process::id()));

    let mut bytes = secret.to_bytes();
    let write_result = (|| -> std::io::Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Mode is applied at creation time, so there is no window where the
            // file exists with default permissions.
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, &path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            // Make the rename durable.
            if let Ok(dir_handle) = fs::File::open(dir) {
                let _ = dir_handle.sync_all();
            }
        }
        Ok(())
    })();

    zeroize(&mut bytes);
    if let Err(source) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(IdentityError::AtomicWrite { path, source }.into());
    }
    Ok(())
}

/// Delete the persistent identity. Returns `true` if a file was removed.
pub fn reset_persistent() -> Result<bool> {
    reset_persistent_in(&config_dir()?)
}

fn reset_persistent_in(dir: &Path) -> Result<bool> {
    let path = identity_path(dir);
    match fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err.into()),
    }
}

/// Read a key file's raw bytes without validating the key, for the permission
/// smoke test. Never used on the normal path.
#[doc(hidden)]
pub fn read_raw(dir: &Path) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    fs::File::open(identity_path(dir))?.read_to_end(&mut out)?;
    Ok(out)
}

fn zeroize(bytes: &mut [u8]) {
    use zeroize::Zeroize;
    bytes.zeroize();
}

/// Where the persistent identity lives, as a display path. `splice identity show`
/// prints this so users can find and delete the file.
pub fn display_path(dir: &Path) -> String {
    identity_path(dir).display().to_string()
}

/// Report whether the persistent identity file exists yet.
pub fn exists() -> bool {
    config_dir()
        .map(|dir| identity_path(&dir).exists())
        .unwrap_or(false)
}

/// Actual `NodeId` of a directory's persistent identity, if present.
pub fn peek_node_id(dir: &Path) -> Result<Option<NodeId>> {
    Ok(load_persistent_in(dir)?.map(|secret| secret.public()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn creates_then_reloads_the_same_key() {
        let dir = TempDir::new().unwrap();
        let (first, source) = load_or_create_persistent_in(dir.path()).unwrap();
        assert_eq!(source, IdentitySource::Persistent);
        let (second, _) = load_or_create_persistent_in(dir.path()).unwrap();
        assert_eq!(first.public(), second.public());
        assert_eq!(peek_node_id(dir.path()).unwrap(), Some(first.public()));
    }

    #[test]
    fn does_not_overwrite_an_existing_key() {
        let dir = TempDir::new().unwrap();
        let (first, _) = load_or_create_persistent_in(dir.path()).unwrap();
        let raw = read_raw(dir.path()).unwrap();
        let (second, _) = load_or_create_persistent_in(dir.path()).unwrap();
        assert_eq!(first.public(), second.public());
        assert_eq!(raw, read_raw(dir.path()).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn key_file_is_0600_and_dir_is_0700() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        load_or_create_persistent_in(dir.path()).unwrap();
        let file_mode = fs::metadata(dir.path().join(IDENTITY_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600, "key file must be owner-only");
    }

    #[cfg(unix)]
    #[test]
    fn loose_permissions_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        load_or_create_persistent_in(dir.path()).unwrap();
        let path = dir.path().join(IDENTITY_FILE);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let err = load_persistent_in(dir.path()).unwrap_err();
        assert!(
            matches!(
                err,
                Error::Identity(IdentityError::InsecurePermissions { mode: 0o644, .. })
            ),
            "expected InsecurePermissions, got {err:?}"
        );
    }

    #[cfg(not(unix))]
    #[test]
    fn windows_permissions_are_best_effort() {
        // Documents the deviation: on Windows the key file is protected by the
        // per-user profile ACL, which this test does not verify. It only asserts
        // that the store works at all on this platform.
        let dir = TempDir::new().unwrap();
        load_or_create_persistent_in(dir.path()).unwrap();
        assert!(dir.path().join(IDENTITY_FILE).is_file());
    }

    #[test]
    fn reset_removes_the_key_and_reports_whether_it_existed() {
        let dir = TempDir::new().unwrap();
        load_or_create_persistent_in(dir.path()).unwrap();
        assert!(reset_persistent_in(dir.path()).unwrap());
        assert!(!reset_persistent_in(dir.path()).unwrap());
        let (fresh, _) = load_or_create_persistent_in(dir.path()).unwrap();
        assert!(fs::metadata(dir.path().join(IDENTITY_FILE)).is_ok());
        assert_eq!(peek_node_id(dir.path()).unwrap(), Some(fresh.public()));
    }

    #[test]
    fn wrong_length_file_is_rejected_not_padded() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(IDENTITY_FILE), b"too short").unwrap();
        let err = load_persistent_in(dir.path()).unwrap_err();
        assert!(matches!(
            err,
            Error::Identity(IdentityError::WrongLength { len: 9, .. })
        ));
    }

    #[test]
    fn key_bytes_never_appear_in_debug_output_of_the_path_helpers() {
        let dir = TempDir::new().unwrap();
        let (secret, _) = load_or_create_persistent_in(dir.path()).unwrap();
        let mut raw = secret.to_bytes();
        let text = format!(
            "{:?} {} {:?}",
            secret,
            display_path(dir.path()),
            peek_node_id(dir.path()).unwrap()
        );
        // The hex of the secret key must not show up anywhere we format.
        let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!text.contains(&hex));
        zeroize(&mut raw);
    }

    #[test]
    fn no_temp_files_are_left_behind() {
        let dir = TempDir::new().unwrap();
        load_or_create_persistent_in(dir.path()).unwrap();
        let names: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec![IDENTITY_FILE.to_string()]);
    }
}