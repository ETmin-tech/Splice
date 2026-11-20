//! Persistent trust store (§5.6, I16).
//!
//! Layout: `<config-dir>/trust.json` — JSON, owner-only, one entry per pinned
//! device. An entry records the [`NodeId`] that TLS authenticates, a human alias,
//! timestamps, and the two auto-accept fields. The file holds **no key material and
//! no secret** (a `NodeId` is a public key), so the permission rule exists to stop
//! another local account from *pinning* a device, not to hide anything.
//!
//! JSON rather than TOML because the file is machine-written and machine-read and
//! its shape is a list of records. The choice is recorded in `Laporan-1.md` §10.
//!
//! Failure policy, in the order the code checks it:
//!
//! * Missing file → empty store, not an error (first run).
//! * Loose Unix permissions → refused. Another user could otherwise pin a device.
//! * Unparsable or self-inconsistent file → the original bytes are copied to
//!   `trust.json.bak` and [`TrustError::Corrupt`] is returned. The live file is left
//!   alone: a half-understood store is never overwritten or repaired in place,
//!   because silently dropping entries would drop trust records the user expects.
//! * A newer `version` → [`TrustError::UnsupportedVersion`], with no backup: the file
//!   is not damaged, this build is simply too old to read it.
//!
//! Writes are atomic (temp file in the same directory, `sync_all`, `rename`), so a
//! crash leaves either the old store or the new one, never a truncated file.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::constants::{ALIAS_MAX_LEN, AUTO_ACCEPT_MAX_BYTES};
use crate::error::{Error, Result, TrustError};
use crate::identity::{config_dir, NodeId};
use crate::proto::messages::{is_invisible_format, sanitize_alias};

/// File name inside the config directory.
pub const TRUST_FILE: &str = "trust.json";

/// Suffix appended to the old file when the store cannot be parsed.
pub const TRUST_BACKUP_SUFFIX: &str = ".bak";

/// On-disk format version. Bump only when the shape changes incompatibly.
pub const TRUST_FORMAT_VERSION: u8 = 1;

/// One pinned device (§5.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustEntry {
    /// Authenticated by TLS on every connection; never re-derived from data.
    pub node_id: NodeId,
    /// Display name, already sanitized and unique within the store.
    pub alias: String,
    /// Unix seconds when the entry was created.
    pub created_at: u64,
    /// Unix seconds of the last successful trusted connection; `0` = never.
    pub last_seen: u64,
    /// §5.6 default: never accept a transfer without asking.
    pub auto_accept: bool,
    /// Size cap for auto-accepted transfers (§5.6, `AUTO_ACCEPT_MAX_BYTES`).
    pub auto_accept_max_bytes: u64,
}

impl TrustEntry {
    /// A new entry with the spec's defaults: auto-accept off, 1 GiB cap.
    pub fn new(node_id: NodeId, alias: impl Into<String>, now: Duration) -> Self {
        Self {
            node_id,
            alias: alias.into(),
            created_at: now.as_secs(),
            last_seen: 0,
            auto_accept: false,
            auto_accept_max_bytes: AUTO_ACCEPT_MAX_BYTES,
        }
    }

    /// Whether a trusted connection counts as seen before right now.
    pub fn mark_seen(&mut self, now: Duration) {
        self.last_seen = now.as_secs();
    }
}

/// The file as it appears on disk. Kept separate from [`TrustEntry`] so the wire
/// shape (hex text) is explicit and `NodeId` needs no serde impls.
#[derive(Debug, Serialize, Deserialize)]
struct TrustFile {
    version: u8,
    devices: Vec<TrustRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TrustRecord {
    node_id: String,
    alias: String,
    created_at: u64,
    last_seen: u64,
    auto_accept: bool,
    auto_accept_max_bytes: u64,
}

impl From<&TrustEntry> for TrustRecord {
    fn from(entry: &TrustEntry) -> Self {
        Self {
            node_id: entry.node_id.to_string(),
            alias: entry.alias.clone(),
            created_at: entry.created_at,
            last_seen: entry.last_seen,
            auto_accept: entry.auto_accept,
            auto_accept_max_bytes: entry.auto_accept_max_bytes,
        }
    }
}

impl TrustRecord {
    fn into_entry(self) -> std::result::Result<TrustEntry, String> {
        let node_id = NodeId::from_str(&self.node_id)
            .map_err(|_| format!("device {:.16}… has a malformed node id", self.node_id))?;
        if self.alias.is_empty() {
            return Err(format!("device {} has an empty alias", node_id.prefix8()));
        }
        if self.alias.chars().count() > ALIAS_MAX_LEN {
            return Err(format!(
                "device {} has an over-long alias",
                node_id.prefix8()
            ));
        }
        if self.alias.chars().any(char::is_control) {
            return Err(format!(
                "device {} has a control character in its alias",
                node_id.prefix8()
            ));
        }
        if self.alias.chars().any(is_invisible_format) {
            return Err(format!(
                "device {} has an invisible formatting character in its alias",
                node_id.prefix8()
            ));
        }
        Ok(TrustEntry {
            node_id,
            alias: self.alias,
            created_at: self.created_at,
            last_seen: self.last_seen,
            auto_accept: self.auto_accept,
            auto_accept_max_bytes: self.auto_accept_max_bytes,
        })
    }
}

/// The loaded store. Every lookup is by [`NodeId`]: an alias is a label, never an
/// identity, so renaming a device cannot grant it trust.
#[derive(Debug)]
pub struct TrustStore {
    path: PathBuf,
    entries: Vec<TrustEntry>,
}

impl TrustStore {
    /// Load `trust.json` from `dir`. A missing file is an empty store.
    pub fn load_in(dir: &Path) -> Result<Self> {
        let path = dir.join(TRUST_FILE);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    path,
                    entries: Vec::new(),
                })
            }
            Err(err) => return Err(err.into()),
        };

        check_permissions(&path)?;
        let text = match std::str::from_utf8(&bytes) {
            Ok(text) => text,
            Err(_) => return Err(quarantine(&path, "file is not valid UTF-8".into())),
        };
        let file: TrustFile = match serde_json::from_str(text) {
            Ok(file) => file,
            Err(err) => return Err(quarantine(&path, err.to_string())),
        };

        if file.version > TRUST_FORMAT_VERSION {
            // Not damage: a newer build wrote this. Do not back up, do not touch.
            return Err(TrustError::UnsupportedVersion {
                path,
                version: file.version,
                supported: TRUST_FORMAT_VERSION,
            }
            .into());
        }

        let mut entries: Vec<TrustEntry> = Vec::with_capacity(file.devices.len());
        for record in file.devices {
            let entry = match record.into_entry() {
                Ok(entry) => entry,
                Err(detail) => return Err(quarantine(&path, detail)),
            };
            if entries.iter().any(|other| other.node_id == entry.node_id) {
                return Err(quarantine(
                    &path,
                    format!("device {} appears twice", entry.node_id.prefix8()),
                ));
            }
            if entries
                .iter()
                .any(|other| other.alias.eq_ignore_ascii_case(&entry.alias))
            {
                return Err(quarantine(
                    &path,
                    format!("alias {:?} appears twice", entry.alias),
                ));
            }
            entries.push(entry);
        }

        Ok(Self { path, entries })
    }

    /// Load from the platform config directory (`$SPLICE_CONFIG_DIR` when set).
    pub fn load() -> Result<Self> {
        Self::load_in(&config_dir()?)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Display path, for `splice devices` and error text.
    pub fn display_path(&self) -> String {
        self.path.display().to_string()
    }

    pub fn entries(&self) -> &[TrustEntry] {
        &self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// The single question I13 asks: is this NodeId pinned?
    pub fn contains(&self, id: &NodeId) -> bool {
        self.entries.iter().any(|entry| entry.node_id == *id)
    }

    pub fn get(&self, id: &NodeId) -> Option<&TrustEntry> {
        self.entries.iter().find(|entry| entry.node_id == *id)
    }

    pub fn find_by_alias(&self, alias: &str) -> Option<&TrustEntry> {
        self.entries
            .iter()
            .find(|entry| entry.alias.eq_ignore_ascii_case(alias))
    }

    /// Whether `alias` is free (case-insensitive), used to warn before prompting.
    pub fn alias_is_free(&self, alias: &str) -> bool {
        self.find_by_alias(alias).is_none()
    }

    /// A free variant of `desired`: `desired-2`, `desired-3`, … trimmed to fit
    /// `ALIAS_MAX_LEN`. Returns the input unchanged when it is already free.
    pub fn suggest_alias(&self, desired: &str) -> String {
        if self.alias_is_free(desired) {
            return desired.to_string();
        }
        for n in 2..1000u32 {
            let suffix = format!("-{n}");
            let take = ALIAS_MAX_LEN.saturating_sub(suffix.chars().count());
            let stem = truncate_chars(desired, take);
            let candidate = format!("{stem}{suffix}");
            if self.alias_is_free(&candidate) {
                return candidate;
            }
        }
        truncate_chars(desired, ALIAS_MAX_LEN)
    }

    /// Add a device and persist it. The alias is sanitized here, so no caller can
    /// write a control character into the file.
    ///
    /// Re-adding the **same NodeId with the same alias** is a no-op (`Ok`), because
    /// a repeated pairing of a device that is already known should not be an error
    /// the user has to work around. Any other collision is an error:
    ///
    /// * same NodeId, different alias → [`TrustError::DuplicateNodeId`] (the device
    ///   is already here; use `devices rm` first to rename).
    /// * same alias, different NodeId → [`TrustError::DuplicateAlias`], and the
    ///   caller shows [`Self::suggest_alias`] to the user.
    pub fn add(&mut self, entry: TrustEntry) -> Result<()> {
        let alias = sanitize_alias(&entry.alias)?;

        if let Some(existing) = self.get(&entry.node_id) {
            if existing.alias.eq_ignore_ascii_case(&alias) {
                return Ok(());
            }
            return Err(TrustError::DuplicateNodeId {
                id: entry.node_id.prefix8(),
                alias: existing.alias.clone(),
            }
            .into());
        }
        if self.find_by_alias(&alias).is_some() {
            return Err(TrustError::DuplicateAlias { alias }.into());
        }

        let mut stored = entry;
        stored.alias = alias;
        self.entries.push(stored);
        if let Err(err) = self.save() {
            // Keep memory and disk in agreement: a failed save must not leave a
            // device trusted until the process exits.
            self.entries.pop();
            return Err(err);
        }
        Ok(())
    }

    /// Remove by alias (or by the 8-character shorthand of the NodeId) and persist.
    /// Returns the removed entry so the caller can close live connections.
    pub fn remove(&mut self, alias_or_id: &str) -> Result<TrustEntry> {
        let wanted = alias_or_id.trim();
        let index = self
            .entries
            .iter()
            .position(|entry| {
                entry.alias.eq_ignore_ascii_case(wanted)
                    || entry.node_id.shorthand().eq_ignore_ascii_case(wanted)
                    || entry.node_id.to_string().eq_ignore_ascii_case(wanted)
            })
            .ok_or_else(|| TrustError::NotFound(wanted.to_string()))?;

        let entry = self.entries.remove(index);
        if let Err(err) = self.save() {
            self.entries.insert(index, entry);
            return Err(err);
        }
        Ok(entry)
    }

    /// Record a successful trusted connection. Persists `last_seen`.
    pub fn touch(&mut self, id: &NodeId, now: Duration) -> Result<()> {
        let Some(index) = self.entries.iter().position(|entry| entry.node_id == *id) else {
            return Err(TrustError::NotFound(id.prefix8()).into());
        };
        let previous = self.entries[index].last_seen;
        self.entries[index].mark_seen(now);
        if let Err(err) = self.save() {
            self.entries[index].last_seen = previous;
            return Err(err);
        }
        Ok(())
    }

    /// Write the store atomically, owner-only.
    pub fn save(&self) -> Result<()> {
        let file = TrustFile {
            version: TRUST_FORMAT_VERSION,
            devices: self.entries.iter().map(TrustRecord::from).collect(),
        };
        let mut bytes = serde_json::to_vec_pretty(&file).map_err(|err| TrustError::Save {
            path: self.path.clone(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()),
        })?;
        bytes.push(b'\n');

        let result = write_atomic(&self.path, &bytes);
        match result {
            Ok(()) => Ok(()),
            Err(source) => Err(TrustError::Save {
                path: self.path.clone(),
                source,
            }
            .into()),
        }
    }
}

/// Truncate on a character boundary.
fn truncate_chars(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

/// Copy an unreadable store aside and build the error that names the backup.
///
/// The live file is never rewritten here: whatever is in it stays available for a
/// human to inspect, and no entry is dropped behind the user's back.
fn quarantine(path: &Path, detail: String) -> Error {
    let backup = path.with_extension(format!("json{TRUST_BACKUP_SUFFIX}"));
    match fs::copy(path, &backup) {
        Ok(_) => TrustError::Corrupt {
            path: path.to_path_buf(),
            detail,
            backup,
        }
        .into(),
        Err(source) => TrustError::BackupFailed {
            path: path.to_path_buf(),
            detail,
            source,
        }
        .into(),
    }
}

/// Refuse a store another local user can rewrite (I16, Unix only).
#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(TrustError::InsecurePermissions {
            path: path.to_path_buf(),
            mode,
        }
        .into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) -> Result<()> {
    // Best effort, exactly like the identity key: Windows protects the config
    // directory through the profile ACL, which is not verified here.
    Ok(())
}

/// Temp file + `sync_all` + `rename`, mode applied at creation on Unix.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }

    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| TRUST_FILE.to_string());
    let tmp = dir.join(format!("{file_name}.tmp{}", std::process::id()));

    let result = (|| -> std::io::Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            if let Ok(dir_handle) = fs::File::open(dir) {
                let _ = dir_handle.sync_all();
            }
        }
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeSecret;
    use tempfile::TempDir;

    fn node() -> NodeId {
        NodeSecret::generate().public()
    }

    fn open(dir: &TempDir) -> TrustStore {
        TrustStore::load_in(dir.path()).unwrap()
    }

    fn add(store: &mut TrustStore, alias: &str) -> NodeId {
        let id = node();
        store
            .add(TrustEntry::new(id, alias, Duration::ZERO))
            .unwrap();
        id
    }

    /// Write a store file the way the loader expects to find it (owner-only).
    ///
    /// A plain `fs::write` inherits the umask, which on Linux is `0644`; the
    /// loader then stops at the permission check, before it can report the
    /// corruption these tests are about.
    fn write_store_file(path: &std::path::Path, bytes: impl AsRef<[u8]>) {
        fs::write(path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn missing_file_is_an_empty_store() {
        let dir = TempDir::new().unwrap();
        let store = open(&dir);
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert_eq!(store.display_path(), store.path().display().to_string());
        // Reading an empty store must not create the file.
        assert!(!store.path().exists());
    }

    #[test]
    fn add_then_reload_roundtrips() {
        let dir = TempDir::new().unwrap();
        let now = Duration::from_secs(1_700_000_000);
        let id = node();
        {
            let mut store = open(&dir);
            store
                .add(TrustEntry::new(id, "laptop", now))
                .expect("fresh alias");
        }
        let store = open(&dir);
        assert_eq!(store.len(), 1);
        let entry = store.get(&id).expect("entry survives reload");
        assert_eq!(entry.alias, "laptop");
        assert_eq!(entry.created_at, 1_700_000_000);
        assert_eq!(entry.last_seen, 0);
        assert!(!entry.auto_accept);
        assert_eq!(entry.auto_accept_max_bytes, AUTO_ACCEPT_MAX_BYTES);
        assert!(store.contains(&id));
        assert!(!store.contains(&node()));
    }

    #[test]
    fn readding_same_node_and_alias_is_a_noop() {
        let dir = TempDir::new().unwrap();
        let mut store = open(&dir);
        let id = add(&mut store, "laptop");
        store
            .add(TrustEntry::new(id, "LAPTOP", Duration::from_secs(1)))
            .expect("same node, same alias modulo case");
        assert_eq!(store.len(), 1);
        assert_eq!(store.entries()[0].alias, "laptop");
    }

    #[test]
    fn readding_same_node_with_new_alias_is_refused() {
        let dir = TempDir::new().unwrap();
        let mut store = open(&dir);
        let id = add(&mut store, "laptop");
        let err = store
            .add(TrustEntry::new(id, "desktop", Duration::ZERO))
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Trust(TrustError::DuplicateNodeId { ref alias, .. }) if alias == "laptop"
        ));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn same_alias_other_node_is_refused_and_suggested() {
        let dir = TempDir::new().unwrap();
        let mut store = open(&dir);
        add(&mut store, "laptop");
        let err = store
            .add(TrustEntry::new(node(), "Laptop", Duration::ZERO))
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Trust(TrustError::DuplicateAlias { ref alias }) if alias == "Laptop"
        ));
        assert_eq!(store.len(), 1);

        assert_eq!(store.suggest_alias("laptop"), "laptop-2");
        assert!(!store.alias_is_free("LAPTOP"));
        assert!(store.alias_is_free("laptop-2"));
    }

    #[test]
    fn suggest_alias_keeps_the_limit() {
        let dir = TempDir::new().unwrap();
        let mut store = open(&dir);
        let long = "a".repeat(ALIAS_MAX_LEN);
        add(&mut store, &long);
        // The "-2" suffix must fit inside the limit, not push past it.
        let suggestion = store.suggest_alias(&long);
        assert!(suggestion.chars().count() <= ALIAS_MAX_LEN);
        assert!(suggestion.starts_with("aaaa"));
        assert!(suggestion.ends_with("-2"));
        assert!(store.alias_is_free(&suggestion));
    }

    #[test]
    fn alias_is_sanitized_before_storing() {
        let dir = TempDir::new().unwrap();
        let mut store = open(&dir);
        let id = node();
        store
            .add(TrustEntry::new(id, "  lap\t\ttop  ", Duration::ZERO))
            .unwrap();
        assert_eq!(store.get(&id).unwrap().alias, "lap top");
        // And the sanitized form is what the file holds.
        let text = fs::read_to_string(store.path()).unwrap();
        assert!(text.contains("\"lap top\""));
    }

    #[test]
    fn empty_alias_is_refused() {
        let dir = TempDir::new().unwrap();
        let mut store = open(&dir);
        let err = store
            .add(TrustEntry::new(node(), " \u{200b}\t ", Duration::ZERO))
            .unwrap_err();
        assert!(matches!(err, Error::Trust(TrustError::EmptyAlias)));
        assert!(store.is_empty());
    }

    #[test]
    fn remove_accepts_alias_shorthand_and_full_hex() {
        let dir = TempDir::new().unwrap();
        let mut store = open(&dir);

        let by_alias = add(&mut store, "laptop");
        let removed = store.remove("  LAPTOP ").unwrap();
        assert_eq!(removed.node_id, by_alias);

        let by_short = add(&mut store, "desktop");
        let removed = store.remove(&by_short.shorthand()).unwrap();
        assert_eq!(removed.node_id, by_short);

        let by_hex = add(&mut store, "phone");
        let removed = store.remove(&by_hex.to_string()).unwrap();
        assert_eq!(removed.node_id, by_hex);

        assert!(store.is_empty());
        assert!(open(&dir).is_empty(), "removals are persisted");
    }

    #[test]
    fn remove_unknown_is_not_found() {
        let dir = TempDir::new().unwrap();
        let mut store = open(&dir);
        let err = store.remove("nobody").unwrap_err();
        assert!(matches!(
            err,
            Error::Trust(TrustError::NotFound(ref what)) if what == "nobody"
        ));
    }

    #[test]
    fn touch_records_last_seen_and_persists() {
        let dir = TempDir::new().unwrap();
        let mut store = open(&dir);
        let id = add(&mut store, "laptop");
        store.touch(&id, Duration::from_secs(42)).unwrap();
        assert_eq!(store.get(&id).unwrap().last_seen, 42);
        assert_eq!(open(&dir).get(&id).unwrap().last_seen, 42);

        let err = store.touch(&node(), Duration::ZERO).unwrap_err();
        assert!(matches!(err, Error::Trust(TrustError::NotFound(_))));
    }

    #[test]
    fn corrupt_json_is_quarantined_and_live_file_kept() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(TRUST_FILE);
        write_store_file(&path, b"{not json at all");

        let err = TrustStore::load_in(dir.path()).unwrap_err();
        let backup = match err {
            Error::Trust(TrustError::Corrupt {
                path: ref reported,
                backup,
                ..
            }) => {
                assert_eq!(reported, &path);
                backup
            }
            other => panic!("expected Corrupt, got {other:?}"),
        };
        assert_eq!(backup, dir.path().join("trust.json.bak"));
        assert_eq!(fs::read(&backup).unwrap(), b"{not json at all");
        assert_eq!(
            fs::read(&path).unwrap(),
            b"{not json at all",
            "the original file is never rewritten"
        );
    }

    #[test]
    fn non_utf8_file_is_quarantined() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(TRUST_FILE);
        write_store_file(&path, [0xff, 0xfe, 0x00]);
        let err = TrustStore::load_in(dir.path()).unwrap_err();
        assert!(matches!(err, Error::Trust(TrustError::Corrupt { .. })));
        assert!(dir.path().join("trust.json.bak").exists());
    }

    #[test]
    fn newer_version_is_unsupported_and_never_touched() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(TRUST_FILE);
        let text = format!(
            "{{\"version\":{}, \"devices\":[]}}",
            TRUST_FORMAT_VERSION + 1
        );
        write_store_file(&path, &text);

        let err = TrustStore::load_in(dir.path()).unwrap_err();
        assert!(matches!(
            err,
            Error::Trust(TrustError::UnsupportedVersion { version, .. })
                if version == TRUST_FORMAT_VERSION + 1
        ));
        assert!(!dir.path().join("trust.json.bak").exists());
        assert_eq!(fs::read_to_string(&path).unwrap(), text);
    }

    #[test]
    fn duplicate_node_ids_in_the_file_are_corrupt() {
        let dir = TempDir::new().unwrap();
        let id = node();
        let path = dir.path().join(TRUST_FILE);
        let text = format!(
            r#"{{"version":1,"devices":[
                {{"node_id":"{id}","alias":"a","created_at":0,"last_seen":0,"auto_accept":false,"auto_accept_max_bytes":1}},
                {{"node_id":"{id}","alias":"b","created_at":0,"last_seen":0,"auto_accept":false,"auto_accept_max_bytes":1}}
            ]}}"#
        );
        write_store_file(&path, &text);
        let err = TrustStore::load_in(dir.path()).unwrap_err();
        assert!(matches!(err, Error::Trust(TrustError::Corrupt { .. })));
    }

    #[test]
    fn duplicate_aliases_in_the_file_are_corrupt() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(TRUST_FILE);
        let text = format!(
            r#"{{"version":1,"devices":[
                {{"node_id":"{}","alias":"Home","created_at":0,"last_seen":0,"auto_accept":false,"auto_accept_max_bytes":1}},
                {{"node_id":"{}","alias":"home","created_at":0,"last_seen":0,"auto_accept":false,"auto_accept_max_bytes":1}}
            ]}}"#,
            node(),
            node()
        );
        write_store_file(&path, &text);
        let err = TrustStore::load_in(dir.path()).unwrap_err();
        assert!(matches!(err, Error::Trust(TrustError::Corrupt { .. })));
    }

    #[test]
    fn a_malformed_node_id_is_corrupt_not_a_panic() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(TRUST_FILE);
        write_store_file(
            &path,
            r#"{"version":1,"devices":[{"node_id":"zz","alias":"x","created_at":0,"last_seen":0,"auto_accept":false,"auto_accept_max_bytes":1}]}"#,
        );
        let err = TrustStore::load_in(dir.path()).unwrap_err();
        assert!(matches!(err, Error::Trust(TrustError::Corrupt { .. })));
    }

    #[test]
    fn an_invisible_format_character_in_the_file_is_corrupt() {
        // `sanitize_alias` strips these on the way in, so the only way one reaches
        // the store is a hand-edited or foreign file. It must be refused there too:
        // the alias is rendered in `splice devices` and in the consent prompt.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(TRUST_FILE);
        let text = format!(
            r#"{{"version":1,"devices":[{{"node_id":"{}","alias":"lap\u202etop","created_at":0,"last_seen":0,"auto_accept":false,"auto_accept_max_bytes":1}}]}}"#,
            node()
        );
        write_store_file(&path, &text);
        let err = TrustStore::load_in(dir.path()).unwrap_err();
        assert!(matches!(err, Error::Trust(TrustError::Corrupt { .. })));
    }

    #[test]
    fn an_over_long_alias_is_corrupt_but_the_cap_itself_is_accepted() {
        // `into_entry`'s cap is `> ALIAS_MAX_LEN`, not `>=`: an alias of exactly
        // the limit is legal (the sanitizer produces one) and must load.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(TRUST_FILE);
        let at_cap = "a".repeat(ALIAS_MAX_LEN);
        let text = format!(
            r#"{{"version":1,"devices":[{{"node_id":"{}","alias":"{at_cap}","created_at":0,"last_seen":0,"auto_accept":false,"auto_accept_max_bytes":1}}]}}"#,
            node()
        );
        write_store_file(&path, &text);
        let store = TrustStore::load_in(dir.path()).expect("an alias at the cap is legal");
        assert_eq!(store.entries()[0].alias.chars().count(), ALIAS_MAX_LEN);
    }

    #[test]
    fn an_alias_past_the_cap_is_corrupt() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(TRUST_FILE);
        let too_long = "a".repeat(ALIAS_MAX_LEN + 1);
        let text = format!(
            r#"{{"version":1,"devices":[{{"node_id":"{}","alias":"{too_long}","created_at":0,"last_seen":0,"auto_accept":false,"auto_accept_max_bytes":1}}]}}"#,
            node()
        );
        write_store_file(&path, &text);
        let err = TrustStore::load_in(dir.path()).unwrap_err();
        assert!(matches!(err, Error::Trust(TrustError::Corrupt { .. })));
    }

    #[test]
    fn a_directory_in_place_of_the_store_is_an_io_error_not_an_empty_store() {
        // The `NotFound` guard must mean "first run" only. A path that exists but
        // cannot be read is an error; reporting it as an empty store would let the
        // next `add` silently replace whatever is there.
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join(TRUST_FILE)).unwrap();
        let err = TrustStore::load_in(dir.path()).unwrap_err();
        assert!(
            matches!(err, Error::Io(_)),
            "an unreadable store must surface the io error, got {err:?}"
        );
    }

    #[test]
    fn a_loaded_store_is_not_empty_and_lists_its_entries() {
        // `is_empty` is what `devices` and `listen` branch on; a hard `true` would
        // tell a user with pinned devices that none are pinned.
        let dir = TempDir::new().unwrap();
        let mut store = open(&dir);
        assert!(store.is_empty());
        let id = add(&mut store, "laptop");
        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);
        assert!(store.contains(&id));
        assert!(
            !store.contains(&node()),
            "an unpinned node must not read as pinned"
        );
        assert!(open(&dir).contains(&id));
    }

    #[test]
    fn a_control_character_in_the_file_is_corrupt() {
        // The neighbouring check the format-character one was added beside.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(TRUST_FILE);
        let text = format!(
            r#"{{"version":1,"devices":[{{"node_id":"{}","alias":"lap\u001btop","created_at":0,"last_seen":0,"auto_accept":false,"auto_accept_max_bytes":1}}]}}"#,
            node()
        );
        write_store_file(&path, &text);
        let err = TrustStore::load_in(dir.path()).unwrap_err();
        assert!(matches!(err, Error::Trust(TrustError::Corrupt { .. })));
    }

    #[test]
    fn save_leaves_no_temporary_files() {
        let dir = TempDir::new().unwrap();
        let mut store = open(&dir);
        add(&mut store, "laptop");
        let names: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec![TRUST_FILE.to_string()]);
    }

    #[test]
    fn the_file_holds_no_key_material() {
        let dir = TempDir::new().unwrap();
        let mut store = open(&dir);
        let secret = NodeSecret::generate();
        store
            .add(TrustEntry::new(
                secret.public(),
                "laptop",
                Duration::from_secs(7),
            ))
            .unwrap();

        let text = fs::read_to_string(store.path()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        let device = &value["devices"][0];
        let mut keys: Vec<&str> = device
            .as_object()
            .expect("device is an object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "alias",
                "auto_accept",
                "auto_accept_max_bytes",
                "created_at",
                "last_seen",
                "node_id",
            ],
            "the file shape is exactly these fields, nothing more"
        );
        // Only the public key is written; the file has no secret to leak.
        assert_eq!(device["node_id"], secret.public().to_string());
    }

    #[cfg(unix)]
    #[test]
    fn file_is_0600_and_dir_is_0700() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let mut store = open(&dir);
        add(&mut store, "laptop");

        let file_mode = fs::metadata(dir.path().join(TRUST_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600, "trust store must be owner-only");
        let dir_mode = fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "config dir must be owner-only");
    }

    #[cfg(unix)]
    #[test]
    fn loose_permissions_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(TRUST_FILE);
        fs::write(&path, r#"{"version":1,"devices":[]}"#).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let err = TrustStore::load_in(dir.path()).unwrap_err();
        assert!(matches!(
            err,
            Error::Trust(TrustError::InsecurePermissions { mode: 0o644, .. })
        ));
        assert!(!dir.path().join("trust.json.bak").exists());
    }
}
