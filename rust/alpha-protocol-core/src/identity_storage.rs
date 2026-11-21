//! Identity file storage and persistence
//!
//! Handles saving and loading node identities to prevent wallet regeneration
//! on restart. Similar to the Python APN Core implementation.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::identity::NodeIdentity;

const IDENTITY_FILE: &str = "node_identity.json";
const BACKUP_SUFFIX: &str = ".backup";

/// Stored identity data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredIdentity {
    pub node_id: String,
    pub wallet_address: String,
    pub mnemonic: String,
    pub public_key: String,
}

impl From<&NodeIdentity> for StoredIdentity {
    fn from(identity: &NodeIdentity) -> Self {
        Self {
            node_id: identity.short_id(),
            wallet_address: identity.address().to_string(),
            mnemonic: identity.mnemonic_phrase(),
            public_key: identity.public_key_hex(),
        }
    }
}

/// Environment variable that overrides the data directory.
pub const DATA_DIR_ENV: &str = "APN_DATA_DIR";

/// Get the data directory: `$APN_DATA_DIR` if set, otherwise `~/.apn`.
///
/// The directory is created if missing and kept owner-only (0700).
pub fn get_config_dir() -> Result<PathBuf> {
    let config_dir = match std::env::var(DATA_DIR_ENV) {
        Ok(dir) if !dir.trim().is_empty() => PathBuf::from(dir),
        _ => {
            let home = std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .context("Could not determine home directory (set APN_DATA_DIR)")?;
            Path::new(&home).join(".apn")
        }
    };

    if !config_dir.exists() {
        fs::create_dir_all(&config_dir)
            .with_context(|| format!("Failed to create {}", config_dir.display()))?;
    }

    // Owner-only directory on Unix. Best effort: the directory may belong to
    // someone else when a read-only command is run by another user.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(&config_dir) {
            if meta.permissions().mode() & 0o077 != 0 {
                let _ = fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700));
            }
        }
    }

    Ok(config_dir)
}

/// Write a file that only its owner can read (0600), atomically.
///
/// The file is created with mode 0600 from the start (never world-readable,
/// not even briefly) and renamed into place.
pub fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;

    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    let _ = fs::remove_file(&tmp);

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options
        .open(&tmp)
        .with_context(|| format!("Failed to create {}", tmp.display()))?;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);

    fs::rename(&tmp, path).with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

/// Make sure an existing file is owner-only (0600). No-op off Unix.
pub fn ensure_private(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)?.permissions().mode();
        if mode & 0o177 != 0 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            tracing::warn!(
                "Tightened permissions on {} to owner-only (was {:o})",
                path.display(),
                mode & 0o777
            );
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Get path to identity file
pub fn get_identity_file_path() -> Result<PathBuf> {
    Ok(get_config_dir()?.join(IDENTITY_FILE))
}

/// Load existing identity from file
pub fn load_identity() -> Result<Option<NodeIdentity>> {
    let identity_file = get_identity_file_path()?;

    if !identity_file.exists() {
        tracing::info!(
            "No existing identity file found at {}",
            identity_file.display()
        );
        return Ok(None);
    }

    tracing::debug!("Loading existing identity from {}", identity_file.display());

    // The file holds the recovery phrase: keep it owner-only.
    ensure_private(&identity_file)?;

    // Read and parse identity file
    let contents = fs::read_to_string(&identity_file)
        .context("Failed to read identity file. If corrupted, backup and delete it to generate new identity.")?;

    let stored: StoredIdentity = serde_json::from_str(&contents)
        .context("Identity file is corrupted (invalid JSON). Backup the file and delete it to generate new identity. WARNING: This will create a new wallet!")?;

    // Validate required fields
    if stored.node_id.is_empty() || stored.wallet_address.is_empty() || stored.mnemonic.is_empty() {
        anyhow::bail!(
            "Identity file is missing required fields. Backup and delete to generate new identity."
        );
    }

    // Recreate identity from mnemonic
    let identity = NodeIdentity::from_mnemonic_phrase(&stored.mnemonic)
        .context("Failed to recreate identity from stored mnemonic")?;

    // Verify it matches stored data
    if identity.short_id() != stored.node_id {
        anyhow::bail!(
            "Identity verification failed: node_id mismatch (file: {}, derived: {})",
            stored.node_id,
            identity.short_id()
        );
    }

    tracing::info!("Loaded node identity {}", identity.short_id());

    Ok(Some(identity))
}

/// Save identity to file (with backup)
pub fn save_identity(identity: &NodeIdentity) -> Result<()> {
    let identity_file = get_identity_file_path()?;
    let backup_file = identity_file.with_extension(format!("json{}", BACKUP_SUFFIX));

    // Create backup if file exists (owner-only, like the original)
    if identity_file.exists() {
        let existing =
            fs::read(&identity_file).context("Failed to read identity file for backup")?;
        write_private_file(&backup_file, &existing)
            .context("Failed to create backup of identity file")?;
        tracing::info!("Created backup: {}", backup_file.display());
    }

    // Prepare identity data
    let stored = StoredIdentity::from(identity);
    let json = serde_json::to_string_pretty(&stored).context("Failed to serialize identity")?;

    // Write identity file, owner-only from creation
    write_private_file(&identity_file, json.as_bytes()).context("Failed to write identity file")?;

    // Verify the saved file can be read back
    let verification =
        fs::read_to_string(&identity_file).context("Failed to verify saved identity file")?;
    let verified: StoredIdentity = serde_json::from_str(&verification)
        .context("Identity verification failed - saved file is not valid JSON")?;

    if verified.node_id != identity.short_id() {
        anyhow::bail!(
            "Identity verification failed: node_id mismatch after save (expected: {}, got: {})",
            identity.short_id(),
            verified.node_id
        );
    }

    tracing::info!("Saved identity to {}", identity_file.display());

    Ok(())
}

/// Load or create identity (with persistence)
pub fn load_or_create_identity(import_mnemonic: Option<&str>) -> Result<NodeIdentity> {
    // If importing from mnemonic, use it directly
    if let Some(mnemonic) = import_mnemonic {
        tracing::info!("Importing identity from provided recovery phrase");
        let identity = NodeIdentity::from_mnemonic_phrase(mnemonic)?;
        save_identity(&identity)?;
        return Ok(identity);
    }

    Ok(load_or_create()?.0)
}

/// Load the stored identity, or create and save a new one.
///
/// Returns the identity and whether it was created by this call. The caller
/// is responsible for showing the recovery phrase to the operator when (and
/// only when) the identity was just created. Nothing here logs the phrase.
pub fn load_or_create() -> Result<(NodeIdentity, bool)> {
    if let Some(identity) = load_identity()? {
        return Ok((identity, false));
    }

    let identity = NodeIdentity::generate()?;
    save_identity(&identity)?;
    tracing::info!(
        "Created new node identity {} (saved, reused on restart)",
        identity.short_id()
    );

    Ok((identity, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stored_identity_roundtrip() {
        let identity = NodeIdentity::generate().unwrap();
        let stored = StoredIdentity::from(&identity);

        let json = serde_json::to_string(&stored).unwrap();
        let parsed: StoredIdentity = serde_json::from_str(&json).unwrap();

        assert_eq!(stored.node_id, parsed.node_id);
        assert_eq!(stored.wallet_address, parsed.wallet_address);
        assert_eq!(stored.mnemonic, parsed.mnemonic);
    }

    #[cfg(unix)]
    #[test]
    fn test_private_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("apn-priv-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret.json");

        write_private_file(&path, b"{}").unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        // A file that was left readable by others is tightened on load.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        ensure_private(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        fs::remove_dir_all(&dir).unwrap();
    }
}
