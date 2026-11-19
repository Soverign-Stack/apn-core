//! Claim code (enrolment)
//!
//! On first run the node creates a random claim code and keeps it next to
//! its identity, in a file only its owner can read. The owner types the code
//! into the Dashboard to attach the node to their organization.
//!
//! The code is a secret. It is random, not derived from the public key, and
//! it never leaves the machine: heartbeats carry only its SHA-256 hash.

use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity_storage;

/// 32 unambiguous symbols: no I, O, 0 or 1.
pub const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// Number of symbols in a code (shown as `XXXXX-XXXXX`).
pub const CODE_LEN: usize = 10;

const CLAIM_FILE: &str = "claim_code.json";

/// A claim code, held in its canonical form: 10 uppercase symbols, no dash.
#[derive(Clone, PartialEq, Eq)]
pub struct ClaimCode(String);

// The code is a secret: keep it out of debug output.
impl std::fmt::Debug for ClaimCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ClaimCode(<redacted>)")
    }
}

impl ClaimCode {
    /// Create a new random code from the operating system's secure generator.
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        let code: String = (0..CODE_LEN)
            // 32 symbols: every index is equally likely, no modulo bias.
            .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
            .collect();
        Self(code)
    }

    /// Parse what an operator typed: dashes and spaces are ignored, lower
    /// case is accepted. Anything else that is not in the alphabet is an error.
    pub fn parse(input: &str) -> Result<Self> {
        let code: String = input
            .chars()
            .filter(|c| *c != '-' && !c.is_whitespace())
            .map(|c| c.to_ascii_uppercase())
            .collect();

        anyhow::ensure!(
            code.len() == CODE_LEN,
            "a claim code has {} characters (got {})",
            CODE_LEN,
            code.len()
        );
        anyhow::ensure!(
            code.bytes().all(|b| ALPHABET.contains(&b)),
            "a claim code uses only the characters {}",
            std::str::from_utf8(ALPHABET).unwrap_or_default()
        );
        Ok(Self(code))
    }

    /// The form shown to the operator: `XXXXX-XXXXX`.
    pub fn display(&self) -> String {
        format!("{}-{}", &self.0[..CODE_LEN / 2], &self.0[CODE_LEN / 2..])
    }

    /// The canonical form: 10 uppercase symbols, no dash.
    pub fn canonical(&self) -> &str {
        &self.0
    }

    /// `claim_hash`: lowercase hex SHA-256 of the canonical form.
    pub fn hash(&self) -> String {
        hex::encode(Sha256::digest(self.0.as_bytes()))
    }
}

/// `claim_hash` for a code as typed (with or without dash, any case).
pub fn claim_hash(code: &str) -> Result<String> {
    Ok(ClaimCode::parse(code)?.hash())
}

/// What is kept on disk.
#[derive(Clone, Serialize, Deserialize)]
struct StoredClaim {
    /// `XXXXX-XXXXX`
    claim_code: String,
    /// The node this code belongs to
    node_id: String,
    /// Unix seconds
    created_at: i64,
}

/// A stored claim code and when it was created.
#[derive(Debug, Clone)]
pub struct ClaimRecord {
    pub code: ClaimCode,
    pub created_at: i64,
}

/// Path of the claim code file (same directory as the identity).
pub fn claim_file_path() -> Result<PathBuf> {
    Ok(identity_storage::get_config_dir()?.join(CLAIM_FILE))
}

/// Load the claim code for `node_id`, if one is stored.
///
/// A code stored for a different node (the identity was replaced) is ignored.
pub fn load(node_id: &str) -> Result<Option<ClaimRecord>> {
    let path = claim_file_path()?;
    if !path.exists() {
        return Ok(None);
    }
    identity_storage::ensure_private(&path)?;

    let contents = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let stored: StoredClaim = serde_json::from_str(&contents)
        .with_context(|| format!("{} is corrupted; delete it to get a new claim code", path.display()))?;

    if stored.node_id != node_id {
        return Ok(None);
    }
    Ok(Some(ClaimRecord {
        code: ClaimCode::parse(&stored.claim_code)
            .with_context(|| format!("{} holds an invalid claim code", path.display()))?,
        created_at: stored.created_at,
    }))
}

/// Load the claim code for `node_id`, creating and saving one if needed.
///
/// Returns the record and whether it was created by this call.
pub fn load_or_create(node_id: &str) -> Result<(ClaimRecord, bool)> {
    if let Some(record) = load(node_id)? {
        return Ok((record, false));
    }

    let record = ClaimRecord {
        code: ClaimCode::generate(),
        created_at: chrono::Utc::now().timestamp(),
    };
    let stored = StoredClaim {
        claim_code: record.code.display(),
        node_id: node_id.to_string(),
        created_at: record.created_at,
    };
    let path = claim_file_path()?;
    identity_storage::write_private_file(&path, serde_json::to_string_pretty(&stored)?.as_bytes())
        .context("Failed to save the claim code")?;

    Ok((record, true))
}
