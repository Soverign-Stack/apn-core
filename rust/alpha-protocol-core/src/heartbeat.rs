//! Signed heartbeat (wire contract v1)
//!
//! The node publishes the same JSON payload to `apn.discovery` once at start
//! and to `apn.heartbeat` every 30 seconds. The payload is signed with the
//! node's Ed25519 key over the UTF-8 bytes of
//!
//! ```text
//! apn-hb-v1|{node_id}|{ts}|{claim_hash}
//! ```
//!
//! By default the payload carries no hostname, no hardware description and no
//! IP address. Hostname and hardware are sent only when the operator opts in
//! (`--share-hardware`), inside a separate optional `hardware` object.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{identity::NodeIdentity, wire::NodeResources};

/// Domain prefix of the signed string.
pub const SIGNATURE_PREFIX: &str = "apn-hb-v1";

/// A receiver rejects heartbeats whose `ts` is further than this from its clock.
pub const MAX_CLOCK_SKEW_SECS: i64 = 120;

/// Seconds between heartbeats.
pub const HEARTBEAT_INTERVAL_SECS: u64 = 30;

/// Coarse capabilities. Nothing finer than three booleans leaves the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub relay: bool,
    pub compute: bool,
    pub storage: bool,
}

impl Capabilities {
    pub const ALL: Capabilities = Capabilities {
        relay: true,
        compute: true,
        storage: true,
    };

    pub const NONE: Capabilities = Capabilities {
        relay: false,
        compute: false,
        storage: false,
    };

    /// Parse a comma-separated list such as `relay,compute`. `none` or an
    /// empty string means no capability.
    pub fn parse_list(list: &str) -> Result<Self, String> {
        let mut caps = Capabilities::NONE;
        for item in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            match item.to_ascii_lowercase().as_str() {
                "relay" => caps.relay = true,
                "compute" => caps.compute = true,
                "storage" => caps.storage = true,
                "none" => {}
                other => {
                    return Err(format!(
                        "unknown capability '{}' (use relay, compute, storage)",
                        other
                    ))
                }
            }
        }
        Ok(caps)
    }
}

/// Optional machine details, sent only with `--share-hardware`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hardware {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<NodeResources>,
}

/// The heartbeat payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    /// `apn_` + first 8 hex chars of SHA-256(public key)
    pub node_id: String,
    /// Ed25519 public key, hex
    pub public_key: String,
    /// Unix seconds, node clock
    pub ts: i64,
    /// Node software version
    pub version: String,
    /// Hex SHA-256 of the claim code
    pub claim_hash: String,
    /// Coarse capabilities
    pub capabilities: Capabilities,
    /// Hex Ed25519 signature over [`signing_string`]
    pub sig: String,

    // Fields the node sent before the contract and still sends unchanged.
    /// "0x" + hex SHA-256(public key). Derivable from `public_key`; not used
    /// for payments.
    #[serde(default)]
    pub wallet_address: String,
    /// Same instant as `ts`, RFC 3339
    #[serde(default)]
    pub timestamp: String,
    /// Label chosen by the operator with `--name`; absent otherwise
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,

    /// Only with `--share-hardware`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardware: Option<Hardware>,
}

/// Why a heartbeat was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("public_key is not a valid Ed25519 key")]
    BadPublicKey,
    #[error("node_id does not match public_key")]
    NodeIdMismatch,
    #[error("sig is not a valid signature encoding")]
    BadSignatureEncoding,
    #[error("signature does not verify")]
    BadSignature,
    #[error("timestamp is {0} s away from the local clock (limit {MAX_CLOCK_SKEW_SECS} s)")]
    StaleTimestamp(i64),
}

/// The exact string that is signed: `apn-hb-v1|{node_id}|{ts}|{claim_hash}`.
pub fn signing_string(node_id: &str, ts: i64, claim_hash: &str) -> String {
    format!("{}|{}|{}|{}", SIGNATURE_PREFIX, node_id, ts, claim_hash)
}

/// Node id for a public key: `apn_` + first 8 hex chars of SHA-256(key).
///
/// This is the derivation the node has always used (via the "wallet
/// address", which is "0x" + hex SHA-256 of the public key).
pub fn node_id_from_public_key(public_key: &[u8; 32]) -> String {
    let hash = Sha256::digest(public_key);
    format!("apn_{}", &hex::encode(hash)[..8])
}

impl Heartbeat {
    /// Build and sign a heartbeat for `ts` (Unix seconds).
    pub fn new_signed(
        identity: &NodeIdentity,
        ts: i64,
        claim_hash: &str,
        capabilities: Capabilities,
        device_name: Option<String>,
        hardware: Option<Hardware>,
    ) -> Self {
        let node_id = identity.short_id();
        let sig = identity.sign(signing_string(&node_id, ts, claim_hash).as_bytes());
        let timestamp = chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)
            .map(|t| t.to_rfc3339())
            .unwrap_or_default();

        Self {
            node_id,
            public_key: identity.public_key_hex(),
            ts,
            version: env!("CARGO_PKG_VERSION").to_string(),
            claim_hash: claim_hash.to_string(),
            capabilities,
            sig: hex::encode(sig.to_bytes()),
            wallet_address: identity.address().to_string(),
            timestamp,
            device_name,
            hardware,
        }
    }

    /// Check the signature and the binding between key and node id.
    /// Does not look at the clock.
    pub fn verify_signature(&self) -> Result<(), VerifyError> {
        let key_bytes: [u8; 32] = hex::decode(&self.public_key)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(VerifyError::BadPublicKey)?;
        let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| VerifyError::BadPublicKey)?;

        if node_id_from_public_key(&key_bytes) != self.node_id {
            return Err(VerifyError::NodeIdMismatch);
        }

        let sig_bytes: [u8; 64] = hex::decode(&self.sig)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(VerifyError::BadSignatureEncoding)?;
        let signature = Signature::from_bytes(&sig_bytes);

        let message = signing_string(&self.node_id, self.ts, &self.claim_hash);
        key.verify_strict(message.as_bytes(), &signature)
            .map_err(|_| VerifyError::BadSignature)
    }

    /// The full receiver-side check from the contract: signature, node id
    /// binding, and `|now - ts| <= 120 s`.
    pub fn verify(&self, now_unix: i64) -> Result<(), VerifyError> {
        self.verify_signature()?;
        let skew = (now_unix - self.ts).abs();
        if skew > MAX_CLOCK_SKEW_SECS {
            return Err(VerifyError::StaleTimestamp(skew));
        }
        Ok(())
    }
}
