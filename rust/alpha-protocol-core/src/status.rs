//! Node status file
//!
//! The running node writes a small `status.json` into its data directory on
//! every state change and every heartbeat. `apn_node status` reads it, so the
//! status command needs no network access and no connection to the running
//! process. The file holds no secrets.

use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::identity_storage;

const STATUS_FILE: &str = "status.json";

/// State of the connection to the relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RelayState {
    /// Started, no connection yet
    Connecting,
    Connected,
    /// Was connected, lost the connection, retrying
    Disconnected,
    /// The node was stopped cleanly
    Stopped,
}

impl RelayState {
    pub fn label(&self) -> &'static str {
        match self {
            RelayState::Connecting => "CONNECTING (not connected yet)",
            RelayState::Connected => "CONNECTED",
            RelayState::Disconnected => "DISCONNECTED (retrying)",
            RelayState::Stopped => "STOPPED",
        }
    }
}

/// Snapshot written by the running node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    pub node_id: String,
    pub version: String,
    pub pid: u32,
    /// Unix seconds
    pub started_at: i64,
    /// Unix seconds; refreshed at least once per heartbeat interval
    pub updated_at: i64,
    /// Relay URL without credentials
    pub relay_url: String,
    pub relay_state: RelayState,
    /// Unix seconds of the last change of `relay_state`
    pub relay_state_since: i64,
    /// Last connection error reported by the relay client, if any
    #[serde(default)]
    pub last_relay_error: Option<String>,
    /// Unix seconds of the last heartbeat handed to the relay
    #[serde(default)]
    pub last_heartbeat_at: Option<i64>,
    /// Subject of the last heartbeat (`apn.discovery` or `apn.heartbeat`)
    #[serde(default)]
    pub last_heartbeat_subject: Option<String>,
    /// Heartbeats sent since the process started
    #[serde(default)]
    pub heartbeats_sent: u64,
    pub heartbeat_interval_secs: u64,
}

impl NodeStatus {
    pub fn new(node_id: &str, relay_url: &str, heartbeat_interval_secs: u64, now: i64) -> Self {
        Self {
            node_id: node_id.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            pid: std::process::id(),
            started_at: now,
            updated_at: now,
            relay_url: relay_url.to_string(),
            relay_state: RelayState::Connecting,
            relay_state_since: now,
            last_relay_error: None,
            last_heartbeat_at: None,
            last_heartbeat_subject: None,
            heartbeats_sent: 0,
            heartbeat_interval_secs,
        }
    }

    pub fn set_relay_state(&mut self, state: RelayState, now: i64) {
        if self.relay_state != state {
            self.relay_state = state;
            self.relay_state_since = now;
        }
        if state == RelayState::Connected {
            self.last_relay_error = None;
        }
        self.updated_at = now;
    }

    pub fn record_heartbeat(&mut self, subject: &str, now: i64) {
        self.last_heartbeat_at = Some(now);
        self.last_heartbeat_subject = Some(subject.to_string());
        self.heartbeats_sent += 1;
        self.updated_at = now;
    }

    /// A status file is stale when the process that wrote it has stopped
    /// refreshing it: nothing for three intervals (at least 90 s).
    pub fn is_stale(&self, now: i64) -> bool {
        let limit = (self.heartbeat_interval_secs as i64 * 3).max(90);
        now - self.updated_at > limit
    }

    /// Is the node process that wrote this file still alive?
    pub fn process_alive(&self, now: i64) -> bool {
        if self.relay_state == RelayState::Stopped || self.is_stale(now) {
            return false;
        }
        #[cfg(target_os = "linux")]
        {
            std::path::Path::new(&format!("/proc/{}", self.pid)).exists()
        }
        #[cfg(not(target_os = "linux"))]
        {
            true
        }
    }

    /// Save to the data directory (atomic replace).
    pub fn save(&self) -> Result<()> {
        let path = status_file_path()?;
        identity_storage::write_private_file(&path, serde_json::to_string_pretty(self)?.as_bytes())
            .with_context(|| format!("Failed to write {}", path.display()))
    }
}

/// Path of the status file.
pub fn status_file_path() -> Result<PathBuf> {
    Ok(identity_storage::get_config_dir()?.join(STATUS_FILE))
}

/// Read the status file, if the node has ever written one.
pub fn load() -> Result<Option<NodeStatus>> {
    let path = status_file_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    Ok(serde_json::from_str(&contents).ok())
}

/// "42s", "5m 3s", "2h 10m", "3d 4h"
pub fn format_duration(secs: i64) -> String {
    let secs = secs.max(0);
    match secs {
        0..=59 => format!("{}s", secs),
        60..=3599 => format!("{}m {}s", secs / 60, secs % 60),
        3600..=86_399 => format!("{}h {}m", secs / 3600, (secs % 3600) / 60),
        _ => format!("{}d {}h", secs / 86_400, (secs % 86_400) / 3600),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_transitions() {
        let mut status = NodeStatus::new("apn_00000000", "nats://127.0.0.1:4222", 30, 1000);
        assert_eq!(status.relay_state, RelayState::Connecting);

        status.last_relay_error = Some("IO error".into());
        status.set_relay_state(RelayState::Connected, 1010);
        assert_eq!(status.relay_state_since, 1010);
        assert!(status.last_relay_error.is_none());

        // Same state again does not move the "since" time.
        status.set_relay_state(RelayState::Connected, 1020);
        assert_eq!(status.relay_state_since, 1010);

        status.record_heartbeat("apn.heartbeat", 1040);
        assert_eq!(status.last_heartbeat_at, Some(1040));
        assert_eq!(status.heartbeats_sent, 1);
    }

    #[test]
    fn test_staleness() {
        let status = NodeStatus::new("apn_00000000", "nats://127.0.0.1:4222", 30, 1000);
        assert!(!status.is_stale(1000 + 90));
        assert!(status.is_stale(1000 + 91));
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(42), "42s");
        assert_eq!(format_duration(303), "5m 3s");
        assert_eq!(format_duration(7800), "2h 10m");
        assert_eq!(format_duration(273_600), "3d 4h");
    }
}
