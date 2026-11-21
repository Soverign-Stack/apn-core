//! NATS Relay
//!
//! All node traffic goes through a NATS broker (`APN_RELAY_URL`). The client
//! supports credentials (user/password or a NATS creds file) and TLS
//! (`tls://` URLs), reconnects on its own with backoff, and reports every
//! connect and disconnect.

use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use async_nats::{Client, ConnectOptions};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::mesh::MeshMessage;

/// Environment variables read by [`RelayConfig::from_env`].
pub const ENV_RELAY_URL: &str = "APN_RELAY_URL";
pub const ENV_RELAY_USER: &str = "APN_RELAY_USER";
pub const ENV_RELAY_PASSWORD: &str = "APN_RELAY_PASSWORD";
pub const ENV_RELAY_CREDS: &str = "APN_RELAY_CREDS";
/// Optional PEM file with extra root certificates (private CA on the relay).
pub const ENV_RELAY_CA: &str = "APN_RELAY_CA";

/// How the node authenticates to the relay.
#[derive(Clone, Default, PartialEq, Eq)]
pub enum RelayAuth {
    /// No credentials (only works while the relay is still open).
    #[default]
    None,
    /// `APN_RELAY_USER` / `APN_RELAY_PASSWORD`
    UserPassword { user: String, password: String },
    /// `APN_RELAY_CREDS`: path to a NATS `.creds` file
    CredsFile(PathBuf),
}

// Never print the password.
impl std::fmt::Debug for RelayAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayAuth::None => write!(f, "None"),
            RelayAuth::UserPassword { user, .. } => {
                write!(
                    f,
                    "UserPassword {{ user: {:?}, password: <redacted> }}",
                    user
                )
            }
            RelayAuth::CredsFile(path) => write!(f, "CredsFile({:?})", path),
        }
    }
}

impl RelayAuth {
    /// Short description for log lines (no secrets).
    pub fn describe(&self) -> &'static str {
        match self {
            RelayAuth::None => "no credentials",
            RelayAuth::UserPassword { .. } => "user/password",
            RelayAuth::CredsFile(_) => "creds file",
        }
    }

    /// Build from optional values (as read from the environment).
    pub fn from_parts(
        user: Option<String>,
        password: Option<String>,
        creds: Option<String>,
    ) -> Result<Self> {
        let clean = |v: Option<String>| v.filter(|s| !s.trim().is_empty());
        let (user, password, creds) = (clean(user), clean(password), clean(creds));

        match (user, password, creds) {
            (None, None, None) => Ok(RelayAuth::None),
            (None, None, Some(path)) => Ok(RelayAuth::CredsFile(PathBuf::from(path))),
            (Some(user), Some(password), None) => Ok(RelayAuth::UserPassword { user, password }),
            (Some(_), None, None) | (None, Some(_), None) => anyhow::bail!(
                "{} and {} must be set together",
                ENV_RELAY_USER,
                ENV_RELAY_PASSWORD
            ),
            _ => anyhow::bail!(
                "Set either {}/{} or {}, not both",
                ENV_RELAY_USER,
                ENV_RELAY_PASSWORD,
                ENV_RELAY_CREDS
            ),
        }
    }

    pub fn from_env() -> Result<Self> {
        Self::from_parts(
            std::env::var(ENV_RELAY_USER).ok(),
            std::env::var(ENV_RELAY_PASSWORD).ok(),
            std::env::var(ENV_RELAY_CREDS).ok(),
        )
    }
}

/// NATS relay configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    /// NATS server URL (`nats://host:4222` or `tls://host:4222`)
    pub url: String,
    /// Node identifier
    pub node_id: String,
    /// Reconnect on disconnect
    pub auto_reconnect: bool,
    /// Credentials (never serialized)
    #[serde(skip)]
    pub auth: RelayAuth,
    /// Extra root certificates for TLS (PEM file)
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            url: crate::DEFAULT_NATS_RELAY.to_string(),
            node_id: String::new(),
            auto_reconnect: true,
            auth: RelayAuth::None,
            ca_file: None,
        }
    }
}

impl RelayConfig {
    /// Read `APN_RELAY_URL`, credentials and CA file from the environment.
    pub fn from_env(node_id: &str) -> Result<Self> {
        let url = std::env::var(ENV_RELAY_URL)
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| crate::DEFAULT_NATS_RELAY.to_string());
        Ok(Self {
            url,
            node_id: node_id.to_string(),
            auto_reconnect: true,
            auth: RelayAuth::from_env()?,
            ca_file: std::env::var(ENV_RELAY_CA)
                .ok()
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from),
        })
    }

    /// True when the URL asks for TLS.
    pub fn uses_tls(&self) -> bool {
        url_uses_tls(&self.url)
    }
}

/// True for `tls://` URLs.
pub fn url_uses_tls(url: &str) -> bool {
    url.trim().to_ascii_lowercase().starts_with("tls://")
}

/// The URL with any `user:password@` part removed, safe for logs and status.
pub fn redact_url(url: &str) -> String {
    match (url.find("://"), url.rfind('@')) {
        (Some(scheme_end), Some(at)) if at > scheme_end => {
            format!("{}{}", &url[..scheme_end + 3], &url[at + 1..])
        }
        (None, Some(at)) => url[at + 1..].to_string(),
        _ => url.to_string(),
    }
}

/// Split `scheme://user:password@host` into the bare URL and the credentials.
pub fn split_url_credentials(url: &str) -> (String, Option<(String, String)>) {
    let bare = redact_url(url);
    let creds = match (url.find("://"), url.rfind('@')) {
        (Some(scheme_end), Some(at)) if at > scheme_end => {
            let userinfo = &url[scheme_end + 3..at];
            userinfo
                .split_once(':')
                .map(|(u, p)| (u.to_string(), p.to_string()))
        }
        _ => None,
    };
    (bare, creds)
}

/// Delay before reconnect attempt number `attempt` (1-based).
///
/// First attempt is immediate, then 1 s, 2 s, 4 s ... capped at 60 s.
pub fn reconnect_delay(attempt: usize) -> Duration {
    if attempt <= 1 {
        return Duration::ZERO;
    }
    let exp = (attempt - 2).min(6) as u32;
    Duration::from_secs((1u64 << exp).min(60))
}

/// NATS relay client for NAT traversal
pub struct NatsRelay {
    config: RelayConfig,
    client: Option<Client>,
    message_tx: mpsc::UnboundedSender<RelayEvent>,
}

/// Events from the relay
#[derive(Debug, Clone)]
pub enum RelayEvent {
    Connected,
    Disconnected,
    MessageReceived { subject: String, payload: Vec<u8> },
    Error(String),
}

/// NATS subjects for APN
pub mod subjects {
    /// Peer registry: apn.registry.<node_id>
    pub fn registry(node_id: &str) -> String {
        format!("apn.registry.{}", node_id)
    }

    /// Peer discovery broadcast
    pub const DISCOVERY: &str = "apn.discovery";

    /// Task announcements
    pub const TASKS: &str = "apn.tasks";

    /// Heartbeat/status updates
    pub const HEARTBEAT: &str = "apn.heartbeat";

    /// Direct messages: apn.dm.<recipient_node_id>
    pub fn direct_message(recipient: &str) -> String {
        format!("apn.dm.{}", recipient)
    }

    /// Signaling for WebRTC/P2P setup: apn.signal.<node_id>
    pub fn signaling(node_id: &str) -> String {
        format!("apn.signal.{}", node_id)
    }
}

impl NatsRelay {
    /// Create a new NATS relay client
    pub fn new(config: RelayConfig, message_tx: mpsc::UnboundedSender<RelayEvent>) -> Self {
        Self {
            config,
            client: None,
            message_tx,
        }
    }

    /// Clone the relay for spawning the listener task
    /// This shares the same NATS client connection
    pub fn clone_for_listener(&self) -> Self {
        Self {
            config: self.config.clone(),
            client: self.client.clone(),
            message_tx: self.message_tx.clone(),
        }
    }

    /// Start connecting to the NATS server.
    ///
    /// Returns as soon as the client exists; it does not wait for the server.
    /// The connection is established (and re-established after any drop) in
    /// the background with backoff. Each change is logged and reported as
    /// [`RelayEvent::Connected`] / [`RelayEvent::Disconnected`].
    pub async fn connect(&mut self) -> Result<()> {
        // Credentials written into the URL are honoured, but the URL that is
        // logged, shown in status and handed to the client never has them.
        let (shown_url, url_credentials) = split_url_credentials(&self.config.url);
        let auth = match (&self.config.auth, url_credentials) {
            (RelayAuth::None, Some((user, password))) => RelayAuth::UserPassword { user, password },
            (configured, _) => configured.clone(),
        };
        let tls = self.config.uses_tls();

        let mut options = ConnectOptions::new()
            .name(&self.config.node_id)
            .retry_on_initial_connect()
            .connection_timeout(Duration::from_secs(10))
            .ping_interval(Duration::from_secs(20))
            .max_reconnects(None);

        options = options.reconnect_delay_callback({
            let shown_url = shown_url.clone();
            move |attempt| {
                let base = reconnect_delay(attempt);
                if base.is_zero() {
                    return base;
                }
                // Up to 20% jitter so a fleet does not reconnect in step.
                let jitter = base.mul_f64(rand::random::<f64>() * 0.2);
                let delay = base + jitter;
                tracing::info!(
                    "Relay {}: retrying in {:.1}s (attempt {})",
                    shown_url,
                    delay.as_secs_f64(),
                    attempt
                );
                delay
            }
        });

        options = options.event_callback({
            let tx = self.message_tx.clone();
            let shown_url = shown_url.clone();
            move |event| {
                let tx = tx.clone();
                let shown_url = shown_url.clone();
                async move {
                    match event {
                        async_nats::Event::Connected => {
                            tracing::info!("Relay CONNECTED: {}", shown_url);
                            let _ = tx.send(RelayEvent::Connected);
                        }
                        async_nats::Event::Disconnected => {
                            tracing::warn!(
                                "Relay DISCONNECTED: {} (will reconnect automatically)",
                                shown_url
                            );
                            let _ = tx.send(RelayEvent::Disconnected);
                        }
                        async_nats::Event::ClientError(err) => {
                            tracing::warn!("Relay {}: connection attempt failed: {} (check the address, TLS setting and credentials)", shown_url, err);
                            let _ = tx.send(RelayEvent::Error(err.to_string()));
                        }
                        async_nats::Event::ServerError(err) => {
                            tracing::warn!("Relay {}: server error: {}", shown_url, err);
                            let _ = tx.send(RelayEvent::Error(err.to_string()));
                        }
                        other => tracing::debug!("Relay {}: {}", shown_url, other),
                    }
                }
            }
        });

        match &auth {
            RelayAuth::None => {}
            RelayAuth::UserPassword { user, password } => {
                options = options.user_and_password(user.clone(), password.clone());
            }
            RelayAuth::CredsFile(path) => {
                options = options
                    .credentials_file(path)
                    .await
                    .with_context(|| format!("Cannot read relay creds file {}", path.display()))?;
            }
        }

        if tls {
            options = options.require_tls(true);
        }
        if let Some(ca) = &self.config.ca_file {
            if !ca.is_file() {
                anyhow::bail!("Relay CA file {} not found", ca.display());
            }
            options = options.add_root_certificates(ca.clone());
        }

        tracing::info!(
            "Connecting to relay {} ({}, {})",
            shown_url,
            if tls {
                "TLS required"
            } else {
                "TLS only if the relay asks for it"
            },
            auth.describe()
        );

        let client = async_nats::connect_with_options(shown_url.as_str(), options)
            .await
            .with_context(|| format!("Invalid relay configuration for {}", shown_url))?;

        self.client = Some(client);
        Ok(())
    }

    /// Disconnect from the NATS server
    pub async fn disconnect(&mut self) -> Result<()> {
        if let Some(client) = self.client.take() {
            // Flush only when there is a live connection, and never wait
            // long: a flush against a dead relay would block shutdown.
            if client.connection_state() == async_nats::connection::State::Connected {
                let _ = tokio::time::timeout(Duration::from_secs(3), client.flush()).await;
            }
            // Client will close when dropped
        }

        let _ = self.message_tx.send(RelayEvent::Disconnected);
        Ok(())
    }

    /// Publish a message to a subject
    pub async fn publish(&self, subject: &str, payload: &[u8]) -> Result<()> {
        let client = self.client.as_ref().context("Not connected to NATS")?;

        client
            .publish(subject.to_string(), payload.to_vec().into())
            .await
            .context("Failed to publish message")?;

        tracing::debug!("Published {} bytes to {}", payload.len(), subject);
        Ok(())
    }

    /// Publish a mesh message
    pub async fn publish_message(&self, subject: &str, message: &MeshMessage) -> Result<()> {
        let payload = serde_json::to_vec(message)?;
        self.publish(subject, &payload).await
    }

    /// Subscribe to a subject
    pub async fn subscribe(&self, subject: &str) -> Result<async_nats::Subscriber> {
        let client = self.client.as_ref().context("Not connected to NATS")?;

        let subscriber = client
            .subscribe(subject.to_string())
            .await
            .context("Failed to subscribe")?;

        tracing::debug!("Subscribed to {}", subject);
        Ok(subscriber)
    }

    /// Announce this node to the network
    pub async fn announce(
        &self,
        wallet_address: &str,
        capabilities: &[String],
        resources: Option<&crate::wire::NodeResources>,
        device_name: Option<&str>,
    ) -> Result<()> {
        let announcement = PeerAnnouncement {
            node_id: self.config.node_id.clone(),
            wallet_address: wallet_address.to_string(),
            capabilities: capabilities.to_vec(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            resources: resources.cloned(),
            hostname: crate::resources::get_hostname(),
            device_name: device_name.map(String::from),
        };

        let payload = serde_json::to_vec(&announcement)?;

        // Publish to registry
        self.publish(&subjects::registry(&self.config.node_id), &payload)
            .await?;

        // Broadcast to discovery
        self.publish(subjects::DISCOVERY, &payload).await?;

        Ok(())
    }

    /// Send heartbeat with resource status
    pub async fn send_heartbeat(
        &self,
        resources: Option<&crate::wire::NodeResources>,
    ) -> Result<()> {
        let heartbeat = serde_json::json!({
            "node_id": self.config.node_id,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "resources": resources,
        });

        let payload = serde_json::to_vec(&heartbeat)?;
        self.publish(subjects::HEARTBEAT, &payload).await?;

        tracing::debug!("Heartbeat sent with resources");
        Ok(())
    }

    /// Send a direct message to another node
    pub async fn send_direct(&self, recipient: &str, message: &MeshMessage) -> Result<()> {
        let subject = subjects::direct_message(recipient);
        self.publish_message(&subject, message).await
    }

    /// Request-reply pattern for signaling
    pub async fn request(&self, subject: &str, payload: &[u8]) -> Result<Vec<u8>> {
        let client = self.client.as_ref().context("Not connected to NATS")?;

        let response = client
            .request(subject.to_string(), payload.to_vec().into())
            .await
            .context("Request failed")?;

        Ok(response.payload.to_vec())
    }

    /// Run the relay event loop (processes incoming messages)
    pub async fn run(&self) -> Result<()> {
        let client = self.client.as_ref().context("Not connected to NATS")?;

        // Subscribe to our direct message subject
        let dm_subject = subjects::direct_message(&self.config.node_id);
        let mut dm_subscriber = client.subscribe(dm_subject.clone()).await?;

        // Subscribe to signaling
        let signal_subject = subjects::signaling(&self.config.node_id);
        let mut signal_subscriber = client.subscribe(signal_subject.clone()).await?;

        // Subscribe to discovery
        let mut discovery_subscriber = client.subscribe(subjects::DISCOVERY.to_string()).await?;

        // Subscribe to heartbeat
        let mut heartbeat_subscriber = client.subscribe(subjects::HEARTBEAT.to_string()).await?;

        tracing::info!(
            "Relay listening on: {}, {}, {}, {}",
            dm_subject,
            signal_subject,
            subjects::DISCOVERY,
            subjects::HEARTBEAT
        );

        loop {
            tokio::select! {
                Some(msg) = dm_subscriber.next() => {
                    let _ = self.message_tx.send(RelayEvent::MessageReceived {
                        subject: msg.subject.to_string(),
                        payload: msg.payload.to_vec(),
                    });
                }

                Some(msg) = signal_subscriber.next() => {
                    let _ = self.message_tx.send(RelayEvent::MessageReceived {
                        subject: msg.subject.to_string(),
                        payload: msg.payload.to_vec(),
                    });
                }

                Some(msg) = discovery_subscriber.next() => {
                    let _ = self.message_tx.send(RelayEvent::MessageReceived {
                        subject: msg.subject.to_string(),
                        payload: msg.payload.to_vec(),
                    });
                }

                Some(msg) = heartbeat_subscriber.next() => {
                    let _ = self.message_tx.send(RelayEvent::MessageReceived {
                        subject: msg.subject.to_string(),
                        payload: msg.payload.to_vec(),
                    });
                }
            }
        }
    }

    /// True only while the connection to the server is up.
    pub fn is_connected(&self) -> bool {
        self.client
            .as_ref()
            .map(|c| c.connection_state() == async_nats::connection::State::Connected)
            .unwrap_or(false)
    }

    /// Push buffered messages to the server (bounded wait).
    pub async fn flush(&self) -> Result<()> {
        let client = self.client.as_ref().context("Not connected to NATS")?;
        tokio::time::timeout(Duration::from_secs(5), client.flush())
            .await
            .context("Relay flush timed out")?
            .context("Relay flush failed")?;
        Ok(())
    }

    /// The relay URL without credentials.
    pub fn display_url(&self) -> String {
        redact_url(&self.config.url)
    }
}

/// Peer announcement message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAnnouncement {
    pub node_id: String,
    pub wallet_address: String,
    pub capabilities: Vec<String>,
    pub timestamp: String,
    pub resources: Option<crate::wire::NodeResources>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_config_default() {
        let config = RelayConfig::default();
        assert_eq!(config.url, crate::DEFAULT_NATS_RELAY);
    }

    #[test]
    fn test_auth_from_parts() {
        assert_eq!(
            RelayAuth::from_parts(None, None, None).unwrap(),
            RelayAuth::None
        );
        assert_eq!(
            RelayAuth::from_parts(Some("u".into()), Some("p".into()), None).unwrap(),
            RelayAuth::UserPassword {
                user: "u".into(),
                password: "p".into()
            }
        );
        assert_eq!(
            RelayAuth::from_parts(None, Some("".into()), Some("/etc/apn/node.creds".into()))
                .unwrap(),
            RelayAuth::CredsFile(PathBuf::from("/etc/apn/node.creds"))
        );
        // user without password, and both methods at once, are refused
        assert!(RelayAuth::from_parts(Some("u".into()), None, None).is_err());
        assert!(
            RelayAuth::from_parts(Some("u".into()), Some("p".into()), Some("f".into())).is_err()
        );
    }

    #[test]
    fn test_auth_debug_hides_password() {
        let auth = RelayAuth::UserPassword {
            user: "node1".into(),
            password: "hunter2-secret".into(),
        };
        assert!(!format!("{:?}", auth).contains("hunter2-secret"));
    }

    #[test]
    fn test_redact_url_and_tls() {
        assert_eq!(
            redact_url("nats://u:p@relay.example:4222"),
            "nats://relay.example:4222"
        );
        assert_eq!(
            redact_url("tls://relay.example:4222"),
            "tls://relay.example:4222"
        );
        assert_eq!(
            split_url_credentials("tls://u:p@relay.example:4222"),
            (
                "tls://relay.example:4222".to_string(),
                Some(("u".to_string(), "p".to_string()))
            )
        );
        assert_eq!(split_url_credentials("nats://relay.example:4222").1, None);
        assert!(url_uses_tls("tls://relay.example:4222"));
        assert!(!url_uses_tls("nats://relay.example:4222"));
    }

    #[test]
    fn test_reconnect_backoff() {
        assert_eq!(reconnect_delay(1), Duration::ZERO);
        assert_eq!(reconnect_delay(2), Duration::from_secs(1));
        assert_eq!(reconnect_delay(3), Duration::from_secs(2));
        assert_eq!(reconnect_delay(5), Duration::from_secs(8));
        assert_eq!(reconnect_delay(8), Duration::from_secs(60));
        assert_eq!(reconnect_delay(500), Duration::from_secs(60));
    }

    #[test]
    fn test_subjects() {
        assert_eq!(subjects::registry("node123"), "apn.registry.node123");
        assert_eq!(subjects::direct_message("peer456"), "apn.dm.peer456");
        assert_eq!(subjects::signaling("node789"), "apn.signal.node789");
    }
}
