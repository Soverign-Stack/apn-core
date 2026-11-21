//! Integration test: a real `apn_node` process, a real NATS server.
//!
//! Needs a local NATS server and its URL in `APN_TEST_NATS_URL`, e.g.
//!
//! ```text
//! docker run --rm -d --name apn-test-nats -p 127.0.0.1:14222:4222 nats:2.10
//! APN_TEST_NATS_URL=nats://127.0.0.1:14222 cargo test --test heartbeat_nats -- --nocapture
//! ```
//!
//! Without the variable the test reports that it was skipped. It refuses to
//! run against anything that is not a loopback address, so it can never touch
//! the production relay.

use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

use alpha_protocol_core::heartbeat::Heartbeat;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use futures::StreamExt;
use sha2::{Digest, Sha256};

struct NodeProcess {
    child: Child,
    data_dir: PathBuf,
}

impl Drop for NodeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

async fn wait_for_file(path: &Path) {
    for _ in 0..100 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{} was not created", path.display());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_publishes_signed_heartbeats_to_nats() {
    let Ok(url) = std::env::var("APN_TEST_NATS_URL") else {
        eprintln!("SKIPPED: set APN_TEST_NATS_URL to a local NATS server to run this test");
        return;
    };
    assert!(
        url.contains("127.0.0.1") || url.contains("localhost"),
        "APN_TEST_NATS_URL must be a loopback address, got {}",
        url
    );

    // Listen first, so nothing the node sends can be missed.
    let client = async_nats::connect(&url)
        .await
        .expect("local NATS server not reachable");
    let mut discovery = client.subscribe("apn.discovery").await.unwrap();
    let mut heartbeats = client.subscribe("apn.heartbeat").await.unwrap();
    client.flush().await.unwrap();

    // Start the real binary with a fresh identity.
    let data_dir = std::env::temp_dir().join(format!("apn-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data_dir);
    std::fs::create_dir_all(&data_dir).unwrap();
    let log_path = data_dir.join("node.log");
    let log = std::fs::File::create(&log_path).unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_apn_node"))
        .args(["run", "--heartbeat-interval", "1"])
        .env("APN_DATA_DIR", &data_dir)
        .env("APN_RELAY_URL", &url)
        .env_remove("APN_RELAY_USER")
        .env_remove("APN_RELAY_PASSWORD")
        .env_remove("APN_RELAY_CREDS")
        .env_remove("APN_RELAY_CA")
        .env_remove("APN_SHARE_HARDWARE")
        .env_remove("APN_NODE_NAME")
        .stdin(Stdio::null())
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .expect("failed to start apn_node");
    let node = NodeProcess {
        child,
        data_dir: data_dir.clone(),
    };

    // What the node stored locally (never printed by this test).
    let claim_path = data_dir.join("claim_code.json");
    wait_for_file(&claim_path).await;
    let claim = read_json(&claim_path);
    let node_id = claim["node_id"].as_str().unwrap().to_string();
    let claim_code = claim["claim_code"].as_str().unwrap().to_string();
    let expected_claim_hash = hex::encode(Sha256::digest(
        claim_code.replace('-', "").to_uppercase().as_bytes(),
    ));
    let phrase = read_json(&data_dir.join("node_identity.json"))["mnemonic"]
        .as_str()
        .unwrap()
        .to_string();

    // Collect one discovery message and three heartbeats from OUR node.
    // (Other nodes may be using the same test server.)
    let mut got_discovery: Vec<Vec<u8>> = Vec::new();
    let mut got_heartbeats: Vec<Vec<u8>> = Vec::new();
    let is_ours = |payload: &[u8]| {
        serde_json::from_slice::<serde_json::Value>(payload)
            .ok()
            .and_then(|v| v["node_id"].as_str().map(|id| id == node_id))
            .unwrap_or(false)
    };

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while got_discovery.is_empty() || got_heartbeats.len() < 3 {
        tokio::select! {
            Some(msg) = discovery.next() => {
                if is_ours(&msg.payload) { got_discovery.push(msg.payload.to_vec()); }
            }
            Some(msg) = heartbeats.next() => {
                if is_ours(&msg.payload) { got_heartbeats.push(msg.payload.to_vec()); }
            }
            _ = tokio::time::sleep_until(deadline) => {
                panic!(
                    "timed out: {} discovery, {} heartbeat messages (node log: {})",
                    got_discovery.len(),
                    got_heartbeats.len(),
                    std::fs::read_to_string(&log_path).unwrap_or_default()
                );
            }
        }
    }

    assert_eq!(
        got_discovery.len(),
        1,
        "apn.discovery is sent once at start"
    );

    let now = chrono::Utc::now().timestamp();
    let mut last_ts = 0;
    for raw in got_discovery.iter().chain(got_heartbeats.iter()) {
        let text = std::str::from_utf8(raw).unwrap();
        let hb: Heartbeat = serde_json::from_slice(raw).expect("payload must parse");

        // 1. The crate's receiver-side check: signature, id binding, clock window.
        hb.verify(now).expect("heartbeat must verify");

        // 2. The same check done by hand from the raw JSON, no crate helpers.
        let json: serde_json::Value = serde_json::from_slice(raw).unwrap();
        let key_bytes: [u8; 32] = hex::decode(json["public_key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let sig_bytes: [u8; 64] = hex::decode(json["sig"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let message = format!(
            "apn-hb-v1|{}|{}|{}",
            json["node_id"].as_str().unwrap(),
            json["ts"].as_i64().unwrap(),
            json["claim_hash"].as_str().unwrap()
        );
        VerifyingKey::from_bytes(&key_bytes)
            .unwrap()
            .verify(message.as_bytes(), &Signature::from_bytes(&sig_bytes))
            .expect("raw signature check failed");
        assert_eq!(
            json["node_id"].as_str().unwrap(),
            format!("apn_{}", &hex::encode(Sha256::digest(key_bytes))[..8])
        );

        // 3. Enrolment: only the hash of the claim code travels.
        assert_eq!(hb.claim_hash, expected_claim_hash);
        assert!(!text.contains(&claim_code));
        assert!(!text.contains(&claim_code.replace('-', "")));

        // 4. Privacy defaults.
        for removed in [
            "hostname",
            "hardware",
            "resources",
            "gpu_model",
            "device_name",
        ] {
            assert!(
                json.get(removed).is_none(),
                "{} must be absent by default",
                removed
            );
        }
        assert!(json["capabilities"]["relay"].is_boolean());
        assert_eq!(hb.version, env!("CARGO_PKG_VERSION"));

        assert!(hb.ts >= last_ts, "timestamps must not go backwards");
        last_ts = hb.ts;
    }

    // `apn_node status` sees the running node as connected (exit code 0).
    let status = Command::new(env!("CARGO_BIN_EXE_apn_node"))
        .arg("status")
        .env("APN_DATA_DIR", &data_dir)
        .output()
        .unwrap();
    let status_text = String::from_utf8_lossy(&status.stdout).to_string();
    assert!(status.status.success(), "status failed:\n{}", status_text);
    assert!(status_text.contains(&node_id));
    assert!(status_text.contains("CONNECTED"));
    assert!(!status_text.contains(&claim_code));

    // `apn_node claim-code` prints the stored code.
    let shown = Command::new(env!("CARGO_BIN_EXE_apn_node"))
        .arg("claim-code")
        .env("APN_DATA_DIR", &data_dir)
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&shown.stdout).trim(), claim_code);

    // Neither secret reached the node's log (this is what a service journal sees).
    let node_log = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        node_log.contains("Relay CONNECTED"),
        "connect line missing from the log"
    );
    assert!(
        !node_log.contains(&phrase),
        "recovery phrase leaked into the log"
    );
    assert!(
        !node_log.contains(&claim_code),
        "claim code leaked into the log"
    );

    eprintln!(
        "EXECUTED against {}: verified 1 discovery + {} heartbeat messages from {}",
        url,
        got_heartbeats.len(),
        node_id
    );
    drop(node);
}
