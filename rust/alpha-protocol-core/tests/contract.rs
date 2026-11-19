//! Wire-contract tests (sprint 1): signature string and verification, claim
//! code generation and hashing, and the shape of the heartbeat payload.
//!
//! These use only the crate's public API plus independent re-computation
//! with the underlying crypto crates, so they also serve as a reference for
//! the Dashboard side.

use alpha_protocol_core::{
    claim::{self, ClaimCode, ALPHABET, CODE_LEN},
    heartbeat::{
        node_id_from_public_key, signing_string, Capabilities, Hardware, Heartbeat, VerifyError,
        MAX_CLOCK_SKEW_SECS,
    },
    identity::NodeIdentity,
    wire::NodeResources,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

const TS: i64 = 1_795_000_000;

fn sample(identity: &NodeIdentity, claim_hash: &str) -> Heartbeat {
    Heartbeat::new_signed(identity, TS, claim_hash, Capabilities::ALL, None, None)
}

fn some_claim_hash() -> String {
    ClaimCode::generate().hash()
}

// ---------------------------------------------------------------- signature

#[test]
fn signing_string_is_exactly_the_contract_format() {
    assert_eq!(
        signing_string("apn_1a2b3c4d", 1_795_000_000, "abc123"),
        "apn-hb-v1|apn_1a2b3c4d|1795000000|abc123"
    );
    // empty claim hash keeps the trailing separator
    assert_eq!(
        signing_string("apn_1a2b3c4d", 0, ""),
        "apn-hb-v1|apn_1a2b3c4d|0|"
    );
}

#[test]
fn signature_verifies_with_an_independent_ed25519_check() {
    let identity = NodeIdentity::generate().unwrap();
    let claim_hash = some_claim_hash();
    let hb = sample(&identity, &claim_hash);

    // Rebuild everything from the JSON fields only, as a receiver would.
    let key_bytes: [u8; 32] = hex::decode(&hb.public_key).unwrap().try_into().unwrap();
    let key = VerifyingKey::from_bytes(&key_bytes).unwrap();
    let sig_bytes: [u8; 64] = hex::decode(&hb.sig).unwrap().try_into().unwrap();
    let message = format!("apn-hb-v1|{}|{}|{}", hb.node_id, hb.ts, hb.claim_hash);

    key.verify(message.as_bytes(), &Signature::from_bytes(&sig_bytes))
        .expect("signature must verify over the contract string");

    assert_eq!(hb.sig.len(), 128, "sig is 64 bytes, hex");
    assert_eq!(hb.public_key.len(), 64, "public_key is 32 bytes, hex");
    assert!(hb.verify(TS).is_ok());
}

#[test]
fn node_id_is_bound_to_the_public_key() {
    let identity = NodeIdentity::generate().unwrap();
    let hb = sample(&identity, &some_claim_hash());

    // apn_ + first 8 hex chars of SHA-256(public key): the existing derivation.
    let expected = format!(
        "apn_{}",
        &hex::encode(Sha256::digest(identity.public_key_bytes()))[..8]
    );
    assert_eq!(hb.node_id, expected);
    assert_eq!(hb.node_id, identity.short_id());
    assert_eq!(
        node_id_from_public_key(identity.public_key_bytes()),
        expected
    );
}

#[test]
fn tampering_with_any_signed_field_is_rejected() {
    let identity = NodeIdentity::generate().unwrap();
    let other = NodeIdentity::generate().unwrap();
    let hb = sample(&identity, &some_claim_hash());
    assert_eq!(hb.verify(TS), Ok(()));

    let mut t = hb.clone();
    t.ts += 1;
    assert_eq!(t.verify(TS), Err(VerifyError::BadSignature));

    let mut t = hb.clone();
    t.claim_hash = some_claim_hash();
    assert_eq!(t.verify(TS), Err(VerifyError::BadSignature));

    // Someone else's node id with our key.
    let mut t = hb.clone();
    t.node_id = other.short_id();
    assert_eq!(t.verify(TS), Err(VerifyError::NodeIdMismatch));

    // Our node id with someone else's key.
    let mut t = hb.clone();
    t.public_key = other.public_key_hex();
    assert_eq!(t.verify(TS), Err(VerifyError::NodeIdMismatch));

    // A valid signature by another key over our fields.
    let mut t = hb.clone();
    t.sig = hex::encode(
        other
            .sign(signing_string(&hb.node_id, hb.ts, &hb.claim_hash).as_bytes())
            .to_bytes(),
    );
    assert_eq!(t.verify(TS), Err(VerifyError::BadSignature));

    let mut t = hb.clone();
    t.sig = "zz".into();
    assert_eq!(t.verify(TS), Err(VerifyError::BadSignatureEncoding));

    let mut t = hb.clone();
    t.public_key = "1234".into();
    assert_eq!(t.verify(TS), Err(VerifyError::BadPublicKey));
}

#[test]
fn unsigned_fields_do_not_affect_verification() {
    // version, capabilities and hardware are outside the signed string
    // (contract v1). This test documents that limit.
    let identity = NodeIdentity::generate().unwrap();
    let mut hb = sample(&identity, &some_claim_hash());
    hb.version = "9.9.9".into();
    hb.capabilities = Capabilities::NONE;
    assert_eq!(hb.verify(TS), Ok(()));
}

#[test]
fn clock_window_is_120_seconds_either_way() {
    let identity = NodeIdentity::generate().unwrap();
    let hb = sample(&identity, &some_claim_hash());

    assert_eq!(MAX_CLOCK_SKEW_SECS, 120);
    assert_eq!(hb.verify(TS + 120), Ok(()));
    assert_eq!(hb.verify(TS - 120), Ok(()));
    assert_eq!(hb.verify(TS + 121), Err(VerifyError::StaleTimestamp(121)));
    assert_eq!(hb.verify(TS - 121), Err(VerifyError::StaleTimestamp(121)));
}

#[test]
fn heartbeat_survives_a_json_round_trip() {
    let identity = NodeIdentity::generate().unwrap();
    let hb = sample(&identity, &some_claim_hash());
    let parsed: Heartbeat = serde_json::from_slice(&serde_json::to_vec(&hb).unwrap()).unwrap();
    assert_eq!(parsed.verify(TS), Ok(()));
}

// --------------------------------------------------------------- claim code

#[test]
fn claim_code_has_the_contract_shape() {
    assert_eq!(
        std::str::from_utf8(ALPHABET).unwrap(),
        "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    );
    assert_eq!(CODE_LEN, 10);

    for _ in 0..500 {
        let code = ClaimCode::generate();
        assert_eq!(code.canonical().len(), 10);
        assert!(code.canonical().bytes().all(|b| ALPHABET.contains(&b)));

        let shown = code.display();
        assert_eq!(shown.len(), 11);
        assert_eq!(shown.as_bytes()[5], b'-');
        assert_eq!(shown.replace('-', ""), code.canonical());
        for forbidden in ['I', 'O', '0', '1'] {
            assert!(!shown.contains(forbidden));
        }
    }
}

#[test]
fn claim_codes_are_random() {
    let codes: std::collections::HashSet<String> = (0..2000)
        .map(|_| ClaimCode::generate().canonical().to_string())
        .collect();
    // 32^10 possibilities: any repeat in 2000 draws means a broken generator.
    assert_eq!(codes.len(), 2000);

    // Every symbol of the alphabet shows up (20 000 draws over 32 symbols).
    let seen: std::collections::HashSet<char> = codes.iter().flat_map(|c| c.chars()).collect();
    assert_eq!(seen.len(), 32);
}

#[test]
fn claim_code_is_not_derived_from_the_node_key() {
    // Same identity, two codes: they differ, so the key does not determine the code.
    let a = ClaimCode::generate();
    let b = ClaimCode::generate();
    assert_ne!(a, b);
}

#[test]
fn claim_hash_is_sha256_of_the_code_without_dash_uppercase() {
    // Known answer: sha256("ABCDEFGHJK")
    const KNOWN: &str = "f57cbf1e3e471b25db4b8ad0844df41b2dae9c7d1944944d128e49294d412f66";
    assert_eq!(ClaimCode::parse("ABCDE-FGHJK").unwrap().hash(), KNOWN);

    // What the operator types is normalised before hashing.
    for typed in [
        "ABCDE-FGHJK",
        "ABCDEFGHJK",
        "abcde-fghjk",
        " abcde fghjk ",
        "AbCdE-fGhJk",
    ] {
        assert_eq!(
            claim::claim_hash(typed).unwrap(),
            KNOWN,
            "typed as {:?}",
            typed
        );
    }

    // Independent computation for a random code.
    let code = ClaimCode::generate();
    let expected = hex::encode(Sha256::digest(code.display().replace('-', "").as_bytes()));
    assert_eq!(code.hash(), expected);
    assert_eq!(code.hash().len(), 64);
    assert_eq!(code.hash(), code.hash().to_lowercase());
}

#[test]
fn invalid_claim_codes_are_refused() {
    assert!(ClaimCode::parse("ABCDE-FGHJ").is_err()); // too short
    assert!(ClaimCode::parse("ABCDE-FGHJKL").is_err()); // too long
    assert!(ClaimCode::parse("ABCDE-FGHJ0").is_err()); // zero is not in the alphabet
    assert!(ClaimCode::parse("ABCDE-FGHJI").is_err()); // neither is I
    assert!(ClaimCode::parse("").is_err());
}

#[test]
fn claim_code_is_hidden_from_debug_output() {
    let code = ClaimCode::generate();
    assert!(!format!("{:?}", code).contains(code.canonical()));
}

// ------------------------------------------------------------ payload shape

fn keys(value: &serde_json::Value) -> Vec<String> {
    let mut keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    keys
}

#[test]
fn default_payload_has_exactly_the_expected_fields() {
    let identity = NodeIdentity::generate().unwrap();
    let hb = sample(&identity, &some_claim_hash());
    let json: serde_json::Value = serde_json::to_value(&hb).unwrap();

    assert_eq!(
        keys(&json),
        [
            "capabilities",
            "claim_hash",
            "node_id",
            "public_key",
            "sig",
            "timestamp",
            "ts",
            "version",
            "wallet_address",
        ]
    );

    assert!(json["node_id"].is_string());
    assert!(json["public_key"].is_string());
    assert!(json["ts"].is_i64(), "ts is an integer");
    assert_eq!(json["ts"], TS);
    assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
    assert!(json["claim_hash"].is_string());
    assert!(json["sig"].is_string());

    // capabilities: an object of exactly three booleans
    assert_eq!(keys(&json["capabilities"]), ["compute", "relay", "storage"]);
    for flag in ["relay", "compute", "storage"] {
        assert!(json["capabilities"][flag].is_boolean());
    }
}

#[test]
fn default_payload_has_no_hostname_hardware_or_ips() {
    let identity = NodeIdentity::generate().unwrap();
    let hb = sample(&identity, &some_claim_hash());
    let text = serde_json::to_string(&hb).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();

    for removed in [
        "hostname",
        "hardware",
        "resources",
        "device_name",
        "cpu_cores",
        "ram_mb",
        "storage_gb",
        "gpu_available",
        "gpu_model",
        "local_ip",
        "local_ips",
        "ip",
        "ips",
    ] {
        assert!(
            json.get(removed).is_none(),
            "field {:?} must be absent",
            removed
        );
        assert!(
            !text.contains(&format!("\"{}\"", removed)),
            "{:?} must not appear anywhere in the payload",
            removed
        );
    }

    // The machine's real hostname must not appear either.
    if let Some(host) = alpha_protocol_core::resources::get_hostname() {
        if host.len() >= 5 {
            assert!(!text.contains(&host), "hostname leaked into the payload");
        }
    }
}

#[test]
fn hardware_is_sent_only_on_opt_in_and_in_its_own_object() {
    let identity = NodeIdentity::generate().unwrap();
    let hardware = Hardware {
        hostname: Some("example-host".into()),
        resources: Some(NodeResources::default()),
    };
    let hb = Heartbeat::new_signed(
        &identity,
        TS,
        &some_claim_hash(),
        Capabilities::ALL,
        Some("My node".into()),
        Some(hardware),
    );
    let json: serde_json::Value = serde_json::to_value(&hb).unwrap();

    assert_eq!(json["hardware"]["hostname"], "example-host");
    assert!(json["hardware"]["resources"]["cpu_cores"].is_number());
    assert_eq!(json["device_name"], "My node");
    // Still nothing at the top level.
    assert!(json.get("hostname").is_none());
    assert!(json.get("resources").is_none());
    // And the signature is unaffected by the optional object.
    assert_eq!(hb.verify(TS), Ok(()));
}

#[test]
fn capabilities_parse_from_a_list() {
    assert_eq!(
        Capabilities::parse_list("relay,compute,storage"),
        Ok(Capabilities::ALL)
    );
    assert_eq!(Capabilities::parse_list("none"), Ok(Capabilities::NONE));
    assert_eq!(
        Capabilities::parse_list(" Relay "),
        Ok(Capabilities {
            relay: true,
            compute: false,
            storage: false
        })
    );
    assert!(Capabilities::parse_list("mining").is_err());
}
