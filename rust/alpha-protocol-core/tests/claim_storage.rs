//! Claim code storage. Kept in its own test binary because it points
//! `APN_DATA_DIR` at a temporary directory for the whole process.

use alpha_protocol_core::{claim, identity_storage};

#[test]
fn claim_code_is_created_once_stored_owner_only_and_bound_to_the_node() {
    let dir = std::env::temp_dir().join(format!("apn-claim-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::env::set_var(identity_storage::DATA_DIR_ENV, &dir);

    // Nothing stored yet.
    assert!(claim::load("apn_aaaaaaaa").unwrap().is_none());

    // First call creates, second call returns the same code.
    let (first, created) = claim::load_or_create("apn_aaaaaaaa").unwrap();
    assert!(created);
    let (second, created_again) = claim::load_or_create("apn_aaaaaaaa").unwrap();
    assert!(!created_again);
    assert_eq!(first.code, second.code);
    assert_eq!(first.created_at, second.created_at);

    // Stored next to the identity, readable by the owner only.
    let path = claim::claim_file_path().unwrap();
    assert_eq!(path.parent().unwrap(), dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);
        assert_eq!(dir_mode, 0o700);
    }

    // The identity file gets the same treatment.
    let (identity, identity_created) = identity_storage::load_or_create().unwrap();
    assert!(identity_created);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let id_path = identity_storage::get_identity_file_path().unwrap();
        assert_eq!(
            std::fs::metadata(&id_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let (reloaded, created) = identity_storage::load_or_create().unwrap();
    assert!(!created);
    assert_eq!(identity.short_id(), reloaded.short_id());

    // A different node (identity replaced) does not inherit the old code.
    let (other, created) = claim::load_or_create("apn_bbbbbbbb").unwrap();
    assert!(created);
    assert_ne!(other.code, first.code);

    std::fs::remove_dir_all(&dir).unwrap();
}
