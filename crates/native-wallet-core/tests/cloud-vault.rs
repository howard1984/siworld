use siworld_native_wallet_core::cloud_vault::{Account, SNAPSHOT_BYTES, digest};
const PASS: &str = "independent-synthetic-vault-passphrase";
#[test]
fn independent_recovery_authentication_and_fixed_size_snapshots() {
    let mut a = Account::create().unwrap();
    let b = Account::create().unwrap();
    assert_ne!(a.locator(), b.locator());
    assert_ne!(a.public_key(), b.public_key());
    let recovery = a.recovery(PASS).unwrap();
    let restored = Account::restore(&recovery, PASS).unwrap();
    assert_eq!(restored.public_key(), a.public_key());
    assert!(Account::restore(&recovery, "wrong-password").is_err());
    let empty = a.snapshot(&[], PASS).unwrap();
    assert_eq!(empty.len(), SNAPSHOT_BYTES);
    let again = a.snapshot(&[], PASS).unwrap();
    assert_ne!(empty, again);
    let mut p = vec![0u8; 4196];
    p[36..44].copy_from_slice(b"SWNCNT01");
    let full = a.snapshot(&vec![p.clone(); 100], PASS).unwrap();
    assert_eq!(full.len(), SNAPSHOT_BYTES);
    assert!(a.snapshot(&vec![p; 101], PASS).is_err());
    assert_eq!(a.read_snapshot(&full, PASS, 1, [0; 32]).unwrap().len(), 100);
    assert!(b.read_snapshot(&full, PASS, 1, [0; 32]).is_err());
    assert!(a.read_snapshot(&full, PASS, 2, [0; 32]).is_err());
    let h = digest(&full);
    let signature = a.sign_revision(1, &h, &[0; 32]);
    a.verify_revision(1, &h, &[0; 32], &signature).unwrap();
    assert!(b.verify_revision(1, &h, &[0; 32], &signature).is_err());
    a.accept(1, h).unwrap();
    assert!(a.read_snapshot(&empty, PASS, 1, [0; 32]).is_err());
    assert!(a.accept(0, [0; 32]).is_err());
    let saved = a.recovery(PASS).unwrap();
    let resumed = Account::restore(&saved, PASS).unwrap();
    assert_eq!(resumed.revision, 1);
    assert_eq!(resumed.digest, h);
    let mut corrupt = full;
    corrupt[200] ^= 1;
    assert!(a.read_snapshot(&corrupt, PASS, 1, [0; 32]).is_err());
    let challenge = "ab".repeat(32);
    let previous = "00".repeat(32);
    let sig = a
        .sign_request(
            "http://localhost:18892",
            "PUT",
            &challenge,
            1,
            b"ciphertext",
            &previous,
        )
        .unwrap();
    assert_ne!(
        sig,
        a.sign_request(
            "http://localhost:18892",
            "GET",
            &challenge,
            1,
            b"ciphertext",
            &previous
        )
        .unwrap()
    );
    assert!(
        a.sign_request(
            "https://example.invalid\nforged",
            "PUT",
            &challenge,
            1,
            b"ciphertext",
            &previous
        )
        .is_err()
    );
}
