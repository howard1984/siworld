use super::*;
use native::issuance::derive_asset_id;
use p3_field::PrimeCharacteristicRing;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "siworld-isolated-issuer-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn binding(campaign: u8) -> RehearsalBinding {
    let bytes = serde_json::to_vec(
        &json!({"version":1,"campaign_id":crate::local::hex(&[campaign;32]),
        "network":crate::local::hex(&[2;32]),"prior_network":crate::local::hex(&[1;32]),
        "genesis_parameters_sha256":crate::local::hex(&[3;32])}),
    )
    .unwrap();
    RehearsalBinding::decode(&bytes, Sha256::digest(&bytes).into()).unwrap()
}
fn prepared(
    root: &Directory,
    purpose: Purpose,
    parameters: &RehearsalBinding,
) -> ([u8; ISSUER_KEY_BYTES], PathBuf) {
    let path = root.0.join("key");
    // Synthetic seed is confined to the existing private test fixture helper.
    prepare_seed(
        &path,
        parameters.network(),
        purpose,
        0,
        Zeroizing::new([7; 32]),
    )
    .unwrap();
    storage::Directory::open(&path)
        .unwrap()
        .write_once("rehearsal.json", parameters.bytes())
        .unwrap();
    let value: Value =
        serde_json::from_slice(&fs::read(path.join("public.json")).unwrap()).unwrap();
    let authority =
        crate::eng2_operations::public_bytes(&value["public_key_hex"], ISSUER_KEY_BYTES)
            .unwrap()
            .try_into()
            .unwrap();
    (authority, path)
}
fn declaration(
    authority: [u8; ISSUER_KEY_BYTES],
) -> (IssuanceDeclaration, IssuerExpectation, IssuancePolicy) {
    let metadata = AssetMetadata {
        name: "Synthetic fixture asset".into(),
        decimals: 2,
    };
    let asset_id = derive_asset_id(&[2; 32], &authority, 0);
    let declaration = IssuanceDeclaration {
        network: [2; 32],
        version: 1,
        issuer_key: authority,
        sequence: 0,
        asset_id,
        public_supply: 2,
        metadata: metadata.clone(),
        issuance_fee_atoms: 10,
        note_commitments: (1..=crate::issuance::INITIAL_NOTES)
            .map(|n| [native::multi_asset::F::from_u64(n as u64); 12])
            .collect(),
        note_ciphertext_digests: vec![[1; 32]; crate::issuance::INITIAL_NOTES],
    };
    let expectation = IssuerExpectation {
        sequence: 0,
        asset_id,
        public_supply: 2,
        metadata,
        issuance_fee_atoms: 10,
    };
    let policy = IssuancePolicy {
        max_notes: crate::issuance::INITIAL_NOTES,
        max_metadata_bytes: 128,
        max_ciphertext_bytes_per_note: 8192,
        required_fee_atoms: 10,
    };
    (declaration, expectation, policy)
}
#[test]
fn issuer_signs_actual_fixed_context_and_consumes_the_single_attempt() {
    let root = Directory::new();
    let parameters = binding(4);
    let (authority, path) = prepared(&root, Purpose::Issuer, &parameters);
    let (declaration, expectation, policy) = declaration(authority);
    let mut signer = IssuerSigner::open(&path, &parameters, authority).unwrap();
    let signature = signer.sign(&declaration, &expectation, policy).unwrap();
    SignedIssuance {
        declaration: declaration.clone(),
        signature: Some(signature),
    }
    .verify_signature()
    .unwrap();
    assert!(signer.sign(&declaration, &expectation, policy).is_err());
    assert!(
        ml_dsa_65::verify(
            &ml_dsa_65::MLDSA65VerificationKey::new(authority),
            &declaration.canonical_bytes(),
            b"wrong context",
            &ml_dsa_65::MLDSA65Signature::new(signature)
        )
        .is_err()
    );
}
#[test]
fn issuer_rejects_wrong_purpose_network_campaign_key_and_public_economics() {
    let root = Directory::new();
    let parameters = binding(4);
    let (authority, path) = prepared(&root, Purpose::Issuer, &parameters);
    assert!(IssuerSigner::open(&path, &binding(5), authority).is_err());
    assert!(IssuerSigner::open(&path, &parameters, [9; ISSUER_KEY_BYTES]).is_err());
    let (mut declaration, expectation, policy) = declaration(authority);
    declaration.network = [8; 32];
    assert!(
        IssuerSigner::open(&path, &parameters, authority)
            .unwrap()
            .sign(&declaration, &expectation, policy)
            .is_err()
    );
    declaration.network = [2; 32];
    declaration.public_supply += 1;
    assert!(
        IssuerSigner::open(&path, &parameters, authority)
            .unwrap()
            .sign(&declaration, &expectation, policy)
            .is_err()
    );
    let wrong = Directory::new();
    let (other, path) = prepared(&wrong, Purpose::Founder, &parameters);
    assert!(IssuerSigner::open(&path, &parameters, other).is_err());
    assert!(
        prepare(
            &root.0.join("unbound"),
            parameters.network(),
            Purpose::Issuer,
            0
        )
        .is_err()
    );
    assert!(!root.0.join("unbound").exists());
}

#[test]
fn issuer_initializer_persists_bound_public_context_and_refuses_overwrite() {
    let root = Directory::new();
    let parameters = binding(4);
    let path = root.0.join("fresh");
    let receipt = prepare_isolated_issuer(&path, &parameters).unwrap();
    assert_eq!(receipt["encrypted"], false);
    assert_eq!(receipt["temporary_isolated_issuer"], true);
    assert_eq!(
        fs::read(path.join("rehearsal.json")).unwrap(),
        parameters.bytes()
    );
    let original_public = fs::read(path.join("public.json")).unwrap();
    assert!(prepare_isolated_issuer(&path, &parameters).is_err());
    assert_eq!(fs::read(path.join("public.json")).unwrap(), original_public);
    let value: Value = serde_json::from_slice(&original_public).unwrap();
    let authority =
        crate::eng2_operations::public_bytes(&value["public_key_hex"], ISSUER_KEY_BYTES)
            .unwrap()
            .try_into()
            .unwrap();
    assert!(IssuerSigner::open(&path, &parameters, authority).is_ok());
    fs::write(path.join("public.json"), b"{}").unwrap();
    assert!(IssuerSigner::open(&path, &parameters, authority).is_err());
}
