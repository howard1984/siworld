use super::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU64, Ordering};
fn prerequisites() -> Prerequisites {
    // Public synthetic parameters only; no identity seed or proof is derived.
    Prerequisites {
        version: 1,
        reward_role: "reward".into(),
        parameters: json!({
        "version":1,"network":"01".repeat(32),"proof_profile":crate::local::hex(&crate::proofs::protocol_profile_fingerprint()),
        "fixture":false,"work_bits":0,"genesis_timestamp":"1","genesis_target":"ff".repeat(32),
        "pow_iterations":1,"target_interval":300,"economics":"production","fee_mode":"legacy-miner",
        "checkpoint_threshold":2,"checkpoint_public_keys":["0b".repeat(1952),"0c".repeat(1952),"0d".repeat(1952)],
        "founder_public_key":"0e".repeat(1952),"revocation_public_key":"0f".repeat(1952),
        "fee_destination":"$actor:fee_destination","fund":{"team_index":0,"members":[
            {"basis_points":10000,"public_key":"10".repeat(1952),"destination":"$actor:fund_destination"}]},
        "issuance":{"max_metadata_bytes":256,"max_per_block":4}}),
    }
}
fn addresses() -> [String; 5] {
    std::array::from_fn(|i| format!("{:08x}{}", i + 1, "00".repeat(1228)))
}
#[test]
fn pregenesis_roles_project_through_current_sealed_genesis_serializers() {
    let p = prerequisites();
    let a = addresses();
    let original = p.parameters.clone();
    let sealed = resolve(&p, &a).unwrap();
    let encoded = sealed.encode().unwrap();
    assert_eq!(Genesis::decode(&encoded).unwrap().id(), sealed.id());
    assert_eq!(sealed.config().network, [1; 32]);
    assert_eq!(p.parameters, original);
    let mut changed = a;
    changed[2] = format!("06000000{}", "00".repeat(1228));
    assert_ne!(resolve(&p, &changed).unwrap().id(), sealed.id());
}
#[test]
fn pregenesis_rejects_unknown_fields_bad_rules_and_unbound_role_destinations() {
    for (field, replacement) in [
        ("seed", json!("unaccepted")),
        ("fixture", json!(true)),
        ("pow_iterations", json!(0)),
        ("proof_profile", json!("00".repeat(32))),
        ("fee_destination", json!(addresses()[2])),
    ] {
        let mut p = prerequisites();
        p.parameters[field] = replacement;
        assert!(resolve(&p, &addresses()).is_err());
    }
    let mut p = prerequisites();
    p.parameters["fund"]["members"][0]["destination"] = json!("$actor:payer");
    assert!(resolve(&p, &addresses()).is_err());
    let mut p = prerequisites();
    p.reward_role = "recipient".into();
    assert!(resolve(&p, &addresses()).is_err());
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "siworld-custody-input-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        Self(p)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
#[test]
fn frozen_public_input_pins_and_new_output_reject_replacement_and_aliases() {
    use std::os::unix::fs::symlink;
    let root = Directory::new();
    let path = root.0.join("public.json");
    fs::write(&path, b"public").unwrap();
    let input = Input {
        path: path.clone(),
        sha256: sha(b"public"),
    };
    assert_eq!(load(&input, 6).unwrap(), b"public");
    fs::write(&path, b"change").unwrap();
    assert!(load(&input, 6).is_err());
    fs::write(&path, b"public").unwrap();
    let alias = root.0.join("alias");
    symlink(&path, &alias).unwrap();
    assert!(read(&alias, 6).is_err());
    let linked = root.0.join("linked");
    fs::hard_link(&path, &linked).unwrap();
    assert!(load(&input, 6).is_err());
    fs::remove_file(linked).unwrap();
    let destination = root.0.join("evidence");
    let mut output = Output::create(&destination).unwrap();
    output.write("public.json", b"original").unwrap();
    assert!(output.write("public.json", b"replacement").is_err());
    assert!(Output::create(&destination).is_err());
    assert_eq!(
        fs::read(destination.join("public.json")).unwrap(),
        b"original"
    );
}

#[test]
fn parent_sync_failure_retains_empty_output_without_a_completion_receipt() {
    let root = Directory::new();
    let path = root.0.join("incomplete");
    let failed = Output::create_with_parent_sync(&path, |parent| {
        assert_eq!(parent, root.0.as_path());
        assert!(path.is_dir());
        assert_eq!(fs::read_dir(&path).unwrap().count(), 0);
        Err("synthetic parent synchronization failure".into())
    });
    assert!(failed.is_err());
    assert!(path.is_dir());
    assert_eq!(fs::read_dir(&path).unwrap().count(), 0);
    assert!(!path.join("completed.json").exists());
    assert!(Output::create(&path).is_err());
}
