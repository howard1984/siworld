use super::*;
use crate::identity::checkpoint_authority::Authority;
use crate::service::Lease;
use std::{
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "siworld-checkpoint-rejection-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path.canonicalize().unwrap())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn write_json(path: &Path, value: &Value) {
    write(path, &serde_json::to_vec(value).unwrap());
}

struct GateFixture {
    _parent: Directory,
    data: PathBuf,
    run: String,
    final_value: Value,
}
impl GateFixture {
    fn new() -> Self {
        let parent = Directory::new();
        let data = parent.0.join("fixture");
        let config = local::initialize(&data, 0).unwrap();
        let run = "a".repeat(64);
        fs::create_dir(data.join("service-runs")).unwrap();
        fs::create_dir(data.join("service-runs").join(&run)).unwrap();
        for dir in [
            data.join("service-runs"),
            data.join("service-runs").join(&run),
        ] {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        write(&data.join("chain.redb"), b"synthetic-unopened-database");
        write(
            &data.join("native-peer-identity.secret"),
            b"synthetic-unread-identity",
        );
        write(&data.join(LEASE_FILE), b"");
        let peers = json!({"version":1,"engineering":true,"listen":null,"mining":false,
            "peers":[{"synthetic":true}]});
        write_json(&data.join("fixture-peers.json"), &peers);
        let config_sha = sha(&fs::read(data.join("engineering-network.bin")).unwrap());
        let peers_sha = sha(&fs::read(data.join("fixture-peers.json")).unwrap());
        let identity = json!({"schema_version":1,"run_id":run,"process_id":7,
            "network_id":local::hex(&config.network),"binary_sha256":"b".repeat(64),
            "configuration_sha256":config_sha,"peer_configuration_sha256":peers_sha,"started_unix_ms":100});
        write_json(
            &data.join("service-runs").join(&run).join("run.json"),
            &identity,
        );
        let mut final_value = identity;
        for (field, value) in json!({"phase":"stopped","state_available":true,"height":96,
            "error_code":null,"pow_attempts":0,"tip":"c".repeat(64),
            "state_fingerprint":"d".repeat(64),"cumulative_work":"0".repeat(128),
            "storage_metrics":{"role":"validator"}})
        .as_object()
        .unwrap()
        {
            final_value[field] = value.clone();
        }
        let result = Self {
            _parent: parent,
            data,
            run,
            final_value,
        };
        result.save_final();
        result
    }
    fn save_final(&self) {
        write_json(
            &self
                .data
                .join("service-runs")
                .join(&self.run)
                .join("final.json"),
            &self.final_value,
        );
        write_json(&self.data.join(STATUS_FILE), &self.final_value);
    }
}

#[test]
fn admission_requires_exact_clean_final_nonauthority_nonmining_validator() {
    let mut f = GateFixture::new();
    preflight(&f.data, &f.run).unwrap();
    for (field, bad) in [
        ("phase", json!("networking")),
        ("pow_attempts", json!(1)),
        ("error_code", json!("failed")),
        ("state_available", json!(false)),
        ("run_id", json!("f".repeat(64))),
    ] {
        let saved = f.final_value[field].clone();
        f.final_value[field] = bad;
        f.save_final();
        assert!(preflight(&f.data, &f.run).is_err(), "{field}");
        f.final_value[field] = saved;
    }
    f.save_final();
    symlink(
        "absent",
        f.data.join("engineering-checkpoint-authority.secret"),
    )
    .unwrap();
    assert_eq!(
        preflight(&f.data, &f.run).unwrap_err(),
        "authority_material_forbidden"
    );
}

#[test]
fn missing_or_active_existing_lease_rejects_before_database_or_certificates() {
    let f = GateFixture::new();
    let lease = Lease::acquire(&f.data).unwrap();
    let missing = f.data.join("nonexistent-public-certificate");
    assert_eq!(
        run(&f.data, &f.run, &missing, &missing).unwrap_err(),
        "exclusive_existing_service_lease_unavailable"
    );
    drop(lease);
    fs::remove_file(f.data.join(LEASE_FILE)).unwrap();
    assert!(run(&f.data, &f.run, &missing, &missing).is_err());
    assert!(!f.data.join(LEASE_FILE).exists());
    assert_eq!(
        fs::read(f.data.join("chain.redb")).unwrap(),
        b"synthetic-unopened-database"
    );
}

#[test]
fn links_and_changed_public_configuration_fail_admission_without_store_open() {
    let f = GateFixture::new();
    let certificate = f.data.join("certificate.bin");
    write(&certificate, b"public-certificate");
    fs::hard_link(&certificate, f.data.join("certificate-link.bin")).unwrap();
    assert!(read_file(&certificate, MAX_CERTIFICATE_BYTES).is_err());
    let alias = f._parent.0.join("alias");
    symlink(&f.data, &alias).unwrap();
    assert!(preflight(&alias, &f.run).is_err());
    let (_, mut peers) = read_json(&f.data.join("fixture-peers.json")).unwrap();
    peers["mining"] = json!(true);
    write_json(&f.data.join("fixture-peers.json"), &peers);
    assert_eq!(
        preflight(&f.data, &f.run).unwrap_err(),
        "original_outbound_nonmining_configuration_required"
    );
}

#[test]
fn finite_production_api_rejections_preserve_full_semantics_and_exact_reopen() {
    // Independent synthetic authorities and a synthetic chain verifier exercise
    // harness control flow. This test is not actual native-chain acceptance.
    let parent = Directory::new();
    let data = parent.0.join("network");
    let config = local::initialize(&data, 0).unwrap();
    let binding = Binding::new(&config);
    crate::identity::NativeIdentity::initialize(&data, binding).unwrap();
    let first = Directory::new();
    let second = Directory::new();
    let a = Authority::initialize(&first.0, binding).unwrap();
    let b = Authority::initialize(&second.0, binding).unwrap();
    let roster = Roster::new(binding, [a.public_key(), b.public_key()]).unwrap();
    let verifier = crate::fixtures::TestVerifier;
    let mut store = Store::open(data.join("chain.redb"), config.clone(), &verifier).unwrap();
    store.configure_storage(Role::Validator).unwrap();
    for index in 0..96 {
        let block = crate::fixtures::candidate(store.state(), 2_000_000 + index * 10_000);
        store.append(&block, &verifier).unwrap();
    }
    let mut certificates = Vec::new();
    for (sequence, issued) in [(1, 21_600), (2, 43_200)] {
        let candidate = store
            .engineering_checkpoint_candidate(&roster, 72, sequence, issued, &verifier)
            .unwrap();
        let cert = Certificate {
            statement: candidate.statement().clone(),
            votes: vec![
                store
                    .sign_engineering_checkpoint(&a, &roster, &candidate)
                    .unwrap(),
                store
                    .sign_engineering_checkpoint(&b, &roster, &candidate)
                    .unwrap(),
            ],
        };
        store
            .accept_engineering_checkpoint(&cert, &roster, issued, &verifier)
            .unwrap();
        certificates.push(cert);
    }
    let all = cases(&certificates[1], &certificates[0]).unwrap();
    assert_eq!(all.len(), 5);
    assert_eq!(
        Certificate::decode(&all[0].bytes).err().unwrap(),
        "two checkpoint signatures required"
    );
    for case in &all[1..4] {
        let bad = Certificate::decode(&case.bytes).unwrap();
        assert_eq!(bad.votes[0].signature, certificates[1].votes[0].signature);
        assert_eq!(bad.votes[1].signature, certificates[1].votes[1].signature);
    }
    for case in &all[2..4] {
        assert_eq!(
            Certificate::decode(&case.bytes).unwrap().statement.sequence,
            3
        );
        assert!(case.signature_preserving_sequence_advance);
    }
    assert_eq!(all[4].bytes, certificates[0].encode().unwrap());
    let (before, results) = exercise(
        &mut store,
        &certificates[1],
        &certificates[0],
        &roster,
        43_200,
        &verifier,
    )
    .unwrap();
    assert_eq!(results.len(), 5);
    assert_eq!(results[2]["rejection_code"], "checkpoint signature invalid");
    assert_eq!(results[3]["rejection_code"], "checkpoint signature invalid");
    assert_eq!(
        results[4]["verification_layer"],
        "production_store_persisted_cursor"
    );
    assert_eq!(before, invariant(&store).unwrap());
    assert!(
        exercise(
            &mut store,
            &certificates[0],
            &certificates[1],
            &roster,
            43_200,
            &verifier
        )
        .is_err()
    );
    drop(store);
    let reopened = Store::check_restart_existing(
        data.join("chain.redb"),
        config,
        &NativeVerifier::new().unwrap(),
    )
    .unwrap();
    assert_eq!(before, invariant(&reopened).unwrap());
}
