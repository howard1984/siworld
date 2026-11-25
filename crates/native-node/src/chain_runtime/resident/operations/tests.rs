use super::*;
use crate::eng2::driver::Head;
use crate::eng2_governance::{
    Action, ActionKind, Authorization, SIGNATURE_BYTES, SignedAction, SignerRole,
};
use std::{io::Write, os::unix::fs::OpenOptionsExt};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("eng2-operations-{}", crate::local::hex(&random)));
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn write(&self, name: &str, bytes: &[u8]) {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.0.join(name))
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn head() -> Head {
    Head {
        network: [1; 32],
        genesis: [2; 32],
        height: 9,
        id: [3; 32],
        work: 0.into(),
    }
}
fn bundle() -> Value {
    // A synthetic framed signature, deliberately not authenticated. Queueing
    // proves no signature validity, entitlement, activation or native inclusion.
    let action = SignedAction {
        action: Action {
            network: [1; 32],
            sequence: 1,
            kind: ActionKind::ProposeIssuanceFee {
                amount_atoms: 100_000_000,
            },
        },
        signatures: vec![Authorization {
            role: SignerRole::Founder,
            signature: [7; SIGNATURE_BYTES],
        }],
    };
    json!({"version":1,"operations":{"version":1,"network":crate::local::hex(&[1;32]),"height":"10",
        "fund_claims":[],"governance":[crate::local::hex(&action.encode().unwrap())]},"issuances":[]})
}
fn request(run: &str) -> Value {
    json!({"version":1,"run_id":run,"network":crate::local::hex(&[1;32]),"genesis":crate::local::hex(&[2;32]),
        "parent":crate::local::hex(&[3;32]),"height":"10","bundle":bundle()})
}
fn enqueue(mailbox: &Mailbox, value: &Value) {
    let _lock = mailbox.files.lock().unwrap();
    mailbox
        .files
        .replace(
            REQUEST,
            &serde_json::to_vec(value).unwrap(),
            MAX_REQUEST_BYTES,
        )
        .unwrap();
}
fn mailbox(directory: &Directory) -> Mailbox {
    Mailbox::open(&directory.0, &"a".repeat(64), [1; 32], [2; 32]).unwrap()
}
#[test]
fn run_parent_height_context_reject_without_rewriting_public_signatures() {
    let directory = Directory::new();
    let mailbox = mailbox(&directory);
    let budget = p2p::Budget::new(64 * 1024 * 1024);
    let original = request(&mailbox.run);
    for field in ["run_id", "network", "genesis", "parent", "height"] {
        let mut stale = original.clone();
        stale[field] = if field == "height" {
            json!("11")
        } else {
            json!("b".repeat(64))
        };
        enqueue(&mailbox, &stale);
        assert!(mailbox.take(&head(), &budget).unwrap().is_none());
        let outcome = result(&directory.0, &mailbox.run).unwrap();
        assert_eq!(outcome["outcome"], "request_rejected");
        assert!(outcome["block_id"].is_null());
        assert!(
            mailbox
                .files
                .read(REQUEST, MAX_REQUEST_BYTES)
                .unwrap()
                .is_none()
        );
    }
    enqueue(&mailbox, &original);
    let before = budget.available().unwrap();
    let mut active = mailbox.take(&head(), &budget).unwrap().unwrap();
    assert!(budget.available().unwrap() < before);
    let (operations, issuances) = active.inputs();
    assert!(issuances.is_empty());
    assert_eq!(
        operations.unwrap().encode().unwrap(),
        serde_json::to_vec(&original["bundle"]["operations"]).unwrap()
    );
    assert_eq!(
        result(&directory.0, &mailbox.run).unwrap()["outcome"],
        "preparing"
    );
    drop(active);
    assert_eq!(
        result(&directory.0, &mailbox.run).unwrap()["outcome"],
        "production_interrupted"
    );
    assert_eq!(budget.available().unwrap(), before);
}
#[test]
fn restart_consumes_only_bounded_requests_and_marks_old_work_interrupted() {
    let directory = Directory::new();
    directory.write("permanent.bin", b"permanent fixture");
    let mailbox = mailbox(&directory);
    enqueue(&mailbox, &request(&mailbox.run));
    let budget = p2p::Budget::new(64 * 1024 * 1024);
    let mut active = mailbox.take(&head(), &budget).unwrap().unwrap();
    // A forced process loss would skip Drop. Preserve only its bounded receipt.
    active.finished = true;
    drop(active);
    enqueue(&mailbox, &request(&mailbox.run));
    drop(mailbox);
    let restarted = Mailbox::open(&directory.0, &"b".repeat(64), [1; 32], [2; 32]).unwrap();
    assert!(
        restarted
            .files
            .read(REQUEST, MAX_REQUEST_BYTES)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        result(&directory.0, &"a".repeat(64)).unwrap()["outcome"],
        "interrupted"
    );
    assert!(result(&directory.0, &"b".repeat(64)).is_err());
    assert_eq!(
        fs::read(directory.0.join("permanent.bin")).unwrap(),
        b"permanent fixture"
    );
}
#[test]
fn malformed_oversized_shared_and_symlink_files_do_not_escape_mailbox() {
    use std::os::unix::fs::symlink;
    let directory = Directory::new();
    let mailbox = mailbox(&directory);
    let budget = p2p::Budget::new(64 * 1024 * 1024);
    {
        let _lock = mailbox.files.lock().unwrap();
        mailbox
            .files
            .replace(REQUEST, b"not JSON", MAX_REQUEST_BYTES)
            .unwrap();
    }
    assert!(mailbox.take(&head(), &budget).unwrap().is_none());
    let before = budget.available().unwrap();
    enqueue(&mailbox, &request(&mailbox.run));
    assert!(mailbox.take(&head(), &p2p::Budget::new(1)).is_err());
    assert_eq!(budget.available().unwrap(), before);
    assert!(
        mailbox
            .files
            .read(REQUEST, MAX_REQUEST_BYTES)
            .unwrap()
            .is_some()
    );
    mailbox.files.remove(REQUEST, MAX_REQUEST_BYTES).unwrap();
    let target = directory.0.join("permanent.bin");
    directory.write("permanent.bin", b"permanent fixture");
    let selected = directory.0.join("eng2-operations").join(REQUEST);
    symlink(&target, &selected).unwrap();
    assert!(mailbox.take(&head(), &budget).is_err());
    assert!(mailbox.files.remove(REQUEST, MAX_REQUEST_BYTES).is_err());
    fs::remove_file(&selected).unwrap();
    fs::hard_link(&target, &selected).unwrap();
    assert!(mailbox.take(&head(), &budget).is_err());
    fs::remove_file(&selected).unwrap();
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&selected)
        .unwrap();
    file.set_len(MAX_REQUEST_BYTES as u64 + 1).unwrap();
    assert!(mailbox.take(&head(), &budget).is_err());
    assert_eq!(fs::read(target).unwrap(), b"permanent fixture");
}
#[test]
fn canonical_bundles_bound_records_and_preserve_issuance_bytes() {
    use native::{
        issuance::{AssetMetadata, IssuanceDeclaration, SignedIssuance},
        multi_asset::{AssetId, F},
    };
    use p3_field::PrimeCharacteristicRing;
    let record = IssuanceRecord {
        signed: SignedIssuance {
            declaration: IssuanceDeclaration {
                network: [1; 32],
                version: 1,
                issuer_key: [1; native::issuance::ISSUER_KEY_BYTES],
                sequence: 1,
                asset_id: AssetId([2; 32]),
                public_supply: 3,
                metadata: AssetMetadata {
                    name: "Synthetic".into(),
                    decimals: 0,
                },
                issuance_fee_atoms: 5_000_000_000,
                note_commitments: vec![[F::ZERO; 12]; 3],
                note_ciphertext_digests: vec![[0; 32]; 3],
            },
            signature: Some([7; native::issuance::ISSUER_SIGNATURE_BYTES]),
        },
        ciphertexts: vec![vec![0; crate::issuance::CIPHERTEXT_BYTES]; 3],
        proof: vec![1],
        fee_commitment: [0; 48],
        fee_rho: [0; 48],
    };
    let encoded = record.encode().unwrap();
    let mut value =
        json!({"version":1,"operations":null,"issuances":[crate::local::hex(&encoded)]});
    let (operations, records) = decode_bundle(&value, [1; 32], 10).unwrap();
    assert!(operations.is_none());
    assert_eq!(records[0].encode().unwrap(), encoded);
    assert!(decode_bundle(&value, [2; 32], 10).is_err());
    value["issuances"] = json!(vec![
        crate::local::hex(&encoded);
        crate::issuance::RECORDS_CODEC_LIMIT + 1
    ]);
    assert!(decode_bundle(&value, [1; 32], 10).is_err());
    value = bundle();
    value["operations"]["governance"] = json!([]);
    assert!(decode_bundle(&value, [1; 32], 10).is_err());
    value = bundle();
    value["unknown"] = Value::Null;
    assert!(decode_bundle(&value, [1; 32], 10).is_err());
    assert!(canonical(b"{\"version\":1,\"version\":1}", 100).is_err());
    assert!(canonical(b"{}\n", 100).is_err());
    assert!(height("010").is_err());
    assert!(height("0").is_err());
    assert!(hash(&"A".repeat(64)).is_err());
}
#[test]
fn explicit_cli_admission_has_one_slot_and_never_reports_commit() {
    let directory = Directory::new();
    // Reuse the existing synthetic genesis fixture, not any deployed identity.
    let state = crate::eng2::snapshot::tests::bootstrap();
    let genesis = Genesis::seal(
        state.chain.config.clone(),
        state.governance.clone(),
        crate::eng2::genesis::FeeMode::LegacyMiner,
    )
    .unwrap();
    directory.write("genesis.bin", &genesis.encode().unwrap());
    let run = "a".repeat(64);
    let expected = crate::local::hex(&genesis.id());
    let mailbox =
        Mailbox::open(&directory.0, &run, genesis.config().network, genesis.id()).unwrap();
    directory.write("public.json", &serde_json::to_vec(&bundle()).unwrap());
    let public = directory.0.join("public.json");
    let mut status = json!({"schema_version":2,"run_id":run,"tip":crate::local::hex(&[3;32]),"height":9,
        "network_id":crate::local::hex(&genesis.config().network),"genesis_id":expected,
        "mining_enabled":true,"ready":true,"phase":"mining","updated_unix_ms":unix_ms().unwrap()});
    service::atomic_json(&directory.0.join(service::STATUS_FILE), &status).unwrap();
    for (selected_run, parent, next) in [
        ("b".repeat(64), crate::local::hex(&[3; 32]), "10"),
        (run.clone(), crate::local::hex(&[4; 32]), "10"),
        (run.clone(), crate::local::hex(&[3; 32]), "11"),
    ] {
        assert!(
            submit(
                &directory.0,
                &public,
                &selected_run,
                &parent,
                next,
                &expected
            )
            .is_err()
        );
    }
    let queued = submit(
        &directory.0,
        &public,
        &run,
        &crate::local::hex(&[3; 32]),
        "10",
        &expected,
    )
    .unwrap();
    assert_eq!(queued["outcome"], "queued");
    assert!(queued["block_id"].is_null());
    assert!(
        submit(
            &directory.0,
            &public,
            &run,
            &crate::local::hex(&[3; 32]),
            "10",
            &expected
        )
        .is_err()
    );
    let actual_head = Head {
        genesis: genesis.id(),
        ..head()
    };
    let budget = p2p::Budget::new(64 * 1024 * 1024);
    let mut active = mailbox.take(&actual_head, &budget).unwrap().unwrap();
    assert!(
        submit(
            &directory.0,
            &public,
            &run,
            &crate::local::hex(&[3; 32]),
            "10",
            &expected
        )
        .is_err()
    );
    active.fail("engine_rejected");
    drop(active);
    status["updated_unix_ms"] = json!(unix_ms().unwrap().saturating_sub(16_000));
    service::atomic_json(&directory.0.join(service::STATUS_FILE), &status).unwrap();
    assert!(
        submit(
            &directory.0,
            &public,
            &run,
            &crate::local::hex(&[3; 32]),
            "10",
            &expected
        )
        .is_err()
    );
    assert_eq!(
        result(&directory.0, &run).unwrap()["outcome"],
        "engine_rejected"
    );
    let mut files = fs::read_dir(directory.0.join("eng2-operations"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    files.sort();
    assert_eq!(files, vec!["lock", "result.json"]);
    assert!(!directory.0.join("chain.redb").exists());
    assert!(!directory.0.join("native-peer-identity.secret").exists());
}

#[test]
fn normal_owner_query_contention_recovers_and_unresponsive_lock_is_bounded() {
    let directory = Directory::new();
    let files = io::Files::open(&directory.0).unwrap();
    let held = files.lock().unwrap();
    let path = directory.0.clone();
    let (ready, sampled) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let files = io::Files::open(&path).unwrap();
        ready.send(()).unwrap();
        files.lock().map(drop)
    });
    sampled.recv_timeout(Duration::from_secs(1)).unwrap();
    std::thread::sleep(Duration::from_millis(20));
    drop(held);
    assert!(worker.join().unwrap().is_ok());
    let held = files.lock().unwrap();
    let started = Instant::now();
    assert!(io::Files::open(&directory.0).unwrap().lock().is_err());
    assert!(started.elapsed() >= Duration::from_secs(1));
    assert!(started.elapsed() < Duration::from_secs(3));
    drop(held);
    assert!(files.lock().is_ok());
}
