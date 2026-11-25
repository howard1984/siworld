//! Opt-in public-history replay through the owner-local operations mailbox.
//! This does not run a resident, prove wallet work, or qualify private ingress.

use super::*;
use crate::eng2::{
    body::Body,
    header::{HEADER_BYTES, Header},
};
use redb::{
    Database, ReadOnlyDatabase, ReadableDatabase, ReadableTable, ReadableTableMetadata,
    TableDefinition,
};
use std::{
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
};

const BLOCKS: TableDefinition<u64, &[u8]> = TableDefinition::new("eng2-canonical-blocks-v1");
const INDEX: TableDefinition<u64, &[u8]> = TableDefinition::new("eng2-canonical-index-v1");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("eng2-canonical-meta-v1");

fn public_file(directory: &Path, name: &str) -> PathBuf {
    let path = directory.join(name);
    let metadata = fs::symlink_metadata(&path).expect("explicit public fixture file required");
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(metadata.nlink(), 1);
    path
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

#[test]
#[ignore = "requires an explicitly supplied closed public native 28-block fixture"]
fn real_public_claim_crosses_mailbox_and_native_durable_commit() {
    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    assert_ne!(std::env::var("CI").as_deref(), Ok("true"));
    let source = PathBuf::from(
        std::env::var_os("SIWORLD_ENG2_NATIVE_FIXTURE")
            .expect("set the completed public native fixture directory"),
    );
    let destination = PathBuf::from(
        std::env::var_os("SIWORLD_ENG2_OPERATIONS_FIXTURE")
            .expect("set a new disposable owner-only operations fixture directory"),
    );
    assert!(source.is_absolute() && destination.is_absolute());
    assert_eq!(source.canonicalize().unwrap(), source);
    let source_metadata = fs::symlink_metadata(&source).unwrap();
    assert!(source_metadata.file_type().is_dir());
    assert_eq!(source_metadata.uid(), rustix::process::geteuid().as_raw());
    assert!(!destination.exists());
    let source_database = public_file(&source, "chain.redb");
    let source_before = fs::metadata(&source_database).unwrap();
    let genesis_bytes = fs::read(public_file(&source, "genesis.bin")).unwrap();
    let completed: Value =
        serde_json::from_slice(&fs::read(public_file(&source, "result.json")).unwrap()).unwrap();
    assert_eq!(completed["native_proof_blocks"], "28");
    assert_eq!(completed["durable_reopen_audit"], "passed");
    let genesis = || Genesis::decode(&genesis_bytes).unwrap();
    let network = genesis().config().network;
    let original_record = {
        // The source database is opened through the actual read-only backend.
        // No wallet, signer, seed, sidecar or peer-identity path is derived.
        let database = ReadOnlyDatabase::open(&source_database).unwrap();
        let transaction = database.begin_read().unwrap();
        let table = transaction.open_table(BLOCKS).unwrap();
        assert_eq!(table.len().unwrap(), 28);
        table.get(26).unwrap().unwrap().value().to_vec()
    };
    let imports = ImportLimits {
        chain: Limits {
            max_leaves: 1_000_000,
            max_nullifiers: 1_000_000,
            max_component_bytes: 64 * 1024 * 1024,
        },
        max_snapshot_bytes: 512 * 1024 * 1024,
    };
    let engine = super::super::execution::Engine::new(genesis(), imports.chain).unwrap();
    let header = Header::decode(&original_record[..HEADER_BYTES], &network).unwrap();
    assert_eq!(header.height, 26);
    let original = Body::decode(
        &original_record[HEADER_BYTES..],
        network,
        26,
        engine.body_policy(),
    )
    .unwrap();
    assert_eq!(
        original.commitment(engine.body_policy()).unwrap(),
        header.body_commitment
    );
    assert_eq!(original.fund_claims.len(), 1);
    assert!(original.governance.is_empty() && original.issuances.is_empty());
    drop(engine);
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&destination)
        .unwrap();
    assert_eq!(destination.canonicalize().unwrap(), destination);
    write_private(&destination.join("genesis.bin"), &genesis_bytes);
    let database_path = destination.join("chain.redb");
    fs::copy(&source_database, &database_path).unwrap();
    fs::set_permissions(&database_path, fs::Permissions::from_mode(0o600)).unwrap();
    {
        // Only this registered disposable public-data copy is modified. The
        // accepted prefix is independently audited once before actual admission.
        let database = Database::open(&database_path).unwrap();
        let transaction = database.begin_write().unwrap();
        let mut blocks = transaction.open_table(BLOCKS).unwrap();
        let parent = Header::decode(
            &blocks.get(25).unwrap().unwrap().value()[..HEADER_BYTES],
            &network,
        )
        .unwrap();
        assert_eq!(parent.id().unwrap(), header.parent);
        for height in 26..=28 {
            blocks.remove(height).unwrap();
            transaction
                .open_table(INDEX)
                .unwrap()
                .remove(height)
                .unwrap();
        }
        drop(blocks);
        let mut head = 25u64.to_le_bytes().to_vec();
        head.extend_from_slice(&parent.id().unwrap());
        head.extend_from_slice(&parent.execution_commitment);
        transaction
            .open_table(META)
            .unwrap()
            .insert("head", head.as_slice())
            .unwrap();
        transaction.commit().unwrap();
    }
    let verifier = NativeVerifier::new().unwrap();
    let audit_started = Instant::now();
    let store = Store::audit_existing(&database_path, genesis(), imports.chain, &verifier).unwrap();
    let audit_ms = audit_started.elapsed().as_millis();
    let mut owner = Driver::new(store, verifier, imports).unwrap();
    let parent = owner.head().unwrap();
    assert_eq!(parent.height, 25);
    let spend = &original.fund_claims[0].spend;
    let fund_before = owner
        .engine()
        .state()
        .fund()
        .balance(spend.account)
        .unwrap();
    assert_eq!(fund_before.spend_count, spend.counter);
    let run = crate::local::hex(&blake3::derive_key(
        "siworld eng2 public operations replay run v1",
        &header.id().unwrap(),
    ));
    let mailbox = operations::Mailbox::open(&destination, &run, network, genesis().id()).unwrap();
    let claim_bytes = original.fund_claims[0].encode();
    let bundle = json!({"version":1,"network":crate::local::hex(&network),"height":"26",
        "fund_claims":[crate::local::hex(&claim_bytes)],"governance":[]});
    let request = json!({"version":1,"run_id":run,"network":crate::local::hex(&network),
        "genesis":crate::local::hex(&genesis().id()),"parent":crate::local::hex(&parent.id),
        "height":"26","bundle":{"version":1,"operations":bundle,"issuances":[]}});
    // Qualify the real inbox decoder and durable result, not the CLI's fresh
    // resident-status gate. No fabricated running-service status is installed.
    write_private(
        &destination.join("eng2-operations/request.json"),
        &serde_json::to_vec(&request).unwrap(),
    );
    let budget = p2p::Budget::new(64 * 1024 * 1024);
    let before = budget.available().unwrap();
    let started = Instant::now();
    let mut submission = mailbox.take(&parent, &budget).unwrap().unwrap();
    assert!(budget.available().unwrap() < before);
    let preparing = operations::result(&destination, &run).unwrap();
    assert_eq!(preparing["outcome"], "preparing");
    assert!(preparing["block_id"].is_null());
    let (operations, issuances) = submission.inputs();
    assert!(issuances.is_empty());
    let mut candidate = original.clone();
    candidate.fund_claims.clear();
    candidate.governance.clear();
    operations.unwrap().attach_to(&mut candidate).unwrap();
    assert_eq!(candidate.fund_claims[0].encode(), claim_bytes);
    assert_eq!(candidate, original);
    let accepted = owner.accept(&header, &candidate).unwrap();
    assert_eq!(accepted.execution_commitment(), header.execution_commitment);
    let fund_after = owner
        .engine()
        .state()
        .fund()
        .balance(spend.account)
        .unwrap();
    assert_eq!(
        fund_after.spent,
        fund_before.spent + u128::from(spend.amount)
    );
    assert_eq!(fund_after.spend_count, fund_before.spend_count + 1);
    submission.committed(&accepted, owner.store());
    drop(submission);
    assert_eq!(budget.available().unwrap(), before);
    let receipt = operations::result(&destination, &run).unwrap();
    assert_eq!(receipt["outcome"], "committed");
    assert_eq!(
        receipt["block_id"],
        crate::local::hex(&header.id().unwrap())
    );
    assert_eq!(owner.head().unwrap().id, header.id().unwrap());
    assert_eq!(
        owner.store().block(26).unwrap().1.fund_claims[0].encode(),
        claim_bytes
    );
    let commit_ms = started.elapsed().as_millis();
    drop(owner);
    {
        // Independently reopen only the public committed record. Native
        // verification already ran in Driver.accept; do not repeat that audit.
        let database = ReadOnlyDatabase::open(&database_path).unwrap();
        let transaction = database.begin_read().unwrap();
        let table = transaction.open_table(BLOCKS).unwrap();
        assert_eq!(table.len().unwrap(), 26);
        assert_eq!(table.get(26).unwrap().unwrap().value(), original_record);
    }
    let source_after = fs::metadata(&source_database).unwrap();
    assert_eq!(source_before.len(), source_after.len());
    assert_eq!(
        source_before.modified().unwrap(),
        source_after.modified().unwrap()
    );
    assert!(!destination.join("native-peer-identity.secret").exists());
    assert!(!destination.join(service::STATUS_FILE).exists());
    let report = json!({"scope":"public-fixture-owner-mailbox-native-replay",
        "proof_generation":false,"custody_reads":false,"resident_started":false,
        "cli_fresh_status_gate":"not_exercised","private_transaction_ingress":"blocked_missing_fee_opening",
        "encrypted_transaction_relay":"not_exercised","live_readiness":"not_qualified",
        "prefix_height":"25","height":"26","prefix_audit_ms":audit_ms.to_string(),
        "mailbox_to_durable_commit_ms":commit_ms.to_string(),"unchanged_public_claim":"passed",
        "native_driver_accept":"passed","fund_debit_and_counter":"passed",
        "reopened_public_record":"exact_match",
        "tip":crate::local::hex(&header.id().unwrap()),
        "execution_commitment":crate::local::hex(&header.execution_commitment)});
    write_private(
        &destination.join("operations-qualification.json"),
        &serde_json::to_vec(&report).unwrap(),
    );
    println!("{report}");
    // Preserve this explicitly selected disposable copy for independent review.
}

#[test]
#[ignore = "requires an explicitly supplied closed public native 28-block fixture"]
fn real_public_governance_crosses_synthetic_status_gate_and_native_durable_commit() {
    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    assert_ne!(std::env::var("CI").as_deref(), Ok("true"));
    let source = PathBuf::from(
        std::env::var_os("SIWORLD_ENG2_NATIVE_FIXTURE").expect("completed public fixture required"),
    );
    let destination = PathBuf::from(
        std::env::var_os("SIWORLD_ENG2_GOVERNANCE_FIXTURE")
            .expect("new disposable governance fixture required"),
    );
    assert!(source.is_absolute() && destination.is_absolute());
    assert_eq!(source.canonicalize().unwrap(), source);
    let source_metadata = fs::symlink_metadata(&source).unwrap();
    assert!(source_metadata.file_type().is_dir());
    assert_eq!(source_metadata.uid(), rustix::process::geteuid().as_raw());
    assert!(!destination.exists());
    let source_database = public_file(&source, "chain.redb");
    let source_before = fs::metadata(&source_database).unwrap();
    let genesis_bytes = fs::read(public_file(&source, "genesis.bin")).unwrap();
    let completed: Value =
        serde_json::from_slice(&fs::read(public_file(&source, "result.json")).unwrap()).unwrap();
    assert_eq!(completed["native_proof_blocks"], "28");
    assert_eq!(completed["durable_reopen_audit"], "passed");
    let genesis = || Genesis::decode(&genesis_bytes).unwrap();
    let network = genesis().config().network;
    let original_records = {
        // Read only two already public accepted records. No seed, signer,
        // wallet, identity, private sidecar or source database write is used.
        let database = ReadOnlyDatabase::open(&source_database).unwrap();
        let transaction = database.begin_read().unwrap();
        let table = transaction.open_table(BLOCKS).unwrap();
        assert_eq!(table.len().unwrap(), 28);
        [1u64, 2].map(|height| table.get(height).unwrap().unwrap().value().to_vec())
    };
    let imports = ImportLimits {
        chain: Limits {
            max_leaves: 1_000_000,
            max_nullifiers: 1_000_000,
            max_component_bytes: 64 * 1024 * 1024,
        },
        max_snapshot_bytes: 512 * 1024 * 1024,
    };
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&destination)
        .unwrap();
    assert_eq!(destination.canonicalize().unwrap(), destination);
    write_private(&destination.join("genesis.bin"), &genesis_bytes);
    let database_path = destination.join("chain.redb");
    let store = Store::create(&database_path, genesis(), imports.chain).unwrap();
    let verifier = NativeVerifier::new().unwrap();
    let mut owner = Driver::new(store, verifier, imports).unwrap();
    let policy = owner.engine().body_policy();
    let records = original_records.each_ref().map(|record| {
        let header = Header::decode(&record[..HEADER_BYTES], &network).unwrap();
        let body = Body::decode(&record[HEADER_BYTES..], network, header.height, policy).unwrap();
        assert_eq!(body.governance.len(), 1);
        assert!(body.fund_claims.is_empty() && body.issuances.is_empty());
        (header, body)
    });
    let started = Instant::now();
    owner.accept(&records[0].0, &records[0].1).unwrap();
    assert_eq!(owner.engine().state().governance().sequence(), 1);
    assert!(
        owner
            .engine()
            .state()
            .governance()
            .pending_issuance_fee()
            .is_some()
    );
    let parent = owner.head().unwrap();
    assert_eq!(parent.height, 1);
    assert_eq!(parent.id, records[1].0.parent);
    let run = crate::local::hex(&blake3::derive_key(
        "siworld eng2 public governance replay run v1",
        &records[1].0.id().unwrap(),
    ));
    let expected = crate::local::hex(&genesis().id());
    let mailbox = operations::Mailbox::open(&destination, &run, network, genesis().id()).unwrap();
    let action_bytes = records[1].1.governance[0].encode().unwrap();
    let bundle = json!({"version":1,"operations":{"version":1,"network":crate::local::hex(&network),"height":"2",
        "fund_claims":[],"governance":[crate::local::hex(&action_bytes)]},"issuances":[]});
    let public_bundle = destination.join("public-governance-bundle.json");
    write_private(&public_bundle, &serde_json::to_vec(&bundle).unwrap());
    // This status is explicitly synthetic. It exercises the unchanged public
    // submission gate, never resident liveness, peer readiness or real mining.
    service::atomic_json(
        &destination.join(service::STATUS_FILE),
        &json!({
            "schema_version":2,"run_id":run,"tip":crate::local::hex(&parent.id),"height":1,
            "network_id":crate::local::hex(&network),"genesis_id":expected,"mining_enabled":true,
            "ready":true,"phase":"synthetic_public_fixture","operations_error":null,
            "updated_unix_ms":unix_ms().unwrap(),"qualification_status_origin":"synthetic"
        }),
    )
    .unwrap();
    let submitted = Instant::now();
    let queued = operations::submit(
        &destination,
        &public_bundle,
        &run,
        &crate::local::hex(&parent.id),
        "2",
        &expected,
    )
    .unwrap();
    assert_eq!(queued["outcome"], "queued");
    assert!(queued["block_id"].is_null());
    let budget = p2p::Budget::new(64 * 1024 * 1024);
    let before = budget.available().unwrap();
    let mut submission = mailbox.take(&parent, &budget).unwrap().unwrap();
    assert_eq!(
        operations::result(&destination, &run).unwrap()["outcome"],
        "preparing"
    );
    let (operations, issuances) = submission.inputs();
    assert!(issuances.is_empty());
    let mut candidate = records[1].1.clone();
    candidate.governance.clear();
    operations.unwrap().attach_to(&mut candidate).unwrap();
    assert_eq!(candidate, records[1].1);
    let accepted = owner.accept(&records[1].0, &candidate).unwrap();
    assert_eq!(owner.engine().state().governance().sequence(), 2);
    assert!(
        owner
            .engine()
            .state()
            .governance()
            .pending_issuance_fee()
            .is_none()
    );
    assert_eq!(
        owner.engine().state().governance().issuance_fee_atoms(),
        5_000_000_000
    );
    submission.committed(&accepted, owner.store());
    drop(submission);
    assert_eq!(budget.available().unwrap(), before);
    let receipt = operations::result(&destination, &run).unwrap();
    assert_eq!(receipt["outcome"], "committed");
    assert_eq!(
        receipt["block_id"],
        crate::local::hex(&records[1].0.id().unwrap())
    );
    let public_record = crate::eng2_operations::records::committed_governance_records(&accepted)
        .unwrap()
        .unwrap();
    let parsed: Value = serde_json::from_slice(&public_record).unwrap();
    assert_eq!(parsed["governance_inclusions"][0]["sequence"], "2");
    assert_eq!(parsed["governance_inclusions"][0]["effective_height"], "2");
    write_private(
        &destination.join("governance-committed.json"),
        &public_record,
    );
    let commit_ms = submitted.elapsed().as_millis();
    let tip = owner.head().unwrap();
    assert_eq!(tip.height, 2);
    drop(owner);
    {
        let database = ReadOnlyDatabase::open(&database_path).unwrap();
        let transaction = database.begin_read().unwrap();
        let table = transaction.open_table(BLOCKS).unwrap();
        assert_eq!(table.len().unwrap(), 2);
        for (index, record) in original_records.iter().enumerate() {
            assert_eq!(
                table.get(index as u64 + 1).unwrap().unwrap().value(),
                record
            );
        }
    }
    assert_eq!(
        fs::read(destination.join("governance-committed.json")).unwrap(),
        public_record
    );
    let source_after = fs::metadata(&source_database).unwrap();
    assert_eq!(source_before.len(), source_after.len());
    assert_eq!(
        source_before.modified().unwrap(),
        source_after.modified().unwrap()
    );
    assert!(!destination.join("native-peer-identity.secret").exists());
    let report = json!({"scope":"synthetic-status-public-governance-native-durable-replay",
        "proof_generation":false,"reused_native_proof_blocks":2,"fresh_status":"synthetic",
        "headless_signature":"separately_qualified_with_existing_unit_keys","native_signature":"unchanged_public_h2_signature",
        "custody_reads":false,"rehearsal_seed_reads":false,"resident_started":false,
        "network_readiness":"not_qualified","submit_to_durable_commit_ms":commit_ms.to_string(),
        "total_replay_ms":started.elapsed().as_millis().to_string(),"height":"2","governance_sequence":"2",
        "pending_issuance_fee":false,"active_issuance_fee_atoms":"5000000000",
        "native_driver_accept":"passed","reopened_records":"exact_match",
        "tip":crate::local::hex(&tip.id),"execution_commitment":crate::local::hex(&records[1].0.execution_commitment)});
    write_private(
        &destination.join("governance-qualification.json"),
        &serde_json::to_vec(&report).unwrap(),
    );
    println!("{report}");
}
