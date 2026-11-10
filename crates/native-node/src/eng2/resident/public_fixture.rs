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
