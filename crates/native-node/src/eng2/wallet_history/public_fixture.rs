//! Opt-in receipt qualification against closed, previously verified public history.
//! Only an explicitly selected new copy is audited; no wallet custody is opened.
use super::*;
use crate::{
    eng2::{
        genesis::Genesis, runtime_export::PublicExport, snapshot::ImportLimits,
        state_components::Limits,
    },
    proofs::NativeVerifier,
};
use native::codec::{PublicTransaction, encode_digest};
use redb::{ReadOnlyDatabase, ReadableDatabase, ReadableTableMetadata, TableDefinition};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Instant,
};

const BLOCKS: TableDefinition<u64, &[u8]> = TableDefinition::new("eng2-canonical-blocks-v1");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("eng2-canonical-meta-v1");

fn public_file(directory: &Path, name: &str) -> (PathBuf, fs::Metadata) {
    let path = directory.join(name);
    let metadata = fs::symlink_metadata(&path).expect("explicit public fixture file required");
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(metadata.nlink(), 1);
    (path, metadata)
}

fn unchanged(path: &Path, before: &fs::Metadata) {
    let after = fs::symlink_metadata(path).unwrap();
    assert!(after.file_type().is_file());
    assert_eq!(before.dev(), after.dev());
    assert_eq!(before.ino(), after.ino());
    assert_eq!(before.len(), after.len());
    assert_eq!(before.modified().unwrap(), after.modified().unwrap());
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
fn actual_accepted_history_exports_authenticated_public_receipts() {
    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    assert_ne!(std::env::var("CI").as_deref(), Ok("true"));
    let started = Instant::now();
    let source = PathBuf::from(
        std::env::var_os("SIWORLD_ENG2_NATIVE_FIXTURE")
            .expect("set the completed public native fixture directory"),
    );
    let destination = PathBuf::from(
        std::env::var_os("SIWORLD_ENG2_RECEIPT_FIXTURE")
            .expect("set a new registered owner-only receipt qualification directory"),
    );
    assert!(source.is_absolute() && destination.is_absolute());
    assert_eq!(source.canonicalize().unwrap(), source);
    let source_metadata = fs::symlink_metadata(&source).unwrap();
    assert!(source_metadata.file_type().is_dir());
    assert_eq!(source_metadata.uid(), rustix::process::geteuid().as_raw());
    assert!(!destination.exists());
    let parent = destination.parent().unwrap();
    assert_eq!(parent.canonicalize().unwrap(), parent);
    let parent_metadata = fs::symlink_metadata(parent).unwrap();
    assert!(parent_metadata.file_type().is_dir());
    assert_eq!(parent_metadata.uid(), rustix::process::geteuid().as_raw());
    let (source_database, source_before) = public_file(&source, "chain.redb");
    let (source_genesis, genesis_before) = public_file(&source, "genesis.bin");
    let (source_result, result_before) = public_file(&source, "result.json");
    let genesis_bytes = fs::read(&source_genesis).unwrap();
    let completed: Value = serde_json::from_slice(&fs::read(&source_result).unwrap()).unwrap();
    assert_eq!(completed["native_proof_blocks"], "28");
    assert_eq!(completed["durable_reopen_audit"], "passed");
    let genesis = || Genesis::decode(&genesis_bytes).unwrap();
    let original_head = {
        // Open only the closed public source through the actual read-only backend.
        // Do not derive wallet, seed, signer, sidecar or peer-identity paths.
        let database = ReadOnlyDatabase::open(&source_database).unwrap();
        let transaction = database.begin_read().unwrap();
        assert_eq!(transaction.open_table(BLOCKS).unwrap().len().unwrap(), 28);
        let table = transaction.open_table(META).unwrap();
        assert_eq!(
            table.get("genesis").unwrap().unwrap().value(),
            genesis_bytes
        );
        table.get("head").unwrap().unwrap().value().to_vec()
    };
    assert_eq!(
        u64::from_le_bytes(original_head[..8].try_into().unwrap()),
        28
    );
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&destination)
        .unwrap();
    assert_eq!(destination.canonicalize().unwrap(), destination);
    write_private(&destination.join("genesis.bin"), &genesis_bytes);
    let copy_started = Instant::now();
    let database_path = destination.join("chain.redb");
    fs::copy(&source_database, &database_path).unwrap();
    fs::set_permissions(&database_path, fs::Permissions::from_mode(0o600)).unwrap();
    let copy_ms = copy_started.elapsed().as_millis();
    let copy_before = fs::metadata(&database_path).unwrap();
    assert_eq!(source_before.len(), copy_before.len());
    let imports = ImportLimits {
        chain: Limits {
            max_leaves: 1_000_000,
            max_nullifiers: 1_000_000,
            max_component_bytes: 64 * 1024 * 1024,
        },
        max_snapshot_bytes: 512 * 1024 * 1024,
    };
    let verifier = NativeVerifier::new().unwrap();
    let audit_started = Instant::now();
    // One native audit of the intact new copy. No proof is generated, no block
    // is truncated or replayed through admission, and no resident is started.
    let store = Store::audit_existing(&database_path, genesis(), imports.chain, &verifier).unwrap();
    let audit_ms = audit_started.elapsed().as_millis();
    let head = Head::capture(&store).unwrap();
    assert_eq!(head.height(), 28);
    assert_eq!(head.tip(), original_head[8..40]);
    assert_eq!(completed["tip"], crate::local::hex(&head.tip()));
    let export_directory = destination.join("public-export");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&export_directory)
        .unwrap();
    let exporter = PublicExport::open(&export_directory, &store, imports).unwrap();
    let published = store.header(head.height()).unwrap().timestamp;
    let published_head = exporter.publish_wallet_head(&store, published).unwrap();
    assert_eq!(published_head, head);
    assert_eq!(
        fs::read(export_directory.join("wallet-genesis.bin")).unwrap(),
        genesis_bytes
    );
    let context = Context::from_genesis(&genesis_bytes, genesis().id()).unwrap();
    let projected: Value =
        serde_json::from_slice(&fs::read(export_directory.join("wallet-head.json")).unwrap())
            .unwrap();
    assert_eq!(projected, head.projection(published).unwrap());
    let budget = p2p::Budget::new(512 * 1024 * 1024);
    let available = budget.available().unwrap();
    let exports_started = Instant::now();
    let header_name = exporter
        .publish_wallet_headers(&store, &head, 1, 28, &budget)
        .unwrap();
    assert_eq!(budget.available().unwrap(), available);
    let header_bytes = fs::read(export_directory.join(header_name)).unwrap();
    let page =
        codec::HeaderPage::decode(&context, (head.height(), head.tip()), &header_bytes).unwrap();
    assert_eq!(page.from, 1);
    assert_eq!(page.headers.len(), 28);
    for (index, header) in page.headers.iter().enumerate() {
        assert_eq!(
            header.encode().unwrap(),
            store.header(index as u64 + 1).unwrap().encode().unwrap()
        );
    }
    let mut rows = Vec::new();
    for height in [26, 28] {
        let export_started = Instant::now();
        let name = exporter
            .publish_wallet_receipts(&store, &head, height, &budget)
            .unwrap();
        assert_eq!(budget.available().unwrap(), available);
        let bytes = fs::read(export_directory.join(name)).unwrap();
        assert!(bytes.len() <= codec::MAX_RECEIPT_BYTES);
        let (header, body) = store.block(height).unwrap();
        let encoded_header = header.encode().unwrap();
        let decoded = ReceiptBlock::decode(&context, &encoded_header, &bytes).unwrap();
        assert_eq!(decoded.header().encode().unwrap(), encoded_header);
        assert_eq!(decoded.body_bytes(), store.block_size(height).unwrap());
        assert_eq!(decoded.reward_mode(), body.reward_mode);
        assert_eq!(decoded.rewards(), body.rewards);
        assert_eq!(
            decoded.transactions(),
            body.transactions
                .iter()
                .map(|tx| tx.record.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            decoded.fund_outputs(),
            body.fund_claims
                .iter()
                .map(|claim| claim.spend.clone())
                .collect::<Vec<_>>()
        );
        let expected_issuances = body
            .issuances
            .iter()
            .map(|record| {
                let mut public = record.clone();
                public.proof.clear();
                public
            })
            .collect::<Vec<_>>();
        assert_eq!(decoded.issuances(), expected_issuances);
        let mut expected_outputs = Vec::new();
        for tx in &body.transactions {
            let public = PublicTransaction::decode(&tx.record.body).unwrap();
            expected_outputs.extend(public.cm.iter().map(encode_digest));
            assert!(decoded.contains_statement(&tx.record.statement_id(&context.config().network)));
        }
        for record in &body.issuances {
            expected_outputs.extend(
                record
                    .signed
                    .declaration
                    .note_commitments
                    .iter()
                    .map(encode_digest),
            );
        }
        expected_outputs.extend(body.rewards.iter().map(|record| record.commitment));
        expected_outputs.extend(body.fund_claims.iter().map(|claim| claim.spend.commitment));
        assert_eq!(decoded.outputs().unwrap(), expected_outputs);
        if height == 26 {
            assert_eq!(body.fund_claims.len(), 1);
        }
        rows.push(json!({"height":height.to_string(),"canonical_body_bytes":decoded.body_bytes().to_string(),
            "receipt_bytes":bytes.len().to_string(),"all_transaction_slots":decoded.transactions().len().to_string(),
            "fund_outputs":decoded.fund_outputs().len().to_string(),"issuances":decoded.issuances().len().to_string(),
            "outputs":expected_outputs.len().to_string(),"export_decode_compare_ms":export_started.elapsed().as_millis().to_string(),
            "header_exact":"passed","public_records_exact":"passed","output_order_exact":"passed",
            "statement_inclusion":"passed","body_length_exact":"passed"}));
    }
    let export_ms = exports_started.elapsed().as_millis();
    head.check_current(&store).unwrap();
    drop(exporter);
    drop(store);
    let copy_after = fs::metadata(&database_path).unwrap();
    unchanged(&source_database, &source_before);
    unchanged(&source_genesis, &genesis_before);
    unchanged(&source_result, &result_before);
    let mut artifact_bytes = 0u64;
    for entry in fs::read_dir(&export_directory).unwrap() {
        let entry = entry.unwrap();
        let metadata = fs::symlink_metadata(entry.path()).unwrap();
        assert!(metadata.file_type().is_file());
        artifact_bytes += metadata.len();
    }
    let report = json!({"scope":"closed-public-history-wallet-receipt-export",
        "proof_generation":false,"custody_reads":false,"resident_started":false,"network_access":false,
        "browser_sync":"not_exercised","retention_before_pruning":"not_implemented",
        "accepted_height":"28","tip":crate::local::hex(&head.tip()),"native_audits":"1",
        "copy_ms":copy_ms.to_string(),"native_audit_ms":audit_ms.to_string(),"exports_ms":export_ms.to_string(),
        "total_ms":started.elapsed().as_millis().to_string(),"source_unchanged":"passed",
        "database_bytes_before_audit":copy_before.len().to_string(),"database_bytes_after_audit":copy_after.len().to_string(),
        "database_allocated_bytes_after_audit":(copy_after.blocks()*512).to_string(),
        "public_artifact_bytes":artifact_bytes.to_string(),"header_page_bytes":header_bytes.len().to_string(),
        "header_page_exact":"passed","rows":rows});
    write_private(
        &destination.join("receipt-qualification.json"),
        &serde_json::to_vec(&report).unwrap(),
    );
    println!("{report}");
    // Preserve this explicitly registered public-data copy for independent review.
}
