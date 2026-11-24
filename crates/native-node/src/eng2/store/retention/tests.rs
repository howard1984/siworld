//! Cursor persistence and tamper detection, independent of native admission.
use super::*;
use std::path::PathBuf;
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let mut id = [0; 16];
        getrandom::fill(&mut id).unwrap();
        let path = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("proof-retention-{}", crate::local::hex(&id)));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
        }
        #[cfg(not(unix))]
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn fixture(dir: &Directory) -> (Database, crate::identity::NativeIdentity, Hash, Record) {
    let state = crate::eng2::snapshot::tests::bootstrap();
    let genesis = Genesis::seal(
        state.chain().config.clone(),
        state.governance().clone(),
        crate::eng2::genesis::FeeMode::LegacyMiner,
    )
    .unwrap();
    let identity =
        crate::identity::NativeIdentity::initialize(&dir.0, genesis.peer_binding()).unwrap();
    let database = Database::create(dir.0.join("cursor.redb")).unwrap();
    let record = Record {
        version: 1,
        genesis: genesis.id(),
        policy: Policy::miner(None).unwrap(),
        credited_seconds: 1,
        checkpoint: None,
        floor: 0,
        prefix: seed(genesis.id()),
        observed_through: 0,
        finality: BTreeMap::new(),
    };
    (database, identity, genesis.id(), record)
}
#[test]
fn cursor_and_body_deletion_share_an_atomic_transaction() {
    let dir = Directory::new();
    let (database, identity, genesis, mut record) = fixture(&dir);
    let tx = database.begin_write().unwrap();
    tx.open_table(BLOCKS)
        .unwrap()
        .insert(1, b"retained".as_slice())
        .unwrap();
    write_record(&tx, &record, &identity).unwrap();
    tx.commit().unwrap();
    {
        let tx = database.begin_write().unwrap();
        tx.open_table(BLOCKS).unwrap().remove(1).unwrap();
        record.credited_seconds += 1;
        write_record(&tx, &record, &identity).unwrap();
        // Dropping the uncommitted transaction must retain both old records.
    }
    let tx = database.begin_read().unwrap();
    assert!(tx.open_table(BLOCKS).unwrap().get(1).unwrap().is_some());
    assert_eq!(
        read_record(&tx.open_table(TABLE).unwrap(), genesis, &identity)
            .unwrap()
            .credited_seconds,
        1
    );
}
#[test]
fn cursor_rejects_unsigned_edits_missing_seals_and_other_identities() {
    let dir = Directory::new();
    let other = Directory::new();
    let (database, identity, genesis, record) = fixture(&dir);
    let (_, other_identity, _, _) = fixture(&other);
    let tx = database.begin_write().unwrap();
    write_record(&tx, &record, &identity).unwrap();
    tx.commit().unwrap();
    {
        let tx = database.begin_read().unwrap();
        assert!(read_record(&tx.open_table(TABLE).unwrap(), genesis, &other_identity).is_err());
    }
    let tx = database.begin_write().unwrap();
    let mut changed = record;
    changed.floor = 1;
    tx.open_table(TABLE)
        .unwrap()
        .insert("payload", changed.encode().unwrap().as_slice())
        .unwrap();
    tx.commit().unwrap();
    {
        let tx = database.begin_read().unwrap();
        assert!(read_record(&tx.open_table(TABLE).unwrap(), genesis, &identity).is_err());
    }
    let tx = database.begin_write().unwrap();
    tx.open_table(TABLE).unwrap().remove("seal").unwrap();
    tx.commit().unwrap();
    let tx = database.begin_read().unwrap();
    assert!(read_record(&tx.open_table(TABLE).unwrap(), genesis, &identity).is_err());
}
#[test]
fn permanent_prefix_rejects_receipt_and_digest_replacement() {
    let dir = Directory::new();
    let (database, identity, genesis, mut record) = fixture(&dir);
    let raw = b"permanent public fixture record";
    let id = *blake3::hash(raw).as_bytes();
    record.floor = 1;
    record.prefix = next(seed(genesis), 1, id);
    let tx = database.begin_write().unwrap();
    tx.open_table(PERMANENT_RECEIPTS)
        .unwrap()
        .insert(1, raw.as_slice())
        .unwrap();
    tx.open_table(PERMANENT_RECEIPT_IDS)
        .unwrap()
        .insert(1, id.as_slice())
        .unwrap();
    write_record(&tx, &record, &identity).unwrap();
    tx.commit().unwrap();
    assert_eq!(
        read_floor(&database.begin_read().unwrap(), genesis, &identity).unwrap(),
        1
    );
    let changed = b"replaced permanent public record";
    let tx = database.begin_write().unwrap();
    tx.open_table(PERMANENT_RECEIPTS)
        .unwrap()
        .insert(1, changed.as_slice())
        .unwrap();
    tx.open_table(PERMANENT_RECEIPT_IDS)
        .unwrap()
        .insert(1, blake3::hash(changed).as_bytes().as_slice())
        .unwrap();
    tx.commit().unwrap();
    assert!(read_floor(&database.begin_read().unwrap(), genesis, &identity).is_err());
}
#[test]
#[ignore = "owner-local only: inspects explicitly supplied disposable native fixture"]
fn existing_native_fixture_signer_compatibility() {
    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    let source = PathBuf::from(
        std::env::var_os("SIWORLD_PROOF_RETENTION_SOURCE")
            .expect("explicit disposable fixture required"),
    );
    assert!(source.is_absolute() && source.join("disposable-fixture").is_file());
    let genesis = Genesis::decode(&std::fs::read(source.join("genesis.bin")).unwrap()).unwrap();
    assert!(genesis.config().fixture);
    let keys = [3u8, 4, 5].map(|n| {
        *libcrux_ml_dsa::ml_dsa_65::generate_key_pair([n; 32])
            .verification_key
            .as_ref()
    });
    let matched = genesis.initial_governance().active_roster().keys() == &keys;
    println!(
        "{}",
        serde_json::json!({"known_public_fixture_signers":matched,"source_mutations":0,"proof_generation":false})
    );
}

/// Reuse a closed, minimum-work RandomX source without running a node or
/// generating proofs. The short miner threshold exercises physical body
/// deletion and the same permanent wallet reader used by service nodes.
#[cfg(all(unix, feature = "eng2-runtime"))]
#[test]
#[ignore = "owner-local only: requires a closed native RandomX H36 corpus"]
fn randomx_signed_floor_and_wallet_receipt_survive_proof_body_expiry() {
    use crate::eng2::{
        runtime_export::{
            PreparedCheckpoint, WalletPolicy,
            host::{Host, initialize_fixture_custody, vote_with_fixture_custody},
        },
        snapshot::ImportLimits,
        wallet_history::{self, Head, codec},
    };
    use libcrux_ml_dsa::ml_dsa_65;
    use std::time::Instant;

    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    let source = PathBuf::from(
        std::env::var_os("SIWORLD_PROOF_RETENTION_SOURCE").expect("closed fixture required"),
    );
    assert!(source.is_absolute() && source.join("disposable-fixture").is_file());
    let raw = std::fs::read(source.join("genesis.bin")).unwrap();
    assert_eq!(&raw[..8], b"SWE2POW5");
    let genesis = || Genesis::decode(&raw).unwrap();
    assert!(genesis().checkpoint_fork_choice());
    assert_eq!(genesis().config().genesis_target, [255; 32]);
    let keys = [3, 4, 5].map(|seed| {
        *ml_dsa_65::generate_key_pair([seed; 32])
            .verification_key
            .as_ref()
    });
    assert_eq!(
        genesis().initial_governance().active_roster().keys(),
        &keys,
        "known fixture signers required"
    );
    let limits = Limits {
        max_leaves: 1_000_000,
        max_nullifiers: 1_000_000,
        max_component_bytes: 64 * 1024 * 1024,
    };
    let imports = ImportLimits {
        chain: limits,
        max_snapshot_bytes: 64 * 1024 * 1024,
    };
    let directory = Directory::new();
    let identity =
        crate::identity::NativeIdentity::initialize(&directory.0, genesis().peer_binding())
            .unwrap();
    let mut store = Store::initialize_selected(&directory.0, genesis(), limits, identity).unwrap();
    let custody = Directory::new();
    let export = directory.0.join("public");
    let signers = [0, 1].map(|slot| {
        let key = custody.0.join(format!("fixture-signer-{slot}.bin"));
        initialize_fixture_custody(&key, &export, &store, slot);
        key
    });
    let verifier = NativeVerifier::for_genesis(&genesis()).unwrap();
    let original = redb::Database::builder()
        .set_cache_size(16 * 1024 * 1024)
        .open_read_only(source.join("chain.redb"))
        .unwrap();
    let read = original.begin_read().unwrap();
    let blocks = read.open_table(BLOCKS).unwrap();
    assert!(blocks.len().unwrap() >= 36);
    for height in 1..=36 {
        let row = blocks.get(height).unwrap().unwrap();
        let (header, body) = decode(store.engine(), row.value()).unwrap();
        store.append(&header, &body, &verifier).unwrap();
        if height % 12 == 0 {
            store.archive_checkpoint_anchor(imports).unwrap();
        }
    }
    let prepared = PreparedCheckpoint::prepare_from_archive(&store, imports)
        .unwrap()
        .unwrap();
    let statement = prepared.statement();
    assert_eq!(statement.checkpoint_height, 12);
    let votes = [
        vote_with_fixture_custody(&signers[0], &export, &store, &prepared, true),
        vote_with_fixture_custody(&signers[1], &export, &store, &prepared, false),
    ];
    let now = store.header(36).unwrap().timestamp;
    let certified = prepared.certify(&store, votes, now).unwrap();
    store.admit_finalized_checkpoint(&certified).unwrap();
    assert!(store.check_finalized_ancestor(11).is_err());
    assert!(store.check_finalized_ancestor(12).is_ok());

    let budget = crate::p2p::Budget::new(1024 * 1024 * 1024);
    let pins = crate::eng2::bootstrap::leases::Registry::default().body_pins(Instant::now());
    let head = Head::capture(&store).unwrap();
    let before = wallet_history::receipts(&store, &head, 1, &budget).unwrap();
    let digest = blake3::hash(before.bytes());
    let mut maintenance = Maintenance::new(Policy::miner(Some(24)).unwrap()).unwrap();
    let warmup = maintenance
        .tick(&mut store, Some(&certified), now, 0, &budget, &pins)
        .unwrap();
    assert_eq!(warmup.removed_blocks, 0);
    let report = maintenance
        .tick(&mut store, Some(&certified), now + 1, 1, &budget, &pins)
        .unwrap();
    assert!(report.removed_blocks > 0 && report.removed_encoded_bytes > 0);
    assert!(store.block(1).is_err());
    drop(store);

    let reopened = Store::resume_selected(&directory.0, genesis(), limits).unwrap();
    assert_eq!(
        reopened.finalized_checkpoint().unwrap().as_ref(),
        Some(certified.certificate())
    );
    assert!(reopened.block(1).is_err());
    assert_eq!(head, Head::capture(&reopened).unwrap());
    let after = wallet_history::receipts(&reopened, &head, 1, &budget).unwrap();
    assert_eq!(blake3::hash(after.bytes()), digest);
    let context = codec::Context::from_genesis(&raw, genesis().id()).unwrap();
    let header = reopened.header(1).unwrap().encode().unwrap();
    let decoded = codec::ReceiptBlock::decode(&context, &header, after.bytes()).unwrap();
    assert_eq!(decoded.transactions().len(), 16);
    let mut tampered = after.bytes().to_vec();
    let last = tampered.last_mut().expect("nonempty receipt");
    *last ^= 1;
    assert!(codec::ReceiptBlock::decode(&context, &header, &tampered).is_err());

    // Run the real publisher after deletion, starting with no cached wallet
    // receipts. An optional private output lets the HTTP and WASM adapters
    // consume the exact same generation in owner-local acceptance.
    use std::os::unix::fs::DirBuilderExt;
    let wallet_export = std::env::var_os("SIWORLD_FIXTURE_WALLET_EXPORT")
        .map(PathBuf::from)
        .unwrap_or_else(|| directory.0.join("wallet"));
    assert!(wallet_export.is_absolute());
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&wallet_export)
        .unwrap();
    let mut host = Host::open(&wallet_export, &reopened, imports, None).unwrap();
    host.enable_wallet_export(&reopened, WalletPolicy::default(), &budget)
        .unwrap();
    let progress = (0..=head.height())
        .map(|_| {
            host.tick_wallet_export(&reopened, now, &budget)
                .unwrap()
                .unwrap()
        })
        .find(|progress| progress.current)
        .expect("complete wallet export after body deletion");
    assert_eq!(progress.published_height, Some(head.height()));
    assert_eq!(host.wallet_export_diagnostic(), ("current", None));
    assert_eq!(
        std::fs::read(wallet_export.join("wallet-checkpoint-eng2.bin")).unwrap(),
        certified.certificate().encode().unwrap()
    );
    let filename = format!("wallet-1-{}.bin", crate::local::hex(&after.id()));
    assert_eq!(
        std::fs::read(wallet_export.join(filename)).unwrap(),
        after.bytes()
    );
    println!(
        "native_floor=12 native_head=36 signer_restore_abstained=true removed_body_bytes={} receipt_digest={digest}",
        report.removed_encoded_bytes
    );
}

/// Full native acceptance using existing public proofs; no miner, proof generation,
/// production key, live network or modification of the supplied source is used.
#[test]
#[ignore = "owner-local only: requires disposable complete native H38 fixture"]
fn real_store_prune_reopen_replay_and_signed_checkpoint_sync() {
    use crate::eng2::{
        admission::AdmissionPlan,
        certificate::Vote,
        runtime_export::PreparedCheckpoint,
        selection::{HeaderRules, VerifiedHeaders},
        snapshot::ImportLimits,
    };
    use libcrux_ml_dsa::ml_dsa_65;
    use siworld_core::pow::Work;
    use std::time::Instant;
    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    let source = PathBuf::from(
        std::env::var_os("SIWORLD_PROOF_RETENTION_SOURCE")
            .expect("explicit disposable fixture required"),
    );
    assert!(source.is_absolute() && source.join("disposable-fixture").is_file());
    let encoded = std::fs::read(source.join("genesis.bin")).unwrap();
    let genesis = || Genesis::decode(&encoded).unwrap();
    assert!(genesis().config().fixture);
    assert_eq!(genesis().config().genesis_target, [0xff; 32]);
    assert_eq!(genesis().config().pow_iterations, 0);
    let keys = [3u8, 4, 5].map(|n| {
        *ml_dsa_65::generate_key_pair([n; 32])
            .verification_key
            .as_ref()
    });
    assert_eq!(
        genesis().initial_governance().active_roster().keys(),
        &keys,
        "known public test signers required"
    );
    // This read-only fixture source is not a resident database. Keep its test
    // cache bounded instead of adding another default cache to the process.
    let source_db = redb::Database::builder()
        .set_cache_size(16 * 1024 * 1024)
        .open_read_only(source.join("chain.redb"))
        .unwrap();
    let source_tx = source_db.begin_read().unwrap();
    let source_blocks = source_tx.open_table(BLOCKS).unwrap();
    let record = |height| {
        source_blocks
            .get(height)
            .unwrap()
            .expect("H38 complete native history required")
            .value()
            .to_vec()
    };
    let limits = Limits {
        max_leaves: 1_000_000,
        max_nullifiers: 1_000_000,
        max_component_bytes: 64 * 1024 * 1024,
    };
    let imports = ImportLimits {
        chain: limits,
        max_snapshot_bytes: 64 * 1024 * 1024,
    };
    let directory = Directory::new();
    let identity =
        crate::identity::NativeIdentity::initialize(&directory.0, genesis().peer_binding())
            .unwrap();
    let path = directory.0.join("chain.redb");
    let mut store = Store::create(&path, genesis(), limits).unwrap();
    store.enable_authenticated_restart(identity).unwrap();
    let verifier = NativeVerifier::for_genesis(&genesis()).unwrap();
    let budget = crate::p2p::Budget::new(1024 * 1024 * 1024);
    let config = genesis().config().clone();
    let branch_rules = HeaderRules {
        network: config.network,
        genesis: genesis().id(),
        genesis_timestamp: config.genesis_timestamp,
        genesis_target: config.genesis_target,
        target_interval: config.target_interval,
        asert_half_life: config.asert_half_life(),
        pow_iterations: config.pow_iterations,
        pow_algorithm: config.pow_algorithm(),
        max_headers: 1000,
    };
    let mut branches = crate::eng2::branches::BranchStore::create(
        &directory.0.join("branches.redb"),
        branch_rules.clone(),
        crate::eng2::branches::Limits {
            maximum_headers: 1000,
            maximum_body_bytes: 4 * 1024 * 1024 * 1024,
        },
    )
    .unwrap();
    let start = Instant::now();
    let mut orphan = None;
    for height in 1..=36 {
        let (header, body) = decode(store.engine(), &record(height)).unwrap();
        let committed = store.append(&header, &body, &verifier).unwrap();
        branches
            .retain_committed(&header, &body, store.engine().body_policy(), &committed)
            .unwrap();
        if height % 12 == 0 {
            store.archive_checkpoint_anchor(imports).unwrap();
        }
        if height == 1 {
            let mut fork = header.clone();
            fork.nonce = fork.nonce.wrapping_add(1);
            let qualified =
                VerifiedHeaders::verify(branch_rules.clone(), vec![fork.clone()]).unwrap();
            branches.retain_verified_headers(&qualified).unwrap();
            branches
                .retain_body(&fork, &body, store.engine().body_policy())
                .unwrap();
            orphan = Some(fork);
        }
    }
    let original_tip = store.engine().state().tip();
    let published = 1_000_000;
    let vote = |prepared: &PreparedCheckpoint, slot: u8| Vote {
        slot,
        signature: *ml_dsa_65::sign(
            &ml_dsa_65::generate_key_pair([3 + slot; 32]).signing_key,
            &prepared.statement().encode().unwrap(),
            crate::eng2::certificate::Statement::signing_context(),
            [7 + slot; 32],
        )
        .unwrap()
        .as_ref(),
    };
    let prepared = PreparedCheckpoint::prepare_from_archive(&store, imports)
        .unwrap()
        .unwrap();
    assert_eq!(prepared.statement().checkpoint_height, 12);
    let votes = [vote(&prepared, 0), vote(&prepared, 1)];
    let mut forged = votes.clone();
    forged[1].signature[0] ^= 1;
    assert!(prepared.certify(&store, forged, published).is_err());
    let prepared = PreparedCheckpoint::prepare_from_archive(&store, imports)
        .unwrap()
        .unwrap();
    let checkpoint = prepared.certify(&store, votes, published).unwrap();
    let policy = Policy::miner(Some(24)).unwrap();
    let pins = crate::eng2::bootstrap::leases::Registry::default().body_pins(Instant::now());
    let mut maintenance = Maintenance::new(policy).unwrap();
    let mut tick = 0;
    let mut removed_bytes = 0;
    #[cfg(feature = "eng2-runtime")]
    {
        use crate::eng2::runtime_export::{PublicExport, host::Host};
        use std::time::Duration;
        let export_root = directory.0.join("retained-publication");
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&export_root)
            .unwrap();
        let mut export = PublicExport::open(&export_root, &store, imports).unwrap();
        assert!(
            export
                .publish_checkpoint(&store, &checkpoint, imports)
                .unwrap()
        );
        drop(export);
        // Fixture allowance, independent of any deployment budget.
        let checkpoint_budget = crate::p2p::Budget::new(2 * 1024 * 1024 * 1024);
        let mut host =
            Host::open_resident(&export_root, &store, imports, None, &checkpoint_budget).unwrap();
        // Replay the observed occupancy as reservation pressure. Its causes
        // cannot be distinguished from the historical failure counters.
        let historical_pressure = budget.reserve(1_048_274_467).unwrap();
        assert!(budget.reserve(38_736_346).is_err());
        assert!(host.pruning_checkpoint(&store).is_none());
        let deadline = Instant::now() + Duration::from_secs(120);
        while !host.reconcile_retained_async(&store, || Ok(None)).unwrap() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(host.pruning_checkpoint(&store).is_some());
        assert!(host.retained_failure_diagnostic().is_none());
        drop(historical_pressure);
        assert!(!host.reconcile_retained_async(&store, || Ok(None)).unwrap());
        assert!(host.latest_checkpoint().is_none());
        assert_eq!(
            host.pruning_checkpoint(&store).unwrap().certificate(),
            checkpoint.certificate(),
        );
        tick += 1;
        let pinned = host.pruning_checkpoint(&store);
        let warmup = maintenance
            .tick(&mut store, pinned, published + tick, tick, &budget, &pins)
            .unwrap();
        assert_eq!(warmup.paused, Some(Pause::ClockUncertain));
        assert_eq!(warmup.removed_blocks, 0);
        tick += 1;
        let pinned = host.pruning_checkpoint(&store);
        let report = maintenance
            .tick(&mut store, pinned, published + tick, tick, &budget, &pins)
            .unwrap();
        assert!(report.removed_blocks > 0 && report.removed_encoded_bytes > 0);
        assert!(report.paused.is_none());
        removed_bytes += report.removed_encoded_bytes;
        let unready_since = Instant::now();
        assert!(host.restoration_stalled(unready_since + Duration::from_secs(300)));
        std::fs::remove_file(export_root.join("checkpoint-eng2.json")).unwrap();
        assert!(host.pruning_checkpoint(&store).is_none());
        tick += 1;
        let blocked = maintenance
            .tick(&mut store, None, published + tick, tick, &budget, &pins)
            .unwrap();
        assert_eq!(blocked.paused, Some(Pause::CheckpointUnavailable));
        assert_eq!(blocked.removed_blocks, 0);
        host.pause_reorganization_exports_at(36).unwrap();
        assert!(host.pruning_checkpoint(&store).is_none());
        host.stop_preparation().unwrap();
        drop(host);
        let occupied = checkpoint_budget.reserve(1_048_274_467).unwrap();
        let request = checkpoint_budget.reserve(47_667_586).unwrap();
        drop((occupied, request));
    }

    let mut removed_branch_bytes = 0;
    let mut replayed = 0;
    {
        let mut prune = |store: &mut Store| {
            for _ in 0..40 {
                tick += 1;
                let report = maintenance
                    .tick(
                        store,
                        Some(&checkpoint),
                        published + tick,
                        tick,
                        &budget,
                        &pins,
                    )
                    .unwrap();
                removed_bytes += report.removed_encoded_bytes;
                if report.paused.is_none() {
                    let (_, bytes) = maintenance
                        .prune_branch_proofs(&mut branches, store, &pins, &budget)
                        .unwrap();
                    removed_branch_bytes += bytes;
                }
                if report.pruned_through == 12 {
                    return;
                }
            }
            panic!("bounded maintenance did not prune eligible prefix");
        };
        prune(&mut store);
        assert!(store.block(12).is_err());
        assert!(store.permanent_receipt(12).unwrap().is_some());
        assert!(store.block(13).is_ok());
        assert_eq!(store.engine().state().tip(), original_tip);
        drop(store);
        store = Store::resume_existing(&path, genesis(), limits).unwrap();
        assert_eq!(store.engine().state().tip(), original_tip);
        for depth in [1, 2, 7] {
            let ancestor = 36 - depth;
            let id = store.header(ancestor).unwrap().id().unwrap();
            store.restore_ancestor(ancestor, id).unwrap();
            for height in ancestor + 1..=36 {
                let (header, body) = decode(store.engine(), &record(height)).unwrap();
                store.append(&header, &body, &verifier).unwrap();
                replayed += 1;
            }
            assert_eq!(store.engine().state().tip(), original_tip);
            prune(&mut store);
        }
    }
    assert!(
        branches
            .entry(store.header(12).unwrap().id().unwrap())
            .unwrap()
            .is_some()
    );
    assert!(
        branches
            .body_size(store.header(12).unwrap().id().unwrap())
            .unwrap()
            .is_none()
    );
    assert!(
        branches
            .body_size(store.header(13).unwrap().id().unwrap())
            .unwrap()
            .is_some()
    );
    let orphan = orphan.unwrap();
    let orphan_id = orphan.id().unwrap();
    assert!(branches.body_size(orphan_id).unwrap().is_none());
    assert_eq!(
        branches.entry(orphan_id).unwrap().unwrap().status,
        crate::eng2::branches::Status::HeaderQualified
    );
    let public = branches
        .expired_public_record_for_test(orphan_id)
        .unwrap()
        .unwrap();
    let context =
        crate::eng2::wallet_history::codec::Context::from_genesis(&encoded, genesis().id())
            .unwrap();
    crate::eng2::wallet_history::codec::ReceiptBlock::decode(
        &context,
        &orphan.encode().unwrap(),
        &public,
    )
    .unwrap();
    // The branch assertions are complete; the independent fresh-node import
    // does not need this additional resident cache.
    drop(branches);
    // Checkpoint expiry and capability absence must not delete another body.
    let before = store
        .database
        .begin_read()
        .unwrap()
        .open_table(BLOCKS)
        .unwrap()
        .len()
        .unwrap();
    tick += 1;
    let missing = maintenance
        .tick(&mut store, None, published + tick, tick, &budget, &pins)
        .unwrap();
    assert_eq!(missing.paused, Some(Pause::CheckpointUnavailable));
    assert_eq!(missing.removed_blocks, 0);
    let stale = maintenance
        .tick(
            &mut store,
            Some(&checkpoint),
            published + policy::CHECKPOINT_STALE_SECONDS + 1,
            policy::CHECKPOINT_STALE_SECONDS + 1,
            &budget,
            &pins,
        )
        .unwrap();
    assert_eq!(stale.paused, Some(Pause::CheckpointStale));
    assert_eq!(stale.removed_blocks, 0);
    assert_eq!(
        store
            .database
            .begin_read()
            .unwrap()
            .open_table(BLOCKS)
            .unwrap()
            .len()
            .unwrap(),
        before
    );
    // Validation and the exact production template path still operate after expiry.
    let (header, body) = decode(store.engine(), &record(37)).unwrap();
    store.append(&header, &body, &verifier).unwrap();
    let (expected, body) = decode(store.engine(), &record(38)).unwrap();
    let template = store
        .engine()
        .prepare_header(&body, expected.timestamp, &verifier)
        .unwrap();
    let mut expected = expected;
    expected.nonce = 0;
    assert_eq!(template, expected);
    for height in 1..=37 {
        store
            .materialize_permanent_receipt(height, &budget)
            .unwrap();
    }
    let config = genesis().config().clone();
    let headers = (1..=37).map(|h| store.header(h).unwrap()).collect();
    let verified = VerifiedHeaders::verify(
        HeaderRules {
            network: config.network,
            genesis: genesis().id(),
            genesis_timestamp: config.genesis_timestamp,
            genesis_target: config.genesis_target,
            target_interval: config.target_interval,
            asert_half_life: config.asert_half_life(),
            pow_iterations: config.pow_iterations,
            pow_algorithm: config.pow_algorithm(),
            max_headers: 1000,
        },
        headers,
    )
    .unwrap();
    let plan = AdmissionPlan::select_signed(&[&verified], Work::one())
        .unwrap()
        .at_checkpoint(12, 13, 37)
        .unwrap();
    struct Source<'a>(&'a Store);
    impl crate::eng2::import::Source for Source<'_> {
        fn receipt(&mut self, height: u64, maximum: usize) -> Result<Vec<u8>, String> {
            let raw = self
                .0
                .permanent_receipt(height)?
                .ok_or("missing test receipt")?;
            if raw.len() > maximum {
                return Err("receipt test cap".into());
            }
            Ok(raw)
        }
        fn body(&mut self, height: u64, maximum: usize) -> Result<Vec<u8>, String> {
            let (_, body) = self.0.block(height)?;
            let raw = body.encode(self.0.engine().body_policy())?;
            if raw.len() > maximum {
                return Err("body test cap".into());
            }
            Ok(raw)
        }
    }
    let certificate = checkpoint.certificate().encode().unwrap();
    let witness = checkpoint
        .witness()
        .encode(limits.max_component_bytes)
        .unwrap();
    let verified = crate::eng2::import::verify(
        crate::eng2::import::Input {
            genesis: &encoded,
            pinned_genesis: genesis().id(),
            plan: &plan,
            certificate: &certificate,
            witness: &witness,
            snapshot: checkpoint.snapshot_bytes(),
        },
        &mut Source(&store),
        crate::eng2::import::Policy {
            state: imports,
            max_headers: 1000,
            max_verification_bytes: 4 * 1024 * 1024 * 1024,
        },
        || false,
    )
    .unwrap();
    let fresh = Directory::new();
    std::fs::write(fresh.0.join("genesis.bin"), &encoded).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            fresh.0.join("genesis.bin"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    crate::identity::NativeIdentity::initialize(&fresh.0, genesis().peer_binding()).unwrap();
    let synced = match verified
        .install(&fresh.0, &mut Source(&store), || false)
        .unwrap()
    {
        crate::eng2::import::Installation::Durable(store) => store,
        _ => panic!("test import durability unconfirmed"),
    };
    assert_eq!(synced.engine().state().height(), 37);
    assert_eq!(synced.engine().state().tip(), store.engine().state().tip());
    println!(
        "{}",
        serde_json::json!({"scope":"owner-local-real-native-proof-retention","native_initial_appends":36,"retained_replay_depths":[1,2,7],"native_replayed_blocks":replayed,"append_after_pruning":true,"exact_production_template_after_pruning":true,"authenticated_pruned_reopen":true,"pending_authenticated_deletion":cfg!(feature = "eng2-runtime"),"stalled_missing_cursor_blocked":cfg!(feature = "eng2-runtime"),"historical_shared_pressure_checkpoint_worker_isolated":cfg!(feature = "eng2-runtime"),"forged_signature_rejected":true,"missing_and_stale_checkpoint_paused":true,"fresh_two_of_three_import_height":37,"logical_encoded_bytes_removed":removed_bytes,"canonical_branch_duplicate_bytes_removed":removed_branch_bytes,"elapsed_seconds":start.elapsed().as_secs_f64(),"source_modified":false,"new_proof_generation":false,"mining":false,"physical_shrink_measured":false})
    );
}
