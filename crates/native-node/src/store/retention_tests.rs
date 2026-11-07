use super::*;
use crate::{
    fixtures::{TestVerifier, candidate},
    identity::NativeIdentity,
    p2p::Binding,
    storage_policy::{Role, SERVICE_RETENTION_SECONDS},
};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Directory(std::path::PathBuf);
impl Directory {
    fn new() -> Self {
        Self::with_config(Config::development([47; 32], 0).unwrap())
    }
    fn with_config(config: Config) -> Self {
        let path = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "siworld-proof-retention-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
        crate::local::initialize_config(&path, config.clone()).unwrap();
        NativeIdentity::initialize(&path, Binding::new(&config)).unwrap();
        Self(path)
    }
    fn open(&self) -> Store {
        Store::open(
            self.0.join("chain.redb"),
            crate::local::load(&self.0).unwrap(),
            &TestVerifier,
        )
        .unwrap()
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn append(store: &mut Store, count: u32, seed: u32) {
    for i in 0..count {
        let block = candidate(store.state(), seed + i * 100_000);
        store.append(&block, &TestVerifier).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn capacity_alarm_does_not_pause_any_role_or_change_retention_across_reopen() {
    for role in [
        Role::Bootstrap,
        Role::Validator,
        Role::Miner,
        Role::Ordinary,
    ] {
        let directory = Directory::new();
        let mut store = directory.open();
        store.configure_storage(role).unwrap();
        append(&mut store, 1, 100_000);
        let pressure = directory.0.join("capacity-pressure.fixture");
        std::fs::File::create_new(&pressure)
            .unwrap()
            .set_len(200_000_000_001)
            .unwrap();
        let service = role.serves_historical_proofs();
        assert!(store.storage_ingestion_ready().unwrap());
        let metrics = store.storage_metrics().unwrap();
        assert_eq!(metrics["storage_budget_exceeded"], service);
        assert_eq!(metrics["storage_ingestion_paused"], false);
        assert_eq!(metrics["storage_budget_behavior"], "alarm-only");
        assert_eq!(metrics["database_limit_bytes"], serde_json::Value::Null);
        assert_eq!(metrics["ingestion_limit_bytes"], serde_json::Value::Null);
        assert_eq!(metrics["auxiliary_limit_bytes"], serde_json::Value::Null);
        let admission =
            crate::storage_budget::auxiliary_write(&directory.0.join("status.json"), 1, false)
                .unwrap();
        drop(admission);
        append(&mut store, 1, 200_000);
        let expected = store.state().fingerprint();
        drop(store);
        let reopened = directory.open();
        assert_eq!(reopened.storage_role().unwrap(), Some(role));
        assert_eq!(reopened.state().height, 2);
        assert_eq!(reopened.state().fingerprint(), expected);
        assert!(reopened.storage_ingestion_ready().unwrap());
        assert_eq!(
            reopened.storage_metrics().unwrap()["storage_budget_exceeded"],
            service
        );
    }
}

#[test]
fn storage_capacity_failure_preserves_state_rewards_and_other_node_progress() {
    for branch_commit in [false, true] {
        let directory = Directory::new();
        let mut store = directory.open();
        store.configure_storage(Role::Validator).unwrap();
        let first = crate::producer::production_fixture(store.state(), 100_000);
        let first_id = first.block.id().unwrap();
        store
            .save_reward_receipt(&first_id, &first.reward_secret)
            .unwrap();
        store
            .append_produced(&first.block, &first.reward_secret, &TestVerifier)
            .unwrap();
        let expected = store.state().fingerprint();
        let rewards = store.miner_reward_view().unwrap();
        let config = store.state().config.clone();
        let accepted = store.state().clone();
        let base = store.storage_base.clone();
        drop(store);
        let path = directory.0.join("chain.redb");
        let before = std::fs::metadata(&path).unwrap().len();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let owner = receipts::Owner::bind(&path, &file).unwrap();
        // A real small file budget forces an allocator failure, without filling
        // the host disk or creating a 200 GB fixture.
        let limit = before + 4096;
        let database = Database::builder()
            .create_with_backend(
                crate::storage_budget::CappedBackend::with_limit(file, limit).unwrap(),
            )
            .unwrap();
        let mut store = Store {
            database,
            state: accepted,
            receipt_owner: owner,
            path: path.clone(),
            storage_base: base,
            retention_clock_started: false,
        };
        let mut next = crate::producer::production_fixture(store.state(), 300_000).block;
        next.settlement_proof = vec![1; crate::wire::MAX_SETTLEMENT_PROOF];
        for transaction in &mut next.transactions {
            transaction.proof = vec![1; 128 * 1024];
        }
        let result = if branch_commit {
            store
                .consider_branch(
                    1,
                    &[next],
                    CandidatePolicy::default(),
                    &StorageVerifier::new(false),
                )
                .map(|_| ())
                .map_err(|e| format!("{e:?}"))
        } else {
            store.append(&next, &StorageVerifier::new(false))
        };
        assert!(result.is_err());
        let reason = result.unwrap_err();
        assert!(
            reason.contains("write")
                || reason.contains("commit")
                || reason.contains("canonical attachment failed"),
            "unexpected failure: {reason}"
        );
        assert_eq!(store.state().fingerprint(), expected);
        drop(store);
        assert!(std::fs::metadata(&path).unwrap().len() <= limit);
        let store = directory.open();
        assert_eq!(store.state().fingerprint(), expected);
        assert_eq!(store.state().height, 1);
        assert_eq!(store.canonical_id(1).unwrap(), first_id);
        assert_eq!(store.verify_local_rewards().unwrap(), 1);
        assert_eq!(store.miner_reward_view().unwrap(), rewards);
        assert_eq!(store.storage_metrics().unwrap()["pruned_proof_blocks"], 0);
        let healthy_directory = Directory::with_config(config);
        let mut healthy = healthy_directory.open();
        healthy.append(&first.block, &TestVerifier).unwrap();
        assert_eq!(healthy.state().fingerprint(), expected);
        append(&mut healthy, 1, 400_000);
        assert_eq!(healthy.state().height, 2);
        assert_eq!(store.state().height, 1);
    }
}

#[test]
fn miner_expiry_keeps_ninety_six_proofs_and_reopens_identical_state() {
    let directory = Directory::new();
    let mut store = directory.open();
    store.configure_storage(Role::Miner).unwrap();
    append(&mut store, 100, 100_000);
    let before = store.state().fingerprint();
    let old_id = store.canonical_id(1).unwrap();
    // Retained detached evidence has the same permanent-data obligations.
    {
        let txn = store.database.begin_write().unwrap();
        let original = txn
            .open_table(BLOCKS)
            .unwrap()
            .get(1)
            .unwrap()
            .unwrap()
            .value()
            .to_vec();
        txn.open_table(DETACHED)
            .unwrap()
            .insert(old_id.as_slice(), encode_detached(&original).as_slice())
            .unwrap();
        txn.commit().unwrap();
    }
    assert_eq!(store.expire_proofs(1000, true, &TestVerifier).unwrap(), 4);
    assert_eq!(
        store.storage_metrics().unwrap()["retained_proof_blocks"],
        96
    );
    assert_eq!(store.storage_metrics().unwrap()["pruned_proof_blocks"], 4);
    assert!(!store.serves_historical_proofs().unwrap());
    assert_eq!(
        store.storage_metrics().unwrap()["detached_proof_body_bytes"],
        0
    );
    assert_eq!(store.detached_count().unwrap(), 1);
    let genesis = crate::wire::Snapshot {
        height: 0,
        block_id: store.state().config.genesis_id(),
    };
    assert!(crate::sync::serve_batch(&store, genesis, genesis, 1, 640 * 1024 * 1024).is_err());
    assert!(store.block(4).is_err());
    assert!(store.block(5).is_ok());
    assert_eq!(store.canonical_id(1).unwrap(), old_id);
    assert_eq!(store.state().fingerprint(), before);
    assert!(store.configure_storage(Role::Validator).is_err());
    drop(store);
    let mut store = directory.open();
    assert_eq!(store.state().fingerprint(), before);
    assert_eq!(store.state().height, 100);
    // A branch still reconstructs its ancestor from the local replay base.
    let ancestor = store
        .ancestor_state(99, 0, CandidatePolicy::default(), &TestVerifier)
        .unwrap();
    let first = candidate(&ancestor, 20_000_000);
    let mut branch = ancestor.clone();
    branch.apply(&first, &TestVerifier).unwrap();
    let second = candidate(&branch, 20_100_000);
    assert!(matches!(
        store
            .consider_branch(
                99,
                &[first, second],
                CandidatePolicy::default(),
                &TestVerifier
            )
            .unwrap(),
        BranchOutcome::Adopted { .. }
    ));
    assert_eq!(
        store.storage_metrics().unwrap()["retained_proof_blocks"],
        97
    );
    let expected = store.state().fingerprint();
    drop(store);
    assert_eq!(directory.open().state().fingerprint(), expected);
    // Altering a proof-free permanent record must invalidate the sealed prefix.
    let db = Database::open(directory.0.join("chain.redb")).unwrap();
    let txn = db.begin_write().unwrap();
    {
        let mut table = txn.open_table(BLOCKS).unwrap();
        let mut record = table.get(1).unwrap().unwrap().value().to_vec();
        let last = record.len() - 1;
        record[last] ^= 1;
        table.insert(1, record.as_slice()).unwrap();
    }
    txn.commit().unwrap();
    drop(db);
    assert!(
        Store::open_existing(
            directory.0.join("chain.redb"),
            crate::local::load(&directory.0).unwrap(),
            &TestVerifier
        )
        .is_err()
    );
}

/// Synthetic verifier for storage tests only. These bytes are not real STARKs.
struct StorageVerifier {
    reject_second: bool,
    settlements: std::cell::Cell<usize>,
}
impl StorageVerifier {
    fn new(reject_second: bool) -> Self {
        Self {
            reject_second,
            settlements: std::cell::Cell::new(0),
        }
    }
}
impl BlockVerifier for StorageVerifier {
    fn transaction(
        &self,
        public: &native::codec::PublicTransaction,
        context: &native::codec::ProofContext,
        fee: &native::multi_asset::Digest,
        root: &native::multi_asset::Digest,
        proof: &[u8],
    ) -> Result<(), String> {
        let _ = (public, context, fee, root);
        if !proof.is_empty() && proof.iter().all(|b| *b == 1) {
            Ok(())
        } else {
            Err("synthetic storage transaction rejected".into())
        }
    }
    fn settlement(
        &self,
        _: &[native::multi_asset::Digest],
        _: &native::settlement::RewardPlan,
        _: crate::wire::Hash,
        _: crate::wire::Hash,
        _: &[native::multi_asset::Digest],
        proof: &[u8],
    ) -> Result<(), String> {
        self.settlements.set(self.settlements.get() + 1);
        if (self.reject_second && self.settlements.get() == 2)
            || proof.is_empty()
            || proof.iter().any(|b| *b != 1)
        {
            Err("synthetic storage proof rejected".into())
        } else {
            Ok(())
        }
    }
}

#[test]
fn validator_expiry_uses_observed_finality_time_and_preserves_recovery() {
    let directory = Directory::new();
    let mut store = directory.open();
    // One deliberately large synthetic proof makes physical page reclamation
    // observable without manufacturing real production proof measurements.
    let produced = crate::producer::production_fixture(store.state(), 100_000);
    let mut first = produced.block;
    first.settlement_proof = vec![1; crate::wire::MAX_SETTLEMENT_PROOF];
    for transaction in &mut first.transactions {
        transaction.proof = vec![1; 128 * 1024];
    }
    let first_id = first.id().unwrap();
    store
        .save_reward_receipt(&first_id, &produced.reward_secret)
        .unwrap();
    store
        .append_produced(
            &first,
            &produced.reward_secret,
            &StorageVerifier::new(false),
        )
        .unwrap();
    append(&mut store, 25, 200_000);
    store.configure_storage(Role::Validator).unwrap();
    let expected = store.state().fingerprint();
    let reward_before = store.miner_reward_view().unwrap();
    let mut wallet = crate::wallet::Wallet::from_seed(
        store.state().config.network,
        zeroize::Zeroizing::new([42; 32]),
        0,
    )
    .unwrap();
    wallet
        .scan_light_data(store.state(), &[first.clone()], &[first_id], false)
        .unwrap();
    let balance_before = wallet.balances(store.state().height).unwrap();
    assert!(!balance_before.is_empty());
    let before_bytes = std::fs::metadata(directory.0.join("chain.redb"))
        .unwrap()
        .len();
    assert_eq!(store.expire_proofs(1000, true, &TestVerifier).unwrap(), 0);
    assert_eq!(
        store
            .expire_proofs(1000 + SERVICE_RETENTION_SECONDS - 1, true, &TestVerifier)
            .unwrap(),
        0
    );
    // Either a changed worked public header or a changed saved fingerprint on
    // the second row must roll back the already converted first row, its seal,
    // proof accounting and the clock observation in the same transaction.
    let original_second = {
        let txn = store.database.begin_read().unwrap();
        txn.open_table(BLOCKS)
            .unwrap()
            .get(2)
            .unwrap()
            .unwrap()
            .value()
            .to_vec()
    };
    for (offset, reason) in [
        (105, "storage finality belongs to another canonical block"),
        (
            original_second.len() - 1,
            "storage replay fingerprint mismatch",
        ),
    ] {
        let mut changed = original_second.clone();
        changed[offset] ^= 1;
        let txn = store.database.begin_write().unwrap();
        txn.open_table(BLOCKS)
            .unwrap()
            .insert(2, changed.as_slice())
            .unwrap();
        txn.commit().unwrap();
        let before = retention_snapshot(&store);
        assert_eq!(
            store
                .expire_proofs(
                    1000 + SERVICE_RETENTION_SECONDS,
                    true,
                    &StorageVerifier::new(true)
                )
                .unwrap_err(),
            reason
        );
        assert_eq!(retention_snapshot(&store), before);
        assert!(store.block(1).is_ok());
        assert_eq!(store.storage_base.as_ref().unwrap().height, 0);
        assert_eq!(store.state().fingerprint(), expected);
        assert_eq!(store.miner_reward_view().unwrap(), reward_before);
        let txn = store.database.begin_write().unwrap();
        txn.open_table(BLOCKS)
            .unwrap()
            .insert(2, original_second.as_slice())
            .unwrap();
        txn.commit().unwrap();
    }
    let unused_verifier = StorageVerifier::new(true);
    assert_eq!(
        store
            .expire_proofs(1000 + SERVICE_RETENTION_SECONDS, true, &unused_verifier)
            .unwrap(),
        2
    );
    assert_eq!(unused_verifier.settlements.get(), 0);
    assert_eq!(
        store.storage_metrics().unwrap()["retained_proof_blocks"],
        24
    );
    assert!(store.serves_historical_proofs().unwrap());
    assert_eq!(store.state().fingerprint(), expected);
    assert_eq!(store.verify_local_rewards().unwrap(), 1);
    assert_eq!(store.miner_reward_view().unwrap(), reward_before);
    let compact =
        crate::compact::CompactBlock::decode(&store.public_compact_block(1).unwrap()).unwrap();
    assert_eq!(compact.id, first_id);
    assert_eq!(compact.block.rewards, first.rewards);
    let mut recovered = crate::wallet::Wallet::from_seed(
        store.state().config.network,
        zeroize::Zeroizing::new([42; 32]),
        0,
    )
    .unwrap();
    recovered
        .scan_light_data(store.state(), &[compact.block], &[first_id], false)
        .unwrap();
    assert_eq!(
        recovered.balances(store.state().height).unwrap(),
        balance_before
    );
    assert_eq!(recovered.head().unwrap().0, store.state().height);
    drop(store);
    let mut store = directory.open();
    assert_eq!(store.state().fingerprint(), expected);
    store.compact_expired_storage(&TestVerifier).unwrap();
    let after_bytes = std::fs::metadata(directory.0.join("chain.redb"))
        .unwrap()
        .len();
    assert!(
        after_bytes < before_bytes,
        "compaction did not reclaim synthetic proof pages"
    );
    eprintln!(
        "synthetic_storage_measurement before_bytes={before_bytes} after_compact_bytes={after_bytes}"
    );
    assert_eq!(store.state().fingerprint(), expected);
    assert_eq!(store.miner_reward_view().unwrap(), reward_before);
}

/// Logical contents, rather than redb's abort-safe physical page allocation.
fn retention_snapshot(store: &Store) -> Vec<Vec<u8>> {
    let txn = store.database.begin_read().unwrap();
    let mut result = Vec::new();
    for row in txn.open_table(retention::STORAGE).unwrap().iter().unwrap() {
        let (key, value) = row.unwrap();
        let mut entry = key.value().as_bytes().to_vec();
        entry.push(0);
        entry.extend_from_slice(value.value());
        result.push(entry);
    }
    for row in txn.open_table(retention::FINALITY).unwrap().iter().unwrap() {
        let (height, value) = row.unwrap();
        let mut entry = height.value().to_le_bytes().to_vec();
        entry.extend_from_slice(value.value());
        result.push(entry);
    }
    for row in txn.open_table(BLOCKS).unwrap().iter().unwrap() {
        let (height, value) = row.unwrap();
        let mut entry = height.value().to_le_bytes().to_vec();
        entry.extend_from_slice(blake3::hash(value.value()).as_bytes());
        result.push(entry);
    }
    result
}

#[test]
fn restart_downtime_and_clock_steps_never_shorten_service_retention() {
    let directory = Directory::new();
    let mut store = directory.open();
    append(&mut store, 25, 100_000);
    store.configure_storage(Role::Bootstrap).unwrap();
    store.expire_proofs(1000, true, &TestVerifier).unwrap();
    assert_eq!(
        store
            .expire_proofs(1000 + SERVICE_RETENTION_SECONDS, false, &TestVerifier)
            .unwrap(),
        0
    );
    drop(store);
    let mut store = directory.open();
    let now = 1000 + 10 * SERVICE_RETENTION_SECONDS;
    // Unobserved downtime or a forward jump on restart cannot expire data.
    assert_eq!(store.expire_proofs(now, true, &TestVerifier).unwrap(), 0);
    assert_eq!(
        store
            .expire_proofs(now + SERVICE_RETENTION_SECONDS - 1, true, &TestVerifier)
            .unwrap(),
        0
    );
    // A backward discontinuity resets the certain-age window conservatively.
    assert_eq!(
        store.expire_proofs(now - 1, true, &TestVerifier).unwrap(),
        0
    );
    assert_eq!(
        store
            .expire_proofs(now - 1 + SERVICE_RETENTION_SECONDS, true, &TestVerifier)
            .unwrap(),
        1
    );
}

#[test]
fn modified_local_checkpoint_seal_is_rejected_before_replay() {
    let directory = Directory::new();
    let mut store = directory.open();
    store.configure_storage(Role::Ordinary).unwrap();
    drop(store);
    let db = Database::open(directory.0.join("chain.redb")).unwrap();
    let txn = db.begin_write().unwrap();
    {
        let mut table = txn.open_table(retention::STORAGE).unwrap();
        let mut seal = table.get("seal").unwrap().unwrap().value().to_vec();
        seal[0] ^= 1;
        table.insert("seal", seal.as_slice()).unwrap();
    }
    txn.commit().unwrap();
    drop(db);
    assert!(
        Store::open_existing(
            directory.0.join("chain.redb"),
            crate::local::load(&directory.0).unwrap(),
            &TestVerifier
        )
        .is_err()
    );
}

#[test]
fn explicit_role_selection_before_expiry_is_allowed_without_discarding_history() {
    let directory = Directory::new();
    let mut store = directory.open();
    store.configure_storage(Role::Ordinary).unwrap();
    assert!(!store.serves_historical_proofs().unwrap());
    store.configure_storage(Role::Validator).unwrap();
    assert_eq!(store.storage_role().unwrap(), Some(Role::Validator));
    assert!(store.serves_historical_proofs().unwrap());
    drop(store);
    assert_eq!(
        directory.open().storage_role().unwrap(),
        Some(Role::Validator)
    );
}

#[test]
fn nonfixture_service_retains_proofs_until_remote_checkpoint_delivery_is_qualified() {
    let config = Config::asert_development([48; 32], 1000, [255; 32], 1)
        .unwrap()
        .with_test_fund_registry()
        .unwrap();
    let directory = Directory::with_config(config);
    let mut store = directory.open();
    append(&mut store, 25, 100_000);
    store.configure_storage(Role::Validator).unwrap();
    let before = store.state().fingerprint();
    assert_eq!(store.expire_proofs(1000, true, &TestVerifier).unwrap(), 0);
    assert_eq!(
        store
            .expire_proofs(1000 + 10 * SERVICE_RETENTION_SECONDS, true, &TestVerifier)
            .unwrap(),
        0
    );
    assert!(store.block(1).is_ok());
    assert_eq!(
        store.storage_metrics().unwrap()["expiry_state"],
        "checkpoint_delivery_unavailable"
    );
    assert_eq!(
        store.storage_metrics().unwrap()["remote_checkpoint_bootstrap"],
        false
    );
    assert_eq!(store.state().fingerprint(), before);
}
