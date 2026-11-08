use super::*;
use crate::state::BlockVerifier;
use crate::wire::{
    DigestBytes, Hash, PUBLIC_BYTES, PublicRecord, REWARD_CIPHERTEXT_BYTES, RewardRecord,
    Transaction,
};
use native::codec::{ProofContext, PublicTransaction, encode_digest};
use native::multi_asset::{Digest, F};
use p3_field::PrimeCharacteristicRing;
use std::cell::Cell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);
impl TestDir {
    fn new() -> Self {
        let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        loop {
            let path = base.join(format!(
                "siworld-native-store-{}-{}",
                std::process::id(),
                NEXT_DIR.fetch_add(1, Ordering::Relaxed)
            ));
            #[cfg(not(windows))]
            let created = std::fs::create_dir(&path);
            #[cfg(windows)]
            let created = if path.exists() {
                Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists))
            } else {
                siworld_miner_platform::Directory::create(&path)
                    .map(|_| ())
                    .map_err(std::io::Error::other)
            };
            match created {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("cannot create synthetic test directory: {error}"),
            }
        }
    }
    fn db(&self) -> PathBuf {
        self.0.join("chain.redb")
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
struct TestVerifier {
    transactions: Cell<usize>,
    settlements: Cell<usize>,
    reject: bool,
}
impl BlockVerifier for TestVerifier {
    fn transaction(
        &self,
        _: &PublicTransaction,
        _: &ProofContext,
        _: &Digest,
        _: &Digest,
        proof: &[u8],
    ) -> Result<(), String> {
        self.transactions.set(self.transactions.get() + 1);
        if !self.reject && proof == [1] {
            Ok(())
        } else {
            Err("test transaction rejection".into())
        }
    }
    fn settlement(
        &self,
        _: &[Digest],
        _: &native::settlement::RewardPlan,
        _: Hash,
        _: Hash,
        _: &[Digest],
        proof: &[u8],
    ) -> Result<(), String> {
        self.settlements.set(self.settlements.get() + 1);
        if !self.reject && proof == [1] {
            Ok(())
        } else {
            Err("test settlement rejection".into())
        }
    }
}
fn config() -> Config {
    Config::development([91; 32], 0).unwrap()
}
fn felt(value: u32) -> DigestBytes {
    let mut digest = [F::ZERO; 12];
    digest[0] = F::from_u32(value);
    encode_digest(&digest)
}
fn candidate(state: &State, seed: u32) -> Block {
    let mut transactions = Vec::new();
    for i in 0..64u32 {
        let mut body = [0; PUBLIC_BYTES];
        for j in 0..5u32 {
            body[j as usize * 48..(j as usize + 1) * 48].copy_from_slice(&felt(seed + i * 5 + j));
        }
        transactions.push(Transaction {
            record: PublicRecord::new(state.tip_snapshot().selector, body, felt(seed + 10000 + i))
                .unwrap(),
            proof: vec![1],
        });
    }
    transactions.sort_by_key(|tx| tx.record.statement_id(&state.config.network));
    let mut block = Block {
        network: state.config.network,
        height: state.height + 1,
        parent: state.tip,
        timestamp: state.timestamp() + state.config.target_interval,
        target: state.next_target(),
        nonce: 0,
        transactions,
        reward_mode: crate::state::RewardMode::Voyager,
        rewards: vec![RewardRecord {
            commitment: felt(seed + 20000),
            ciphertext: [0; REWARD_CIPHERTEXT_BYTES],
        }],
        fund_spends: Vec::new(),
        issuances: Vec::new(),
        settlement_proof: vec![1],
    };
    let seed = block.pow_seed().unwrap();
    while !siworld_core::pow::meets_target(
        &siworld_core::pow::pow_hash(&seed, block.nonce, state.config.pow_iterations),
        &block.target,
    ) {
        block.nonce += 1;
    }
    block
}
fn populated(path: &Path) -> (Block, Hash) {
    let mut store = Store::open(path, config(), &TestVerifier::default()).unwrap();
    let block = candidate(store.state(), 1);
    store.append(&block, &TestVerifier::default()).unwrap();
    (block, store.state().fingerprint())
}
fn tamper(path: &Path, operation: impl FnOnce(&redb::WriteTransaction)) {
    let db = Database::open(path).unwrap();
    let txn = db.begin_write().unwrap();
    operation(&txn);
    txn.commit().unwrap();
}

#[test]
fn initializes_once_and_reopens_genesis() {
    let dir = TestDir::new();
    let store = Store::open(dir.db(), config(), &TestVerifier::default()).unwrap();
    let initial = store.state().fingerprint();
    assert_eq!(store.state().height, 0);
    drop(store);
    let reopened = Store::open(dir.db(), config(), &TestVerifier::default()).unwrap();
    assert_eq!(reopened.state().fingerprint(), initial);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(dir.db()).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn existing_only_open_never_reinitializes_missing_history() {
    let dir = TestDir::new();
    assert!(Store::open_existing(dir.db(), config(), &TestVerifier::default()).is_err());
    assert!(!dir.db().exists());
    populated(&dir.db());
    let moved = dir.0.join("preserved.redb");
    std::fs::rename(dir.db(), &moved).unwrap();
    assert!(Store::open_existing(dir.db(), config(), &TestVerifier::default()).is_err());
    assert!(!dir.db().exists());
    assert_eq!(
        Store::open_existing(moved, config(), &TestVerifier::default())
            .unwrap()
            .state()
            .height,
        1
    );
}

#[test]
fn replays_every_transaction_and_settlement_in_every_block() {
    let dir = TestDir::new();
    let mut store = Store::open(dir.db(), config(), &TestVerifier::default()).unwrap();
    for seed in [1, 100000] {
        let block = candidate(store.state(), seed);
        store.append(&block, &TestVerifier::default()).unwrap();
    }
    let expected = store.state().fingerprint();
    drop(store);
    let verifier = TestVerifier::default();
    let reopened = Store::open(dir.db(), config(), &verifier).unwrap();
    assert_eq!(reopened.state().height, 2);
    assert_eq!(reopened.state().fingerprint(), expected);
    assert_eq!(verifier.transactions.get(), 128);
    assert_eq!(verifier.settlements.get(), 2);
    let block = reopened.block(1).unwrap();
    assert_eq!(block.height, 1);
    assert_eq!(block.transactions.len(), 64);
    assert!(reopened.block(0).is_err());
    assert!(reopened.block(3).is_err());
}

#[test]
fn replay_does_not_trust_the_saved_fingerprint_in_place_of_proofs() {
    let dir = TestDir::new();
    populated(&dir.db());
    let verifier = TestVerifier {
        reject: true,
        ..Default::default()
    };
    assert!(Store::open(dir.db(), config(), &verifier).is_err());
    assert_eq!(verifier.transactions.get(), 1);
}

fn restart_identity(dir: &TestDir) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    crate::identity::NativeIdentity::initialize(&dir.0, crate::p2p::Binding::new(&config()))
        .unwrap();
}

#[test]
fn authenticated_restart_does_not_repeat_committed_proof_verification() {
    let dir = TestDir::new();
    restart_identity(&dir);
    let mut store = Store::open(dir.db(), config(), &TestVerifier::default()).unwrap();
    for seed in [1, 100_000] {
        let block = candidate(store.state(), seed);
        store.append(&block, &TestVerifier::default()).unwrap();
    }
    let expected = store.state().fingerprint();
    drop(store);
    let verifier = TestVerifier {
        reject: true,
        ..Default::default()
    };
    let resumed = Store::resume_existing(dir.db(), config(), &verifier).unwrap();
    assert_eq!(resumed.state().fingerprint(), expected);
    assert_eq!(verifier.transactions.get(), 0);
    assert_eq!(verifier.settlements.get(), 0);
    drop(resumed);
    // The independent offline audit continues to verify every retained proof.
    assert!(Store::open_existing(dir.db(), config(), &verifier).is_err());
}

#[test]
fn miner_initialization_resumes_existing_history_and_preserves_its_seal() {
    let dir = TestDir::new();
    restart_identity(&dir);
    assert!(Store::resume_existing(dir.db(), config(), &TestVerifier::default()).is_err());
    let mut store = Store::open_or_resume(dir.db(), config(), &TestVerifier::default()).unwrap();
    let block = candidate(store.state(), 1);
    store.append(&block, &TestVerifier::default()).unwrap();
    let seal = store
        .database
        .begin_read()
        .unwrap()
        .open_table(resume::RESUME)
        .unwrap()
        .get("seal")
        .unwrap()
        .unwrap()
        .value()
        .to_vec();
    drop(store);
    let verifier = TestVerifier {
        reject: true,
        ..Default::default()
    };
    let resumed = Store::open_or_resume(dir.db(), config(), &verifier).unwrap();
    assert_eq!(resumed.state().height, 1);
    assert_eq!(verifier.transactions.get(), 0);
    let read = resumed.database.begin_read().unwrap();
    assert_eq!(
        read.open_table(resume::RESUME)
            .unwrap()
            .get("seal")
            .unwrap()
            .unwrap()
            .value(),
        seal
    );
}

#[test]
fn authenticated_restart_verifies_only_a_committed_tail_after_the_seal() {
    let dir = TestDir::new();
    restart_identity(&dir);
    let (first, _) = populated(&dir.db());
    let mut accepted = State::new(config()).unwrap();
    accepted.apply(&first, &TestVerifier::default()).unwrap();
    let second = candidate(&accepted, 100_000);
    accepted.apply(&second, &TestVerifier::default()).unwrap();
    let mut record = second.encode().unwrap();
    record.extend_from_slice(&accepted.fingerprint());
    tamper(&dir.db(), |transaction| {
        transaction
            .open_table(BLOCKS)
            .unwrap()
            .insert(2, record.as_slice())
            .unwrap();
        transaction
            .open_table(META)
            .unwrap()
            .insert("head", head(&accepted).as_slice())
            .unwrap();
    });
    let verifier = TestVerifier::default();
    let resumed = Store::resume_existing(dir.db(), config(), &verifier).unwrap();
    assert_eq!(resumed.state().fingerprint(), accepted.fingerprint());
    assert_eq!(verifier.transactions.get(), 64);
    assert_eq!(verifier.settlements.get(), 1);
}

#[test]
fn legacy_restart_performs_one_audit_then_reuses_the_verified_commit() {
    let dir = TestDir::new();
    populated(&dir.db());
    restart_identity(&dir);
    let verifier = TestVerifier::default();
    drop(Store::resume_existing(dir.db(), config(), &verifier).unwrap());
    assert_eq!(verifier.transactions.get(), 64);
    let verifier = TestVerifier::default();
    drop(Store::resume_existing(dir.db(), config(), &verifier).unwrap());
    assert_eq!(verifier.transactions.get(), 0);
    assert_eq!(verifier.settlements.get(), 0);
}

#[test]
fn aborted_or_rejected_updates_preserve_the_authenticated_restart_boundary() {
    let dir = TestDir::new();
    restart_identity(&dir);
    let (first, expected) = populated(&dir.db());
    let mut store = Store::resume_existing(dir.db(), config(), &TestVerifier::default()).unwrap();
    let mut second = candidate(store.state(), 100_000);
    second.transactions[63].proof = vec![0];
    assert!(store.append(&second, &TestVerifier::default()).is_err());
    {
        let transaction = store.database.begin_write().unwrap();
        transaction.open_table(BLOCKS).unwrap().remove(1).unwrap();
        transaction
            .open_table(META)
            .unwrap()
            .insert("head", [0u8; 72].as_slice())
            .unwrap();
        // No commit: the prior state and its authenticated seal remain atomic.
    }
    drop(store);
    let verifier = TestVerifier {
        reject: true,
        ..Default::default()
    };
    let resumed = Store::resume_existing(dir.db(), config(), &verifier).unwrap();
    assert_eq!(resumed.state().fingerprint(), expected);
    assert_eq!(resumed.block(1).unwrap(), first);
    assert_eq!(verifier.transactions.get(), 0);
}

#[test]
fn malformed_or_foreign_restart_records_are_rejected_without_replacement() {
    for key in ["state", "rewards", "seal"] {
        let dir = TestDir::new();
        restart_identity(&dir);
        populated(&dir.db());
        let mut changed = Vec::new();
        tamper(&dir.db(), |transaction| {
            let mut table = transaction.open_table(resume::RESUME).unwrap();
            changed = table.get(key).unwrap().unwrap().value().to_vec();
            changed[0] ^= 1;
            table.insert(key, changed.as_slice()).unwrap();
        });
        assert!(Store::resume_existing(dir.db(), config(), &TestVerifier::default()).is_err());
        let database = Database::open(dir.db()).unwrap();
        let read = database.begin_read().unwrap();
        assert_eq!(
            read.open_table(resume::RESUME)
                .unwrap()
                .get(key)
                .unwrap()
                .unwrap()
                .value(),
            changed
        );
    }
    let source = TestDir::new();
    restart_identity(&source);
    populated(&source.db());
    let other = TestDir::new();
    restart_identity(&other);
    std::fs::copy(source.db(), other.db()).unwrap();
    assert!(Store::resume_existing(other.db(), config(), &TestVerifier::default()).is_err());
}

#[test]
fn incomplete_restart_or_missing_identity_never_silently_downgrades() {
    for key in ["state", "rewards", "seal"] {
        let dir = TestDir::new();
        restart_identity(&dir);
        populated(&dir.db());
        tamper(&dir.db(), |transaction| {
            transaction
                .open_table(resume::RESUME)
                .unwrap()
                .remove(key)
                .unwrap();
        });
        assert!(Store::resume_existing(dir.db(), config(), &TestVerifier::default()).is_err());
        let database = Database::open(dir.db()).unwrap();
        let read = database.begin_read().unwrap();
        let table = read.open_table(resume::RESUME).unwrap();
        assert_eq!(table.len().unwrap(), 2);
        assert!(table.get(key).unwrap().is_none());
    }
    let dir = TestDir::new();
    restart_identity(&dir);
    populated(&dir.db());
    let identity = dir.0.join("native-peer-identity.secret");
    let preserved = dir.0.join("preserved-identity.fixture");
    std::fs::rename(&identity, &preserved).unwrap();
    assert!(Store::resume_existing(dir.db(), config(), &TestVerifier::default()).is_err());
    assert!(!identity.exists());
    let foreign = TestDir::new();
    restart_identity(&foreign);
    std::fs::copy(foreign.0.join("native-peer-identity.secret"), &identity).unwrap();
    assert!(Store::resume_existing(dir.db(), config(), &TestVerifier::default()).is_err());
    std::fs::remove_file(&identity).unwrap();
    std::fs::rename(&preserved, &identity).unwrap();
    assert!(Store::resume_existing(dir.db(), config(), &TestVerifier::default()).is_ok());
}

#[test]
fn restart_expiry_floor_must_match_the_committed_branch_and_anchor() {
    let dir = TestDir::new();
    restart_identity(&dir);
    let mut store = Store::open(dir.db(), config(), &TestVerifier::default()).unwrap();
    let genesis = store.state().clone();
    let block = candidate(store.state(), 1);
    store.append(&block, &TestVerifier::default()).unwrap();
    let floor = store.state().clone();
    let second = candidate(store.state(), 100_000);
    store.append(&second, &TestVerifier::default()).unwrap();
    assert!(resume::check_floor(&store.database, store.state(), &genesis).is_ok());
    assert!(resume::check_floor(&store.database, store.state(), &floor).is_ok());
    let (alternative, _) = branch(&genesis, 1, 1_000_000);
    let mut different = genesis.clone();
    different
        .apply(&alternative[0], &TestVerifier::default())
        .unwrap();
    assert!(resume::check_floor(&store.database, store.state(), &different).is_err());
    let mut wrong_root = floor.clone();
    wrong_root.snapshots.back_mut().unwrap().recent_root[0] ^= 1;
    assert!(resume::check_floor(&store.database, store.state(), &wrong_root).is_err());
    let accepted = store.state().clone();
    let transaction = store.database.begin_write().unwrap();
    transaction
        .open_table(BLOCKS)
        .unwrap()
        .remove(floor.height)
        .unwrap();
    transaction.commit().unwrap();
    assert!(resume::check_floor(&store.database, &accepted, &floor).is_err());
}

#[test]
fn restart_capacity_exhaustion_disables_acceleration_without_rejecting_valid_blocks() {
    let dir = TestDir::new();
    restart_identity(&dir);
    let mut store = Store::open(dir.db(), config(), &TestVerifier::default()).unwrap();
    let block = candidate(store.state(), 1);
    store.append(&block, &TestVerifier::default()).unwrap();
    store.resume_cache.as_mut().unwrap().maximum_bytes = 1;
    let block = candidate(store.state(), 100_000);
    store.append(&block, &TestVerifier::default()).unwrap();
    assert!(store.resume_cache.is_none());
    let expected = store.state().fingerprint();
    let transaction = store.database.begin_read().unwrap();
    assert!(
        !transaction
            .list_tables()
            .unwrap()
            .any(|table| table.name() == resume::RESUME.name())
    );
    drop(transaction);
    drop(store);
    // The optional cache is absent, so a later restart performs the explicit
    // retained-proof audit before creating a new qualified acceleration record.
    let verifier = TestVerifier::default();
    let resumed = Store::resume_existing(dir.db(), config(), &verifier).unwrap();
    assert_eq!(resumed.state().fingerprint(), expected);
    assert_eq!(verifier.transactions.get(), 128);
}

#[test]
fn restart_rejects_head_rollback_missing_anchor_and_unverified_tail() {
    for kind in 0..3 {
        let dir = TestDir::new();
        restart_identity(&dir);
        let (first, _) = populated(&dir.db());
        let mut state = State::new(config()).unwrap();
        state.apply(&first, &TestVerifier::default()).unwrap();
        let next = candidate(&state, 100_000);
        state.apply(&next, &TestVerifier::default()).unwrap();
        tamper(&dir.db(), |transaction| {
            if kind == 0 {
                transaction
                    .open_table(META)
                    .unwrap()
                    .insert("head", head(&State::new(config()).unwrap()).as_slice())
                    .unwrap();
            } else if kind == 1 {
                transaction.open_table(BLOCKS).unwrap().remove(1).unwrap();
            } else {
                let mut unverified = next.clone();
                unverified.transactions[0].proof[0] = 0;
                let mut record = unverified.encode().unwrap();
                record.extend_from_slice(&state.fingerprint());
                transaction
                    .open_table(BLOCKS)
                    .unwrap()
                    .insert(2, record.as_slice())
                    .unwrap();
                transaction
                    .open_table(META)
                    .unwrap()
                    .insert("head", head(&state).as_slice())
                    .unwrap();
            }
        });
        assert!(Store::resume_existing(dir.db(), config(), &TestVerifier::default()).is_err());
    }
}

#[test]
fn authenticated_reorganization_resumes_the_accepted_branch_without_replaying_it() {
    let dir = TestDir::new();
    restart_identity(&dir);
    let mut store = Store::open(dir.db(), config(), &TestVerifier::default()).unwrap();
    let genesis = store.state().clone();
    let first = candidate(store.state(), 1);
    store.append(&first, &TestVerifier::default()).unwrap();
    let (replacement, expected) = branch(&genesis, 2, 100_000);
    store
        .consider_branch(
            0,
            &replacement,
            CandidatePolicy::default(),
            &TestVerifier::default(),
        )
        .unwrap();
    drop(store);
    let verifier = TestVerifier {
        reject: true,
        ..Default::default()
    };
    let mut store = Store::resume_existing(dir.db(), config(), &verifier).unwrap();
    assert_eq!(store.state().fingerprint(), expected.fingerprint());
    assert_eq!(store.detached_count().unwrap(), 1);
    assert_eq!(verifier.transactions.get(), 0);
    // The current-head cache must not become the reorganization replay floor.
    let (next, expected) = branch(&genesis, 3, 1_000_000);
    store
        .consider_branch(
            0,
            &next,
            CandidatePolicy::default(),
            &TestVerifier::default(),
        )
        .unwrap();
    assert_eq!(store.state().fingerprint(), expected.fingerprint());
}

#[test]
fn rejected_append_changes_neither_memory_nor_durable_state() {
    let dir = TestDir::new();
    let mut store = Store::open(dir.db(), config(), &TestVerifier::default()).unwrap();
    let before = store.state().fingerprint();
    let mut block = candidate(store.state(), 1);
    block.transactions[63].proof = vec![0];
    assert!(store.append(&block, &TestVerifier::default()).is_err());
    assert_eq!(store.state().fingerprint(), before);
    drop(store);
    let reopened = Store::open(dir.db(), config(), &TestVerifier::default()).unwrap();
    assert_eq!(reopened.state().fingerprint(), before);
}

#[test]
fn a_conflicting_durable_head_is_not_exposed_as_accepted_memory() {
    let dir = TestDir::new();
    let mut store = Store::open(dir.db(), config(), &TestVerifier::default()).unwrap();
    let before = store.state().fingerprint();
    let block = candidate(store.state(), 1);
    {
        let txn = store.database.begin_write().unwrap();
        {
            let mut meta = txn.open_table(META).unwrap();
            let _ = meta.insert("head", [0u8; 72].as_slice()).unwrap();
        }
        txn.commit().unwrap();
    }
    assert!(store.append(&block, &TestVerifier::default()).is_err());
    assert_eq!(store.state().fingerprint(), before);
}

#[test]
fn wrong_configuration_is_rejected_and_the_original_stays_readable() {
    let dir = TestDir::new();
    let (_, expected) = populated(&dir.db());
    for wrong in [
        Config::development([92; 32], 0).unwrap(),
        Config::development([91; 32], 1).unwrap(),
    ] {
        assert!(Store::open(dir.db(), wrong, &TestVerifier::default()).is_err());
    }
    assert_eq!(
        Store::open(dir.db(), config(), &TestVerifier::default())
            .unwrap()
            .state()
            .fingerprint(),
        expected
    );
}

#[test]
fn missing_or_unrecognized_metadata_and_tables_are_never_reinitialized() {
    for kind in 0..6 {
        let dir = TestDir::new();
        drop(Store::open(dir.db(), config(), &TestVerifier::default()).unwrap());
        tamper(&dir.db(), |txn| match kind {
            0 | 1 => {
                let mut table = txn.open_table(META).unwrap();
                let _ = table
                    .remove(if kind == 0 { "config" } else { "head" })
                    .unwrap();
            }
            2 => {
                let _ = txn.delete_table(BLOCKS).unwrap();
            }
            3 => {
                let _ = txn.delete_table(META).unwrap();
            }
            4 => {
                let mut table = txn.open_table(META).unwrap();
                let _ = table.insert("unknown", &[0u8][..]).unwrap();
            }
            _ => {
                drop(
                    txn.open_table(TableDefinition::<u64, u64>::new("unexpected"))
                        .unwrap(),
                );
            }
        });
        assert!(
            Store::open(dir.db(), config(), &TestVerifier::default()).is_err(),
            "case {kind}"
        );
    }
}

#[test]
fn rejects_missing_and_gapped_blocks_and_changed_state_fingerprints() {
    for kind in 0..4 {
        let dir = TestDir::new();
        populated(&dir.db());
        tamper(&dir.db(), |txn| {
            let mut blocks = txn.open_table(BLOCKS).unwrap();
            let value = blocks.get(1).unwrap().unwrap().value().to_vec();
            match kind {
                0 => {
                    let _ = blocks.remove(1).unwrap();
                }
                1 => {
                    let _ = blocks.remove(1).unwrap();
                    let _ = blocks.insert(2, value.as_slice()).unwrap();
                }
                2 => {
                    let mut bad = value;
                    *bad.last_mut().unwrap() ^= 1;
                    let _ = blocks.insert(1, bad.as_slice()).unwrap();
                }
                _ => {
                    let mut bad = value;
                    bad.truncate(31);
                    let _ = blocks.insert(1, bad.as_slice()).unwrap();
                }
            }
        });
        assert!(
            Store::open(dir.db(), config(), &TestVerifier::default()).is_err(),
            "case {kind}"
        );
    }
}

#[test]
fn rejects_noncanonical_or_trailing_stored_block_data() {
    for trailing in [false, true] {
        let dir = TestDir::new();
        populated(&dir.db());
        tamper(&dir.db(), |txn| {
            let mut blocks = txn.open_table(BLOCKS).unwrap();
            let mut bad = blocks.get(1).unwrap().unwrap().value().to_vec();
            if trailing {
                bad.insert(bad.len() - 32, 0);
            } else {
                bad[0] ^= 1;
            }
            let _ = blocks.insert(1, bad.as_slice()).unwrap();
        });
        assert!(Store::open(dir.db(), config(), &TestVerifier::default()).is_err());
    }
}

#[test]
fn rejects_changed_committed_height_tip_or_head_fingerprint() {
    for offset in [0, 8, 40] {
        let dir = TestDir::new();
        populated(&dir.db());
        tamper(&dir.db(), |txn| {
            let mut meta = txn.open_table(META).unwrap();
            let mut bad = meta.get("head").unwrap().unwrap().value().to_vec();
            bad[offset] ^= 1;
            let _ = meta.insert("head", bad.as_slice()).unwrap();
        });
        assert!(Store::open(dir.db(), config(), &TestVerifier::default()).is_err());
    }
}

#[test]
fn existing_empty_random_and_truncated_files_fail_closed() {
    for data in [vec![], vec![17; 23], vec![0; 4096]] {
        let dir = TestDir::new();
        std::fs::write(dir.db(), &data).unwrap();
        assert!(Store::open(dir.db(), config(), &TestVerifier::default()).is_err());
        assert_eq!(std::fs::read(dir.db()).unwrap(), data);
    }
    let dir = TestDir::new();
    populated(&dir.db());
    let file = OpenOptions::new().write(true).open(dir.db()).unwrap();
    file.set_len(32).unwrap();
    drop(file);
    assert!(Store::open(dir.db(), config(), &TestVerifier::default()).is_err());
    assert_eq!(std::fs::metadata(dir.db()).unwrap().len(), 32);
}

#[test]
fn invalid_public_config_is_not_persisted() {
    let dir = TestDir::new();
    assert!(
        Store::open(
            dir.db(),
            Config {
                network: [0; 32],
                ..config()
            },
            &TestVerifier::default()
        )
        .is_err()
    );
    assert!(!dir.db().exists());
}

#[cfg(unix)]
#[test]
fn symlinks_and_nonregular_paths_are_rejected_without_following_them() {
    use std::os::unix::fs::symlink;
    let dir = TestDir::new();
    let target = dir.0.join("target");
    std::fs::write(&target, b"original evidence").unwrap();
    symlink(&target, dir.db()).unwrap();
    assert!(Store::open(dir.db(), config(), &TestVerifier::default()).is_err());
    assert_eq!(std::fs::read(target).unwrap(), b"original evidence");
    assert!(Store::open(&dir.0, config(), &TestVerifier::default()).is_err());
}

#[test]
fn asert_rules_and_replayed_work_are_durable_and_wrong_rules_fail_closed() {
    let dir = TestDir::new();
    let base = Config::asert_development([93; 32], 1_700_000_000, [0xff; 32], 1)
        .unwrap()
        .with_fund_wallets(
            siworld_core::v1_economics::FundAllocation::new_bps(vec![5000, 5000], 1).unwrap(),
            Config::development([121; 32], 0)
                .unwrap()
                .fund_verifying_keys,
        )
        .unwrap();
    let mut store = Store::open(dir.db(), base.clone(), &TestVerifier::default()).unwrap();
    let block = candidate(store.state(), 1);
    store.append(&block, &TestVerifier::default()).unwrap();
    let work = store.state().cumulative_work;
    let timestamps = store.state().timestamps.clone();
    drop(store);
    for field in 0..4 {
        let mut changed = base.clone();
        match field {
            0 => changed.genesis_timestamp += 1,
            1 => changed.genesis_target[31] ^= 1,
            2 => changed.pow_iterations += 1,
            _ => changed.target_interval += 1,
        }
        assert!(Store::open_existing(dir.db(), changed, &TestVerifier::default()).is_err());
    }
    let reopened = Store::open_existing(dir.db(), base, &TestVerifier::default()).unwrap();
    assert_eq!(reopened.state().cumulative_work, work);
    assert_eq!(reopened.state().timestamps, timestamps);
    assert_eq!(reopened.block(1).unwrap().target, block.target);
    assert_eq!(reopened.block(1).unwrap().timestamp, block.timestamp);
}
#[test]
fn old_store_configuration_is_rejected_without_reinitialization() {
    let dir = TestDir::new();
    populated(&dir.db());
    let mut legacy = b"SWNS\x01\0".to_vec();
    legacy.extend_from_slice(native::codec::SUITE_ID);
    legacy.extend_from_slice(&config().network);
    legacy.push(0);
    legacy.extend_from_slice(&[0; 32]);
    tamper(&dir.db(), |txn| {
        txn.open_table(META)
            .unwrap()
            .insert("config", legacy.as_slice())
            .unwrap();
    });
    assert!(Store::open_existing(dir.db(), config(), &TestVerifier::default()).is_err());
    let db = Database::open(dir.db()).unwrap();
    let txn = db.begin_read().unwrap();
    let meta = txn.open_table(META).unwrap();
    assert_eq!(meta.get("config").unwrap().unwrap().value(), legacy);
    assert_eq!(txn.open_table(BLOCKS).unwrap().len().unwrap(), 1);
}

fn branch(ancestor: &State, length: usize, seed: u32) -> (Vec<Block>, State) {
    let mut state = ancestor.clone();
    let mut blocks = Vec::new();
    for index in 0..length {
        let block = candidate(&state, seed + index as u32 * 100_000);
        state.apply(&block, &TestVerifier::default()).unwrap();
        blocks.push(block);
    }
    (blocks, state)
}

#[test]
fn equal_or_less_work_forks_never_replace_canonical_state() {
    use crate::chain::{BranchOutcome, CandidatePolicy};
    let dir = TestDir::new();
    let mut store = Store::open(dir.db(), config(), &TestVerifier::default()).unwrap();
    let genesis = store.state().clone();
    let (main, _) = branch(&genesis, 2, 1);
    for block in &main {
        store.append(block, &TestVerifier::default()).unwrap();
    }
    let expected = store.state().fingerprint();
    for length in [1, 2] {
        let (alternative, _) = branch(&genesis, length, 10_000_000);
        assert!(matches!(
            store.consider_branch(
                0,
                &alternative,
                CandidatePolicy::default(),
                &TestVerifier::default()
            ),
            Ok(BranchOutcome::Unchanged { .. })
        ));
        assert_eq!(store.state().fingerprint(), expected);
        assert_eq!(store.detached_count().unwrap(), 0);
    }
    drop(store);
    assert_eq!(
        Store::open_existing(dir.db(), config(), &TestVerifier::default())
            .unwrap()
            .state()
            .fingerprint(),
        expected
    );
}

#[test]
fn higher_work_reorganization_replaces_all_fork_specific_state_and_is_durable() {
    use crate::chain::{BranchOutcome, CandidatePolicy};
    let dir = TestDir::new();
    let mut store = Store::open(dir.db(), config(), &TestVerifier::default()).unwrap();
    let common = candidate(store.state(), 1);
    store.append(&common, &TestVerifier::default()).unwrap();
    let ancestor = store.state().clone();
    let (old, old_state) = branch(&ancestor, 1, 1_000_000);
    store.append(&old[0], &TestVerifier::default()).unwrap();
    let (replacement, expected) = branch(&ancestor, 2, 10_000_000);
    assert!(matches!(
        store.consider_branch(
            1,
            &replacement,
            CandidatePolicy::default(),
            &TestVerifier::default()
        ),
        Ok(BranchOutcome::Adopted {
            detached: 1,
            attached: 2,
            ..
        })
    ));
    assert_eq!(store.state().fingerprint(), expected.fingerprint());
    assert!(
        store
            .state()
            .snapshot(old_state.tip_snapshot().selector)
            .is_err()
    );
    assert!(
        store
            .state()
            .snapshot(ancestor.tip_snapshot().selector)
            .is_ok()
    );
    assert!(
        !store
            .state()
            .commitments
            .contains(&old[0].rewards[0].commitment)
    );
    assert!(
        store
            .state()
            .commitments
            .contains(&replacement[1].rewards[0].commitment)
    );
    for nullifier in old_state.spent.difference(&ancestor.spent) {
        assert!(!store.state().spent.contains(nullifier));
    }
    assert_eq!(store.detached_count().unwrap(), 1);
    assert_eq!(store.detached_block(&old[0].id().unwrap()).unwrap(), old[0]);
    assert_eq!(store.block(1).unwrap(), common);
    let fingerprint = expected.fingerprint();
    drop(store);
    let reopened = Store::open_existing(dir.db(), config(), &TestVerifier::default()).unwrap();
    assert_eq!(reopened.state().fingerprint(), fingerprint);
    assert_eq!(reopened.state().economics, expected.economics);
    assert_eq!(reopened.detached_count().unwrap(), 1);
    assert_eq!(
        reopened.detached_block(&old[0].id().unwrap()).unwrap(),
        old[0]
    );
}

fn economic_candidate(state: &State, seed: u32, mode: crate::state::RewardMode) -> Block {
    let mut block = candidate(state, seed);
    block.reward_mode = mode;
    if mode == crate::state::RewardMode::Holder {
        block.rewards = (0..5)
            .map(|index| RewardRecord {
                commitment: felt(seed + 20_000 + index),
                ciphertext: [index as u8; REWARD_CIPHERTEXT_BYTES],
            })
            .collect();
    }
    remine(&mut block, state);
    block
}

fn signed_economic_fund_spend(
    network: Hash,
    account: u8,
    amount: u64,
) -> crate::fund_spend::FundSpend {
    use libcrux_ml_dsa::ml_dsa_65;
    use native::codec::decode_digest;
    use native::multi_asset::{Hasher, Note, SIP_ASSET_ID};
    let pair = ml_dsa_65::generate_key_pair([83 + account; 32]);
    let mut spend = crate::fund_spend::FundSpend {
        account,
        counter: 0,
        amount,
        owner: felt(180_000_000 + u32::from(account)),
        rho: encode_digest(&crate::fund_spend::canonical_rho(network, account, 0)),
        rseed: felt(180_000_010 + u32::from(account)),
        commitment: [0; 48],
        ciphertext: [account + 3; 1313],
        verifying_key: *pair.verification_key.as_ref(),
        signature: [0; crate::fund_spend::SIGNATURE_BYTES],
    };
    let note = Note {
        asset_id: SIP_ASSET_ID,
        owner: decode_digest(&spend.owner).unwrap(),
        value: amount,
        unlock_height: 0,
        rho: decode_digest(&spend.rho).unwrap(),
        rseed: decode_digest(&spend.rseed).unwrap(),
    };
    spend.commitment = encode_digest(&Hasher::new().note_cm(&note));
    spend.signature = *ml_dsa_65::sign(
        &pair.signing_key,
        &spend.message(network),
        b"siworld v0",
        [84 + account; 32],
    )
    .unwrap()
    .as_ref();
    spend
}

#[test]
fn mixed_mode_reorganization_restores_maturity_vesting_and_independent_fund_spends_durably() {
    use crate::chain::{BranchOutcome, CandidatePolicy, ChainError};
    use crate::state::RewardMode;
    use siworld_core::v1_economics::{EconomicsParams, FundAccount, FundAllocation};
    // The first credit matures at height 25 and first vests at height 289.
    // Both forks cross the same boundary; the accepted fork has more work.
    for boundary in [25u64, 289] {
        let directory = TestDir::new();
        let mut cfg = config()
            .with_economics(EconomicsParams::engineering([60, 120, 180, 240], 3).unwrap())
            .unwrap()
            .with_fund_wallets(
                FundAllocation::new_bps(vec![3000, 7000], 1).unwrap(),
                Config::development([121; 32], 0)
                    .unwrap()
                    .fund_verifying_keys,
            )
            .unwrap();
        for account in 0..2u8 {
            let spend = signed_economic_fund_spend(cfg.network, account, 1);
            cfg.fund_verifying_keys[usize::from(account)] = spend.verifying_key;
        }
        let mut store = Store::open(directory.db(), cfg.clone(), &TestVerifier::default()).unwrap();
        for height in 1..=(boundary - 2) {
            let mode = if height % 2 == 1 {
                RewardMode::Holder
            } else {
                RewardMode::Voyager
            };
            let block = economic_candidate(store.state(), height as u32 * 100_000, mode);
            store.append(&block, &TestVerifier::default()).unwrap();
        }
        let ancestor = store.state().clone();
        let mut old = Vec::new();
        for index in 0..2u32 {
            let mut block = economic_candidate(
                store.state(),
                50_000_000 + index * 100_000,
                RewardMode::Voyager,
            );
            if block.height == boundary {
                let before = store.state().economics.fund(FundAccount::FIRST).unwrap();
                let mut released = store.state().economics.clone();
                released.advance(boundary, block.reward_mode).unwrap();
                let after = released.fund(FundAccount::FIRST).unwrap();
                assert!(after.direct_unlocked > before.direct_unlocked);
                if boundary == 25 {
                    assert_eq!(before.direct_unlocked, 0);
                    assert_eq!(after.vesting_unlocked, 0);
                } else {
                    assert_eq!(before.vesting_unlocked, 0);
                    assert!(after.vesting_unlocked > 0);
                }
                block.fund_spends.push(signed_economic_fund_spend(
                    cfg.network,
                    0,
                    u64::try_from(after.available().unwrap()).unwrap(),
                ));
                remine(&mut block, store.state());
            }
            store.append(&block, &TestVerifier::default()).unwrap();
            old.push(block);
        }
        let orphan = store.state().clone();
        assert!(orphan.economics.fund(FundAccount::FIRST).unwrap().spent > 0);
        assert_eq!(orphan.economics.fund(FundAccount::SECOND).unwrap().spent, 0);
        let orphan_payout = old[1].fund_spends[0].commitment;

        let mut expected = ancestor.clone();
        let mut replacement = Vec::new();
        let mut spend_parent = None;
        let mut first_available = 0;
        for (index, mode) in [RewardMode::Holder, RewardMode::Voyager, RewardMode::Holder]
            .into_iter()
            .enumerate()
        {
            let mut block =
                economic_candidate(&expected, 100_000_000 + index as u32 * 100_000, mode);
            if block.height == boundary {
                spend_parent = Some(expected.clone());
                let mut released = expected.economics.clone();
                released.advance(boundary, mode).unwrap();
                first_available = u64::try_from(
                    released
                        .fund(FundAccount::FIRST)
                        .unwrap()
                        .available()
                        .unwrap(),
                )
                .unwrap();
                let second_available = u64::try_from(
                    released
                        .fund(FundAccount::SECOND)
                        .unwrap()
                        .available()
                        .unwrap(),
                )
                .unwrap();
                assert!(second_available > first_available + 1);
                block.fund_spends.push(signed_economic_fund_spend(
                    cfg.network,
                    1,
                    second_available,
                ));
                remine(&mut block, &expected);
            }
            expected.apply(&block, &TestVerifier::default()).unwrap();
            replacement.push(block);
        }
        let accepted_payout = replacement[1].fund_spends[0].commitment;
        let mut overdraft = replacement.clone();
        overdraft[1].fund_spends[0] =
            signed_economic_fund_spend(cfg.network, 0, first_available + 1);
        remine(&mut overdraft[1], &spend_parent.unwrap());
        let before = store.state().fingerprint();
        let result = store.consider_branch(
            ancestor.height,
            &overdraft,
            CandidatePolicy::default(),
            &TestVerifier::default(),
        );
        match result {
            Err(ChainError::Invalid(reason)) => {
                assert!(reason.contains("exceeds unlocked unspent entitlement"));
            }
            other => panic!("independent fund overdraft must reject atomically: {other:?}"),
        }
        assert_eq!(store.state().fingerprint(), before);
        assert_eq!(store.state().economics, orphan.economics);
        assert_eq!(store.block(boundary).unwrap(), old[1]);
        assert_eq!(store.detached_count().unwrap(), 0);

        assert!(matches!(
            store.consider_branch(
                ancestor.height,
                &replacement,
                CandidatePolicy::default(),
                &TestVerifier::default(),
            ),
            Ok(BranchOutcome::Adopted {
                detached: 2,
                attached: 3,
                ..
            })
        ));
        assert_ne!(
            orphan.economics.totals().holder_pool,
            expected.economics.totals().holder_pool
        );
        assert!(orphan.economics.totals().burned > expected.economics.totals().burned);
        assert_ne!(
            orphan.economics.locked_schedule(),
            expected.economics.locked_schedule()
        );
        assert_eq!(
            expected.economics.fund(FundAccount::FIRST).unwrap().spent,
            0
        );
        assert_eq!(
            expected
                .economics
                .fund(FundAccount::FIRST)
                .unwrap()
                .spend_count,
            0
        );
        assert!(expected.economics.fund(FundAccount::SECOND).unwrap().spent > 0);
        assert_eq!(
            expected
                .economics
                .fund(FundAccount::SECOND)
                .unwrap()
                .spend_count,
            1
        );
        assert_eq!(store.state().fingerprint(), expected.fingerprint());
        assert_eq!(store.state().economics, expected.economics);
        assert!(!store.state().commitments.contains(&orphan_payout));
        assert!(store.state().commitments.contains(&accepted_payout));
        assert_eq!(store.detached_count().unwrap(), 2);
        for block in &old {
            assert_eq!(store.detached_block(&block.id().unwrap()).unwrap(), *block);
        }
        expected.economics.assert_supply_invariant().unwrap();
        drop(store);
        let reopened = Store::open_existing(directory.db(), cfg, &TestVerifier::default()).unwrap();
        assert_eq!(reopened.state().fingerprint(), expected.fingerprint());
        assert_eq!(reopened.state().economics, expected.economics);
        assert!(!reopened.state().commitments.contains(&orphan_payout));
        assert!(reopened.state().commitments.contains(&accepted_payout));
        assert_eq!(reopened.block(boundary).unwrap(), replacement[1]);
        assert_eq!(reopened.detached_count().unwrap(), 2);
    }
}

#[test]
fn twenty_four_wallet_registry_claims_roll_back_atomically_and_recover_after_restart() {
    use crate::chain::{BranchOutcome, CandidatePolicy};
    use crate::state::RewardMode;
    use siworld_core::v1_economics::{FundAccount, FundAllocation};
    let directory = TestDir::new();
    let base = config();
    let mut shares = vec![400; 24];
    shares[23] = 800;
    let keys = (0..24u8)
        .map(|account| signed_economic_fund_spend(base.network, account, 1).verifying_key)
        .collect();
    let cfg = base
        .with_fund_wallets(FundAllocation::new_bps(shares, 23).unwrap(), keys)
        .unwrap();
    let mut store = Store::open(directory.db(), cfg.clone(), &TestVerifier::default()).unwrap();
    for height in 1..=24u32 {
        let block = economic_candidate(store.state(), height * 100_000, RewardMode::Voyager);
        store.append(&block, &TestVerifier::default()).unwrap();
    }
    let ancestor = store.state().clone();
    let mut old = economic_candidate(store.state(), 40_000_000, RewardMode::Voyager);
    old.fund_spends
        .push(signed_economic_fund_spend(cfg.network, 23, 1));
    remine(&mut old, store.state());
    store.append(&old, &TestVerifier::default()).unwrap();
    let old_commitment = old.fund_spends[0].commitment;
    let orphan = store.state().clone();
    let mut replacement = Vec::new();
    let mut expected = ancestor.clone();
    for index in 0..2u32 {
        let mut block =
            economic_candidate(&expected, 60_000_000 + index * 100_000, RewardMode::Holder);
        if index == 0 {
            block.fund_spends = [0, 20]
                .into_iter()
                .map(|account| signed_economic_fund_spend(cfg.network, account, 1))
                .collect();
        }
        remine(&mut block, &expected);
        expected.apply(&block, &TestVerifier::default()).unwrap();
        replacement.push(block);
    }
    let mut invalid = replacement.clone();
    invalid[0].fund_spends[1] = signed_economic_fund_spend(cfg.network, 20, u64::MAX);
    remine(&mut invalid[0], &ancestor);
    assert!(
        store
            .consider_branch(
                ancestor.height,
                &invalid,
                CandidatePolicy::default(),
                &TestVerifier::default()
            )
            .is_err()
    );
    assert_eq!(store.state().fingerprint(), orphan.fingerprint());
    assert_eq!(store.state().economics, orphan.economics);
    assert!(matches!(
        store.consider_branch(
            ancestor.height,
            &replacement,
            CandidatePolicy::default(),
            &TestVerifier::default()
        ),
        Ok(BranchOutcome::Adopted { .. })
    ));
    assert_eq!(
        store
            .state()
            .economics
            .fund(FundAccount::new(23).unwrap())
            .unwrap()
            .spent,
        0
    );
    assert_eq!(
        store
            .state()
            .economics
            .fund(FundAccount::new(20).unwrap())
            .unwrap()
            .spent,
        1
    );
    assert_eq!(
        store
            .state()
            .economics
            .fund(FundAccount::new(0).unwrap())
            .unwrap()
            .spent,
        1
    );
    assert!(!store.state().commitments.contains(&old_commitment));
    assert_eq!(store.state().economics.funds().len(), 24);
    drop(store);
    let reopened = Store::open_existing(directory.db(), cfg, &TestVerifier::default()).unwrap();
    assert_eq!(reopened.state().fingerprint(), expected.fingerprint());
    assert_eq!(
        reopened.state().economics.funds(),
        expected.economics.funds()
    );
    assert!(!reopened.state().commitments.contains(&old_commitment));
}

#[test]
fn invalid_candidate_proofs_snapshot_and_ancestry_are_atomic() {
    use crate::chain::{CandidatePolicy, ChainError};
    for mutation in 0..6 {
        let dir = TestDir::new();
        let mut store = Store::open(dir.db(), config(), &TestVerifier::default()).unwrap();
        let genesis = store.state().clone();
        let old = candidate(store.state(), 1);
        store.append(&old, &TestVerifier::default()).unwrap();
        let before = store.state().fingerprint();
        let (mut blocks, _) = branch(&genesis, 2, 10_000_000);
        match mutation {
            0 => blocks[1].transactions[63].proof = vec![0],
            1 => blocks[1].settlement_proof = vec![0],
            2 => blocks[0].parent = old.id().unwrap(),
            3 => blocks[1].height += 1,
            4 => blocks[1].transactions[0].record.snapshot = store.state().tip_snapshot().selector,
            _ => blocks.swap(0, 1),
        }
        assert!(matches!(
            store.consider_branch(
                0,
                &blocks,
                CandidatePolicy::default(),
                &TestVerifier::default()
            ),
            Err(ChainError::Invalid(_))
        ));
        assert_eq!(store.state().fingerprint(), before);
        assert_eq!(store.detached_count().unwrap(), 0);
        drop(store);
        assert_eq!(
            Store::open_existing(dir.db(), config(), &TestVerifier::default())
                .unwrap()
                .state()
                .fingerprint(),
            before
        );
    }
}

#[test]
fn resource_exhaustion_and_missing_candidates_leave_state_retryable() {
    use crate::chain::{CandidatePolicy, ChainError};
    let dir = TestDir::new();
    let mut store = Store::open(dir.db(), config(), &TestVerifier::default()).unwrap();
    let genesis = store.state().clone();
    let old = candidate(store.state(), 1);
    store.append(&old, &TestVerifier::default()).unwrap();
    let before = store.state().fingerprint();
    let (blocks, _) = branch(&genesis, 2, 10_000_000);
    for policy in [
        CandidatePolicy {
            max_blocks: 1,
            ..CandidatePolicy::default()
        },
        CandidatePolicy {
            max_bytes: 1,
            ..CandidatePolicy::default()
        },
        CandidatePolicy {
            max_retained_bytes: 1,
            ..CandidatePolicy::default()
        },
    ] {
        assert!(matches!(
            store.consider_branch(0, &blocks, policy, &TestVerifier::default()),
            Err(ChainError::ResourceExhausted(_))
        ));
        assert_eq!(store.state().fingerprint(), before);
        assert_eq!(store.detached_count().unwrap(), 0);
    }
    assert!(matches!(
        store.consider_branch(0, &[], CandidatePolicy::default(), &TestVerifier::default()),
        Err(ChainError::Invalid(_))
    ));
    assert!(matches!(
        store.consider_branch(
            2,
            &blocks,
            CandidatePolicy::default(),
            &TestVerifier::default()
        ),
        Err(ChainError::Invalid(_))
    ));
}

#[test]
fn finalized_boundary_preserves_23_and_24_rollback_and_rejects_25() {
    use crate::chain::{BranchOutcome, CandidatePolicy, ChainError};
    for depth in [23usize, 24, 25] {
        let dir = TestDir::new();
        let mut store = Store::open(dir.db(), config(), &TestVerifier::default()).unwrap();
        let genesis = store.state().clone();
        let (main, _) = branch(&genesis, 25, 1);
        let mut ancestor = genesis.clone();
        for (index, block) in main.iter().enumerate() {
            store.append(block, &TestVerifier::default()).unwrap();
            if index + 1 == 25 - depth {
                ancestor = store.state().clone();
            }
        }
        let before = store.state().fingerprint();
        let (blocks, expected) = branch(&ancestor, depth + 1, 10_000_000);
        let result = store.consider_branch(
            (25 - depth) as u64,
            &blocks,
            CandidatePolicy::default(),
            &TestVerifier::default(),
        );
        if depth <= 24 {
            assert!(matches!(result, Ok(BranchOutcome::Adopted { .. })));
            assert_eq!(store.state().fingerprint(), expected.fingerprint());
            assert_eq!(store.block(1).unwrap(), main[0]);
        } else {
            assert_eq!(result, Err(ChainError::ReorganizationLimit));
            assert_eq!(store.state().fingerprint(), before);
        }
    }
}

#[test]
fn canonical_selection_uses_actual_work_even_when_winner_is_shorter() {
    use crate::chain::{BranchOutcome, CandidatePolicy};
    let dir = TestDir::new();
    let cfg = Config::development([94; 32], 1).unwrap();
    let mut store = Store::open(dir.db(), cfg, &TestVerifier::default()).unwrap();
    let genesis = store.state().clone();
    for index in 0..4 {
        let mut block = candidate(store.state(), 1 + index * 100_000);
        block.timestamp = store.state().timestamp() + 14_400;
        remine(&mut block, store.state());
        store.append(&block, &TestVerifier::default()).unwrap();
    }
    let old_work = store.state().cumulative_work;
    let (blocks, expected) = branch(&genesis, 3, 10_000_000);
    assert!(expected.cumulative_work > old_work);
    assert!(matches!(
        store.consider_branch(
            0,
            &blocks,
            CandidatePolicy::default(),
            &TestVerifier::default()
        ),
        Ok(BranchOutcome::Adopted { .. })
    ));
    assert_eq!(store.state().height, 3);
    assert_eq!(store.state().fingerprint(), expected.fingerprint());
    assert!(store.block(4).is_err());
    assert_eq!(store.detached_count().unwrap(), 4);
}

fn remine(block: &mut Block, state: &State) {
    block.nonce = 0;
    let seed = block.pow_seed().unwrap();
    while !siworld_core::pow::meets_target(
        &siworld_core::pow::pow_hash(&seed, block.nonce, state.config.pow_iterations),
        &block.target,
    ) {
        block.nonce += 1;
    }
}

#[test]
fn aborted_reorganization_transaction_preserves_reopen_state_and_evidence() {
    let dir = TestDir::new();
    let (original, expected) = populated(&dir.db());
    let store = Store::open_existing(dir.db(), config(), &TestVerifier::default()).unwrap();
    {
        let txn = store.database.begin_write().unwrap();
        {
            let mut blocks = txn.open_table(BLOCKS).unwrap();
            let record = blocks.get(1).unwrap().unwrap().value().to_vec();
            txn.open_table(DETACHED)
                .unwrap()
                .insert(original.id().unwrap().as_slice(), record.as_slice())
                .unwrap();
            blocks.remove(1).unwrap();
            txn.open_table(META)
                .unwrap()
                .insert("head", head(&State::new(config()).unwrap()).as_slice())
                .unwrap();
        }
        // Dropping the single uncommitted redb transaction models interruption
        // before the commit boundary, without any filesystem history restore.
    }
    drop(store);
    let reopened = Store::open_existing(dir.db(), config(), &TestVerifier::default()).unwrap();
    assert_eq!(reopened.state().fingerprint(), expected);
    assert_eq!(reopened.block(1).unwrap(), original);
    assert_eq!(reopened.detached_count().unwrap(), 0);
}

#[test]
fn replay_allowance_exhaustion_does_not_invalidate_a_valid_branch() {
    use crate::chain::{CandidatePolicy, ChainError};
    let dir = TestDir::new();
    let mut store = Store::open(dir.db(), config(), &TestVerifier::default()).unwrap();
    let common = candidate(store.state(), 1);
    store.append(&common, &TestVerifier::default()).unwrap();
    let ancestor = store.state().clone();
    let old = candidate(store.state(), 1_000_000);
    store.append(&old, &TestVerifier::default()).unwrap();
    let before = store.state().fingerprint();
    let (blocks, expected) = branch(&ancestor, 2, 10_000_000);
    let policy = CandidatePolicy {
        max_replay_blocks: 0,
        ..CandidatePolicy::default()
    };
    assert_eq!(
        store.consider_branch(1, &blocks, policy, &TestVerifier::default()),
        Err(ChainError::ResourceExhausted(
            "canonical ancestor replay allowance"
        ))
    );
    assert_eq!(store.state().fingerprint(), before);
    store
        .consider_branch(
            1,
            &blocks,
            CandidatePolicy::default(),
            &TestVerifier::default(),
        )
        .unwrap();
    assert_eq!(store.state().fingerprint(), expected.fingerprint());
}

#[test]
fn unused_owned_proof_capacity_is_charged_before_candidate_verification() {
    use crate::chain::{CandidatePolicy, ChainError};
    let dir = TestDir::new();
    let mut store = Store::open(dir.db(), config(), &TestVerifier::default()).unwrap();
    let before = store.state().fingerprint();
    let mut block = candidate(store.state(), 1);
    block.transactions[0].proof.reserve_exact(1024 * 1024);
    let policy = CandidatePolicy {
        max_bytes: 512 * 1024,
        ..CandidatePolicy::default()
    };
    let verifier = TestVerifier::default();
    assert!(matches!(
        store.consider_branch(0, &[block], policy, &verifier),
        Err(ChainError::ResourceExhausted(_))
    ));
    assert_eq!(verifier.transactions.get(), 0);
    assert_eq!(verifier.settlements.get(), 0);
    assert_eq!(store.state().fingerprint(), before);
}

#[test]
fn corrupted_detached_evidence_fails_reopen_without_reinitialization() {
    use crate::chain::CandidatePolicy;
    let dir = TestDir::new();
    let mut store = Store::open(dir.db(), config(), &TestVerifier::default()).unwrap();
    let genesis = store.state().clone();
    let original = candidate(store.state(), 1);
    store.append(&original, &TestVerifier::default()).unwrap();
    let (replacement, _) = branch(&genesis, 2, 10_000_000);
    store
        .consider_branch(
            0,
            &replacement,
            CandidatePolicy::default(),
            &TestVerifier::default(),
        )
        .unwrap();
    drop(store);
    let id = original.id().unwrap();
    tamper(&dir.db(), |txn| {
        let mut table = txn.open_table(DETACHED).unwrap();
        let mut record = table.get(id.as_slice()).unwrap().unwrap().value().to_vec();
        *record.last_mut().unwrap() ^= 1;
        table.insert(id.as_slice(), record.as_slice()).unwrap();
    });
    assert!(Store::open_existing(dir.db(), config(), &TestVerifier::default()).is_err());
    let database = Database::open(dir.db()).unwrap();
    let txn = database.begin_read().unwrap();
    assert_eq!(txn.open_table(BLOCKS).unwrap().len().unwrap(), 2);
    assert_eq!(txn.open_table(DETACHED).unwrap().len().unwrap(), 1);
}

#[test]
fn read_only_wallet_replay_verifies_every_proof_and_enforces_local_bounds() {
    let dir = TestDir::new();
    let mut store = Store::open(dir.db(), config(), &TestVerifier::default()).unwrap();
    for seed in [1, 100000] {
        let block = candidate(store.state(), seed);
        store.append(&block, &TestVerifier::default()).unwrap();
    }
    let fingerprint = store.state().fingerprint();
    drop(store);
    assert!(
        read_only_history(&dir.db(), config(), &TestVerifier::default(), 1, usize::MAX).is_err()
    );
    assert!(read_only_history(&dir.db(), config(), &TestVerifier::default(), 4096, 1).is_err());
    let before = std::fs::read(dir.db()).unwrap();
    let verifier = TestVerifier::default();
    let (state, blocks) =
        read_only_history(&dir.db(), config(), &verifier, 4096, 512 * 1024 * 1024).unwrap();
    assert_eq!(state.fingerprint(), fingerprint);
    assert_eq!(blocks.len(), 2);
    assert_eq!(std::fs::read(dir.db()).unwrap(), before);
    assert_eq!(verifier.transactions.get(), 128);
    assert_eq!(verifier.settlements.get(), 2);
    assert!(
        read_only_history(
            &dir.db(),
            config(),
            &TestVerifier {
                reject: true,
                ..Default::default()
            },
            4096,
            512 * 1024 * 1024
        )
        .is_err()
    );
}

#[test]
fn read_only_wallet_replay_rejects_wrong_configuration_without_writes() {
    let dir = TestDir::new();
    drop(Store::open(dir.db(), config(), &TestVerifier::default()).unwrap());
    let before = std::fs::read(dir.db()).unwrap();
    let other = Config::development([92; 32], 0).unwrap();
    assert!(
        read_only_history(
            &dir.db(),
            other,
            &TestVerifier::default(),
            64,
            4 * 1024 * 1024
        )
        .is_err()
    );
    assert_eq!(std::fs::read(dir.db()).unwrap(), before);
}

#[test]
fn read_only_wallet_replay_rejects_nonpositive_limits_before_filesystem_access() {
    let dir = TestDir::new();
    for (blocks, bytes) in [(0, 1), (1, 0), (0, 0)] {
        let error =
            match read_only_history(&dir.db(), config(), &TestVerifier::default(), blocks, bytes) {
                Ok(_) => panic!("nonpositive local scan limits must fail"),
                Err(error) => error,
            };
        assert_eq!(error, "wallet replay resource limits must be positive");
        assert!(!dir.db().exists());
    }
}

#[cfg(unix)]
#[test]
fn read_only_wallet_replay_rejects_symlink_without_touching_target() {
    let dir = TestDir::new();
    drop(Store::open(dir.db(), config(), &TestVerifier::default()).unwrap());
    let before = std::fs::read(dir.db()).unwrap();
    let alias = dir.0.join("readonly-alias.redb");
    std::os::unix::fs::symlink(dir.db(), &alias).unwrap();
    assert!(
        read_only_history(
            &alias,
            config(),
            &TestVerifier::default(),
            64,
            4 * 1024 * 1024
        )
        .is_err()
    );
    assert!(
        std::fs::symlink_metadata(&alias)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read(dir.db()).unwrap(), before);
}

#[test]
fn read_only_wallet_replay_rejects_corruption_without_repair() {
    let dir = TestDir::new();
    drop(Store::open(dir.db(), config(), &TestVerifier::default()).unwrap());
    let mut damaged = std::fs::read(dir.db()).unwrap();
    damaged[0] ^= 0x80;
    std::fs::write(dir.db(), &damaged).unwrap();
    assert!(
        read_only_history(
            &dir.db(),
            config(),
            &TestVerifier::default(),
            64,
            4 * 1024 * 1024
        )
        .is_err()
    );
    assert_eq!(std::fs::read(dir.db()).unwrap(), damaged);
}
