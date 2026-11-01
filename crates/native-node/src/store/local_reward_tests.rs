//! Local production ownership is durable independently of canonical membership.
use super::*;
use crate::fixtures::{TestVerifier, candidate};
use crate::runtime::Node;
use crate::wire::Hash;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join(format!(
            "siworld-local-index-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
    fn database(&self) -> PathBuf {
        self.0.join("chain.redb")
    }
    fn receipt(&self, id: &Hash) -> PathBuf {
        self.0
            .join(format!("reward-{}.secret", crate::local::hex(id)))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn config() -> Config {
    Config::development([175; 32], 0).unwrap()
}
fn open(directory: &Directory) -> Node<TestVerifier> {
    Node::new(
        Store::open(directory.database(), config(), &TestVerifier).unwrap(),
        TestVerifier,
    )
}
fn produce(node: &mut Node<TestVerifier>, seed: u32) -> Hash {
    let permit = node.begin_production().unwrap();
    let produced = crate::producer::production_fixture(node.state(), seed);
    let prepared = node.bind_produced(permit, produced).unwrap();
    node.commit_produced(prepared).unwrap()
}

#[test]
fn imported_blocks_need_no_local_receipt_but_deleted_owned_receipts_fail_restart() {
    let directory = Directory::new();
    let mut node = open(&directory);
    assert!(node.store().has_local_reward_index().unwrap());
    assert_eq!(node.store().verify_local_rewards().unwrap(), 0);
    let owned = produce(&mut node, 230_000);
    let remote = candidate(node.state(), 240_000);
    let remote_id = remote.id().unwrap();
    node.import_branch(1, &[remote], CandidatePolicy::default())
        .unwrap();
    assert!(!directory.receipt(&remote_id).exists());
    assert_eq!(node.store().verify_local_rewards().unwrap(), 1);
    drop(node);
    let node = Node::new(
        Store::open_existing(directory.database(), config(), &TestVerifier).unwrap(),
        TestVerifier,
    );
    assert_eq!(node.store().verify_local_rewards().unwrap(), 1);
    std::fs::remove_file(directory.receipt(&owned)).unwrap();
    assert!(node.store().verify_local_rewards().is_err());
    drop(node);
    assert!(Store::open_existing(directory.database(), config(), &TestVerifier).is_err());
}

#[test]
fn local_ownership_and_receipts_remain_verifiable_after_reorganization() {
    let directory = Directory::new();
    let mut node = open(&directory);
    let owned = produce(&mut node, 250_000);
    let mut ancestor = State::new(config()).unwrap();
    let first = candidate(&ancestor, 260_000);
    ancestor.apply(&first, &TestVerifier).unwrap();
    let second = candidate(&ancestor, 270_000);
    node.import_branch(0, &[first, second], CandidatePolicy::default())
        .unwrap();
    assert_eq!(node.store().detached_count().unwrap(), 1);
    assert_eq!(
        node.store().detached_block(&owned).unwrap().id().unwrap(),
        owned
    );
    assert_eq!(node.store().verify_local_rewards().unwrap(), 1);
    drop(node);
    let store = Store::open_existing(directory.database(), config(), &TestVerifier).unwrap();
    assert_eq!(store.verify_local_rewards().unwrap(), 1);
}

#[test]
fn index_marker_or_table_removal_is_detected_without_reinitialization() {
    for remove_table in [false, true] {
        let directory = Directory::new();
        let mut node = open(&directory);
        produce(&mut node, 280_000);
        drop(node);
        let database = Database::open(directory.database()).unwrap();
        let txn = database.begin_write().unwrap();
        if remove_table {
            txn.delete_table(LOCAL_REWARDS).unwrap();
        } else {
            txn.open_table(META)
                .unwrap()
                .remove(LOCAL_REWARDS_MARKER)
                .unwrap();
        }
        txn.commit().unwrap();
        drop(database);
        assert!(Store::open_existing(directory.database(), config(), &TestVerifier).is_err());
    }
}

#[test]
fn legacy_unindexed_history_requires_explicit_network_qualification() {
    let directory = Directory::new();
    let mut node = open(&directory);
    let remote = candidate(node.state(), 290_000);
    node.import_branch(0, &[remote], CandidatePolicy::default())
        .unwrap();
    drop(node);
    let database = Database::open(directory.database()).unwrap();
    let txn = database.begin_write().unwrap();
    txn.delete_table(LOCAL_REWARDS).unwrap();
    txn.open_table(META)
        .unwrap()
        .remove(LOCAL_REWARDS_MARKER)
        .unwrap();
    txn.commit().unwrap();
    drop(database);
    let store = Store::open_existing(directory.database(), config(), &TestVerifier).unwrap();
    assert!(!store.has_local_reward_index().unwrap());
    assert!(
        store
            .require_local_reward_index()
            .unwrap_err()
            .contains("legacy")
    );
    assert!(store.verify_local_rewards().is_err());
    assert_eq!(store.state().height, 1);
}

#[test]
fn failed_transition_never_adds_local_ownership_and_changed_receipt_digest_is_rejected() {
    let directory = Directory::new();
    let mut node = open(&directory);
    let permit = node.begin_production().unwrap();
    let mut produced = crate::producer::production_fixture(node.state(), 300_000);
    produced.block.settlement_proof[0] ^= 1;
    let prepared = node.bind_produced(permit, produced).unwrap();
    assert!(node.commit_produced(prepared).is_err());
    assert_eq!(node.store().verify_local_rewards().unwrap(), 0);
    let owned = produce(&mut node, 310_000);
    let mut receipt = std::fs::read(directory.receipt(&owned)).unwrap();
    let last = receipt.len() - 1;
    receipt[last] ^= 1;
    std::fs::write(directory.receipt(&owned), receipt).unwrap();
    assert!(node.store().verify_local_rewards().is_err());
}

#[test]
fn deleting_local_ownership_row_is_detected_by_the_durable_count_marker() {
    let directory = Directory::new();
    let mut node = open(&directory);
    let owned = produce(&mut node, 320_000);
    drop(node);
    let database = Database::open(directory.database()).unwrap();
    let txn = database.begin_write().unwrap();
    txn.open_table(LOCAL_REWARDS)
        .unwrap()
        .remove(owned.as_slice())
        .unwrap();
    txn.commit().unwrap();
    drop(database);
    assert!(Store::open_existing(directory.database(), config(), &TestVerifier).is_err());
}
