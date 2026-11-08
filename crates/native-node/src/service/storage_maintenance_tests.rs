use super::*;
use crate::{fixtures::TestVerifier, state::BlockVerifier, storage_policy::Role};
use native::{
    codec::{ProofContext, PublicTransaction},
    multi_asset::Digest,
};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use std::{
    cell::Cell,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new(sealed: bool, blocks: u32, produced: bool) -> Self {
        let path = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "siworld-resume-maintenance-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        let config = local::initialize(&path, 0).unwrap();
        if sealed {
            crate::identity::NativeIdentity::initialize(&path, crate::p2p::Binding::new(&config))
                .unwrap();
        }
        let mut store = Store::open(path.join("chain.redb"), config, &TestVerifier).unwrap();
        for i in 0..blocks {
            if produced {
                let item =
                    crate::producer::production_fixture(store.state(), 100_000 + i * 100_000);
                let id = item.block.id().unwrap();
                store.save_reward_receipt(&id, &item.reward_secret).unwrap();
                store
                    .append_produced(&item.block, &item.reward_secret, &TestVerifier)
                    .unwrap();
            } else {
                let block = crate::fixtures::candidate(store.state(), 100_000 + i * 100_000);
                store.append(&block, &TestVerifier).unwrap();
            }
        }
        Self(path)
    }
    fn db(&self) -> PathBuf {
        self.0.join("chain.redb")
    }
    fn open(&self) -> Store {
        Store::open_existing(self.db(), local::load(&self.0).unwrap(), &TestVerifier).unwrap()
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[derive(Default)]
struct CountingVerifier {
    transactions: Cell<usize>,
    settlements: Cell<usize>,
    reject: bool,
}
impl BlockVerifier for CountingVerifier {
    fn transaction(
        &self,
        t: &PublicTransaction,
        c: &ProofContext,
        a: &Digest,
        b: &Digest,
        p: &[u8],
    ) -> Result<(), String> {
        self.transactions.set(self.transactions.get() + 1);
        if self.reject {
            Err("synthetic retained proof rejection".into())
        } else {
            TestVerifier.transaction(t, c, a, b, p)
        }
    }
    fn settlement(
        &self,
        d: &[Digest],
        p: &native::settlement::RewardPlan,
        a: Hash,
        b: Hash,
        n: &[Digest],
        proof: &[u8],
    ) -> Result<(), String> {
        self.settlements.set(self.settlements.get() + 1);
        if self.reject {
            Err("synthetic retained proof rejection".into())
        } else {
            TestVerifier.settlement(d, p, a, b, n, proof)
        }
    }
}
// Inspect logical rows; opening redb may legitimately change file allocator bytes.
fn snapshot(path: &Path) -> String {
    let database = redb::Database::open(path).unwrap();
    let transaction = database.begin_read().unwrap();
    let mut h = blake3::Hasher::new();
    for name in transaction.list_tables().unwrap() {
        use redb::TableHandle;
        h.update(name.name().as_bytes());
    }
    for name in ["native-store-meta-v2", "local-verified-restart-v1"] {
        let table = TableDefinition::<&str, &[u8]>::new(name);
        if let Ok(rows) = transaction.open_table(table) {
            for row in rows.iter().unwrap() {
                let (k, v) = row.unwrap();
                h.update(k.value().as_bytes());
                h.update(v.value());
            }
        }
    }
    let rows = transaction
        .open_table(TableDefinition::<u64, &[u8]>::new("canonical-blocks-v2"))
        .unwrap();
    for row in rows.iter().unwrap() {
        let (k, v) = row.unwrap();
        h.update(&k.value().to_le_bytes());
        h.update(v.value());
    }
    let rows = transaction
        .open_table(TableDefinition::<&[u8], &[u8]>::new(
            "local-production-receipts-v1",
        ))
        .unwrap();
    for row in rows.iter().unwrap() {
        let (k, v) = row.unwrap();
        h.update(k.value());
        h.update(v.value());
    }
    h.finalize().to_hex().to_string()
}
fn tamper(path: &Path, f: impl FnOnce(&redb::WriteTransaction)) {
    let database = redb::Database::open(path).unwrap();
    let tx = database.begin_write().unwrap();
    f(&tx);
    tx.commit().unwrap();
}
#[test]
fn resume_maintenance_missing_cache_has_no_fallback_or_policy_write() {
    let directory = Directory::new(false, 1, false);
    crate::identity::NativeIdentity::initialize(
        &directory.0,
        crate::p2p::Binding::new(&local::load(&directory.0).unwrap()),
    )
    .unwrap();
    let before = snapshot(&directory.db());
    let verifier = CountingVerifier::default();
    let error =
        storage_maintain_resume_with_verifier(&directory.0, Role::Miner, 96, 1000, &verifier)
            .unwrap_err();
    assert!(
        error.contains("authenticated restart record required"),
        "{error}"
    );
    assert_eq!(verifier.transactions.get(), 0);
    assert_eq!(verifier.settlements.get(), 0);
    assert_eq!(snapshot(&directory.db()), before);
}
#[test]
fn resume_maintenance_refuses_stale_seal_head_index_and_receipt_before_mutation() {
    for kind in 0..5 {
        let directory = Directory::new(true, 1, true);
        match kind {
            0 => tamper(&directory.db(), |tx| {
                tx.open_table(TableDefinition::<&str, &[u8]>::new(
                    "local-verified-restart-v1",
                ))
                .unwrap()
                .remove("seal")
                .unwrap();
            }),
            1 => tamper(&directory.db(), |tx| {
                let mut table = tx
                    .open_table(TableDefinition::<&str, &[u8]>::new("native-store-meta-v2"))
                    .unwrap();
                let mut head = table.get("head").unwrap().unwrap().value().to_vec();
                head[40] ^= 1;
                table.insert("head", head.as_slice()).unwrap();
            }),
            2 => tamper(&directory.db(), |tx| {
                let mut table = tx
                    .open_table(TableDefinition::<&[u8], &[u8]>::new(
                        "local-production-receipts-v1",
                    ))
                    .unwrap();
                let key = table
                    .iter()
                    .unwrap()
                    .next()
                    .unwrap()
                    .unwrap()
                    .0
                    .value()
                    .to_vec();
                table.remove(key.as_slice()).unwrap();
            }),
            3 => {
                let store = directory.open();
                let id = store.canonical_id(1).unwrap();
                drop(store);
                std::fs::remove_file(
                    directory
                        .0
                        .join(format!("reward-{}.secret", local::hex(&id))),
                )
                .unwrap();
            }
            _ => tamper(&directory.db(), |tx| {
                let mut table = tx
                    .open_table(TableDefinition::<u64, &[u8]>::new("canonical-blocks-v2"))
                    .unwrap();
                let row = table.get(1).unwrap().unwrap().value().to_vec();
                table.insert(2, row.as_slice()).unwrap();
            }),
        }
        let before = snapshot(&directory.db());
        let verifier = CountingVerifier::default();
        assert!(
            storage_maintain_resume_with_verifier(&directory.0, Role::Miner, 96, 1000, &verifier)
                .is_err(),
            "kind {kind}"
        );
        assert_eq!(verifier.transactions.get(), 0);
        assert_eq!(verifier.settlements.get(), 0);
        assert_eq!(snapshot(&directory.db()), before, "kind {kind}");
    }
}
#[test]
fn resume_maintenance_replays_only_retained_tail_and_preserves_permanent_state_and_rewards() {
    let directory = Directory::new(true, 100, true);
    let store = directory.open();
    let expected = store.state().clone();
    let rewards = store.miner_reward_view().unwrap();
    let ids: Vec<_> = (1..=100).map(|h| store.canonical_id(h).unwrap()).collect();
    drop(store);
    let verifier = CountingVerifier::default();
    let report =
        storage_maintain_resume_with_verifier(&directory.0, Role::Miner, 96, 1000, &verifier)
            .unwrap();
    assert_eq!(report["authenticated_restart_only"], true);
    assert_eq!(report["historical_prefix_proof_replay_checked"], false);
    assert_eq!(report["proof_tail_replay_checked"], true);
    assert_eq!(report["local_reward_receipts_checked"], 100);
    assert_eq!(report["expired_blocks"], 4);
    assert_eq!(report["before_head"], report["after_head"]);
    assert_eq!(report["after"]["retained_proof_blocks"], 96);
    assert_eq!(report["after"]["pruned_proof_blocks"], 4);
    assert_eq!(verifier.transactions.get(), 96 * 64);
    assert_eq!(verifier.settlements.get(), 96);
    let store = directory.open();
    assert_eq!(store.state().fingerprint(), expected.fingerprint());
    assert_eq!(store.state().cumulative_work, expected.cumulative_work);
    assert_eq!(store.verify_local_rewards().unwrap(), 100);
    assert_eq!(store.miner_reward_view().unwrap(), rewards);
    assert_eq!(
        (1..=100)
            .map(|h| store.canonical_id(h).unwrap())
            .collect::<Vec<_>>(),
        ids
    );
    assert!(store.block(4).is_err());
    assert!(store.block(5).is_ok());
    drop(store);
    assert!(restart_check_offline(&directory.0).is_ok());
}
#[test]
fn resume_maintenance_retained_proof_rejection_returns_no_success_and_preserves_chain_state() {
    let directory = Directory::new(true, 100, false);
    let store = directory.open();
    let expected = store.state().fingerprint();
    drop(store);
    let verifier = CountingVerifier {
        reject: true,
        ..Default::default()
    };
    assert!(
        storage_maintain_resume_with_verifier(&directory.0, Role::Miner, 96, 1000, &verifier)
            .is_err()
    );
    assert!(verifier.transactions.get() > 0);
    let store = directory.open();
    assert_eq!(store.state().fingerprint(), expected);
    // Pruning is durable even if the later independent proof audit fails.
    assert_eq!(
        store.storage_metrics().unwrap()["retained_proof_blocks"],
        96
    );
}
#[test]
fn resume_maintenance_requires_idle_lease_and_local_role_before_database_mutation() {
    let directory = Directory::new(true, 1, false);
    let before = snapshot(&directory.db());
    let verifier = CountingVerifier::default();
    let lease = Lease::acquire(&directory.0).unwrap();
    let error =
        storage_maintain_resume_with_verifier(&directory.0, Role::Miner, 96, 1000, &verifier)
            .unwrap_err();
    assert!(error.contains("holds the engineering lease"));
    drop(lease);
    for role in [Role::Bootstrap, Role::Validator] {
        assert!(
            storage_maintain_resume_with_verifier(&directory.0, role, 96, 1000, &verifier).is_err()
        );
    }
    assert!(
        storage_maintain_resume_with_verifier(&directory.0, Role::Ordinary, 23, 1000, &verifier)
            .is_err()
    );
    assert_eq!(verifier.transactions.get(), 0);
    assert_eq!(snapshot(&directory.db()), before);
}

#[test]
fn resume_maintenance_refuses_existing_service_policy_without_changing_it() {
    for role in [Role::Bootstrap, Role::Validator] {
        let directory = Directory::new(true, 1, false);
        let mut store = directory.open();
        store.configure_storage(role).unwrap();
        drop(store);
        let before = snapshot(&directory.db());
        let verifier = CountingVerifier::default();
        let error =
            storage_maintain_resume_with_verifier(&directory.0, Role::Miner, 96, 1000, &verifier)
                .unwrap_err();
        assert!(error.contains("cannot migrate a service-node storage policy"));
        assert_eq!(directory.open().storage_role().unwrap(), Some(role));
        assert_eq!(snapshot(&directory.db()), before);
        assert_eq!(verifier.transactions.get(), 0);
    }
}
#[test]
fn resume_maintenance_rejects_corrupted_retained_proof_without_repairing_its_bytes() {
    let directory = Directory::new(true, 1, false);
    let store = directory.open();
    let expected = store.state().fingerprint();
    let mut block = store.block(1).unwrap();
    drop(store);
    block.transactions[0].proof = vec![2];
    let mut row = block.encode().unwrap();
    row.extend_from_slice(&expected);
    tamper(&directory.db(), |tx| {
        tx.open_table(TableDefinition::<u64, &[u8]>::new("canonical-blocks-v2"))
            .unwrap()
            .insert(1, row.as_slice())
            .unwrap();
    });
    let verifier = CountingVerifier::default();
    assert!(
        storage_maintain_resume_with_verifier(&directory.0, Role::Miner, 96, 1000, &verifier)
            .is_err()
    );
    let database = redb::Database::open(directory.db()).unwrap();
    let transaction = database.begin_read().unwrap();
    let table = transaction
        .open_table(TableDefinition::<u64, &[u8]>::new("canonical-blocks-v2"))
        .unwrap();
    assert_eq!(table.get(1).unwrap().unwrap().value(), row);
}
