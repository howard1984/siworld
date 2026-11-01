//! Production lifecycle fixtures exercise persistence with a test proof verifier.
//! Reward encryption and recovery-receipt authentication use the actual primitives.
use super::*;
use crate::fixtures::{TestVerifier, candidate};
use native::codec::encode_digest;
use native::multi_asset::{F, Hasher};
use p3_field::PrimeCharacteristicRing;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join(format!(
            "siworld-production-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
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
fn setup(directory: &Directory) -> Node<TestVerifier> {
    let config = crate::state::Config::development([171; 32], 0).unwrap();
    Node::new(
        Store::open(directory.0.join("chain.redb"), config, &TestVerifier).unwrap(),
        TestVerifier,
    )
}
fn prepared(node: &Node<TestVerifier>, seed: u32) -> PreparedBlock {
    node.bind_produced(
        node.begin_production().unwrap(),
        crate::producer::production_fixture(node.state(), seed),
    )
    .unwrap()
}
fn assert_unchanged(node: &Node<TestVerifier>, fingerprint: Hash) {
    assert_eq!(node.state().fingerprint(), fingerprint);
}

#[test]
fn committed_production_keeps_authenticated_receipt_and_reopens_same_state() {
    let directory = Directory::new();
    let mut node = setup(&directory);
    let prepared = prepared(&node, 30_000);
    let id = prepared.block().id().unwrap();
    let config = node.state().config.clone();
    assert!(!directory.receipt(&id).exists());
    assert_eq!(node.commit_produced(prepared).unwrap(), id);
    let receipt = crate::local::read_reward(&directory.0, &id).unwrap();
    crate::producer::validate_reward_secret(&node.store().block(1).unwrap(), &receipt).unwrap();
    let fingerprint = node.state().fingerprint();
    assert_eq!(node.state().height, 1);
    drop(node);
    let reopened =
        Store::open_existing(directory.0.join("chain.redb"), config, &TestVerifier).unwrap();
    assert_eq!(reopened.state().fingerprint(), fingerprint);
}

#[test]
fn malformed_reward_receipt_is_rejected_before_any_receipt_or_chain_write() {
    let directory = Directory::new();
    let mut node = setup(&directory);
    let mut prepared = prepared(&node, 40_000);
    let fingerprint = node.state().fingerprint();
    let id = prepared.block().id().unwrap();
    prepared.produced.reward_secret[0] ^= 1;
    assert!(node.commit_produced(prepared).is_err());
    assert_unchanged(&node, fingerprint);
    assert!(!directory.receipt(&id).exists());
}

#[test]
fn existing_receipt_is_never_overwritten_and_failed_write_leaves_chain_unchanged() {
    let directory = Directory::new();
    let mut node = setup(&directory);
    let prepared = prepared(&node, 50_000);
    let id = prepared.block().id().unwrap();
    let fingerprint = node.state().fingerprint();
    crate::local::save_reward(&directory.0, &id, b"preserved fixture evidence").unwrap();
    assert!(node.commit_produced(prepared).is_err());
    assert_unchanged(&node, fingerprint);
    assert_eq!(
        std::fs::read(directory.receipt(&id)).unwrap(),
        b"preserved fixture evidence"
    );
}

#[test]
fn branch_adoption_invalidates_pending_production_without_writing_its_receipt() {
    let directory = Directory::new();
    let mut node = setup(&directory);
    let prepared = prepared(&node, 60_000);
    let id = prepared.block().id().unwrap();
    let incoming = candidate(node.state(), 70_000);
    node.import_branch(0, &[incoming], CandidatePolicy::default())
        .unwrap();
    let fingerprint = node.state().fingerprint();
    assert!(node.commit_produced(prepared).is_err());
    assert_unchanged(&node, fingerprint);
    assert!(!directory.receipt(&id).exists());
}

#[test]
fn identical_state_does_not_authorize_another_node_or_retired_generation() {
    let first = Directory::new();
    let second = Directory::new();
    let mut node = setup(&first);
    let mut other = setup(&second);
    assert_eq!(node.state().fingerprint(), other.state().fingerprint());
    let foreign = prepared(&node, 80_000);
    let id = foreign.block().id().unwrap();
    assert!(other.commit_produced(foreign).is_err());
    assert!(!second.receipt(&id).exists());
    let stale = prepared(&node, 90_000);
    let fingerprint = node.state().fingerprint();
    node.production_generation += 1;
    assert!(node.commit_produced(stale).is_err());
    assert_unchanged(&node, fingerprint);
}

#[test]
fn exhausted_generation_rejects_production_and_branch_before_writing() {
    let directory = Directory::new();
    let mut node = setup(&directory);
    let produced = prepared(&node, 100_000);
    node.production_generation = u64::MAX;
    assert!(node.begin_production().is_err());
    let id = produced.block().id().unwrap();
    let fingerprint = node.state().fingerprint();
    assert!(node.commit_produced(produced).is_err());
    assert!(!directory.receipt(&id).exists());
    let incoming = candidate(node.state(), 110_000);
    assert!(
        node.import_branch(0, &[incoming], CandidatePolicy::default())
            .is_err()
    );
    assert_unchanged(&node, fingerprint);
}

#[test]
fn database_or_directory_replacement_prevents_receipt_and_chain_commit() {
    for replace_directory in [false, true] {
        let directory = Directory::new();
        let moved = Directory::new();
        let mut node = setup(&directory);
        let produced = prepared(&node, 120_000);
        let id = produced.block().id().unwrap();
        let fingerprint = node.state().fingerprint();
        if replace_directory {
            std::fs::remove_dir(&moved.0).unwrap();
            std::fs::rename(&directory.0, &moved.0).unwrap();
            std::fs::create_dir(&directory.0).unwrap();
        } else {
            std::fs::rename(directory.0.join("chain.redb"), moved.0.join("chain.redb")).unwrap();
            std::fs::write(directory.0.join("chain.redb"), b"replacement evidence").unwrap();
        }
        assert!(node.commit_produced(produced).is_err());
        assert_unchanged(&node, fingerprint);
        assert!(!directory.receipt(&id).exists());
        assert!(!moved.receipt(&id).exists());
        drop(node);
    }
}

#[test]
fn nonprivate_storage_and_symlink_receipts_cannot_accept_local_production() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    for mode in 0..4 {
        let directory = Directory::new();
        let mut node = setup(&directory);
        let produced = prepared(&node, 125_000);
        let id = produced.block().id().unwrap();
        let fingerprint = node.state().fingerprint();
        let preserved = directory.0.join("preserved");
        match mode {
            0 => std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o755))
                .unwrap(),
            1 => std::fs::set_permissions(
                directory.0.join("chain.redb"),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap(),
            2 => std::fs::hard_link(directory.0.join("chain.redb"), &preserved).unwrap(),
            _ => {
                std::fs::write(&preserved, b"preserved fixture evidence").unwrap();
                symlink(&preserved, directory.receipt(&id)).unwrap();
            }
        }
        assert!(node.commit_produced(produced).is_err());
        assert_unchanged(&node, fingerprint);
        if mode == 3 {
            assert_eq!(
                std::fs::read(&preserved).unwrap(),
                b"preserved fixture evidence"
            );
        } else {
            assert!(!directory.receipt(&id).exists());
        }
    }
}

#[test]
fn rejected_consensus_block_keeps_saved_receipt_for_review_and_head_unchanged() {
    let directory = Directory::new();
    let mut node = setup(&directory);
    let mut produced = prepared(&node, 130_000);
    produced.block_mut().settlement_proof[0] = 2;
    let id = produced.block().id().unwrap();
    let fingerprint = node.state().fingerprint();
    assert!(node.commit_produced(produced).is_err());
    assert_unchanged(&node, fingerprint);
    let receipt = crate::local::read_reward(&directory.0, &id).unwrap();
    assert!(!receipt.is_empty());
}

#[test]
fn accepted_production_reconciles_all_pending_queues() {
    use native::confidential_fees::FeeOpening;
    let directory = Directory::new();
    let mut node = setup(&directory);
    let mut produced = crate::producer::production_fixture(node.state(), 140_000);
    let opening = FeeOpening::dummy([F::from_u32(17); 8]);
    let tx = &mut produced.block.transactions[0];
    tx.record.fee_commit = encode_digest(&Hasher::new().fee_commit(0, &opening.blind));
    let envelope = tx.encode_envelope(&node.state().config.network).unwrap();
    let id = tx.record.statement_id(&node.state().config.network);
    let sidecar = Sidecar {
        transaction_id: id,
        fee: 0,
        blind: [17; 8],
    };
    // Test-only parallel reservations let this assertion cover both queue pruners.
    node.submit_local(&envelope, Some(&sidecar.encode().unwrap()))
        .unwrap();
    node.padding
        .insert(
            node.store.state(),
            crate::pool::Padding {
                transaction: tx.clone(),
                opening,
            },
            &TestVerifier,
        )
        .unwrap();
    let (signed, witness, _) = native::issuance::sample_issuance(3);
    let record = crate::issuance::IssuanceRecord {
        signed,
        ciphertexts: witness.ciphertexts,
        proof: vec![1],
        fee_commitment: encode_digest(&[F::from_u32(19); 12]),
        fee_rho: encode_digest(&[F::from_u32(20); 12]),
    };
    node.pending_issuances
        .insert(record.signed.declaration.binding(), record);
    assert_eq!(node.mempool.len(), 1);
    assert_eq!(node.padding.len(), 1);
    assert_eq!(node.pending_issuance_count(), 1);
    produced
        .block
        .transactions
        .sort_by_key(|tx| tx.record.statement_id(&produced.block.network));
    let prepared = node
        .bind_produced(node.begin_production().unwrap(), produced)
        .unwrap();
    node.commit_produced(prepared).unwrap();
    assert_eq!(node.mempool.len(), 0);
    assert_eq!(node.padding.len(), 0);
    assert_eq!(node.pending_issuance_count(), 0);
}

#[test]
fn external_production_permit_rejects_foreign_stale_and_restarted_owners() {
    let first = Directory::new();
    let second = Directory::new();
    let mut node = setup(&first);
    let other = setup(&second);
    let permit = node.begin_production().unwrap();
    let produced = crate::producer::production_fixture(node.state(), 150_000);
    let id = produced.block.id().unwrap();
    assert!(other.bind_produced(permit, produced).is_err());
    assert!(!first.receipt(&id).exists());
    assert!(!second.receipt(&id).exists());

    let permit = node.begin_production().unwrap();
    let produced = crate::producer::production_fixture(node.state(), 160_000);
    let id = produced.block.id().unwrap();
    node.import_branch(
        0,
        &[candidate(node.state(), 170_000)],
        CandidatePolicy::default(),
    )
    .unwrap();
    assert!(node.bind_produced(permit, produced).is_err());
    assert!(!first.receipt(&id).exists());

    let permit = node.begin_production().unwrap();
    let produced = crate::producer::production_fixture(node.state(), 180_000);
    let id = produced.block.id().unwrap();
    let config = node.state().config.clone();
    drop(node);
    let node = Node::new(
        Store::open_existing(first.0.join("chain.redb"), config, &TestVerifier).unwrap(),
        TestVerifier,
    );
    assert!(node.bind_produced(permit, produced).is_err());
    assert!(!first.receipt(&id).exists());
}

#[test]
fn durable_receipt_before_interrupted_append_can_resume_after_restart() {
    let directory = Directory::new();
    let node = setup(&directory);
    let produced = crate::producer::production_fixture(node.state(), 190_000);
    let id = produced.block.id().unwrap();
    let config = node.state().config.clone();
    let expected_receipt = produced.reward_secret.clone();
    node.store()
        .save_reward_receipt(&id, &produced.reward_secret)
        .unwrap();
    let fingerprint = node.state().fingerprint();
    drop(node);
    let mut node = Node::new(
        Store::open_existing(directory.0.join("chain.redb"), config, &TestVerifier).unwrap(),
        TestVerifier,
    );
    assert_eq!(node.state().fingerprint(), fingerprint);
    assert_eq!(node.state().height, 0);
    let prepared = node
        .bind_produced(node.begin_production().unwrap(), produced)
        .unwrap();
    assert_eq!(node.commit_produced(prepared).unwrap(), id);
    assert_eq!(node.state().height, 1);
    assert_eq!(
        crate::local::read_reward(&directory.0, &id)
            .unwrap()
            .as_slice(),
        expected_receipt.as_slice()
    );
}

#[test]
fn partial_or_linked_receipts_never_resume_or_change_the_canonical_head() {
    use std::os::unix::fs::PermissionsExt;
    for variant in 0..4 {
        let directory = Directory::new();
        let mut node = setup(&directory);
        let prepared = prepared(&node, 200_000);
        let id = prepared.block().id().unwrap();
        let fingerprint = node.state().fingerprint();
        crate::local::save_reward(&directory.0, &id, &prepared.produced.reward_secret).unwrap();
        match variant {
            0 => {
                let mut bytes = std::fs::read(directory.receipt(&id)).unwrap();
                bytes.pop();
                std::fs::write(directory.receipt(&id), bytes).unwrap();
            }
            1 => {
                let mut bytes = std::fs::read(directory.receipt(&id)).unwrap();
                bytes[0] ^= 1;
                std::fs::write(directory.receipt(&id), bytes).unwrap();
            }
            2 => std::fs::hard_link(directory.receipt(&id), directory.0.join("linked")).unwrap(),
            _ => std::fs::set_permissions(
                directory.receipt(&id),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap(),
        }
        let existing = std::fs::read(directory.receipt(&id)).unwrap();
        assert!(node.commit_produced(prepared).is_err());
        assert_unchanged(&node, fingerprint);
        assert_eq!(std::fs::read(directory.receipt(&id)).unwrap(), existing);
    }
}
