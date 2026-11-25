use p3_field::PrimeCharacteristicRing;
use siworld_native_proof::common::{Digest, F};
use siworld_native_proof::snapshots::{
    ACCEPTED_SNAPSHOT_LIMIT, AdmissionError, CanonicalSnapshot, RemovalReason, SnapshotError,
    SnapshotId, SnapshotPool,
};

fn block_id(height: u64, branch: u8) -> [u8; 32] {
    let mut id = [branch; 32];
    id[..8].copy_from_slice(&height.to_le_bytes());
    id
}

fn snapshot(height: u64, branch: u8, parent_branch: u8) -> CanonicalSnapshot {
    CanonicalSnapshot {
        id: SnapshotId {
            height,
            block_id: block_id(height, branch),
        },
        parent_block_id: block_id(height.saturating_sub(1), parent_branch),
        recent_roots_root: [F::from_u32((height as u32).wrapping_add(branch as u32)); 12],
    }
}

fn nullifiers(seed: u32) -> [Digest; 2] {
    [[F::from_u32(seed); 12], [F::from_u32(seed + 1); 12]]
}

fn chain(tip: u64) -> SnapshotPool<&'static str> {
    let mut pool = SnapshotPool::new(snapshot(0, 1, 0)).unwrap();
    for height in 1..=tip {
        pool.append_canonical(snapshot(height, 1, 1)).unwrap();
    }
    pool
}

#[test]
fn accepts_the_4096th_newest_snapshot_and_rejects_the_4097th() {
    let mut pool = chain(4095);
    assert_eq!(pool.accepted_len(), ACCEPTED_SNAPSHOT_LIMIT);
    assert!(pool.accepted_root(snapshot(0, 1, 0).id).is_some());
    let change = pool.append_canonical(snapshot(4096, 1, 1)).unwrap();
    assert!(pool.accepted_root(snapshot(0, 1, 0).id).is_none());
    assert!(pool.accepted_root(snapshot(1, 1, 1).id).is_some());
    assert_eq!(change.removed_snapshots.len(), 1);
    assert_eq!(change.removed_snapshots[0].reason, RemovalReason::Expired);
    assert_eq!(pool.accepted_len(), ACCEPTED_SNAPSHOT_LIMIT);
}

#[test]
fn root_lookup_uses_a_canonical_identity_and_the_trusted_stored_root() {
    let pool = chain(3);
    let canonical = snapshot(2, 1, 1);
    assert_eq!(
        pool.accepted_root(canonical.id),
        Some(&canonical.recent_roots_root)
    );
    assert!(pool.accepted_root(snapshot(2, 2, 1).id).is_none());
    assert!(pool.accepted_root(snapshot(4, 1, 1).id).is_none());
}

#[test]
fn expiry_evicts_pending_entries_and_releases_nullifier_reservations() {
    let mut pool = chain(4095);
    let expired = snapshot(0, 1, 0).id;
    let retained = snapshot(1, 1, 1).id;
    pool.insert_verified([1; 32], expired, nullifiers(10), "reprove")
        .unwrap();
    pool.insert_verified([2; 32], retained, nullifiers(20), "retain")
        .unwrap();
    let change = pool.append_canonical(snapshot(4096, 1, 1)).unwrap();
    assert_eq!(change.evicted_transactions.len(), 1);
    let evicted = &change.evicted_transactions[0];
    assert_eq!(evicted.transaction_id, [1; 32]);
    assert_eq!(evicted.snapshot_id, expired);
    assert_eq!(evicted.reason, RemovalReason::Expired);
    assert_eq!(evicted.payload, "reprove");
    assert!(!pool.is_reserved(&nullifiers(10)[0]));
    assert!(!pool.is_reserved(&nullifiers(10)[1]));
    assert!(pool.is_reserved(&nullifiers(20)[0]));
    assert_eq!(pool.pending_len(), 1);
    assert!(pool.contains_pending(&[2; 32]));
    assert_eq!(
        pool.insert_verified([3; 32], expired, nullifiers(30), "late"),
        Err(AdmissionError::UnknownSnapshot)
    );
}

#[test]
fn reorg_removes_orphans_and_evicts_only_entries_bound_to_removed_snapshots() {
    let mut pool = chain(3);
    let ancestor = snapshot(1, 1, 1).id;
    let orphan = snapshot(2, 1, 1).id;
    pool.insert_verified([2; 32], orphan, nullifiers(10), "orphan")
        .unwrap();
    pool.insert_verified([1; 32], ancestor, nullifiers(20), "stable")
        .unwrap();
    let replacement = [snapshot(2, 2, 1), snapshot(3, 2, 2), snapshot(4, 2, 2)];
    let change = pool
        .replace_canonical_suffix(ancestor, &replacement)
        .unwrap();
    assert!(pool.accepted_root(orphan).is_none());
    assert!(pool.accepted_root(snapshot(3, 1, 1).id).is_none());
    assert_eq!(
        pool.accepted_root(replacement[0].id),
        Some(&replacement[0].recent_roots_root)
    );
    assert_eq!(pool.tip(), &replacement[2]);
    assert_eq!(change.removed_snapshots.len(), 2);
    assert!(
        change
            .removed_snapshots
            .iter()
            .all(|entry| entry.reason == RemovalReason::Orphaned)
    );
    assert_eq!(change.evicted_transactions.len(), 1);
    assert_eq!(
        change.evicted_transactions[0].reason,
        RemovalReason::Orphaned
    );
    assert_eq!(change.evicted_transactions[0].payload, "orphan");
    assert!(!pool.is_reserved(&nullifiers(10)[0]));
    assert!(pool.contains_pending(&[1; 32]));
}

#[test]
fn invalid_chain_updates_leave_snapshots_and_pending_entries_unchanged() {
    let mut pool = chain(3);
    let tip = pool.tip().clone();
    pool.insert_verified([1; 32], tip.id, nullifiers(10), "retain")
        .unwrap();
    assert_eq!(
        pool.append_canonical(snapshot(5, 1, 1)).unwrap_err(),
        SnapshotError::UnexpectedHeight
    );
    assert_eq!(
        pool.append_canonical(snapshot(4, 1, 2)).unwrap_err(),
        SnapshotError::ParentMismatch
    );
    let invalid = [snapshot(2, 2, 1), snapshot(3, 2, 1)];
    assert_eq!(
        pool.replace_canonical_suffix(snapshot(1, 1, 1).id, &invalid)
            .unwrap_err(),
        SnapshotError::ParentMismatch
    );
    assert_eq!(
        pool.replace_canonical_suffix(snapshot(1, 9, 1).id, &[])
            .unwrap_err(),
        SnapshotError::UnknownAncestor
    );
    assert_eq!(pool.tip(), &tip);
    assert_eq!(pool.accepted_len(), 4);
    assert!(pool.contains_pending(&[1; 32]));
    assert!(pool.is_reserved(&nullifiers(10)[0]));
}

#[test]
fn a_snapshot_identity_cannot_be_rebound_to_another_root() {
    let mut pool = chain(3);
    let original = snapshot(2, 1, 1);
    let mut changed = original.clone();
    changed.recent_roots_root[0] += F::ONE;
    assert_eq!(
        pool.replace_canonical_suffix(snapshot(1, 1, 1).id, &[changed])
            .unwrap_err(),
        SnapshotError::ConflictingSnapshot
    );
    assert_eq!(
        pool.accepted_root(original.id),
        Some(&original.recent_roots_root)
    );
}

#[test]
fn pending_conflicts_are_atomic_and_removal_releases_both_nullifiers() {
    let mut pool = chain(1);
    let current = pool.tip().id;
    let pair = nullifiers(10);
    pool.insert_verified([1; 32], current, pair, "first")
        .unwrap();
    assert_eq!(
        pool.insert_verified([1; 32], current, nullifiers(20), "duplicate"),
        Err(AdmissionError::DuplicateTransaction)
    );
    assert_eq!(
        pool.insert_verified([2; 32], current, [pair[0], nullifiers(30)[0]], "conflict"),
        Err(AdmissionError::NullifierConflict)
    );
    assert_eq!(
        pool.insert_verified([3; 32], current, [pair[0], pair[0]], "duplicate nullifier"),
        Err(AdmissionError::DuplicateNullifier)
    );
    assert_eq!(pool.pending_len(), 1);
    assert!(!pool.is_reserved(&nullifiers(20)[0]));
    assert!(!pool.is_reserved(&nullifiers(30)[0]));
    assert_eq!(pool.remove_pending(&[1; 32]), Some("first"));
    assert!(!pool.is_reserved(&pair[0]));
    assert!(!pool.is_reserved(&pair[1]));
}

#[test]
fn equal_tree_roots_do_not_keep_an_orphan_snapshot_identity_accepted() {
    let mut pool = chain(2);
    let orphan = pool.tip().clone();
    let mut replacement = snapshot(2, 2, 1);
    replacement.recent_roots_root = orphan.recent_roots_root;
    pool.replace_canonical_suffix(snapshot(1, 1, 1).id, &[replacement.clone()])
        .unwrap();
    assert!(pool.accepted_root(orphan.id).is_none());
    assert_eq!(
        pool.accepted_root(replacement.id),
        Some(&orphan.recent_roots_root)
    );
}

#[test]
fn replacing_an_identical_suffix_keeps_its_pending_entry() {
    let mut pool = chain(2);
    let original = pool.tip().clone();
    pool.insert_verified([1; 32], original.id, nullifiers(10), "retain")
        .unwrap();
    let change = pool
        .replace_canonical_suffix(snapshot(1, 1, 1).id, &[original])
        .unwrap();
    assert!(change.removed_snapshots.is_empty());
    assert!(change.evicted_transactions.is_empty());
    assert_eq!(pool.pending_len(), 1);
}

#[test]
fn height_overflow_is_rejected_without_mutation() {
    let history: Vec<_> = ((u64::MAX - 4095)..=u64::MAX)
        .map(|height| snapshot(height, 1, 1))
        .collect();
    let mut pool: SnapshotPool<()> = SnapshotPool::from_canonical_history(&history).unwrap();
    let tip = pool.tip().clone();
    assert_eq!(
        pool.append_canonical(snapshot(0, 2, 1)).unwrap_err(),
        SnapshotError::HeightOverflow
    );
    assert_eq!(pool.tip(), &tip);
}

#[test]
fn shorter_reorg_requires_authoritative_refill_for_revived_boundary_snapshot() {
    let mut pool = chain(4096);
    let old_tip = pool.tip().clone();
    let ancestor = snapshot(4095, 1, 1).id;
    assert!(pool.accepted_root(snapshot(0, 1, 0).id).is_none());
    assert_eq!(
        pool.replace_canonical_suffix(ancestor, &[]).unwrap_err(),
        SnapshotError::IncompleteHistory
    );
    assert_eq!(pool.tip(), &old_tip);
    let change = pool
        .replace_canonical_suffix_with_refill(ancestor, &[], &[snapshot(0, 1, 0)])
        .unwrap();
    assert_eq!(pool.accepted_len(), ACCEPTED_SNAPSHOT_LIMIT);
    assert!(pool.accepted_root(snapshot(0, 1, 0).id).is_some());
    assert!(pool.accepted_root(old_tip.id).is_none());
    assert_eq!(change.removed_snapshots.len(), 1);
    assert_eq!(change.removed_snapshots[0].reason, RemovalReason::Orphaned);
}

#[test]
fn actual_native_proof_binds_snapshot_identity_and_rejects_expiry_or_orphan_reenveloping() {
    use siworld_native_proof::FriParams;
    use siworld_native_proof::codec::{ProofContext, PublicTransaction};
    use siworld_native_proof::common::{FEE_BASE, Hasher, acc_witnesses, sample_slot};
    use siworld_native_proof::encryption::{ChangeCiphertext, PaymentCiphertext};
    use siworld_native_proof::snapshots::{
        PreparedSnapshotVerifier, SnapshotBytesVerification, SnapshotVerification,
    };
    use siworld_native_proof::transaction::TransactionProver;

    let witness = acc_witnesses(vec![sample_slot(820, false)], 1200, FEE_BASE, 821)
        .0
        .remove(0);
    let fields = witness.slot.public_inputs(&Hasher::new());
    let public = PublicTransaction {
        nf: fields.nf,
        cm: fields.cm_out,
        payment: PaymentCiphertext {
            kem_ciphertext: [1; 1088],
            body: [2; 208],
            tag: [3; 16],
            view_tag: 4,
        },
        change: ChangeCiphertext {
            nonce: [5; 12],
            body: [6; 208],
            tag: [7; 16],
            view_tag: 8,
        },
    };
    let mut proof_snapshot = snapshot(2, 1, 1);
    let context = ProofContext::for_snapshot(
        [9; 32],
        proof_snapshot.id.height,
        proof_snapshot.id.block_id,
    );
    let witness = public.bind_witness(&witness, &context).unwrap();
    let prover = TransactionProver::new(FriParams::fast());
    let (proof, _) = prover.prove(&witness);
    let request = SnapshotVerification {
        transaction: &public,
        prover: &prover,
        proof: &proof,
        context: &context,
        fee_commit: &fields.fee_commit,
    };
    proof_snapshot.recent_roots_root = witness.anchors_root(&Hasher::new());
    let mut pool: SnapshotPool<&str> = chain(1);
    pool.append_canonical(proof_snapshot.clone()).unwrap();
    for height in 3..=4097 {
        let mut next = snapshot(height, 1, 1);
        if height == 3 {
            next.recent_roots_root = proof_snapshot.recent_roots_root;
        }
        pool.append_canonical(next).unwrap();
    }
    // Height two is now the 4096th newest accepted snapshot. A proof cannot
    // select another accepted identity, even when both state roots are equal.
    pool.verify_transaction(proof_snapshot.id, &request)
        .unwrap();
    assert!(matches!(
        pool.verify_transaction(snapshot(3, 1, 1).id, &request),
        Err(AdmissionError::InvalidProof(_))
    ));
    let misleading_context = context.bind_snapshot(999, [99; 32]);
    let misleading_request = SnapshotVerification {
        context: &misleading_context,
        ..request
    };
    pool.verify_transaction(proof_snapshot.id, &misleading_request)
        .unwrap();
    let verifier = PreparedSnapshotVerifier::new(&prover).unwrap();
    let proof_body = postcard::to_allocvec(&proof).unwrap();
    let bytes_request = SnapshotBytesVerification {
        transaction: &public,
        verifier: &verifier,
        proof_body: &proof_body,
        context: &context,
        fee_commit: &fields.fee_commit,
    };
    let mut extended = proof_body.clone();
    extended.push(0);
    let invalid_request = SnapshotBytesVerification {
        proof_body: &extended,
        ..bytes_request
    };
    assert!(matches!(
        pool.verify_bytes_and_insert([8; 32], proof_snapshot.id, &invalid_request, "reject"),
        Err(AdmissionError::InvalidEncoding(_))
    ));
    assert_eq!(pool.pending_len(), 0);
    assert!(!pool.is_reserved(&public.nf[0]));
    pool.verify_bytes_and_insert([8; 32], proof_snapshot.id, &bytes_request, "reprove")
        .unwrap();
    let change = pool.append_canonical(snapshot(4098, 1, 1)).unwrap();
    assert_eq!(change.evicted_transactions[0].payload, "reprove");
    assert_eq!(
        pool.verify_transaction(proof_snapshot.id, &request),
        Err(AdmissionError::UnknownSnapshot)
    );
    assert!(!pool.is_reserved(&public.nf[0]));
    assert_eq!(
        pool.verify_bytes_and_insert([8; 32], proof_snapshot.id, &invalid_request, "expired"),
        Err(AdmissionError::UnknownSnapshot)
    );

    let mut fork: SnapshotPool<&str> = chain(1);
    let ancestor = fork.tip().id;
    let original = proof_snapshot.clone();
    fork.append_canonical(original.clone()).unwrap();
    fork.verify_and_insert([8; 32], original.id, &request, "orphan")
        .unwrap();
    let mut replacement = snapshot(2, 2, 1);
    replacement.recent_roots_root = original.recent_roots_root;
    fork.replace_canonical_suffix(ancestor, &[replacement.clone()])
        .unwrap();
    assert_eq!(
        fork.verify_transaction(original.id, &request),
        Err(AdmissionError::UnknownSnapshot)
    );
    assert!(!fork.is_reserved(&public.nf[0]));
    assert!(matches!(
        fork.verify_and_insert([8; 32], replacement.id, &request, "reject"),
        Err(AdmissionError::InvalidProof(_))
    ));
    assert!(matches!(
        fork.verify_bytes_and_insert([8; 32], replacement.id, &bytes_request, "reenveloped"),
        Err(AdmissionError::InvalidProof(_))
    ));
    assert_eq!(fork.pending_len(), 0);
    assert!(!fork.is_reserved(&public.nf[0]));
    assert!(!fork.is_reserved(&public.nf[1]));
}

#[test]
fn bootstrap_requires_the_complete_contiguous_canonical_window() {
    assert!(matches!(
        SnapshotPool::<()>::new(snapshot(1, 1, 1)),
        Err(SnapshotError::IncompleteHistory)
    ));
    let invalid = [snapshot(0, 1, 0), snapshot(1, 1, 2)];
    assert!(matches!(
        SnapshotPool::<()>::from_canonical_history(&invalid),
        Err(SnapshotError::ParentMismatch)
    ));
    let mut pool = chain(1);
    let mut reused_id = snapshot(2, 1, 1);
    reused_id.id.block_id = pool.tip().id.block_id;
    assert_eq!(
        pool.append_canonical(reused_id).unwrap_err(),
        SnapshotError::DuplicateBlockId
    );
    assert_eq!(pool.tip().id, snapshot(1, 1, 1).id);
}

#[test]
fn invalid_refill_is_atomic_and_does_not_accept_an_unrelated_boundary_root() {
    let mut pool = chain(4096);
    let old_tip = pool.tip().clone();
    let ancestor = snapshot(4095, 1, 1).id;
    assert_eq!(
        pool.replace_canonical_suffix_with_refill(ancestor, &[], &[snapshot(0, 2, 0)])
            .unwrap_err(),
        SnapshotError::ParentMismatch
    );
    assert_eq!(pool.tip(), &old_tip);
    assert!(pool.accepted_root(snapshot(0, 2, 0).id).is_none());
}

#[test]
fn multiple_evictions_have_deterministic_transaction_order() {
    let mut pool = chain(3);
    pool.insert_verified([3; 32], snapshot(2, 1, 1).id, nullifiers(30), "third")
        .unwrap();
    pool.insert_verified([1; 32], snapshot(3, 1, 1).id, nullifiers(10), "first")
        .unwrap();
    let change = pool
        .replace_canonical_suffix(snapshot(1, 1, 1).id, &[snapshot(2, 2, 1)])
        .unwrap();
    let ids: Vec<_> = change
        .evicted_transactions
        .iter()
        .map(|entry| entry.transaction_id)
        .collect();
    assert_eq!(ids, vec![[1; 32], [3; 32]]);
    assert_eq!(pool.pending_len(), 0);
    assert!(!pool.is_reserved(&nullifiers(10)[0]));
    assert!(!pool.is_reserved(&nullifiers(30)[0]));
}
