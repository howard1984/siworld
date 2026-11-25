//! Deterministic native snapshot acceptance and pending-transaction cleanup.
//!
//! The canonical chain updater supplies snapshots only after validating their
//! blocks and state transitions. Peer-provided roots cannot populate this index.
//! Each stored root commits to a separate depth-12 recent-anchor tree; the
//! accepted snapshot history does not alter that tree or the transaction AIR.
//! This engineering API is not connected to the retained node or network.

use crate::Cfg;
use crate::codec::{ProofContext, PublicTransaction, encode_digest};
use crate::common::Digest;
use crate::proof_codec::{ProofDecodeError, ProofShape};
use crate::transaction::TransactionProver;
use p3_uni_stark::Proof;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Number of canonical recent-root-tree snapshots accepted, including the tip.
/// This policy is independent of the number of anchors inside each tree.
pub const ACCEPTED_SNAPSHOT_LIMIT: usize = 4096;
pub type TransactionId = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SnapshotId {
    pub height: u64,
    pub block_id: [u8; 32],
}

/// State produced by a trusted, validated canonical block transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalSnapshot {
    pub id: SnapshotId,
    pub parent_block_id: [u8; 32],
    pub recent_roots_root: Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotError {
    UnexpectedHeight,
    HeightOverflow,
    ParentMismatch,
    DuplicateBlockId,
    ConflictingSnapshot,
    UnknownAncestor,
    IncompleteHistory,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    UnknownSnapshot,
    DuplicateTransaction,
    DuplicateNullifier,
    NullifierConflict,
    InvalidProof(String),
    InvalidEncoding(ProofDecodeError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemovalReason {
    Expired,
    Orphaned,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemovedSnapshot {
    pub snapshot_id: SnapshotId,
    pub reason: RemovalReason,
}

#[derive(Debug)]
pub struct EvictedTransaction<T> {
    pub transaction_id: TransactionId,
    pub snapshot_id: SnapshotId,
    pub reason: RemovalReason,
    /// Returned to the caller for wallet reproof/rebroadcast handling.
    pub payload: T,
}

#[derive(Debug)]
pub struct SnapshotChange<T> {
    pub removed_snapshots: Vec<RemovedSnapshot>,
    pub evicted_transactions: Vec<EvictedTransaction<T>>,
}

/// Trusted verifier/context and a structurally decoded typed proof.
/// Untrusted proof bytes must pass bounded decoding before constructing this view.
pub struct SnapshotVerification<'a> {
    pub transaction: &'a PublicTransaction,
    pub prover: &'a TransactionProver,
    pub proof: &'a Proof<Cfg>,
    pub context: &'a ProofContext,
    pub fee_commit: &'a Digest,
}

/// Decoder metadata prepared once from the same trusted prover artifacts used
/// for verification. A transaction cannot select a different schema or key.
pub struct PreparedSnapshotVerifier<'a> {
    prover: &'a TransactionProver,
    shape: ProofShape,
}

impl<'a> PreparedSnapshotVerifier<'a> {
    pub fn new(prover: &'a TransactionProver) -> Result<Self, ProofDecodeError> {
        let shape = ProofShape::from_trusted(&prover.air, &prover.vk, &prover.cfg)?;
        Ok(Self { prover, shape })
    }
}

/// Peer proof bytes paired with local verification metadata and decoded fields.
#[derive(Clone, Copy)]
pub struct SnapshotBytesVerification<'a, 'v> {
    pub transaction: &'a PublicTransaction,
    pub verifier: &'a PreparedSnapshotVerifier<'v>,
    pub proof_body: &'a [u8],
    pub context: &'a ProofContext,
    pub fee_commit: &'a Digest,
}

struct PendingTransaction<T> {
    snapshot_id: SnapshotId,
    nullifiers: [[u8; 48]; 2],
    payload: T,
}

/// Snapshot-bound pending entries and their nullifier reservations.
/// This is not a complete network mempool: byte/work quotas, proof-byte decoding,
/// confirmed-state conflicts and block inclusion remain caller responsibilities.
pub struct SnapshotPool<T> {
    snapshots: VecDeque<CanonicalSnapshot>,
    pending: BTreeMap<TransactionId, PendingTransaction<T>>,
    reservations: BTreeMap<[u8; 48], TransactionId>,
}

impl<T> SnapshotPool<T> {
    /// Initialize from trusted genesis state. A later starting point requires
    /// the complete accepted canonical window via `from_canonical_history`.
    pub fn new(genesis: CanonicalSnapshot) -> Result<Self, SnapshotError> {
        Self::from_canonical_history(&[genesis])
    }

    /// Restore the complete newest canonical window from trusted chain storage.
    /// Snapshots must be oldest first, contiguous, and include every accepted
    /// height. This function verifies index consistency, not block consensus.
    pub fn from_canonical_history(history: &[CanonicalSnapshot]) -> Result<Self, SnapshotError> {
        validate_window(history)?;
        Ok(Self {
            snapshots: history.iter().cloned().collect(),
            pending: BTreeMap::new(),
            reservations: BTreeMap::new(),
        })
    }

    pub fn tip(&self) -> &CanonicalSnapshot {
        self.snapshots.back().expect("validated nonempty history")
    }

    pub fn accepted_len(&self) -> usize {
        self.snapshots.len()
    }

    /// Resolve the root from trusted canonical state; an envelope supplies an
    /// identity, never the verification root itself.
    pub fn accepted_root(&self, id: SnapshotId) -> Option<&Digest> {
        self.snapshots
            .iter()
            .find(|snapshot| snapshot.id == id)
            .map(|snapshot| &snapshot.recent_roots_root)
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn contains_pending(&self, transaction_id: &TransactionId) -> bool {
        self.pending.contains_key(transaction_id)
    }

    pub fn is_reserved(&self, nullifier: &Digest) -> bool {
        self.reservations.contains_key(&encode_digest(nullifier))
    }

    /// Append one validated canonical state and atomically evict expired entries.
    pub fn append_canonical(
        &mut self,
        snapshot: CanonicalSnapshot,
    ) -> Result<SnapshotChange<T>, SnapshotError> {
        validate_successor(self.tip(), &snapshot)?;
        if self
            .snapshots
            .iter()
            .any(|known| known.id.block_id == snapshot.id.block_id)
        {
            return Err(SnapshotError::DuplicateBlockId);
        }
        self.snapshots.push_back(snapshot);
        let removed = if self.snapshots.len() > ACCEPTED_SNAPSHOT_LIMIT {
            vec![RemovedSnapshot {
                snapshot_id: self.snapshots.pop_front().expect("nonempty window").id,
                reason: RemovalReason::Expired,
            }]
        } else {
            Vec::new()
        };
        Ok(self.finish_change(removed))
    }

    /// Replace a canonical suffix. A shorter tip may need previously expired
    /// roots; reject atomically when the required trusted refill is absent.
    pub fn replace_canonical_suffix(
        &mut self,
        ancestor: SnapshotId,
        replacement: &[CanonicalSnapshot],
    ) -> Result<SnapshotChange<T>, SnapshotError> {
        self.replace_canonical_suffix_with_refill(ancestor, replacement, &[])
    }

    /// `older_prefix` supplies exactly the missing older window snapshots from
    /// authoritative chain storage after a shorter reorg. This never invents
    /// roots or restores previously evicted pending entries. The caller also
    /// enforces the chain's reorganization-depth and consensus rules.
    pub fn replace_canonical_suffix_with_refill(
        &mut self,
        ancestor: SnapshotId,
        replacement: &[CanonicalSnapshot],
        older_prefix: &[CanonicalSnapshot],
    ) -> Result<SnapshotChange<T>, SnapshotError> {
        let ancestor_index = self
            .snapshots
            .iter()
            .position(|entry| entry.id == ancestor)
            .ok_or(SnapshotError::UnknownAncestor)?;
        let mut next: VecDeque<_> = self
            .snapshots
            .iter()
            .take(ancestor_index + 1)
            .cloned()
            .collect();
        for snapshot in replacement {
            if let Some(known) = self
                .snapshots
                .iter()
                .find(|known| known.id.block_id == snapshot.id.block_id)
                && known != snapshot
            {
                return Err(SnapshotError::ConflictingSnapshot);
            }
            validate_successor(next.back().expect("ancestor exists"), snapshot)?;
            if next
                .iter()
                .any(|known| known.id.block_id == snapshot.id.block_id)
            {
                return Err(SnapshotError::DuplicateBlockId);
            }
            next.push_back(snapshot.clone());
            if next.len() > ACCEPTED_SNAPSHOT_LIMIT {
                next.pop_front();
            }
        }
        let tip_height = next.back().expect("ancestor exists").id.height;
        let first_height = tip_height.saturating_sub((ACCEPTED_SNAPSHOT_LIMIT - 1) as u64);
        let expected_len = (tip_height - first_height + 1) as usize;
        let missing = expected_len
            .checked_sub(next.len())
            .ok_or(SnapshotError::IncompleteHistory)?;
        if older_prefix.len() != missing {
            return Err(SnapshotError::IncompleteHistory);
        }
        for snapshot in older_prefix.iter().rev() {
            next.push_front(snapshot.clone());
        }
        let next: Vec<_> = next.into_iter().collect();
        validate_window(&next)?;
        let kept: BTreeSet<_> = next.iter().map(|entry| entry.id).collect();
        let removed = self
            .snapshots
            .iter()
            .filter(|entry| !kept.contains(&entry.id))
            .map(|entry| RemovedSnapshot {
                snapshot_id: entry.id,
                reason: if entry.id.height > ancestor.height {
                    RemovalReason::Orphaned
                } else {
                    RemovalReason::Expired
                },
            })
            .collect();
        self.snapshots = next.into();
        Ok(self.finish_change(removed))
    }

    /// Verify with the stored root and identity selected by canonical state.
    /// Snapshot expiry/orphaning is checked before cryptographic verification.
    /// The local network/format context cannot supply a competing snapshot
    /// binding: the selected height and block ID always replace it.
    pub fn verify_transaction(
        &self,
        snapshot_id: SnapshotId,
        request: &SnapshotVerification<'_>,
    ) -> Result<(), AdmissionError> {
        let root = self
            .accepted_root(snapshot_id)
            .ok_or(AdmissionError::UnknownSnapshot)?;
        let expected_context = request
            .context
            .bind_snapshot(snapshot_id.height, snapshot_id.block_id);
        request
            .transaction
            .verify(
                request.prover,
                request.proof,
                &expected_context,
                request.fee_commit,
                root,
            )
            .map_err(AdmissionError::InvalidProof)
    }

    /// Verify then atomically insert and reserve both nullifiers. Failed proof,
    /// unknown snapshot or conflict leaves all pending state unchanged.
    pub fn verify_and_insert(
        &mut self,
        transaction_id: TransactionId,
        snapshot_id: SnapshotId,
        request: &SnapshotVerification<'_>,
        payload: T,
    ) -> Result<(), AdmissionError> {
        self.check_admission(transaction_id, snapshot_id, &request.transaction.nf)?;
        self.verify_transaction(snapshot_id, request)?;
        self.insert_verified(transaction_id, snapshot_id, request.transaction.nf, payload)
    }

    /// Resolve the canonical snapshot, bound/decode proof bytes, verify, then
    /// reserve nullifiers and insert. All rejection paths leave state unchanged.
    /// The caller enforces outer-envelope, byte/work and confirmed-state limits.
    pub fn verify_bytes_and_insert(
        &mut self,
        transaction_id: TransactionId,
        snapshot_id: SnapshotId,
        request: &SnapshotBytesVerification<'_, '_>,
        payload: T,
    ) -> Result<(), AdmissionError> {
        self.check_admission(transaction_id, snapshot_id, &request.transaction.nf)?;
        let proof = request
            .verifier
            .shape
            .decode(request.proof_body)
            .map_err(AdmissionError::InvalidEncoding)?;
        let typed = SnapshotVerification {
            transaction: request.transaction,
            prover: request.verifier.prover,
            proof: &proof,
            context: request.context,
            fee_commit: request.fee_commit,
        };
        self.verify_and_insert(transaction_id, snapshot_id, &typed, payload)
    }

    /// Index a transaction already checked by the trusted admission caller.
    /// Prefer `verify_and_insert` when a typed proof is available. This method
    /// performs snapshot/conflict checks but cannot establish proof validity.
    pub fn insert_verified(
        &mut self,
        transaction_id: TransactionId,
        snapshot_id: SnapshotId,
        nullifiers: [Digest; 2],
        payload: T,
    ) -> Result<(), AdmissionError> {
        self.check_admission(transaction_id, snapshot_id, &nullifiers)?;
        let nullifiers = nullifiers.map(|nullifier| encode_digest(&nullifier));
        for nullifier in nullifiers {
            self.reservations.insert(nullifier, transaction_id);
        }
        self.pending.insert(
            transaction_id,
            PendingTransaction {
                snapshot_id,
                nullifiers,
                payload,
            },
        );
        Ok(())
    }

    pub fn remove_pending(&mut self, transaction_id: &TransactionId) -> Option<T> {
        self.remove_entry(transaction_id).map(|entry| entry.payload)
    }

    fn check_admission(
        &self,
        transaction_id: TransactionId,
        snapshot_id: SnapshotId,
        nullifiers: &[Digest; 2],
    ) -> Result<(), AdmissionError> {
        if self.accepted_root(snapshot_id).is_none() {
            return Err(AdmissionError::UnknownSnapshot);
        }
        if self.pending.contains_key(&transaction_id) {
            return Err(AdmissionError::DuplicateTransaction);
        }
        if nullifiers[0] == nullifiers[1] {
            return Err(AdmissionError::DuplicateNullifier);
        }
        if nullifiers.iter().any(|value| self.is_reserved(value)) {
            return Err(AdmissionError::NullifierConflict);
        }
        Ok(())
    }

    fn remove_entry(&mut self, transaction_id: &TransactionId) -> Option<PendingTransaction<T>> {
        let entry = self.pending.remove(transaction_id)?;
        for nullifier in entry.nullifiers {
            let owner = self.reservations.remove(&nullifier);
            debug_assert_eq!(owner, Some(*transaction_id));
        }
        Some(entry)
    }

    fn finish_change(&mut self, removed_snapshots: Vec<RemovedSnapshot>) -> SnapshotChange<T> {
        let reasons: BTreeMap<_, _> = removed_snapshots
            .iter()
            .map(|entry| (entry.snapshot_id, entry.reason))
            .collect();
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(id, entry)| reasons.get(&entry.snapshot_id).map(|reason| (*id, *reason)))
            .collect();
        let evicted_transactions = expired
            .into_iter()
            .map(|(id, reason)| {
                let entry = self.remove_entry(&id).expect("selected pending entry");
                EvictedTransaction {
                    transaction_id: id,
                    snapshot_id: entry.snapshot_id,
                    reason,
                    payload: entry.payload,
                }
            })
            .collect();
        SnapshotChange {
            removed_snapshots,
            evicted_transactions,
        }
    }
}

fn validate_successor(
    parent: &CanonicalSnapshot,
    child: &CanonicalSnapshot,
) -> Result<(), SnapshotError> {
    let expected = parent
        .id
        .height
        .checked_add(1)
        .ok_or(SnapshotError::HeightOverflow)?;
    if child.id.height != expected {
        return Err(SnapshotError::UnexpectedHeight);
    }
    if child.parent_block_id != parent.id.block_id {
        return Err(SnapshotError::ParentMismatch);
    }
    Ok(())
}

fn validate_window(history: &[CanonicalSnapshot]) -> Result<(), SnapshotError> {
    let tip = history.last().ok_or(SnapshotError::IncompleteHistory)?;
    let first_height = tip
        .id
        .height
        .saturating_sub((ACCEPTED_SNAPSHOT_LIMIT - 1) as u64);
    let expected_len = (tip.id.height - first_height + 1) as usize;
    if history.len() != expected_len || history[0].id.height != first_height {
        return Err(SnapshotError::IncompleteHistory);
    }
    let mut blocks = BTreeSet::new();
    for (index, snapshot) in history.iter().enumerate() {
        if !blocks.insert(snapshot.id.block_id) {
            return Err(SnapshotError::DuplicateBlockId);
        }
        if index > 0 {
            validate_successor(&history[index - 1], snapshot)?;
        }
    }
    Ok(())
}
