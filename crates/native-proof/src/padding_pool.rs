//! Bounded pre-generation of private, snapshot-bound empty transactions.
//!
//! This module exposes preparation and queue APIs; it does not run background
//! proving, change canonical state or connect to the retained node network.

use crate::codec::{ProofContext, PublicTransaction, encode_digest};
use crate::common::{
    ANCHOR_DEPTH, ANCHOR_RING, AccWitness, Digest, F, Hasher, InputWitness, OutputWitness,
    SlotWitness, TREE_DEPTH,
};
use crate::encryption::{
    EncryptionContext, EncryptionError, OutputPairCiphertexts, RecipientViewKey,
    SenderChangeSecret, check_output_pair_before_broadcast, encrypt_change,
    encrypt_payment_with_opening,
};
use crate::envelope::{
    EnvelopeError, FEE_SIDECAR_BYTES, FIXED_ENVELOPE_BYTES, FeeOpeningSidecar, FeeSidecarError,
    NativeEnvelope, statement_id, validate_fee_sidecar,
};
use crate::proof_codec::ProofShape;
use crate::snapshots::{SnapshotId, SnapshotPool, TransactionId};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use zeroize::Zeroizing;

pub const PADDING_POOL_TARGET: usize = 64;
pub const PADDING_POOL_MAX_ENTRIES: usize = 128;
/// Serialized envelopes and private sidecars; excludes bounded map metadata.
pub const PADDING_POOL_MAX_BYTES: usize = 65 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaddingError {
    Anchor,
    Entropy,
    Encryption(EncryptionError),
    Witness,
    SnapshotUnavailable,
    NonzeroFee,
    Sidecar(FeeSidecarError),
    Envelope(EnvelopeError),
    DuplicateTransaction,
    NullifierConflict,
    CountLimit,
    ByteLimit,
}

/// Private anchor witness selected from trusted canonical chain storage.
#[derive(Clone)]
pub struct EmptyAnchorWitness {
    pub anchor: Digest,
    pub anchor_height: u64,
    pub base_fee: u64,
    pub anchor_path: Vec<(Digest, bool)>,
}

impl EmptyAnchorWitness {
    pub fn from_witness(witness: &AccWitness) -> Self {
        Self {
            anchor: witness.slot.anchor,
            anchor_height: witness.anchor_height,
            base_fee: witness.base_fee,
            anchor_path: witness.anchor_path.clone(),
        }
    }
}

/// Locally checked zero-value witness with genuine payment/change encryption.
/// An authorized proving worker still has to produce and verify its native proof.
/// Temporary encryption keys are discarded after authenticated consistency checks.
pub struct PreparedEmptyTransaction {
    witness: AccWitness,
    transaction: PublicTransaction,
    context: ProofContext,
    fee_commit: Digest,
    sidecar: FeeOpeningSidecar,
}

impl PreparedEmptyTransaction {
    pub fn witness(&self) -> &AccWitness {
        &self.witness
    }
    pub fn transaction(&self) -> &PublicTransaction {
        &self.transaction
    }
    pub fn context(&self) -> ProofContext {
        self.context
    }
    pub fn fee_commit(&self) -> Digest {
        self.fee_commit
    }
    pub fn sidecar(&self) -> FeeOpeningSidecar {
        self.sidecar.clone()
    }
}

/// Prepare an empty transaction without a funded note. The trusted snapshot and
/// root must come from canonical storage. Zero-valued inputs retain fixed-width
/// paths but skip note-tree membership; the recent-root membership stays checked.
pub fn prepare_empty_transaction(
    network: [u8; 32],
    snapshot: SnapshotId,
    anchor: &EmptyAnchorWitness,
    accepted_root: &Digest,
) -> Result<PreparedEmptyTransaction, PaddingError> {
    let h = Hasher::new();
    if anchor.anchor_path.len() != ANCHOR_DEPTH
        || anchor.anchor_height > snapshot.height
        || snapshot.height - anchor.anchor_height >= ANCHOR_RING as u64
        || anchor.base_fee == 0
        || anchor.base_fee.checked_mul(4).is_none()
        || anchor
            .anchor_path
            .iter()
            .enumerate()
            .any(|(level, (_, right))| *right != (anchor.anchor_height >> level & 1 != 0))
        || h.merkle_root(
            &h.anchor_entry(&anchor.anchor, anchor.anchor_height, anchor.base_fee),
            &anchor.anchor_path,
        ) != *accepted_root
    {
        return Err(PaddingError::Anchor);
    }
    let inputs = [fresh_input()?, fresh_input()?];
    let recipient =
        RecipientViewKey::generate(h.owner(&random_digest()?)).map_err(PaddingError::Encryption)?;
    let address = recipient.address();
    let change_secret = SenderChangeSecret::generate().map_err(PaddingError::Encryption)?;
    let slot = SlotWitness {
        anchor: anchor.anchor,
        inputs,
        outputs: [
            OutputWitness {
                owner: address.owner(),
                value: 0,
                unlock_height: 0,
                rseed: random_digest()?,
            },
            OutputWitness {
                owner: h.owner(&random_digest()?),
                value: 0,
                unlock_height: 0,
                rseed: random_digest()?,
            },
        ],
        fee: 0,
        fee_blind: random_fields()?,
        fee_is_priority: false,
    };
    let fields = slot
        .check_with_base_fee(&h, anchor.base_fee)
        .map_err(|_| PaddingError::Witness)?;
    let notes = [
        slot.output_note(&h, &fields.nf, 0),
        slot.output_note(&h, &fields.nf, 1),
    ];
    let encryption_context = EncryptionContext::new(network);
    let (payment, opening) = encrypt_payment_with_opening(&address, &notes[0], &encryption_context)
        .map_err(PaddingError::Encryption)?;
    let change = encrypt_change(&change_secret, &notes[1], &encryption_context)
        .map_err(PaddingError::Encryption)?;
    let checked = check_output_pair_before_broadcast(
        OutputPairCiphertexts {
            commitments: fields.cm_out,
            payment,
            change,
        },
        &notes,
        &address,
        &opening,
        &change_secret,
        &encryption_context,
    )
    .map_err(PaddingError::Encryption)?;
    let transaction = PublicTransaction {
        nf: fields.nf,
        cm: *checked.commitments(),
        payment: checked.payment().clone(),
        change: checked.change().clone(),
    };
    let context = ProofContext::for_snapshot(network, snapshot.height, snapshot.block_id);
    let witness = transaction
        .bind_witness(
            &AccWitness {
                slot,
                d_ct: [0; 32],
                anchor_height: anchor.anchor_height,
                base_fee: anchor.base_fee,
                anchor_path: anchor.anchor_path.clone(),
            },
            &context,
        )
        .map_err(|_| PaddingError::Witness)?;
    witness
        .check(&h, accepted_root)
        .map_err(|_| PaddingError::Witness)?;
    let id = statement_id(&network, snapshot, &transaction, &fields.fee_commit);
    let sidecar = FeeOpeningSidecar::new(id, 0, witness.slot.fee_blind);
    Ok(PreparedEmptyTransaction {
        witness,
        transaction,
        context,
        fee_commit: fields.fee_commit,
        sidecar,
    })
}

fn random_fields<const N: usize>() -> Result<[F; N], PaddingError> {
    let mut fields = [F::ZERO; N];
    let mut bytes = Zeroizing::new([0u8; 4]);
    for field in &mut fields {
        loop {
            getrandom::fill(bytes.as_mut()).map_err(|_| PaddingError::Entropy)?;
            let value = u32::from_le_bytes(*bytes);
            if value < F::ORDER_U32 {
                *field = F::from_u32(value);
                break;
            }
        }
    }
    Ok(fields)
}
fn random_digest() -> Result<Digest, PaddingError> {
    random_fields()
}
fn fresh_input() -> Result<InputWitness, PaddingError> {
    Ok(InputWitness {
        nk: random_digest()?,
        rho: random_digest()?,
        rseed: random_digest()?,
        value: 0,
        unlock_height: 0,
        dummy: true,
        path: vec![([F::ZERO; 12], false); TREE_DEPTH],
    })
}

pub struct QueuedPadding {
    transaction_id: TransactionId,
    snapshot_id: SnapshotId,
    nullifiers: [Digest; 2],
    envelope: Vec<u8>,
    sidecar: Zeroizing<[u8; FEE_SIDECAR_BYTES]>,
}
impl QueuedPadding {
    pub fn transaction_id(&self) -> TransactionId {
        self.transaction_id
    }
    pub fn snapshot_id(&self) -> SnapshotId {
        self.snapshot_id
    }
    pub fn envelope_bytes(&self) -> &[u8] {
        &self.envelope
    }
    pub fn sidecar_bytes(&self) -> &[u8; FEE_SIDECAR_BYTES] {
        &self.sidecar
    }
    pub fn payload_bytes(&self) -> usize {
        self.envelope.len() + FEE_SIDECAR_BYTES
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscardReason {
    SnapshotUnavailable,
    Included,
    NullifierConflict,
}
pub struct DiscardedPadding {
    pub entry: QueuedPadding,
    pub reason: DiscardReason,
}

/// Local empty-proof inventory. The caller verifies each proof before enqueueing
/// and supplies confirmed-state nullifier conflicts at every admission/selection.
/// Queue entries do not reserve public mempool capacity or disclose private tier
/// flags. All methods are deterministic except the separate preparation helper.
pub struct PaddingPool {
    entries: BTreeMap<TransactionId, QueuedPadding>,
    order: VecDeque<TransactionId>,
    nullifiers: BTreeSet<[u8; 48]>,
    payload_bytes: usize,
    byte_limit: usize,
}

impl Default for PaddingPool {
    fn default() -> Self {
        Self::new()
    }
}
impl PaddingPool {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            order: VecDeque::new(),
            nullifiers: BTreeSet::new(),
            payload_bytes: 0,
            byte_limit: PADDING_POOL_MAX_BYTES,
        }
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }
    pub fn needs_refill(&self) -> bool {
        self.len() < PADDING_POOL_TARGET
    }

    /// Trusted-caller boundary: the complete native proof must already have
    /// verified against this envelope's canonical statement and snapshot root.
    /// This method independently checks syntax, zero-fee opening, snapshot,
    /// count/bytes and nullifier conflicts before changing the queue.
    pub fn enqueue_verified<T>(
        &mut self,
        envelope: &NativeEnvelope<'_>,
        sidecar: &FeeOpeningSidecar,
        shape: &ProofShape,
        snapshots: &SnapshotPool<T>,
        mut unavailable: impl FnMut(&Digest) -> bool,
    ) -> Result<(), PaddingError> {
        if snapshots.accepted_root(envelope.snapshot_id()).is_none() {
            return Err(PaddingError::SnapshotUnavailable);
        }
        if sidecar.fee() != 0 {
            return Err(PaddingError::NonzeroFee);
        }
        // The native transaction proof has already checked its private fee
        // schedule; this queue checks only the authenticated zero opening.
        validate_fee_sidecar(envelope, Some(sidecar)).map_err(PaddingError::Sidecar)?;
        let id = envelope.transaction_id();
        if self.entries.contains_key(&id) {
            return Err(PaddingError::DuplicateTransaction);
        }
        if self.len() >= PADDING_POOL_MAX_ENTRIES {
            return Err(PaddingError::CountLimit);
        }
        let payload = FIXED_ENVELOPE_BYTES + envelope.proof_body().len() + FEE_SIDECAR_BYTES;
        if self
            .payload_bytes
            .checked_add(payload)
            .filter(|n| *n <= self.byte_limit)
            .is_none()
        {
            return Err(PaddingError::ByteLimit);
        }
        let nullifiers = envelope.transaction().nf;
        if nullifiers.iter().any(|nf| {
            self.nullifiers.contains(&encode_digest(nf))
                || snapshots.is_reserved(nf)
                || unavailable(nf)
        }) {
            return Err(PaddingError::NullifierConflict);
        }
        let bytes = envelope.encode(shape).map_err(PaddingError::Envelope)?;
        let entry = QueuedPadding {
            transaction_id: id,
            snapshot_id: envelope.snapshot_id(),
            nullifiers,
            envelope: bytes,
            sidecar: Zeroizing::new(sidecar.encode()),
        };
        for nf in &nullifiers {
            self.nullifiers.insert(encode_digest(nf));
        }
        self.payload_bytes += entry.payload_bytes();
        self.entries.insert(id, entry);
        self.order.push_back(id);
        Ok(())
    }

    /// Invalidate expired/orphaned snapshots, included transactions and newly
    /// unavailable nullifiers after a canonical-chain or mempool update.
    pub fn reconcile<T>(
        &mut self,
        snapshots: &SnapshotPool<T>,
        included: &BTreeSet<TransactionId>,
        mut unavailable: impl FnMut(&Digest) -> bool,
    ) -> Vec<DiscardedPadding> {
        let discarded: Vec<_> = self
            .entries
            .iter()
            .filter_map(|(id, entry)| {
                let reason = if snapshots.accepted_root(entry.snapshot_id).is_none() {
                    DiscardReason::SnapshotUnavailable
                } else if included.contains(id) {
                    DiscardReason::Included
                } else if entry
                    .nullifiers
                    .iter()
                    .any(|nf| snapshots.is_reserved(nf) || unavailable(nf))
                {
                    DiscardReason::NullifierConflict
                } else {
                    return None;
                };
                Some((*id, reason))
            })
            .collect();
        let mut removed = Vec::with_capacity(discarded.len());
        for (id, reason) in discarded {
            removed.push(DiscardedPadding {
                entry: self.remove(&id).expect("selected queue entry"),
                reason,
            });
        }
        removed
    }

    /// Recheck canonical dependencies immediately before handing a proof to a
    /// block builder. Selection releases only this queue's private reservations.
    pub fn take_ready<T>(
        &mut self,
        snapshots: &SnapshotPool<T>,
        included: &BTreeSet<TransactionId>,
        unavailable: impl FnMut(&Digest) -> bool,
    ) -> (Option<QueuedPadding>, Vec<DiscardedPadding>) {
        let discarded = self.reconcile(snapshots, included, unavailable);
        let next = self.order.front().copied().and_then(|id| self.remove(&id));
        (next, discarded)
    }

    fn remove(&mut self, id: &TransactionId) -> Option<QueuedPadding> {
        let entry = self.entries.remove(id)?;
        self.order.retain(|known| known != id);
        for nf in &entry.nullifiers {
            self.nullifiers.remove(&encode_digest(nf));
        }
        self.payload_bytes -= entry.payload_bytes();
        Some(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FriParams;
    use crate::common::{FEE_BASE, FEE_BLIND_LEN, acc_witnesses, sample_slot};
    use crate::envelope::tests::fixture;
    use crate::snapshots::CanonicalSnapshot;
    use crate::transaction::TransactionProver;

    fn snapshot(height: u64, block: u8, parent: u8, root: Digest) -> CanonicalSnapshot {
        CanonicalSnapshot {
            id: SnapshotId {
                height,
                block_id: [block; 32],
            },
            parent_block_id: [parent; 32],
            recent_roots_root: root,
        }
    }

    // Queue-policy fixtures use structurally admitted bodies only. Cryptographic
    // validity is the enqueue_verified caller contract, tested separately below.
    fn structural_entry(index: u32, snapshot: SnapshotId) -> (Vec<u8>, FeeOpeningSidecar) {
        let f = fixture();
        let mut transaction = f.transaction.clone();
        transaction.nf[0] = [F::from_u32(2 * index + 1); 12];
        transaction.nf[1] = [F::from_u32(2 * index + 2); 12];
        let blind = [F::from_u32(index); FEE_BLIND_LEN];
        let fee = Hasher::new().fee_commit(0, &blind);
        let envelope =
            NativeEnvelope::from_parts([9; 32], snapshot, transaction, fee, &f.body, &f.shape)
                .unwrap();
        let sidecar = FeeOpeningSidecar::new(envelope.transaction_id(), 0, blind);
        (envelope.encode(&f.shape).unwrap(), sidecar)
    }

    fn enqueue(
        pool: &mut PaddingPool,
        index: u32,
        snapshots: &SnapshotPool<()>,
    ) -> Result<(), PaddingError> {
        let (bytes, sidecar) = structural_entry(index, snapshots.tip().id);
        let envelope = NativeEnvelope::decode(&bytes, &[9; 32], &fixture().shape).unwrap();
        pool.enqueue_verified(&envelope, &sidecar, &fixture().shape, snapshots, |_| false)
    }

    #[test]
    fn fresh_empty_preparation_uses_real_encryption_and_native_proof() {
        let h = Hasher::new();
        let (mut witnesses, root) = acc_witnesses(vec![sample_slot(301, false)], 0, FEE_BASE, 302);
        let anchor = EmptyAnchorWitness::from_witness(&witnesses.remove(0));
        let snapshots = SnapshotPool::<()>::new(snapshot(0, 1, 0, root)).unwrap();
        let prepared =
            prepare_empty_transaction([9; 32], snapshots.tip().id, &anchor, &root).unwrap();
        let other = prepare_empty_transaction([9; 32], snapshots.tip().id, &anchor, &root).unwrap();
        assert_ne!(prepared.transaction().nf, other.transaction().nf);
        assert_ne!(
            prepared.transaction().payment.kem_ciphertext,
            other.transaction().payment.kem_ciphertext
        );
        assert!(
            prepared
                .witness()
                .slot
                .inputs
                .iter()
                .all(|i| i.dummy && i.value == 0)
        );
        assert!(prepared.witness().slot.outputs.iter().all(|o| o.value == 0));
        assert_eq!(prepared.witness().slot.fee, 0);
        assert_eq!(
            prepared.witness().d_ct,
            prepared
                .transaction()
                .ciphertext_digest(&prepared.context())
        );
        prepared.witness().check(&h, &root).unwrap();
        let prover = TransactionProver::new(FriParams::fast());
        let (proof, statement) = prover.prove(prepared.witness());
        prover.verify(&proof, &statement).unwrap();
        prepared
            .transaction()
            .verify(
                &prover,
                &proof,
                &prepared.context(),
                &prepared.fee_commit(),
                &root,
            )
            .unwrap();
        let shape = ProofShape::from_trusted(&prover.air, &prover.vk, &prover.cfg).unwrap();
        let body = postcard::to_allocvec(&proof).unwrap();
        let envelope = NativeEnvelope::from_parts(
            [9; 32],
            snapshots.tip().id,
            prepared.transaction().clone(),
            prepared.fee_commit(),
            &body,
            &shape,
        )
        .unwrap();
        let mut pool = PaddingPool::new();
        pool.enqueue_verified(&envelope, &prepared.sidecar(), &shape, &snapshots, |_| {
            false
        })
        .unwrap();
        let (ready, discarded) = pool.take_ready(&snapshots, &BTreeSet::new(), |_| false);
        assert!(discarded.is_empty());
        assert_eq!(ready.unwrap().transaction_id(), envelope.transaction_id());
        assert_eq!(pool.payload_bytes(), 0);
    }

    #[test]
    fn rejects_invalid_anchor_before_randomness_or_proving() {
        let (mut witnesses, root) = acc_witnesses(vec![sample_slot(303, false)], 0, FEE_BASE, 304);
        let anchor = EmptyAnchorWitness::from_witness(&witnesses.remove(0));
        let id = SnapshotId {
            height: 0,
            block_id: [1; 32],
        };
        let mut invalid = anchor.clone();
        invalid.anchor_path.pop();
        assert_eq!(
            prepare_empty_transaction([9; 32], id, &invalid, &root).err(),
            Some(PaddingError::Anchor)
        );
        let mut invalid = anchor.clone();
        invalid.anchor_path[0].1 = !invalid.anchor_path[0].1;
        assert_eq!(
            prepare_empty_transaction([9; 32], id, &invalid, &root).err(),
            Some(PaddingError::Anchor)
        );
        let mut invalid = anchor.clone();
        invalid.base_fee = 0;
        assert_eq!(
            prepare_empty_transaction([9; 32], id, &invalid, &root).err(),
            Some(PaddingError::Anchor)
        );
        assert_eq!(
            prepare_empty_transaction([9; 32], id, &anchor, &[F::ONE; 12]).err(),
            Some(PaddingError::Anchor)
        );
        let mut invalid = anchor;
        invalid.anchor_height = 1;
        assert_eq!(
            prepare_empty_transaction([9; 32], id, &invalid, &root).err(),
            Some(PaddingError::Anchor)
        );
    }

    #[test]
    fn queue_has_target_count_and_hard_count_and_byte_limits() {
        let snapshots = SnapshotPool::<()>::new(snapshot(0, 1, 0, [F::ZERO; 12])).unwrap();
        let mut pool = PaddingPool::new();
        assert!(pool.needs_refill());
        for i in 0..PADDING_POOL_TARGET as u32 {
            enqueue(&mut pool, i, &snapshots).unwrap();
        }
        assert!(!pool.needs_refill());
        for i in PADDING_POOL_TARGET..PADDING_POOL_MAX_ENTRIES {
            enqueue(&mut pool, i as u32, &snapshots).unwrap();
        }
        assert_eq!(pool.len(), 128);
        let before = pool.payload_bytes();
        assert_eq!(
            enqueue(&mut pool, 200, &snapshots),
            Err(PaddingError::CountLimit)
        );
        assert_eq!(pool.payload_bytes(), before);
        assert!(before <= PADDING_POOL_MAX_BYTES);
        let mut pool = PaddingPool::new();
        pool.byte_limit = 1;
        assert_eq!(
            enqueue(&mut pool, 0, &snapshots),
            Err(PaddingError::ByteLimit)
        );
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.payload_bytes(), 0);
    }

    #[test]
    fn queue_rejects_nonzero_fees_duplicates_and_nullifier_conflicts_atomically() {
        let mut snapshots = SnapshotPool::<()>::new(snapshot(0, 1, 0, [F::ZERO; 12])).unwrap();
        let mut pool = PaddingPool::new();
        enqueue(&mut pool, 1, &snapshots).unwrap();
        assert_eq!(
            enqueue(&mut pool, 1, &snapshots),
            Err(PaddingError::DuplicateTransaction)
        );
        let (same_nullifiers, _) = structural_entry(1, snapshots.tip().id);
        let original =
            NativeEnvelope::decode(&same_nullifiers, &[9; 32], &fixture().shape).unwrap();
        let mut changed = original.transaction().clone();
        changed.change.tag[0] ^= 1;
        let changed = NativeEnvelope::from_parts(
            [9; 32],
            snapshots.tip().id,
            changed,
            *original.fee_commit(),
            original.proof_body(),
            &fixture().shape,
        )
        .unwrap();
        let changed_sidecar =
            FeeOpeningSidecar::new(changed.transaction_id(), 0, [F::ONE; FEE_BLIND_LEN]);
        assert_eq!(
            pool.enqueue_verified(
                &changed,
                &changed_sidecar,
                &fixture().shape,
                &snapshots,
                |_| false
            ),
            Err(PaddingError::NullifierConflict)
        );
        let (bytes, sidecar) = structural_entry(2, snapshots.tip().id);
        let envelope = NativeEnvelope::decode(&bytes, &[9; 32], &fixture().shape).unwrap();
        assert_eq!(
            pool.enqueue_verified(&envelope, &sidecar, &fixture().shape, &snapshots, |_| true),
            Err(PaddingError::NullifierConflict)
        );
        snapshots
            .insert_verified([4; 32], snapshots.tip().id, envelope.transaction().nf, ())
            .unwrap();
        assert_eq!(
            pool.enqueue_verified(&envelope, &sidecar, &fixture().shape, &snapshots, |_| false),
            Err(PaddingError::NullifierConflict)
        );
        assert_eq!(pool.len(), 1);
        let (bytes, _) = structural_entry(3, snapshots.tip().id);
        let envelope = NativeEnvelope::decode(&bytes, &[9; 32], &fixture().shape).unwrap();
        let sidecar = FeeOpeningSidecar::new(
            envelope.transaction_id(),
            FEE_BASE,
            [F::ZERO; FEE_BLIND_LEN],
        );
        assert_eq!(
            pool.enqueue_verified(&envelope, &sidecar, &fixture().shape, &snapshots, |_| false),
            Err(PaddingError::NonzeroFee)
        );
    }

    #[test]
    fn reorg_inclusion_and_nullifier_conflicts_discard_queued_entries() {
        let genesis = snapshot(0, 1, 0, [F::ZERO; 12]);
        let mut snapshots = SnapshotPool::<()>::new(genesis.clone()).unwrap();
        snapshots
            .append_canonical(snapshot(1, 2, 1, [F::ONE; 12]))
            .unwrap();
        let mut pool = PaddingPool::new();
        enqueue(&mut pool, 1, &snapshots).unwrap();
        snapshots
            .replace_canonical_suffix(genesis.id, &[snapshot(1, 3, 1, [F::ZERO; 12])])
            .unwrap();
        let (ready, removed) = pool.take_ready(&snapshots, &BTreeSet::new(), |_| false);
        assert!(ready.is_none());
        assert_eq!(removed[0].reason, DiscardReason::SnapshotUnavailable);
        enqueue(&mut pool, 2, &snapshots).unwrap();
        let included: BTreeSet<_> = pool.entries.keys().copied().collect();
        let removed = pool.reconcile(&snapshots, &included, |_| false);
        assert_eq!(removed[0].reason, DiscardReason::Included);
        enqueue(&mut pool, 3, &snapshots).unwrap();
        let (ready, removed) = pool.take_ready(&snapshots, &BTreeSet::new(), |_| true);
        assert!(ready.is_none());
        assert_eq!(removed[0].reason, DiscardReason::NullifierConflict);
        assert_eq!(pool.payload_bytes(), 0);
        assert!(pool.nullifiers.is_empty());
    }

    #[test]
    fn expiring_snapshot_releases_all_padding_reservations() {
        let mut snapshots = SnapshotPool::<()>::new(snapshot(0, 1, 0, [F::ZERO; 12])).unwrap();
        let mut pool = PaddingPool::new();
        enqueue(&mut pool, 1, &snapshots).unwrap();
        for height in 1..=crate::snapshots::ACCEPTED_SNAPSHOT_LIMIT as u64 {
            let mut block_id = [0; 32];
            block_id[..8].copy_from_slice(&height.to_le_bytes());
            block_id[31] = 5;
            let next = CanonicalSnapshot {
                id: SnapshotId { height, block_id },
                parent_block_id: snapshots.tip().id.block_id,
                recent_roots_root: [F::ZERO; 12],
            };
            snapshots.append_canonical(next).unwrap();
        }
        let removed = pool.reconcile(&snapshots, &BTreeSet::new(), |_| false);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].reason, DiscardReason::SnapshotUnavailable);
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.payload_bytes(), 0);
        assert!(pool.nullifiers.is_empty());
    }
}
