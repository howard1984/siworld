use super::*;
use crate::state::{Config, State};
use crate::wire::{PUBLIC_BYTES, PublicRecord};
use native::codec::PublicTransaction;
use native::multi_asset::F;
use p3_field::PrimeCharacteristicRing;
use std::cell::Cell;
struct Verifier {
    calls: Cell<usize>,
}
impl BlockVerifier for Verifier {
    fn transaction(
        &self,
        _: &PublicTransaction,
        _: &ProofContext,
        _: &Digest,
        _: &Digest,
        proof: &[u8],
    ) -> Result<(), String> {
        self.calls.set(self.calls.get() + 1);
        if !proof.is_empty() && proof.iter().all(|byte| *byte == 1) {
            Ok(())
        } else {
            Err("invalid synthetic proof".into())
        }
    }
    fn settlement(
        &self,
        _: &[Digest],
        _: &native::settlement::RewardPlan,
        _: Hash,
        _: Hash,
        _: &[Digest],
        _: &[u8],
    ) -> Result<(), String> {
        unreachable!()
    }
}
fn verifier() -> Verifier {
    Verifier {
        calls: Cell::new(0),
    }
}
fn state() -> State {
    State::new(Config::development([73; 32], 0).unwrap()).unwrap()
}
fn digest(value: u32) -> DigestBytes {
    let mut fields = [F::ZERO; 12];
    fields[0] = F::from_u32(value);
    encode_digest(&fields)
}
fn entry(state: &State, seed: u32) -> Padding {
    let mut body = [0; PUBLIC_BYTES];
    for i in 0..5 {
        body[i * 48..(i + 1) * 48].copy_from_slice(&digest(seed + i as u32));
    }
    let opening = FeeOpening::dummy(core::array::from_fn(|i| F::from_u32(seed + i as u32 + 100)));
    let fee = encode_digest(&Hasher::new().fee_commit(0, &opening.blind));
    Padding {
        transaction: Transaction {
            record: PublicRecord::new(state.tip_snapshot().selector, body, fee).unwrap(),
            proof: vec![1],
        },
        opening,
    }
}
#[test]
fn independent_verification_precedes_reservation_and_rejection_is_atomic() {
    let state = state();
    let verify = verifier();
    let mut pool = Pool::new(state.config.network);
    let mut bad = entry(&state, 1);
    bad.transaction.proof[0] = 0;
    assert!(pool.insert(&state, bad, &verify).is_err());
    assert_eq!(verify.calls.get(), 1);
    assert_eq!(pool.len(), 0);
    assert_eq!(pool.bytes(), 0);
    pool.insert(&state, entry(&state, 1), &verify).unwrap();
}
#[test]
fn both_inputs_and_every_output_are_reserved_atomically() {
    for field in 0..5 {
        let state = state();
        let verify = verifier();
        let mut pool = Pool::new(state.config.network);
        let first = entry(&state, 1);
        let reused = first.transaction.record.body[field * 48..(field + 1) * 48].to_vec();
        pool.insert(&state, first, &verify).unwrap();
        let before = pool.bytes();
        let mut second = entry(&state, 1000);
        second.transaction.record.body[field * 48..(field + 1) * 48].copy_from_slice(&reused);
        assert!(pool.insert(&state, second, &verify).is_err());
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.bytes(), before);
    }
}
#[test]
fn expired_removed_and_conflicting_entries_are_evicted() {
    for reason in 0..4 {
        let mut state = state();
        let verify = verifier();
        let mut pool = Pool::new(state.config.network);
        let first = entry(&state, 1);
        let public = PublicTransaction::decode(&first.transaction.record.body).unwrap();
        pool.insert(&state, first, &verify).unwrap();
        match reason {
            0 => state.snapshots.back_mut().unwrap().selector.block_id[0] ^= 1,
            1 => state.height = 4096,
            2 => {
                state.spent.insert(encode_digest(&public.nf[1]));
            }
            _ => {
                state.commitments.insert(encode_digest(&public.cm[2]));
            }
        }
        assert_eq!(pool.prune(&state).unwrap(), 1);
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.bytes(), 0);
    }
}
#[test]
fn consumed_positions_cannot_be_reinserted_before_commit() {
    let state = state();
    let verify = verifier();
    let mut pool = Pool::new(state.config.network);
    for i in 0..64 {
        pool.insert(&state, entry(&state, 1 + i * 1000), &verify)
            .unwrap();
    }
    assert!(pool.ready());
    let taken = pool.take(&state, 64).unwrap();
    assert_eq!(pool.len(), 0);
    assert_eq!(pool.bytes(), 0);
    for value in taken {
        assert!(pool.insert(&state, value, &verify).is_err());
    }
    assert!(pool.take(&state, 64).is_err());
}
#[test]
fn count_and_byte_caps_are_independent_and_bad_take_is_atomic() {
    let state = state();
    let verify = verifier();
    let mut pool = Pool::new(state.config.network);
    for i in 0..MAX_ENTRIES {
        pool.insert(&state, entry(&state, 1 + i as u32 * 1000), &verify)
            .unwrap();
    }
    let bytes = pool.bytes();
    assert!(pool.insert(&state, entry(&state, 999999), &verify).is_err());
    assert_eq!(pool.len(), MAX_ENTRIES);
    assert_eq!(pool.bytes(), bytes);
    assert!(pool.take(&state, 65).is_err());
    assert_eq!(pool.len(), MAX_ENTRIES);
    let mut pool = Pool::new(state.config.network);
    for i in 0..MAX_ENTRIES {
        let mut value = entry(&state, 1 + i as u32 * 1000);
        value.transaction.proof.resize(MAX_TX_PROOF, 1);
        if pool.insert(&state, value, &verify).is_err() {
            assert!(pool.len() >= MIN_READY);
            break;
        }
    }
    assert!(pool.bytes() <= MAX_BYTES);
    assert!(pool.len() < MAX_ENTRIES);
}
#[test]
fn wrong_network_opening_and_duplicate_identity_are_rejected() {
    let state = state();
    let verify = verifier();
    let mut pool = Pool::new([74; 32]);
    assert!(pool.insert(&state, entry(&state, 1), &verify).is_err());
    let mut pool = Pool::new(state.config.network);
    let mut invalid = entry(&state, 1);
    invalid.opening.blind[0] += F::ONE;
    assert!(pool.insert(&state, invalid, &verify).is_err());
    pool.insert(&state, entry(&state, 1), &verify).unwrap();
    assert!(pool.insert(&state, entry(&state, 1), &verify).is_err());
    assert_eq!(pool.len(), 1);
}

#[test]
fn maximum_proof_backpressure_preserves_a_ready_queue_and_resumes_after_consumption() {
    let state = state();
    let verify = verifier();
    let mut pool = Pool::new(state.config.network);
    let mut next = 0u32;
    while pool.can_grow() {
        let mut value = entry(&state, 1 + next * 1000);
        value.transaction.proof.resize(MAX_TX_PROOF, 1);
        pool.insert(&state, value, &verify).unwrap();
        next += 1;
    }
    assert!(pool.ready());
    assert!(pool.len() < MAX_ENTRIES);
    assert!(pool.bytes() <= MAX_BYTES);
    let before = pool.bytes();
    let calls = verify.calls.get();
    let mut overflow = entry(&state, 999999);
    overflow.transaction.proof.resize(MAX_TX_PROOF, 1);
    assert!(pool.insert(&state, overflow, &verify).is_err());
    assert_eq!(pool.bytes(), before);
    assert_eq!(verify.calls.get(), calls);
    let consumed = pool.take(&state, MIN_READY).unwrap();
    assert_eq!(consumed.len(), MIN_READY);
    assert!(pool.can_grow());
}

#[test]
fn retained_proof_allocation_discards_unaccounted_spare_capacity() {
    let state = state();
    let verify = verifier();
    let mut pool = Pool::new(state.config.network);
    let mut value = entry(&state, 1);
    let mut oversized = Vec::with_capacity(4 * 1024 * 1024);
    oversized.push(1);
    value.transaction.proof = oversized;
    let id = value.transaction.record.statement_id(&state.config.network);
    pool.insert(&state, value, &verify).unwrap();
    let retained = &pool.entries.get(&id).unwrap().value.transaction.proof;
    assert_eq!(retained.len(), 1);
    assert_eq!(retained.capacity(), 1);
    assert!(pool.bytes() < 64 * 1024);
}

#[test]
fn fill_selection_supports_arbitrary_shortfalls_and_preserves_all_conflict_tombstones() {
    for count in [0, 1, 3, 15, 63, 64, 65, 127, 128] {
        let state = state();
        let verify = verifier();
        let mut pool = Pool::new(state.config.network);
        for index in 0..128 {
            pool.insert(&state, entry(&state, 1 + index * 1000), &verify)
                .unwrap();
        }
        let bytes = pool.bytes();
        let selected = pool.take_for_fill(&state, count).unwrap();
        assert_eq!(selected.len(), count);
        assert_eq!(pool.len(), 128 - count);
        assert!(pool.bytes() <= bytes);
        if count == 0 {
            assert_eq!(pool.bytes(), bytes);
        }
        if count == 128 {
            assert_eq!(pool.bytes(), 0);
        }
        for value in selected {
            assert!(pool.insert(&state, value, &verify).is_err());
        }
        assert_eq!(pool.len(), 128 - count);
    }
}

#[test]
fn failed_fill_counts_leave_originals_bytes_and_reservations_unchanged() {
    let state = state();
    let verify = verifier();
    let mut pool = Pool::new(state.config.network);
    for index in 0..64 {
        pool.insert(&state, entry(&state, 1 + index * 1000), &verify)
            .unwrap();
    }
    let ids: Vec<_> = pool.entries.keys().copied().collect();
    let before = (
        pool.len(),
        pool.bytes(),
        pool.inputs.len(),
        pool.outputs.len(),
        pool.consumed.len(),
    );
    for count in [65, MAX_SLOTS, MAX_SLOTS + 1, usize::MAX] {
        assert!(pool.take_for_fill(&state, count).is_err());
        assert_eq!(
            (
                pool.len(),
                pool.bytes(),
                pool.inputs.len(),
                pool.outputs.len(),
                pool.consumed.len()
            ),
            before
        );
        assert_eq!(pool.entries.keys().copied().collect::<Vec<_>>(), ids);
    }
    assert!(pool.take(&state, 63).is_err());
    assert!(pool.take(&state, 65).is_err());
    assert_eq!(pool.take_for_fill(&state, 63).unwrap().len(), 63);
    assert_eq!(pool.take_for_fill(&state, 1).unwrap().len(), 1);
    assert_eq!(pool.bytes(), 0);
}

#[cfg(feature = "eng2-runtime")]
#[test]
fn abandoned_private_templates_do_not_fill_publication_reservations() {
    let state = state();
    let verify = verifier();
    let mut pool = Pool::new(state.config.network);

    for round in 0..(MAX_CONSUMED / 16 + 2) {
        for position in 0..16 {
            let seed = 1 + (round * 16 + position) as u32 * 1000;
            pool.insert(&state, entry(&state, seed), &verify).unwrap();
        }
        let selected = pool
            .take_for_fill_with_visibility(&state, 16, true)
            .unwrap();
        assert_eq!(pool.consumed.len(), 16);
        assert_eq!(
            pool.take_for_fill_with_visibility(&state, 0, true).err(),
            Some(FillError::PrivateTemplateActive)
        );
        drop(selected);
        pool.discard_unpublished_template();
        assert!(pool.is_empty());
        assert!(pool.consumed.is_empty());
    }
}

#[cfg(feature = "eng2-runtime")]
#[test]
fn attempted_publication_is_never_released_by_private_cancellation() {
    let state = state();
    let verify = verifier();
    let mut pool = Pool::new(state.config.network);
    pool.insert(&state, entry(&state, 1), &verify).unwrap();
    drop(pool.take_for_fill_with_visibility(&state, 1, true).unwrap());
    pool.mark_template_published();
    pool.discard_unpublished_template();
    assert_eq!(pool.consumed.len(), 1);
    assert!(pool.insert(&state, entry(&state, 1), &verify).is_err());

    assert_eq!(
        pool.take_for_fill_with_visibility(&state, 1, true).err(),
        Some(FillError::Insufficient { required: 1 })
    );
    for id in 1..MAX_CONSUMED {
        pool.consumed.insert(
            blake3::hash(&id.to_le_bytes()).into(),
            Consumed {
                inputs: [[0; 48]; 2],
                outputs: [[0; 48]; 3],
            },
        );
    }
    pool.insert(&state, entry(&state, 1000), &verify).unwrap();
    assert_eq!(
        pool.take_for_fill_with_visibility(&state, 1, true).err(),
        Some(FillError::ReservationsExhausted)
    );
    assert_eq!(pool.len(), 1);
    assert_eq!(pool.consumed.len(), MAX_CONSUMED);
}
