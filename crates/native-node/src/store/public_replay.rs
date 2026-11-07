//! Deterministic public effects for authenticated, previously accepted history.
//! This helper confers no proof validity and must remain paired with either
//! every saved verified fingerprint or a pinned signed checkpoint summary.
use crate::{
    compact::CompactBlock,
    state::{CanonicalSnapshot, SNAPSHOT_WINDOW, State, base_fee},
    wire::Snapshot,
};
use native::{
    codec::{PublicTransaction, decode_digest, encode_digest},
    multi_asset::{Hasher, RecentRoots},
};
use siworld_core::{pow, v1_economics::FundAccount};
use std::collections::BTreeSet;

// This reconstructs deterministic public effects only after the compact range
// proof authenticates every field to the original worked seed. It confers no
// validity by itself: remote bootstrap compares the complete result and prefix
// to an independently signed checkpoint. Local accepted-history callers must
// compare every result to its independently verified saved state fingerprint.
pub(super) fn reconstruct_public_effects(
    state: &mut State,
    compact: &CompactBlock,
) -> Result<(), String> {
    let block = &compact.block;
    if block.network != state.config.network
        || state.height.checked_add(1) != Some(block.height)
        || block.parent != state.tip
        || block.timestamp <= state.median_time_past()
        || block.target != state.next_target()
        || !pow::meets_target(
            &pow::pow_hash(&compact.seed, block.nonce, state.config.pow_iterations),
            &block.target,
        )
    {
        return Err("checkpoint permanent work, timestamp or ancestry mismatch".into());
    }
    let cumulative_work = state
        .cumulative_work
        .checked_add(pow::block_work(&block.target))
        .ok_or("checkpoint cumulative work overflow")?;
    let mut spends = BTreeSet::new();
    let mut outputs = BTreeSet::new();
    let mut leaves = Vec::new();
    for transaction in &block.transactions {
        state.snapshot(transaction.record.snapshot)?;
        let public = PublicTransaction::decode(&transaction.record.body)
            .map_err(|_| "checkpoint public transaction encoding")?;
        for nullifier in public.nf {
            let value = encode_digest(&nullifier);
            if state.spent.contains(&value) || !spends.insert(value) {
                return Err("checkpoint repeated nullifier".into());
            }
        }
        for commitment in public.cm {
            let value = encode_digest(&commitment);
            if state.commitments.contains(&value) || !outputs.insert(value) {
                return Err("checkpoint repeated transaction commitment".into());
            }
            state.tree.append(commitment)?;
            leaves.push(commitment);
        }
    }
    let transaction_outputs = outputs.clone();
    if let Some(policy) = &state.config.issuance {
        if block.issuances.len() > usize::from(policy.max_per_block) {
            return Err("checkpoint issuance count limit".into());
        }
    } else if !block.issuances.is_empty() {
        return Err("checkpoint issuance policy unavailable".into());
    }
    for issuance in &block.issuances {
        // The compact decoder checked original proof framing. A one-byte shape
        // placeholder enables public declaration/signature validation only;
        // it is never passed to a proof verifier or persisted as a proof.
        let mut public = issuance.clone();
        public.proof = vec![0];
        public.validate(&state.config)?;
        if !transaction_outputs.contains(&issuance.fee_commitment)
            && !state.commitments.contains(&issuance.fee_commitment)
        {
            return Err("checkpoint issuance fee commitment unavailable".into());
        }
        state.assets.apply(&public, block.height)?;
        for commitment in &issuance.signed.declaration.note_commitments {
            let value = encode_digest(commitment);
            if state.commitments.contains(&value) || !outputs.insert(value) {
                return Err("checkpoint repeated issuance commitment".into());
            }
            state.tree.append(*commitment)?;
            leaves.push(*commitment);
        }
    }
    for reward in &block.rewards {
        let value = decode_digest(&reward.commitment)
            .map_err(|_| "checkpoint reward commitment encoding")?;
        if state.commitments.contains(&reward.commitment) || !outputs.insert(reward.commitment) {
            return Err("checkpoint repeated reward commitment".into());
        }
        state.tree.append(value)?;
        leaves.push(value);
    }
    state
        .economics
        .advance(block.height, block.reward_mode)
        .map_err(|error| error.to_string())?;
    for spend in &block.fund_spends {
        let account =
            FundAccount::new(usize::from(spend.account)).map_err(|error| error.to_string())?;
        let key = state
            .config
            .fund_verifying_keys
            .get(account.index())
            .ok_or("checkpoint development fund signer unavailable")?;
        let note = spend.verify(state.config.network, key)?;
        state
            .economics
            .spend_fund(account, u128::from(spend.amount), spend.counter)
            .map_err(|error| error.to_string())?;
        if state.commitments.contains(&spend.commitment) || !outputs.insert(spend.commitment) {
            return Err("checkpoint repeated development fund commitment".into());
        }
        let value = Hasher::new().note_cm(&note);
        state.tree.append(value)?;
        leaves.push(value);
    }
    state
        .economics
        .assert_supply_invariant()
        .map_err(|error| error.to_string())?;
    let hasher = Hasher::new();
    let mut roots = RecentRoots::new();
    for snapshot in &state.snapshots {
        if block.height - snapshot.selector.height < SNAPSHOT_WINDOW as u64 {
            roots.insert(
                &hasher,
                snapshot.selector.height,
                &decode_digest(&snapshot.commitment_root)
                    .map_err(|_| "checkpoint recent root encoding")?,
                base_fee(snapshot.selector.height),
            );
        }
    }
    roots.insert(
        &hasher,
        block.height,
        &state.tree.root(),
        base_fee(block.height),
    );
    state.snapshots.push_back(CanonicalSnapshot {
        selector: Snapshot {
            height: block.height,
            block_id: compact.id,
        },
        commitment_root: encode_digest(&state.tree.root()),
        recent_root: encode_digest(&roots.tree(&hasher).root()),
    });
    while state.snapshots.len() > SNAPSHOT_WINDOW {
        state.snapshots.pop_front();
    }
    state.height = block.height;
    state.tip = compact.id;
    state.cumulative_work = cumulative_work;
    state.timestamps.push_back(block.timestamp);
    while state.timestamps.len() > siworld_core::params::MEDIAN_TIME_PAST_WINDOW {
        state.timestamps.pop_front();
    }
    state.spent.extend(spends);
    state.commitments.extend(outputs);
    state.leaves.extend(leaves);
    Ok(())
}
