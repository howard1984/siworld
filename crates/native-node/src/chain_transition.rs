//! Shared isolated chain actions, independent of a version's block identity.
//!
//! Enclosing engines authenticate the full header/body, economic settlement,
//! governance and fund operations before publishing the returned state.

use crate::issuance::IssuanceRecord;
use crate::state::{
    BlockVerifier, CanonicalSnapshot, CommitmentTree, SNAPSHOT_WINDOW, State, TransactionProof,
};
use crate::wire::{
    DigestBytes, GROUP, Hash, MAX_REWARDS, MAX_SLOTS, MAX_TX_PROOF, MIN_SLOTS, RewardRecord,
    Transaction,
};
use native::codec::{ProofContext, PublicTransaction, decode_digest, encode_digest};
use native::multi_asset::{Digest, Hasher, RecentRoots};
use std::collections::BTreeSet;

#[derive(Clone, Copy)]
pub(crate) struct Context {
    pub network: Hash,
    pub height: u64,
    pub parent: Hash,
    pub timestamp: u64,
    pub target: Hash,
}

pub(crate) struct Actions<'a> {
    pub transactions: &'a [Transaction],
    pub issuances: &'a [IssuanceRecord],
    pub rewards: &'a [RewardRecord],
}

pub(crate) struct PreparedActions<'a> {
    parent: &'a State,
    context: Context,
    actions: Actions<'a>,
    transaction_proofs: Vec<TransactionProof<'a>>,
    fees: Vec<Digest>,
    rewards: Vec<Digest>,
    tree: CommitmentTree,
    assets: crate::issuance::AssetRegistry,
    spends: BTreeSet<DigestBytes>,
    outputs: BTreeSet<DigestBytes>,
    leaves: Vec<Digest>,
}
/// Created only by executing the actual verifier on the prepared proof contexts.
pub(crate) struct CheckedActions<'a> {
    prepared: PreparedActions<'a>,
}

/// A complete delta; construction can fail, but publication performs no proof,
/// encoding, accounting or allocation-dependent validation. Keep the target
/// parent exclusively owned until this delta is published or discarded.
pub(crate) struct ChainDelta {
    context: Context,
    parent_work: siworld_core::pow::Work,
    parent_root: Digest,
    cumulative_work: siworld_core::pow::Work,
    tree: CommitmentTree,
    assets: crate::issuance::AssetRegistry,
    spends: BTreeSet<DigestBytes>,
    outputs: BTreeSet<DigestBytes>,
    leaves: Vec<Digest>,
    snapshot: CanonicalSnapshot,
}

/// Read-only candidate chain state derived only after the shared proof checks.
/// This does not authorize settlement, the header or live state adoption.
pub struct ChainPreview<'a> {
    parent: &'a State,
    delta: &'a ChainDelta,
    timestamps: std::collections::VecDeque<u64>,
    snapshots: std::collections::VecDeque<CanonicalSnapshot>,
}

impl ChainPreview<'_> {
    pub fn versioned_execution(
        &self,
        parent: &crate::eng2::snapshot::SnapshotState,
        ledgers: crate::eng2::state_components::VersionedLedgers<'_>,
        binding: crate::eng2::state_components::Binding,
        limits: crate::eng2::state_components::Limits,
    ) -> Result<crate::eng2::state_components::ExecutionPreview, String> {
        use crate::eng2::commitment::SnapshotTip;
        use crate::eng2::state_components::{ChainView, ExecutionComponents, ExecutionPreview};
        if !std::ptr::eq(&parent.chain, self.parent)
            || binding.parent != self.delta.context.parent
            || parent.nullifiers.len() != self.parent.spent.len() as u64
        {
            return Err("versioned preview parent differs".into());
        }
        // Only accepted insertions are path-copied. Permanent leaves, membership
        // sets and nullifier values stay borrowed from the exclusively held parent.
        let mut nullifiers = parent.nullifiers.clone();
        for value in &self.delta.spends {
            nullifiers.insert(*value)?;
        }
        let members = self
            .parent
            .config
            .fund_allocation
            .as_ref()
            .ok_or("missing versioned fund allocation")?
            .basis_points()
            .len();
        let external = ledgers.components(
            self.delta.context.network,
            self.delta.context.height,
            members,
            limits,
        )?;
        let view = ChainView {
            fee_mode: parent.fee_mode(),
            config: &self.parent.config,
            height: self.delta.context.height,
            tip: self.delta.snapshot.selector.block_id,
            cumulative_work: self.delta.cumulative_work,
            timestamps: &self.timestamps,
            tree: &self.delta.tree,
            leaves: self
                .parent
                .leaves
                .len()
                .checked_add(self.delta.leaves.len())
                .ok_or("preview leaf count overflow")?,
            commitments: self
                .parent
                .commitments
                .len()
                .checked_add(self.delta.outputs.len())
                .ok_or("preview membership count overflow")?,
            spent: self
                .parent
                .spent
                .len()
                .checked_add(self.delta.spends.len())
                .ok_or("preview nullifier count overflow")?,
            assets: &self.delta.assets,
            snapshots: &self.snapshots,
        };
        let tip = if view.tip == [0; 32] {
            SnapshotTip::Staged
        } else {
            SnapshotTip::Materialized(view.tip)
        };
        let commitment = ExecutionComponents::from_view(view, &nullifiers, binding, tip, limits)?
            .assemble(external)?;
        Ok(ExecutionPreview::new(commitment, nullifiers))
    }
}

impl ChainDelta {
    pub(crate) fn restart_chain_bytes(&self, parent: &State) -> Result<Vec<u8>, String> {
        let preview = self.preview(parent)?;
        crate::eng2::restart::encode_chain(
            self.context.height,
            self.snapshot.selector.block_id,
            self.cumulative_work,
            &preview.timestamps,
            &self.tree,
            parent.leaves.len() + self.leaves.len(),
            parent.spent.len() + self.spends.len(),
            &preview.snapshots,
            &self.assets,
        )
    }
    pub(crate) fn new_leaves(&self) -> &[Digest] {
        &self.leaves
    }
    pub(crate) fn new_spends(&self) -> &BTreeSet<DigestBytes> {
        &self.spends
    }
    pub(crate) fn preview<'a>(&'a self, parent: &'a State) -> Result<ChainPreview<'a>, String> {
        if parent.config.network != self.context.network
            || parent.height.checked_add(1) != Some(self.context.height)
            || parent.tip != self.context.parent
            || parent.cumulative_work != self.parent_work
            || parent.tree.root() != self.parent_root
        {
            return Err("chain delta parent differs".into());
        }
        let mut timestamps = parent.timestamps.clone();
        timestamps.push_back(self.context.timestamp);
        while timestamps.len() > siworld_core::params::MEDIAN_TIME_PAST_WINDOW {
            timestamps.pop_front();
        }
        let mut snapshots = parent.snapshots.clone();
        snapshots.push_back(self.snapshot.clone());
        while snapshots.len() > SNAPSHOT_WINDOW {
            snapshots.pop_front();
        }
        Ok(ChainPreview {
            parent,
            delta: self,
            timestamps,
            snapshots,
        })
    }
    pub(crate) fn commit_into(self, state: &mut State) -> Result<(), String> {
        let ChainPreview {
            timestamps,
            snapshots,
            ..
        } = self.preview(state)?;
        state.tree = self.tree;
        state.height = self.context.height;
        state.tip = self.snapshot.selector.block_id;
        state.timestamps = timestamps;
        state.cumulative_work = self.cumulative_work;
        state.assets = self.assets;
        state.spent.extend(self.spends);
        state.commitments.extend(self.outputs);
        state.leaves.extend(self.leaves);
        state.snapshots = snapshots;
        Ok(())
    }
}

impl<'a> PreparedActions<'a> {
    pub(crate) fn prepare(
        parent: &'a State,
        context: Context,
        actions: Actions<'a>,
    ) -> Result<Self, String> {
        Self::prepare_with_issuance_policy(parent, context, actions, None)
    }
    /// The versioned engine supplies a policy derived from frozen governance.
    /// None retains the immutable V1 issuance fee; no peer selects this value.
    pub(crate) fn prepare_with_issuance_policy(
        parent: &'a State,
        context: Context,
        actions: Actions<'a>,
        issuance_policy: Option<&crate::issuance::ActiveIssuancePolicy<'_>>,
    ) -> Result<Self, String> {
        if context.network != parent.config.network {
            return Err("block network mismatch".into());
        }
        if parent.height.checked_add(1) != Some(context.height) {
            return Err("nonconsecutive block height".into());
        }
        if context.parent != parent.tip {
            return Err("block parent mismatch".into());
        }
        if context.timestamp <= parent.median_time_past() {
            return Err("block timestamp does not exceed median time past".into());
        }
        if context.target != parent.next_target() {
            return Err("block target does not match ASERT".into());
        }
        if !(MIN_SLOTS..=MAX_SLOTS).contains(&actions.transactions.len())
            || !actions.transactions.len().is_multiple_of(GROUP)
            || actions.rewards.is_empty()
            || actions.rewards.len() > MAX_REWARDS
            || actions.issuances.len() > crate::issuance::RECORDS_CODEC_LIMIT
        {
            return Err("chain action count limit".into());
        }
        let mut spends = BTreeSet::new();
        let mut outputs = BTreeSet::new();
        let mut leaves = Vec::new();
        let mut fees = Vec::with_capacity(actions.transactions.len());
        let mut tree = parent.tree.clone();
        let mut transaction_proofs = Vec::with_capacity(actions.transactions.len());
        let mut previous = None;
        for tx in actions.transactions {
            if tx.proof.is_empty() || tx.proof.len() > MAX_TX_PROOF {
                return Err("transaction proof byte limit".into());
            }
            let identity = tx.record.statement_id(&context.network);
            if previous.is_some_and(|previous| previous >= identity) {
                return Err("noncanonical transaction order".into());
            }
            previous = Some(identity);
            let snapshot = parent.snapshot(tx.record.snapshot)?;
            let root =
                decode_digest(&snapshot.recent_root).map_err(|_| "invalid stored snapshot root")?;
            let public = PublicTransaction::decode(&tx.record.body)
                .map_err(|_| "noncanonical transaction public values")?;
            let fee =
                decode_digest(&tx.record.fee_commit).map_err(|_| "noncanonical fee commitment")?;
            for nf in public.nf {
                let nf = encode_digest(&nf);
                if parent.spent.contains(&nf) || !spends.insert(nf) {
                    return Err("nullifier already used".into());
                }
            }
            for cm in public.cm {
                let bytes = encode_digest(&cm);
                if parent.commitments.contains(&bytes) || !outputs.insert(bytes) {
                    return Err("output commitment already used".into());
                }
                tree.append(cm)?;
                leaves.push(cm);
            }
            transaction_proofs.push(TransactionProof {
                public,
                context: ProofContext::for_snapshot(
                    context.network,
                    tx.record.snapshot.height,
                    tx.record.snapshot.block_id,
                ),
                fee,
                root,
                proof: &tx.proof,
            });
            fees.push(fee);
        }
        let mut assets = parent.assets.clone();
        if let Some(policy) = &parent.config.issuance {
            if actions.issuances.len() > usize::from(policy.max_per_block) {
                return Err("issuance count exceeds configured block limit".into());
            }
        } else if !actions.issuances.is_empty() {
            return Err("issuance destination and policy are not configured".into());
        }
        let transaction_outputs = outputs.clone();
        for issuance in actions.issuances {
            issuance.validate_shape()?;
            if let Some(policy) = issuance_policy {
                issuance.validate_with_policy(&parent.config, policy)?;
            } else {
                issuance.validate(&parent.config)?;
            }
            if !transaction_outputs.contains(&issuance.fee_commitment)
                && !parent.commitments.contains(&issuance.fee_commitment)
            {
                return Err(
                    "issuance fee output is not in verified canonical history or this block".into(),
                );
            }
            assets.apply(issuance, context.height)?;
            for commitment in &issuance.signed.declaration.note_commitments {
                let bytes = encode_digest(commitment);
                if parent.commitments.contains(&bytes) || !outputs.insert(bytes) {
                    return Err("issuance output commitment already used".into());
                }
                tree.append(*commitment)?;
                leaves.push(*commitment);
            }
        }
        let mut rewards = Vec::with_capacity(actions.rewards.len());
        for record in actions.rewards {
            let reward =
                decode_digest(&record.commitment).map_err(|_| "noncanonical miner reward")?;
            if parent.commitments.contains(&record.commitment) || !outputs.insert(record.commitment)
            {
                return Err("reward commitment already used".into());
            }
            tree.append(reward)?;
            leaves.push(reward);
            rewards.push(reward);
        }
        Ok(Self {
            parent,
            context,
            actions,
            transaction_proofs,
            fees,
            rewards,
            tree,
            assets,
            spends,
            outputs,
            leaves,
        })
    }
    pub(crate) fn verify(
        self,
        verifier: &impl BlockVerifier,
    ) -> Result<CheckedActions<'a>, String> {
        verifier.transactions(&self.transaction_proofs)?;
        for issuance in self.actions.issuances {
            verifier.issuance(issuance)?;
        }
        Ok(CheckedActions { prepared: self })
    }

    /// Verify the exact prepared contexts using the native verifier and a
    /// locally bounded worker/byte policy. No caller-supplied success flag is
    /// accepted and no state is published while proofs are running.
    /// This V1 adapter is retained for regression tests; the versioned engine
    /// requires its own proof profile before a production pool is connected.
    #[cfg(test)]
    pub(crate) fn verify_native_parallel(
        self,
        verifier: &crate::proofs::NativeVerifier,
        policy: crate::eng2::proof_window::Policy,
    ) -> Result<CheckedActions<'a>, crate::eng2::proof_window::WindowError> {
        self.verify_in_pool(verifier, policy)
    }

    #[cfg(test)]
    fn verify_in_pool(
        self,
        verifier: &(impl BlockVerifier + Sync),
        policy: crate::eng2::proof_window::Policy,
    ) -> Result<CheckedActions<'a>, crate::eng2::proof_window::WindowError> {
        use crate::eng2::proof_window::{self, BlockProofs, WindowError};
        enum Job<'p, 'b> {
            Transaction(&'p TransactionProof<'b>),
            Issuance(&'p IssuanceRecord),
        }
        // The jobs borrow this exact prepared object's immutable public values,
        // snapshot context, fee/root and proof bytes. The checked object is
        // constructed only after the pool verifies all of them successfully.
        {
            let count = self
                .transaction_proofs
                .len()
                .checked_add(self.actions.issuances.len())
                .ok_or(WindowError::Bounds)?;
            let mut jobs = Vec::new();
            jobs.try_reserve_exact(count)
                .map_err(|_| WindowError::Resources)?;
            jobs.extend(self.transaction_proofs.iter().map(Job::Transaction));
            jobs.extend(self.actions.issuances.iter().map(Job::Issuance));
            let mut binding =
                blake3::Hasher::new_derive_key("siworld prepared chain proof contexts v1");
            binding.update(&self.context.network);
            binding.update(&self.context.parent);
            binding.update(&self.context.height.to_le_bytes());
            binding.update(&self.context.timestamp.to_le_bytes());
            binding.update(&self.context.target);
            let blocks = [BlockProofs {
                block_id: *binding.finalize().as_bytes(),
                jobs: &jobs,
            }];
            proof_window::verify(
                &blocks,
                policy,
                |job| match job {
                    Job::Transaction(proof) => proof.proof.len(),
                    Job::Issuance(record) => record.proof.len(),
                },
                |job| match job {
                    Job::Transaction(proof) => verifier.transaction(
                        &proof.public,
                        &proof.context,
                        &proof.fee,
                        &proof.root,
                        proof.proof,
                    ),
                    Job::Issuance(record) => verifier.issuance(record),
                },
            )?;
        }
        Ok(CheckedActions { prepared: self })
    }
}
impl CheckedActions<'_> {
    pub(crate) fn fees(&self) -> &[Digest] {
        &self.prepared.fees
    }
    pub(crate) fn rewards(&self) -> &[Digest] {
        &self.prepared.rewards
    }
    /// The enclosing engine must first verify the version-specific signature,
    /// proof, entitlement and supply checks authorizing this output.
    pub(crate) fn append_authorized_output(&mut self, commitment: Digest) -> Result<(), String> {
        let bytes = encode_digest(&commitment);
        if self.prepared.parent.commitments.contains(&bytes)
            || self.prepared.outputs.contains(&bytes)
        {
            return Err("authorized output commitment already used".into());
        }
        // Append can fail at capacity; do not change membership before it succeeds.
        self.prepared.tree.append(commitment)?;
        self.prepared.outputs.insert(bytes);
        self.prepared.leaves.push(commitment);
        Ok(())
    }
    pub(crate) fn finish(
        self,
        identity: Hash,
        fee_base: impl Fn(u64) -> Result<u64, String>,
    ) -> Result<ChainDelta, String> {
        let Self { prepared: p } = self;
        let cumulative_work = p
            .parent
            .cumulative_work
            .checked_add(siworld_core::pow::block_work(&p.context.target))
            .ok_or("cumulative engineering work overflow")?;
        let mut roots = RecentRoots::new();
        let h = Hasher::new();
        for snapshot in &p.parent.snapshots {
            let age = p
                .context
                .height
                .checked_sub(snapshot.selector.height)
                .ok_or("future stored snapshot")?;
            if age < SNAPSHOT_WINDOW as u64 {
                roots.insert(
                    &h,
                    snapshot.selector.height,
                    &decode_digest(&snapshot.commitment_root).map_err(|_| "invalid stored root")?,
                    fee_base(snapshot.selector.height)?,
                );
            }
        }
        roots.insert(
            &h,
            p.context.height,
            &p.tree.root(),
            fee_base(p.context.height)?,
        );
        let snapshot = CanonicalSnapshot {
            selector: crate::wire::Snapshot {
                height: p.context.height,
                block_id: identity,
            },
            commitment_root: encode_digest(&p.tree.root()),
            recent_root: encode_digest(&roots.tree(&h).root()),
        };
        Ok(ChainDelta {
            context: p.context,
            parent_work: p.parent.cumulative_work,
            parent_root: p.parent.tree.root(),
            cumulative_work,
            tree: p.tree,
            assets: p.assets,
            spends: p.spends,
            outputs: p.outputs,
            leaves: p.leaves,
            snapshot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{TestVerifier, candidate};
    use crate::state::Config;
    use crate::wire::Block;
    use native::codec::decode_digest;
    use native::multi_asset::F;
    use p3_field::PrimeCharacteristicRing;

    fn context(block: &Block) -> Context {
        Context {
            network: block.network,
            height: block.height,
            parent: block.parent,
            timestamp: block.timestamp,
            target: block.target,
        }
    }
    fn actions(block: &Block) -> Actions<'_> {
        Actions {
            transactions: &block.transactions,
            issuances: &block.issuances,
            rewards: &block.rewards,
        }
    }

    #[test]
    fn versioned_preview_matches_full_committed_state_without_copying_permanent_history() {
        use crate::eng2::commitment::SnapshotTip;
        use crate::eng2::snapshot::tests::{binding, bootstrap};
        use crate::eng2::state_components::{ChainComponents, Limits, VersionedLedgers};
        let parent = bootstrap();
        let before = parent.chain.fingerprint();
        let block = candidate(&parent.chain, 900_000);
        let allocation = parent.chain.config.fund_allocation.as_ref().unwrap();
        let economics = parent
            .economics
            .prepare(1, block.reward_mode, allocation)
            .unwrap()
            .0;
        let mut fund = parent.fund.clone();
        fund.advance(1, siworld_core::v1_economics::subsidy(1).unwrap())
            .unwrap();
        let mut governance = parent.governance.clone();
        governance.apply_block(1, &[]).unwrap();
        let limits = Limits {
            max_leaves: 5000,
            max_nullifiers: 5000,
            max_component_bytes: 16 * 1024 * 1024,
        };
        let binding = binding(&parent, parent.tip());
        let ledgers = || VersionedLedgers {
            economics: &economics,
            fund: &fund,
            governance: &governance,
        };
        let delta = PreparedActions::prepare(&parent.chain, context(&block), actions(&block))
            .unwrap()
            .verify(&TestVerifier)
            .unwrap()
            .finish([23; 32], crate::eng2_economics::fee_base)
            .unwrap();
        let preview = delta.preview(&parent.chain).unwrap();
        let executed = preview
            .versioned_execution(&parent, ledgers(), binding, limits)
            .unwrap();
        assert_eq!(parent.chain.fingerprint(), before);
        assert_eq!(parent.nullifiers.len(), 0);
        assert_eq!(executed.nullifiers().len(), 128);
        let staged_delta =
            PreparedActions::prepare(&parent.chain, context(&block), actions(&block))
                .unwrap()
                .verify(&TestVerifier)
                .unwrap()
                .finish([0; 32], crate::eng2_economics::fee_base)
                .unwrap();
        let staged_execution = staged_delta
            .preview(&parent.chain)
            .unwrap()
            .versioned_execution(&parent, ledgers(), binding, limits)
            .unwrap();
        assert_eq!(staged_execution.commitment(), executed.commitment());
        assert!(
            preview
                .versioned_execution(
                    &parent,
                    VersionedLedgers {
                        economics: &parent.economics,
                        fund: &fund,
                        governance: &governance,
                    },
                    binding,
                    limits
                )
                .is_err()
        );

        let stale_parent = parent.clone();
        assert!(
            preview
                .versioned_execution(&stale_parent, ledgers(), binding, limits)
                .is_err()
        );
        assert!(
            preview
                .versioned_execution(
                    &parent,
                    ledgers(),
                    binding,
                    Limits {
                        max_nullifiers: 127,
                        ..limits
                    }
                )
                .is_err()
        );
        assert_eq!(parent.chain.fingerprint(), before);

        let mut committed = parent.clone();
        delta.commit_into(&mut committed.chain).unwrap();
        committed.economics = economics;
        committed.fund = fund;
        committed.governance = governance;
        let (commitment, nullifiers) = executed.into_parts();
        committed.nullifiers = nullifiers;
        assert_eq!(
            commitment,
            committed.execution_commitment(binding, limits).unwrap()
        );
        let full = ChainComponents::recompute(
            &committed.chain,
            binding,
            SnapshotTip::Materialized(committed.tip()),
            limits,
        )
        .unwrap()
        .assemble(
            VersionedLedgers {
                economics: &committed.economics,
                fund: &committed.fund,
                governance: &committed.governance,
            }
            .components(committed.network(), committed.height(), 2, limits)
            .unwrap(),
        )
        .unwrap();
        assert_eq!(commitment, full);
        assert_eq!(parent.chain.fingerprint(), before);
    }

    #[test]
    fn shared_chain_actions_match_the_existing_native_transition() {
        let initial = State::new(Config::development([62; 32], 0).unwrap()).unwrap();
        let block = candidate(&initial, 200_000);
        let before = initial.fingerprint();
        let prepared =
            PreparedActions::prepare(&initial, context(&block), actions(&block)).unwrap();
        let checked = prepared.verify(&TestVerifier).unwrap();
        assert_eq!(checked.fees().len(), block.transactions.len());
        assert_eq!(checked.rewards().len(), block.rewards.len());
        let delta = checked
            .finish(block.id().unwrap(), |h| Ok(crate::state::base_fee(h)))
            .unwrap();
        let mut staged = initial.clone();
        delta.commit_into(&mut staged).unwrap();
        staged
            .economics
            .advance(block.height, block.reward_mode)
            .unwrap();
        let mut legacy = initial.clone();
        legacy.apply(&block, &TestVerifier).unwrap();
        assert_eq!(staged.fingerprint(), legacy.fingerprint());
        assert_eq!(initial.fingerprint(), before);
    }

    #[test]
    fn rejected_proof_or_late_finalization_never_changes_the_parent() {
        let initial = State::new(Config::development([63; 32], 0).unwrap()).unwrap();
        let mut block = candidate(&initial, 300_000);
        let before = initial.fingerprint();
        block.transactions[19].proof = vec![0];
        let prepared =
            PreparedActions::prepare(&initial, context(&block), actions(&block)).unwrap();
        assert!(prepared.verify(&TestVerifier).is_err());
        assert_eq!(initial.fingerprint(), before);
        block.transactions[19].proof = vec![1];
        let checked = PreparedActions::prepare(&initial, context(&block), actions(&block))
            .unwrap()
            .verify(&TestVerifier)
            .unwrap();
        assert!(
            checked
                .finish([9; 32], |_| Err("fee kernel unavailable".into()))
                .is_err()
        );
        assert_eq!(initial.fingerprint(), before);
    }

    #[test]
    fn staged_identity_is_independent_and_authorized_outputs_are_one_use() {
        let initial = State::new(Config::development([64; 32], 0).unwrap()).unwrap();
        let block = candidate(&initial, 400_000);
        let mut checked = PreparedActions::prepare(&initial, context(&block), actions(&block))
            .unwrap()
            .verify(&TestVerifier)
            .unwrap();
        let existing_reward = decode_digest(&block.rewards[0].commitment).unwrap();
        assert!(checked.append_authorized_output(existing_reward).is_err());
        let output = [F::from_u32(7); 12];
        checked.append_authorized_output(output).unwrap();
        assert!(checked.append_authorized_output(output).is_err());
        let delta = checked
            .finish([0; 32], |h| Ok(crate::state::base_fee(h)))
            .unwrap();
        let mut staged = initial.clone();
        delta.commit_into(&mut staged).unwrap();
        assert_eq!(staged.tip, [0; 32]);
        assert_eq!(staged.tip_snapshot().selector.block_id, [0; 32]);
        assert_eq!(staged.tree.count, 194);
        assert_eq!(initial.height, 0);
    }

    #[test]
    fn context_and_canonical_order_are_checked_before_proof_execution() {
        let initial = State::new(Config::development([65; 32], 0).unwrap()).unwrap();
        let mut block = candidate(&initial, 500_000);
        let mut wrong = context(&block);
        wrong.parent = [0; 32];
        assert!(PreparedActions::prepare(&initial, wrong, actions(&block)).is_err());
        wrong = context(&block);
        wrong.target = [1; 32];
        assert!(PreparedActions::prepare(&initial, wrong, actions(&block)).is_err());
        wrong = context(&block);
        wrong.timestamp = initial.timestamp();
        assert!(PreparedActions::prepare(&initial, wrong, actions(&block)).is_err());
        block.transactions.swap(0, 1);
        assert!(PreparedActions::prepare(&initial, context(&block), actions(&block)).is_err());
    }

    #[test]
    fn a_completed_delta_cannot_publish_on_a_different_parent() {
        let initial = State::new(Config::development([66; 32], 0).unwrap()).unwrap();
        let block = candidate(&initial, 600_000);
        let delta = PreparedActions::prepare(&initial, context(&block), actions(&block))
            .unwrap()
            .verify(&TestVerifier)
            .unwrap()
            .finish([7; 32], |h| Ok(crate::state::base_fee(h)))
            .unwrap();
        let mut different = initial.clone();
        different.tip = [8; 32];
        let before = different.fingerprint();
        assert!(delta.commit_into(&mut different).is_err());
        assert_eq!(different.fingerprint(), before);
    }

    #[test]
    fn native_parallel_checks_reject_synthetic_proofs_and_preserve_the_parent() {
        use crate::eng2::proof_window::{Policy, WindowError};
        let initial = State::new(Config::development([67; 32], 0).unwrap()).unwrap();
        let block = candidate(&initial, 700_000);
        let before = initial.fingerprint();
        let verifier = crate::proofs::NativeVerifier::new().unwrap();
        let policy = Policy {
            workers: 4,
            max_blocks: 1,
            max_jobs: 64,
            max_proof_bytes: 64,
        };
        let prepared =
            PreparedActions::prepare(&initial, context(&block), actions(&block)).unwrap();
        assert!(matches!(
            prepared.verify_native_parallel(&verifier, policy),
            Err(WindowError::Proof {
                block: 0,
                job: 0,
                ..
            })
        ));
        let prepared =
            PreparedActions::prepare(&initial, context(&block), actions(&block)).unwrap();
        assert!(matches!(
            prepared.verify_native_parallel(
                &verifier,
                Policy {
                    max_proof_bytes: 63,
                    ..policy
                }
            ),
            Err(WindowError::Bounds)
        ));
        assert_eq!(initial.fingerprint(), before);
    }

    #[test]
    fn pool_success_verifies_every_prepared_context_before_delta_publication() {
        use crate::eng2::proof_window::Policy;
        use native::codec::{ProofContext, PublicTransaction};
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Counter(AtomicUsize);
        impl BlockVerifier for Counter {
            fn transaction(
                &self,
                public: &PublicTransaction,
                context: &ProofContext,
                fee: &Digest,
                root: &Digest,
                proof: &[u8],
            ) -> Result<(), String> {
                self.0.fetch_add(1, Ordering::SeqCst);
                TestVerifier.transaction(public, context, fee, root, proof)
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
                Err("unexpected settlement job".into())
            }
        }
        let initial = State::new(Config::development([68; 32], 0).unwrap()).unwrap();
        let block = candidate(&initial, 800_000);
        let counter = Counter(AtomicUsize::new(0));
        let prepared =
            PreparedActions::prepare(&initial, context(&block), actions(&block)).unwrap();
        let checked = prepared
            .verify_in_pool(
                &counter,
                Policy {
                    workers: 4,
                    max_blocks: 1,
                    max_jobs: 64,
                    max_proof_bytes: 64,
                },
            )
            .unwrap();
        assert_eq!(counter.0.load(Ordering::SeqCst), 64);
        let delta = checked
            .finish([0; 32], |h| Ok(crate::state::base_fee(h)))
            .unwrap();
        let mut staged = initial.clone();
        delta.commit_into(&mut staged).unwrap();
        assert_eq!(staged.height, 1);
        assert_eq!(initial.height, 0);
    }
}
