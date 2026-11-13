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
    pub(super) parent: &'a State,
    pub(super) context: Context,
    pub(super) actions: Actions<'a>,
    pub(super) transaction_proofs: Vec<TransactionProof<'a>>,
    pub(super) fees: Vec<Digest>,
    pub(super) rewards: Vec<Digest>,
    pub(super) tree: CommitmentTree,
    pub(super) assets: crate::issuance::AssetRegistry,
    pub(super) spends: BTreeSet<DigestBytes>,
    pub(super) outputs: BTreeSet<DigestBytes>,
    pub(super) leaves: Vec<Digest>,
}
/// Created only by executing the actual verifier on the prepared proof contexts.
pub(crate) struct CheckedActions<'a> {
    pub(super) prepared: PreparedActions<'a>,
}

/// A complete delta; construction can fail, but publication performs no proof,
/// encoding, accounting or allocation-dependent validation. Keep the target
/// parent exclusively owned until this delta is published or discarded.
pub(crate) struct ChainDelta {
    pub(super) context: Context,
    pub(super) parent_work: siworld_core::pow::Work,
    pub(super) parent_root: Digest,
    pub(super) cumulative_work: siworld_core::pow::Work,
    pub(super) tree: CommitmentTree,
    pub(super) assets: crate::issuance::AssetRegistry,
    pub(super) spends: BTreeSet<DigestBytes>,
    pub(super) outputs: BTreeSet<DigestBytes>,
    pub(super) leaves: Vec<Digest>,
    pub(super) snapshot: CanonicalSnapshot,
}

/// Read-only candidate chain state derived only after the shared proof checks.
/// This does not authorize settlement, the header or live state adoption.
pub struct ChainPreview<'a> {
    #[cfg(siworld_native_node)]
    pub(super) parent: &'a State,
    #[cfg(siworld_native_node)]
    pub(super) delta: &'a ChainDelta,
    #[cfg(not(siworld_native_node))]
    _borrow: std::marker::PhantomData<(&'a State, &'a ChainDelta)>,
    pub(super) timestamps: std::collections::VecDeque<u64>,
    pub(super) snapshots: std::collections::VecDeque<CanonicalSnapshot>,
}

impl ChainDelta {
    #[cfg(siworld_native_node)]
    pub(crate) fn new_leaves(&self) -> &[Digest] {
        &self.leaves
    }
    #[cfg(siworld_native_node)]
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
            #[cfg(siworld_native_node)]
            parent,
            #[cfg(siworld_native_node)]
            delta: self,
            #[cfg(not(siworld_native_node))]
            _borrow: std::marker::PhantomData,
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
