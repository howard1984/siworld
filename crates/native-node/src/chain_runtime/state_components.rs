//! Local reconstruction of the chain-owned execution-state components.
//!
//! Economic and governance adapters remain separate; neither a storage checksum
//! nor peer-supplied component hashes can replace these canonical encodings.

use super::commitment::{self, Component, ComponentId, SnapshotTip};
use crate::state::{CanonicalSnapshot, CommitmentTree, Config, State};
use crate::wire::Hash;
use native::codec::{decode_digest, encode_digest};
use std::collections::{BTreeSet, VecDeque};

pub use crate::chain_transition::ChainPreview;

/// Actual versioned ledgers, never peer-supplied commitment descriptors.
pub struct VersionedLedgers<'a> {
    pub economics: &'a crate::eng2_economics::EconomicState,
    pub fund: &'a crate::eng2_fund::FundLedger,
    pub governance: &'a crate::eng2_governance::GovernanceState,
}
impl VersionedLedgers<'_> {
    pub fn components(
        &self,
        network: Hash,
        height: u64,
        members: usize,
        limits: Limits,
    ) -> Result<[Component; 6], String> {
        self.check_context(network, height, members)?;
        let [pool, counters, locked] = self.economics.component_bytes()?;
        let external = [
            pool,
            self.fund.canonical_component_bytes()?,
            self.governance.canonical_fee_destination_bytes()?,
            self.governance.canonical_component_bytes()?,
            counters,
            locked,
        ];
        let ids = [
            ComponentId::HolderPool,
            ComponentId::DevelopmentFund,
            ComponentId::FeeDestination,
            ComponentId::Governance,
            ComponentId::IssuanceAndBurn,
            ComponentId::LockedRewards,
        ];
        ids.into_iter()
            .zip(external)
            .map(|(id, bytes)| {
                Component::from_local_encoding(id, &bytes, limits.max_component_bytes)
                    .map_err(|_| "external snapshot component byte bound".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| "external component count".into())
    }

    pub(crate) fn check_context(
        &self,
        network: Hash,
        height: u64,
        members: usize,
    ) -> Result<(), String> {
        if self.economics.network() != network
            || self.fund.network() != network
            || self.governance.network() != network
            || self.economics.height() != height
            || self.fund.height() != height
            || self.governance.height() != height
            || members > crate::eng2_governance::MAX_FUND_MEMBERS
            || self
                .governance
                .active_fund_destination(members as u8)
                .is_ok()
            || (0..members).any(|member| {
                self.governance
                    .active_fund_destination(member as u8)
                    .is_err()
            })
        {
            return Err("snapshot component network, height or membership differs".into());
        }
        self.economics
            .verify_fund_entitlement(self.fund.total_entitlement())
    }
}

/// A calculated candidate commitment, not a proof or state-adoption capability.
pub struct ExecutionPreview {
    commitment: Hash,
    nullifiers: super::nullifiers::NullifierSet,
}
impl ExecutionPreview {
    pub(crate) fn new(commitment: Hash, nullifiers: super::nullifiers::NullifierSet) -> Self {
        Self {
            commitment,
            nullifiers,
        }
    }
    pub fn commitment(&self) -> Hash {
        self.commitment
    }
    pub fn nullifiers(&self) -> &super::nullifiers::NullifierSet {
        &self.nullifiers
    }
    pub fn into_parts(self) -> (Hash, super::nullifiers::NullifierSet) {
        (self.commitment, self.nullifiers)
    }
}

#[derive(Clone, Copy)]
pub struct Limits {
    pub max_leaves: usize,
    pub max_nullifiers: usize,
    pub max_component_bytes: usize,
}

#[derive(Clone, Copy)]
pub struct Binding {
    pub genesis: Hash,
    pub rules_commitment: Hash,
    pub parent: Hash,
}

pub struct ChainComponents {
    network: Hash,
    height: u64,
    parent: Hash,
    first: [Component; 4],
    assets: Component,
    encodings: [Vec<u8>; 5],
}

/// Compact current-state encodings. Construction from a live carrier is
/// internal; raw snapshots always use full reconstruction before this path.
pub(crate) struct ExecutionComponents {
    network: Hash,
    height: u64,
    parent: Hash,
    first: [Component; 4],
    assets: Component,
}

/// References to actual accepted or staged objects. No permanent value vector
/// is copied or exposed through this view, and no asserted root is accepted.
pub(crate) struct ChainView<'a> {
    pub fee_mode: super::genesis::FeeMode,
    pub config: &'a Config,
    pub height: u64,
    pub tip: Hash,
    pub cumulative_work: siworld_core::pow::Work,
    pub timestamps: &'a VecDeque<u64>,
    pub tree: &'a CommitmentTree,
    pub leaves: usize,
    pub commitments: usize,
    pub spent: usize,
    pub assets: &'a crate::issuance::AssetRegistry,
    pub snapshots: &'a VecDeque<CanonicalSnapshot>,
}
impl<'a> From<&'a State> for ChainView<'a> {
    fn from(state: &'a State) -> Self {
        Self {
            fee_mode: super::genesis::FeeMode::ConfidentialDestination,
            config: &state.config,
            height: state.height,
            tip: state.tip,
            cumulative_work: state.cumulative_work,
            timestamps: &state.timestamps,
            tree: &state.tree,
            leaves: state.leaves.len(),
            commitments: state.commitments.len(),
            spent: state.spent.len(),
            assets: &state.assets,
            snapshots: &state.snapshots,
        }
    }
}
impl ExecutionComponents {
    #[cfg(test)]
    pub(crate) fn from_local_state(
        state: &State,
        nullifiers: &super::nullifiers::NullifierSet,
        binding: Binding,
        tip: SnapshotTip,
        limits: Limits,
    ) -> Result<Self, String> {
        Self::from_view(state.into(), nullifiers, binding, tip, limits)
    }
    pub(crate) fn from_local_state_for_fee_mode(
        state: &State,
        nullifiers: &super::nullifiers::NullifierSet,
        binding: Binding,
        tip: SnapshotTip,
        limits: Limits,
        fee_mode: super::genesis::FeeMode,
    ) -> Result<Self, String> {
        let mut view: ChainView<'_> = state.into();
        view.fee_mode = fee_mode;
        Self::from_view(view, nullifiers, binding, tip, limits)
    }
    pub(crate) fn from_view(
        state: ChainView<'_>,
        nullifiers: &super::nullifiers::NullifierSet,
        binding: Binding,
        tip: SnapshotTip,
        limits: Limits,
    ) -> Result<Self, String> {
        if binding.genesis == [0; 32]
            || binding.rules_commitment == [0; 32]
            || (state.height == 0) != (binding.parent == [0; 32])
            || state.tree.count != state.leaves as u64
            || state.commitments != state.leaves
            || nullifiers.len() != state.spent as u64
            || state.leaves > limits.max_leaves
            || state.spent > limits.max_nullifiers
        {
            return Err("invalid local incremental chain context".into());
        }
        match tip {
            SnapshotTip::Materialized(id) if state.tip != id => {
                return Err("local materialized tip differs".into());
            }
            SnapshotTip::Staged if state.height == 0 || state.tip != [0; 32] => {
                return Err("invalid local staged tip".into());
            }
            _ => (),
        }
        let window = siworld_core::params::MEDIAN_TIME_PAST_WINDOW;
        let expected_times = (state.height.min(window as u64 - 1) + 1) as usize;
        if state.timestamps.len() != expected_times
            || (state.height == 0
                && (state.tip != binding.genesis
                    || state.timestamps.back().copied() != Some(state.config.genesis_timestamp)
                    || !state.cumulative_work.is_zero()
                    || state.tree.count != 0
                    || state.spent != 0
                    || !state.assets.is_empty()))
            || (state.height != 0 && state.cumulative_work.is_zero())
        {
            return Err("invalid local chain work or timestamp context".into());
        }
        let snapshots = commitment::snapshot_encoding(state.height, tip, state.snapshots)
            .map_err(|_| "invalid local snapshot encoding")?;
        if state.snapshots.front().is_some_and(|snapshot| {
            snapshot.selector.height == 0 && snapshot.selector.block_id != binding.genesis
        }) || state
            .snapshots
            .back()
            .is_none_or(|snapshot| snapshot.commitment_root != encode_digest(&state.tree.root()))
        {
            return Err("local latest snapshot differs from actual roots".into());
        }
        // This is bounded by the fixed recent-root window; no permanent leaf
        // or nullifier vector is scanned, cloned, sorted or hashed here.
        let recent = canonical_recent_root_snapshots(state.snapshots, state.fee_mode)?;
        if state
            .snapshots
            .back()
            .is_none_or(|snapshot| snapshot.recent_root != recent)
        {
            return Err("local recent root differs".into());
        }
        let mut context = BoundedBytes::new(limits.max_component_bytes);
        context.extend(&1u16.to_le_bytes())?;
        context.extend(&state.config.network)?;
        context.extend(&binding.genesis)?;
        context.extend(&binding.rules_commitment)?;
        context.extend(&state.height.to_le_bytes())?;
        context.extend(&binding.parent)?;
        context.extend(&state.cumulative_work.to_little_endian())?;
        context.extend(&(state.timestamps.len() as u64).to_le_bytes())?;
        for timestamp in state.timestamps {
            context.extend(&timestamp.to_le_bytes())?;
        }
        let mut assets = BoundedBytes::new(limits.max_component_bytes);
        let mut overflow = false;
        state.assets.visit_encoding(&mut |part| {
            if !overflow && assets.extend(part).is_err() {
                overflow = true;
            }
        });
        if overflow {
            return Err("local asset component exceeds bound".into());
        }
        let component = |id, bytes: &[u8]| {
            Component::from_local_encoding(id, bytes, limits.max_component_bytes)
                .map_err(|_| "local execution component byte bound".to_owned())
        };
        Ok(Self {
            network: state.config.network,
            height: state.height,
            parent: binding.parent,
            first: [
                component(ComponentId::ChainContext, &context.bytes)?,
                component(
                    ComponentId::CommitmentTree,
                    &tree_execution_encoding(state.tree),
                )?,
                component(ComponentId::Nullifiers, &nullifiers.execution_encoding())?,
                component(ComponentId::RecentRoots, &snapshots)?,
            ],
            assets: component(ComponentId::AssetRegistry, &assets.bytes)?,
        })
    }
    pub(crate) fn assemble(self, external: [Component; 6]) -> Result<Hash, String> {
        let components: Vec<_> = self
            .first
            .into_iter()
            .chain(external)
            .chain([self.assets])
            .collect();
        commitment::aggregate(self.network, self.height, self.parent, &components)
            .map_err(|_| "invalid external component order".into())
    }
}

/// Initialize only the chain-owned carrier. Versioned economics and governance
/// must be initialized separately; this carrier's V1 economics is never used by
/// the versioned engine. The pinned engineering genesis is supplied locally.
pub fn genesis_chain(config: crate::state::Config, genesis: Hash) -> Result<State, String> {
    genesis_chain_for_fee_mode(
        config,
        genesis,
        super::genesis::FeeMode::ConfidentialDestination,
    )
}
pub(crate) fn genesis_chain_for_fee_mode(
    config: crate::state::Config,
    genesis: Hash,
    fee_mode: super::genesis::FeeMode,
) -> Result<State, String> {
    if genesis == [0; 32] {
        return Err("invalid pinned engineering genesis".into());
    }
    let mut state = State::new(config)?;
    state.tip = genesis;
    state
        .snapshots
        .back_mut()
        .expect("genesis snapshot")
        .selector
        .block_id = genesis;
    let root = canonical_recent_root_snapshots(&state.snapshots, fee_mode)?;
    state
        .snapshots
        .back_mut()
        .expect("genesis snapshot")
        .recent_root = root;
    Ok(state)
}

#[cfg(test)]
fn canonical_recent_root(state: &State) -> Result<crate::wire::DigestBytes, String> {
    canonical_recent_root_snapshots(
        &state.snapshots,
        super::genesis::FeeMode::ConfidentialDestination,
    )
}
fn canonical_recent_root_snapshots(
    snapshots: &VecDeque<CanonicalSnapshot>,
    fee_mode: super::genesis::FeeMode,
) -> Result<crate::wire::DigestBytes, String> {
    let mut roots = native::multi_asset::RecentRoots::new();
    let hasher = native::multi_asset::Hasher::new();
    for snapshot in snapshots {
        roots.insert(
            &hasher,
            snapshot.selector.height,
            &decode_digest(&snapshot.commitment_root).map_err(|_| "invalid recent-root field")?,
            fee_mode.base_fee(snapshot.selector.height)?,
        );
    }
    Ok(encode_digest(&roots.tree(&hasher).root()))
}

impl ChainComponents {
    /// Canonical chain-owned bytes in component order 1, 2, 3, 4, 11.
    pub fn canonical_bytes(&self) -> [&[u8]; 5] {
        self.encodings.each_ref().map(Vec::as_slice)
    }

    /// Reconstruct chain-owned state from bounded canonical bytes. This checks
    /// state shape only; admission must authenticate all eleven components
    /// against the selected header before exposing the imported state.
    pub fn reconstruct(
        config: crate::state::Config,
        binding: Binding,
        tip: Hash,
        bytes: [&[u8]; 5],
        limits: Limits,
    ) -> Result<State, String> {
        Self::reconstruct_for_fee_mode(
            config,
            binding,
            tip,
            bytes,
            limits,
            super::genesis::FeeMode::ConfidentialDestination,
        )
    }
    pub(crate) fn reconstruct_for_fee_mode(
        config: crate::state::Config,
        binding: Binding,
        tip: Hash,
        bytes: [&[u8]; 5],
        limits: Limits,
        fee_mode: super::genesis::FeeMode,
    ) -> Result<State, String> {
        if bytes
            .iter()
            .any(|part| part.len() > limits.max_component_bytes)
        {
            return Err("chain component exceeds byte bound".into());
        }
        let mut state = genesis_chain_for_fee_mode(config, binding.genesis, fee_mode)?;
        let mut context = Reader::new(bytes[0]);
        if u16::from_le_bytes(context.array()?) != 1
            || context.array::<32>()? != state.config.network
            || context.array::<32>()? != binding.genesis
            || context.array::<32>()? != binding.rules_commitment
        {
            return Err("imported chain network or pinned rules differ".into());
        }
        state.height = context.u64()?;
        if context.array::<32>()? != binding.parent {
            return Err("imported chain parent differs".into());
        }
        state.tip = tip;
        state.cumulative_work =
            siworld_core::pow::Work::from_little_endian(&context.array::<64>()?);
        let times = context.count(siworld_core::params::MEDIAN_TIME_PAST_WINDOW)?;
        context.exact_remaining(times, 8)?;
        state.timestamps.clear();
        for _ in 0..times {
            state.timestamps.push_back(context.u64()?);
        }

        let mut tree_bytes = Reader::new(bytes[1]);
        let count = tree_bytes.count(limits.max_leaves)?;
        let root = tree_bytes.digest()?;
        let frontier_count = tree_bytes.count(native::multi_asset::TREE_DEPTH)?;
        if frontier_count != native::multi_asset::TREE_DEPTH {
            return Err("imported tree frontier length differs".into());
        }
        let mut frontier = Vec::new();
        frontier
            .try_reserve_exact(frontier_count)
            .map_err(|_| "import frontier allocation limit")?;
        for _ in 0..frontier_count {
            frontier.push(encode_digest(&tree_bytes.digest()?));
        }
        if tree_bytes.count(limits.max_leaves)? != count {
            return Err("imported tree and leaf counts differ".into());
        }
        tree_bytes.exact_remaining(count, 96)?;
        state
            .leaves
            .try_reserve_exact(count)
            .map_err(|_| "import leaf allocation limit")?;
        for _ in 0..count {
            let leaf = tree_bytes.digest()?;
            if !state.commitments.insert(encode_digest(&leaf)) {
                return Err("duplicate imported commitment leaf".into());
            }
            state.tree.append(leaf)?;
            state.leaves.push(leaf);
        }
        let mut previous = None;
        for _ in 0..count {
            let member = encode_digest(&tree_bytes.digest()?);
            if previous.is_some_and(|old| old >= member) || !state.commitments.contains(&member) {
                return Err("noncanonical imported commitment membership".into());
            }
            previous = Some(member);
        }
        if state.tree.root() != root || state.tree.cache_frontier() != frontier {
            return Err("reconstructed tree differs from imported root or frontier".into());
        }

        let mut nullifiers = Reader::new(bytes[2]);
        let count = nullifiers.count(limits.max_nullifiers)?;
        nullifiers.exact_remaining(count, 48)?;
        let mut previous = None;
        for _ in 0..count {
            let nullifier = encode_digest(&nullifiers.digest()?);
            if previous.is_some_and(|old| old >= nullifier) {
                return Err("noncanonical imported nullifier order".into());
            }
            state.spent.insert(nullifier);
            previous = Some(nullifier);
        }

        let mut snapshots = Reader::new(bytes[3]);
        let count = snapshots.count(crate::state::SNAPSHOT_WINDOW)?;
        let first = state
            .height
            .saturating_sub(crate::state::SNAPSHOT_WINDOW as u64 - 1);
        if count as u64 != state.height - first + 1 {
            return Err("imported recent-root window length differs".into());
        }
        state.snapshots.clear();
        for index in 0..count {
            let height = snapshots.u64()?;
            if height != first + index as u64 {
                return Err("imported snapshot heights are not contiguous".into());
            }
            let tag = snapshots.array::<1>()?[0];
            let block_id = if height == state.height && height != 0 {
                if tag != 1 {
                    return Err("imported newest snapshot is not SelfAtHeight".into());
                }
                tip
            } else {
                if tag != 0 {
                    return Err("imported historical snapshot has a self selector".into());
                }
                snapshots.array()?
            };
            state.snapshots.push_back(crate::state::CanonicalSnapshot {
                selector: crate::wire::Snapshot { height, block_id },
                commitment_root: encode_digest(&snapshots.digest()?),
                recent_root: encode_digest(&snapshots.digest()?),
            });
        }
        snapshots.exact_remaining(0, 1)?;
        state.assets =
            crate::issuance::AssetRegistry::decode_canonical_state(bytes[4], state.height)?;
        let canonical = Self::recompute_for_fee_mode(
            &state,
            binding,
            SnapshotTip::Materialized(tip),
            limits,
            fee_mode,
        )?;
        if canonical.canonical_bytes() != bytes {
            return Err("reconstructed chain encoding differs".into());
        }
        Ok(state)
    }
    /// Rebuild the imported tree and membership from canonical leaves. This is
    /// an import-time adapter, not a per-block history rescan. The binding must
    /// come from the locally pinned network rules, never snapshot metadata.
    pub fn recompute(
        state: &State,
        binding: Binding,
        tip: SnapshotTip,
        limits: Limits,
    ) -> Result<Self, String> {
        Self::recompute_for_fee_mode(
            state,
            binding,
            tip,
            limits,
            super::genesis::FeeMode::ConfidentialDestination,
        )
    }
    pub(crate) fn recompute_for_fee_mode(
        state: &State,
        binding: Binding,
        tip: SnapshotTip,
        limits: Limits,
        fee_mode: super::genesis::FeeMode,
    ) -> Result<Self, String> {
        if binding.genesis == [0; 32]
            || binding.rules_commitment == [0; 32]
            || (state.height == 0) != (binding.parent == [0; 32])
            || state.leaves.len() > limits.max_leaves
            || state.spent.len() > limits.max_nullifiers
            || state.tree.count != state.leaves.len() as u64
            || state.commitments.len() != state.leaves.len()
        {
            return Err("invalid chain component shape or binding".into());
        }
        let window = siworld_core::params::MEDIAN_TIME_PAST_WINDOW;
        let expected_times = (state.height.min(window as u64 - 1) + 1) as usize;
        if state.timestamps.len() != expected_times
            || (state.height == 0
                && (state.timestamp() != state.config.genesis_timestamp
                    || !state.cumulative_work.is_zero()
                    || state.tip != binding.genesis
                    || !state.leaves.is_empty()
                    || !state.spent.is_empty()
                    || !state.assets.is_empty()))
            || (state.height != 0 && state.cumulative_work.is_zero())
        {
            return Err("invalid imported chain context".into());
        }
        match tip {
            SnapshotTip::Materialized(id) if state.tip != id => {
                return Err("imported state tip differs".into());
            }
            SnapshotTip::Staged if state.height == 0 || state.tip != [0; 32] => {
                return Err("invalid staged state tip".into());
            }
            _ => (),
        }
        if state.snapshots.front().is_some_and(|snapshot| {
            snapshot.selector.height == 0 && snapshot.selector.block_id != binding.genesis
        }) {
            return Err("snapshot genesis differs".into());
        }

        // Check exact bounded lengths before copying sets or rebuilding a tree.
        let frontier = state.tree.cache_frontier();
        checked_size(
            24 + 48 + frontier.len() * 48,
            state.leaves.len(),
            96,
            limits.max_component_bytes,
        )?;
        checked_size(8, state.spent.len(), 48, limits.max_component_bytes)?;
        let snapshot_bytes = state
            .snapshots
            .len()
            .checked_mul(137)
            .and_then(|size| size.checked_add(8))
            .and_then(|size| size.checked_sub(if state.height == 0 { 0 } else { 32 }))
            .ok_or("snapshot component length overflow")?;
        checked_size(0, snapshot_bytes, 1, limits.max_component_bytes)?;
        let mut context = BoundedBytes::new(limits.max_component_bytes);
        context.extend(&1u16.to_le_bytes())?;
        context.extend(&state.config.network)?;
        context.extend(&binding.genesis)?;
        context.extend(&binding.rules_commitment)?;
        context.extend(&state.height.to_le_bytes())?;
        context.extend(&binding.parent)?;
        context.extend(&state.cumulative_work.to_little_endian())?;
        context.extend(&(state.timestamps.len() as u64).to_le_bytes())?;
        for timestamp in &state.timestamps {
            context.extend(&timestamp.to_le_bytes())?;
        }

        let mut tree = CommitmentTree::new();
        let mut membership = BTreeSet::new();
        for leaf in &state.leaves {
            let bytes = encode_digest(leaf);
            // Encoding must not silently reduce a noncanonical field.
            if decode_digest(&bytes).map_err(|_| "invalid commitment field")? != *leaf
                || !membership.insert(bytes)
            {
                return Err("duplicate or noncanonical commitment leaf".into());
            }
            tree.append(*leaf)?;
        }
        if tree.root() != state.tree.root()
            || tree.cache_frontier() != frontier
            || membership != state.commitments
            || state
                .snapshots
                .back()
                .is_none_or(|s| s.commitment_root != encode_digest(&tree.root()))
        {
            return Err("imported commitment tree or membership differs".into());
        }
        let recent_root = canonical_recent_root_snapshots(&state.snapshots, fee_mode)?;
        if state
            .snapshots
            .back()
            .is_none_or(|snapshot| snapshot.recent_root != recent_root)
        {
            return Err("imported latest recent root differs from versioned fees".into());
        }
        let mut tree_bytes = BoundedBytes::new(limits.max_component_bytes);
        tree_bytes.extend(&tree.count.to_le_bytes())?;
        tree_bytes.extend(&encode_digest(&tree.root()))?;
        tree_bytes.extend(&(frontier.len() as u64).to_le_bytes())?;
        for node in &frontier {
            tree_bytes.extend(node)?;
        }
        tree_bytes.extend(&(state.leaves.len() as u64).to_le_bytes())?;
        for leaf in &state.leaves {
            tree_bytes.extend(&encode_digest(leaf))?;
        }
        for commitment in &membership {
            tree_bytes.extend(commitment)?;
        }

        let mut nullifiers = BoundedBytes::new(limits.max_component_bytes);
        nullifiers.extend(&(state.spent.len() as u64).to_le_bytes())?;
        for nullifier in &state.spent {
            let _ = decode_digest(nullifier).map_err(|_| "noncanonical nullifier field")?;
            nullifiers.extend(nullifier)?;
        }
        let snapshots = commitment::snapshot_encoding(state.height, tip, &state.snapshots)
            .map_err(|_| "invalid recent-root snapshot component")?;
        let mut assets = BoundedBytes::new(limits.max_component_bytes);
        let mut overflow = false;
        state.assets.visit_encoding(&mut |part| {
            if !overflow && assets.extend(part).is_err() {
                overflow = true;
            }
        });
        if overflow {
            return Err("asset component exceeds byte bound".into());
        }
        // This validates encoding shape and canonical order. It does not prove
        // historical issuance: the selected work-authenticated header binds it.
        crate::issuance::AssetRegistry::decode_canonical_state(&assets.bytes, state.height)?;
        let component = |id, bytes: &[u8]| {
            Component::from_local_encoding(id, bytes, limits.max_component_bytes)
                .map_err(|_| "invalid chain component byte bound".to_owned())
        };
        let tree_execution = tree_execution_encoding(&tree);
        let nullifier_execution =
            super::nullifiers::NullifierSet::rebuild(&state.spent)?.execution_encoding();
        Ok(Self {
            network: state.config.network,
            height: state.height,
            parent: binding.parent,
            first: [
                component(ComponentId::ChainContext, &context.bytes)?,
                component(ComponentId::CommitmentTree, &tree_execution)?,
                component(ComponentId::Nullifiers, &nullifier_execution)?,
                component(ComponentId::RecentRoots, &snapshots)?,
            ],
            assets: component(ComponentId::AssetRegistry, &assets.bytes)?,
            encodings: [
                context.bytes,
                tree_bytes.bytes,
                nullifiers.bytes,
                snapshots,
                assets.bytes,
            ],
        })
    }

    /// The external order is Holder pool, fund, destination, governance,
    /// issuance/burn and locked rewards. Every component ID is checked again.
    pub fn assemble(self, external: [Component; 6]) -> Result<Hash, String> {
        ExecutionComponents {
            network: self.network,
            height: self.height,
            parent: self.parent,
            first: self.first,
            assets: self.assets,
        }
        .assemble(external)
    }
}

/// Compact execution encoding derived from the actual append-tree state. Raw
/// snapshot bytes additionally carry every leaf needed for independent rebuild.
pub fn tree_execution_encoding(tree: &CommitmentTree) -> [u8; 58] {
    let mut bytes = [0; 58];
    bytes[..2].copy_from_slice(&2u16.to_le_bytes());
    bytes[2..10].copy_from_slice(&tree.count.to_le_bytes());
    bytes[10..].copy_from_slice(&encode_digest(&tree.root()));
    bytes
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let end = self
            .position
            .checked_add(N)
            .ok_or("import offset overflow")?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or("truncated chain component")?;
        self.position = end;
        Ok(bytes.try_into().expect("checked fixed component width"))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn count(&mut self, limit: usize) -> Result<usize, String> {
        let count = usize::try_from(self.u64()?).map_err(|_| "import count conversion")?;
        if count > limit {
            return Err("import count exceeds bound".into());
        }
        Ok(count)
    }
    fn exact_remaining(&self, count: usize, width: usize) -> Result<(), String> {
        if count
            .checked_mul(width)
            .and_then(|size| self.position.checked_add(size))
            != Some(self.bytes.len())
        {
            return Err("noncanonical chain component length".into());
        }
        Ok(())
    }
    fn digest(&mut self) -> Result<native::multi_asset::Digest, String> {
        decode_digest(&self.array()?).map_err(|_| "noncanonical imported field".into())
    }
}

fn checked_size(base: usize, count: usize, width: usize, limit: usize) -> Result<(), String> {
    if count
        .checked_mul(width)
        .and_then(|n| base.checked_add(n))
        .is_none_or(|n| n > limit)
    {
        return Err("chain component exceeds byte bound".into());
    }
    Ok(())
}

struct BoundedBytes {
    bytes: Vec<u8>,
    limit: usize,
}
impl BoundedBytes {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }
    fn extend(&mut self, part: &[u8]) -> Result<(), String> {
        checked_size(self.bytes.len(), part.len(), 1, self.limit)?;
        self.bytes
            .try_reserve(part.len())
            .map_err(|_| "component allocation limit")?;
        self.bytes.extend_from_slice(part);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::commitment::ComponentId::*;
    use super::*;
    use crate::state::Config;

    fn state() -> State {
        let config = Config::development([1; 32], 0).unwrap();
        let genesis = config.genesis_id();
        genesis_chain(config, genesis).unwrap()
    }
    fn limits() -> Limits {
        Limits {
            max_leaves: 100,
            max_nullifiers: 100,
            max_component_bytes: 1024 * 1024,
        }
    }
    fn binding(state: &State) -> Binding {
        Binding {
            genesis: state.config.genesis_id(),
            rules_commitment: [9; 32],
            parent: [0; 32],
        }
    }
    fn external() -> [Component; 6] {
        [
            HolderPool,
            DevelopmentFund,
            FeeDestination,
            Governance,
            IssuanceAndBurn,
            LockedRewards,
        ]
        .map(|id| {
            Component::from_local_encoding(id, b"synthetic external canonical state", 1024).unwrap()
        })
    }

    fn populated() -> (State, Binding) {
        use crate::state::CanonicalSnapshot;
        use native::multi_asset::F;
        use p3_field::PrimeCharacteristicRing;
        let mut state = state();
        let mut binding = binding(&state);
        binding.parent = state.tip;
        state.height = 1;
        state.tip = [3; 32];
        state.cumulative_work = 1.into();
        state
            .timestamps
            .push_back(state.config.genesis_timestamp + 300);
        let leaf = [F::ONE; 12];
        state.tree.append(leaf).unwrap();
        state.leaves.push(leaf);
        state.commitments.insert(encode_digest(&leaf));
        state.spent.insert(encode_digest(&[F::ZERO; 12]));
        state.snapshots.push_back(CanonicalSnapshot {
            selector: crate::wire::Snapshot {
                height: 1,
                block_id: state.tip,
            },
            commitment_root: encode_digest(&state.tree.root()),
            recent_root: encode_digest(&[F::ZERO; 12]),
        });
        let recent_root = canonical_recent_root(&state).unwrap();
        state.snapshots.back_mut().unwrap().recent_root = recent_root;
        (state, binding)
    }

    #[test]
    fn canonical_raw_chain_import_rebuilds_genesis_and_populated_state() {
        let genesis = state();
        for (state, binding) in [(genesis.clone(), binding(&genesis)), populated()] {
            let encoded = ChainComponents::recompute(
                &state,
                binding,
                SnapshotTip::Materialized(state.tip),
                limits(),
            )
            .unwrap();
            let imported = ChainComponents::reconstruct(
                state.config.clone(),
                binding,
                state.tip,
                encoded.canonical_bytes(),
                limits(),
            )
            .unwrap();
            assert_eq!(imported.fingerprint(), state.fingerprint());
            let rebuilt = ChainComponents::recompute(
                &imported,
                binding,
                SnapshotTip::Materialized(imported.tip),
                limits(),
            )
            .unwrap();
            assert_eq!(rebuilt.canonical_bytes(), encoded.canonical_bytes());
        }
    }

    #[test]
    fn raw_chain_import_rejects_inconsistent_tree_sets_context_and_window() {
        let (state, binding) = populated();
        let encoded = ChainComponents::recompute(
            &state,
            binding,
            SnapshotTip::Materialized(state.tip),
            limits(),
        )
        .unwrap();
        let original = encoded.canonical_bytes().map(<[u8]>::to_vec);
        let import = |bytes: &[Vec<u8>; 5]| {
            ChainComponents::reconstruct(
                state.config.clone(),
                binding,
                state.tip,
                bytes.each_ref().map(Vec::as_slice),
                limits(),
            )
        };
        // Network, pinned rules, parent, frontier, leaf, membership, nullifier,
        // recent-root height/selector and asset encoding cannot be substituted.
        for (component, offset) in [
            (0, 2),
            (0, 66),
            (0, 106),
            (1, 8),
            (1, 64),
            (1, original[1].len() - 96),
            (1, original[1].len() - 48),
            (3, 8),
            (3, 16),
            (4, 0),
        ] {
            let mut changed = original.clone();
            changed[component][offset] ^= 1;
            assert!(
                import(&changed).is_err(),
                "component {component}, offset {offset}"
            );
        }
        let mut changed = original.clone();
        changed[1][..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(import(&changed).is_err());
        changed = original.clone();
        changed[2][..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(import(&changed).is_err());
        changed = original.clone();
        changed[2][8..12].copy_from_slice(
            &<native::multi_asset::F as p3_field::PrimeField32>::ORDER_U32.to_le_bytes(),
        );
        assert!(import(&changed).is_err());
        for component in 0..5 {
            changed = original.clone();
            changed[component].push(0);
            assert!(import(&changed).is_err());
        }
        assert!(
            ChainComponents::reconstruct(
                state.config.clone(),
                binding,
                state.tip,
                encoded.canonical_bytes(),
                Limits {
                    max_leaves: 0,
                    ..limits()
                },
            )
            .is_err()
        );
    }

    #[test]
    fn versioned_genesis_and_latest_recent_root_use_the_versioned_fee_base() {
        assert_eq!(
            crate::eng2_economics::fee_base(0),
            crate::eng2_economics::fee_base(1)
        );
        assert_eq!(
            crate::eng2_economics::EconomicState::new([1; 32])
                .unwrap()
                .issued(),
            0
        );
        let config = Config::development([1; 32], 0).unwrap();
        let legacy = State::new(config.clone()).unwrap();
        let versioned = genesis_chain(config, [7; 32]).unwrap();
        assert_eq!(versioned.tip, [7; 32]);
        assert_eq!(versioned.tip_snapshot().selector.block_id, [7; 32]);
        assert_ne!(
            versioned.tip_snapshot().recent_root,
            legacy.tip_snapshot().recent_root
        );
        let (mut state, binding) = populated();
        state.snapshots.back_mut().unwrap().recent_root = encode_digest(
            &state
                .recent_roots()
                .unwrap()
                .tree(&native::multi_asset::Hasher::new())
                .root(),
        );
        assert!(
            ChainComponents::recompute(
                &state,
                binding,
                SnapshotTip::Materialized(state.tip),
                limits()
            )
            .is_err()
        );
    }

    #[test]
    fn compact_local_execution_matches_full_reconstruction_without_rehashing_historical_nullifiers()
    {
        use native::multi_asset::F;
        use p3_field::PrimeCharacteristicRing;
        let (mut state, binding) = populated();
        for index in 1..=64 {
            state.spent.insert(encode_digest(&[F::from_u32(index); 12]));
        }
        let nullifiers = super::super::nullifiers::NullifierSet::rebuild(&state.spent).unwrap();
        let full = ChainComponents::recompute(
            &state,
            binding,
            SnapshotTip::Materialized(state.tip),
            limits(),
        )
        .unwrap()
        .assemble(external())
        .unwrap();
        super::super::nullifiers::reset_test_hash_calls();
        let compact = ExecutionComponents::from_local_state(
            &state,
            &nullifiers,
            binding,
            SnapshotTip::Materialized(state.tip),
            limits(),
        )
        .unwrap()
        .assemble(external())
        .unwrap();
        assert_eq!(compact, full);
        assert_eq!(super::super::nullifiers::test_hash_calls(), 0);
        let stale = super::super::nullifiers::NullifierSet::new();
        assert!(
            ExecutionComponents::from_local_state(
                &state,
                &stale,
                binding,
                SnapshotTip::Materialized(state.tip),
                limits()
            )
            .is_err()
        );
        let mut staged = state.clone();
        staged.tip = [0; 32];
        staged.snapshots.back_mut().unwrap().selector.block_id = [0; 32];
        let staged_root = ExecutionComponents::from_local_state(
            &staged,
            &nullifiers,
            binding,
            SnapshotTip::Staged,
            limits(),
        )
        .unwrap()
        .assemble(external())
        .unwrap();
        assert_eq!(staged_root, full);
    }

    #[test]
    fn staged_and_materialized_populated_state_have_the_same_commitment() {
        let (mut state, binding) = populated();
        let materialized = ChainComponents::recompute(
            &state,
            binding,
            SnapshotTip::Materialized(state.tip),
            limits(),
        )
        .unwrap()
        .assemble(external())
        .unwrap();
        state.tip = [0; 32];
        state.snapshots.back_mut().unwrap().selector.block_id = [0; 32];
        let staged = ChainComponents::recompute(&state, binding, SnapshotTip::Staged, limits())
            .unwrap()
            .assemble(external())
            .unwrap();
        assert_eq!(staged, materialized);
        assert!(
            ChainComponents::recompute(
                &state,
                binding,
                SnapshotTip::Materialized([3; 32]),
                limits()
            )
            .is_err()
        );
    }

    #[test]
    fn populated_state_commits_work_time_and_sets_and_rejects_inconsistent_membership() {
        use native::multi_asset::F;
        use p3_field::PrimeCharacteristicRing;
        let (original, binding) = populated();
        let digest = |state: &State| {
            ChainComponents::recompute(
                state,
                binding,
                SnapshotTip::Materialized(state.tip),
                limits(),
            )
            .unwrap()
            .assemble(external())
            .unwrap()
        };
        let expected = digest(&original);
        let mut changed = original.clone();
        changed.cumulative_work += siworld_core::pow::Work::one();
        assert_ne!(digest(&changed), expected);
        changed = original.clone();
        *changed.timestamps.back_mut().unwrap() += 1;
        assert_ne!(digest(&changed), expected);
        changed = original.clone();
        changed.spent.insert(encode_digest(&[F::ONE; 12]));
        assert_ne!(digest(&changed), expected);
        changed = original.clone();
        changed.leaves.push(changed.leaves[0]);
        changed.tree.append(changed.leaves[0]).unwrap();
        assert!(
            ChainComponents::recompute(
                &changed,
                binding,
                SnapshotTip::Materialized(changed.tip),
                limits()
            )
            .is_err()
        );
        changed = original.clone();
        changed.timestamps.pop_front();
        assert!(
            ChainComponents::recompute(
                &changed,
                binding,
                SnapshotTip::Materialized(changed.tip),
                limits()
            )
            .is_err()
        );
        changed = original;
        changed.snapshots.front_mut().unwrap().selector.block_id = [8; 32];
        assert!(
            ChainComponents::recompute(
                &changed,
                binding,
                SnapshotTip::Materialized(changed.tip),
                limits()
            )
            .is_err()
        );
    }

    #[test]
    fn rebuilds_native_chain_components_without_storage_fingerprint() {
        let state = state();
        let c = ChainComponents::recompute(
            &state,
            binding(&state),
            SnapshotTip::Materialized(state.tip),
            limits(),
        )
        .unwrap();
        let committed = c.assemble(external()).unwrap();
        assert_ne!(committed, state.fingerprint());
        let mut different = binding(&state);
        different.rules_commitment[0] ^= 1;
        assert_ne!(
            ChainComponents::recompute(
                &state,
                different,
                SnapshotTip::Materialized(state.tip),
                limits()
            )
            .unwrap()
            .assemble(external())
            .unwrap(),
            committed
        );
        let mut reordered = external();
        reordered.swap(1, 2);
        assert!(
            ChainComponents::recompute(
                &state,
                binding(&state),
                SnapshotTip::Materialized(state.tip),
                limits()
            )
            .unwrap()
            .assemble(reordered)
            .is_err()
        );
    }

    #[test]
    fn malformed_tree_frontier_or_membership_and_nullifiers_are_rejected() {
        let original = state();
        let mut changed = original.clone();
        changed.tree.count = 1;
        assert!(
            ChainComponents::recompute(
                &changed,
                binding(&original),
                SnapshotTip::Materialized(original.tip),
                limits()
            )
            .is_err()
        );
        changed = original.clone();
        changed.commitments.insert([0; 48]);
        assert!(
            ChainComponents::recompute(
                &changed,
                binding(&original),
                SnapshotTip::Materialized(original.tip),
                limits()
            )
            .is_err()
        );
        changed = original.clone();
        changed.spent.insert([0xff; 48]);
        assert!(
            ChainComponents::recompute(
                &changed,
                binding(&original),
                SnapshotTip::Materialized(original.tip),
                limits()
            )
            .is_err()
        );
        changed = original.clone();
        changed.timestamps.clear();
        assert!(
            ChainComponents::recompute(
                &changed,
                binding(&original),
                SnapshotTip::Materialized(original.tip),
                limits()
            )
            .is_err()
        );
        changed = original.clone();
        changed.snapshots.back_mut().unwrap().commitment_root = [1; 48];
        assert!(
            ChainComponents::recompute(
                &changed,
                binding(&original),
                SnapshotTip::Materialized(original.tip),
                limits()
            )
            .is_err()
        );
    }

    #[test]
    fn byte_and_set_limits_reject_before_unbounded_encoding() {
        let state = state();
        let mut bounded = limits();
        bounded.max_component_bytes = 1;
        assert!(
            ChainComponents::recompute(
                &state,
                binding(&state),
                SnapshotTip::Materialized(state.tip),
                bounded
            )
            .is_err()
        );
        let mut changed = state.clone();
        changed.spent.insert([0; 48]);
        bounded = limits();
        bounded.max_nullifiers = 0;
        assert!(
            ChainComponents::recompute(
                &changed,
                binding(&state),
                SnapshotTip::Materialized(state.tip),
                bounded
            )
            .is_err()
        );
    }
}
