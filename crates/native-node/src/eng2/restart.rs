//! Authenticated local committed-state recovery, separate from native audits.
//! Permanent rows append only accepted deltas; no historical proof is replayed.

use super::{
    genesis::Genesis,
    snapshot::SnapshotState,
    state_components::{Binding, Limits},
};
use crate::{
    eng2_economics::EconomicState,
    eng2_fund::FundLedger,
    eng2_governance::GovernanceState,
    identity::NativeIdentity,
    state::{CanonicalSnapshot, CommitmentTree, State},
    wire::{DigestBytes, Hash},
};
use native::codec::{decode_digest, encode_digest};
use redb::{ReadableTable, TableDefinition};
use siworld_core::pow::Work;
use std::collections::{BTreeSet, VecDeque};

pub(super) const CACHE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("eng2-local-committed-state-v1");
pub(super) const LEAVES: TableDefinition<u64, &[u8]> =
    TableDefinition::new("eng2-local-committed-leaves-v1");
pub(super) const SPENDS: TableDefinition<u64, &[u8]> =
    TableDefinition::new("eng2-local-committed-spends-v1");
pub(super) struct Context {
    pub identity: NativeIdentity,
    pub leaves: Hash,
    pub spends: Hash,
}
impl Context {
    pub fn write(
        &self,
        transaction: &redb::WriteTransaction,
        genesis: &Genesis,
        bytes: &[u8],
        leaves: Hash,
        spends: Hash,
    ) -> Result<(), String> {
        let seal = self
            .identity
            .seal_local_storage(digest(genesis, bytes, leaves, spends))
            .map_err(|_| "local committed-state seal failed")?;
        let mut table = transaction
            .open_table(CACHE)
            .map_err(|_| "local committed-state table unavailable")?;
        for (key, value) in [
            ("state", bytes),
            ("leaves", leaves.as_slice()),
            ("spends", spends.as_slice()),
            ("seal", seal.as_slice()),
        ] {
            table
                .insert(key, value)
                .map_err(|_| "local committed-state write failed")?;
        }
        Ok(())
    }
}
pub(super) fn row_hash(previous: Hash, index: u64, bytes: &DigestBytes) -> Hash {
    let mut hash = blake3::Hasher::new_derive_key("siworld eng2 local accepted row chain v1");
    hash.update(&previous);
    hash.update(&index.to_le_bytes());
    hash.update(bytes);
    *hash.finalize().as_bytes()
}
fn blob(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    output.extend_from_slice(bytes);
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn encode_chain(
    height: u64,
    tip: Hash,
    work: Work,
    timestamps: &VecDeque<u64>,
    tree: &CommitmentTree,
    leaves: usize,
    spends: usize,
    snapshots: &VecDeque<CanonicalSnapshot>,
    assets: &crate::issuance::AssetRegistry,
) -> Result<Vec<u8>, String> {
    if tree.count != leaves as u64 {
        return Err("restart tree count differs".into());
    }
    let mut bytes = b"SW2LC001".to_vec();
    bytes.extend_from_slice(&height.to_le_bytes());
    bytes.extend_from_slice(&tip);
    bytes.extend_from_slice(&work.to_big_endian());
    bytes.extend_from_slice(&(timestamps.len() as u64).to_le_bytes());
    for value in timestamps {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(&(leaves as u64).to_le_bytes());
    bytes.extend_from_slice(&(spends as u64).to_le_bytes());
    bytes.extend_from_slice(&encode_digest(&tree.root()));
    let frontier = tree.cache_frontier();
    bytes.extend_from_slice(&(frontier.len() as u64).to_le_bytes());
    for node in frontier {
        bytes.extend_from_slice(&node);
    }
    bytes.extend_from_slice(&(snapshots.len() as u64).to_le_bytes());
    for snapshot in snapshots {
        bytes.extend_from_slice(&snapshot.selector.height.to_le_bytes());
        bytes.extend_from_slice(&snapshot.selector.block_id);
        bytes.extend_from_slice(&snapshot.commitment_root);
        bytes.extend_from_slice(&snapshot.recent_root);
    }
    let mut registry = Vec::new();
    assets.visit_encoding(&mut |part| registry.extend_from_slice(part));
    blob(&mut bytes, &registry);
    Ok(bytes)
}
pub(super) fn current_chain(state: &State) -> Result<Vec<u8>, String> {
    encode_chain(
        state.height,
        state.tip,
        state.cumulative_work,
        &state.timestamps,
        &state.tree,
        state.leaves.len(),
        state.spent.len(),
        &state.snapshots,
        &state.assets,
    )
}
pub(super) fn image(
    chain: &[u8],
    economics: &EconomicState,
    fund: &FundLedger,
    governance: &GovernanceState,
    root: Hash,
    limits: Limits,
) -> Result<Vec<u8>, String> {
    let [pool, counters, locked] = economics.component_bytes()?;
    let fund = fund.canonical_component_bytes()?;
    let governance = governance.canonical_component_bytes()?;
    let mut bytes = b"SW2LR001".to_vec();
    bytes.extend_from_slice(&root);
    for part in [
        chain,
        pool.as_slice(),
        counters.as_slice(),
        locked.as_slice(),
        fund.as_slice(),
        governance.as_slice(),
    ] {
        if part.len() > limits.max_component_bytes {
            return Err("local restart component exceeds bound".into());
        }
        blob(&mut bytes, part);
    }
    Ok(bytes)
}
pub(super) fn digest(genesis: &Genesis, bytes: &[u8], leaves: Hash, spends: Hash) -> Hash {
    let mut hash =
        blake3::Hasher::new_derive_key("siworld eng2 atomically accepted restart state v1");
    hash.update(&genesis.id());
    hash.update(&genesis.rules_commitment());
    hash.update(&(bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
    hash.update(&leaves);
    hash.update(&spends);
    *hash.finalize().as_bytes()
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let (a, b) = self
            .0
            .split_at_checked(n)
            .ok_or("truncated local restart state")?;
        self.0 = b;
        Ok(a)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        Ok(self.take(N)?.try_into().expect("checked restart field"))
    }
    fn number(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn count(&mut self, max: usize) -> Result<usize, String> {
        let n = usize::try_from(self.number()?).map_err(|_| "restart count overflow")?;
        if n > max {
            return Err("restart count exceeds bound".into());
        }
        Ok(n)
    }
    fn blob(&mut self, max: usize) -> Result<&'a [u8], String> {
        let n = self.count(max)?;
        self.take(n)
    }
}
pub(super) fn restore(
    genesis: &Genesis,
    bytes: &[u8],
    leaves: Vec<native::multi_asset::Digest>,
    spent: BTreeSet<DigestBytes>,
    limits: Limits,
    parent: Hash,
) -> Result<(SnapshotState, Hash), String> {
    let mut r = Reader(bytes);
    if r.take(8)? != b"SW2LR001" {
        return Err("invalid local restart encoding".into());
    }
    let root = r.array()?;
    let chain_bytes = r.blob(limits.max_component_bytes)?;
    let economic = [
        r.blob(limits.max_component_bytes)?,
        r.blob(limits.max_component_bytes)?,
        r.blob(limits.max_component_bytes)?,
    ];
    let fund_bytes = r.blob(limits.max_component_bytes)?;
    let governance_bytes = r.blob(limits.max_component_bytes)?;
    if !r.0.is_empty() {
        return Err("trailing local restart state".into());
    }
    let mut r = Reader(chain_bytes);
    if r.take(8)? != b"SW2LC001" {
        return Err("invalid local chain restart encoding".into());
    }
    let height = r.number()?;
    let tip = r.array()?;
    let work = Work::from_big_endian(&r.array::<64>()?);
    let n = r.count(siworld_core::params::MEDIAN_TIME_PAST_WINDOW)?;
    let timestamps = (0..n)
        .map(|_| r.number())
        .collect::<Result<VecDeque<_>, _>>()?;
    if r.count(limits.max_leaves)? != leaves.len() || r.count(limits.max_nullifiers)? != spent.len()
    {
        return Err("local restart permanent counts differ".into());
    }
    let tree_root = r.array()?;
    let n = r.count(native::multi_asset::TREE_DEPTH)?;
    let frontier = (0..n).map(|_| r.array()).collect::<Result<Vec<_>, _>>()?;
    let tree = CommitmentTree::from_local_cache(leaves.len() as u64, &frontier, tree_root)?;
    let n = r.count(crate::state::SNAPSHOT_WINDOW)?;
    let mut snapshots = VecDeque::new();
    for _ in 0..n {
        snapshots.push_back(CanonicalSnapshot {
            selector: crate::wire::Snapshot {
                height: r.number()?,
                block_id: r.array()?,
            },
            commitment_root: r.array()?,
            recent_root: r.array()?,
        });
    }
    let assets = crate::issuance::AssetRegistry::decode_canonical_state(
        r.blob(limits.max_component_bytes)?,
        height,
    )?;
    if !r.0.is_empty() {
        return Err("trailing local chain restart state".into());
    }
    let mut chain = State::new(genesis.config().clone())?;
    chain.height = height;
    chain.tip = tip;
    chain.cumulative_work = work;
    chain.timestamps = timestamps;
    chain.tree = tree;
    chain.commitments = leaves.iter().map(encode_digest).collect();
    chain.leaves = leaves;
    chain.spent = spent;
    chain.snapshots = snapshots;
    chain.assets = assets;
    if chain.commitments.len() != chain.leaves.len() {
        return Err("duplicate local restart leaf".into());
    }
    let state = SnapshotState {
        fee_mode: genesis.fee_mode(),
        nullifiers: super::nullifiers::NullifierSet::rebuild(&chain.spent)?,
        chain,
        economics: EconomicState::from_components(genesis.config().network, height, economic)?,
        fund: FundLedger::decode_component(
            fund_bytes,
            genesis.config().network,
            genesis
                .config()
                .fund_allocation
                .as_ref()
                .ok_or("restart fund allocation missing")?,
        )?,
        governance: GovernanceState::decode_component(governance_bytes, genesis.config().network)?,
    };
    state.check_context()?;
    if state.execution_commitment(
        Binding {
            genesis: genesis.id(),
            rules_commitment: genesis.rules_commitment(),
            parent,
        },
        limits,
    )? != root
    {
        return Err("local restart state differs from sealed execution root".into());
    }
    Ok((state, root))
}
pub(super) fn read_rows(
    table: &impl ReadableTable<u64, &'static [u8]>,
    maximum: usize,
) -> Result<(Vec<DigestBytes>, Hash), String> {
    if table
        .len()
        .map_err(|_| "local restart row count unavailable")?
        > maximum as u64
    {
        return Err("local restart permanent rows exceed bound".into());
    }
    let mut values = Vec::new();
    let mut hash = [0; 32];
    for row in table.iter().map_err(|_| "local restart rows unavailable")? {
        let (index, value) = row.map_err(|_| "local restart row unavailable")?;
        if index.value() != values.len() as u64 {
            return Err("local restart rows are not contiguous".into());
        }
        let bytes: DigestBytes = value
            .value()
            .try_into()
            .map_err(|_| "invalid local restart row width")?;
        let _ = decode_digest(&bytes).map_err(|_| "noncanonical local restart row")?;
        hash = row_hash(hash, index.value(), &bytes);
        values.push(bytes);
    }
    Ok((values, hash))
}
