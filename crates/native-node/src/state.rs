//! Deterministic native engineering-chain transition shared by production and replay.
//! No peer-supplied verifier key, private fee opening, or local clock enters this transition.
use crate::proofs::NativeVerifier;
use crate::wire::{Block, DigestBytes, GROUP, Hash, MAX_SLOTS, MIN_SLOTS, Snapshot};
use native::codec::{ProofContext, PublicTransaction, decode_digest, encode_digest};
use native::confidential_fees::{FeeOpening, SettlementSlot};
use native::multi_asset::{Digest, F, Hasher, RecentRoots, TREE_DEPTH};
use native::settlement::{RewardAllocation as PlanAllocation, RewardMode as PlanMode, RewardPlan};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use siworld_core::pow::{self, Work};
pub use siworld_core::v1_economics::RewardMode;
use siworld_core::v1_economics::{
    self as economics, EconomicsLedger, EconomicsParams, FundAccount, FundAllocation,
    MAX_FUND_WALLETS, RewardAllocation,
};
use std::collections::{BTreeSet, VecDeque};

pub const SNAPSHOT_WINDOW: usize = 4096;
pub const MAX_REORG_DEPTH: u64 = 24;

pub const TARGET_INTERVAL: u64 = 300;
pub const MAX_POW_ITERATIONS: u64 = 1_000_000;
const FUND_CONFIG_OFFSET: usize = 146;
const FUND_WALLET_BYTES: usize = 2 + crate::fund_spend::VERIFYING_KEY_BYTES;
const ISSUANCE_CONFIG_OFFSET: usize = FUND_CONFIG_OFFSET + 2 + MAX_FUND_WALLETS * FUND_WALLET_BYTES;
const CONFIG_REVISION_OFFSET: usize = ISSUANCE_CONFIG_OFFSET + 52;
const CONFIG_REVISION: u32 = 5;
pub const CONFIG_RULE_BYTES: usize = CONFIG_REVISION_OFFSET + 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub network: Hash,
    /// Fixture selector only; an ASERT service uses its immutable target.
    pub work_bits: u8,
    pub genesis_timestamp: u64,
    pub genesis_target: Hash,
    pub target_interval: u64,
    pub pow_iterations: u64,
    pub fixture: bool,
    pub economics: EconomicsParams,
    pub fund_allocation: Option<FundAllocation>,
    /// Immutable public ML-DSA-65 keys, ordered with the genesis allocation.
    pub fund_verifying_keys: Vec<[u8; crate::fund_spend::VERIFYING_KEY_BYTES]>,
    /// Explicit isolated-network issuance policy and dedicated fee owner.
    pub issuance: Option<crate::issuance::IssuanceConfig>,
}
impl Config {
    /// Deterministic cheap development fixture, never service qualification.
    pub fn development(network: Hash, work_bits: u8) -> Result<Self, String> {
        if network == [0; 32] || work_bits > 24 {
            return Err("invalid engineering network configuration".into());
        }
        let target = (Work::from_big_endian(&[0xff; 32]) >> usize::from(work_bits)).to_big_endian();
        Ok(Self {
            network,
            work_bits,
            genesis_timestamp: 1,
            genesis_target: target[32..].try_into().expect("256-bit target"),
            target_interval: TARGET_INTERVAL,
            pow_iterations: 0,
            fixture: true,
            economics: EconomicsParams::production(),
            fund_allocation: Some(
                FundAllocation::new_bps(vec![5000, 5000], 1)
                    .expect("synthetic fixture basis points"),
            ),
            fund_verifying_keys: synthetic_fund_keys(),
            issuance: None,
        })
    }
    /// Explicit disposable ASERT engineering network, not a public genesis.
    pub fn asert_development(
        network: Hash,
        genesis_timestamp: u64,
        genesis_target: Hash,
        pow_iterations: u64,
    ) -> Result<Self, String> {
        if network == [0; 32]
            || genesis_timestamp == 0
            || genesis_target == [0; 32]
            || !(1..=MAX_POW_ITERATIONS).contains(&pow_iterations)
        {
            return Err("invalid ASERT engineering network configuration".into());
        }
        Ok(Self {
            network,
            work_bits: 0,
            genesis_timestamp,
            genesis_target,
            target_interval: TARGET_INTERVAL,
            pow_iterations,
            fixture: false,
            economics: EconomicsParams::production(),
            fund_allocation: None,
            fund_verifying_keys: Vec::new(),
            issuance: None,
        })
    }
    /// Compressed timings are confined to explicit disposable fixture networks.
    pub fn with_economics(mut self, params: EconomicsParams) -> Result<Self, String> {
        params.validate().map_err(|e| e.to_string())?;
        if !self.fixture && params != EconomicsParams::production() {
            return Err("compressed economic timings require an engineering fixture".into());
        }
        self.economics = params;
        self.validate()?;
        Ok(self)
    }
    /// A complete immutable public genesis registry is required before production.
    pub fn with_fund_wallets(
        mut self,
        allocation: FundAllocation,
        verifying_keys: Vec<[u8; crate::fund_spend::VERIFYING_KEY_BYTES]>,
    ) -> Result<Self, String> {
        self.fund_allocation = Some(allocation);
        self.fund_verifying_keys = verifying_keys;
        self.validate()?;
        Ok(self)
    }
    /// Publicly reproducible keys for a disposable engineering genesis only.
    /// These keys have no custody security and must never fund a live network.
    pub fn with_test_fund_registry(self) -> Result<Self, String> {
        let mut shares = vec![400; 24];
        shares[23] = 800;
        let keys = (0u32..24)
            .map(|index| {
                let seed = blake3::derive_key(
                    "siworld disposable twenty-four-wallet fund fixture v1",
                    &index.to_le_bytes(),
                );
                *libcrux_ml_dsa::ml_dsa_65::generate_key_pair(seed)
                    .verification_key
                    .as_ref()
            })
            .collect();
        self.with_fund_wallets(
            FundAllocation::new_bps(shares, 23).map_err(|e| e.to_string())?,
            keys,
        )
    }
    pub fn validate(&self) -> Result<(), String> {
        self.economics.validate().map_err(|e| e.to_string())?;
        if let Some(policy) = &self.issuance {
            policy.validate()?;
        }
        match &self.fund_allocation {
            None if !self.fund_verifying_keys.is_empty() => {
                return Err("fund keys require an immutable genesis allocation".into());
            }
            Some(allocation)
                if allocation.basis_points().len() != self.fund_verifying_keys.len()
                    || self.fund_verifying_keys.len() > MAX_FUND_WALLETS
                    || self
                        .fund_verifying_keys
                        .iter()
                        .any(|key| key.iter().all(|byte| *byte == 0))
                    || self
                        .fund_verifying_keys
                        .iter()
                        .enumerate()
                        .any(|(index, key)| self.fund_verifying_keys[..index].contains(key)) =>
            {
                return Err("invalid immutable fund wallet key registry".into());
            }
            _ => {}
        }
        if !self.fixture && self.economics != EconomicsParams::production() {
            return Err("compressed economic timings require an engineering fixture".into());
        }
        let mut expected = if self.fixture {
            Self::development(self.network, self.work_bits)?
        } else {
            Self::asert_development(
                self.network,
                self.genesis_timestamp,
                self.genesis_target,
                self.pow_iterations,
            )?
        };
        expected.economics = self.economics.clone();
        expected.fund_allocation = self.fund_allocation.clone();
        expected.fund_verifying_keys = self.fund_verifying_keys.clone();
        expected.issuance = self.issuance.clone();
        if &expected != self {
            return Err("noncanonical engineering network rules".into());
        }
        Ok(())
    }
    /// Fixed-width canonical engineering rules, also used by local and DB metadata.
    pub fn encode_rules(&self) -> [u8; CONFIG_RULE_BYTES] {
        let mut bytes = [0; CONFIG_RULE_BYTES];
        bytes[..32].copy_from_slice(&self.network);
        bytes[32] = self.work_bits;
        bytes[33] = u8::from(self.fixture);
        bytes[34..42].copy_from_slice(&self.genesis_timestamp.to_le_bytes());
        bytes[42..74].copy_from_slice(&self.genesis_target);
        bytes[74..82].copy_from_slice(&self.target_interval.to_le_bytes());
        bytes[82..90].copy_from_slice(&self.pow_iterations.to_le_bytes());
        bytes[90..146].copy_from_slice(&self.economics.canonical_bytes());
        if let Some(allocation) = &self.fund_allocation {
            bytes[FUND_CONFIG_OFFSET] = allocation.basis_points().len() as u8;
            bytes[FUND_CONFIG_OFFSET + 1] = allocation.team_index() as u8;
            for (index, (share, key)) in allocation
                .basis_points()
                .iter()
                .zip(&self.fund_verifying_keys)
                .enumerate()
            {
                let offset = FUND_CONFIG_OFFSET + 2 + index * FUND_WALLET_BYTES;
                bytes[offset..offset + 2].copy_from_slice(&share.to_le_bytes());
                bytes[offset + 2..offset + FUND_WALLET_BYTES].copy_from_slice(key);
            }
        }
        if let Some(policy) = &self.issuance {
            let offset = ISSUANCE_CONFIG_OFFSET;
            bytes[offset] = 1;
            bytes[offset + 1..offset + 49].copy_from_slice(&policy.fee_owner);
            bytes[offset + 49..offset + 51]
                .copy_from_slice(&policy.max_metadata_bytes.to_le_bytes());
            bytes[offset + 51] = policy.max_per_block;
        }
        bytes[CONFIG_REVISION_OFFSET..CONFIG_REVISION_OFFSET + 4]
            .copy_from_slice(&CONFIG_REVISION.to_le_bytes());
        bytes[CONFIG_REVISION_OFFSET + 4..]
            .copy_from_slice(&u32::from(economics::ECONOMICS_RULE_VERSION).to_le_bytes());
        bytes
    }
    pub fn decode_rules(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != CONFIG_RULE_BYTES
            || bytes[33] > 1
            || bytes[CONFIG_REVISION_OFFSET..CONFIG_REVISION_OFFSET + 4]
                != CONFIG_REVISION.to_le_bytes()
            || bytes[CONFIG_REVISION_OFFSET + 4..]
                != u32::from(economics::ECONOMICS_RULE_VERSION).to_le_bytes()
        {
            return Err("invalid engineering rule encoding".into());
        }
        let count = usize::from(bytes[FUND_CONFIG_OFFSET]);
        let team = usize::from(bytes[FUND_CONFIG_OFFSET + 1]);
        let policy_offset = ISSUANCE_CONFIG_OFFSET;
        if count > MAX_FUND_WALLETS
            || (count == 0 && team != 0)
            || bytes[FUND_CONFIG_OFFSET + 2 + count * FUND_WALLET_BYTES..policy_offset]
                .iter()
                .any(|value| *value != 0)
            || bytes[policy_offset] > 1
            || (bytes[policy_offset] == 0
                && bytes[policy_offset + 1..CONFIG_REVISION_OFFSET]
                    .iter()
                    .any(|value| *value != 0))
        {
            return Err("noncanonical fund registry or issuance configuration".into());
        }
        let mut basis_points = Vec::with_capacity(count);
        let mut fund_verifying_keys = Vec::with_capacity(count);
        for index in 0..count {
            let offset = FUND_CONFIG_OFFSET + 2 + index * FUND_WALLET_BYTES;
            basis_points.push(u16::from_le_bytes(
                bytes[offset..offset + 2].try_into().expect("fixed share"),
            ));
            fund_verifying_keys.push(
                bytes[offset + 2..offset + FUND_WALLET_BYTES]
                    .try_into()
                    .expect("fixed fund key"),
            );
        }
        let config = Self {
            network: bytes[..32].try_into().expect("fixed network width"),
            work_bits: bytes[32],
            fixture: bytes[33] == 1,
            genesis_timestamp: u64::from_le_bytes(
                bytes[34..42].try_into().expect("fixed timestamp"),
            ),
            genesis_target: bytes[42..74].try_into().expect("fixed target"),
            target_interval: u64::from_le_bytes(bytes[74..82].try_into().expect("fixed interval")),
            pow_iterations: u64::from_le_bytes(bytes[82..90].try_into().expect("fixed iterations")),
            fund_allocation: if count == 0 {
                None
            } else {
                Some(FundAllocation::new_bps(basis_points, team).map_err(|e| e.to_string())?)
            },
            fund_verifying_keys,
            issuance: if bytes[policy_offset] == 0 {
                None
            } else {
                Some(crate::issuance::IssuanceConfig {
                    fee_owner: bytes[policy_offset + 1..policy_offset + 49]
                        .try_into()
                        .expect("fixed issuance fee owner"),
                    max_metadata_bytes: u16::from_le_bytes(
                        bytes[policy_offset + 49..policy_offset + 51]
                            .try_into()
                            .expect("fixed issuance metadata limit"),
                    ),
                    max_per_block: bytes[policy_offset + 51],
                })
            },
            economics: EconomicsParams {
                maturity: u64::from_le_bytes(bytes[90..98].try_into().expect("fixed maturity")),
                holder_unlock_offsets: core::array::from_fn(|i| {
                    u64::from_le_bytes(
                        bytes[98 + i * 8..106 + i * 8]
                            .try_into()
                            .expect("fixed tranche offset"),
                    )
                }),
                blocks_per_day: u64::from_le_bytes(
                    bytes[130..138].try_into().expect("fixed protocol day"),
                ),
                fund_vesting_days: u64::from_le_bytes(
                    bytes[138..146].try_into().expect("fixed vesting duration"),
                ),
            },
        };
        config.validate()?;
        Ok(config)
    }
    pub fn genesis_id(&self) -> Hash {
        self.genesis_id_for_profile(&crate::proofs::protocol_profile_fingerprint())
    }
    pub(crate) fn genesis_id_for_profile(&self, profile: &Hash) -> Hash {
        let mut h = blake3::Hasher::new_derive_key("siworld native engineering genesis v2");
        h.update(&self.encode_rules());
        h.update(b"asert:14400;mtp:11;sequential-blake3");
        h.update(native::codec::SUITE_ID);
        h.update(profile);
        *h.finalize().as_bytes()
    }
}

/// Deterministic public keys for disposable fixtures; never production allocations.
fn synthetic_fund_keys() -> Vec<[u8; crate::fund_spend::VERIFYING_KEY_BYTES]> {
    static KEYS: std::sync::OnceLock<Vec<[u8; crate::fund_spend::VERIFYING_KEY_BYTES]>> =
        std::sync::OnceLock::new();
    KEYS.get_or_init(|| {
        [83, 84]
            .into_iter()
            .map(|seed| {
                *libcrux_ml_dsa::ml_dsa_65::generate_key_pair([seed; 32])
                    .verification_key
                    .as_ref()
            })
            .collect()
    })
    .clone()
}

pub trait BlockVerifier {
    /// Proof validity only; State independently checks the signed declaration,
    /// destination-bound fee output, uniqueness and commitment insertion.
    fn issuance(&self, _record: &crate::issuance::IssuanceRecord) -> Result<(), String> {
        Err("issuance proof verification is unavailable".into())
    }
    fn transaction(
        &self,
        public: &PublicTransaction,
        context: &ProofContext,
        fee: &Digest,
        root: &Digest,
        proof: &[u8],
    ) -> Result<(), String>;
    #[allow(clippy::too_many_arguments)]
    fn settlement(
        &self,
        fees: &[Digest],
        plan: &RewardPlan,
        network: Hash,
        list_hash: Hash,
        rewards: &[Digest],
        proof: &[u8],
    ) -> Result<(), String>;
}
impl BlockVerifier for NativeVerifier {
    fn issuance(&self, record: &crate::issuance::IssuanceRecord) -> Result<(), String> {
        self.verify_issuance(record)
    }
    fn transaction(
        &self,
        public: &PublicTransaction,
        context: &ProofContext,
        fee: &Digest,
        root: &Digest,
        proof: &[u8],
    ) -> Result<(), String> {
        self.verify_transaction(public, context, fee, root, proof)
    }
    fn settlement(
        &self,
        fees: &[Digest],
        plan: &RewardPlan,
        network: Hash,
        list_hash: Hash,
        rewards: &[Digest],
        proof: &[u8],
    ) -> Result<(), String> {
        self.verify_settlement(fees, plan, network, list_hash, rewards, proof)
    }
}

#[derive(Clone, Debug)]
pub struct CommitmentTree {
    pub count: u64,
    frontier: Vec<Digest>,
    zeros: Vec<Digest>,
    root: Digest,
}
impl Default for CommitmentTree {
    fn default() -> Self {
        Self::new()
    }
}
impl CommitmentTree {
    pub fn new() -> Self {
        let h = Hasher::new();
        let mut zeros = vec![[F::ZERO; 12]];
        for i in 0..TREE_DEPTH {
            zeros.push(h.compress(&zeros[i], &zeros[i]));
        }
        Self {
            count: 0,
            frontier: vec![[F::ZERO; 12]; TREE_DEPTH],
            root: zeros[TREE_DEPTH],
            zeros,
        }
    }
    pub fn root(&self) -> Digest {
        self.root
    }
    pub fn append(&mut self, leaf: Digest) -> Result<(), String> {
        if self.count >= (1u64 << TREE_DEPTH) {
            return Err("commitment tree capacity".into());
        }
        let h = Hasher::new();
        let mut node = leaf;
        let mut index = self.count;
        for level in 0..TREE_DEPTH {
            if index & 1 == 0 {
                self.frontier[level] = node;
                node = h.compress(&node, &self.zeros[level]);
            } else {
                node = h.compress(&self.frontier[level], &node);
            }
            index >>= 1;
        }
        self.count += 1;
        self.root = node;
        Ok(())
    }
    /// Local wallet witness construction; all public commitments must be supplied.
    pub fn path(&self, leaves: &[Digest], index: usize) -> Result<Vec<(Digest, bool)>, String> {
        if leaves.len() as u64 != self.count || index >= leaves.len() {
            return Err("invalid commitment path request".into());
        }
        let h = Hasher::new();
        let mut nodes = leaves.to_vec();
        let mut position = index;
        let mut path = Vec::with_capacity(TREE_DEPTH);
        for level in 0..TREE_DEPTH {
            let sibling = nodes
                .get(position ^ 1)
                .copied()
                .unwrap_or(self.zeros[level]);
            path.push((sibling, position & 1 == 1));
            nodes = nodes
                .chunks(2)
                .map(|pair| h.compress(&pair[0], pair.get(1).unwrap_or(&self.zeros[level])))
                .collect();
            position >>= 1;
        }
        Ok(path)
    }
}

#[derive(Clone, Debug)]
pub struct CanonicalSnapshot {
    pub selector: Snapshot,
    pub commitment_root: DigestBytes,
    pub recent_root: DigestBytes,
}
#[derive(Clone, Debug)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub tip: Hash,
    pub timestamps: VecDeque<u64>,
    pub cumulative_work: Work,
    pub tree: CommitmentTree,
    pub spent: BTreeSet<DigestBytes>,
    pub commitments: BTreeSet<DigestBytes>,
    pub leaves: Vec<Digest>,
    pub snapshots: VecDeque<CanonicalSnapshot>,
    pub economics: EconomicsLedger,
    pub assets: crate::issuance::AssetRegistry,
}
impl State {
    pub fn new(config: Config) -> Result<Self, String> {
        config.validate()?;
        let genesis_timestamp = config.genesis_timestamp;
        let mut economics =
            EconomicsLedger::new(config.economics.clone()).map_err(|e| e.to_string())?;
        if let Some(allocation) = &config.fund_allocation {
            economics = economics
                .with_fund_allocation(allocation.clone())
                .map_err(|e| e.to_string())?;
        }
        let tree = CommitmentTree::new();
        let root = tree.root();
        let h = Hasher::new();
        let mut roots = RecentRoots::new();
        roots.insert(&h, 0, &root, base_fee(0));
        let selector = Snapshot {
            height: 0,
            block_id: config.genesis_id(),
        };
        let recent_root = encode_digest(&roots.tree(&h).root());
        Ok(Self {
            config,
            height: 0,
            tip: selector.block_id,
            timestamps: VecDeque::from([genesis_timestamp]),
            cumulative_work: Work::zero(),
            tree,
            spent: BTreeSet::new(),
            commitments: BTreeSet::new(),
            leaves: Vec::new(),
            snapshots: VecDeque::from([CanonicalSnapshot {
                selector,
                commitment_root: encode_digest(&root),
                recent_root,
            }]),
            economics,
            assets: crate::issuance::AssetRegistry::default(),
        })
    }
    /// Compute the only reward allocation permitted by the accepted parent state.
    pub fn reward_allocation(&self, mode: RewardMode) -> Result<RewardAllocation, String> {
        let height = self
            .height
            .checked_add(1)
            .ok_or("reward height exhausted")?;
        let mut trial = self.economics.clone();
        trial.advance(height, mode).map_err(|e| e.to_string())
    }
    pub fn reward_plan(&self, mode: RewardMode) -> Result<RewardPlan, String> {
        Ok(plan_from_allocation(&self.reward_allocation(mode)?))
    }
    pub fn timestamp(&self) -> u64 {
        *self.timestamps.back().expect("genesis timestamp retained")
    }
    pub fn median_time_past(&self) -> u64 {
        let timestamps: Vec<_> = self.timestamps.iter().copied().collect();
        pow::median_time_past(&timestamps).expect("genesis timestamp retained")
    }
    pub fn next_target(&self) -> Hash {
        pow::asert_target(
            &self.config.genesis_target,
            self.config.genesis_timestamp,
            self.config.target_interval,
            self.height,
            self.timestamp(),
        )
    }
    pub fn tip_snapshot(&self) -> &CanonicalSnapshot {
        self.snapshots.back().expect("genesis snapshot retained")
    }
    pub fn snapshot(&self, selector: Snapshot) -> Result<&CanonicalSnapshot, String> {
        if selector.height > self.height || self.height - selector.height >= SNAPSHOT_WINDOW as u64
        {
            return Err("expired or future canonical snapshot".into());
        }
        self.snapshots
            .iter()
            .find(|s| s.selector == selector)
            .ok_or_else(|| "unknown or removed canonical snapshot".into())
    }
    pub fn recent_roots(&self) -> Result<RecentRoots, String> {
        let h = Hasher::new();
        let mut roots = RecentRoots::new();
        for s in &self.snapshots {
            roots.insert(
                &h,
                s.selector.height,
                &decode_digest(&s.commitment_root).map_err(|_| "invalid stored root")?,
                base_fee(s.selector.height),
            );
        }
        Ok(roots)
    }
    /// All structural, snapshot, spend, output and independent proof checks finish
    /// before any accepted-state field changes. Durable callers commit the block
    /// and resulting fingerprint together before exposing this state.
    pub fn apply(&mut self, block: &Block, verifier: &impl BlockVerifier) -> Result<(), String> {
        block.validate_shape()?;
        if block.network != self.config.network {
            return Err("block network mismatch".into());
        }
        if self.height.checked_add(1) != Some(block.height) {
            return Err("nonconsecutive block height".into());
        }
        if block.parent != self.tip {
            return Err("block parent mismatch".into());
        }
        if block.timestamp <= self.median_time_past() {
            return Err("block timestamp does not exceed median time past".into());
        }
        if block.target != self.next_target() {
            return Err("block target does not match ASERT".into());
        }
        let seed = block.pow_seed()?;
        let work = pow::pow_hash(&seed, block.nonce, self.config.pow_iterations);
        if !pow::meets_target(&work, &block.target) {
            return Err("insufficient engineering proof of work".into());
        }
        let cumulative_work = self
            .cumulative_work
            .checked_add(pow::block_work(&block.target))
            .ok_or("cumulative engineering work overflow")?;
        let id = block.id()?;
        let mut spends = BTreeSet::new();
        let mut outputs = BTreeSet::new();
        let mut leaves = Vec::new();
        let mut fees = Vec::with_capacity(MAX_SLOTS);
        let mut trial_tree = self.tree.clone();
        for tx in &block.transactions {
            let snapshot = self.snapshot(tx.record.snapshot)?;
            let root =
                decode_digest(&snapshot.recent_root).map_err(|_| "invalid stored snapshot root")?;
            let public = PublicTransaction::decode(&tx.record.body)
                .map_err(|_| "noncanonical transaction public values")?;
            let fee =
                decode_digest(&tx.record.fee_commit).map_err(|_| "noncanonical fee commitment")?;
            for nf in public.nf {
                let nf = encode_digest(&nf);
                if self.spent.contains(&nf) || !spends.insert(nf) {
                    return Err("nullifier already used".into());
                }
            }
            for cm in public.cm {
                let bytes = encode_digest(&cm);
                if self.commitments.contains(&bytes) || !outputs.insert(bytes) {
                    return Err("output commitment already used".into());
                }
                trial_tree.append(cm)?;
                leaves.push(cm);
            }
            let context = ProofContext::for_snapshot(
                self.config.network,
                tx.record.snapshot.height,
                tx.record.snapshot.block_id,
            );
            verifier.transaction(&public, &context, &fee, &root, &tx.proof)?;
            fees.push(fee);
        }
        let mut trial_assets = self.assets.clone();
        if let Some(policy) = &self.config.issuance {
            if block.issuances.len() > usize::from(policy.max_per_block) {
                return Err("issuance count exceeds configured block limit".into());
            }
        } else if !block.issuances.is_empty() {
            return Err("issuance destination and policy are not configured".into());
        }
        // An exact declaration-bound fund note may be paid in this block or
        // already exist in canonical history. Registry consumption is one-use;
        // spending that fund note later does not undo the historical payment.
        let transaction_outputs = outputs.clone();
        for issuance in &block.issuances {
            issuance.validate(&self.config)?;
            if !transaction_outputs.contains(&issuance.fee_commitment)
                && !self.commitments.contains(&issuance.fee_commitment)
            {
                return Err(
                    "issuance fee output is not in verified canonical history or this block".into(),
                );
            }
            verifier.issuance(issuance)?;
            trial_assets.apply(issuance, block.height)?;
            for commitment in &issuance.signed.declaration.note_commitments {
                let bytes = encode_digest(commitment);
                if self.commitments.contains(&bytes) || !outputs.insert(bytes) {
                    return Err("issuance output commitment already used".into());
                }
                trial_tree.append(*commitment)?;
                leaves.push(*commitment);
            }
        }
        let mut rewards = Vec::with_capacity(block.rewards.len());
        for record in &block.rewards {
            let reward =
                decode_digest(&record.commitment).map_err(|_| "noncanonical miner reward")?;
            if self.commitments.contains(&record.commitment) || !outputs.insert(record.commitment) {
                return Err("reward commitment already used".into());
            }
            trial_tree.append(reward)?;
            leaves.push(reward);
            rewards.push(reward);
        }
        fees.extend(
            tail_slots(self.config.network, block.height, block.transactions.len())?
                .iter()
                .map(|s| s.commitment),
        );
        let mut trial_economics = self.economics.clone();
        let allocation = trial_economics
            .advance(block.height, block.reward_mode)
            .map_err(|e| e.to_string())?;
        let plan = plan_from_allocation(&allocation);
        verifier.settlement(
            &fees,
            &plan,
            self.config.network,
            block.list_digest(),
            &rewards,
            &block.settlement_proof,
        )?;
        for spend in &block.fund_spends {
            let account =
                FundAccount::new(usize::from(spend.account)).map_err(|e| e.to_string())?;
            let key = self
                .config
                .fund_verifying_keys
                .get(account.index())
                .ok_or("fund wallet is not configured by genesis")?;
            let note = spend.verify(self.config.network, key)?;
            trial_economics
                .spend_fund(account, u128::from(spend.amount), spend.counter)
                .map_err(|e| e.to_string())?;
            let commitment = Hasher::new().note_cm(&note);
            if self.commitments.contains(&spend.commitment) || !outputs.insert(spend.commitment) {
                return Err("fund payout commitment already used".into());
            }
            trial_tree.append(commitment)?;
            leaves.push(commitment);
        }
        trial_economics
            .assert_supply_invariant()
            .map_err(|e| e.to_string())?;
        let mut roots = RecentRoots::new();
        let h = Hasher::new();
        for s in &self.snapshots {
            if block.height - s.selector.height < SNAPSHOT_WINDOW as u64 {
                roots.insert(
                    &h,
                    s.selector.height,
                    &decode_digest(&s.commitment_root).map_err(|_| "invalid stored root")?,
                    base_fee(s.selector.height),
                );
            }
        }
        roots.insert(&h, block.height, &trial_tree.root(), base_fee(block.height));
        let snapshot = CanonicalSnapshot {
            selector: Snapshot {
                height: block.height,
                block_id: id,
            },
            commitment_root: encode_digest(&trial_tree.root()),
            recent_root: encode_digest(&roots.tree(&h).root()),
        };
        self.tree = trial_tree;
        self.height = block.height;
        self.tip = id;
        self.timestamps.push_back(block.timestamp);
        while self.timestamps.len() > siworld_core::params::MEDIAN_TIME_PAST_WINDOW {
            self.timestamps.pop_front();
        }
        self.cumulative_work = cumulative_work;
        self.economics = trial_economics;
        self.assets = trial_assets;
        self.spent.extend(spends);
        self.commitments.extend(outputs);
        self.leaves.extend(leaves);
        self.snapshots.push_back(snapshot);
        while self.snapshots.len() > SNAPSHOT_WINDOW {
            self.snapshots.pop_front();
        }
        Ok(())
    }
    /// Public deterministic state checksum for replay and storage corruption checks.
    pub fn fingerprint(&self) -> Hash {
        let mut h = blake3::Hasher::new_derive_key("siworld native engineering state v2");
        h.update(&self.config.genesis_id());
        h.update(&self.height.to_le_bytes());
        h.update(&self.tip);
        h.update(&self.cumulative_work.to_big_endian());
        h.update(&(self.timestamps.len() as u64).to_le_bytes());
        for timestamp in &self.timestamps {
            h.update(&timestamp.to_le_bytes());
        }
        h.update(&encode_digest(&self.tree.root()));
        h.update(&self.tree.count.to_le_bytes());
        for n in &self.spent {
            h.update(n);
        }
        for c in &self.commitments {
            h.update(c);
        }
        self.assets.visit_encoding(&mut |part| {
            h.update(part);
        });
        self.economics.visit_encoding(&mut |part| {
            h.update(part);
        });
        for s in &self.snapshots {
            h.update(&s.selector.height.to_le_bytes());
            h.update(&s.selector.block_id);
            h.update(&s.commitment_root);
            h.update(&s.recent_root);
        }
        *h.finalize().as_bytes()
    }
}

pub fn base_fee(height: u64) -> u64 {
    // The genesis snapshot has no subsidy but selects the first paid-block tier.
    economics::fee_base(height.max(1)).expect("positive bounded subsidy schedule")
}
/// Top-level miner base and independently rounded wallet credits.
pub fn subsidy_split(height: u64, funds: &FundAllocation) -> (u64, Vec<u64>) {
    let reward = economics::subsidy(height.max(1)).expect("positive subsidy height");
    let credits = funds.credits(reward);
    let pool = (u128::from(reward) * 3 / 100) as u64;
    (reward - credits.iter().sum::<u64>() - pool, credits)
}
fn plan_from_allocation(allocation: &RewardAllocation) -> RewardPlan {
    RewardPlan {
        block_height: allocation.height,
        mode: match allocation.mode {
            RewardMode::Voyager => PlanMode::Voyager,
            RewardMode::Holder => PlanMode::Holder,
        },
        allocations: allocation
            .reward_notes
            .iter()
            .map(|note| PlanAllocation {
                amount: note.amount,
                unlock_height: note.unlock_height,
            })
            .collect(),
    }
}
pub fn satisfies_work(id: &Hash, bits: u8) -> bool {
    if bits > 24 {
        return false;
    }
    let mut remaining = bits;
    for byte in id {
        if remaining == 0 {
            return true;
        }
        let take = remaining.min(8);
        if byte.leading_zeros() < u32::from(take) {
            return false;
        }
        remaining -= take;
    }
    remaining == 0
}

/// Public, deterministic zero-fee rows of the fixed-576 relation. These are
/// internal settlement rows, never additional transactions or chain flags.
pub fn tail_slots(network: Hash, height: u64, count: usize) -> Result<Vec<SettlementSlot>, String> {
    if !(MIN_SLOTS..=MAX_SLOTS).contains(&count) || !count.is_multiple_of(GROUP) {
        return Err("invalid settlement position count".into());
    }
    let h = Hasher::new();
    let mut slots = Vec::with_capacity(MAX_SLOTS - count);
    for index in count..MAX_SLOTS {
        let mut hash = blake3::Hasher::new_derive_key("siworld native zero fee settlement tail v1");
        hash.update(&network);
        hash.update(&height.to_le_bytes());
        hash.update(&(count as u16).to_le_bytes());
        hash.update(&(index as u16).to_le_bytes());
        let raw = hash.finalize();
        let blind = core::array::from_fn(|i| {
            F::from_u32(
                u32::from_le_bytes(
                    raw.as_bytes()[i * 4..i * 4 + 4]
                        .try_into()
                        .expect("fixed word"),
                ) % F::ORDER_U32,
            )
        });
        slots.push(SettlementSlot::from_opening(&h, FeeOpening::dummy(blind)));
    }
    Ok(slots)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod proof_profile_tests {
    use super::*;

    #[test]
    fn genesis_authenticates_the_selected_proof_profile() {
        let config = Config::development([94; 32], 0).unwrap();
        let profile = crate::proofs::protocol_profile_fingerprint();
        let genesis = config.genesis_id();
        assert_eq!(genesis, config.genesis_id_for_profile(&profile));
        assert_eq!(genesis, config.genesis_id());
        let mut changed = profile;
        changed[0] ^= 1;
        assert_ne!(genesis, config.genesis_id_for_profile(&changed));
    }

    #[test]
    fn encoded_rules_require_the_current_economic_order() {
        let config = Config::development([95; 32], 0).unwrap();
        let mut encoded = config.encode_rules();
        assert_eq!(Config::decode_rules(&encoded).unwrap(), config);
        assert!(Config::decode_rules(&encoded[..encoded.len() - 8]).is_err());
        let offset = encoded.len() - 4;
        encoded[offset..].copy_from_slice(&2u32.to_le_bytes());
        assert!(Config::decode_rules(&encoded).is_err());
        encoded = config.encode_rules();
        let offset = encoded.len() - 8;
        encoded[offset..offset + 4].copy_from_slice(&4u32.to_le_bytes());
        assert!(Config::decode_rules(&encoded).is_err());
    }

    #[test]
    fn disposable_asert_genesis_can_use_twenty_four_test_wallets() {
        let config = Config::asert_development([96; 32], 1, [0xff; 32], 1)
            .unwrap()
            .with_test_fund_registry()
            .unwrap();
        let allocation = config.fund_allocation.as_ref().unwrap();
        assert_eq!(allocation.basis_points().len(), 24);
        assert_eq!(
            allocation
                .basis_points()
                .iter()
                .map(|x| u32::from(*x))
                .sum::<u32>(),
            10_000
        );
        assert_eq!(allocation.team_index(), 23);
        assert_eq!(config.fund_verifying_keys.len(), 24);
        assert_eq!(
            Config::decode_rules(&config.encode_rules()).unwrap(),
            config
        );
        State::new(config).unwrap();
    }
}
