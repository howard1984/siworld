//! Bounded full-proof synchronization and exact-proof compact reconstruction.
//! Advertised heights/work are hints only. Canonical changes use Store's shared
//! transition and verified work. Checkpoint trust is deliberately not inferred.
use crate::chain::{BranchOutcome, CandidatePolicy, ChainError};
use crate::state::BlockVerifier;
use crate::store::Store;
use crate::wire::{
    Block, GROUP, Hash, MAX_BLOCK_BYTES, MAX_FUND_SPENDS, MAX_REWARDS, MAX_SETTLEMENT_PROOF,
    MAX_SLOTS, MIN_SLOTS, REWARD_RECORD_BYTES, RewardMode, RewardRecord, Snapshot, Transaction,
    reward_count, validate_fund_spends, validate_rewards,
};
use std::collections::BTreeSet;

pub const MAX_LOCATORS: usize = 64;
pub const MAX_BATCH_BLOCKS: usize = 16;
pub const MAX_MISSING: usize = 16;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Locator {
    pub entries: Vec<Snapshot>,
}
impl Locator {
    pub fn from_store(store: &Store) -> Result<Self, String> {
        let mut entries = Vec::new();
        let mut height = store.state().height;
        let mut step = 1u64;
        loop {
            entries.push(Snapshot {
                height,
                block_id: canonical_id(store, height)?,
            });
            if height == 0 {
                break;
            }
            if entries.len() > 10 {
                step = step.saturating_mul(2);
            }
            height = height.saturating_sub(step);
            if entries.len() == MAX_LOCATORS - 1 {
                height = 0;
            }
        }
        Ok(Self { entries })
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.entries.is_empty() || self.entries.len() > MAX_LOCATORS {
            return Err("locator count limit".into());
        }
        let mut identities = BTreeSet::new();
        if self
            .entries
            .iter()
            .any(|entry| !identities.insert(entry.block_id))
        {
            return Err("repeated locator block identity".into());
        }
        for pair in self.entries.windows(2) {
            if pair[0].height <= pair[1].height {
                return Err("noncanonical locator".into());
            }
        }
        if self.entries.last().expect("nonempty").height != 0 {
            return Err("locator missing genesis anchor".into());
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut out = Vec::with_capacity(2 + 40 * self.entries.len());
        out.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
        for s in &self.entries {
            out.extend_from_slice(&s.height.to_le_bytes());
            out.extend_from_slice(&s.block_id);
        }
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 2 {
            return Err("truncated locator".into());
        }
        let count = u16::from_le_bytes(bytes[..2].try_into().expect("fixed count")) as usize;
        if count == 0 || count > MAX_LOCATORS || bytes.len() != 2 + 40 * count {
            return Err("locator byte limit".into());
        }
        let entries = bytes[2..]
            .as_chunks::<40>()
            .0
            .iter()
            .map(|b| Snapshot {
                height: u64::from_le_bytes(b[..8].try_into().expect("fixed height")),
                block_id: b[8..].try_into().expect("fixed ID"),
            })
            .collect();
        let value = Self { entries };
        value.validate()?;
        Ok(value)
    }
    pub fn common_ancestor(&self, store: &Store) -> Result<Snapshot, String> {
        self.validate()?;
        let genesis = self.entries.last().expect("nonempty");
        if genesis.block_id != store.state().config.genesis_id() {
            return Err("locator genesis mismatch".into());
        }
        for s in &self.entries {
            if s.height <= store.state().height && canonical_id(store, s.height)? == s.block_id {
                return Ok(*s);
            }
        }
        Err("no canonical locator ancestor".into())
    }
}
/// Non-genesis lookups decode one complete stored block. Network callers must
/// reserve a maximum block plus bookkeeping before resolving locators or bases.
pub fn canonical_id(store: &Store, height: u64) -> Result<Hash, String> {
    if height == 0 {
        Ok(store.state().config.genesis_id())
    } else {
        store.canonical_id(height)
    }
}
pub struct Batch {
    pub ancestor: Snapshot,
    pub after: Snapshot,
    pub blocks: Vec<Block>,
    pub more: bool,
}
/// The caller pins a canonical ancestor and continuation ID. A changed source
/// fork returns unavailability; it never substitutes a different history.
pub fn serve_batch(
    store: &Store,
    ancestor: Snapshot,
    after: Snapshot,
    limit: usize,
    byte_budget: usize,
) -> Result<Batch, String> {
    if !store.serves_historical_proofs()? {
        return Err("historical proof service disabled for this local storage role".into());
    }
    if limit == 0
        || limit > MAX_BATCH_BLOCKS
        || byte_budget > 640 * 1024 * 1024
        || ancestor.height > after.height
        || after.height > store.state().height
        || canonical_id(store, ancestor.height)? != ancestor.block_id
        || canonical_id(store, after.height)? != after.block_id
    {
        return Err("unavailable synchronization continuation".into());
    }
    if after.height == store.state().height {
        return Ok(Batch {
            ancestor,
            after,
            blocks: Vec::new(),
            more: false,
        });
    }
    let outer_bytes = limit
        .checked_mul(std::mem::size_of::<Block>())
        .ok_or("sync vector byte overflow")?;
    if outer_bytes > byte_budget {
        return Err("synchronization resource unavailable".into());
    }
    let mut blocks = Vec::with_capacity(limit);
    let mut bytes = outer_bytes;
    // A continuation at u64::MAX is already terminal; it never wraps to genesis.
    for height in after
        .height
        .checked_add(1)
        .into_iter()
        .flat_map(|first| first..=store.state().height)
    {
        if blocks.len() == limit {
            break;
        }
        // Reserve room for one maximum block before reading/copying a record.
        if bytes
            .checked_add(MAX_BLOCK_BYTES)
            .is_none_or(|n| n > byte_budget)
        {
            break;
        }
        let block = store.block(height)?;
        bytes = bytes
            .checked_add(block.encoded_len()?)
            .ok_or("sync byte overflow")?;
        blocks.push(block);
    }
    let last = blocks.last().map(|b| b.height).unwrap_or(after.height);
    if blocks.is_empty() && last < store.state().height {
        return Err("synchronization resource unavailable".into());
    }
    Ok(Batch {
        ancestor,
        after,
        blocks,
        more: last < store.state().height,
    })
}
/// One branch remains owned by one synchronization attempt. Disconnect drops
/// its uncommitted buffers. The caller never turns exhaustion into peer fraud.
pub struct Staging {
    base: Snapshot,
    anchor: Hash,
    blocks: Vec<Block>,
    policy: CandidatePolicy,
}
impl Staging {
    pub fn new(store: &Store, base: Snapshot, policy: CandidatePolicy) -> Result<Self, ChainError> {
        crate::chain::check_ancestor(store.state().height, base.height)?;
        if canonical_id(store, base.height).map_err(ChainError::Local)? != base.block_id {
            return Err(ChainError::Invalid("sync base mismatch".into()));
        }
        Ok(Self {
            base,
            anchor: store.state().fingerprint(),
            blocks: Vec::new(),
            policy,
        })
    }
    pub fn base(&self) -> Snapshot {
        self.base
    }
    pub fn continuation(&self) -> Result<Snapshot, String> {
        self.blocks
            .last()
            .map(|b| {
                Ok(Snapshot {
                    height: b.height,
                    block_id: b.id()?,
                })
            })
            .unwrap_or(Ok(self.base))
    }
    pub fn accept(
        &mut self,
        store: &mut Store,
        batch: Batch,
        verifier: &impl BlockVerifier,
    ) -> Result<BranchOutcome, ChainError> {
        if store.state().fingerprint() != self.anchor {
            return Err(ChainError::Local(
                "canonical state changed during sync".into(),
            ));
        }
        if batch.ancestor != self.base
            || batch.after != self.continuation().map_err(ChainError::Invalid)?
            || batch.blocks.is_empty()
            || batch.blocks.len() > MAX_BATCH_BLOCKS
        {
            return Err(ChainError::Invalid("unexpected sync batch".into()));
        }
        let old = self.blocks.len();
        let total = old
            .checked_add(batch.blocks.len())
            .ok_or(ChainError::ResourceExhausted("sync staged count"))?;
        if total > self.policy.max_blocks {
            return Err(ChainError::ResourceExhausted("sync staged count"));
        }
        let previous_bytes = if self.blocks.is_empty() {
            0
        } else {
            crate::chain::candidate_budget(&self.blocks, self.policy)?
        };
        let incoming_bytes = crate::chain::candidate_budget(&batch.blocks, self.policy)?;
        // Include both old/new outer allocations during a possible reallocation,
        // and the incoming vector until its elements have been moved.
        let outer_bytes = self
            .blocks
            .capacity()
            .checked_add(batch.blocks.capacity())
            .and_then(|n| n.checked_add(total))
            .and_then(|n| n.checked_mul(std::mem::size_of::<Block>()))
            .ok_or(ChainError::ResourceExhausted("sync outer vector bytes"))?;
        if previous_bytes
            .checked_add(incoming_bytes)
            .and_then(|n| n.checked_add(outer_bytes))
            .is_none_or(|n| n > self.policy.max_bytes)
        {
            return Err(ChainError::ResourceExhausted("sync staged bytes"));
        }
        self.blocks
            .try_reserve_exact(batch.blocks.len())
            .map_err(|_| ChainError::ResourceExhausted("sync staging allocation"))?;
        self.blocks.extend(batch.blocks);
        let owned = crate::chain::candidate_budget(&self.blocks, self.policy).and_then(|bytes| {
            let outer = self
                .blocks
                .capacity()
                .checked_mul(std::mem::size_of::<Block>())
                .and_then(|n| n.checked_add(bytes))
                .ok_or(ChainError::ResourceExhausted("sync outer vector bytes"))?;
            if outer > self.policy.max_bytes {
                return Err(ChainError::ResourceExhausted("sync staged bytes"));
            }
            Ok(())
        });
        if let Err(e) = owned {
            self.blocks.truncate(old);
            return Err(e);
        }
        let result = store.consider_branch(self.base.height, &self.blocks, self.policy, verifier);
        match &result {
            Ok(BranchOutcome::Adopted { .. }) => {
                self.base = Snapshot {
                    height: store.state().height,
                    block_id: store.state().tip,
                };
                self.anchor = store.state().fingerprint();
                self.blocks.clear();
            }
            Err(_) => self.blocks.truncate(old),
            _ => {}
        }
        result
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reference {
    pub statement: Hash,
    pub proof: Hash,
}
pub fn reference(tx: &Transaction, network: &Hash) -> Reference {
    Reference {
        statement: tx.record.statement_id(network),
        proof: *blake3::hash(&tx.proof).as_bytes(),
    }
}
#[derive(Clone)]
pub struct CompactBlock {
    pub network: Hash,
    pub height: u64,
    pub parent: Hash,
    pub timestamp: u64,
    pub target: Hash,
    pub nonce: u64,
    pub expected_id: Hash,
    pub references: Vec<Reference>,
    pub reward_mode: RewardMode,
    pub rewards: Vec<RewardRecord>,
    pub fund_spends: Vec<crate::fund_spend::FundSpend>,
    pub issuances: Vec<crate::issuance::IssuanceRecord>,
    pub settlement: Vec<u8>,
}
impl CompactBlock {
    pub fn from_block(block: &Block) -> Result<Self, String> {
        block.validate_shape()?;
        Ok(Self {
            network: block.network,
            height: block.height,
            parent: block.parent,
            timestamp: block.timestamp,
            target: block.target,
            nonce: block.nonce,
            expected_id: block.id()?,
            references: block
                .transactions
                .iter()
                .map(|t| reference(t, &block.network))
                .collect(),
            reward_mode: block.reward_mode,
            rewards: block.rewards.clone(),
            fund_spends: block.fund_spends.clone(),
            issuances: block.issuances.clone(),
            settlement: block.settlement_proof.clone(),
        })
    }
    /// Checks the complete announced skeleton against a previously accepted
    /// block without cloning its proof artifacts. This is used for a lost-ACK
    /// retry; an expected block ID alone does not authenticate substituted
    /// references, rewards, issuance records or settlement bytes.
    pub fn matches_block(&self, block: &Block) -> Result<bool, String> {
        self.validate()?;
        block.validate_shape()?;
        Ok(self.network == block.network
            && self.height == block.height
            && self.parent == block.parent
            && self.timestamp == block.timestamp
            && self.target == block.target
            && self.nonce == block.nonce
            && self.expected_id == block.id()?
            && self.reward_mode == block.reward_mode
            && self.rewards == block.rewards
            && self.fund_spends == block.fund_spends
            && self.issuances == block.issuances
            && self.settlement == block.settlement_proof
            && self.references.len() == block.transactions.len()
            && self
                .references
                .iter()
                .zip(&block.transactions)
                .all(|(expected, transaction)| reference(transaction, &block.network) == *expected))
    }
    fn validate(&self) -> Result<(), String> {
        validate_rewards(self.reward_mode, &self.rewards)?;
        validate_fund_spends(&self.fund_spends)?;
        if self.issuances.len() > crate::issuance::RECORDS_CODEC_LIMIT {
            return Err("compact issuance count limit".into());
        }
        for issuance in &self.issuances {
            issuance.validate_shape()?;
        }
        if !(MIN_SLOTS..=MAX_SLOTS).contains(&self.references.len())
            || !self.references.len().is_multiple_of(GROUP)
            || self.height == 0
            || self.settlement.is_empty()
            || self.settlement.len() > MAX_SETTLEMENT_PROOF
            || self.timestamp == 0
            || self.target == [0; 32]
            || self
                .references
                .windows(2)
                .any(|w| w[0].statement >= w[1].statement)
        {
            return Err("invalid compact block".into());
        }
        Ok(())
    }
    pub fn missing(&self, mut contains: impl FnMut(&Reference) -> bool) -> Vec<Reference> {
        self.references
            .iter()
            .filter(|r| !contains(r))
            .copied()
            .collect()
    }
    /// A request is limited to 16 references. Responses are separate bounded
    /// envelopes; sidecars are not part of a public block reconstruction.
    pub fn missing_request(&self, contains: impl FnMut(&Reference) -> bool) -> Vec<Reference> {
        self.missing(contains)
            .into_iter()
            .take(MAX_MISSING)
            .collect()
    }
    pub fn reconstruct(
        &self,
        mut resolve: impl FnMut(&Reference) -> Option<Transaction>,
    ) -> Result<Block, String> {
        self.validate()?;
        let mut transactions = Vec::with_capacity(self.references.len());
        for r in &self.references {
            let tx = resolve(r).ok_or("compact transaction unavailable")?;
            if reference(&tx, &self.network) != *r {
                return Err("compact proof or statement mismatch".into());
            }
            transactions.push(tx);
        }
        let block = Block {
            network: self.network,
            height: self.height,
            parent: self.parent,
            timestamp: self.timestamp,
            target: self.target,
            nonce: self.nonce,
            transactions,
            reward_mode: self.reward_mode,
            rewards: self.rewards.clone(),
            fund_spends: self.fund_spends.clone(),
            issuances: self.issuances.clone(),
            settlement_proof: self.settlement.clone(),
        };
        block.validate_shape()?;
        if block.id()? != self.expected_id {
            return Err("compact block identity mismatch".into());
        }
        Ok(block)
    }
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut out = Vec::new();
        out.extend_from_slice(b"SWCP");
        out.extend_from_slice(&3u16.to_le_bytes());
        out.extend_from_slice(&self.network);
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&self.parent);
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&self.target);
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.extend_from_slice(&self.expected_id);
        out.extend_from_slice(&(self.references.len() as u16).to_le_bytes());
        out.push(self.reward_mode.to_byte());
        out.push(self.fund_spends.len() as u8);
        out.push(self.issuances.len() as u8);
        for r in &self.references {
            out.extend_from_slice(&r.statement);
            out.extend_from_slice(&r.proof);
        }
        for reward in &self.rewards {
            out.extend_from_slice(&reward.commitment);
            out.extend_from_slice(&reward.ciphertext);
        }
        for spend in &self.fund_spends {
            out.extend_from_slice(&spend.encode());
        }
        for issuance in &self.issuances {
            let bytes = issuance.encode()?;
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(&bytes);
        }
        out.extend_from_slice(&(self.settlement.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.settlement);
        Ok(out)
    }
    pub fn decode(bytes: &[u8], network: &Hash) -> Result<Self, String> {
        const FIXED: usize =
            4 + 2 + 32 + 8 + 32 + 8 + 32 + 8 + 32 + 2 + 1 + 1 + 1 + REWARD_RECORD_BYTES + 4;
        if bytes.len() < FIXED
            || bytes.len()
                > FIXED
                    + (MAX_REWARDS - 1) * REWARD_RECORD_BYTES
                    + MAX_FUND_SPENDS * crate::fund_spend::ENCODED_BYTES
                    + crate::issuance::RECORDS_CODEC_LIMIT * (4 + crate::issuance::MAX_RECORD_BYTES)
                    + MAX_SLOTS * 64
                    + MAX_SETTLEMENT_PROOF
        {
            return Err("compact byte limit".into());
        }
        let mut r = Cursor { bytes, position: 0 };
        if r.take(4)? != b"SWCP" || r.array::<2>()? != 3u16.to_le_bytes() {
            return Err("compact version".into());
        }
        let n = r.array()?;
        if &n != network {
            return Err("compact network mismatch".into());
        }
        let height = r.u64()?;
        let parent = r.array()?;
        let timestamp = r.u64()?;
        let target = r.array()?;
        let nonce = r.u64()?;
        let expected_id = r.array()?;
        let count = u16::from_le_bytes(r.array()?) as usize;
        let reward_mode = RewardMode::from_byte(r.array::<1>()?[0]).map_err(|e| e.to_string())?;
        let fund_count = usize::from(r.array::<1>()?[0]);
        if fund_count > MAX_FUND_SPENDS {
            return Err("compact fund expenditure count limit".into());
        }
        let issuance_count = usize::from(r.array::<1>()?[0]);
        if issuance_count > crate::issuance::RECORDS_CODEC_LIMIT {
            return Err("compact issuance count limit".into());
        }
        if !(MIN_SLOTS..=MAX_SLOTS).contains(&count)
            || !count.is_multiple_of(GROUP)
            || bytes.len() < FIXED + count * 64 + 1
        {
            return Err("compact count limit".into());
        }
        let mut references = Vec::with_capacity(count);
        for _ in 0..count {
            references.push(Reference {
                statement: r.array()?,
                proof: r.array()?,
            });
        }
        let mut rewards = Vec::with_capacity(reward_count(reward_mode));
        for _ in 0..reward_count(reward_mode) {
            rewards.push(RewardRecord {
                commitment: r.array()?,
                ciphertext: r.array()?,
            });
        }
        let mut fund_spends = Vec::with_capacity(fund_count);
        for _ in 0..fund_count {
            fund_spends.push(crate::fund_spend::FundSpend::decode(
                r.take(crate::fund_spend::ENCODED_BYTES)?,
            )?);
        }
        let mut issuances = Vec::with_capacity(issuance_count);
        for _ in 0..issuance_count {
            let length = u32::from_le_bytes(r.array()?) as usize;
            if length > crate::issuance::MAX_RECORD_BYTES {
                return Err("compact issuance byte limit".into());
            }
            issuances.push(crate::issuance::IssuanceRecord::decode(r.take(length)?)?);
        }
        let length = u32::from_le_bytes(r.array()?) as usize;
        if length == 0 || length > MAX_SETTLEMENT_PROOF || length != bytes.len() - r.position {
            return Err("compact settlement length".into());
        }
        let value = Self {
            network: n,
            height,
            parent,
            timestamp,
            target,
            nonce,
            expected_id,
            references,
            reward_mode,
            rewards,
            fund_spends,
            issuances,
            settlement: r.take(length)?.to_vec(),
        };
        value.validate()?;
        Ok(value)
    }
}
struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.position.checked_add(n).ok_or("compact overflow")?;
        let b = self
            .bytes
            .get(self.position..end)
            .ok_or("truncated compact")?;
        self.position = end;
        Ok(b)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        Ok(self.take(N)?.try_into().expect("bounded fixed array"))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.array()?))
    }
}
#[cfg(test)]
mod tests;
