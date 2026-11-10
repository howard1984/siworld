//! Engineering-v2 header/receipt wallet state under explicit full-node trust.
//!
//! This client verifies complete header work and receipt inclusion. It does not
//! execute governance, verify transaction proofs, or authenticate a checkpoint
//! state. Every receipt from genesis must be scanned before a balance is usable.
use crate::{
    eng2_history::{Context, HEADER_BYTES, Header, ReceiptBlock},
    paths::OwnedPaths,
    state::{CanonicalSnapshot, SNAPSHOT_WINDOW, State, base_fee},
    wallet::Wallet,
    wire::{Block, DigestBytes, Hash, Snapshot},
};
use native::{
    codec::{PublicTransaction, decode_digest, encode_digest},
    multi_asset::{Hasher, RecentRoots},
};
use serde_json::json;
use siworld_core::pow;
use std::collections::BTreeSet;
use zeroize::Zeroizing;

#[path = "eng2_light_cache.rs"]
mod cache;
/// Exact immutable native proof profile compiled into this client.
pub fn native_profile() -> Hash {
    crate::proofs::protocol_profile_fingerprint()
}
pub const MAX_HEADERS: usize = 100_000;
pub const TRUST: &str = "eng2-header-work-and-body-receipt-authenticated-full-node-consensus";

pub struct Eng2LightState {
    context: Context,
    state: State,
    wallet: Wallet,
    paths: OwnedPaths,
    headers: Vec<Header>,
}
impl Eng2LightState {
    pub fn new(
        genesis: &[u8],
        expected: Hash,
        seed: Zeroizing<[u8; 32]>,
        account: u32,
    ) -> Result<Self, String> {
        Self::from_context(Context::from_genesis(genesis, expected)?, seed, account)
    }
    fn from_context(
        context: Context,
        seed: Zeroizing<[u8; 32]>,
        account: u32,
    ) -> Result<Self, String> {
        // State is only a private note/tree carrier. Its V1 genesis, execution
        // function and economic ledger are never used to validate eng2 blocks.
        let mut state = State::new(context.config().clone())?;
        state.tip = context.genesis();
        state
            .snapshots
            .back_mut()
            .ok_or("missing initial wallet root")?
            .selector
            .block_id = context.genesis();
        let mut wallet = Wallet::from_seed(context.config().network, seed, account)?;
        wallet.scan_light_data(&state, &[], &[], false)?;
        Ok(Self {
            context,
            state,
            wallet,
            paths: OwnedPaths::new(),
            headers: Vec::new(),
        })
    }
    pub fn fresh(&self, seed: Zeroizing<[u8; 32]>, account: u32) -> Result<Self, String> {
        Self::from_context(self.context.clone(), seed, account)
    }
    pub fn context(&self) -> &Context {
        &self.context
    }
    pub fn height(&self) -> u64 {
        self.state.height
    }
    pub fn tip(&self) -> Hash {
        self.state.tip
    }
    pub fn cumulative_work(&self) -> pow::Work {
        self.state.cumulative_work
    }
    pub fn wallet(&self) -> &Wallet {
        &self.wallet
    }
    pub fn root(&self) -> DigestBytes {
        encode_digest(&self.state.tree.root())
    }
    pub fn header(&self, height: u64) -> Option<&Header> {
        usize::try_from(height.checked_sub(1)?)
            .ok()
            .and_then(|index| self.headers.get(index))
    }
    pub fn fork(&self, seed: Zeroizing<[u8; 32]>, account: u32) -> Result<Self, String> {
        let mut result = Self::from_context(self.context.clone(), seed, account)?;
        result.wallet.copy_light_receipts(&self.wallet)?;
        result.state = self.state.clone();
        result.paths = self.paths.clone();
        result.headers = self.headers.clone();
        Ok(result)
    }
    /// Only complete candidate scans may replace an accepted local wallet.
    pub fn check_head(
        &self,
        height: u64,
        tip: Hash,
        previous: Option<&Self>,
    ) -> Result<(), String> {
        if self.height() != height || self.tip() != tip || self.headers.len() as u64 != height {
            return Err("eng2 wallet candidate does not reach the pinned head".into());
        }
        if previous.is_some_and(|previous| {
            binding(&self.context) != binding(&previous.context)
                || self.wallet.address() != previous.wallet.address()
                || self.tip() != previous.tip()
                    && self.cumulative_work() <= previous.cumulative_work()
        }) {
            return Err("eng2 wallet candidate context or greater-work requirement failed".into());
        }
        Ok(())
    }
    /// No accepted private field changes until work, authentication, note and
    /// tree/path checks all succeed. No omitted receipt prefix is accepted.
    pub fn append(&mut self, raw_header: &[u8], bytes: &[u8]) -> Result<(), String> {
        if self.headers.len() >= MAX_HEADERS {
            return Err("eng2 wallet header capacity exceeded".into());
        }
        let header = Header::decode(raw_header, &self.context.config().network)
            .map_err(|_| "eng2 wallet header encoding rejected")?;
        let mut trial = self.state.clone();
        verify_header(&trial, &header)?;
        let encoded: [u8; HEADER_BYTES] = raw_header
            .try_into()
            .map_err(|_| "eng2 wallet header width rejected")?;
        let receipt = ReceiptBlock::decode(&self.context, &encoded, bytes)?;
        let staged = receipt.scan_receipts(&self.wallet)?;
        let owned_nullifiers = self
            .wallet
            .receipts()
            .iter()
            .chain(&staged)
            .map(|row| row.nullifier)
            .collect::<BTreeSet<_>>();
        let mut nullifiers = BTreeSet::new();
        for record in receipt.transactions() {
            trial.snapshot(record.snapshot)?;
            let public = PublicTransaction::decode(&record.body)
                .map_err(|_| "eng2 wallet transaction public fields rejected")?;
            for nullifier in public.nf {
                let bytes = encode_digest(&nullifier);
                if !nullifiers.insert(bytes) {
                    return Err("eng2 wallet duplicate block nullifier".into());
                }
                if owned_nullifiers.contains(&bytes) && !trial.spent.insert(bytes) {
                    return Err("eng2 wallet owned nullifier already spent".into());
                }
            }
        }
        for issuance in receipt.issuances() {
            trial.assets.apply(issuance, header.height)?;
        }
        let owned_outputs = staged
            .iter()
            .filter(|row| row.note().value > 0 && !trial.spent.contains(&row.nullifier))
            .map(|row| row.commitment)
            .collect::<BTreeSet<_>>();
        let mut paths = self.paths.clone();
        for row in self.wallet.receipts() {
            if trial.spent.contains(&row.nullifier) {
                paths.remove(&row.commitment);
            }
        }
        let mut outputs = BTreeSet::new();
        for bytes in receipt.outputs()? {
            if !outputs.insert(bytes) {
                return Err("eng2 wallet duplicate block output".into());
            }
            let retain = owned_outputs.contains(&bytes);
            if retain && !trial.commitments.insert(bytes) {
                return Err("eng2 wallet owned commitment already present".into());
            }
            let leaf =
                decode_digest(&bytes).map_err(|_| "eng2 wallet commitment field rejected")?;
            trial.tree.append(leaf)?;
            paths.append(leaf, retain)?;
        }
        if paths.root() != trial.tree.root() || paths.count() != trial.tree.count {
            return Err("eng2 wallet private path frontier differs".into());
        }
        let id = header
            .id()
            .map_err(|_| "eng2 wallet header identity rejected")?;
        let mut roots = RecentRoots::new();
        let hasher = Hasher::new();
        for snapshot in &trial.snapshots {
            if header.height - snapshot.selector.height < SNAPSHOT_WINDOW as u64 {
                roots.insert(
                    &hasher,
                    snapshot.selector.height,
                    &decode_digest(&snapshot.commitment_root)
                        .map_err(|_| "eng2 wallet local root rejected")?,
                    base_fee(snapshot.selector.height),
                );
            }
        }
        roots.insert(
            &hasher,
            header.height,
            &trial.tree.root(),
            base_fee(header.height),
        );
        trial.snapshots.push_back(CanonicalSnapshot {
            selector: Snapshot {
                height: header.height,
                block_id: id,
            },
            commitment_root: encode_digest(&trial.tree.root()),
            recent_root: encode_digest(&roots.tree(&hasher).root()),
        });
        while trial.snapshots.len() > SNAPSHOT_WINDOW {
            trial.snapshots.pop_front();
        }
        advance_header(&mut trial, &header)?;
        // This carrier supplies only a canonical receipt timestamp to the
        // private wallet. It is never encoded, executed or passed to V1 sync.
        let timestamp = Block {
            network: header.network,
            height: header.height,
            parent: header.parent,
            timestamp: header.timestamp,
            target: header.target,
            nonce: header.nonce,
            transactions: Vec::new(),
            reward_mode: receipt.reward_mode(),
            rewards: Vec::new(),
            fund_spends: Vec::new(),
            issuances: Vec::new(),
            settlement_proof: Vec::new(),
        };
        self.wallet
            .commit_light_receipts(&trial, staged, &[timestamp], true);
        self.state = trial;
        self.paths = paths;
        self.headers.push(header);
        Ok(())
    }
    pub fn balance_json(&self) -> Result<String, String> {
        let balances = self.wallet.balance_details(&self.state)?;
        let assets = balances
            .available
            .keys()
            .chain(balances.locked.keys())
            .collect::<BTreeSet<_>>();
        let rows = assets.into_iter().map(|asset| json!({"asset": crate::local::hex(&asset.0), "available_atoms":balances.available.get(asset).copied().unwrap_or(0).to_string(),"locked_atoms":balances.locked.get(asset).copied().unwrap_or(0).to_string()})).collect::<Vec<_>>();
        let tranches = balances.tranches.iter().map(|row| json!({"asset":crate::local::hex(&row.asset.0),"amount_atoms":row.amount.to_string(),"unlock_height":row.unlock_height,"estimated_timestamp":row.estimated_timestamp})).collect::<Vec<_>>();
        Ok(json!({"version":2,"network":crate::local::hex(&self.context.config().network),"genesis":crate::local::hex(&self.context.genesis()),"rules":crate::local::hex(&self.context.rules()),"profile":crate::local::hex(&self.context.profile()),"fee_mode":self.context.fee_mode(),"height":self.height(),"tip":crate::local::hex(&self.tip()),"trust":TRUST,"full_node_consensus_verified":false,"send_supported":false,"rows":rows,"locked_tranches":tranches}).to_string())
    }
    pub fn history_json(&self) -> String {
        serde_json::Value::Array(self.wallet.receipts().iter().filter(|row| row.note().value > 0 && row.output_index != 1 && row.output_index != 2).map(|row| json!({"id":crate::local::hex(&row.commitment),"block_id":crate::local::hex(&row.block_id),"height":row.height,"asset":crate::local::hex(&row.note().asset_id.0),"amount_atoms":row.note().value.to_string(),"unlock_height":row.note().unlock_height,"spent":row.spent,"kind":if row.output_index == 0 { "received" } else if row.output_index < 8 { "mining" } else { "allocation" }})).collect()).to_string()
    }
}
fn binding(context: &Context) -> Vec<u8> {
    let mut result = Vec::with_capacity(129);
    for value in [
        context.config().network,
        context.genesis(),
        context.rules(),
        context.profile(),
    ] {
        result.extend_from_slice(&value);
    }
    result.push(context.fee_mode());
    result
}
fn verify_header(state: &State, header: &Header) -> Result<(), String> {
    if header.network != state.config.network
        || header.height
            != state
                .height
                .checked_add(1)
                .ok_or("eng2 wallet height overflow")?
        || header.parent != state.tip
        || header.timestamp <= state.median_time_past()
    {
        return Err("eng2 wallet header continuity or time rejected".into());
    }
    if header.target != state.next_target()
        || !pow::meets_target(
            &pow::pow_hash(
                &header
                    .pow_seed()
                    .map_err(|_| "eng2 wallet header work seed rejected")?,
                header.nonce,
                state.config.pow_iterations,
            ),
            &header.target,
        )
    {
        return Err("eng2 wallet header difficulty or work rejected".into());
    }
    state
        .cumulative_work
        .checked_add(pow::block_work(&header.target))
        .ok_or("eng2 wallet cumulative work overflow")?;
    Ok(())
}
fn advance_header(state: &mut State, header: &Header) -> Result<(), String> {
    let id = header
        .id()
        .map_err(|_| "eng2 wallet header identity rejected")?;
    let work = state
        .cumulative_work
        .checked_add(pow::block_work(&header.target))
        .ok_or("eng2 wallet cumulative work overflow")?;
    state.height = header.height;
    state.tip = id;
    state.cumulative_work = work;
    state.timestamps.push_back(header.timestamp);
    while state.timestamps.len() > siworld_core::params::MEDIAN_TIME_PAST_WINDOW {
        state.timestamps.pop_front();
    }
    Ok(())
}
