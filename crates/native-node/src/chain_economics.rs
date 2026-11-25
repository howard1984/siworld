//! Subsidy-only economic state for the version-two execution commitment.
//!
//! Fund releases and claims belong to the separate fund state. This module
//! records the exact aggregate credit that must match that state's entitlement.
//! Confidential fees are transfers and never enter these public counters.
use crate::wire::Hash;
use siworld_core::v1_economics::{
    self as economics, EconomicsParams, FundAllocation, RewardAllocation, RewardMode,
};
use std::collections::BTreeMap;

pub const MAX_LOCKED_ENTRIES: usize = 210_240;
const MAX_UNLOCK_OFFSET: u64 = 210_240;
const HEADER_BYTES: usize = 46;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EconomicState {
    network: Hash,
    height: u64,
    pool: u128,
    issued: u128,
    burned: u128,
    miner_credited: u128,
    fund_credited: u128,
    locked: u128,
    schedule: BTreeMap<u64, u128>,
}

pub fn fee_base(height: u64) -> Result<u64, String> {
    // The genesis snapshot selects the first paid-block fee tier. This does
    // not credit a genesis subsidy or advance the issuance ledger.
    economics::fee_base(height.max(1))
        .map(|fee| fee / 10)
        .map_err(|error| error.to_string())
}

pub fn fee_priority(height: u64) -> Result<u64, String> {
    fee_base(height)?
        .checked_mul(4)
        .ok_or_else(|| "priority fee overflow".into())
}

impl EconomicState {
    pub fn new(network: Hash) -> Result<Self, String> {
        if network == [0; 32] {
            return Err("invalid economic network binding".into());
        }
        Ok(Self {
            network,
            height: 0,
            pool: 0,
            issued: 0,
            burned: 0,
            miner_credited: 0,
            fund_credited: 0,
            locked: 0,
            schedule: BTreeMap::new(),
        })
    }

    pub fn network(&self) -> Hash {
        self.network
    }
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn pool(&self) -> u128 {
        self.pool
    }
    pub fn issued(&self) -> u128 {
        self.issued
    }
    pub fn burned(&self) -> u128 {
        self.burned
    }
    pub fn miner_credited(&self) -> u128 {
        self.miner_credited
    }
    pub fn fund_credited(&self) -> u128 {
        self.fund_credited
    }
    pub fn locked_schedule(&self) -> &BTreeMap<u64, u128> {
        &self.schedule
    }
    pub fn locked_total(&self) -> u128 {
        self.locked
    }

    /// Return isolated candidate state. The enclosing shared block engine must
    /// validate fund credits, settlement proofs and all components before adoption.
    pub fn prepare(
        &self,
        height: u64,
        mode: RewardMode,
        funds: &FundAllocation,
    ) -> Result<(Self, RewardAllocation), String> {
        if self.height.checked_add(1) != Some(height) {
            return Err("nonconsecutive economic height".into());
        }
        self.validate()?;
        let reward = economics::subsidy(height).map_err(|error| error.to_string())?;
        let allocation = economics::allocate_reward(
            &EconomicsParams::production(),
            funds,
            height,
            mode,
            reward,
            self.pool,
        )
        .map_err(|error| error.to_string())?;
        let credit = allocation.miner_subsidy_credit();
        let fund_credit = allocation
            .fund_credit
            .iter()
            .try_fold(0u128, |sum, amount| {
                sum.checked_add(u128::from(*amount))
                    .ok_or("fund credit overflow")
            })?;
        let mut next = self.clone();
        next.height = height;
        next.pool = allocation.pool_after;
        next.issued = self
            .issued
            .checked_add(u128::from(reward))
            .ok_or("issuance overflow")?;
        next.burned = self
            .burned
            .checked_add(u128::from(allocation.burn))
            .ok_or("burn overflow")?;
        next.miner_credited = self
            .miner_credited
            .checked_add(credit)
            .ok_or("subsidy credit overflow")?;
        next.fund_credited = self
            .fund_credited
            .checked_add(fund_credit)
            .ok_or("fund credit overflow")?;
        let matured = next.schedule.remove(&height).unwrap_or(0);
        next.locked = self
            .locked
            .checked_sub(matured)
            .and_then(|value| value.checked_add(credit))
            .ok_or("locked subsidy overflow")?;
        for note in &allocation.reward_notes {
            if note.amount == 0 {
                continue;
            }
            let previous = next.schedule.get(&note.unlock_height).copied().unwrap_or(0);
            let amount = previous
                .checked_add(u128::from(note.amount))
                .ok_or("unlock schedule overflow")?;
            next.schedule.insert(note.unlock_height, amount);
        }
        next.validate()?;
        Ok((next, allocation))
    }

    pub fn verify_fund_entitlement(&self, entitlement: u128) -> Result<(), String> {
        if self.fund_credited != entitlement {
            return Err("fund entitlement differs from subsidy credits".into());
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), String> {
        let accounted = self
            .miner_credited
            .checked_add(self.fund_credited)
            .and_then(|value| value.checked_add(self.pool))
            .and_then(|value| value.checked_add(self.burned))
            .ok_or("supply counter overflow")?;
        if self.network == [0; 32]
            || accounted != self.issued
            || self.locked > self.miner_credited
            || self.schedule.len() > MAX_LOCKED_ENTRIES
        {
            return Err("invalid subsidy conservation or schedule bounds".into());
        }
        let mut total = 0u128;
        for (&height, &amount) in &self.schedule {
            if height <= self.height || height - self.height > MAX_UNLOCK_OFFSET || amount == 0 {
                return Err("invalid future unlock schedule".into());
            }
            total = total
                .checked_add(amount)
                .ok_or("unlock schedule sum overflow")?;
        }
        if total != self.locked || (self.height == 0 && (self.issued != 0 || self.locked != 0)) {
            return Err("locked subsidy or genesis state differs".into());
        }
        Ok(())
    }

    fn header(&self, magic: &[u8; 4]) -> Vec<u8> {
        let mut bytes = magic.to_vec();
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&self.network);
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes
    }

    /// Exact component order: 5 Holder pool, 9 issuance/burn, 10 locked rewards.
    pub fn component_bytes(&self) -> Result<[Vec<u8>; 3], String> {
        self.validate()?;
        let mut pool = self.header(b"SW2P");
        pool.extend_from_slice(&self.pool.to_le_bytes());
        let mut counters = self.header(b"SW2I");
        for value in [
            self.issued,
            self.burned,
            self.miner_credited,
            self.fund_credited,
        ] {
            counters.extend_from_slice(&value.to_le_bytes());
        }
        let mut locked = self.header(b"SW2L");
        locked.extend_from_slice(&self.locked.to_le_bytes());
        locked.extend_from_slice(&(self.schedule.len() as u32).to_le_bytes());
        for (height, amount) in &self.schedule {
            locked.extend_from_slice(&height.to_le_bytes());
            locked.extend_from_slice(&amount.to_le_bytes());
        }
        Ok([pool, counters, locked])
    }

    pub fn from_components(network: Hash, height: u64, bytes: [&[u8]; 3]) -> Result<Self, String> {
        if bytes[0].len() != HEADER_BYTES + 16
            || bytes[1].len() != HEADER_BYTES + 64
            || bytes[2].len() < HEADER_BYTES + 20
            || bytes[2].len() > HEADER_BYTES + 20 + MAX_LOCKED_ENTRIES * 24
        {
            return Err("invalid bounded economic component length".into());
        }
        let mut result = Self::new(network)?;
        result.height = height;
        for (body, magic) in bytes.iter().zip([b"SW2P", b"SW2I", b"SW2L"]) {
            if body[..HEADER_BYTES] != result.header(magic) {
                return Err("economic component network or height differs".into());
            }
        }
        let number = |body: &[u8], offset: usize| {
            u128::from_le_bytes(
                body[offset..offset + 16]
                    .try_into()
                    .expect("bounded economic counter"),
            )
        };
        result.pool = number(bytes[0], HEADER_BYTES);
        result.issued = number(bytes[1], HEADER_BYTES);
        result.burned = number(bytes[1], HEADER_BYTES + 16);
        result.miner_credited = number(bytes[1], HEADER_BYTES + 32);
        result.fund_credited = number(bytes[1], HEADER_BYTES + 48);
        result.locked = number(bytes[2], HEADER_BYTES);
        let count = u32::from_le_bytes(bytes[2][62..66].try_into().expect("bounded schedule count"))
            as usize;
        if count > MAX_LOCKED_ENTRIES || bytes[2].len() != HEADER_BYTES + 20 + count * 24 {
            return Err("invalid bounded unlock schedule count".into());
        }
        let mut previous = None;
        for entry in bytes[2][66..].as_chunks::<24>().0 {
            let unlock = u64::from_le_bytes(entry[..8].try_into().expect("bounded unlock"));
            let amount = number(entry, 8);
            if previous.is_some_and(|old| old >= unlock) {
                return Err("noncanonical unlock schedule ordering".into());
            }
            result.schedule.insert(unlock, amount);
            previous = Some(unlock);
        }
        result.validate()?;
        if result
            .component_bytes()?
            .iter()
            .zip(bytes)
            .any(|(local, remote)| local != remote)
        {
            return Err("noncanonical economic component".into());
        }
        Ok(result)
    }
}
