//! Integer-only economic accounting for the native V1 protocol.
//!
//! These rules are independent of the retained legacy issuance implementation.
//! Heights identify target-time intervals; wall clocks never affect unlocks.
//! Amounts here are subsidy atoms only. Confidential transaction fees and fund
//! payouts are transfers, and must not be counted as additional issuance.

use std::collections::{BTreeMap, VecDeque};

pub const INITIAL_REWARD: u64 = 3_394_524_515;
pub const EPOCH_BLOCKS: u64 = 4_032;
pub const TAIL_REWARD: u64 = 100_000_000;
pub const TAIL_REWARD_60_SECONDS: u64 = 20_000_000;
pub const COINBASE_MATURITY: u64 = 24;
pub const BLOCKS_PER_DAY: u64 = 288;
/// A projection year is exactly 365 protocol days, not a calendar anniversary.
pub const BLOCKS_PER_YEAR: u64 = 365 * BLOCKS_PER_DAY;
pub const FUND_VESTING_DAYS: u64 = 1_461;
pub const HOLDER_UNLOCK_OFFSETS: [u64; 4] = [52_560, 105_120, 157_680, 210_240];
pub const POOL_PAYOUT_DIVISOR: u128 = 4_032;
pub const MAX_FUND_WALLETS: usize = 32;
pub const FUND_BASIS_POINTS: u16 = 10_000;
/// Version 3 claims the pre-block Holder balance before adding block credits.
pub const ECONOMICS_RULE_VERSION: u16 = 3;
const DECAY_Q32: u64 = crate::params::DECAY_Q32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EconomicsError {
    InvalidHeight,
    NonConsecutiveHeight,
    InvalidParameters,
    UnconfiguredFund,
    InvalidMode,
    InvalidAmount,
    Overflow,
    FundCounter,
    FundOverdraft,
    InvalidFundAccount,
    SupplyMismatch,
    RewardMismatch,
}
impl std::fmt::Display for EconomicsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidHeight => "subsidy requires a positive block height",
            Self::NonConsecutiveHeight => "economic transition height is not consecutive",
            Self::InvalidParameters => "invalid immutable economic timing parameters",
            Self::UnconfiguredFund => "development fund allocation is not configured",
            Self::InvalidMode => "unknown reward mode",
            Self::InvalidAmount => "fund expenditure must be positive",
            Self::Overflow => "economic accounting overflow",
            Self::FundCounter => "fund expenditure counter is not the next counter",
            Self::FundOverdraft => "fund expenditure exceeds unlocked unspent entitlement",
            Self::InvalidFundAccount => "fund wallet index is not configured",
            Self::SupplyMismatch => "subsidy conservation invariant failed",
            Self::RewardMismatch => "reward notes differ from the selected mode allocation",
        })
    }
}
impl std::error::Error for EconomicsError {}

type Result<T> = std::result::Result<T, EconomicsError>;

/// Immutable timings that must be authenticated by a network's genesis rules.
/// Compressed engineering schedules have a distinct canonical encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EconomicsParams {
    pub maturity: u64,
    pub holder_unlock_offsets: [u64; 4],
    pub blocks_per_day: u64,
    pub fund_vesting_days: u64,
}
impl EconomicsParams {
    pub const fn production() -> Self {
        Self {
            maturity: COINBASE_MATURITY,
            holder_unlock_offsets: HOLDER_UNLOCK_OFFSETS,
            blocks_per_day: BLOCKS_PER_DAY,
            fund_vesting_days: FUND_VESTING_DAYS,
        }
    }
    /// Only unlock intervals are compressed; issuance and maturity are unchanged.
    pub fn engineering(holder_unlock_offsets: [u64; 4], fund_vesting_days: u64) -> Result<Self> {
        let params = Self {
            holder_unlock_offsets,
            fund_vesting_days,
            ..Self::production()
        };
        params.validate()?;
        Ok(params)
    }
    pub fn validate(&self) -> Result<()> {
        if self.maturity != COINBASE_MATURITY
            || self.blocks_per_day != BLOCKS_PER_DAY
            || !(1..=FUND_VESTING_DAYS).contains(&self.fund_vesting_days)
            || self.holder_unlock_offsets[0] <= self.maturity
            || self.holder_unlock_offsets.windows(2).any(|w| w[0] >= w[1])
            || self
                .holder_unlock_offsets
                .iter()
                .zip(HOLDER_UNLOCK_OFFSETS)
                .any(|(a, b)| *a > b)
        {
            return Err(EconomicsError::InvalidParameters);
        }
        Ok(())
    }
    /// Seven little-endian u64 values; caller binds this to versioned rules.
    pub fn canonical_bytes(&self) -> [u8; 56] {
        let values = [
            self.maturity,
            self.holder_unlock_offsets[0],
            self.holder_unlock_offsets[1],
            self.holder_unlock_offsets[2],
            self.holder_unlock_offsets[3],
            self.blocks_per_day,
            self.fund_vesting_days,
        ];
        let mut bytes = [0; 56];
        for (chunk, value) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(values) {
            chunk.copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }
}

/// Exact wallet shares within the ten-percent subsidy fund allocation.
/// There is no default count, ratio, key or address. Every wallet has an
/// independent entitlement and expenditure budget. Key authentication belongs
/// to the network configuration, outside this arithmetic interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundAllocation {
    basis_points: Vec<u16>,
    team_index: usize,
}
impl FundAllocation {
    pub fn new_bps(basis_points: Vec<u16>, team_index: usize) -> Result<Self> {
        if basis_points.is_empty()
            || basis_points.len() > MAX_FUND_WALLETS
            || team_index >= basis_points.len()
            || basis_points.contains(&0)
        {
            return Err(EconomicsError::InvalidParameters);
        }
        let sum = basis_points
            .iter()
            .try_fold(0u32, |sum, share| sum.checked_add(u32::from(*share)))
            .ok_or(EconomicsError::Overflow)?;
        if sum != u32::from(FUND_BASIS_POINTS) {
            return Err(EconomicsError::InvalidParameters);
        }
        Ok(Self {
            basis_points,
            team_index,
        })
    }
    pub fn basis_points(&self) -> &[u16] {
        &self.basis_points
    }
    pub fn team_index(&self) -> usize {
        self.team_index
    }
    /// Heap capacity owned by the shares, excluding the inline allocation.
    pub fn owned_bytes(&self) -> Option<usize> {
        self.basis_points
            .capacity()
            .checked_mul(std::mem::size_of::<u16>())
    }
    pub fn credits(&self, subsidy: u64) -> Vec<u64> {
        let total_fund = subsidy / 10;
        let mut credits: Vec<_> = self
            .basis_points
            .iter()
            .map(|share| {
                (u128::from(total_fund) * u128::from(*share) / u128::from(FUND_BASIS_POINTS)) as u64
            })
            .collect();
        // Exact positive basis points sum to 10,000, so floors cannot exceed
        // total_fund, and assigning their remainder cannot overflow any share.
        let residual = total_fund - credits.iter().sum::<u64>();
        credits[self.team_index] += residual;
        credits
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RewardMode {
    Voyager,
    Holder,
}
impl RewardMode {
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Voyager => 0,
            Self::Holder => 1,
        }
    }
    pub fn from_byte(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Voyager),
            1 => Ok(Self::Holder),
            _ => Err(EconomicsError::InvalidMode),
        }
    }
    pub const fn name(self) -> &'static str {
        match self {
            Self::Voyager => "voyager",
            Self::Holder => "holder",
        }
    }
    pub fn from_name(value: &str) -> Result<Self> {
        match value {
            "voyager" => Ok(Self::Voyager),
            "holder" => Ok(Self::Holder),
            _ => Err(EconomicsError::InvalidMode),
        }
    }
}

pub fn epoch_of(height: u64) -> Result<u64> {
    height
        .checked_sub(1)
        .map(|h| h / EPOCH_BLOCKS)
        .ok_or(EconomicsError::InvalidHeight)
}
fn decay(reward: u64) -> u64 {
    ((u128::from(reward) * u128::from(DECAY_Q32)) >> 32) as u64
}
fn reward_at_epoch(epoch: u64) -> u64 {
    let mut reward = INITIAL_REWARD;
    for _ in 0..epoch {
        if reward == TAIL_REWARD {
            break;
        }
        reward = decay(reward).max(TAIL_REWARD);
    }
    reward
}
pub fn subsidy(height: u64) -> Result<u64> {
    Ok(reward_at_epoch(epoch_of(height)?))
}
pub fn fee_base(height: u64) -> Result<u64> {
    Ok(subsidy(height)? / crate::params::FEE_BASE_DIVISOR)
}
pub fn fee_priority(height: u64) -> Result<u64> {
    fee_base(height)?
        .checked_mul(crate::params::FEE_PRIORITY_MULT)
        .ok_or(EconomicsError::Overflow)
}
pub fn tail_entry_epoch() -> u64 {
    let mut reward = INITIAL_REWARD;
    let mut epoch = 0;
    while reward > TAIL_REWARD {
        reward = decay(reward).max(TAIL_REWARD);
        epoch += 1;
    }
    epoch
}
pub fn tail_entry_height() -> u64 {
    tail_entry_epoch() * EPOCH_BLOCKS + 1
}

/// Expected private note amount. Index must also bind distinct reward rho values
/// in the settlement relation; using height alone would reuse nullifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RewardNote {
    pub index: u8,
    pub amount: u64,
    pub unlock_height: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RewardAllocation {
    pub height: u64,
    pub mode: RewardMode,
    pub subsidy: u64,
    pub miner_base: u64,
    pub fund_credit: Vec<u64>,
    pub protocol_pool_credit: u64,
    pub mode_pool_credit: u64,
    pub pool_before: u128,
    pub pool_payout: u64,
    pub pool_after: u128,
    pub burn: u64,
    /// Subsidy only. Confidential fees are added to note zero by settlement.
    pub reward_notes: Vec<RewardNote>,
}
impl RewardAllocation {
    pub fn miner_subsidy_credit(&self) -> u128 {
        self.reward_notes.iter().map(|n| u128::from(n.amount)).sum()
    }
    pub fn verify_reward_notes(&self, actual: &[RewardNote]) -> Result<()> {
        if self.reward_notes == actual {
            Ok(())
        } else {
            Err(EconomicsError::RewardMismatch)
        }
    }
    pub fn check_conservation(&self) -> Result<()> {
        let available = self
            .pool_before
            .checked_add(u128::from(self.subsidy))
            .ok_or(EconomicsError::Overflow)?;
        let accounted = self
            .miner_subsidy_credit()
            .checked_add(self.pool_after)
            .and_then(|v| v.checked_add(u128::from(self.burn)))
            .and_then(|v| {
                self.fund_credit
                    .iter()
                    .try_fold(v, |sum, credit| sum.checked_add(u128::from(*credit)))
            })
            .ok_or(EconomicsError::Overflow)?;
        if available == accounted {
            Ok(())
        } else {
            Err(EconomicsError::SupplyMismatch)
        }
    }
}
fn percent(amount: u64, numerator: u64) -> u64 {
    (u128::from(amount) * u128::from(numerator) / 100) as u64
}

/// Allocate one subsidy by claiming the pre-block pool before crediting it.
/// The fund receives floor(subsidy / 10), with wallet split residuals assigned
/// to its configured team wallet. Other splits round down to the miner note.
pub fn allocate_reward(
    params: &EconomicsParams,
    funds: &FundAllocation,
    height: u64,
    mode: RewardMode,
    subsidy: u64,
    pool_before: u128,
) -> Result<RewardAllocation> {
    params.validate()?;
    if height == 0 {
        return Err(EconomicsError::InvalidHeight);
    }
    let fund_credit = funds.credits(subsidy);
    let total_fund: u64 = fund_credit.iter().sum();
    let protocol_pool_credit = percent(subsidy, 3);
    let miner_base = subsidy - total_fund - protocol_pool_credit;
    let mut pool_after = pool_before;
    let mut mode_pool_credit = 0;
    let mut pool_payout = 0;
    let mut burn = 0;
    let mut reward_notes = Vec::with_capacity(if mode == RewardMode::Holder { 5 } else { 1 });
    let immediate = match mode {
        RewardMode::Voyager => {
            burn = percent(miner_base, 5);
            mode_pool_credit = percent(miner_base, 20);
            pool_after = pool_after
                .checked_add(u128::from(mode_pool_credit))
                .ok_or(EconomicsError::Overflow)?;
            miner_base - burn - mode_pool_credit
        }
        RewardMode::Holder => {
            let payout = pool_after / POOL_PAYOUT_DIVISOR;
            pool_payout = u64::try_from(payout).map_err(|_| EconomicsError::Overflow)?;
            pool_after -= payout;
            (miner_base - 4 * (miner_base / 10))
                .checked_add(pool_payout)
                .ok_or(EconomicsError::Overflow)?
        }
    };
    pool_after = pool_after
        .checked_add(u128::from(protocol_pool_credit))
        .ok_or(EconomicsError::Overflow)?;
    reward_notes.push(RewardNote {
        index: 0,
        amount: immediate,
        unlock_height: height
            .checked_add(params.maturity)
            .ok_or(EconomicsError::Overflow)?,
    });
    if mode == RewardMode::Holder {
        for (index, offset) in params.holder_unlock_offsets.iter().enumerate() {
            reward_notes.push(RewardNote {
                index: (index + 1) as u8,
                amount: miner_base / 10,
                unlock_height: height
                    .checked_add(*offset)
                    .ok_or(EconomicsError::Overflow)?,
            });
        }
    }
    let allocation = RewardAllocation {
        height,
        mode,
        subsidy,
        miner_base,
        fund_credit,
        protocol_pool_credit,
        mode_pool_credit,
        pool_before,
        pool_payout,
        pool_after,
        burn,
        reward_notes,
    };
    allocation.check_conservation()?;
    Ok(allocation)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FundAccount(u8);
impl FundAccount {
    pub const FIRST: Self = Self(0);
    pub const SECOND: Self = Self(1);
    pub fn new(index: usize) -> Result<Self> {
        if index >= MAX_FUND_WALLETS {
            return Err(EconomicsError::InvalidFundAccount);
        }
        Ok(Self(index as u8))
    }
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FundBalance {
    pub entitlement: u128,
    pub direct_unlocked: u128,
    pub vesting_unlocked: u128,
    pub spent: u128,
    /// The zero-based next expenditure counter for this account.
    pub spend_count: u64,
}
impl FundBalance {
    pub fn unlocked(&self) -> Result<u128> {
        self.direct_unlocked
            .checked_add(self.vesting_unlocked)
            .ok_or(EconomicsError::Overflow)
    }
    pub fn available(&self) -> Result<u128> {
        self.unlocked()?
            .checked_sub(self.spent)
            .ok_or(EconomicsError::FundOverdraft)
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EconomicsTotals {
    pub issued: u128,
    /// Cumulative subsidy note credits, including pool payments, excluding fees.
    pub miner_subsidy_credited: u128,
    pub holder_pool: u128,
    pub burned: u128,
    /// Scheduled immature/locked miner subsidy, excluding private voluntary locks.
    pub locked_subsidy: u128,
}

/// A consecutive credit interval with identical per-block fund amounts.
/// At most roughly 106 issuance cohorts need remain under production timings.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FundCohort {
    start: u64,
    end: u64,
    credit: Vec<u64>,
}
impl FundCohort {
    fn direct(&self, index: usize) -> u64 {
        self.credit[index] / 2
    }
    fn vested(&self, index: usize) -> u64 {
        self.credit[index] - self.direct(index)
    }
}

/// Public subsidy ledger. Consensus callers authenticate signatures separately.
/// Advance the candidate ledger to block H before checking its expenditures:
/// credit h is directly spendable in block h+24. Failure never mutates state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EconomicsLedger {
    params: EconomicsParams,
    height: u64,
    current_subsidy: u64,
    totals: EconomicsTotals,
    funds: Vec<FundBalance>,
    fund_allocation: Option<FundAllocation>,
    locked_schedule: BTreeMap<u64, u128>,
    fund_cohorts: VecDeque<FundCohort>,
}
impl EconomicsLedger {
    pub fn new(params: EconomicsParams) -> Result<Self> {
        params.validate()?;
        Ok(Self {
            params,
            height: 0,
            current_subsidy: INITIAL_REWARD,
            totals: EconomicsTotals::default(),
            funds: Vec::new(),
            fund_allocation: None,
            locked_schedule: BTreeMap::new(),
            fund_cohorts: VecDeque::new(),
        })
    }
    /// Configure immutable per-wallet arithmetic before the first block.
    pub fn with_fund_allocation(mut self, allocation: FundAllocation) -> Result<Self> {
        if self.height != 0 || self.fund_allocation.is_some() {
            return Err(EconomicsError::InvalidParameters);
        }
        self.funds = vec![FundBalance::default(); allocation.basis_points().len()];
        self.fund_allocation = Some(allocation);
        Ok(self)
    }
    pub fn params(&self) -> &EconomicsParams {
        &self.params
    }
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn totals(&self) -> EconomicsTotals {
        self.totals
    }
    pub fn fund(&self, account: FundAccount) -> Result<FundBalance> {
        self.funds
            .get(account.index())
            .copied()
            .ok_or(EconomicsError::InvalidFundAccount)
    }
    pub fn funds(&self) -> &[FundBalance] {
        &self.funds
    }
    pub fn fund_allocation(&self) -> Option<&FundAllocation> {
        self.fund_allocation.as_ref()
    }
    pub fn locked_schedule(&self) -> &BTreeMap<u64, u128> {
        &self.locked_schedule
    }

    /// Conservative owned-data accounting for a caller's local resource policy.
    /// This is not an allocator or process resident-memory measurement.
    pub fn logical_memory_bytes(&self) -> Option<usize> {
        let cohort_data = self.fund_cohorts.iter().try_fold(0usize, |total, cohort| {
            total.checked_add(
                cohort
                    .credit
                    .capacity()
                    .checked_mul(std::mem::size_of::<u64>())?,
            )
        })?;
        let allocation_data = self
            .fund_allocation
            .as_ref()
            .map_or(Some(0), FundAllocation::owned_bytes)?;
        self.locked_schedule
            .len()
            .checked_mul(128)?
            .checked_add(
                self.fund_cohorts
                    .capacity()
                    .checked_mul(std::mem::size_of::<FundCohort>())?,
            )?
            .checked_add(cohort_data)?
            .checked_add(allocation_data)?
            .checked_add(
                self.funds
                    .capacity()
                    .checked_mul(std::mem::size_of::<FundBalance>())?,
            )?
            .checked_add(std::mem::size_of::<Self>())
    }

    /// Stream every field, including future release schedules, into a caller's
    /// authenticated state encoding without allocating a second schedule copy.
    pub fn visit_encoding(&self, emit: &mut impl FnMut(&[u8])) {
        emit(&ECONOMICS_RULE_VERSION.to_le_bytes());
        emit(&self.params.canonical_bytes());
        emit(&self.height.to_le_bytes());
        emit(&self.current_subsidy.to_le_bytes());
        emit(&[u8::from(self.fund_allocation.is_some())]);
        if let Some(allocation) = &self.fund_allocation {
            emit(&(allocation.basis_points().len() as u16).to_le_bytes());
            emit(&(allocation.team_index() as u16).to_le_bytes());
            for share in allocation.basis_points() {
                emit(&share.to_le_bytes());
            }
        }
        for value in [
            self.totals.issued,
            self.totals.miner_subsidy_credited,
            self.totals.holder_pool,
            self.totals.burned,
            self.totals.locked_subsidy,
        ] {
            emit(&value.to_le_bytes());
        }
        emit(&(self.funds.len() as u16).to_le_bytes());
        for fund in &self.funds {
            for value in [
                fund.entitlement,
                fund.direct_unlocked,
                fund.vesting_unlocked,
                fund.spent,
            ] {
                emit(&value.to_le_bytes());
            }
            emit(&fund.spend_count.to_le_bytes());
        }
        emit(&(self.locked_schedule.len() as u64).to_le_bytes());
        for (height, amount) in &self.locked_schedule {
            emit(&height.to_le_bytes());
            emit(&amount.to_le_bytes());
        }
        emit(&(self.fund_cohorts.len() as u64).to_le_bytes());
        for cohort in &self.fund_cohorts {
            emit(&cohort.start.to_le_bytes());
            emit(&cohort.end.to_le_bytes());
            for credit in &cohort.credit {
                emit(&credit.to_le_bytes());
            }
        }
    }

    /// Check lifetime subsidy creation without counting a transfer twice.
    pub fn assert_supply_invariant(&self) -> Result<()> {
        let accounted = self
            .totals
            .miner_subsidy_credited
            .checked_add(self.totals.holder_pool)
            .and_then(|v| v.checked_add(self.totals.burned))
            .and_then(|v| {
                self.funds
                    .iter()
                    .try_fold(v, |total, fund| total.checked_add(fund.entitlement))
            })
            .ok_or(EconomicsError::Overflow)?;
        if accounted != self.totals.issued
            || self.totals.locked_subsidy > self.totals.miner_subsidy_credited
        {
            return Err(EconomicsError::SupplyMismatch);
        }
        if self
            .fund_allocation
            .as_ref()
            .map_or(0, |allocation| allocation.basis_points().len())
            != self.funds.len()
        {
            return Err(EconomicsError::SupplyMismatch);
        }
        for fund in &self.funds {
            if fund.unlocked()? > fund.entitlement || fund.spent > fund.unlocked()? {
                return Err(EconomicsError::SupplyMismatch);
            }
        }
        Ok(())
    }

    /// Scheduled supply estimate. Private voluntarily locked transaction notes
    /// cannot be counted by a public ledger and are excluded from this measure.
    pub fn scheduled_circulating(&self) -> Result<u128> {
        let mut unavailable = self
            .totals
            .holder_pool
            .checked_add(self.totals.burned)
            .and_then(|v| v.checked_add(self.totals.locked_subsidy))
            .ok_or(EconomicsError::Overflow)?;
        for fund in &self.funds {
            let locked = fund
                .entitlement
                .checked_sub(fund.unlocked()?)
                .ok_or(EconomicsError::SupplyMismatch)?;
            unavailable = unavailable
                .checked_add(locked)
                .ok_or(EconomicsError::Overflow)?;
        }
        self.totals
            .issued
            .checked_sub(unavailable)
            .ok_or(EconomicsError::SupplyMismatch)
    }

    /// Exact daily release increments, telescoped over equal-credit intervals.
    /// For a deposit, day d releases floor(v*d/T)-floor(v*(d-1)/T).
    fn fund_release_increment(&self, height: u64) -> Result<Vec<u128>> {
        let day = self.params.blocks_per_day;
        let duration = self.params.fund_vesting_days;
        let mut total = vec![0u128; self.funds.len()];
        for cohort in &self.fund_cohorts {
            let first_day = height.saturating_sub(cohort.end).div_ceil(day).max(1);
            let last_day = height.saturating_sub(cohort.start) / day;
            let last_day = last_day.min(duration);
            if first_day <= last_day {
                let mut previous_credit = None;
                let mut released = 0;
                for (index, total) in total.iter_mut().enumerate() {
                    let value = cohort.vested(index);
                    // Adjacent equal shares have identical per-deposit release
                    // increments; reuse the arithmetic without merging ledgers.
                    if previous_credit != Some(value) {
                        released = u128::from(value) * u128::from(last_day) / u128::from(duration)
                            - u128::from(value) * u128::from(first_day - 1) / u128::from(duration);
                        previous_credit = Some(value);
                    }
                    *total = total
                        .checked_add(released)
                        .ok_or(EconomicsError::Overflow)?;
                }
            }
        }
        Ok(total)
    }

    pub fn advance(&mut self, height: u64, mode: RewardMode) -> Result<RewardAllocation> {
        if self.height.checked_add(1) != Some(height) {
            return Err(EconomicsError::NonConsecutiveHeight);
        }
        self.assert_supply_invariant()?;
        let reward = if self.height != 0 && (height - 1).is_multiple_of(EPOCH_BLOCKS) {
            decay(self.current_subsidy).max(TAIL_REWARD)
        } else {
            self.current_subsidy
        };
        let fund_allocation = self
            .fund_allocation
            .as_ref()
            .ok_or(EconomicsError::UnconfiguredFund)?;
        let allocation = allocate_reward(
            &self.params,
            fund_allocation,
            height,
            mode,
            reward,
            self.totals.holder_pool,
        )?;
        let credits = &allocation.fund_credit;
        if credits.len() != self.funds.len() {
            return Err(EconomicsError::InvalidParameters);
        }
        let release = self.fund_release_increment(height)?;
        let matured = height
            .checked_sub(self.params.maturity)
            .filter(|h| *h > 0)
            .and_then(|h| {
                self.fund_cohorts
                    .iter()
                    .rev()
                    .find(|c| c.start <= h && h <= c.end)
            });
        let mut funds = self.funds.clone();
        for (index, fund) in funds.iter_mut().enumerate() {
            fund.entitlement = fund
                .entitlement
                .checked_add(u128::from(credits[index]))
                .ok_or(EconomicsError::Overflow)?;
            fund.direct_unlocked = fund
                .direct_unlocked
                .checked_add(u128::from(matured.map_or(0, |cohort| cohort.direct(index))))
                .ok_or(EconomicsError::Overflow)?;
            fund.vesting_unlocked = fund
                .vesting_unlocked
                .checked_add(release[index])
                .ok_or(EconomicsError::Overflow)?;
            if fund.unlocked()? > fund.entitlement {
                return Err(EconomicsError::SupplyMismatch);
            }
        }
        let scheduled_new: u128 = allocation
            .reward_notes
            .iter()
            .map(|n| u128::from(n.amount))
            .sum();
        let unlock_now = self.locked_schedule.get(&height).copied().unwrap_or(0);
        let totals = EconomicsTotals {
            issued: self
                .totals
                .issued
                .checked_add(u128::from(reward))
                .ok_or(EconomicsError::Overflow)?,
            miner_subsidy_credited: self
                .totals
                .miner_subsidy_credited
                .checked_add(scheduled_new)
                .ok_or(EconomicsError::Overflow)?,
            holder_pool: allocation.pool_after,
            burned: self
                .totals
                .burned
                .checked_add(u128::from(allocation.burn))
                .ok_or(EconomicsError::Overflow)?,
            locked_subsidy: self
                .totals
                .locked_subsidy
                .checked_sub(unlock_now)
                .and_then(|v| v.checked_add(scheduled_new))
                .ok_or(EconomicsError::Overflow)?,
        };
        let mut updates = Vec::with_capacity(allocation.reward_notes.len());
        for note in &allocation.reward_notes {
            let value = self
                .locked_schedule
                .get(&note.unlock_height)
                .copied()
                .unwrap_or(0)
                .checked_add(u128::from(note.amount))
                .ok_or(EconomicsError::Overflow)?;
            updates.push((note.unlock_height, value));
        }
        let duration = self
            .params
            .fund_vesting_days
            .checked_mul(self.params.blocks_per_day)
            .ok_or(EconomicsError::Overflow)?;
        let retired = self
            .fund_cohorts
            .iter()
            .take_while(|c| height.saturating_sub(c.end) >= duration)
            .count();
        // Every fallible calculation has completed. Mutate only after preflight.
        self.height = height;
        self.current_subsidy = reward;
        self.totals = totals;
        self.funds = funds;
        self.locked_schedule.remove(&height);
        for (unlock, amount) in updates {
            self.locked_schedule.insert(unlock, amount);
        }
        for _ in 0..retired {
            self.fund_cohorts.pop_front();
        }
        if let Some(last) = self
            .fund_cohorts
            .back_mut()
            .filter(|c| &c.credit == credits)
        {
            last.end = height;
        } else {
            self.fund_cohorts.push_back(FundCohort {
                start: height,
                end: height,
                credit: credits.clone(),
            });
        }
        Ok(allocation)
    }

    /// This check does not authenticate an ML-DSA signature or consume a counter.
    pub fn check_fund_spend(&self, account: FundAccount, amount: u128, counter: u64) -> Result<()> {
        let fund = self.fund(account)?;
        if amount == 0 {
            return Err(EconomicsError::InvalidAmount);
        }
        if counter != fund.spend_count {
            return Err(EconomicsError::FundCounter);
        }
        if amount > fund.available()? {
            return Err(EconomicsError::FundOverdraft);
        }
        fund.spent
            .checked_add(amount)
            .ok_or(EconomicsError::Overflow)?;
        fund.spend_count
            .checked_add(1)
            .ok_or(EconomicsError::Overflow)?;
        Ok(())
    }
    pub fn spend_fund(&mut self, account: FundAccount, amount: u128, counter: u64) -> Result<()> {
        self.check_fund_spend(account, amount, counter)?;
        let fund = &mut self.funds[account.index()];
        fund.spent += amount;
        fund.spend_count += 1;
        Ok(())
    }
    /// Apply a caller-bounded list of independently authenticated claims.
    /// A later invalid claim leaves every wallet and counter unchanged.
    pub fn spend_funds(&mut self, claims: &[(FundAccount, u128, u64)]) -> Result<()> {
        let mut funds = self.funds.clone();
        for (account, amount, counter) in claims {
            let fund = funds
                .get_mut(account.index())
                .ok_or(EconomicsError::InvalidFundAccount)?;
            if *amount == 0 {
                return Err(EconomicsError::InvalidAmount);
            }
            if *counter != fund.spend_count {
                return Err(EconomicsError::FundCounter);
            }
            if *amount > fund.available()? {
                return Err(EconomicsError::FundOverdraft);
            }
            fund.spent = fund
                .spent
                .checked_add(*amount)
                .ok_or(EconomicsError::Overflow)?;
            fund.spend_count = fund
                .spend_count
                .checked_add(1)
                .ok_or(EconomicsError::Overflow)?;
        }
        self.funds = funds;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmissionProjection {
    pub height: u64,
    pub issued: u128,
    pub last_subsidy: u64,
}
/// Sum complete epoch intervals, then one constant tail interval. Cost depends
/// on the finite decay schedule, never on the number of simulated blocks.
pub fn project_blocks(blocks: u64) -> Result<EmissionProjection> {
    let mut remaining = blocks;
    let mut reward = INITIAL_REWARD;
    let mut issued = 0u128;
    let mut last_subsidy = 0;
    while remaining > 0 {
        let count = if reward == TAIL_REWARD {
            remaining
        } else {
            remaining.min(EPOCH_BLOCKS)
        };
        issued = issued
            .checked_add(u128::from(reward) * u128::from(count))
            .ok_or(EconomicsError::Overflow)?;
        remaining -= count;
        last_subsidy = reward;
        reward = decay(reward).max(TAIL_REWARD);
    }
    Ok(EmissionProjection {
        height: blocks,
        issued,
        last_subsidy,
    })
}
pub fn project_years(years: u64) -> Result<EmissionProjection> {
    project_blocks(
        years
            .checked_mul(BLOCKS_PER_YEAR)
            .ok_or(EconomicsError::Overflow)?,
    )
}

#[cfg(test)]
#[path = "v1_economics_tests.rs"]
mod tests;
