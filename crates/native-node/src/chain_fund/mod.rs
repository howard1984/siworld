//! Integer-only development-fund accounting for the separately activated network.
//! Authentication and recipient verification precede this arithmetic interface.
use crate::wire::Hash;
use siworld_core::v1_economics::{FundAllocation, FundBalance, MAX_FUND_WALLETS};

pub const DIRECT_DELAY_BLOCKS: u64 = 24;
pub const MONTH_BLOCKS: u64 = 8766;
pub const MONTHS: u64 = 48;
pub const VESTING_BLOCKS: u64 = MONTH_BLOCKS * MONTHS;
mod codec;

fn require(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn add(left: u128, right: u128) -> Result<u128, String> {
    left.checked_add(right)
        .ok_or("fund accounting overflow".into())
}
fn monthly_delta(locked: u64, month: u64) -> u128 {
    let locked = u128::from(locked);
    locked * u128::from(month) / u128::from(MONTHS)
        - locked * u128::from(month - 1) / u128::from(MONTHS)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Cohort {
    start: u64,
    end: u64,
    credits: Vec<u64>,
}
impl Cohort {
    fn count_through(&self, height: u64) -> u128 {
        if height < self.start {
            0
        } else {
            u128::from(self.end.min(height) - self.start + 1)
        }
    }
    fn outstanding(&self, member: usize, height: u64) -> Result<(u128, u128), String> {
        let credit = self.credits[member];
        let direct = credit / 2;
        let locked = credit - direct;
        let direct_released = height
            .checked_sub(DIRECT_DELAY_BLOCKS)
            .map_or(0, |h| self.count_through(h) * u128::from(direct));
        let mut monthly_released = 0;
        for month in 1..=MONTHS {
            if let Some(h) = height.checked_sub(month * MONTH_BLOCKS) {
                monthly_released = add(
                    monthly_released,
                    self.count_through(h) * monthly_delta(locked, month),
                )?;
            }
        }
        let count = self.count_through(self.end);
        Ok((
            (count * u128::from(direct))
                .checked_sub(direct_released)
                .ok_or("fund direct release exceeds credits")?,
            (count * u128::from(locked))
                .checked_sub(monthly_released)
                .ok_or("fund monthly release exceeds credits")?,
        ))
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundLedger {
    network: Hash,
    height: u64,
    allocation: FundAllocation,
    total_entitlement: u128,
    balances: Vec<FundBalance>,
    direct_entitlement: Vec<u128>,
    cohorts: Vec<Cohort>,
}
impl FundLedger {
    pub fn new(network: Hash, allocation: FundAllocation) -> Result<Self, String> {
        let ledger = Self {
            network,
            height: 0,
            balances: vec![FundBalance::default(); allocation.basis_points().len()],
            direct_entitlement: vec![0; allocation.basis_points().len()],
            allocation,
            total_entitlement: 0,
            cohorts: Vec::new(),
        };
        ledger.validate()?;
        Ok(ledger)
    }
    pub fn network(&self) -> Hash {
        self.network
    }
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn total_entitlement(&self) -> u128 {
        self.total_entitlement
    }
    pub fn balance(&self, member: u8) -> Result<FundBalance, String> {
        self.balances
            .get(usize::from(member))
            .copied()
            .ok_or("unknown fund member".into())
    }
    /// Advance before claims at this height. The enclosing block transition
    /// authenticates the subsidy and stages this ledger with all other state.
    pub fn advance(&mut self, height: u64, subsidy: u64) -> Result<(), String> {
        require(
            self.height.checked_add(1) == Some(height),
            "fund height must advance exactly one block",
        )?;
        let mut staged = self.clone();
        let credits = staged.allocation.credits(subsidy);
        let at = |h: u64| self.cohorts.iter().find(|c| c.start <= h && h <= c.end);
        for (member, balance) in staged.balances.iter_mut().enumerate() {
            balance.entitlement = add(balance.entitlement, u128::from(credits[member]))?;
            staged.direct_entitlement[member] = add(
                staged.direct_entitlement[member],
                u128::from(credits[member] / 2),
            )?;
            let direct = height
                .checked_sub(DIRECT_DELAY_BLOCKS)
                .and_then(at)
                .map_or(0, |c| c.credits[member] / 2);
            balance.direct_unlocked = add(balance.direct_unlocked, u128::from(direct))?;
            for month in 1..=MONTHS {
                if let Some(cohort) = height.checked_sub(month * MONTH_BLOCKS).and_then(at) {
                    let credit = cohort.credits[member];
                    balance.vesting_unlocked = add(
                        balance.vesting_unlocked,
                        monthly_delta(credit - credit / 2, month),
                    )?;
                }
            }
        }
        staged.total_entitlement = add(
            staged.total_entitlement,
            credits.iter().map(|x| u128::from(*x)).sum(),
        )?;
        if credits.iter().any(|credit| *credit != 0) {
            if let Some(last) = staged
                .cohorts
                .last_mut()
                .filter(|last| last.end.checked_add(1) == Some(height) && last.credits == credits)
            {
                last.end = height;
            } else {
                staged.cohorts.push(Cohort {
                    start: height,
                    end: height,
                    credits,
                });
            }
        }
        // The credit that completes period 48 at this height has no remaining
        // lock. Keep only its later neighbors, without changing lifetime totals.
        let earliest = height.saturating_sub(VESTING_BLOCKS) + 1;
        staged.cohorts.retain(|cohort| cohort.end >= earliest);
        if let Some(first) = staged.cohorts.first_mut() {
            first.start = first.start.max(earliest);
        }
        staged.height = height;
        staged.validate()?;
        *self = staged;
        Ok(())
    }
    /// Arithmetic only: the enclosing engine must first construct its verified
    /// claim capability from the immutable member authority and active recipient.
    pub fn spend(&mut self, member: u8, amount: u128, counter: u64) -> Result<(), String> {
        let balance = self.balance(member)?;
        require(
            amount > 0 && counter == balance.spend_count,
            "fund amount or next counter invalid",
        )?;
        require(
            amount <= balance.available().map_err(|e| e.to_string())?,
            "fund claim exceeds unlocked unspent entitlement",
        )?;
        let spent = add(balance.spent, amount)?;
        let count = counter.checked_add(1).ok_or("fund counter overflow")?;
        self.balances[usize::from(member)].spent = spent;
        self.balances[usize::from(member)].spend_count = count;
        Ok(())
    }
    pub fn spend_many(&mut self, claims: &[(u8, u128, u64)]) -> Result<(), String> {
        let mut staged = self.clone();
        for (member, amount, counter) in claims {
            staged.spend(*member, *amount, *counter)?;
        }
        *self = staged;
        Ok(())
    }
    fn validate(&self) -> Result<(), String> {
        require(
            self.network != [0; 32]
                && !self.balances.is_empty()
                && self.balances.len() <= MAX_FUND_WALLETS
                && self.direct_entitlement.len() == self.balances.len()
                && self.balances.len() == self.allocation.basis_points().len(),
            "fund ledger context invalid",
        )?;
        let earliest = self.height.saturating_sub(VESTING_BLOCKS) + 1;
        require(
            self.cohorts.len() <= VESTING_BLOCKS as usize,
            "fund cohort count exceeds active credit heights",
        )?;
        for (index, cohort) in self.cohorts.iter().enumerate() {
            require(
                cohort.start >= earliest
                    && cohort.start > 0
                    && cohort.start <= cohort.end
                    && cohort.end <= self.height
                    && cohort.credits.len() == self.balances.len()
                    && cohort.credits.iter().any(|c| *c != 0),
                "fund cohort context invalid",
            )?;
            if index > 0 {
                let previous = &self.cohorts[index - 1];
                require(
                    previous.end < cohort.start
                        && !(previous.end.checked_add(1) == Some(cohort.start)
                            && previous.credits == cohort.credits),
                    "fund cohorts overlap or are not maximally compressed",
                )?;
            }
        }
        let mut total = 0;
        for (member, balance) in self.balances.iter().enumerate() {
            let released = balance.unlocked().map_err(|e| e.to_string())?;
            require(
                released <= balance.entitlement
                    && balance.spent <= released
                    && ((balance.spent == 0) == (balance.spend_count == 0))
                    && u128::from(balance.spend_count) <= balance.spent,
                "fund balance or counter invariant invalid",
            )?;
            let outstanding =
                self.cohorts
                    .iter()
                    .try_fold((0, 0), |(direct, monthly), cohort| {
                        let (d, m) = cohort.outstanding(member, self.height)?;
                        Ok::<_, String>((add(direct, d)?, add(monthly, m)?))
                    })?;
            let direct_entitlement = self.direct_entitlement[member];
            require(
                direct_entitlement <= balance.entitlement
                    && add(balance.direct_unlocked, outstanding.0)? == direct_entitlement
                    && add(balance.vesting_unlocked, outstanding.1)?
                        == balance.entitlement - direct_entitlement,
                "fund outstanding schedule differs from locked entitlement",
            )?;
            total = add(total, balance.entitlement)?;
        }
        require(
            total == self.total_entitlement,
            "fund aggregate entitlement differs from member totals",
        )?;
        if self.height == 0 {
            require(
                total == 0 && self.cohorts.is_empty(),
                "initial fund ledger is nonempty",
            )?;
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests;
