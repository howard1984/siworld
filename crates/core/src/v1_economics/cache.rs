//! Local authenticated checkpoint decoding; this does not authenticate history.
use super::*;

impl EconomicsLedger {
    /// The caller must authenticate every byte to a previously verified local
    /// checkpoint before invoking this decoder. Shape checks are not proofs.
    pub fn from_authenticated_encoding(
        bytes: &[u8],
        params: EconomicsParams,
        allocation: Option<FundAllocation>,
    ) -> Result<Self> {
        struct Reader<'a>(&'a [u8]);
        impl Reader<'_> {
            fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
                let (head, tail) = self
                    .0
                    .split_at_checked(N)
                    .ok_or(EconomicsError::InvalidParameters)?;
                self.0 = tail;
                head.try_into()
                    .map_err(|_| EconomicsError::InvalidParameters)
            }
            fn u16(&mut self) -> Result<u16> {
                Ok(u16::from_le_bytes(self.take()?))
            }
            fn u64(&mut self) -> Result<u64> {
                Ok(u64::from_le_bytes(self.take()?))
            }
            fn u128(&mut self) -> Result<u128> {
                Ok(u128::from_le_bytes(self.take()?))
            }
        }
        params.validate()?;
        let mut r = Reader(bytes);
        if r.u16()? != ECONOMICS_RULE_VERSION || r.take::<56>()? != params.canonical_bytes() {
            return Err(EconomicsError::InvalidParameters);
        }
        let height = r.u64()?;
        let current_subsidy = r.u64()?;
        let has_allocation = r.take::<1>()?[0];
        if has_allocation > 1 || (has_allocation == 1) != allocation.is_some() {
            return Err(EconomicsError::InvalidParameters);
        }
        if let Some(expected) = &allocation {
            let count = usize::from(r.u16()?);
            let team = usize::from(r.u16()?);
            if count != expected.basis_points().len() || team != expected.team_index() {
                return Err(EconomicsError::InvalidParameters);
            }
            for share in expected.basis_points() {
                if r.u16()? != *share {
                    return Err(EconomicsError::InvalidParameters);
                }
            }
        }
        let totals = EconomicsTotals {
            issued: r.u128()?,
            miner_subsidy_credited: r.u128()?,
            holder_pool: r.u128()?,
            burned: r.u128()?,
            locked_subsidy: r.u128()?,
        };
        let count = usize::from(r.u16()?);
        if count != allocation.as_ref().map_or(0, |a| a.basis_points().len()) {
            return Err(EconomicsError::InvalidParameters);
        }
        let mut funds = Vec::with_capacity(count);
        for _ in 0..count {
            funds.push(FundBalance {
                entitlement: r.u128()?,
                direct_unlocked: r.u128()?,
                vesting_unlocked: r.u128()?,
                spent: r.u128()?,
                spend_count: r.u64()?,
            });
        }
        let locked = r.u64()?;
        if locked > (r.0.len() / 24) as u64 {
            return Err(EconomicsError::InvalidParameters);
        }
        let mut locked_schedule = BTreeMap::new();
        let mut previous = None;
        for _ in 0..locked {
            let at = r.u64()?;
            let amount = r.u128()?;
            if at <= height || amount == 0 || previous.is_some_and(|last| at <= last) {
                return Err(EconomicsError::InvalidParameters);
            }
            locked_schedule.insert(at, amount);
            previous = Some(at);
        }
        let cohorts = r.u64()?;
        let cohort_bytes = 16usize
            .checked_add(8 * count)
            .ok_or(EconomicsError::Overflow)?;
        if cohorts > (r.0.len() / cohort_bytes) as u64 {
            return Err(EconomicsError::InvalidParameters);
        }
        let mut fund_cohorts = VecDeque::new();
        let mut previous = None;
        for _ in 0..cohorts {
            let start = r.u64()?;
            let end = r.u64()?;
            if start == 0
                || start > end
                || end > height
                || previous.is_some_and(|last| start <= last)
            {
                return Err(EconomicsError::InvalidParameters);
            }
            let mut credit = Vec::with_capacity(count);
            for _ in 0..count {
                credit.push(r.u64()?);
            }
            fund_cohorts.push_back(FundCohort { start, end, credit });
            previous = Some(end);
        }
        if !r.0.is_empty() {
            return Err(EconomicsError::InvalidParameters);
        }
        let result = Self {
            params,
            height,
            current_subsidy,
            totals,
            funds,
            fund_allocation: allocation,
            locked_schedule,
            fund_cohorts,
        };
        result.assert_supply_invariant()?;
        let mut canonical = Vec::new();
        result.visit_encoding(&mut |part| canonical.extend_from_slice(part));
        if canonical != bytes {
            return Err(EconomicsError::InvalidParameters);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authenticated_cache_preserves_future_holder_rewards_and_fund_balances() {
        let allocation = FundAllocation::new_bps(vec![7000, 3000], 1).unwrap();
        let mut original = EconomicsLedger::new(EconomicsParams::production())
            .unwrap()
            .with_fund_allocation(allocation.clone())
            .unwrap();
        for h in 1..=50 {
            original
                .advance(
                    h,
                    if h % 2 == 0 {
                        RewardMode::Holder
                    } else {
                        RewardMode::Voyager
                    },
                )
                .unwrap();
        }
        let mut encoded = Vec::new();
        original.visit_encoding(&mut |part| encoded.extend_from_slice(part));
        let mut restored = EconomicsLedger::from_authenticated_encoding(
            &encoded,
            original.params().clone(),
            Some(allocation),
        )
        .unwrap();
        assert_eq!(original, restored);
        assert!(
            EconomicsLedger::from_authenticated_encoding(
                &encoded[..encoded.len() - 1],
                original.params().clone(),
                original.fund_allocation().cloned()
            )
            .is_err()
        );
        for h in 51..=80 {
            assert_eq!(
                original.advance(h, RewardMode::Holder).unwrap(),
                restored.advance(h, RewardMode::Holder).unwrap()
            );
            assert_eq!(original, restored);
        }
    }
}
