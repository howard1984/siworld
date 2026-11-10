//! Canonical component-6 reconstruction with fixed network and allocation context.
use super::*;
const MAGIC: &[u8; 8] = b"SWG2FND1";
// At most one cohort per active credit height, with 32 member credits each.
// This bound is derived from the full release horizon, not a smaller cohort cap.
pub const MAX_COMPONENT_BYTES: usize = 8
    + 32
    + 8
    + 24
    + 16
    + 2
    + MAX_FUND_WALLETS * 90
    + 4
    + VESTING_BLOCKS as usize * (16 + 8 * MAX_FUND_WALLETS);

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], String> {
        let (head, tail) = self
            .0
            .split_at_checked(count)
            .ok_or("truncated fund component")?;
        self.0 = tail;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        Ok(self.take(N)?.try_into().expect("bounded fund field"))
    }
    fn byte(&mut self) -> Result<u8, String> {
        Ok(self.array::<1>()?[0])
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn u128(&mut self) -> Result<u128, String> {
        Ok(u128::from_le_bytes(self.array()?))
    }
}
impl FundLedger {
    pub fn canonical_component_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&self.network);
        out.extend_from_slice(&self.height.to_le_bytes());
        for value in [DIRECT_DELAY_BLOCKS, MONTH_BLOCKS, MONTHS] {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out.extend_from_slice(&self.total_entitlement.to_le_bytes());
        out.extend_from_slice(&[
            self.balances.len() as u8,
            self.allocation.team_index() as u8,
        ]);
        for share in self.allocation.basis_points() {
            out.extend_from_slice(&share.to_le_bytes());
        }
        for (member, balance) in self.balances.iter().enumerate() {
            for value in [
                balance.entitlement,
                balance.direct_unlocked,
                balance.vesting_unlocked,
                balance.spent,
            ] {
                out.extend_from_slice(&value.to_le_bytes());
            }
            out.extend_from_slice(&balance.spend_count.to_le_bytes());
            out.extend_from_slice(&self.direct_entitlement[member].to_le_bytes());
        }
        out.extend_from_slice(&(self.cohorts.len() as u32).to_le_bytes());
        for cohort in &self.cohorts {
            out.extend_from_slice(&cohort.start.to_le_bytes());
            out.extend_from_slice(&cohort.end.to_le_bytes());
            for credit in &cohort.credits {
                out.extend_from_slice(&credit.to_le_bytes());
            }
        }
        require(
            out.len() <= MAX_COMPONENT_BYTES,
            "fund component byte bound exceeded",
        )?;
        Ok(out)
    }
    pub fn decode_component(
        bytes: &[u8],
        expected_network: Hash,
        expected_allocation: &FundAllocation,
    ) -> Result<Self, String> {
        require(
            bytes.len() <= MAX_COMPONENT_BYTES,
            "fund component byte bound exceeded",
        )?;
        let mut reader = Reader(bytes);
        require(
            &reader.array::<8>()? == MAGIC,
            "fund component version mismatch",
        )?;
        let network = reader.array()?;
        require(
            network == expected_network,
            "fund component network mismatch",
        )?;
        let height = reader.u64()?;
        require(
            [reader.u64()?, reader.u64()?, reader.u64()?]
                == [DIRECT_DELAY_BLOCKS, MONTH_BLOCKS, MONTHS],
            "fund fixed release schedule mismatch",
        )?;
        let total_entitlement = reader.u128()?;
        let count = usize::from(reader.byte()?);
        let team = usize::from(reader.byte()?);
        require(
            count > 0 && count <= MAX_FUND_WALLETS,
            "fund member count exceeds bound",
        )?;
        let mut shares = Vec::with_capacity(count);
        for _ in 0..count {
            shares.push(u16::from_le_bytes(reader.array()?));
        }
        let allocation = FundAllocation::new_bps(shares, team).map_err(|e| e.to_string())?;
        require(
            &allocation == expected_allocation,
            "fund immutable allocation mismatch",
        )?;
        let mut balances = Vec::with_capacity(count);
        let mut direct_entitlement = Vec::with_capacity(count);
        for _ in 0..count {
            balances.push(FundBalance {
                entitlement: reader.u128()?,
                direct_unlocked: reader.u128()?,
                vesting_unlocked: reader.u128()?,
                spent: reader.u128()?,
                spend_count: reader.u64()?,
            });
            direct_entitlement.push(reader.u128()?);
        }
        let cohort_count = u32::from_le_bytes(reader.array()?) as usize;
        require(
            cohort_count <= VESTING_BLOCKS as usize
                && reader.0.len() == cohort_count * (16 + 8 * count),
            "fund cohort count or remaining length invalid",
        )?;
        let mut cohorts = Vec::with_capacity(cohort_count);
        for _ in 0..cohort_count {
            let start = reader.u64()?;
            let end = reader.u64()?;
            let mut credits = Vec::with_capacity(count);
            for _ in 0..count {
                credits.push(reader.u64()?);
            }
            cohorts.push(Cohort {
                start,
                end,
                credits,
            });
        }
        let ledger = Self {
            network,
            height,
            allocation,
            total_entitlement,
            balances,
            direct_entitlement,
            cohorts,
        };
        ledger.validate()?;
        require(
            reader.0.is_empty() && ledger.canonical_component_bytes()? == bytes,
            "noncanonical fund component encoding",
        )?;
        Ok(ledger)
    }
}
