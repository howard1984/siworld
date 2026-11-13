//! Public integer audit of native V1 subsidy, pool, burn and fund accounting.
//!
//! Supplied transaction and settlement proofs are independently replayed. Fees
//! remain private and are transfers, not new issuance. Private wallet receipts
//! and voluntarily locked transaction values are outside this public audit.
use crate::state::{BlockVerifier, Config, RewardMode, State};
use crate::wire::{Block, Hash};
use siworld_core::v1_economics::FundBalance;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundWalletIdentity {
    pub account: u8,
    pub basis_points: u16,
    pub team_remainder: bool,
    pub verifying_key: [u8; crate::fund_spend::VERIFYING_KEY_BYTES],
}
fn fund_wallets(config: &Config) -> Vec<FundWalletIdentity> {
    config
        .fund_allocation
        .as_ref()
        .map_or_else(Vec::new, |allocation| {
            allocation
                .basis_points()
                .iter()
                .zip(&config.fund_verifying_keys)
                .enumerate()
                .map(|(index, (share, key))| FundWalletIdentity {
                    account: index as u8,
                    basis_points: *share,
                    team_remainder: index == allocation.team_index(),
                    verifying_key: *key,
                })
                .collect()
        })
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeightIssuance {
    pub height: u64,
    pub block_id: Hash,
    pub mode: RewardMode,
    pub subsidy: u64,
    pub miner_subsidy: u128,
    pub fund_credit: Vec<u64>,
    pub protocol_pool_credit: u64,
    pub mode_pool_credit: u64,
    pub pool_payout: u64,
    pub burn: u64,
    pub pool_balance: u128,
    pub locked_subsidy: u128,
    pub scheduled_circulating: u128,
    pub funds: Vec<FundBalance>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditReport {
    pub network: Hash,
    pub height: u64,
    pub tip: Hash,
    pub fingerprint: Hash,
    pub total_subsidy: u128,
    pub miner_subsidy: u128,
    pub holder_pool: u128,
    pub burned: u128,
    pub locked_subsidy: u128,
    pub scheduled_circulating: u128,
    pub funds: Vec<FundBalance>,
    /// Immutable public genesis identities in the same order as `funds`.
    pub fund_wallets: Vec<FundWalletIdentity>,
    pub heights: Vec<HeightIssuance>,
    pub asset_issuance_supported: bool,
    /// Public declarations have been checked during the same canonical replay.
    pub issued_assets: Vec<(Hash, crate::issuance::PublicAsset)>,
    pub fund_spending_supported: bool,
}
impl AuditReport {
    pub fn check_head(&self, height: u64, tip: Hash, fingerprint: Hash) -> Result<(), String> {
        if (self.height, self.tip, self.fingerprint) != (height, tip, fingerprint) {
            return Err("issuance audit does not match the accepted state".into());
        }
        Ok(())
    }
    pub fn check_supply(&self) -> Result<(), String> {
        let initial = self
            .miner_subsidy
            .checked_add(self.holder_pool)
            .and_then(|value| value.checked_add(self.burned))
            .ok_or("public supply audit overflow")?;
        let accounted = self.funds.iter().try_fold(initial, |total, fund| {
            total
                .checked_add(fund.entitlement)
                .ok_or("public supply audit overflow")
        })?;
        if accounted != self.total_subsidy {
            return Err("public supply conservation failed".into());
        }
        Ok(())
    }
}
/// The caller authenticates the selected canonical history or checkpoint.
/// Replacement replay discards every orphan pool, burn, fund and unlock change.
pub fn replay_chain(
    config: Config,
    blocks: &[Block],
    verifier: &impl BlockVerifier,
) -> Result<(State, AuditReport), String> {
    replay_blocks(config, blocks.iter().cloned().map(Ok), verifier)
}
/// Stream one full-proof block at a time. Missing data aborts the audit.
pub fn replay_blocks(
    config: Config,
    blocks: impl IntoIterator<Item = Result<Block, String>>,
    verifier: &impl BlockVerifier,
) -> Result<(State, AuditReport), String> {
    let mut state = State::new(config)?;
    let mut heights = Vec::new();
    let mut miner_total = 0u128;
    let mut fund_total = vec![0u128; state.economics.funds().len()];
    let mut subsidy_total = 0u128;
    let mut burned_total = 0u128;
    for block in blocks {
        let block = block?;
        let allocation = state.reward_allocation(block.reward_mode)?;
        state.apply(&block, verifier)?;
        allocation.check_conservation().map_err(|e| e.to_string())?;
        subsidy_total = subsidy_total
            .checked_add(u128::from(allocation.subsidy))
            .ok_or("subsidy audit overflow")?;
        miner_total = miner_total
            .checked_add(allocation.miner_subsidy_credit())
            .ok_or("miner subsidy audit overflow")?;
        burned_total = burned_total
            .checked_add(u128::from(allocation.burn))
            .ok_or("burn audit overflow")?;
        for (total, credit) in fund_total.iter_mut().zip(&allocation.fund_credit) {
            *total = total
                .checked_add(u128::from(*credit))
                .ok_or("fund audit overflow")?;
        }
        let totals = state.economics.totals();
        let funds = state.economics.funds().to_vec();
        if totals.issued != subsidy_total
            || totals.miner_subsidy_credited != miner_total
            || totals.burned != burned_total
            || totals.holder_pool != allocation.pool_after
            || funds.len() != fund_total.len()
            || funds
                .iter()
                .zip(&fund_total)
                .any(|(fund, total)| fund.entitlement != *total)
        {
            return Err("accepted economics differ from the integer audit".into());
        }
        state
            .economics
            .assert_supply_invariant()
            .map_err(|e| e.to_string())?;
        heights.push(HeightIssuance {
            height: block.height,
            block_id: state.tip,
            mode: block.reward_mode,
            subsidy: allocation.subsidy,
            miner_subsidy: allocation.miner_subsidy_credit(),
            fund_credit: allocation.fund_credit,
            protocol_pool_credit: allocation.protocol_pool_credit,
            mode_pool_credit: allocation.mode_pool_credit,
            pool_payout: allocation.pool_payout,
            burn: allocation.burn,
            pool_balance: totals.holder_pool,
            locked_subsidy: totals.locked_subsidy,
            scheduled_circulating: state
                .economics
                .scheduled_circulating()
                .map_err(|e| e.to_string())?,
            funds,
        });
    }
    let totals = state.economics.totals();
    let report = AuditReport {
        network: state.config.network,
        height: state.height,
        tip: state.tip,
        fingerprint: state.fingerprint(),
        total_subsidy: subsidy_total,
        miner_subsidy: miner_total,
        holder_pool: totals.holder_pool,
        burned: burned_total,
        locked_subsidy: totals.locked_subsidy,
        scheduled_circulating: state
            .economics
            .scheduled_circulating()
            .map_err(|e| e.to_string())?,
        funds: state.economics.funds().to_vec(),
        fund_wallets: fund_wallets(&state.config),
        heights,
        asset_issuance_supported: true,
        issued_assets: state
            .assets
            .iter()
            .map(|(id, asset)| (*id, asset.clone()))
            .collect(),
        fund_spending_supported: true,
    };
    report.check_supply()?;
    Ok((state, report))
}

#[cfg(all(test, siworld_native_node))]
pub(crate) mod tests;

#[cfg(all(test, siworld_native_node))]
mod streaming_tests {
    use super::*;
    use crate::fixtures::{TestVerifier, candidate};
    #[test]
    fn streaming_and_slice_audits_agree_on_the_exact_chain() {
        let config = Config::development([73; 32], 0).unwrap();
        let mut state = State::new(config.clone()).unwrap();
        let first = candidate(&state, 1);
        state.apply(&first, &TestVerifier).unwrap();
        let second = candidate(&state, 100_000);
        let blocks = [first, second];
        let (_, slice) = replay_chain(config.clone(), &blocks, &TestVerifier).unwrap();
        let (state, stream) =
            replay_blocks(config, blocks.into_iter().map(Ok), &TestVerifier).unwrap();
        assert_eq!(stream, slice);
        stream
            .check_head(state.height, state.tip, state.fingerprint())
            .unwrap();
    }
    #[test]
    fn streaming_source_failure_aborts_without_consuming_further_blocks() {
        let config = Config::development([74; 32], 0).unwrap();
        let state = State::new(config.clone()).unwrap();
        let first = candidate(&state, 1);
        let source = std::iter::once(Ok(first))
            .chain(std::iter::once(Err("source unavailable".to_owned())))
            .chain(std::iter::from_fn(|| -> Option<Result<Block, String>> {
                panic!("source was consumed after failure")
            }));
        assert!(
            matches!(replay_blocks(config, source, &TestVerifier), Err(reason) if reason == "source unavailable")
        );
    }
}
