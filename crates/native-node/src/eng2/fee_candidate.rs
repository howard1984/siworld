//! Inactive adapters between native-checked transactions and CompleteFee.
//!
//! These types establish block-local input provenance, not canonical admission.
//! The retained native transaction verifier is not a registered V2 transaction
//! suite. No Engine, Store, producer or transport entry point uses this module.

use super::{execution::NativeTransactions, genesis::FeeMode};
use crate::proof_codec::v2::{
    ConsensusProofLimits, ProtocolBinding,
    complete_fee::{self, FeeSchedule, SettlementPolicy, Statement, StatementInputs},
};
use native::{encryption::PaymentCiphertext, multi_asset::Digest};

pub mod receive;

/// Genesis-independent inputs for the fee portion of a future rules manifest.
/// This excludes genesis, rules and the derived per-genesis frame identity.
/// It neither selects a full transaction suite nor registers a network.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalFeeSuite {
    source_program: [u8; 32],
    proof_limits: [u8; ConsensusProofLimits::BYTES],
}
impl LocalFeeSuite {
    pub fn local() -> Self {
        Self {
            source_program: complete_fee::source_identity(),
            proof_limits: ConsensusProofLimits.encode(),
        }
    }
    pub fn source_program(&self) -> [u8; 32] {
        self.source_program
    }
    pub fn proof_limits(&self) -> &[u8; ConsensusProofLimits::BYTES] {
        &self.proof_limits
    }
    fn bind(&self, checked: &NativeTransactions<'_>) -> ProtocolBinding {
        let binding = checked.binding();
        ProtocolBinding {
            genesis: binding.genesis,
            rules: binding.rules_commitment,
            air: self.source_program,
        }
    }
}

/// Only native-checked block inputs can construct this adapter. Public arrays,
/// serialized manifests and guard receipts cannot construct one. It does not
/// prove CompleteFee or confer permission to publish a ledger transition.
/// Keeping the checked object also keeps its actual parent/body lifetime.
pub struct NativeCheckedFeeInputs<'a> {
    checked: NativeTransactions<'a>,
    suite: LocalFeeSuite,
    policy: SettlementPolicy,
    fees: Vec<Digest>,
    payment: PaymentCiphertext,
}
impl<'a> NativeCheckedFeeInputs<'a> {
    pub fn from_native_checked(checked: NativeTransactions<'a>) -> Result<Self, String> {
        if checked.parent().fee_mode() != FeeMode::ConfidentialDestination {
            return Err("fee candidate requires confidential destination state".into());
        }
        let body = checked.body();
        let header = checked.header();
        let existing = checked.settlement_policy();
        if existing.max_slots != body.transactions.len()
            || existing.plan.block_height != header.height
            || existing.fee_owner != checked.fee_destination().owner()
        {
            return Err("native fee policy context differs".into());
        }
        let previous_standard = siworld_core::v1_economics::fee_base(header.height)
            .map_err(|error| error.to_string())?;
        let fees = FeeSchedule::from_previous_standard(previous_standard)?;
        if fees.standard() != existing.fees.standard()
            || fees.priority() != existing.fees.priority()
        {
            return Err("native fee policy schedule differs".into());
        }
        let policy = SettlementPolicy {
            plan: existing.plan.clone(),
            fee_owner: existing.fee_owner,
            fees,
            max_slots: complete_fee::CAPACITY,
        };
        let fees = ordered_fee_commitments(
            header.network,
            header.height,
            body.transactions.len(),
            checked.fees(),
        )?;
        let bytes = &body.fee_output.ciphertext;
        // Retained fixed reward-payment layout, also used by the native wallet.
        let payment = PaymentCiphertext {
            kem_ciphertext: bytes[..1088].try_into().expect("fixed KEM width"),
            body: bytes[1088..1296].try_into().expect("fixed payment width"),
            tag: bytes[1296..1312].try_into().expect("fixed tag width"),
            view_tag: bytes[1312],
        };
        Ok(Self {
            suite: LocalFeeSuite::local(),
            checked,
            policy,
            fees,
            payment,
        })
    }
    /// Derive all public inputs from the held native-checked block context.
    /// No verifier setup, STARK verification or state transition occurs here.
    pub fn statement(&self) -> Result<Statement, complete_fee::Error> {
        Statement::from_authenticated(
            StatementInputs {
                policy: &self.policy,
                network: self.checked.header().network,
                transaction_list_digest: self.checked.body().list_digest(),
                address: self.checked.fee_destination(),
                fee_commitments: &self.fees,
                reward_commitments: self.checked.rewards(),
                fee_commitment: self.checked.fee_commitment(),
                ciphertext: &self.payment,
            },
            self.suite.bind(&self.checked),
        )
    }
    pub fn suite(&self) -> &LocalFeeSuite {
        &self.suite
    }
    pub fn ordered_fee_commitments(&self) -> &[Digest] {
        &self.fees
    }
    pub fn native_checked(&self) -> &NativeTransactions<'a> {
        &self.checked
    }
}

fn ordered_fee_commitments(
    network: [u8; 32],
    height: u64,
    native_body_slots: usize,
    checked_fees: &[Digest],
) -> Result<Vec<Digest>, String> {
    if checked_fees.len() != native_body_slots {
        return Err("checked fee count differs from native body slots".into());
    }
    let tail = crate::state::tail_slots(network, height, native_body_slots)?;
    let mut commitments = Vec::with_capacity(complete_fee::CAPACITY);
    commitments.extend_from_slice(checked_fees);
    commitments.extend(tail.into_iter().map(|slot| slot.commitment));
    if commitments.len() != complete_fee::CAPACITY {
        return Err("complete fee capacity differs".into());
    }
    Ok(commitments)
}

#[cfg(test)]
mod tests;
