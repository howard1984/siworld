//! Concrete legacy native production using the versioned economic reward plan.

use super::{body::Body, execution::Engine, genesis::FeeMode, header::Header};
use crate::{
    pool::Padding,
    producer::{MiningSettings, PreparedCandidate, prepare_candidate_with_plan, prove_candidate},
    proofs::{NativeProver, NativeVerifier},
    wire::Hash,
};
use zeroize::Zeroizing;

pub struct ProducedBlock {
    pub header: Header,
    pub body: Body,
    /// Private encryption receipts. Never publish or log this material.
    pub reward_secret: Zeroizing<Vec<u8>>,
}

/// Create actual native settlement, derive the execution template through the
/// same verifier path as admission, then search a bounded native nonce range.
/// This operation changes no canonical state or durable storage.
#[allow(clippy::too_many_arguments)]
pub fn assemble(
    engine: &Engine,
    prover: &NativeProver,
    verifier: &NativeVerifier,
    positions: Vec<Padding>,
    timestamp: u64,
    settings: &MiningSettings,
    max_attempts: u64,
) -> Result<ProducedBlock, String> {
    assemble_with_operations(
        engine,
        prover,
        verifier,
        positions,
        timestamp,
        settings,
        max_attempts,
        None,
        Vec::new(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn assemble_with_operations(
    engine: &Engine,
    prover: &NativeProver,
    verifier: &NativeVerifier,
    positions: Vec<Padding>,
    timestamp: u64,
    settings: &MiningSettings,
    max_attempts: u64,
    operations: Option<crate::eng2_operations::PendingOperations>,
    issuances: Vec<crate::issuance::IssuanceRecord>,
) -> Result<ProducedBlock, String> {
    if max_attempts == 0 {
        return Err("production requires a positive work budget".into());
    }
    prepare(
        engine, positions, timestamp, settings, operations, issuances,
    )?
    .prove(prover)?
    .prepare_work(engine, verifier)?
    .mine(max_attempts)
}

/// Bounded current-parent material. No chain carrier or permanent row is owned.
pub struct PreparedBlock {
    parent: Hash,
    timestamp: u64,
    profile: Hash,
    candidate: PreparedCandidate,
    operations: Option<crate::eng2_operations::PendingOperations>,
    issuances: Vec<crate::issuance::IssuanceRecord>,
}
pub struct ProvedBlock {
    parent: Hash,
    timestamp: u64,
    body: Body,
    reward_secret: Zeroizing<Vec<u8>>,
}
pub struct Work {
    header: Header,
    body: Body,
    pow_iterations: u64,
    reward_secret: Zeroizing<Vec<u8>>,
}

/// Prepare against the current state while the owner is briefly borrowed.
/// Native settlement proving and nonce search are explicit later operations.
pub fn prepare(
    engine: &Engine,
    positions: Vec<Padding>,
    timestamp: u64,
    settings: &MiningSettings,
    operations: Option<crate::eng2_operations::PendingOperations>,
    issuances: Vec<crate::issuance::IssuanceRecord>,
) -> Result<PreparedBlock, String> {
    let state = engine.state();
    if state.fee_mode() != FeeMode::LegacyMiner {
        return Err("production requires sealed legacy fee mode".into());
    }
    let height = state
        .height()
        .checked_add(1)
        .ok_or("production height overflow")?;
    let allocation = state
        .chain()
        .config
        .fund_allocation
        .as_ref()
        .ok_or("missing fund allocation")?;
    let (_, reward) = state
        .economics()
        .prepare(height, settings.mode, allocation)?;
    let candidate = prepare_candidate_with_plan(
        state.chain(),
        positions,
        timestamp,
        settings,
        crate::state::plan_from_allocation(&reward),
    )?;
    Ok(PreparedBlock {
        parent: state.tip(),
        timestamp,
        profile: engine.body_policy().profile,
        candidate,
        operations,
        issuances,
    })
}
impl PreparedBlock {
    /// Run the actual prover without borrowing the live chain owner.
    pub fn prove(self, prover: &NativeProver) -> Result<ProvedBlock, String> {
        let produced = prove_candidate(prover, self.candidate)?;
        let mut body = Body {
            network: produced.block.network,
            height: produced.block.height,
            profile: self.profile,
            transactions: produced.block.transactions,
            reward_mode: produced.block.reward_mode,
            rewards: produced.block.rewards,
            fee_output: super::execution::legacy_fee_output(),
            fund_claims: Vec::new(),
            governance: Vec::new(),
            issuances: self.issuances,
            settlement_proof: produced.block.settlement_proof,
        };
        if let Some(operations) = self.operations {
            operations.attach_to(&mut body)?;
        }
        Ok(ProvedBlock {
            parent: self.parent,
            timestamp: self.timestamp,
            body,
            reward_secret: produced.reward_secret,
        })
    }
}
impl ProvedBlock {
    /// Independently verify the real proof and derive the current execution
    /// template. A changed parent rejects the stale candidate before work.
    pub fn prepare_work(self, engine: &Engine, verifier: &NativeVerifier) -> Result<Work, String> {
        if engine.state().tip() != self.parent
            || engine.state().height().checked_add(1) != Some(self.body.height)
        {
            return Err("proved candidate parent changed".into());
        }
        let header = engine.prepare_header(&self.body, self.timestamp, verifier)?;
        Ok(Work {
            header,
            body: self.body,
            pow_iterations: engine.state().chain().config.pow_iterations,
            reward_secret: self.reward_secret,
        })
    }
}
impl Work {
    /// Search outside the owner lock. Admission still checks the exact current
    /// parent, all proofs and complete state commitment before durable commit.
    pub fn mine(mut self, max_attempts: u64) -> Result<ProducedBlock, String> {
        if max_attempts == 0 {
            return Err("production requires a positive work budget".into());
        }
        let seed = self
            .header
            .pow_seed()
            .map_err(|_| "invalid production header")?;
        for nonce in 0..max_attempts {
            if siworld_core::pow::meets_target(
                &siworld_core::pow::pow_hash(&seed, nonce, self.pow_iterations),
                &self.header.target,
            ) {
                self.header.nonce = nonce;
                return Ok(ProducedBlock {
                    header: self.header,
                    body: self.body,
                    reward_secret: self.reward_secret,
                });
            }
        }
        Err("native production work budget exhausted".into())
    }
}
