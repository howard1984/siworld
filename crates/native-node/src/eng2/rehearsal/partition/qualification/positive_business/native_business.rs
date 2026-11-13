//! Owner-operated positive business material for a nonfixture legacy network.
//! This module does not register a new protocol or qualify a release.
//! Prover, nonce work and durable append require an external resource guard.

use crate::{
    eng2::{execution::CommittedBlock, genesis::FeeMode, producer, store::Store},
    eng2_operations::PendingOperations,
    pool::Padding,
    producer::{MiningSettings, prepare_padding},
    proofs::{NativeProver, NativeVerifier},
    state::State,
    wallet::{
        FeeTier, PreparedTransfer, Wallet, WalletPayment,
        issuance::{IssuanceRequest, WalletIssuance},
    },
    wire::{DigestBytes, Hash, MIN_SLOTS},
};
use native::{
    confidential_fees::FeeOpening,
    encryption::PaymentAddress,
    multi_asset::{AssetId, F},
};
use p3_field::PrimeCharacteristicRing;

/// Use current wallet notes and the ordinary host-validated native prover.
/// Standard, priority and two-input self-payment use the same production API.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_payment(
    wallet: &Wallet,
    state: &State,
    selected: [Option<DigestBytes>; 2],
    recipient: &PaymentAddress,
    asset: AssetId,
    amount: u64,
    tier: FeeTier,
    now: u64,
    prover: &NativeProver,
    mut before_proof: impl FnMut(&PreparedTransfer) -> Result<(), String>,
) -> Result<WalletPayment, String> {
    if state.config.fixture || state.config.pow_iterations == 0 {
        return Err("business material requires a nonfixture native state".into());
    }
    let prepared = wallet.prepare_transfer(state, selected, recipient, asset, amount, tier, now)?;
    before_proof(&prepared)?;
    prepared.prove(prover)
}

pub(crate) struct BusinessInputs {
    pub payments: Vec<(WalletPayment, FeeTier)>,
    pub issuances: Vec<WalletIssuance>,
    pub operations: Option<PendingOperations>,
}

/// Bytes are the actual header followed by the ordinary canonical body.
/// Independent stopped-store audit and wallet observations remain separate.
pub(crate) struct AppendedBusinessBlock {
    pub committed: CommittedBlock,
    pub frame: Vec<u8>,
    pub transactions: Vec<Hash>,
    pub issuances: Vec<Hash>,
}

/// Openings must be protected by caller-owned storage before records move into
/// the block. Callbacks receive the original positive bundles, not projections.
#[allow(clippy::too_many_arguments)]
pub(crate) fn append_business_block(
    store: &mut Store,
    prover: &NativeProver,
    verifier: &NativeVerifier,
    inputs: BusinessInputs,
    timestamp: u64,
    settings: &MiningSettings,
    max_attempts: u64,
    mut protect_payment: impl FnMut(&WalletPayment) -> Result<(), String>,
    mut protect_issuance: impl FnMut(&WalletIssuance) -> Result<(), String>,
    mut protect_reward: impl FnMut(&producer::ProducedBlock) -> Result<(), String>,
    mut before_phase: impl FnMut(&str) -> Result<(), String>,
) -> Result<AppendedBusinessBlock, String> {
    let engine = store.engine();
    let state = engine.state().chain();
    if state.config.fixture
        || state.config.pow_iterations == 0
        || engine.genesis().fee_mode() != FeeMode::LegacyMiner
        || inputs.payments.len() > MIN_SLOTS
        || max_attempts == 0
    {
        return Err("business material context or bounded work budget differs".into());
    }
    if inputs.payments.is_empty() && inputs.issuances.is_empty() && inputs.operations.is_none() {
        return Err("business block requires an explicit operation".into());
    }
    let network = state.config.network;
    let mut positions = Vec::with_capacity(MIN_SLOTS);
    let mut transactions = Vec::with_capacity(inputs.payments.len());
    for (payment, tier) in inputs.payments {
        payment
            .sidecar
            .check_opening(&payment.transaction.record, &network)?;
        let expected_fee = crate::state::base_fee(payment.transaction.record.snapshot.height)
            .checked_mul(if tier == FeeTier::Priority { 4 } else { 1 })
            .ok_or("business fee overflow")?;
        if payment.sidecar.fee != expected_fee {
            return Err("business payment sidecar differs from requested fee tier".into());
        }
        protect_payment(&payment)?;
        transactions.push(payment.transaction.record.statement_id(&network));
        positions.push(Padding {
            opening: FeeOpening {
                fee: payment.sidecar.fee,
                blind: payment.sidecar.blind.map(F::from_u32),
                dummy: false,
                priority: tier == FeeTier::Priority,
            },
            transaction: payment.transaction,
        });
    }
    let mut issuances = Vec::with_capacity(inputs.issuances.len());
    let mut issuance_ids = Vec::with_capacity(inputs.issuances.len());
    for issuance in inputs.issuances {
        issuance.record.validate(&state.config)?;
        verifier.verify_issuance(&issuance.record)?;
        protect_issuance(&issuance)?;
        issuance_ids.push(issuance.record.signed.declaration.binding());
        issuances.push(issuance.record);
    }
    while positions.len() < MIN_SLOTS {
        before_phase("before_fresh_padding_transaction_proof")?;
        positions.push(prepare_padding(state, prover)?);
    }
    before_phase("before_native_candidate_prepare")?;
    let prepared = producer::prepare(
        engine,
        positions,
        timestamp,
        settings,
        inputs.operations,
        issuances,
    )?;
    before_phase("before_native_settlement_proof")?;
    let proved = prepared.prove(prover)?;
    before_phase("before_native_template_verification")?;
    let work = proved.prepare_work(engine, verifier)?;
    before_phase("before_bounded_nonce_search")?;
    let produced = work.mine(max_attempts)?;
    protect_reward(&produced)?;
    let policy = engine.body_policy();
    let mut frame = produced
        .header
        .encode()
        .map_err(|_| "native header encoding failed")?
        .to_vec();
    frame.extend_from_slice(&produced.body.encode(policy)?);
    before_phase("before_final_native_append")?;
    let committed = store.append(&produced.header, &produced.body, verifier)?;
    // Original private receipts have reached the custody callbacks before append.
    // Callback success does not imply durable storage or crash recovery.
    // The returned frame contains only the ordinary public block bytes.
    Ok(AppendedBusinessBlock {
        committed,
        frame,
        transactions,
        issuances: issuance_ids,
    })
}

/// The signing callback must use the request's independently held issuer key.
/// The declaration signature is checked by attach_signature before proving.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_paid_issuance(
    wallet: &Wallet,
    state: &State,
    selected: [Option<DigestBytes>; 2],
    fee_destination: &PaymentAddress,
    request: IssuanceRequest,
    tier: FeeTier,
    now: u64,
    sign: impl FnOnce(&[u8]) -> Result<[u8; native::issuance::ISSUER_SIGNATURE_BYTES], String>,
    issuance_prover: &native::issuance_air::IssuanceProver,
    transaction_prover: &NativeProver,
    mut before_proof: impl FnMut(&PreparedTransfer) -> Result<(), String>,
    mut before_phase: impl FnMut(&str) -> Result<(), String>,
) -> Result<(WalletIssuance, WalletPayment), String> {
    if state.config.fixture || state.config.pow_iterations == 0 {
        return Err("issuance material requires a nonfixture native state".into());
    }
    let prepared = wallet.prepare_issuance(&state.config, request)?;
    let fee = wallet.prepare_issuance_fee(
        state,
        selected,
        fee_destination,
        prepared.declaration(),
        tier,
        now,
    )?;
    before_proof(fee.transfer())?;
    let receipt = fee.receipt().clone();
    let signature = sign(&prepared.signature_message())?;
    let signed = prepared.attach_signature(signature)?;
    before_phase("before_native_issuance_proof")?;
    let issuance = signed.prove(issuance_prover, &receipt, &state.config)?;
    before_phase("before_native_issuance_fee_transaction_proof")?;
    let payment = fee.into_transfer().prove(transaction_prover)?;
    Ok((issuance, payment))
}

/// Preserve the production two-input consolidation selection and maturity rules.
pub(crate) fn prove_small_sip_consolidation(
    wallet: &Wallet,
    state: &State,
    max_note_value: u64,
    tier: FeeTier,
    now: u64,
    prover: &NativeProver,
    mut before_proof: impl FnMut(&PreparedTransfer) -> Result<(), String>,
) -> Result<Option<WalletPayment>, String> {
    if state.config.fixture || state.config.pow_iterations == 0 {
        return Err("consolidation material requires a nonfixture native state".into());
    }
    wallet
        .prepare_small_sip_consolidation(state, max_note_value, tier, now)?
        .map(|prepared| {
            before_proof(&prepared)?;
            prepared.prove(prover)
        })
        .transpose()
}
