//! Versioned native execution with an explicit genesis-bound legacy fee mode.

use super::{
    body,
    fund_claim::{AuthorizedFundClaim, DebitedFundOutput},
    genesis::{FeeMode, Genesis},
    header::Header,
    snapshot::SnapshotState,
    state_components::{Binding, Limits, VersionedLedgers},
};
use crate::{
    chain_transition::{Actions, ChainDelta, CheckedActions, Context, PreparedActions},
    eng2_economics::EconomicState,
    eng2_fund::FundLedger,
    eng2_governance::{GovernanceState, Inclusion},
    proofs::NativeVerifier,
    wire::{Hash, RewardRecord},
};

#[cfg(feature = "eng2-runtime")]
fn precommit_failure(original: String) -> super::accept_observation::Failure {
    use super::accept_observation::{CommitKnowledge, Failure, OtherClass, Phase};
    Failure::other(
        original,
        OtherClass::CandidateValidation,
        Phase::Execution,
        CommitKnowledge::NotReached,
    )
}

/// The fixed body slot is unused under `LegacyMiner`, is not appended to the
/// commitment tree and cannot carry a payment or alternate fee destination.
pub fn legacy_fee_output() -> RewardRecord {
    RewardRecord {
        commitment: [0; 48],
        ciphertext: [0; crate::wire::REWARD_CIPHERTEXT_BYTES],
    }
}

/// Successful native verification and atomic in-memory state publication.
///
/// This capability does not assert disk durability. A host must persist the
/// accepted header/body and state before exporting governance records or
/// reporting durable acceptance. There is no public constructor.
pub struct CommittedBlock {
    network: Hash,
    height: u64,
    id: Hash,
    execution_commitment: Hash,
    inclusions: Vec<Inclusion>,
}
impl CommittedBlock {
    pub fn network(&self) -> Hash {
        self.network
    }
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn id(&self) -> Hash {
        self.id
    }
    pub fn execution_commitment(&self) -> Hash {
        self.execution_commitment
    }
    pub fn inclusions(&self) -> &[Inclusion] {
        &self.inclusions
    }
}

/// Exclusively owned versioned state. The complete immutable native proof
/// profile and legacy fee rule come from the locally sealed genesis.
pub struct Engine {
    genesis: Genesis,
    state: SnapshotState,
    limits: Limits,
}
impl Engine {
    /// Isolated checkpoint candidate only. The import owner keeps this engine
    /// private until complete native tail execution and current-roster checks.
    pub(super) fn from_imported_anchor(
        genesis: Genesis,
        anchor: super::snapshot::ImportedAnchor,
        limits: Limits,
    ) -> Result<Self, String> {
        Self::from_authenticated_local_state(genesis, anchor.into_state(), limits)
    }
    pub(super) fn from_authenticated_local_state(
        genesis: Genesis,
        state: SnapshotState,
        limits: Limits,
    ) -> Result<Self, String> {
        state.check_context()?;
        if state.chain.config != *genesis.config() || state.fee_mode() != genesis.fee_mode() {
            return Err("authenticated local state differs from sealed genesis".into());
        }
        Ok(Self {
            genesis,
            state,
            limits,
        })
    }
    pub(super) fn limits(&self) -> Limits {
        self.limits
    }
    pub fn new(genesis: Genesis, limits: Limits) -> Result<Self, String> {
        let state = genesis.initial_state()?;
        let result = Self {
            genesis,
            state,
            limits,
        };
        result
            .state
            .execution_commitment(result.binding([0; 32]), limits)?;
        Ok(result)
    }
    pub fn genesis(&self) -> &Genesis {
        &self.genesis
    }
    pub fn state(&self) -> &SnapshotState {
        &self.state
    }
    pub fn body_policy(&self) -> body::Policy {
        body::Policy {
            profile: crate::proofs::protocol_profile_fingerprint(),
            max_body_bytes: crate::wire::MAX_BLOCK_BYTES
                + crate::wire::REWARD_RECORD_BYTES
                + 4 * 1024 * 1024,
            max_settlement_proof_bytes: crate::wire::MAX_SETTLEMENT_PROOF,
        }
    }
    fn binding(&self, parent: Hash) -> Binding {
        Binding {
            genesis: self.genesis.id(),
            rules_commitment: self.genesis.rules_commitment(),
            parent,
        }
    }
    /// Construct a work template using the same actual proof, settlement and
    /// execution path as validation. Only final nonce work is deferred.
    pub fn prepare_header(
        &self,
        body: &body::Body,
        timestamp: u64,
        verifier: &NativeVerifier,
    ) -> Result<Header, String> {
        let mut header = Header {
            network: self.state.network(),
            height: self
                .state
                .height()
                .checked_add(1)
                .ok_or("height overflow")?,
            parent: self.state.tip(),
            timestamp,
            target: self.state.chain.next_target(),
            execution_commitment: [0; 32],
            body_commitment: body.commitment(self.body_policy())?,
            nonce: 0,
        };
        let staged = PreparedBlock::prepare_inner(
            &self.state,
            &header,
            body,
            self.binding(self.state.tip()),
            self.body_policy(),
            HeaderUse::Template,
        )?
        .verify_transactions(verifier)?
        .legacy_delta(verifier, self.limits)?;
        header.execution_commitment = staged.commitment;
        Ok(header)
    }
    /// Verify the complete actual native block before changing any chain or
    /// typed-ledger state. All fallible work precedes atomic publication.
    pub fn apply(
        &mut self,
        header: &Header,
        body: &body::Body,
        verifier: &NativeVerifier,
    ) -> Result<CommittedBlock, String> {
        let staged = self.stage(header, body, verifier)?;
        self.publish(staged)
    }
    pub(super) fn stage(
        &self,
        header: &Header,
        body: &body::Body,
        verifier: &NativeVerifier,
    ) -> Result<StagedBlock, String> {
        if self.state.fee_mode() != self.genesis.fee_mode()
            || self.genesis.fee_mode() != FeeMode::LegacyMiner
        {
            return Err("native engine fee mode differs from sealed genesis".into());
        }
        PreparedBlock::prepare(
            &self.state,
            header,
            body,
            self.binding(self.state.tip()),
            self.body_policy(),
        )?
        .verify_transactions(verifier)?
        .legacy_delta(verifier, self.limits)
    }
    #[cfg(feature = "eng2-runtime")]
    pub(super) fn stage_diagnosed(
        &self,
        header: &Header,
        body: &body::Body,
        verifier: &NativeVerifier,
    ) -> Result<StagedBlock, super::accept_observation::Failure> {
        if self.state.fee_mode() != self.genesis.fee_mode()
            || self.genesis.fee_mode() != FeeMode::LegacyMiner
        {
            return Err(precommit_failure(
                "native engine fee mode differs from sealed genesis".into(),
            ));
        }
        PreparedBlock::prepare(
            &self.state,
            header,
            body,
            self.binding(self.state.tip()),
            self.body_policy(),
        )
        .map_err(precommit_failure)?
        .verify_transactions_diagnosed(verifier)?
        .legacy_delta_diagnosed(verifier, self.limits)
    }
    pub(super) fn publish(&mut self, staged: StagedBlock) -> Result<CommittedBlock, String> {
        let StagedBlock {
            network,
            height,
            id,
            delta,
            ledgers,
            nullifiers,
            commitment,
        } = staged;
        if id == [0; 32] {
            return Err("an unmined template cannot be published".into());
        }
        // ChainDelta checks its exact parent before the first mutation. The
        // remaining assignments are infallible and publish the same candidate.
        delta.commit_into(&mut self.state.chain)?;
        self.state.economics = ledgers.economics;
        self.state.fund = ledgers.fund;
        self.state.governance = ledgers.governance;
        self.state.nullifiers = nullifiers;
        Ok(CommittedBlock {
            network,
            height,
            id,
            execution_commitment: commitment,
            inclusions: ledgers.inclusions,
        })
    }
}

pub(super) struct StagedBlock {
    network: Hash,
    height: u64,
    id: Hash,
    delta: ChainDelta,
    ledgers: CandidateLedgers,
    nullifiers: super::nullifiers::NullifierSet,
    commitment: Hash,
}
impl StagedBlock {
    pub(super) fn restart_image(
        &self,
        parent: &SnapshotState,
        limits: Limits,
    ) -> Result<Vec<u8>, String> {
        super::restart::image(
            &self.delta.restart_chain_bytes(&parent.chain)?,
            &self.ledgers.economics,
            &self.ledgers.fund,
            &self.ledgers.governance,
            self.commitment,
            limits,
        )
    }
    pub(super) fn new_leaves(&self) -> &[Digest] {
        self.delta.new_leaves()
    }
    pub(super) fn new_spends(&self) -> &std::collections::BTreeSet<crate::wire::DigestBytes> {
        self.delta.new_spends()
    }
}
#[derive(Clone, Copy)]
enum HeaderUse {
    Mined,
    Template,
}
use crate::eng2_settlement::{FeeSchedule, SettlementPolicy};
use native::{codec::decode_digest, encryption::PaymentAddress, multi_asset::Digest};

struct CandidateLedgers {
    economics: EconomicState,
    fund: FundLedger,
    frozen: GovernanceState,
    governance: GovernanceState,
    inclusions: Vec<Inclusion>,
    outputs: Vec<DebitedFundOutput>,
    settlement: SettlementPolicy,
    fee_commitment: Digest,
}
impl CandidateLedgers {
    fn view(&self) -> VersionedLedgers<'_> {
        VersionedLedgers {
            economics: &self.economics,
            fund: &self.fund,
            governance: &self.governance,
        }
    }
}

pub struct PreparedBlock<'a> {
    parent: &'a SnapshotState,
    header: &'a Header,
    body: &'a body::Body,
    binding: Binding,
    actions: PreparedActions<'a>,
    ledgers: CandidateLedgers,
    header_use: HeaderUse,
}
/// Actual native transaction and issuance proofs passed for these exact inputs.
/// This is not settlement verification, an executable delta or live admission.
pub struct NativeTransactions<'a> {
    parent: &'a SnapshotState,
    header: &'a Header,
    body: &'a body::Body,
    binding: Binding,
    actions: CheckedActions<'a>,
    ledgers: CandidateLedgers,
    header_use: HeaderUse,
}
impl<'a> PreparedBlock<'a> {
    pub fn prepare(
        parent: &'a SnapshotState,
        header: &'a Header,
        body: &'a body::Body,
        binding: Binding,
        policy: body::Policy,
    ) -> Result<Self, String> {
        Self::prepare_inner(parent, header, body, binding, policy, HeaderUse::Mined)
    }
    fn prepare_inner(
        parent: &'a SnapshotState,
        header: &'a Header,
        body: &'a body::Body,
        binding: Binding,
        policy: body::Policy,
        header_use: HeaderUse,
    ) -> Result<Self, String> {
        parent.check_context()?;
        if parent.fee_mode() == FeeMode::LegacyMiner && body.fee_output != legacy_fee_output() {
            return Err("legacy fee output must be the unused all-zero sentinel".into());
        }
        if binding.genesis == [0; 32]
            || binding.rules_commitment == [0; 32]
            || binding.parent != parent.tip()
            || header.network != parent.network()
            || body.network != header.network
            || body.height != header.height
            || body.commitment(policy)? != header.body_commitment
        {
            return Err("isolated block binding or complete body commitment differs".into());
        }
        let seed = header.pow_seed().map_err(|_| "invalid isolated header")?;
        if matches!(header_use, HeaderUse::Mined)
            && !siworld_core::pow::meets_target(
                &siworld_core::pow::pow_hash(
                    &seed,
                    header.nonce,
                    parent.chain.config.pow_iterations,
                ),
                &header.target,
            )
        {
            return Err("isolated header has insufficient work".into());
        }
        // The current block observes only previously included operations whose
        // delay has elapsed. New operations cannot change this block's policy.
        let mut frozen = parent.governance.clone();
        frozen.apply_block(header.height, &[])?;
        let issuance_policy = crate::issuance::ActiveIssuancePolicy::new(
            frozen.active_fee_destination(),
            frozen.issuance_fee_atoms(),
        )?;
        let actions = PreparedActions::prepare_with_issuance_policy(
            &parent.chain,
            Context {
                network: header.network,
                height: header.height,
                parent: header.parent,
                timestamp: header.timestamp,
                target: header.target,
            },
            Actions {
                transactions: &body.transactions,
                issuances: &body.issuances,
                rewards: &body.rewards,
            },
            Some(&issuance_policy),
        )?;
        // Both clones are bounded governance state. The frozen policy activates
        // only previously included operations; new actions cannot change this
        // block's settlement destination or fund recipients.
        let mut governance = parent.governance.clone();
        let inclusions = governance.apply_block(header.height, &body.governance)?;
        let allocation = parent
            .chain
            .config
            .fund_allocation
            .as_ref()
            .ok_or("missing isolated fund allocation")?;
        let (economics, rewards) =
            parent
                .economics
                .prepare(header.height, body.reward_mode, allocation)?;
        let mut fund = parent.fund.clone();
        fund.advance(
            header.height,
            siworld_core::v1_economics::subsidy(header.height)
                .map_err(|error| error.to_string())?,
        )?;
        let mut outputs = Vec::with_capacity(body.fund_claims.len());
        for claim in &body.fund_claims {
            outputs.push(
                AuthorizedFundClaim::verify(claim, &parent.chain.config, &frozen, header.height)?
                    .debit(&mut fund)?,
            );
        }
        economics.verify_fund_entitlement(fund.total_entitlement())?;
        let previous_standard = siworld_core::v1_economics::fee_base(header.height)
            .map_err(|error| error.to_string())?;
        let settlement = SettlementPolicy {
            plan: crate::state::plan_from_allocation(&rewards),
            fee_owner: frozen.active_fee_destination().owner(),
            fees: FeeSchedule::from_previous_standard(previous_standard)?,
            max_slots: body.transactions.len(),
        };
        settlement.plan.validate()?;
        Ok(Self {
            parent,
            header,
            body,
            binding,
            header_use,
            actions,
            ledgers: CandidateLedgers {
                economics,
                fund,
                frozen,
                governance,
                inclusions,
                outputs,
                settlement,
                fee_commitment: decode_digest(&body.fee_output.commitment)
                    .map_err(|_| "noncanonical isolated fee commitment")?,
            },
        })
    }
    pub fn parent(&self) -> &SnapshotState {
        self.parent
    }
    pub fn ledgers(&self) -> VersionedLedgers<'_> {
        self.ledgers.view()
    }
    /// Invoke the actual fixed-profile native verifier on every exact prepared
    /// transaction and issuance context. No success assertion is accepted.
    pub fn verify_transactions(
        self,
        verifier: &NativeVerifier,
    ) -> Result<NativeTransactions<'a>, String> {
        let mut actions = self.actions.verify(verifier)?;
        for output in &self.ledgers.outputs {
            if output.network() != self.header.network || output.height() != self.header.height {
                return Err("debited isolated fund output context differs".into());
            }
            actions.append_authorized_output(output.commitment())?;
        }
        Ok(NativeTransactions {
            parent: self.parent,
            header: self.header,
            body: self.body,
            binding: self.binding,
            header_use: self.header_use,
            actions,
            ledgers: self.ledgers,
        })
    }
    #[cfg(feature = "eng2-runtime")]
    fn verify_transactions_diagnosed(
        self,
        verifier: &NativeVerifier,
    ) -> Result<NativeTransactions<'a>, super::accept_observation::Failure> {
        let mut actions = self.actions.verify_native_diagnosed(verifier)?;
        for output in &self.ledgers.outputs {
            if output.network() != self.header.network || output.height() != self.header.height {
                return Err(precommit_failure(
                    "debited isolated fund output context differs".into(),
                ));
            }
            actions
                .append_authorized_output(output.commitment())
                .map_err(precommit_failure)?;
        }
        Ok(NativeTransactions {
            parent: self.parent,
            header: self.header,
            body: self.body,
            binding: self.binding,
            header_use: self.header_use,
            actions,
            ledgers: self.ledgers,
        })
    }
}
impl NativeTransactions<'_> {
    pub fn parent(&self) -> &SnapshotState {
        self.parent
    }
    pub fn header(&self) -> &Header {
        self.header
    }
    pub fn body(&self) -> &body::Body {
        self.body
    }
    pub fn binding(&self) -> Binding {
        self.binding
    }
    pub fn ledgers(&self) -> VersionedLedgers<'_> {
        self.ledgers.view()
    }
    pub fn settlement_policy(&self) -> &SettlementPolicy {
        &self.ledgers.settlement
    }
    pub fn fee_destination(&self) -> &PaymentAddress {
        self.ledgers.frozen.active_fee_destination()
    }
    pub fn fees(&self) -> &[Digest] {
        self.actions.fees()
    }
    pub fn rewards(&self) -> &[Digest] {
        self.actions.rewards()
    }
    pub fn fee_commitment(&self) -> Digest {
        self.ledgers.fee_commitment
    }
    fn legacy_delta(
        self,
        verifier: &NativeVerifier,
        limits: Limits,
    ) -> Result<StagedBlock, String> {
        if self.parent.fee_mode() != FeeMode::LegacyMiner
            || self.body.fee_output != legacy_fee_output()
        {
            return Err("legacy settlement is not selected by this genesis".into());
        }
        let mut fees = self.actions.fees().to_vec();
        fees.extend(
            crate::state::tail_slots(
                self.header.network,
                self.header.height,
                self.body.transactions.len(),
            )?
            .iter()
            .map(|slot| slot.commitment),
        );
        verifier.verify_settlement(
            &fees,
            &self.ledgers.settlement.plan,
            self.header.network,
            self.body.list_digest(),
            self.actions.rewards(),
            &self.body.settlement_proof,
        )?;
        let identity = match self.header_use {
            HeaderUse::Mined => self
                .header
                .id()
                .map_err(|_| "invalid native header identity")?,
            HeaderUse::Template => [0; 32],
        };
        let delta = self
            .actions
            .finish(identity, |height| FeeMode::LegacyMiner.base_fee(height))?;
        let (commitment, nullifiers) = delta
            .preview(&self.parent.chain)?
            .versioned_execution(self.parent, self.ledgers.view(), self.binding, limits)?
            .into_parts();
        if matches!(self.header_use, HeaderUse::Mined)
            && commitment != self.header.execution_commitment
        {
            return Err("native execution commitment differs from complete checked state".into());
        }
        Ok(StagedBlock {
            network: self.header.network,
            height: self.header.height,
            id: identity,
            delta,
            ledgers: self.ledgers,
            nullifiers,
            commitment,
        })
    }
    #[cfg(feature = "eng2-runtime")]
    fn legacy_delta_diagnosed(
        self,
        verifier: &NativeVerifier,
        limits: Limits,
    ) -> Result<StagedBlock, super::accept_observation::Failure> {
        if self.parent.fee_mode() != FeeMode::LegacyMiner
            || self.body.fee_output != legacy_fee_output()
        {
            return Err(precommit_failure(
                "legacy settlement is not selected by this genesis".into(),
            ));
        }
        let mut fees = self.actions.fees().to_vec();
        fees.extend(
            crate::state::tail_slots(
                self.header.network,
                self.header.height,
                self.body.transactions.len(),
            )
            .map_err(precommit_failure)?
            .iter()
            .map(|slot| slot.commitment),
        );
        verifier.verify_settlement_diagnosed(
            &fees,
            &self.ledgers.settlement.plan,
            self.header.network,
            self.body.list_digest(),
            self.actions.rewards(),
            &self.body.settlement_proof,
        )?;
        let identity = match self.header_use {
            HeaderUse::Mined => self
                .header
                .id()
                .map_err(|_| precommit_failure("invalid native header identity".into()))?,
            HeaderUse::Template => [0; 32],
        };
        let delta = self
            .actions
            .finish(identity, |height| FeeMode::LegacyMiner.base_fee(height))
            .map_err(precommit_failure)?;
        let (commitment, nullifiers) = delta
            .preview(&self.parent.chain)
            .map_err(precommit_failure)?
            .versioned_execution(self.parent, self.ledgers.view(), self.binding, limits)
            .map_err(precommit_failure)?
            .into_parts();
        if matches!(self.header_use, HeaderUse::Mined)
            && commitment != self.header.execution_commitment
        {
            return Err(precommit_failure(
                "native execution commitment differs from complete checked state".into(),
            ));
        }
        Ok(StagedBlock {
            network: self.header.network,
            height: self.header.height,
            id: identity,
            delta,
            ledgers: self.ledgers,
            nullifiers,
            commitment,
        })
    }
}

#[cfg(test)]
mod tests;
