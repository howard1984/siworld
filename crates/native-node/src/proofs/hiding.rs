//! Genesis-bound salted adapters for the retained native proof relations.
use super::NativeProofGenesis as Genesis;
use super::{
    NativePreparation, NativeRejectionEvidence, NativeVerificationFailure, RejectedNativeRelation,
    SETTLEMENT_CAPACITY, check_context, settlement_statement,
};
use crate::proof_codec::v2::{
    Identity, MAX_ISSUANCE_PROOF_BYTES, MAX_TRANSACTION_PROOF_BYTES, ProtocolBinding, Relation,
    backend::{
        Config, IssuanceProver, IssuanceVerifier, Profile, SettlementProver, SettlementVerifier,
        TransactionProver, TransactionVerifier, TranscriptContext,
    },
    native::NativeProofShape,
};
use native::{
    codec::{ProofContext, PublicTransaction},
    issuance::IssuanceWitness,
    multi_asset::{AccWitness, Digest, Hasher},
    settlement::{FixedSettlementWitness, RewardPlan},
};
use p3_air::{Air, symbolic::SymbolicAirBuilder};
use p3_uni_stark::PreprocessedVerifierKey;
use std::sync::OnceLock;

type Failure = NativeVerificationFailure;

// This closure includes the retained AIRs, trace adapters, salted PCS and public
// preprocessing recipe. A source change creates a new profile and genesis.
fn air_identity() -> [u8; 32] {
    static ID: OnceLock<[u8; 32]> = OnceLock::new();
    *ID.get_or_init(|| {
        let mut hash = blake3::Hasher::new_derive_key(
            "siworld retained native V2 AIR and preprocessing closure",
        );
        for source in [
            include_bytes!("../../../bench-d8/src/lib.rs").as_slice(),
            include_bytes!("../../../bench-d8/src/air.rs").as_slice(),
            include_bytes!("../../../bench-d8/src/common.rs").as_slice(),
            include_bytes!("../../../bench-d8/src/fee_settlement.rs").as_slice(),
            include_bytes!("../../../bench-multi-asset/src/lib.rs").as_slice(),
            include_bytes!("../../../bench-multi-asset/src/multi_asset.rs").as_slice(),
            include_bytes!("../../../bench-multi-asset/src/multi_asset_trace.rs").as_slice(),
            include_bytes!("../../../bench-multi-asset/src/confidential_fees.rs").as_slice(),
            include_bytes!("../../../bench-multi-asset/src/codec.rs").as_slice(),
            include_bytes!("../../../bench-multi-asset/src/multi_asset_air.rs").as_slice(),
            include_bytes!("../../../bench-multi-asset/src/multi_asset_transaction.rs").as_slice(),
            include_bytes!("../../../bench-multi-asset/src/settlement.rs").as_slice(),
            include_bytes!("../../../bench-multi-asset/src/issuance_air.rs").as_slice(),
            include_bytes!("../../../bench-multi-asset/src/issuance.rs").as_slice(),
            include_bytes!("../../Cargo.lock").as_slice(),
            include_bytes!("hiding.rs").as_slice(),
            include_bytes!("../proofs.rs").as_slice(),
            include_bytes!("../proof_codec/v2.rs").as_slice(),
            include_bytes!("../proof_codec/v2/native.rs").as_slice(),
            include_bytes!("../proof_codec/v2/backend/entropy.rs").as_slice(),
            include_bytes!("../proof_codec/v2/backend/owner.rs").as_slice(),
            include_bytes!("../proof_codec/v2/backend/mod.rs").as_slice(),
            include_bytes!("../proof_codec/v2/backend/pcs.rs").as_slice(),
            include_bytes!("../proof_codec/v2/backend/relations.rs").as_slice(),
            include_bytes!("../proof_codec/v2/backend/issuance_trace.rs").as_slice(),
            include_bytes!("../proof_codec/v2/backend/settlement_trace.rs").as_slice(),
        ] {
            hash.update(&(source.len() as u64).to_le_bytes());
            hash.update(source);
        }
        *hash.finalize().as_bytes()
    })
}
pub(super) fn profile_fingerprint() -> [u8; 32] {
    let mut hash =
        blake3::Hasher::new_derive_key("siworld genesis retained native salted proof profile v2");
    hash.update(&super::legacy_profile_fingerprint());
    hash.update(&air_identity());
    for (relation, profile, capacity, limit) in [
        (
            Relation::Transaction,
            Profile::transaction(),
            0u32,
            MAX_TRANSACTION_PROOF_BYTES,
        ),
        (
            Relation::Settlement,
            Profile::settlement(),
            SETTLEMENT_CAPACITY as u32,
            MAX_TRANSACTION_PROOF_BYTES,
        ),
        (
            Relation::Issuance,
            Profile::issuance(),
            crate::issuance::INITIAL_NOTES as u32,
            MAX_ISSUANCE_PROOF_BYTES,
        ),
    ] {
        hash.update(&[relation as u8]);
        hash.update(&profile.id());
        hash.update(&capacity.to_le_bytes());
        hash.update(&(limit as u64).to_le_bytes());
    }
    *hash.finalize().as_bytes()
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Context {
    network: [u8; 32],
    binding: ProtocolBinding,
}
impl Context {
    fn from_genesis(genesis: &Genesis) -> Result<Self, String> {
        #[cfg(siworld_native_node)]
        let (id, rules) = (genesis.id(), genesis.rules_commitment());
        #[cfg(not(siworld_native_node))]
        let (id, rules) = (genesis.genesis(), genesis.rules());
        let result = Self {
            network: genesis.config().network,
            binding: ProtocolBinding {
                genesis: id,
                rules,
                air: air_identity(),
            },
        };
        if [
            result.network,
            result.binding.genesis,
            result.binding.rules,
            result.binding.air,
        ]
        .contains(&[0; 32])
        {
            return Err("salted native proof binding must be nonzero".into());
        }
        Ok(result)
    }
}
fn preparation(message: impl Into<String>) -> Failure {
    Failure::Preparation(message.into(), NativePreparation::Context)
}
fn structure() -> Failure {
    Failure::Preparation(
        "salted native proof frame rejected".into(),
        NativePreparation::Structure,
    )
}
fn rejected(relation: RejectedNativeRelation) -> Failure {
    Failure::Rejected(NativeRejectionEvidence { relation })
}
fn shape<A: Air<SymbolicAirBuilder<native::multi_asset::F>>>(
    context: Context,
    air: &A,
    key: &PreprocessedVerifierKey<Config>,
    config: &Config,
    profile: Profile,
    relation: Relation,
    limit: usize,
) -> Result<NativeProofShape, String> {
    NativeProofShape::from_trusted(air, key, config, profile, relation, context.binding, limit)
        .map_err(|_| "local salted native proof shape rejected".into())
}
pub(super) struct Verifier {
    context: Context,
    transaction: TransactionVerifier,
    settlement: SettlementVerifier,
    issuance: IssuanceVerifier,
    transaction_shape: NativeProofShape,
    settlement_shape: NativeProofShape,
    issuance_shape: NativeProofShape,
    transaction_context: TranscriptContext,
    settlement_context: TranscriptContext,
    issuance_context: TranscriptContext,
}
impl Verifier {
    pub(super) fn new(genesis: &Genesis) -> Result<Self, String> {
        // These process-local keys are derived only from compiled public AIRs.
        // A fresh process rebuilds them; no witness or private attempt is cached.
        struct Keys {
            transaction: PreprocessedVerifierKey<Config>,
            settlement: PreprocessedVerifierKey<Config>,
            issuance: PreprocessedVerifierKey<Config>,
        }
        static KEYS: OnceLock<Result<Keys, String>> = OnceLock::new();
        let keys = KEYS
            .get_or_init(|| {
                Ok(Keys {
                    transaction: TransactionVerifier::from_public_parameters(
                        Profile::transaction(),
                    )?
                    .verification_key()
                    .clone(),
                    settlement: SettlementVerifier::from_public_parameters(
                        SETTLEMENT_CAPACITY,
                        Profile::settlement(),
                    )?
                    .verification_key()
                    .clone(),
                    issuance: IssuanceVerifier::from_public_parameters(
                        crate::issuance::INITIAL_NOTES,
                        Profile::issuance(),
                    )?
                    .verification_key()
                    .clone(),
                })
            })
            .as_ref()
            .map_err(Clone::clone)?;
        Self::from_components(
            Context::from_genesis(genesis)?,
            TransactionVerifier::from_trusted_key(Profile::transaction(), keys.transaction.clone()),
            SettlementVerifier::from_trusted_key(
                SETTLEMENT_CAPACITY,
                Profile::settlement(),
                keys.settlement.clone(),
            ),
            IssuanceVerifier::from_trusted_key(
                crate::issuance::INITIAL_NOTES,
                Profile::issuance(),
                keys.issuance.clone(),
            ),
        )
    }
    fn from_components(
        context: Context,
        transaction: TransactionVerifier,
        settlement: SettlementVerifier,
        issuance: IssuanceVerifier,
    ) -> Result<Self, String> {
        let transaction_shape = shape(
            context,
            &transaction.air,
            transaction.verification_key(),
            transaction.public_config(),
            Profile::transaction(),
            Relation::Transaction,
            MAX_TRANSACTION_PROOF_BYTES,
        )?;
        let settlement_shape = shape(
            context,
            &settlement.air,
            settlement.verification_key(),
            settlement.public_config(),
            Profile::settlement(),
            Relation::Settlement,
            MAX_TRANSACTION_PROOF_BYTES,
        )?;
        let issuance_shape = shape(
            context,
            &issuance.air,
            issuance.verification_key(),
            issuance.public_config(),
            Profile::issuance(),
            Relation::Issuance,
            MAX_ISSUANCE_PROOF_BYTES,
        )?;
        let transcript =
            |identity| TranscriptContext::new(context.network, context.binding, identity);
        let transaction_context = transcript(transaction_shape.identity())?;
        let settlement_context = transcript(settlement_shape.identity())?;
        let issuance_context = transcript(issuance_shape.identity())?;
        Ok(Self {
            context,
            transaction,
            settlement,
            issuance,
            transaction_shape,
            settlement_shape,
            issuance_shape,
            transaction_context,
            settlement_context,
            issuance_context,
        })
    }
    pub(super) fn identity(&self, relation: Relation) -> Result<Identity, String> {
        match relation {
            Relation::Transaction => Ok(self.transaction_shape.identity()),
            Relation::Settlement => Ok(self.settlement_shape.identity()),
            Relation::Issuance => Ok(self.issuance_shape.identity()),
            Relation::CompleteFee => Err("complete fee is not a retained runtime relation".into()),
        }
    }
    #[cfg(siworld_native_node)]
    pub(super) fn authenticates(&self, genesis: &Genesis) -> bool {
        Context::from_genesis(genesis).is_ok_and(|context| context == self.context)
    }
    pub(super) fn transaction(
        &self,
        public: &PublicTransaction,
        context: &ProofContext,
        fee: &Digest,
        root: &Digest,
        frame: &[u8],
    ) -> Result<(), Failure> {
        check_context(context).map_err(preparation)?;
        if context.network != self.context.network {
            return Err(preparation(
                "salted transaction network differs from genesis",
            ));
        }
        PublicTransaction::decode(&public.encode()).map_err(|_| structure())?;
        let proof = self
            .transaction_shape
            .decode(frame)
            .map_err(|_| structure())?;
        self.transaction
            .verify_with_context(
                self.transaction_context,
                &proof,
                &public.statement(context, fee, root),
            )
            .map_err(|_| rejected(RejectedNativeRelation::Transaction))
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn settlement(
        &self,
        fees: &[Digest],
        plan: &RewardPlan,
        network: [u8; 32],
        list_hash: [u8; 32],
        rewards: &[Digest],
        frame: &[u8],
    ) -> Result<(), Failure> {
        if network != self.context.network {
            return Err(preparation(
                "salted settlement network differs from genesis",
            ));
        }
        let public =
            settlement_statement(fees, plan, network, list_hash, rewards).map_err(preparation)?;
        let proof = self
            .settlement_shape
            .decode(frame)
            .map_err(|_| structure())?;
        self.settlement
            .verify_with_context(self.settlement_context, &proof, &public)
            .map_err(|_| rejected(RejectedNativeRelation::Settlement))
    }
    pub(super) fn issuance(&self, record: &crate::issuance::IssuanceRecord) -> Result<(), Failure> {
        record.validate_shape().map_err(preparation)?;
        if record.signed.declaration.network != self.context.network {
            return Err(preparation("salted issuance network differs from genesis"));
        }
        let proof = self
            .issuance_shape
            .decode(&record.proof)
            .map_err(|_| structure())?;
        self.issuance
            .verify_with_context(
                self.issuance_context,
                &proof,
                &record.signed.declaration.public_inputs(),
            )
            .map_err(|_| rejected(RejectedNativeRelation::Issuance))
    }
}
pub(super) struct Prover {
    transaction: TransactionProver,
    settlement: SettlementProver,
    issuance: IssuanceProver,
    verifier: Verifier,
}
impl Prover {
    pub(super) fn new(genesis: &Genesis) -> Result<Self, String> {
        let transaction = TransactionProver::new(Profile::transaction())?;
        let settlement = SettlementProver::new(SETTLEMENT_CAPACITY, Profile::settlement())?;
        let issuance = IssuanceProver::new(crate::issuance::INITIAL_NOTES, Profile::issuance())?;
        let verifier = Verifier::from_components(
            Context::from_genesis(genesis)?,
            transaction.verifier(),
            settlement.verifier(),
            issuance.verifier(),
        )?;
        Ok(Self {
            transaction,
            settlement,
            issuance,
            verifier,
        })
    }
    pub(super) fn transaction(
        &self,
        witness: &AccWitness,
        public: &PublicTransaction,
        context: &ProofContext,
    ) -> Result<Vec<u8>, String> {
        check_context(context)?;
        if context.network != self.verifier.context.network {
            return Err("salted transaction network differs from genesis".into());
        }
        let bound = public
            .bind_witness(witness, context)
            .map_err(|_| "transaction witness binding rejected")?;
        let hasher = Hasher::new();
        let root = bound.anchors_root(&hasher);
        let height = context.snapshot().ok_or("missing canonical snapshot")?.0;
        bound
            .check_at_snapshot(&hasher, &root, height)
            .map_err(str::to_owned)?;
        let fee = hasher.fee_commit(bound.slot.fee, &bound.slot.fee_blind);
        let (proof, returned) = self.transaction.prove_at_snapshot_with_context(
            self.verifier.transaction_context,
            &bound,
            height,
        )?;
        if returned != public.statement(context, &fee, &root) {
            return Err("salted transaction statement reconstruction mismatch".into());
        }
        let frame = self
            .verifier
            .transaction_shape
            .encode(&proof)
            .map_err(|_| "salted transaction encoding failed")?;
        self.verifier
            .transaction(public, context, &fee, &root, &frame)
            .map_err(Failure::into_original)?;
        Ok(frame)
    }
    pub(super) fn settlement(&self, witness: &FixedSettlementWitness) -> Result<Vec<u8>, String> {
        if witness.network != self.verifier.context.network
            || witness.capacity() != SETTLEMENT_CAPACITY
        {
            return Err("salted settlement witness binding differs".into());
        }
        let (proof, public) = self
            .settlement
            .prove_with_context(self.verifier.settlement_context, witness)?;
        let fees = witness
            .slots
            .iter()
            .map(|slot| slot.commitment)
            .collect::<Vec<_>>();
        if public
            != settlement_statement(
                &fees,
                &witness.plan,
                witness.network,
                witness.transaction_list_digest,
                &witness.reward_commitments(),
            )?
        {
            return Err("salted settlement statement reconstruction mismatch".into());
        }
        let frame = self
            .verifier
            .settlement_shape
            .encode(&proof)
            .map_err(|_| "salted settlement encoding failed")?;
        self.verifier
            .settlement(
                &fees,
                &witness.plan,
                witness.network,
                witness.transaction_list_digest,
                &witness.reward_commitments(),
                &frame,
            )
            .map_err(Failure::into_original)?;
        Ok(frame)
    }
    pub(super) fn issuance(&self, witness: &IssuanceWitness) -> Result<Vec<u8>, String> {
        if witness.declaration.network != self.verifier.context.network
            || witness.notes.len() != crate::issuance::INITIAL_NOTES
        {
            return Err("salted issuance witness binding differs".into());
        }
        let (proof, public) = self
            .issuance
            .prove_with_context(self.verifier.issuance_context, witness)
            .map_err(|_| "salted issuance proving failed")?;
        if public != witness.declaration.public_inputs() {
            return Err("salted issuance statement reconstruction mismatch".into());
        }
        self.verifier
            .issuance
            .verify_with_context(self.verifier.issuance_context, &proof, &public)
            .map_err(|_| "salted issuance self-verification failed")?;
        self.verifier
            .issuance_shape
            .encode(&proof)
            .map_err(|_| "salted issuance encoding failed".into())
    }
}

#[cfg(all(test, siworld_native_node))]
mod tests {
    use super::*;
    use crate::eng2::{body::Body, execution::Engine, genesis::FeeMode, state_components::Limits};
    fn genesis() -> Genesis {
        let initial = crate::eng2::snapshot::tests::bootstrap();
        Genesis::seal(
            initial.chain.config.clone(),
            initial.governance.clone(),
            FeeMode::LegacyMiner,
        )
        .unwrap()
    }
    #[test]
    fn salted_genesis_identity_differs_from_legacy_and_binds_network_rules() {
        let first = genesis();
        assert_ne!(
            profile_fingerprint(),
            crate::proofs::legacy_profile_fingerprint()
        );
        let context = Context::from_genesis(&first).unwrap();
        assert_eq!(context.network, first.config().network);
        assert_eq!(context.binding.genesis, first.id());
        assert_eq!(context.binding.rules, first.rules_commitment());
        let mut config = first.config().clone();
        config.work_bits += 1;
        config.genesis_target = crate::state::Config::development(config.network, config.work_bits)
            .unwrap()
            .genesis_target;
        let other = Genesis::seal(
            config,
            first.initial_governance().clone(),
            FeeMode::LegacyMiner,
        )
        .unwrap();
        assert_ne!(
            context.binding,
            Context::from_genesis(&other).unwrap().binding
        );
    }
    #[test]
    fn engine_rejects_unbound_legacy_verifier_before_template_or_state_changes() {
        let selected = genesis();
        let engine = Engine::new(
            selected,
            Limits {
                max_leaves: 10000,
                max_nullifiers: 10000,
                max_component_bytes: 16 * 1024 * 1024,
            },
        )
        .unwrap();
        let before = (engine.state().height(), engine.state().tip());
        let body = Body {
            network: engine.state().network(),
            height: 1,
            profile: profile_fingerprint(),
            transactions: Vec::new(),
            reward_mode: siworld_core::v1_economics::RewardMode::Holder,
            rewards: Vec::new(),
            fee_output: crate::eng2::execution::legacy_fee_output(),
            fund_claims: Vec::new(),
            governance: Vec::new(),
            issuances: Vec::new(),
            settlement_proof: vec![1],
        };
        let verifier = crate::proofs::NativeVerifier::new().unwrap();
        assert!(!verifier.authenticates(engine.genesis()));
        let result = engine.prepare_header(&body, 1, &verifier);
        assert!(
            matches!(result, Err(ref error) if error == "native verifier differs from sealed salted genesis")
        );
        assert_eq!(before, (engine.state().height(), engine.state().tip()));
    }
    #[test]
    fn genesis_bound_shapes_reject_v1_and_wrong_frame_identity_for_all_relations() {
        let selected = genesis();
        let verifier = Verifier::new(&selected).unwrap();
        assert!(verifier.authenticates(&selected));
        for shape in [
            &verifier.transaction_shape,
            &verifier.settlement_shape,
            &verifier.issuance_shape,
        ] {
            assert!(shape.decode(&[1; 64]).is_err());
            let limit = if shape.identity().relation == Relation::Issuance {
                MAX_ISSUANCE_PROOF_BYTES
            } else {
                MAX_TRANSACTION_PROOF_BYTES
            };
            let mut frame = crate::proof_codec::v2::encode(shape.identity(), &[0], limit).unwrap();
            assert!(crate::proof_codec::v2::parse(&frame, shape.identity(), limit).is_ok());
            assert!(shape.decode(&frame).is_err());
            frame[12] ^= 1;
            assert_eq!(
                crate::proof_codec::v2::parse(&frame, shape.identity(), limit),
                Err(crate::proof_codec::v2::FrameError::Identity)
            );
            assert!(shape.decode(&frame).is_err());
        }
        let mut config = selected.config().clone();
        config.work_bits += 1;
        config.genesis_target = crate::state::Config::development(config.network, config.work_bits)
            .unwrap()
            .genesis_target;
        let other = Genesis::seal(
            config,
            selected.initial_governance().clone(),
            FeeMode::LegacyMiner,
        )
        .unwrap();
        assert!(!verifier.authenticates(&other));
    }
}
