//! Native-only conversion from opaque completed-verifier evidence.
use super::{CommitKnowledge, Failure, OtherClass, Phase, Relation};
use crate::proofs::{
    NativePreparation, NativeRejectionEvidence, NativeVerificationFailure, NativeVerifier,
    RejectedNativeRelation,
};
use native::codec::{ProofContext, PublicTransaction};
use native::multi_asset::Digest;
use native::settlement::RewardPlan;

impl NativeRejectionEvidence {
    pub(crate) fn relation(self) -> Relation {
        match self.kind() {
            RejectedNativeRelation::Transaction => Relation::Transaction,
            RejectedNativeRelation::Settlement => Relation::LegacySettlement,
            RejectedNativeRelation::Issuance => Relation::Issuance,
        }
    }
}

impl NativeVerificationFailure {
    fn into_observation(self) -> Failure {
        match self {
            Self::Preparation(original, preparation) => Failure::other(
                original,
                match preparation {
                    NativePreparation::Context => OtherClass::CandidateValidation,
                    NativePreparation::Structure => OtherClass::ProofStructure,
                },
                Phase::ProofPreparation,
                CommitKnowledge::NotReached,
            ),
            Self::Rejected(evidence) => Failure::from_native_verifier(evidence),
        }
    }
}

impl NativeVerifier {
    pub(crate) fn verify_issuance_diagnosed(
        &self,
        record: &crate::issuance::IssuanceRecord,
    ) -> Result<(), Failure> {
        self.verify_issuance_typed(record)
            .map_err(NativeVerificationFailure::into_observation)
    }
    pub(crate) fn verify_transaction_diagnosed(
        &self,
        public: &PublicTransaction,
        context: &ProofContext,
        fee: &Digest,
        root: &Digest,
        proof: &[u8],
    ) -> Result<(), Failure> {
        self.verify_transaction_typed(public, context, fee, root, proof)
            .map_err(NativeVerificationFailure::into_observation)
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn verify_settlement_diagnosed(
        &self,
        fees: &[Digest],
        plan: &RewardPlan,
        network: [u8; 32],
        list_hash: [u8; 32],
        rewards: &[Digest],
        proof: &[u8],
    ) -> Result<(), Failure> {
        self.verify_settlement_typed(fees, plan, network, list_hash, rewards, proof)
            .map_err(NativeVerificationFailure::into_observation)
    }
}
