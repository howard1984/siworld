//! Fixed-profile native proof adapters for the separate engineering network.

#[path = "proofs/hiding.rs"]
mod hiding;

use crate::proof_codec::{
    MAX_SETTLEMENT_PROOF_BODY_LEN, MAX_TRANSACTION_PROOF_BODY_LEN, ProofShape,
};
use native::codec::{FORMAT_VERSION, ProofContext, PublicTransaction};
use native::multi_asset::{AccWitness, Digest, F, Hasher};
use native::multi_asset_transaction::{TransactionAir, TransactionProver};
use native::settlement::{
    FixedSettlementWitness, RewardPlan, SettlementAir, SettlementProver, validate_settlement_public,
};
use native::{Cfg, FriParams};
use p3_air::{
    Air, BaseAir,
    symbolic::{AirLayout, SymbolicAirBuilder, get_max_constraint_degree},
};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_symmetric::MerkleCap;
use p3_uni_stark::{PreprocessedVerifierKey, verify_with_preprocessed};
use sha2::{Digest as _, Sha256};
use std::sync::OnceLock;

const MANIFEST: &[u8] =
    include_bytes!("../../bench-multi-asset/artifacts/v1-native-proof-profiles.json");
const MANIFEST_SHA256: &str = "c50622d69bdb6db816121dd716255f64ab796c37fdab8a96675e34875ecb8664";
const KEY_HEADER: usize = 47;
const KEY_COMMITMENT: usize = 1 + 2 * 12 * 4;
const SETTLEMENT_CAPACITY: usize = 576;
// Bump when relation semantics change without changing the trusted dimensions.
// This identifier is independent of reports, source hashes and measurements.
const RELATION_REVISION: &[u8] = b"native-v1-economics-1";

#[derive(Clone, Copy)]
enum Relation {
    Transaction,
    Settlement,
}

impl Relation {
    #[cfg(test)]
    fn name(self) -> &'static str {
        match self {
            Self::Transaction => "transaction",
            Self::Settlement => "settlement",
        }
    }
    fn id(self) -> u8 {
        match self {
            Self::Transaction => 1,
            Self::Settlement => 2,
        }
    }
    fn capacity(self) -> u32 {
        match self {
            Self::Transaction => 0,
            Self::Settlement => SETTLEMENT_CAPACITY as u32,
        }
    }
    fn hash(self) -> &'static str {
        match self {
            Self::Transaction => "95f1062213f8475310d70e750662776f7c70c3aeea18a155511f16d91b4ae019",
            Self::Settlement => "121013f3aa709772c97bfb74f369e920e608818fc3d6abdafdeb385ef4ed440c",
        }
    }
    fn key_hex(self) -> &'static str {
        match self {
            Self::Transaction => {
                "53574d5001000100000000070000002900000014000000000000001400000001000000f70000000900000061000000024caa9036bdc17f000261f26a7e2a8720d728662df8e6dc329adaa24c8069757821754e6128445b7c6bcf8755b3c29471506755375888a26c2436f61248d39375a1adea57d05ec969cdbe5c2b11780d107269f831d5af42353822f123a74c0710"
            }
            Self::Settlement => {
                "53574d5001000240020000080000002400000014000000000000001400000001000000610200000b00000061000000027b37d36275d64d34f8b4676aaa32582fc569ac42391b5e15584bcf60ec5519575fd1fb2af8895634c02824717c41667ae8b92273779fb57b864e0c40fced5a26c10f6853d046dc2cfdf5e0098b807a0c2c1fad6e5ffa3e06f85aaa6101105f07"
            }
        }
    }
    fn params(self) -> FriParams {
        let (log_blowup, num_queries) = match self {
            Self::Transaction => (7, 41),
            Self::Settlement => (8, 36),
        };
        FriParams {
            log_blowup,
            num_queries,
            query_pow_bits: 20,
            commit_pow_bits: 0,
            batch_pow_bits: 20,
            max_log_arity: 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TrustedAirShape {
    main_width: u64,
    preprocessed_width: u64,
    public_values: u64,
    base_height: u64,
    constraint_degree: u64,
}

impl TrustedAirShape {
    fn from_air<A: Air<SymbolicAirBuilder<F>>>(air: &A, base_height: usize) -> Self {
        Self {
            main_width: air.width() as u64,
            preprocessed_width: air.preprocessed_width() as u64,
            public_values: air.num_public_values() as u64,
            base_height: base_height as u64,
            constraint_degree: get_max_constraint_degree::<F, A>(
                air,
                AirLayout::from_air(air),
                base_height,
            ) as u64,
        }
    }
}

// Construct only deterministic AIR schedules and metadata. Neither this path
// nor symbolic degree extraction constructs a trace, key, prover or proof.
fn trusted_airs() -> (TransactionAir, SettlementAir) {
    (
        TransactionAir::new().with_min_height(Relation::Transaction.params().hiding_min_height()),
        SettlementAir::new(SETTLEMENT_CAPACITY)
            .with_min_height(Relation::Settlement.params().hiding_min_height()),
    )
}

fn trusted_air_shapes() -> [TrustedAirShape; 2] {
    let (transaction, settlement) = trusted_airs();
    [
        TrustedAirShape::from_air(&transaction, transaction.slot.height),
        TrustedAirShape::from_air(&settlement, settlement.height),
    ]
}

/// Consensus identity of the exact fixed proof relations. SWMP encodings bind
/// kind, capacity, FRI parameters, preprocessing dimensions and roots; the
/// semantic revision and actual AIR shapes also bind the admission decoder.
/// Measurement reports and their source hashes are deliberately excluded.
/// Only trusted local constructors and fixed constants enter this identity.
pub(crate) fn legacy_profile_fingerprint() -> [u8; 32] {
    static FINGERPRINT: OnceLock<[u8; 32]> = OnceLock::new();
    *FINGERPRINT.get_or_init(|| {
        let transaction = decode_hex(Relation::Transaction.key_hex())
            .expect("fixed transaction key has canonical hex encoding");
        let settlement = decode_hex(Relation::Settlement.key_hex())
            .expect("fixed settlement key has canonical hex encoding");
        profile_fingerprint_from_keys(
            native::codec::SUITE_ID,
            FORMAT_VERSION,
            RELATION_REVISION,
            &transaction,
            &settlement,
            &trusted_air_shapes(),
        )
    })
}

/// The active engineering profile binds the retained AIRs and the complete
/// deterministic V2 preprocessing recipe. Network genesis and rules are bound
/// separately in every V2 frame identity.
pub(crate) fn protocol_profile_fingerprint() -> [u8; 32] {
    hiding::profile_fingerprint()
}

fn profile_fingerprint_from_keys(
    suite: &[u8],
    version: u16,
    revision: &[u8],
    transaction: &[u8],
    settlement: &[u8],
    shapes: &[TrustedAirShape; 2],
) -> [u8; 32] {
    let mut hash = blake3::Hasher::new_derive_key("siworld native protocol proof profile v1");
    hash.update(&version.to_le_bytes());
    hash.update(&(suite.len() as u64).to_le_bytes());
    hash.update(suite);
    hash.update(&(revision.len() as u64).to_le_bytes());
    hash.update(revision);
    for ((relation, key), shape) in [(1u8, transaction), (2u8, settlement)]
        .into_iter()
        .zip(shapes)
    {
        hash.update(&[relation]);
        hash.update(&(key.len() as u64).to_le_bytes());
        hash.update(key);
        for dimension in [
            shape.main_width,
            shape.preprocessed_width,
            shape.public_values,
            shape.base_height,
            shape.constraint_degree,
        ] {
            hash.update(&dimension.to_le_bytes());
        }
    }
    hash.update(&crate::issuance::profile_id());
    *hash.finalize().as_bytes()
}

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2)
        || text
            .bytes()
            .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
    {
        return Err("noncanonical frozen artifact hex".into());
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |b| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            Ok((digit(pair[0]) << 4) | digit(pair[1]))
        })
        .collect()
}

fn has_hash(bytes: &[u8], hash: &str) -> Result<bool, String> {
    Ok(Sha256::digest(bytes).as_slice() == decode_hex(hash)?)
}

fn frozen_key_bytes(relation: Relation) -> Result<Vec<u8>, String> {
    if !has_hash(MANIFEST, MANIFEST_SHA256)? {
        return Err("frozen native relation manifest authentication failed".into());
    }
    decode_hex(relation.key_hex())
}

/// Load authenticated public commitments directly, without constructing any
/// preprocessing trace, prover data or proof. No input from a peer reaches
/// this function. The fixed two-root cap is decoded without dynamic lengths.
fn load_key(relation: Relation, bytes: &[u8]) -> Result<PreprocessedVerifierKey<Cfg>, String> {
    if bytes.len() != KEY_HEADER + KEY_COMMITMENT || !has_hash(bytes, relation.hash())? {
        return Err("frozen native public key authentication failed".into());
    }
    let word = |offset| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    if &bytes[..6] != b"SWMP\x01\x00" || bytes[6] != relation.id() || word(7) != relation.capacity()
    {
        return Err("frozen native public key relation mismatch".into());
    }
    let p = relation.params();
    let parameters = [
        p.log_blowup,
        p.num_queries,
        p.query_pow_bits,
        p.commit_pow_bits,
        p.batch_pow_bits,
        p.max_log_arity,
    ];
    if parameters
        .iter()
        .enumerate()
        .any(|(i, v)| word(11 + 4 * i) != *v)
        || word(43) as usize != KEY_COMMITMENT
        || bytes[KEY_HEADER] != 2
    {
        return Err("frozen native public key profile mismatch".into());
    }
    let mut roots = vec![[F::ZERO; 12]; 2];
    for (value, encoded) in roots
        .iter_mut()
        .flatten()
        .zip(bytes[KEY_HEADER + 1..].as_chunks::<4>().0.iter())
    {
        let raw = u32::from_le_bytes(*encoded);
        if raw >= F::ORDER_U32 {
            return Err("noncanonical frozen preprocessing commitment".into());
        }
        // Public-key artifacts use P3's fixed-width Montgomery-word serde,
        // unlike the canonical integers used in transaction public codecs.
        // Decode only this authenticated four-byte scalar, with no vectors.
        *value = postcard::from_bytes(encoded)
            .map_err(|_| "invalid frozen preprocessing field encoding")?;
    }
    Ok(PreprocessedVerifierKey {
        width: word(35) as usize,
        degree_bits: word(39) as usize,
        commitment: MerkleCap::new(roots),
    })
}

fn check_context(context: &ProofContext) -> Result<(), String> {
    if context.version() != FORMAT_VERSION || context.snapshot().is_none() {
        return Err("native transaction requires a locally selected canonical snapshot".into());
    }
    Ok(())
}

fn settlement_statement(
    fees: &[Digest],
    plan: &RewardPlan,
    network: [u8; 32],
    list_hash: [u8; 32],
    rewards: &[Digest],
) -> Result<Vec<F>, String> {
    if fees.len() != SETTLEMENT_CAPACITY {
        return Err(
            "native settlement requires exactly 576 locally derived fee commitments".into(),
        );
    }
    native::settlement::settlement_public(fees, plan, network, list_hash, rewards)
}

/// Verification-only resident data, authenticated against local fixed keys.
/// This constructor never invokes preprocessing setup or a prover.
pub struct NativeVerifier {
    hiding: Option<hiding::Verifier>,
    transaction_cfg: Cfg,
    transaction_air: TransactionAir,
    transaction_vk: PreprocessedVerifierKey<Cfg>,
    transaction_shape: ProofShape,
    settlement_cfg: Cfg,
    settlement_air: SettlementAir,
    settlement_vk: PreprocessedVerifierKey<Cfg>,
    settlement_shape: ProofShape,
    issuance: crate::issuance::IssuanceVerifier,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum RejectedNativeRelation {
    Transaction,
    Settlement,
    Issuance,
}

/// Constructed only after a completed native verifier returns rejection.
/// Private fields prevent callers from attributing arbitrary local errors.
#[derive(Debug)]
pub(crate) struct NativeRejectionEvidence {
    relation: RejectedNativeRelation,
}

impl NativeRejectionEvidence {
    fn original_error(self) -> &'static str {
        match self.kind() {
            RejectedNativeRelation::Transaction => "native transaction proof verification failed",
            RejectedNativeRelation::Settlement => "native settlement proof verification failed",
            RejectedNativeRelation::Issuance => "native issuance proof verification failed",
        }
    }

    pub(crate) fn kind(self) -> RejectedNativeRelation {
        self.relation
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum NativePreparation {
    Context,
    Structure,
}

#[derive(Debug)]
pub(crate) enum NativeVerificationFailure {
    Preparation(String, NativePreparation),
    Rejected(NativeRejectionEvidence),
}

impl NativeVerificationFailure {
    fn into_original(self) -> String {
        match self {
            Self::Preparation(
                original,
                NativePreparation::Context | NativePreparation::Structure,
            ) => original,
            Self::Rejected(evidence) => evidence.original_error().into(),
        }
    }
}

impl NativeVerifier {
    /// Select the mandatory salted profile from an already sealed genesis.
    /// This constructor never accepts a frame-selected AIR, key or binding.
    pub fn for_genesis(genesis: &crate::eng2::genesis::Genesis) -> Result<Self, String> {
        let mut verifier = Self::new()?;
        verifier.hiding = Some(hiding::Verifier::new(genesis)?);
        Ok(verifier)
    }
    /// Read-only public metadata for the locally selected retained proof domain.
    pub fn proof_identity(
        &self,
        relation: crate::proof_codec::v2::Relation,
    ) -> Result<crate::proof_codec::v2::Identity, String> {
        self.hiding
            .as_ref()
            .ok_or("proof identity requires a sealed salted genesis")?
            .identity(relation)
    }
    pub(crate) fn authenticates(&self, genesis: &crate::eng2::genesis::Genesis) -> bool {
        self.hiding
            .as_ref()
            .is_some_and(|v| v.authenticates(genesis))
    }
    pub fn new() -> Result<Self, String> {
        let tp = Relation::Transaction.params();
        let sp = Relation::Settlement.params();
        let transaction_cfg = tp.config();
        let settlement_cfg = sp.config();
        let (transaction_air, settlement_air) = trusted_airs();
        let transaction_vk = load_key(
            Relation::Transaction,
            &frozen_key_bytes(Relation::Transaction)?,
        )?;
        let settlement_vk = load_key(
            Relation::Settlement,
            &frozen_key_bytes(Relation::Settlement)?,
        )?;
        if transaction_vk.width != transaction_air.preprocessed_width()
            || transaction_vk.degree_bits != transaction_air.degree_bits() + 1
            || settlement_vk.width != settlement_air.preprocessed_width()
            || settlement_vk.degree_bits != settlement_air.degree_bits() + 1
        {
            return Err("native AIR differs from frozen verification key dimensions".into());
        }
        let transaction_shape = ProofShape::from_trusted(
            &transaction_air,
            &transaction_vk,
            &transaction_cfg,
            MAX_TRANSACTION_PROOF_BODY_LEN,
        )
        .map_err(|e| e.to_string())?;
        let settlement_shape = ProofShape::from_trusted(
            &settlement_air,
            &settlement_vk,
            &settlement_cfg,
            MAX_SETTLEMENT_PROOF_BODY_LEN,
        )
        .map_err(|e| e.to_string())?;
        Ok(Self {
            hiding: None,
            transaction_cfg,
            transaction_air,
            transaction_vk,
            transaction_shape,
            settlement_cfg,
            settlement_air,
            settlement_vk,
            settlement_shape,
            issuance: crate::issuance::IssuanceVerifier::new()?,
        })
    }

    pub fn verify_issuance(&self, record: &crate::issuance::IssuanceRecord) -> Result<(), String> {
        self.verify_issuance_typed(record)
            .map_err(NativeVerificationFailure::into_original)
    }

    pub(crate) fn verify_issuance_typed(
        &self,
        record: &crate::issuance::IssuanceRecord,
    ) -> Result<(), NativeVerificationFailure> {
        if let Some(verifier) = &self.hiding {
            return verifier.issuance(record);
        }
        use crate::issuance::IssuanceVerificationFailure;
        self.issuance
            .verify_typed(record)
            .map_err(|error| match error {
                IssuanceVerificationFailure::Preparation(original) => {
                    NativeVerificationFailure::Preparation(original, NativePreparation::Structure)
                }
                IssuanceVerificationFailure::Rejected(_evidence) => {
                    NativeVerificationFailure::Rejected(NativeRejectionEvidence {
                        relation: RejectedNativeRelation::Issuance,
                    })
                }
            })
    }

    pub fn verify_transaction(
        &self,
        public: &PublicTransaction,
        context: &ProofContext,
        fee: &Digest,
        root: &Digest,
        proof: &[u8],
    ) -> Result<(), String> {
        self.verify_transaction_typed(public, context, fee, root, proof)
            .map_err(NativeVerificationFailure::into_original)
    }

    pub(crate) fn verify_transaction_typed(
        &self,
        public: &PublicTransaction,
        context: &ProofContext,
        fee: &Digest,
        root: &Digest,
        proof: &[u8],
    ) -> Result<(), NativeVerificationFailure> {
        if let Some(verifier) = &self.hiding {
            return verifier.transaction(public, context, fee, root, proof);
        }
        check_context(context).map_err(|original| {
            NativeVerificationFailure::Preparation(original, NativePreparation::Context)
        })?;
        PublicTransaction::decode(&public.encode()).map_err(|e| {
            NativeVerificationFailure::Preparation(
                format!("public transaction: {e:?}"),
                NativePreparation::Structure,
            )
        })?;
        let proof = self.transaction_shape.decode(proof).map_err(|e| {
            NativeVerificationFailure::Preparation(e.to_string(), NativePreparation::Structure)
        })?;
        let statement = public.statement(context, fee, root);
        verify_with_preprocessed(
            &self.transaction_cfg,
            &self.transaction_air,
            &proof,
            &statement,
            Some(&self.transaction_vk),
        )
        .map_err(|_| {
            NativeVerificationFailure::Rejected(NativeRejectionEvidence {
                relation: RejectedNativeRelation::Transaction,
            })
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_settlement(
        &self,
        fees: &[Digest],
        plan: &RewardPlan,
        network: [u8; 32],
        list_hash: [u8; 32],
        rewards: &[Digest],
        proof: &[u8],
    ) -> Result<(), String> {
        self.verify_settlement_typed(fees, plan, network, list_hash, rewards, proof)
            .map_err(NativeVerificationFailure::into_original)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn verify_settlement_typed(
        &self,
        fees: &[Digest],
        plan: &RewardPlan,
        network: [u8; 32],
        list_hash: [u8; 32],
        rewards: &[Digest],
        proof: &[u8],
    ) -> Result<(), NativeVerificationFailure> {
        if let Some(verifier) = &self.hiding {
            return verifier.settlement(fees, plan, network, list_hash, rewards, proof);
        }
        let public =
            settlement_statement(fees, plan, network, list_hash, rewards).map_err(|original| {
                NativeVerificationFailure::Preparation(original, NativePreparation::Context)
            })?;
        let proof = self.settlement_shape.decode(proof).map_err(|e| {
            NativeVerificationFailure::Preparation(e.to_string(), NativePreparation::Structure)
        })?;
        verify_with_preprocessed(
            &self.settlement_cfg,
            &self.settlement_air,
            &proof,
            &public,
            Some(&self.settlement_vk),
        )
        .map_err(|_| {
            NativeVerificationFailure::Rejected(NativeRejectionEvidence {
                relation: RejectedNativeRelation::Settlement,
            })
        })
    }
}

/// Fixed-profile resident prover for a disposable single-node engineering
/// network. Preprocessing occurs once at service startup and remains resident.
pub struct NativeProver {
    hiding: Option<hiding::Prover>,
    transaction: Option<TransactionProver>,
    settlement: Option<SettlementProver>,
    verifier: NativeVerifier,
}

fn same_key(left: &PreprocessedVerifierKey<Cfg>, right: &PreprocessedVerifierKey<Cfg>) -> bool {
    left.width == right.width
        && left.degree_bits == right.degree_bits
        && left.commitment == right.commitment
}

impl NativeProver {
    pub fn for_genesis(genesis: &crate::eng2::genesis::Genesis) -> Result<Self, String> {
        Ok(Self {
            hiding: Some(hiding::Prover::new(genesis)?),
            transaction: None,
            settlement: None,
            // The historical verifier is retained only for the separate V1 API.
            verifier: NativeVerifier::new()?,
        })
    }
    /// Generates the fixed three-note V2 issuance proof; record policy and
    /// declaration signatures remain independently checked by admission.
    pub fn issuance(&self, witness: &native::issuance::IssuanceWitness) -> Result<Vec<u8>, String> {
        self.hiding
            .as_ref()
            .ok_or("issuance requires sealed V2 genesis")?
            .issuance(witness)
    }
    pub fn new() -> Result<Self, String> {
        let verifier = NativeVerifier::new()?;
        let transaction = TransactionProver::new(Relation::Transaction.params());
        let settlement = SettlementProver::new(SETTLEMENT_CAPACITY, Relation::Settlement.params());
        if !same_key(&transaction.vk, &verifier.transaction_vk)
            || !same_key(&settlement.vk, &verifier.settlement_vk)
        {
            return Err(
                "resident prover preprocessing differs from frozen verification keys".into(),
            );
        }
        Ok(Self {
            hiding: None,
            transaction: Some(transaction),
            settlement: Some(settlement),
            verifier,
        })
    }

    pub fn transaction(
        &self,
        witness: &AccWitness,
        public: &PublicTransaction,
        context: &ProofContext,
    ) -> Result<Vec<u8>, String> {
        if let Some(prover) = &self.hiding {
            return prover.transaction(witness, public, context);
        }
        check_context(context)?;
        let bound = public
            .bind_witness(witness, context)
            .map_err(|e| format!("transaction witness binding: {e:?}"))?;
        let hasher = Hasher::new();
        let root = bound.anchors_root(&hasher);
        let snapshot_height = context.snapshot().ok_or("missing canonical snapshot")?.0;
        bound
            .check_at_snapshot(&hasher, &root, snapshot_height)
            .map_err(str::to_owned)?;
        let fee = hasher.fee_commit(bound.slot.fee, &bound.slot.fee_blind);
        let (proof, generated_statement) = self
            .transaction
            .as_ref()
            .ok_or("legacy transaction prover unavailable")?
            .prove_at_snapshot(&bound, snapshot_height);
        if generated_statement != public.statement(context, &fee, &root) {
            return Err("native prover statement reconstruction mismatch".into());
        }
        let bytes = postcard::to_allocvec(&proof).map_err(|e| e.to_string())?;
        self.verifier
            .verify_transaction(public, context, &fee, &root, &bytes)?;
        Ok(bytes)
    }

    pub fn settlement(&self, witness: &FixedSettlementWitness) -> Result<Vec<u8>, String> {
        if let Some(prover) = &self.hiding {
            return prover.settlement(witness);
        }
        if witness.capacity() != SETTLEMENT_CAPACITY {
            return Err("native settlement witness capacity must be 576".into());
        }
        witness
            .check(&Hasher::new())
            .map_err(|_| "invalid local settlement witness".to_owned())?;
        let (proof, public) = self
            .settlement
            .as_ref()
            .ok_or("legacy settlement prover unavailable")?
            .prove(witness);
        validate_settlement_public(SETTLEMENT_CAPACITY, &public)?;
        let bytes = postcard::to_allocvec(&proof).map_err(|e| e.to_string())?;
        let fees: Vec<_> = witness.slots.iter().map(|slot| slot.commitment).collect();
        self.verifier.verify_settlement(
            &fees,
            &witness.plan,
            witness.network,
            witness.transaction_list_digest,
            &witness.reward_commitments(),
            &bytes,
        )?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_profile_binds_suite_version_and_both_exact_keys() {
        let transaction = decode_hex(Relation::Transaction.key_hex()).unwrap();
        let settlement = decode_hex(Relation::Settlement.key_hex()).unwrap();
        let shapes = trusted_air_shapes();
        let fingerprint_for_keys =
            |suite: &[u8], version, transaction: &[u8], settlement: &[u8]| {
                profile_fingerprint_from_keys(
                    suite,
                    version,
                    RELATION_REVISION,
                    transaction,
                    settlement,
                    &shapes,
                )
            };
        let fingerprint = fingerprint_for_keys(
            native::codec::SUITE_ID,
            FORMAT_VERSION,
            &transaction,
            &settlement,
        );
        assert_eq!(fingerprint, protocol_profile_fingerprint());
        assert_eq!(fingerprint, protocol_profile_fingerprint());
        assert_ne!(
            fingerprint,
            fingerprint_for_keys(
                b"different-proof-suite",
                FORMAT_VERSION,
                &transaction,
                &settlement,
            )
        );
        assert_ne!(
            fingerprint,
            fingerprint_for_keys(
                native::codec::SUITE_ID,
                FORMAT_VERSION + 1,
                &transaction,
                &settlement,
            )
        );
        // Include relation type/capacity, each FRI word, dimensions and every
        // preprocessing-commitment byte, not only the decoded AIR dimensions.
        for (kind, original) in [&transaction, &settlement].into_iter().enumerate() {
            for offset in 0..original.len() {
                let mut changed = original.to_vec();
                changed[offset] ^= 1;
                let candidate = if kind == 0 {
                    fingerprint_for_keys(
                        native::codec::SUITE_ID,
                        FORMAT_VERSION,
                        &changed,
                        &settlement,
                    )
                } else {
                    fingerprint_for_keys(
                        native::codec::SUITE_ID,
                        FORMAT_VERSION,
                        &transaction,
                        &changed,
                    )
                };
                assert_ne!(fingerprint, candidate, "relation {kind}, offset {offset}");
            }
        }
        assert_ne!(
            fingerprint,
            fingerprint_for_keys(
                native::codec::SUITE_ID,
                FORMAT_VERSION,
                &settlement,
                &transaction,
            )
        );
    }

    #[test]
    fn protocol_profile_uses_the_actual_trusted_air_shapes() {
        let (transaction, settlement) = trusted_airs();
        let shapes = trusted_air_shapes();
        for (shape, width, preprocessed, public, height, degree) in [
            (
                shapes[0],
                transaction.width(),
                transaction.preprocessed_width(),
                transaction.num_public_values(),
                transaction.slot.height,
                get_max_constraint_degree::<F, _>(
                    &transaction,
                    AirLayout::from_air(&transaction),
                    transaction.slot.height,
                ),
            ),
            (
                shapes[1],
                settlement.width(),
                settlement.preprocessed_width(),
                settlement.num_public_values(),
                settlement.height,
                get_max_constraint_degree::<F, _>(
                    &settlement,
                    AirLayout::from_air(&settlement),
                    settlement.height,
                ),
            ),
        ] {
            assert_eq!(shape.main_width, width as u64);
            assert_eq!(shape.preprocessed_width, preprocessed as u64);
            assert_eq!(shape.public_values, public as u64);
            assert_eq!(shape.base_height, height as u64);
            assert_eq!(shape.constraint_degree, degree as u64);
        }
    }

    #[test]
    fn unchanged_keys_cannot_reuse_genesis_with_a_different_relation_or_shape() {
        let transaction = decode_hex(Relation::Transaction.key_hex()).unwrap();
        let settlement = decode_hex(Relation::Settlement.key_hex()).unwrap();
        let shapes = trusted_air_shapes();
        let profile = |revision: &[u8], shapes: &[TrustedAirShape; 2]| {
            profile_fingerprint_from_keys(
                native::codec::SUITE_ID,
                FORMAT_VERSION,
                revision,
                &transaction,
                &settlement,
                shapes,
            )
        };
        let original = profile(RELATION_REVISION, &shapes);
        let config = crate::state::Config::development([95; 32], 0).unwrap();
        let genesis = config.genesis_id();
        assert_eq!(original, protocol_profile_fingerprint());
        assert_eq!(genesis, config.genesis_id_for_profile(&original));
        let changed_revision = profile(b"different-relation-revision", &shapes);
        assert_ne!(original, changed_revision);
        assert_ne!(genesis, config.genesis_id_for_profile(&changed_revision));
        // Main-trace optimizations can retain exactly the same SWMP bytes.
        // Every trusted shape component must still change network identity.
        for relation in 0..shapes.len() {
            for dimension in 0..5 {
                let mut changed = shapes;
                let shape = &mut changed[relation];
                match dimension {
                    0 => shape.main_width += 1,
                    1 => shape.preprocessed_width += 1,
                    2 => shape.public_values += 1,
                    3 => shape.base_height *= 2,
                    4 => shape.constraint_degree += 1,
                    _ => unreachable!(),
                }
                let candidate = profile(RELATION_REVISION, &changed);
                assert_ne!(
                    original, candidate,
                    "relation {relation}, dimension {dimension}"
                );
                assert_ne!(genesis, config.genesis_id_for_profile(&candidate));
            }
        }
    }

    #[test]
    fn frozen_public_keys_load_without_prover_setup() {
        assert!(NativeVerifier::new().is_ok());
    }

    #[test]
    fn embedded_relation_keys_match_the_authenticated_manifest() {
        let manifest: serde_json::Value = serde_json::from_slice(MANIFEST).unwrap();
        let relations = manifest["relations"].as_array().unwrap();
        for relation in [Relation::Transaction, Relation::Settlement] {
            let matching: Vec<_> = relations
                .iter()
                .filter(|entry| entry["kind"] == relation.name())
                .collect();
            assert_eq!(matching.len(), 1);
            let key = matching[0];
            assert_eq!(
                key["capacity"].as_u64(),
                Some(u64::from(relation.capacity()))
            );
            assert_eq!(key["public_verifier_key"]["encoding"], "SWMP-v1");
            assert_eq!(key["public_verifier_key"]["sha256"], relation.hash());
            assert_eq!(key["public_verifier_key"]["hex"], relation.key_hex());
        }
    }

    #[test]
    fn frozen_key_commitments_reencode_exact_montgomery_words() {
        for relation in [Relation::Transaction, Relation::Settlement] {
            let bytes = frozen_key_bytes(relation).unwrap();
            let key = load_key(relation, &bytes).unwrap();
            assert_eq!(
                postcard::to_allocvec(&key.commitment).unwrap(),
                bytes[KEY_HEADER..]
            );
        }
    }

    #[test]
    fn changed_public_key_cannot_select_its_own_authentication_hash() {
        let mut bytes = frozen_key_bytes(Relation::Transaction).unwrap();
        bytes[47] ^= 1;
        assert!(load_key(Relation::Transaction, &bytes).is_err());
    }

    #[test]
    fn relation_type_capacity_and_profile_mismatches_are_rejected() {
        let original = frozen_key_bytes(Relation::Transaction).unwrap();
        assert!(load_key(Relation::Settlement, &original).is_err());
        for offset in [0, 4, 6, 7, 11, 15, 19, 23, 27, 31, 35, 39, 43] {
            let mut bytes = original.clone();
            bytes[offset] ^= 1;
            assert!(load_key(Relation::Transaction, &bytes).is_err());
        }
        let mut trailing = original;
        trailing.push(0);
        assert!(load_key(Relation::Transaction, &trailing).is_err());
    }

    #[test]
    fn settlement_context_requires_fixed_capacity_and_mode_bound_rewards() {
        use native::settlement::{RewardAllocation, RewardMode, RewardPlan};
        let digest = [F::ZERO; 12];
        let plan = RewardPlan {
            block_height: 1,
            mode: RewardMode::Voyager,
            allocations: vec![RewardAllocation {
                amount: 1,
                unlock_height: 25,
            }],
        };
        assert!(settlement_statement(&[], &plan, [0; 32], [0; 32], &[digest]).is_err());
        let fees = vec![digest; 576];
        assert!(settlement_statement(&fees, &plan, [0; 32], [0; 32], &[]).is_err());
        let mut invalid = plan.clone();
        invalid.mode = RewardMode::Holder;
        assert!(settlement_statement(&fees, &invalid, [0; 32], [0; 32], &[digest]).is_err());
        invalid = plan;
        invalid.block_height = u64::MAX;
        assert!(settlement_statement(&fees, &invalid, [0; 32], [0; 32], &[digest]).is_err());
    }

    #[test]
    fn unbound_snapshot_and_malformed_proof_are_rejected() {
        let witness = native::multi_asset::sample_empty_witness(601);
        let public = fixture_public(&witness);
        let h = Hasher::new();
        let verifier = NativeVerifier::new().unwrap();
        let fee = h.fee_commit(0, &witness.slot.fee_blind);
        let root = witness.anchors_root(&h);
        assert!(
            verifier
                .verify_transaction(&public, &ProofContext::new([4; 32]), &fee, &root, &[],)
                .is_err()
        );
        let context = ProofContext::for_snapshot([4; 32], 600, [5; 32]);
        assert!(
            verifier
                .verify_transaction(&public, &context, &fee, &root, &[])
                .is_err()
        );
        assert!(
            verifier
                .verify_transaction(
                    &public,
                    &context,
                    &fee,
                    &root,
                    &vec![0; MAX_TRANSACTION_PROOF_BODY_LEN + 1],
                )
                .is_err()
        );
    }

    #[test]
    fn reconstructed_settlement_statement_matches_the_relation_codec() {
        let witness = native::settlement::sample_fixed_settlement_witness(
            576,
            native::settlement::RewardMode::Holder,
        );
        let fees: Vec<_> = witness.slots.iter().map(|s| s.commitment).collect();
        let rewards = witness.reward_commitments();
        let public = settlement_statement(
            &fees,
            &witness.plan,
            witness.network,
            witness.transaction_list_digest,
            &rewards,
        )
        .unwrap();
        assert_eq!(public, witness.public_inputs());
    }

    // This fixture tests the proof's complete byte binding. Ciphertext
    // correctness is separately enforced by wallet encryption self-checks.
    fn fixture_public(witness: &AccWitness) -> PublicTransaction {
        let fields = witness.slot.public_inputs(&Hasher::new());
        let mut body = [0u8; native::codec::PUBLIC_TRANSACTION_BYTES];
        for (i, digest) in fields.nf.iter().chain(&fields.cm_out).enumerate() {
            body[i * 48..(i + 1) * 48].copy_from_slice(&native::codec::encode_digest(digest));
        }
        PublicTransaction::decode(&body).unwrap()
    }

    #[test]
    #[ignore = "explicit fixed-profile proof compatibility check, not a benchmark"]
    fn fixed_profiles_roundtrip_rejects_context_and_body_mutation() {
        let prover = NativeProver::new().unwrap();
        let verifier = NativeVerifier::new().unwrap();
        let witness = native::multi_asset::sample_empty_witness(602);
        let public = fixture_public(&witness);
        let context = ProofContext::for_snapshot([6; 32], 600, [7; 32]);
        let h = Hasher::new();
        let fee = h.fee_commit(0, &witness.slot.fee_blind);
        let root = witness.anchors_root(&h);
        let proof = prover.transaction(&witness, &public, &context).unwrap();
        assert!(proof.len() <= MAX_TRANSACTION_PROOF_BODY_LEN);
        verifier
            .verify_transaction(&public, &context, &fee, &root, &proof)
            .unwrap();
        let changed_context = ProofContext::for_snapshot(context.network, 600, [8; 32]);
        assert!(
            verifier
                .verify_transaction(&public, &changed_context, &fee, &root, &proof)
                .is_err()
        );
        let mut changed = public.clone();
        changed.payment.body[0] ^= 1;
        assert!(
            verifier
                .verify_transaction(&changed, &context, &fee, &root, &proof)
                .is_err()
        );
        let mut corrupt = proof;
        corrupt[0] ^= 1;
        assert!(
            verifier
                .verify_transaction(&public, &context, &fee, &root, &corrupt)
                .is_err()
        );

        let settlement = native::settlement::sample_fixed_settlement_witness(
            576,
            native::settlement::RewardMode::Holder,
        );
        let fees: Vec<_> = settlement
            .slots
            .iter()
            .map(|slot| slot.commitment)
            .collect();
        let rewards = settlement.reward_commitments();
        let settlement_proof = prover.settlement(&settlement).unwrap();
        assert!(settlement_proof.len() <= MAX_SETTLEMENT_PROOF_BODY_LEN);
        verifier
            .verify_settlement(
                &fees,
                &settlement.plan,
                settlement.network,
                settlement.transaction_list_digest,
                &rewards,
                &settlement_proof,
            )
            .unwrap();
        for mutation in 0..4 {
            let mut plan = settlement.plan.clone();
            let mut changed_rewards = rewards.clone();
            let mut list = settlement.transaction_list_digest;
            match mutation {
                0 => plan.allocations[0].amount += 1,
                1 => plan.allocations[1].unlock_height += 1,
                2 => changed_rewards.swap(0, 1),
                _ => list[0] ^= 1,
            }
            assert!(
                verifier
                    .verify_settlement(
                        &fees,
                        &plan,
                        settlement.network,
                        list,
                        &changed_rewards,
                        &settlement_proof,
                    )
                    .is_err()
            );
        }
    }
}
