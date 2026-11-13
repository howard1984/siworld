//! Inactive single-AIR batch adapter for a separately authenticated fee circuit.
//!
//! This codec includes lookup/permutation openings and never falls back to the
//! uni-STARK schema. Structural admission is followed by the stock batch
//! verifier. Selecting a real fee AIR, its complete source digest and a genesis
//! registry remains the caller's obligation; this module selects no network.
use super::backend::{Config, Profile, PublicPreprocessing};
use super::{ConsensusProofLimits, FRAME_BYTES, Identity, ProtocolBinding, Relation};
use crate::proof_codec::{
    Cursor, DIGEST_ELEMENTS, EXTENSION_DEGREE, FoldShape, ProofDecodeError, RoundShape,
    power_of_two,
};
use ::native::{FriParams, multi_asset::F};
use p3_air::{Air, symbolic::AirLayout};
use p3_batch_stark::{
    BatchProof, CommonData, ProverData, folder::VerifierConstraintFolderWithLookups,
};
use p3_commit::Pcs;
use p3_field::TwoAdicField;
use p3_lookup::{InteractionSymbolicBuilder, LogUpGadget};
use p3_uni_stark::StarkGenericConfig;

type E = <Config as StarkGenericConfig>::Challenge;

const MAX_VECTOR_BYTES: usize = 32 * 1024 * 1024;
const SALTS: usize = 9;
const MASKS: usize = 8;
const QUERIES: usize = 80;
const BLOWUP: usize = 5;

pub fn profile() -> Profile {
    Profile::new(FriParams {
        log_blowup: BLOWUP as u32,
        num_queries: QUERIES as u32,
        query_pow_bits: 0,
        commit_pow_bits: 0,
        batch_pow_bits: 0,
        max_log_arity: 1,
    })
    .expect("fixed complete fee batch parameters")
}

#[derive(Debug)]
pub enum Error {
    TrustedConfiguration,
    Frame(super::FrameError),
    Body(ProofDecodeError),
    Verification,
}

/// A batch verifier owns the exact AIR and locally rebuilt preprocessing.
/// No key, geometry, public-input vector or circuit is selected by a frame.
pub struct CompleteFeeBatchVerifier<A> {
    public: PublicPreprocessing,
    air: A,
    common: CommonData<Config>,
    shape: CompleteFeeBatchShape,
}

impl<A> CompleteFeeBatchVerifier<A>
where
    A: Air<InteractionSymbolicBuilder<F, E>>
        + for<'a> Air<VerifierConstraintFolderWithLookups<'a, Config>>,
{
    pub fn from_authenticated_air(
        air: A,
        extended_degree_bits: usize,
        binding: ProtocolBinding,
    ) -> Result<Self, Error> {
        if !(9..=12).contains(&extended_degree_bits)
            || air.width() == 0
            || air.width() > 8192
            || air.preprocessed_width() == 0
            || air.preprocessed_width() > 2048
            || air.num_public_values() > 16384
            || air.num_periodic_columns() != 0
            || !air.public_boundary_io().is_empty()
            || [binding.genesis, binding.rules, binding.air].contains(&[0; 32])
        {
            return Err(Error::TrustedConfiguration);
        }
        let public = PublicPreprocessing::new(profile());
        let data = ProverData::from_airs_and_degrees(
            public.config(),
            core::slice::from_ref(&air),
            &[extended_degree_bits],
        )
        .map_err(|_| Error::TrustedConfiguration)?;
        let shape = CompleteFeeBatchShape::from_trusted(
            &air,
            &data.common,
            public.config(),
            extended_degree_bits,
            binding,
        )?;
        Ok(Self {
            public,
            air,
            common: data.common,
            shape,
        })
    }
    pub fn shape(&self) -> &CompleteFeeBatchShape {
        &self.shape
    }
    /// Rebuild `statement` from authenticated ordered block state, not the proof.
    /// This result is not a ledger-transition or canonical-context capability.
    pub fn verify(&self, frame: &[u8], statement: &[F]) -> Result<(), Error> {
        if statement.len() != self.air.num_public_values() {
            return Err(Error::TrustedConfiguration);
        }
        let proof = self.shape.decode(frame)?;
        p3_batch_stark::verify_batch(
            self.public.config(),
            core::slice::from_ref(&self.air),
            &proof,
            &[statement.to_vec()],
            &self.common,
        )
        .map_err(|_| Error::Verification)
    }
}

pub struct CompleteFeeBatchShape {
    identity: Identity,
    main: usize,
    pre: usize,
    main_next: bool,
    pre_next: bool,
    permutation: usize,
    chunks: usize,
    degree_bits: usize,
    input_roots: usize,
    input_path_hashes: usize,
    rounds: Vec<RoundShape>,
    folds: Vec<FoldShape>,
}
impl CompleteFeeBatchShape {
    fn from_trusted<A: Air<InteractionSymbolicBuilder<F, E>>>(
        air: &A,
        common: &CommonData<Config>,
        cfg: &Config,
        degree_bits: usize,
        binding: ProtocolBinding,
    ) -> Result<Self, Error> {
        if cfg.is_zk() != 1
            || cfg.pcs().profile().id() != profile().id()
            || cfg.ood_proof_of_work_bits() != 0
            || cfg.lookup_proof_of_work_bits() != 0
            || common.lookups.len() != 1
            || common.lookups[0].is_empty()
            || common.lookups[0].len() > 256
        {
            return Err(Error::TrustedConfiguration);
        }
        let preprocessed = common
            .preprocessed
            .as_ref()
            .ok_or(Error::TrustedConfiguration)?;
        if preprocessed.instances.len() != 1 || preprocessed.matrix_to_instance != [0] {
            return Err(Error::TrustedConfiguration);
        }
        let meta = preprocessed.instances[0]
            .as_ref()
            .ok_or(Error::TrustedConfiguration)?;
        if meta.matrix_index != 0
            || meta.width != air.preprocessed_width()
            || meta.degree_bits != degree_bits
        {
            return Err(Error::TrustedConfiguration);
        }
        let domain = <<Config as StarkGenericConfig>::Pcs as Pcs<
            E,
            <Config as StarkGenericConfig>::Challenger,
        >>::natural_domain_for_degree(
            cfg.pcs(),
            power_of_two(degree_bits - 1).map_err(Error::Body)?,
        );
        let log_chunks =
            p3_batch_stark::symbolic::get_log_num_quotient_chunks_for_domain::<F, E, A, _>(
                air,
                AirLayout::from_air(air),
                domain,
                &common.lookups[0],
                1,
                &LogUpGadget::new(),
            );
        let chunks = power_of_two(
            log_chunks
                .checked_add(1)
                .ok_or(Error::TrustedConfiguration)?,
        )
        .map_err(Error::Body)?;
        if chunks > 64 {
            return Err(Error::TrustedConfiguration);
        }
        let log_height = degree_bits
            .checked_add(BLOWUP)
            .filter(|n| *n <= F::TWO_ADICITY)
            .ok_or(Error::TrustedConfiguration)?;
        let input_roots = power_of_two(1.min(log_height)).map_err(Error::Body)?;
        if preprocessed.commitment.num_roots() != input_roots {
            return Err(Error::TrustedConfiguration);
        }
        let permutation = common.lookups[0]
            .len()
            .checked_add(1)
            .and_then(|n| n.checked_mul(EXTENSION_DEGREE))
            .ok_or(Error::TrustedConfiguration)?;
        let main_next = !air.main_next_row_columns().is_empty();
        let pre_next = !air.preprocessed_next_row_columns().is_empty();
        let rounds = vec![
            RoundShape {
                matrices: 1,
                width: EXTENSION_DEGREE + MASKS,
                points: 1,
                random_values: MASKS,
            },
            RoundShape {
                matrices: 1,
                width: air.width() + MASKS,
                points: 1 + usize::from(main_next),
                random_values: MASKS,
            },
            RoundShape {
                matrices: chunks,
                width: EXTENSION_DEGREE + MASKS,
                points: 1,
                random_values: MASKS,
            },
            RoundShape {
                matrices: 1,
                width: air.preprocessed_width(),
                points: 1 + usize::from(pre_next),
                random_values: 0,
            },
            RoundShape {
                matrices: 1,
                width: permutation + MASKS,
                points: 2,
                random_values: MASKS,
            },
        ];
        let mut current_height = log_height;
        let mut folds = Vec::new();
        for arity in p3_fri::fold_schedule(&[log_height], BLOWUP, 1) {
            current_height -= arity;
            let cap = 2.min(current_height);
            folds.push(FoldShape {
                cap_roots: power_of_two(cap).map_err(Error::Body)?,
                siblings: power_of_two(arity).map_err(Error::Body)? - 1,
                path_hashes: super::native::maximum_pruned_hashes(current_height, cap, QUERIES)
                    .map_err(Error::Body)?,
            });
        }
        let mut result = Self {
            identity: Identity {
                relation: Relation::CompleteFee,
                profile: [0; 32],
            },
            main: air.width(),
            pre: air.preprocessed_width(),
            main_next,
            pre_next,
            permutation,
            chunks,
            degree_bits,
            input_roots,
            input_path_hashes: super::native::maximum_pruned_hashes(
                log_height,
                1.min(log_height),
                QUERIES,
            )
            .map_err(Error::Body)?,
            rounds,
            folds,
        };
        let mut h = blake3::Hasher::new_derive_key("siworld native complete fee batch identity v2");
        h.update(b"SIWZKP2/batch-postcard/closed-single-AIR/permutation-lookup-terminal-zero");
        h.update(&ConsensusProofLimits.encode());
        for digest in [binding.genesis, binding.rules, binding.air, profile().id()] {
            h.update(&digest);
        }
        let key = postcard::to_allocvec(&preprocessed.commitment)
            .map_err(|_| Error::TrustedConfiguration)?;
        h.update(&(key.len() as u64).to_le_bytes());
        h.update(&key);
        for value in [
            result.main,
            result.pre,
            usize::from(main_next),
            usize::from(pre_next),
            permutation,
            chunks,
            degree_bits,
            input_roots,
            result.input_path_hashes,
            MAX_VECTOR_BYTES,
        ] {
            h.update(&(value as u64).to_le_bytes());
        }
        result.identity.profile = *h.finalize().as_bytes();
        Ok(result)
    }
    pub fn identity(&self) -> Identity {
        self.identity
    }
    pub fn encode(&self, proof: &BatchProof<Config>) -> Result<Vec<u8>, Error> {
        let body = postcard::to_allocvec(proof)
            .map_err(|_| Error::Body(ProofDecodeError::DependencyCodec))?;
        self.validate_body(&body).map_err(Error::Body)?;
        super::encode(self.identity, &body, super::MAX_FEE_PROOF_BYTES).map_err(Error::Frame)
    }
    pub fn decode(&self, frame: &[u8]) -> Result<BatchProof<Config>, Error> {
        let body =
            super::parse(frame, self.identity, super::MAX_FEE_PROOF_BYTES).map_err(Error::Frame)?;
        self.validate_body(body).map_err(Error::Body)?;
        let (proof, tail) = postcard::take_from_bytes::<BatchProof<Config>>(body)
            .map_err(|_| Error::Body(ProofDecodeError::DependencyCodec))?;
        if !tail.is_empty()
            || postcard::to_allocvec(&proof)
                .map_err(|_| Error::Body(ProofDecodeError::DependencyCodec))?
                != body
        {
            return Err(Error::Body(ProofDecodeError::NonCanonical));
        }
        Ok(proof)
    }
    fn validate_body(&self, bytes: &[u8]) -> Result<(), ProofDecodeError> {
        if bytes.is_empty() || bytes.len() > super::MAX_FEE_PROOF_BYTES - FRAME_BYTES {
            return Err(ProofDecodeError::BodyTooLarge);
        }
        let mut c = Cursor::<MAX_VECTOR_BYTES> {
            bytes,
            offset: 0,
            declared_vector_bytes: 0,
        };
        c.cap("batch_main", self.input_roots)?;
        c.option("batch_permutation", true)?;
        c.cap("batch_permutation", self.input_roots)?;
        c.cap("batch_quotient", self.input_roots)?;
        c.option("batch_random", true)?;
        c.cap("batch_random", self.input_roots)?;
        c.exact_vec("batch_instances", 1, size_of::<Vec<E>>() * 8)?;
        c.extension_vec("batch_main_local", self.main)?;
        c.optional_extension_vec("batch_main_next", self.main_next, self.main)?;
        c.option("batch_preprocessed", true)?;
        c.extension_vec("batch_pre_local", self.pre)?;
        c.optional_extension_vec("batch_pre_next", self.pre_next, self.pre)?;
        c.exact_vec("batch_quotient_chunks", self.chunks, size_of::<Vec<E>>())?;
        for _ in 0..self.chunks {
            c.extension_vec("batch_quotient_chunk", EXTENSION_DEGREE)?;
        }
        c.optional_extension_vec("batch_random_opening", true, EXTENSION_DEGREE)?;
        c.extension_vec("batch_permutation_local", self.permutation)?;
        c.extension_vec("batch_permutation_next", self.permutation)?;
        c.exact_vec(
            "batch_random_rounds",
            self.rounds.len(),
            size_of::<Vec<Vec<Vec<E>>>>(),
        )?;
        for r in &self.rounds {
            c.exact_vec(
                "batch_random_matrices",
                r.matrices,
                size_of::<Vec<Vec<E>>>(),
            )?;
            for _ in 0..r.matrices {
                c.exact_vec("batch_random_points", r.points, size_of::<Vec<E>>())?;
                for _ in 0..r.points {
                    c.extension_vec("batch_random_values", r.random_values)?;
                }
            }
        }
        c.witness("batch_pow", true)?;
        c.exact_vec(
            "batch_fri_commits",
            self.folds.len(),
            size_of::<Vec<[F; DIGEST_ELEMENTS]>>(),
        )?;
        for f in &self.folds {
            c.cap("batch_fri_cap", f.cap_roots)?;
        }
        c.exact_vec("batch_commit_pow", self.folds.len(), size_of::<F>())?;
        for _ in &self.folds {
            c.witness("batch_commit_pow", true)?;
        }
        c.exact_vec(
            "batch_input_rounds",
            self.rounds.len(),
            size_of::<Vec<()>>() * 3,
        )?;
        for r in &self.rounds {
            c.exact_vec("batch_input_queries", QUERIES, size_of::<Vec<Vec<F>>>())?;
            for _ in 0..QUERIES {
                c.exact_vec("batch_input_matrices", r.matrices, size_of::<Vec<F>>())?;
                for _ in 0..r.matrices {
                    c.base_vec("batch_input_values", r.width)?;
                }
            }
            c.salts(QUERIES, r.matrices, SALTS)?;
            c.path("batch_input_path", self.input_path_hashes)?;
        }
        c.exact_vec(
            "batch_fri_openings",
            self.folds.len(),
            size_of::<Vec<()>>() * 3,
        )?;
        for f in &self.folds {
            c.exact_vec("batch_fri_queries", QUERIES, size_of::<Vec<E>>())?;
            for _ in 0..QUERIES {
                c.extension_vec("batch_fri_siblings", f.siblings)?;
            }
            c.salts(QUERIES, 1, SALTS)?;
            c.path("batch_fri_path", f.path_hashes)?;
        }
        c.extension_vec("batch_final_polynomial", 1)?;
        c.witness("batch_query_pow", true)?;
        c.exact_vec("batch_lookup_terminals", 1, size_of::<Option<E>>())?;
        c.option("batch_lookup_terminal", true)?;
        let start = c.offset;
        c.fields(EXTENSION_DEGREE)?;
        if c.bytes[start..c.offset].iter().any(|b| *b != 0) {
            return Err(ProofDecodeError::Shape("nonzero_closed_lookup_terminal"));
        }
        c.exact_vec("batch_degree_bits", 1, size_of::<usize>())?;
        if c.varint()? != self.degree_bits {
            return Err(ProofDecodeError::Shape("batch_degree_bits"));
        }
        c.option("batch_lookup_pow", true)?;
        c.witness("batch_lookup_pow", true)?;
        c.witness("batch_ood_pow", true)?;
        if c.offset != bytes.len() {
            return Err(ProofDecodeError::TrailingBytes);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "batch/tests.rs"]
mod tests;
