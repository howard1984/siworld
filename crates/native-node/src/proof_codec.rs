//! Bounded decoder for the fixed native D8/W24 engineering proof profiles.
//!
//! Derived from the frozen native admission decoder without changing its
//! proof schema. This adapter selects a local per-relation body limit.
//!
//! A byte limit alone does not constrain nested allocation requests. This
//! module first walks the entire pinned postcard schema without allocating.
//! Vector counts, field encodings, option presence, degree and FRI geometry
//! are checked against metadata constructed from the trusted AIR, key and
//! configuration. Only that validated input reaches the dependency decoder.
//! Decoding establishes structure, not proof validity: callers must still
//! verify the proof against their independently reconstructed statement.

use native::{Cfg, multi_asset::F};
use p3_air::{
    Air,
    symbolic::{AirLayout, SymbolicAirBuilder},
};
use p3_commit::Pcs;
use p3_field::{PrimeField32, TwoAdicField};
use p3_recursion::{VerifierLimits, builtin_config::SuiteIdV1};
use p3_uni_stark::{PreprocessedVerifierKey, Proof, StarkGenericConfig};

/// Transaction body limit; public inputs are reconstructed independently.
pub const MAX_TRANSACTION_PROOF_BODY_LEN: usize = 655_360;
/// Fixed-capacity settlement body limit.
///
/// This is the native decoder admission limit and must match the wire,
/// compact-block, block-size and memory-budget constants.
pub const MAX_SETTLEMENT_PROOF_BODY_LEN: usize = 655_360;
/// Issuance proofs retain their independently frozen 512 KiB admission cap.
pub const MAX_ISSUANCE_PROOF_BODY_LEN: usize = 524_288;

// An additional aggregate budget covers all declared vector payloads and
// headers. This is an admission bound, not an allocator/process RSS claim.
const MAX_DECLARED_VECTOR_BYTES: usize = 4 * 1024 * 1024;
const EXTENSION_DEGREE: usize = 8;
const DIGEST_ELEMENTS: usize = 12;
type Challenge = <Cfg as StarkGenericConfig>::Challenge;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofDecodeError {
    InvalidTrustedShape,
    BodyTooLarge,
    Truncated,
    NonCanonical,
    NonCanonicalField,
    Shape(&'static str),
    AllocationBudget,
    TrailingBytes,
    DependencyCodec,
}

impl core::fmt::Display for ProofDecodeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "native proof admission: {self:?}")
    }
}

impl std::error::Error for ProofDecodeError {}

#[derive(Clone, Debug)]
struct RoundShape {
    matrices: usize,
    width: usize,
    points: usize,
    random_values: usize,
}

#[derive(Clone, Debug)]
struct FoldShape {
    cap_roots: usize,
    siblings: usize,
    path_hashes: usize,
}

/// Admission schema prepared once from local verification metadata.
/// None of its dimensions are selected by a peer or read from a proof body.
#[derive(Clone, Debug)]
pub struct ProofShape {
    body_limit: usize,
    main_width: usize,
    preprocessed_width: usize,
    main_next: bool,
    preprocessed_next: bool,
    quotient_chunks: usize,
    degree_bits: usize,
    input_cap_roots: usize,
    input_path_hashes: usize,
    num_queries: usize,
    final_poly_len: usize,
    zero_batch_work: bool,
    zero_commit_work: bool,
    zero_query_work: bool,
    zero_ood_work: bool,
    rounds: Vec<RoundShape>,
    folds: Vec<FoldShape>,
}

impl ProofShape {
    /// Construct a schema for this crate's concrete random-codeword D8/W24
    /// suite. The AIR, preprocessing key and configuration must be local,
    /// authenticated verification artifacts, never transaction-supplied data.
    /// This format has ordinary binary MMCS paths and no salt vectors.
    pub fn from_trusted<A>(
        air: &A,
        vk: &PreprocessedVerifierKey<Cfg>,
        cfg: &Cfg,
        body_limit: usize,
    ) -> Result<Self, ProofDecodeError>
    where
        A: Air<SymbolicAirBuilder<F>>,
    {
        let descriptor = cfg.descriptor();
        if ![
            MAX_TRANSACTION_PROOF_BODY_LEN,
            MAX_SETTLEMENT_PROOF_BODY_LEN,
            MAX_ISSUANCE_PROOF_BODY_LEN,
        ]
        .contains(&body_limit)
            || descriptor.suite() != SuiteIdV1::ExperimentalKoalaBearD8Poseidon2W24RandomCodewordFri
            || descriptor.salt_elements() != 0
            || cfg.is_zk() != 1
            || descriptor.validate(&VerifierLimits::default()).is_err()
            || vk.degree_bits == 0
            || vk.degree_bits > F::TWO_ADICITY
            || vk.width == 0
            || vk.width != air.preprocessed_width()
            || air.width() == 0
            || air.width() > body_limit / (EXTENSION_DEGREE * 4)
            || vk.width > body_limit / (EXTENSION_DEGREE * 4)
        {
            return Err(ProofDecodeError::InvalidTrustedShape);
        }
        let log_blowup = descriptor.log_blowup() as usize;
        let log_height = vk
            .degree_bits
            .checked_add(log_blowup)
            .filter(|height| *height <= F::TWO_ADICITY)
            .ok_or(ProofDecodeError::InvalidTrustedShape)?;
        let domain =
            <<Cfg as StarkGenericConfig>::Pcs as Pcs<
                Challenge,
                <Cfg as StarkGenericConfig>::Challenger,
            >>::natural_domain_for_degree(cfg.pcs(), power_of_two(vk.degree_bits - 1)?);
        let layout = AirLayout {
            preprocessed_width: vk.width,
            main_width: air.width(),
            num_public_values: air.num_public_values(),
            num_periodic_columns: air.num_periodic_columns(),
            ..Default::default()
        };
        let log_chunks = p3_uni_stark::get_log_num_quotient_chunks_for_domain::<F, A>(
            air,
            layout,
            domain,
            cfg.is_zk(),
        );
        let quotient_chunks = power_of_two(
            log_chunks
                .checked_add(1)
                .ok_or(ProofDecodeError::InvalidTrustedShape)?,
        )?;
        if quotient_chunks > body_limit / (EXTENSION_DEGREE * 4) {
            return Err(ProofDecodeError::InvalidTrustedShape);
        }
        let input_cap_height = (descriptor.input_cap_height() as usize).min(log_height);
        let input_cap_roots = power_of_two(input_cap_height)?;
        if vk.commitment.num_roots() != input_cap_roots {
            return Err(ProofDecodeError::InvalidTrustedShape);
        }
        let num_queries = descriptor.num_queries() as usize;
        let random_values = descriptor.num_random_codewords() as usize;
        let main_next = !air.main_next_row_columns().is_empty();
        let preprocessed_next = !air.preprocessed_next_row_columns().is_empty();
        let masked_width = |width: usize| {
            width
                .checked_add(random_values)
                .ok_or(ProofDecodeError::InvalidTrustedShape)
        };
        // In the hiding uni-STARK, all quotient chunks are randomized back
        // onto the same extended degree as the main/preprocessed/random trace.
        let rounds = vec![
            RoundShape {
                matrices: 1,
                width: masked_width(EXTENSION_DEGREE)?,
                points: 1,
                random_values,
            },
            RoundShape {
                matrices: 1,
                width: masked_width(air.width())?,
                points: 1 + usize::from(main_next),
                random_values,
            },
            RoundShape {
                matrices: quotient_chunks,
                width: masked_width(EXTENSION_DEGREE)?,
                points: 1,
                random_values,
            },
            RoundShape {
                matrices: 1,
                width: vk.width,
                points: 1 + usize::from(preprocessed_next),
                random_values: 0,
            },
        ];
        let final_log_height = (descriptor.log_final_poly_len() as usize)
            .checked_add(log_blowup)
            .filter(|height| *height < log_height)
            .ok_or(ProofDecodeError::InvalidTrustedShape)?;
        let log_arities = p3_fri::fold_schedule(
            &[log_height],
            final_log_height,
            descriptor.max_log_arity() as usize,
        );
        let mut current_log_height = log_height;
        let mut folds = Vec::with_capacity(log_arities.len());
        for log_arity in log_arities {
            // Each FRI commitment hashes rows of arity values before folding,
            // so its binary MMCS tree already has the post-fold row height.
            current_log_height -= log_arity;
            let cap_height = (descriptor.commit_cap_height() as usize).min(current_log_height);
            folds.push(FoldShape {
                cap_roots: power_of_two(cap_height)?,
                siblings: power_of_two(log_arity)? - 1,
                path_hashes: num_queries
                    .checked_mul(current_log_height - cap_height)
                    .ok_or(ProofDecodeError::InvalidTrustedShape)?,
            });
        }
        Ok(Self {
            body_limit,
            main_width: air.width(),
            preprocessed_width: vk.width,
            main_next,
            preprocessed_next,
            quotient_chunks,
            degree_bits: vk.degree_bits,
            input_cap_roots,
            input_path_hashes: num_queries
                .checked_mul(log_height - input_cap_height)
                .ok_or(ProofDecodeError::InvalidTrustedShape)?,
            num_queries,
            final_poly_len: power_of_two(descriptor.log_final_poly_len() as usize)?,
            zero_batch_work: descriptor.batch_pow_bits() == 0,
            zero_commit_work: descriptor.commit_pow_bits() == 0,
            zero_query_work: descriptor.query_pow_bits() == 0,
            zero_ood_work: cfg.ood_proof_of_work_bits() == 0,
            rounds,
            folds,
        })
    }

    /// Decode only after a complete, allocation-free schema walk, then require
    /// exact consumption and canonical re-encoding. Perform cryptographic
    /// verification afterwards; an admitted shape can contain a false proof.
    pub fn decode(&self, bytes: &[u8]) -> Result<Proof<Cfg>, ProofDecodeError> {
        self.validate_encoding(bytes)?;
        let (proof, remaining) = postcard::take_from_bytes::<Proof<Cfg>>(bytes)
            .map_err(|_| ProofDecodeError::DependencyCodec)?;
        if !remaining.is_empty() {
            return Err(ProofDecodeError::TrailingBytes);
        }
        let canonical =
            postcard::to_allocvec(&proof).map_err(|_| ProofDecodeError::DependencyCodec)?;
        if canonical != bytes {
            return Err(ProofDecodeError::NonCanonical);
        }
        Ok(proof)
    }

    /// Allocation-free schema preflight for bounded framing and admission.
    /// This establishes neither proof validity nor a typed proof allocation.
    pub fn validate_encoding(&self, bytes: &[u8]) -> Result<(), ProofDecodeError> {
        if bytes.len() > self.body_limit {
            return Err(ProofDecodeError::BodyTooLarge);
        }
        let mut cursor = Cursor {
            bytes,
            offset: 0,
            declared_vector_bytes: 0,
        };
        cursor.cap("trace_commitment", self.input_cap_roots)?;
        cursor.cap("quotient_commitment", self.input_cap_roots)?;
        cursor.option("random_commitment", true)?;
        cursor.cap("random_commitment", self.input_cap_roots)?;
        cursor.extension_vec("trace_local", self.main_width)?;
        cursor.optional_extension_vec("trace_next", self.main_next, self.main_width)?;
        cursor.optional_extension_vec("preprocessed_local", true, self.preprocessed_width)?;
        cursor.optional_extension_vec(
            "preprocessed_next",
            self.preprocessed_next,
            self.preprocessed_width,
        )?;
        cursor.exact_vec(
            "quotient_chunks",
            self.quotient_chunks,
            size_of::<Vec<Challenge>>(),
        )?;
        for _ in 0..self.quotient_chunks {
            cursor.extension_vec("quotient_chunk", EXTENSION_DEGREE)?;
        }
        cursor.optional_extension_vec("random_opening", true, EXTENSION_DEGREE)?;
        cursor.exact_vec(
            "hiding_rounds",
            self.rounds.len(),
            size_of::<Vec<Vec<Vec<Challenge>>>>(),
        )?;
        for round in &self.rounds {
            cursor.exact_vec(
                "hiding_matrices",
                round.matrices,
                size_of::<Vec<Vec<Challenge>>>(),
            )?;
            for _ in 0..round.matrices {
                cursor.exact_vec("hiding_points", round.points, size_of::<Vec<Challenge>>())?;
                for _ in 0..round.points {
                    cursor.extension_vec("hiding_values", round.random_values)?;
                }
            }
        }
        cursor.witness("batch_work", self.zero_batch_work)?;
        cursor.exact_vec(
            "fri_commitments",
            self.folds.len(),
            size_of::<Vec<[F; DIGEST_ELEMENTS]>>(),
        )?;
        for fold in &self.folds {
            cursor.cap("fri_commitment", fold.cap_roots)?;
        }
        cursor.exact_vec("commit_work", self.folds.len(), size_of::<F>())?;
        for _ in &self.folds {
            cursor.witness("commit_work", self.zero_commit_work)?;
        }
        // Two vector headers per BatchMultiOpening: rows plus pruned paths.
        cursor.exact_vec("input_rounds", self.rounds.len(), 2 * size_of::<Vec<()>>())?;
        for round in &self.rounds {
            cursor.exact_vec("input_queries", self.num_queries, size_of::<Vec<Vec<F>>>())?;
            for _ in 0..self.num_queries {
                cursor.exact_vec("input_matrices", round.matrices, size_of::<Vec<F>>())?;
                for _ in 0..round.matrices {
                    cursor.base_vec("input_values", round.width)?;
                }
            }
            cursor.path("input_path", self.input_path_hashes)?;
        }
        // CommitPhaseMultiStep likewise owns two vector headers.
        cursor.exact_vec(
            "commit_openings",
            self.folds.len(),
            2 * size_of::<Vec<()>>(),
        )?;
        for fold in &self.folds {
            cursor.exact_vec(
                "commit_queries",
                self.num_queries,
                size_of::<Vec<Challenge>>(),
            )?;
            for _ in 0..self.num_queries {
                cursor.extension_vec("commit_siblings", fold.siblings)?;
            }
            cursor.path("commit_path", fold.path_hashes)?;
        }
        cursor.extension_vec("final_polynomial", self.final_poly_len)?;
        cursor.witness("query_work", self.zero_query_work)?;
        if cursor.varint()? != self.degree_bits {
            return Err(ProofDecodeError::Shape("degree_bits"));
        }
        cursor.witness("ood_work", self.zero_ood_work)?;
        if cursor.offset != bytes.len() {
            return Err(ProofDecodeError::TrailingBytes);
        }
        Ok(())
    }
}

fn power_of_two(log: usize) -> Result<usize, ProofDecodeError> {
    u32::try_from(log)
        .ok()
        .and_then(|log| 1usize.checked_shl(log))
        .ok_or(ProofDecodeError::InvalidTrustedShape)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
    declared_vector_bytes: usize,
}

impl Cursor<'_> {
    fn byte(&mut self) -> Result<u8, ProofDecodeError> {
        let value = *self
            .bytes
            .get(self.offset)
            .ok_or(ProofDecodeError::Truncated)?;
        self.offset += 1;
        Ok(value)
    }

    // Postcard's sequence counts and usize are unsigned base-128 varints.
    // Enforce the minimal u64 encoding, then the host's representable range.
    fn varint(&mut self) -> Result<usize, ProofDecodeError> {
        let mut value = 0u64;
        for index in 0..10 {
            let byte = self.byte()?;
            let payload = byte & 0x7f;
            if index == 9 && payload > 1 {
                return Err(ProofDecodeError::NonCanonical);
            }
            value |= u64::from(payload) << (index * 7);
            if byte & 0x80 == 0 {
                if index > 0 && payload == 0 {
                    return Err(ProofDecodeError::NonCanonical);
                }
                return usize::try_from(value).map_err(|_| ProofDecodeError::NonCanonical);
            }
        }
        Err(ProofDecodeError::NonCanonical)
    }

    fn charge(&mut self, count: usize, element_bytes: usize) -> Result<(), ProofDecodeError> {
        self.declared_vector_bytes = count
            .checked_mul(element_bytes)
            .and_then(|bytes| bytes.checked_add(size_of::<Vec<()>>()))
            .and_then(|bytes| self.declared_vector_bytes.checked_add(bytes))
            .filter(|bytes| *bytes <= MAX_DECLARED_VECTOR_BYTES)
            .ok_or(ProofDecodeError::AllocationBudget)?;
        Ok(())
    }

    fn exact_vec(
        &mut self,
        label: &'static str,
        count: usize,
        element_bytes: usize,
    ) -> Result<(), ProofDecodeError> {
        if self.varint()? != count {
            return Err(ProofDecodeError::Shape(label));
        }
        self.charge(count, element_bytes)
    }

    fn option(&mut self, label: &'static str, present: bool) -> Result<(), ProofDecodeError> {
        if self.byte()? != u8::from(present) {
            return Err(ProofDecodeError::Shape(label));
        }
        Ok(())
    }

    fn fields(&mut self, count: usize) -> Result<(), ProofDecodeError> {
        let end = count
            .checked_mul(4)
            .and_then(|bytes| self.offset.checked_add(bytes))
            .filter(|end| *end <= self.bytes.len())
            .ok_or(ProofDecodeError::Truncated)?;
        for bytes in self.bytes[self.offset..end].as_chunks::<4>().0 {
            let raw = u32::from_le_bytes(*bytes);
            if raw >= F::ORDER_U32 {
                return Err(ProofDecodeError::NonCanonicalField);
            }
        }
        self.offset = end;
        Ok(())
    }

    fn witness(&mut self, label: &'static str, zero_work: bool) -> Result<(), ProofDecodeError> {
        let start = self.offset;
        self.fields(1)?;
        if zero_work && self.bytes[start..self.offset] != [0; 4] {
            return Err(ProofDecodeError::Shape(label));
        }
        Ok(())
    }

    fn extension_vec(&mut self, label: &'static str, count: usize) -> Result<(), ProofDecodeError> {
        self.exact_vec(label, count, size_of::<Challenge>())?;
        self.fields(
            count
                .checked_mul(EXTENSION_DEGREE)
                .ok_or(ProofDecodeError::AllocationBudget)?,
        )
    }

    fn optional_extension_vec(
        &mut self,
        label: &'static str,
        present: bool,
        count: usize,
    ) -> Result<(), ProofDecodeError> {
        self.option(label, present)?;
        if present {
            self.extension_vec(label, count)?;
        }
        Ok(())
    }

    fn base_vec(&mut self, label: &'static str, count: usize) -> Result<(), ProofDecodeError> {
        self.exact_vec(label, count, size_of::<F>())?;
        self.fields(count)
    }

    fn cap(&mut self, label: &'static str, roots: usize) -> Result<(), ProofDecodeError> {
        self.exact_vec(label, roots, size_of::<[F; DIGEST_ELEMENTS]>())?;
        self.fields(
            roots
                .checked_mul(DIGEST_ELEMENTS)
                .ok_or(ProofDecodeError::AllocationBudget)?,
        )
    }

    fn path(&mut self, label: &'static str, maximum_hashes: usize) -> Result<(), ProofDecodeError> {
        let hashes = self.varint()?;
        if hashes > maximum_hashes {
            return Err(ProofDecodeError::Shape(label));
        }
        self.charge(hashes, size_of::<[F; DIGEST_ELEMENTS]>())?;
        self.fields(
            hashes
                .checked_mul(DIGEST_ELEMENTS)
                .ok_or(ProofDecodeError::AllocationBudget)?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use native::{FriParams, multi_asset::F};
    use p3_air::{Air, AirBuilder, BaseAir};
    use p3_field::PrimeCharacteristicRing;
    use p3_fri::{BatchMultiOpening, CommitPhaseMultiStep, FriProof};
    use p3_matrix::dense::RowMajorMatrix;
    use p3_merkle_tree::PrunedMerklePaths;
    use p3_symmetric::MerkleCap;
    use p3_uni_stark::{Commitments, OpenedValues, PreprocessedOpenedValues};

    struct TinyAir;
    impl BaseAir<F> for TinyAir {
        fn width(&self) -> usize {
            3
        }
        fn preprocessed_width(&self) -> usize {
            2
        }
        fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
            Some(RowMajorMatrix::new(vec![F::ZERO; 64 * 2], 2))
        }
        fn max_constraint_degree(&self) -> Option<usize> {
            Some(3)
        }
    }
    impl<AB: AirBuilder<F = F>> Air<AB> for TinyAir {
        fn eval(&self, builder: &mut AB) {
            builder.assert_zero(AB::Expr::ZERO);
        }
    }

    fn fixture() -> (ProofShape, Cfg, PreprocessedVerifierKey<Cfg>) {
        let cfg = FriParams::fast().config();
        let vk = PreprocessedVerifierKey {
            width: 2,
            degree_bits: 7,
            commitment: MerkleCap::new(vec![[F::ZERO; 12]; 2]),
        };
        let shape =
            ProofShape::from_trusted(&TinyAir, &vk, &cfg, MAX_SETTLEMENT_PROOF_BODY_LEN).unwrap();
        (shape, cfg, vk)
    }

    // Structural fixtures are deliberately not cryptographically valid. The
    // final test separately checks compatibility with an actual prover.
    fn proof(shape: &ProofShape) -> Proof<Cfg> {
        let cap = |roots| MerkleCap::new(vec![[F::ZERO; 12]; roots]);
        let empty_path = || PrunedMerklePaths {
            sibling_hashes: Vec::new(),
        };
        let zero = <Cfg as StarkGenericConfig>::Challenge::ZERO;
        Proof {
            commitments: Commitments {
                trace: cap(shape.input_cap_roots),
                quotient_chunks: cap(shape.input_cap_roots),
                random: Some(cap(shape.input_cap_roots)),
            },
            opened_values: OpenedValues {
                trace_local: vec![zero; shape.main_width],
                trace_next: shape.main_next.then(|| vec![zero; shape.main_width]),
                preprocessed: Some(PreprocessedOpenedValues {
                    local: vec![zero; shape.preprocessed_width],
                    next: shape
                        .preprocessed_next
                        .then(|| vec![zero; shape.preprocessed_width]),
                }),
                quotient_chunks: vec![vec![zero; EXTENSION_DEGREE]; shape.quotient_chunks],
                random: Some(vec![zero; EXTENSION_DEGREE]),
            },
            opening_proof: (
                shape
                    .rounds
                    .iter()
                    .map(|round| {
                        vec![vec![vec![zero; round.random_values]; round.points]; round.matrices]
                    })
                    .collect(),
                FriProof {
                    batch_pow_witness: F::ZERO,
                    commit_phase_commits: shape
                        .folds
                        .iter()
                        .map(|fold| cap(fold.cap_roots))
                        .collect(),
                    commit_pow_witnesses: vec![F::ZERO; shape.folds.len()],
                    input_openings: shape
                        .rounds
                        .iter()
                        .map(|round| BatchMultiOpening {
                            opened_values: vec![
                                vec![vec![F::ZERO; round.width]; round.matrices];
                                shape.num_queries
                            ],
                            opening_proof: empty_path(),
                        })
                        .collect(),
                    commit_phase_openings: shape
                        .folds
                        .iter()
                        .map(|fold| CommitPhaseMultiStep {
                            sibling_values: vec![vec![zero; fold.siblings]; shape.num_queries],
                            opening_proof: empty_path(),
                        })
                        .collect(),
                    final_poly: vec![zero; shape.final_poly_len],
                    query_pow_witness: F::ZERO,
                },
            ),
            degree_bits: shape.degree_bits,
            ood_pow_witness: F::ZERO,
        }
    }

    fn encoded(proof: &Proof<Cfg>) -> Vec<u8> {
        postcard::to_allocvec(proof).unwrap()
    }
    fn rejects(change: impl FnOnce(&mut Proof<Cfg>)) {
        let (shape, _, _) = fixture();
        let mut value = proof(&shape);
        change(&mut value);
        assert!(shape.decode(&encoded(&value)).is_err());
    }

    #[test]
    fn canonical_structural_proof_roundtrips() {
        let (shape, _, _) = fixture();
        let bytes = encoded(&proof(&shape));
        assert_eq!(encoded(&shape.decode(&bytes).unwrap()), bytes);
    }

    #[test]
    fn rejects_wire_limit_and_trailing_or_truncated_input() {
        let (shape, _, _) = fixture();
        assert_eq!(
            shape
                .decode(&vec![0; MAX_SETTLEMENT_PROOF_BODY_LEN + 1])
                .err(),
            Some(ProofDecodeError::BodyTooLarge)
        );
        let mut bytes = encoded(&proof(&shape));
        bytes.push(0);
        assert_eq!(
            shape.decode(&bytes).err(),
            Some(ProofDecodeError::TrailingBytes)
        );
        bytes.pop();
        for end in [0, 1, bytes.len() / 2, bytes.len() - 1] {
            assert!(shape.decode(&bytes[..end]).is_err());
        }
    }

    #[test]
    fn rejects_nonminimal_or_overflowing_lengths_before_allocation() {
        let (shape, _, _) = fixture();
        let bytes = encoded(&proof(&shape));
        let mut nonminimal = vec![bytes[0] | 0x80, 0];
        nonminimal.extend_from_slice(&bytes[1..]);
        assert_eq!(
            shape.decode(&nonminimal).err(),
            Some(ProofDecodeError::NonCanonical)
        );
        for prefix in [vec![0xff; 10], vec![0xff, 0xff, 0xff, 0xff, 0x7f], vec![0]] {
            let mut invalid = prefix;
            invalid.extend_from_slice(&bytes[1..]);
            assert!(shape.decode(&invalid).is_err());
        }
    }

    #[test]
    fn rejects_huge_nested_trace_length_before_reading_values() {
        let (shape, _, _) = fixture();
        let value = proof(&shape);
        let offset = postcard::to_allocvec(&value.commitments).unwrap().len();
        let bytes = encoded(&value);
        let mut invalid = bytes[..offset].to_vec();
        invalid.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x0f]);
        invalid.extend_from_slice(&bytes[offset + 1..]);
        assert_eq!(
            shape.decode(&invalid).err(),
            Some(ProofDecodeError::Shape("trace_local"))
        );
    }

    #[test]
    fn rejects_adversarial_lengths_at_deep_pcs_levels_before_allocation() {
        let (shape, _, _) = fixture();
        let value = proof(&shape);
        let bytes = encoded(&value);
        let hiding_offset = postcard::to_allocvec(&value.commitments).unwrap().len()
            + postcard::to_allocvec(&value.opened_values).unwrap().len();
        let fri = &value.opening_proof.1;
        let input_offset = hiding_offset
            + postcard::to_allocvec(&value.opening_proof.0).unwrap().len()
            + postcard::to_allocvec(&fri.batch_pow_witness).unwrap().len()
            + postcard::to_allocvec(&fri.commit_phase_commits)
                .unwrap()
                .len()
            + postcard::to_allocvec(&fri.commit_pow_witnesses)
                .unwrap()
                .len();
        let path_offset = input_offset
            + 1
            + postcard::to_allocvec(&fri.input_openings[0].opened_values)
                .unwrap()
                .len();
        for (offset, label) in [
            (hiding_offset, "hiding_rounds"),
            (hiding_offset + 1, "hiding_matrices"),
            (hiding_offset + 2, "hiding_points"),
            (hiding_offset + 3, "hiding_values"),
            (input_offset, "input_rounds"),
            (input_offset + 1, "input_queries"),
            (input_offset + 2, "input_matrices"),
            (input_offset + 3, "input_values"),
            (path_offset, "input_path"),
        ] {
            // Canonical u64::MAX; no large payload accompanies the prefix.
            let mut invalid = bytes[..offset].to_vec();
            invalid.extend_from_slice(&[0xff; 9]);
            invalid.push(1);
            invalid.extend_from_slice(&bytes[offset + 1..]);
            assert_eq!(
                shape.decode(&invalid).err(),
                Some(ProofDecodeError::Shape(label))
            );
        }
    }

    #[test]
    fn rejects_noncanonical_field_and_invalid_option_tag() {
        let (shape, _, _) = fixture();
        let mut bytes = encoded(&proof(&shape));
        bytes[1..5].copy_from_slice(&F::ORDER_U32.to_le_bytes());
        assert_eq!(
            shape.decode(&bytes).err(),
            Some(ProofDecodeError::NonCanonicalField)
        );
        let mut bytes = encoded(&proof(&shape));
        let random_tag = 2 * (1 + shape.input_cap_roots * DIGEST_ELEMENTS * 4);
        bytes[random_tag] = 2;
        assert_eq!(
            shape.decode(&bytes).err(),
            Some(ProofDecodeError::Shape("random_commitment"))
        );
    }

    #[test]
    fn rejects_wrong_fixed_openings_and_presence() {
        rejects(|p| p.commitments.random = None);
        rejects(|p| p.opened_values.trace_local.pop().map(|_| ()).unwrap());
        rejects(|p| p.opened_values.trace_next = None);
        rejects(|p| p.opened_values.preprocessed = None);
        rejects(|p| p.opened_values.preprocessed.as_mut().unwrap().next = None);
        rejects(|p| {
            p.opened_values.quotient_chunks[0]
                .pop()
                .map(|_| ())
                .unwrap()
        });
        rejects(|p| p.opened_values.random = None);
        rejects(|p| p.degree_bits += 1);
    }

    #[test]
    fn rejects_hiding_opening_nesting_mismatches() {
        rejects(|p| {
            p.opening_proof.0.pop();
        });
        rejects(|p| {
            p.opening_proof.0[1].pop();
        });
        rejects(|p| {
            p.opening_proof.0[1][0].pop();
        });
        rejects(|p| {
            p.opening_proof.0[1][0][0].pop();
        });
        rejects(|p| {
            p.opening_proof.0[3][0][0].push(<Cfg as StarkGenericConfig>::Challenge::ZERO);
        });
    }

    #[test]
    fn rejects_fri_round_query_matrix_and_final_polynomial_mismatches() {
        rejects(|p| {
            p.opening_proof.1.commit_phase_commits.pop();
        });
        rejects(|p| {
            p.opening_proof.1.commit_pow_witnesses.pop();
        });
        rejects(|p| {
            p.opening_proof.1.input_openings.pop();
        });
        rejects(|p| {
            p.opening_proof.1.input_openings[0].opened_values.pop();
        });
        rejects(|p| {
            p.opening_proof.1.input_openings[0].opened_values[0].pop();
        });
        rejects(|p| {
            p.opening_proof.1.input_openings[0].opened_values[0][0].pop();
        });
        rejects(|p| {
            p.opening_proof.1.commit_phase_openings.pop();
        });
        rejects(|p| {
            p.opening_proof.1.commit_phase_openings[0]
                .sibling_values
                .pop();
        });
        rejects(|p| {
            p.opening_proof.1.commit_phase_openings[0].sibling_values[0].pop();
        });
        rejects(|p| {
            p.opening_proof.1.final_poly.pop();
        });
    }

    #[test]
    fn rejects_multiproofs_beyond_trusted_tree_geometry() {
        let (shape, _, _) = fixture();
        let mut value = proof(&shape);
        value.opening_proof.1.input_openings[0]
            .opening_proof
            .sibling_hashes = vec![[F::ZERO; 12]; shape.input_path_hashes + 1];
        assert_eq!(
            shape.decode(&encoded(&value)).err(),
            Some(ProofDecodeError::Shape("input_path"))
        );
        let mut value = proof(&shape);
        value.opening_proof.1.commit_phase_openings[0]
            .opening_proof
            .sibling_hashes = vec![[F::ZERO; 12]; shape.folds[0].path_hashes + 1];
        assert_eq!(
            shape.decode(&encoded(&value)).err(),
            Some(ProofDecodeError::Shape("commit_path"))
        );
    }

    #[test]
    fn rejects_unused_nonzero_grinding_witnesses() {
        rejects(|p| p.ood_pow_witness = F::ONE);
        rejects(|p| p.opening_proof.1.batch_pow_witness = F::ONE);
        rejects(|p| p.opening_proof.1.commit_pow_witnesses[0] = F::ONE);
        rejects(|p| p.opening_proof.1.query_pow_witness = F::ONE);
    }

    #[test]
    fn trusted_key_metadata_must_match_air_and_descriptor() {
        let (_, cfg, mut vk) = fixture();
        vk.width += 1;
        assert!(
            ProofShape::from_trusted(&TinyAir, &vk, &cfg, MAX_SETTLEMENT_PROOF_BODY_LEN).is_err()
        );
        vk.width -= 1;
        vk.degree_bits = usize::MAX;
        assert!(
            ProofShape::from_trusted(&TinyAir, &vk, &cfg, MAX_SETTLEMENT_PROOF_BODY_LEN).is_err()
        );
    }

    #[test]
    fn bounded_decode_accepts_a_real_native_proof_and_verifies() {
        for max_log_arity in [1, 2, 3] {
            let cfg = FriParams {
                max_log_arity,
                ..FriParams::fast()
            }
            .config();
            let (pdata, vk) = p3_uni_stark::setup_preprocessed(&cfg, &TinyAir, 6)
                .unwrap()
                .unwrap();
            let shape =
                ProofShape::from_trusted(&TinyAir, &vk, &cfg, MAX_SETTLEMENT_PROOF_BODY_LEN)
                    .unwrap();
            let generated = p3_uni_stark::prove_with_preprocessed(
                &cfg,
                &TinyAir,
                RowMajorMatrix::new(vec![F::ZERO; 64 * 3], 3),
                &[],
                Some(&pdata),
            )
            .unwrap();
            let bytes = encoded(&generated);
            let decoded = shape.decode(&bytes).unwrap();
            p3_uni_stark::verify_with_preprocessed(&cfg, &TinyAir, &decoded, &[], Some(&vk))
                .unwrap();
        }
    }

    #[test]
    fn relation_cap_and_aggregate_budget_are_trusted_local_limits() {
        let (_, cfg, vk) = fixture();
        assert!(ProofShape::from_trusted(&TinyAir, &vk, &cfg, 1).is_err());
        assert!(ProofShape::from_trusted(&TinyAir, &vk, &cfg, usize::MAX).is_err());
        let shape =
            ProofShape::from_trusted(&TinyAir, &vk, &cfg, MAX_TRANSACTION_PROOF_BODY_LEN).unwrap();
        assert_eq!(shape.body_limit, 655_360);
        assert!(ProofShape::from_trusted(&TinyAir, &vk, &cfg, MAX_ISSUANCE_PROOF_BODY_LEN).is_ok());
        assert!(
            ProofShape::from_trusted(&TinyAir, &vk, &cfg, MAX_ISSUANCE_PROOF_BODY_LEN + 1).is_err()
        );
        assert_eq!(MAX_DECLARED_VECTOR_BYTES, 4_194_304);
        let mut cursor = Cursor {
            bytes: &[],
            offset: 0,
            declared_vector_bytes: 0,
        };
        assert_eq!(
            cursor.charge(usize::MAX, 48),
            Err(ProofDecodeError::AllocationBudget)
        );
        assert_eq!(
            cursor.charge(MAX_DECLARED_VECTOR_BYTES, 1),
            Err(ProofDecodeError::AllocationBudget)
        );
    }
}
