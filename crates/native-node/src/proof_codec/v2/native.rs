//! Bounded canonical admission for the explicit salted native uni-STARK body.
use super::backend::{Config, Profile};
use super::{FRAME_BYTES, FrameError, Identity, ProtocolBinding, Relation};
use crate::proof_codec::{
    DIGEST_ELEMENTS, EXTENSION_DEGREE, FoldShape, ProofDecodeError, ProofShape, RoundShape,
    power_of_two,
};
use ::native::multi_asset::F;
use p3_air::{
    Air,
    symbolic::{AirLayout, SymbolicAirBuilder},
};
use p3_commit::Pcs;
use p3_field::TwoAdicField;
use p3_uni_stark::{PreprocessedVerifierKey, Proof, StarkGenericConfig};

const INPUT_CAP: usize = 1;
const FRI_CAP: usize = 2;
const SALTS: usize = 9;
const CODEWORDS: usize = 8;
type Challenge = <Config as StarkGenericConfig>::Challenge;

#[derive(Debug)]
pub enum DecodeError {
    Frame(FrameError),
    Body(ProofDecodeError),
}

/// Local trusted metadata fixes every nested vector before typed decoding.
pub struct NativeProofShape {
    schema: ProofShape,
    identity: Identity,
    frame_limit: usize,
}

impl NativeProofShape {
    /// The AIR, key, profile, configuration and identity must all be authenticated
    /// local inputs. A peer-supplied profile or key is not an admission policy.
    pub fn from_trusted<A>(
        air: &A,
        key: &PreprocessedVerifierKey<Config>,
        config: &Config,
        profile: Profile,
        relation: Relation,
        binding: ProtocolBinding,
        frame_limit: usize,
    ) -> Result<Self, ProofDecodeError>
    where
        A: Air<SymbolicAirBuilder<F>>,
    {
        let params = profile.params();
        if relation == Relation::CompleteFee
            || !(FRAME_BYTES + 1..=relation.maximum_frame_bytes()).contains(&frame_limit)
            || (relation == Relation::Issuance && frame_limit > 524_288)
            || config.is_zk() != 1
            || config.pcs().profile().id() != profile.id()
            || config.ood_proof_of_work_bits() != 0
            || config.lookup_proof_of_work_bits() != 0
            || key.degree_bits == 0
            || key.degree_bits > F::TWO_ADICITY
            || key.width == 0
            || key.width != air.preprocessed_width()
            || air.width() == 0
            || params.max_log_arity != 1
        {
            return Err(ProofDecodeError::InvalidTrustedShape);
        }
        let log_blowup = params.log_blowup as usize;
        let log_height = key
            .degree_bits
            .checked_add(log_blowup)
            .filter(|height| *height <= F::TWO_ADICITY)
            .ok_or(ProofDecodeError::InvalidTrustedShape)?;
        let domain = <<Config as StarkGenericConfig>::Pcs as Pcs<
            Challenge,
            <Config as StarkGenericConfig>::Challenger,
        >>::natural_domain_for_degree(
            config.pcs(), power_of_two(key.degree_bits - 1)?
        );
        let layout = AirLayout {
            preprocessed_width: key.width,
            main_width: air.width(),
            num_public_values: air.num_public_values(),
            num_periodic_columns: air.num_periodic_columns(),
            ..Default::default()
        };
        let log_chunks = p3_uni_stark::get_log_num_quotient_chunks_for_domain::<F, A>(
            air,
            layout,
            domain,
            config.is_zk(),
        );
        let chunks = power_of_two(
            log_chunks
                .checked_add(1)
                .ok_or(ProofDecodeError::InvalidTrustedShape)?,
        )?;
        let input_cap = INPUT_CAP.min(log_height);
        let input_roots = power_of_two(input_cap)?;
        if key.commitment.num_roots() != input_roots {
            return Err(ProofDecodeError::InvalidTrustedShape);
        }
        let queries = params.num_queries as usize;
        let main_next = !air.main_next_row_columns().is_empty();
        let pre_next = !air.preprocessed_next_row_columns().is_empty();
        let masked = |width: usize| {
            width
                .checked_add(CODEWORDS)
                .ok_or(ProofDecodeError::InvalidTrustedShape)
        };
        let rounds = vec![
            RoundShape {
                matrices: 1,
                width: masked(EXTENSION_DEGREE)?,
                points: 1,
                random_values: CODEWORDS,
            },
            RoundShape {
                matrices: 1,
                width: masked(air.width())?,
                points: 1 + usize::from(main_next),
                random_values: CODEWORDS,
            },
            RoundShape {
                matrices: chunks,
                width: masked(EXTENSION_DEGREE)?,
                points: 1,
                random_values: CODEWORDS,
            },
            RoundShape {
                matrices: 1,
                width: key.width,
                points: 1 + usize::from(pre_next),
                random_values: 0,
            },
        ];
        let mut current_height = log_height;
        let mut folds = Vec::new();
        for arity in p3_fri::fold_schedule(&[log_height], log_blowup, 1) {
            current_height -= arity;
            let cap = FRI_CAP.min(current_height);
            folds.push(FoldShape {
                cap_roots: power_of_two(cap)?,
                siblings: power_of_two(arity)? - 1,
                path_hashes: maximum_pruned_hashes(current_height, cap, queries)?,
            });
        }
        let schema = ProofShape {
            body_limit: frame_limit - FRAME_BYTES,
            salt_elements: SALTS,
            main_width: air.width(),
            preprocessed_width: key.width,
            main_next,
            preprocessed_next: pre_next,
            quotient_chunks: chunks,
            degree_bits: key.degree_bits,
            input_cap_roots: input_roots,
            input_path_hashes: maximum_pruned_hashes(log_height, input_cap, queries)?,
            num_queries: queries,
            final_poly_len: 1,
            zero_batch_work: params.batch_pow_bits == 0,
            zero_commit_work: params.commit_pow_bits == 0,
            zero_query_work: params.query_pow_bits == 0,
            zero_ood_work: config.ood_proof_of_work_bits() == 0,
            rounds,
            folds,
        };
        let identity = bind_identity(relation, binding, profile, key, &schema)?;
        let result = Self {
            schema,
            identity,
            frame_limit,
        };
        if result.maximum_frame_bytes()? > frame_limit {
            return Err(ProofDecodeError::BodyTooLarge);
        }
        Ok(result)
    }

    /// Composite identity derived from the exact local relation, key and shape.
    pub const fn identity(&self) -> Identity {
        self.identity
    }

    pub fn encode(&self, proof: &Proof<Config>) -> Result<Vec<u8>, DecodeError> {
        let body = postcard::to_allocvec(proof)
            .map_err(|_| DecodeError::Body(ProofDecodeError::DependencyCodec))?;
        self.schema
            .validate_encoding(&body)
            .map_err(DecodeError::Body)?;
        super::encode(self.identity, &body, self.frame_limit).map_err(DecodeError::Frame)
    }

    pub fn decode(&self, bytes: &[u8]) -> Result<Proof<Config>, DecodeError> {
        let body =
            super::parse(bytes, self.identity, self.frame_limit).map_err(DecodeError::Frame)?;
        self.schema
            .validate_encoding(body)
            .map_err(DecodeError::Body)?;
        let (proof, tail) = postcard::take_from_bytes::<Proof<Config>>(body)
            .map_err(|_| DecodeError::Body(ProofDecodeError::DependencyCodec))?;
        if !tail.is_empty()
            || postcard::to_allocvec(&proof)
                .map_err(|_| DecodeError::Body(ProofDecodeError::DependencyCodec))?
                != body
        {
            return Err(DecodeError::Body(ProofDecodeError::NonCanonical));
        }
        Ok(proof)
    }

    /// Conservative structural bound, including every framing/vector byte and
    /// the maximum pruned authentication frontier at each individual tree.
    pub fn maximum_frame_bytes(&self) -> Result<usize, ProofDecodeError> {
        let s = &self.schema;
        let mut size = Size::default();
        size.add(FRAME_BYTES)?;
        size.add(3 * cap(s.input_cap_roots)? + 1)?;
        size.add(ext(s.main_width)?)?;
        size.add(1 + if s.main_next { ext(s.main_width)? } else { 0 })?;
        size.add(1 + ext(s.preprocessed_width)?)?;
        size.add(
            1 + if s.preprocessed_next {
                ext(s.preprocessed_width)?
            } else {
                0
            },
        )?;
        size.add(vector(s.quotient_chunks, ext(EXTENSION_DEGREE)?)?)?;
        size.add(1 + ext(EXTENSION_DEGREE)?)?;
        size.add(varint(s.rounds.len()))?;
        for round in &s.rounds {
            size.add(vector(
                round.matrices,
                vector(round.points, ext(round.random_values)?)?,
            )?)?;
        }
        size.add(4)?;
        size.add(varint(s.folds.len()))?;
        for fold in &s.folds {
            size.add(cap(fold.cap_roots)?)?;
        }
        size.add(base(s.folds.len())?)?;
        size.add(varint(s.rounds.len()))?;
        for round in &s.rounds {
            let row = varint(round.matrices)
                .checked_add(
                    round
                        .matrices
                        .checked_mul(base(round.width)?)
                        .ok_or(ProofDecodeError::InvalidTrustedShape)?,
                )
                .ok_or(ProofDecodeError::InvalidTrustedShape)?;
            size.add(vector(s.num_queries, row)?)?;
            size.add(vector(
                s.num_queries,
                vector(round.matrices, base(SALTS)?)?,
            )?)?;
            size.add(vector(s.input_path_hashes, DIGEST_ELEMENTS * 4)?)?;
        }
        size.add(varint(s.folds.len()))?;
        for fold in &s.folds {
            size.add(vector(s.num_queries, ext(fold.siblings)?)?)?;
            size.add(vector(s.num_queries, vector(1, base(SALTS)?)?)?)?;
            size.add(vector(fold.path_hashes, DIGEST_ELEMENTS * 4)?)?;
        }
        size.add(ext(s.final_poly_len)?)?;
        size.add(4 + varint(s.degree_bits) + 4)?;
        Ok(size.0)
    }
}

fn bind_identity(
    relation: Relation,
    binding: ProtocolBinding,
    profile: Profile,
    key: &PreprocessedVerifierKey<Config>,
    schema: &ProofShape,
) -> Result<Identity, ProofDecodeError> {
    let mut hash = blake3::Hasher::new_derive_key("siworld native hiding proof identity v2");
    hash.update(b"SIWZKP2\0/postcard-canonical/pruned-mmcs-v1");
    hash.update(&super::ConsensusProofLimits.encode());
    hash.update(&[relation as u8]);
    hash.update(&binding.genesis);
    hash.update(&binding.rules);
    hash.update(&binding.air);
    hash.update(&profile.id());
    hash.update(&(key.width as u64).to_le_bytes());
    hash.update(&(key.degree_bits as u64).to_le_bytes());
    let key_bytes = postcard::to_allocvec(&key.commitment)
        .map_err(|_| ProofDecodeError::InvalidTrustedShape)?;
    hash.update(&(key_bytes.len() as u64).to_le_bytes());
    hash.update(&key_bytes);
    for n in [
        schema.body_limit,
        schema.salt_elements,
        schema.main_width,
        schema.preprocessed_width,
        schema.quotient_chunks,
        schema.degree_bits,
        schema.input_cap_roots,
        schema.input_path_hashes,
        schema.num_queries,
        schema.final_poly_len,
    ] {
        hash.update(&(n as u64).to_le_bytes());
    }
    hash.update(&[
        schema.main_next as u8,
        schema.preprocessed_next as u8,
        schema.zero_batch_work as u8,
        schema.zero_commit_work as u8,
        schema.zero_query_work as u8,
        schema.zero_ood_work as u8,
    ]);
    hash.update(&(schema.rounds.len() as u64).to_le_bytes());
    for round in &schema.rounds {
        for n in [
            round.matrices,
            round.width,
            round.points,
            round.random_values,
        ] {
            hash.update(&(n as u64).to_le_bytes());
        }
    }
    hash.update(&(schema.folds.len() as u64).to_le_bytes());
    for fold in &schema.folds {
        for n in [fold.cap_roots, fold.siblings, fold.path_hashes] {
            hash.update(&(n as u64).to_le_bytes());
        }
    }
    Ok(Identity {
        relation,
        profile: *hash.finalize().as_bytes(),
    })
}

#[derive(Default)]
struct Size(usize);
impl Size {
    fn add(&mut self, n: usize) -> Result<(), ProofDecodeError> {
        self.0 = self
            .0
            .checked_add(n)
            .ok_or(ProofDecodeError::InvalidTrustedShape)?;
        Ok(())
    }
}
fn varint(mut n: usize) -> usize {
    let mut bytes = 1;
    while n >= 128 {
        bytes += 1;
        n >>= 7;
    }
    bytes
}
fn vector(n: usize, item: usize) -> Result<usize, ProofDecodeError> {
    n.checked_mul(item)
        .and_then(|n_bytes| n_bytes.checked_add(varint(n)))
        .ok_or(ProofDecodeError::InvalidTrustedShape)
}
fn base(n: usize) -> Result<usize, ProofDecodeError> {
    vector(n, 4)
}
fn ext(n: usize) -> Result<usize, ProofDecodeError> {
    vector(n, EXTENSION_DEGREE * 4)
}
fn cap(n: usize) -> Result<usize, ProofDecodeError> {
    vector(n, DIGEST_ELEMENTS * 4)
}

pub(super) fn maximum_pruned_hashes(
    height: usize,
    cap: usize,
    queries: usize,
) -> Result<usize, ProofDecodeError> {
    if cap > height || height >= usize::BITS as usize || queries > 256 {
        return Err(ProofDecodeError::InvalidTrustedShape);
    }
    let depth = height - cap;
    let mut maximum = 0;
    for n in 0..=queries.min(1 << height) {
        if depth == 0 {
            continue;
        }
        let internal: usize = (1..depth).map(|level| n.min(1 << (height - level))).sum();
        maximum = maximum.max(2 * n.min(1 << cap) + internal - n);
    }
    Ok(maximum)
}

#[cfg(test)]
#[path = "native/tests.rs"]
mod tests;
