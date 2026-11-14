//! Salted input and FRI MMCSs with separate public and private authority.
use super::entropy::{EntropyError, Streams};
use super::owner::{AccessError, Alias, Owner, OwnerError};
use super::{FRI_CAP_HEIGHT, INPUT_CAP_HEIGHT, Profile, RANDOM_CODEWORDS, SALT_ELEMENTS};
use ::native::common::F;
use p3_challenger::{CanObserve, DuplexChallenger};
use p3_commit::{
    CommitmentOpening, ExtensionMmcs, OpenedValues, OpeningRequest, Pcs, UnivariateStarkPcs,
};
use p3_dft::Radix2DitParallel;
use p3_field::{Field, PrimeCharacteristicRing, extension::BinomialExtensionField};
use p3_fri::{FriParameters, HidingFriPcs};
use p3_koala_bear::{Poseidon2KoalaBear, default_koalabear_poseidon2_24};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, StarkGenericConfig};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

pub type E = BinomialExtensionField<F, 8>;
pub type Challenger = DuplexChallenger<F, Poseidon2KoalaBear<24>, 24, 12>;
type SaltMmcs = MerkleTreeHidingMmcs<
    <F as Field>::Packing,
    <F as Field>::Packing,
    PaddingFreeSponge<Poseidon2KoalaBear<24>, 24, 12, 12>,
    TruncatedPermutation<Poseidon2KoalaBear<24>, 2, 12, 24>,
    StdRng,
    2,
    12,
    SALT_ELEMENTS,
>;
type RawPcs =
    HidingFriPcs<F, Radix2DitParallel<F>, SaltMmcs, ExtensionMmcs<F, E, SaltMmcs>, StdRng>;
type Domain = <RawPcs as Pcs<E, Challenger>>::Domain;
type Commitment = <RawPcs as Pcs<E, Challenger>>::Commitment;
type Data = <RawPcs as Pcs<E, Challenger>>::ProverData;
type Proof = <RawPcs as Pcs<E, Challenger>>::Proof;
type Error = <RawPcs as Pcs<E, Challenger>>::Error;
type ProverError = <RawPcs as Pcs<E, Challenger>>::ProverError;

fn mmcs(rng: StdRng, cap: usize) -> SaltMmcs {
    let p = default_koalabear_poseidon2_24();
    SaltMmcs::new(
        PaddingFreeSponge::new(p.clone()),
        TruncatedPermutation::new(p),
        cap,
        rng,
    )
}
fn raw(profile: Profile, input_rng: StdRng, fri_rng: StdRng, masks: StdRng) -> RawPcs {
    let p = profile.params();
    let fri = FriParameters {
        log_blowup: p.log_blowup as usize,
        num_queries: p.num_queries as usize,
        log_final_poly_len: 0,
        max_log_arity: p.max_log_arity as usize,
        batch_proof_of_work_bits: p.batch_pow_bits as usize,
        commit_proof_of_work_bits: p.commit_pow_bits as usize,
        query_proof_of_work_bits: p.query_pow_bits as usize,
        mmcs: ExtensionMmcs::new(mmcs(fri_rng, FRI_CAP_HEIGHT)),
    };
    HidingFriPcs::new(
        Radix2DitParallel::default(),
        mmcs(input_rng, INPUT_CAP_HEIGHT),
        fri,
        RANDOM_CODEWORDS,
        masks,
    )
}
fn public_seed(profile: Profile, purpose: &str) -> StdRng {
    StdRng::from_seed(blake3::derive_key(purpose, &profile.id()))
}
/// Only the public preprocessing method exists on this deterministic backend.
/// Its seeds are public constants; private commits/openings cannot reach it.
struct PublicPreprocessingOnly {
    inner: RawPcs,
}
impl PublicPreprocessingOnly {
    fn new(profile: Profile) -> Self {
        Self {
            inner: raw(
                profile,
                public_seed(
                    profile,
                    "siworld native hiding v2 public preprocessing input salts",
                ),
                public_seed(
                    profile,
                    "siworld native hiding v2 disabled public FRI stream",
                ),
                public_seed(
                    profile,
                    "siworld native hiding v2 disabled public mask stream",
                ),
            ),
        }
    }
    fn commit_public(
        &self,
        values: impl IntoIterator<Item = (Domain, RowMajorMatrix<F>)>,
    ) -> Result<(Commitment, Data), ProverError> {
        UnivariateStarkPcs::<E, Challenger>::commit_preprocessing(&self.inner, values)
    }
}

pub struct PrivatePcs {
    inner: Arc<RawPcs>,
    fence: Alias,
    profile: Profile,
}
impl PrivatePcs {
    /// Exact read-only backend parameters; no private stream or seed access.
    pub const fn profile(&self) -> Profile {
        self.profile
    }
}
impl Clone for PrivatePcs {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            fence: self.fence.clone(),
            profile: self.profile,
        }
    }
}
/// Locally selected proof domain; outer frame bytes never supply authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TranscriptContext([u8; 32]);
impl TranscriptContext {
    pub fn new(
        network: [u8; 32],
        binding: crate::proof_codec::v2::ProtocolBinding,
        identity: crate::proof_codec::v2::Identity,
    ) -> Result<Self, String> {
        if identity.relation == crate::proof_codec::v2::Relation::CompleteFee
            || [
                network,
                binding.genesis,
                binding.rules,
                binding.air,
                identity.profile,
            ]
            .contains(&[0; 32])
        {
            return Err("invalid retained proof transcript context".into());
        }
        let mut hash =
            blake3::Hasher::new_derive_key("siworld retained salted proof transcript context v2");
        hash.update(&[identity.relation as u8]);
        hash.update(&network);
        hash.update(&binding.genesis);
        hash.update(&binding.rules);
        hash.update(&binding.air);
        // The trusted composite identity includes backend profile, key and shape.
        hash.update(&identity.profile);
        Ok(Self(*hash.finalize().as_bytes()))
    }
    fn observe(self, challenger: &mut Challenger) {
        const LABEL: &[u8] = b"siworld retained native proof domain v2";
        challenger.observe(F::from_usize(LABEL.len()));
        for byte in LABEL.iter().chain(self.0.iter()) {
            challenger.observe(F::from_u8(*byte));
        }
    }
}
pub type Config = StarkConfig<PrivatePcs, E, Challenger>;
fn config(pcs: PrivatePcs) -> Config {
    StarkConfig::new(pcs, DuplexChallenger::new(default_koalabear_poseidon2_24()))
}
fn config_with_context(pcs: PrivatePcs, context: TranscriptContext) -> Config {
    let mut challenger = DuplexChallenger::new(default_koalabear_poseidon2_24());
    context.observe(&mut challenger);
    StarkConfig::new(pcs, challenger)
}
/// Reusable trusted public setup and verification route. It has no owner that
/// can activate private operations; deterministic seeds cannot create a proof.
pub struct PublicPreprocessing {
    config: Config,
    profile: Profile,
}
impl PublicPreprocessing {
    pub fn new(profile: Profile) -> Self {
        let (_, fence) = Owner::new();
        let inner = PublicPreprocessingOnly::new(profile).inner;
        Self {
            config: config(PrivatePcs {
                inner: Arc::new(inner),
                fence,
                profile,
            }),
            profile,
        }
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    /// Reuses only public preprocessing; every proof transcript starts here.
    pub fn config_with_context(&self, context: TranscriptContext) -> Config {
        config_with_context(self.config.pcs().clone(), context)
    }
    pub const fn profile(&self) -> Profile {
        self.profile
    }
}
/// One proof attempt. No raw PCS, RNG or seed access and no Clone or Debug.
/// All configuration aliases retire on callback return or unwind.
pub struct PrivateAttempt {
    config: Config,
    owner: Owner,
}
impl PrivateAttempt {
    pub fn from_os(profile: Profile) -> Result<Self, EntropyError> {
        Self::from_os_with(profile, config)
    }
    /// Mandatory context route for genesis-bound retained proofs.
    pub fn from_os_with_context(
        profile: Profile,
        context: TranscriptContext,
    ) -> Result<Self, EntropyError> {
        Self::from_os_with(profile, |pcs| config_with_context(pcs, context))
    }
    fn from_os_with(
        profile: Profile,
        initialize: impl FnOnce(PrivatePcs) -> Config,
    ) -> Result<Self, EntropyError> {
        let streams = Streams::from_os()?;
        let (owner, fence) = Owner::new();
        Ok(Self {
            config: initialize(PrivatePcs {
                inner: Arc::new(raw(
                    profile,
                    streams.input_salts,
                    streams.fri_salts,
                    streams.masks,
                )),
                fence,
                profile,
            }),
            owner,
        })
    }
    pub fn run<R>(&self, f: impl FnOnce(&Config) -> R) -> Result<R, OwnerError> {
        self.owner.run(|| f(&self.config))
    }
}
impl Pcs<E, Challenger> for PrivatePcs {
    type Domain = Domain;
    type Commitment = Commitment;
    type ProverData = Data;
    type Proof = Proof;
    type Error = Error;
    type ProverError = AccessError<ProverError>;
    fn natural_domain_for_degree(&self, n: usize) -> Domain {
        Pcs::<E, Challenger>::natural_domain_for_degree(&*self.inner, n)
    }
    fn commit(
        &self,
        v: impl IntoIterator<Item = (Domain, RowMajorMatrix<F>)>,
    ) -> Result<(Commitment, Data), Self::ProverError> {
        self.fence
            .access(false, || Pcs::<E, Challenger>::commit(&*self.inner, v))
    }
    fn open(
        &self,
        v: Vec<OpeningRequest<'_, Data, E>>,
        c: &mut Challenger,
    ) -> Result<(OpenedValues<E>, Proof), Self::ProverError> {
        self.open_with_preprocessing(v, c, None)
    }
    fn verify(
        &self,
        v: Vec<CommitmentOpening<E, Commitment, Domain>>,
        p: &Proof,
        c: &mut Challenger,
    ) -> Result<(), Error> {
        Pcs::<E, Challenger>::verify(&*self.inner, v, p, c)
    }
}
impl UnivariateStarkPcs<E, Challenger> for PrivatePcs {
    type EvaluationsOnDomain<'a> =
        <RawPcs as UnivariateStarkPcs<E, Challenger>>::EvaluationsOnDomain<'a>;
    const ZK: bool = true;
    fn log_max_trace_height(&self) -> usize {
        UnivariateStarkPcs::<E, Challenger>::log_max_trace_height(&*self.inner)
    }
    fn log_min_trace_height(&self) -> usize {
        UnivariateStarkPcs::<E, Challenger>::log_min_trace_height(&*self.inner)
    }
    fn commit_preprocessing(
        &self,
        v: impl IntoIterator<Item = (Domain, RowMajorMatrix<F>)>,
    ) -> Result<(Commitment, Data), Self::ProverError> {
        PublicPreprocessingOnly::new(self.profile)
            .commit_public(v)
            .map_err(AccessError::Backend)
    }
    fn get_quotient_ldes(
        &self,
        v: impl IntoIterator<Item = (Domain, RowMajorMatrix<F>)>,
        n: usize,
    ) -> Result<Vec<RowMajorMatrix<F>>, Self::ProverError> {
        self.fence.access(false, || {
            UnivariateStarkPcs::<E, Challenger>::get_quotient_ldes(&*self.inner, v, n)
        })
    }
    fn commit_ldes(
        &self,
        v: Vec<RowMajorMatrix<F>>,
    ) -> Result<(Commitment, Data), Self::ProverError> {
        self.fence.access(false, || {
            UnivariateStarkPcs::<E, Challenger>::commit_ldes(&*self.inner, v)
        })
    }
    fn get_evaluations_on_domain<'a>(
        &self,
        d: &'a Data,
        i: usize,
        n: Domain,
    ) -> Self::EvaluationsOnDomain<'a> {
        UnivariateStarkPcs::<E, Challenger>::get_evaluations_on_domain(&*self.inner, d, i, n)
    }
    fn get_evaluations_on_domain_no_random<'a>(
        &self,
        d: &'a Data,
        i: usize,
        n: Domain,
    ) -> Self::EvaluationsOnDomain<'a> {
        UnivariateStarkPcs::<E, Challenger>::get_evaluations_on_domain_no_random(
            &*self.inner,
            d,
            i,
            n,
        )
    }
    fn open_with_preprocessing(
        &self,
        v: Vec<OpeningRequest<'_, Data, E>>,
        c: &mut Challenger,
        p: Option<usize>,
    ) -> Result<(OpenedValues<E>, Proof), Self::ProverError> {
        self.fence.access(true, || {
            UnivariateStarkPcs::<E, Challenger>::open_with_preprocessing(&*self.inner, v, c, p)
        })
    }
    fn verify_with_preprocessing(
        &self,
        v: Vec<CommitmentOpening<E, Commitment, Domain>>,
        p: &Proof,
        c: &mut Challenger,
        i: Option<usize>,
    ) -> Result<(), Error> {
        UnivariateStarkPcs::<E, Challenger>::verify_with_preprocessing(&*self.inner, v, p, c, i)
    }
    fn get_opt_randomization_poly_commitment(
        &self,
        d: impl IntoIterator<Item = Domain>,
    ) -> Result<Option<(Commitment, Data)>, Self::ProverError> {
        self.fence.access(false, || {
            UnivariateStarkPcs::<E, Challenger>::get_opt_randomization_poly_commitment(
                &*self.inner,
                d,
            )
        })
    }
}
