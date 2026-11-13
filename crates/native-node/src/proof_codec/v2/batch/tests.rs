use super::super::backend::PrivateAttempt;
use super::*;
use p3_air::{AirBuilder, BaseAir, PermutationAirBuilder, WindowAccess};
use p3_batch_stark::StarkInstance;
use p3_field::PrimeCharacteristicRing;
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

#[derive(Clone)]
struct SmallLookupAir;
impl BaseAir<F> for SmallLookupAir {
    fn width(&self) -> usize {
        1
    }
    fn preprocessed_width(&self) -> usize {
        1
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        Some(RowMajorMatrix::new(vec![F::ONE; 256], 1))
    }
    fn num_public_values(&self) -> usize {
        1
    }
}
impl<AB: AirBuilder<F = F> + PermutationAirBuilder + InteractionBuilder> Air<AB>
    for SmallLookupAir
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice()[0];
        let expected = builder.public_values()[0];
        builder.assert_eq(local, expected);
        builder.push_local_interaction(vec![
            (vec![local.into()], Count::bounded(AB::Expr::ONE, 1)),
            (vec![local.into()], Count::provided(-AB::Expr::ONE)),
        ]);
    }
}
fn binding() -> ProtocolBinding {
    ProtocolBinding {
        genesis: [1; 32],
        rules: [2; 32],
        air: [3; 32],
    }
}

#[test]
fn small_lookup_air_roundtrip_checks_fresh_verifier_and_adversarial_batch_fields() {
    // A small synthetic lookup AIR exercises the real typed batch backend.
    // It does not establish that the complete confidential-fee AIR is integrated.
    let verifier =
        CompleteFeeBatchVerifier::from_authenticated_air(SmallLookupAir, 9, binding()).unwrap();
    let public = PublicPreprocessing::new(profile());
    let data = ProverData::from_airs_and_degrees(public.config(), &[SmallLookupAir], &[9]).unwrap();
    let trace = RowMajorMatrix::new(vec![F::ONE; 256], 1);
    let attempt = PrivateAttempt::from_os(profile()).unwrap();
    let mut proof = attempt
        .run(|cfg| {
            p3_batch_stark::prove_batch(
                cfg,
                &[StarkInstance {
                    air: &SmallLookupAir,
                    trace: &trace,
                    public_values: vec![F::ONE],
                }],
                &data,
            )
        })
        .unwrap()
        .unwrap();
    let frame = verifier.shape.encode(&proof).unwrap();
    assert!(frame.len() <= super::super::MAX_FEE_PROOF_BYTES);
    let fresh =
        CompleteFeeBatchVerifier::from_authenticated_air(SmallLookupAir, 9, binding()).unwrap();
    fresh.verify(&frame, &[F::ONE]).unwrap();
    assert!(matches!(
        fresh.verify(&frame, &[F::TWO]),
        Err(Error::Verification)
    ));
    let mut wrong_identity = frame.clone();
    wrong_identity[12] ^= 1;
    assert!(matches!(
        fresh.shape.decode(&wrong_identity),
        Err(Error::Frame(super::super::FrameError::Identity))
    ));
    let truncated = &frame[..frame.len() - 1];
    assert!(fresh.shape.decode(truncated).is_err());
    let terminal = proof.lookup_terminals[0].as_mut().unwrap();
    terminal.0 += E::ONE;
    assert!(matches!(
        fresh.shape.encode(&proof),
        Err(Error::Body(ProofDecodeError::Shape(
            "nonzero_closed_lookup_terminal"
        )))
    ));
    proof.lookup_terminals[0].as_mut().unwrap().0 -= E::ONE;
    proof.opened_values.instances[0].permutation_local.pop();
    let raw = postcard::to_allocvec(&proof).unwrap();
    let frame = super::super::encode(
        fresh.shape.identity(),
        &raw,
        super::super::MAX_FEE_PROOF_BYTES,
    )
    .unwrap();
    assert!(matches!(
        fresh.shape.decode(&frame),
        Err(Error::Body(ProofDecodeError::Shape(
            "batch_permutation_local"
        )))
    ));
}

#[test]
fn binding_and_degree_are_selected_before_preprocessing_or_proof_decoding() {
    for degree in [0, 8, 13, usize::MAX] {
        assert!(matches!(
            CompleteFeeBatchVerifier::from_authenticated_air(SmallLookupAir, degree, binding()),
            Err(Error::TrustedConfiguration)
        ));
    }
    let mut empty = binding();
    empty.genesis = [0; 32];
    assert!(matches!(
        CompleteFeeBatchVerifier::from_authenticated_air(SmallLookupAir, 9, empty),
        Err(Error::TrustedConfiguration)
    ));
    let a = CompleteFeeBatchVerifier::from_authenticated_air(SmallLookupAir, 9, binding()).unwrap();
    let mut changed = binding();
    changed.rules[0] ^= 1;
    let b = CompleteFeeBatchVerifier::from_authenticated_air(SmallLookupAir, 9, changed).unwrap();
    assert_ne!(a.shape.identity(), b.shape.identity());
    assert_eq!(a.shape.identity().relation, Relation::CompleteFee);
}
