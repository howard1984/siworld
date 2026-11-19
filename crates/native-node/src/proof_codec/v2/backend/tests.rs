use super::*;
use ::native::common::F;
use p3_commit::{Pcs, UnivariateStarkPcs};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::StarkGenericConfig;

fn small() -> Profile {
    Profile::new(::native::FriParams::fast()).unwrap()
}
fn values() -> RowMajorMatrix<F> {
    RowMajorMatrix::new(vec![F::ZERO; 128], 2)
}

#[test]
fn public_preprocessing_is_deterministic_and_has_no_private_authority() {
    let a = PublicPreprocessing::new(small());
    let b = PublicPreprocessing::new(small());
    let domain = a.config().pcs().natural_domain_for_degree(128);
    let (ac, _) = a
        .config()
        .pcs()
        .commit_preprocessing([(domain, values())])
        .unwrap();
    let (bc, _) = b
        .config()
        .pcs()
        .commit_preprocessing([(domain, values())])
        .unwrap();
    assert_eq!(ac, bc);
    assert!(matches!(
        a.config().pcs().commit([(domain, values())]),
        Err(AccessError::Owner(OwnerError::Inactive))
    ));
}

#[test]
fn each_private_attempt_uses_fresh_salts_and_retires_all_aliases() {
    let attempt = PrivateAttempt::from_os(small()).unwrap();
    let (commitment, alias) = attempt
        .run(|config| {
            let domain = config.pcs().natural_domain_for_degree(128);
            let (commitment, _) = config.pcs().commit([(domain, values())]).unwrap();
            (commitment, config.clone())
        })
        .unwrap();
    assert!(matches!(attempt.run(|_| ()), Err(OwnerError::Spent)));
    let domain = alias.pcs().natural_domain_for_degree(128);
    assert!(matches!(
        alias.pcs().commit([(domain, values())]),
        Err(AccessError::Owner(OwnerError::Spent))
    ));
    let second = PrivateAttempt::from_os(small()).unwrap();
    let other = second
        .run(|config| config.pcs().commit([(domain, values())]).unwrap().0)
        .unwrap();
    assert_ne!(commitment, other);
}

#[test]
fn panic_retires_attempt_without_granting_private_retry() {
    let attempt = PrivateAttempt::from_os(small()).unwrap();
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = attempt.run::<()>(|_| panic!("synthetic callback failure"));
    }));
    assert!(failed.is_err());
    assert!(matches!(attempt.run(|_| ()), Err(OwnerError::Spent)));
}

#[test]
fn public_data_can_be_created_through_different_private_attempts() {
    let a = PrivateAttempt::from_os(small()).unwrap();
    let b = PrivateAttempt::from_os(small()).unwrap();
    let commit = |config: &Config| {
        let domain = config.pcs().natural_domain_for_degree(128);
        config
            .pcs()
            .commit_preprocessing([(domain, values())])
            .unwrap()
            .0
    };
    assert_eq!(a.run(commit).unwrap(), b.run(commit).unwrap());
}

#[test]
fn explicit_profile_identity_binds_parameters_and_is_distinct_from_v1() {
    let base = Profile::transaction();
    assert_ne!(base.id(), Profile::settlement().id());
    assert_ne!(
        base.id(),
        *blake3::hash(b"native-v1-economics-1").as_bytes()
    );
    assert_eq!(SALT_ELEMENTS, 9);
    assert_eq!(RANDOM_CODEWORDS, 8);
    let mut changed = base.params();
    changed.num_queries += 1;
    assert_ne!(base.id(), Profile::new(changed).unwrap().id());
    changed.max_log_arity = 2;
    assert!(Profile::new(changed).is_err());
}

struct TinyAir;
impl p3_air::BaseAir<F> for TinyAir {
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
impl<AB: p3_air::AirBuilder<F = F>> p3_air::Air<AB> for TinyAir {
    fn eval(&self, builder: &mut AB) {
        use p3_air::WindowAccess;
        let x: AB::Expr = builder.main().current_slice()[0].into();
        let fixed: AB::Expr = builder.preprocessed().current_slice()[0].into();
        builder.assert_zero(x.clone() * x.clone() * x.clone());
        builder.assert_eq(x, fixed);
    }
}

#[test]
fn tiny_proof_reuses_public_preprocessing_across_fresh_private_attempts() {
    use p3_uni_stark::{prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
    let public = PublicPreprocessing::new(small());
    let (pdata, vk) = setup_preprocessed(public.config(), &TinyAir, 6)
        .unwrap()
        .unwrap();
    // Fixed bounded fixture: 64 rows, width 3, q=2, blowup=4, no grinding.
    // Its complete opening geometry is below this conservative static budget.
    const SMALL_PROOF_LIMIT: usize = 64 * 1024;
    let mut proofs = Vec::new();
    for _ in 0..2 {
        let attempt = PrivateAttempt::from_os(small()).unwrap();
        let proof = attempt
            .run(|cfg| {
                let proof = prove_with_preprocessed(
                    cfg,
                    &TinyAir,
                    RowMajorMatrix::new(vec![F::ZERO; 64 * 3], 3),
                    &[],
                    Some(&pdata),
                );
                let domain = cfg.pcs().natural_domain_for_degree(128);
                assert!(matches!(
                    cfg.pcs().commit([(domain, values())]),
                    Err(AccessError::Owner(OwnerError::Spent))
                ));
                proof
            })
            .unwrap()
            .unwrap();
        verify_with_preprocessed(public.config(), &TinyAir, &proof, &[], Some(&vk)).unwrap();
        let bytes = postcard::to_allocvec(&proof).unwrap();
        assert!(bytes.len() < SMALL_PROOF_LIMIT);
        println!("native hiding V2 TinyAir proof bytes: {}", bytes.len());
        proofs.push(proof);
    }
    assert_ne!(
        postcard::to_allocvec(&proofs[0]).unwrap(),
        postcard::to_allocvec(&proofs[1]).unwrap()
    );
    proofs[0].opening_proof.1.input_openings[0].opening_proof.0[0][0][0] += F::ONE;
    assert!(
        verify_with_preprocessed(public.config(), &TinyAir, &proofs[0], &[], Some(&vk)).is_err()
    );
    proofs[1].opening_proof.1.commit_phase_openings[0]
        .opening_proof
        .0[0][0][0] += F::ONE;
    assert!(
        verify_with_preprocessed(public.config(), &TinyAir, &proofs[1], &[], Some(&vk)).is_err()
    );
}
