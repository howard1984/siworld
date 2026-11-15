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

#[test]
fn independent_suite_preserves_geometry_and_rejects_legacy_proof_bodies() {
    use crate::proof_codec::v2::{self, ProtocolBinding, Relation};
    use p3_uni_stark::{prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
    let legacy_profile = super::super::Profile::new(::native::FriParams::fast()).unwrap();
    let legacy = super::super::PublicPreprocessing::new(legacy_profile);
    let current = PublicPreprocessing::new(small());
    let (old_data, old_key) = setup_preprocessed(legacy.config(), &TinyAir, 6)
        .unwrap()
        .unwrap();
    let (new_data, new_key) = setup_preprocessed(current.config(), &TinyAir, 6)
        .unwrap()
        .unwrap();
    assert_ne!(legacy_profile.id(), small().id());
    assert_ne!(old_key.commitment, new_key.commitment);
    for (old, new) in [
        (super::super::Profile::transaction(), Profile::transaction()),
        (super::super::Profile::settlement(), Profile::settlement()),
        (super::super::Profile::issuance(), Profile::issuance()),
    ] {
        assert_eq!(old.minimum_height(), new.minimum_height());
        let a = old.params();
        let b = new.params();
        assert_eq!(
            (a.log_blowup, a.num_queries, a.max_log_arity),
            (b.log_blowup, b.num_queries, b.max_log_arity)
        );
        assert_eq!(
            (a.batch_pow_bits, a.commit_pow_bits, a.query_pow_bits),
            (b.batch_pow_bits, b.commit_pow_bits, b.query_pow_bits)
        );
        assert_ne!(old.id(), new.id());
    }
    // Bounded 64-row/q2/no-grinding positive controls; no real relation proof.
    let old = super::super::PrivateAttempt::from_os(legacy_profile)
        .unwrap()
        .run(|cfg| {
            prove_with_preprocessed(
                cfg,
                &TinyAir,
                RowMajorMatrix::new(vec![F::ZERO; 64 * 3], 3),
                &[],
                Some(&old_data),
            )
        })
        .unwrap()
        .unwrap();
    let new = PrivateAttempt::from_os(small())
        .unwrap()
        .run(|cfg| {
            prove_with_preprocessed(
                cfg,
                &TinyAir,
                RowMajorMatrix::new(vec![F::ZERO; 64 * 3], 3),
                &[],
                Some(&new_data),
            )
        })
        .unwrap()
        .unwrap();
    verify_with_preprocessed(legacy.config(), &TinyAir, &old, &[], Some(&old_key)).unwrap();
    verify_with_preprocessed(current.config(), &TinyAir, &new, &[], Some(&new_key)).unwrap();
    let binding = ProtocolBinding {
        genesis: [1; 32],
        rules: [2; 32],
        air: [3; 32],
    };
    // All retained relation codes must reject a legacy frame and a legacy body
    // relabeled with the correct new outer identity. This fixture tests suite
    // routing, not the real relation's AIR or production genesis acceptance.
    for relation in [
        Relation::Transaction,
        Relation::Settlement,
        Relation::Issuance,
    ] {
        let limit = relation.maximum_frame_bytes();
        let a = v2::native::NativeProofShape::from_trusted(
            &TinyAir,
            &old_key,
            legacy.config(),
            legacy_profile,
            relation,
            binding,
            limit,
        )
        .unwrap();
        let b = v2::retained_native::NativeProofShape::from_trusted(
            &TinyAir,
            &new_key,
            current.config(),
            small(),
            relation,
            binding,
            limit,
        )
        .unwrap();
        let old_frame = a.encode(&old).unwrap();
        let new_frame = b.encode(&new).unwrap();
        assert!(b.decode(&old_frame).is_err());
        assert!(a.decode(&new_frame).is_err());
        let mut relabeled = old_frame;
        relabeled[12..44].copy_from_slice(&b.identity().profile);
        let decoded = b.decode(&relabeled).unwrap();
        assert!(
            verify_with_preprocessed(current.config(), &TinyAir, &decoded, &[], Some(&new_key))
                .is_err()
        );
        let mut relabeled = new_frame;
        relabeled[12..44].copy_from_slice(&a.identity().profile);
        let decoded = a.decode(&relabeled).unwrap();
        assert!(
            verify_with_preprocessed(legacy.config(), &TinyAir, &decoded, &[], Some(&old_key))
                .is_err()
        );
    }
}
