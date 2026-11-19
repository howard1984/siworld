use super::*;
use p3_field::Field;

#[test]
fn canonical_vector_matches_independent_shake256() {
    let hasher = InputLeafHash::new([0x42; 32]);
    let values = [0, 1, F::ORDER_U32 - 1, F::ORDER_U32 - 2, 42].map(F::from_u32);
    let digest: [F; 12] = hasher.hash_slice(&values);
    // SHAKE256 vector computed from the specified canonical bytes, separately
    // from the incremental Rust implementation. No private material is used.
    assert_eq!(
        digest.map(|x| x.as_canonical_u32()),
        [
            811505216, 613627314, 883863752, 1888435075, 553067219, 1628417052, 581461763,
            1563268846, 2119361059, 373782646, 1889140915, 1498633157
        ]
    );
    assert_eq!(hasher.header().len(), 68);
}

#[test]
fn profile_order_count_and_trailing_zero_are_bound() {
    let a = InputLeafHash::new([3; 32]);
    let b = InputLeafHash::new([4; 32]);
    let one = F::ONE;
    let zero = F::ZERO;
    let hash = |h: InputLeafHash, fields: &[F]| -> [F; 12] { h.hash_slice(fields) };
    assert_ne!(hash(a, &[one]), hash(b, &[one]));
    assert_ne!(hash(a, &[one]), hash(a, &[one, zero]));
    assert_ne!(hash(a, &[zero, one]), hash(a, &[one, zero]));
    assert_ne!(hash(a, &[]), hash(a, &[zero]));
}

#[test]
fn segmented_scalar_batch_and_packed_lanes_agree() {
    type P = <F as Field>::Packing;
    let hasher = InputLeafHash::new([0x17; 32]);
    // Cross several rate boundaries and include a non-multiple of rate/width.
    let packed: Vec<P> = (0..113)
        .map(|row| P::from_fn(|lane| F::from_usize(row * 19 + lane)))
        .collect();
    let digest: [P; 12] = hasher.hash_slice(&packed);
    let segmented: [P; 12] =
        hasher.hash_iter_slices([&packed[..7], &packed[7..109], &packed[109..]]);
    for lane in 0..P::WIDTH {
        let scalar: Vec<F> = packed.iter().map(|p| p.extract(lane)).collect();
        let expected: [F; 12] = hasher.hash_slice(&scalar);
        for j in 0..12 {
            assert_eq!(digest[j].extract(lane), expected[j]);
            assert_eq!(segmented[j].extract(lane), expected[j]);
        }
    }
    let scalar: Vec<F> = (0..30).map(F::from_usize).collect();
    let mut batch = [[F::ZERO; 12]; 3];
    hasher.hash_many(&scalar, &mut batch);
    for (part, digest) in scalar.as_chunks::<10>().0.iter().zip(batch) {
        let expected: [F; 12] = hasher.hash_slice(part);
        assert_eq!(digest, expected);
    }
    let mut empty = [[F::ZERO; 12]; 2];
    hasher.hash_many(&[], &mut empty);
    assert_eq!(empty[0], empty[1]);
    assert_eq!(empty[0], hasher.hash_slice(&[] as &[F]));
}

#[test]
fn finite_field_map_rejects_and_zero_fills_exactly() {
    let mut bytes = [0xff; 256];
    assert_eq!(map_prefix(&bytes), [F::ZERO; 12]);
    for (j, slot) in bytes.as_chunks_mut::<4>().0.iter_mut().take(11).enumerate() {
        slot.copy_from_slice(&((j as u32 + 1) << 1).to_le_bytes());
    }
    let mut expected = [F::ZERO; 12];
    for (j, value) in expected.iter_mut().take(11).enumerate() {
        *value = F::from_usize(j + 1);
    }
    assert_eq!(map_prefix(&bytes), expected);
    for (j, slot) in bytes.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        slot.copy_from_slice(&(((j as u32 + 1) << 1) | 1).to_le_bytes());
    }
    assert_eq!(
        map_prefix(&bytes),
        core::array::from_fn(|j| F::from_usize(j + 1))
    );
    let mut threshold = [0; 256];
    for slot in threshold.as_chunks_mut::<4>().0.iter_mut() {
        slot.copy_from_slice(&(F::ORDER_U32 << 1).to_le_bytes());
    }
    assert_eq!(map_prefix(&threshold), [F::ZERO; 12]);
}
