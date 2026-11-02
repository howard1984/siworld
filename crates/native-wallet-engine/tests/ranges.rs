use siworld_native_wallet_engine::ranges::{DOMAIN, RangeProof};

#[test]
fn binds_ranges_to_existing_derive_key_hash_at_irregular_boundaries() {
    for length in [151, 1024, 1025, 2048, 2049, 3007, 8193, 65539] {
        let data: Vec<u8> = (0..length).map(|i| (i * 17) as u8).collect();
        let end = length.min(2300);
        let proof = RangeProof::create(&data, &[(0, 150), (length - end, end)]).unwrap();
        let root = *blake3::Hasher::new_derive_key(DOMAIN)
            .update(&data)
            .finalize()
            .as_bytes();
        let sparse = RangeProof::verify(&proof, root).unwrap();
        assert_eq!(sparse.read(0, 150).unwrap(), data[..150]);
        assert_eq!(
            sparse.read(length - end, end).unwrap(),
            data[length - end..]
        );
        let mut changed = proof.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(RangeProof::verify(&changed, root).is_err());
        let mut wrong = root;
        wrong[0] ^= 1;
        assert!(RangeProof::verify(&proof, wrong).is_err());
        let mut extra = proof.clone();
        extra.push(0);
        assert!(RangeProof::verify(&extra, root).is_err());
        assert!(RangeProof::verify(&proof[..proof.len() - 1], root).is_err());
    }
}

#[test]
fn hidden_ranges_cannot_be_read_or_mistaken_for_zeroes() {
    let data = vec![7; 16385];
    let proof = RangeProof::create(&data, &[(0, 150), (16000, 100)]).unwrap();
    let root = *blake3::Hasher::new_derive_key(DOMAIN)
        .update(&data)
        .finalize()
        .as_bytes();
    let sparse = RangeProof::verify(&proof, root).unwrap();
    assert!(sparse.read(1024, 1).is_err());
    assert!(sparse.read(usize::MAX, 1).is_err());
    assert!(proof.len() < 4096);
}

#[test]
fn sparse_shapes_match_standard_hash_across_deterministic_range_patterns() {
    let mut x = 7919u64;
    for _ in 0..100 {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
        let length = 1 + (x as usize % 120000);
        let bytes = (0..length)
            .map(|i| ((i * 31) ^ length) as u8)
            .collect::<Vec<_>>();
        let from = x as usize % length;
        let count = (length - from).min(7 + length % 3300);
        let encoded = RangeProof::create(&bytes, &[(from, count)]).unwrap();
        let root = *blake3::Hasher::new_derive_key(DOMAIN)
            .update(&bytes)
            .finalize()
            .as_bytes();
        assert_eq!(
            RangeProof::verify(&encoded, root)
                .unwrap()
                .read(from, count)
                .unwrap(),
            bytes[from..from + count]
        );
        let mut malformed = encoded;
        malformed[16] = 3;
        assert!(RangeProof::verify(&malformed, root).is_err());
    }
}
