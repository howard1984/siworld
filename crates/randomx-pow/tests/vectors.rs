use siworld_randomx_pow::{Cache, Dataset, Implementation, epoch_key, header_input, key_height};

const VECTORS: [(u64, &str); 5] = [
    (
        0,
        "f2a8226f7d1e6a07b0b77ca2042eeaaa82fbb2b42685f14c3facfb7e239c0cb6",
    ),
    (
        1,
        "8ac46e1fa56c89e1f5a91e45c4ba74f56d9f9459b20e1d915ad5477e431ae59c",
    ),
    (
        255,
        "ac16f7e48acc7ee661b82af6356c4463eeb56b250aa741f35c4f3dcd06775c74",
    ),
    (
        256,
        "b85b27881df55b54e62071be2514c65a3200e3657b13a487c953456b6dc890e7",
    ),
    (
        0x0123456789abcdef,
        "330507df44f1fd2fe0f5b8fc8d0935410757d9665ad81cb7e81f7c7c722e35f2",
    ),
];

fn fixture_key() -> Vec<u8> {
    let mut key = b"SIWORLD/RandomX/offline-cache-key/v1\0".to_vec();
    key.extend_from_slice(&[0x53; 32]);
    key
}

fn check_vectors(mut hash: impl FnMut(&[u8]) -> [u8; 32]) {
    for (nonce, expected) in VECTORS {
        let mut message = b"SIWORLD/RandomX/offline-pow-input/v1\0".to_vec();
        message.extend_from_slice(&[0xac; 32]);
        message.extend_from_slice(&nonce.to_le_bytes());
        let actual: String = hash(&message)
            .iter()
            .map(|value| format!("{value:02x}"))
            .collect();
        assert_eq!(actual, expected, "nonce {nonce}");
    }
}

#[test]
fn pinned_salt_light_mode_matches_fixed_vectors() {
    let cache = Cache::new(&fixture_key(), Implementation::Portable).unwrap();
    let mut vm = cache.vm().unwrap();
    check_vectors(|message| vm.hash(message));
}

#[test]
#[ignore = "requires a dedicated owner-controlled machine with a full RandomX dataset"]
fn pinned_salt_fast_mode_matches_fixed_vectors() {
    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    let cache = Cache::new(&fixture_key(), Implementation::Hardware).unwrap();
    let dataset = Dataset::new(&cache, 4).unwrap();
    let mut vm = dataset.vm().unwrap();
    check_vectors(|message| vm.hash(message));
}

#[test]
fn epoch_switch_is_delayed_and_uses_the_candidate_branch() {
    let genesis = [1; 32];
    for (height, seed_height) in [
        (1, 0),
        (64, 0),
        (2111, 0),
        (2112, 2048),
        (4159, 2048),
        (4160, 4096),
    ] {
        assert_eq!(key_height(height), seed_height);
    }
    assert_eq!(epoch_key(genesis, 0, |_| panic!()), None);
    assert_eq!(epoch_key(genesis, 2112, |_| None), None);
    assert_eq!(
        epoch_key(genesis, 1, |_| panic!()),
        epoch_key(genesis, 2111, |_| panic!())
    );
    let a = epoch_key(genesis, 2112, |height| (height == 2048).then_some([2; 32])).unwrap();
    let b = epoch_key(genesis, 2112, |height| (height == 2048).then_some([3; 32])).unwrap();
    assert_ne!(a, b);
    assert_ne!(Some(a), epoch_key([4; 32], 2112, |_| Some([2; 32])));
    assert_eq!(
        &header_input([7; 32], 0x0123456789abcdef)[55..],
        &0x0123456789abcdefu64.to_le_bytes()
    );
}
