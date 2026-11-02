use native::codec::encode_digest;
use native::multi_asset::{F, Hasher, TREE_DEPTH};
use p3_field::PrimeCharacteristicRing;
use siworld_native_wallet_engine::{paths::OwnedPaths, state::CommitmentTree};
#[test]
fn retained_private_paths_match_full_native_tree_after_every_append() {
    let mut native = CommitmentTree::new();
    let mut paths = OwnedPaths::new();
    let mut leaves = Vec::new();
    let mut owned = Vec::new();
    for i in 0..130u32 {
        let leaf = Hasher::new().compress(&[F::from_u32(i + 1); 12], &[F::from_u32(i + 2000); 12]);
        let retain = i % 23 == 0;
        native.append(leaf).unwrap();
        paths.append(leaf, retain).unwrap();
        leaves.push(leaf);
        if retain {
            owned.push(i as usize);
        }
        assert_eq!(native.root(), paths.root());
        assert_eq!(paths.count(), native.count);
        for &index in &owned {
            assert_eq!(
                paths.path(&encode_digest(&leaves[index])).unwrap(),
                native.path(&leaves, index).unwrap()
            );
            assert_eq!(
                paths.path(&encode_digest(&leaves[index])).unwrap().len(),
                TREE_DEPTH
            );
        }
    }
    assert_eq!(paths.len(), 6);
    assert!(paths.path(&[255; 48]).is_err());
}
