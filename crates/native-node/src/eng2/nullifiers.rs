//! Persistent sparse-Merkle nullifier state with exact 384-bit canonical keys.
use crate::wire::{DigestBytes, Hash};
use std::sync::{Arc, OnceLock};

pub const KEY_BITS: u16 = 384;
pub const EXECUTION_BYTES: usize = 42;

/// Cached hashes can only be created by actual canonical insertion or rebuild.
#[derive(Clone)]
pub struct NullifierSet {
    root: Hash,
    count: u64,
    node: Option<Arc<Node>>,
}
impl Default for NullifierSet {
    fn default() -> Self {
        Self::new()
    }
}
impl NullifierSet {
    pub fn new() -> Self {
        Self {
            root: empty()[0],
            count: 0,
            node: None,
        }
    }
    pub fn root(&self) -> Hash {
        self.root
    }
    pub fn len(&self) -> u64 {
        self.count
    }
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
    pub fn contains(&self, key: &DigestBytes) -> bool {
        let Some(mut node) = self.node.as_deref() else {
            return false;
        };
        loop {
            match &node.kind {
                Kind::Leaf => return node.key == *key,
                Kind::Branch { left, right, .. } => {
                    if common_prefix(&node.key, key) < node.depth {
                        return false;
                    }
                    node = if bit(key, node.depth) { right } else { left };
                }
            }
        }
    }
    pub fn insert(&mut self, key: DigestBytes) -> Result<(), String> {
        let _ = native::codec::decode_digest(&key).map_err(|_| "noncanonical nullifier field")?;
        let count = self
            .count
            .checked_add(1)
            .ok_or("nullifier count overflow")?;
        let node = match &self.node {
            Some(parent) => insert(parent, key)?,
            None => Node::leaf(key),
        };
        let root = lift(node.hash, &node.key, node.depth, 0);
        // Every error has occurred before changing the accepted root or node.
        self.node = Some(node);
        self.root = root;
        self.count = count;
        Ok(())
    }
    pub fn rebuild<'a>(values: impl IntoIterator<Item = &'a DigestBytes>) -> Result<Self, String> {
        let mut state = Self::new();
        for value in values {
            state.insert(*value)?;
        }
        Ok(state)
    }
    pub fn insert_many(&mut self, values: &[DigestBytes]) -> Result<(), String> {
        let mut staged = self.clone();
        for value in values {
            staged.insert(*value)?;
        }
        *self = staged;
        Ok(())
    }
    pub fn execution_encoding(&self) -> [u8; EXECUTION_BYTES] {
        let mut bytes = [0; EXECUTION_BYTES];
        bytes[..2].copy_from_slice(&2u16.to_le_bytes());
        bytes[2..10].copy_from_slice(&self.count.to_le_bytes());
        bytes[10..].copy_from_slice(&self.root);
        bytes
    }
}

enum Kind {
    Leaf,
    Branch {
        left: Arc<Node>,
        right: Arc<Node>,
        left_hash: Hash,
        right_hash: Hash,
    },
}
struct Node {
    depth: u16,
    key: DigestBytes,
    hash: Hash,
    kind: Kind,
}
impl Node {
    fn leaf(key: DigestBytes) -> Arc<Self> {
        Arc::new(Self {
            depth: KEY_BITS,
            key,
            hash: blake3::derive_key("siworld eng2 nullifier occupied leaf v2", &key),
            kind: Kind::Leaf,
        })
    }
    fn branch(depth: u16, left: Arc<Node>, right: Arc<Node>) -> Arc<Self> {
        debug_assert!(depth < left.depth && depth < right.depth);
        debug_assert!(!bit(&left.key, depth) && bit(&right.key, depth));
        let left_hash = lift(left.hash, &left.key, left.depth, depth + 1);
        let right_hash = lift(right.hash, &right.key, right.depth, depth + 1);
        Self::with_children(depth, left, right, left_hash, right_hash)
    }
    fn with_children(
        depth: u16,
        left: Arc<Node>,
        right: Arc<Node>,
        left_hash: Hash,
        right_hash: Hash,
    ) -> Arc<Self> {
        let hash = branch_hash(depth, left_hash, right_hash);
        Arc::new(Self {
            depth,
            key: left.key,
            hash,
            kind: Kind::Branch {
                left,
                right,
                left_hash,
                right_hash,
            },
        })
    }
}
fn insert(node: &Arc<Node>, key: DigestBytes) -> Result<Arc<Node>, String> {
    let common = common_prefix(&node.key, &key);
    if common == KEY_BITS {
        return Err("nullifier already present".into());
    }
    if common < node.depth {
        let leaf = Node::leaf(key);
        return Ok(if bit(&key, common) {
            Node::branch(common, Arc::clone(node), leaf)
        } else {
            Node::branch(common, leaf, Arc::clone(node))
        });
    }
    match &node.kind {
        Kind::Leaf => Err("invalid nullifier trie path".into()),
        Kind::Branch {
            left,
            right,
            left_hash,
            right_hash,
        } => Ok(if bit(&key, node.depth) {
            let changed = insert(right, key)?;
            let changed_hash = lift(changed.hash, &changed.key, changed.depth, node.depth + 1);
            Node::with_children(
                node.depth,
                Arc::clone(left),
                changed,
                *left_hash,
                changed_hash,
            )
        } else {
            let changed = insert(left, key)?;
            let changed_hash = lift(changed.hash, &changed.key, changed.depth, node.depth + 1);
            Node::with_children(
                node.depth,
                changed,
                Arc::clone(right),
                changed_hash,
                *right_hash,
            )
        }),
    }
}
fn bit(key: &DigestBytes, depth: u16) -> bool {
    key[usize::from(depth / 8)] & (1 << (7 - depth % 8)) != 0
}
fn common_prefix(left: &DigestBytes, right: &DigestBytes) -> u16 {
    for (index, (&left, &right)) in left.iter().zip(right).enumerate() {
        let different = left ^ right;
        if different != 0 {
            return index as u16 * 8 + different.leading_zeros() as u16;
        }
    }
    KEY_BITS
}
fn branch_hash(depth: u16, left: Hash, right: Hash) -> Hash {
    #[cfg(test)]
    HASH_CALLS.with(|count| count.set(count.get() + 1));
    let mut bytes = [0u8; 66];
    bytes[..2].copy_from_slice(&depth.to_le_bytes());
    bytes[2..34].copy_from_slice(&left);
    bytes[34..].copy_from_slice(&right);
    blake3::derive_key("siworld eng2 nullifier branch v2", &bytes)
}
#[cfg(test)]
thread_local! { static HASH_CALLS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) }; }
#[cfg(test)]
pub(crate) fn reset_test_hash_calls() {
    HASH_CALLS.with(|count| count.set(0));
}
#[cfg(test)]
pub(crate) fn test_hash_calls() -> u64 {
    HASH_CALLS.with(std::cell::Cell::get)
}
fn empty() -> &'static [Hash; 385] {
    static EMPTY: OnceLock<[Hash; 385]> = OnceLock::new();
    EMPTY.get_or_init(|| {
        let mut hashes = [[0u8; 32]; 385];
        hashes[384] = blake3::derive_key("siworld eng2 nullifier empty leaf v2", &[]);
        for depth in (0..384).rev() {
            hashes[depth] = branch_hash(depth as u16, hashes[depth + 1], hashes[depth + 1]);
        }
        hashes
    })
}
fn lift(mut hash: Hash, key: &DigestBytes, from: u16, to: u16) -> Hash {
    for depth in (to..from).rev() {
        hash = if bit(key, depth) {
            branch_hash(depth, empty()[usize::from(depth + 1)], hash)
        } else {
            branch_hash(depth, hash, empty()[usize::from(depth + 1)])
        };
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use native::{codec::encode_digest, multi_asset::F};
    use p3_field::{PrimeCharacteristicRing, PrimeField32};

    fn key(first: u32, last: u32) -> DigestBytes {
        let mut fields = [F::ZERO; 12];
        fields[0] = F::from_u32(first);
        fields[11] = F::from_u32(last);
        encode_digest(&fields)
    }
    fn reference(values: &[DigestBytes]) -> Hash {
        fn branch(depth: u16, left: Hash, right: Hash) -> Hash {
            let mut bytes = depth.to_le_bytes().to_vec();
            bytes.extend_from_slice(&left);
            bytes.extend_from_slice(&right);
            blake3::derive_key("siworld eng2 nullifier branch v2", &bytes)
        }
        let mut empty = [[0u8; 32]; 385];
        empty[384] = blake3::derive_key("siworld eng2 nullifier empty leaf v2", &[]);
        for depth in (0..384).rev() {
            empty[depth] = branch(depth as u16, empty[depth + 1], empty[depth + 1]);
        }
        fn subtree(values: &[DigestBytes], depth: usize, empty: &[Hash; 385]) -> Hash {
            if values.is_empty() {
                return empty[depth];
            }
            if depth == 384 {
                assert_eq!(values.len(), 1);
                return blake3::derive_key("siworld eng2 nullifier occupied leaf v2", &values[0]);
            }
            let mut left = Vec::new();
            let mut right = Vec::new();
            for value in values {
                if (value[depth / 8] >> (7 - depth % 8)) & 1 == 0 {
                    left.push(*value);
                } else {
                    right.push(*value);
                }
            }
            branch(
                depth as u16,
                subtree(&left, depth + 1, empty),
                subtree(&right, depth + 1, empty),
            )
        }
        subtree(values, 0, &empty)
    }
    #[test]
    fn empty_root_and_all_insert_orders_match_full_sparse_reference() {
        let keys = [key(0, 0), key(1, 0), key(0, 1), key(0, 256), key(0, 65536)];
        let mut set = NullifierSet::new();
        assert_eq!(set.root(), reference(&[]));
        assert!(set.is_empty());
        for (index, value) in keys.iter().enumerate() {
            set.insert(*value).unwrap();
            assert!(set.contains(value));
            assert_eq!(set.len(), index as u64 + 1);
            assert_eq!(set.root(), reference(&keys[..=index]));
        }
        let rebuilt = NullifierSet::rebuild(keys.iter().rev()).unwrap();
        assert_eq!(set.execution_encoding(), rebuilt.execution_encoding());
        assert_eq!(set.execution_encoding()[..2], 2u16.to_le_bytes());
        assert_eq!(set.execution_encoding()[2..10], 5u64.to_le_bytes());
        fn permutations(values: &mut [DigestBytes], at: usize, expected: Hash) {
            if at == values.len() {
                assert_eq!(
                    NullifierSet::rebuild(values.iter()).unwrap().root(),
                    expected
                );
                return;
            }
            for index in at..values.len() {
                values.swap(at, index);
                permutations(values, at + 1, expected);
                values.swap(at, index);
            }
        }
        permutations(&mut keys.clone(), 0, set.root());
    }
    #[test]
    fn shared_prefix_final_bit_divergence_and_persistent_forks_preserve_exact_keys() {
        // The only differing bit is the final bit of the full encoded key.
        let a = key(0, 0);
        let b = key(0, 1 << 24);
        let c = key(1, 0);
        assert_eq!(&a[..47], &b[..47]);
        assert_eq!(a[47] ^ b[47], 1);
        let mut parent = NullifierSet::new();
        parent.insert(a).unwrap();
        let parent_root = parent.root();
        let mut left = parent.clone();
        let mut right = parent.clone();
        left.insert(b).unwrap();
        right.insert(c).unwrap();
        assert_eq!(parent.root(), parent_root);
        assert_eq!(parent.len(), 1);
        assert!(!parent.contains(&b));
        assert!(!parent.contains(&c));
        assert_eq!(left.root(), reference(&[a, b]));
        assert_eq!(right.root(), reference(&[a, c]));
        assert_ne!(left.root(), right.root());
        assert!(!left.contains(&c));
    }
    #[test]
    fn duplicate_or_noncanonical_value_cannot_change_the_root_or_membership() {
        let value = key(2, 3);
        let mut set = NullifierSet::new();
        set.insert(value).unwrap();
        let before = set.execution_encoding();
        assert!(set.insert(value).is_err());
        assert_eq!(set.execution_encoding(), before);
        let mut invalid = value;
        invalid[..4].copy_from_slice(&F::ORDER_U32.to_le_bytes());
        assert!(set.insert(invalid).is_err());
        assert_eq!(set.execution_encoding(), before);
        assert!(set.contains(&value));
        assert!(!set.contains(&invalid));
        assert!(NullifierSet::rebuild([&value, &value]).is_err());
        assert!(set.insert_many(&[key(5, 6), value]).is_err());
        assert_eq!(set.execution_encoding(), before);
        assert!(!set.contains(&key(5, 6)));
    }
    #[test]
    fn insertion_hash_work_has_a_fixed_path_bound_and_the_trie_has_linear_live_nodes() {
        fn nodes(node: &Node) -> usize {
            match &node.kind {
                Kind::Leaf => 1,
                Kind::Branch { left, right, .. } => 1 + nodes(left) + nodes(right),
            }
        }
        let mut set = NullifierSet::new();
        for index in 0..256u32 {
            HASH_CALLS.with(|count| count.set(0));
            set.insert(key(index, index.reverse_bits() % F::ORDER_U32))
                .unwrap();
            let hashes = HASH_CALLS.with(std::cell::Cell::get);
            assert!(
                hashes <= 3 * u64::from(KEY_BITS),
                "insertion {index}: {hashes} hashes"
            );
            assert_eq!(
                nodes(set.node.as_ref().unwrap()),
                2 * set.len() as usize - 1
            );
        }
        let values: Vec<_> = (0..256u32)
            .map(|index| key(index, index.reverse_bits() % F::ORDER_U32))
            .collect();
        assert_eq!(set.root(), reference(&values));
    }
}
