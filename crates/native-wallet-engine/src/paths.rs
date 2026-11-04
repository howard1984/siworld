//! Incremental commitment frontier and paths for owned notes only.
use native::{
    codec::encode_digest,
    multi_asset::{Digest, F, Hasher, TREE_DEPTH},
};
use p3_field::PrimeCharacteristicRing;
use std::collections::BTreeMap;
type Path = Vec<(Digest, bool)>;
#[derive(Clone)]
pub struct OwnedPaths {
    count: u64,
    frontier: Vec<Digest>,
    zeros: Vec<Digest>,
    root: Digest,
    owned: BTreeMap<[u8; 48], (u64, Path)>,
}
impl Default for OwnedPaths {
    fn default() -> Self {
        Self::new()
    }
}
impl OwnedPaths {
    pub fn new() -> Self {
        let h = Hasher::new();
        let mut zeros = vec![[F::ZERO; 12]];
        for level in 0..TREE_DEPTH {
            zeros.push(h.compress(&zeros[level], &zeros[level]));
        }
        Self {
            count: 0,
            frontier: vec![[F::ZERO; 12]; TREE_DEPTH],
            root: zeros[TREE_DEPTH],
            zeros,
            owned: BTreeMap::new(),
        }
    }
    /// Start an empty-owned-note view from an independently authenticated local tree cache.
    pub fn from_tree_cache(
        count: u64,
        frontier: &[crate::wire::DigestBytes],
        root: crate::wire::DigestBytes,
    ) -> Result<Self, String> {
        let tree = crate::state::CommitmentTree::from_local_cache(count, frontier, root)?;
        let mut paths = Self::new();
        paths.count = count;
        paths.root = tree.root();
        paths.frontier = frontier
            .iter()
            .map(|v| {
                native::codec::decode_digest(v).map_err(|_| "Invalid cached frontier.".to_owned())
            })
            .collect::<Result<_, _>>()?;
        Ok(paths)
    }
    pub fn count(&self) -> u64 {
        self.count
    }
    pub fn root(&self) -> Digest {
        self.root
    }
    pub fn len(&self) -> usize {
        self.owned.len()
    }
    pub fn is_empty(&self) -> bool {
        self.owned.is_empty()
    }
    pub fn path(&self, commitment: &[u8; 48]) -> Result<Path, String> {
        self.owned
            .get(commitment)
            .map(|(_, p)| p.clone())
            .ok_or("Owned incremental path unavailable.".into())
    }
    pub fn all_paths(&self) -> BTreeMap<[u8; 48], Path> {
        self.owned
            .iter()
            .map(|(cm, (_, p))| (*cm, p.clone()))
            .collect()
    }
    pub fn remove(&mut self, commitment: &[u8; 48]) {
        self.owned.remove(commitment);
    }
    pub fn append(&mut self, leaf: Digest, retain: bool) -> Result<(), String> {
        if self.count >= (1u64 << TREE_DEPTH) || retain && self.owned.len() >= 5000 {
            return Err("Light commitment or owned-path capacity.".into());
        }
        let cm = encode_digest(&leaf);
        if retain && self.owned.contains_key(&cm) {
            return Err("Owned commitment reused.".into());
        }
        let h = Hasher::new();
        let index = self.count;
        let mut at = index;
        let mut node = leaf;
        let mut trace = Vec::with_capacity(TREE_DEPTH);
        let mut path = Vec::with_capacity(TREE_DEPTH);
        for level in 0..TREE_DEPTH {
            trace.push(node);
            let right = at & 1 == 1;
            path.push((
                if right {
                    self.frontier[level]
                } else {
                    self.zeros[level]
                },
                right,
            ));
            if right {
                node = h.compress(&self.frontier[level], &node);
            } else {
                self.frontier[level] = node;
                node = h.compress(&node, &self.zeros[level]);
            }
            at >>= 1;
        }
        for (old, proof) in self.owned.values_mut() {
            let level = (*old ^ index).ilog2() as usize;
            proof[level] = (trace[level], false);
        }
        if retain {
            self.owned.insert(cm, (index, path));
        }
        self.count += 1;
        self.root = node;
        Ok(())
    }
}
