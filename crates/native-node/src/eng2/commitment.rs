//! Fixed component framing and acyclic recent-root commitment encoding.
//!
//! Component bytes must come from canonical local state encoders. This framing
//! does not authenticate a peer's assertion about omitted state.

use crate::state::{CanonicalSnapshot, SNAPSHOT_WINDOW};
use crate::wire::Hash;
use std::collections::VecDeque;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ComponentId {
    ChainContext = 1,
    CommitmentTree = 2,
    Nullifiers = 3,
    RecentRoots = 4,
    HolderPool = 5,
    DevelopmentFund = 6,
    FeeDestination = 7,
    Governance = 8,
    IssuanceAndBurn = 9,
    LockedRewards = 10,
    AssetRegistry = 11,
}
pub const COMPONENTS: [ComponentId; 11] = [
    ComponentId::ChainContext,
    ComponentId::CommitmentTree,
    ComponentId::Nullifiers,
    ComponentId::RecentRoots,
    ComponentId::HolderPool,
    ComponentId::DevelopmentFund,
    ComponentId::FeeDestination,
    ComponentId::Governance,
    ComponentId::IssuanceAndBurn,
    ComponentId::LockedRewards,
    ComponentId::AssetRegistry,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitmentError {
    Components,
    ByteLimit,
    SnapshotWindow,
    SnapshotIdentity,
    Digest,
    Descriptor,
}

pub const DESCRIPTOR_BYTES: usize = 42;

/// A hash-binding witness, not reconstructed component state. Peer descriptors
/// may establish inclusion at a header but cannot authenticate snapshot import.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor {
    id: ComponentId,
    bytes: u64,
    digest: Hash,
}
impl Descriptor {
    pub fn encode(self) -> [u8; DESCRIPTOR_BYTES] {
        let mut bytes = [0; DESCRIPTOR_BYTES];
        bytes[..2].copy_from_slice(&(self.id as u16).to_le_bytes());
        bytes[2..10].copy_from_slice(&self.bytes.to_le_bytes());
        bytes[10..].copy_from_slice(&self.digest);
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, CommitmentError> {
        if bytes.len() != DESCRIPTOR_BYTES {
            return Err(CommitmentError::Descriptor);
        }
        let raw = u16::from_le_bytes(bytes[..2].try_into().expect("fixed component identifier"));
        let id = COMPONENTS
            .iter()
            .copied()
            .find(|id| *id as u16 == raw)
            .ok_or(CommitmentError::Descriptor)?;
        Ok(Self {
            id,
            bytes: u64::from_le_bytes(bytes[2..10].try_into().expect("fixed component length")),
            digest: bytes[10..].try_into().expect("fixed component digest"),
        })
    }
    pub fn id(self) -> ComponentId {
        self.id
    }
    pub fn encoded_len(self) -> u64 {
        self.bytes
    }
    pub fn digest(self) -> Hash {
        self.digest
    }
}

#[derive(Clone, Debug)]
pub struct Component {
    id: ComponentId,
    bytes: u64,
    digest: Hash,
}
impl Component {
    pub fn descriptor(&self) -> Descriptor {
        Descriptor {
            id: self.id,
            bytes: self.bytes,
            digest: self.digest,
        }
    }
    pub fn from_local_encoding(
        id: ComponentId,
        bytes: &[u8],
        limit: usize,
    ) -> Result<Self, CommitmentError> {
        if bytes.len() > limit {
            return Err(CommitmentError::ByteLimit);
        }
        let length = u64::try_from(bytes.len()).map_err(|_| CommitmentError::ByteLimit)?;
        let mut hash = blake3::Hasher::new_derive_key("siworld eng2 execution component v1");
        hash.update(&(id as u16).to_le_bytes());
        hash.update(&length.to_le_bytes());
        hash.update(bytes);
        Ok(Self {
            id,
            bytes: length,
            digest: *hash.finalize().as_bytes(),
        })
    }
}

/// Reconstruct an aggregate for a bounded inclusion witness. This checks hash
/// framing only; import must still rebuild all eleven actual state components.
pub fn aggregate_descriptors(
    network: Hash,
    height: u64,
    parent: Hash,
    descriptors: &[Descriptor],
) -> Result<Hash, CommitmentError> {
    aggregate_records(network, height, parent, descriptors.iter().copied())
}

pub fn aggregate(
    network: Hash,
    height: u64,
    parent: Hash,
    components: &[Component],
) -> Result<Hash, CommitmentError> {
    aggregate_records(
        network,
        height,
        parent,
        components.iter().map(Component::descriptor),
    )
}

fn aggregate_records(
    network: Hash,
    height: u64,
    parent: Hash,
    components: impl ExactSizeIterator<Item = Descriptor>,
) -> Result<Hash, CommitmentError> {
    if components.len() != COMPONENTS.len() {
        return Err(CommitmentError::Components);
    }
    let mut hash = blake3::Hasher::new_derive_key("siworld eng2 execution state v1");
    hash.update(&1u16.to_le_bytes());
    hash.update(&network);
    hash.update(&height.to_le_bytes());
    hash.update(&parent);
    hash.update(&(COMPONENTS.len() as u16).to_le_bytes());
    for (component, id) in components.zip(COMPONENTS) {
        if component.id != id {
            return Err(CommitmentError::Components);
        }
        hash.update(&(component.id as u16).to_le_bytes());
        hash.update(&component.bytes.to_le_bytes());
        hash.update(&component.digest);
    }
    Ok(*hash.finalize().as_bytes())
}

#[derive(Clone, Copy)]
pub enum SnapshotTip {
    Staged,
    Materialized(Hash),
}

pub fn snapshot_encoding(
    height: u64,
    tip: SnapshotTip,
    snapshots: &VecDeque<CanonicalSnapshot>,
) -> Result<Vec<u8>, CommitmentError> {
    let first = height.saturating_sub(SNAPSHOT_WINDOW as u64 - 1);
    let count = height - first + 1;
    if snapshots.len() as u64 != count {
        return Err(CommitmentError::SnapshotWindow);
    }
    let mut out = Vec::with_capacity(8 + snapshots.len() * (8 + 1 + 32 + 48 + 48));
    out.extend_from_slice(&count.to_le_bytes());
    for (index, snapshot) in snapshots.iter().enumerate() {
        let current = first + index as u64;
        if snapshot.selector.height != current {
            return Err(CommitmentError::SnapshotWindow);
        }
        let _ = native::codec::decode_digest(&snapshot.commitment_root)
            .map_err(|_| CommitmentError::Digest)?;
        let _ = native::codec::decode_digest(&snapshot.recent_root)
            .map_err(|_| CommitmentError::Digest)?;
        out.extend_from_slice(&current.to_le_bytes());
        if current == height && height != 0 {
            match tip {
                SnapshotTip::Staged if snapshot.selector.block_id != [0; 32] => {
                    return Err(CommitmentError::SnapshotIdentity);
                }
                SnapshotTip::Materialized(id) if snapshot.selector.block_id != id => {
                    return Err(CommitmentError::SnapshotIdentity);
                }
                _ => (),
            }
            out.push(1); // SelfAtHeight: no reference to the still-unmined header ID.
        } else {
            if current == 0 && height == 0 {
                match tip {
                    SnapshotTip::Materialized(id) if snapshot.selector.block_id == id => (),
                    _ => return Err(CommitmentError::SnapshotIdentity),
                }
            }
            out.push(0);
            out.extend_from_slice(&snapshot.selector.block_id);
        }
        out.extend_from_slice(&snapshot.commitment_root);
        out.extend_from_slice(&snapshot.recent_root);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Snapshot;
    use native::codec::encode_digest;
    use native::multi_asset::F;
    use p3_field::PrimeCharacteristicRing;

    fn components() -> Vec<Component> {
        COMPONENTS
            .into_iter()
            .map(|id| Component::from_local_encoding(id, &[id as u8], 1024).unwrap())
            .collect()
    }

    #[test]
    fn bounded_descriptors_match_local_aggregate_and_reject_unknown_order_or_shape() {
        let components = components();
        let descriptors: Vec<_> = components.iter().map(Component::descriptor).collect();
        let root = aggregate([1; 32], 2, [2; 32], &components).unwrap();
        assert_eq!(
            aggregate_descriptors([1; 32], 2, [2; 32], &descriptors),
            Ok(root)
        );
        for descriptor in &descriptors {
            let bytes = descriptor.encode();
            assert_eq!(&bytes[..2], &(descriptor.id as u16).to_le_bytes());
            assert_eq!(Descriptor::decode(&bytes), Ok(*descriptor));
            assert_eq!(
                Descriptor::decode(&bytes[..41]),
                Err(CommitmentError::Descriptor)
            );
        }
        let mut invalid = descriptors[0].encode();
        invalid[..2].copy_from_slice(&12u16.to_le_bytes());
        assert_eq!(
            Descriptor::decode(&invalid),
            Err(CommitmentError::Descriptor)
        );
        let mut changed = descriptors.clone();
        changed.swap(1, 2);
        assert_eq!(
            aggregate_descriptors([1; 32], 2, [2; 32], &changed),
            Err(CommitmentError::Components)
        );
        changed = descriptors.clone();
        changed[7].bytes += 1;
        assert_ne!(
            aggregate_descriptors([1; 32], 2, [2; 32], &changed),
            Ok(root)
        );
        changed = descriptors;
        changed[7].digest[0] ^= 1;
        assert_ne!(
            aggregate_descriptors([1; 32], 2, [2; 32], &changed),
            Ok(root)
        );
    }
    fn snapshots() -> VecDeque<CanonicalSnapshot> {
        (0..=2)
            .map(|height| CanonicalSnapshot {
                selector: Snapshot {
                    height,
                    block_id: [height as u8 + 1; 32],
                },
                commitment_root: encode_digest(&[F::ZERO; 12]),
                recent_root: encode_digest(&[F::ONE; 12]),
            })
            .collect()
    }

    #[test]
    fn rejects_missing_duplicate_swapped_and_component_substitutions() {
        let c = components();
        let valid = aggregate([1; 32], 2, [2; 32], &c).unwrap();
        assert_eq!(
            aggregate([1; 32], 2, [2; 32], &c[..10]),
            Err(CommitmentError::Components)
        );
        let mut changed = c.clone();
        changed.swap(1, 2);
        assert_eq!(
            aggregate([1; 32], 2, [2; 32], &changed),
            Err(CommitmentError::Components)
        );
        changed = c.clone();
        changed[3] = c[2].clone();
        assert_eq!(
            aggregate([1; 32], 2, [2; 32], &changed),
            Err(CommitmentError::Components)
        );
        for index in 0..11 {
            changed = c.clone();
            changed[index] =
                Component::from_local_encoding(COMPONENTS[index], b"changed", 1024).unwrap();
            assert_ne!(aggregate([1; 32], 2, [2; 32], &changed).unwrap(), valid);
        }
        assert_ne!(aggregate([9; 32], 2, [2; 32], &c).unwrap(), valid);
        assert_ne!(aggregate([1; 32], 3, [2; 32], &c).unwrap(), valid);
        assert_ne!(aggregate([1; 32], 2, [9; 32], &c).unwrap(), valid);
    }

    #[test]
    fn component_and_aggregate_match_independent_recomputation() {
        let c = components();
        let mut expected = blake3::Hasher::new_derive_key("siworld eng2 execution state v1");
        expected.update(&1u16.to_le_bytes());
        expected.update(&[1; 32]);
        expected.update(&2u64.to_le_bytes());
        expected.update(&[2; 32]);
        expected.update(&11u16.to_le_bytes());
        for id in COMPONENTS {
            let mut component =
                blake3::Hasher::new_derive_key("siworld eng2 execution component v1");
            component.update(&(id as u16).to_le_bytes());
            component.update(&1u64.to_le_bytes());
            component.update(&[id as u8]);
            expected.update(&(id as u16).to_le_bytes());
            expected.update(&1u64.to_le_bytes());
            expected.update(component.finalize().as_bytes());
        }
        assert_eq!(
            aggregate([1; 32], 2, [2; 32], &c).unwrap(),
            *expected.finalize().as_bytes()
        );
        assert!(Component::from_local_encoding(ComponentId::Nullifiers, b"oversized", 1).is_err());
    }

    #[test]
    fn materializing_newest_block_id_preserves_acyclic_commitment() {
        let mut s = snapshots();
        s.back_mut().unwrap().selector.block_id = [0; 32];
        let staged = snapshot_encoding(2, SnapshotTip::Staged, &s).unwrap();
        for final_id in [[3; 32], [4; 32]] {
            s.back_mut().unwrap().selector.block_id = final_id;
            assert_eq!(
                snapshot_encoding(2, SnapshotTip::Materialized(final_id), &s).unwrap(),
                staged
            );
        }
        assert!(snapshot_encoding(2, SnapshotTip::Materialized([8; 32]), &s).is_err());
        assert!(snapshot_encoding(2, SnapshotTip::Staged, &s).is_err());
        s[0].selector.block_id[0] ^= 1;
        assert_ne!(
            snapshot_encoding(2, SnapshotTip::Materialized([4; 32]), &s).unwrap(),
            staged
        );
    }

    #[test]
    fn recent_root_window_rejects_gaps_omissions_and_noncanonical_roots() {
        let mut s = snapshots();
        s.pop_front();
        assert!(snapshot_encoding(2, SnapshotTip::Materialized([3; 32]), &s).is_err());
        s = snapshots();
        s[1].selector.height = 0;
        assert!(snapshot_encoding(2, SnapshotTip::Materialized([3; 32]), &s).is_err());
        s = snapshots();
        s[1].recent_root = [0xff; 48];
        assert_eq!(
            snapshot_encoding(2, SnapshotTip::Materialized([3; 32]), &s),
            Err(CommitmentError::Digest)
        );
        s = snapshots();
        s.pop_back();
        s.pop_back();
        assert!(snapshot_encoding(0, SnapshotTip::Materialized([1; 32]), &s).is_ok());
        assert!(snapshot_encoding(0, SnapshotTip::Staged, &s).is_err());
    }
}
