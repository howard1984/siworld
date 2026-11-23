//! Authenticated root and metadata records of the fixed-size candidate.

use super::{Geometry, UNIT_BYTES, payload::PAYLOAD_BYTES};
use crate::{Error, Result, crypto};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, ops::Range};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"SVFX0001";
const ROOT: &[u8] = b"SVFX0001/root";
const META: &[u8] = b"SVFX0001/meta";
const META_SEED: &[u8] = b"SVFX0001/metadata-seed";
const WRAP: &[u8] = b"SVFX0001/wrap";
const ARENA_UNITS: u32 = 1_024;
const MAX_PAGES: u32 = 341;
const PAGE_DATA: usize = PAYLOAD_BYTES - 12;
const END: u32 = u32::MAX;
const MAX_COUNTER: u64 = 1 << 32;
pub const ROOT_BYTES: usize = 4_096;
pub const WRAP_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Root {
    pub sequence: u64,
    pub epoch: u64,
    pub first_page: u32,
    pub page_count: u32,
    pub stream_length: u64,
    pub digest: [u8; 32],
}

#[derive(Clone, Copy)]
pub struct Slot {
    geometry: Geometry,
    safe_id: [u8; 16],
    number: u8,
}

pub struct Wrap {
    pub safe_id: [u8; 16],
    pub epoch: u64,
    pub local_seed: crypto::Secret,
    pub management: Option<ManagementGrant>,
}

pub struct ManagementGrant {
    pub peer_metadata_seed: crypto::Secret,
    pub peer_local_seed: crypto::Secret,
}

impl Wrap {
    fn check(&self, geometry: Geometry, slot: u8) -> Result<()> {
        let local = Slot::new(geometry, self.safe_id, slot)?;
        if !(1..=MAX_COUNTER).contains(&self.epoch) || *self.local_seed == [0; 32] {
            return Err(Error::InvalidFormat);
        }
        if let Some(grant) = &self.management {
            let peer = Slot {
                number: 1 - slot,
                ..local
            };
            if *grant.peer_local_seed == [0; 32]
                || *grant.peer_local_seed == *self.local_seed
                || *grant.peer_metadata_seed != *peer.metadata_seed(&grant.peer_local_seed)
            {
                return Err(Error::InvalidFormat);
            }
        }
        Ok(())
    }

    fn ad(geometry: Geometry, slot: u8, lane: u8) -> Result<Vec<u8>> {
        if slot > 1 || lane > 1 {
            return Err(Error::InvalidFormat);
        }
        let mut ad = WRAP.to_vec();
        ad.extend(geometry.binding());
        ad.extend([slot, lane]);
        Ok(ad)
    }

    pub fn seal(&self, geometry: Geometry, slot: u8, lane: u8, password: &str) -> Result<Vec<u8>> {
        self.check(geometry, slot)?;
        let ad = Self::ad(geometry, slot, lane)?;
        let salt = crypto::random::<16>()?;
        let stretched = crypto::stretch(password, &salt)?;
        let key = crypto::derive(&stretched, &salt, &ad);
        let mut plain = Zeroizing::new([0; 200]);
        plain[..8].copy_from_slice(MAGIC);
        plain[8..10].copy_from_slice(&1_u16.to_le_bytes());
        plain[10] = slot;
        plain[12..16].copy_from_slice(&geometry.binding()[8..]);
        plain[16..32].copy_from_slice(&self.safe_id);
        plain[32..40].copy_from_slice(&self.epoch.to_le_bytes());
        plain[40..72].copy_from_slice(self.local_seed.as_ref());
        if let Some(grant) = &self.management {
            plain[11] = 1;
            plain[72..104].copy_from_slice(grant.peer_metadata_seed.as_ref());
            plain[104..136].copy_from_slice(grant.peer_local_seed.as_ref());
        }
        let mut out = salt.to_vec();
        out.extend(seal(&key, &ad, plain.as_ref())?);
        Ok(out)
    }

    pub fn open(
        geometry: Geometry,
        slot: u8,
        lane: u8,
        password: &str,
        record: &[u8],
    ) -> Result<Self> {
        if record.len() != WRAP_BYTES {
            return Err(Error::InvalidFormat);
        }
        let ad = Self::ad(geometry, slot, lane)?;
        let salt = array(&record[..16]);
        let stretched = crypto::stretch(password, &salt)?;
        let key = crypto::derive(&stretched, &salt, &ad);
        let plain = open(&key, &ad, &record[16..], WRAP_BYTES - 16)?;
        if &plain[..8] != MAGIC
            || plain[8..10] != [1, 0]
            || plain[10] != slot
            || plain[11] > 1
            || plain[12..16] != geometry.binding()[8..]
            || !zeros(&plain[136..])
            || (plain[11] == 0 && !zeros(&plain[72..136]))
        {
            return Err(Error::InvalidFormat);
        }
        let result = Self {
            safe_id: array(&plain[16..32]),
            epoch: u64::from_le_bytes(array(&plain[32..40])),
            local_seed: Zeroizing::new(array(&plain[40..72])),
            management: (plain[11] == 1).then(|| ManagementGrant {
                peer_metadata_seed: Zeroizing::new(array(&plain[72..104])),
                peer_local_seed: Zeroizing::new(array(&plain[104..136])),
            }),
        };
        result.check(geometry, slot)?;
        Ok(result)
    }
}

impl Slot {
    pub fn new(geometry: Geometry, safe_id: [u8; 16], number: u8) -> Result<Self> {
        if number > 1 || safe_id == [0; 16] {
            return Err(Error::InvalidFormat);
        }
        Ok(Self {
            geometry,
            safe_id,
            number,
        })
    }

    pub fn metadata_seed(&self, local_seed: &[u8; 32]) -> crypto::Secret {
        self.key(local_seed, META_SEED)
    }

    fn key(&self, seed: &[u8; 32], label: &[u8]) -> crypto::Secret {
        let mut info = label.to_vec();
        info.push(self.number);
        crypto::derive(seed, &self.safe_id, &info)
    }

    fn ad(&self, label: &[u8]) -> Vec<u8> {
        let mut ad = label.to_vec();
        ad.extend(self.safe_id);
        ad.extend(self.geometry.binding());
        ad.push(self.number);
        ad
    }

    pub fn metadata_range(&self) -> Range<u32> {
        let first = 2 + u32::from(self.number) * ARENA_UNITS;
        first..first + ARENA_UNITS
    }

    fn check_root(&self, root: &Root) -> Result<()> {
        if !(1..=MAX_COUNTER).contains(&root.sequence)
            || !(1..=MAX_COUNTER).contains(&root.epoch)
            || !(1..=MAX_PAGES).contains(&root.page_count)
            || root.stream_length < 8
            || root.stream_length.div_ceil(PAGE_DATA as u64) != u64::from(root.page_count)
            || !self.metadata_range().contains(&root.first_page)
        {
            return Err(Error::InvalidFormat);
        }
        Ok(())
    }

    pub fn seal_root(&self, seed: &[u8; 32], lane: u8, root: &Root) -> Result<Vec<u8>> {
        self.check_root(root)?;
        let ad = self.root_ad(lane)?;
        let mut plain = Zeroizing::new(vec![0; ROOT_BYTES - 40]);
        plain[..8].copy_from_slice(MAGIC);
        plain[8..10].copy_from_slice(&1_u16.to_le_bytes());
        plain[10] = self.number;
        plain[12..16].copy_from_slice(&self.geometry.binding()[8..]);
        plain[16..32].copy_from_slice(&self.safe_id);
        plain[32..40].copy_from_slice(&root.sequence.to_le_bytes());
        plain[40..48].copy_from_slice(&root.epoch.to_le_bytes());
        plain[48..52].copy_from_slice(&root.first_page.to_le_bytes());
        plain[52..56].copy_from_slice(&root.page_count.to_le_bytes());
        plain[56..64].copy_from_slice(&root.stream_length.to_le_bytes());
        plain[64..96].copy_from_slice(&root.digest);
        seal(&self.key(seed, ROOT), &ad, &plain)
    }

    pub fn open_root(&self, seed: &[u8; 32], lane: u8, record: &[u8]) -> Result<Root> {
        let ad = self.root_ad(lane)?;
        let plain = open(&self.key(seed, ROOT), &ad, record, ROOT_BYTES)?;
        if &plain[..8] != MAGIC
            || plain[8..10] != [1, 0]
            || plain[10] != self.number
            || plain[11] != 0
            || plain[12..16] != self.geometry.binding()[8..]
            || plain[16..32] != self.safe_id
            || !zeros(&plain[96..])
        {
            return Err(Error::InvalidFormat);
        }
        let root = Root {
            sequence: u64::from_le_bytes(array(&plain[32..40])),
            epoch: u64::from_le_bytes(array(&plain[40..48])),
            first_page: u32::from_le_bytes(array(&plain[48..52])),
            page_count: u32::from_le_bytes(array(&plain[52..56])),
            stream_length: u64::from_le_bytes(array(&plain[56..64])),
            digest: array(&plain[64..96]),
        };
        self.check_root(&root)?;
        Ok(root)
    }

    fn root_ad(&self, lane: u8) -> Result<Vec<u8>> {
        if lane > 1 {
            return Err(Error::InvalidFormat);
        }
        let mut ad = self.ad(ROOT);
        ad.push(lane);
        Ok(ad)
    }

    fn meta_ad(&self, unit: u32, sequence: u64, ordinal: u32) -> Vec<u8> {
        let mut ad = self.ad(META);
        ad.extend(unit.to_le_bytes());
        ad.extend(sequence.to_le_bytes());
        ad.extend(ordinal.to_le_bytes());
        ad
    }

    pub fn seal_index(
        &self,
        seed: &[u8; 32],
        sequence: u64,
        epoch: u64,
        units: &[u32],
        stream: &[u8],
    ) -> Result<(Root, Vec<Vec<u8>>)> {
        let root = Root {
            sequence,
            epoch,
            first_page: *units.first().ok_or(Error::InvalidFormat)?,
            page_count: u32::try_from(units.len()).map_err(|_| Error::Limit)?,
            stream_length: stream.len() as u64,
            digest: Sha256::digest(stream).into(),
        };
        self.check_root(&root)?;
        let mut seen = BTreeSet::new();
        if units
            .iter()
            .any(|&unit| !self.metadata_range().contains(&unit) || !seen.insert(unit))
        {
            return Err(Error::InvalidFormat);
        }
        let key = self.key(seed, META);
        let mut records = Vec::with_capacity(units.len());
        for (i, (&unit, bytes)) in units.iter().zip(stream.chunks(PAGE_DATA)).enumerate() {
            let mut plain = Zeroizing::new(vec![0; PAYLOAD_BYTES]);
            plain[..4].copy_from_slice(&units.get(i + 1).copied().unwrap_or(END).to_le_bytes());
            plain[4..8].copy_from_slice(&(i as u32).to_le_bytes());
            plain[8..12].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
            plain[12..12 + bytes.len()].copy_from_slice(bytes);
            records.push(seal(&key, &self.meta_ad(unit, sequence, i as u32), &plain)?);
        }
        Ok((root, records))
    }

    pub fn open_index(
        &self,
        seed: &[u8; 32],
        root: &Root,
        mut read: impl FnMut(u32, &mut [u8]) -> Result<()>,
    ) -> Result<(Zeroizing<Vec<u8>>, BTreeSet<u32>)> {
        self.check_root(root)?;
        let key = self.key(seed, META);
        let mut stream = Zeroizing::new(Vec::with_capacity(root.stream_length as usize));
        let mut seen = BTreeSet::new();
        let mut unit = root.first_page;
        let mut record = vec![0; UNIT_BYTES as usize];
        for ordinal in 0..root.page_count {
            if !self.metadata_range().contains(&unit) || !seen.insert(unit) {
                return Err(Error::InvalidFormat);
            }
            read(unit, &mut record)?;
            let ad = self.meta_ad(unit, root.sequence, ordinal);
            let plain = open(&key, &ad, &record, UNIT_BYTES as usize)?;
            let next = u32::from_le_bytes(array(&plain[..4]));
            let expected = (root.stream_length as usize - stream.len()).min(PAGE_DATA);
            if u32::from_le_bytes(array(&plain[4..8])) != ordinal
                || u32::from_le_bytes(array(&plain[8..12])) as usize != expected
                || !zeros(&plain[12 + expected..])
                || (next == END) != (ordinal + 1 == root.page_count)
            {
                return Err(Error::InvalidFormat);
            }
            stream.extend_from_slice(&plain[12..12 + expected]);
            unit = next;
        }
        let digest: [u8; 32] = Sha256::digest(stream.as_slice()).into();
        if digest != root.digest || stream.len() as u64 != root.stream_length {
            return Err(Error::InvalidFormat);
        }
        Ok((stream, seen))
    }
}

fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().expect("validated record size")
}

fn zeros(bytes: &[u8]) -> bool {
    bytes.iter().all(|&byte| byte == 0)
}

fn seal(key: &[u8; 32], ad: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    let nonce = crypto::random::<24>()?;
    let mut record = nonce.to_vec();
    record.extend(crypto::seal(key, &nonce, ad, plain)?);
    Ok(record)
}

fn open(key: &[u8; 32], ad: &[u8], record: &[u8], size: usize) -> Result<Zeroizing<Vec<u8>>> {
    if record.len() != size {
        return Err(Error::InvalidFormat);
    }
    crypto::unseal(key, &array(&record[..24]), ad, &record[24..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticates_roots_and_index_pages_at_their_exact_locations() {
        let slot = Slot::new(Geometry::new(1).unwrap(), [1; 16], 0).unwrap();
        let seed = slot.metadata_seed(&[2; 32]);
        let stream = vec![3; PAGE_DATA + 1];
        let units = [2, 3];
        let (root, pages) = slot.seal_index(&seed, 7, 3, &units, &stream).unwrap();
        let record = slot.seal_root(&seed, 1, &root).unwrap();
        assert_eq!(slot.open_root(&seed, 1, &record).unwrap(), root);
        assert!(slot.open_root(&seed, 0, &record).is_err());
        let (read, seen) = slot
            .open_index(&seed, &root, |unit, bytes| {
                bytes.copy_from_slice(&pages[(unit - 2) as usize]);
                Ok(())
            })
            .unwrap();
        assert_eq!(*read, stream);
        assert_eq!(seen, BTreeSet::from(units));
        assert!(
            slot.open_index(&seed, &root, |unit, bytes| {
                bytes.copy_from_slice(&pages[(3 - unit) as usize]);
                Ok(())
            })
            .is_err()
        );
        let mut damaged = record;
        damaged[ROOT_BYTES / 2..].fill(0);
        assert!(slot.open_root(&seed, 1, &damaged).is_err());
    }

    #[test]
    fn rejects_a_validly_encrypted_page_with_a_self_loop() {
        let slot = Slot::new(Geometry::new(1).unwrap(), [1; 16], 0).unwrap();
        let seed = slot.metadata_seed(&[2; 32]);
        let stream = vec![0; PAGE_DATA + 1];
        let (root, _) = slot.seal_index(&seed, 7, 3, &[2, 3], &stream).unwrap();
        let mut malformed = vec![0; PAYLOAD_BYTES];
        malformed[..4].copy_from_slice(&2_u32.to_le_bytes());
        malformed[8..12].copy_from_slice(&(PAGE_DATA as u32).to_le_bytes());
        let record = seal(&slot.key(&seed, META), &slot.meta_ad(2, 7, 0), &malformed).unwrap();
        assert!(matches!(
            slot.open_index(&seed, &root, |_, out| {
                out.copy_from_slice(&record);
                Ok(())
            }),
            Err(Error::InvalidFormat)
        ));
    }
}
