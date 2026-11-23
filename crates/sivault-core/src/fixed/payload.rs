//! Payload units in the provisional fixed-size format.

use super::{Geometry, UNIT_BYTES};
use crate::{Error, Result, crypto};
use zeroize::Zeroizing;

pub const PAYLOAD_BYTES: usize = UNIT_BYTES as usize - 24 - 16;
const LABEL: &[u8] = b"SVFX0001/data";

pub struct FileRevision {
    geometry: Geometry,
    safe_id: [u8; 16],
    slot: u8,
    entry_id: [u8; 16],
    revision_id: [u8; 16],
    total: u64,
    count: u32,
}

impl FileRevision {
    pub fn new(
        geometry: Geometry,
        safe_id: [u8; 16],
        slot: u8,
        entry_id: [u8; 16],
        revision_id: [u8; 16],
        total: u64,
    ) -> Result<Self> {
        if slot > 1 || [safe_id, entry_id, revision_id].contains(&[0; 16]) {
            return Err(Error::InvalidFormat);
        }
        let count = total.div_ceil(PAYLOAD_BYTES as u64);
        if count > geometry.data_range().len() as u64 {
            return Err(Error::Limit);
        }
        Ok(Self {
            geometry,
            safe_id,
            slot,
            entry_id,
            revision_id,
            total,
            count: count as u32,
        })
    }

    fn binding(&self, unit: u32, ordinal: u32) -> Result<(usize, Vec<u8>)> {
        if ordinal >= self.count || !self.geometry.data_range().contains(&unit) {
            return Err(Error::InvalidFormat);
        }
        let used = (self.total - u64::from(ordinal) * PAYLOAD_BYTES as u64)
            .min(PAYLOAD_BYTES as u64) as u32;
        let mut ad = LABEL.to_vec();
        ad.extend(self.safe_id);
        ad.extend(self.geometry.binding());
        ad.push(self.slot);
        ad.extend(unit.to_le_bytes());
        ad.extend(self.entry_id);
        ad.extend(self.revision_id);
        ad.extend(ordinal.to_le_bytes());
        ad.extend(self.count.to_le_bytes());
        ad.extend(self.total.to_le_bytes());
        ad.extend(used.to_le_bytes());
        Ok((used as usize, ad))
    }

    fn key(&self, seed: &[u8; 32]) -> crypto::Secret {
        let mut info = LABEL.to_vec();
        info.push(self.slot);
        info.extend(self.entry_id);
        info.extend(self.revision_id);
        crypto::derive(seed, &self.safe_id, &info)
    }

    pub fn seal(&self, seed: &[u8; 32], unit: u32, ordinal: u32, bytes: &[u8]) -> Result<Vec<u8>> {
        let (used, ad) = self.binding(unit, ordinal)?;
        if bytes.len() != used {
            return Err(Error::InvalidFormat);
        }
        let mut padded = Zeroizing::new(vec![0; PAYLOAD_BYTES]);
        padded[..used].copy_from_slice(bytes);
        let nonce = crypto::random::<24>()?;
        let mut record = nonce.to_vec();
        record.extend(crypto::seal(&self.key(seed), &nonce, &ad, &padded)?);
        Ok(record)
    }

    pub fn open(
        &self,
        seed: &[u8; 32],
        unit: u32,
        ordinal: u32,
        record: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        if record.len() != UNIT_BYTES as usize {
            return Err(Error::InvalidFormat);
        }
        let (used, ad) = self.binding(unit, ordinal)?;
        let nonce = record[..24].try_into().map_err(|_| Error::InvalidFormat)?;
        let mut plain = crypto::unseal(&self.key(seed), nonce, &ad, &record[24..])?;
        if plain[used..].iter().any(|&byte| byte != 0) {
            return Err(Error::InvalidFormat);
        }
        // Truncate only after accepting that the discarded bytes are all zero.
        plain.truncate(used);
        Ok(plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed::FIRST_DATA_UNIT;

    #[test]
    fn final_unit_is_bound_to_location_revision_and_length() {
        let geometry = Geometry::new(1).unwrap();
        let total = PAYLOAD_BYTES as u64 + 1;
        let revision = FileRevision::new(geometry, [1; 16], 0, [2; 16], [3; 16], total).unwrap();
        let unit = FIRST_DATA_UNIT + 1;
        let seed = [4; 32];
        let record = revision.seal(&seed, unit, 1, b"x").unwrap();
        assert_eq!(record.len(), UNIT_BYTES as usize);
        assert_eq!(
            revision.open(&seed, unit, 1, &record).unwrap().as_slice(),
            b"x"
        );
        assert!(revision.open(&seed, unit + 1, 1, &record).is_err());
        assert!(revision.open(&seed, unit, 0, &record).is_err());
        assert!(revision.open(&seed, unit, 1, &record[1..]).is_err());
        let other = FileRevision::new(geometry, [1; 16], 0, [2; 16], [5; 16], total).unwrap();
        assert!(other.open(&seed, unit, 1, &record).is_err());
        let longer = FileRevision::new(geometry, [1; 16], 0, [2; 16], [3; 16], total + 1).unwrap();
        assert!(longer.open(&seed, unit, 1, &record).is_err());
    }

    #[test]
    fn authenticated_nonzero_padding_is_invalid() {
        let revision =
            FileRevision::new(Geometry::new(1).unwrap(), [1; 16], 1, [2; 16], [3; 16], 1).unwrap();
        let seed = [4; 32];
        let nonce = [5; 24];
        let mut record = nonce.to_vec();
        let (_, ad) = revision.binding(FIRST_DATA_UNIT, 0).unwrap();
        record.extend(
            crypto::seal(&revision.key(&seed), &nonce, &ad, &vec![1; PAYLOAD_BYTES]).unwrap(),
        );
        assert!(matches!(
            revision.open(&seed, FIRST_DATA_UNIT, 0, &record),
            Err(Error::InvalidFormat)
        ));
    }
}
