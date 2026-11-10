//! Independently authenticated fixed-width headers for engineering version 2.

use crate::wire::Hash;

pub const HEADER_BYTES: usize = 190;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub network: Hash,
    pub height: u64,
    pub parent: Hash,
    pub timestamp: u64,
    pub target: Hash,
    pub execution_commitment: Hash,
    pub body_commitment: Hash,
    pub nonce: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderError {
    Encoding,
    Network,
    Target,
    Body,
    BodyLimit,
}

impl Header {
    pub fn encode(&self) -> Result<[u8; HEADER_BYTES], HeaderError> {
        if self.target == [0; 32] {
            return Err(HeaderError::Target);
        }
        let mut bytes = [0; HEADER_BYTES];
        bytes[..4].copy_from_slice(b"SWE2");
        bytes[4..6].copy_from_slice(&2u16.to_le_bytes());
        bytes[6..38].copy_from_slice(&self.network);
        bytes[38..46].copy_from_slice(&self.height.to_le_bytes());
        bytes[46..78].copy_from_slice(&self.parent);
        bytes[78..86].copy_from_slice(&self.timestamp.to_le_bytes());
        bytes[86..118].copy_from_slice(&self.target);
        bytes[118..150].copy_from_slice(&self.execution_commitment);
        bytes[150..182].copy_from_slice(&self.body_commitment);
        bytes[182..190].copy_from_slice(&self.nonce.to_le_bytes());
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8], network: &Hash) -> Result<Self, HeaderError> {
        if bytes.len() != HEADER_BYTES || &bytes[..6] != b"SWE2\x02\x00" {
            return Err(HeaderError::Encoding);
        }
        if &bytes[6..38] != network {
            return Err(HeaderError::Network);
        }
        let header = Self {
            network: *network,
            height: u64::from_le_bytes(bytes[38..46].try_into().expect("fixed height")),
            parent: bytes[46..78].try_into().expect("fixed parent"),
            timestamp: u64::from_le_bytes(bytes[78..86].try_into().expect("fixed timestamp")),
            target: bytes[86..118].try_into().expect("fixed target"),
            execution_commitment: bytes[118..150]
                .try_into()
                .expect("fixed execution commitment"),
            body_commitment: bytes[150..182].try_into().expect("fixed body commitment"),
            nonce: u64::from_le_bytes(bytes[182..190].try_into().expect("fixed nonce")),
        };
        header.encode()?;
        Ok(header)
    }
    pub fn pow_seed(&self) -> Result<Hash, HeaderError> {
        Ok(blake3::derive_key(
            "siworld eng2 header pow seed v1",
            &self.encode()?[..182],
        ))
    }
    pub fn id(&self) -> Result<Hash, HeaderError> {
        let mut preimage = [0; 40];
        preimage[..32].copy_from_slice(&self.pow_seed()?);
        preimage[32..].copy_from_slice(&self.nonce.to_le_bytes());
        Ok(blake3::derive_key(
            "siworld eng2 block identity v1",
            &preimage,
        ))
    }
    pub fn verify_body(&self, body: &[u8], limit: usize) -> Result<(), HeaderError> {
        if body_commitment(body, limit)? != self.body_commitment {
            return Err(HeaderError::Body);
        }
        Ok(())
    }
}

pub fn body_commitment(body: &[u8], limit: usize) -> Result<Hash, HeaderError> {
    if body.len() > limit {
        return Err(HeaderError::BodyLimit);
    }
    let mut hash = blake3::Hasher::new_derive_key("siworld eng2 canonical block body v1");
    hash.update(&(body.len() as u64).to_le_bytes());
    hash.update(body);
    Ok(*hash.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> Header {
        Header {
            network: [1; 32],
            height: 7,
            parent: [2; 32],
            timestamp: 2101,
            target: [0xff; 32],
            execution_commitment: [3; 32],
            body_commitment: body_commitment(b"canonical synthetic body", 1024).unwrap(),
            nonce: 11,
        }
    }

    #[test]
    fn exact_canonical_header_roundtrip_and_integer_layout() {
        let header = header();
        let bytes = header.encode().unwrap();
        assert_eq!(bytes.len(), HEADER_BYTES);
        assert_eq!(&bytes[..6], b"SWE2\x02\x00");
        assert_eq!(&bytes[38..46], &7u64.to_le_bytes());
        assert_eq!(&bytes[182..190], &11u64.to_le_bytes());
        assert_eq!(Header::decode(&bytes, &header.network), Ok(header));
    }

    #[test]
    fn rejects_noncanonical_header_before_accepting_claimed_fields() {
        let header = header();
        let bytes = header.encode().unwrap();
        assert_eq!(
            Header::decode(&bytes[..189], &header.network),
            Err(HeaderError::Encoding)
        );
        let mut extended = bytes.to_vec();
        extended.push(0);
        assert_eq!(
            Header::decode(&extended, &header.network),
            Err(HeaderError::Encoding)
        );
        let mut wrong = bytes;
        wrong[4] = 3;
        assert_eq!(
            Header::decode(&wrong, &header.network),
            Err(HeaderError::Encoding)
        );
        assert_eq!(Header::decode(&bytes, &[9; 32]), Err(HeaderError::Network));
        let mut zero = header;
        zero.target = [0; 32];
        assert_eq!(zero.encode(), Err(HeaderError::Target));
    }

    #[test]
    fn every_claimed_metadata_field_is_inside_the_work_seed() {
        let original = header();
        let seed = original.pow_seed().unwrap();
        let mut variants = Vec::new();
        let mut h = original.clone();
        h.network[0] ^= 1;
        variants.push(h);
        let mut h = original.clone();
        h.height += 1;
        variants.push(h);
        let mut h = original.clone();
        h.parent[0] ^= 1;
        variants.push(h);
        let mut h = original.clone();
        h.timestamp += 1;
        variants.push(h);
        let mut h = original.clone();
        h.target[0] ^= 1;
        variants.push(h);
        let mut h = original.clone();
        h.execution_commitment[0] ^= 1;
        variants.push(h);
        let mut h = original.clone();
        h.body_commitment[0] ^= 1;
        variants.push(h);
        for variant in variants {
            assert_ne!(variant.pow_seed().unwrap(), seed);
            assert_ne!(variant.id().unwrap(), original.id().unwrap());
        }
        let mut nonce = original.clone();
        nonce.nonce += 1;
        assert_eq!(nonce.pow_seed(), original.pow_seed());
        assert_ne!(nonce.id(), original.id());
    }

    #[test]
    fn independent_full_header_and_detached_header_calculations_agree() {
        let header = header();
        let bytes = header.encode().unwrap();
        let seed = blake3::derive_key("siworld eng2 header pow seed v1", &bytes[..182]);
        assert_eq!(header.pow_seed().unwrap(), seed);
        let mut preimage = [0u8; 40];
        preimage[..32].copy_from_slice(&seed);
        preimage[32..].copy_from_slice(&header.nonce.to_le_bytes());
        assert_eq!(
            header.id().unwrap(),
            blake3::derive_key("siworld eng2 block identity v1", &preimage)
        );
        assert_eq!(
            Header::decode(&bytes, &header.network).unwrap().id(),
            header.id()
        );
    }

    #[test]
    fn full_body_binding_rejects_substitution_and_oversized_input() {
        let header = header();
        assert_eq!(
            header.verify_body(b"canonical synthetic body", 1024),
            Ok(())
        );
        assert_eq!(
            header.verify_body(b"different body", 1024),
            Err(HeaderError::Body)
        );
        assert_eq!(
            header.verify_body(b"canonical synthetic body", 3),
            Err(HeaderError::BodyLimit)
        );
        assert_ne!(body_commitment(b"a", 1024), body_commitment(b"a\0", 1024));
    }
}
