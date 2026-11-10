//! Immutable public wallet artifact codecs. These do not select a chain.
use super::header::{HEADER_BYTES, Header};
use crate::{eng2::wallet_history::codec::MAX_RECEIPT_BYTES, wire::Hash};
use sha2::{Digest as _, Sha256};

pub const CHUNK_HEADERS: usize = 128;
pub const MAX_HEIGHT: u64 = 100_000;
pub const MAX_CHUNKS: usize = (MAX_HEIGHT as usize).div_ceil(CHUNK_HEADERS);
pub const BINDING_BYTES: usize = 129;
pub const CHUNK_PREFIX: usize = 147;
pub const RECORD_BYTES: usize = HEADER_BYTES + 32 + 4 + 32;
pub const MAX_CHUNK_BYTES: usize = CHUNK_PREFIX + CHUNK_HEADERS * RECORD_BYTES;
pub const MANIFEST_PREFIX: usize = 179;
pub const DESCRIPTOR_BYTES: usize = 46;
pub const MAX_MANIFEST_BYTES: usize = MANIFEST_PREFIX + MAX_CHUNKS * DESCRIPTOR_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding(pub [u8; BINDING_BYTES]);
impl Binding {
    pub fn new(network: Hash, genesis: Hash, rules: Hash, profile: Hash) -> Self {
        let mut bytes = [0; BINDING_BYTES];
        for (part, value) in bytes[..128]
            .as_chunks_mut::<32>()
            .0
            .iter_mut()
            .zip([network, genesis, rules, profile])
        {
            part.copy_from_slice(&value);
        }
        Self(bytes)
    }
    pub fn network(&self) -> Hash {
        self.0[..32].try_into().expect("fixed network")
    }
    pub fn genesis(&self) -> Hash {
        self.0[32..64].try_into().expect("fixed genesis")
    }
}
pub fn digest(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub header: [u8; HEADER_BYTES],
    pub id: Hash,
    pub receipt_bytes: u32,
    pub receipt_digest: Hash,
}
impl Record {
    pub fn from_receipt(
        binding: &Binding,
        raw: [u8; HEADER_BYTES],
        receipt: &[u8],
    ) -> Result<Self, String> {
        let header =
            Header::decode(&raw, &binding.network()).map_err(|_| "wallet chunk header rejected")?;
        if receipt.len() < 8 + BINDING_BYTES + HEADER_BYTES + 17
            || receipt.len() > MAX_RECEIPT_BYTES
            || &receipt[..8] != b"SWE2WLT1"
            || receipt[8..137] != binding.0
            || receipt[137..327] != raw
        {
            return Err("wallet chunk receipt binding rejected".into());
        }
        Ok(Self {
            header: raw,
            id: header
                .id()
                .map_err(|_| "wallet chunk header identity rejected")?,
            receipt_bytes: u32::try_from(receipt.len())
                .map_err(|_| "wallet receipt length overflow")?,
            receipt_digest: digest(receipt),
        })
    }
    pub fn decoded(&self, binding: &Binding) -> Result<Header, String> {
        let header = Header::decode(&self.header, &binding.network())
            .map_err(|_| "wallet chunk header rejected")?;
        if header
            .id()
            .map_err(|_| "wallet chunk header identity rejected")?
            != self.id
            || !(8 + BINDING_BYTES + HEADER_BYTES + 17..=MAX_RECEIPT_BYTES)
                .contains(&(self.receipt_bytes as usize))
        {
            return Err("wallet chunk record identity or receipt bound rejected".into());
        }
        Ok(header)
    }
    pub fn check_receipt(&self, binding: &Binding, bytes: &[u8]) -> Result<(), String> {
        if Self::from_receipt(binding, self.header, bytes)? != *self {
            return Err("wallet receipt differs from complete generation".into());
        }
        Ok(())
    }
    pub fn receipt_name(&self, height: u64) -> String {
        format!("wallet-{height}-{}.bin", crate::local::hex(&self.id))
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chunk {
    pub from: u64,
    pub records: Vec<Record>,
}
impl Chunk {
    fn check(&self, binding: &Binding) -> Result<(), String> {
        if binding.0[128] != 0
            || self.from == 0
            || self.from > MAX_HEIGHT
            || !(self.from - 1).is_multiple_of(CHUNK_HEADERS as u64)
            || !(1..=CHUNK_HEADERS).contains(&self.records.len())
            || self.from + self.records.len() as u64 - 1 > MAX_HEIGHT
        {
            return Err("wallet chunk range rejected".into());
        }
        let mut previous = None;
        for (index, record) in self.records.iter().enumerate() {
            let header = record.decoded(binding)?;
            if header.height != self.from + index as u64
                || previous.is_some_and(|id| header.parent != id)
                || header.height == 1 && header.parent != binding.genesis()
            {
                return Err("wallet chunk continuity rejected".into());
            }
            previous = Some(record.id);
        }
        Ok(())
    }
    pub fn encode(&self, binding: &Binding) -> Result<Vec<u8>, String> {
        self.check(binding)?;
        let mut bytes = Vec::with_capacity(CHUNK_PREFIX + self.records.len() * RECORD_BYTES);
        bytes.extend(b"SWE2WHC1");
        bytes.extend(binding.0);
        bytes.extend(self.from.to_le_bytes());
        bytes.extend((self.records.len() as u16).to_le_bytes());
        for record in &self.records {
            bytes.extend(record.header);
            bytes.extend(record.id);
            bytes.extend(record.receipt_bytes.to_le_bytes());
            bytes.extend(record.receipt_digest);
        }
        Ok(bytes)
    }
    pub fn decode(binding: &Binding, bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < CHUNK_PREFIX
            || bytes.len() > MAX_CHUNK_BYTES
            || &bytes[..8] != b"SWE2WHC1"
            || bytes[8..137] != binding.0
        {
            return Err("wallet chunk encoding or context rejected".into());
        }
        let from = u64::from_le_bytes(bytes[137..145].try_into().expect("fixed start"));
        let count = u16::from_le_bytes(bytes[145..147].try_into().expect("fixed count")) as usize;
        if count == 0 || count > CHUNK_HEADERS || bytes.len() != CHUNK_PREFIX + count * RECORD_BYTES
        {
            return Err("wallet chunk length rejected".into());
        }
        let mut records = Vec::with_capacity(count);
        for row in bytes[CHUNK_PREFIX..].as_chunks::<RECORD_BYTES>().0 {
            records.push(Record {
                header: row[..190].try_into().expect("fixed header"),
                id: row[190..222].try_into().expect("fixed identity"),
                receipt_bytes: u32::from_le_bytes(row[222..226].try_into().expect("fixed length")),
                receipt_digest: row[226..258].try_into().expect("fixed digest"),
            });
        }
        let value = Self { from, records };
        value.check(binding)?;
        Ok(value)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub from: u64,
    pub count: u16,
    pub bytes: u32,
    pub digest: Hash,
}
impl Descriptor {
    pub fn from_chunk(binding: &Binding, chunk: &Chunk) -> Result<(Self, Vec<u8>), String> {
        let bytes = chunk.encode(binding)?;
        Ok((
            Self {
                from: chunk.from,
                count: chunk.records.len() as u16,
                bytes: bytes.len() as u32,
                digest: digest(&bytes),
            },
            bytes,
        ))
    }
    pub fn name(&self) -> String {
        format!("wallet-chunk-{}.bin", crate::local::hex(&self.digest))
    }
    pub fn decode_chunk(&self, binding: &Binding, bytes: &[u8]) -> Result<Chunk, String> {
        if bytes.len() != self.bytes as usize || digest(bytes) != self.digest {
            return Err("wallet chunk digest or length rejected".into());
        }
        let chunk = Chunk::decode(binding, bytes)?;
        if chunk.from != self.from || chunk.records.len() != self.count as usize {
            return Err("wallet chunk differs from generation descriptor".into());
        }
        Ok(chunk)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub height: u64,
    pub tip: Hash,
    pub chunks: Vec<Descriptor>,
}
impl Manifest {
    pub fn check(&self, binding: &Binding) -> Result<(), String> {
        if binding.0[128] != 0
            || self.height > MAX_HEIGHT
            || self.chunks.len() != (self.height as usize).div_ceil(CHUNK_HEADERS)
            || self.height == 0 && self.tip != binding.genesis()
        {
            return Err("wallet generation head or coverage rejected".into());
        }
        let mut next = 1;
        for (index, row) in self.chunks.iter().enumerate() {
            let count = usize::from(row.count);
            if row.from != next
                || !(1..=CHUNK_HEADERS).contains(&count)
                || index + 1 != self.chunks.len() && count != CHUNK_HEADERS
                || row.bytes as usize != CHUNK_PREFIX + count * RECORD_BYTES
            {
                return Err("wallet generation descriptor coverage rejected".into());
            }
            next += count as u64;
        }
        if next != self.height + 1 {
            return Err("wallet generation incomplete receipt coverage".into());
        }
        Ok(())
    }
    pub fn name(&self) -> String {
        format!(
            "wallet-generation-{}-{}.bin",
            self.height,
            crate::local::hex(&self.tip)
        )
    }
    pub fn encode(&self, binding: &Binding) -> Result<Vec<u8>, String> {
        self.check(binding)?;
        let mut bytes = Vec::with_capacity(MANIFEST_PREFIX + self.chunks.len() * DESCRIPTOR_BYTES);
        bytes.extend(b"SWE2WGM1");
        bytes.extend(binding.0);
        bytes.extend(self.height.to_le_bytes());
        bytes.extend(self.tip);
        bytes.extend((self.chunks.len() as u16).to_le_bytes());
        for row in &self.chunks {
            bytes.extend(row.from.to_le_bytes());
            bytes.extend(row.count.to_le_bytes());
            bytes.extend(row.bytes.to_le_bytes());
            bytes.extend(row.digest);
        }
        Ok(bytes)
    }
    pub fn decode(binding: &Binding, bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < MANIFEST_PREFIX
            || bytes.len() > MAX_MANIFEST_BYTES
            || &bytes[..8] != b"SWE2WGM1"
            || bytes[8..137] != binding.0
        {
            return Err("wallet generation encoding or context rejected".into());
        }
        let height = u64::from_le_bytes(bytes[137..145].try_into().expect("fixed height"));
        let tip = bytes[145..177].try_into().expect("fixed tip");
        let count = u16::from_le_bytes(bytes[177..179].try_into().expect("fixed count")) as usize;
        if count > MAX_CHUNKS || bytes.len() != MANIFEST_PREFIX + count * DESCRIPTOR_BYTES {
            return Err("wallet generation length rejected".into());
        }
        let chunks = bytes[MANIFEST_PREFIX..]
            .as_chunks::<DESCRIPTOR_BYTES>()
            .0
            .iter()
            .map(|row| Descriptor {
                from: u64::from_le_bytes(row[..8].try_into().expect("fixed start")),
                count: u16::from_le_bytes(row[8..10].try_into().expect("fixed count")),
                bytes: u32::from_le_bytes(row[10..14].try_into().expect("fixed length")),
                digest: row[14..46].try_into().expect("fixed digest"),
            })
            .collect();
        let value = Self {
            height,
            tip,
            chunks,
        };
        value.check(binding)?;
        Ok(value)
    }
}
#[cfg(test)]
mod tests;
