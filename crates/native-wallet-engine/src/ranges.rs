//! Selective disclosure of the existing BLAKE3 PoW preimage; no new chain root.
use blake3::hazmat::{
    HasherExt, Mode, hash_derive_key_context, left_subtree_len, merge_subtrees_non_root,
    merge_subtrees_root,
};
use std::collections::BTreeMap;
pub const DOMAIN: &str = "siworld native engineering pow seed v2";
const MAX_PREIMAGE: usize = crate::wire::MAX_BLOCK_BYTES - 8;
pub const MAX_COMPACT: usize = 8 * 1024 * 1024;

pub struct RangeProof;
pub struct Sparse {
    pub length: usize,
    chunks: BTreeMap<usize, Vec<u8>>,
}
impl Sparse {
    pub fn require_exact_ranges(&self, ranges: &[(usize, usize)]) -> Result<(), String> {
        let mut expected = std::collections::BTreeSet::new();
        for &(at, len) in ranges {
            if len > 0 {
                let end = at.checked_add(len - 1).ok_or("Compact range overflow.")?;
                for chunk in at / 1024..=end / 1024 {
                    expected.insert(chunk);
                }
            }
        }
        if !self.chunks.keys().copied().eq(expected) {
            return Err("Noncanonical compact disclosure includes extra historical data.".into());
        }
        Ok(())
    }

    pub fn read(&self, offset: usize, length: usize) -> Result<Vec<u8>, String> {
        let end = offset
            .checked_add(length)
            .ok_or("Compact range overflow.")?;
        if end > self.length || length > MAX_COMPACT {
            return Err("Compact range exceeds limit.".into());
        }
        let mut result = Vec::with_capacity(length);
        let mut at = offset;
        while at < end {
            let chunk = self
                .chunks
                .get(&(at / 1024))
                .ok_or("Required compact data was concealed.")?;
            let from = at % 1024;
            let take = (end - at).min(chunk.len() - from);
            result.extend_from_slice(&chunk[from..from + take]);
            at += take;
        }
        Ok(result)
    }
}
fn hash_nonroot(data: &[u8], offset: usize) -> [u8; 32] {
    blake3::Hasher::new_derive_key(DOMAIN)
        .set_input_offset(offset as u64)
        .update(data)
        .finalize_non_root()
}
impl RangeProof {
    pub fn create(data: &[u8], ranges: &[(usize, usize)]) -> Result<Vec<u8>, String> {
        if data.is_empty()
            || data.len() > MAX_PREIMAGE
            || ranges
                .iter()
                .any(|(a, n)| a.checked_add(*n).is_none_or(|e| e > data.len()))
        {
            return Err("Invalid compact disclosure range.".into());
        }
        let mut out = b"SWLR0001".to_vec();
        out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        fn emit(
            data: &[u8],
            offset: usize,
            ranges: &[(usize, usize)],
            root: bool,
            out: &mut Vec<u8>,
        ) {
            let selected = root
                || ranges
                    .iter()
                    .any(|(a, n)| *a < offset + data.len() && a + n > offset);
            if !selected {
                out.push(0);
                out.extend_from_slice(&hash_nonroot(data, offset));
            } else if data.len() <= 1024 {
                out.push(1);
                out.extend_from_slice(data);
            } else {
                out.push(2);
                let left = left_subtree_len(data.len() as u64) as usize;
                emit(&data[..left], offset, ranges, false, out);
                emit(&data[left..], offset + left, ranges, false, out);
            }
        }
        emit(data, 0, ranges, true, &mut out);
        if out.len() > MAX_COMPACT {
            return Err("Compact response byte limit.".into());
        }
        Ok(out)
    }
    pub fn verify(encoded: &[u8], root: [u8; 32]) -> Result<Sparse, String> {
        if encoded.len() < 17 || encoded.len() > MAX_COMPACT || &encoded[..8] != b"SWLR0001" {
            return Err("Invalid compact range envelope.".into());
        }
        let length = u64::from_le_bytes(encoded[8..16].try_into().unwrap());
        if length == 0 || length > MAX_PREIMAGE as u64 {
            return Err("Compact preimage length limit.".into());
        }
        let mut sparse = Sparse {
            length: length as usize,
            chunks: BTreeMap::new(),
        };
        let key = hash_derive_key_context(DOMAIN);
        struct Reader<'a> {
            bytes: &'a [u8],
            at: usize,
            nodes: usize,
        }
        impl Reader<'_> {
            fn take(&mut self, n: usize) -> Result<&[u8], String> {
                let end = self.at.checked_add(n).ok_or("Range proof overflow.")?;
                let v = self
                    .bytes
                    .get(self.at..end)
                    .ok_or("Truncated range proof.")?;
                self.at = end;
                Ok(v)
            }
        }
        fn walk(
            r: &mut Reader<'_>,
            offset: usize,
            len: usize,
            is_root: bool,
            key: &[u8; 32],
            s: &mut Sparse,
        ) -> Result<[u8; 32], String> {
            r.nodes += 1;
            if r.nodes > 65536 {
                return Err("Range proof node limit.".into());
            }
            match r.take(1)?[0] {
                0 if !is_root => Ok(r.take(32)?.try_into().unwrap()),
                1 if len <= 1024 => {
                    let data = r.take(len)?;
                    let mut h = blake3::Hasher::new_derive_key(DOMAIN);
                    h.set_input_offset(offset as u64).update(data);
                    s.chunks.insert(offset / 1024, data.to_vec());
                    Ok(if is_root {
                        *h.finalize().as_bytes()
                    } else {
                        h.finalize_non_root()
                    })
                }
                2 if len > 1024 => {
                    let n = left_subtree_len(len as u64) as usize;
                    let a = walk(r, offset, n, false, key, s)?;
                    let b = walk(r, offset + n, len - n, false, key, s)?;
                    Ok(if is_root {
                        *merge_subtrees_root(&a, &b, Mode::DeriveKeyMaterial(key)).as_bytes()
                    } else {
                        merge_subtrees_non_root(&a, &b, Mode::DeriveKeyMaterial(key))
                    })
                }
                _ => Err("Invalid range proof tree shape.".into()),
            }
        }
        let mut r = Reader {
            bytes: encoded,
            at: 16,
            nodes: 0,
        };
        let computed = walk(&mut r, 0, length as usize, true, &key, &mut sparse)?;
        if computed != root || r.at != encoded.len() {
            return Err("Compact range authentication failed.".into());
        }
        Ok(sparse)
    }
}
