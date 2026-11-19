//! BLAKE3 subtree authentication for the existing canonical body hash.
//!
//! The hash input remains `u64_le(body_length) || canonical_body`, with the
//! unchanged derive-key context. The descriptor carries chaining values for
//! aligned subtrees, not a new commitment. Its first piece authenticates the
//! encoded length before any remaining piece can be admitted.

use crate::{eng2::header::Header, wire::Hash};
use blake3::hazmat::{self, HasherExt, Mode};
use std::ops::Range;

const CONTEXT: &str = "siworld eng2 canonical block body v1";
pub const PIECE_BYTES: usize = 4 * 1024;
const LENGTH_BYTES: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub body_bytes: u64,
    pub subtrees: Vec<Hash>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Bound,
    Shape,
    Commitment,
    Piece,
    Length,
}

/// A descriptor authenticated against one exact header, including its length.
pub struct Authenticated {
    descriptor: Descriptor,
    block: Hash,
    context: Hash,
    height: u64,
}

/// Bytes authenticated at an exact offset in one exact committed body.
pub struct VerifiedPiece {
    block: Hash,
    index: usize,
    body_range: Range<usize>,
    bytes: Vec<u8>,
}

impl VerifiedPiece {
    pub fn block(&self) -> Hash {
        self.block
    }
    pub fn index(&self) -> usize {
        self.index
    }
    pub fn range(&self) -> Range<usize> {
        self.body_range.clone()
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Descriptor {
    pub fn decode(bytes: &[u8], limit: usize) -> Result<Self, Error> {
        if bytes.len() < LENGTH_BYTES {
            return Err(Error::Shape);
        }
        let body_bytes =
            u64::from_le_bytes(bytes[..LENGTH_BYTES].try_into().expect("fixed length"));
        let (_, count) = shape(body_bytes, limit)?;
        if bytes.len() != LENGTH_BYTES + count * 32 {
            return Err(Error::Shape);
        }
        Ok(Self {
            body_bytes,
            subtrees: bytes[LENGTH_BYTES..].as_chunks::<32>().0.to_vec(),
        })
    }

    pub fn encode(&self, limit: usize) -> Result<Vec<u8>, Error> {
        let (_, count) = shape(self.body_bytes, limit)?;
        if count != self.subtrees.len() {
            return Err(Error::Shape);
        }
        let mut bytes = Vec::with_capacity(LENGTH_BYTES + count * 32);
        bytes.extend_from_slice(&self.body_bytes.to_le_bytes());
        for subtree in &self.subtrees {
            bytes.extend_from_slice(subtree);
        }
        Ok(bytes)
    }

    /// Build only from an already bounded canonical encoding. This operation
    /// never verifies the native transaction or settlement proofs.
    pub fn build(body: &[u8], limit: usize) -> Result<Self, Error> {
        let (_, count) = shape(body.len() as u64, limit)?;
        let context = hazmat::hash_derive_key_context(CONTEXT);
        let mut subtrees = Vec::with_capacity(count);
        for index in 0..count {
            let bytes = encoded_piece(body, index)?;
            subtrees.push(piece_cv(&context, index, &bytes));
        }
        Ok(Self {
            body_bytes: body.len() as u64,
            subtrees,
        })
    }

    /// Authenticate the descriptor and length with the first transfer piece.
    /// Root finalization differs from non-root CV finalization, so one-piece
    /// bodies are checked directly against the header's unchanged hash.
    pub fn authenticate(
        self,
        header: &Header,
        first: Vec<u8>,
        limit: usize,
    ) -> Result<(Authenticated, VerifiedPiece), Error> {
        let (input_bytes, count) = shape(self.body_bytes, limit)?;
        if self.subtrees.len() != count || first.len() != input_bytes.min(PIECE_BYTES) {
            return Err(Error::Shape);
        }
        if first[..LENGTH_BYTES] != self.body_bytes.to_le_bytes() {
            return Err(Error::Length);
        }
        let context = hazmat::hash_derive_key_context(CONTEXT);
        let mode = Mode::DeriveKeyMaterial(&context);
        let root = if count == 1 {
            *blake3::Hasher::new_from_context_key(&context)
                .update(&first)
                .finalize()
                .as_bytes()
        } else {
            let split = split_at(count);
            *hazmat::merge_subtrees_root(
                &subtree_cv(&self.subtrees[..split], mode),
                &subtree_cv(&self.subtrees[split..], mode),
                mode,
            )
            .as_bytes()
        };
        if root != header.body_commitment {
            return Err(Error::Commitment);
        }
        let authenticated = Authenticated {
            descriptor: self,
            block: header.id().map_err(|_| Error::Commitment)?,
            context,
            height: header.height,
        };
        let first = authenticated.verify(0, first)?;
        Ok((authenticated, first))
    }
}

impl Authenticated {
    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn same_descriptor(&self, other: &Self) -> bool {
        self.block == other.block
            && self.context == other.context
            && self.height == other.height
            && self.descriptor.body_bytes == other.descriptor.body_bytes
            && self.descriptor.subtrees == other.descriptor.subtrees
    }

    pub fn body_bytes(&self) -> usize {
        // Construction checked the platform-width conversion and bound.
        self.descriptor.body_bytes as usize
    }
    pub fn piece_count(&self) -> usize {
        self.descriptor.subtrees.len()
    }
    pub fn block(&self) -> Hash {
        self.block
    }
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn range(&self, index: usize) -> Result<Range<usize>, Error> {
        if index >= self.piece_count() {
            return Err(Error::Bound);
        }
        let start = index * PIECE_BYTES;
        let end = start
            .saturating_add(PIECE_BYTES)
            .min(self.body_bytes() + LENGTH_BYTES);
        Ok(start.saturating_sub(LENGTH_BYTES)..end - LENGTH_BYTES)
    }
    pub fn verify(&self, index: usize, mut bytes: Vec<u8>) -> Result<VerifiedPiece, Error> {
        let range = self.range(index)?;
        let expected = range.len() + if index == 0 { LENGTH_BYTES } else { 0 };
        if bytes.len() != expected
            || piece_cv(&self.context, index, &bytes) != self.descriptor.subtrees[index]
        {
            return Err(Error::Piece);
        }
        if index == 0 {
            if bytes[..LENGTH_BYTES] != self.descriptor.body_bytes.to_le_bytes() {
                return Err(Error::Length);
            }
            bytes.drain(..LENGTH_BYTES);
        }
        Ok(VerifiedPiece {
            block: self.block,
            index,
            body_range: range,
            bytes,
        })
    }
}

/// Return a transfer piece including the original hash-input length prefix.
/// A maximum of one fixed-size piece is allocated per invocation.
pub fn encoded_piece(body: &[u8], index: usize) -> Result<Vec<u8>, Error> {
    let input_bytes = body.len().checked_add(LENGTH_BYTES).ok_or(Error::Bound)?;
    let start = index.checked_mul(PIECE_BYTES).ok_or(Error::Bound)?;
    if start >= input_bytes || body.is_empty() {
        return Err(Error::Bound);
    }
    let end = start.saturating_add(PIECE_BYTES).min(input_bytes);
    let mut bytes = Vec::with_capacity(end - start);
    if index == 0 {
        bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
    }
    bytes.extend_from_slice(&body[start.saturating_sub(LENGTH_BYTES)..end - LENGTH_BYTES]);
    Ok(bytes)
}

fn shape(body_bytes: u64, limit: usize) -> Result<(usize, usize), Error> {
    let length = usize::try_from(body_bytes).map_err(|_| Error::Bound)?;
    if length == 0 || length > limit {
        return Err(Error::Bound);
    }
    let input = length.checked_add(LENGTH_BYTES).ok_or(Error::Bound)?;
    Ok((input, input.div_ceil(PIECE_BYTES)))
}

fn piece_cv(context: &Hash, index: usize, bytes: &[u8]) -> Hash {
    blake3::Hasher::new_from_context_key(context)
        .set_input_offset((index * PIECE_BYTES) as u64)
        .update(bytes)
        .finalize_non_root()
}

// For n leaves, BLAKE3's left subtree contains the largest power of two
// strictly smaller than n. Each leaf here is itself a four-chunk subtree;
// only the final right-edge leaf may be shorter.
fn split_at(count: usize) -> usize {
    count.next_power_of_two() / 2
}

fn subtree_cv(values: &[Hash], mode: Mode<'_>) -> Hash {
    if values.len() == 1 {
        values[0]
    } else {
        let split = split_at(values.len());
        hazmat::merge_subtrees_non_root(
            &subtree_cv(&values[..split], mode),
            &subtree_cv(&values[split..], mode),
            mode,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eng2::header::body_commitment;

    fn header(body: &[u8]) -> Header {
        Header {
            network: [1; 32],
            height: 1,
            parent: [2; 32],
            timestamp: 1,
            target: [255; 32],
            execution_commitment: [3; 32],
            body_commitment: body_commitment(body, body.len()).unwrap(),
            nonce: 0,
        }
    }
    fn data(length: usize) -> Vec<u8> {
        (0..length).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn subtree_roots_match_unchanged_header_hash_at_tree_boundaries() {
        for length in [
            1,
            63,
            64,
            1015,
            1016,
            1017,
            1023,
            1024,
            1025,
            PIECE_BYTES - 9,
            PIECE_BYTES - 8,
            PIECE_BYTES - 7,
            PIECE_BYTES,
            2 * PIECE_BYTES - 8,
            2 * PIECE_BYTES + 1,
            3 * PIECE_BYTES,
            4 * PIECE_BYTES + 77,
            7 * PIECE_BYTES + 9,
            8 * PIECE_BYTES - 8,
            65527,
            65528,
            65529,
            65535,
            65536,
            65537,
            131073,
        ] {
            let body = data(length);
            let descriptor = Descriptor::build(&body, length).unwrap();
            let (authenticated, first) = descriptor
                .authenticate(&header(&body), encoded_piece(&body, 0).unwrap(), length)
                .unwrap();
            assert_eq!(first.bytes(), &body[first.range()]);
            for index in 1..authenticated.piece_count() {
                let piece = authenticated
                    .verify(index, encoded_piece(&body, index).unwrap())
                    .unwrap();
                assert_eq!(piece.bytes(), &body[piece.range()]);
            }
        }
    }

    #[test]
    fn every_small_subtree_shape_and_chunk_tail_matches_the_original_hasher() {
        // Exercise every subtree count through 34, including non-power-of-two
        // shapes, and both sides of every chunk boundary in the right edge.
        // Lengths refer to the original hash input, including its eight bytes.
        for full_pieces in 0..=33 {
            for tail in [
                1, 7, 8, 63, 64, 65, 1023, 1024, 1025, 2047, 2048, 2049, 3071, 3072, 3073, 4095,
                4096,
            ] {
                let input_length = full_pieces * PIECE_BYTES + tail;
                let Some(length) = input_length
                    .checked_sub(LENGTH_BYTES)
                    .filter(|length| *length > 0)
                else {
                    continue;
                };
                let body = data(length);
                let expected = header(&body);
                let descriptor = Descriptor::build(&body, length).unwrap();
                assert_eq!(
                    descriptor.subtrees.len(),
                    input_length.div_ceil(PIECE_BYTES)
                );
                let encoded = descriptor.encode(length).unwrap();
                let descriptor = Descriptor::decode(&encoded, length).unwrap();
                let (authenticated, first) = descriptor
                    .authenticate(&expected, encoded_piece(&body, 0).unwrap(), length)
                    .unwrap();
                let mut covered = first.bytes().len();
                for index in 1..authenticated.piece_count() {
                    let piece = authenticated
                        .verify(index, encoded_piece(&body, index).unwrap())
                        .unwrap();
                    assert_eq!(piece.bytes(), &body[piece.range()]);
                    covered += piece.bytes().len();
                }
                assert_eq!(covered, length);
            }
        }
    }

    #[test]
    fn corrupt_descriptor_length_piece_and_wrong_header_fail_closed() {
        let body = data(3 * PIECE_BYTES + 17);
        let descriptor = Descriptor::build(&body, body.len()).unwrap();
        let first = encoded_piece(&body, 0).unwrap();
        let mut bad = descriptor.clone();
        bad.subtrees[2][0] ^= 1;
        assert!(matches!(
            bad.authenticate(&header(&body), first.clone(), body.len()),
            Err(Error::Commitment)
        ));
        let mut bad = descriptor.clone();
        bad.body_bytes -= 1;
        assert!(matches!(
            bad.authenticate(&header(&body), first.clone(), body.len()),
            Err(Error::Length)
        ));
        let mut bad = header(&body);
        bad.body_commitment[0] ^= 1;
        assert!(
            descriptor
                .clone()
                .authenticate(&bad, first.clone(), body.len())
                .is_err()
        );
        let (authenticated, _) = descriptor
            .authenticate(&header(&body), first, body.len())
            .unwrap();
        let mut bytes = encoded_piece(&body, 1).unwrap();
        bytes[3] ^= 1;
        assert!(matches!(authenticated.verify(1, bytes), Err(Error::Piece)));
        assert!(
            authenticated
                .verify(2, encoded_piece(&body, 1).unwrap())
                .is_err()
        );
        assert!(authenticated.verify(usize::MAX, vec![]).is_err());
    }

    #[test]
    fn untrusted_bounds_are_checked_before_tree_work() {
        for length in [0, u64::MAX] {
            let descriptor = Descriptor {
                body_bytes: length,
                subtrees: vec![],
            };
            assert!(matches!(
                descriptor.authenticate(&header(&[1]), vec![], 100),
                Err(Error::Bound)
            ));
        }
        assert!(Descriptor::build(&[1; 101], 100).is_err());
        assert!(encoded_piece(&[1], usize::MAX).is_err());
        assert!(Descriptor::decode(&u64::MAX.to_le_bytes(), 100).is_err());
        let body = data(2 * PIECE_BYTES);
        let descriptor = Descriptor::build(&body, body.len()).unwrap();
        let encoded = descriptor.encode(body.len()).unwrap();
        assert_eq!(
            Descriptor::decode(&encoded, body.len()).unwrap(),
            descriptor
        );
        assert!(Descriptor::decode(&encoded[..encoded.len() - 1], body.len()).is_err());
        let mut extra = encoded;
        extra.extend_from_slice(&[0; 32]);
        assert!(Descriptor::decode(&extra, body.len()).is_err());
    }

    #[test]
    #[ignore = "bounded 40 MiB local authentication measurement"]
    fn forty_mib_authentication_measurement() {
        let body = data(40 * 1024 * 1024);
        for sample in 0..3 {
            let start = std::time::Instant::now();
            let header = header(&body);
            let full = start.elapsed();
            let start = std::time::Instant::now();
            let descriptor = Descriptor::build(&body, body.len()).unwrap();
            let build = start.elapsed();
            let descriptor_bytes = descriptor.encode(body.len()).unwrap().len();
            let start = std::time::Instant::now();
            let (authenticated, first) = descriptor
                .authenticate(&header, encoded_piece(&body, 0).unwrap(), body.len())
                .unwrap();
            let mut authenticated_bytes = first.bytes().len();
            for index in 1..authenticated.piece_count() {
                let piece = authenticated
                    .verify(index, encoded_piece(&body, index).unwrap())
                    .unwrap();
                assert_eq!(piece.bytes(), &body[piece.range()]);
                authenticated_bytes += piece.bytes().len();
            }
            let verify = start.elapsed();
            assert_eq!(authenticated_bytes, body.len());
            println!(
                "sample={sample} body_bytes={} piece_bytes={PIECE_BYTES} pieces={} descriptor_bytes={descriptor_bytes} complete_hash_us={} descriptor_build_us={} all_pieces_authenticate_us={}",
                body.len(),
                authenticated.piece_count(),
                full.as_micros(),
                build.as_micros(),
                verify.as_micros()
            );
        }
    }
}
