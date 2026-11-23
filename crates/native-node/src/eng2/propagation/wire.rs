//! Bounded messages for use inside the existing authenticated eng-2 channel.
//!
//! These codecs do not open sockets, negotiate a capability, authenticate a
//! remote identity, authorize a source, or change resident peer behavior.

use super::{authentication::PIECE_BYTES, pipeline::Request};
use crate::{p2p, wire::Hash};

const QUERY: u8 = 0x40;
const PIECE: u8 = 0x41;
const VERSION: u8 = 1;
const QUERY_PREFIX: usize = 44;
const PIECE_PREFIX: usize = 38;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Bound,
    Framing,
}

#[derive(Debug)]
pub struct Query {
    reservation: Option<p2p::Reservation>,
    pub height: u64,
    pub block: Hash,
    pub pieces: Vec<usize>,
}
impl PartialEq for Query {
    fn eq(&self, other: &Self) -> bool {
        self.height == other.height && self.block == other.block && self.pieces == other.pieces
    }
}
impl Eq for Query {}
impl Query {
    pub(crate) fn retain_reservation(&mut self, reservation: p2p::Reservation) {
        self.reservation = Some(reservation);
    }
}

pub struct Piece<'a> {
    pub block: Hash,
    pub index: usize,
    pub bytes: &'a [u8],
}

/// Compress sorted piece runs so one bounded query can request every missing
/// byte in its assigned transaction ranges, without transaction-ID queries.
pub fn encode_query(
    height: u64,
    requests: &[Request],
    maximum_pieces: usize,
) -> Result<Vec<u8>, Error> {
    let first = requests.first().ok_or(Error::Bound)?;
    if height == 0 || requests.len() > maximum_pieces || maximum_pieces > u32::MAX as usize {
        return Err(Error::Bound);
    }
    let mut indices = Vec::with_capacity(requests.len());
    for request in requests {
        if request.block != first.block
            || request.peer != first.peer
            || request.sequence != first.sequence
            || request.piece >= maximum_pieces
        {
            return Err(Error::Framing);
        }
        indices.push(u32::try_from(request.piece).map_err(|_| Error::Bound)?);
    }
    indices.sort_unstable();
    let mut runs: Vec<(u32, u32)> = Vec::new();
    for index in indices {
        if let Some((start, count)) = runs.last_mut() {
            if index < *start + *count {
                return Err(Error::Framing);
            }
            if index == *start + *count {
                *count += 1;
                continue;
            }
        }
        runs.push((index, 1));
    }
    if runs.len() > u16::MAX as usize || QUERY_PREFIX + 8 * runs.len() > p2p::MAX_CONTROL_BYTES {
        return Err(Error::Bound);
    }
    let mut bytes = Vec::with_capacity(QUERY_PREFIX + 8 * runs.len());
    bytes.extend_from_slice(&[QUERY, VERSION]);
    bytes.extend_from_slice(&height.to_le_bytes());
    bytes.extend_from_slice(&first.block);
    bytes.extend_from_slice(&(runs.len() as u16).to_le_bytes());
    for (start, count) in runs {
        bytes.extend_from_slice(&start.to_le_bytes());
        bytes.extend_from_slice(&count.to_le_bytes());
    }
    Ok(bytes)
}

pub fn decode_query(bytes: &[u8], maximum_pieces: usize) -> Result<Query, Error> {
    let total = query_piece_count(bytes, maximum_pieces)?;
    let height = u64::from_le_bytes(bytes[2..10].try_into().expect("validated height"));
    let block = bytes[10..42].try_into().expect("validated identity");
    let mut pieces = Vec::with_capacity(total);
    for run in bytes[QUERY_PREFIX..].as_chunks::<8>().0 {
        let start = u32::from_le_bytes(run[..4].try_into().expect("validated start")) as usize;
        let count = u32::from_le_bytes(run[4..].try_into().expect("validated count")) as usize;
        pieces.extend(start..start + count);
    }
    Ok(Query {
        height,
        block,
        pieces,
        reservation: None,
    })
}

/// Validate without allocating so the transport can reserve expanded storage
/// before a compact run list becomes an owned vector of piece indices.
pub(crate) fn query_piece_count(bytes: &[u8], maximum_pieces: usize) -> Result<usize, Error> {
    if maximum_pieces > u32::MAX as usize {
        return Err(Error::Bound);
    }
    if bytes.len() < QUERY_PREFIX
        || bytes.len() > p2p::MAX_CONTROL_BYTES
        || bytes[..2] != [QUERY, VERSION]
    {
        return Err(Error::Framing);
    }
    let height = u64::from_le_bytes(bytes[2..10].try_into().expect("fixed height"));
    let count = u16::from_le_bytes(bytes[42..44].try_into().expect("fixed run count")) as usize;
    if height == 0 || count == 0 || bytes.len() != QUERY_PREFIX + 8 * count {
        return Err(Error::Framing);
    }
    // Validate all counts and intervals before expanding or allocating indices.
    let mut previous = 0usize;
    let mut total = 0usize;
    for (ordinal, run) in bytes[QUERY_PREFIX..].as_chunks::<8>().0.iter().enumerate() {
        let start = u32::from_le_bytes(run[..4].try_into().expect("fixed run start")) as usize;
        let count = u32::from_le_bytes(run[4..].try_into().expect("fixed run count")) as usize;
        let end = start.checked_add(count).ok_or(Error::Bound)?;
        total = total.checked_add(count).ok_or(Error::Bound)?;
        if count == 0
            || (ordinal != 0 && start <= previous)
            || end > maximum_pieces
            || total > maximum_pieces
        {
            return Err(Error::Bound);
        }
        previous = end;
    }
    Ok(total)
}

pub fn encode_piece(block: Hash, index: usize, payload: &[u8]) -> Result<Vec<u8>, Error> {
    if payload.is_empty() || payload.len() > PIECE_BYTES {
        return Err(Error::Bound);
    }
    let index = u32::try_from(index).map_err(|_| Error::Bound)?;
    let mut bytes = Vec::with_capacity(PIECE_PREFIX + payload.len());
    bytes.extend_from_slice(&[PIECE, VERSION]);
    bytes.extend_from_slice(&block);
    bytes.extend_from_slice(&index.to_le_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

pub fn decode_piece(bytes: &[u8], maximum_pieces: usize) -> Result<Piece<'_>, Error> {
    if bytes.len() <= PIECE_PREFIX
        || bytes.len() > PIECE_PREFIX + PIECE_BYTES
        || bytes[..2] != [PIECE, VERSION]
    {
        return Err(Error::Framing);
    }
    let block = bytes[2..34].try_into().expect("fixed block identity");
    let index = u32::from_le_bytes(bytes[34..38].try_into().expect("fixed piece index")) as usize;
    if index >= maximum_pieces {
        return Err(Error::Bound);
    }
    Ok(Piece {
        block,
        index,
        bytes: &bytes[PIECE_PREFIX..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_runs_reject_duplicates_overlap_trailing_bytes_and_forged_counts() {
        let request = |piece| Request {
            sequence: 1,
            block: [1; 32],
            peer: [2; 32],
            piece,
            maximum_response_wire: 5000,
        };
        let encoded = encode_query(1, &[request(2), request(3), request(8)], 10).unwrap();
        assert_eq!(decode_query(&encoded, 10).unwrap().pieces, vec![2, 3, 8]);
        assert!(encode_query(1, &[request(2), request(2)], 10).is_err());
        let mut bad = encoded.clone();
        bad[QUERY_PREFIX + 4..QUERY_PREFIX + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_query(&bad, 10).is_err());
        let mut bad = encoded.clone();
        bad[QUERY_PREFIX + 8..QUERY_PREFIX + 12].copy_from_slice(&3u32.to_le_bytes());
        assert!(decode_query(&bad, 10).is_err());
        let mut bad = encoded;
        bad.push(0);
        assert!(decode_query(&bad, 10).is_err());
    }
    #[test]
    fn piece_framing_is_bound_before_payload_copy() {
        let encoded = encode_piece([3; 32], 7, &[9; PIECE_BYTES]).unwrap();
        let piece = decode_piece(&encoded, 8).unwrap();
        assert_eq!(piece.block, [3; 32]);
        assert_eq!(piece.index, 7);
        assert_eq!(piece.bytes.len(), PIECE_BYTES);
        assert!(decode_piece(&encoded, 7).is_err());
        let mut bad = encoded;
        bad.push(1);
        assert!(decode_piece(&bad, 8).is_err());
    }
}
