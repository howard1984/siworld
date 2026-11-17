//! Locate transaction envelopes only from already authenticated body bytes.
//!
//! These ranges establish framing positions, never native validity. Bodies
//! still require the unchanged complete decoder and admission path.

use super::{authentication::PIECE_BYTES, pipeline::Transfer};
use crate::{
    eng2::{
        body::{PREFIX_BYTES, Policy},
        header::Header,
    },
    wire::*,
};
use std::ops::Range;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    NeedPiece(usize),
    Context,
    Bound,
    Framing,
}

/// A slot range derived from this exact block's authenticated length framing.
/// Fields are private so remote boundaries cannot manufacture this capability.
#[derive(Clone, Debug)]
pub struct Slot {
    block: Hash,
    ordinal: usize,
    range: Range<usize>,
}
impl Slot {
    pub fn block(&self) -> Hash {
        self.block
    }
    pub fn ordinal(&self) -> usize {
        self.ordinal
    }
    pub fn range(&self) -> Range<usize> {
        self.range.clone()
    }
    pub fn prefix<'a>(&self, transfer: &'a Transfer) -> Result<&'a [u8], Error> {
        if transfer.block() != self.block {
            return Err(Error::Context);
        }
        bytes(
            transfer,
            self.range.start..self.range.start + TX_PREFIX_BYTES,
        )
    }
    pub fn envelope<'a>(&self, transfer: &'a Transfer) -> Result<&'a [u8], Error> {
        if transfer.block() != self.block {
            return Err(Error::Context);
        }
        bytes(transfer, self.range.clone())
    }
}

pub struct Layout {
    pub slots: Vec<Slot>,
    pub settlement: Range<usize>,
}

/// Determine the canonical indexing pieces from a locally available body.
/// The receiver independently authenticates these pieces before discovering
/// any slot boundaries. No transaction identifier is requested or disclosed.
pub fn index_pieces(body: &crate::eng2::body::Body, policy: Policy) -> Result<Vec<usize>, Error> {
    body.encoded_len(policy).map_err(|_| Error::Framing)?;
    let mut indices = std::collections::BTreeSet::new();
    let mut include = |range: Range<usize>| {
        for index in (range.start + 8) / PIECE_BYTES..=(range.end - 1 + 8) / PIECE_BYTES {
            indices.insert(index);
        }
    };
    include(0..PREFIX_BYTES);
    let mut cursor = PREFIX_BYTES
        + (body.rewards.len() + 1) * REWARD_RECORD_BYTES
        + body.fund_claims.len() * crate::eng2::fund_claim::ENCODED_BYTES;
    for action in &body.governance {
        include(cursor..cursor + 4);
        cursor += 4 + action.encode().map_err(|_| Error::Framing)?.len();
    }
    for issuance in &body.issuances {
        include(cursor..cursor + 4);
        cursor += 4 + issuance.encoded_len().map_err(|_| Error::Framing)?;
    }
    for transaction in &body.transactions {
        include(cursor..cursor + 4 + TX_PREFIX_BYTES);
        cursor += 4 + TX_PREFIX_BYTES + transaction.proof.len();
        include(cursor - 1..cursor);
    }
    include(cursor..cursor + 4);
    Ok(indices.into_iter().collect())
}

pub fn inspect(transfer: &Transfer, header: &Header, policy: Policy) -> Result<Layout, Error> {
    if header.id().map_err(|_| Error::Context)? != transfer.block() {
        return Err(Error::Context);
    }
    let prefix = bytes(transfer, 0..PREFIX_BYTES)?;
    if prefix[..6] != *b"SW2B\x01\x00"
        || prefix[6..38] != header.network
        || prefix[38..46] != header.height.to_le_bytes()
        || prefix[46..78] != policy.profile
    {
        return Err(Error::Context);
    }
    let count = u16::from_le_bytes(prefix[78..80].try_into().expect("fixed slot count")) as usize;
    let reward_mode = match prefix[80] {
        0 => RewardMode::Voyager,
        1 => RewardMode::Holder,
        _ => return Err(Error::Framing),
    };
    let rewards = usize::from(prefix[81]);
    let claims = usize::from(prefix[82]);
    let governance = usize::from(prefix[83]);
    let issuances = usize::from(prefix[84]);
    if !(MIN_SLOTS..=MAX_SLOTS).contains(&count)
        || !count.is_multiple_of(GROUP)
        || rewards != reward_count(reward_mode)
        || claims > MAX_FUND_SPENDS
        || governance > crate::eng2_governance::MAX_ACTIONS_PER_BLOCK
        || issuances > crate::issuance::RECORDS_CODEC_LIMIT
    {
        return Err(Error::Framing);
    }
    let mut cursor = PREFIX_BYTES
        + (rewards + 1) * REWARD_RECORD_BYTES
        + claims * crate::eng2::fund_claim::ENCODED_BYTES;
    if cursor > transfer.body_bytes() {
        return Err(Error::Bound);
    }
    for _ in 0..governance {
        let _ = blob(
            transfer,
            &mut cursor,
            1,
            crate::eng2_governance::SignedAction::MAX_ENCODED_BYTES,
        )?;
    }
    for _ in 0..issuances {
        let _ = blob(transfer, &mut cursor, 1, crate::issuance::MAX_RECORD_BYTES)?;
    }
    let mut slots = Vec::with_capacity(count);
    for ordinal in 0..count {
        let range = blob(
            transfer,
            &mut cursor,
            TX_PREFIX_BYTES + 1,
            MAX_ENVELOPE_BYTES,
        )?;
        slots.push(Slot {
            block: transfer.block(),
            ordinal,
            range,
        });
    }
    let settlement = blob(transfer, &mut cursor, 1, policy.max_settlement_proof_bytes)?;
    if cursor != transfer.body_bytes() || cursor > policy.max_body_bytes {
        return Err(Error::Framing);
    }
    Ok(Layout { slots, settlement })
}

fn blob(
    transfer: &Transfer,
    cursor: &mut usize,
    minimum: usize,
    maximum: usize,
) -> Result<Range<usize>, Error> {
    let end = cursor.checked_add(4).ok_or(Error::Bound)?;
    let prefix = bytes(transfer, *cursor..end)?;
    let length = u32::from_le_bytes(prefix.try_into().expect("fixed blob length")) as usize;
    if !(minimum..=maximum).contains(&length) {
        return Err(Error::Bound);
    }
    let next = end.checked_add(length).ok_or(Error::Bound)?;
    if next > transfer.body_bytes() {
        return Err(Error::Bound);
    }
    *cursor = next;
    Ok(end..next)
}

fn bytes(transfer: &Transfer, range: Range<usize>) -> Result<&[u8], Error> {
    if range.start >= range.end || range.end > transfer.body_bytes() {
        return Err(Error::Bound);
    }
    if let Some(bytes) = transfer.authenticated_bytes(range.clone()) {
        return Ok(bytes);
    }
    let first = (range.start + 8) / PIECE_BYTES;
    let last = (range.end - 1 + 8) / PIECE_BYTES;
    for index in first..=last {
        let start = (index * PIECE_BYTES).saturating_sub(8).max(range.start);
        let end = ((index + 1) * PIECE_BYTES - 8).min(range.end);
        if transfer.authenticated_bytes(start..end).is_none() {
            return Err(Error::NeedPiece(index));
        }
    }
    Err(Error::Framing)
}
