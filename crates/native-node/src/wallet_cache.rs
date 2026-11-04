//! Explicit private local receipt encoding, never a network or telemetry format.
use super::*;
use std::collections::BTreeSet;

const RECEIPT_BYTES: usize = 243;
const MAX_RECEIPTS: usize = 100000;

impl Wallet {
    /// The caller must seal these private bytes before persistence.
    pub fn local_receipt_cache(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        if self.receipts.len() > MAX_RECEIPTS {
            return Err("Private receipt cache capacity exceeded.".into());
        }
        let mut out = Zeroizing::new(Vec::with_capacity(4 + RECEIPT_BYTES * self.receipts.len()));
        out.extend_from_slice(&(self.receipts.len() as u32).to_le_bytes());
        for r in &self.receipts {
            out.extend_from_slice(&r.commitment);
            out.extend_from_slice(&r.height.to_le_bytes());
            out.extend_from_slice(&r.block_id);
            out.push(r.output_index);
            out.push(u8::from(r.spent));
            out.push(u8::from(r.eligible_timestamp.is_some()));
            out.extend_from_slice(&r.eligible_timestamp.unwrap_or(0).to_le_bytes());
            out.extend_from_slice(&r.note.asset_id.0);
            out.extend_from_slice(&r.note.value.to_le_bytes());
            out.extend_from_slice(&r.note.unlock_height.to_le_bytes());
            out.extend_from_slice(&encode_digest(&r.note.rho));
            out.extend_from_slice(&encode_digest(&r.note.rseed));
        }
        Ok(out)
    }

    /// Restore only bytes opened from the same identity's authenticated local envelope.
    /// This does not authenticate a receipt supplied by a remote node.
    pub fn open_local_receipts(&mut self, state: &mut State, bytes: &[u8]) -> Result<(), String> {
        let mut input = bytes;
        let count = u32::from_le_bytes(take(&mut input)?) as usize;
        if count > MAX_RECEIPTS
            || input.len() != count * RECEIPT_BYTES
            || state.config.network != self.keys.network
        {
            return Err("Private receipt cache size or network differs.".into());
        }
        let mut receipts = Vec::with_capacity(count);
        let mut seen = BTreeSet::new();
        let mut nullifiers = BTreeSet::new();
        let mut spent = BTreeSet::new();
        let mut commitments = BTreeSet::new();
        for _ in 0..count {
            let cm = take(&mut input)?;
            let height = u64::from_le_bytes(take(&mut input)?);
            let block_id = take(&mut input)?;
            let output_index = take::<1>(&mut input)?[0];
            let is_spent = boolean(&mut input)?;
            let has_time = boolean(&mut input)?;
            let timestamp = u64::from_le_bytes(take(&mut input)?);
            let note = Note {
                owner: self.address().owner(),
                asset_id: AssetId(take(&mut input)?),
                value: u64::from_le_bytes(take(&mut input)?),
                unlock_height: u64::from_le_bytes(take(&mut input)?),
                rho: decode_digest(&take(&mut input)?).map_err(|_| "Invalid cached note field.")?,
                rseed: decode_digest(&take(&mut input)?)
                    .map_err(|_| "Invalid cached note field.")?,
            };
            if height == 0
                || height > state.height
                || encode_digest(&Hasher::new().note_cm(&note)) != cm
                || !seen.insert(cm)
                || has_time != (height.max(note.unlock_height) <= state.height)
                || !has_time && timestamp != 0
            {
                return Err("Private receipt cache invariant differs.".into());
            }
            let mut receipt = self.receipt(
                note,
                decode_digest(&cm).map_err(|_| "Invalid cached commitment.")?,
                height,
                block_id,
                output_index,
            );
            if !nullifiers.insert(receipt.nullifier) {
                return Err("Cached nullifier reused.".into());
            }
            receipt.eligible_timestamp = has_time.then_some(timestamp);
            if is_spent {
                spent.insert(receipt.nullifier);
            }
            if receipt.note.value > 0 {
                commitments.insert(cm);
            }
            receipts.push(receipt);
        }
        // All decoding and identity checks finish before replacing accepted fields.
        state.spent = spent;
        state.commitments = commitments;
        self.commit_light_receipts(state, receipts, &[], false);
        Ok(())
    }
}
fn take<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], String> {
    let (next, rest) = input
        .split_at_checked(N)
        .ok_or("Truncated private receipt cache.")?;
    *input = rest;
    next.try_into()
        .map_err(|_| "Private receipt width differs.".into())
}
fn boolean(input: &mut &[u8]) -> Result<bool, String> {
    match take::<1>(input)?[0] {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err("Invalid private receipt flag.".into()),
    }
}
