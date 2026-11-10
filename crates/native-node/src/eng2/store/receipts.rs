//! Atomic permanent receipt materialization from the accepted Store adapter.
//! Full bodies and all chain-state tables are preserved; this enables no pruning.
use super::{INDEX, PERMANENT_RECEIPT_IDS, PERMANENT_RECEIPTS, Store};
use crate::{
    eng2::{
        genesis::Genesis,
        header::Header,
        wallet_history::{self, codec},
    },
    p2p,
    wire::Hash,
};
use redb::{Durability, ReadableTable, WriteTransaction};

#[cfg(test)]
mod tests;

/// A checked borrowed blob cannot be constructed without exact immutable
/// context, accepted header and canonical body-length authentication.
struct Checked<'a> {
    height: u64,
    index: Vec<u8>,
    bytes: &'a [u8],
    digest: Hash,
}
impl<'a> Checked<'a> {
    fn new(
        genesis: &Genesis,
        header: &Header,
        body_bytes: usize,
        bytes: &'a [u8],
    ) -> Result<Self, String> {
        if header.height == 0 || bytes.len() > codec::MAX_RECEIPT_BYTES {
            return Err("permanent receipt height or size rejected".into());
        }
        let context = codec::Context::from_genesis(&genesis.encode()?, genesis.id())?;
        let encoded = header
            .encode()
            .map_err(|_| "permanent receipt header rejected")?;
        let receipt = codec::ReceiptBlock::decode(&context, &encoded, bytes)?;
        if receipt.body_bytes() != body_bytes {
            return Err(
                "permanent receipt canonical body length differs from accepted index".into(),
            );
        }
        Ok(Self {
            height: header.height,
            index: super::compact_record(header, body_bytes)?,
            bytes,
            digest: *blake3::hash(bytes).as_bytes(),
        })
    }

    /// Both records share one caller-owned immediate transaction. Conflicting
    /// or incomplete existing pairs are preserved for diagnosis, never repaired
    /// implicitly from a newly supplied projection.
    fn write(&self, transaction: &WriteTransaction) -> Result<(), String> {
        {
            let index = transaction
                .open_table(INDEX)
                .map_err(|_| "permanent receipt accepted index unavailable")?;
            let accepted = index
                .get(self.height)
                .map_err(|_| "permanent receipt accepted index read failed")?
                .ok_or("permanent receipt height is not durably accepted")?;
            if accepted.value() != self.index {
                return Err(
                    "permanent receipt differs from exact accepted header or length".into(),
                );
            }
        }
        let mut receipts = transaction
            .open_table(PERMANENT_RECEIPTS)
            .map_err(|_| "permanent receipt table unavailable")?;
        let mut identities = transaction
            .open_table(PERMANENT_RECEIPT_IDS)
            .map_err(|_| "permanent receipt digest table unavailable")?;
        {
            let existing = receipts
                .get(self.height)
                .map_err(|_| "permanent receipt lookup failed")?;
            let identity = identities
                .get(self.height)
                .map_err(|_| "permanent receipt digest lookup failed")?;
            match (existing, identity) {
                (Some(existing), Some(identity)) => {
                    if existing.value() != self.bytes || identity.value() != self.digest {
                        return Err("existing permanent receipt pair conflicts; preserved".into());
                    }
                    return Ok(());
                }
                (None, None) => {}
                _ => return Err("existing permanent receipt pair incomplete; preserved".into()),
            }
        }
        receipts
            .insert(self.height, self.bytes)
            .map_err(|_| "permanent receipt write failed")?;
        identities
            .insert(self.height, self.digest.as_slice())
            .map_err(|_| "permanent receipt digest write failed")?;
        Ok(())
    }
}

impl Store {
    /// Explicit bounded backfill, also usable immediately after native acceptance.
    /// The accepted Store exporter owns the reservation while buffers are live.
    /// Failure preserves full bodies and never changes chain acceptance or state.
    /// Repeating a completed height is idempotent; no existing row is overwritten.
    pub fn materialize_permanent_receipt(
        &self,
        height: u64,
        budget: &p2p::Budget,
    ) -> Result<usize, String> {
        let head = wallet_history::Head::capture(self)?;
        let exported = wallet_history::receipts(self, &head, height, budget)?;
        let header = self.header(height)?;
        let checked = Checked::new(
            self.engine.genesis(),
            &header,
            self.block_size(height)?,
            exported.bytes(),
        )?;
        head.check_current(self)?;
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|_| "permanent receipt transaction unavailable")?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|_| "permanent receipt durability unavailable")?;
        checked.write(&transaction)?;
        transaction
            .commit()
            .map_err(|_| "permanent receipt durable commit failed")?;
        head.check_current(self)?;
        Ok(exported.bytes().len())
    }
}
