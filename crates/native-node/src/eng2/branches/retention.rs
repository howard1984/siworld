//! Expired proof bodies become permanent public records in a separate branch
//! namespace. Neither these records nor retained headers grant native validity.
use super::*;
use std::ops::Bound::{Excluded, Unbounded};
const PUBLIC: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("eng2-branches-expired-public-v1");
const PUBLIC_IDS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("eng2-branches-expired-public-ids-v1");

impl BranchStore {
    /// The canonical owner's sealed floor incorporates the configured role,
    /// authenticated checkpoint and observed service finality age. All branch
    /// bodies above that floor and all active bootstrap promises remain intact.
    pub(crate) fn prune_expired_bodies(
        &mut self,
        store: &Store,
        pins: &super::super::bootstrap::BodyPins,
        after: Option<Hash>,
        budget: &crate::p2p::Budget,
    ) -> Result<(Option<Hash>, usize, usize), String> {
        use super::super::wallet_history::codec::{Context, MAX_RECEIPT_BYTES, ReceiptBlock};
        store.ensure_exportable()?;
        let floor = store.proof_retention_floor()?;
        if floor == 0 {
            return Ok((None, 0, 0));
        }
        let _reservation = budget
            .reserve(64 * 1024 * 1024 + 4 * MAX_RECEIPT_BYTES + 1024 * 1024)
            .map_err(|_| "branch proof pruning budget unavailable")?;
        let context = Context::from_genesis(
            &store.engine().genesis().encode()?,
            store.engine().genesis().id(),
        )?;
        let mut selected = Vec::new();
        let mut cursor = None;
        let mut removed_bytes = 0usize;
        let read = self
            .database
            .begin_read()
            .map_err(|_| "branch pruning read unavailable")?;
        let bodies = read
            .open_table(BODIES)
            .map_err(|_| "branch pruning bodies unavailable")?;
        let headers = read
            .open_table(HEADERS)
            .map_err(|_| "branch pruning headers unavailable")?;
        let range: (std::ops::Bound<&[u8]>, std::ops::Bound<&[u8]>) = (
            after
                .as_ref()
                .map_or(Unbounded, |id| Excluded(id.as_slice())),
            Unbounded,
        );
        let mut stopped = false;
        for (scanned, row) in bodies
            .range::<&[u8]>(range)
            .map_err(|_| "branch pruning body range unavailable")?
            .enumerate()
        {
            let (key, body) = row.map_err(|_| "branch pruning body unavailable")?;
            let id: Hash = key
                .value()
                .try_into()
                .map_err(|_| "branch pruning identity width invalid")?;
            if scanned == 128 {
                stopped = true;
                break;
            }
            let raw_header = headers
                .get(id.as_slice())
                .map_err(|_| "branch pruning header unavailable")?
                .ok_or("branch pruning header missing")?;
            let entry = Entry::decode(raw_header.value(), &self.rules.network)?;
            if entry
                .header
                .id()
                .map_err(|_| "branch pruning identity invalid")?
                != id
            {
                return Err("branch pruning key differs from header".into());
            }
            if entry.header.height <= floor && !pins.protects(entry.header.height) {
                if selected.len() == 4
                    || body.value().len() > (64 * 1024 * 1024usize).saturating_sub(removed_bytes)
                {
                    stopped = true;
                    break;
                }
                if body.value().len() > store.engine().body_policy().max_body_bytes {
                    return Err("branch pruning body exceeds policy".into());
                }
                // The existing public codec checks exact header/body framing and
                // commitments without retaining proof or private side inputs.
                let public = ReceiptBlock::export(
                    &context,
                    &entry
                        .header
                        .encode()
                        .map_err(|_| "branch pruning header encoding invalid")?,
                    body.value(),
                )?;
                if public.len() > MAX_RECEIPT_BYTES {
                    return Err("branch pruning public record exceeds limit".into());
                }
                removed_bytes += body.value().len();
                selected.push((id, body.value().len(), public, entry));
            }
            cursor = Some(id);
        }
        // A short scan reached the end. A full/byte-bounded scan resumes after
        // its last completed row; deleted rows need no remote retry or ticket.
        if !stopped {
            cursor = None;
        }
        drop(headers);
        drop(bodies);
        drop(read);
        if selected.is_empty() {
            return Ok((cursor, 0, 0));
        }
        let mut tx = self
            .database
            .begin_write()
            .map_err(|_| "branch pruning transaction unavailable")?;
        tx.set_durability(Durability::Immediate)
            .map_err(|_| "branch pruning durability unavailable")?;
        tx.set_quick_repair(true);
        {
            let mut bodies = tx
                .open_table(BODIES)
                .map_err(|_| "branch pruning bodies unavailable")?;
            let mut headers = tx
                .open_table(HEADERS)
                .map_err(|_| "branch pruning headers unavailable")?;
            let mut meta = tx
                .open_table(META)
                .map_err(|_| "branch pruning metadata unavailable")?;
            let mut public = tx
                .open_table(PUBLIC)
                .map_err(|_| "branch pruning public table unavailable")?;
            let mut ids = tx
                .open_table(PUBLIC_IDS)
                .map_err(|_| "branch pruning public index unavailable")?;
            let total = meta_number(&meta, "body-bytes")?
                .checked_sub(removed_bytes as u64)
                .ok_or("branch pruning byte accounting underflow")?;
            for (id, size, receipt, entry) in &mut selected {
                let digest = *blake3::hash(receipt).as_bytes();
                match (
                    public
                        .get(id.as_slice())
                        .map_err(|_| "branch pruning public read failed")?,
                    ids.get(id.as_slice())
                        .map_err(|_| "branch pruning public digest read failed")?,
                ) {
                    (Some(old), Some(old_id))
                        if old.value() == receipt.as_slice() && old_id.value() == digest => {}
                    (None, None) => {}
                    _ => return Err("branch pruning public record pair conflicts".into()),
                }
                public
                    .insert(id.as_slice(), receipt.as_slice())
                    .map_err(|_| "branch pruning public write failed")?;
                ids.insert(id.as_slice(), digest.as_slice())
                    .map_err(|_| "branch pruning public digest write failed")?;
                let old = bodies
                    .remove(id.as_slice())
                    .map_err(|_| "branch pruning removal failed")?
                    .ok_or("branch pruning body disappeared")?;
                if old.value().len() != *size {
                    return Err("branch pruning body size changed".into());
                }
                if entry.status == Status::BodyRetained {
                    entry.status = Status::HeaderQualified;
                    headers
                        .insert(id.as_slice(), entry.encode()?.as_slice())
                        .map_err(|_| "branch pruning availability update failed")?;
                }
            }
            meta.insert("body-bytes", total.to_le_bytes().as_slice())
                .map_err(|_| "branch pruning accounting failed")?;
        }
        tx.commit().map_err(|_| "branch pruning commit uncertain")?;
        self.selection_changed();
        Ok((cursor, selected.len(), removed_bytes))
    }
    #[cfg(test)]
    pub(crate) fn expired_public_record_for_test(
        &self,
        id: Hash,
    ) -> Result<Option<Vec<u8>>, String> {
        let read = self
            .database
            .begin_read()
            .map_err(|_| "branch test read unavailable")?;
        let public = read
            .open_table(PUBLIC)
            .map_err(|_| "branch test public records unavailable")?;
        let ids = read
            .open_table(PUBLIC_IDS)
            .map_err(|_| "branch test public index unavailable")?;
        let Some(row) = public
            .get(id.as_slice())
            .map_err(|_| "branch test receipt unavailable")?
        else {
            return Ok(None);
        };
        let hash = ids
            .get(id.as_slice())
            .map_err(|_| "branch test digest unavailable")?
            .ok_or("branch test digest missing")?;
        if hash.value() != blake3::hash(row.value()).as_bytes() {
            return Err("branch test public record modified".into());
        }
        Ok(Some(row.value().to_vec()))
    }
}
