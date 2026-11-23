//! Reconstruct a shadow database from the exact locally certified prefix.
//! The source transaction is immutable, and the target is never the active
//! generation. After the prefix is copied, native append verifies every
//! candidate block above the checkpoint.

use super::{generations::Record, *};
use crate::eng2::snapshot::{ImportLimits, SnapshotState};

pub(in crate::eng2) struct ShadowPrefix {
    source: redb::ReadTransaction,
    selector: Record,
    genesis: Vec<u8>,
    limits: ImportLimits,
    body_floor: u64,
    through: u64,
    next: u64,
    lookup: Option<Header>,
    imported: Option<(u64, Hash)>,
}

impl Store {
    pub(in crate::eng2) fn capture_shadow_prefix(
        &self,
        selector: Record,
        limits: ImportLimits,
    ) -> Result<ShadowPrefix, String> {
        self.ensure_exportable()?;
        if self.generation_record()? != selector {
            return Err("shadow prefix requires the active generation".into());
        }
        let identity = &self
            .restart
            .as_ref()
            .ok_or("shadow prefix custody missing")?
            .identity;
        let (through, lookup) = match selector.floor() {
            None => (0, None),
            Some(certificate) => {
                let statement = &certificate.statement;
                let header = self.header(statement.checkpoint_height)?;
                if header
                    .id()
                    .map_err(|_| "shadow checkpoint header invalid")?
                    != statement.checkpoint_block
                {
                    return Err("shadow checkpoint differs from selected prefix".into());
                }
                (header.height, Some(header))
            }
        };
        let source = self
            .database
            .begin_read()
            .map_err(|_| "shadow prefix capture failed")?;
        let body_floor = retention::read_floor(&source, self.engine.genesis().id(), identity)?
            .max(self.imported_prefix);
        if body_floor > through {
            return Err("shadow prefix lacks authenticated retained history".into());
        }
        Ok(ShadowPrefix {
            source,
            selector,
            genesis: self.engine.genesis().encode()?,
            limits,
            body_floor,
            through,
            next: 1,
            lookup,
            imported: (self.imported_prefix != 0)
                .then_some((self.imported_prefix, self.import_seed)),
        })
    }

    /// Seal the completed shadow only if the live selector still matches.
    /// The owner supplies the signing identity here, never to replay workers.
    pub(in crate::eng2) fn seal_shadow_prefix(
        &self,
        prefix: &ShadowPrefix,
        target: &mut Store,
        identity: crate::identity::NativeIdentity,
    ) -> Result<(), String> {
        if self.generation_record()? != prefix.selector
            || target.generation_control.is_some()
            || target.engine.genesis().id() != self.engine.genesis().id()
            || target.engine.state().height() < prefix.through
            || prefix.next <= prefix.through
        {
            return Err("shadow replay selector or acknowledged prefix changed".into());
        }
        let expected = self
            .restart
            .as_ref()
            .ok_or("shadow replay custody missing")?
            .identity
            .descriptor()
            .map_err(|_| "shadow live owner descriptor unavailable")?;
        if identity
            .descriptor()
            .map_err(|_| "shadow sealing identity unavailable")?
            .fingerprint()
            != expected.fingerprint()
        {
            return Err("shadow sealing owner identity differs".into());
        }
        if prefix.through != 0 {
            let mut txn = target
                .database
                .begin_write()
                .map_err(|_| "shadow retention write unavailable")?;
            durable(&mut txn)?;
            retention::copy_prefix_cursor(
                &prefix.source,
                &txn,
                self.engine.genesis().id(),
                &identity,
                prefix.through,
            )?;
            txn.commit().map_err(|_| "shadow retention commit failed")?;
        }
        target.enable_authenticated_restart(identity)
    }
}

impl ShadowPrefix {
    pub(in crate::eng2) fn height(&self) -> u64 {
        self.through
    }

    pub(in crate::eng2) fn next_bytes(&self) -> Result<usize, String> {
        if self.next > self.through {
            return Ok(0);
        }
        let block = self
            .source
            .open_table(BLOCKS)
            .map_err(|_| "shadow source bodies unavailable")?
            .get(self.next)
            .map_err(|_| "shadow source body length unavailable")?
            .map_or(0, |row| row.value().len());
        let receipt = match self.source.open_table(PERMANENT_RECEIPTS) {
            Ok(table) => table
                .get(self.next)
                .map_err(|_| "shadow source receipt length unavailable")?
                .map_or(0, |row| row.value().len()),
            Err(redb::TableError::TableDoesNotExist(_)) => 0,
            Err(_) => return Err("shadow source receipts unavailable".into()),
        };
        block
            .checked_add(receipt)
            .ok_or("shadow prefix byte accounting overflow".into())
    }

    pub(in crate::eng2) fn snapshot_bytes(&self) -> Result<usize, String> {
        if self.through == 0 {
            return Ok(0);
        }
        let checkpoint = self
            .source
            .open_table(ANCHORS)
            .map_err(|_| "shadow source snapshot unavailable")?
            .get(self.through)
            .map_err(|_| "shadow source snapshot length unavailable")?
            .ok_or("shadow source snapshot missing")?
            .value()
            .len();
        checkpoint
            .checked_add(self.provenance_bytes()?)
            .ok_or("shadow snapshot byte accounting overflow".into())
    }

    fn provenance_bytes(&self) -> Result<usize, String> {
        match self.imported {
            Some((height, seed)) => imported::shadow_provenance(&self.source, height, seed, None),
            None => Ok(0),
        }
    }

    pub(in crate::eng2) fn canonical_block(
        &self,
        target: &Store,
        height: u64,
    ) -> Result<(Header, Body), String> {
        if height <= self.through {
            return Err("shadow replay requested a block before the seed".into());
        }
        let blocks = self
            .source
            .open_table(BLOCKS)
            .map_err(|_| "shadow source bodies unavailable")?;
        let raw = blocks
            .get(height)
            .map_err(|_| "shadow source body read failed")?
            .ok_or("shadow source body was not retained")?;
        decode(&target.engine, raw.value())
    }

    pub(in crate::eng2) fn canonical_size(&self, height: u64) -> Result<usize, String> {
        let blocks = self
            .source
            .open_table(BLOCKS)
            .map_err(|_| "shadow source bodies unavailable")?;
        Ok(blocks
            .get(height)
            .map_err(|_| "shadow source body read failed")?
            .ok_or("shadow source body was not retained")?
            .value()
            .len())
    }

    pub(in crate::eng2) fn copy_next(
        &mut self,
        target: &Store,
        budget: &crate::p2p::Budget,
    ) -> Result<bool, String> {
        if self.next > self.through {
            return Ok(false);
        }
        if target.restart.is_some()
            || target.engine.state().height() != 0
            || target.generation_control.is_some()
            || target.engine.genesis().encode()? != self.genesis
        {
            return Err("shadow prefix target is not an unadmitted genesis store".into());
        }
        let height = self.next;
        let index = self
            .source
            .open_table(INDEX)
            .map_err(|_| "shadow prefix index missing")?;
        let index = index
            .get(height)
            .map_err(|_| "shadow prefix index unavailable")?
            .ok_or("shadow prefix index gap")?;
        let (header, body_bytes) = decode_compact(index.value(), target.engine.state().network())?;
        if header.height != height {
            return Err("shadow prefix header height differs".into());
        }
        let blocks = self
            .source
            .open_table(BLOCKS)
            .map_err(|_| "shadow prefix bodies unavailable")?;
        let body = blocks
            .get(height)
            .map_err(|_| "shadow prefix body read failed")?;
        match &body {
            None if height <= self.body_floor => {}
            Some(body)
                if height > self.body_floor
                    && body.value().len()
                        == HEADER_BYTES
                            .checked_add(body_bytes)
                            .ok_or("shadow body size overflow")?
                    && body.value().get(..HEADER_BYTES) == Some(&index.value()[..HEADER_BYTES]) => {
            }
            _ => return Err("shadow prefix body range differs".into()),
        }
        let open_receipts = self.source.open_table(PERMANENT_RECEIPTS);
        let open_ids = self.source.open_table(PERMANENT_RECEIPT_IDS);
        let (receipt, id) = match (&open_receipts, &open_ids) {
            (Ok(receipts), Ok(ids)) => (
                receipts
                    .get(height)
                    .map_err(|_| "shadow prefix receipt unavailable")?,
                ids.get(height)
                    .map_err(|_| "shadow prefix receipt digest unavailable")?,
            ),
            (
                Err(redb::TableError::TableDoesNotExist(_)),
                Err(redb::TableError::TableDoesNotExist(_)),
            ) => (None, None),
            _ => return Err("shadow prefix receipt schema differs".into()),
        };
        let receipt_len = receipt
            .as_ref()
            .map(|entry| entry.value().len())
            .unwrap_or(0);
        let body_len = body.as_ref().map(|entry| entry.value().len()).unwrap_or(0);
        let bytes = body_len
            .checked_add(receipt_len)
            .and_then(|size| size.checked_mul(4))
            .and_then(|size| size.checked_add(64 * 1024))
            .ok_or("shadow prefix scratch overflow")?;
        let _memory = budget
            .reserve(bytes)
            .map_err(|_| "shadow prefix shared byte budget deferred")?;
        let mut txn = target
            .database
            .begin_write()
            .map_err(|_| "shadow prefix write unavailable")?;
        durable(&mut txn)?;
        {
            let mut table = txn
                .open_table(INDEX)
                .map_err(|_| "shadow prefix output index missing")?;
            if table
                .insert(height, index.value())
                .map_err(|_| "shadow prefix index write failed")?
                .is_some()
            {
                return Err("shadow prefix cannot replace an existing row".into());
            }
        }
        if let Some(body) = body {
            let (encoded_header, encoded_body) = decode(&target.engine, body.value())?;
            if encoded_header != header
                || encoded_body.commitment(target.engine.body_policy())? != header.body_commitment
            {
                return Err("shadow source body differs from the certified prefix".into());
            }
            txn.open_table(BLOCKS)
                .map_err(|_| "shadow prefix output body table missing")?
                .insert(height, body.value())
                .map_err(|_| "shadow prefix body write failed")?;
        }
        match (receipt, id) {
            (Some(receipt), Some(id)) => {
                if blake3::hash(receipt.value()).as_bytes().as_slice() != id.value() {
                    return Err("shadow prefix receipt digest differs".into());
                }
                receipts::copy_checked_receipt(
                    &txn,
                    target.engine.genesis(),
                    &header,
                    body_bytes,
                    receipt.value(),
                )?;
            }
            (None, None) if height > self.body_floor => {}
            _ => return Err("shadow prefix receipt pair missing".into()),
        }
        txn.commit()
            .map_err(|_| "shadow prefix row commit failed")?;
        self.next = height
            .checked_add(1)
            .ok_or("shadow prefix cursor overflow")?;
        Ok(true)
    }

    pub(in crate::eng2) fn start_replay(
        &self,
        target: &mut Store,
        budget: &crate::p2p::Budget,
    ) -> Result<crate::p2p::Reservation, String> {
        if self.next <= self.through
            || target.restart.is_some()
            || target.generation_control.is_some()
            || target.engine.state().height() != 0
            || target.engine.genesis().encode()? != self.genesis
        {
            return Err(
                "shadow checkpoint initialization requires a complete copied prefix".into(),
            );
        }
        let Some(header) = &self.lookup else {
            return budget
                .reserve(0)
                .map_err(|_| "shadow genesis budget unavailable".into());
        };
        let table = self
            .source
            .open_table(ANCHORS)
            .map_err(|_| "shadow checkpoint state unavailable")?;
        let snapshot = table
            .get(header.height)
            .map_err(|_| "shadow checkpoint state read failed")?
            .ok_or("shadow checkpoint state missing")?;
        let bytes = snapshot.value();
        if bytes.len() > self.limits.max_snapshot_bytes {
            return Err("shadow checkpoint state exceeds snapshot budget".into());
        }
        // Preserve the canonical owner's ordinary memory headroom. The inherited
        // archive calculation includes decoded state and reconstruction scratch.
        let memory = crate::eng2::runtime_export::archive_work::ArchiveWork::reserve(
            bytes.len(),
            self.provenance_bytes()?,
            budget,
        )
        .map_err(|error| {
            if error.budget.is_some_and(|failure| {
                matches!(
                    failure.failure,
                    Some(crate::p2p::ReserveFailure::Exhausted(_))
                )
            }) {
                return "shadow checkpoint prefix memory deferred".into();
            }
            error.to_string()
        })?;
        let genesis = Genesis::decode(&self.genesis)?;
        let snapshot =
            SnapshotState::from_committed_components(&genesis, header, bytes, self.limits)?;
        let engine = Engine::from_authenticated_local_state(genesis, snapshot, self.limits.chain)?;
        let mut txn = target
            .database
            .begin_write()
            .map_err(|_| "shadow state write unavailable")?;
        durable(&mut txn)?;
        {
            let index = txn
                .open_table(INDEX)
                .map_err(|_| "shadow checkpoint prefix unavailable")?;
            if index
                .len()
                .map_err(|_| "shadow checkpoint index count unavailable")?
                != self.through
            {
                return Err("shadow checkpoint index incomplete".into());
            }
        }
        {
            let mut meta = txn
                .open_table(META)
                .map_err(|_| "shadow state metadata unavailable")?;
            meta.insert(
                "head",
                head(&engine, header.execution_commitment).as_slice(),
            )
            .map_err(|_| "shadow checkpoint head write failed")?;
            txn.open_table(ANCHORS)
                .map_err(|_| "shadow state archive unavailable")?
                .insert(header.height, bytes)
                .map_err(|_| "shadow state archive write failed")?;
        }
        if let Some((height, seed)) = self.imported {
            imported::shadow_provenance(&self.source, height, seed, Some(&txn))?;
        }
        txn.commit()
            .map_err(|_| "shadow checkpoint state commit failed")?;
        target.engine = engine;
        if let Some((height, seed)) = self.imported {
            target.imported_prefix = height;
            target.import_seed = seed;
        }
        Ok(memory)
    }
}

fn durable(txn: &mut redb::WriteTransaction) -> Result<(), String> {
    txn.set_durability(Durability::Immediate)
        .map_err(|_| "shadow durability unavailable")?;
    txn.set_quick_repair(true);
    Ok(())
}
