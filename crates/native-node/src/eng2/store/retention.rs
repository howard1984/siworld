//! Bounded canonical proof expiry with an identity-sealed local retention cursor.
//! Only BLOCKS proof bodies are removed. Accepted headers, permanent receipts,
//! commitment/nullifier rows, execution state and checkpoint anchors are kept.
use super::*;
use crate::eng2::proof_retention::{
    self as policy, Checkpoint, Clock, Decision, Finality, Pause, Policy,
};
use redb::TableHandle;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("eng2-local-proof-retention-v1");
const MAX_METADATA_BYTES: usize = 16 * 1024 * 1024;
const MAX_FINALITY_ROWS: usize = 65536;
const MAX_BATCH_BLOCKS: usize = 4;
const MAX_BATCH_BYTES: usize = 64 * 1024 * 1024;
const MAX_FINALITY_BATCH: u64 = 128;
const DOMAIN: &str = "siworld eng2 local proof retention cursor v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    genesis: Hash,
    policy: Policy,
    credited_seconds: u64,
    checkpoint: Option<Checkpoint>,
    floor: u64,
    prefix: Hash,
    observed_through: u64,
    finality: BTreeMap<u64, Finality>,
}
impl Record {
    fn encode(&self) -> Result<Vec<u8>, String> {
        if self.finality.len() > MAX_FINALITY_ROWS {
            return Err("proof retention finality observation limit".into());
        }
        let bytes =
            serde_json::to_vec(self).map_err(|_| "proof retention cursor encoding failed")?;
        if bytes.len() > MAX_METADATA_BYTES {
            return Err("proof retention cursor byte limit".into());
        }
        Ok(bytes)
    }
}
fn seed(genesis: Hash) -> Hash {
    blake3::derive_key(DOMAIN, &genesis)
}
fn next(previous: Hash, height: u64, id: Hash) -> Hash {
    let mut h = blake3::Hasher::new_derive_key(DOMAIN);
    h.update(&previous);
    h.update(&height.to_le_bytes());
    h.update(&id);
    *h.finalize().as_bytes()
}
fn read_record(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    genesis: Hash,
    identity: &crate::identity::NativeIdentity,
) -> Result<Record, String> {
    if table
        .len()
        .map_err(|_| "proof retention cursor count unavailable")?
        != 2
    {
        return Err("proof retention cursor incomplete".into());
    }
    let payload = table
        .get("payload")
        .map_err(|_| "proof retention cursor unavailable")?
        .ok_or("proof retention cursor missing")?;
    let bytes = payload.value();
    if bytes.len() > MAX_METADATA_BYTES {
        return Err("proof retention cursor byte limit".into());
    }
    let seal = table
        .get("seal")
        .map_err(|_| "proof retention seal unavailable")?
        .ok_or("proof retention seal missing")?;
    identity
        .descriptor()
        .map_err(|_| "proof retention identity unavailable")?
        .verify_local_storage(blake3::derive_key(DOMAIN, bytes), seal.value())
        .map_err(|_| "proof retention cursor authentication failed")?;
    let record: Record =
        serde_json::from_slice(bytes).map_err(|_| "proof retention cursor decoding failed")?;
    if record.version != 1
        || record.genesis != genesis
        || record.finality.len() > MAX_FINALITY_ROWS
        || record.encode()? != bytes
    {
        return Err("proof retention cursor context rejected".into());
    }
    if matches!(record.policy, Policy::Miner { blocks } if blocks < policy::MIN_MINER_BLOCKS) {
        return Err("proof retention miner window rejected".into());
    }
    Ok(record)
}
fn write_record(
    transaction: &redb::WriteTransaction,
    record: &Record,
    identity: &crate::identity::NativeIdentity,
) -> Result<(), String> {
    let bytes = record.encode()?;
    let seal = identity
        .seal_local_storage(blake3::derive_key(DOMAIN, &bytes))
        .map_err(|_| "proof retention cursor sealing failed")?;
    let mut table = transaction
        .open_table(TABLE)
        .map_err(|_| "proof retention cursor table unavailable")?;
    table
        .insert("payload", bytes.as_slice())
        .map_err(|_| "proof retention cursor write failed")?;
    table
        .insert("seal", seal.as_slice())
        .map_err(|_| "proof retention seal write failed")?;
    Ok(())
}
fn authenticate_prefix(
    record: &Record,
    ids: &impl ReadableTable<u64, &'static [u8]>,
    receipts: &impl ReadableTable<u64, &'static [u8]>,
) -> Result<(), String> {
    let mut prefix = seed(record.genesis);
    for height in 1..=record.floor {
        let expected = ids
            .get(height)
            .map_err(|_| "proof retention receipt index unavailable")?
            .ok_or("proof retention permanent receipt index gap")?;
        let id: Hash = expected
            .value()
            .try_into()
            .map_err(|_| "proof retention receipt digest width")?;
        let row = receipts
            .get(height)
            .map_err(|_| "proof retention permanent receipt unavailable")?
            .ok_or("proof retention permanent receipt gap")?;
        if row.value().is_empty()
            || row.value().len() > super::super::wallet_history::codec::MAX_RECEIPT_BYTES
            || blake3::hash(row.value()).as_bytes() != &id
        {
            return Err("proof retention permanent receipt modified".into());
        }
        prefix = next(prefix, height, id);
    }
    if prefix != record.prefix {
        return Err("proof retention permanent prefix differs from local seal".into());
    }
    Ok(())
}

/// Carry the authenticated deletion cursor to a replayed copy. Timing and
/// checkpoint observations above the copied prefix cannot authorize pruning.
#[cfg(all(unix, feature = "eng2-runtime"))]
pub(super) fn copy_prefix_cursor(
    source: &redb::ReadTransaction,
    destination: &redb::WriteTransaction,
    genesis: Hash,
    identity: &crate::identity::NativeIdentity,
    through: u64,
) -> Result<(), String> {
    let table = match source.open_table(TABLE) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(()),
        Err(_) => return Err("shadow source retention cursor unavailable".into()),
    };
    let mut record = read_record(&table, genesis, identity)?;
    if record.floor > through {
        return Err("shadow prefix would omit previously pruned history".into());
    }
    record.finality.retain(|&height, _| height <= through);
    record.observed_through = record.observed_through.min(through);
    if record
        .checkpoint
        .is_some_and(|checkpoint| checkpoint.height > through)
    {
        record.checkpoint = None;
    }
    write_record(destination, &record, identity)
}

/// Verify the retention cursor during ordinary accepted-state recovery. A local
/// seal only authenticates this store's earlier verified history, never a peer.
pub(super) fn read_floor(
    transaction: &redb::ReadTransaction,
    genesis: Hash,
    identity: &crate::identity::NativeIdentity,
) -> Result<u64, String> {
    let table = match transaction.open_table(TABLE) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
        Err(_) => return Err("proof retention cursor table unavailable".into()),
    };
    let record = read_record(&table, genesis, identity)?;
    if record.floor != 0 {
        authenticate_prefix(
            &record,
            &transaction
                .open_table(PERMANENT_RECEIPT_IDS)
                .map_err(|_| "proof retention index missing")?,
            &transaction
                .open_table(PERMANENT_RECEIPTS)
                .map_err(|_| "proof retention receipts missing")?,
        )?;
    }
    Ok(record.floor)
}
pub(super) fn restored_floor(
    transaction: &redb::WriteTransaction,
    genesis: Hash,
    identity: &crate::identity::NativeIdentity,
) -> Result<u64, String> {
    if !transaction
        .list_tables()
        .map_err(|_| "proof retention schema unavailable")?
        .any(|table| table.name() == TABLE.name())
    {
        return Ok(0);
    }
    let record = read_record(
        &transaction
            .open_table(TABLE)
            .map_err(|_| "proof retention cursor unavailable")?,
        genesis,
        identity,
    )?;
    if record.floor != 0 {
        authenticate_prefix(
            &record,
            &transaction
                .open_table(PERMANENT_RECEIPT_IDS)
                .map_err(|_| "proof retention index missing")?,
            &transaction
                .open_table(PERMANENT_RECEIPTS)
                .map_err(|_| "proof retention receipts missing")?,
        )?;
    }
    Ok(record.floor)
}

#[derive(Clone, Copy, Debug)]
pub struct Report {
    pub paused: Option<Pause>,
    pub removed_blocks: usize,
    pub removed_encoded_bytes: usize,
    pub pruned_through: u64,
    pub more_eligible: bool,
    pub removed_branch_blocks: usize,
    pub removed_branch_encoded_bytes: usize,
}
/// A current owner's process-local clock. Creating this handle enables no
/// background task, network operation or proof deletion.
pub struct Maintenance {
    policy: Policy,
    clock: Option<Clock>,
    prior_payload: Option<Hash>,
    branch_cursor: Option<Hash>,
}
impl Maintenance {
    pub fn new(policy: Policy) -> Result<Self, String> {
        if matches!(policy, Policy::Miner { blocks } if blocks < policy::MIN_MINER_BLOCKS) {
            return Err("proof retention requires at least 24 miner blocks".into());
        }
        Ok(Self {
            policy,
            clock: None,
            prior_payload: None,
            branch_cursor: None,
        })
    }
    pub(crate) fn prune_branch_proofs(
        &mut self,
        branches: &mut super::super::branches::BranchStore,
        store: &Store,
        pins: &super::super::bootstrap::BodyPins,
        budget: &crate::p2p::Budget,
    ) -> Result<(usize, usize), String> {
        let (cursor, blocks, bytes) =
            branches.prune_expired_bodies(store, pins, self.branch_cursor, budget)?;
        self.branch_cursor = cursor;
        Ok((blocks, bytes))
    }
    /// At most four canonical blocks and 64 MiB per call. The caller is the
    /// existing exclusive owner; wall/monotonic clocks are local observations.
    /// No body can expire without a checked current 2-of-3 capability, complete
    /// permanent receipt and an authenticated local accepted-state restart seal.
    pub fn tick(
        &mut self,
        store: &mut Store,
        checkpoint: Option<&super::super::runtime_export::CertifiedCheckpoint>,
        now: u64,
        monotonic: u64,
        budget: &crate::p2p::Budget,
        pins: &super::super::bootstrap::BodyPins,
    ) -> Result<Report, String> {
        store.ensure_exportable()?;
        let context = store
            .restart
            .as_ref()
            .ok_or("proof retention requires authenticated local restart")?;
        let genesis = store.engine.genesis().id();
        let read = store
            .database
            .begin_read()
            .map_err(|_| "proof retention read unavailable")?;
        let mut record = match read.open_table(TABLE) {
            Ok(table) => read_record(&table, genesis, &context.identity)?,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                let mut prefix = seed(genesis);
                if store.imported_prefix != 0 {
                    let ids = read
                        .open_table(PERMANENT_RECEIPT_IDS)
                        .map_err(|_| "proof retention imported receipt index missing")?;
                    for height in 1..=store.imported_prefix {
                        let row = ids
                            .get(height)
                            .map_err(|_| "proof retention imported digest unavailable")?
                            .ok_or("proof retention imported digest missing")?;
                        let id: Hash = row
                            .value()
                            .try_into()
                            .map_err(|_| "proof retention imported digest width")?;
                        prefix = next(prefix, height, id);
                    }
                }
                Record {
                    version: 1,
                    genesis,
                    policy: self.policy,
                    credited_seconds: 0,
                    checkpoint: None,
                    floor: store.imported_prefix,
                    prefix,
                    observed_through: store.imported_prefix,
                    finality: BTreeMap::new(),
                }
            }
            Err(_) => return Err("proof retention cursor read failed".into()),
        };
        if record.policy != self.policy {
            return Err("proof retention policy change requires explicit migration".into());
        }
        let payload = blake3::derive_key(DOMAIN, &record.encode()?);
        if self.prior_payload != Some(payload) {
            self.clock = Some(Clock::resume(record.credited_seconds));
            if record.floor != 0 {
                authenticate_prefix(
                    &record,
                    &read
                        .open_table(PERMANENT_RECEIPT_IDS)
                        .map_err(|_| "proof retention index missing")?,
                    &read
                        .open_table(PERMANENT_RECEIPTS)
                        .map_err(|_| "proof retention receipts missing")?,
                )?;
            }
        }
        drop(read);
        let clock = self
            .clock
            .as_mut()
            .ok_or("proof retention clock unavailable")?;
        let clock_certain = clock.observe(now, monotonic).is_ok();
        record.credited_seconds = clock.credited_seconds;
        let current = checkpoint.map(|cp| cp.pruning_context(store)).transpose()?;
        if let Some(cp) = current {
            if let Some(previous) = record.checkpoint
                && (cp.height < previous.height
                    || (cp.height == previous.height
                        && (cp.block != previous.block || cp.published != previous.published)))
            {
                return Err(
                    "proof retention checkpoint regressed or changed publication time".into(),
                );
            }
            record.checkpoint = Some(cp);
        }
        let head = store.engine.state().height();
        if record.floor > head.saturating_sub(policy::MIN_MINER_BLOCKS) {
            return Err("proof retention floor exceeds rollback protection".into());
        }
        // Absence of a current capability never reuses persisted authority.
        let mut paused = match policy::decide(
            self.policy,
            0,
            [0; 32],
            head,
            current,
            now,
            clock_certain,
            record.credited_seconds,
            None,
        ) {
            Decision::Paused(reason) => Some(reason),
            _ => None,
        };
        if paused.is_none() && self.policy == Policy::Service {
            let cp = current.expect("checked capability");
            let end = cp
                .height
                .min(record.observed_through.saturating_add(MAX_FINALITY_BATCH));
            for height in record.observed_through.saturating_add(1)..=end {
                if record.finality.len() >= MAX_FINALITY_ROWS {
                    return Err("proof retention finality observation limit".into());
                }
                let block = store
                    .header(height)?
                    .id()
                    .map_err(|_| "proof retention finality header rejected")?;
                record.finality.entry(height).or_insert(Finality {
                    block,
                    credited_at: record.credited_seconds,
                });
                record.observed_through = height;
            }
        }
        let mut selected = Vec::new();
        let mut bytes = 0usize;
        if paused.is_none() {
            for height in record.floor.saturating_add(1)..=head {
                if pins.protects(height) {
                    break;
                }
                let block = store
                    .header(height)?
                    .id()
                    .map_err(|_| "proof retention header identity rejected")?;
                match policy::decide(
                    self.policy,
                    height,
                    block,
                    head,
                    current,
                    now,
                    clock_certain,
                    record.credited_seconds,
                    record.finality.get(&height).copied(),
                ) {
                    Decision::ExpireProofBody => {}
                    Decision::Keep => break,
                    Decision::Paused(reason) => {
                        paused = Some(reason);
                        break;
                    }
                }
                let size = store
                    .block_size(height)?
                    .checked_add(HEADER_BYTES)
                    .ok_or("proof retention body size overflow")?;
                if selected.len() == MAX_BATCH_BLOCKS
                    || size > MAX_BATCH_BYTES.saturating_sub(bytes)
                {
                    break;
                }
                store.materialize_permanent_receipt(height, budget)?;
                selected.push((height, block, size));
                bytes += size;
            }
        }
        let identity = &store
            .restart
            .as_ref()
            .ok_or("proof retention restart context disappeared")?
            .identity;
        let mut transaction = store
            .database
            .begin_write()
            .map_err(|_| "proof retention transaction unavailable")?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|_| "proof retention durability unavailable")?;
        transaction.set_quick_repair(true);
        {
            let mut bodies = transaction
                .open_table(BLOCKS)
                .map_err(|_| "proof retention body table unavailable")?;
            let receipts = transaction.open_table(PERMANENT_RECEIPTS).ok();
            let ids = transaction.open_table(PERMANENT_RECEIPT_IDS).ok();
            for &(height, block, size) in &selected {
                let receipt = receipts
                    .as_ref()
                    .ok_or("proof retention permanent receipts missing")?
                    .get(height)
                    .map_err(|_| "proof retention receipt unavailable")?
                    .ok_or("proof retention receipt missing")?;
                let id = ids
                    .as_ref()
                    .ok_or("proof retention receipt index missing")?
                    .get(height)
                    .map_err(|_| "proof retention receipt digest unavailable")?
                    .ok_or("proof retention receipt digest missing")?;
                let digest = *blake3::hash(receipt.value()).as_bytes();
                if id.value() != digest {
                    return Err("proof retention permanent receipt digest differs".into());
                }
                let header = store.header(height)?;
                let context = super::super::wallet_history::codec::Context::from_genesis(
                    &store.engine.genesis().encode()?,
                    genesis,
                )?;
                let public = super::super::wallet_history::codec::ReceiptBlock::decode(
                    &context,
                    &header
                        .encode()
                        .map_err(|_| "proof retention header encoding failed")?,
                    receipt.value(),
                )?;
                if public.body_bytes().checked_add(HEADER_BYTES) != Some(size) {
                    return Err("proof retention permanent public record length differs".into());
                }
                let body = bodies
                    .get(height)
                    .map_err(|_| "proof retention body lookup failed")?
                    .ok_or("proof retention body missing")?;
                if body.value().len() != size
                    || body.value().get(..HEADER_BYTES)
                        != Some(
                            header
                                .encode()
                                .map_err(|_| "proof retention header encoding failed")?
                                .as_slice(),
                        )
                    || header
                        .id()
                        .map_err(|_| "proof retention identity invalid")?
                        != block
                {
                    return Err("proof retention body differs from accepted header".into());
                }
                drop(body);
                bodies
                    .remove(height)
                    .map_err(|_| "proof retention body deletion failed")?
                    .ok_or("proof retention body disappeared")?;
                record.floor = height;
                record.prefix = next(record.prefix, height, digest);
                record.finality.remove(&height);
            }
        }
        write_record(&transaction, &record, identity)?;
        store.usable = false;
        transaction
            .commit()
            .map_err(|_| "proof retention commit uncertain; reopen required")?;
        store.usable = true;
        self.prior_payload = Some(blake3::derive_key(DOMAIN, &record.encode()?));
        Ok(Report {
            paused,
            removed_blocks: selected.len(),
            removed_encoded_bytes: bytes,
            pruned_through: record.floor,
            more_eligible: selected.len() == MAX_BATCH_BLOCKS,
            removed_branch_blocks: 0,
            removed_branch_encoded_bytes: 0,
        })
    }
}

#[cfg(test)]
mod tests;

impl Store {
    pub(crate) fn proof_retention_floor(&self) -> Result<u64, String> {
        self.ensure_exportable()?;
        let context = self
            .restart
            .as_ref()
            .ok_or("proof retention restart context unavailable")?;
        read_floor(
            &self
                .database
                .begin_read()
                .map_err(|_| "proof retention floor read unavailable")?,
            self.engine.genesis().id(),
            &context.identity,
        )
    }
}
