//! Durable reconstructed anchors, selected bodies and authenticated transfer pins.
//!
//! This cache never advertises an admitted head or a complete verified proof
//! tail. Restarted consumers must reauthenticate cached bytes through import.
use super::{
    admission::AdmissionPlan,
    snapshot::{ImportLimits, ImportedAnchor},
    state_components::Binding,
};
use crate::wire::Hash;
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use std::path::Path;

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("eng2-anchor-meta-v1");
const SNAPSHOTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("eng2-reconstructed-anchors-v1");
const LEASES: TableDefinition<u64, &[u8]> = TableDefinition::new("eng2-anchor-transfer-pins-v1");
const TAILS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("eng2-selected-body-cache-v1");
const PINNED_HEADERS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("eng2-transfer-selected-headers-v1");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context {
    pub network: Hash,
    pub genesis: Hash,
    pub rules_commitment: Hash,
}
#[derive(Clone, Copy)]
pub struct Policy {
    pub max_active_transfers: usize,
    pub max_lease_seconds: u64,
    pub max_chunk_bytes: usize,
    pub max_snapshot_bytes: usize,
}
impl Policy {
    fn check(self) -> Result<(), String> {
        if !(1..=64).contains(&self.max_active_transfers)
            || !(1..=86_400).contains(&self.max_lease_seconds)
            || !(1..=1_048_576).contains(&self.max_chunk_bytes)
            || self.max_snapshot_bytes == 0
        {
            return Err("invalid bounded archive transfer policy".into());
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredAnchor {
    pub height: u64,
    pub id: Hash,
    pub bytes: u64,
    pub digest: Hash,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredBody {
    pub height: u64,
    pub id: Hash,
    pub bytes: u64,
}
#[derive(Clone, Copy)]
pub struct TailChunk {
    pub height: u64,
    pub offset: u64,
    pub bytes: usize,
}
/// A local lease handle, bound to the authenticated transport peer identity.
pub struct Transfer {
    id: u64,
    peer: Hash,
    anchor: StoredAnchor,
    window: PinnedWindow,
}
impl Transfer {
    pub fn anchor(&self) -> StoredAnchor {
        self.anchor
    }
    pub fn window(&self) -> PinnedWindow {
        self.window
    }
}
/// Inclusive resource reservation, not an assertion of verified tail availability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PinnedWindow {
    pub anchor_height: u64,
    pub anchor_id: Hash,
    pub tip_height: u64,
    pub tip_id: Hash,
}
impl PinnedWindow {
    pub fn contains_height(self, height: u64) -> bool {
        self.anchor_height <= height && height <= self.tip_height
    }
}
pub struct Archive {
    database: Database,
    context: Context,
    policy: Policy,
}

impl Archive {
    pub fn store_tail_body(
        &mut self,
        plan: &AdmissionPlan,
        body: &super::body::Body,
        policy: super::body::Policy,
    ) -> Result<StoredBody, String> {
        let pin = plan.pin();
        if pin.network != self.context.network
            || pin.genesis != self.context.genesis
            || body.network != pin.network
            || body.height < pin.anchor_height.max(1)
            || body.height > pin.tip_height
        {
            return Err("tail body differs from archive context or selected window".into());
        }
        let header = plan
            .headers()
            .header(body.height)
            .ok_or("selected body header missing")?;
        if body.commitment(policy)? != header.body_commitment {
            return Err("tail body differs from selected header commitment".into());
        }
        let length = body.encoded_len(policy)?;
        let stored = StoredBody {
            height: body.height,
            id: header.id().map_err(|_| "selected body identity invalid")?,
            bytes: length as u64,
        };
        let mut record = Vec::new();
        record
            .try_reserve_exact(
                super::header::HEADER_BYTES
                    .checked_add(8)
                    .and_then(|n| n.checked_add(length))
                    .ok_or("tail record length overflow")?,
            )
            .map_err(|_| "tail record allocation unavailable")?;
        record.extend_from_slice(
            &header
                .encode()
                .map_err(|_| "selected header encoding invalid")?,
        );
        record.extend_from_slice(&stored.bytes.to_le_bytes());
        body.write_to(&mut record, policy)
            .map_err(|_| "selected body encoding unavailable")?;
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|_| "tail body transaction unavailable")?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|_| "tail body durability unavailable")?;
        {
            let mut table = transaction
                .open_table(TAILS)
                .map_err(|_| "tail body table unavailable")?;
            let differs = table
                .get(body_key(stored).as_slice())
                .map_err(|_| "tail body unreadable")?
                .is_some_and(|previous| previous.value() != record);
            if differs {
                return Err("immutable selected body bytes differ".into());
            }
            table
                .insert(body_key(stored).as_slice(), record.as_slice())
                .map_err(|_| "tail body write failed")?;
        }
        transaction
            .commit()
            .map_err(|_| "tail body durable commit failed")?;
        Ok(stored)
    }
    pub fn body_descriptor(
        &self,
        transfer: &Transfer,
        peer: Hash,
        height: u64,
        now: u64,
    ) -> Result<StoredBody, String> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| "tail body read unavailable")?;
        let id = self.leased_body_id(&transaction, transfer, peer, height, now)?;
        let table = transaction
            .open_table(TAILS)
            .map_err(|_| "tail body table unavailable")?;
        let key = body_key(StoredBody {
            height,
            id,
            bytes: 0,
        });
        let row = table
            .get(key.as_slice())
            .map_err(|_| "tail body unreadable")?
            .ok_or("selected proof body is not cached")?;
        let (stored, header, raw) =
            check_body_record(row.value(), self.context.network, height, id)?;
        header
            .verify_body(raw, raw.len())
            .map_err(|_| "cached selected body integrity differs")?;
        Ok(stored)
    }
    pub fn read_tail_chunk(
        &self,
        transfer: &Transfer,
        peer: Hash,
        request: TailChunk,
        now: u64,
    ) -> Result<Vec<u8>, String> {
        if request.bytes == 0 || request.bytes > self.policy.max_chunk_bytes {
            return Err("tail transfer chunk byte bound".into());
        }
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| "tail body read unavailable")?;
        let id = self.leased_body_id(&transaction, transfer, peer, request.height, now)?;
        let table = transaction
            .open_table(TAILS)
            .map_err(|_| "tail body table unavailable")?;
        let key = body_key(StoredBody {
            height: request.height,
            id,
            bytes: 0,
        });
        let row = table
            .get(key.as_slice())
            .map_err(|_| "tail body unreadable")?
            .ok_or("selected proof body is not cached")?;
        let (_, _, raw) = check_body_record(row.value(), self.context.network, request.height, id)?;
        let offset =
            usize::try_from(request.offset).map_err(|_| "tail transfer offset overflow")?;
        if offset > raw.len() {
            return Err("tail transfer offset exceeds body".into());
        }
        let end = offset
            .checked_add(request.bytes)
            .ok_or("tail transfer range overflow")?
            .min(raw.len());
        // The receiving admission session rechecks the complete header-bound
        // body before decoding or execution. Do not rehash it for every chunk.
        Ok(raw[offset..end].to_vec())
    }

    fn leased_body_id(
        &self,
        transaction: &redb::ReadTransaction,
        transfer: &Transfer,
        peer: Hash,
        height: u64,
        now: u64,
    ) -> Result<Hash, String> {
        if height == 0 || !transfer.window.contains_height(height) {
            return Err("requested body lies outside the reserved proof window".into());
        }
        let meta = transaction
            .open_table(META)
            .map_err(|_| "transfer metadata unavailable")?;
        if now
            < number(
                meta.get("clock")
                    .map_err(|_| "archive clock unreadable")?
                    .ok_or("archive clock missing")?
                    .value(),
            )?
        {
            return Err("tail transfer clock regressed".into());
        }
        let leases = transaction
            .open_table(LEASES)
            .map_err(|_| "transfer pin table unavailable")?;
        let row = leases
            .get(transfer.id)
            .map_err(|_| "transfer pin unreadable")?
            .ok_or("transfer pin is no longer active")?;
        let lease = Lease::decode(row.value())?;
        lease.matches(transfer, peer)?;
        if now < lease.issued || now > lease.deadline {
            return Err("tail transfer lies outside its reservation".into());
        }
        let headers = transaction
            .open_table(PINNED_HEADERS)
            .map_err(|_| "selected transfer headers unavailable")?;
        let key = pinned_header_key(transfer.id, height);
        let row = headers
            .get(key.as_slice())
            .map_err(|_| "selected transfer header unreadable")?
            .ok_or("selected transfer header missing")?;
        row.value()
            .try_into()
            .map_err(|_| "selected transfer header identity width".into())
    }
    pub fn create(path: &Path, context: Context, policy: Policy) -> Result<Self, String> {
        Self::open(path, context, policy, true)
    }
    pub fn open_existing(path: &Path, context: Context, policy: Policy) -> Result<Self, String> {
        Self::open(path, context, policy, false)
    }
    fn open(path: &Path, context: Context, policy: Policy, create: bool) -> Result<Self, String> {
        policy.check()?;
        if [context.network, context.genesis, context.rules_commitment].contains(&[0; 32]) {
            return Err("invalid archive network context".into());
        }
        let (file, created) = crate::store::open_regular_file(path, create)?;
        if created != create {
            return Err("anchor archive creation requires an absent path".into());
        }
        let backend = redb::backends::FileBackend::new(file)
            .map_err(|_| "anchor archive backend is unavailable")?;
        let mut builder = Database::builder();
        builder.set_cache_size(32 * 1024 * 1024);
        builder.set_repair_callback(|session| session.abort());
        let database = builder
            .create_with_backend(backend)
            .map_err(|_| "anchor archive is damaged or unavailable")?;
        if create {
            let mut transaction = database
                .begin_write()
                .map_err(|_| "anchor archive initialization failed")?;
            transaction
                .set_durability(Durability::Immediate)
                .map_err(|_| "anchor archive durability failed")?;
            {
                let mut meta = transaction
                    .open_table(META)
                    .map_err(|_| "anchor archive metadata creation failed")?;
                meta.insert("context", context_bytes(context).as_slice())
                    .map_err(|_| "anchor archive context write failed")?;
                for field in ["clock", "next"] {
                    meta.insert(field, 0u64.to_le_bytes().as_slice())
                        .map_err(|_| "anchor archive counter write failed")?;
                }
            }
            transaction
                .open_table(SNAPSHOTS)
                .map_err(|_| "anchor archive snapshot table failed")?;
            transaction
                .open_table(LEASES)
                .map_err(|_| "anchor archive lease table failed")?;
            transaction
                .open_table(TAILS)
                .map_err(|_| "anchor archive tail table failed")?;
            transaction
                .open_table(PINNED_HEADERS)
                .map_err(|_| "anchor archive header pin table failed")?;
            transaction
                .commit()
                .map_err(|_| "anchor archive initialization commit failed")?;
            crate::store::sync_parent(path)?;
        }
        {
            let transaction = database
                .begin_read()
                .map_err(|_| "anchor archive read failed")?;
            let meta = transaction
                .open_table(META)
                .map_err(|_| "anchor archive context is missing")?;
            if meta
                .get("context")
                .map_err(|_| "anchor archive context unreadable")?
                .ok_or("anchor archive context missing")?
                .value()
                != context_bytes(context)
            {
                return Err("anchor archive network or rules differ".into());
            }
            for field in ["clock", "next"] {
                let value = meta
                    .get(field)
                    .map_err(|_| "anchor archive counter unreadable")?
                    .ok_or("anchor archive counter missing")?;
                number(value.value())?;
            }
            transaction
                .open_table(SNAPSHOTS)
                .map_err(|_| "anchor archive snapshot table missing")?;
            transaction
                .open_table(LEASES)
                .map_err(|_| "anchor archive transfer table missing")?;
            transaction
                .open_table(TAILS)
                .map_err(|_| "anchor archive body table missing")?;
            transaction
                .open_table(PINNED_HEADERS)
                .map_err(|_| "anchor archive header pin table missing")?;
        }
        Ok(Self {
            database,
            context,
            policy,
        })
    }
    pub fn store_anchor(
        &mut self,
        anchor: &ImportedAnchor,
        plan: &AdmissionPlan,
        limits: ImportLimits,
    ) -> Result<StoredAnchor, String> {
        let pin = anchor.pin();
        if pin != plan.pin()
            || pin.network != self.context.network
            || pin.genesis != self.context.genesis
            || anchor.binding().rules_commitment != self.context.rules_commitment
        {
            return Err("stored anchor does not match archive context or plan".into());
        }
        let parent = if pin.anchor_height == 0 {
            [0; 32]
        } else {
            plan.headers()
                .id(pin.anchor_height - 1)
                .map_err(|_| "stored anchor parent unavailable")?
        };
        let components = anchor.state().canonical_components(
            Binding {
                genesis: self.context.genesis,
                rules_commitment: self.context.rules_commitment,
                parent,
            },
            limits.chain,
        )?;
        let raw = super::snapshot::encode_components(&components, limits)?;
        if raw.len() > self.policy.max_snapshot_bytes {
            return Err("stored anchor exceeds archive byte bound".into());
        }
        let stored = StoredAnchor {
            height: pin.anchor_height,
            id: pin.anchor_id,
            bytes: raw.len() as u64,
            digest: *blake3::hash(&raw).as_bytes(),
        };
        let mut record = Vec::with_capacity(40 + raw.len());
        record.extend_from_slice(&stored.digest);
        record.extend_from_slice(&stored.bytes.to_le_bytes());
        record.extend_from_slice(&raw);
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|_| "anchor write transaction unavailable")?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|_| "anchor write durability unavailable")?;
        {
            let mut table = transaction
                .open_table(SNAPSHOTS)
                .map_err(|_| "anchor table unavailable")?;
            let previous = table
                .get(anchor_key(stored).as_slice())
                .map_err(|_| "stored anchor unreadable")?
                .map(|value| value.value().to_vec());
            if previous.as_ref().is_some_and(|value| value != &record) {
                return Err("immutable stored anchor bytes differ".into());
            }
            table
                .insert(anchor_key(stored).as_slice(), record.as_slice())
                .map_err(|_| "anchor write failed")?;
        }
        transaction
            .commit()
            .map_err(|_| "anchor durable commit failed")?;
        Ok(stored)
    }
    pub fn load_anchor(&self, anchor: StoredAnchor) -> Result<Vec<u8>, String> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| "anchor read transaction unavailable")?;
        let table = transaction
            .open_table(SNAPSHOTS)
            .map_err(|_| "anchor table unavailable")?;
        let row = table
            .get(anchor_key(anchor).as_slice())
            .map_err(|_| "stored anchor unreadable")?
            .ok_or("stored anchor missing")?;
        let raw = check_record(row.value(), anchor, self.policy)?;
        if blake3::hash(raw).as_bytes() != &anchor.digest {
            return Err("stored anchor integrity differs".into());
        }
        Ok(raw.to_vec())
    }
    pub fn begin_transfer(
        &mut self,
        anchor: StoredAnchor,
        plan: &AdmissionPlan,
        peer: Hash,
        now: u64,
        seconds: u64,
    ) -> Result<Transfer, String> {
        if peer == [0; 32] || seconds == 0 || seconds > self.policy.max_lease_seconds {
            return Err("invalid transfer peer or duration".into());
        }
        let pin = plan.pin();
        if pin.network != self.context.network
            || pin.genesis != self.context.genesis
            || pin.anchor_height != anchor.height
            || pin.anchor_id != anchor.id
        {
            return Err("transfer window differs from source-selected anchor".into());
        }
        let window = PinnedWindow {
            anchor_height: anchor.height,
            anchor_id: anchor.id,
            tip_height: pin.tip_height,
            tip_id: pin.tip_id,
        };
        let deadline = now
            .checked_add(seconds)
            .ok_or("transfer deadline overflow")?;
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|_| "transfer reservation unavailable")?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|_| "transfer durability unavailable")?;
        let id;
        {
            let snapshots = transaction
                .open_table(SNAPSHOTS)
                .map_err(|_| "anchor table unavailable")?;
            let row = snapshots
                .get(anchor_key(anchor).as_slice())
                .map_err(|_| "transfer anchor unreadable")?
                .ok_or("transfer anchor missing")?;
            check_record(row.value(), anchor, self.policy)?;
            let leases = transaction
                .open_table(LEASES)
                .map_err(|_| "transfer pin table unavailable")?;
            let mut count = 0usize;
            for row in leases
                .iter()
                .map_err(|_| "transfer pin count unavailable")?
            {
                let (_, value) = row.map_err(|_| "transfer pin row unreadable")?;
                Lease::decode(value.value())?;
                count += 1;
            }
            if count >= self.policy.max_active_transfers {
                return Err("active transfer limit reached".into());
            }
            let mut meta = transaction
                .open_table(META)
                .map_err(|_| "transfer metadata unavailable")?;
            advance_clock(&mut meta, now)?;
            let previous = number(
                meta.get("next")
                    .map_err(|_| "transfer sequence unreadable")?
                    .ok_or("transfer sequence missing")?
                    .value(),
            )?;
            id = previous
                .checked_add(1)
                .ok_or("transfer sequence overflow")?;
            meta.insert("next", id.to_le_bytes().as_slice())
                .map_err(|_| "transfer sequence write failed")?;
        }
        let lease = Lease {
            key: anchor_key(anchor),
            peer,
            issued: now,
            deadline,
            tip_height: window.tip_height,
            tip_id: window.tip_id,
        };
        transaction
            .open_table(LEASES)
            .map_err(|_| "transfer pin table unavailable")?
            .insert(id, lease.encode().as_slice())
            .map_err(|_| "transfer pin write failed")?;
        {
            let mut headers = transaction
                .open_table(PINNED_HEADERS)
                .map_err(|_| "selected transfer header table unavailable")?;
            for height in window.anchor_height..=window.tip_height {
                let selected = plan
                    .headers()
                    .id(height)
                    .map_err(|_| "selected transfer header missing")?;
                headers
                    .insert(
                        pinned_header_key(id, height).as_slice(),
                        selected.as_slice(),
                    )
                    .map_err(|_| "selected transfer header pin failed")?;
            }
        }
        transaction
            .commit()
            .map_err(|_| "transfer reservation commit failed")?;
        Ok(Transfer {
            id,
            peer,
            anchor,
            window,
        })
    }
    pub fn read_chunk(
        &self,
        transfer: &Transfer,
        peer: Hash,
        offset: u64,
        length: usize,
        now: u64,
    ) -> Result<Vec<u8>, String> {
        if peer != transfer.peer || length == 0 || length > self.policy.max_chunk_bytes {
            return Err("transfer peer or chunk bound differs".into());
        }
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| "transfer read unavailable")?;
        let meta = transaction
            .open_table(META)
            .map_err(|_| "transfer metadata unavailable")?;
        if now
            < number(
                meta.get("clock")
                    .map_err(|_| "archive clock unreadable")?
                    .ok_or("archive clock missing")?
                    .value(),
            )?
        {
            return Err("transfer clock regressed".into());
        }
        let leases = transaction
            .open_table(LEASES)
            .map_err(|_| "transfer pin table unavailable")?;
        let row = leases
            .get(transfer.id)
            .map_err(|_| "transfer pin unreadable")?
            .ok_or("transfer pin is no longer active")?;
        let lease = Lease::decode(row.value())?;
        lease.matches(transfer, peer)?;
        if now < lease.issued || now > lease.deadline {
            return Err("transfer clock is outside its reservation".into());
        }
        let table = transaction
            .open_table(SNAPSHOTS)
            .map_err(|_| "anchor table unavailable")?;
        let row = table
            .get(lease.key.as_slice())
            .map_err(|_| "transfer snapshot unreadable")?
            .ok_or("pinned snapshot is missing")?;
        let raw = check_record(row.value(), transfer.anchor, self.policy)?;
        let offset = usize::try_from(offset).map_err(|_| "transfer offset overflow")?;
        if offset > raw.len() {
            return Err("transfer offset exceeds snapshot".into());
        }
        let end = offset
            .checked_add(length)
            .ok_or("transfer range overflow")?
            .min(raw.len());
        Ok(raw[offset..end].to_vec())
    }
    pub fn complete(&mut self, transfer: Transfer, peer: Hash) -> Result<(), String> {
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|_| "transfer completion unavailable")?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|_| "transfer completion durability unavailable")?;
        {
            let mut leases = transaction
                .open_table(LEASES)
                .map_err(|_| "transfer pin table unavailable")?;
            {
                let row = leases
                    .get(transfer.id)
                    .map_err(|_| "transfer pin unreadable")?
                    .ok_or("transfer pin missing")?;
                Lease::decode(row.value())?.matches(&transfer, peer)?;
            }
            leases
                .remove(transfer.id)
                .map_err(|_| "transfer pin release failed")?;
        }
        remove_header_pins(&transaction, transfer.id, transfer.window)?;
        transaction
            .commit()
            .map_err(|_| "transfer completion commit failed".to_owned())
    }
    pub fn expire(&mut self, now: u64) -> Result<usize, String> {
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|_| "transfer expiry unavailable")?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|_| "transfer expiry durability unavailable")?;
        {
            advance_clock(
                &mut transaction
                    .open_table(META)
                    .map_err(|_| "transfer metadata unavailable")?,
                now,
            )?;
        }
        let mut expired = Vec::new();
        {
            let mut leases = transaction
                .open_table(LEASES)
                .map_err(|_| "transfer pin table unavailable")?;
            for row in leases
                .iter()
                .map_err(|_| "transfer pin iteration unavailable")?
            {
                let (id, value) = row.map_err(|_| "transfer pin row unreadable")?;
                let lease = Lease::decode(value.value())?;
                if lease.deadline < now {
                    expired.push((id.value(), lease.window()));
                }
            }
            for (id, _) in &expired {
                leases
                    .remove(*id)
                    .map_err(|_| "transfer pin expiry failed")?;
            }
        }
        for (id, window) in &expired {
            remove_header_pins(&transaction, *id, *window)?;
        }
        transaction
            .commit()
            .map_err(|_| "transfer expiry commit failed")?;
        Ok(expired.len())
    }
    pub fn pinned_anchors(&self) -> Result<Vec<(u64, Hash)>, String> {
        Ok(self
            .pinned_windows()?
            .into_iter()
            .map(|window| (window.anchor_height, window.anchor_id))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect())
    }
    pub fn pinned_windows(&self) -> Result<Vec<PinnedWindow>, String> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| "transfer pin read unavailable")?;
        let table = transaction
            .open_table(LEASES)
            .map_err(|_| "transfer pin table unavailable")?;
        let mut pinned = std::collections::BTreeSet::new();
        for row in table
            .iter()
            .map_err(|_| "transfer pin iteration unavailable")?
        {
            let (_, value) = row.map_err(|_| "transfer pin row unreadable")?;
            let lease = Lease::decode(value.value())?;
            pinned.insert(PinnedWindow {
                anchor_height: u64::from_be_bytes(
                    lease.key[..8].try_into().expect("fixed anchor height"),
                ),
                anchor_id: lease.key[8..].try_into().expect("fixed anchor ID"),
                tip_height: lease.tip_height,
                tip_id: lease.tip_id,
            });
        }
        Ok(pinned.into_iter().collect())
    }
}

fn context_bytes(context: Context) -> Vec<u8> {
    let mut bytes = b"SW2A\x02\x00".to_vec();
    for value in [context.network, context.genesis, context.rules_commitment] {
        bytes.extend_from_slice(&value);
    }
    bytes
}
fn body_key(body: StoredBody) -> [u8; 40] {
    let mut key = [0; 40];
    key[..8].copy_from_slice(&body.height.to_be_bytes());
    key[8..].copy_from_slice(&body.id);
    key
}
fn pinned_header_key(transfer: u64, height: u64) -> [u8; 16] {
    let mut key = [0; 16];
    key[..8].copy_from_slice(&transfer.to_be_bytes());
    key[8..].copy_from_slice(&height.to_be_bytes());
    key
}
fn remove_header_pins(
    transaction: &redb::WriteTransaction,
    transfer: u64,
    window: PinnedWindow,
) -> Result<(), String> {
    let mut headers = transaction
        .open_table(PINNED_HEADERS)
        .map_err(|_| "selected transfer header table unavailable")?;
    for height in window.anchor_height..=window.tip_height {
        headers
            .remove(pinned_header_key(transfer, height).as_slice())
            .map_err(|_| "selected transfer header release failed")?;
    }
    Ok(())
}
fn check_body_record(
    record: &[u8],
    network: Hash,
    height: u64,
    id: Hash,
) -> Result<(StoredBody, super::header::Header, &[u8]), String> {
    let prefix = super::header::HEADER_BYTES + 8;
    if record.len() < prefix {
        return Err("truncated cached selected body".into());
    }
    let header = super::header::Header::decode(&record[..super::header::HEADER_BYTES], &network)
        .map_err(|_| "cached selected body header invalid")?;
    let bytes = number(&record[super::header::HEADER_BYTES..prefix])?;
    if header.height != height
        || header.id().map_err(|_| "cached body identity invalid")? != id
        || bytes != (record.len() - prefix) as u64
    {
        return Err("cached selected body descriptor differs".into());
    }
    Ok((StoredBody { height, id, bytes }, header, &record[prefix..]))
}
fn anchor_key(anchor: StoredAnchor) -> [u8; 40] {
    let mut key = [0; 40];
    key[..8].copy_from_slice(&anchor.height.to_be_bytes());
    key[8..].copy_from_slice(&anchor.id);
    key
}
fn number(bytes: &[u8]) -> Result<u64, String> {
    Ok(u64::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| "invalid archive counter width")?,
    ))
}
fn advance_clock(meta: &mut redb::Table<&str, &[u8]>, now: u64) -> Result<(), String> {
    let previous = number(
        meta.get("clock")
            .map_err(|_| "archive clock unreadable")?
            .ok_or("archive clock missing")?
            .value(),
    )?;
    if now == 0 || now < previous {
        return Err("archive clock is uncertain or regressed".into());
    }
    meta.insert("clock", now.to_le_bytes().as_slice())
        .map_err(|_| "archive clock write failed")?;
    Ok(())
}
fn check_record(bytes: &[u8], anchor: StoredAnchor, policy: Policy) -> Result<&[u8], String> {
    if bytes.len() < 40
        || bytes.len() - 40 > policy.max_snapshot_bytes
        || bytes[..32] != anchor.digest
        || number(&bytes[32..40])? != anchor.bytes
        || anchor.bytes != (bytes.len() - 40) as u64
    {
        return Err("stored snapshot descriptor differs".into());
    }
    Ok(&bytes[40..])
}
struct Lease {
    key: [u8; 40],
    peer: Hash,
    issued: u64,
    deadline: u64,
    tip_height: u64,
    tip_id: Hash,
}
impl Lease {
    fn window(&self) -> PinnedWindow {
        PinnedWindow {
            anchor_height: u64::from_be_bytes(
                self.key[..8].try_into().expect("fixed anchor height"),
            ),
            anchor_id: self.key[8..].try_into().expect("fixed anchor ID"),
            tip_height: self.tip_height,
            tip_id: self.tip_id,
        }
    }
    fn encode(&self) -> [u8; 128] {
        let mut bytes = [0; 128];
        bytes[..40].copy_from_slice(&self.key);
        bytes[40..72].copy_from_slice(&self.peer);
        bytes[72..80].copy_from_slice(&self.issued.to_le_bytes());
        bytes[80..88].copy_from_slice(&self.deadline.to_le_bytes());
        bytes[88..96].copy_from_slice(&self.tip_height.to_le_bytes());
        bytes[96..].copy_from_slice(&self.tip_id);
        bytes
    }
    fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 128 {
            return Err("invalid transfer pin encoding".into());
        }
        let result = Self {
            key: bytes[..40].try_into().expect("fixed anchor key"),
            peer: bytes[40..72].try_into().expect("fixed peer identity"),
            issued: number(&bytes[72..80])?,
            deadline: number(&bytes[80..88])?,
            tip_height: number(&bytes[88..96])?,
            tip_id: bytes[96..].try_into().expect("fixed transfer head"),
        };
        let anchor_height =
            u64::from_be_bytes(result.key[..8].try_into().expect("fixed anchor height"));
        if result.peer == [0; 32]
            || result.issued == 0
            || result.deadline <= result.issued
            || result
                .tip_height
                .saturating_sub(super::selection::TAIL_BLOCKS)
                != anchor_height
        {
            return Err("invalid transfer pin context".into());
        }
        Ok(result)
    }
    fn matches(&self, transfer: &Transfer, peer: Hash) -> Result<(), String> {
        if peer != transfer.peer
            || peer != self.peer
            || self.key != anchor_key(transfer.anchor)
            || self.tip_height != transfer.window.tip_height
            || self.tip_id != transfer.window.tip_id
        {
            return Err("transfer handle or authenticated peer differs".into());
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::snapshot::{self, encode_components};
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    struct Temp(std::path::PathBuf);
    impl Temp {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(1);
            let path = std::env::temp_dir().join(format!(
                "eng2-anchor-cache-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> std::path::PathBuf {
            self.0.join("anchors.redb")
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn policy() -> Policy {
        Policy {
            max_active_transfers: 2,
            max_lease_seconds: 3600,
            max_chunk_bytes: 1024,
            max_snapshot_bytes: 32 * 1024 * 1024,
        }
    }
    fn fixture() -> (
        Context,
        ImportedAnchor,
        AdmissionPlan,
        ImportLimits,
        Vec<u8>,
    ) {
        let bootstrap = snapshot::tests::bootstrap();
        let limits = snapshot::tests::limits();
        let binding = snapshot::tests::binding(&bootstrap, [0; 32]);
        let plan = snapshot::tests::plan(&bootstrap, [8; 32], 1);
        let raw = encode_components(
            &bootstrap
                .canonical_components(binding, limits.chain)
                .unwrap(),
            limits,
        )
        .unwrap();
        let anchor =
            ImportedAnchor::reconstruct(&plan, &bootstrap, binding.rules_commitment, &raw, limits)
                .unwrap();
        (
            Context {
                network: bootstrap.network(),
                genesis: bootstrap.tip(),
                rules_commitment: binding.rules_commitment,
            },
            anchor,
            plan,
            limits,
            raw,
        )
    }
    pub(crate) fn body_fixture() -> (
        Context,
        ImportedAnchor,
        AdmissionPlan,
        ImportLimits,
        super::super::body::Body,
    ) {
        use super::super::header::Header;
        use super::super::selection::{HeaderRules, SourceObservation, VerifiedHeaders};
        let bootstrap = snapshot::tests::bootstrap();
        let limits = snapshot::tests::limits();
        let binding = snapshot::tests::binding(&bootstrap, [0; 32]);
        let mut body = super::super::body::tests::body();
        body.network = bootstrap.network();
        body.height = 1;
        for claim in &mut body.fund_claims {
            claim.network = body.network;
            claim.height = body.height;
        }
        for action in &mut body.governance {
            action.action.network = body.network;
        }
        for transaction in &mut body.transactions {
            transaction.record.snapshot = crate::wire::Snapshot {
                height: 0,
                block_id: bootstrap.tip(),
            };
        }
        body.transactions
            .sort_by_key(|transaction| transaction.record.statement_id(&body.network));
        let config = &bootstrap.chain.config;
        let rules = HeaderRules {
            network: config.network,
            genesis: bootstrap.tip(),
            genesis_timestamp: config.genesis_timestamp,
            genesis_target: config.genesis_target,
            target_interval: config.target_interval,
            pow_iterations: config.pow_iterations,
            max_headers: 1000,
        };
        let header = Header {
            network: rules.network,
            height: 1,
            parent: rules.genesis,
            timestamp: rules.genesis_timestamp + 300,
            target: [255; 32],
            execution_commitment: [8; 32],
            body_commitment: body
                .commitment(super::super::body::tests::policy())
                .unwrap(),
            nonce: 0,
        };
        let headers = VerifiedHeaders::verify(rules, vec![header]).unwrap();
        let sources: Vec<_> = (1..=3)
            .map(|id| SourceObservation {
                authenticated_identity: [id; 32],
                transport_address: std::net::IpAddr::from([10, id, 0, 1]),
                chain: &headers,
            })
            .collect();
        let plan = AdmissionPlan::select(&sources, siworld_core::pow::Work::one()).unwrap();
        let raw = encode_components(
            &bootstrap
                .canonical_components(binding, limits.chain)
                .unwrap(),
            limits,
        )
        .unwrap();
        let anchor =
            ImportedAnchor::reconstruct(&plan, &bootstrap, binding.rules_commitment, &raw, limits)
                .unwrap();
        (
            Context {
                network: bootstrap.network(),
                genesis: bootstrap.tip(),
                rules_commitment: binding.rules_commitment,
            },
            anchor,
            plan,
            limits,
            body,
        )
    }
    #[test]
    fn selected_header_body_bytes_and_complete_window_pins_survive_restart() {
        let temp = Temp::new();
        let (context, anchor, plan, limits, body) = body_fixture();
        let body_policy = super::super::body::tests::policy();
        let raw = body.encode(body_policy).unwrap();
        let mut archive = Archive::create(&temp.path(), context, policy()).unwrap();
        let stored_anchor = archive.store_anchor(&anchor, &plan, limits).unwrap();
        let stored_body = archive.store_tail_body(&plan, &body, body_policy).unwrap();
        let transfer = archive
            .begin_transfer(stored_anchor, &plan, [7; 32], 100, 60)
            .unwrap();
        drop(archive);
        let mut archive = Archive::open_existing(&temp.path(), context, policy()).unwrap();
        assert_eq!(
            archive.body_descriptor(&transfer, [7; 32], 1, 120).unwrap(),
            stored_body
        );
        let mut downloaded = Vec::new();
        while downloaded.len() < raw.len() {
            downloaded.extend_from_slice(
                &archive
                    .read_tail_chunk(
                        &transfer,
                        [7; 32],
                        TailChunk {
                            height: 1,
                            offset: downloaded.len() as u64,
                            bytes: 1024,
                        },
                        120,
                    )
                    .unwrap(),
            );
        }
        assert_eq!(downloaded, raw);
        assert!(
            archive
                .read_tail_chunk(
                    &transfer,
                    [8; 32],
                    TailChunk {
                        height: 1,
                        offset: 0,
                        bytes: 1
                    },
                    120
                )
                .is_err()
        );
        assert!(archive.body_descriptor(&transfer, [7; 32], 2, 120).is_err());
        assert!(archive.body_descriptor(&transfer, [7; 32], 1, 161).is_err());
        assert_eq!(archive.pinned_windows().unwrap().len(), 1);
        archive.complete(transfer, [7; 32]).unwrap();
        assert!(archive.pinned_windows().unwrap().is_empty());
    }
    #[test]
    fn tail_storage_rejects_a_body_that_does_not_match_the_selected_header() {
        let temp = Temp::new();
        let (context, _anchor, plan, _limits, mut body) = body_fixture();
        let mut archive = Archive::create(&temp.path(), context, policy()).unwrap();
        body.settlement_proof[0] ^= 1;
        assert!(
            archive
                .store_tail_body(&plan, &body, super::super::body::tests::policy())
                .is_err()
        );
    }
    #[test]
    fn cached_body_corruption_is_detected_and_transfer_header_pins_release_atomically() {
        let temp = Temp::new();
        let (context, anchor, plan, limits, body) = body_fixture();
        let body_policy = super::super::body::tests::policy();
        let mut archive = Archive::create(&temp.path(), context, policy()).unwrap();
        let stored = archive.store_anchor(&anchor, &plan, limits).unwrap();
        let body = archive.store_tail_body(&plan, &body, body_policy).unwrap();
        let transfer = archive
            .begin_transfer(stored, &plan, [7; 32], 100, 60)
            .unwrap();
        let transaction = archive.database.begin_write().unwrap();
        {
            let mut table = transaction.open_table(TAILS).unwrap();
            let mut damaged = table
                .get(body_key(body).as_slice())
                .unwrap()
                .unwrap()
                .value()
                .to_vec();
            *damaged.last_mut().unwrap() ^= 1;
            table
                .insert(body_key(body).as_slice(), damaged.as_slice())
                .unwrap();
        }
        transaction.commit().unwrap();
        assert!(archive.body_descriptor(&transfer, [7; 32], 1, 120).is_err());
        assert_eq!(archive.pinned_windows().unwrap(), vec![transfer.window()]);
        archive.complete(transfer, [7; 32]).unwrap();
        let transaction = archive.database.begin_read().unwrap();
        assert_eq!(
            transaction
                .open_table(PINNED_HEADERS)
                .unwrap()
                .iter()
                .unwrap()
                .count(),
            0
        );
    }
    #[test]
    fn actual_reconstructed_anchor_and_its_pins_survive_a_database_reopen() {
        let temp = Temp::new();
        let (context, anchor, plan, limits, raw) = fixture();
        let mut archive = Archive::create(&temp.path(), context, policy()).unwrap();
        let stored = archive.store_anchor(&anchor, &plan, limits).unwrap();
        assert_eq!(archive.load_anchor(stored).unwrap(), raw);
        let transfer = archive
            .begin_transfer(stored, &plan, [7; 32], 100, 60)
            .unwrap();
        assert_eq!(
            archive.pinned_anchors().unwrap(),
            vec![(stored.height, stored.id)]
        );
        drop(archive);
        let mut reopened = Archive::open_existing(&temp.path(), context, policy()).unwrap();
        assert_eq!(
            reopened
                .read_chunk(&transfer, [7; 32], 0, 1024, 120)
                .unwrap(),
            raw[..1024]
        );
        assert_eq!(reopened.load_anchor(stored).unwrap(), raw);
        let mut downloaded = Vec::new();
        while downloaded.len() < raw.len() {
            let chunk = reopened
                .read_chunk(&transfer, [7; 32], downloaded.len() as u64, 1024, 120)
                .unwrap();
            assert!(!chunk.is_empty());
            downloaded.extend_from_slice(&chunk);
        }
        assert_eq!(downloaded, raw);
        reopened.complete(transfer, [7; 32]).unwrap();
        assert!(reopened.pinned_anchors().unwrap().is_empty());
    }
    #[test]
    fn peer_identity_chunk_bounds_capacity_expiry_and_clock_regression_are_enforced() {
        let temp = Temp::new();
        let (context, anchor, plan, limits, _) = fixture();
        let mut archive = Archive::create(&temp.path(), context, policy()).unwrap();
        let stored = archive.store_anchor(&anchor, &plan, limits).unwrap();
        let one = archive
            .begin_transfer(stored, &plan, [1; 32], 100, 60)
            .unwrap();
        let two = archive
            .begin_transfer(stored, &plan, [2; 32], 100, 60)
            .unwrap();
        assert!(
            archive
                .begin_transfer(stored, &plan, [3; 32], 100, 60)
                .is_err()
        );
        assert!(archive.read_chunk(&one, [2; 32], 0, 1, 101).is_err());
        assert!(archive.read_chunk(&one, [1; 32], 0, 1025, 101).is_err());
        assert!(
            archive
                .read_chunk(&one, [1; 32], stored.bytes + 1, 1, 101)
                .is_err()
        );
        assert!(archive.read_chunk(&one, [1; 32], 0, 1, 99).is_err());
        assert!(archive.read_chunk(&one, [1; 32], 0, 1, 161).is_err());
        assert_eq!(archive.pinned_anchors().unwrap().len(), 1);
        assert!(archive.expire(99).is_err());
        assert_eq!(archive.expire(160).unwrap(), 0);
        assert_eq!(archive.expire(161).unwrap(), 2);
        assert!(archive.read_chunk(&two, [2; 32], 0, 1, 161).is_err());
        assert!(archive.pinned_anchors().unwrap().is_empty());
        assert!(
            archive
                .begin_transfer(stored, &plan, [0; 32], 162, 60)
                .is_err()
        );
        assert!(
            archive
                .begin_transfer(stored, &plan, [3; 32], 162, 3601)
                .is_err()
        );
        assert!(
            archive
                .begin_transfer(stored, &plan, [3; 32], 162, 60)
                .is_ok()
        );
    }
    #[test]
    fn wrong_network_or_existing_path_never_reinitializes_the_archive() {
        let temp = Temp::new();
        let (context, _, _, _, _) = fixture();
        assert!(Archive::open_existing(&temp.path(), context, policy()).is_err());
        drop(Archive::create(&temp.path(), context, policy()).unwrap());
        assert!(Archive::create(&temp.path(), context, policy()).is_err());
        let other = Context {
            network: [9; 32],
            ..context
        };
        assert!(Archive::open_existing(&temp.path(), other, policy()).is_err());
        assert!(Archive::open_existing(&temp.path(), context, policy()).is_ok());
    }

    #[test]
    fn empty_files_and_corrupted_snapshot_records_are_preserved_and_rejected() {
        let temp = Temp::new();
        let (context, anchor, plan, limits, _) = fixture();
        let empty = temp.0.join("empty.redb");
        std::fs::write(&empty, []).unwrap();
        assert!(Archive::open_existing(&empty, context, policy()).is_err());
        assert_eq!(std::fs::metadata(&empty).unwrap().len(), 0);
        let mut archive = Archive::create(&temp.path(), context, policy()).unwrap();
        let stored = archive.store_anchor(&anchor, &plan, limits).unwrap();
        let transaction = archive.database.begin_write().unwrap();
        {
            let mut table = transaction.open_table(SNAPSHOTS).unwrap();
            let mut bytes = table
                .get(anchor_key(stored).as_slice())
                .unwrap()
                .unwrap()
                .value()
                .to_vec();
            *bytes.last_mut().unwrap() ^= 1;
            table
                .insert(anchor_key(stored).as_slice(), bytes.as_slice())
                .unwrap();
        }
        transaction.commit().unwrap();
        assert!(archive.load_anchor(stored).is_err());
        assert!(archive.store_anchor(&anchor, &plan, limits).is_err());
        drop(archive);
        let other_path = temp.0.join("other.redb");
        let mut other = Archive::create(
            &other_path,
            Context {
                rules_commitment: [5; 32],
                ..context
            },
            policy(),
        )
        .unwrap();
        assert!(other.store_anchor(&anchor, &plan, limits).is_err());
    }

    #[test]
    fn selected_long_chain_reserves_all_313_inclusive_heights_across_restart() {
        let temp = Temp::new();
        let bootstrap = snapshot::tests::bootstrap();
        let mut state = snapshot::tests::populated(&bootstrap);
        let limits = snapshot::tests::limits();
        let binding = snapshot::tests::binding(&bootstrap, bootstrap.tip());
        let commitment = state.execution_commitment(binding, limits.chain).unwrap();
        let plan = snapshot::tests::plan(&bootstrap, commitment, 313);
        state.chain.tip = plan.pin().anchor_id;
        state.chain.snapshots.back_mut().unwrap().selector.block_id = plan.pin().anchor_id;
        let raw = encode_components(
            &state.canonical_components(binding, limits.chain).unwrap(),
            limits,
        )
        .unwrap();
        let anchor =
            ImportedAnchor::reconstruct(&plan, &bootstrap, binding.rules_commitment, &raw, limits)
                .unwrap();
        let context = Context {
            network: bootstrap.network(),
            genesis: bootstrap.tip(),
            rules_commitment: binding.rules_commitment,
        };
        let mut archive = Archive::create(&temp.path(), context, policy()).unwrap();
        let stored = archive.store_anchor(&anchor, &plan, limits).unwrap();
        let transfer = archive
            .begin_transfer(stored, &plan, [7; 32], 100, 60)
            .unwrap();
        drop(archive);
        let mut reopened = Archive::open_existing(&temp.path(), context, policy()).unwrap();
        let windows = reopened.pinned_windows().unwrap();
        assert_eq!(windows, vec![transfer.window]);
        assert_eq!(windows[0].tip_height - windows[0].anchor_height + 1, 313);
        assert!(windows[0].contains_height(1));
        assert!(windows[0].contains_height(313));
        assert!(!windows[0].contains_height(0));
        assert!(!windows[0].contains_height(314));
        assert!(reopened.read_chunk(&transfer, [7; 32], 0, 1, 161).is_err());
        assert_eq!(reopened.pinned_windows().unwrap(), windows);
        assert_eq!(reopened.expire(161).unwrap(), 1);
        assert!(reopened.pinned_windows().unwrap().is_empty());
    }
}
