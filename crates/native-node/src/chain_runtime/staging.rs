//! Isolated resumable acquisition of an authenticated anchor and selected bodies.
//!
//! Completion waits for the actual native versioned proof verifier. This module
//! has no operation that admits a live head or publishes an execution-success flag.

use super::{
    admission::AdmissionPlan,
    archive::{Archive, StoredAnchor, StoredBody, Transfer},
    body::{Body, Policy as BodyPolicy},
    snapshot::{ImportLimits, ImportedAnchor, SnapshotState},
};
use crate::wire::Hash;
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use std::path::Path;

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("eng2-isolated-sync-meta-v1");
const OBJECTS: TableDefinition<u64, &[u8]> =
    TableDefinition::new("eng2-isolated-sync-downloads-v1");
const PARTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("eng2-isolated-sync-parts-v1");
const RAW: TableDefinition<u64, &[u8]> = TableDefinition::new("eng2-isolated-sync-raw-v1");
const FILE: &str = "staging.redb";

#[derive(Clone, Copy)]
pub struct Policy {
    pub import: ImportLimits,
    pub body: BodyPolicy,
    pub max_download_bytes: u64,
    pub max_chunk_bytes: usize,
    pub max_chunks_per_object: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    AcquiringAnchor,
    AcquiringTail,
    AwaitingNativeVerification,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Progress {
    pub phase: Phase,
    pub anchor_bytes: u64,
    pub downloaded_bytes: u64,
    pub completed_bodies: Vec<u64>,
}
pub struct Session<'a> {
    database: Database,
    plan: &'a AdmissionPlan,
    bootstrap: &'a SnapshotState,
    rules: Hash,
    policy: Policy,
    stored_anchor: StoredAnchor,
    anchor: Option<ImportedAnchor>,
}
impl<'a> Session<'a> {
    pub fn create(
        directory: &Path,
        plan: &'a AdmissionPlan,
        bootstrap: &'a SnapshotState,
        rules: Hash,
        policy: Policy,
        anchor: StoredAnchor,
    ) -> Result<Self, String> {
        let binding = binding(plan, bootstrap, rules, policy)?;
        check_anchor(anchor, plan, policy)?;
        create_directory(directory)?;
        let database = open_database(directory, true)?;
        let mut transaction = database
            .begin_write()
            .map_err(|_| "isolated staging initialization unavailable")?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|_| "isolated staging durability unavailable")?;
        {
            let mut meta = transaction
                .open_table(META)
                .map_err(|_| "isolated staging metadata unavailable")?;
            meta.insert("binding", binding.as_slice())
                .map_err(|_| "isolated staging binding write failed")?;
            meta.insert("anchor", anchor_bytes(anchor).as_slice())
                .map_err(|_| "isolated anchor descriptor write failed")?;
            meta.insert("downloaded", 0u64.to_le_bytes().as_slice())
                .map_err(|_| "isolated staging counter write failed")?;
        }
        transaction
            .open_table(OBJECTS)
            .map_err(|_| "isolated download table unavailable")?
            .insert(
                0,
                Object {
                    id: anchor.id,
                    bytes: anchor.bytes,
                    received: 0,
                    chunks: 0,
                }
                .encode()
                .as_slice(),
            )
            .map_err(|_| "isolated anchor reservation failed")?;
        transaction
            .open_table(PARTS)
            .map_err(|_| "isolated part table unavailable")?;
        transaction
            .open_table(RAW)
            .map_err(|_| "isolated raw table unavailable")?;
        transaction
            .commit()
            .map_err(|_| "isolated staging initialization commit failed")?;
        crate::store::sync_parent(&directory.join(FILE))?;
        crate::store::sync_parent(directory)?;
        Ok(Self {
            database,
            plan,
            bootstrap,
            rules,
            policy,
            stored_anchor: anchor,
            anchor: None,
        })
    }
    pub fn open_existing(
        directory: &Path,
        plan: &'a AdmissionPlan,
        bootstrap: &'a SnapshotState,
        rules: Hash,
        policy: Policy,
    ) -> Result<Self, String> {
        let expected = binding(plan, bootstrap, rules, policy)?;
        let database = open_database(directory, false)?;
        let anchor = {
            let transaction = database
                .begin_read()
                .map_err(|_| "isolated staging metadata read failed")?;
            let meta = transaction
                .open_table(META)
                .map_err(|_| "isolated staging metadata missing")?;
            if meta
                .get("binding")
                .map_err(|_| "isolated staging binding unreadable")?
                .ok_or("isolated staging binding missing")?
                .value()
                != expected
            {
                return Err("isolated staging selected plan, rules or policy differs".into());
            }
            decode_anchor(
                meta.get("anchor")
                    .map_err(|_| "isolated anchor descriptor unreadable")?
                    .ok_or("isolated anchor descriptor missing")?
                    .value(),
            )?
        };
        check_anchor(anchor, plan, policy)?;
        let mut session = Self {
            database,
            plan,
            bootstrap,
            rules,
            policy,
            stored_anchor: anchor,
            anchor: None,
        };
        session.reauthenticate()?;
        Ok(session)
    }
    pub fn progress(&self) -> Result<Progress, String> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| "isolated staging progress unavailable")?;
        let meta = transaction
            .open_table(META)
            .map_err(|_| "isolated staging metadata unavailable")?;
        let downloaded_bytes = number(
            meta.get("downloaded")
                .map_err(|_| "isolated download counter unreadable")?
                .ok_or("isolated download counter missing")?
                .value(),
        )?;
        let objects = transaction
            .open_table(OBJECTS)
            .map_err(|_| "isolated download table unavailable")?;
        let anchor_bytes = Object::decode(
            objects
                .get(0)
                .map_err(|_| "isolated anchor progress unreadable")?
                .ok_or("isolated anchor reservation missing")?
                .value(),
        )?
        .received;
        let raw = transaction
            .open_table(RAW)
            .map_err(|_| "isolated raw table unavailable")?;
        let mut completed_bodies = Vec::new();
        for row in raw
            .iter()
            .map_err(|_| "isolated raw iteration unavailable")?
        {
            let (height, _) = row.map_err(|_| "isolated raw record unreadable")?;
            if height.value() != 0 {
                completed_bodies.push(height.value());
            }
        }
        let phase = if self.anchor.is_none() {
            Phase::AcquiringAnchor
        } else if completed_bodies.len() as u64
            == self.plan.pin().tip_height - self.plan.pin().anchor_height
        {
            Phase::AwaitingNativeVerification
        } else {
            Phase::AcquiringTail
        };
        Ok(Progress {
            phase,
            anchor_bytes,
            downloaded_bytes,
            completed_bodies,
        })
    }
    pub fn anchor(&self) -> Option<&ImportedAnchor> {
        self.anchor.as_ref()
    }
    pub fn push_anchor_chunk(&mut self, offset: u64, bytes: &[u8]) -> Result<(), String> {
        self.push(0, offset, bytes)
    }
    pub fn pull_anchor(
        &mut self,
        source: &Archive,
        transfer: &Transfer,
        peer: Hash,
        now: u64,
    ) -> Result<(), String> {
        self.check_transfer(transfer)?;
        loop {
            let object = self.object(0)?;
            if object.received == object.bytes {
                return Ok(());
            }
            let chunk = source.read_chunk(
                transfer,
                peer,
                object.received,
                self.policy.max_chunk_bytes,
                now,
            )?;
            self.push_anchor_chunk(object.received, &chunk)?;
        }
    }
    pub fn begin_body(&mut self, body: StoredBody) -> Result<(), String> {
        if self.anchor.is_none() {
            return Err("isolated anchor is not reconstructed".into());
        }
        self.check_body_descriptor(body)?;
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|_| "isolated body reservation unavailable")?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|_| "isolated body reservation durability unavailable")?;
        {
            let mut objects = transaction
                .open_table(OBJECTS)
                .map_err(|_| "isolated download table unavailable")?;
            if let Some(existing) = objects
                .get(body.height)
                .map_err(|_| "isolated body reservation unreadable")?
            {
                let existing = Object::decode(existing.value())?;
                return if existing.id == body.id && existing.bytes == body.bytes {
                    Ok(())
                } else {
                    Err("immutable isolated body reservation differs".into())
                };
            }
            let mut reserved = body.bytes;
            for row in objects
                .iter()
                .map_err(|_| "isolated reservation iteration unavailable")?
            {
                let (_, value) = row.map_err(|_| "isolated reservation unreadable")?;
                reserved = reserved
                    .checked_add(Object::decode(value.value())?.bytes)
                    .ok_or("isolated download reservation overflow")?;
            }
            if reserved > self.policy.max_download_bytes {
                return Err("isolated total download budget exceeded".into());
            }
            objects
                .insert(
                    body.height,
                    Object {
                        id: body.id,
                        bytes: body.bytes,
                        received: 0,
                        chunks: 0,
                    }
                    .encode()
                    .as_slice(),
                )
                .map_err(|_| "isolated body reservation write failed")?;
        }
        transaction
            .commit()
            .map_err(|_| "isolated body reservation commit failed".into())
    }
    pub fn push_body_chunk(
        &mut self,
        height: u64,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), String> {
        if height == 0 || self.anchor.is_none() {
            return Err("isolated tail requires a reconstructed anchor".into());
        }
        self.push(height, offset, bytes)
    }
    pub fn pull_body(
        &mut self,
        source: &Archive,
        transfer: &Transfer,
        peer: Hash,
        height: u64,
        now: u64,
    ) -> Result<(), String> {
        self.check_transfer(transfer)?;
        self.begin_body(source.body_descriptor(transfer, peer, height, now)?)?;
        loop {
            let object = self.object(height)?;
            if object.received == object.bytes {
                return Ok(());
            }
            let chunk = source.read_tail_chunk(
                transfer,
                peer,
                super::archive::TailChunk {
                    height,
                    offset: object.received,
                    bytes: self.policy.max_chunk_bytes,
                },
                now,
            )?;
            self.push_body_chunk(height, object.received, &chunk)?;
        }
    }
    pub fn read_body(&self, height: u64) -> Result<Body, String> {
        if self.anchor.is_none() {
            return Err("isolated anchor is not reconstructed".into());
        }
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| "isolated body read unavailable")?;
        let raw = transaction
            .open_table(RAW)
            .map_err(|_| "isolated raw table unavailable")?;
        let row = raw
            .get(height)
            .map_err(|_| "isolated body unreadable")?
            .ok_or("isolated body download is incomplete")?;
        self.validate_body(height, row.value())
    }
    /// Prepare the actual acquired anchor's successor through the shared native
    /// chain path. This does not verify settlement or publish any state.
    pub fn prepare_anchor_successor<'s>(
        &'s self,
        body: &'s Body,
    ) -> Result<super::execution::PreparedBlock<'s>, String> {
        let anchor = self
            .anchor
            .as_ref()
            .ok_or("isolated anchor is not reconstructed")?;
        let state = anchor.state();
        if state.height().checked_add(1) != Some(body.height) {
            return Err("isolated body is not the acquired anchor successor".into());
        }
        let object = self.object(body.height)?;
        if object.received != object.bytes {
            return Err("isolated successor download is incomplete".into());
        }
        self.check_body_descriptor(StoredBody {
            height: body.height,
            id: object.id,
            bytes: object.bytes,
        })?;
        let header = self
            .plan
            .headers()
            .header(body.height)
            .ok_or("selected successor header missing")?;
        {
            let transaction = self
                .database
                .begin_read()
                .map_err(|_| "isolated successor read unavailable")?;
            let raw = transaction
                .open_table(RAW)
                .map_err(|_| "isolated successor raw table unavailable")?;
            let row = raw
                .get(body.height)
                .map_err(|_| "isolated successor unreadable")?
                .ok_or("isolated successor bytes missing")?;
            if row.value().len() as u64 != object.bytes {
                return Err("isolated successor byte count differs".into());
            }
            header
                .verify_body(row.value(), self.policy.body.max_body_bytes)
                .map_err(|_| "isolated successor stored commitment differs")?;
        }
        super::execution::PreparedBlock::prepare(
            state,
            header,
            body,
            super::state_components::Binding {
                genesis: self.plan.pin().genesis,
                rules_commitment: self.rules,
                parent: state.tip(),
            },
            self.policy.body,
        )
    }
    fn object(&self, object: u64) -> Result<Object, String> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| "isolated download progress unavailable")?;
        let objects = transaction
            .open_table(OBJECTS)
            .map_err(|_| "isolated download table unavailable")?;
        Object::decode(
            objects
                .get(object)
                .map_err(|_| "isolated download progress unreadable")?
                .ok_or("isolated download reservation missing")?
                .value(),
        )
    }
    fn check_body_descriptor(&self, body: StoredBody) -> Result<(), String> {
        let pin = self.plan.pin();
        if body.height <= pin.anchor_height
            || body.height > pin.tip_height
            || body.bytes == 0
            || body.bytes > self.policy.body.max_body_bytes as u64
            || body.bytes > chunk_capacity(self.policy)?
            || self
                .plan
                .headers()
                .id(body.height)
                .map_err(|_| "selected tail header missing")?
                != body.id
        {
            return Err("isolated body differs from selected header or byte bound".into());
        }
        Ok(())
    }
    fn check_transfer(&self, transfer: &Transfer) -> Result<(), String> {
        let pin = self.plan.pin();
        if transfer.anchor() != self.stored_anchor
            || transfer.window()
                != (super::archive::PinnedWindow {
                    anchor_height: pin.anchor_height,
                    anchor_id: pin.anchor_id,
                    tip_height: pin.tip_height,
                    tip_id: pin.tip_id,
                })
        {
            return Err("source transfer differs from isolated selected plan".into());
        }
        Ok(())
    }
    fn validate_body(&self, height: u64, bytes: &[u8]) -> Result<Body, String> {
        self.check_body_descriptor(StoredBody {
            height,
            id: self
                .plan
                .headers()
                .id(height)
                .map_err(|_| "selected body identity missing")?,
            bytes: bytes.len() as u64,
        })?;
        self.plan
            .headers()
            .header(height)
            .ok_or("selected body header missing")?
            .verify_body(bytes, self.policy.body.max_body_bytes)
            .map_err(|_| "isolated body differs from selected header commitment")?;
        Body::decode(bytes, self.plan.pin().network, height, self.policy.body)
    }
    fn import_anchor(&self, raw: &[u8]) -> Result<ImportedAnchor, String> {
        if raw.len() as u64 != self.stored_anchor.bytes
            || blake3::hash(raw).as_bytes() != &self.stored_anchor.digest
        {
            return Err("isolated anchor transfer digest differs".into());
        }
        ImportedAnchor::reconstruct(
            self.plan,
            self.bootstrap,
            self.rules,
            raw,
            self.policy.import,
        )
    }
    fn push(&mut self, target: u64, offset: u64, bytes: &[u8]) -> Result<(), String> {
        let object = self.object(target)?;
        let next = offset
            .checked_add(bytes.len() as u64)
            .ok_or("isolated chunk offset overflow")?;
        if bytes.is_empty()
            || bytes.len() > self.policy.max_chunk_bytes
            || offset != object.received
            || next > object.bytes
        {
            return Err("isolated chunk order, offset or byte bound differs".into());
        }
        let complete = next == object.bytes;
        let mut assembled = Vec::new();
        if object.chunks >= self.policy.max_chunks_per_object as u64 {
            return Err("isolated object chunk-count bound exceeded".into());
        }
        if complete {
            let transaction = self
                .database
                .begin_read()
                .map_err(|_| "isolated chunk assembly unavailable")?;
            assembled
                .try_reserve_exact(
                    usize::try_from(object.bytes).map_err(|_| "isolated object length overflow")?,
                )
                .map_err(|_| "isolated object allocation unavailable")?;
            let parts = scan_parts(
                &transaction,
                target,
                object.received,
                self.policy,
                Some(&mut assembled),
            )?;
            if parts as u64 != object.chunks {
                return Err("isolated object chunk count differs from durable progress".into());
            }
        }
        let mut imported = None;
        if complete {
            assembled.extend_from_slice(bytes);
            if target == 0 {
                imported = Some(self.import_anchor(&assembled)?);
            } else {
                self.validate_body(target, &assembled)?;
            }
        }
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|_| "isolated chunk write unavailable")?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|_| "isolated chunk durability unavailable")?;
        {
            let mut meta = transaction
                .open_table(META)
                .map_err(|_| "isolated staging metadata unavailable")?;
            let downloaded = number(
                meta.get("downloaded")
                    .map_err(|_| "isolated download counter unreadable")?
                    .ok_or("isolated download counter missing")?
                    .value(),
            )?
            .checked_add(bytes.len() as u64)
            .ok_or("isolated download counter overflow")?;
            if downloaded > self.policy.max_download_bytes {
                return Err("isolated total download budget exceeded".into());
            }
            meta.insert("downloaded", downloaded.to_le_bytes().as_slice())
                .map_err(|_| "isolated download counter write failed")?;
        }
        {
            let mut objects = transaction
                .open_table(OBJECTS)
                .map_err(|_| "isolated download table unavailable")?;
            if Object::decode(
                objects
                    .get(target)
                    .map_err(|_| "isolated progress unreadable")?
                    .ok_or("isolated reservation missing")?
                    .value(),
            )? != object
            {
                return Err("isolated progress changed during chunk assembly".into());
            }
            objects
                .insert(
                    target,
                    Object {
                        received: next,
                        chunks: object.chunks + 1,
                        ..object
                    }
                    .encode()
                    .as_slice(),
                )
                .map_err(|_| "isolated progress write failed")?;
        }
        if complete {
            transaction
                .open_table(RAW)
                .map_err(|_| "isolated raw table unavailable")?
                .insert(target, assembled.as_slice())
                .map_err(|_| "isolated completed object write failed")?;
            let mut table = transaction
                .open_table(PARTS)
                .map_err(|_| "isolated part table unavailable")?;
            let keys = table
                .range(part_key(target, 0).as_slice()..=part_key(target, u64::MAX).as_slice())
                .map_err(|_| "isolated part iteration unavailable")?
                .map(|row| {
                    row.map(|(key, _)| key.value().to_vec())
                        .map_err(|_| "isolated part key unreadable")
                })
                .collect::<Result<Vec<_>, _>>()?;
            for key in keys {
                table
                    .remove(key.as_slice())
                    .map_err(|_| "isolated completed-part replacement failed")?;
            }
        } else {
            transaction
                .open_table(PARTS)
                .map_err(|_| "isolated part table unavailable")?
                .insert(part_key(target, offset).as_slice(), bytes)
                .map_err(|_| "isolated chunk write failed")?;
        }
        transaction
            .commit()
            .map_err(|_| "isolated chunk durable commit failed")?;
        if target == 0 && complete {
            self.anchor = imported;
        }
        Ok(())
    }
    fn reauthenticate(&mut self) -> Result<(), String> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| "isolated restart verification unavailable")?;
        let objects = transaction
            .open_table(OBJECTS)
            .map_err(|_| "isolated download table missing")?;
        let raw = transaction
            .open_table(RAW)
            .map_err(|_| "isolated raw table missing")?;
        let mut downloaded = 0u64;
        let mut reserved = 0u64;
        let mut imported = None;
        let mut count = 0u64;
        for row in objects
            .iter()
            .map_err(|_| "isolated download iteration unavailable")?
        {
            let (target, value) = row.map_err(|_| "isolated download descriptor unreadable")?;
            let target = target.value();
            let object = Object::decode(value.value())?;
            if object.chunks > self.policy.max_chunks_per_object as u64 {
                return Err("isolated restart chunk-count bound exceeded".into());
            }
            count += 1;
            if target == 0 {
                if object.id != self.stored_anchor.id || object.bytes != self.stored_anchor.bytes {
                    return Err("isolated anchor reservation differs".into());
                }
            } else {
                self.check_body_descriptor(StoredBody {
                    height: target,
                    id: object.id,
                    bytes: object.bytes,
                })?;
            }
            downloaded = downloaded
                .checked_add(object.received)
                .ok_or("isolated restart counter overflow")?;
            reserved = reserved
                .checked_add(object.bytes)
                .ok_or("isolated restart reservation overflow")?;
            if object.received == object.bytes {
                let row = raw
                    .get(target)
                    .map_err(|_| "isolated completed object unreadable")?
                    .ok_or("isolated completed object missing")?;
                if row.value().len() as u64 != object.bytes {
                    return Err("isolated completed object length differs".into());
                }
                if target == 0 {
                    imported = Some(self.import_anchor(row.value())?);
                } else {
                    self.validate_body(target, row.value())?;
                }
                if scan_parts(&transaction, target, 0, self.policy, None)? != 0 {
                    return Err("completed isolated object retains partial chunks".into());
                }
            } else {
                if raw
                    .get(target)
                    .map_err(|_| "isolated raw object unreadable")?
                    .is_some()
                {
                    return Err("partial isolated object has a completed record".into());
                }
                if scan_parts(&transaction, target, object.received, self.policy, None)? as u64
                    != object.chunks
                {
                    return Err("isolated restart partial chunk count differs".into());
                }
            }
        }
        if objects
            .get(0)
            .map_err(|_| "isolated anchor reservation unreadable")?
            .is_none()
            || count > self.plan.pin().tip_height - self.plan.pin().anchor_height + 1
            || (count > 1 && imported.is_none())
            || reserved > self.policy.max_download_bytes
        {
            return Err("isolated restart object count or reservation differs".into());
        }
        for row in raw
            .iter()
            .map_err(|_| "isolated raw iteration unavailable")?
        {
            let (target, _) = row.map_err(|_| "isolated raw record unreadable")?;
            if objects
                .get(target.value())
                .map_err(|_| "isolated raw reservation unreadable")?
                .is_none()
            {
                return Err("unreserved isolated raw object".into());
            }
        }
        let parts = transaction
            .open_table(PARTS)
            .map_err(|_| "isolated part table missing")?;
        for row in parts
            .iter()
            .map_err(|_| "isolated part iteration unavailable")?
        {
            let (key, _) = row.map_err(|_| "isolated part unreadable")?;
            let (target, _) = decode_part_key(key.value())?;
            if objects
                .get(target)
                .map_err(|_| "isolated part reservation unreadable")?
                .is_none()
            {
                return Err("unreserved isolated partial object".into());
            }
        }
        let meta = transaction
            .open_table(META)
            .map_err(|_| "isolated metadata missing")?;
        if downloaded
            != number(
                meta.get("downloaded")
                    .map_err(|_| "isolated counter unreadable")?
                    .ok_or("isolated counter missing")?
                    .value(),
            )?
            || downloaded > self.policy.max_download_bytes
        {
            return Err("isolated restart download accounting differs".into());
        }
        self.anchor = imported;
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Object {
    id: Hash,
    bytes: u64,
    received: u64,
    chunks: u64,
}
impl Object {
    fn encode(self) -> [u8; 56] {
        let mut out = [0; 56];
        out[..32].copy_from_slice(&self.id);
        out[32..40].copy_from_slice(&self.bytes.to_le_bytes());
        out[40..48].copy_from_slice(&self.received.to_le_bytes());
        out[48..].copy_from_slice(&self.chunks.to_le_bytes());
        out
    }
    fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 56 {
            return Err("isolated object descriptor width".into());
        }
        let result = Self {
            id: bytes[..32].try_into().expect("fixed object identity"),
            bytes: number(&bytes[32..40])?,
            received: number(&bytes[40..48])?,
            chunks: number(&bytes[48..])?,
        };
        if result.bytes == 0
            || result.received > result.bytes
            || (result.received == 0) != (result.chunks == 0)
        {
            return Err("isolated object descriptor bound".into());
        }
        Ok(result)
    }
}
fn number(bytes: &[u8]) -> Result<u64, String> {
    Ok(u64::from_le_bytes(
        bytes.try_into().map_err(|_| "isolated integer width")?,
    ))
}
fn anchor_bytes(anchor: StoredAnchor) -> Vec<u8> {
    let mut bytes = anchor.height.to_le_bytes().to_vec();
    bytes.extend_from_slice(&anchor.id);
    bytes.extend_from_slice(&anchor.bytes.to_le_bytes());
    bytes.extend_from_slice(&anchor.digest);
    bytes
}
fn decode_anchor(bytes: &[u8]) -> Result<StoredAnchor, String> {
    if bytes.len() != 80 {
        return Err("isolated anchor descriptor width".into());
    }
    Ok(StoredAnchor {
        height: number(&bytes[..8])?,
        id: bytes[8..40].try_into().expect("fixed anchor identity"),
        bytes: number(&bytes[40..48])?,
        digest: bytes[48..].try_into().expect("fixed anchor digest"),
    })
}
fn check_anchor(anchor: StoredAnchor, plan: &AdmissionPlan, policy: Policy) -> Result<(), String> {
    if anchor.height != plan.pin().anchor_height
        || anchor.id != plan.pin().anchor_id
        || anchor.bytes == 0
        || anchor.bytes > policy.import.max_snapshot_bytes as u64
        || anchor.bytes > policy.max_download_bytes
        || anchor.bytes > chunk_capacity(policy)?
    {
        return Err("isolated anchor descriptor differs from selected plan or byte bound".into());
    }
    Ok(())
}
fn chunk_capacity(policy: Policy) -> Result<u64, String> {
    (policy.max_chunk_bytes as u64)
        .checked_mul(policy.max_chunks_per_object as u64)
        .ok_or_else(|| "isolated chunk capacity overflow".into())
}
fn part_key(target: u64, offset: u64) -> [u8; 16] {
    let mut key = [0; 16];
    key[..8].copy_from_slice(&target.to_be_bytes());
    key[8..].copy_from_slice(&offset.to_be_bytes());
    key
}
fn decode_part_key(bytes: &[u8]) -> Result<(u64, u64), String> {
    if bytes.len() != 16 {
        return Err("isolated part key width".into());
    }
    Ok((
        u64::from_be_bytes(bytes[..8].try_into().expect("fixed target")),
        u64::from_be_bytes(bytes[8..].try_into().expect("fixed offset")),
    ))
}
fn scan_parts(
    transaction: &redb::ReadTransaction,
    target: u64,
    expected: u64,
    policy: Policy,
    mut output: Option<&mut Vec<u8>>,
) -> Result<usize, String> {
    let parts = transaction
        .open_table(PARTS)
        .map_err(|_| "isolated part table unavailable")?;
    let mut offset = 0u64;
    let mut count = 0usize;
    for row in parts
        .range(part_key(target, 0).as_slice()..=part_key(target, u64::MAX).as_slice())
        .map_err(|_| "isolated part range unavailable")?
    {
        let (key, value) = row.map_err(|_| "isolated part unreadable")?;
        let (found_target, found_offset) = decode_part_key(key.value())?;
        if found_target != target
            || found_offset != offset
            || value.value().is_empty()
            || value.value().len() > policy.max_chunk_bytes
            || count >= policy.max_chunks_per_object
        {
            return Err("isolated partial chunk sequence or bound differs".into());
        }
        offset = offset
            .checked_add(value.value().len() as u64)
            .ok_or("isolated part count overflow")?;
        if offset > expected {
            return Err("isolated partial chunks exceed durable progress".into());
        }
        if let Some(out) = &mut output {
            out.extend_from_slice(value.value());
        }
        count += 1;
    }
    if offset != expected {
        return Err("isolated partial chunks differ from durable progress".into());
    }
    Ok(count)
}
fn binding(
    plan: &AdmissionPlan,
    bootstrap: &SnapshotState,
    rules: Hash,
    policy: Policy,
) -> Result<Vec<u8>, String> {
    let pin = plan.pin();
    if rules == [0; 32]
        || bootstrap.height() != 0
        || bootstrap.network() != pin.network
        || bootstrap.tip() != pin.genesis
        || policy.body.profile == [0; 32]
        || policy.body.max_body_bytes < super::body::PREFIX_BYTES
        || policy.body.max_settlement_proof_bytes == 0
        || policy.body.max_settlement_proof_bytes > u32::MAX as usize
        || policy.max_download_bytes == 0
        || !(1..=1_048_576).contains(&policy.max_chunk_bytes)
        || !(1..=1_048_576).contains(&policy.max_chunks_per_object)
        || policy.import.max_snapshot_bytes == 0
        || policy.import.chain.max_component_bytes == 0
    {
        return Err("invalid isolated synchronization context or policy".into());
    }
    let mut bytes = b"SW2D\x01\x00".to_vec();
    for value in [
        pin.network,
        pin.genesis,
        rules,
        pin.anchor_id,
        pin.tip_id,
        policy.body.profile,
    ] {
        bytes.extend_from_slice(&value);
    }
    for value in [
        pin.anchor_height,
        pin.tip_height,
        plan.headers().rules().genesis_timestamp,
        plan.headers().rules().target_interval,
        plan.headers().rules().pow_iterations,
        plan.headers().rules().max_headers as u64,
        policy.import.chain.max_leaves as u64,
        policy.import.chain.max_nullifiers as u64,
        policy.import.chain.max_component_bytes as u64,
        policy.import.max_snapshot_bytes as u64,
        policy.body.max_body_bytes as u64,
        policy.body.max_settlement_proof_bytes as u64,
        policy.max_download_bytes,
        policy.max_chunk_bytes as u64,
        policy.max_chunks_per_object as u64,
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(&plan.headers().rules().genesis_target);
    for value in [pin.cumulative_work, pin.tail_work, pin.local_work_floor] {
        bytes.extend_from_slice(&value.to_little_endian());
    }
    let mut headers = blake3::Hasher::new_derive_key("siworld eng2 isolated selected headers v1");
    for height in 1..=pin.tip_height {
        headers.update(
            &plan
                .headers()
                .header(height)
                .ok_or("selected isolated header missing")?
                .encode()
                .map_err(|_| "selected isolated header invalid")?,
        );
    }
    bytes.extend_from_slice(headers.finalize().as_bytes());
    Ok(bytes)
}
fn create_directory(path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    siworld_miner_platform::Directory::create(path)?;
    #[cfg(not(windows))]
    {
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(path)
            .map_err(|_| "isolated synchronization requires a new directory")?;
    }
    check_directory(path)
}
fn check_directory(path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    siworld_miner_platform::Directory::open(path)?.check()?;
    let metadata = std::fs::symlink_metadata(path).map_err(|_| "isolated directory unavailable")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("isolated directory is not a real directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err("isolated directory is not private to this user".into());
        }
    }
    Ok(())
}
fn open_database(directory: &Path, create: bool) -> Result<Database, String> {
    check_directory(directory)?;
    let (file, created) = crate::store::open_regular_file(&directory.join(FILE), create)?;
    if created != create {
        return Err("isolated database creation requires an absent file".into());
    }
    let backend = redb::backends::FileBackend::new(file)
        .map_err(|_| "isolated database backend unavailable")?;
    let mut builder = Database::builder();
    builder.set_cache_size(16 * 1024 * 1024);
    builder.set_repair_callback(|session| session.abort());
    builder
        .create_with_backend(backend)
        .map_err(|_| "isolated database is damaged or unavailable".into())
}

#[cfg(test)]
mod tests;
