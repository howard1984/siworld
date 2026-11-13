//! Independent competing-branch retention. Header qualification is distinct
//! from complete native execution and never publishes a canonical head.

use super::{
    body::{Body, Policy},
    execution::CommittedBlock,
    header::{HEADER_BYTES, Header},
    selection::{HeaderRules, VerifiedHeaders},
    store::{BodyAvailability, Store},
};
pub mod discovery;

use crate::wire::Hash;
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use siworld_core::pow::Work;
use std::{collections::BTreeSet, fs::OpenOptions, path::Path};

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("eng2-branches-meta-v1");
const HEADERS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("eng2-branches-headers-v1");
const BODIES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("eng2-branches-bodies-v1");
const RECORD_BYTES: usize = HEADER_BYTES + 64 + 8 + 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    HeaderQualified,
    BodyRetained,
    Executed,
    Invalid,
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub header: Header,
    pub cumulative_work: Work,
    pub first_seen: u64,
    pub status: Status,
}
impl Entry {
    fn encode(&self) -> Result<Vec<u8>, String> {
        let mut out = self
            .header
            .encode()
            .map_err(|_| "branch header encoding")?
            .to_vec();
        out.extend_from_slice(&self.cumulative_work.to_big_endian());
        out.extend_from_slice(&self.first_seen.to_le_bytes());
        out.push(match self.status {
            Status::HeaderQualified => 0,
            Status::BodyRetained => 1,
            Status::Executed => 2,
            Status::Invalid => 3,
        });
        Ok(out)
    }
    fn decode(bytes: &[u8], network: &Hash) -> Result<Self, String> {
        if bytes.len() != RECORD_BYTES {
            return Err("branch record length rejected".into());
        }
        let first_seen = u64::from_le_bytes(
            bytes[HEADER_BYTES + 64..HEADER_BYTES + 72]
                .try_into()
                .unwrap(),
        );
        if first_seen == 0 {
            return Err("branch arrival sequence rejected".into());
        }
        Ok(Self {
            header: Header::decode(&bytes[..HEADER_BYTES], network)
                .map_err(|_| "branch stored header rejected")?,
            cumulative_work: Work::from_big_endian(&bytes[HEADER_BYTES..HEADER_BYTES + 64]),
            first_seen,
            status: match bytes[RECORD_BYTES - 1] {
                0 => Status::HeaderQualified,
                1 => Status::BodyRetained,
                2 => Status::Executed,
                3 => Status::Invalid,
                _ => return Err("branch status rejected".into()),
            },
        })
    }
}

#[derive(Clone, Copy)]
pub struct Limits {
    pub maximum_headers: usize,
    pub maximum_body_bytes: u64,
}

/// This is a verification candidate, not an adopted or fully valid chain.
#[derive(Clone, Debug)]
pub struct CandidatePath {
    pub ancestor_height: u64,
    pub ancestor_id: Hash,
    pub ancestor_execution_commitment: Option<Hash>,
    pub removed: Vec<Hash>,
    pub replacement: Vec<Hash>,
    pub cumulative_work: Work,
    pub first_seen: u64,
}

/// Complete retained materials for one ordered replay. The private records
/// prevent callers from replacing an identity after the preflight succeeded.
/// This is not a native validity capability: every block still uses append.
#[derive(Clone, Debug)]
pub struct ReplayPlan {
    rules_binding: Hash,
    ancestor_height: u64,
    ancestor_id: Hash,
    ancestor_execution_commitment: Option<Hash>,
    records: Vec<ReplayRecord>,
    encoded_body_bytes: u64,
}
#[derive(Clone, Debug)]
struct ReplayRecord {
    header: Header,
    body_bytes: usize,
}
impl ReplayPlan {
    pub fn ancestor(&self) -> (u64, Hash, Option<Hash>) {
        (
            self.ancestor_height,
            self.ancestor_id,
            self.ancestor_execution_commitment,
        )
    }
    pub fn len(&self) -> usize {
        self.records.len()
    }
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    pub fn encoded_body_bytes(&self) -> u64 {
        self.encoded_body_bytes
    }
    pub fn tip(&self) -> Result<Hash, String> {
        self.records.last().map_or(Ok(self.ancestor_id), |record| {
            record
                .header
                .id()
                .map_err(|_| "replay header identity rejected".into())
        })
    }
}

/// Both replay paths must be fully retained before the owner restores state.
/// Original blocks are ordered from the ancestor towards the old tip, ready
/// for complete append-based recovery when a replacement proves invalid.
#[derive(Clone, Debug)]
pub struct SwitchReplay {
    pub path: CandidatePath,
    pub original: ReplayPlan,
    pub replacement: ReplayPlan,
}

/// This file must be different from the canonical database. Restoring a
/// canonical redb savepoint cannot alter any table owned by this database.
pub struct BranchStore {
    database: Database,
    rules: HeaderRules,
    limits: Limits,
    selection_revision: u64,
}
/// A pinned immutable header view for bounded retained-checkpoint inspection.
pub(crate) struct CheckpointHeaders {
    transaction: redb::ReadTransaction,
    network: Hash,
}
impl CheckpointHeaders {
    pub(crate) fn header(&self, height: u64, id: Hash) -> Result<Option<Header>, String> {
        let table = self
            .transaction
            .open_table(HEADERS)
            .map_err(|_| "captured retained headers unavailable")?;
        let entry = table
            .get(id.as_slice())
            .map_err(|_| "captured retained header lookup failed")?
            .map(|row| Entry::decode(row.value(), &self.network))
            .transpose()?;
        if entry
            .as_ref()
            .is_some_and(|entry| entry.header.height != height)
        {
            return Err("captured retained header height differs".into());
        }
        Ok(entry.map(|entry| entry.header))
    }
}
impl BranchStore {
    pub(crate) fn capture_checkpoint_headers(&self) -> Result<CheckpointHeaders, String> {
        Ok(CheckpointHeaders {
            transaction: self
                .database
                .begin_read()
                .map_err(|_| "retained checkpoint read unavailable")?,
            network: self.rules.network,
        })
    }
    /// In-process cache invalidation only, reset on reopen. It changes after a
    /// committed eligibility mutation, never for duplicate bodies or execution
    /// status upgrades. Selection itself remains a bounded full-header scan.
    pub fn selection_revision(&self) -> u64 {
        self.selection_revision
    }
    fn selection_changed(&mut self) {
        self.selection_revision = self.selection_revision.wrapping_add(1);
    }
    /// Creates a new file only. No existing branch evidence is overwritten.
    pub fn create(path: &Path, rules: HeaderRules, limits: Limits) -> Result<Self, String> {
        VerifiedHeaders::verify(rules.clone(), vec![]).map_err(|_| "branch rules rejected")?;
        if limits.maximum_headers == 0 || limits.maximum_body_bytes == 0 {
            return Err("branch resource limits rejected".into());
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
        }
        let file = options
            .open(path)
            .map_err(|_| "new branch file unavailable or exists")?;
        let backend =
            redb::backends::FileBackend::new(file).map_err(|_| "branch backend unavailable")?;
        let database = Database::builder()
            .create_with_backend(backend)
            .map_err(|_| "branch database creation failed")?;
        let mut transaction = database
            .begin_write()
            .map_err(|_| "branch transaction unavailable")?;
        transaction.set_quick_repair(true);
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|_| "branch durability unavailable")?;
        {
            let mut meta = transaction
                .open_table(META)
                .map_err(|_| "branch metadata unavailable")?;
            meta.insert("rules", rules_bytes(&rules).as_slice())
                .map_err(|_| "branch rules write failed")?;
            meta.insert("next-arrival", 1u64.to_le_bytes().as_slice())
                .map_err(|_| "branch arrival write failed")?;
            meta.insert("body-bytes", 0u64.to_le_bytes().as_slice())
                .map_err(|_| "branch accounting write failed")?;
            transaction
                .open_table(HEADERS)
                .map_err(|_| "branch headers unavailable")?;
            transaction
                .open_table(BODIES)
                .map_err(|_| "branch bodies unavailable")?;
        }
        transaction
            .commit()
            .map_err(|_| "branch initialization commit failed")?;
        crate::store::sync_parent(path)?;
        Ok(Self {
            database,
            rules,
            limits,
            selection_revision: 0,
        })
    }

    pub fn open(path: &Path, rules: HeaderRules, limits: Limits) -> Result<Self, String> {
        VerifiedHeaders::verify(rules.clone(), vec![]).map_err(|_| "branch rules rejected")?;
        if limits.maximum_headers == 0 || limits.maximum_body_bytes == 0 {
            return Err("branch resource limits rejected".into());
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
        }
        let file = options
            .open(path)
            .map_err(|_| "existing branch file unavailable")?;
        let metadata = file
            .metadata()
            .map_err(|_| "branch file metadata unavailable")?;
        if !metadata.is_file() || metadata.len() == 0 {
            return Err("branch file is not regular".into());
        }
        let backend =
            redb::backends::FileBackend::new(file).map_err(|_| "branch backend unavailable")?;
        let mut builder = Database::builder();
        // Quick-repair allocator snapshots accompany every committed write.
        // A full repair is an explicit offline operation, never an implicit open.
        builder.set_repair_callback(|session| session.abort());
        let database = builder
            .create_with_backend(backend)
            .map_err(|_| "branch database open failed")?;
        {
            let transaction = database
                .begin_read()
                .map_err(|_| "branch read unavailable")?;
            let meta = transaction
                .open_table(META)
                .map_err(|_| "branch metadata unavailable")?;
            if meta
                .get("rules")
                .map_err(|_| "branch rules unavailable")?
                .ok_or("branch rules missing")?
                .value()
                != rules_bytes(&rules)
            {
                return Err("branch immutable rules differ".into());
            }
        }
        Ok(Self {
            database,
            rules,
            limits,
            selection_revision: 0,
        })
    }

    /// Complete header validation is supplied by an unforgeable checked path.
    /// The first locally committed arrival sequence survives duplicate offers
    /// and process restart; no remote clock or work claim is trusted.
    pub fn retain_verified_headers(&mut self, path: &VerifiedHeaders) -> Result<(), String> {
        let mut inserted = false;
        if path.rules() != &self.rules {
            return Err("branch header rules differ".into());
        }
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|_| "branch write unavailable")?;
        transaction.set_quick_repair(true);
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|_| "branch durability unavailable")?;
        {
            let mut meta = transaction
                .open_table(META)
                .map_err(|_| "branch metadata unavailable")?;
            let mut headers = transaction
                .open_table(HEADERS)
                .map_err(|_| "branch headers unavailable")?;
            use redb::ReadableTableMetadata;
            let mut count = headers.len().map_err(|_| "branch count unavailable")?;
            let mut next = meta_number(&meta, "next-arrival")?;
            for height in 1..=path.height() {
                let header = path
                    .header(height)
                    .ok_or("verified branch header missing")?;
                let id = header.id().map_err(|_| "branch identity rejected")?;
                let work = path
                    .work_at(height)
                    .map_err(|_| "branch work unavailable")?;
                if let Some(old) = headers
                    .get(id.as_slice())
                    .map_err(|_| "branch lookup failed")?
                {
                    let old = Entry::decode(old.value(), &self.rules.network)?;
                    if old.header != *header || old.cumulative_work != work {
                        return Err("existing branch record conflicts".into());
                    }
                    continue;
                }
                count = count.checked_add(1).ok_or("branch count overflow")?;
                if count > self.limits.maximum_headers as u64 {
                    return Err("branch header capacity reached".into());
                }
                inserted = true;
                let record = Entry {
                    header: header.clone(),
                    cumulative_work: work,
                    first_seen: next,
                    status: Status::HeaderQualified,
                };
                next = next.checked_add(1).ok_or("branch arrival overflow")?;
                headers
                    .insert(id.as_slice(), record.encode()?.as_slice())
                    .map_err(|_| "branch header write failed")?;
            }
            meta.insert("next-arrival", next.to_le_bytes().as_slice())
                .map_err(|_| "branch arrival write failed")?;
        }
        transaction
            .commit()
            .map_err(|_| "branch header commit failed".to_string())?;
        if inserted {
            self.selection_changed();
        }
        Ok(())
    }

    pub fn entry(&self, id: Hash) -> Result<Option<Entry>, String> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| "branch read unavailable")?;
        let headers = transaction
            .open_table(HEADERS)
            .map_err(|_| "branch headers unavailable")?;
        headers
            .get(id.as_slice())
            .map_err(|_| "branch lookup failed")?
            .map(|row| Entry::decode(row.value(), &self.rules.network))
            .transpose()
    }

    /// Framing and body commitment only. This method cannot assert execution
    /// validity; all native proofs and state transitions remain mandatory.
    pub fn retain_body(
        &mut self,
        header: &Header,
        body: &Body,
        policy: Policy,
    ) -> Result<(), String> {
        if body.network != header.network
            || body.height != header.height
            || body.commitment(policy)? != header.body_commitment
        {
            return Err("branch body binding rejected".into());
        }
        let id = header.id().map_err(|_| "branch identity rejected")?;
        let mut entry = self
            .entry(id)?
            .ok_or("branch header must be independently qualified first")?;
        if entry.header != *header || entry.status == Status::Invalid {
            return Err("branch header unavailable for retention".into());
        }
        let encoded = body.encode(policy)?;
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|_| "branch write unavailable")?;
        transaction.set_quick_repair(true);
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|_| "branch durability unavailable")?;
        {
            let mut bodies = transaction
                .open_table(BODIES)
                .map_err(|_| "branch bodies unavailable")?;
            if let Some(old) = bodies
                .get(id.as_slice())
                .map_err(|_| "branch body read failed")?
            {
                if old.value() != encoded {
                    return Err("existing branch body conflicts".into());
                }
                return Ok(());
            }
            let mut meta = transaction
                .open_table(META)
                .map_err(|_| "branch metadata unavailable")?;
            let total = meta_number(&meta, "body-bytes")?
                .checked_add(encoded.len() as u64)
                .ok_or("branch byte accounting overflow")?;
            if total > self.limits.maximum_body_bytes {
                return Err("branch body capacity reached".into());
            }
            meta.insert("body-bytes", total.to_le_bytes().as_slice())
                .map_err(|_| "branch accounting write failed")?;
            bodies
                .insert(id.as_slice(), encoded.as_slice())
                .map_err(|_| "branch body write failed")?;
            if entry.status == Status::HeaderQualified {
                entry.status = Status::BodyRetained;
            }
            transaction
                .open_table(HEADERS)
                .map_err(|_| "branch headers unavailable")?
                .insert(id.as_slice(), entry.encode()?.as_slice())
                .map_err(|_| "branch status write failed")?;
        }
        transaction
            .commit()
            .map_err(|_| "branch body commit failed".to_string())
    }

    /// Read persisted length without allocating or decoding raw proof data.
    /// Callers reserve the node-wide body budget before loading the body.
    pub fn body_size(&self, id: Hash) -> Result<Option<usize>, String> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| "branch read unavailable")?;
        let bodies = transaction
            .open_table(BODIES)
            .map_err(|_| "branch bodies unavailable")?;
        bodies
            .get(id.as_slice())
            .map_err(|_| "branch lookup failed")?
            .map(|row| Ok(row.value().len()))
            .transpose()
    }

    pub fn body(&self, id: Hash, policy: Policy) -> Result<Option<Body>, String> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| "branch read unavailable")?;
        let bodies = transaction
            .open_table(BODIES)
            .map_err(|_| "branch bodies unavailable")?;
        let Some(row) = bodies
            .get(id.as_slice())
            .map_err(|_| "branch body read failed")?
        else {
            return Ok(None);
        };
        if row.value().len() > policy.max_body_bytes {
            return Err("stored branch body exceeds local limit".into());
        }
        let entry = self.entry(id)?.ok_or("stored branch body header missing")?;
        Body::decode(row.value(), self.rules.network, entry.header.height, policy).map(Some)
    }

    /// Check all materials before any canonical savepoint is restored. A missing
    /// body, imported-only history, invalid ancestor or noncontiguous path must
    /// stop switching; compact headers and receipt projections cannot replay it.
    pub fn replay_plan(
        &self,
        ancestor: Hash,
        ids: &[Hash],
        policy: Policy,
    ) -> Result<ReplayPlan, String> {
        if ids.len() > self.limits.maximum_headers || !self.valid_ancestry(ancestor)? {
            return Err("replay path bound or ancestor rejected".into());
        }
        let anchor = if ancestor == self.rules.genesis {
            None
        } else {
            self.entry(ancestor)?
        };
        let ancestor_height = anchor.as_ref().map_or(0, |entry| entry.header.height);
        let mut plan = ReplayPlan {
            rules_binding: *blake3::hash(&rules_bytes(&self.rules)).as_bytes(),
            ancestor_height,
            ancestor_id: ancestor,
            ancestor_execution_commitment: anchor.map(|entry| entry.header.execution_commitment),
            records: Vec::new(),
            encoded_body_bytes: 0,
        };
        plan.records
            .try_reserve_exact(ids.len())
            .map_err(|_| "replay plan reservation failed")?;
        let mut previous = ancestor;
        let mut height = ancestor_height;
        for id in ids {
            height = height.checked_add(1).ok_or("replay height overflow")?;
            let entry = self.entry(*id)?.ok_or("replay header missing")?;
            if entry.status == Status::Invalid
                || entry.header.height != height
                || entry.header.parent != previous
                || entry
                    .header
                    .id()
                    .map_err(|_| "replay header identity rejected")?
                    != *id
            {
                return Err("replay path is invalid or noncontiguous".into());
            }
            let body = self
                .body(*id, policy)?
                .ok_or("complete replay body unavailable")?;
            let body_bytes = body.encoded_len(policy)?;
            if body.commitment(policy)? != entry.header.body_commitment {
                return Err("replay body differs from qualified header".into());
            }
            plan.encoded_body_bytes = plan
                .encoded_body_bytes
                .checked_add(body_bytes as u64)
                .ok_or("replay byte accounting overflow")?;
            if plan.encoded_body_bytes > self.limits.maximum_body_bytes {
                return Err("replay materials exceed retained byte limit".into());
            }
            plan.records.push(ReplayRecord {
                header: entry.header,
                body_bytes,
            });
            previous = *id;
        }
        Ok(plan)
    }

    pub fn prepare_switch(
        &self,
        current: Hash,
        candidate: Hash,
        policy: Policy,
    ) -> Result<SwitchReplay, String> {
        let path = self.candidate_path(current, candidate)?;
        let preferred = if current == self.rules.genesis {
            true
        } else {
            let old = self
                .entry(current)?
                .ok_or("current branch header missing")?;
            path.cumulative_work > old.cumulative_work
                || (path.cumulative_work == old.cumulative_work && path.first_seen < old.first_seen)
        };
        if !preferred {
            return Err("candidate is not preferred by verified work and arrival".into());
        }
        if path.removed.len() > 24 {
            return Err("reorganization depth exceeds retained window".into());
        }
        let original_ids: Vec<_> = path.removed.iter().rev().copied().collect();
        let original = self.replay_plan(path.ancestor_id, &original_ids, policy)?;
        let replacement = self.replay_plan(path.ancestor_id, &path.replacement, policy)?;
        Ok(SwitchReplay {
            path,
            original,
            replacement,
        })
    }

    /// Load at most one full block for the owner's ordinary complete verifier.
    /// Recheck identity and body binding after preflight and after reopening the
    /// independent database; preflight alone is never acceptance evidence.
    pub fn replay_block(
        &self,
        plan: &ReplayPlan,
        index: usize,
        policy: Policy,
    ) -> Result<(Header, Body), String> {
        if plan.rules_binding != *blake3::hash(&rules_bytes(&self.rules)).as_bytes() {
            return Err("replay plan immutable rules differ".into());
        }
        let record = plan
            .records
            .get(index)
            .ok_or("replay block index unavailable")?;
        let id = record
            .header
            .id()
            .map_err(|_| "replay header identity rejected")?;
        let entry = self.entry(id)?.ok_or("retained replay header missing")?;
        if entry.header != record.header || entry.status == Status::Invalid {
            return Err("retained replay header changed or invalid".into());
        }
        let body = self
            .body(id, policy)?
            .ok_or("retained replay body missing")?;
        if body.encoded_len(policy)? != record.body_bytes
            || body.commitment(policy)? != record.header.body_commitment
        {
            return Err("retained replay body changed".into());
        }
        Ok((record.header.clone(), body))
    }

    /// Preserve the complete old suffix before restoring its canonical store.
    /// Only immutable accepted Store exports are read; no proof is regenerated.
    /// On any failure the canonical store is untouched and switching must stop.
    pub fn archive_canonical_suffix(
        &mut self,
        canonical: &Store,
        ancestor_height: u64,
    ) -> Result<ReplayPlan, String> {
        canonical.ensure_exportable()?;
        let state = canonical.engine().state();
        let height = state.height();
        if canonical.engine().genesis().id() != self.rules.genesis
            || state.network() != self.rules.network
            || ancestor_height > height
            || height - ancestor_height > 24
            || height > self.rules.max_headers as u64
        {
            return Err("canonical archive context or depth rejected".into());
        }
        for current in (ancestor_height..height).map(|height| height + 1) {
            if !matches!(
                canonical.body_availability(current)?,
                BodyAvailability::Full { .. }
            ) {
                return Err("complete canonical replay body is unavailable".into());
            }
        }
        let mut headers = Vec::new();
        headers
            .try_reserve_exact(height as usize)
            .map_err(|_| "canonical header reservation failed")?;
        for current in 1..=height {
            headers.push(canonical.header(current)?);
        }
        let qualified = VerifiedHeaders::verify(self.rules.clone(), headers)
            .map_err(|_| "canonical header qualification failed")?;
        self.retain_verified_headers(&qualified)?;
        let policy = canonical.engine().body_policy();
        let mut ids = Vec::new();
        for current in (ancestor_height..height).map(|height| height + 1) {
            let (header, body) = canonical.block(current)?;
            self.retain_body(&header, &body, policy)?;
            ids.push(
                header
                    .id()
                    .map_err(|_| "canonical archive identity rejected")?,
            );
        }
        self.replay_plan(
            qualified
                .id(ancestor_height)
                .map_err(|_| "canonical ancestor unavailable")?,
            &ids,
            policy,
        )
    }

    /// Retain one already executed block with O(1) indexed lookups. The caller
    /// first commits its canonical Store; failure here must pause production.
    /// No full-history verification or rewrite occurs on ordinary acceptance.
    /// Native capability binds the complete header identity and execution root;
    /// the retained parent path binds it to this store's immutable genesis.
    pub fn retain_committed(
        &mut self,
        header: &Header,
        body: &Body,
        policy: Policy,
        verified: &CommittedBlock,
    ) -> Result<(), String> {
        let id = header
            .id()
            .map_err(|_| "committed branch identity rejected")?;
        if header.height == 0
            || header.height > self.rules.max_headers as u64
            || header.network != self.rules.network
            || verified.network() != header.network
            || verified.height() != header.height
            || verified.id() != id
            || verified.execution_commitment() != header.execution_commitment
            || body.network != header.network
            || body.height != header.height
            || body.commitment(policy)? != header.body_commitment
        {
            return Err("committed branch capability or body differs".into());
        }
        let length = body.encoded_len(policy)?;
        if length as u64 > self.limits.maximum_body_bytes {
            return Err("committed branch body exceeds capacity".into());
        }
        let encoded = body.encode(policy)?;
        let mut inserted = false;
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|_| "branch write unavailable")?;
        transaction.set_quick_repair(true);
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|_| "branch durability unavailable")?;
        {
            let mut headers = transaction
                .open_table(HEADERS)
                .map_err(|_| "branch headers unavailable")?;
            let mut bodies = transaction
                .open_table(BODIES)
                .map_err(|_| "branch bodies unavailable")?;
            let mut meta = transaction
                .open_table(META)
                .map_err(|_| "branch metadata unavailable")?;
            let parent_work = if header.height == 1 {
                if header.parent != self.rules.genesis {
                    return Err("committed branch genesis differs".into());
                }
                Work::zero()
            } else {
                let parent = headers
                    .get(header.parent.as_slice())
                    .map_err(|_| "branch parent lookup failed")?
                    .ok_or("committed branch parent missing")?;
                let parent = Entry::decode(parent.value(), &self.rules.network)?;
                if parent.header.height.checked_add(1) != Some(header.height)
                    || parent
                        .header
                        .id()
                        .map_err(|_| "branch parent identity rejected")?
                        != header.parent
                    || parent.status == Status::Invalid
                {
                    return Err("committed branch parent rejected".into());
                }
                parent.cumulative_work
            };
            let work = parent_work
                .checked_add(siworld_core::pow::block_work(&header.target))
                .ok_or("committed branch work overflow")?;
            let old = headers
                .get(id.as_slice())
                .map_err(|_| "branch lookup failed")?
                .map(|row| Entry::decode(row.value(), &self.rules.network))
                .transpose()?;
            let first_seen = if let Some(old) = old {
                if old.header != *header
                    || old.cumulative_work != work
                    || old.status == Status::Invalid
                {
                    return Err("existing committed branch record conflicts".into());
                }
                old.first_seen
            } else {
                inserted = true;
                use redb::ReadableTableMetadata;
                if headers.len().map_err(|_| "branch count unavailable")?
                    >= self.limits.maximum_headers as u64
                {
                    return Err("branch header capacity reached".into());
                }
                let next = meta_number(&meta, "next-arrival")?;
                let following = next.checked_add(1).ok_or("branch arrival overflow")?;
                meta.insert("next-arrival", following.to_le_bytes().as_slice())
                    .map_err(|_| "branch arrival write failed")?;
                next
            };
            let body_present = if let Some(old_body) = bodies
                .get(id.as_slice())
                .map_err(|_| "branch body lookup failed")?
            {
                if old_body.value() != encoded {
                    return Err("existing committed branch body conflicts".into());
                }
                true
            } else {
                false
            };
            if !body_present {
                let total = meta_number(&meta, "body-bytes")?
                    .checked_add(length as u64)
                    .ok_or("branch byte accounting overflow")?;
                if total > self.limits.maximum_body_bytes {
                    return Err("branch body capacity reached".into());
                }
                meta.insert("body-bytes", total.to_le_bytes().as_slice())
                    .map_err(|_| "branch accounting write failed")?;
                bodies
                    .insert(id.as_slice(), encoded.as_slice())
                    .map_err(|_| "branch body write failed")?;
            }
            let entry = Entry {
                header: header.clone(),
                cumulative_work: work,
                first_seen,
                status: Status::Executed,
            };
            headers
                .insert(id.as_slice(), entry.encode()?.as_slice())
                .map_err(|_| "branch header write failed")?;
        }
        transaction
            .commit()
            .map_err(|_| "committed branch retention failed".to_string())?;
        if inserted {
            self.selection_changed();
        }
        Ok(())
    }

    /// Only an actual native execution capability can mark a retained block as
    /// executed. It remains separate from canonical disk acceptance.
    pub fn record_execution(&mut self, verified: &CommittedBlock) -> Result<(), String> {
        let id = verified.id();
        let mut entry = self.entry(id)?.ok_or("executed branch header missing")?;
        if entry.status == Status::Invalid
            || entry.status == Status::HeaderQualified
            || verified.network() != self.rules.network
            || verified.height() != entry.header.height
            || verified.execution_commitment() != entry.header.execution_commitment
        {
            return Err("branch execution capability differs".into());
        }
        entry.status = Status::Executed;
        self.update_entry(id, &entry)
    }

    /// Invalidity is explicit and durable. A local timeout must not call this
    /// method: timeout is deferred work rather than consensus invalidity.
    pub fn mark_invalid(&mut self, id: Hash) -> Result<(), String> {
        let mut entry = self.entry(id)?.ok_or("invalid branch header missing")?;
        if entry.status == Status::Invalid {
            return Ok(());
        }
        entry.status = Status::Invalid;
        self.update_entry(id, &entry)?;
        self.selection_changed();
        Ok(())
    }

    fn update_entry(&mut self, id: Hash, entry: &Entry) -> Result<(), String> {
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|_| "branch write unavailable")?;
        transaction.set_quick_repair(true);
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|_| "branch durability unavailable")?;
        transaction
            .open_table(HEADERS)
            .map_err(|_| "branch headers unavailable")?
            .insert(id.as_slice(), entry.encode()?.as_slice())
            .map_err(|_| "branch status write failed")?;
        transaction
            .commit()
            .map_err(|_| "branch status commit failed".to_string())
    }

    /// Returns the greatest header-qualified candidate, with durable first-seen
    /// tie breaking. Neither this choice nor possession of its body authorizes
    /// adoption; the owner must fully execute the replacement first.
    pub fn best_candidate(&self) -> Result<Option<Hash>, String> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| "branch read unavailable")?;
        let headers = transaction
            .open_table(HEADERS)
            .map_err(|_| "branch headers unavailable")?;
        use redb::ReadableTableMetadata;
        let count = headers.len().map_err(|_| "branch count unavailable")?;
        if count > self.limits.maximum_headers as u64 {
            return Err("retained branch headers exceed local capacity".into());
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(count as usize)
            .map_err(|_| "branch scan reservation failed")?;
        for row in headers.iter().map_err(|_| "branch iteration unavailable")? {
            let (key, value) = row.map_err(|_| "branch iteration failed")?;
            let id: Hash = key
                .value()
                .try_into()
                .map_err(|_| "branch identity length rejected")?;
            let entry = Entry::decode(value.value(), &self.rules.network)?;
            if entry
                .header
                .id()
                .map_err(|_| "stored branch header identity rejected")?
                != id
            {
                return Err("stored branch key differs from header".into());
            }
            entries.push((id, entry));
        }
        entries.sort_unstable_by_key(|(_, entry)| entry.header.height);
        let mut eligible = BTreeSet::from([self.rules.genesis]);
        let mut best: Option<(Hash, Entry)> = None;
        for (id, entry) in entries {
            if entry.status == Status::Invalid || !eligible.contains(&entry.header.parent) {
                continue;
            }
            eligible.insert(id);
            if best.as_ref().is_none_or(|(_, old)| {
                entry.cumulative_work > old.cumulative_work
                    || (entry.cumulative_work == old.cumulative_work
                        && entry.first_seen < old.first_seen)
            }) {
                best = Some((id, entry));
            }
        }
        Ok(best.map(|(id, _)| id))
    }

    fn valid_ancestry(&self, mut id: Hash) -> Result<bool, String> {
        for _ in 0..=self.limits.maximum_headers {
            if id == self.rules.genesis {
                return Ok(true);
            }
            let entry = self.entry(id)?.ok_or("branch ancestor missing")?;
            if entry.status == Status::Invalid {
                return Ok(false);
            }
            id = entry.header.parent;
        }
        Err("branch ancestry bound exceeded".into())
    }

    pub fn candidate_path(&self, current: Hash, candidate: Hash) -> Result<CandidatePath, String> {
        if !self.valid_ancestry(candidate)? {
            return Err("candidate has an invalid ancestor".into());
        }
        let selected = self.entry(candidate)?.ok_or("candidate header missing")?;
        let mut current_path = Vec::new();
        let mut current_ids = BTreeSet::from([self.rules.genesis]);
        let mut id = current;
        for _ in 0..=self.limits.maximum_headers {
            if id == self.rules.genesis {
                break;
            }
            if !current_ids.insert(id) {
                return Err("current branch cycle rejected".into());
            }
            let entry = self.entry(id)?.ok_or("current branch ancestor missing")?;
            current_path.push(id);
            id = entry.header.parent;
        }
        if id != self.rules.genesis {
            return Err("current ancestry bound exceeded".into());
        }
        let mut replacement = Vec::new();
        id = candidate;
        for _ in 0..=self.limits.maximum_headers {
            if current_ids.contains(&id) {
                break;
            }
            let entry = self.entry(id)?.ok_or("candidate ancestor missing")?;
            replacement.push(id);
            id = entry.header.parent;
        }
        if !current_ids.contains(&id) {
            return Err("common ancestor bound exceeded".into());
        }
        let ancestor = if id == self.rules.genesis {
            None
        } else {
            self.entry(id)?
        };
        let removed = current_path
            .into_iter()
            .take_while(|old| old != &id)
            .collect();
        replacement.reverse();
        Ok(CandidatePath {
            ancestor_height: ancestor.as_ref().map_or(0, |v| v.header.height),
            ancestor_id: id,
            ancestor_execution_commitment: ancestor.map(|v| v.header.execution_commitment),
            removed,
            replacement,
            cumulative_work: selected.cumulative_work,
            first_seen: selected.first_seen,
        })
    }
}

fn meta_number(
    meta: &impl ReadableTable<&'static str, &'static [u8]>,
    key: &str,
) -> Result<u64, String> {
    let value = meta
        .get(key)
        .map_err(|_| "branch metadata read failed")?
        .ok_or("branch metadata missing")?;
    Ok(u64::from_le_bytes(
        value
            .value()
            .try_into()
            .map_err(|_| "branch metadata length rejected")?,
    ))
}
fn rules_bytes(rules: &HeaderRules) -> Vec<u8> {
    let mut bytes = b"SW-BRANCH-RULES-1".to_vec();
    bytes.extend_from_slice(&rules.network);
    bytes.extend_from_slice(&rules.genesis);
    bytes.extend_from_slice(&rules.genesis_timestamp.to_le_bytes());
    bytes.extend_from_slice(&rules.genesis_target);
    bytes.extend_from_slice(&rules.target_interval.to_le_bytes());
    bytes.extend_from_slice(&rules.pow_iterations.to_le_bytes());
    bytes
}

#[cfg(test)]
pub(crate) mod tests;
