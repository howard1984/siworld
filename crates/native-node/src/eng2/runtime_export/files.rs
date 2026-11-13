//! Descriptor-confined public artifacts and write-once public signature journals.
use super::*;
use rustix::fs::{AtFlags, Mode, OFlags, fsync, openat, renameat, unlinkat};
#[cfg(any(test, feature = "eng2-runtime"))]
use std::io::{Seek, SeekFrom};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

mod generations;
mod wallet;
pub use generations::{WalletPolicy, WalletProgress, WalletPublisher};

pub(super) struct SavedPublication {
    pub(super) certificate: Certificate,
    pub(super) witness: AuthorizationWitness,
    pub(super) snapshot: Vec<u8>,
    pub(super) published: u64,
}
fn publication_name(height: u64) -> String {
    format!("checkpoint-publication-{height:020}.json")
}

pub struct PublicExport {
    root: fs::File,
    network: Hash,
    genesis: Hash,
    rules: Hash,
    latest: Option<(u64, Hash, u64)>,
    cached_head: Option<(u64, Hash)>,
    blocks: Vec<Value>,
    material_generation: std::cell::Cell<u64>,
}
impl PublicExport {
    /// The host creates its dedicated directory. All subsequent filesystem
    /// operations remain relative to this opened directory descriptor.
    pub fn open(root: &Path, store: &Store, limits: ImportLimits) -> Result<Self, String> {
        let mut value = Self::open_unrestored(root, store)?;
        if let Some(checkpoint) = value.restore_latest(store, limits)? {
            value.remember_publication(&checkpoint)?;
        }
        Ok(value)
    }
    pub(super) fn remember_publication(
        &mut self,
        checkpoint: &CertifiedCheckpoint,
    ) -> Result<(), String> {
        let bytes = checkpoint
            .certificate
            .encode()
            .map_err(|_| "invalid restored certificate")?;
        self.latest = Some((
            checkpoint.certificate.statement.checkpoint_height,
            *blake3::hash(&bytes).as_bytes(),
            checkpoint.published,
        ));
        Ok(())
    }
    pub(super) fn open_unrestored(root: &Path, store: &Store) -> Result<Self, String> {
        store.ensure_exportable()?;
        let root = OpenOptions::new()
            .read(true)
            .custom_flags((OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::CLOEXEC).bits() as i32)
            .open(root)
            .map_err(|_| "eng2 export directory unavailable")?;
        let engine = store.engine();
        let value = Self {
            root,
            network: engine.state().network(),
            genesis: engine.genesis().id(),
            rules: engine.genesis().rules_commitment(),
            latest: None,
            cached_head: None,
            blocks: Vec::new(),
            material_generation: std::cell::Cell::new(0),
        };
        value.check_root()?;
        value.write_once(
            "eng2-context.bin",
            &[
                value.network.as_slice(),
                value.genesis.as_slice(),
                value.rules.as_slice(),
            ]
            .concat(),
        )?;
        Ok(value)
    }
    fn check_root(&self) -> Result<(), String> {
        let metadata = self
            .root
            .metadata()
            .map_err(|_| "eng2 export directory metadata unavailable")?;
        if !metadata.is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o777 != 0o700
        {
            return Err("eng2 export requires a private owner directory with mode 700".into());
        }
        Ok(())
    }
    fn check_store(&self, store: &Store) -> Result<(), String> {
        self.check_root()?;
        store.ensure_exportable()?;
        if self.network != store.engine().state().network()
            || self.genesis != store.engine().genesis().id()
            || self.rules != store.engine().genesis().rules_commitment()
        {
            return Err("eng2 export is bound to another durable store".into());
        }
        Ok(())
    }
    /// Reuse the first durable candidate for this anchor and roster epoch,
    /// including its exact authorization head, after a restart or head advance.
    pub fn prepare_checkpoint(
        &mut self,
        store: &Store,
        limits: ImportLimits,
    ) -> Result<Option<PreparedCheckpoint>, String> {
        self.check_store(store)?;
        let state = store.engine().state();
        let Some(height) = eligible_checkpoint(state.height()) else {
            return Ok(None);
        };
        let name = candidate_name(state.governance().active_roster().epoch_sequence, height);
        if let Some(bytes) = self.read_optional(&name, candidate_bound(limits)?)? {
            return decode_candidate(store, &bytes, limits).map(Some);
        }
        let prepared = PreparedCheckpoint::prepare_from_archive(store, limits)?
            .ok_or("eligible checkpoint disappeared")?;
        self.write_candidate(&name, &prepared, limits)?;
        Ok(Some(prepared))
    }
    #[cfg(any(test, feature = "eng2-runtime"))]
    pub(super) fn retained_reader(
        &self,
        budget: &crate::p2p::Budget,
    ) -> Result<RetainedReader, String> {
        self.check_root()?;
        let memory = budget
            .reserve(64 * 1024)
            .map_err(|_| "checkpoint retained reader metadata budget unavailable")?;
        let mut material =
            blake3::Hasher::new_derive_key("siworld eng2 checkpoint retained material v1");
        material.update(&self.network);
        material.update(&self.genesis);
        material.update(&self.rules);
        let root = self
            .root
            .metadata()
            .map_err(|_| "checkpoint retained root metadata unavailable")?;
        material.update(&root.dev().to_le_bytes());
        material.update(&root.ino().to_le_bytes());
        Ok(RetainedReader {
            export: Self {
                root: self
                    .root
                    .try_clone()
                    .map_err(|_| "checkpoint retained directory duplicate failed")?,
                network: self.network,
                genesis: self.genesis,
                rules: self.rules,
                latest: None,
                cached_head: None,
                blocks: Vec::new(),
                material_generation: std::cell::Cell::new(0),
            },
            budget: budget.clone(),
            memory: std::cell::RefCell::new(vec![memory]),
            material: std::cell::RefCell::new(material),
        })
    }
    pub fn latest_height(&self) -> Option<u64> {
        self.latest.map(|row| row.0)
    }
    /// Persist only an internally prepared, currently matched candidate. The
    /// host invokes this under the original live signing-readiness guard.
    pub(super) fn retain_prepared(
        &self,
        store: &Store,
        prepared: &PreparedCheckpoint,
        limits: ImportLimits,
    ) -> Result<(), String> {
        self.check_store(store)?;
        prepared.check_current(store)?;
        self.write_candidate(
            &candidate_name(
                prepared.statement.roster_sequence,
                prepared.statement.checkpoint_height,
            ),
            prepared,
            limits,
        )
    }
    pub fn last_publication(&self) -> Option<u64> {
        self.latest.map(|row| row.2)
    }
    pub fn resume_candidate(
        &self,
        store: &Store,
        limits: ImportLimits,
    ) -> Result<Option<PreparedCheckpoint>, String> {
        self.check_store(store)?;
        let state = store.engine().state();
        let Some(height) = eligible_checkpoint(state.height()) else {
            return Ok(None);
        };
        let name = candidate_name(state.governance().active_roster().epoch_sequence, height);
        self.read_optional(&name, candidate_bound(limits)?)?
            .map(|bytes| decode_candidate(store, &bytes, limits))
            .transpose()
    }
    pub fn accept_proposal(
        &self,
        store: &Store,
        statement: Statement,
        witness: AuthorizationWitness,
        limits: ImportLimits,
    ) -> Result<PreparedCheckpoint, String> {
        self.check_store(store)?;
        let prepared = PreparedCheckpoint::from_proposal(store, statement, witness, limits)?;
        self.write_candidate(
            &candidate_name(
                prepared.statement.roster_sequence,
                prepared.statement.checkpoint_height,
            ),
            &prepared,
            limits,
        )?;
        Ok(prepared)
    }
    pub(super) fn write_status(&self, bytes: &[u8]) -> Result<(), String> {
        if bytes.len() > 8192 {
            return Err("checkpoint status exceeds byte bound".into());
        }
        self.replace("checkpoint-status-eng2.json", bytes)
    }
    /// The caller supplies a borrowed protected key. The exact public candidate
    /// and signature are journaled durably before a vote can leave this method.
    pub fn sign_vote(
        &mut self,
        store: &Store,
        prepared: &PreparedCheckpoint,
        slot: u8,
        key: &MLDSA65SigningKey,
        randomness: [u8; 32],
        limits: ImportLimits,
    ) -> Result<Vote, String> {
        self.check_store(store)?;
        prepared.check_current(store)?;
        self.write_candidate(
            &candidate_name(
                prepared.statement.roster_sequence,
                prepared.statement.checkpoint_height,
            ),
            prepared,
            limits,
        )?;
        let name = format!(
            "vote-{:020}-{:020}-{}.eng2.bin",
            prepared.statement.roster_sequence, prepared.statement.checkpoint_height, slot
        );
        let statement = prepared
            .statement
            .encode()
            .map_err(|_| "checkpoint statement malformed")?;
        if let Some(bytes) = self.read_optional(
            &name,
            super::super::certificate::STATEMENT_BYTES
                + 1
                + super::super::certificate::SIGNATURE_BYTES,
        )? {
            let vote = decode_vote(&statement, slot, &bytes)?;
            prepared.verify_vote(&vote)?;
            return Ok(vote);
        }
        let vote = prepared.sign(store, slot, key, randomness)?;
        self.write_once(
            &name,
            &[statement.as_slice(), &[slot], vote.signature.as_slice()].concat(),
        )?;
        Ok(vote)
    }
    /// Restore public artifacts only after checking exact cursor fields, content
    /// digests, local historical state, executed authorization and both signatures.
    pub fn restore_latest(
        &self,
        store: &Store,
        limits: ImportLimits,
    ) -> Result<Option<CertifiedCheckpoint>, String> {
        self.check_store(store)?;
        let Some(bytes) = self.read_optional("checkpoint-eng2.json", 8192)? else {
            return Ok(None);
        };
        let saved = self.read_publication(&bytes, limits)?;
        let prepared = PreparedCheckpoint::restore_prefix(
            store,
            saved.certificate.statement.clone(),
            saved.witness,
            saved.snapshot,
            limits,
        )?;
        saved
            .certificate
            .check_signatures(prepared.roster.keys())
            .map_err(|_| "checkpoint publication signatures invalid")?;
        Ok(Some(CertifiedCheckpoint {
            prepared,
            certificate: saved.certificate,
            published: saved.published,
        }))
    }
    fn read_publication(
        &self,
        bytes: &[u8],
        limits: ImportLimits,
    ) -> Result<SavedPublication, String> {
        self.read_publication_using(bytes, limits, |name, bound| self.read(name, bound))
    }
    fn read_publication_using(
        &self,
        bytes: &[u8],
        limits: ImportLimits,
        mut read: impl FnMut(&str, usize) -> Result<Vec<u8>, String>,
    ) -> Result<SavedPublication, String> {
        let cursor: Value =
            serde_json::from_slice(bytes).map_err(|_| "checkpoint publication cursor malformed")?;
        const FIELDS: [&str; 14] = [
            "version",
            "network",
            "genesis",
            "rules_commitment",
            "height",
            "checkpoint_block",
            "authorization_height",
            "authorization_block",
            "published_unix_seconds",
            "certificate_digest",
            "certificate_file",
            "witness_file",
            "snapshot_file",
            "snapshot_bytes",
        ];
        let object = cursor
            .as_object()
            .ok_or("checkpoint publication cursor must be an object")?;
        if object.len() != FIELDS.len()
            || !FIELDS.iter().all(|key| object.contains_key(*key))
            || cursor["version"] != 2
            || cursor["network"] != crate::local::hex(&self.network)
            || cursor["genesis"] != crate::local::hex(&self.genesis)
            || cursor["rules_commitment"] != crate::local::hex(&self.rules)
        {
            return Err("checkpoint publication cursor differs from the export context".into());
        }
        let digest = decode_hash(
            cursor["certificate_digest"]
                .as_str()
                .ok_or("checkpoint certificate digest missing")?,
        )?;
        let certificate_name = artifact_name(&cursor, "certificate_file", ".certificate-eng2.bin")?;
        if certificate_name != format!("{}.certificate-eng2.bin", crate::local::hex(&digest)) {
            return Err("checkpoint certificate filename differs from its digest".into());
        }
        let certificate = read(
            &certificate_name,
            super::super::certificate::CERTIFICATE_BYTES,
        )?;
        if *blake3::hash(&certificate).as_bytes() != digest {
            return Err("checkpoint certificate digest differs".into());
        }
        let certificate = Certificate::decode(&certificate, self.network)
            .map_err(|_| "checkpoint publication certificate malformed")?;
        let statement = &certificate.statement;
        if cursor["height"].as_u64() != Some(statement.checkpoint_height)
            || cursor["checkpoint_block"] != crate::local::hex(&statement.checkpoint_block)
            || cursor["authorization_height"].as_u64() != Some(statement.authorization_height)
            || cursor["authorization_block"] != crate::local::hex(&statement.authorization_block)
        {
            return Err("checkpoint publication cursor differs from its statement".into());
        }
        let witness_name = artifact_name(&cursor, "witness_file", ".witness-eng2.bin")?;
        let snapshot_name = artifact_name(&cursor, "snapshot_file", ".snapshot-eng2.bin")?;
        let witness = read(&witness_name, witness_bound(limits)?)?;
        let snapshot = read(&snapshot_name, limits.max_snapshot_bytes)?;
        if witness_name != format!("{}.witness-eng2.bin", blake3::hash(&witness).to_hex())
            || snapshot_name != format!("{}.snapshot-eng2.bin", blake3::hash(&snapshot).to_hex())
            || cursor["snapshot_bytes"].as_u64() != Some(snapshot.len() as u64)
        {
            return Err("checkpoint public dependency digest or length differs".into());
        }
        let witness = AuthorizationWitness::decode(&witness, limits.chain.max_component_bytes)
            .map_err(|_| "invalid checkpoint publication witness")?;
        let published = cursor["published_unix_seconds"]
            .as_u64()
            .filter(|v| *v < (1u64 << 53))
            .ok_or("checkpoint publication time invalid")?;
        Ok(SavedPublication {
            certificate,
            witness,
            snapshot,
            published,
        })
    }
    fn retained_votes(&self, statement: &Statement) -> Result<Vec<Vote>, String> {
        self.retained_votes_using(statement, |name, bound| self.read_optional(name, bound))
    }
    fn retained_votes_using(
        &self,
        statement: &Statement,
        mut read: impl FnMut(&str, usize) -> Result<Option<Vec<u8>>, String>,
    ) -> Result<Vec<Vote>, String> {
        let encoded = statement
            .encode()
            .map_err(|_| "checkpoint journal statement invalid")?;
        let mut votes = Vec::new();
        for slot in 0..3 {
            let name = format!(
                "vote-{:020}-{:020}-{slot}.eng2.bin",
                statement.roster_sequence, statement.checkpoint_height
            );
            if let Some(bytes) = read(
                &name,
                encoded.len() + 1 + super::super::certificate::SIGNATURE_BYTES,
            )? {
                votes.push(decode_vote(&encoded, slot, &bytes)?);
            }
        }
        Ok(votes)
    }
    pub(super) fn restore_latest_retained(
        &self,
        store: &Store,
        limits: ImportLimits,
        retained: &mut impl FnMut(u64, Hash) -> Result<Option<Header>, String>,
    ) -> Result<super::retained::Restored<CertifiedCheckpoint>, String> {
        self.check_store(store)?;
        let Some(bytes) = self.read_optional("checkpoint-eng2.json", 8192)? else {
            return Ok(super::retained::Restored::Absent);
        };
        let saved = self.read_publication(&bytes, limits)?;
        let votes = self.retained_votes(&saved.certificate.statement)?;
        super::retained::publication(
            store,
            saved.certificate,
            saved.witness,
            saved.snapshot,
            saved.published,
            &votes,
            limits,
            retained,
        )
    }
    /// Keep the first publication time outside the mutable advertisement. This
    /// is an immutable publication dependency, not a switch recovery journal.
    pub(super) fn withdraw_checkpoint(
        &mut self,
        checkpoint: &CertifiedCheckpoint,
    ) -> Result<(), String> {
        let cursor = self.publication_cursor(checkpoint)?;
        if let Some(old) = self.read_optional("checkpoint-eng2.json", 8192)? {
            let actual: Value = serde_json::from_slice(&old)
                .map_err(|_| "checkpoint cursor malformed before withdrawal")?;
            let expected: Value = serde_json::from_slice(&cursor)
                .map_err(|_| "checkpoint cursor construction invalid")?;
            if actual != expected {
                return Err("checkpoint cursor differs before withdrawal".into());
            }
        }
        self.write_once(
            &publication_name(checkpoint.certificate.statement.checkpoint_height),
            &cursor,
        )?;
        self.remove_cursor("checkpoint-eng2.json")?;
        self.latest = None;
        Ok(())
    }
    pub(super) fn remove_retired_checkpoint_cursor(&mut self, height: u64) -> Result<(), String> {
        let bytes = self
            .read_optional("checkpoint-eng2.json", 8192)?
            .ok_or("checked retired checkpoint cursor disappeared")?;
        self.write_once(&publication_name(height), &bytes)?;
        self.remove_cursor("checkpoint-eng2.json")?;
        self.latest = None;
        Ok(())
    }
    fn remove_cursor(&self, name: &str) -> Result<(), String> {
        if self.read_optional(name, 8192)?.is_some() {
            self.note_material_write(name)?;
            match unlinkat(&self.root, name, AtFlags::empty()) {
                Ok(()) | Err(rustix::io::Errno::NOENT) => (),
                Err(_) => return Err("checkpoint cursor withdrawal failed".into()),
            }
            fsync(&self.root).map_err(|_| "checkpoint cursor withdrawal sync failed")?;
        }
        Ok(())
    }
    fn publication_cursor(&self, checkpoint: &CertifiedCheckpoint) -> Result<Vec<u8>, String> {
        let certificate = checkpoint
            .certificate
            .encode()
            .map_err(|_| "checkpoint certificate malformed")?;
        let witness = checkpoint
            .witness()
            .encode(usize::MAX)
            .map_err(|_| "checkpoint witness encoding invalid")?;
        let digest = *blake3::hash(&certificate).as_bytes();
        let statement = &checkpoint.certificate.statement;
        let snapshot_name = format!(
            "{}.snapshot-eng2.bin",
            blake3::hash(checkpoint.snapshot_bytes()).to_hex()
        );
        let witness_name = format!("{}.witness-eng2.bin", blake3::hash(&witness).to_hex());
        let certificate_name = format!("{}.certificate-eng2.bin", crate::local::hex(&digest));
        serde_json::to_vec(&json!({"version":2,"network":crate::local::hex(&self.network),"genesis":crate::local::hex(&self.genesis),
            "rules_commitment":crate::local::hex(&self.rules),"height":statement.checkpoint_height,"checkpoint_block":crate::local::hex(&statement.checkpoint_block),
            "authorization_height":statement.authorization_height,"authorization_block":crate::local::hex(&statement.authorization_block),
            "published_unix_seconds":checkpoint.published,"certificate_digest":crate::local::hex(&digest),"certificate_file":certificate_name,
            "witness_file":witness_name,"snapshot_file":snapshot_name,"snapshot_bytes":checkpoint.snapshot_bytes().len()}))
            .map_err(|_| "checkpoint cursor encoding failed".into())
    }
    pub(super) fn resume_candidate_retained(
        &self,
        store: &Store,
        limits: ImportLimits,
        retained: &mut impl FnMut(u64, Hash) -> Result<Option<Header>, String>,
    ) -> Result<super::retained::Restored<PreparedCheckpoint>, String> {
        use super::retained::Restored;
        self.check_store(store)?;
        let state = store.engine().state();
        let Some(height) = eligible_checkpoint(state.height()) else {
            return Ok(Restored::Absent);
        };
        let epoch = state.governance().active_roster().epoch_sequence;
        let mut candidate = Restored::Absent;
        if let Some(bytes) =
            self.read_optional(&candidate_name(epoch, height), candidate_bound(limits)?)?
        {
            let (statement, witness, snapshot) =
                decode_candidate_parts(&bytes, state.network(), limits)?;
            if statement.checkpoint_height != height || statement.roster_sequence != epoch {
                return Err("saved checkpoint candidate filename context differs".into());
            }
            let votes = self.retained_votes(&statement)?;
            candidate = super::retained::candidate(
                store, statement, witness, snapshot, &votes, limits, retained,
            )?;
        }
        if let Some(bytes) = self.read_optional(&publication_name(height), 8192)? {
            let saved = self.read_publication(&bytes, limits)?;
            if saved.certificate.statement.checkpoint_height != height {
                return Err("checkpoint publication filename height differs".into());
            }
            let votes = self.retained_votes(&saved.certificate.statement)?;
            // Even a still-current original certificate is retired here: a
            // withdrawn cursor must not cause certification with a new time.
            let _checked = super::retained::publication(
                store,
                saved.certificate,
                saved.witness,
                saved.snapshot,
                saved.published,
                &votes,
                limits,
                retained,
            )?;
            return Ok(Restored::Retired(height));
        }
        Ok(candidate)
    }
    /// Snapshot dependencies precede the cursor. A duplicate certificate never
    /// refreshes the local pruning-staleness clock or overwrites public content.
    pub fn publish_checkpoint(
        &mut self,
        store: &Store,
        checkpoint: &CertifiedCheckpoint,
        limits: ImportLimits,
    ) -> Result<bool, String> {
        self.check_store(store)?;
        checkpoint.check_current(store)?;
        let certificate = checkpoint
            .certificate
            .encode()
            .map_err(|_| "checkpoint certificate malformed")?;
        let digest = *blake3::hash(&certificate).as_bytes();
        let statement = &checkpoint.certificate.statement;
        if !self.accept_publication(statement.checkpoint_height, digest, checkpoint.published)? {
            return Ok(false);
        }
        if checkpoint.snapshot_bytes().len() > limits.max_snapshot_bytes {
            return Err("checkpoint public snapshot exceeds local byte bound".into());
        }
        let witness = checkpoint
            .witness()
            .encode(limits.chain.max_component_bytes)
            .map_err(|_| "checkpoint witness exceeds local byte bound")?;
        let snapshot_name = format!(
            "{}.snapshot-eng2.bin",
            blake3::hash(checkpoint.snapshot_bytes()).to_hex()
        );
        let witness_name = format!("{}.witness-eng2.bin", blake3::hash(&witness).to_hex());
        let certificate_name = format!("{}.certificate-eng2.bin", crate::local::hex(&digest));
        self.write_once(&snapshot_name, checkpoint.snapshot_bytes())?;
        self.write_once(&witness_name, &witness)?;
        self.write_once(&certificate_name, &certificate)?;
        let cursor = self.publication_cursor(checkpoint)?;
        self.write_once(&publication_name(statement.checkpoint_height), &cursor)?;
        checkpoint.check_current(store)?;
        self.replace("checkpoint-eng2.json", &cursor)?;
        self.latest = Some((statement.checkpoint_height, digest, checkpoint.published));
        Ok(true)
    }
    fn accept_publication(&self, height: u64, digest: Hash, now: u64) -> Result<bool, String> {
        if let Some((previous_height, previous_digest, published)) = self.latest {
            if height < previous_height || now < published {
                return Err("checkpoint publication rollback rejected".into());
            }
            if height == previous_height {
                return if digest == previous_digest {
                    Ok(false)
                } else {
                    Err(
                        "another certificate already occupies this checkpoint publication height"
                            .into(),
                    )
                };
            }
        }
        Ok(true)
    }
    pub fn publication_due(&self, now: u64, head: u64) -> Result<bool, String> {
        let Some(height) = eligible_checkpoint(head) else {
            return Ok(false);
        };
        match self.latest {
            None => Ok(true),
            Some((previous, _, published)) => {
                let _elapsed = now
                    .checked_sub(published)
                    .ok_or("checkpoint publication clock moved backwards")?;
                Ok(height > previous)
            }
        }
    }
    pub fn pruning_paused(&self, now: u64) -> Result<bool, String> {
        match self.latest {
            None => Ok(true),
            Some((_, _, published)) => Ok(now
                .checked_sub(published)
                .ok_or("checkpoint publication clock moved backwards")?
                > STALE_SECONDS),
        }
    }
    /// The initial write reads at most 101 bodies. Subsequent calls decode only
    /// new rows; the cached-head guard reads only a header, never a proof body.
    pub fn publish_current(
        &mut self,
        store: &Store,
        published: u64,
        checkpoint: Option<&CertifiedCheckpoint>,
    ) -> Result<(), String> {
        self.check_store(store)?;
        let state = store.engine().state();
        let minimum = state.height().saturating_sub(100).max(1);
        let mut blocks = Vec::new();
        let mut next = minimum;
        if let Some((height, id)) = self.cached_head
            && height <= state.height()
            && (height == 0 && id == self.genesis
                || height > 0
                    && store
                        .header(height)?
                        .id()
                        .map_err(|_| "invalid cached export head")?
                        == id)
        {
            blocks = self
                .blocks
                .iter()
                .filter(|row| row["height"].as_u64().is_some_and(|h| h >= minimum))
                .cloned()
                .collect();
            next = (height + 1).max(minimum);
        }
        for height in next..=state.height() {
            blocks.push(public_block(store, height)?);
        }
        let value = projection_with_blocks(store, published, checkpoint, blocks.clone())?;
        let bytes = serde_json::to_vec(&value).map_err(|_| "eng2 projection encoding failed")?;
        self.replace("explorer.json", &bytes)?;
        self.cached_head = Some((state.height(), state.tip()));
        self.blocks = blocks;
        Ok(())
    }
    fn open_read(&self, name: &str, limit: usize) -> Result<Option<fs::File>, String> {
        self.check_root()?;
        let descriptor = match openat(
            &self.root,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(value) => value,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => return Err("eng2 public artifact unavailable".into()),
        };
        let file = fs::File::from(descriptor);
        let metadata = file
            .metadata()
            .map_err(|_| "eng2 public artifact metadata unavailable")?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.len() > limit as u64
        {
            return Err("eng2 public artifact type, permissions or byte bound invalid".into());
        }
        Ok(Some(file))
    }
    fn read_optional(&self, name: &str, limit: usize) -> Result<Option<Vec<u8>>, String> {
        let Some(file) = self.open_read(name, limit)? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file.take((limit as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| "eng2 public artifact read failed")?;
        if bytes.len() > limit {
            return Err("eng2 public artifact exceeds byte bound".into());
        }
        Ok(Some(bytes))
    }
    fn read(&self, name: &str, limit: usize) -> Result<Vec<u8>, String> {
        self.read_optional(name, limit)?
            .ok_or_else(|| "eng2 public artifact missing".into())
    }
    pub(super) fn material_generation(&self) -> u64 {
        self.material_generation.get()
    }
    fn note_material_write(&self, name: &str) -> Result<(), String> {
        if name == "checkpoint-eng2.json"
            || name.starts_with("candidate-")
            || name.starts_with("vote-")
            || name.starts_with("checkpoint-publication-")
            || name.ends_with(".snapshot-eng2.bin")
            || name.ends_with(".witness-eng2.bin")
            || name.ends_with(".certificate-eng2.bin")
        {
            self.material_generation.set(
                self.material_generation
                    .get()
                    .checked_add(1)
                    .ok_or("checkpoint material generation exhausted")?,
            );
        }
        Ok(())
    }
    #[cfg(feature = "eng2-runtime")]
    pub(super) fn forget_publication(&mut self) {
        self.latest = None;
    }
    #[cfg(feature = "eng2-runtime")]
    pub(super) fn retire_checked_cursor(
        &mut self,
        height: u64,
        expected: &[u8],
    ) -> Result<(), String> {
        if self.read_optional("checkpoint-eng2.json", 8192)?.as_deref() != Some(expected) {
            return Err("checkpoint retired cursor changed after authentication".into());
        }
        self.write_once(&publication_name(height), expected)?;
        self.remove_cursor("checkpoint-eng2.json")?;
        self.latest = None;
        Ok(())
    }
    fn write_candidate(
        &self,
        name: &str,
        prepared: &PreparedCheckpoint,
        limits: ImportLimits,
    ) -> Result<(), String> {
        let encoded = CandidateEncoding::new(prepared, limits)?;
        self.write_once_parts(name, &encoded.parts())
    }
    fn immutable_matches_parts(
        &self,
        name: &str,
        parts: &[&[u8]],
        length: usize,
    ) -> Result<Option<bool>, String> {
        let Some(mut file) = self.open_read(name, length)? else {
            return Ok(None);
        };
        // Compare actual bytes, including the final chunk. Metadata or a cached
        // digest cannot establish immutable-file equality.
        let mut buffer = [0u8; IMMUTABLE_COMPARE_BYTES];
        for part in parts {
            for expected in part.chunks(IMMUTABLE_COMPARE_BYTES) {
                if let Err(error) = file.read_exact(&mut buffer[..expected.len()]) {
                    return if error.kind() == std::io::ErrorKind::UnexpectedEof {
                        Ok(Some(false))
                    } else {
                        Err("eng2 public artifact read failed".into())
                    };
                }
                if &buffer[..expected.len()] != expected {
                    return Ok(Some(false));
                }
            }
        }
        let mut trailing = [0u8; 1];
        if file
            .read(&mut trailing)
            .map_err(|_| "eng2 public artifact read failed")?
            != 0
        {
            return Err("eng2 public artifact exceeds byte bound".into());
        }
        Ok(Some(true))
    }
    fn write_once(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        self.write_once_parts(name, &[bytes])
    }
    fn write_once_parts(&self, name: &str, parts: &[&[u8]]) -> Result<(), String> {
        let length = parts.iter().try_fold(0usize, |length, part| {
            length
                .checked_add(part.len())
                .ok_or("eng2 immutable artifact length overflow")
        })?;
        if let Some(matches) = self.immutable_matches_parts(name, parts, length)? {
            return if matches {
                Ok(())
            } else {
                Err("eng2 immutable public artifact differs".into())
            };
        }
        self.note_material_write(name)?;
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)
            .map_err(|_| "eng2 immutable temporary identity unavailable")?;
        let temporary = format!("{}.tmp", crate::local::hex(&random));
        let result: Result<(), String> = (|| {
            let descriptor = openat(
                &self.root,
                temporary.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| "eng2 immutable temporary create failed")?;
            let mut file = fs::File::from(descriptor);
            for part in parts {
                file.write_all(part)
                    .map_err(|_| "eng2 immutable temporary write failed")?;
            }
            file.sync_all()
                .map_err(|_| "eng2 immutable temporary write failed")?;
            self.install_immutable_parts(temporary.as_str(), name, parts, length)?;
            fsync(&self.root).map_err(|_| "eng2 immutable public directory sync failed".into())
        })();
        // Only this invocation's uninstalled temporary file may be removed.
        let _ = unlinkat(&self.root, temporary.as_str(), AtFlags::empty());
        result
    }
    #[cfg(any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android",
        target_os = "redox"
    ))]
    fn install_immutable_parts(
        &self,
        temporary: &str,
        name: &str,
        parts: &[&[u8]],
        length: usize,
    ) -> Result<(), String> {
        match rustix::fs::renameat_with(
            &self.root,
            temporary,
            &self.root,
            name,
            rustix::fs::RenameFlags::NOREPLACE,
        ) {
            Ok(()) => Ok(()),
            Err(rustix::io::Errno::EXIST) => {
                if self.immutable_matches_parts(name, parts, length)? == Some(true) {
                    Ok(())
                } else {
                    Err("eng2 concurrent immutable public artifact differs".into())
                }
            }
            Err(_) => Err("eng2 immutable atomic installation failed".into()),
        }
    }
    #[cfg(not(any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android",
        target_os = "redox"
    )))]
    fn install_immutable_parts(
        &self,
        _temporary: &str,
        _name: &str,
        _parts: &[&[u8]],
        _length: usize,
    ) -> Result<(), String> {
        Err("eng2 immutable atomic publication is unsupported on this platform".into())
    }
    fn replace(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        self.note_material_write(name)?;
        // Refuse a symlink, shared file or permission change at the old cursor.
        self.read_optional(name, MAX_PROJECTION_BYTES)?;
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(|_| "eng2 export temporary identity unavailable")?;
        let temporary = format!("{}.tmp", crate::local::hex(&random));
        let result: Result<(), String> = (|| {
            let descriptor = openat(
                &self.root,
                temporary.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| "eng2 export temporary write unavailable")?;
            let mut file = fs::File::from(descriptor);
            file.write_all(bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| "eng2 export write failed")?;
            renameat(&self.root, temporary.as_str(), &self.root, name)
                .map_err(|_| "eng2 export atomic replacement failed")?;
            fsync(&self.root).map_err(|_| "eng2 export directory sync failed".into())
        })();
        if result.is_err() {
            let _ = unlinkat(&self.root, temporary.as_str(), AtFlags::empty());
        }
        result
    }
}
/// Read-only operations exposed to the one owned validation worker. No writer,
/// signer, Store or mutable cursor API is available through this wrapper.
#[cfg(any(test, feature = "eng2-runtime"))]
pub(super) struct RetainedReader {
    export: PublicExport,
    budget: crate::p2p::Budget,
    memory: std::cell::RefCell<Vec<crate::p2p::Reservation>>,
    material: std::cell::RefCell<blake3::Hasher>,
}
#[cfg(any(test, feature = "eng2-runtime"))]
impl RetainedReader {
    fn observe(&self, name: &str, bytes: Option<&[u8]>) {
        let mut hash = self.material.borrow_mut();
        hash.update(&(name.len() as u64).to_le_bytes());
        hash.update(name.as_bytes());
        hash.update(&[u8::from(bytes.is_some())]);
        if let Some(bytes) = bytes {
            hash.update(&(bytes.len() as u64).to_le_bytes());
            hash.update(blake3::hash(bytes).as_bytes());
        }
    }
    pub(super) fn material_identity(&self) -> Hash {
        *self.material.borrow().clone().finalize().as_bytes()
    }
    pub(super) fn read_optional(
        &self,
        name: &str,
        limit: usize,
    ) -> Result<Option<Vec<u8>>, String> {
        self.export.check_root()?;
        let descriptor = match openat(
            &self.export.root,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(value) => value,
            Err(rustix::io::Errno::NOENT) => {
                self.observe(name, None);
                return Ok(None);
            }
            Err(_) => return Err("checkpoint retained artifact open failed".into()),
        };
        let mut file = fs::File::from(descriptor);
        let before = file
            .metadata()
            .map_err(|_| "checkpoint retained metadata unavailable")?;
        if !before.is_file()
            || before.nlink() != 1
            || before.uid() != rustix::process::geteuid().as_raw()
            || before.permissions().mode() & 0o777 != 0o600
            || before.len() > limit as u64
        {
            return Err("checkpoint retained artifact type, permissions or bound invalid".into());
        }
        let length =
            usize::try_from(before.len()).map_err(|_| "checkpoint retained length overflow")?;
        let mut charge = length
            .checked_mul(2)
            .ok_or("checkpoint retained workspace overflow")?;
        if name.ends_with(".witness-eng2.bin") {
            charge = length
                .checked_mul(16)
                .ok_or("checkpoint retained witness workspace overflow")?;
        } else if name.starts_with("candidate-") {
            const PREFIX: usize = 6 + super::super::certificate::STATEMENT_BYTES;
            let mut framing = [0; PREFIX + 16];
            file.read_exact(&mut framing)
                .map_err(|_| "checkpoint retained candidate framing unavailable")?;
            let witness = usize::try_from(u64::from_le_bytes(
                framing[PREFIX..PREFIX + 8]
                    .try_into()
                    .expect("fixed witness length"),
            ))
            .map_err(|_| "checkpoint retained witness length overflow")?;
            charge = charge
                .checked_add(
                    witness
                        .checked_mul(14)
                        .ok_or("checkpoint retained witness workspace overflow")?,
                )
                .ok_or("checkpoint retained workspace overflow")?;
            file.seek(SeekFrom::Start(0))
                .map_err(|_| "checkpoint retained candidate rewind failed")?;
        }
        let reservation = self
            .budget
            .reserve(charge)
            .map_err(|_| "checkpoint retained artifact budget unavailable")?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| "checkpoint retained allocation failed")?;
        bytes.resize(length, 0);
        file.read_exact(&mut bytes)
            .map_err(|_| "checkpoint retained artifact read failed")?;
        let mut trailing = [0; 1];
        if file
            .read(&mut trailing)
            .map_err(|_| "checkpoint retained trailing read failed")?
            != 0
        {
            return Err("checkpoint retained artifact length changed".into());
        }
        let after = file
            .metadata()
            .map_err(|_| "checkpoint retained metadata disappeared")?;
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || before.uid() != after.uid()
            || before.permissions().mode() != after.permissions().mode()
            || after.nlink() != 1
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return Err("checkpoint retained artifact changed while reading".into());
        }
        if bytes.capacity() > charge {
            return Err("checkpoint retained capacity exceeds reservation".into());
        }
        self.observe(name, Some(&bytes));
        self.memory.borrow_mut().push(reservation);
        Ok(Some(bytes))
    }
    #[cfg(feature = "eng2-runtime")]
    pub(super) fn read_publication(
        &self,
        bytes: &[u8],
        limits: ImportLimits,
    ) -> Result<SavedPublication, String> {
        self.export
            .read_publication_using(bytes, limits, |name, bound| {
                self.read_optional(name, bound)?
                    .ok_or_else(|| "checkpoint retained dependency missing".into())
            })
    }
    #[cfg(feature = "eng2-runtime")]
    pub(super) fn votes(&self, statement: &Statement) -> Result<Vec<Vote>, String> {
        self.export
            .retained_votes_using(statement, |name, bound| self.read_optional(name, bound))
    }
    #[cfg(feature = "eng2-runtime")]
    pub(super) fn candidate(
        &self,
        epoch: u64,
        height: u64,
        limits: ImportLimits,
    ) -> Result<Option<(Statement, AuthorizationWitness, Vec<u8>)>, String> {
        self.read_optional(&candidate_name(epoch, height), candidate_bound(limits)?)?
            .map(|bytes| decode_candidate_parts(&bytes, self.export.network, limits))
            .transpose()
    }
    #[cfg(feature = "eng2-runtime")]
    pub(super) fn withdrawn(&self, height: u64) -> Result<Option<Vec<u8>>, String> {
        self.read_optional(&publication_name(height), 8192)
    }
}

fn candidate_name(epoch: u64, height: u64) -> String {
    format!("candidate-{epoch:020}-{height:020}.eng2.bin")
}
fn witness_bound(limits: ImportLimits) -> Result<usize, String> {
    limits
        .chain
        .max_component_bytes
        .checked_add(10 + 11 * super::super::commitment::DESCRIPTOR_BYTES)
        .ok_or_else(|| "checkpoint witness bound overflow".into())
}
fn candidate_bound(limits: ImportLimits) -> Result<usize, String> {
    limits
        .max_snapshot_bytes
        .checked_add(witness_bound(limits)?)
        .and_then(|n| n.checked_add(6 + super::super::certificate::STATEMENT_BYTES + 16))
        .ok_or_else(|| "checkpoint candidate bound overflow".into())
}
const IMMUTABLE_COMPARE_BYTES: usize = 64 * 1024;

/// The snapshot stays borrowed for the complete write and equality comparison.
/// The encoded candidate format remains unchanged.
struct CandidateEncoding<'a> {
    statement: [u8; super::super::certificate::STATEMENT_BYTES],
    lengths: [u8; 16],
    witness: Vec<u8>,
    snapshot: &'a [u8],
}
impl<'a> CandidateEncoding<'a> {
    fn new(prepared: &'a PreparedCheckpoint, limits: ImportLimits) -> Result<Self, String> {
        let statement = prepared
            .statement
            .encode()
            .map_err(|_| "checkpoint statement malformed")?;
        let witness = prepared
            .witness
            .encode(limits.chain.max_component_bytes)
            .map_err(|_| "checkpoint witness exceeds bounds")?;
        let snapshot = prepared.snapshot_bytes();
        if snapshot.len() > limits.max_snapshot_bytes {
            return Err("checkpoint candidate snapshot exceeds bounds".into());
        }
        let length = 6usize
            .checked_add(statement.len())
            .and_then(|n| n.checked_add(16))
            .and_then(|n| n.checked_add(witness.len()))
            .and_then(|n| n.checked_add(snapshot.len()))
            .ok_or("checkpoint candidate bound overflow")?;
        if length > candidate_bound(limits)? {
            return Err("checkpoint candidate exceeds bounds".into());
        }
        let mut lengths = [0u8; 16];
        lengths[..8].copy_from_slice(&(witness.len() as u64).to_le_bytes());
        lengths[8..].copy_from_slice(&(snapshot.len() as u64).to_le_bytes());
        Ok(Self {
            statement,
            lengths,
            witness,
            snapshot,
        })
    }
    fn parts(&self) -> [&[u8]; 5] {
        [
            b"SW2P\x01\x00",
            &self.statement,
            &self.lengths,
            &self.witness,
            self.snapshot,
        ]
    }
}

// Preserve the previous contiguous encoder as an independent format oracle.
#[cfg(test)]
fn encode_candidate(
    prepared: &PreparedCheckpoint,
    limits: ImportLimits,
) -> Result<Vec<u8>, String> {
    let statement = prepared
        .statement
        .encode()
        .map_err(|_| "checkpoint statement malformed")?;
    let witness = prepared
        .witness
        .encode(limits.chain.max_component_bytes)
        .map_err(|_| "checkpoint witness exceeds bounds")?;
    let snapshot = prepared.snapshot_bytes();
    if snapshot.len() > limits.max_snapshot_bytes {
        return Err("checkpoint candidate snapshot exceeds bounds".into());
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(
            candidate_bound(limits)?.min(6 + statement.len() + 16 + witness.len() + snapshot.len()),
        )
        .map_err(|_| "checkpoint candidate allocation failed")?;
    bytes.extend_from_slice(b"SW2P\x01\x00");
    bytes.extend_from_slice(&statement);
    bytes.extend_from_slice(&(witness.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&(snapshot.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&witness);
    bytes.extend_from_slice(snapshot);
    Ok(bytes)
}
fn decode_candidate(
    store: &Store,
    bytes: &[u8],
    limits: ImportLimits,
) -> Result<PreparedCheckpoint, String> {
    let (statement, witness, snapshot) =
        decode_candidate_parts(bytes, store.engine().state().network(), limits)?;
    PreparedCheckpoint::restore(store, statement, witness, snapshot, limits)
}
fn decode_candidate_parts(
    bytes: &[u8],
    network: Hash,
    limits: ImportLimits,
) -> Result<(Statement, AuthorizationWitness, Vec<u8>), String> {
    let prefix = 6 + super::super::certificate::STATEMENT_BYTES;
    if bytes.len() > candidate_bound(limits)?
        || bytes.len() < prefix + 16
        || &bytes[..6] != b"SW2P\x01\x00"
    {
        return Err("checkpoint candidate encoding invalid".into());
    }
    let statement = Statement::decode(&bytes[6..prefix], network)
        .map_err(|_| "checkpoint candidate statement malformed")?;
    let witness_len = usize::try_from(u64::from_le_bytes(
        bytes[prefix..prefix + 8].try_into().expect("fixed length"),
    ))
    .map_err(|_| "checkpoint witness length overflow")?;
    let snapshot_len = usize::try_from(u64::from_le_bytes(
        bytes[prefix + 8..prefix + 16]
            .try_into()
            .expect("fixed length"),
    ))
    .map_err(|_| "checkpoint snapshot length overflow")?;
    let witness_end = (prefix + 16)
        .checked_add(witness_len)
        .ok_or("checkpoint candidate length overflow")?;
    if witness_len > witness_bound(limits)?
        || snapshot_len > limits.max_snapshot_bytes
        || witness_end.checked_add(snapshot_len) != Some(bytes.len())
    {
        return Err("checkpoint candidate length differs".into());
    }
    let witness = AuthorizationWitness::decode(
        &bytes[prefix + 16..witness_end],
        limits.chain.max_component_bytes,
    )
    .map_err(|_| "checkpoint candidate witness malformed")?;
    Ok((statement, witness, bytes[witness_end..].to_vec()))
}
fn decode_vote(statement: &[u8], slot: u8, bytes: &[u8]) -> Result<Vote, String> {
    if bytes.len() != statement.len() + 1 + super::super::certificate::SIGNATURE_BYTES
        || bytes[..statement.len()] != *statement
        || bytes[statement.len()] != slot
    {
        return Err(
            "checkpoint journal refuses another statement for this anchor and signer epoch".into(),
        );
    }
    Ok(Vote {
        slot,
        signature: bytes[statement.len() + 1..]
            .try_into()
            .map_err(|_| "checkpoint vote journal signature malformed")?,
    })
}
fn artifact_name(cursor: &Value, key: &str, suffix: &str) -> Result<String, String> {
    let text = cursor[key]
        .as_str()
        .ok_or("checkpoint artifact filename missing")?;
    decode_hash(
        text.strip_suffix(suffix)
            .ok_or("checkpoint artifact filename suffix differs")?,
    )?;
    Ok(text.into())
}
fn decode_hash(text: &str) -> Result<Hash, String> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid canonical public digest".into());
    }
    let mut result = [0; 32];
    for (out, pair) in result.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        let nibble = |b: u8| {
            if b.is_ascii_digit() {
                b - b'0'
            } else {
                b - b'a' + 10
            }
        };
        *out = nibble(pair[0]) * 16 + nibble(pair[1]);
    }
    Ok(result)
}

#[cfg(test)]
mod tests;
