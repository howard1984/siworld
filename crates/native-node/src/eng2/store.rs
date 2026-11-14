//! Durable versioned history and authenticated locally committed-state recovery.
//!
//! Native verification precedes every canonical commit. Explicit audits replay
//! that history; ordinary recovery requires the same atomic accepted-state seal
//! and existing local identity, without treating imported state as accepted.

use super::{
    body::Body,
    execution::{CommittedBlock, Engine},
    genesis::Genesis,
    header::{HEADER_BYTES, Header},
    state_components::Limits,
};
use crate::{proofs::NativeVerifier, wire::Hash};
use redb::{
    Database, Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
};
#[cfg(not(windows))]
use std::fs::OpenOptions;
use std::path::Path;
#[cfg(all(test, unix, feature = "eng2-rehearsal"))]
mod commitment_tests;
mod imported;
mod receipts;

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("eng2-canonical-meta-v1");
const BLOCKS: TableDefinition<u64, &[u8]> = TableDefinition::new("eng2-canonical-blocks-v1");
const INDEX: TableDefinition<u64, &[u8]> = TableDefinition::new("eng2-canonical-index-v1");
const INDEX_BYTES: usize = HEADER_BYTES + 8;
const ANCHORS: TableDefinition<u64, &[u8]> =
    TableDefinition::new("eng2-committed-anchor-states-v1");
pub(crate) const PERMANENT_RECEIPTS: TableDefinition<u64, &[u8]> =
    TableDefinition::new("eng2-permanent-receipts-v1");
pub(crate) const PERMANENT_RECEIPT_IDS: TableDefinition<u64, &[u8]> =
    TableDefinition::new("eng2-permanent-receipt-ids-v1");

pub struct Store {
    database: Database,
    #[cfg(windows)]
    _directory: siworld_miner_platform::Directory,
    #[cfg(windows)]
    file_identity: (u32, u64),
    engine: Engine,
    usable: bool,
    restart: Option<super::restart::Context>,
    imported_prefix: u64,
    import_seed: Hash,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyAvailability {
    Unavailable,
    Full { encoded_body_bytes: usize },
}
impl Store {
    /// Initialize only a new absent file. Existing state is never overwritten.
    pub fn create(path: &Path, genesis: Genesis, limits: Limits) -> Result<Self, String> {
        #[cfg(windows)]
        let directory = siworld_miner_platform::Directory::open(
            path.parent().ok_or("versioned database parent missing")?,
        )?;
        #[cfg(windows)]
        let file =
            directory.create_file(path.file_name().ok_or("versioned database name missing")?)?;
        #[cfg(windows)]
        let file_identity = siworld_miner_platform::file_identity(&file)?;
        #[cfg(not(windows))]
        let file = {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options
                    .mode(0o600)
                    .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
            }
            options
                .open(path)
                .map_err(|_| "new versioned database is unavailable or exists")?
        };
        let backend = redb::backends::FileBackend::new(file)
            .map_err(|_| "versioned database backend unavailable")?;
        let database = Database::builder()
            .create_with_backend(backend)
            .map_err(|_| "versioned database creation failed")?;
        let engine = Engine::new(genesis, limits)?;
        let mut txn = database
            .begin_write()
            .map_err(|_| "versioned database initialization failed")?;
        txn.set_durability(Durability::Immediate)
            .map_err(|_| "versioned database durability unavailable")?;
        {
            let mut meta = txn
                .open_table(META)
                .map_err(|_| "versioned metadata unavailable")?;
            meta.insert("genesis", engine.genesis().encode()?.as_slice())
                .map_err(|_| "versioned genesis write failed")?;
            meta.insert("head", head(&engine, [0; 32]).as_slice())
                .map_err(|_| "versioned head write failed")?;
            txn.open_table(BLOCKS)
                .map_err(|_| "versioned block table unavailable")?;
            txn.open_table(INDEX)
                .map_err(|_| "versioned compact index unavailable")?;
        }
        txn.commit()
            .map_err(|_| "versioned database initialization commit failed")?;
        crate::store::sync_parent(path)?;
        Ok(Self {
            database,
            #[cfg(windows)]
            _directory: directory,
            #[cfg(windows)]
            file_identity,
            engine,
            usable: true,
            restart: None,
            imported_prefix: 0,
            import_seed: [0; 32],
        })
    }
    /// Independently reconstruct every committed block and execution root and
    /// rebuild its compact index in the same explicit audit. Malformed,
    /// mismatched, empty or incomplete existing files are rejected atomically.
    pub fn audit_existing(
        path: &Path,
        genesis: Genesis,
        limits: Limits,
        verifier: &NativeVerifier,
    ) -> Result<Self, String> {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|_| "existing versioned database unavailable")?;
        if !metadata.file_type().is_file() || metadata.len() == 0 {
            return Err("existing versioned database is not a nonempty regular file".into());
        }
        #[cfg(windows)]
        let directory = siworld_miner_platform::Directory::open(
            path.parent().ok_or("versioned database parent missing")?,
        )?;
        #[cfg(windows)]
        let file = directory.open_file(
            path.file_name().ok_or("versioned database name missing")?,
            true,
        )?;
        #[cfg(windows)]
        let file_identity = siworld_miner_platform::file_identity(&file)?;
        #[cfg(not(windows))]
        let file = {
            let mut options = OpenOptions::new();
            options.read(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
            }
            options
                .open(path)
                .map_err(|_| "existing versioned database open failed")?
        };
        if file
            .metadata()
            .map_err(|_| "versioned file metadata unavailable")?
            .len()
            == 0
        {
            return Err("existing versioned database is empty".into());
        }
        let backend = redb::backends::FileBackend::new(file)
            .map_err(|_| "versioned database backend unavailable")?;
        let mut builder = Database::builder();
        builder.set_repair_callback(|session| session.abort());
        let database = builder
            .create_with_backend(backend)
            .map_err(|_| "damaged or incompatible versioned database")?;
        let mut engine = Engine::new(genesis, limits)?;
        let mut txn = database
            .begin_write()
            .map_err(|_| "versioned metadata read failed")?;
        txn.set_durability(Durability::Immediate)
            .map_err(|_| "versioned audit durability unavailable")?;
        let meta = txn
            .open_table(META)
            .map_err(|_| "versioned metadata missing")?;
        let expected_genesis = engine.genesis().encode()?;
        if meta
            .get("genesis")
            .map_err(|_| "versioned genesis read failed")?
            .as_ref()
            .map(|v| v.value())
            != Some(expected_genesis.as_slice())
        {
            return Err("versioned database genesis differs from local selection".into());
        }
        let blocks = txn
            .open_table(BLOCKS)
            .map_err(|_| "versioned canonical history missing")?;
        let mut index = txn
            .open_table(INDEX)
            .map_err(|_| "versioned audit compact index unavailable")?;
        let mut commitment = [0; 32];
        for row in blocks.iter().map_err(|_| "versioned history scan failed")? {
            let (height, bytes) = row.map_err(|_| "versioned canonical record unavailable")?;
            let (header, body) = decode(&engine, bytes.value())?;
            if height.value() != header.height {
                return Err("versioned canonical key differs from header height".into());
            }
            let accepted = engine.apply(&header, &body, verifier)?;
            commitment = accepted.execution_commitment();
            let compact = compact_record(&header, bytes.value().len() - HEADER_BYTES)?;
            index
                .insert(height.value(), compact.as_slice())
                .map_err(|_| "versioned audit compact index write failed")?;
        }
        if index
            .len()
            .map_err(|_| "versioned compact index count unavailable")?
            != engine.state().height()
            || blocks
                .len()
                .map_err(|_| "versioned record count unavailable")?
                != engine.state().height()
            || meta
                .get("head")
                .map_err(|_| "versioned head read failed")?
                .as_ref()
                .map(|v| v.value())
                != Some(head(&engine, commitment).as_slice())
        {
            return Err("versioned durable head differs from independent native replay".into());
        }
        drop(index);
        drop(blocks);
        drop(meta);
        txn.commit()
            .map_err(|_| "versioned audit compact index durable commit failed")?;
        Ok(Self {
            database,
            #[cfg(windows)]
            _directory: directory,
            #[cfg(windows)]
            file_identity,
            engine,
            usable: true,
            restart: None,
            imported_prefix: 0,
            import_seed: [0; 32],
        })
    }
    pub fn engine(&self) -> &Engine {
        &self.engine
    }
    /// Resume the exact locally authenticated last committed state. This never
    /// verifies historical transaction or settlement proofs and never silently
    /// falls back to a history audit or regenerates a missing identity.
    pub fn resume_existing(path: &Path, genesis: Genesis, limits: Limits) -> Result<Self, String> {
        let directory = path.parent().ok_or("restart parent directory missing")?;
        let identity = crate::identity::NativeIdentity::load(directory, &genesis.peer_binding())
            .map_err(|_| "existing versioned restart identity unavailable")?;
        Self::resume_with_loaded_identity(path, genesis, limits, identity)
    }
    /// Resume only an owner-local public database copy under the already loaded
    /// fixture identity. Custody remains in its original private directory.
    #[cfg(all(test, unix, feature = "eng2-rehearsal"))]
    pub(crate) fn resume_qualification_copy(
        path: &Path,
        genesis: Genesis,
        limits: Limits,
        identity: crate::identity::NativeIdentity,
    ) -> Result<Self, String> {
        Self::resume_with_loaded_identity(path, genesis, limits, identity)
    }
    fn resume_with_loaded_identity(
        path: &Path,
        genesis: Genesis,
        limits: Limits,
        identity: crate::identity::NativeIdentity,
    ) -> Result<Self, String> {
        if identity
            .descriptor()
            .map_err(|_| "versioned restart identity descriptor unavailable")?
            .binding()
            != genesis.peer_binding()
        {
            return Err("versioned restart identity binding differs".into());
        }
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|_| "existing versioned restart database unavailable")?;
        if !metadata.file_type().is_file() || metadata.len() == 0 {
            return Err("invalid existing versioned restart database".into());
        }
        #[cfg(windows)]
        let directory = siworld_miner_platform::Directory::open(
            path.parent().ok_or("versioned database parent missing")?,
        )?;
        #[cfg(windows)]
        let file = directory.open_file(
            path.file_name().ok_or("versioned database name missing")?,
            true,
        )?;
        #[cfg(windows)]
        let file_identity = siworld_miner_platform::file_identity(&file)?;
        #[cfg(not(windows))]
        let file = {
            let mut options = OpenOptions::new();
            options.read(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
            }
            options
                .open(path)
                .map_err(|_| "versioned restart database open failed")?
        };
        #[cfg(windows)]
        if file
            .metadata()
            .map_err(|_| "versioned restart file metadata unavailable")?
            .len()
            == 0
        {
            return Err("existing versioned restart database is empty".into());
        }
        let backend = redb::backends::FileBackend::new(file)
            .map_err(|_| "versioned restart backend unavailable")?;
        let mut builder = Database::builder();
        builder.set_repair_callback(|session| session.abort());
        let database = builder
            .create_with_backend(backend)
            .map_err(|_| "damaged versioned restart database")?;
        let txn = database
            .begin_read()
            .map_err(|_| "versioned restart read unavailable")?;
        let meta = txn
            .open_table(META)
            .map_err(|_| "versioned restart metadata missing")?;
        let encoded = genesis.encode()?;
        if meta
            .get("genesis")
            .map_err(|_| "restart genesis read failed")?
            .as_ref()
            .map(|value| value.value())
            != Some(encoded.as_slice())
        {
            return Err("restart genesis differs from local configuration".into());
        }
        let head_bytes = meta
            .get("head")
            .map_err(|_| "restart head unavailable")?
            .ok_or("restart head missing")?;
        let head_bytes = head_bytes.value();
        if head_bytes.len() != 72 {
            return Err("invalid restart head width".into());
        }
        let height =
            u64::from_le_bytes(head_bytes[..8].try_into().expect("checked restart height"));
        let blocks = txn
            .open_table(BLOCKS)
            .map_err(|_| "restart canonical table missing")?;
        let (imported_prefix, import_seed) = imported::resume_context(&txn, height)?;
        if blocks
            .len()
            .map_err(|_| "restart block count unavailable")?
            != height - imported_prefix
        {
            return Err("restart canonical count differs".into());
        }
        let index = txn
            .open_table(INDEX)
            .map_err(|_| "restart compact index missing; explicit audit required")?;
        if index.len().map_err(|_| "restart index count unavailable")? != height {
            return Err("restart compact index count differs".into());
        }
        let parent = if height == 0 {
            [0; 32]
        } else {
            let value = index
                .get(height)
                .map_err(|_| "restart tip unavailable")?
                .ok_or("restart tip missing")?;
            let (header, _) = decode_compact(value.value(), genesis.config().network)?;
            if header.height != height
                || header
                    .id()
                    .map_err(|_| "restart identity invalid")?
                    .as_slice()
                    != &head_bytes[8..40]
                || header.execution_commitment.as_slice() != &head_bytes[40..]
            {
                return Err("restart canonical header differs from durable head".into());
            }
            header.parent
        };
        let table = txn
            .open_table(super::restart::CACHE)
            .map_err(|_| "authenticated restart record missing; explicit audit required")?;
        if table
            .len()
            .map_err(|_| "restart record count unavailable")?
            != 5
        {
            return Err("incomplete authenticated restart record".into());
        }
        let read = |key: &str, max: usize| -> Result<Vec<u8>, String> {
            let value = table
                .get(key)
                .map_err(|_| "restart field unavailable")?
                .ok_or("restart field missing")?;
            if value.value().len() > max {
                return Err("restart field exceeds bound".into());
            }
            Ok(value.value().to_vec())
        };
        let maximum = limits
            .max_component_bytes
            .checked_mul(6)
            .and_then(|size| size.checked_add(88))
            .ok_or("restart total bound overflow")?;
        let bytes = read("state", maximum)?;
        let leaves: Hash = read("leaves", 32)?
            .try_into()
            .map_err(|_| "restart leaf digest width")?;
        let spends: Hash = read("spends", 32)?
            .try_into()
            .map_err(|_| "restart spend digest width")?;
        let sealed_index: Hash = read("index", 32)?
            .try_into()
            .map_err(|_| "restart compact index digest width")?;
        let seal = read("seal", crate::identity::storage_checkpoint::SEAL_BYTES)?;
        identity
            .descriptor()
            .map_err(|_| "restart descriptor unavailable")?
            .verify_local_storage(
                super::restart::digest(&genesis, &bytes, leaves, spends, sealed_index),
                &seal,
            )
            .map_err(|_| "authenticated restart seal mismatch")?;
        let index_digest = authenticate_header_prefix_seed(
            &index,
            genesis.config().network,
            genesis.id(),
            height,
            head_bytes[8..40].try_into().expect("checked restart tip"),
            import_seed,
        )?;
        if index_digest != sealed_index {
            return Err("restart compact index differs from accepted local seal".into());
        }
        let (leaf_values, leaf_digest) = super::restart::read_rows(
            &txn.open_table(super::restart::LEAVES)
                .map_err(|_| "restart permanent leaves missing")?,
            limits.max_leaves,
        )?;
        let (spent_values, spent_digest) = super::restart::read_rows(
            &txn.open_table(super::restart::SPENDS)
                .map_err(|_| "restart permanent spends missing")?,
            limits.max_nullifiers,
        )?;
        if leaf_digest != leaves || spent_digest != spends {
            return Err("restart permanent rows differ from accepted local seal".into());
        }
        let spent: std::collections::BTreeSet<_> = spent_values.iter().copied().collect();
        if spent.len() != spent_values.len() {
            return Err("duplicate restart nullifier".into());
        }
        let leaves_decoded = leaf_values
            .iter()
            .map(|value| {
                native::codec::decode_digest(value).map_err(|_| "invalid restart leaf".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (state, root) =
            super::restart::restore(&genesis, &bytes, leaves_decoded, spent, limits, parent)?;
        if state.height() != height
            || state.tip().as_slice() != &head_bytes[8..40]
            || (height > 0 && root.as_slice() != &head_bytes[40..])
        {
            return Err("authenticated restart state differs from exact durable head".into());
        }
        let engine = Engine::from_authenticated_local_state(genesis, state, limits)?;
        drop(txn);
        let result = Self {
            database,
            #[cfg(windows)]
            _directory: directory,
            #[cfg(windows)]
            file_identity,
            engine,
            usable: true,
            restart: Some(super::restart::Context {
                identity,
                leaves,
                spends,
                index: index_digest,
            }),
            imported_prefix,
            import_seed,
        };
        result.ensure_exportable()?;
        Ok(result)
    }
    /// Explicitly authenticate this already verified local head for later fast
    /// recovery. The supplied existing identity must bind this exact genesis.
    /// This one-time qualification scans permanent public rows; later accepted
    /// blocks append only their checked delta and a bounded current-state image.
    pub fn enable_authenticated_restart(
        &mut self,
        identity: crate::identity::NativeIdentity,
    ) -> Result<(), String> {
        self.ensure_exportable()?;
        let binding = self.engine.genesis().peer_binding();
        if identity
            .descriptor()
            .map_err(|_| "restart identity unavailable")?
            .binding()
            != binding
            || self.restart.is_some()
        {
            return Err("restart identity differs or handle is already qualified".into());
        }
        let state = self.engine.state();
        let parent = if state.height() == 0 {
            [0; 32]
        } else {
            self.header(state.height())?.parent
        };
        let root = state.execution_commitment(
            super::state_components::Binding {
                genesis: self.engine.genesis().id(),
                rules_commitment: self.engine.genesis().rules_commitment(),
                parent,
            },
            self.engine.limits(),
        )?;
        let bytes = super::restart::image(
            &super::restart::current_chain(state.chain())?,
            state.economics(),
            state.fund(),
            state.governance(),
            root,
            self.engine.limits(),
        )?;
        let mut txn = self
            .database
            .begin_write()
            .map_err(|_| "restart qualification unavailable")?;
        txn.set_durability(Durability::Immediate)
            .map_err(|_| "restart qualification durability unavailable")?;
        let mut leaves = [0; 32];
        let mut spends = [0; 32];
        {
            let mut table = txn
                .open_table(super::restart::LEAVES)
                .map_err(|_| "restart leaf table unavailable")?;
            if table.len().map_err(|_| "restart leaf count unavailable")? != 0 {
                return Err("existing restart leaves require verified resume; preserved".into());
            }
            for (index, value) in state.chain().leaves.iter().enumerate() {
                let value = native::codec::encode_digest(value);
                leaves = super::restart::row_hash(leaves, index as u64, &value);
                table
                    .insert(index as u64, value.as_slice())
                    .map_err(|_| "restart leaf write failed")?;
            }
            let mut table = txn
                .open_table(super::restart::SPENDS)
                .map_err(|_| "restart spend table unavailable")?;
            if table.len().map_err(|_| "restart spend count unavailable")? != 0 {
                return Err("existing restart spends require verified resume; preserved".into());
            }
            for (index, value) in state.chain().spent.iter().enumerate() {
                spends = super::restart::row_hash(spends, index as u64, value);
                table
                    .insert(index as u64, value.as_slice())
                    .map_err(|_| "restart spend write failed")?;
            }
        }
        let context = super::restart::Context {
            identity,
            leaves,
            spends,
            index: authenticate_header_prefix_seed(
                &txn.open_table(INDEX)
                    .map_err(|_| "restart qualification compact index unavailable")?,
                self.engine.state().network(),
                self.engine.genesis().id(),
                self.engine.state().height(),
                self.engine.state().tip(),
                self.import_seed,
            )?,
        };
        context.write(
            &txn,
            self.engine.genesis(),
            &bytes,
            leaves,
            spends,
            context.index,
        )?;
        self.usable = false;
        txn.commit()
            .map_err(|_| "restart qualification durable commit failed")?;
        self.restart = Some(context);
        self.usable = true;
        Ok(())
    }
    /// Check that this non-poisoned handle still exposes the exact durable
    /// canonical head. Call before deriving an externally publishable export.
    pub fn ensure_exportable(&self) -> Result<(), String> {
        if !self.usable {
            return Err("ambiguous versioned commit requires verified reopen before export".into());
        }
        let txn = self
            .database
            .begin_read()
            .map_err(|_| "versioned export metadata unavailable")?;
        let meta = txn
            .open_table(META)
            .map_err(|_| "versioned export head unavailable")?;
        let mut commitment = [0; 32];
        if self.engine.state().height() > 0 {
            let table = txn
                .open_table(INDEX)
                .map_err(|_| "versioned export history unavailable")?;
            let value = table
                .get(self.engine.state().height())
                .map_err(|_| "versioned export header unavailable")?
                .ok_or("versioned export header missing")?;
            let (header, _) = decode_compact(value.value(), self.engine.state().network())?;
            if header.height != self.engine.state().height()
                || header
                    .id()
                    .map_err(|_| "invalid versioned export identity")?
                    != self.engine.state().tip()
            {
                return Err("versioned export engine differs from durable header".into());
            }
            commitment = header.execution_commitment;
        }
        if meta
            .get("head")
            .map_err(|_| "versioned export head read failed")?
            .as_ref()
            .map(|value| value.value())
            != Some(head(&self.engine, commitment).as_slice())
        {
            return Err("versioned export metadata differs from actual engine head".into());
        }
        Ok(())
    }
    /// Archive only the actual current accepted state at a checkpoint boundary.
    /// Failure does not change validation or proof-retention permission.
    pub fn archive_checkpoint_anchor(
        &self,
        limits: super::snapshot::ImportLimits,
    ) -> Result<(), String> {
        self.ensure_exportable()?;
        let height = self.engine.state().height();
        if height == 0 || !height.is_multiple_of(crate::eng2::runtime_export::CHECKPOINT_INTERVAL) {
            return Err("checkpoint archive requires a positive checkpoint boundary".into());
        }
        let header = self.header(height)?;
        let binding = super::state_components::Binding {
            genesis: self.engine.genesis().id(),
            rules_commitment: self.engine.genesis().rules_commitment(),
            parent: header.parent,
        };
        let components = self
            .engine
            .state()
            .canonical_components(binding, limits.chain)?;
        if self
            .engine
            .state()
            .execution_commitment(binding, limits.chain)?
            != header.execution_commitment
        {
            return Err("checkpoint archive differs from actual accepted header".into());
        }
        let bytes = super::snapshot::encode_components(&components, limits)?;
        self.persist_checkpoint_archive(height, &bytes)
    }
    fn persist_checkpoint_archive(&self, height: u64, bytes: &[u8]) -> Result<(), String> {
        let mut txn = self
            .database
            .begin_write()
            .map_err(|_| "checkpoint archive transaction unavailable")?;
        txn.set_durability(Durability::Immediate)
            .map_err(|_| "checkpoint archive durability unavailable")?;
        {
            let mut table = txn
                .open_table(ANCHORS)
                .map_err(|_| "checkpoint archive table unavailable")?;
            if let Some(existing) = table
                .get(height)
                .map_err(|_| "checkpoint archive read failed")?
                && existing.value() != bytes
            {
                return Err("existing checkpoint archive differs; preserved".into());
            }
            table
                .insert(height, bytes)
                .map_err(|_| "checkpoint archive write failed")?;
        }
        txn.commit()
            .map_err(|_| "checkpoint archive durable commit failed".into())
    }
    /// Capture immutable archive and at most 71 accepted native suffix blocks.
    /// Capture is read-only and reserves shared workspace before copying bytes;
    /// native reconstruction and proof replay run outside the canonical owner.
    pub fn capture_checkpoint_archive(
        &self,
        height: u64,
        limits: super::snapshot::ImportLimits,
        budget: &crate::p2p::Budget,
    ) -> Result<super::runtime_export::archive_work::ArchiveWork, String> {
        self.ensure_exportable()?;
        if height == 0 || height > self.engine.state().height() {
            return Err("invalid checkpoint preparation archive height".into());
        }
        let anchor = self.header(height)?;
        let txn = self
            .database
            .begin_read()
            .map_err(|_| "checkpoint preparation archive read unavailable")?;
        let table = txn
            .open_table(ANCHORS)
            .map_err(|_| "checkpoint preparation archive table unavailable")?;
        let lower = height
            .saturating_sub(crate::eng2::runtime_export::LEGACY_CHECKPOINT_INTERVAL - 1)
            .max(1);
        let mut entries = table
            .range(lower..=height)
            .map_err(|_| "checkpoint preparation archive range unavailable")?;
        let (key, bytes) = entries
            .next_back()
            .ok_or("checkpoint preparation archive missing within bounded migration window")?
            .map_err(|_| "checkpoint preparation archive read failed")?;
        let base_height = key.value();
        if bytes.value().len() > limits.max_snapshot_bytes {
            return Err("checkpoint preparation archive exceeds byte bound".into());
        }
        let base = self.header(base_height)?;
        let suffix_bytes = (base_height + 1..=height).try_fold(0usize, |total, h| {
            total
                .checked_add(self.block_size(h)?)
                .ok_or_else(|| "checkpoint suffix byte bound overflow".to_owned())
        })?;
        let reservation = super::runtime_export::archive_work::ArchiveWork::reserve(
            bytes.value().len(),
            suffix_bytes,
            budget,
        )?;
        let suffix = (base_height + 1..=height)
            .map(|h| self.block(h))
            .collect::<Result<Vec<_>, _>>()?;
        super::runtime_export::archive_work::ArchiveWork::capture(
            self,
            anchor,
            base,
            bytes.value(),
            suffix,
            reservation,
            limits,
        )
    }
    /// Reconstruct and recheck a prior explicitly archived actual state. The
    /// checkpoint publisher separately requires 24 later confirmations.
    pub fn checkpoint_anchor(
        &self,
        height: u64,
        limits: super::snapshot::ImportLimits,
    ) -> Result<super::snapshot::SnapshotState, String> {
        self.ensure_exportable()?;
        if height == 0 || height > self.engine.state().height() {
            return Err("invalid requested checkpoint archive height".into());
        }
        let header = self.header(height)?;
        let txn = self
            .database
            .begin_read()
            .map_err(|_| "checkpoint archive read unavailable")?;
        let table = txn
            .open_table(ANCHORS)
            .map_err(|_| "checkpoint archive is not available")?;
        if let Some(bytes) = table
            .get(height)
            .map_err(|_| "checkpoint archive lookup failed")?
        {
            return super::snapshot::SnapshotState::from_committed_components(
                self.engine.genesis(),
                &header,
                bytes.value(),
                limits,
            );
        }
        // A cadence upgrade can introduce a boundary absent from an older
        // archive. Reconstruct only a bounded suffix in an isolated engine;
        // normal committed-state recovery and canonical tables are unchanged.
        let lower =
            height.saturating_sub(crate::eng2::runtime_export::LEGACY_CHECKPOINT_INTERVAL - 1);
        let mut entries = table
            .range(lower..height)
            .map_err(|_| "checkpoint migration archive range unavailable")?;
        let (base_height, base_bytes) = loop {
            let (key, value) = entries
                .next_back()
                .ok_or("checkpoint archive missing within bounded migration window")?
                .map_err(|_| "checkpoint migration archive read failed")?;
            let candidate = key.value();
            if candidate > 0 {
                break (candidate, value.value().to_vec());
            }
        };
        drop(entries);
        drop(table);
        drop(txn);
        let base_header = self.header(base_height)?;
        let base = super::snapshot::SnapshotState::from_committed_components(
            self.engine.genesis(),
            &base_header,
            &base_bytes,
            limits,
        )?;
        let mut reconstructed = Engine::from_authenticated_local_state(
            Genesis::decode(&self.engine.genesis().encode()?)?,
            base,
            self.engine.limits(),
        )?;
        let verifier = NativeVerifier::new()?;
        for current in base_height + 1..=height {
            let (header, body) = self.block(current)?;
            reconstructed.apply(&header, &body, &verifier)?;
        }
        let binding = super::state_components::Binding {
            genesis: self.engine.genesis().id(),
            rules_commitment: self.engine.genesis().rules_commitment(),
            parent: header.parent,
        };
        let components = reconstructed
            .state()
            .canonical_components(binding, limits.chain)?;
        let bytes = super::snapshot::encode_components(&components, limits)?;
        let state = super::snapshot::SnapshotState::from_committed_components(
            self.engine.genesis(),
            &header,
            &bytes,
            limits,
        )?;
        self.persist_checkpoint_archive(height, &bytes)?;
        Ok(state)
    }
    /// The sole successful return occurs after an immediate durable redb commit
    /// and in-memory publication of the same fully verified native block.
    pub fn append(
        &mut self,
        header: &Header,
        body: &Body,
        verifier: &NativeVerifier,
    ) -> Result<CommittedBlock, String> {
        if !self.usable {
            return Err(
                "versioned store requires verified reopen after publication failure".into(),
            );
        }
        let staged = self.engine.stage(header, body, verifier)?;
        let mut bytes = header
            .encode()
            .map_err(|_| "invalid versioned header")?
            .to_vec();
        body.write_to(&mut bytes, self.engine.body_policy())
            .map_err(|_| "versioned body encoding failed")?;
        let compact = compact_record(header, bytes.len() - HEADER_BYTES)?;
        let mut txn = self
            .database
            .begin_write()
            .map_err(|_| "versioned block transaction unavailable")?;
        txn.set_durability(Durability::Immediate)
            .map_err(|_| "versioned block durability unavailable")?;
        {
            let mut index = txn
                .open_table(INDEX)
                .map_err(|_| "versioned compact index unavailable")?;
            if index
                .len()
                .map_err(|_| "versioned compact index count unavailable")?
                != self.engine.state().height()
                || index
                    .get(header.height)
                    .map_err(|_| "versioned compact index lookup failed")?
                    .is_some()
            {
                return Err("versioned compact index differs from accepted parent".into());
            }
            index
                .insert(header.height, compact.as_slice())
                .map_err(|_| "versioned compact index write failed")?;
        }
        let mut next_restart = None;
        if let Some(context) = &self.restart {
            let mut leaves = context.leaves;
            let mut spends = context.spends;
            {
                let mut table = txn
                    .open_table(super::restart::LEAVES)
                    .map_err(|_| "restart leaf table unavailable")?;
                let base = self.engine.state().chain().leaves.len() as u64;
                if table.len().map_err(|_| "restart leaf count unavailable")? != base {
                    return Err("restart leaf table differs from actual parent".into());
                }
                for (index, value) in staged.new_leaves().iter().enumerate() {
                    let index = base + index as u64;
                    let value = native::codec::encode_digest(value);
                    leaves = super::restart::row_hash(leaves, index, &value);
                    table
                        .insert(index, value.as_slice())
                        .map_err(|_| "restart leaf append failed")?;
                }
                let mut table = txn
                    .open_table(super::restart::SPENDS)
                    .map_err(|_| "restart spend table unavailable")?;
                let base = self.engine.state().chain().spent.len() as u64;
                if table.len().map_err(|_| "restart spend count unavailable")? != base {
                    return Err("restart spend table differs from actual parent".into());
                }
                for (index, value) in staged.new_spends().iter().enumerate() {
                    let index = base + index as u64;
                    spends = super::restart::row_hash(spends, index, value);
                    table
                        .insert(index, value.as_slice())
                        .map_err(|_| "restart spend append failed")?;
                }
            }
            context.write(
                &txn,
                self.engine.genesis(),
                &staged.restart_image(self.engine.state(), self.engine.limits())?,
                leaves,
                spends,
                index_row_hash(context.index, header.height, &compact),
            )?;
            next_restart = Some((
                leaves,
                spends,
                index_row_hash(context.index, header.height, &compact),
            ));
        }
        {
            let mut blocks = txn
                .open_table(BLOCKS)
                .map_err(|_| "versioned canonical table unavailable")?;
            if blocks
                .get(header.height)
                .map_err(|_| "versioned canonical lookup failed")?
                .is_some()
            {
                return Err("versioned canonical height already exists".into());
            }
            blocks
                .insert(header.height, bytes.as_slice())
                .map_err(|_| "versioned canonical write failed")?;
            let mut value = Vec::with_capacity(72);
            value.extend_from_slice(&header.height.to_le_bytes());
            value.extend_from_slice(&header.id().map_err(|_| "invalid versioned identity")?);
            value.extend_from_slice(&header.execution_commitment);
            txn.open_table(META)
                .map_err(|_| "versioned head metadata unavailable")?
                .insert("head", value.as_slice())
                .map_err(|_| "versioned head write failed")?;
        }
        // Ambiguous I/O failures poison this handle; never continue production
        // until a fresh verified reopen reconciles the durable commit boundary.
        self.usable = false;
        txn.commit()
            .map_err(|_| "versioned canonical durable commit failed")?;
        let result = self.engine.publish(staged)?;
        if let (Some(context), Some((leaves, spends, index))) = (&mut self.restart, next_restart) {
            context.leaves = leaves;
            context.spends = spends;
            context.index = index;
        }
        self.usable = true;
        Ok(result)
    }
    /// Return canonical public header/body bytes for explicit independent replay.
    pub fn block(&self, height: u64) -> Result<(Header, Body), String> {
        let (expected, length) = self.compact(height)?;
        if height <= self.imported_prefix {
            return Err("historical proof body is unavailable before imported checkpoint".into());
        }
        let txn = self
            .database
            .begin_read()
            .map_err(|_| "versioned block read unavailable")?;
        let table = txn
            .open_table(BLOCKS)
            .map_err(|_| "versioned block table unavailable")?;
        let value = table
            .get(height)
            .map_err(|_| "versioned block lookup failed")?
            .ok_or("versioned block missing")?;
        if value.value().len() != HEADER_BYTES + length
            || value.value().get(..HEADER_BYTES)
                != Some(
                    expected
                        .encode()
                        .map_err(|_| "invalid accepted compact header")?
                        .as_slice(),
                )
        {
            return Err("versioned body record differs from accepted compact index".into());
        }
        decode(&self.engine, value.value())
    }
    /// Read only the fixed-width persisted header, without allocating a body.
    pub fn header(&self, height: u64) -> Result<Header, String> {
        self.compact(height).map(|(header, _)| header)
    }
    fn compact(&self, height: u64) -> Result<(Header, usize), String> {
        self.check_readable()?;
        if height == 0 || height > self.engine.state().height() {
            return Err("versioned compact index height is not accepted".into());
        }
        let txn = self
            .database
            .begin_read()
            .map_err(|_| "versioned header read unavailable")?;
        let table = txn
            .open_table(INDEX)
            .map_err(|_| "versioned header table unavailable")?;
        let value = table
            .get(height)
            .map_err(|_| "versioned header lookup failed")?
            .ok_or("versioned header missing")?;
        let compact = decode_compact(value.value(), self.engine.state().network())?;
        if compact.0.height != height || compact.1 > self.engine.body_policy().max_body_bytes {
            return Err("invalid accepted compact index context or body bound".into());
        }
        Ok(compact)
    }
    /// Size the persisted body before callers reserve memory for decoding.
    pub fn block_size(&self, height: u64) -> Result<usize, String> {
        self.compact(height).map(|(_, length)| length)
    }
    /// Observe an actual body record separately from permanent compact length
    /// metadata. This checks framing and presence, not native proof validity.
    /// Callers reserve for the indexed size before reading the record.
    pub fn body_availability(&self, height: u64) -> Result<BodyAvailability, String> {
        self.check_readable()?;
        if height == 0 || height > self.engine.state().height() || height <= self.imported_prefix {
            return Ok(BodyAvailability::Unavailable);
        }
        let (header, length) = self.compact(height)?;
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| "versioned body availability unavailable")?;
        let table = transaction
            .open_table(BLOCKS)
            .map_err(|_| "versioned body table unavailable")?;
        let Some(value) = table
            .get(height)
            .map_err(|_| "versioned body presence read failed")?
        else {
            return Ok(BodyAvailability::Unavailable);
        };
        if value.value().len() != HEADER_BYTES + length
            || value.value().get(..HEADER_BYTES)
                != Some(
                    header
                        .encode()
                        .map_err(|_| "invalid accepted compact header")?
                        .as_slice(),
                )
        {
            return Err("versioned body presence differs from accepted compact metadata".into());
        }
        Ok(BodyAvailability::Full {
            encoded_body_bytes: length,
        })
    }
    fn check_readable(&self) -> Result<(), String> {
        if self.usable {
            Ok(())
        } else {
            Err("ambiguous versioned commit requires verified reopen before reading".into())
        }
    }
}
fn head(engine: &Engine, commitment: Hash) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(72);
    bytes.extend_from_slice(&engine.state().height().to_le_bytes());
    bytes.extend_from_slice(&engine.state().tip());
    bytes.extend_from_slice(&commitment);
    bytes
}
fn compact_record(header: &Header, body_bytes: usize) -> Result<Vec<u8>, String> {
    let mut compact = header
        .encode()
        .map_err(|_| "invalid compact header")?
        .to_vec();
    compact.extend_from_slice(
        &u64::try_from(body_bytes)
            .map_err(|_| "body size overflow")?
            .to_le_bytes(),
    );
    Ok(compact)
}
fn decode_compact(bytes: &[u8], network: Hash) -> Result<(Header, usize), String> {
    if bytes.len() != INDEX_BYTES {
        return Err("invalid compact index width".into());
    }
    let header =
        Header::decode(&bytes[..HEADER_BYTES], &network).map_err(|_| "invalid compact header")?;
    let length = usize::try_from(u64::from_le_bytes(
        bytes[HEADER_BYTES..]
            .try_into()
            .expect("checked compact index"),
    ))
    .map_err(|_| "compact body length overflow")?;
    if length == 0 {
        return Err("empty compact body length".into());
    }
    Ok((header, length))
}
fn index_row_hash(previous: Hash, height: u64, bytes: &[u8]) -> Hash {
    let mut digest = blake3::Hasher::new_derive_key("siworld eng2 local accepted compact index v1");
    digest.update(&previous);
    digest.update(&height.to_le_bytes());
    digest.update(bytes);
    *digest.finalize().as_bytes()
}
/// Read only the separate fixed-width compact index, authenticate ancestry
/// from genesis to the sealed tip, and bind every recorded body length.
#[cfg(test)]
fn authenticate_header_prefix(
    index: &impl ReadableTable<u64, &'static [u8]>,
    network: Hash,
    genesis: Hash,
    height: u64,
    tip: Hash,
) -> Result<Hash, String> {
    authenticate_header_prefix_seed(index, network, genesis, height, tip, [0; 32])
}
fn authenticate_header_prefix_seed(
    index: &impl ReadableTable<u64, &'static [u8]>,
    network: Hash,
    genesis: Hash,
    height: u64,
    tip: Hash,
    seed: Hash,
) -> Result<Hash, String> {
    if index.len().map_err(|_| "restart index count unavailable")? != height {
        return Err("restart compact index count differs".into());
    }
    let mut expected = genesis;
    let mut digest = seed;
    for height in 1..=height {
        let record = index
            .get(height)
            .map_err(|_| "restart header prefix lookup failed")?
            .ok_or("restart header prefix missing")?;
        let (header, _) = decode_compact(record.value(), network)?;
        if header.height != height || header.parent != expected {
            return Err("restart accepted header prefix differs from sealed tip".into());
        }
        expected = header
            .id()
            .map_err(|_| "restart header prefix identity invalid")?;
        digest = index_row_hash(digest, height, record.value());
    }
    if expected != tip {
        return Err("restart accepted header prefix differs from sealed tip".into());
    }
    Ok(digest)
}
fn decode(engine: &Engine, bytes: &[u8]) -> Result<(Header, Body), String> {
    let header = Header::decode(
        bytes
            .get(..HEADER_BYTES)
            .ok_or("truncated versioned header")?,
        &engine.state().network(),
    )
    .map_err(|_| "invalid versioned canonical header")?;
    let body = Body::decode(
        &bytes[HEADER_BYTES..],
        header.network,
        header.height,
        engine.body_policy(),
    )?;
    if body.commitment(engine.body_policy())? != header.body_commitment {
        return Err("persisted canonical body differs from accepted header".into());
    }
    Ok((header, body))
}

#[cfg(test)]
mod tests {
    use super::super::genesis::FeeMode;
    use super::*;
    fn genesis() -> Genesis {
        let state = crate::eng2::snapshot::tests::bootstrap();
        Genesis::seal(
            state.chain.config.clone(),
            state.governance.clone(),
            FeeMode::LegacyMiner,
        )
        .unwrap()
    }
    fn private_directory(label: &str) -> std::path::PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let directory = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "eng2-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        directory
    }
    #[test]
    fn restart_header_authentication_rejects_an_older_substituted_header_without_reading_proofs() {
        let directory = private_directory("header-prefix");
        let database = Database::create(directory.join("headers.redb")).unwrap();
        let mut first = Header {
            network: [1; 32],
            height: 1,
            parent: [2; 32],
            timestamp: 1,
            target: [0xff; 32],
            execution_commitment: [3; 32],
            body_commitment: [4; 32],
            nonce: 0,
        };
        let second = Header {
            height: 2,
            parent: first.id().unwrap(),
            timestamp: 2,
            ..first.clone()
        };
        let transaction = database.begin_write().unwrap();
        {
            let mut table = transaction.open_table(INDEX).unwrap();
            // No body table exists: this authenticates metadata, not proofs.
            table
                .insert(1, compact_record(&first, 4096).unwrap().as_slice())
                .unwrap();
            table
                .insert(2, compact_record(&second, 8192).unwrap().as_slice())
                .unwrap();
            let original = authenticate_header_prefix(
                &table,
                first.network,
                first.parent,
                2,
                second.id().unwrap(),
            )
            .unwrap();
            table
                .insert(2, compact_record(&second, 8191).unwrap().as_slice())
                .unwrap();
            assert_ne!(
                authenticate_header_prefix(
                    &table,
                    first.network,
                    first.parent,
                    2,
                    second.id().unwrap()
                )
                .unwrap(),
                original
            );
            first.nonce = 1;
            table
                .insert(1, compact_record(&first, 4096).unwrap().as_slice())
                .unwrap();
            assert!(
                authenticate_header_prefix(
                    &table,
                    first.network,
                    first.parent,
                    2,
                    second.id().unwrap()
                )
                .is_err()
            );
        }
        transaction.commit().unwrap();
        drop(database);
        fs_remove_fixture(directory);
    }
    fn fs_remove_fixture(directory: std::path::PathBuf) {
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    #[ignore = "requires a disposable copy of at least 24 accepted native blocks"]
    fn checkpoint_archive_migration_verifies_a_bounded_native_suffix_without_changing_head() {
        let directory = std::path::PathBuf::from(
            std::env::var_os("SIWORLD_CHECKPOINT_ARCHIVE_FIXTURE").unwrap(),
        );
        assert!(directory.is_absolute() && directory.file_name().unwrap() == "archive-fixture");
        assert!(directory.join("disposable-fixture").is_file());
        let path = directory.join("chain.redb");
        let genesis_bytes = std::fs::read(directory.join("genesis.bin")).unwrap();
        let genesis = || Genesis::decode(&genesis_bytes).unwrap();
        let records = {
            let database = Database::open(&path).unwrap();
            let txn = database.begin_write().unwrap();
            let mut blocks = txn.open_table(BLOCKS).unwrap();
            let records: Vec<Vec<u8>> = (13..=24)
                .map(|height| blocks.get(height).unwrap().unwrap().value().to_vec())
                .collect();
            let header = Header::decode(
                &blocks.get(12).unwrap().unwrap().value()[..HEADER_BYTES],
                &genesis().config().network,
            )
            .unwrap();
            let extra: Vec<u64> = blocks
                .range(13..)
                .unwrap()
                .map(|row| row.unwrap().0.value())
                .collect();
            for height in &extra {
                blocks.remove(*height).unwrap();
            }
            drop(blocks);
            let mut index = txn.open_table(INDEX).unwrap();
            for height in extra {
                index.remove(height).unwrap();
            }
            drop(index);
            let mut anchors = txn.open_table(ANCHORS).unwrap();
            let existing: Vec<u64> = anchors
                .iter()
                .unwrap()
                .map(|row| row.unwrap().0.value())
                .collect();
            for height in existing {
                anchors.remove(height).unwrap();
            }
            drop(anchors);
            let mut head = 12u64.to_le_bytes().to_vec();
            head.extend_from_slice(&header.id().unwrap());
            head.extend_from_slice(&header.execution_commitment);
            txn.open_table(META)
                .unwrap()
                .insert("head", head.as_slice())
                .unwrap();
            txn.commit().unwrap();
            records
        };
        let limits = super::super::snapshot::ImportLimits {
            chain: Limits {
                max_leaves: 1_000_000,
                max_nullifiers: 1_000_000,
                max_component_bytes: 64 * 1024 * 1024,
            },
            max_snapshot_bytes: 512 * 1024 * 1024,
        };
        let verifier = NativeVerifier::new().unwrap();
        let mut store = Store::audit_existing(&path, genesis(), limits.chain, &verifier).unwrap();
        store.archive_checkpoint_anchor(limits).unwrap();
        for record in &records {
            let (header, body) = decode(store.engine(), record).unwrap();
            store.append(&header, &body, &verifier).unwrap();
        }
        let before = head(
            store.engine(),
            store.header(24).unwrap().execution_commitment,
        );
        let original = records[0].clone();
        let mut corrupt = original.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        let txn = store.database.begin_write().unwrap();
        txn.open_table(BLOCKS)
            .unwrap()
            .insert(13, corrupt.as_slice())
            .unwrap();
        txn.commit().unwrap();
        assert!(store.checkpoint_anchor(24, limits).is_err());
        assert_eq!(
            head(
                store.engine(),
                store.header(24).unwrap().execution_commitment
            ),
            before
        );
        let txn = store.database.begin_write().unwrap();
        assert!(txn.open_table(ANCHORS).unwrap().get(24).unwrap().is_none());
        txn.open_table(BLOCKS)
            .unwrap()
            .insert(13, original.as_slice())
            .unwrap();
        txn.commit().unwrap();
        let budget = crate::p2p::Budget::new(512 * 1024 * 1024);
        let mut worker = crate::eng2::runtime_export::archive_work::ArchiveWorker::default();
        worker
            .start(
                store
                    .capture_checkpoint_archive(24, limits, &budget)
                    .unwrap(),
            )
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
        let independently_validated = loop {
            if let Some(value) = worker.try_complete().unwrap() {
                break value;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "native suffix replay deadline exceeded"
            );
            std::thread::sleep(std::time::Duration::from_millis(2));
        };
        independently_validated.check_current(&store).unwrap();
        assert_eq!(independently_validated.state().height(), 24);
        // Independent preparation does not add an archive or alter canonical
        // history, even when it fully verifies a missing cadence boundary.
        {
            let txn = store.database.begin_read().unwrap();
            assert!(txn.open_table(ANCHORS).unwrap().get(24).unwrap().is_none());
        }
        let migrated = store.checkpoint_anchor(24, limits).unwrap();
        assert_eq!(migrated.height(), 24);
        let binding = crate::eng2::state_components::Binding {
            genesis: store.engine().genesis().id(),
            rules_commitment: store.engine().genesis().rules_commitment(),
            parent: store.header(24).unwrap().parent,
        };
        let canonical = crate::eng2::snapshot::encode_components(
            &migrated
                .canonical_components(binding, limits.chain)
                .unwrap(),
            limits,
        )
        .unwrap();
        assert_eq!(independently_validated.snapshot_bytes(), canonical);
        assert_eq!(
            head(
                store.engine(),
                store.header(24).unwrap().execution_commitment
            ),
            before
        );
        // Successful reconstruction is cached. It no longer reads the suffix.
        let txn = store.database.begin_write().unwrap();
        txn.open_table(BLOCKS)
            .unwrap()
            .insert(13, corrupt.as_slice())
            .unwrap();
        txn.commit().unwrap();
        assert_eq!(store.checkpoint_anchor(24, limits).unwrap().height(), 24);
        println!(
            "bounded_checkpoint_archive_native_replay=passed blocks=12 accepted_head_unchanged=true corrupt_suffix_rejected=true"
        );
    }
    #[test]
    fn persisted_body_reads_reject_proof_byte_corruption_before_export() {
        let engine = Engine::new(genesis(), crate::eng2::snapshot::tests::limits().chain).unwrap();
        let mut body = crate::eng2::body::tests::body();
        body.profile = engine.body_policy().profile;
        body.network = engine.state().network();
        body.fund_claims.clear();
        body.governance.clear();
        body.transactions
            .sort_by_key(|tx| tx.record.statement_id(&body.network));
        let header = Header {
            network: body.network,
            height: body.height,
            parent: engine.state().tip(),
            timestamp: 1,
            target: [0xff; 32],
            execution_commitment: [2; 32],
            body_commitment: body.commitment(engine.body_policy()).unwrap(),
            nonce: 0,
        };
        let mut bytes = header.encode().unwrap().to_vec();
        body.write_to(&mut bytes, engine.body_policy()).unwrap();
        assert!(decode(&engine, &bytes).is_ok());
        *bytes.last_mut().unwrap() ^= 1;
        assert!(
            decode(&engine, &bytes)
                .err()
                .unwrap()
                .contains("differs from accepted header")
        );
    }
    #[test]
    #[ignore = "requires an explicitly supplied completed native 28-block fixture"]
    fn real_native_fixture_qualifies_incremental_authenticated_restart() {
        use std::time::Instant;
        let source = std::path::PathBuf::from(
            std::env::var_os("SIWORLD_ENG2_NATIVE_FIXTURE")
                .expect("set the completed native fixture directory"),
        );
        let destination = std::path::PathBuf::from(
            std::env::var_os("SIWORLD_ENG2_RESUME_FIXTURE")
                .expect("set a new disposable resume fixture directory"),
        );
        assert!(source.is_absolute() && destination.is_absolute());
        assert_eq!(source.canonicalize().unwrap(), source);
        assert!(
            std::fs::symlink_metadata(&source)
                .unwrap()
                .file_type()
                .is_dir()
        );
        assert!(!destination.exists());
        for name in ["genesis.bin", "chain.redb", "result.json"] {
            assert!(
                std::fs::symlink_metadata(source.join(name))
                    .unwrap()
                    .file_type()
                    .is_file()
            );
        }
        let completed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(source.join("result.json")).unwrap()).unwrap();
        assert_eq!(completed["native_proof_blocks"], "28");
        assert_eq!(completed["durable_reopen_audit"], "passed");
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&destination).unwrap();
        assert_eq!(destination.canonicalize().unwrap(), destination);
        let path = destination.join("chain.redb");
        // Only public genesis and the already closed canonical database are
        // copied. Wallet or governance custody is not read or copied.
        let genesis_bytes = std::fs::read(source.join("genesis.bin")).unwrap();
        std::fs::write(destination.join("genesis.bin"), &genesis_bytes).unwrap();
        std::fs::copy(source.join("chain.redb"), &path).unwrap();
        let limits = Limits {
            max_leaves: 1_000_000,
            max_nullifiers: 1_000_000,
            max_component_bytes: 64 * 1024 * 1024,
        };
        let genesis = || Genesis::decode(&genesis_bytes).unwrap();
        let (last_record, prefix_header) = {
            // Truncate only this newly created disposable copy to the actual
            // previous accepted record. The independent native audit below
            // authenticates the complete copied prefix before qualification.
            let database = Database::open(&path).unwrap();
            let transaction = database.begin_write().unwrap();
            let mut table = transaction.open_table(BLOCKS).unwrap();
            assert_eq!(table.len().unwrap(), 28);
            let record = table.get(28).unwrap().unwrap().value().to_vec();
            let prefix = Header::decode(
                &table.get(27).unwrap().unwrap().value()[..HEADER_BYTES],
                &genesis().config().network,
            )
            .unwrap();
            table.remove(28).unwrap();
            drop(table);
            transaction.open_table(INDEX).unwrap().remove(28).unwrap();
            let mut head = 27u64.to_le_bytes().to_vec();
            head.extend_from_slice(&prefix.id().unwrap());
            head.extend_from_slice(&prefix.execution_commitment);
            transaction
                .open_table(META)
                .unwrap()
                .insert("head", head.as_slice())
                .unwrap();
            transaction.commit().unwrap();
            (record, prefix)
        };
        let verifier = NativeVerifier::new().unwrap();
        let mut prefix = Store::audit_existing(&path, genesis(), limits, &verifier).unwrap();
        assert_eq!(prefix.engine().state().tip(), prefix_header.id().unwrap());
        let identity =
            crate::identity::NativeIdentity::initialize(&destination, genesis().peer_binding())
                .unwrap();
        prefix.enable_authenticated_restart(identity).unwrap();
        drop(prefix);
        let timer = Instant::now();
        let resumed = Store::resume_existing(&path, genesis(), limits).unwrap();
        let prefix_elapsed = timer.elapsed();
        assert_eq!(resumed.engine().state().height(), 27);
        assert_eq!(resumed.header(27).unwrap(), prefix_header);
        let prefix_leaves = resumed.engine().state().chain().leaves.len();
        let prefix_spends = resumed.engine().state().chain().spent.len();
        let (header, body) = decode(resumed.engine(), &last_record).unwrap();
        let mut driver = super::super::driver::Driver::new(
            resumed,
            verifier,
            super::super::snapshot::ImportLimits {
                chain: limits,
                max_snapshot_bytes: 512 * 1024 * 1024,
            },
        )
        .unwrap();
        let accepted = driver.accept(&header, &body).unwrap();
        assert_eq!(accepted.execution_commitment(), header.execution_commitment);
        assert_eq!(accepted.height(), 28);
        let final_leaves = driver.engine().state().chain().leaves.len();
        let final_spends = driver.engine().state().chain().spent.len();
        assert!(final_leaves > prefix_leaves && final_spends > prefix_spends);
        drop(driver);
        let timer = Instant::now();
        let resumed = Store::resume_existing(&path, genesis(), limits).unwrap();
        let full_elapsed = timer.elapsed();
        assert_eq!(resumed.engine().state().tip(), header.id().unwrap());
        assert_eq!(resumed.engine().state().height(), 28);
        assert_eq!(resumed.engine().state().chain().leaves.len(), final_leaves);
        assert_eq!(resumed.engine().state().chain().spent.len(), final_spends);
        assert_eq!(resumed.header(28).unwrap(), header);
        let actual_root = resumed
            .engine()
            .state()
            .execution_commitment(
                super::super::state_components::Binding {
                    genesis: genesis().id(),
                    rules_commitment: genesis().rules_commitment(),
                    parent: header.parent,
                },
                limits,
            )
            .unwrap();
        assert_eq!(actual_root, header.execution_commitment);
        assert!(prefix_elapsed.as_secs() < 300 && full_elapsed.as_secs() < 300);
        let original_compact = compact_record(
            &header,
            body.encoded_len(resumed.engine.body_policy()).unwrap(),
        )
        .unwrap();
        let mut changed_length = original_compact.clone();
        let length = u64::from_le_bytes(changed_length[HEADER_BYTES..].try_into().unwrap());
        changed_length[HEADER_BYTES..].copy_from_slice(&(length + 1).to_le_bytes());
        let transaction = resumed.database.begin_write().unwrap();
        transaction
            .open_table(INDEX)
            .unwrap()
            .insert(28, changed_length.as_slice())
            .unwrap();
        transaction.commit().unwrap();
        assert!(
            resumed
                .block(28)
                .err()
                .unwrap()
                .contains("differs from accepted compact index")
        );
        drop(resumed);
        assert!(
            Store::resume_existing(&path, genesis(), limits)
                .err()
                .unwrap()
                .contains("compact index differs from accepted local seal")
        );
        // Restore only the deliberately changed metadata in this registered
        // disposable copy, preserving a healthy fixture for review.
        let database = Database::open(&path).unwrap();
        let transaction = database.begin_write().unwrap();
        transaction
            .open_table(INDEX)
            .unwrap()
            .insert(28, original_compact.as_slice())
            .unwrap();
        transaction.commit().unwrap();
        drop(database);
        let restored = Store::resume_existing(&path, genesis(), limits).unwrap();
        assert_eq!(restored.engine().state().tip(), header.id().unwrap());
        let report = serde_json::json!({
            "scope":"copied-native-history-authenticated-restart", "proof_generation":false,
            "prefix_height":"27", "prefix_resume_ms":prefix_elapsed.as_millis().to_string(),
            "prefix_leaves":prefix_leaves.to_string(), "prefix_nullifiers":prefix_spends.to_string(),
            "height":"28", "resume_ms":full_elapsed.as_millis().to_string(),
            "leaves":final_leaves.to_string(), "nullifiers":final_spends.to_string(),
            "tip":crate::local::hex(&header.id().unwrap()),
            "execution_commitment":crate::local::hex(&actual_root),
            "exact_head_and_root":"passed", "incremental_native_commit":"passed",
            "native_driver_accept":"passed",
            "body_length_cross_check":"passed", "body_length_seal_tamper":"rejected",
            "under_five_minutes":"passed", "database_bytes":std::fs::metadata(&path).unwrap().len().to_string(),
        });
        std::fs::write(
            destination.join("resume-qualification.json"),
            serde_json::to_vec(&report).unwrap(),
        )
        .unwrap();
        println!("{report}");
        // The registered disposable copy is preserved for independent review.
    }
    #[test]
    fn authenticated_resume_requires_existing_identity_and_exact_committed_seal() {
        let limits = crate::eng2::snapshot::tests::limits().chain;
        let directory = private_directory("resume");
        let path = directory.join("chain.redb");
        let original = genesis();
        let identity =
            crate::identity::NativeIdentity::initialize(&directory, original.peer_binding())
                .unwrap();
        let mut store = Store::create(
            &path,
            Genesis::decode(&original.encode().unwrap()).unwrap(),
            limits,
        )
        .unwrap();
        store.enable_authenticated_restart(identity).unwrap();
        let expected = store
            .engine()
            .state()
            .execution_commitment(
                super::super::state_components::Binding {
                    genesis: original.id(),
                    rules_commitment: original.rules_commitment(),
                    parent: [0; 32],
                },
                limits,
            )
            .unwrap();
        drop(store);
        // There is no verifier argument or historical-proof fallback in resume.
        let store = Store::resume_existing(
            &path,
            Genesis::decode(&original.encode().unwrap()).unwrap(),
            limits,
        )
        .unwrap();
        assert_eq!(store.engine().state().height(), 0);
        assert_eq!(store.engine().state().tip(), original.id());
        assert_eq!(
            store
                .engine()
                .state()
                .execution_commitment(
                    super::super::state_components::Binding {
                        genesis: original.id(),
                        rules_commitment: original.rules_commitment(),
                        parent: [0; 32]
                    },
                    limits
                )
                .unwrap(),
            expected
        );
        let transaction = store.database.begin_write().unwrap();
        {
            let mut table = transaction
                .open_table(super::super::restart::CACHE)
                .unwrap();
            let mut state = table.get("state").unwrap().unwrap().value().to_vec();
            state[8] ^= 1;
            table.insert("state", state.as_slice()).unwrap();
        }
        transaction.commit().unwrap();
        drop(store);
        assert!(
            Store::resume_existing(
                &path,
                Genesis::decode(&original.encode().unwrap()).unwrap(),
                limits
            )
            .err()
            .unwrap()
            .contains("seal mismatch")
        );
        // Removing a synthetic test identity must not trigger key regeneration.
        let identity_path = directory.join("native-peer-identity.secret");
        std::fs::remove_file(&identity_path).unwrap();
        assert!(Store::resume_existing(&path, original, limits).is_err());
        assert!(!identity_path.exists());
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn authenticated_resume_rejects_row_or_head_tampering_and_wrong_binding() {
        let limits = crate::eng2::snapshot::tests::limits().chain;
        for corrupt_rows in [false, true] {
            let directory = private_directory("resume-tamper");
            let path = directory.join("chain.redb");
            let original = genesis();
            let identity =
                crate::identity::NativeIdentity::initialize(&directory, original.peer_binding())
                    .unwrap();
            let mut store = Store::create(
                &path,
                Genesis::decode(&original.encode().unwrap()).unwrap(),
                limits,
            )
            .unwrap();
            store.enable_authenticated_restart(identity).unwrap();
            let transaction = store.database.begin_write().unwrap();
            if corrupt_rows {
                transaction
                    .open_table(super::super::restart::LEAVES)
                    .unwrap()
                    .insert(0, [0u8; 48].as_slice())
                    .unwrap();
            } else {
                let mut wrong = head(store.engine(), [0; 32]);
                wrong[8] ^= 1;
                transaction
                    .open_table(META)
                    .unwrap()
                    .insert("head", wrong.as_slice())
                    .unwrap();
            }
            transaction.commit().unwrap();
            drop(store);
            assert!(
                Store::resume_existing(
                    &path,
                    Genesis::decode(&original.encode().unwrap()).unwrap(),
                    limits
                )
                .is_err()
            );
            let other = Genesis::seal(
                crate::state::Config::development(original.config().network, 1).unwrap(),
                original.initial_governance().clone(),
                FeeMode::LegacyMiner,
            )
            .unwrap();
            assert!(Store::resume_existing(&path, other, limits).is_err());
            std::fs::remove_dir_all(directory).unwrap();
        }
    }
    #[test]
    fn durable_genesis_audit_rejects_overwrite_wrong_genesis_and_corrupted_head() {
        let directory =
            std::env::temp_dir().join(format!("eng2-native-store-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("chain.redb");
        let make_genesis = || {
            let state = crate::eng2::snapshot::tests::bootstrap();
            Genesis::seal(
                state.chain.config.clone(),
                state.governance.clone(),
                FeeMode::LegacyMiner,
            )
            .unwrap()
        };
        let limits = Limits {
            max_leaves: 10_000,
            max_nullifiers: 10_000,
            max_component_bytes: 16 * 1024 * 1024,
        };
        let store = Store::create(&path, make_genesis(), limits).unwrap();
        assert!(Store::create(&path, make_genesis(), limits).is_err());
        drop(store);
        let verifier = NativeVerifier::new().unwrap();
        let original = make_genesis();
        let other = Genesis::seal(
            crate::state::Config::development(original.config().network, 1).unwrap(),
            original.initial_governance().clone(),
            FeeMode::LegacyMiner,
        )
        .unwrap();
        assert!(Store::audit_existing(&path, other, limits, &verifier).is_err());
        let mut store = Store::audit_existing(&path, make_genesis(), limits, &verifier).unwrap();
        assert_eq!(store.engine().state().height(), 0);
        store.ensure_exportable().unwrap();
        store.usable = false;
        assert!(store.ensure_exportable().is_err());
        store.usable = true;
        let txn = store.database.begin_write().unwrap();
        txn.open_table(META)
            .unwrap()
            .insert("head", [0u8; 72].as_slice())
            .unwrap();
        txn.commit().unwrap();
        assert!(store.ensure_exportable().is_err());
        drop(store);
        assert!(Store::audit_existing(&path, make_genesis(), limits, &verifier).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
