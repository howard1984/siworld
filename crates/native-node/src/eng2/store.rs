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
use std::{fs::OpenOptions, path::Path};

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("eng2-canonical-meta-v1");
const BLOCKS: TableDefinition<u64, &[u8]> = TableDefinition::new("eng2-canonical-blocks-v1");
const ANCHORS: TableDefinition<u64, &[u8]> =
    TableDefinition::new("eng2-committed-anchor-states-v1");

pub struct Store {
    database: Database,
    engine: Engine,
    usable: bool,
    restart: Option<super::restart::Context>,
}
impl Store {
    /// Initialize only a new absent file. Existing state is never overwritten.
    pub fn create(path: &Path, genesis: Genesis, limits: Limits) -> Result<Self, String> {
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
            .map_err(|_| "new versioned database is unavailable or exists")?;
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
        }
        txn.commit()
            .map_err(|_| "versioned database initialization commit failed")?;
        crate::store::sync_parent(path)?;
        Ok(Self {
            database,
            engine,
            usable: true,
            restart: None,
        })
    }
    /// Independently reconstruct every committed block and execution root. A
    /// malformed, mismatched, empty or incomplete existing file is rejected.
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
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
        }
        let file = options
            .open(path)
            .map_err(|_| "existing versioned database open failed")?;
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
        let txn = database
            .begin_read()
            .map_err(|_| "versioned metadata read failed")?;
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
        let mut commitment = [0; 32];
        for row in blocks.iter().map_err(|_| "versioned history scan failed")? {
            let (height, bytes) = row.map_err(|_| "versioned canonical record unavailable")?;
            let (header, body) = decode(&engine, bytes.value())?;
            if height.value() != header.height {
                return Err("versioned canonical key differs from header height".into());
            }
            let accepted = engine.apply(&header, &body, verifier)?;
            commitment = accepted.execution_commitment();
        }
        if blocks
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
        drop(txn);
        Ok(Self {
            database,
            engine,
            usable: true,
            restart: None,
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
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|_| "existing versioned restart database unavailable")?;
        if !metadata.file_type().is_file() || metadata.len() == 0 {
            return Err("invalid existing versioned restart database".into());
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
            .map_err(|_| "versioned restart database open failed")?;
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
        if blocks
            .len()
            .map_err(|_| "restart block count unavailable")?
            != height
        {
            return Err("restart canonical count differs".into());
        }
        let parent = if height == 0 {
            [0; 32]
        } else {
            let value = blocks
                .get(height)
                .map_err(|_| "restart tip unavailable")?
                .ok_or("restart tip missing")?;
            let header = Header::decode(
                value
                    .value()
                    .get(..HEADER_BYTES)
                    .ok_or("restart tip truncated")?,
                &genesis.config().network,
            )
            .map_err(|_| "restart tip invalid")?;
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
            != 4
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
        let seal = read("seal", crate::identity::storage_checkpoint::SEAL_BYTES)?;
        identity
            .descriptor()
            .map_err(|_| "restart descriptor unavailable")?
            .verify_local_storage(
                super::restart::digest(&genesis, &bytes, leaves, spends),
                &seal,
            )
            .map_err(|_| "authenticated restart seal mismatch")?;
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
            engine,
            usable: true,
            restart: Some(super::restart::Context {
                identity,
                leaves,
                spends,
            }),
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
        };
        context.write(&txn, self.engine.genesis(), &bytes, leaves, spends)?;
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
                .open_table(BLOCKS)
                .map_err(|_| "versioned export history unavailable")?;
            let value = table
                .get(self.engine.state().height())
                .map_err(|_| "versioned export header unavailable")?
                .ok_or("versioned export header missing")?;
            let header = Header::decode(
                value
                    .value()
                    .get(..HEADER_BYTES)
                    .ok_or("truncated versioned export header")?,
                &self.engine.state().network(),
            )
            .map_err(|_| "invalid versioned export header")?;
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
        if height == 0 || !height.is_multiple_of(72) {
            return Err("checkpoint archive requires a positive 72-block boundary".into());
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
                .insert(height, bytes.as_slice())
                .map_err(|_| "checkpoint archive write failed")?;
        }
        txn.commit()
            .map_err(|_| "checkpoint archive durable commit failed".into())
    }
    /// Reconstruct and recheck a prior explicitly archived actual state. The
    /// checkpoint publisher separately requires 24 later confirmations.
    pub fn checkpoint_anchor(
        &self,
        height: u64,
        limits: super::snapshot::ImportLimits,
    ) -> Result<super::snapshot::SnapshotState, String> {
        self.ensure_exportable()?;
        if height == 0 || !height.is_multiple_of(72) || height > self.engine.state().height() {
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
        let bytes = table
            .get(height)
            .map_err(|_| "checkpoint archive lookup failed")?
            .ok_or("checkpoint archive missing")?;
        super::snapshot::SnapshotState::from_committed_components(
            self.engine.genesis(),
            &header,
            bytes.value(),
            limits,
        )
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
        let mut txn = self
            .database
            .begin_write()
            .map_err(|_| "versioned block transaction unavailable")?;
        txn.set_durability(Durability::Immediate)
            .map_err(|_| "versioned block durability unavailable")?;
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
            )?;
            next_restart = Some((leaves, spends));
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
        if let (Some(context), Some((leaves, spends))) = (&mut self.restart, next_restart) {
            context.leaves = leaves;
            context.spends = spends;
        }
        self.usable = true;
        Ok(result)
    }
    /// Return canonical public header/body bytes for explicit independent replay.
    pub fn block(&self, height: u64) -> Result<(Header, Body), String> {
        self.check_readable()?;
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
        decode(&self.engine, value.value())
    }
    /// Read only the fixed-width persisted header, without allocating a body.
    pub fn header(&self, height: u64) -> Result<Header, String> {
        self.check_readable()?;
        let txn = self
            .database
            .begin_read()
            .map_err(|_| "versioned header read unavailable")?;
        let table = txn
            .open_table(BLOCKS)
            .map_err(|_| "versioned header table unavailable")?;
        let value = table
            .get(height)
            .map_err(|_| "versioned header lookup failed")?
            .ok_or("versioned header missing")?;
        Header::decode(
            value
                .value()
                .get(..HEADER_BYTES)
                .ok_or("truncated versioned header")?,
            &self.engine.state().network(),
        )
        .map_err(|_| "invalid versioned persisted header".into())
    }
    /// Size the persisted body before callers reserve memory for decoding.
    pub fn block_size(&self, height: u64) -> Result<usize, String> {
        self.check_readable()?;
        let txn = self
            .database
            .begin_read()
            .map_err(|_| "versioned body size unavailable")?;
        let table = txn
            .open_table(BLOCKS)
            .map_err(|_| "versioned body size table unavailable")?;
        let value = table
            .get(height)
            .map_err(|_| "versioned body size lookup failed")?
            .ok_or("versioned body missing")?;
        value
            .value()
            .len()
            .checked_sub(HEADER_BYTES)
            .ok_or_else(|| "truncated versioned persisted body".into())
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
