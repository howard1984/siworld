//! Durable canonical history for the disposable native engineering chain.
//!
//! Opening always replays every stored block through the caller's verifier. A
//! saved fingerprint detects inconsistent records; it never replaces proof or
//! state-transition verification. Failed opens preserve the database for review.
use crate::chain::{self, BranchOutcome, CandidatePolicy, ChainError, ValidatedBranch};
use crate::state::{BlockVerifier, Config, State};
use crate::wire::{Block, MAX_BLOCK_BYTES};
use redb::{
    Database, Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
    TableHandle,
};
use std::collections::BTreeSet;
use std::fs::{File, Metadata, OpenOptions};
use std::io::ErrorKind;
use std::path::Path;

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("native-store-meta-v2");
const BLOCKS: TableDefinition<u64, &[u8]> = TableDefinition::new("canonical-blocks-v2");
// Created only in the same transaction as an accepted reorganization.
// Existing M1 stores retain their exact two-table schema until that operation.
const DETACHED: TableDefinition<&[u8], &[u8]> = TableDefinition::new("detached-blocks-v1");
const HEAD_BYTES: usize = 72;
const FINGERPRINT_BYTES: usize = 32;
mod receipts;

pub struct Store {
    database: Database,
    state: State,
    receipt_owner: receipts::Owner,
}

impl Store {
    /// Creates an absent database or fully verifies an existing one. Existing
    /// empty, malformed, incompatible or incomplete stores are never initialized.
    pub fn open(
        path: impl AsRef<Path>,
        config: Config,
        verifier: &impl BlockVerifier,
    ) -> Result<Self, String> {
        Self::open_inner(path.as_ref(), config, verifier, true)
    }

    /// Opens a previously initialized history. Read, validation and production
    /// commands must use this entry point so a lost database cannot become a
    /// silently reinitialized genesis history.
    pub fn open_existing(
        path: impl AsRef<Path>,
        config: Config,
        verifier: &impl BlockVerifier,
    ) -> Result<Self, String> {
        Self::open_inner(path.as_ref(), config, verifier, false)
    }

    fn open_inner(
        path: &Path,
        config: Config,
        verifier: &impl BlockVerifier,
        create_allowed: bool,
    ) -> Result<Self, String> {
        config.validate()?;
        let (file, created) = open_regular_file(path, create_allowed)?;
        let receipt_owner = receipts::Owner::bind(path, &file)?;
        let mut builder = Database::builder();
        builder.set_cache_size(32 * 1024 * 1024);
        // An allocator or checksum repair may discard evidence. Recovery of an
        // unclean or damaged database requires a separate, explicit review.
        builder.set_repair_callback(|session| session.abort());
        let database = builder
            .create_file(file)
            .map_err(|_| "invalid, damaged or unavailable native database")?;
        if created {
            initialize(&database, &config)?;
            sync_parent(path)?;
        }
        let state = replay(&database, config, verifier)?;
        Ok(Self {
            database,
            state,
            receipt_owner,
        })
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    pub(crate) fn save_reward_receipt(
        &self,
        id: &crate::wire::Hash,
        secret: &[u8],
    ) -> Result<(), String> {
        self.receipt_owner.save(id, secret)
    }

    /// Returns the complete canonical block, including proofs, for local receipt
    /// inspection. Height zero identifies genesis and has no block record.
    pub fn block(&self, height: u64) -> Result<Block, String> {
        if height == 0 || height > self.state.height {
            return Err("canonical block height unavailable".into());
        }
        let txn = self
            .database
            .begin_read()
            .map_err(|_| "native database read unavailable")?;
        let blocks = txn
            .open_table(BLOCKS)
            .map_err(|_| "native block table missing or incompatible")?;
        let value = blocks
            .get(height)
            .map_err(|_| "native block record unreadable")?
            .ok_or("canonical block missing")?;
        let (bytes, _) = split_record(value.value())?;
        let block = Block::decode(bytes, &self.state.config.network)?;
        if block.height != height {
            return Err("canonical block key mismatch".into());
        }
        Ok(block)
    }

    /// Retained detached blocks are evidence, never accepted-chain authority.
    pub fn detached_count(&self) -> Result<u64, String> {
        let txn = self
            .database
            .begin_read()
            .map_err(|_| "native database read unavailable")?;
        let present = txn
            .list_tables()
            .map_err(|_| "native database schema unreadable")?
            .any(|table| table.name() == DETACHED.name());
        if !present {
            return Ok(0);
        }
        txn.open_table(DETACHED)
            .map_err(|_| "native detached table incompatible")?
            .len()
            .map_err(|_| "native detached count unreadable".into())
    }

    pub fn detached_block(&self, id: &crate::wire::Hash) -> Result<Block, String> {
        let txn = self
            .database
            .begin_read()
            .map_err(|_| "native database read unavailable")?;
        let table = txn
            .open_table(DETACHED)
            .map_err(|_| "native detached evidence unavailable")?;
        let record = table
            .get(id.as_slice())
            .map_err(|_| "native detached record unreadable")?
            .ok_or("native detached record missing")?;
        let (bytes, _) = split_record(detached_record(record.value())?)?;
        let block = Block::decode(bytes, &self.state.config.network)?;
        if block.id()? != *id {
            return Err("native detached identity mismatch".into());
        }
        Ok(block)
    }

    /// Reconstruct a canonical ancestor, verify the full contiguous candidate,
    /// then compare verified cumulative work. Claimed height/work is never used.
    /// Equal work retains the current branch. Local budget failures are retryable.
    pub fn consider_branch(
        &mut self,
        ancestor_height: u64,
        blocks: &[Block],
        policy: CandidatePolicy,
        verifier: &impl BlockVerifier,
    ) -> Result<BranchOutcome, ChainError> {
        chain::check_ancestor(self.state.height, ancestor_height)?;
        let candidate_bytes = chain::candidate_budget(blocks, policy)?;
        let ancestor = self.ancestor_state(ancestor_height, candidate_bytes, policy, verifier)?;
        let branch = chain::validate_candidate(&self.state, ancestor, blocks, policy, verifier)?;
        if !chain::prefer_work(self.state.cumulative_work, branch.accepted.cumulative_work) {
            return Ok(BranchOutcome::Unchanged {
                candidate_height: branch.accepted.height,
                candidate_work: branch.accepted.cumulative_work,
            });
        }
        let outcome = BranchOutcome::Adopted {
            detached: self.state.height - ancestor_height,
            attached: blocks.len(),
            height: branch.accepted.height,
            tip: branch.accepted.tip,
        };
        self.commit_branch(ancestor_height, branch, policy)?;
        Ok(outcome)
    }

    fn ancestor_state(
        &self,
        height: u64,
        candidate_bytes: usize,
        policy: CandidatePolicy,
        verifier: &impl BlockVerifier,
    ) -> Result<State, ChainError> {
        if height == self.state.height {
            chain::check_state_budget(&self.state, candidate_bytes, policy)?;
            return Ok(self.state.clone());
        }
        if height > policy.max_replay_blocks {
            return Err(ChainError::ResourceExhausted(
                "canonical ancestor replay allowance",
            ));
        }
        let txn = self
            .database
            .begin_read()
            .map_err(|_| ChainError::Local("native database read unavailable".into()))?;
        let meta = txn
            .open_table(META)
            .map_err(|_| ChainError::Local("native metadata unavailable".into()))?;
        check_metadata(&meta, &self.state.config, &head(&self.state)).map_err(ChainError::Local)?;
        let table = txn
            .open_table(BLOCKS)
            .map_err(|_| ChainError::Local("native block table unavailable".into()))?;
        if table
            .len()
            .map_err(|_| ChainError::Local("native block count unreadable".into()))?
            != self.state.height
        {
            return Err(ChainError::Local(
                "native block count differs from accepted state".into(),
            ));
        }
        let mut ancestor = State::new(self.state.config.clone()).map_err(ChainError::Local)?;
        for next in 1..=height {
            let record = table
                .get(next)
                .map_err(|_| ChainError::Local("native ancestor record unreadable".into()))?
                .ok_or_else(|| ChainError::Local("native ancestor record missing".into()))?;
            let (bytes, fingerprint) = split_record(record.value()).map_err(ChainError::Local)?;
            let replay_bytes = candidate_bytes
                .checked_add(bytes.len())
                .ok_or(ChainError::ResourceExhausted("ancestor replay bytes"))?;
            chain::check_state_budget(&ancestor, replay_bytes, policy)?;
            let block =
                Block::decode(bytes, &ancestor.config.network).map_err(ChainError::Local)?;
            ancestor
                .apply(&block, verifier)
                .map_err(ChainError::Local)?;
            chain::check_state_budget(&ancestor, replay_bytes, policy)?;
            if ancestor.fingerprint().as_slice() != fingerprint {
                return Err(ChainError::Local(
                    "native ancestor fingerprint mismatch".into(),
                ));
            }
        }
        Ok(ancestor)
    }

    /// Canonical rows, detached evidence and the head move at one durable redb
    /// commit boundary. Failed validation, capacity checks or writes cannot expose
    /// a partial branch; accepted memory changes only after commit succeeds.
    fn commit_branch(
        &mut self,
        ancestor_height: u64,
        branch: ValidatedBranch,
        policy: CandidatePolicy,
    ) -> Result<(), ChainError> {
        let local = |reason: &str| ChainError::Local(reason.to_owned());
        let mut txn = self
            .database
            .begin_write()
            .map_err(|_| local("native database write unavailable"))?;
        txn.set_durability(Durability::Immediate)
            .map_err(|_| local("native database durability unavailable"))?;
        validate_tables(
            txn.list_tables()
                .map_err(|_| local("native database schema unreadable"))?,
            txn.list_multimap_tables()
                .map_err(|_| local("native database schema unreadable"))?
                .next()
                .is_some(),
        )
        .map_err(ChainError::Local)?;
        let detach = ancestor_height < self.state.height;
        let retained_present = txn
            .list_tables()
            .map_err(|_| local("native database schema unreadable"))?
            .any(|table| table.name() == DETACHED.name());
        {
            let mut meta = txn
                .open_table(META)
                .map_err(|_| local("native metadata table unavailable"))?;
            check_metadata(&meta, &self.state.config, &head(&self.state))
                .map_err(ChainError::Local)?;
            let mut canonical = txn
                .open_table(BLOCKS)
                .map_err(|_| local("native canonical table unavailable"))?;
            if canonical
                .len()
                .map_err(|_| local("native block count unreadable"))?
                != self.state.height
            {
                return Err(local("native block count differs from accepted state"));
            }
            if detach || retained_present {
                let mut retained = txn
                    .open_table(DETACHED)
                    .map_err(|_| local("native detached table unavailable"))?;
                let mut retained_bytes = 0usize;
                for row in retained
                    .iter()
                    .map_err(|_| local("native detached iteration unavailable"))?
                {
                    let (key, value) =
                        row.map_err(|_| local("native detached record unreadable"))?;
                    retained_bytes = retained_bytes
                        .checked_add(key.value().len())
                        .and_then(|n| n.checked_add(value.value().len()))
                        .and_then(|n| n.checked_add(64))
                        .ok_or(ChainError::ResourceExhausted(
                            "retained evidence byte accounting",
                        ))?;
                }
                for height in ancestor_height.saturating_add(1)..=self.state.height {
                    let record = canonical
                        .get(height)
                        .map_err(|_| local("native canonical record unreadable"))?
                        .ok_or_else(|| local("native canonical record missing"))?;
                    let (bytes, _) = split_record(record.value()).map_err(ChainError::Local)?;
                    let block = Block::decode(bytes, &self.state.config.network)
                        .map_err(ChainError::Local)?;
                    let id = block.id().map_err(ChainError::Local)?;
                    let missing = {
                        let existing = retained
                            .get(id.as_slice())
                            .map_err(|_| local("native detached record unreadable"))?;
                        if let Some(existing) = existing {
                            if detached_record(existing.value()).map_err(ChainError::Local)?
                                != record.value()
                            {
                                return Err(local("conflicting retained detached record"));
                            }
                            false
                        } else {
                            true
                        }
                    };
                    if missing {
                        retained_bytes = retained_bytes
                            .checked_add(record.value().len())
                            .and_then(|n| n.checked_add(32 + 64 + 32))
                            .ok_or(ChainError::ResourceExhausted(
                                "retained evidence byte accounting",
                            ))?;
                        if retained_bytes > policy.max_retained_bytes {
                            return Err(ChainError::ResourceExhausted(
                                "retained detached evidence bytes",
                            ));
                        }
                        let evidence = encode_detached(record.value());
                        retained
                            .insert(id.as_slice(), evidence.as_slice())
                            .map_err(|_| local("native detached evidence write failed"))?;
                    }
                }
                if retained_bytes > policy.max_retained_bytes {
                    return Err(ChainError::ResourceExhausted(
                        "retained detached evidence bytes",
                    ));
                }
            }
            for height in ancestor_height.saturating_add(1)..=self.state.height {
                canonical
                    .remove(height)
                    .map_err(|_| local("native canonical detach failed"))?;
            }
            for (height, record) in &branch.records {
                if canonical
                    .get(*height)
                    .map_err(|_| local("native canonical record unreadable"))?
                    .is_some()
                {
                    return Err(local("candidate overwrites retained canonical prefix"));
                }
                canonical
                    .insert(*height, record.as_slice())
                    .map_err(|_| local("native canonical attachment failed"))?;
            }
            meta.insert("head", head(&branch.accepted).as_slice())
                .map_err(|_| local("native head write failed"))?;
        }
        txn.commit()
            .map_err(|_| local("native branch commit failed"))?;
        self.state = branch.accepted;
        Ok(())
    }

    /// Commits a verified canonical block and its resulting fingerprint together.
    /// Accepted in-memory state changes only after the durable commit succeeds.
    pub fn append(&mut self, block: &Block, verifier: &impl BlockVerifier) -> Result<(), String> {
        let mut accepted = self.state.clone();
        accepted.apply(block, verifier)?;
        let mut record = block.encode()?;
        record.extend_from_slice(&accepted.fingerprint());
        let mut txn = self
            .database
            .begin_write()
            .map_err(|_| "native database write unavailable")?;
        txn.set_durability(Durability::Immediate)
            .map_err(|_| "native database durability unavailable")?;
        validate_tables(
            txn.list_tables()
                .map_err(|_| "native database schema unreadable")?,
            txn.list_multimap_tables()
                .map_err(|_| "native database schema unreadable")?
                .next()
                .is_some(),
        )?;
        {
            let mut meta = txn
                .open_table(META)
                .map_err(|_| "native metadata table missing or incompatible")?;
            check_metadata(&meta, &self.state.config, &head(&self.state))?;
            let mut blocks = txn
                .open_table(BLOCKS)
                .map_err(|_| "native block table missing or incompatible")?;
            if blocks.len().map_err(|_| "native block count unreadable")? != self.state.height {
                return Err("native block count disagrees with accepted head".into());
            }
            if blocks
                .get(block.height)
                .map_err(|_| "native block record unreadable")?
                .is_some()
            {
                return Err("canonical block already stored".into());
            }
            let _ = blocks
                .insert(block.height, record.as_slice())
                .map_err(|_| "native block write failed")?;
            let next_head = head(&accepted);
            let _ = meta
                .insert("head", next_head.as_slice())
                .map_err(|_| "native head write failed")?;
        }
        txn.commit().map_err(|_| "native block commit failed")?;
        self.state = accepted;
        Ok(())
    }
}

fn initialize(database: &Database, config: &Config) -> Result<(), String> {
    let state = State::new(config.clone())?;
    let mut txn = database
        .begin_write()
        .map_err(|_| "native database initialization unavailable")?;
    txn.set_durability(Durability::Immediate)
        .map_err(|_| "native database durability unavailable")?;
    if txn
        .list_tables()
        .map_err(|_| "native database schema unreadable")?
        .next()
        .is_some()
        || txn
            .list_multimap_tables()
            .map_err(|_| "native database schema unreadable")?
            .next()
            .is_some()
    {
        return Err("new native database is not empty".into());
    }
    {
        let mut meta = txn
            .open_table(META)
            .map_err(|_| "native metadata initialization failed")?;
        let encoded = configuration(config);
        let initial = head(&state);
        let _ = meta
            .insert("config", encoded.as_slice())
            .map_err(|_| "native configuration write failed")?;
        let _ = meta
            .insert("head", initial.as_slice())
            .map_err(|_| "native genesis write failed")?;
        drop(
            txn.open_table(BLOCKS)
                .map_err(|_| "native block table initialization failed")?,
        );
    }
    txn.commit()
        .map_err(|_| "native database initialization commit failed".to_owned())
}

fn replay(
    database: &Database,
    config: Config,
    verifier: &impl BlockVerifier,
) -> Result<State, String> {
    let txn = database
        .begin_read()
        .map_err(|_| "native database read unavailable")?;
    validate_tables(
        txn.list_tables()
            .map_err(|_| "native database schema unreadable")?,
        txn.list_multimap_tables()
            .map_err(|_| "native database schema unreadable")?
            .next()
            .is_some(),
    )?;
    if txn
        .list_tables()
        .map_err(|_| "native database schema unreadable")?
        .any(|table| table.name() == DETACHED.name())
    {
        let detached = txn
            .open_table(DETACHED)
            .map_err(|_| "native detached table incompatible")?;
        for row in detached
            .iter()
            .map_err(|_| "native detached iteration unavailable")?
        {
            let (key, record) = row.map_err(|_| "native detached record unreadable")?;
            let (bytes, _) = split_record(detached_record(record.value())?)?;
            let block = Block::decode(bytes, &config.network)?;
            if key.value() != block.id()?.as_slice() {
                return Err("native detached identity mismatch".into());
            }
        }
    }
    let meta = txn
        .open_table(META)
        .map_err(|_| "native metadata table missing or incompatible")?;
    let encoded = configuration(&config);
    if meta.len().map_err(|_| "native metadata unreadable")? != 2
        || meta
            .get("config")
            .map_err(|_| "native configuration unreadable")?
            .ok_or("native configuration missing")?
            .value()
            != encoded
    {
        return Err("native configuration or metadata mismatch".into());
    }
    let saved = meta
        .get("head")
        .map_err(|_| "native head unreadable")?
        .ok_or("native head missing")?;
    if saved.value().len() != HEAD_BYTES {
        return Err("invalid native head encoding".into());
    }
    let height = u64::from_le_bytes(
        saved.value()[..8]
            .try_into()
            .map_err(|_| "invalid native head height")?,
    );
    let blocks = txn
        .open_table(BLOCKS)
        .map_err(|_| "native block table missing or incompatible")?;
    if blocks.len().map_err(|_| "native block count unreadable")? != height {
        return Err("native block count disagrees with committed head".into());
    }
    let mut state = State::new(config)?;
    for row in blocks
        .iter()
        .map_err(|_| "native block iteration unavailable")?
    {
        let (key, value) = row.map_err(|_| "native block record unreadable")?;
        if state.height.checked_add(1) != Some(key.value()) {
            return Err("missing or gapped canonical block".into());
        }
        let (bytes, fingerprint) = split_record(value.value())?;
        let block = Block::decode(bytes, &state.config.network)?;
        state.apply(&block, verifier)?;
        if state.fingerprint().as_slice() != fingerprint {
            return Err("native block state fingerprint mismatch".into());
        }
    }
    if head(&state).as_slice() != saved.value() {
        return Err("native replay disagrees with committed head".into());
    }
    Ok(state)
}

fn check_metadata(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    config: &Config,
    expected_head: &[u8; HEAD_BYTES],
) -> Result<(), String> {
    let expected_config = configuration(config);
    if table.len().map_err(|_| "native metadata unreadable")? != 2
        || table
            .get("config")
            .map_err(|_| "native configuration unreadable")?
            .ok_or("native configuration missing")?
            .value()
            != expected_config
        || table
            .get("head")
            .map_err(|_| "native head unreadable")?
            .ok_or("native head missing")?
            .value()
            != expected_head
    {
        return Err("native metadata differs from accepted state".into());
    }
    Ok(())
}

fn validate_tables(
    tables: impl Iterator<Item = redb::UntypedTableHandle>,
    has_multimap: bool,
) -> Result<(), String> {
    let names: BTreeSet<_> = tables.map(|table| table.name().to_owned()).collect();
    let expected = BTreeSet::from([META.name().to_owned(), BLOCKS.name().to_owned()]);
    let extended = BTreeSet::from([
        META.name().to_owned(),
        BLOCKS.name().to_owned(),
        DETACHED.name().to_owned(),
    ]);
    if has_multimap || (names != expected && names != extended) {
        return Err("native database schema mismatch".into());
    }
    Ok(())
}

fn configuration(config: &Config) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"SWNS\x02\0");
    bytes.extend_from_slice(native::codec::SUITE_ID);
    bytes.extend_from_slice(&config.encode_rules());
    bytes.extend_from_slice(&config.genesis_id());
    bytes
}
fn head(state: &State) -> [u8; HEAD_BYTES] {
    let mut bytes = [0; HEAD_BYTES];
    bytes[..8].copy_from_slice(&state.height.to_le_bytes());
    bytes[8..40].copy_from_slice(&state.tip);
    bytes[40..].copy_from_slice(&state.fingerprint());
    bytes
}
fn split_record(record: &[u8]) -> Result<(&[u8], &[u8]), String> {
    if record.len() < FINGERPRINT_BYTES || record.len() > MAX_BLOCK_BYTES + FINGERPRINT_BYTES {
        return Err("native block record length invalid".into());
    }
    Ok(record.split_at(record.len() - FINGERPRINT_BYTES))
}

fn encode_detached(record: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(record.len() + 32);
    bytes.extend_from_slice(record);
    let checksum = blake3::derive_key("siworld native detached record v1", record);
    bytes.extend_from_slice(&checksum);
    bytes
}

fn detached_record(bytes: &[u8]) -> Result<&[u8], String> {
    if bytes.len() < 32 || bytes.len() > MAX_BLOCK_BYTES + FINGERPRINT_BYTES + 32 {
        return Err("native detached record length invalid".into());
    }
    let (record, checksum) = bytes.split_at(bytes.len() - 32);
    if blake3::derive_key("siworld native detached record v1", record).as_slice() != checksum {
        return Err("native detached evidence checksum mismatch".into());
    }
    Ok(record)
}

fn open_regular_file(path: &Path, create_allowed: bool) -> Result<(File, bool), String> {
    let existing = match std::fs::symlink_metadata(path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        Err(_) => return Err("native database path unavailable".into()),
    };
    if existing.is_none() && !create_allowed {
        return Err("initialized native database missing".into());
    }
    if existing
        .as_ref()
        .is_some_and(|metadata| !metadata.is_file() || metadata.len() == 0)
    {
        return Err("native database path must be a nonempty regular file".into());
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if existing.is_none() {
        options.create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
    }
    let file = options
        .open(path)
        .map_err(|_| "native database file unavailable")?;
    let opened = file
        .metadata()
        .map_err(|_| "native database file metadata unavailable")?;
    let current = std::fs::symlink_metadata(path)
        .map_err(|_| "native database path changed while opening")?;
    if !opened.is_file()
        || !current.is_file()
        || !same_file(&opened, &current)
        || existing
            .as_ref()
            .is_some_and(|before| !same_file(before, &opened))
    {
        return Err("native database path changed or is not regular".into());
    }
    Ok((file, existing.is_none()))
}
#[cfg(unix)]
fn same_file(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}
#[cfg(not(unix))]
fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.len() == right.len() && left.created().ok() == right.created().ok()
}
fn sync_parent(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "native database directory durability unavailable")?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests;
