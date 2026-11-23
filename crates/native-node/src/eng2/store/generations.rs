//! Authenticated, durable canonical generation selection.
//!
//! The caller holds the owner barrier across each mutation and the in-memory
//! store exchange. Replay and native verification take place before publication.
//! This protects against interrupted commits and stale individual chain files;
//! it does not detect rollback of the entire private owner directory.

use super::Store;
use crate::{
    eng2::{
        certificate::{CERTIFICATE_BYTES, Certificate},
        runtime_export::{CertifiedCheckpoint, confirmed_checkpoint},
    },
    identity::{Descriptor, NativeIdentity, storage_checkpoint::SEAL_BYTES},
    p2p::Binding,
    wire::Hash,
};
use redb::{
    Database, Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
};
use siworld_core::pow::Work;
use std::{
    fs::File,
    path::{Path, PathBuf},
};

use std::{
    fs::{Metadata, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("eng2-generation-selection-v1");
const CONTROL_FILE: &str = "chain-control.redb";
const KEY: &str = "active";
const MAGIC: &[u8; 8] = b"SW2GEN01";
const BASE: usize = 8 + 3 * 32 + 8 + 32 + 8 + 32 + 64 + 1;
const MAX_CONTROL_FILE_BYTES: u64 = 64 * 1024 * 1024;

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Storage(&'static str),
    Invalid(&'static str),
    Stale,
    NotGreaterWork,
    /// The owner must reopen the durable selection before serving again.
    CommitUncertain,
}
impl std::fmt::Display for Error {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(reason) | Self::Invalid(reason) => out.write_str(reason),
            Self::Stale => out.write_str("generation control expected record changed"),
            Self::NotGreaterWork => out.write_str("candidate does not have greater verified work"),
            Self::CommitUncertain => {
                out.write_str("generation control commit requires authenticated reopen")
            }
        }
    }
}
impl From<Error> for String {
    fn from(error: Error) -> Self {
        error.to_string()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Generation {
    number: u64,
    id: Hash,
}
impl Generation {
    pub(crate) fn initial() -> Self {
        Self {
            number: 0,
            id: [0; 32],
        }
    }
    pub(crate) fn successor(self, id: Hash) -> Result<Self> {
        if id == [0; 32] || id == self.id {
            return Err(Error::Invalid("generation successor identity is invalid"));
        }
        Ok(Self {
            number: self
                .number
                .checked_add(1)
                .ok_or(Error::Invalid("generation number exhausted"))?,
            id,
        })
    }
    pub(crate) fn path(self, directory: &Path) -> PathBuf {
        if self == Self::initial() {
            directory.join("chain.redb")
        } else {
            directory.join(format!(
                "chain-generation-{:020}-{}.redb",
                self.number,
                crate::local::hex(&self.id)
            ))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Head {
    pub(crate) height: u64,
    pub(crate) id: Hash,
    pub(crate) work: Work,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Record {
    generation: Generation,
    published: Head,
    floor: Option<Certificate>,
}
impl Record {
    pub(crate) fn generation(&self) -> Generation {
        self.generation
    }
    pub(crate) fn floor(&self) -> Option<&Certificate> {
        self.floor.as_ref()
    }
    #[cfg(test)]
    pub(crate) fn published_head(&self) -> Head {
        self.published
    }
}

trait ChainView {
    fn generation(&self) -> Generation;
    fn binding(&self) -> Binding;
    fn head(&self) -> Result<Head>;
    fn block(&self, height: u64) -> Result<Option<Hash>>;
    fn matches_path(&self, path: &Path) -> Result<bool>;
}

/// A label for an authenticated store; publication verifies the open file identity.
pub(crate) struct StoreView<'a> {
    generation: Generation,
    store: &'a Store,
}
impl<'a> StoreView<'a> {
    pub(crate) fn new(generation: Generation, store: &'a Store) -> Result<Self> {
        store
            .ensure_exportable()
            .map_err(|_| Error::Invalid("generation store cannot be read"))?;
        if store.restart.is_none() {
            return Err(Error::Invalid(
                "generation store does not support authenticated recovery",
            ));
        }
        Ok(Self { generation, store })
    }

    fn matches_identity(&self, expected: &Descriptor) -> Result<bool> {
        let identity = &self
            .store
            .restart
            .as_ref()
            .ok_or(Error::Invalid("generation restart identity unavailable"))?
            .identity;
        Ok(descriptor(identity)?.fingerprint() == expected.fingerprint())
    }
}
impl ChainView for StoreView<'_> {
    fn matches_path(&self, path: &Path) -> Result<bool> {
        self.store
            .matches_owner_path(path)
            .map_err(|_| Error::Invalid("generation file identity unavailable"))
    }
    fn generation(&self) -> Generation {
        self.generation
    }
    fn binding(&self) -> Binding {
        self.store.engine().genesis().peer_binding()
    }
    fn head(&self) -> Result<Head> {
        self.store
            .ensure_exportable()
            .map_err(|_| Error::Invalid("generation store cannot be read"))?;
        let state = self.store.engine().state();
        Ok(Head {
            height: state.height(),
            id: state.tip(),
            work: state.chain().cumulative_work,
        })
    }
    fn block(&self, height: u64) -> Result<Option<Hash>> {
        if height == 0 {
            return Ok(Some(self.binding().genesis));
        }
        if height > self.head()?.height {
            return Ok(None);
        }
        let header = self
            .store
            .header(height)
            .map_err(|_| Error::Invalid("generation header cannot be read"))?;
        Ok(Some(header.id().map_err(|_| {
            Error::Invalid("generation header identity failed")
        })?))
    }
}

pub(crate) struct GenerationControl {
    database: Database,
    file_id: FileId,
    directory: PathBuf,
    binding: Binding,
    record: Record,
    usable: bool,
}
impl GenerationControl {
    /// Only explicit network initialization may create this record.
    pub(crate) fn create(
        directory: &Path,
        identity: &NativeIdentity,
        initially_selected: &StoreView<'_>,
    ) -> Result<Self> {
        if !initially_selected.matches_identity(&descriptor(identity)?)? {
            return Err(Error::Invalid("generation uses a different owner identity"));
        }
        Self::create_with(directory, identity, initially_selected)
    }

    fn create_with(
        directory: &Path,
        identity: &NativeIdentity,
        initially_selected: &impl ChainView,
    ) -> Result<Self> {
        if initially_selected.head()?.height != 0 {
            return Err(Error::Invalid(
                "generation creation requires an authenticated genesis-only store",
            ));
        }
        Self::create_record(directory, identity, initially_selected, None)
    }

    /// The import has already verified the quorum and executed history.
    /// Publish the imported head and its certified floor in the same record.
    pub(super) fn create_imported(
        directory: &Path,
        identity: &NativeIdentity,
        initially_selected: &StoreView<'_>,
        certificate: Certificate,
    ) -> Result<Self> {
        if !initially_selected.matches_identity(&descriptor(identity)?)? {
            return Err(Error::Invalid("generation uses a different owner identity"));
        }
        Self::create_record(directory, identity, initially_selected, Some(certificate))
    }

    pub(super) fn ensure_new(directory: &Path) -> Result<()> {
        match std::fs::symlink_metadata(directory.join(CONTROL_FILE)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            _ => Err(Error::Invalid("existing or unreadable generation selector")),
        }
    }

    fn create_record(
        directory: &Path,
        identity: &NativeIdentity,
        initially_selected: &impl ChainView,
        floor: Option<Certificate>,
    ) -> Result<Self> {
        let binding = descriptor(identity)?.binding();
        let record = Record {
            generation: Generation::initial(),
            published: initially_selected.head()?,
            floor,
        };
        verify(&record, binding, directory, initially_selected)?;
        if let Some(certificate) = &record.floor {
            let statement = &certificate.statement;
            if initially_selected.block(statement.authorization_height)?
                != Some(statement.authorization_block)
            {
                return Err(Error::Invalid(
                    "import authorization differs from selected history",
                ));
            }
        }
        let path = directory.join(CONTROL_FILE);
        sync_candidate(&record.generation.path(directory), initially_selected)?;
        let sealed = seal(identity, binding, &record)?;
        let (database, file_id) = control_database(directory, true)?;
        let mut transaction = database
            .begin_write()
            .map_err(|_| Error::Storage("generation control initialization unavailable"))?;
        immediate(&mut transaction)?;
        {
            let mut table = transaction
                .open_table(TABLE)
                .map_err(|_| Error::Storage("generation control table unavailable"))?;
            if !table
                .is_empty()
                .map_err(|_| Error::Storage("generation control table unreadable"))?
            {
                return Err(Error::Invalid("generation control already has a selection"));
            }
            table
                .insert(KEY, sealed.as_slice())
                .map_err(|_| Error::Storage("generation control write failed"))?;
        }
        check_control_path(directory, file_id)?;
        check_chain_path(initially_selected, &record.generation.path(directory))?;
        transaction.commit().map_err(|_| Error::CommitUncertain)?;
        check_control_path(directory, file_id).map_err(|_| Error::CommitUncertain)?;
        check_chain_path(initially_selected, &record.generation.path(directory))
            .map_err(|_| Error::CommitUncertain)?;
        crate::store::sync_parent(&path).map_err(|_| Error::CommitUncertain)?;
        Ok(Self {
            database,
            file_id,
            directory: directory.to_owned(),
            binding,
            record,
            usable: true,
        })
    }

    /// Authenticate the control before opening only its explicitly named store.
    /// A missing or invalid control or selected chain is never replaced.
    pub(crate) fn open_existing(
        directory: &Path,
        identity: &NativeIdentity,
        open_store: impl FnOnce(&Path) -> std::result::Result<Store, String>,
    ) -> Result<(Self, Store)> {
        Self::open_with(directory, identity, |record, binding| {
            let store = open_store(&record.generation.path(directory))
                .map_err(|_| Error::Invalid("selected store could not be authenticated"))?;
            let view = StoreView::new(record.generation, &store)?;
            if !view.matches_identity(&descriptor(identity)?)? {
                return Err(Error::Invalid("generation uses a different owner identity"));
            }
            verify(record, binding, directory, &view)?;
            Ok(store)
        })
    }

    fn open_with<T>(
        directory: &Path,
        identity: &NativeIdentity,
        authenticate: impl FnOnce(&Record, Binding) -> Result<T>,
    ) -> Result<(Self, T)> {
        let descriptor = descriptor(identity)?;
        let binding = descriptor.binding();
        let (database, file_id) = control_database(directory, false)?;
        let record = {
            let transaction = database
                .begin_read()
                .map_err(|_| Error::Storage("generation control read unavailable"))?;
            let table = transaction
                .open_table(TABLE)
                .map_err(|_| Error::Invalid("generation control table missing or unreadable"))?;
            if table
                .len()
                .map_err(|_| Error::Storage("generation control count unavailable"))?
                != 1
            {
                return Err(Error::Invalid(
                    "generation control must contain exactly one selection",
                ));
            }
            let bytes = table
                .get(KEY)
                .map_err(|_| Error::Storage("generation control selection unreadable"))?
                .ok_or(Error::Invalid("generation control selection missing"))?;
            unseal(&descriptor, bytes.value())?
        };
        let opened = authenticate(&record, binding)?;
        check_control_path(directory, file_id)?;
        Ok((
            Self {
                database,
                file_id,
                directory: directory.to_owned(),
                binding,
                record,
                usable: true,
            },
            opened,
        ))
    }

    pub(crate) fn directory(&self) -> &Path {
        &self.directory
    }

    pub(crate) fn current(&self) -> Result<&Record> {
        self.usable
            .then_some(&self.record)
            .ok_or(Error::CommitUncertain)
    }

    /// Record accepted certificate bytes in the same transaction as the pointer.
    pub(crate) fn advance_floor(
        &mut self,
        identity: &NativeIdentity,
        expected: &Record,
        current: &StoreView<'_>,
        certificate: &CertifiedCheckpoint,
    ) -> Result<bool> {
        self.expect(expected)?;
        certificate.check_current(current.store).map_err(|_| {
            Error::Invalid("checkpoint capability is stale for selected generation")
        })?;
        self.advance_verified_floor(
            identity,
            expected,
            current,
            certificate.certificate().clone(),
        )
    }

    fn advance_verified_floor(
        &mut self,
        identity: &NativeIdentity,
        expected: &Record,
        current: &impl ChainView,
        certificate: Certificate,
    ) -> Result<bool> {
        self.expect(expected)?;
        verify(expected, self.binding, &self.directory, current)?;
        let statement = &certificate.statement;
        if statement.network != self.binding.network
            || !confirmed_checkpoint(statement.checkpoint_height, statement.authorization_height)
            || current.block(statement.checkpoint_height)? != Some(statement.checkpoint_block)
        {
            return Err(Error::Invalid("checkpoint does not name a selected block"));
        }
        if expected
            .floor
            .as_ref()
            .is_some_and(|floor| floor.statement.checkpoint_height >= statement.checkpoint_height)
        {
            return Ok(false);
        }
        let next = Record {
            floor: Some(certificate),
            ..expected.clone()
        };
        let path = expected.generation.path(&self.directory);
        self.compare_and_commit(identity, expected, next, |_| {
            check_chain_path(current, &path)
        })?;
        Ok(true)
    }

    /// Swap the in-memory owner before releasing the same publication barrier.
    pub(crate) fn publish(
        &mut self,
        identity: &NativeIdentity,
        expected: &Record,
        current: &StoreView<'_>,
        candidate: &StoreView<'_>,
    ) -> Result<()> {
        let owner = descriptor(identity)?;
        if !current.matches_identity(&owner)? || !candidate.matches_identity(&owner)? {
            return Err(Error::Invalid("generation uses a different owner identity"));
        }
        self.publish_with(identity, expected, current, candidate, |_| Ok(()))
    }

    fn publish_with(
        &mut self,
        identity: &NativeIdentity,
        expected: &Record,
        current: &impl ChainView,
        candidate: &impl ChainView,
        mut boundary: impl FnMut(CommitBoundary) -> Result<()>,
    ) -> Result<()> {
        self.expect(expected)?;
        let current_head = verify(expected, self.binding, &self.directory, current)?;
        let generation = candidate.generation();
        if generation != expected.generation.successor(generation.id)? {
            return Err(Error::Invalid("candidate is not the next generation"));
        }
        let next = Record {
            generation,
            published: candidate.head()?,
            floor: expected.floor.clone(),
        };
        let candidate_head = verify(&next, self.binding, &self.directory, candidate)?;
        if candidate_head.work <= current_head.work {
            return Err(Error::NotGreaterWork);
        }
        let current_path = expected.generation.path(&self.directory);
        let candidate_path = generation.path(&self.directory);
        sync_candidate(&candidate_path, candidate)?;
        self.compare_and_commit(identity, expected, next, |point| {
            check_chain_path(current, &current_path)?;
            check_chain_path(candidate, &candidate_path)?;
            boundary(point)
        })
    }

    fn expect(&self, expected: &Record) -> Result<()> {
        if self.current()? != expected {
            return Err(Error::Stale);
        }
        Ok(())
    }

    fn compare_and_commit(
        &mut self,
        identity: &NativeIdentity,
        expected: &Record,
        next: Record,
        mut boundary: impl FnMut(CommitBoundary) -> Result<()>,
    ) -> Result<()> {
        self.expect(expected)?;
        check_control_path(&self.directory, self.file_id)?;
        let descriptor = descriptor(identity)?;
        if descriptor.binding() != self.binding {
            return Err(Error::Invalid(
                "generation control signer has a different binding",
            ));
        }
        let sealed = seal(identity, self.binding, &next)?;
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|_| Error::Storage("generation control write unavailable"))?;
        immediate(&mut transaction)?;
        {
            let mut table = transaction
                .open_table(TABLE)
                .map_err(|_| Error::Storage("generation control table unavailable"))?;
            if table
                .len()
                .map_err(|_| Error::Storage("generation control count unavailable"))?
                != 1
            {
                return Err(Error::Invalid(
                    "generation control must contain exactly one selection",
                ));
            }
            let old = table
                .get(KEY)
                .map_err(|_| Error::Storage("generation control selection unreadable"))?
                .ok_or(Error::Invalid("generation control selection missing"))?;
            if unseal(&descriptor, old.value())? != *expected {
                return Err(Error::Stale);
            }
            drop(old);
            table
                .insert(KEY, sealed.as_slice())
                .map_err(|_| Error::Storage("generation control update failed"))?;
        }
        boundary(CommitBoundary::BeforeCommit)?;
        check_control_path(&self.directory, self.file_id)?;
        self.usable = false;
        transaction.commit().map_err(|_| Error::CommitUncertain)?;
        check_control_path(&self.directory, self.file_id).map_err(|_| Error::CommitUncertain)?;
        boundary(CommitBoundary::AfterCommit).map_err(|_| Error::CommitUncertain)?;
        self.record = next;
        self.usable = true;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommitBoundary {
    BeforeCommit,
    AfterCommit,
}

fn verify(
    record: &Record,
    binding: Binding,
    directory: &Path,
    view: &impl ChainView,
) -> Result<Head> {
    check_chain_path(view, &record.generation.path(directory))?;
    if view.binding() != binding
        || view.generation() != record.generation
        || view.block(0)? != Some(binding.genesis)
    {
        return Err(Error::Invalid(
            "selected generation has a different identity or genesis",
        ));
    }
    let head = view.head()?;
    let pin = record.published;
    if head.height < pin.height
        || head.work < pin.work
        || view.block(head.height)? != Some(head.id)
        || view.block(pin.height)? != Some(pin.id)
        || (head.height == pin.height && head != pin)
        || (head.height > pin.height && head.work == pin.work)
        || (head.height == 0) != head.work.is_zero()
    {
        return Err(Error::Invalid(
            "selected generation does not preserve its durable publication head",
        ));
    }
    if let Some(certificate) = &record.floor {
        let statement = &certificate.statement;
        if statement.network != binding.network
            || !confirmed_checkpoint(statement.checkpoint_height, statement.authorization_height)
            || view.block(statement.checkpoint_height)? != Some(statement.checkpoint_block)
        {
            return Err(Error::Invalid(
                "selected generation does not contain the accepted checkpoint",
            ));
        }
    }
    Ok(head)
}

fn descriptor(identity: &NativeIdentity) -> Result<Descriptor> {
    identity
        .descriptor()
        .map_err(|_| Error::Invalid("generation control identity unavailable"))
}

fn pack(binding: Binding, record: &Record) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(BASE + CERTIFICATE_BYTES + SEAL_BYTES);
    bytes.extend(MAGIC);
    for hash in [binding.network, binding.genesis, binding.verifier] {
        bytes.extend(hash);
    }
    bytes.extend(record.generation.number.to_le_bytes());
    bytes.extend(record.generation.id);
    bytes.extend(record.published.height.to_le_bytes());
    bytes.extend(record.published.id);
    bytes.extend(record.published.work.to_big_endian());
    if let Some(certificate) = record.floor.as_ref() {
        bytes.push(1);
        bytes.extend(
            certificate
                .encode()
                .map_err(|_| Error::Invalid("generation checkpoint cannot be encoded"))?,
        );
    } else {
        bytes.push(0);
    }
    Ok(bytes)
}
fn digest(bytes: &[u8]) -> Hash {
    blake3::derive_key("siworld generation control v1", bytes)
}
fn seal(identity: &NativeIdentity, binding: Binding, record: &Record) -> Result<Vec<u8>> {
    let mut bytes = pack(binding, record)?;
    let signature = identity
        .seal_local_storage(digest(&bytes))
        .map_err(|_| Error::Storage("generation control signing failed"))?;
    bytes.extend(signature);
    Ok(bytes)
}
fn unseal(descriptor: &Descriptor, bytes: &[u8]) -> Result<Record> {
    if bytes.len() != BASE + SEAL_BYTES && bytes.len() != BASE + CERTIFICATE_BYTES + SEAL_BYTES {
        return Err(Error::Invalid(
            "generation control encoding length rejected",
        ));
    }
    let (data, signature) = bytes.split_at(bytes.len() - SEAL_BYTES);
    descriptor
        .verify_local_storage(digest(data), signature)
        .map_err(|_| Error::Invalid("generation control seal rejected"))?;
    let binding = descriptor.binding();
    if data[..8] != *MAGIC
        || data[8..40] != binding.network
        || data[40..72] != binding.genesis
        || data[72..104] != binding.verifier
    {
        return Err(Error::Invalid("generation control context differs"));
    }
    let generation = Generation {
        number: u64::from_le_bytes(data[104..112].try_into().expect("fixed generation number")),
        id: data[112..144]
            .try_into()
            .expect("fixed generation identity"),
    };
    let published = Head {
        height: u64::from_le_bytes(data[144..152].try_into().expect("fixed head height")),
        id: data[152..184].try_into().expect("fixed head identity"),
        work: Work::from_big_endian(&data[184..248]),
    };
    if (generation.number == 0) != (generation.id == [0; 32]) {
        return Err(Error::Invalid("generation control identifier is invalid"));
    }
    let floor = match (data[248], data.len()) {
        (0, BASE) => None,
        (1, len) if len == BASE + CERTIFICATE_BYTES => Some(
            Certificate::decode(&data[BASE..], binding.network)
                .map_err(|_| Error::Invalid("generation control checkpoint rejected"))?,
        ),
        _ => {
            return Err(Error::Invalid(
                "generation control checkpoint framing rejected",
            ));
        }
    };
    Ok(Record {
        generation,
        published,
        floor,
    })
}

fn immediate(transaction: &mut redb::WriteTransaction) -> Result<()> {
    transaction
        .set_durability(Durability::Immediate)
        .map_err(|_| Error::Storage("generation control immediate durability unavailable"))?;
    transaction.set_quick_repair(true);
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileId(u64, u64);

fn owner_file_id(metadata: &Metadata) -> Result<FileId> {
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(Error::Invalid(
            "generation file is not private regular owner data",
        ));
    }
    Ok(FileId(metadata.dev(), metadata.ino()))
}

fn path_file_id(path: &Path) -> Result<FileId> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| Error::Storage("generation file path unavailable"))?;
    owner_file_id(&metadata)
}

fn check_control_path(directory: &Path, file_id: FileId) -> Result<()> {
    if path_file_id(&directory.join(CONTROL_FILE))? != file_id {
        return Err(Error::Invalid("generation control file identity changed"));
    }
    Ok(())
}

fn check_chain_path(view: &impl ChainView, path: &Path) -> Result<()> {
    path_file_id(path)?;
    if !view.matches_path(path)? {
        return Err(Error::Invalid(
            "open generation does not match its selected file",
        ));
    }
    Ok(())
}

fn checked_file(path: &Path, create: bool) -> Result<(File, FileId)> {
    use rustix::fs::OFlags;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(create)
        .mode(0o600)
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
        .open(path)
        .map_err(|_| Error::Storage("generation file unavailable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| Error::Storage("generation file metadata unavailable"))?;
    let id = owner_file_id(&metadata)?;
    if path_file_id(path)? != id {
        return Err(Error::Invalid(
            "generation file identity changed while opening",
        ));
    }
    Ok((file, id))
}

fn control_database(directory: &Path, create: bool) -> Result<(Database, FileId)> {
    {
        let directory_metadata = std::fs::symlink_metadata(directory)
            .map_err(|_| Error::Storage("generation directory unavailable"))?;
        if !directory_metadata.is_dir()
            || directory_metadata.mode() & 0o077 != 0
            || directory_metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(Error::Invalid(
                "generation directory is not private owner data",
            ));
        }
    }
    let (file, file_id) = checked_file(&directory.join(CONTROL_FILE), create)?;
    let bytes = file
        .metadata()
        .map_err(|_| Error::Storage("generation control length unavailable"))?
        .len();
    if (!create && bytes == 0) || bytes > MAX_CONTROL_FILE_BYTES {
        return Err(Error::Invalid(
            "generation control database length rejected",
        ));
    }
    let backend = redb::backends::FileBackend::new(file)
        .map_err(|_| Error::Storage("generation control backend unavailable"))?;
    let mut builder = Database::builder();
    builder
        .set_cache_size(1024 * 1024)
        .set_repair_callback(|session| session.abort());
    let database = builder
        .create_with_backend(backend)
        .map_err(|_| Error::Storage("generation control database unavailable"))?;
    Ok((database, file_id))
}

fn sync_candidate(path: &Path, view: &impl ChainView) -> Result<()> {
    let (file, id) = checked_file(path, false)?;
    if file
        .metadata()
        .map_err(|_| Error::Storage("generation file length unavailable"))?
        .len()
        == 0
    {
        return Err(Error::Invalid("generation file is empty"));
    }
    check_chain_path(view, path)?;
    file.sync_all()
        .map_err(|_| Error::Storage("generation file durability unavailable"))?;
    crate::store::sync_parent(path)
        .map_err(|_| Error::Storage("generation directory durability unavailable"))?;
    if path_file_id(path)? != id {
        return Err(Error::Invalid(
            "generation file identity changed while syncing",
        ));
    }
    check_chain_path(view, path)
}

#[cfg(test)]
mod tests;
