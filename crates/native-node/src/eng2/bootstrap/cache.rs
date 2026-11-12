//! Unadmitted durable bootstrap quarantine. No canonical Store or identity is
//! created here; reopening checks every retained chunk before resuming.
use super::{Chunk, Descriptor, MAX_CHUNK_BYTES, Manifest, Object};
use crate::{
    eng2::{header::Header, import::Source},
    p2p,
};
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use std::path::Path;

const FILE: &str = "bootstrap-quarantine.redb";
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("bootstrap-meta-v1");
const HEADERS: TableDefinition<u64, &[u8]> = TableDefinition::new("bootstrap-headers-v1");
const OBJECTS: TableDefinition<u64, &[u8]> = TableDefinition::new("bootstrap-objects-v1");
const PARTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("bootstrap-chunks-v1");

#[derive(Clone, Copy)]
pub struct Policy {
    pub max_bytes: u64,
    pub max_chunks_per_object: u32,
    pub max_body_bytes: usize,
}
impl Policy {
    fn check(self) -> Result<(), String> {
        if self.max_bytes == 0
            || self.max_chunks_per_object == 0
            || self.max_chunks_per_object > 1_048_576
            || self.max_body_bytes == 0
        {
            return Err("bootstrap quarantine policy rejected".into());
        }
        Ok(())
    }
    fn encode(self) -> [u8; 20] {
        let mut bytes = [0; 20];
        bytes[..8].copy_from_slice(&self.max_bytes.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.max_chunks_per_object.to_le_bytes());
        bytes[12..].copy_from_slice(&(self.max_body_bytes as u64).to_le_bytes());
        bytes
    }
    fn check_manifest(self, manifest: &Manifest) -> Result<(), String> {
        self.check()?;
        let minimum = manifest
            .tip_height
            .checked_mul(crate::eng2::header::HEADER_BYTES as u64)
            .and_then(|bytes| bytes.checked_add(manifest.snapshot.length))
            .ok_or("bootstrap minimum payload byte overflow")?;
        if manifest.tip_height == 0 || manifest.snapshot.length == 0 || minimum > self.max_bytes {
            return Err("bootstrap headers and snapshot exceed logical payload budget".into());
        }
        Ok(())
    }
}
#[derive(Clone, Copy)]
struct Progress {
    descriptor: Descriptor,
    received: u64,
    chunks: u32,
}
impl Progress {
    fn encode(self) -> [u8; 52] {
        let mut bytes = [0; 52];
        bytes[..8].copy_from_slice(&self.descriptor.length.to_le_bytes());
        bytes[8..40].copy_from_slice(&self.descriptor.digest);
        bytes[40..48].copy_from_slice(&self.received.to_le_bytes());
        bytes[48..].copy_from_slice(&self.chunks.to_le_bytes());
        bytes
    }
    fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 52 {
            return Err("bootstrap quarantine progress length rejected".into());
        }
        Ok(Self {
            descriptor: Descriptor {
                length: number(&bytes[..8])?,
                digest: bytes[8..40].try_into().expect("fixed hash"),
            },
            received: number(&bytes[40..48])?,
            chunks: u32::from_le_bytes(bytes[48..].try_into().expect("fixed count")),
        })
    }
}
pub struct Quarantine {
    database: Database,
    manifest: Manifest,
    policy: Policy,
    budget: p2p::Budget,
    local_reread_bytes: u64,
    _cache_reservation: p2p::Reservation,
}
pub struct Blob {
    pub bytes: Vec<u8>,
    pub reservation: p2p::Reservation,
}
pub struct HeaderHistory {
    pub headers: Vec<Header>,
    pub reservation: p2p::Reservation,
}
impl Quarantine {
    /// The owner explicitly supplies a new, dedicated private directory.
    /// Existing directories and database files are preserved.
    pub fn create(
        directory: &Path,
        manifest: Manifest,
        policy: Policy,
        budget: p2p::Budget,
    ) -> Result<Self, String> {
        policy.check_manifest(&manifest)?;
        let encoded_manifest = manifest.encode()?;
        let cache_reservation = budget
            .reserve(16 * 1024 * 1024)
            .map_err(|_| "bootstrap quarantine cache memory unavailable")?;
        create_directory(directory)?;
        let database = open_database(directory, true)?;
        let mut transaction = database
            .begin_write()
            .map_err(|_| "bootstrap quarantine initialization unavailable")?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|_| "bootstrap quarantine durability unavailable")?;
        transaction
            .open_table(META)
            .map_err(|_| "bootstrap quarantine metadata unavailable")?
            .insert("manifest", encoded_manifest.as_slice())
            .map_err(|_| "bootstrap manifest write failed")?;
        transaction
            .open_table(META)
            .map_err(|_| "bootstrap quarantine metadata unavailable")?
            .insert("policy", policy.encode().as_slice())
            .map_err(|_| "bootstrap policy write failed")?;
        transaction
            .open_table(HEADERS)
            .map_err(|_| "bootstrap header table unavailable")?;
        transaction
            .open_table(OBJECTS)
            .map_err(|_| "bootstrap object table unavailable")?;
        transaction
            .open_table(PARTS)
            .map_err(|_| "bootstrap chunk table unavailable")?;
        transaction
            .commit()
            .map_err(|_| "bootstrap quarantine initialization failed")?;
        crate::store::sync_parent(&directory.join(FILE))?;
        Ok(Self {
            database,
            manifest,
            policy,
            budget,
            local_reread_bytes: 0,
            _cache_reservation: cache_reservation,
        })
    }
    /// Read the retained manifest without creating a missing quarantine. Resume
    /// callers must request this exact bundle and still run full reopen checks.
    pub fn retained_manifest(directory: &Path) -> Result<Option<Vec<u8>>, String> {
        match std::fs::symlink_metadata(directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("Bootstrap quarantine metadata unavailable; preserve data".into()),
            Ok(_) => (),
        }
        let database = open_database(directory, false)?;
        let transaction = database
            .begin_read()
            .map_err(|_| "Bootstrap retained manifest read failed")?;
        let meta = transaction
            .open_table(META)
            .map_err(|_| "Bootstrap retained manifest table missing")?;
        let row = meta
            .get("manifest")
            .map_err(|_| "Bootstrap retained manifest unavailable")?
            .ok_or("Bootstrap retained manifest missing")?;
        if row.value().len() > super::MAX_MANIFEST_BYTES {
            return Err("Bootstrap retained manifest bound exceeded".into());
        }
        Ok(Some(row.value().to_vec()))
    }
    pub fn reopen(
        directory: &Path,
        manifest: Manifest,
        policy: Policy,
        budget: p2p::Budget,
    ) -> Result<Self, String> {
        policy.check_manifest(&manifest)?;
        let encoded_manifest = manifest.encode()?;
        let cache_reservation = budget
            .reserve(16 * 1024 * 1024)
            .map_err(|_| "bootstrap quarantine cache memory unavailable")?;
        let database = open_database(directory, false)?;
        {
            let transaction = database
                .begin_read()
                .map_err(|_| "bootstrap quarantine reopen unavailable")?;
            let meta = transaction
                .open_table(META)
                .map_err(|_| "bootstrap quarantine binding missing")?;
            if meta
                .get("manifest")
                .map_err(|_| "bootstrap manifest unreadable")?
                .ok_or("bootstrap manifest missing")?
                .value()
                != encoded_manifest
                || meta
                    .get("policy")
                    .map_err(|_| "bootstrap policy unreadable")?
                    .ok_or("bootstrap policy missing")?
                    .value()
                    != policy.encode()
            {
                return Err("bootstrap resume requires identical manifest and policy".into());
            }
        }
        let mut value = Self {
            database,
            manifest,
            policy,
            budget,
            local_reread_bytes: 0,
            _cache_reservation: cache_reservation,
        };
        value.recheck()?;
        Ok(value)
    }
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn local_reread_bytes(&self) -> u64 {
        self.local_reread_bytes
    }
    /// Recover the next acquisition position without treating cached headers as
    /// verified work or an admitted head. This scan runs once on client reopen.
    pub(super) fn next_header(&self) -> Result<u64, String> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| "bootstrap header progress unavailable")?;
        let table = transaction
            .open_table(HEADERS)
            .map_err(|_| "bootstrap header table unavailable")?;
        let mut next = 1u64;
        for row in table
            .iter()
            .map_err(|_| "bootstrap header progress unreadable")?
        {
            let (height, bytes) = row.map_err(|_| "bootstrap cached header unreadable")?;
            if height.value() != next || next > self.manifest.tip_height {
                return Err("bootstrap cached header range is not contiguous".into());
            }
            let header = Header::decode(bytes.value(), &self.manifest.network)
                .map_err(|_| "bootstrap cached header malformed")?;
            if header.height != next {
                return Err("bootstrap cached header index differs".into());
            }
            next += 1;
        }
        Ok(next)
    }
    pub(super) fn progress_at(&self, height: u64) -> Result<Option<(u64, u64)>, String> {
        if height > self.manifest.tip_height {
            return Err("bootstrap progress height exceeds selected history".into());
        }
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| "bootstrap progress unavailable")?;
        let table = transaction
            .open_table(OBJECTS)
            .map_err(|_| "bootstrap progress table unavailable")?;
        table
            .get(height)
            .map_err(|_| "bootstrap progress unreadable")?
            .map(|row| {
                let progress = Progress::decode(row.value())?;
                Ok((progress.received, progress.descriptor.length))
            })
            .transpose()
    }
    pub fn put_header(&self, header: &Header) -> Result<(), String> {
        if header.network != self.manifest.network
            || header.height == 0
            || header.height > self.manifest.tip_height
        {
            return Err("bootstrap header is outside quarantine history".into());
        }
        let encoded = header
            .encode()
            .map_err(|_| "bootstrap header encoding invalid")?;
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|_| "bootstrap header write unavailable")?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|_| "bootstrap header durability unavailable")?;
        {
            let mut table = transaction
                .open_table(HEADERS)
                .map_err(|_| "bootstrap header table unavailable")?;
            if let Some(existing) = table
                .get(header.height)
                .map_err(|_| "bootstrap header read failed")?
            {
                if existing.value() != encoded {
                    return Err("bootstrap conflicting header preserved".into());
                }
                return Ok(());
            }
            table
                .insert(header.height, encoded.as_slice())
                .map_err(|_| "bootstrap header write failed")?;
        }
        transaction
            .commit()
            .map_err(|_| "bootstrap header commit failed".into())
    }
    pub fn headers(&self) -> Result<HeaderHistory, String> {
        let charge = usize::try_from(self.manifest.tip_height)
            .ok()
            .and_then(|count| count.checked_mul(std::mem::size_of::<Header>()))
            .and_then(|bytes| bytes.checked_mul(8))
            .ok_or("bootstrap header memory overflow")?;
        let reservation = self
            .budget
            .reserve(charge)
            .map_err(|_| "bootstrap header memory unavailable")?;
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| "bootstrap header read unavailable")?;
        let table = transaction
            .open_table(HEADERS)
            .map_err(|_| "bootstrap header table unavailable")?;
        let mut headers = Vec::new();
        for height in 1..=self.manifest.tip_height {
            let row = table
                .get(height)
                .map_err(|_| "bootstrap header read failed")?
                .ok_or("bootstrap complete header history not acquired")?;
            headers.push(
                Header::decode(row.value(), &self.manifest.network)
                    .map_err(|_| "bootstrap cached header malformed")?,
            );
        }
        Ok(HeaderHistory {
            headers,
            reservation,
        })
    }
    fn target(&self, object: Object) -> Result<u64, String> {
        match object {
            Object::Snapshot => Ok(0),
            Object::Receipt { height, id }
                if height > 0 && height <= self.manifest.checkpoint_height() =>
            {
                let transaction = self
                    .database
                    .begin_read()
                    .map_err(|_| "bootstrap receipt header read unavailable")?;
                let table = transaction
                    .open_table(HEADERS)
                    .map_err(|_| "bootstrap receipt header table unavailable")?;
                let row = table
                    .get(height)
                    .map_err(|_| "bootstrap receipt header read failed")?
                    .ok_or("bootstrap receipt requires selected header")?;
                let header = Header::decode(row.value(), &self.manifest.network)
                    .map_err(|_| "bootstrap receipt header malformed")?;
                if header
                    .id()
                    .map_err(|_| "bootstrap receipt header malformed")?
                    != id
                {
                    return Err("bootstrap receipt differs from acquired header".into());
                }
                Ok(height)
            }
            _ => Err("bootstrap object is outside manifest availability".into()),
        }
    }
    pub fn progress(&self, object: Object) -> Result<u64, String> {
        let target = self.target(object)?;
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| "bootstrap progress unavailable")?;
        let table = transaction
            .open_table(OBJECTS)
            .map_err(|_| "bootstrap progress table unavailable")?;
        table
            .get(target)
            .map_err(|_| "bootstrap progress read failed")?
            .map(|row| Progress::decode(row.value()).map(|p| p.received))
            .transpose()
            .map(|p| p.unwrap_or(0))
    }
    pub fn push(&mut self, object: Object, offset: u64, chunk: &Chunk) -> Result<(), String> {
        let target = self.target(object)?;
        if target == 0 && chunk.descriptor != self.manifest.snapshot {
            return Err("bootstrap snapshot descriptor differs".into());
        }
        let maximum = if target == 0 {
            self.manifest.snapshot.length
        } else {
            crate::eng2::wallet_history::codec::MAX_RECEIPT_BYTES as u64
        };
        self.push_target(target, offset, chunk, maximum)
    }
    fn push_target(
        &mut self,
        target: u64,
        offset: u64,
        chunk: &Chunk,
        maximum: u64,
    ) -> Result<(), String> {
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|_| "bootstrap chunk transaction unavailable")?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|_| "bootstrap chunk durability unavailable")?;
        let prior = {
            let table = transaction
                .open_table(OBJECTS)
                .map_err(|_| "bootstrap progress unavailable")?;
            table
                .get(target)
                .map_err(|_| "bootstrap progress unreadable")?
                .map(|row| Progress::decode(row.value()))
                .transpose()?
        };
        let prior = prior.unwrap_or(Progress {
            descriptor: chunk.descriptor,
            received: 0,
            chunks: 0,
        });
        let next = offset
            .checked_add(chunk.bytes.len() as u64)
            .ok_or("bootstrap chunk offset overflow")?;
        if chunk.descriptor.length == 0
            || chunk.descriptor.length > maximum
            || prior.descriptor != chunk.descriptor
            || prior.received != offset
            || chunk.bytes.is_empty()
            || chunk.bytes.len() > MAX_CHUNK_BYTES
            || next > chunk.descriptor.length
            || prior.chunks >= self.policy.max_chunks_per_object
        {
            return Err("bootstrap chunk descriptor, order or resource bound rejected".into());
        }
        let objects = transaction
            .open_table(OBJECTS)
            .map_err(|_| "bootstrap object accounting unavailable")?;
        let mut reserved = self
            .manifest
            .tip_height
            .checked_mul(crate::eng2::header::HEADER_BYTES as u64)
            .ok_or("bootstrap complete header byte bound overflow")?;
        for row in objects
            .iter()
            .map_err(|_| "bootstrap object accounting unreadable")?
        {
            let (key, value) = row.map_err(|_| "bootstrap object accounting malformed")?;
            if key.value() != target {
                reserved = reserved
                    .checked_add(Progress::decode(value.value())?.descriptor.length)
                    .ok_or("bootstrap total byte overflow")?;
            }
        }
        drop(objects);
        if reserved
            .checked_add(chunk.descriptor.length)
            .is_none_or(|total| total > self.policy.max_bytes)
        {
            return Err("bootstrap operation byte budget exceeded".into());
        }
        if next == chunk.descriptor.length {
            let read = self
                .database
                .begin_read()
                .map_err(|_| "bootstrap final object scan unavailable")?;
            let mut hash = scan(&read, target, prior, self.policy, None)?;
            hash.update(&chunk.bytes);
            if hash.finalize().as_bytes() != &chunk.descriptor.digest {
                return Err("bootstrap completed object digest differs".into());
            }
        }
        let _scratch = self
            .budget
            .reserve(chunk.bytes.len() + 32)
            .map_err(|_| "bootstrap chunk write memory unavailable")?;
        let mut part = Vec::with_capacity(32 + chunk.bytes.len());
        part.extend_from_slice(blake3::hash(&chunk.bytes).as_bytes());
        part.extend_from_slice(&chunk.bytes);
        transaction
            .open_table(PARTS)
            .map_err(|_| "bootstrap chunk table unavailable")?
            .insert(key(target, offset).as_slice(), part.as_slice())
            .map_err(|_| "bootstrap chunk write failed")?;
        transaction
            .open_table(OBJECTS)
            .map_err(|_| "bootstrap object table unavailable")?
            .insert(
                target,
                Progress {
                    descriptor: chunk.descriptor,
                    received: next,
                    chunks: prior.chunks + 1,
                }
                .encode()
                .as_slice(),
            )
            .map_err(|_| "bootstrap progress write failed")?;
        transaction
            .commit()
            .map_err(|_| "bootstrap durable chunk commit failed".into())
    }
    /// Full bodies have already been reconstructed by the ordinary transport;
    /// their native validity is still checked only by the signed importer.
    pub fn put_body(&mut self, header: &Header, bytes: &[u8]) -> Result<(), String> {
        if header.height <= self.manifest.checkpoint_height()
            || header.height > self.manifest.tip_height
            || bytes.is_empty()
            || bytes.len() > self.policy.max_body_bytes
        {
            return Err("bootstrap tail body bound rejected".into());
        }
        self.put_header(header)?;
        let descriptor = Descriptor {
            length: bytes.len() as u64,
            digest: *blake3::hash(bytes).as_bytes(),
        };
        let received = {
            let transaction = self
                .database
                .begin_read()
                .map_err(|_| "bootstrap body progress unavailable")?;
            let table = transaction
                .open_table(OBJECTS)
                .map_err(|_| "bootstrap body progress table unavailable")?;
            let progress = table
                .get(header.height)
                .map_err(|_| "bootstrap body progress read failed")?
                .map(|row| Progress::decode(row.value()))
                .transpose()?;
            match progress {
                Some(progress) if progress.descriptor == descriptor => progress.received,
                Some(_) => return Err("bootstrap conflicting body preserved".into()),
                None => 0,
            }
        };
        let mut offset = 0;
        for part in bytes.chunks(MAX_CHUNK_BYTES) {
            if offset >= received {
                let _chunk_charge = self
                    .budget
                    .reserve(part.len())
                    .map_err(|_| "bootstrap body chunk memory unavailable")?;
                self.push_target(
                    header.height,
                    offset,
                    &Chunk {
                        descriptor,
                        bytes: part.to_vec(),
                    },
                    self.policy.max_body_bytes as u64,
                )?;
            }
            offset += part.len() as u64;
        }
        Ok(())
    }
    pub fn snapshot(&mut self) -> Result<Blob, String> {
        self.read_target(0, self.manifest.snapshot.length as usize, true)
    }
    fn read_target(
        &mut self,
        target: u64,
        maximum: usize,
        charge_read: bool,
    ) -> Result<Blob, String> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| "bootstrap object read unavailable")?;
        let table = transaction
            .open_table(OBJECTS)
            .map_err(|_| "bootstrap object table unavailable")?;
        let progress = Progress::decode(
            table
                .get(target)
                .map_err(|_| "bootstrap object read failed")?
                .ok_or("bootstrap object not acquired")?
                .value(),
        )?;
        let length = usize::try_from(progress.descriptor.length)
            .map_err(|_| "bootstrap object length overflow")?;
        if progress.received != progress.descriptor.length || length > maximum {
            return Err("bootstrap object incomplete or exceeds read cap".into());
        }
        let charge = length
            .checked_mul(3)
            .and_then(|n| n.checked_add(65536))
            .ok_or("bootstrap object memory overflow")?;
        let reservation = self
            .budget
            .reserve(if charge_read { charge } else { 0 })
            .map_err(|_| "bootstrap object memory unavailable")?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| "bootstrap object allocation unavailable")?;
        scan(
            &transaction,
            target,
            progress,
            self.policy,
            Some(&mut bytes),
        )?;
        if *blake3::hash(&bytes).as_bytes() != progress.descriptor.digest {
            return Err("bootstrap completed object digest differs".into());
        }
        self.local_reread_bytes = self
            .local_reread_bytes
            .checked_add(length as u64)
            .ok_or("bootstrap local reread count overflow")?;
        Ok(Blob { bytes, reservation })
    }
    fn recheck(&mut self) -> Result<(), String> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| "bootstrap resume read unavailable")?;
        let objects = transaction
            .open_table(OBJECTS)
            .map_err(|_| "bootstrap resume objects missing")?;
        let mut reserved = self
            .manifest
            .tip_height
            .checked_mul(crate::eng2::header::HEADER_BYTES as u64)
            .ok_or("bootstrap complete header byte bound overflow")?;
        for row in objects
            .iter()
            .map_err(|_| "bootstrap resume iteration failed")?
        {
            let (target, row) = row.map_err(|_| "bootstrap resume row malformed")?;
            let target = target.value();
            let progress = Progress::decode(row.value())?;
            if target > self.manifest.tip_height
                || (target == 0 && progress.descriptor != self.manifest.snapshot)
                || progress.descriptor.length == 0
                || progress.received > progress.descriptor.length
                || progress.chunks > self.policy.max_chunks_per_object
            {
                return Err("bootstrap resume descriptor rejected".into());
            }
            reserved = reserved
                .checked_add(progress.descriptor.length)
                .ok_or("bootstrap resume byte overflow")?;
            if reserved > self.policy.max_bytes {
                return Err("bootstrap resume exceeds operation budget".into());
            }
            scan(&transaction, target, progress, self.policy, None)?;
        }
        Ok(())
    }
    /// The guard owns a maximum-sized read charge throughout importer Source
    /// use, including installation rereads. It is separate from network bytes.
    pub fn source(&mut self) -> Result<CacheSource<'_>, String> {
        let largest = {
            let transaction = self
                .database
                .begin_read()
                .map_err(|_| "bootstrap source metadata unavailable")?;
            let table = transaction
                .open_table(OBJECTS)
                .map_err(|_| "bootstrap source objects unavailable")?;
            let mut largest = 0usize;
            for height in 1..=self.manifest.tip_height {
                let row = table
                    .get(height)
                    .map_err(|_| "bootstrap source object read failed")?
                    .ok_or("bootstrap source history is incomplete")?;
                let progress = Progress::decode(row.value())?;
                let maximum = if height <= self.manifest.checkpoint_height() {
                    crate::eng2::wallet_history::codec::MAX_RECEIPT_BYTES
                } else {
                    self.policy.max_body_bytes
                };
                let length = usize::try_from(progress.descriptor.length)
                    .map_err(|_| "bootstrap source object length overflow")?;
                if length == 0
                    || length > maximum
                    || progress.received != progress.descriptor.length
                {
                    return Err("bootstrap source object incomplete or exceeds bound".into());
                }
                largest = largest.max(length);
            }
            largest
        };
        let charge = largest
            .checked_mul(3)
            .and_then(|n| n.checked_add(65536))
            .ok_or("bootstrap source memory overflow")?;
        let reservation = self
            .budget
            .reserve(charge)
            .map_err(|_| "bootstrap source memory unavailable")?;
        Ok(CacheSource {
            cache: self,
            _reservation: reservation,
        })
    }
}
pub struct CacheSource<'a> {
    cache: &'a mut Quarantine,
    _reservation: p2p::Reservation,
}
impl Source for CacheSource<'_> {
    fn receipt(&mut self, height: u64, maximum: usize) -> Result<Vec<u8>, String> {
        if height == 0 || height > self.cache.manifest.checkpoint_height() {
            return Err("bootstrap receipt source range rejected".into());
        }
        Ok(self.cache.read_target(height, maximum, false)?.bytes)
    }
    fn body(&mut self, height: u64, maximum: usize) -> Result<Vec<u8>, String> {
        if height <= self.cache.manifest.checkpoint_height()
            || height > self.cache.manifest.tip_height
        {
            return Err("bootstrap body source range rejected".into());
        }
        Ok(self.cache.read_target(height, maximum, false)?.bytes)
    }
}
fn key(target: u64, offset: u64) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&target.to_be_bytes());
    bytes[8..].copy_from_slice(&offset.to_be_bytes());
    bytes
}
fn number(bytes: &[u8]) -> Result<u64, String> {
    Ok(u64::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| "bootstrap number width rejected")?,
    ))
}
fn scan(
    transaction: &redb::ReadTransaction,
    target: u64,
    progress: Progress,
    policy: Policy,
    mut output: Option<&mut Vec<u8>>,
) -> Result<blake3::Hasher, String> {
    let table = transaction
        .open_table(PARTS)
        .map_err(|_| "bootstrap retained chunks missing")?;
    let mut offset = 0u64;
    let mut count = 0u32;
    let mut hash = blake3::Hasher::new();
    for row in table
        .range(key(target, 0).as_slice()..=key(target, u64::MAX).as_slice())
        .map_err(|_| "bootstrap chunk scan failed")?
    {
        let (found, row) = row.map_err(|_| "bootstrap retained chunk unreadable")?;
        let bytes = row.value();
        if found.value() != key(target, offset)
            || bytes.len() <= 32
            || bytes.len() > MAX_CHUNK_BYTES + 32
            || count >= policy.max_chunks_per_object
            || blake3::hash(&bytes[32..]).as_bytes().as_slice() != &bytes[..32]
        {
            return Err("bootstrap retained chunk order, hash or bound differs".into());
        }
        offset = offset
            .checked_add((bytes.len() - 32) as u64)
            .ok_or("bootstrap chunk total overflow")?;
        if offset > progress.received {
            return Err("bootstrap chunks exceed committed progress".into());
        }
        count += 1;
        hash.update(&bytes[32..]);
        if let Some(out) = &mut output {
            out.extend_from_slice(&bytes[32..]);
        }
    }
    if offset != progress.received
        || count != progress.chunks
        || (offset == progress.descriptor.length
            && hash.finalize().as_bytes() != &progress.descriptor.digest)
    {
        return Err("bootstrap retained chunks differ from progress or object digest".into());
    }
    Ok(hash)
}
fn check_directory(path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    siworld_miner_platform::Directory::open(path)?.check()?;
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| "bootstrap quarantine directory unavailable")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("bootstrap quarantine requires a real directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("bootstrap quarantine requires owner-only directory".into());
        }
    }
    Ok(())
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
            .map_err(|_| "bootstrap quarantine requires a new directory")?;
    }
    check_directory(path)
}
fn open_database(directory: &Path, create: bool) -> Result<Database, String> {
    check_directory(directory)?;
    let (file, created) = crate::store::open_regular_file(&directory.join(FILE), create)?;
    if created != create {
        return Err("bootstrap quarantine file creation mode differs".into());
    }
    let backend = redb::backends::FileBackend::new(file)
        .map_err(|_| "bootstrap quarantine backend unavailable")?;
    let mut builder = Database::builder();
    builder.set_cache_size(16 * 1024 * 1024);
    builder.set_repair_callback(|session| session.abort());
    builder
        .create_with_backend(backend)
        .map_err(|_| "bootstrap quarantine damaged or unavailable".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            Self(std::env::temp_dir().join(format!(
                "bootstrap-quarantine-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )))
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            if self.0.exists() {
                std::fs::remove_dir_all(&self.0).unwrap();
            }
        }
    }
    fn policy() -> Policy {
        Policy {
            max_bytes: 1024 * 1024,
            max_chunks_per_object: 8,
            max_body_bytes: 1024,
        }
    }
    #[test]
    fn explicit_resume_preserves_existing_manifest_and_leaves_missing_provider_uncreated() {
        let (_, _, manifest) = crate::eng2::bootstrap::tests::framing_fixture();
        let first = Directory::new();
        let second = Directory::new();
        let budget = p2p::Budget::new(64 * 1024 * 1024);
        assert!(Quarantine::retained_manifest(&first.0).unwrap().is_none());
        assert!(!first.0.exists());
        drop(Quarantine::create(&first.0, manifest.clone(), policy(), budget.clone()).unwrap());
        assert_eq!(
            Quarantine::retained_manifest(&first.0).unwrap().unwrap(),
            manifest.encode().unwrap()
        );
        assert!(Quarantine::retained_manifest(&second.0).unwrap().is_none());
        assert!(!second.0.exists());
        drop(Quarantine::reopen(&first.0, manifest.clone(), policy(), budget.clone()).unwrap());
        drop(Quarantine::create(&second.0, manifest.clone(), policy(), budget).unwrap());
        assert_eq!(
            Quarantine::retained_manifest(&first.0).unwrap(),
            Quarantine::retained_manifest(&second.0).unwrap()
        );
    }
    #[test]
    fn minimum_payload_and_malformed_bounds_reject_before_filesystem_mutation() {
        let (_, _, manifest) = crate::eng2::bootstrap::tests::framing_fixture();
        let minimum = manifest.tip_height * crate::eng2::header::HEADER_BYTES as u64
            + manifest.snapshot.length;
        let budget = p2p::Budget::new(32 * 1024 * 1024);
        let directory = Directory::new();
        let mut exact = policy();
        exact.max_bytes = minimum;
        let mut small = exact;
        small.max_bytes -= 1;
        assert!(Quarantine::create(&directory.0, manifest.clone(), small, budget.clone()).is_err());
        assert!(!directory.0.exists());
        drop(Quarantine::create(&directory.0, manifest.clone(), exact, budget.clone()).unwrap());
        assert!(Quarantine::reopen(&directory.0, manifest.clone(), small, budget.clone()).is_err());
        drop(Quarantine::reopen(&directory.0, manifest.clone(), exact, budget.clone()).unwrap());

        for (height, length) in [(u64::MAX, 1), (1, u64::MAX), (0, 7), (96, 0)] {
            let absent = Directory::new();
            let mut malformed = manifest.clone();
            malformed.tip_height = height;
            malformed.snapshot.length = length;
            assert!(
                Quarantine::create(&absent.0, malformed.clone(), policy(), budget.clone()).is_err()
            );
            assert!(!absent.0.exists());
            assert!(Quarantine::reopen(&directory.0, malformed, policy(), budget.clone()).is_err());
        }
        // Binding validation must also precede directory creation, even when
        // the arithmetic lower bound is plausible and fits the payload cap.
        let absent = Directory::new();
        let mut changed = manifest.clone();
        changed.tip_id[0] ^= 1;
        assert!(Quarantine::create(&absent.0, changed, policy(), budget.clone()).is_err());
        assert!(!absent.0.exists());
        drop(Quarantine::reopen(&directory.0, manifest, exact, budget).unwrap());
    }
    #[test]
    fn durable_partial_resume_rejects_wrong_order_and_changed_bundle_without_any_admission() {
        let (_, _, manifest) = crate::eng2::bootstrap::tests::framing_fixture();
        let directory = Directory::new();
        let budget = p2p::Budget::new(32 * 1024 * 1024);
        let mut cache =
            Quarantine::create(&directory.0, manifest.clone(), policy(), budget.clone()).unwrap();
        let part = |bytes: &[u8]| Chunk {
            descriptor: manifest.snapshot,
            bytes: bytes.to_vec(),
        };
        cache.push(Object::Snapshot, 0, &part(b"fix")).unwrap();
        assert!(cache.snapshot().is_err());
        assert!(cache.push(Object::Snapshot, 0, &part(b"ture")).is_err());
        assert_eq!(cache.progress(Object::Snapshot).unwrap(), 3);
        drop(cache);
        let mut cache =
            Quarantine::reopen(&directory.0, manifest.clone(), policy(), budget.clone()).unwrap();
        assert!(cache.push(Object::Snapshot, 3, &part(b"xxxx")).is_err());
        assert_eq!(cache.progress(Object::Snapshot).unwrap(), 3);
        cache.push(Object::Snapshot, 3, &part(b"ture")).unwrap();
        let blob = cache.snapshot().unwrap();
        assert_eq!(blob.bytes, b"fixture");
        drop(blob);
        assert_eq!(cache.local_reread_bytes(), 7);
        drop(cache);
        let mut changed_policy = policy();
        changed_policy.max_bytes -= 1;
        assert!(
            Quarantine::reopen(
                &directory.0,
                manifest.clone(),
                changed_policy,
                budget.clone()
            )
            .is_err()
        );
        let mut cache = Quarantine::reopen(&directory.0, manifest, policy(), budget).unwrap();
        assert_eq!(cache.snapshot().unwrap().bytes, b"fixture");
        assert!(!directory.0.join("chain.redb").exists());
        assert!(!directory.0.join("identity.bin").exists());
    }
    #[test]
    fn changed_retained_chunk_is_rejected_on_resume_and_preserved() {
        let (_, _, manifest) = crate::eng2::bootstrap::tests::framing_fixture();
        let directory = Directory::new();
        let budget = p2p::Budget::new(32 * 1024 * 1024);
        let mut cache =
            Quarantine::create(&directory.0, manifest.clone(), policy(), budget.clone()).unwrap();
        cache
            .push(
                Object::Snapshot,
                0,
                &Chunk {
                    descriptor: manifest.snapshot,
                    bytes: b"fix".to_vec(),
                },
            )
            .unwrap();
        let transaction = cache.database.begin_write().unwrap();
        transaction
            .open_table(PARTS)
            .unwrap()
            .insert(key(0, 0).as_slice(), b"changed retained bytes".as_slice())
            .unwrap();
        transaction.commit().unwrap();
        drop(cache);
        assert!(Quarantine::reopen(&directory.0, manifest, policy(), budget).is_err());
        assert!(directory.0.join(FILE).exists());
    }
    #[test]
    fn source_reserves_actual_complete_objects_instead_of_large_configured_body_ceiling() {
        let (_, _, manifest) = crate::eng2::bootstrap::tests::framing_fixture();
        let directory = Directory::new();
        let budget = p2p::Budget::new(32 * 1024 * 1024);
        let mut policy = policy();
        policy.max_body_bytes = 512 * 1024 * 1024;
        let mut cache = Quarantine::create(&directory.0, manifest.clone(), policy, budget).unwrap();
        // These rows qualify cache/source bounds only, not valid native history.
        for height in 1..=manifest.tip_height {
            let header = Header {
                network: manifest.network,
                height,
                parent: [1; 32],
                timestamp: height * 300,
                target: [255; 32],
                execution_commitment: [2; 32],
                body_commitment: [3; 32],
                nonce: 0,
            };
            cache.put_header(&header).unwrap();
            if height <= manifest.checkpoint_height() {
                cache
                    .push(
                        Object::Receipt {
                            height,
                            id: header.id().unwrap(),
                        },
                        0,
                        &Chunk {
                            descriptor: manifest.snapshot,
                            bytes: b"fixture".to_vec(),
                        },
                    )
                    .unwrap();
            } else {
                cache.put_body(&header, b"tail").unwrap();
            }
        }
        let mut source = cache.source().unwrap();
        assert_eq!(source.receipt(1, 7).unwrap(), b"fixture");
        assert_eq!(source.body(96, 4).unwrap(), b"tail");
        assert!(source.receipt(1, 6).is_err());
        assert!(source.body(72, 4).is_err());
        drop(source);
        assert_eq!(cache.local_reread_bytes(), 11);
    }
}
