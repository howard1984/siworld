//! Single-owner, opt-in public wallet publication. No new Store or worker.
use super::*;
use crate::{
    eng2::{
        wallet_generation::{self as wire, Binding, Chunk, Descriptor, Manifest, Record},
        wallet_history,
    },
    p2p,
};
use rustix::fs::{Dir, FlockOperation, flock};

pub const RETAINED_HEADS: usize = 4;
pub const RETAIN_SECONDS: u64 = 900;
const METADATA_RESERVE: u64 = 128 * 1024;
const MAX_ENTRIES: usize = 300_010;
const CATALOG_BYTES: usize = 4096;
const MAX_GENESIS: usize = 262144;

#[derive(Clone, Copy, Debug)]
pub struct WalletPolicy {
    pub max_artifact_bytes: u64,
}
impl Default for WalletPolicy {
    fn default() -> Self {
        Self {
            max_artifact_bytes: 32 * 1024 * 1024 * 1024,
        }
    }
}
impl WalletPolicy {
    fn check(self) -> Result<Self, String> {
        if !(METADATA_RESERVE..=1024 * 1024 * 1024 * 1024).contains(&self.max_artifact_bytes) {
            return Err("wallet artifact budget outside finite policy".into());
        }
        Ok(self)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletProgress {
    pub scanned_height: u64,
    pub target_height: u64,
    pub published_height: Option<u64>,
    pub published: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    height: u64,
    tip: Hash,
    digest: Hash,
    expires: u64,
}
#[derive(Clone, Debug, Default)]
struct Catalog {
    sequence: u64,
    entries: Vec<Entry>,
}
fn context_json(binding: &Binding) -> Value {
    json!({"network":crate::local::hex(&binding.0[..32]),"genesis":crate::local::hex(&binding.0[32..64]),"rules":crate::local::hex(&binding.0[64..96]),"profile":crate::local::hex(&binding.0[96..128]),"fee_mode":0})
}
impl Catalog {
    fn encode(&self, binding: &Binding) -> Result<Vec<u8>, String> {
        let mut value = context_json(binding);
        let object = value.as_object_mut().expect("fixed object");
        object.insert("version".into(), json!(1));
        object.insert("sequence".into(), json!(self.sequence));
        object.insert("entries".into(),json!(self.entries.iter().map(|row| json!({"height":row.height,"tip":crate::local::hex(&row.tip),"manifest_sha256":crate::local::hex(&row.digest),"expires_unix_seconds":row.expires})).collect::<Vec<_>>()));
        let bytes = serde_json::to_vec(&value).map_err(|_| "wallet catalog encoding failed")?;
        if bytes.len() > CATALOG_BYTES {
            return Err("wallet catalog exceeds bound".into());
        }
        Ok(bytes)
    }
    fn decode(binding: &Binding, bytes: &[u8]) -> Result<Self, String> {
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| "wallet catalog encoding rejected")?;
        let object = value.as_object().ok_or("wallet catalog object required")?;
        if object.len() != 8
            || value["version"].as_u64() != Some(1)
            || context_json(binding)
                .as_object()
                .expect("fixed context")
                .iter()
                .any(|(k, v)| value.get(k) != Some(v))
        {
            return Err("wallet catalog context or fields rejected".into());
        }
        let sequence = value["sequence"]
            .as_u64()
            .filter(|v| *v < (1 << 53))
            .ok_or("wallet catalog sequence rejected")?;
        let rows = value["entries"]
            .as_array()
            .filter(|rows| !rows.is_empty() && rows.len() <= RETAINED_HEADS)
            .ok_or("wallet catalog entry bound rejected")?;
        let mut entries = Vec::new();
        let mut active = 0;
        for row in rows {
            if row.as_object().is_none_or(|o| o.len() != 4) {
                return Err("wallet catalog entry fields rejected".into());
            }
            let height = row["height"]
                .as_u64()
                .filter(|v| *v <= wire::MAX_HEIGHT)
                .ok_or("wallet catalog height rejected")?;
            let tip = decode_hash(row["tip"].as_str().ok_or("wallet catalog tip absent")?)?;
            let digest = decode_hash(
                row["manifest_sha256"]
                    .as_str()
                    .ok_or("wallet catalog digest absent")?,
            )?;
            let expires = row["expires_unix_seconds"]
                .as_u64()
                .filter(|v| *v < (1 << 53))
                .ok_or("wallet catalog expiry rejected")?;
            if entries
                .iter()
                .any(|old: &Entry| (old.height, old.tip) == (height, tip))
            {
                return Err("duplicate wallet catalog head".into());
            }
            active += usize::from(expires == 0);
            entries.push(Entry {
                height,
                tip,
                digest,
                expires,
            });
        }
        if active != 1 {
            return Err("wallet catalog active generation count rejected".into());
        }
        Ok(Self { sequence, entries })
    }
    fn staged(
        &self,
        height: u64,
        tip: Hash,
        digest: Hash,
        now: u64,
        committed: Option<(u64, Hash)>,
    ) -> Result<Self, String> {
        let mut next = self.clone();
        next.entries
            .retain(|e| e.expires == 0 || now < e.expires || committed == Some((e.height, e.tip)));
        // An orphan active generation can exist after catalog/head interruption.
        // Preserve its complete immutable data as a bounded retained pin.
        for entry in &mut next.entries {
            if entry.expires == 0 || committed == Some((entry.height, entry.tip)) {
                entry.expires = now
                    .checked_add(RETAIN_SECONDS)
                    .filter(|v| *v < (1 << 53))
                    .ok_or("wallet retention clock overflow")?;
            }
        }
        next.entries.retain(|e| (e.height, e.tip) != (height, tip));
        if next.entries.len() >= RETAINED_HEADS {
            return Err("wallet retained generation catalog full".into());
        }
        next.entries.push(Entry {
            height,
            tip,
            digest,
            expires: 0,
        });
        next.sequence = next
            .sequence
            .checked_add(1)
            .filter(|v| *v < (1 << 53))
            .ok_or("wallet catalog sequence exhausted")?;
        Ok(next)
    }
}
struct Acquired {
    native: Option<wallet_history::Export>,
    #[cfg(test)]
    synthetic: Option<Vec<u8>>,
}
impl Acquired {
    fn bytes(&self) -> &[u8] {
        if let Some(value) = &self.native {
            return value.bytes();
        }
        #[cfg(test)]
        if let Some(value) = &self.synthetic {
            return value;
        }
        unreachable!("one acquired public receipt")
    }
}
trait Source {
    fn head(&self) -> (u64, Hash);
    fn header(&self, height: u64) -> Result<crate::eng2::header::Header, String>;
    fn genesis(&self) -> Result<Vec<u8>, String>;
    fn receipt(&self, height: u64, budget: &p2p::Budget) -> Result<Acquired, String>;
}
struct StoreSource<'a> {
    store: &'a Store,
    head: wallet_history::Head,
}
impl Source for StoreSource<'_> {
    fn head(&self) -> (u64, Hash) {
        (self.head.height(), self.head.tip())
    }
    fn header(&self, height: u64) -> Result<crate::eng2::header::Header, String> {
        self.head.check_current(self.store)?;
        self.store.header(height)
    }
    fn genesis(&self) -> Result<Vec<u8>, String> {
        wallet_history::bootstrap(self.store, &self.head)
    }
    fn receipt(&self, height: u64, budget: &p2p::Budget) -> Result<Acquired, String> {
        Ok(Acquired {
            native: Some(wallet_history::receipts(
                self.store, &self.head, height, budget,
            )?),
            #[cfg(test)]
            synthetic: None,
        })
    }
}
/// Owned by the existing canonical-state caller. Its descriptor lease prevents
/// competing publishers; failures pause this export without mutating the Store.
pub struct WalletPublisher {
    binding: Binding,
    policy: WalletPolicy,
    _lease: fs::File,
    _memory: p2p::Reservation,
    reserved: u64,
    allocation_unit: u64,
    poisoned: bool,
    height: u64,
    tip: Hash,
    full: Vec<Descriptor>,
    tail: Vec<Record>,
    catalog: Catalog,
    published: Option<(u64, Hash, u64)>,
    last_now: Option<u64>,
}
impl WalletPublisher {
    pub fn invalidate_advertisement(&mut self) {
        self.published = None;
    }
    pub fn open(
        export: &PublicExport,
        store: &Store,
        policy: WalletPolicy,
        budget: &p2p::Budget,
    ) -> Result<Self, String> {
        export.check_store(store)?;
        let genesis = store.engine().genesis();
        if genesis.fee_mode() as u8 != 0 {
            return Err("wallet export supports only explicit LegacyMiner context".into());
        }
        let binding = Binding::new(
            store.engine().state().network(),
            genesis.id(),
            genesis.rules_commitment(),
            crate::proofs::protocol_profile_fingerprint(),
        );
        let source = StoreSource {
            store,
            head: wallet_history::Head::capture(store)?,
        };
        Self::restore(export, binding, &source, policy, budget)
    }
    fn restore(
        export: &PublicExport,
        binding: Binding,
        source: &impl Source,
        policy: WalletPolicy,
        budget: &p2p::Budget,
    ) -> Result<Self, String> {
        let policy = policy.check()?;
        let memory = budget
            .reserve(4 * (wire::MAX_MANIFEST_BYTES + wire::MAX_CHUNK_BYTES))
            .map_err(|_| "wallet publisher retained metadata memory unavailable")?;
        let descriptor = openat(
            &export.root,
            "wallet-export.lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| "wallet publisher lease unavailable")?;
        let lease = fs::File::from(descriptor);
        let metadata = lease
            .metadata()
            .map_err(|_| "wallet publisher lease metadata unavailable")?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err("wallet publisher lease record rejected".into());
        }
        flock(&lease, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| "another wallet publisher owns the export directory")?;
        let unit = metadata.blksize().max(4096);
        let mut inventory = METADATA_RESERVE.max(
            unit.checked_mul(32)
                .ok_or("wallet mutable metadata reserve overflow")?,
        );
        let mut count = 0;
        let entries =
            Dir::read_from(&export.root).map_err(|_| "wallet artifact inventory unavailable")?;
        for entry in entries {
            let entry = entry.map_err(|_| "wallet artifact inventory failed")?;
            let name = entry.file_name();
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                continue;
            }
            count += 1;
            if count > MAX_ENTRIES {
                return Err("wallet export inventory exceeds entry bound".into());
            }
            let file = openat(
                &export.root,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| "wallet inventory entry rejected")?;
            let metadata = fs::File::from(file)
                .metadata()
                .map_err(|_| "wallet inventory metadata unavailable")?;
            if !metadata.is_file() || metadata.nlink() != 1 {
                return Err("wallet inventory requires unshared regular files".into());
            }
            inventory = inventory
                .checked_add(
                    metadata
                        .blocks()
                        .checked_mul(512)
                        .ok_or("wallet inventory size overflow")?,
                )
                .and_then(|v| v.checked_add(unit))
                .ok_or("wallet inventory size overflow")?;
        }
        let mut reserved = inventory;
        if let Some(bytes) = export.read_optional("wallet-export-budget.json", 2048)? {
            let value: Value = serde_json::from_slice(&bytes)
                .map_err(|_| "wallet artifact reservation journal rejected")?;
            if value.as_object().is_none_or(|v| v.len() != 3)
                || value["version"] != 1
                || value["binding"] != crate::local::hex(&binding.0)
            {
                return Err("wallet artifact reservation context rejected".into());
            }
            reserved = reserved.max(
                value["reserved_bytes"]
                    .as_u64()
                    .ok_or("wallet artifact reservation amount rejected")?,
            );
        }
        if reserved > policy.max_artifact_bytes {
            return Err("wallet artifact budget exhausted".into());
        }
        let catalog = export
            .read_optional("wallet-generations.json", CATALOG_BYTES)?
            .map(|bytes| Catalog::decode(&binding, &bytes))
            .transpose()?
            .unwrap_or_default();
        let mut value = Self {
            tip: binding.genesis(),
            binding,
            policy,
            _lease: lease,
            _memory: memory,
            reserved,
            allocation_unit: unit,
            poisoned: false,
            height: 0,
            full: Vec::new(),
            tail: Vec::new(),
            catalog,
            published: None,
            last_now: None,
        };
        if let Some(bytes) = export.read_optional("wallet-head.json", 2048)? {
            let head: Value = serde_json::from_slice(&bytes)
                .map_err(|_| "wallet current head record rejected")?;
            if head.as_object().is_none_or(|o| o.len() != 9)
                || head["version"].as_u64() != Some(2)
                || context_json(&value.binding)
                    .as_object()
                    .expect("fixed context")
                    .iter()
                    .any(|(k, v)| head.get(k) != Some(v))
            {
                return Err("wallet current head context rejected".into());
            }
            let height = head["height"]
                .as_u64()
                .ok_or("wallet current head height absent")?;
            let tip = decode_hash(head["tip"].as_str().ok_or("wallet current tip absent")?)?;
            let published = head["published_unix_seconds"]
                .as_u64()
                .filter(|v| *v < (1 << 53))
                .ok_or("wallet current publication time rejected")?;
            let entry = value
                .catalog
                .entries
                .iter()
                .find(|e| (e.height, e.tip) == (height, tip))
                .ok_or("wallet committed head is absent from catalog")?;
            let name = format!("wallet-generation-{height}-{}.bin", crate::local::hex(&tip));
            let bytes = export.read(&name, wire::MAX_MANIFEST_BYTES)?;
            if wire::digest(&bytes) != entry.digest {
                return Err("wallet restored generation digest differs".into());
            }
            let manifest = Manifest::decode(&value.binding, &bytes)?;
            if (manifest.height, manifest.tip) != (height, tip) {
                return Err("wallet restored generation head differs".into());
            }
            let current = source.head();
            let canonical = height <= current.0
                && (height == 0 && tip == value.binding.genesis()
                    || height > 0
                        && source
                            .header(height)?
                            .id()
                            .map_err(|_| "wallet restored canonical identity rejected")?
                            == tip);
            if canonical {
                let mut previous = value.binding.genesis();
                for descriptor in &manifest.chunks {
                    let chunk = descriptor.decode_chunk(
                        &value.binding,
                        &export.read(&descriptor.name(), wire::MAX_CHUNK_BYTES)?,
                    )?;
                    if chunk.records[0].decoded(&value.binding)?.parent != previous {
                        return Err("wallet restored chunk prefix differs".into());
                    }
                    for (index, record) in chunk.records.iter().enumerate() {
                        value.receipt_metadata(export, record, chunk.from + index as u64)?;
                    }
                    previous = chunk.records.last().expect("bounded chunk").id;
                    if chunk.records.len() == wire::CHUNK_HEADERS {
                        value.full.push(descriptor.clone());
                    } else {
                        value.tail = chunk.records;
                    }
                }
                if previous != tip {
                    return Err("wallet restored complete prefix differs".into());
                }
                value.height = height;
                value.tip = tip;
            }
            value.published = Some((height, tip, published));
        }
        value.persist_reservation(export)?;
        Ok(value)
    }
    fn receipt_metadata(
        &self,
        export: &PublicExport,
        record: &Record,
        height: u64,
    ) -> Result<(), String> {
        let file = openat(
            &export.root,
            record.receipt_name(height),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| "wallet restored receipt dependency unavailable")?;
        let metadata = fs::File::from(file)
            .metadata()
            .map_err(|_| "wallet restored receipt metadata unavailable")?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.len() != u64::from(record.receipt_bytes)
        {
            return Err("wallet restored receipt dependency rejected".into());
        }
        Ok(())
    }
    fn replace_metadata(
        &mut self,
        export: &PublicExport,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), String> {
        if let Err(error) = export.replace(name, bytes) {
            // A failed cleanup may leave one charged temporary file. Stop
            // further mutable writes until a fresh bounded inventory is taken.
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }
    fn persist_reservation(&mut self, export: &PublicExport) -> Result<(), String> {
        let bytes=serde_json::to_vec(&json!({"version":1,"binding":crate::local::hex(&self.binding.0),"reserved_bytes":self.reserved})).map_err(|_|"wallet reservation encoding failed")?;
        if export.replace("wallet-export-budget.json", &bytes).is_err() {
            self.poisoned = true;
            return Err("wallet reservation journal unavailable; reopen publisher".into());
        }
        Ok(())
    }
    fn immutable(&mut self, export: &PublicExport, name: &str, bytes: &[u8]) -> Result<(), String> {
        if let Some(old) = export.read_optional(name, bytes.len())? {
            return if old == bytes {
                Ok(())
            } else {
                Err("wallet immutable dependency differs".into())
            };
        }
        let charge = (bytes.len() as u64)
            .div_ceil(self.allocation_unit)
            .checked_mul(self.allocation_unit)
            .and_then(|v| v.checked_add(self.allocation_unit))
            .ok_or("wallet artifact charge overflow")?;
        let next = self
            .reserved
            .checked_add(charge)
            .filter(|v| *v <= self.policy.max_artifact_bytes)
            .ok_or("wallet artifact budget exhausted")?;
        self.reserved = next;
        self.persist_reservation(export)?;
        #[cfg(test)]
        if FAIL_IMMUTABLE.with(|flag| flag.replace(false)) {
            return Err("injected immutable write failure after reservation".into());
        }
        export.write_once(name, bytes)
    }
    pub fn tick(
        &mut self,
        export: &PublicExport,
        store: &Store,
        now: u64,
        budget: &p2p::Budget,
    ) -> Result<WalletProgress, String> {
        export.check_store(store)?;
        let source = StoreSource {
            store,
            head: wallet_history::Head::capture(store)?,
        };
        self.step(export, &source, now, budget)
    }
    fn step(
        &mut self,
        export: &PublicExport,
        source: &impl Source,
        now: u64,
        budget: &p2p::Budget,
    ) -> Result<WalletProgress, String> {
        if self.poisoned || now >= (1 << 53) || self.last_now.is_some_and(|last| now < last) {
            return Err("wallet publisher unavailable or clock regressed".into());
        }
        self.last_now = Some(now);
        let _metadata = budget
            .reserve(
                2 * wire::MAX_CHUNK_BYTES
                    + 2 * wire::MAX_MANIFEST_BYTES
                    + 4 * MAX_GENESIS
                    + CATALOG_BYTES,
            )
            .map_err(|_| "wallet export metadata memory unavailable")?;
        let (target, tip) = source.head();
        if target > wire::MAX_HEIGHT {
            return Err("wallet public header capacity exceeded".into());
        }
        if self.height > target
            || self.height > 0
                && source
                    .header(self.height)?
                    .id()
                    .map_err(|_| "wallet prefix identity rejected")?
                    != self.tip
        {
            self.height = 0;
            self.tip = self.binding.genesis();
            self.full.clear();
            self.tail.clear();
        }
        let genesis = source.genesis()?;
        if genesis.len() > MAX_GENESIS {
            return Err("wallet public genesis exceeds bound".into());
        }
        self.immutable(export, "wallet-genesis.bin", &genesis)?;
        if self.height < target {
            let next = self.height + 1;
            let header = source.header(next)?;
            if header.height != next || header.parent != self.tip {
                return Err("wallet source canonical prefix changed".into());
            }
            let raw = header
                .encode()
                .map_err(|_| "wallet source header rejected")?;
            let receipt = source.receipt(next, budget)?;
            let record = Record::from_receipt(&self.binding, raw, receipt.bytes())?;
            self.immutable(export, &record.receipt_name(next), receipt.bytes())?;
            self.tip = record.id;
            self.height = next;
            self.tail.push(record);
            if self.tail.len() == wire::CHUNK_HEADERS {
                let chunk = Chunk {
                    from: next + 1 - wire::CHUNK_HEADERS as u64,
                    records: self.tail.clone(),
                };
                let (descriptor, bytes) = Descriptor::from_chunk(&self.binding, &chunk)?;
                if let Err(error) = self.immutable(export, &descriptor.name(), &bytes) {
                    self.tail.pop();
                    self.height -= 1;
                    self.tip = header.parent;
                    return Err(error);
                }
                self.full.push(descriptor);
                self.tail.clear();
            }
        }
        let mut published = false;
        if self.height == target
            && self.tip == tip
            && self.published.is_none_or(|(h, id, time)| {
                (h, id) != (target, tip) || now.saturating_sub(time) >= 60
            })
        {
            self.publish(export, source, now)?;
            published = true;
        }
        Ok(WalletProgress {
            scanned_height: self.height,
            target_height: target,
            published_height: self.published.map(|v| v.0),
            published,
        })
    }
    fn publish(
        &mut self,
        export: &PublicExport,
        source: &impl Source,
        now: u64,
    ) -> Result<(), String> {
        let mut descriptors = self.full.clone();
        if !self.tail.is_empty() {
            let chunk = Chunk {
                from: self.height + 1 - self.tail.len() as u64,
                records: self.tail.clone(),
            };
            let (descriptor, bytes) = Descriptor::from_chunk(&self.binding, &chunk)?;
            self.immutable(export, &descriptor.name(), &bytes)?;
            descriptors.push(descriptor);
        }
        let manifest = Manifest {
            height: self.height,
            tip: self.tip,
            chunks: descriptors,
        };
        #[cfg(test)]
        if FAIL_BEFORE_MANIFEST.with(|flag| flag.replace(false)) {
            return Err("injected interruption before wallet manifest".into());
        }
        let bytes = manifest.encode(&self.binding)?;
        let hash = wire::digest(&bytes);
        self.immutable(export, &manifest.name(), &bytes)?;
        #[cfg(test)]
        if FAIL_BEFORE_CATALOG.with(|flag| flag.replace(false)) {
            return Err("injected interruption before wallet catalog".into());
        }
        let next = self.catalog.staged(
            self.height,
            self.tip,
            hash,
            now,
            self.published.map(|(height, tip, _)| (height, tip)),
        )?;
        // These are complete immutable dependencies, even if a later cursor
        // replacement fails. The previous advertised head remains resolvable.
        self.replace_metadata(
            export,
            "wallet-generations.json",
            &next.encode(&self.binding)?,
        )?;
        self.catalog = next;
        #[cfg(test)]
        if FAIL_BEFORE_HEAD.with(|flag| flag.replace(false)) {
            return Err("injected interruption before wallet head".into());
        }
        if source.head() != (self.height, self.tip) {
            return Err("wallet source head changed before publication".into());
        }
        let mut head = context_json(&self.binding);
        let object = head.as_object_mut().expect("fixed context");
        object.insert("version".into(), json!(2));
        object.insert("height".into(), json!(self.height));
        object.insert("tip".into(), json!(crate::local::hex(&self.tip)));
        object.insert("published_unix_seconds".into(), json!(now));
        self.replace_metadata(
            export,
            "wallet-head.json",
            &serde_json::to_vec(&head).map_err(|_| "wallet current head encoding failed")?,
        )?;
        self.published = Some((self.height, self.tip, now));
        Ok(())
    }
}
#[cfg(test)]
thread_local! {
    static FAIL_BEFORE_HEAD: std::cell::Cell<bool> = const {std::cell::Cell::new(false)};
    static FAIL_BEFORE_MANIFEST: std::cell::Cell<bool> = const {std::cell::Cell::new(false)};
    static FAIL_BEFORE_CATALOG: std::cell::Cell<bool> = const {std::cell::Cell::new(false)};
    static FAIL_IMMUTABLE: std::cell::Cell<bool> = const {std::cell::Cell::new(false)};
}
#[cfg(test)]
mod tests;
