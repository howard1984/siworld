//! Provisional standard folder format, with immutable records and bounded chunk IO.

use crate::{
    Error, Result,
    crypto::{self, CHUNK_SIZE, PIECE_SIZE, Secret},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[cfg(test)]
mod crash_test;

const MAGIC: &[u8; 8] = b"SVST0001";
const CONTROLLED_MAGIC: &[u8; 8] = b"SVCT0001";
const CONTROLLED_REGISTRATION: &str = "registration-v1";
pub const MAX_CONTROLLED_REGISTRATION: usize = 8192;
const HEADER: usize = 224;
const MAX_INDEX: usize = 128 << 20;
const MAX_ENTRIES: usize = 100_000;
const WINDOWS_DEV_WRITE: bool = cfg!(all(
    windows,
    debug_assertions,
    feature = "dev-windows-write"
));

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Entry {
    pub id: String,
    pub parent: Option<String>,
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    #[serde(skip)]
    revision: [u8; 16],
}

pub(crate) struct Directory {
    path: PathBuf,
    handle: File,
}

impl Directory {
    pub(crate) fn identity(&self) -> Result<same_file::Handle> {
        Ok(same_file::Handle::from_file(self.handle.try_clone()?)?)
    }

    pub(crate) fn open(path: &Path) -> Result<Self> {
        Self::open_access(path, false)
    }

    pub(crate) fn open_export_parent(path: &Path) -> Result<Self> {
        Self::open_access(path, true)
    }

    fn open_access(path: &Path, _pin: bool) -> Result<Self> {
        if !fs::symlink_metadata(path)?.is_dir() {
            return Err(Error::InvalidName);
        }
        #[cfg(unix)]
        let handle = File::from(
            rustix::fs::open(
                path,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(std::io::Error::from)?,
        );
        #[cfg(windows)]
        let handle = {
            use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
            let mut options = OpenOptions::new();
            options.read(true).custom_flags(0x02200000);
            if _pin {
                // Keep the checked path from being redirected by a directory rename.
                options.share_mode(0x00000003);
            }
            let f = options.open(path)?;
            if f.metadata()?.file_attributes() & 0x400 != 0 {
                return Err(Error::InvalidName);
            }
            f
        };
        #[cfg(not(any(unix, windows)))]
        let handle = File::open(path)?;
        Ok(Self {
            path: path.to_owned(),
            handle,
        })
    }

    pub(crate) fn file(&self, name: &str, create: bool) -> Result<File> {
        self.file_access(name, create, false)
    }

    pub(crate) fn file_access(&self, name: &str, create: bool, update: bool) -> Result<File> {
        if name.contains(['/', '\\']) || name == "." || name == ".." {
            return Err(Error::InvalidName);
        }
        #[cfg(unix)]
        let f = {
            use rustix::fs::{Mode, OFlags, openat};
            let flags = if create {
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL
            } else if update {
                OFlags::RDWR
            } else {
                OFlags::RDONLY
            };
            File::from(
                openat(
                    &self.handle,
                    name,
                    flags | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                    Mode::RUSR | Mode::WUSR,
                )
                .map_err(std::io::Error::from)?,
            )
        };
        #[cfg(not(unix))]
        let f = {
            let mut options = OpenOptions::new();
            options
                .read(!create)
                .write(create || update)
                .create_new(create);
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                options.custom_flags(0x00200000);
            }
            options.open(self.path.join(name))?
        };
        let meta = f.metadata()?;
        if !meta.is_file() {
            return Err(Error::InvalidName);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if meta.file_attributes() & 0x400 != 0 {
                return Err(Error::InvalidName);
            }
        }
        Ok(f)
    }

    fn bytes(&self, name: &str, max: usize) -> Result<Vec<u8>> {
        let mut f = self.file(name, false)?;
        let len = usize::try_from(f.metadata()?.len()).map_err(|_| Error::Limit)?;
        if len > max {
            return Err(Error::Limit);
        }
        let mut bytes = Vec::with_capacity(len);
        Read::by_ref(&mut f)
            .take(max as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > max {
            return Err(Error::Limit);
        }
        Ok(bytes)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let mut file = self.file(name, true)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }

    fn publish_generation(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let temporary = format!(".pending-{}", hex(&crypto::random::<16>()?));
        self.write(&temporary, bytes)?;
        #[cfg(test)]
        if name.starts_with("g-") {
            crash_test::pause("before");
        }
        #[cfg(any(target_os = "linux", target_vendor = "apple"))]
        rustix::fs::renameat_with(
            &self.handle,
            temporary.as_str(),
            &self.handle,
            name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(std::io::Error::from)?;
        #[cfg(windows)]
        {
            mutation_supported()?;
            // A same-volume hard link publishes the completed record without replacement.
            let staged = self.path.join(&temporary);
            fs::hard_link(&staged, self.path.join(name))?;
            let _ = fs::remove_file(staged);
        }
        #[cfg(not(any(target_os = "linux", target_vendor = "apple", windows)))]
        {
            let _ = name;
            return Err(Error::Unsupported);
        }
        #[cfg(test)]
        if name.starts_with("g-") {
            crash_test::pause("after");
        }
        #[allow(unreachable_code)]
        self.sync()
    }

    pub(crate) fn sync(&self) -> Result<()> {
        #[cfg(unix)]
        self.handle.sync_all()?;
        #[cfg(windows)]
        {
            self.handle.metadata()?;
            // No directory durability guarantee in the development build.
            mutation_supported()?;
        }
        #[cfg(not(any(unix, windows)))]
        {
            self.handle.metadata()?;
            return Err(Error::Unsupported);
        }
        #[allow(unreachable_code)]
        Ok(())
    }
}

pub struct Safe {
    directory: Directory,
    _lock: File,
    safe_id: [u8; 16],
    generation: u64,
    slot: [u8; 88],
    magic: &'static [u8; 8],
    content_key: Secret,
    entries: Vec<Entry>,
    read_only: bool,
    poisoned: bool,
}

impl Safe {
    pub fn create(path: impl AsRef<Path>, password: &str) -> Result<Self> {
        mutation_supported()?;
        // Validate before creating anything, so a rejected password leaves no safe.
        drop(crypto::password_bytes(password)?);
        let safe_id = crypto::random()?;
        let content_key = Zeroizing::new(crypto::random()?);
        let salt = crypto::random()?;
        let nonce = crypto::random()?;
        let stretched = crypto::stretch(password, &salt)?;
        let key = crypto::derive(&stretched, &safe_id, b"SVST0001/wrap");
        let mut ad = b"SVST0001/wrap".to_vec();
        ad.extend(safe_id);
        let wrapped = crypto::seal(&key, &nonce, &ad, content_key.as_ref())?;
        let mut slot = [0; 88];
        slot[..16].copy_from_slice(&salt);
        slot[16..40].copy_from_slice(&nonce);
        slot[40..].copy_from_slice(&wrapped);
        Self::create_payload(path.as_ref(), safe_id, content_key, slot, MAGIC)
    }

    /// Create a payload whose key is managed by the controlled-open protocol.
    /// No password slot or offline password-opening route is installed.
    pub fn create_controlled(
        path: impl AsRef<Path>,
        safe_id: [u8; 16],
        content_key: Secret,
    ) -> Result<Self> {
        Self::create_payload(
            path.as_ref(),
            safe_id,
            content_key,
            [0; 88],
            CONTROLLED_MAGIC,
        )
    }

    /// Publish the owner's acknowledged registration without replacement.
    /// The protocol layer defines and authenticates the registration bytes.
    pub fn publish_controlled_registration(&self, bytes: &[u8]) -> Result<()> {
        self.writable()?;
        if self.magic != CONTROLLED_MAGIC || bytes.is_empty() {
            return Err(Error::InvalidFormat);
        }
        if bytes.len() > MAX_CONTROLLED_REGISTRATION {
            return Err(Error::Limit);
        }
        self.directory
            .publish_generation(CONTROLLED_REGISTRATION, bytes)
    }

    /// Read bounded, untrusted registration bytes before contacting a peer.
    pub fn read_controlled_registration(path: impl AsRef<Path>) -> Result<Vec<u8>> {
        let bytes = Directory::open(path.as_ref())?
            .bytes(CONTROLLED_REGISTRATION, MAX_CONTROLLED_REGISTRATION)?;
        if bytes.is_empty() {
            return Err(Error::InvalidFormat);
        }
        Ok(bytes)
    }

    /// Stage one candidate without changing the active registration. A digest
    /// in the filename lets an interrupted attempt coexist with a later retry.
    pub fn stage_controlled_pending(
        &self,
        version: u64,
        commitment: &[u8; 32],
        bytes: &[u8],
    ) -> Result<()> {
        self.writable()?;
        if self.magic != CONTROLLED_MAGIC
            || !(1..=MAX_CONTROLLED_REGISTRATION).contains(&bytes.len())
        {
            return Err(Error::InvalidFormat);
        }
        let name = controlled_pending_name(version, commitment)?;
        match self.directory.bytes(&name, MAX_CONTROLLED_REGISTRATION) {
            Ok(old) if old == bytes => return self.directory.sync(),
            Ok(_) => return Err(Error::Authentication),
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        self.directory.publish_generation(&name, bytes)?;
        if self.directory.bytes(&name, MAX_CONTROLLED_REGISTRATION)? != bytes {
            return Err(Error::Authentication);
        }
        self.directory.sync()
    }

    pub fn read_controlled_pending(
        path: impl AsRef<Path>,
        version: u64,
        commitment: &[u8; 32],
    ) -> Result<Vec<u8>> {
        let name = controlled_pending_name(version, commitment)?;
        let bytes = Directory::open(path.as_ref())?.bytes(&name, MAX_CONTROLLED_REGISTRATION)?;
        if bytes.is_empty() {
            return Err(Error::InvalidFormat);
        }
        Ok(bytes)
    }

    pub fn has_controlled_registration(path: impl AsRef<Path>) -> Result<bool> {
        match Directory::open(path.as_ref())?.file(CONTROLLED_REGISTRATION, false) {
            Ok(_) => Ok(true),
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn create_payload(
        path: &Path,
        safe_id: [u8; 16],
        content_key: Secret,
        slot: [u8; 88],
        magic: &'static [u8; 8],
    ) -> Result<Self> {
        mutation_supported()?;
        fs::create_dir(path)?;
        let directory = Directory::open(path)?;
        let lock = directory.file(".sivault-lock", true)?;
        lock.try_lock().map_err(|_| Error::Busy)?;
        let mut safe = Self {
            directory,
            _lock: lock,
            safe_id,
            generation: 0,
            slot,
            magic,
            content_key,
            entries: vec![],
            read_only: false,
            poisoned: false,
        };
        safe.commit(vec![])?;
        Ok(safe)
    }

    pub fn open(path: impl AsRef<Path>, password: &str, read_only: bool) -> Result<Self> {
        Self::open_payload(path.as_ref(), MAGIC, read_only, |safe_id, slot| {
            let stretched = crypto::stretch(password, &array(&slot[..16]))?;
            let wrap = crypto::derive(&stretched, safe_id, b"SVST0001/wrap");
            let mut ad = b"SVST0001/wrap".to_vec();
            ad.extend(safe_id);
            let plain_key = crypto::unseal(&wrap, &array(&slot[16..40]), &ad, &slot[40..])?;
            Ok(Zeroizing::new(array(&plain_key)))
        })
    }

    /// Open only a controlled payload after fresh approval and key unwrap.
    pub fn open_controlled(
        path: impl AsRef<Path>,
        expected_safe_id: [u8; 16],
        content_key: Secret,
        read_only: bool,
    ) -> Result<Self> {
        Self::open_payload(
            path.as_ref(),
            CONTROLLED_MAGIC,
            read_only,
            |safe_id, slot| {
                if *safe_id != expected_safe_id || *slot != [0; 88] {
                    return Err(Error::Authentication);
                }
                Ok(content_key)
            },
        )
    }

    fn open_payload(
        path: &Path,
        magic: &'static [u8; 8],
        read_only: bool,
        resolve_key: impl FnOnce(&[u8; 16], &[u8; 88]) -> Result<Secret>,
    ) -> Result<Self> {
        let directory = Directory::open(path)?;
        let lock = directory.file(".sivault-lock", false)?;
        if read_only {
            lock.try_lock_shared().map_err(|_| Error::Busy)?;
        } else {
            lock.try_lock().map_err(|_| Error::Busy)?;
        }
        let mut generations = BTreeSet::new();
        for child in fs::read_dir(&directory.path)? {
            let name = child?
                .file_name()
                .into_string()
                .map_err(|_| Error::InvalidFormat)?;
            if let Some(suffix) = name.strip_prefix("g-") {
                if suffix.len() != 16 || !suffix.bytes().all(is_hex) {
                    return Err(Error::InvalidFormat);
                }
                let generation =
                    u64::from_str_radix(suffix, 16).map_err(|_| Error::InvalidFormat)?;
                if generation == 0 || generation > u32::MAX as u64 {
                    return Err(Error::InvalidFormat);
                }
                generations.insert(generation);
            }
        }
        let generation = *generations.last().ok_or(Error::InvalidFormat)?;
        let header = directory.bytes(&format!("g-{generation:016x}"), HEADER)?;
        if header.len() != HEADER
            || &header[..8] != magic
            || header[8..16] != [1, 0, 224, 0, 0, 0, 0, 0]
            || header[184..192] != [0; 8]
            || integer(&header[32..40]) != generation
        {
            return Err(Error::InvalidFormat);
        }
        let safe_id = array(&header[16..32]);
        let slot: [u8; 88] = array(&header[96..184]);
        let content_key = resolve_key(&safe_id, &slot)?;
        let commit = crypto::derive(&content_key, &safe_id, b"SVST0001/commit");
        crypto::verify_mac(&commit, &header[..192], &header[192..])?;
        let index_id = array(&header[40..56]);
        let length = integer(&header[56..64]);
        if length < 48 || length > (MAX_INDEX + 40) as u64 {
            return Err(Error::InvalidFormat);
        }
        let index = directory.bytes(&format!("i-{}", hex(&index_id)), MAX_INDEX + 40)?;
        if index.len() as u64 != length || Sha256::digest(&index)[..] != header[64..96] {
            return Err(Error::InvalidFormat);
        }
        let key = crypto::derive(&content_key, &safe_id, b"SVST0001/index");
        let ad = index_ad(&safe_id, &index_id, generation);
        let plain = crypto::unseal(&key, &array(&index[..24]), &ad, &index[24..])?;
        let entries = decode_index(&plain)?;
        let safe = Self {
            directory,
            _lock: lock,
            safe_id,
            generation,
            slot,
            magic,
            content_key,
            entries,
            read_only,
            poisoned: false,
        };
        for entry in safe.entries.iter().filter(|e| !e.is_dir) {
            let pieces = pieces(entry.size)?;
            for piece in 0..pieces {
                let file = safe
                    .directory
                    .file(&piece_name(&entry.revision, piece), false)?;
                if file.metadata()?.len() != piece_stored(piece_length(entry.size, piece)) {
                    return Err(Error::InvalidFormat);
                }
            }
        }
        Ok(safe)
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn create_directory(&mut self, name: &str, parent: Option<&str>) -> Result<Entry> {
        self.writable()?;
        self.check_name(name, parent)?;
        let entry = Entry {
            id: hex(&crypto::random::<16>()?),
            parent: parent.map(str::to_owned),
            name: name.to_owned(),
            is_dir: true,
            size: 0,
            revision: [0; 16],
        };
        let mut entries = self.entries.clone();
        entries.push(entry.clone());
        self.commit(entries)?;
        Ok(entry)
    }

    pub fn import_file(&mut self, source: impl AsRef<Path>, parent: Option<&str>) -> Result<Entry> {
        self.writable()?;
        let name = source
            .as_ref()
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(Error::InvalidName)?;
        self.check_name(name, parent)?;
        if fs::symlink_metadata(source.as_ref())?
            .file_type()
            .is_symlink()
        {
            return Err(Error::InvalidName);
        }
        let mut source_file = source_read(source.as_ref())?;
        let size = source_file.metadata()?.len();
        let entry = Entry {
            id: hex(&crypto::random::<16>()?),
            parent: parent.map(str::to_owned),
            name: name.to_owned(),
            is_dir: false,
            size,
            revision: crypto::random()?,
        };
        let count = pieces(size)?;
        let key = self.piece_key(&entry)?;
        let mut buffer = Zeroizing::new(vec![0; CHUNK_SIZE]);
        for piece in 0..count {
            let mut destination = self
                .directory
                .file(&piece_name(&entry.revision, piece), true)?;
            let prefix = crypto::random::<19>()?;
            destination.write_all(&prefix)?;
            let mut remaining = piece_length(size, piece);
            let ad = self.piece_ad(&entry, piece)?;
            let mut index = 0;
            while remaining > 0 {
                let length = remaining.min(CHUNK_SIZE as u64) as usize;
                source_file.read_exact(&mut buffer[..length])?;
                remaining -= length as u64;
                let ciphertext = crypto::encrypt_chunk(
                    &key,
                    &prefix,
                    index,
                    remaining == 0,
                    &ad,
                    &buffer[..length],
                )?;
                destination.write_all(&ciphertext)?;
                index += 1;
            }
            destination.sync_all()?;
        }
        let mut extra = [0];
        if source_file.read(&mut extra)? != 0 || source_file.metadata()?.len() != size {
            return Err(Error::InvalidFormat);
        }
        self.directory.sync()?;
        let mut entries = self.entries.clone();
        entries.push(entry.clone());
        self.commit(entries)?;
        Ok(entry)
    }

    pub fn export_file(&self, id: &str, destination: impl AsRef<Path>) -> Result<()> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.id == id && !e.is_dir)
            .ok_or(Error::InvalidName)?;
        // Authenticate the full stream before creating an explicit plaintext output.
        self.read_file(entry, &mut std::io::sink())?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination.as_ref())?;
        let result = self
            .read_file(entry, &mut output)
            .and_then(|_| output.sync_all().map_err(Error::from));
        drop(output);
        if result.is_err() {
            let _ = fs::remove_file(destination.as_ref());
        }
        result
    }

    pub fn remove(&mut self, id: &str) -> Result<()> {
        self.writable()?;
        if !self.entries.iter().any(|e| e.id == id) {
            return Err(Error::InvalidName);
        }
        let mut removed = HashSet::from([id.to_owned()]);
        loop {
            let before = removed.len();
            for e in &self.entries {
                if e.parent.as_ref().is_some_and(|p| removed.contains(p)) {
                    removed.insert(e.id.clone());
                }
            }
            if before == removed.len() {
                break;
            }
        }
        self.commit(
            self.entries
                .iter()
                .filter(|e| !removed.contains(&e.id))
                .cloned()
                .collect(),
        )
    }

    fn writable(&self) -> Result<()> {
        if self.read_only {
            Err(Error::ReadOnly)
        } else if self.poisoned {
            Err(Error::Busy)
        } else {
            mutation_supported()
        }
    }

    fn check_name(&self, name: &str, parent: Option<&str>) -> Result<()> {
        validate_name(name)?;
        if parent.is_some_and(|p| !self.entries.iter().any(|e| e.id == p && e.is_dir))
            || self
                .entries
                .iter()
                .any(|e| e.parent.as_deref() == parent && e.name == name)
        {
            return Err(Error::InvalidName);
        }
        if self.entries.len() >= MAX_ENTRIES {
            return Err(Error::Limit);
        }
        Ok(())
    }

    fn piece_key(&self, entry: &Entry) -> Result<Secret> {
        let mut label = b"SVST0001/piece".to_vec();
        label.extend(unhex(&entry.id)?);
        label.extend(entry.revision);
        Ok(crypto::derive(&self.content_key, &self.safe_id, &label))
    }

    fn piece_ad(&self, entry: &Entry, piece: u32) -> Result<Vec<u8>> {
        let mut ad = b"SVST0001/piece".to_vec();
        ad.extend(self.safe_id);
        ad.extend(unhex(&entry.id)?);
        ad.extend(entry.revision);
        ad.extend(piece.to_le_bytes());
        ad.extend(pieces(entry.size)?.to_le_bytes());
        ad.extend(entry.size.to_le_bytes());
        ad.extend((piece_length(entry.size, piece) as u32).to_le_bytes());
        Ok(ad)
    }

    fn read_file(&self, entry: &Entry, output: &mut impl Write) -> Result<()> {
        let key = self.piece_key(entry)?;
        for piece in 0..pieces(entry.size)? {
            let mut file = self
                .directory
                .file(&piece_name(&entry.revision, piece), false)?;
            let mut prefix = [0; 19];
            file.read_exact(&mut prefix)?;
            if file.metadata()?.len() != piece_stored(piece_length(entry.size, piece)) {
                return Err(Error::InvalidFormat);
            }
            let ad = self.piece_ad(entry, piece)?;
            let mut remaining = piece_length(entry.size, piece);
            let mut ciphertext = vec![0; CHUNK_SIZE + 16];
            let mut index = 0;
            while remaining > 0 {
                let length = remaining.min(CHUNK_SIZE as u64) as usize;
                file.read_exact(&mut ciphertext[..length + 16])?;
                remaining -= length as u64;
                let plain = crypto::decrypt_chunk(
                    &key,
                    &prefix,
                    index,
                    remaining == 0,
                    &ad,
                    &ciphertext[..length + 16],
                )?;
                output.write_all(&plain)?;
                index += 1;
            }
            let mut extra = [0];
            if file.read(&mut extra)? != 0 {
                return Err(Error::InvalidFormat);
            }
        }
        Ok(())
    }

    fn commit(&mut self, mut entries: Vec<Entry>) -> Result<()> {
        self.writable()?;
        let generation = self
            .generation
            .checked_add(1)
            .filter(|n| *n <= u32::MAX as u64)
            .ok_or(Error::Limit)?;
        entries.sort_by(|a, b| a.id.cmp(&b.id));
        let plain = encode_index(&entries)?;
        let index_id = crypto::random()?;
        let key = crypto::derive(&self.content_key, &self.safe_id, b"SVST0001/index");
        let nonce = crypto::random()?;
        let mut index = nonce.to_vec();
        index.extend(crypto::seal(
            &key,
            &nonce,
            &index_ad(&self.safe_id, &index_id, generation),
            &plain,
        )?);
        let mut header = [0; HEADER];
        header[..8].copy_from_slice(self.magic);
        header[8..12].copy_from_slice(&[1, 0, 224, 0]);
        header[16..32].copy_from_slice(&self.safe_id);
        header[32..40].copy_from_slice(&generation.to_le_bytes());
        header[40..56].copy_from_slice(&index_id);
        header[56..64].copy_from_slice(&(index.len() as u64).to_le_bytes());
        header[64..96].copy_from_slice(&Sha256::digest(&index));
        header[96..184].copy_from_slice(&self.slot);
        let key = crypto::derive(&self.content_key, &self.safe_id, b"SVST0001/commit");
        let tag = crypto::mac(&key, &header[..192]);
        header[192..].copy_from_slice(&tag);
        self.poisoned = true;
        self.directory
            .write(&format!("i-{}", hex(&index_id)), &index)?;
        self.directory.sync()?;
        self.directory
            .publish_generation(&format!("g-{generation:016x}"), &header)?;
        self.generation = generation;
        self.entries = entries;
        self.poisoned = false;
        Ok(())
    }
}

fn mutation_supported() -> Result<()> {
    if cfg!(any(target_os = "linux", target_vendor = "apple")) || WINDOWS_DEV_WRITE {
        Ok(())
    } else {
        Err(Error::Unsupported)
    }
}

fn source_read(path: &Path) -> Result<File> {
    #[cfg(unix)]
    let file = File::from(
        rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(std::io::Error::from)?,
    );
    #[cfg(not(unix))]
    let file = {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(0x00200000);
        }
        options.open(path)?
    };
    if !file.metadata()?.is_file() {
        return Err(Error::InvalidName);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if file.metadata()?.file_attributes() & 0x400 != 0 {
            return Err(Error::InvalidName);
        }
    }
    Ok(file)
}

pub(crate) fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 255
        || name.contains(['\0', '/', '\\'])
        || [".", ".."].contains(&name)
    {
        return Err(Error::InvalidName);
    }
    Ok(())
}

fn encode_index(entries: &[Entry]) -> Result<Zeroizing<Vec<u8>>> {
    if entries.len() > MAX_ENTRIES {
        return Err(Error::Limit);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.extend((entries.len() as u32).to_le_bytes());
    bytes.extend([0; 4]);
    for entry in entries {
        bytes.extend(unhex(&entry.id)?);
        bytes.extend(match &entry.parent {
            Some(p) => unhex(p)?,
            None => [0; 16],
        });
        bytes.push(if entry.is_dir { 2 } else { 1 });
        bytes.push(0);
        bytes.extend((entry.name.len() as u16).to_le_bytes());
        bytes.extend(pieces(entry.size)?.to_le_bytes());
        bytes.extend(entry.size.to_le_bytes());
        bytes.extend(entry.name.as_bytes());
        if !entry.is_dir {
            bytes.extend(entry.revision);
        }
    }
    if bytes.len() > MAX_INDEX {
        return Err(Error::Limit);
    }
    decode_index(&bytes)?;
    Ok(bytes)
}

fn decode_index(bytes: &[u8]) -> Result<Vec<Entry>> {
    if bytes.len() < 8 || bytes.len() > MAX_INDEX || bytes[4..8] != [0; 4] {
        return Err(Error::InvalidFormat);
    }
    let count = u32::from_le_bytes(array(&bytes[..4])) as usize;
    if count > MAX_ENTRIES {
        return Err(Error::Limit);
    }
    let mut remaining = &bytes[8..];
    let mut entries = Vec::with_capacity(count.min(1024));
    let mut revisions = HashSet::new();
    for _ in 0..count {
        if remaining.len() < 48 {
            return Err(Error::InvalidFormat);
        }
        let id = hex(&remaining[..16]);
        let parent = (remaining[16..32] != [0; 16]).then(|| hex(&remaining[16..32]));
        let kind = remaining[32];
        let len = u16::from_le_bytes(array(&remaining[34..36])) as usize;
        let piece_count = u32::from_le_bytes(array(&remaining[36..40]));
        let size = integer(&remaining[40..48]);
        if remaining[33] != 0
            || ![1, 2].contains(&kind)
            || remaining[..16] == [0; 16]
            || entries.last().is_some_and(|e: &Entry| e.id >= id)
            || remaining.len() < 48 + len
            || len == 0
            || len > 255
        {
            return Err(Error::InvalidFormat);
        }
        let name = std::str::from_utf8(&remaining[48..48 + len])
            .map_err(|_| Error::InvalidFormat)?
            .to_owned();
        validate_name(&name)?;
        remaining = &remaining[48 + len..];
        let mut revision = [0; 16];
        if kind == 1 {
            if remaining.len() < 16 {
                return Err(Error::InvalidFormat);
            }
            revision.copy_from_slice(&remaining[..16]);
            remaining = &remaining[16..];
            if revision == [0; 16] || !revisions.insert(revision) || piece_count != pieces(size)? {
                return Err(Error::InvalidFormat);
            }
        } else if size != 0 || piece_count != 0 {
            return Err(Error::InvalidFormat);
        }
        entries.push(Entry {
            id,
            parent,
            name,
            is_dir: kind == 2,
            size,
            revision,
        });
    }
    if !remaining.is_empty() {
        return Err(Error::InvalidFormat);
    }
    let by_id: std::collections::HashMap<_, _> =
        entries.iter().map(|e| (e.id.as_str(), e)).collect();
    let mut names = HashSet::new();
    for e in &entries {
        if !names.insert((e.parent.as_deref(), e.name.as_str())) {
            return Err(Error::InvalidFormat);
        }
        let mut parent = e.parent.as_deref();
        let mut visited = HashSet::from([e.id.as_str()]);
        while let Some(id) = parent {
            let p = by_id.get(id).ok_or(Error::InvalidFormat)?;
            if !p.is_dir || visited.len() >= 128 || !visited.insert(id) {
                return Err(Error::InvalidFormat);
            }
            parent = p.parent.as_deref();
        }
    }
    Ok(entries)
}

fn index_ad(safe: &[u8; 16], index: &[u8; 16], generation: u64) -> Vec<u8> {
    let mut ad = b"SVST0001/index".to_vec();
    ad.extend(safe);
    ad.extend(index);
    ad.extend(generation.to_le_bytes());
    ad
}
fn pieces(size: u64) -> Result<u32> {
    u32::try_from(size.div_ceil(PIECE_SIZE)).map_err(|_| Error::Limit)
}
fn piece_length(size: u64, index: u32) -> u64 {
    (size - u64::from(index) * PIECE_SIZE).min(PIECE_SIZE)
}
fn piece_stored(length: u64) -> u64 {
    19 + length + length.div_ceil(CHUNK_SIZE as u64) * 16
}
fn piece_name(revision: &[u8; 16], index: u32) -> String {
    format!("p-{}-{index:08x}", hex(revision))
}
fn integer(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(array(bytes))
}
fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().expect("validated fixed slice")
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn controlled_pending_name(version: u64, commitment: &[u8; 32]) -> Result<String> {
    if version < 2 || *commitment == [0; 32] {
        return Err(Error::InvalidFormat);
    }
    Ok(format!("c-{version:016x}-{}", hex(commitment)))
}
fn is_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}
fn unhex(s: &str) -> Result<[u8; 16]> {
    if s.len() != 32 || !s.bytes().all(is_hex) {
        return Err(Error::InvalidFormat);
    }
    let mut bytes = [0; 16];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| Error::InvalidFormat)?;
    }
    Ok(bytes)
}
