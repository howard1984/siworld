//! Descriptor-anchored storage, exclusive custody, and write-once publication.
use super::Result;
use rustix::fs::{
    AtFlags, FlockOperation, Mode, OFlags, flock, linkat, mkdirat, open, openat, unlinkat,
};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

const LOCK_NAME: &str = ".fund-key.lock";

pub(crate) struct Directory {
    directory: File,
    lock: File,
}
impl Directory {
    pub fn create(path: &Path) -> Result<Self> {
        let path = absolute(path)?;
        let parent = open_directory(path.parent().ok_or("key directory requires a parent")?)?;
        let name = path.file_name().ok_or("key directory requires a name")?;
        mkdirat(&parent, name, Mode::from_raw_mode(0o700))
            .map_err(|_| "key creation requires a new directory")?;
        parent
            .sync_all()
            .map_err(|_| "new key directory parent sync failed")?;
        let directory = File::from(
            openat(&parent, name, directory_flags(), Mode::empty())
                .map_err(|_| "cannot open new key directory")?,
        );
        Self::lock(directory, true)
    }
    pub fn open(path: &Path) -> Result<Self> {
        Self::lock(open_directory(&absolute(path)?)?, false)
    }
    fn lock(directory: File, create: bool) -> Result<Self> {
        check_directory(&directory)?;
        let mut flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        if create {
            flags |= OFlags::CREATE | OFlags::EXCL;
        }
        let lock = File::from(
            openat(&directory, LOCK_NAME, flags, Mode::from_raw_mode(0o600))
                .map_err(|_| "cannot open existing exclusive custody lock")?,
        );
        check_private_file(&lock)?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| "key directory is already in use")?;
        if create {
            lock.sync_all().map_err(|_| "custody lock sync failed")?;
            directory
                .sync_all()
                .map_err(|_| "custody directory sync failed")?;
        }
        Ok(Self { directory, lock })
    }
    pub fn read(&self, name: &str, maximum: usize) -> Result<Vec<u8>> {
        let file = File::from(
            openat(&self.directory, name, read_flags(), Mode::empty())
                .map_err(|_| "cannot open key custody record")?,
        );
        check_private_file(&file)?;
        bounded_read(file, maximum)
    }
    pub fn write_once(&self, name: &str, bytes: &[u8]) -> Result<()> {
        if !matches!(name, "seed.vault" | "public.json") {
            return Err("unsupported custody record name".into());
        }
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| "OS randomness unavailable")?;
        let temporary_name = format!(".fund-key-{}.tmp", super::hex(&nonce));
        let mut temporary = File::from(
            openat(
                &self.directory,
                temporary_name.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|_| "cannot create private temporary key record")?,
        );
        let cleanup = Temporary {
            directory: &self.directory,
            name: &temporary_name,
        };
        check_private_file(&temporary)?;
        temporary
            .write_all(bytes)
            .and_then(|()| temporary.sync_all())
            .map_err(|_| "cannot persist private temporary key record")?;
        // Same-filesystem hard-link creation is atomic and cannot replace an
        // existing destination, including a dangling symlink. The temporary
        // link is removed before reads enforce the one-link invariant.
        linkat(
            &self.directory,
            temporary_name.as_str(),
            &self.directory,
            name,
            AtFlags::empty(),
        )
        .map_err(|_| "key record destination already exists or cannot be published")?;
        unlinkat(&self.directory, temporary_name.as_str(), AtFlags::empty())
            .map_err(|_| "key record published but temporary link cleanup failed")?;
        drop(cleanup);
        self.directory
            .sync_all()
            .map_err(|_| "published key directory sync failed")?;
        Ok(())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        // Keep the lock inode permanently; removing it permits split ownership.
        let _ = flock(&self.lock, FlockOperation::Unlock);
    }
}
struct Temporary<'a> {
    directory: &'a File,
    name: &'a str,
}
impl Drop for Temporary<'_> {
    fn drop(&mut self) {
        let _ = unlinkat(self.directory, self.name, AtFlags::empty());
    }
}
fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}
fn read_flags() -> OFlags {
    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC
}
fn absolute(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err("key path is empty or contains parent traversal".into());
    }
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| "cannot resolve key directory")?
            .join(path)
    })
}
fn open_directory(path: &Path) -> Result<File> {
    let mut current = File::from(
        open("/", directory_flags(), Mode::empty()).map_err(|_| "cannot open filesystem root")?,
    );
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                current = File::from(
                    openat(&current, name, directory_flags(), Mode::empty())
                        .map_err(|_| "key path requires existing directories without symlinks")?,
                );
            }
            Component::ParentDir | Component::Prefix(_) => return Err("invalid key path".into()),
        }
    }
    Ok(current)
}
fn check_directory(directory: &File) -> Result<()> {
    let metadata = directory
        .metadata()
        .map_err(|_| "cannot inspect key directory")?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err("key directory requires current ownership and exact mode 0700".into());
    }
    Ok(())
}
fn check_private_file(file: &File) -> Result<()> {
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect key custody record")?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err("key records require current ownership, one link and exact mode 0600".into());
    }
    Ok(())
}
fn bounded_read(file: File, maximum: usize) -> Result<Vec<u8>> {
    if file
        .metadata()
        .map_err(|_| "cannot inspect key record length")?
        .len()
        > maximum as u64
    {
        return Err("key record exceeds its size limit".into());
    }
    let mut bytes = Vec::with_capacity(maximum);
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read key record")?;
    if bytes.len() > maximum {
        return Err("key record exceeds its size limit".into());
    }
    Ok(bytes)
}

/// Public exports need not have private-file modes or current ownership.
/// Symlinks, hard links and nonregular/unbounded files are still rejected.
pub(crate) fn read_public(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let path = absolute(path)?;
    let parent = open_directory(path.parent().ok_or("public record requires a parent")?)?;
    let name = path.file_name().ok_or("public record requires a name")?;
    let file = File::from(
        openat(&parent, name, read_flags(), Mode::empty())
            .map_err(|_| "cannot open public key record")?,
    );
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect public record")?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err("public key record requires a regular file with one link".into());
    }
    bounded_read(file, maximum)
}
