//! Fixed-name, owner-only mailbox files confined to an opened directory.
use super::*;
use rustix::fs::{AtFlags, Mode, OFlags, mkdirat, openat, renameat, unlinkat};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
};

pub(super) struct Files(File);
pub(super) struct Lock(File);
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}
impl Files {
    pub(super) fn open(directory: &Path) -> Result<Self, String> {
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags((OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC).bits() as i32)
            .open(directory)
            .map_err(|_| "operations owner directory unavailable")?;
        Self::check(&parent, true, 0)?;
        match mkdirat(&parent, "eng2-operations", Mode::from_raw_mode(0o700)) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => (),
            Err(_) => return Err("operations mailbox directory creation failed".into()),
        }
        let root = File::from(
            openat(
                &parent,
                "eng2-operations",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| "operations mailbox unavailable")?,
        );
        Self::check(&root, true, 0)?;
        Ok(Self(root))
    }
    fn check(file: &File, directory: bool, limit: usize) -> Result<(), String> {
        let meta = file
            .metadata()
            .map_err(|_| "operations metadata unavailable")?;
        if meta.uid() != rustix::process::geteuid().as_raw()
            || (directory && (!meta.is_dir() || meta.permissions().mode() & 0o777 != 0o700))
            || (!directory
                && (!meta.is_file()
                    || meta.nlink() != 1
                    || meta.permissions().mode() & 0o777 != 0o600
                    || meta.len() > limit as u64))
        {
            return Err("operations file ownership, type, permissions or bound rejected".into());
        }
        Ok(())
    }
    pub(super) fn lock(&self) -> Result<Lock, String> {
        Self::check(&self.0, true, 0)?;
        let file = File::from(
            openat(
                &self.0,
                "lock",
                OFlags::RDWR
                    | OFlags::CREATE
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC
                    | OFlags::NONBLOCK,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|_| "operations lock unavailable")?,
        );
        Self::check(&file, false, 0)?;
        // Bound contention with ordinary owner-local status queries. No
        // unbounded OS lock wait can delay the canonical owner indefinitely.
        let started = Instant::now();
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Lock(file)),
                Err(std::fs::TryLockError::WouldBlock)
                    if started.elapsed() < Duration::from_secs(1) =>
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return Err("operations mailbox lock unavailable".into()),
            }
        }
    }
    pub(super) fn read(&self, name: &str, limit: usize) -> Result<Option<Vec<u8>>, String> {
        let fd = match openat(
            &self.0,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => return Err("operations file unavailable".into()),
        };
        let file = File::from(fd);
        Self::check(&file, false, limit)?;
        let mut bytes = Vec::new();
        file.take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "operations file read failed")?;
        if bytes.len() > limit {
            return Err("operations byte bound exceeded".into());
        }
        Ok(Some(bytes))
    }
    pub(super) fn remove(&self, name: &str, limit: usize) -> Result<(), String> {
        if self.read(name, limit)?.is_some() {
            unlinkat(&self.0, name, AtFlags::empty())
                .map_err(|_| "operations request consumption failed")?;
            self.0
                .sync_all()
                .map_err(|_| "operations directory durability failed")?;
        }
        Ok(())
    }
    pub(super) fn replace(&self, name: &str, bytes: &[u8], limit: usize) -> Result<(), String> {
        if bytes.len() > limit {
            return Err("operations byte bound exceeded".into());
        }
        self.read(name, limit)?;
        // A fixed temporary bounds crash debris. Only a checked ordinary file
        // under the dedicated mailbox may be consumed; permanent data is absent.
        self.remove("writing", MAX_REQUEST_BYTES)?;
        let mut file = File::from(
            openat(
                &self.0,
                "writing",
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|_| "operations temporary creation failed")?,
        );
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| "operations temporary durability failed")?;
        renameat(&self.0, "writing", &self.0, name)
            .map_err(|_| "operations atomic replacement failed")?;
        self.0
            .sync_all()
            .map_err(|_| "operations directory durability failed".into())
    }
}
