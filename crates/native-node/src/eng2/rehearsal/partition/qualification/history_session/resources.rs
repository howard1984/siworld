//! Complete, bounded metadata accounting for the explicitly selected run root.
use super::*;
use std::{fs, os::unix::fs::MetadataExt};

pub(super) struct RunGuard<'a> {
    root: &'a Path,
    device: u64,
    inode: u64,
    pub(super) budget: Budget,
    pub(super) started: Instant,
}
fn add(total: u64, next: u64, maximum: u64) -> Result<u64, String> {
    let result = total
        .checked_add(next)
        .ok_or("session run inventory overflow")?;
    if result > maximum {
        return Err("session complete run budget exceeded".into());
    }
    Ok(result)
}
impl<'a> RunGuard<'a> {
    pub(super) fn new(root: &'a Path, budget: Budget, started: Instant) -> Result<Self, String> {
        let meta =
            fs::symlink_metadata(root).map_err(|_| "session run root metadata unavailable")?;
        if !meta.is_dir() || meta.uid() != rustix::process::geteuid().as_raw() {
            return Err("session requires an existing owner run directory".into());
        }
        Ok(Self {
            root,
            device: meta.dev(),
            inode: meta.ino(),
            budget,
            started,
        })
    }
    pub(super) fn disk(&self, additional: u64) -> Result<(), String> {
        self.budget.tick(self.started, None)?;
        let stat = rustix::fs::statvfs(self.root).map_err(|_| "session disk observation failed")?;
        let free = u64::try_from(stat.f_bavail as u128 * stat.f_frsize as u128)
            .map_err(|_| "session disk observation overflow")?;
        let required = self
            .budget
            .minimum_disk_free_bytes
            .checked_add(additional)
            .ok_or("session disk floor overflow")?;
        if free < required {
            return Err("session disk free floor would be crossed".into());
        }
        Ok(())
    }
    pub(super) fn check(&self, additional: u64) -> Result<(), String> {
        self.disk(additional)?;
        let meta =
            fs::symlink_metadata(self.root).map_err(|_| "session run root metadata unavailable")?;
        if !meta.is_dir() || meta.dev() != self.device || meta.ino() != self.inode {
            return Err("session run root identity changed".into());
        }
        let mut bytes = 0u64;
        let mut entries = 0u64;
        self.walk(self.root, 0, &mut bytes, &mut entries)?;
        add(bytes, additional, self.budget.maximum_run_logical_bytes)?;
        if additional != 0 {
            add(entries, 1, self.budget.maximum_run_entries)?;
        }
        Ok(())
    }
    fn walk(
        &self,
        path: &Path,
        depth: u32,
        bytes: &mut u64,
        entries: &mut u64,
    ) -> Result<(), String> {
        self.budget.tick(self.started, None)?;
        if depth > 64 {
            return Err("session run directory nesting exceeds bound".into());
        }
        *entries = add(*entries, 1, self.budget.maximum_run_entries)?;
        let meta =
            fs::symlink_metadata(path).map_err(|_| "session complete run metadata unavailable")?;
        if meta.dev() != self.device
            || !(meta.is_file() || meta.is_dir())
            || meta.is_file() && meta.nlink() != 1
        {
            return Err(
                "session run inventory refuses links, mounts or unsupported entries".into(),
            );
        }
        if meta.is_file() {
            *bytes = add(*bytes, meta.len(), self.budget.maximum_run_logical_bytes)?;
        }
        if meta.is_dir() {
            for entry in
                fs::read_dir(path).map_err(|_| "session run directory enumeration failed")?
            {
                let entry = entry.map_err(|_| "session run directory entry unavailable")?;
                self.walk(&entry.path(), depth + 1, bytes, entries)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn logical_inventory_reserves_before_writing_and_rejects_overflow() {
        assert_eq!(add(63, 1, 64).unwrap(), 64);
        assert!(add(64, 1, 64).is_err());
        assert!(add(u64::MAX, 1, u64::MAX).is_err());
        assert!(add(10, 0, 9).is_err());
    }
}
