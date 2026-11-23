//! Anchored owner-only Unix storage. Non-Unix platforms fail closed.
use super::{VAULT_FILENAME, VAULT_LEN};
use std::path::Path;

#[cfg(unix)]
mod unix {
    use super::*;
    use rustix::fs::{
        AtFlags, FlockOperation, Mode, OFlags, flock, linkat, mkdirat, open, openat, renameat,
        unlinkat,
    };
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::unix::fs::MetadataExt;
    use std::path::{Component, PathBuf};

    const LOCK_NAME: &str = ".wallet.lock";

    pub struct Directory {
        directory: File,
        lock: File,
    }
    impl Directory {
        pub fn create(path: &Path) -> Result<Self, String> {
            let path = absolute(path)?;
            let parent = open_directory(path.parent().ok_or("wallet directory needs a parent")?)?;
            let name = path.file_name().ok_or("wallet directory needs a name")?;
            mkdirat(&parent, name, Mode::from_raw_mode(0o700))
                .map_err(|_| "wallet creation requires a new directory")?;
            parent
                .sync_all()
                .map_err(|_| "wallet directory created; parent sync failed")?;
            let directory = file(
                openat(&parent, name, directory_flags(), Mode::empty())
                    .map_err(|_| "cannot open new wallet directory")?,
            );
            Self::lock(directory, true)
        }

        pub fn open(path: &Path) -> Result<Self, String> {
            Self::lock(open_directory(&absolute(path)?)?, false)
        }

        fn lock(directory: File, create: bool) -> Result<Self, String> {
            check_directory(&directory)?;
            let lock = file(
                openat(
                    &directory,
                    LOCK_NAME,
                    OFlags::RDWR
                        | if create {
                            OFlags::CREATE
                        } else {
                            OFlags::empty()
                        }
                        | OFlags::NOFOLLOW
                        | OFlags::NONBLOCK
                        | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600),
                )
                .map_err(|_| "cannot open wallet ownership lock")?,
            );
            check_file(&lock)?;
            flock(&lock, FlockOperation::NonBlockingLockExclusive)
                .map_err(|_| "wallet directory is already in use")?;
            // Keep the stable lock inode; deleting it would permit two owners.
            Ok(Self { directory, lock })
        }

        pub fn check_owner(&self) -> Result<(), String> {
            check_directory(&self.directory)?;
            check_file(&self.lock)?;
            let current = file(
                openat(
                    &self.directory,
                    LOCK_NAME,
                    OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| "wallet ownership lock was removed or altered")?,
            );
            check_file(&current)?;
            let expected = self
                .lock
                .metadata()
                .map_err(|_| "cannot inspect wallet ownership")?;
            let current = current
                .metadata()
                .map_err(|_| "cannot inspect wallet ownership")?;
            if (expected.dev(), expected.ino()) != (current.dev(), current.ino()) {
                return Err("wallet ownership lock inode changed".into());
            }
            Ok(())
        }

        #[cfg(feature = "eng2-rehearsal")]
        pub fn write_rehearsal_binding(&self, bytes: &[u8]) -> Result<(), String> {
            if bytes.is_empty() || bytes.len() > 8192 {
                return Err("isolated wallet public binding exceeds bound".into());
            }
            self.write_private("rehearsal.json", bytes, false, || Ok(()))
        }

        #[cfg(feature = "eng2-rehearsal")]
        pub fn read_rehearsal_binding(&self) -> Result<Vec<u8>, String> {
            self.read_private("rehearsal.json", 8192)
        }

        pub fn read_vault(&self) -> Result<Vec<u8>, String> {
            let encoded = self.read_private(VAULT_FILENAME, VAULT_LEN)?;
            if encoded.len() != VAULT_LEN {
                return Err("invalid native wallet vault length".into());
            }
            Ok(encoded)
        }

        pub fn read_journal(&self) -> Result<Vec<u8>, String> {
            self.read_private("payments.journal", super::super::journal::MAX_FILE)
        }

        fn read_private(&self, name: &str, maximum: usize) -> Result<Vec<u8>, String> {
            self.check_owner()?;
            let vault = file(
                openat(
                    &self.directory,
                    name,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| "cannot open native wallet vault")?,
            );
            check_file(&vault)?;
            if vault
                .metadata()
                .map_err(|_| "cannot inspect wallet vault")?
                .len()
                > maximum as u64
            {
                return Err("invalid native wallet vault length".into());
            }
            let mut encoded = Vec::new();
            vault
                .take(maximum as u64 + 1)
                .read_to_end(&mut encoded)
                .map_err(|_| "cannot read native wallet vault")?;
            if encoded.len() > maximum {
                return Err("invalid native wallet vault length".into());
            }
            Ok(encoded)
        }

        pub fn publish_with(
            &self,
            encoded: &[u8],
            before_publish: impl FnOnce() -> Result<(), String>,
        ) -> Result<(), String> {
            self.write_private(VAULT_FILENAME, encoded, false, before_publish)
        }

        pub fn create_journal(&self, encoded: &[u8]) -> Result<(), String> {
            self.write_private("payments.journal", encoded, false, || Ok(()))
        }

        pub fn replace_journal(&self, encoded: &[u8]) -> Result<(), String> {
            let _ = self.read_journal()?;
            self.write_private("payments.journal", encoded, true, || Ok(()))
        }

        fn write_private(
            &self,
            name: &str,
            encoded: &[u8],
            replace: bool,
            before_publish: impl FnOnce() -> Result<(), String>,
        ) -> Result<(), String> {
            self.check_owner()?;
            let mut random = [0; 16];
            getrandom::fill(&mut random).map_err(|_| "OS randomness unavailable")?;
            let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
            let temporary_name = format!(".seed-vault-{suffix}.tmp");
            let mut temporary_file = file(
                openat(
                    &self.directory,
                    temporary_name.as_str(),
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600),
                )
                .map_err(|_| "cannot create private temporary wallet vault")?,
            );
            let cleanup = Temporary {
                directory: &self.directory,
                name: temporary_name.as_str(),
            };
            check_file(&temporary_file)?;
            temporary_file
                .write_all(encoded)
                .and_then(|()| temporary_file.sync_all())
                .map_err(|_| "cannot persist temporary wallet vault")?;
            before_publish()?;
            // A same-directory hard link publishes complete data atomically and
            // rejects every existing target, including a dangling symlink.
            if replace {
                renameat(
                    &self.directory,
                    temporary_name.as_str(),
                    &self.directory,
                    name,
                )
                .map_err(|_| "cannot atomically replace private wallet journal")?;
            } else {
                linkat(
                    &self.directory,
                    temporary_name.as_str(),
                    &self.directory,
                    name,
                    AtFlags::empty(),
                )
                .map_err(|_| "cannot publish private wallet file; destination may already exist")?;
                unlinkat(&self.directory, temporary_name.as_str(), AtFlags::empty())
                    .map_err(|_| "private wallet file published; temporary link cleanup failed")?;
            }
            drop(cleanup);
            self.directory
                .sync_all()
                .map_err(|_| "wallet vault published; directory sync failed")?;
            Ok(())
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            // Explicit unlock also releases an inherited duplicate open-file
            // description after the owning wallet operation has finished.
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

    fn file(fd: rustix::fd::OwnedFd) -> File {
        File::from(fd)
    }

    fn directory_flags() -> OFlags {
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
    }

    fn absolute(path: &Path) -> Result<PathBuf, String> {
        if path.as_os_str().is_empty() {
            return Err("wallet directory path is empty".into());
        }
        if path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::Prefix(_)))
        {
            return Err("wallet directory may not contain parent traversal or a prefix".into());
        }
        if path.is_absolute() {
            Ok(path.to_path_buf())
        } else {
            Ok(std::env::current_dir()
                .map_err(|_| "cannot resolve wallet directory")?
                .join(path))
        }
    }

    /// Walk through pinned directory descriptors; never resolve a symlink in
    /// an ancestor or access a secret via a second path lookup.
    fn open_directory(path: &Path) -> Result<File, String> {
        let mut current = file(
            open("/", directory_flags(), Mode::empty())
                .map_err(|_| "cannot open filesystem root")?,
        );
        for part in path.components() {
            match part {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(name) => {
                    current = file(
                        openat(&current, name, directory_flags(), Mode::empty()).map_err(
                            |_| "wallet path requires existing directories without symlinks",
                        )?,
                    );
                }
                Component::ParentDir | Component::Prefix(_) => {
                    return Err("invalid wallet directory path".into());
                }
            }
        }
        Ok(current)
    }

    fn check_directory(directory: &File) -> Result<(), String> {
        let metadata = directory
            .metadata()
            .map_err(|_| "cannot inspect wallet directory")?;
        if !metadata.is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
        {
            return Err(
                "wallet directory must be owned by this user with mode 0700 or stricter".into(),
            );
        }
        Ok(())
    }

    fn check_file(file: &File) -> Result<(), String> {
        let metadata = file
            .metadata()
            .map_err(|_| "cannot inspect wallet custody file")?;
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(
                "wallet custody files require one link, this owner and mode 0600 or stricter"
                    .into(),
            );
        }
        Ok(())
    }
}

#[cfg(unix)]
pub use unix::Directory;

#[cfg(windows)]
pub use windows::Directory;
#[cfg(windows)]
mod windows {
    use super::*;
    use std::ffi::OsStr;
    use std::fs::File;
    pub struct Directory {
        directory: siworld_miner_platform::Directory,
        lock: File,
    }
    impl Directory {
        pub fn create(path: &Path) -> Result<Self, String> {
            let directory = siworld_miner_platform::Directory::create(path)?;
            let lock = directory.create_file(OsStr::new(".wallet.lock"))?;
            Self::lock(directory, lock)
        }
        pub fn open(path: &Path) -> Result<Self, String> {
            let directory = siworld_miner_platform::Directory::open(path)?;
            let lock = directory.open_file(OsStr::new(".wallet.lock"), true)?;
            Self::lock(directory, lock)
        }
        fn lock(directory: siworld_miner_platform::Directory, lock: File) -> Result<Self, String> {
            lock.try_lock()
                .map_err(|_| "wallet directory is already in use")?;
            let owner = Self { directory, lock };
            owner.check_owner()?;
            Ok(owner)
        }
        pub fn check_owner(&self) -> Result<(), String> {
            self.directory.check()?;
            siworld_miner_platform::check_private(&self.lock, false)?;
            let current = self.directory.open_file(OsStr::new(".wallet.lock"), true)?;
            if siworld_miner_platform::file_identity(&current)?
                != siworld_miner_platform::file_identity(&self.lock)?
            {
                return Err("wallet ownership lock changed".into());
            }
            Ok(())
        }
        #[cfg(feature = "eng2-rehearsal")]
        pub fn write_rehearsal_binding(&self, bytes: &[u8]) -> Result<(), String> {
            if bytes.is_empty() || bytes.len() > 8192 {
                return Err("isolated wallet public binding exceeds bound".into());
            }
            self.write_private("rehearsal.json", bytes, false, || Ok(()))
        }

        #[cfg(feature = "eng2-rehearsal")]
        pub fn read_rehearsal_binding(&self) -> Result<Vec<u8>, String> {
            self.read_private("rehearsal.json", 8192)
        }

        pub fn read_vault(&self) -> Result<Vec<u8>, String> {
            self.check_owner()?;
            let bytes = self.directory.read(VAULT_FILENAME, VAULT_LEN)?;
            if bytes.len() != VAULT_LEN {
                return Err("invalid native wallet vault length".into());
            }
            Ok(bytes)
        }
        pub fn read_journal(&self) -> Result<Vec<u8>, String> {
            self.check_owner()?;
            self.directory
                .read("payments.journal", super::super::journal::MAX_FILE)
        }
        pub fn create_journal(&self, bytes: &[u8]) -> Result<(), String> {
            self.check_owner()?;
            self.directory.write_once("payments.journal", bytes)
        }
        pub fn replace_journal(&self, bytes: &[u8]) -> Result<(), String> {
            let _ = self.read_journal()?;
            self.directory.replace("payments.journal", bytes)
        }
        pub fn publish_with(
            &self,
            bytes: &[u8],
            before_publish: impl FnOnce() -> Result<(), String>,
        ) -> Result<(), String> {
            self.check_owner()?;
            self.directory.publish(VAULT_FILENAME, bytes, || {
                before_publish()?;
                self.check_owner()
            })
        }
    }
}

#[cfg(not(any(unix, windows)))]
pub struct Directory;
#[cfg(not(any(unix, windows)))]
impl Directory {
    pub fn check_owner(&self) -> Result<(), String> {
        Err("native wallet protected storage is supported only on Unix".into())
    }
    pub fn create(_: &Path) -> Result<Self, String> {
        Err("native wallet protected storage is supported only on Unix".into())
    }
    pub fn open(_: &Path) -> Result<Self, String> {
        Err("native wallet protected storage is supported only on Unix".into())
    }
    pub fn read_vault(&self) -> Result<Vec<u8>, String> {
        Err("native wallet protected storage is supported only on Unix".into())
    }
    pub fn read_journal(&self) -> Result<Vec<u8>, String> {
        Err("native wallet protected storage is supported only on Unix".into())
    }
    pub fn create_journal(&self, _: &[u8]) -> Result<(), String> {
        Err("native wallet protected storage is supported only on Unix".into())
    }
    pub fn replace_journal(&self, _: &[u8]) -> Result<(), String> {
        Err("native wallet protected storage is supported only on Unix".into())
    }
    pub fn publish_with(
        &self,
        _: &[u8],
        _: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        Err("native wallet protected storage is supported only on Unix".into())
    }
}
