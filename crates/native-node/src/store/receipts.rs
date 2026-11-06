//! Bind private receipt writes to the already opened canonical store.
use crate::wire::Hash;
use std::fs::File;
use std::path::Path;

#[cfg(unix)]
pub(super) struct Owner {
    directory: File,
    path: std::path::PathBuf,
    database_name: std::ffi::OsString,
    database_identity: std::fs::Metadata,
}
#[cfg(unix)]
impl Owner {
    pub(super) fn bind(path: &Path, database: &File) -> Result<Self, String> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let path_parent =
            std::fs::canonicalize(parent).map_err(|_| "native receipt directory unavailable")?;
        let directory =
            File::open(&path_parent).map_err(|_| "native receipt directory unavailable")?;
        let owner = Self {
            directory,
            path: path_parent,
            database_name: path
                .file_name()
                .ok_or("native database filename unavailable")?
                .to_owned(),
            database_identity: database
                .metadata()
                .map_err(|_| "native database identity unavailable")?,
        };
        owner.check(false)?;
        Ok(owner)
    }
    fn check(&self, private: bool) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt;
        let opened = self
            .directory
            .metadata()
            .map_err(|_| "native receipt directory unavailable")?;
        let named = std::fs::symlink_metadata(&self.path)
            .map_err(|_| "native receipt directory changed")?;
        let database = std::fs::symlink_metadata(self.path.join(&self.database_name))
            .map_err(|_| "native receipt database changed")?;
        if !opened.is_dir()
            || !named.is_dir()
            || named.file_type().is_symlink()
            || !super::same_file(&opened, &named)
            || !database.is_file()
            || database.file_type().is_symlink()
            || !super::same_file(&self.database_identity, &database)
            || (private
                && (opened.uid() != rustix::process::geteuid().as_raw()
                    || opened.mode() & 0o077 != 0
                    || database.uid() != opened.uid()
                    || database.mode() & 0o077 != 0
                    || database.nlink() != 1))
        {
            return Err("native receipt storage ownership changed or is not private".into());
        }
        Ok(())
    }
    pub(super) fn save(&self, id: &Hash, secret: &[u8]) -> Result<(), String> {
        self.check(true)?;
        crate::local::save_reward_at(&self.directory, id, secret)?;
        self.check(true)
    }
    pub(super) fn read(&self, id: &Hash) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
        self.check(true)?;
        let secret = crate::local::read_reward_at(&self.directory, id)?;
        self.check(true)?;
        Ok(secret)
    }
}

#[cfg(windows)]
pub(super) struct Owner {
    directory: siworld_miner_platform::Directory,
    database_name: std::ffi::OsString,
    identity: (u32, u64),
}
#[cfg(windows)]
impl Owner {
    pub(super) fn bind(path: &Path, database: &File) -> Result<Self, String> {
        let owner = Self {
            directory: siworld_miner_platform::Directory::open(
                path.parent().ok_or("database parent unavailable")?,
            )?,
            database_name: path
                .file_name()
                .ok_or("database filename unavailable")?
                .to_owned(),
            identity: siworld_miner_platform::file_identity(database)?,
        };
        owner.check()?;
        Ok(owner)
    }
    fn check(&self) -> Result<(), String> {
        self.directory.check()?;
        let database = self.directory.open_file(&self.database_name, false)?;
        if siworld_miner_platform::file_identity(&database)? != self.identity {
            return Err("native receipt database identity changed".into());
        }
        Ok(())
    }
    pub(super) fn save(&self, id: &Hash, secret: &[u8]) -> Result<(), String> {
        self.check()?;
        if secret.is_empty() || secret.len() > crate::producer::MAX_REWARD_SECRET_BYTES {
            return Err("invalid reward receipt size".into());
        }
        let name = format!("reward-{}.secret", crate::local::hex(id));
        match self.directory.write_once(&name, secret) {
            Ok(()) => (),
            Err(_) => {
                let existing = zeroize::Zeroizing::new(
                    self.directory
                        .read(&name, crate::producer::MAX_REWARD_SECRET_BYTES)?,
                );
                if existing.len() != secret.len()
                    || existing
                        .iter()
                        .zip(secret)
                        .fold(0u8, |d, (a, b)| d | (a ^ b))
                        != 0
                {
                    return Err("existing reward evidence differs; preserved".into());
                }
                self.directory
                    .open_file(std::ffi::OsStr::new(&name), true)?
                    .sync_all()
                    .map_err(|_| "reward durability failed")?;
            }
        }
        self.check()
    }
    pub(super) fn read(&self, id: &Hash) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
        self.check()?;
        let bytes = zeroize::Zeroizing::new(self.directory.read(
            &format!("reward-{}.secret", crate::local::hex(id)),
            crate::producer::MAX_REWARD_SECRET_BYTES,
        )?);
        self.check()?;
        Ok(bytes)
    }
}

#[cfg(not(any(unix, windows)))]
pub(super) struct Owner;
#[cfg(not(any(unix, windows)))]
impl Owner {
    pub(super) fn bind(_: &Path, _: &File) -> Result<Self, String> {
        Ok(Self)
    }
    pub(super) fn save(&self, _: &Hash, _: &[u8]) -> Result<(), String> {
        Err("store-owned reward receipts require a qualified Unix platform".into())
    }
    pub(super) fn read(&self, _: &Hash) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
        Err("store-owned reward receipts require a qualified Unix platform".into())
    }
}
