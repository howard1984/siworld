//! Owner-only, descriptor-relative, write-once local custody.
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, String>;
fn failure() -> String {
    "engineering material storage rejected".into()
}
fn flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}
fn absolute(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty()
        || path.components().any(|x| {
            matches!(x, Component::ParentDir | Component::Prefix(_))
                || matches!(x, Component::Normal(name) if name == ".git")
        })
    {
        return Err(failure());
    }
    Ok(if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir().map_err(|_| failure())?.join(path)
    })
}
fn directory(path: &Path, outside_repository: bool) -> Result<File> {
    let mut current = File::from(fs::open("/", flags(), Mode::empty()).map_err(|_| failure())?);
    for part in path.components() {
        match part {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                if outside_repository
                    && fs::statat(&current, ".git", AtFlags::SYMLINK_NOFOLLOW).is_ok()
                {
                    return Err(failure());
                }
                current = File::from(
                    fs::openat(&current, name, flags(), Mode::empty()).map_err(|_| failure())?,
                );
            }
            _ => return Err(failure()),
        }
    }
    if outside_repository && fs::statat(&current, ".git", AtFlags::SYMLINK_NOFOLLOW).is_ok() {
        return Err(failure());
    }
    Ok(current)
}
fn private_directory(file: &File) -> Result<()> {
    let s = fs::fstat(file).map_err(|_| failure())?;
    if FileType::from_raw_mode(s.st_mode) != FileType::Directory
        || s.st_uid != rustix::process::geteuid().as_raw()
        || s.st_mode & 0o7777 != 0o700
    {
        return Err(failure());
    }
    Ok(())
}
pub(super) struct Directory(File);
impl Directory {
    pub(super) fn create(path: &Path) -> Result<Self> {
        let path = absolute(path)?;
        let parent = directory(path.parent().ok_or_else(failure)?, true)?;
        let name = path.file_name().ok_or_else(failure)?;
        fs::mkdirat(&parent, name, Mode::from_raw_mode(0o700)).map_err(|_| failure())?;
        fs::fsync(&parent).map_err(|_| failure())?;
        let file =
            File::from(fs::openat(&parent, name, flags(), Mode::empty()).map_err(|_| failure())?);
        private_directory(&file)?;
        Ok(Self(file))
    }
    pub(super) fn open(path: &Path) -> Result<Self> {
        let file = directory(&absolute(path)?, true)?;
        private_directory(&file)?;
        Ok(Self(file))
    }
    pub(super) fn write_once(&self, name: &str, bytes: &[u8]) -> Result<()> {
        if !matches!(
            name,
            "pending.secret" | "public.json" | "checkpoint-bound.secret"
        ) {
            return Err(failure());
        }
        // An atomic hard-link publishes a fully synced file without replacing
        // an existing file, directory or dangling symlink.
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(|_| "OS randomness unavailable")?;
        let temporary = format!(".eng2-material-{}.tmp", crate::local::hex(&nonce));
        let mut file = File::from(
            fs::openat(
                &self.0,
                temporary.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|_| failure())?,
        );
        let result = (|| {
            let stat = fs::fstat(&file).map_err(|_| failure())?;
            if stat.st_mode & 0o7777 != 0o600
                || stat.st_uid != rustix::process::geteuid().as_raw()
                || stat.st_nlink != 1
            {
                return Err(failure());
            }
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|_| failure())?;
            fs::linkat(&self.0, temporary.as_str(), &self.0, name, AtFlags::empty())
                .map_err(|_| failure())?;
            Ok(())
        })();
        let cleanup =
            fs::unlinkat(&self.0, temporary.as_str(), AtFlags::empty()).map_err(|_| failure());
        fs::fsync(&self.0).map_err(|_| failure())?;
        result?;
        cleanup
    }
    pub(super) fn read(&self, name: &str, size: usize) -> Result<Zeroizing<Vec<u8>>> {
        let file = File::from(
            fs::openat(
                &self.0,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| failure())?,
        );
        let stat = fs::fstat(&file).map_err(|_| failure())?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_mode & 0o7777 != 0o600
            || stat.st_nlink != 1
            || stat.st_size != size as i64
        {
            return Err(failure());
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(size + 1));
        file.take((size + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| failure())?;
        if bytes.len() != size {
            return Err(failure());
        }
        Ok(bytes)
    }
}
pub(super) fn read_public(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let path = absolute(path)?;
    let parent = directory(path.parent().ok_or_else(failure)?, false)?;
    let file = File::from(
        fs::openat(
            &parent,
            path.file_name().ok_or_else(failure)?,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| failure())?,
    );
    let s = fs::fstat(&file).map_err(|_| failure())?;
    if FileType::from_raw_mode(s.st_mode) != FileType::RegularFile
        || s.st_nlink != 1
        || s.st_size < 0
        || s.st_size as u64 > maximum as u64
    {
        return Err(failure());
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| failure())?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(failure());
    }
    Ok(bytes)
}
