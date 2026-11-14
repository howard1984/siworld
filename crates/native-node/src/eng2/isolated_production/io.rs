//! Descriptor-confined, bounded, immutable owner-local control records.
use super::{DIRECTORY, MAX_BYTES};
use rustix::fs::{AtFlags, Mode, OFlags, mkdirat, openat, unlinkat};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
fn checked(file: &File, directory: bool) -> Result<(), String> {
    let meta = file
        .metadata()
        .map_err(|_| "isolated control metadata unavailable")?;
    if meta.uid() != rustix::process::geteuid().as_raw()
        || (directory && (!meta.is_dir() || meta.permissions().mode() & 0o777 != 0o700))
        || (!directory
            && (!meta.is_file()
                || meta.nlink() != 1
                || meta.permissions().mode() & 0o777 != 0o600
                || meta.len() == 0
                || meta.len() > MAX_BYTES as u64))
    {
        return Err("isolated control ownership, type, mode or bound rejected".into());
    }
    Ok(())
}
fn directory(path: &Path) -> Result<File, String> {
    if !path.is_absolute() || path.canonicalize().ok().as_deref() != Some(path) {
        return Err("isolated control canonical absolute directory required".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC).bits() as i32)
        .open(path)
        .map_err(|_| "isolated control directory unavailable")?;
    checked(&file, true)?;
    Ok(file)
}
fn bytes(file: File) -> Result<Vec<u8>, String> {
    checked(&file, false)?;
    let mut bytes = Vec::new();
    file.take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "isolated control bounded read failed")?;
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err("isolated control byte bound rejected".into());
    }
    Ok(bytes)
}
pub(super) fn input(path: &Path) -> Result<Vec<u8>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK).bits() as i32)
        .open(path)
        .map_err(|_| "isolated control input unavailable")?;
    bytes(file)
}
pub(super) struct Files {
    node: File,
    root: File,
    path: PathBuf,
}
impl Files {
    pub(super) fn exists(node: &Path) -> Result<bool, String> {
        match fs::symlink_metadata(node.join(DIRECTORY)) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err("isolated control path unavailable".into()),
        }
    }
    pub(super) fn initialize(node: &Path) -> Result<Self, String> {
        let parent = directory(node)?;
        mkdirat(&parent, DIRECTORY, Mode::from_raw_mode(0o700))
            .map_err(|_| "isolated control directory must be absent")?;
        parent
            .sync_all()
            .map_err(|_| "isolated control parent durability failed")?;
        Self::open(node)
    }
    pub(super) fn open(node: &Path) -> Result<Self, String> {
        let parent = directory(node)?;
        let root = File::from(
            openat(
                &parent,
                DIRECTORY,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| "isolated control records unavailable")?,
        );
        checked(&root, true)?;
        Ok(Self {
            node: parent,
            root,
            path: node.into(),
        })
    }
    fn current(&self) -> Result<(), String> {
        checked(&self.node, true)?;
        checked(&self.root, true)?;
        let current_node = directory(&self.path)?;
        let current_root = File::from(
            openat(
                &current_node,
                DIRECTORY,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| "isolated control directory disappeared")?,
        );
        checked(&current_root, true)?;
        for (old, current) in [(&self.node, &current_node), (&self.root, &current_root)] {
            let a = old
                .metadata()
                .map_err(|_| "isolated control identity unavailable")?;
            let b = current
                .metadata()
                .map_err(|_| "isolated control identity unavailable")?;
            if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
                return Err("isolated control directory identity changed".into());
            }
        }
        Ok(())
    }
    pub(super) fn read(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
        self.current()?;
        let file = match openat(
            &self.root,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(file) => File::from(file),
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => return Err("isolated control record unavailable".into()),
        };
        bytes(file).map(Some)
    }
    pub(super) fn required(&self, name: &str) -> Result<Vec<u8>, String> {
        self.read(name)?
            .ok_or_else(|| "isolated control record disappeared".into())
    }
    pub(super) fn create(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        self.current()?;
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err("isolated control output byte bound rejected".into());
        }
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce)
            .map_err(|_| "isolated control temporary entropy unavailable")?;
        let temporary = format!("writing-{}", crate::local::hex(&nonce));
        let result = (|| {
            let mut file = File::from(
                openat(
                    &self.root,
                    temporary.as_str(),
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600),
                )
                .map_err(|_| "isolated control temporary creation failed")?,
            );
            file.write_all(bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| "isolated control output durability failed")?;
            checked(&file, false)?;
            self.install(&temporary, name)?;
            self.root
                .sync_all()
                .map_err(|_| "isolated control directory durability failed".into())
        })();
        // Only this invocation's uninstalled temporary record may be removed.
        let _ = unlinkat(&self.root, temporary.as_str(), AtFlags::empty());
        result
    }
    #[cfg(any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android",
        target_os = "redox"
    ))]
    fn install(&self, temporary: &str, name: &str) -> Result<(), String> {
        rustix::fs::renameat_with(
            &self.root,
            temporary,
            &self.root,
            name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|_| "isolated control record must be absent".into())
    }
    #[cfg(not(any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android",
        target_os = "redox"
    )))]
    fn install(&self, _temporary: &str, _name: &str) -> Result<(), String> {
        Err("isolated control atomic installation unsupported on this platform".into())
    }
}
