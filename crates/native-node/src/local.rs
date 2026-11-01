//! Write-once local configuration and protected engineering reward receipts.
use crate::state::Config;
use crate::wire::Hash;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;
const MAGIC: &[u8; 8] = b"SWNDv4\0\0";
const CONFIG_BYTES: usize = 8 + crate::state::CONFIG_RULE_BYTES;
const CONFIG_FILE: &str = "engineering-network.bin";
const MAX_REWARD_SECRET: usize = crate::producer::MAX_REWARD_SECRET_BYTES;
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn check_directory(path: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "engineering directory unavailable")?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err("expected a real engineering directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err("engineering directory permissions are not private".into());
        }
    }
    Ok(())
}
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev() && a.ino() == b.ino()
    }
    #[cfg(not(unix))]
    {
        a.len() == b.len() && a.modified().ok() == b.modified().ok()
    }
}
pub(crate) fn regular_read(path: &Path, private: bool, max: usize) -> Result<File, String> {
    let before = fs::symlink_metadata(path).map_err(|_| "local file unavailable")?;
    if !before.is_file()
        || before.file_type().is_symlink()
        || before.len() == 0
        || before.len() > max as u64
    {
        return Err("invalid local file shape".into());
    }
    let file = File::open(path).map_err(|_| "local file read unavailable")?;
    let opened = file
        .metadata()
        .map_err(|_| "local file metadata unavailable")?;
    let after = fs::symlink_metadata(path).map_err(|_| "local file changed while opening")?;
    if !after.is_file()
        || !same_file(&before, &opened)
        || !same_file(&opened, &after)
        || opened.len() == 0
        || opened.len() > max as u64
    {
        return Err("local file changed while opening".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if private && opened.permissions().mode() & 0o077 != 0 {
            return Err("local private file permissions are not private".into());
        }
    }
    #[cfg(not(unix))]
    let _ = private;
    Ok(file)
}
fn private_new(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|_| "refusing to overwrite or open private material".into())
}
fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|_| "directory durability failed".into())
}
pub fn initialize(path: &Path, work_bits: u8) -> Result<Config, String> {
    let mut network = [0; 32];
    getrandom::fill(&mut network).map_err(|_| "OS entropy unavailable")?;
    initialize_config(path, Config::development(network, work_bits)?)
}
pub fn initialize_asert(
    path: &Path,
    genesis_timestamp: u64,
    target: Hash,
    pow_iterations: u64,
) -> Result<Config, String> {
    let mut network = [0; 32];
    getrandom::fill(&mut network).map_err(|_| "OS entropy unavailable")?;
    initialize_config(
        path,
        Config::asert_development(network, genesis_timestamp, target, pow_iterations)?
            .with_test_fund_registry()?,
    )
}
pub fn initialize_config(path: &Path, config: Config) -> Result<Config, String> {
    config.validate()?;
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .map_err(|_| "initialization requires a new directory with an existing parent")?;
    let mut file = private_new(&path.join(CONFIG_FILE))?;
    file.write_all(MAGIC)
        .and_then(|_| file.write_all(&config.encode_rules()))
        .and_then(|_| file.sync_all())
        .map_err(|_| "configuration durability failed")?;
    sync_directory(path)?;
    sync_directory(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new(".")),
    )?;
    Ok(config)
}
pub fn load(path: &Path) -> Result<Config, String> {
    check_directory(path)?;
    let file = regular_read(&path.join(CONFIG_FILE), true, CONFIG_BYTES)?;
    let mut bytes = Vec::with_capacity(CONFIG_BYTES);
    file.take((CONFIG_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read engineering configuration")?;
    if bytes.len() != CONFIG_BYTES || &bytes[..8] != MAGIC {
        return Err("unsupported engineering configuration; no automatic migration".into());
    }
    Config::decode_rules(&bytes[8..])
}

fn reward_path(path: &Path, id: &Hash) -> PathBuf {
    path.join(format!("reward-{}.secret", hex(id)))
}
pub fn save_reward(path: &Path, id: &Hash, secret: &[u8]) -> Result<(), String> {
    check_directory(path)?;
    if secret.is_empty() || secret.len() > MAX_REWARD_SECRET {
        return Err("invalid reward receipt size".into());
    }
    let mut file = private_new(&reward_path(path, id))?;
    file.write_all(secret)
        .and_then(|_| file.sync_all())
        .map_err(|_| "reward receipt durability failed")?;
    sync_directory(path)
}

/// Store-owned descriptor path. The owner verifies that both this directory and
/// its database entry still identify the opened store before and after writing.
#[cfg(unix)]
pub(crate) fn save_reward_at(directory: &File, id: &Hash, secret: &[u8]) -> Result<(), String> {
    use rustix::fs::{self, FileType, Mode, OFlags};
    let stat = fs::fstat(directory).map_err(|_| "reward directory metadata unavailable")?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o077 != 0
        || secret.is_empty()
        || secret.len() > MAX_REWARD_SECRET
    {
        return Err("invalid private reward directory or receipt".into());
    }
    let name = format!("reward-{}.secret", hex(id));
    let (descriptor, created) = match fs::openat(
        directory,
        name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    ) {
        Ok(descriptor) => (descriptor, true),
        Err(rustix::io::Errno::EXIST) => (
            fs::openat(
                directory,
                name.as_str(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| "existing reward evidence cannot be opened safely")?,
            false,
        ),
        Err(_) => return Err("reward receipt creation failed".into()),
    };
    let mut file = File::from(descriptor);
    let identity = fs::fstat(&file).map_err(|_| "reward receipt metadata unavailable")?;
    let private_regular = |stat: &rustix::fs::Stat| {
        FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
            && stat.st_uid == rustix::process::geteuid().as_raw()
            && stat.st_mode & 0o077 == 0
            && stat.st_nlink == 1
    };
    if !private_regular(&identity) {
        return Err("reward receipt must be an owned private singly linked regular file".into());
    }
    if created {
        file.write_all(secret)
            .map_err(|_| "reward receipt write failed")?;
    } else {
        if usize::try_from(identity.st_size).ok() != Some(secret.len()) {
            return Err("existing reward receipt differs; evidence preserved".into());
        }
        let mut existing = Zeroizing::new(Vec::with_capacity(secret.len()));
        Read::by_ref(&mut file)
            .take((MAX_REWARD_SECRET + 1) as u64)
            .read_to_end(&mut existing)
            .map_err(|_| "existing reward receipt read failed")?;
        if existing.len() != secret.len()
            || existing
                .iter()
                .zip(secret)
                .fold(0u8, |difference, (a, b)| difference | (a ^ b))
                != 0
        {
            return Err("existing reward receipt differs; evidence preserved".into());
        }
    }
    // A retry after a crash must reestablish both durability boundaries even
    // when byte-identical evidence was already present before the append.
    file.sync_all()
        .map_err(|_| "reward receipt durability failed")?;
    let current = fs::fstat(&file).map_err(|_| "reward receipt metadata unavailable")?;
    let named = fs::statat(directory, name.as_str(), fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| "reward receipt entry changed")?;
    if !private_regular(&current)
        || !private_regular(&named)
        || current.st_dev != identity.st_dev
        || current.st_ino != identity.st_ino
        || named.st_dev != current.st_dev
        || named.st_ino != current.st_ino
        || usize::try_from(current.st_size).ok() != Some(secret.len())
        || current.st_size != named.st_size
    {
        return Err("reward receipt identity changed; evidence preserved".into());
    }
    directory
        .sync_all()
        .map_err(|_| "reward directory durability failed".to_owned())
}

/// Read through the store-owned parent descriptor without following links.
#[cfg(unix)]
pub(crate) fn read_reward_at(directory: &File, id: &Hash) -> Result<Zeroizing<Vec<u8>>, String> {
    use rustix::fs::{self, FileType, Mode, OFlags};
    let name = format!("reward-{}.secret", hex(id));
    let descriptor = fs::openat(
        directory,
        name.as_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| "indexed reward receipt unavailable")?;
    let mut file = File::from(descriptor);
    let identity = fs::fstat(&file).map_err(|_| "reward receipt metadata unavailable")?;
    if FileType::from_raw_mode(identity.st_mode) != FileType::RegularFile
        || identity.st_uid != rustix::process::geteuid().as_raw()
        || identity.st_mode & 0o077 != 0
        || identity.st_nlink != 1
        || identity.st_size <= 0
        || usize::try_from(identity.st_size).map_or(true, |n| n > MAX_REWARD_SECRET)
    {
        return Err("indexed reward receipt is not an owned private regular file".into());
    }
    let mut secret = Zeroizing::new(Vec::with_capacity(identity.st_size as usize));
    Read::by_ref(&mut file)
        .take((MAX_REWARD_SECRET + 1) as u64)
        .read_to_end(&mut secret)
        .map_err(|_| "indexed reward receipt read failed")?;
    let current = fs::fstat(&file).map_err(|_| "reward receipt metadata unavailable")?;
    let named = fs::statat(directory, name.as_str(), fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| "indexed reward receipt entry changed")?;
    if current.st_dev != identity.st_dev
        || current.st_ino != identity.st_ino
        || current.st_mode != identity.st_mode
        || current.st_uid != identity.st_uid
        || current.st_nlink != 1
        || current.st_size != identity.st_size
        || named.st_dev != current.st_dev
        || named.st_ino != current.st_ino
        || named.st_mode != current.st_mode
        || named.st_nlink != 1
        || named.st_size != current.st_size
        || secret.len() != identity.st_size as usize
    {
        return Err("indexed reward receipt identity changed".into());
    }
    Ok(secret)
}

pub fn read_reward(path: &Path, id: &Hash) -> Result<Zeroizing<Vec<u8>>, String> {
    check_directory(path)?;
    let path = reward_path(path, id);
    let file = regular_read(&path, true, MAX_REWARD_SECRET)?;
    let mut out = Zeroizing::new(Vec::new());
    file.take((MAX_REWARD_SECRET + 1) as u64)
        .read_to_end(&mut out)
        .map_err(|_| "reward receipt read failed")?;
    if out.len() > MAX_REWARD_SECRET {
        return Err("reward receipt size changed".into());
    }
    Ok(out)
}
#[cfg(test)]
mod tests;
