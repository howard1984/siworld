//! Local wallet preferences. These values never enter consensus or proof inputs.
use crate::wire::Hash;
use std::path::Path;

const FILE_NAME: &str = "wallet-policy.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletNetwork {
    Engineering,
    Testnet,
    Mainnet,
}
impl WalletNetwork {
    pub fn name(self) -> &'static str {
        match self {
            Self::Engineering => "engineering",
            Self::Testnet => "testnet",
            Self::Mainnet => "mainnet",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpendPolicy {
    Manual,
    EnhancedPrivacy,
    Background,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalletPrivacyPolicy {
    pub network_class: WalletNetwork,
    pub enhanced_privacy: bool,
    pub background_delay: bool,
}
impl WalletPrivacyPolicy {
    pub fn for_network(network_class: WalletNetwork) -> Self {
        Self {
            network_class,
            enhanced_privacy: false,
            background_delay: network_class == WalletNetwork::Mainnet,
        }
    }
    pub fn load(directory: &Path, network: Hash) -> Result<Self, String> {
        load(directory, network)
    }
    /// Call only while holding the authenticated wallet's ownership lock.
    pub fn save(self, directory: &Path, network: Hash) -> Result<(), String> {
        save(directory, network, self)
    }
}
impl Default for WalletPrivacyPolicy {
    fn default() -> Self {
        Self::for_network(WalletNetwork::Engineering)
    }
}
fn encode(policy: WalletPrivacyPolicy, network: Hash) -> Result<Vec<u8>, String> {
    if network == [0; 32] {
        return Err("wallet policy requires a nonzero network ID".into());
    }
    let mut raw = serde_json::to_vec(&serde_json::json!({
        "schema": 1,
        "network": crate::local::hex(&network),
        "network_class": policy.network_class.name(),
        "enhanced_privacy": policy.enhanced_privacy,
        "background_delay": policy.background_delay,
    }))
    .map_err(|_| "cannot encode wallet policy")?;
    raw.push(b'\n');
    Ok(raw)
}
fn decode(raw: &[u8], network: Hash) -> Result<WalletPrivacyPolicy, String> {
    let value: serde_json::Value =
        serde_json::from_slice(raw).map_err(|_| "invalid wallet policy JSON")?;
    let object = value.as_object().ok_or("wallet policy must be an object")?;
    if object.len() != 5
        || value["schema"].as_u64() != Some(1)
        || value["network"].as_str() != Some(crate::local::hex(&network).as_str())
    {
        return Err("wallet policy schema or network differs from this wallet".into());
    }
    let network_class = match value["network_class"].as_str() {
        Some("engineering") => WalletNetwork::Engineering,
        Some("testnet") => WalletNetwork::Testnet,
        Some("mainnet") => WalletNetwork::Mainnet,
        _ => return Err("unknown wallet policy network class".into()),
    };
    let policy = WalletPrivacyPolicy {
        network_class,
        enhanced_privacy: value["enhanced_privacy"]
            .as_bool()
            .ok_or("wallet privacy flag must be boolean")?,
        background_delay: value["background_delay"]
            .as_bool()
            .ok_or("wallet background flag must be boolean")?,
    };
    // A single canonical tool-written representation rejects duplicate keys,
    // unknown fields and alternate number spellings without parser ambiguity.
    if encode(policy, network)? != raw {
        return Err("wallet policy requires its canonical local representation".into());
    }
    Ok(policy)
}

#[cfg(unix)]
mod unix {
    use super::*;
    use rustix::fs::{AtFlags, Mode, OFlags, linkat, open, openat, renameat, unlinkat};
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;

    fn flags() -> OFlags {
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
    }
    fn directory(path: &Path) -> Result<File, String> {
        if path.as_os_str().is_empty()
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::Prefix(_)))
        {
            return Err("invalid wallet policy directory".into());
        }
        let absolute = if path.is_absolute() {
            path.to_owned()
        } else {
            std::env::current_dir()
                .map_err(|_| "cannot resolve wallet policy directory")?
                .join(path)
        };
        let mut current = File::from(
            open("/", flags(), Mode::empty()).map_err(|_| "cannot open filesystem root")?,
        );
        for part in absolute.components() {
            if let Component::Normal(name) = part {
                current =
                    File::from(openat(&current, name, flags(), Mode::empty()).map_err(
                        |_| "wallet policy path contains a symlink or missing directory",
                    )?);
            }
        }
        let metadata = current
            .metadata()
            .map_err(|_| "cannot inspect wallet policy directory")?;
        if !metadata.is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
        {
            return Err(
                "wallet policy directory requires this owner and mode 0700 or stricter".into(),
            );
        }
        Ok(current)
    }
    fn checked(file: &File) -> Result<(), String> {
        let metadata = file
            .metadata()
            .map_err(|_| "cannot inspect wallet policy file")?;
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
            || metadata.len() > 4096
        {
            return Err("wallet policy requires one regular owner-only file".into());
        }
        Ok(())
    }
    fn read(directory: &File) -> Result<Option<Vec<u8>>, String> {
        let fd = match openat(
            directory,
            FILE_NAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => return Err("cannot open protected wallet policy".into()),
        };
        let mut file = File::from(fd);
        checked(&file)?;
        let mut raw = Vec::new();
        (&mut file)
            .take(4097)
            .read_to_end(&mut raw)
            .map_err(|_| "cannot read wallet policy")?;
        checked(&file)?;
        if raw.len() > 4096 {
            return Err("wallet policy exceeds its size limit".into());
        }
        Ok(Some(raw))
    }
    pub fn load(path: &Path, network: Hash) -> Result<WalletPrivacyPolicy, String> {
        if network == [0; 32] {
            return Err("wallet policy requires a nonzero network ID".into());
        }
        match read(&directory(path)?)? {
            None => Ok(WalletPrivacyPolicy::default()),
            Some(raw) => decode(&raw, network),
        }
    }
    /// The authenticated caller retains the wallet lock through publication.
    pub fn save(path: &Path, network: Hash, policy: WalletPrivacyPolicy) -> Result<(), String> {
        let encoded = encode(policy, network)?;
        let directory = directory(path)?;
        let before = read(&directory)?;
        if let Some(raw) = &before {
            let _ = decode(raw, network)?;
        }
        let mut suffix = [0u8; 16];
        getrandom::fill(&mut suffix).map_err(|_| "wallet policy randomness unavailable")?;
        let temporary_name = format!(".wallet-policy-{}.tmp", crate::local::hex(&suffix));
        let mut temporary = File::from(
            openat(
                &directory,
                temporary_name.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|_| "cannot create temporary wallet policy")?,
        );
        let result = (|| {
            checked(&temporary)?;
            temporary
                .write_all(&encoded)
                .and_then(|()| temporary.sync_all())
                .map_err(|_| "cannot persist temporary wallet policy")?;
            if read(&directory)? != before {
                return Err("wallet policy changed during update".into());
            }
            if before.is_some() {
                renameat(&directory, temporary_name.as_str(), &directory, FILE_NAME)
                    .map_err(|_| "cannot replace wallet policy")?;
            } else {
                linkat(
                    &directory,
                    temporary_name.as_str(),
                    &directory,
                    FILE_NAME,
                    AtFlags::empty(),
                )
                .map_err(|_| "wallet policy appeared during creation")?;
                unlinkat(&directory, temporary_name.as_str(), AtFlags::empty())
                    .map_err(|_| "cannot unlink temporary wallet policy")?;
            }
            directory
                .sync_all()
                .map_err(|_| "wallet policy saved; directory sync failed")?;
            Ok(())
        })();
        let _ = unlinkat(&directory, temporary_name.as_str(), AtFlags::empty());
        result
    }
}
#[cfg(unix)]
pub use unix::{load, save};
#[cfg(not(unix))]
pub fn load(_: &Path, _: Hash) -> Result<WalletPrivacyPolicy, String> {
    Err("protected wallet policies require Unix".into())
}
#[cfg(not(unix))]
pub fn save(_: &Path, _: Hash, _: WalletPrivacyPolicy) -> Result<(), String> {
    Err("protected wallet policies require Unix".into())
}
#[cfg(all(test, siworld_native_node))]
mod tests;
