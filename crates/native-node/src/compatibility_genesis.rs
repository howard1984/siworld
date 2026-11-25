//! Write-once disposable engineering custody and uncompressed genesis rules.

use crate::{local, state::Config, wire::Hash};
use libcrux_ml_dsa::ml_dsa_65;
use serde_json::{Value, json};
use siworld_core::v1_economics::FundAllocation;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

const KEY_FILES: [&str; 4] = [
    "fund-test.seed",
    "checkpoint-test-1.seed",
    "checkpoint-test-2.seed",
    "checkpoint-test-3.seed",
];
const MANIFEST: &str = "engineering-public.json";

fn public_key(seed: &[u8; 32]) -> String {
    let mut pair = ml_dsa_65::generate_key_pair(*seed);
    let public = local::hex(pair.verification_key.as_ref());
    pair.signing_key.as_mut_slice().zeroize();
    public
}

fn manifest(network: Hash, keys: &[String]) -> Value {
    json!({
        "schema": 1, "name": "siworld-eng-1", "resettable": true,
        "network": local::hex(&network),
        "fund": {"algorithm": "ML-DSA-65", "basis_points": [10000], "team_index": 0, "public_key": keys[0]},
        "checkpoint_policy": {"algorithm": "ML-DSA-65", "threshold": 2, "public_keys": &keys[1..],
            "active": false, "status": "reserved; authenticated checkpoint startup is not implemented"},
        "wallet_background_delay": false, "wallet_enhanced_privacy": false,
    })
}

/// Generate test-only custody on an operations host. No secret is returned or printed.
/// Partial failures preserve all files and require inspection; they never overwrite custody.
pub fn prepare(directory: &Path) -> Result<Value, String> {
    let mut network = [0; 32];
    getrandom::fill(&mut network).map_err(|_| "engineering entropy unavailable")?;
    let mut seeds = Zeroizing::new([[0; 32]; 4]);
    for seed in seeds.iter_mut() {
        getrandom::fill(seed).map_err(|_| "engineering entropy unavailable")?;
    }
    let keys: Vec<_> = seeds.iter().map(public_key).collect();
    if network == [0; 32] || keys.iter().collect::<std::collections::BTreeSet<_>>().len() != 4 {
        return Err("engineering entropy produced duplicate identities".into());
    }
    let public = manifest(network, &keys);
    let storage = storage::create(directory)?;
    for (name, seed) in KEY_FILES.iter().zip(seeds.iter()) {
        storage::write_once(&storage, name, seed)?;
    }
    storage::write_once(&storage, MANIFEST, &encode(&public)?)?;
    Ok(public)
}

fn encode(value: &Value) -> Result<Vec<u8>, String> {
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|_| "engineering manifest encoding failed")?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn checked_manifest(directory: &Path) -> Result<(Hash, Vec<[u8; 1952]>, Value), String> {
    let storage = storage::open(directory)?;
    let raw = storage::read(&storage, MANIFEST, 32768)?;
    let public: Value = serde_json::from_slice(&raw).map_err(|_| "invalid engineering manifest")?;
    let network = decode_hex::<32>(
        public["network"]
            .as_str()
            .ok_or("missing engineering network")?,
    )?;
    let mut keys = Vec::new();
    for name in KEY_FILES {
        let raw = Zeroizing::new(storage::read(&storage, name, 32)?);
        let seed = Zeroizing::new(
            <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| "invalid engineering test seed")?,
        );
        keys.push(public_key(&seed));
    }
    if encode(&manifest(network, &keys))? != raw {
        return Err("engineering manifest differs from its test custody".into());
    }
    let decoded = keys
        .iter()
        .map(|key| decode_hex::<1952>(key))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((network, decoded, public))
}

fn decode_hex<const N: usize>(text: &str) -> Result<[u8; N], String> {
    if text.len() != N * 2 {
        return Err("invalid engineering public key length".into());
    }
    let mut bytes = [0; N];
    for (out, pair) in bytes.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        let digit = |x: u8| match x {
            b'0'..=b'9' => Some(x - b'0'),
            b'a'..=b'f' => Some(x - b'a' + 10),
            _ => None,
        };
        *out = digit(pair[0])
            .zip(digit(pair[1]))
            .map(|(a, b)| a * 16 + b)
            .ok_or("invalid engineering public encoding")?;
    }
    Ok(bytes)
}

/// Seal current ASERT and production economic rules in a fresh data directory.
/// Calibration and wall-clock sampling are initialization operations only.
pub fn initialize(
    directory: &Path,
    custody: &Path,
    timestamp: u64,
    target: Hash,
    iterations: u64,
) -> Result<Config, String> {
    let (network, keys, public) = checked_manifest(custody)?;
    let config = Config::asert_development(network, timestamp, target, iterations)?
        .with_fund_wallets(
            FundAllocation::new_bps(vec![10000], 0).map_err(|e| e.to_string())?,
            vec![keys[0]],
        )?;
    local::initialize_config(directory, config.clone())?;
    let mut sealed = public;
    sealed["genesis_id"] = local::hex(&config.genesis_id()).into();
    sealed["genesis_timestamp"] = timestamp.into();
    sealed["target_interval_seconds"] = config.target_interval.into();
    sealed["economic_timing"] = "production; no time compression".into();
    sealed["initial_target"] = local::hex(&target).into();
    sealed["pow_iterations"] = iterations.into();
    let storage = storage::open(directory)?;
    storage::write_once(&storage, MANIFEST, &encode(&sealed)?)?;
    Ok(config)
}

#[cfg(unix)]
mod storage {
    use rustix::fs::{FileType, Mode, OFlags, fstat, mkdirat, open as open_root, openat};
    use std::{
        fs::File,
        io::{Read, Write},
        path::{Component, Path},
    };
    fn flags() -> OFlags {
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
    }
    fn walk(path: &Path) -> Result<File, String> {
        if path.as_os_str().is_empty()
            || path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
        {
            return Err("invalid engineering custody path".into());
        }
        let path = if path.is_absolute() {
            path.to_owned()
        } else {
            std::env::current_dir()
                .map_err(|_| "working directory unavailable")?
                .join(path)
        };
        let mut directory = File::from(
            open_root("/", flags(), Mode::empty()).map_err(|_| "filesystem root unavailable")?,
        );
        for part in path.components() {
            if let Component::Normal(name) = part {
                directory = File::from(
                    openat(&directory, name, flags(), Mode::empty())
                        .map_err(|_| "engineering custody path is missing or contains a symlink")?,
                );
            }
        }
        Ok(directory)
    }
    fn private(file: &File, directory: bool, max: usize) -> Result<(), String> {
        let stat = fstat(file).map_err(|_| "engineering custody metadata unavailable")?;
        let kind = FileType::from_raw_mode(stat.st_mode);
        if stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_mode & 0o077 != 0
            || if directory {
                kind != FileType::Directory
            } else {
                kind != FileType::RegularFile
                    || stat.st_nlink != 1
                    || stat.st_size < 1
                    || stat.st_size > max as i64
            }
        {
            return Err(
                "engineering custody requires private owned directories and singly linked files"
                    .into(),
            );
        }
        Ok(())
    }
    pub fn open(path: &Path) -> Result<File, String> {
        let directory = walk(path)?;
        private(&directory, true, 0)?;
        Ok(directory)
    }
    pub fn create(path: &Path) -> Result<File, String> {
        let name = path
            .file_name()
            .ok_or("new engineering custody directory required")?;
        let parent = walk(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new(".")),
        )?;
        mkdirat(&parent, name, Mode::from_raw_mode(0o700))
            .map_err(|_| "engineering custody requires a new directory")?;
        parent
            .sync_all()
            .map_err(|_| "engineering parent sync failed")?;
        open(path)
    }
    pub fn write_once(directory: &File, name: &str, bytes: &[u8]) -> Result<(), String> {
        let mut file = File::from(
            openat(
                directory,
                name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|_| "engineering custody refuses overwrites")?,
        );
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .and_then(|_| directory.sync_all())
            .map_err(|_| "engineering custody durability failed".into())
    }
    pub fn read(directory: &File, name: &str, max: usize) -> Result<Vec<u8>, String> {
        let file = File::from(
            openat(
                directory,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| "engineering custody file unavailable")?,
        );
        private(&file, false, max)?;
        let mut bytes = Vec::new();
        file.take((max + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| "engineering custody read failed")?;
        if bytes.len() > max {
            return Err("engineering custody size limit".into());
        }
        Ok(bytes)
    }
}

#[cfg(not(unix))]
mod storage {
    use std::{fs::File, path::Path};
    pub fn create(_: &Path) -> Result<File, String> {
        Err("engineering custody requires Unix ownership controls".into())
    }
    pub fn open(_: &Path) -> Result<File, String> {
        Err("engineering custody requires Unix ownership controls".into())
    }
    pub fn write_once(_: &File, _: &str, _: &[u8]) -> Result<(), String> {
        Err("unsupported engineering custody platform".into())
    }
    pub fn read(_: &File, _: &str, _: usize) -> Result<Vec<u8>, String> {
        Err("unsupported engineering custody platform".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary() -> std::path::PathBuf {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let path =
            std::env::temp_dir().join(format!("engineering-genesis-{}", crate::local::hex(&nonce)));
        std::fs::create_dir(&path).unwrap();
        path.canonicalize().unwrap()
    }

    #[test]
    fn independent_custody_and_public_manifest_preserve_production_rules() {
        let root = temporary();
        let keys = root.join("custody");
        let public = prepare(&keys).unwrap();
        assert_eq!(public["name"], "siworld-eng-1");
        assert_eq!(public["checkpoint_policy"]["active"], false);
        assert_eq!(public["checkpoint_policy"]["threshold"], 2);
        let public_text = public.to_string();
        let mut seeds = std::collections::BTreeSet::new();
        for name in KEY_FILES {
            let seed = std::fs::read(keys.join(name)).unwrap();
            assert_eq!(seed.len(), 32);
            assert!(!public_text.contains(&crate::local::hex(&seed)));
            assert!(seeds.insert(seed));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(keys.join(name))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
        }
        let config =
            initialize(&root.join("genesis"), &keys, 1_800_000_000, [0xff; 32], 64).unwrap();
        assert!(!config.fixture);
        assert_eq!(
            config.economics,
            siworld_core::v1_economics::EconomicsParams::production()
        );
        assert_eq!(config.target_interval, 300);
        assert!(config.issuance.is_none());
        assert_eq!(
            config.fund_allocation.as_ref().unwrap().basis_points(),
            &[10000]
        );
        assert_eq!(config.fund_verifying_keys.len(), 1);
        let peer = crate::local::initialize_config(&root.join("peer"), config.clone()).unwrap();
        assert_eq!(config.genesis_id(), peer.genesis_id());
        assert_eq!(std::fs::read_dir(root.join("peer")).unwrap().count(), 1);
        assert!(prepare(&keys).is_err());
        assert!(initialize(&root.join("genesis"), &keys, 1, [0xff; 32], 64).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn damaged_custody_is_rejected_without_creating_a_network() {
        let root = temporary();
        let keys = root.join("custody");
        prepare(&keys).unwrap();
        std::fs::write(keys.join(KEY_FILES[0]), [7; 32]).unwrap();
        assert!(initialize(&root.join("genesis"), &keys, 1, [0xff; 32], 64).is_err());
        assert!(!root.join("genesis").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlink_and_public_custody_permissions_are_rejected() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = temporary();
        let keys = root.join("custody");
        prepare(&keys).unwrap();
        let alias = root.join("alias");
        symlink(&keys, &alias).unwrap();
        assert!(initialize(&root.join("genesis"), &alias, 1, [0xff; 32], 64).is_err());
        std::fs::set_permissions(
            keys.join(KEY_FILES[1]),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(initialize(&root.join("genesis"), &keys, 1, [0xff; 32], 64).is_err());
        assert!(!root.join("genesis").exists());
        std::fs::remove_dir_all(root).unwrap();
    }
}
