//! Restart hints remain untrusted until their compact chain reaches a canonical anchor.
use crate::{state::Config, wire::Hash};
use std::{
    fs::{self, File, Metadata},
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

const MAX_IDS: usize = 1_000_000;
const MAX_INDEX_BYTES: usize = 68_000_512;

pub(super) struct RestartIndex {
    pub ids: Vec<Hash>,
    pub verified: usize,
}

fn private(metadata: &Metadata, limit: usize) -> bool {
    metadata.is_file()
        && metadata.uid() == rustix::process::geteuid().as_raw()
        && metadata.permissions().mode() & 0o777 == 0o600
        && metadata.nlink() == 1
        && metadata.len() <= limit as u64
}

fn unchanged(a: &Metadata, b: &Metadata) -> bool {
    (
        a.dev(),
        a.ino(),
        a.len(),
        a.mtime(),
        a.mtime_nsec(),
        a.ctime(),
        a.ctime_nsec(),
    ) == (
        b.dev(),
        b.ino(),
        b.len(),
        b.mtime(),
        b.mtime_nsec(),
        b.ctime(),
        b.ctime_nsec(),
    )
}

/// Bound allocation and reject symlinks, special files and replacement during a read.
pub(super) fn read_private(path: &Path, limit: usize) -> Result<Option<Vec<u8>>, String> {
    let named = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("Public archive metadata unavailable.".into()),
    };
    if !private(&named, limit) {
        return Err("Public archive record invalid.".into());
    }
    use rustix::fs::{Mode, OFlags};
    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| "Public archive read unavailable.")?;
    let file = File::from(descriptor);
    let opened = file
        .metadata()
        .map_err(|_| "Public archive metadata unavailable.")?;
    if !private(&opened, limit) || !unchanged(&named, &opened) {
        return Err("Public archive record changed.".into());
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    (&file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Public archive unreadable.")?;
    let after = file
        .metadata()
        .map_err(|_| "Public archive metadata unavailable.")?;
    let renamed = fs::symlink_metadata(path).map_err(|_| "Public archive metadata unavailable.")?;
    if bytes.len() > limit
        || bytes.len() as u64 != opened.len()
        || !private(&after, limit)
        || !private(&renamed, limit)
        || !unchanged(&opened, &after)
        || !unchanged(&opened, &renamed)
    {
        return Err("Public archive record changed.".into());
    }
    Ok(Some(bytes))
}

fn hash(value: &serde_json::Value) -> Option<Hash> {
    let text = value.as_str()?.as_bytes();
    if text.len() != 64 {
        return None;
    }
    let nibble = |byte| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    let mut hash = [0; 32];
    for (output, pair) in hash.iter_mut().zip(text.as_chunks::<2>().0) {
        *output = nibble(pair[0])? * 16 + nibble(pair[1])?;
    }
    Some(hash)
}

pub(super) fn load(root: &Path, config: &Config, height: u64) -> Option<RestartIndex> {
    let bytes = read_private(&root.join("chain.json"), MAX_INDEX_BYTES).ok()??;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let fields = value.as_object()?;
    let count = usize::try_from(value["height"].as_u64()?).ok()?;
    let values = value["ids"].as_array()?;
    if fields.len() != 6
        || value["version"].as_u64() != Some(1)
        || hash(&value["network"])? != config.network
        || hash(&value["genesis"])? != config.genesis_id()
        || count == 0
        || count > MAX_IDS
        || count as u64 > height
        || values.len() != count
    {
        return None;
    }
    let ids = values.iter().map(hash).collect::<Option<Vec<_>>>()?;
    if ids.last() != Some(&hash(&value["tip"])?) {
        return None;
    }
    Some(RestartIndex { ids, verified: 0 })
}
