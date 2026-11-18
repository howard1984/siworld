//! Bounded stdin verifier. All execution authority lives in this process.
//! Input selectors and serialized reports cannot import a verified cache.
use super::*;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::DirBuilder,
    io::{BufRead, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::Path,
};

const ACTION_BYTES: usize = 65536;
const REPORT_BYTES: usize = 4 * 1024 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u16,
    sequence: u64,
    action: Action,
}
#[derive(Deserialize)]
#[serde(tag = "operation", deny_unknown_fields)]
enum Action {
    Seed {
        capture: Hash,
        expected: Request,
    },
    Extend {
        cache: Hash,
        capture: Hash,
        expected: Request,
    },
    Inspect {
        cache: Hash,
    },
    Drop {
        cache: Hash,
    },
}
fn private_directory(path: &Path) -> Result<()> {
    let m = path
        .symlink_metadata()
        .map_err(|_| Error::BodyUnavailable)?;
    if !m.is_dir()
        || m.file_type().is_symlink()
        || m.uid() != rustix::process::geteuid().as_raw()
        || m.mode() & 0o777 != 0o700
    {
        Err(Error::ContextMismatch)
    } else {
        Ok(())
    }
}
fn read_json<T: serde::de::DeserializeOwned>(path: &Path, limit: usize) -> Result<T> {
    use std::io::Read;
    let mut file =
        crate::local::regular_read(path, true, limit).map_err(|_| Error::BodyUnavailable)?;
    let n = usize::try_from(file.metadata().map_err(|_| Error::BodyUnavailable)?.len())
        .map_err(|_| Error::CapacityExceeded)?;
    if n == 0 || n > limit {
        return Err(Error::CapacityExceeded);
    }
    let mut bytes = vec![0; n];
    file.read_exact(&mut bytes)
        .map_err(|_| Error::BodyUnavailable)?;
    if file.read(&mut [0]).map_err(|_| Error::BodyUnavailable)? != 0 {
        return Err(Error::CaptureFailed);
    }
    serde_json::from_slice(&bytes).map_err(|_| Error::ContextMismatch)
}
fn captured(root: &Path, id: Hash, expected: &Request) -> Result<(Inventory, Closed, FileArchive)> {
    let path = root.join("captures").join(crate::local::hex(&id));
    private_directory(&path)?;
    let inventory: Inventory = read_json(&path.join("inventory.json"), REPORT_BYTES)?;
    let closed: Closed = read_json(&path.join("closed.json"), ACTION_BYTES)?;
    if inventory.capture_id != id || inventory.request != *expected {
        return Err(Error::ContextMismatch);
    }
    let archive = FileArchive::open(&path, &inventory)?;
    Ok((inventory, closed, archive))
}
fn describe(prefix: &VerifiedPrefix, budget: &Budget) -> Result<(Value, p2p::Reservation)> {
    let encoding = budget
        .reserve((prefix.selector().target.height as usize + 1) * 6144 + 262144)
        .map_err(|_| Error::CapacityExceeded)?;
    prefix.check_retained_originals()?;
    let (retained, peak) = prefix.allocation_reservation();
    let path = prefix.path()?;
    Ok((
        json!({"result":"INDEPENDENT_NATIVE_EXECUTION_RETAINED", "prefix":prefix.selector(),"checkpoint":prefix.checkpoint(),"path":path,"provenance":prefix.provenance(),"retained_cache_bytes":retained,"peak_reserved_bytes":peak,"native_wallet_publication":false,"native_readiness":false}),
        encoding,
    ))
}
/// Run on already selected owner-private disposable storage. This creates no
/// listener, node identity, key, native publication or service control. EOF
/// destroys every typed cache; a later process must execute originals again.
pub fn verify_session(root: &Path) -> std::result::Result<(), String> {
    private_directory(root).map_err(|e| e.code())?;
    private_directory(&root.join("captures")).map_err(|e| e.code())?;
    let replay_dir = root.join("replays");
    if !replay_dir.exists() {
        DirBuilder::new()
            .mode(0o700)
            .create(&replay_dir)
            .map_err(|_| "historical disposable replay directory unavailable")?;
    }
    private_directory(&replay_dir).map_err(|e| e.code())?;
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| "historical replay session unavailable")?;
    let replay_dir = replay_dir.join(crate::local::hex(&nonce));
    DirBuilder::new()
        .mode(0o700)
        .create(&replay_dir)
        .map_err(|_| "historical replay session unavailable")?;
    let budget = Budget::new(super::memory::CACHE_MEMORY);
    let imports = crate::eng2::resident::limits();
    let mut prefixes: BTreeMap<Hash, VerifiedPrefix> = BTreeMap::new();
    let mut sequence = 0;
    let mut reader = std::io::stdin().lock();
    let mut writer = std::io::stdout().lock();
    loop {
        // take bounds the allocation even for a line without a newline.
        let mut bytes = Vec::new();
        let n = std::io::Read::take(&mut reader, (ACTION_BYTES + 1) as u64)
            .read_until(b'\n', &mut bytes)
            .map_err(|_| "historical verifier input unavailable")?;
        if n == 0 {
            break;
        }
        if n > ACTION_BYTES {
            return Err("historical verifier action bound exceeded".into());
        }
        let parsed = serde_json::from_slice::<Envelope>(&bytes);
        let (current, result, encoding) = (|| -> Result<(u64, Value, p2p::Reservation)> {
            let v = parsed.map_err(|_| Error::ContextMismatch)?;
            if v.version != 1 || v.sequence <= sequence || v.sequence > 65536 {
                return Err(Error::ContextMismatch);
            }
            sequence = v.sequence;
            let (result, encoding) = match v.action {
                Action::Seed { capture, expected } => {
                    if prefixes.len() >= 64 || expected.prefix.is_some() {
                        return Err(Error::CapacityExceeded);
                    }
                    let _input = budget
                        .reserve(8 * 1024 * 1024)
                        .map_err(|_| Error::CapacityExceeded)?;
                    let (inventory, closed, mut archive) = captured(root, capture, &expected)?;
                    let receipt = super::replay::replay_budgeted(
                        &inventory,
                        closed,
                        &expected,
                        &mut archive,
                        &replay_dir.join(format!("replay-{:020}.redb", v.sequence)),
                        imports,
                        &budget,
                        || false,
                    )?;
                    let prefix = VerifiedPrefix::from_replay(&receipt, &archive, imports, &budget)?;
                    drop(receipt);
                    let pin = prefix.selector().cache;
                    prefixes.insert(pin, prefix);
                    describe(prefixes.get(&pin).ok_or(Error::CaptureFailed)?, &budget)?
                }
                Action::Extend {
                    cache,
                    capture,
                    expected,
                } => {
                    if prefixes.len() >= 64 {
                        return Err(Error::CapacityExceeded);
                    }
                    let old = prefixes.get(&cache).ok_or(Error::ContextMismatch)?;
                    let _input = budget
                        .reserve(8 * 1024 * 1024)
                        .map_err(|_| Error::CapacityExceeded)?;
                    let (inventory, closed, mut archive) = captured(root, capture, &expected)?;
                    let prefix = old.extend(
                        &inventory,
                        closed,
                        &expected,
                        &mut archive,
                        imports,
                        &budget,
                        || false,
                    )?;
                    let pin = prefix.selector().cache;
                    prefixes.insert(pin, prefix);
                    describe(prefixes.get(&pin).ok_or(Error::CaptureFailed)?, &budget)?
                }
                Action::Inspect { cache } => {
                    describe(prefixes.get(&cache).ok_or(Error::ContextMismatch)?, &budget)?
                }
                Action::Drop { cache } => {
                    if prefixes.remove(&cache).is_none() {
                        return Err(Error::ContextMismatch);
                    }
                    (
                        json!({"dropped":cache}),
                        budget.reserve(65536).map_err(|_| Error::CapacityExceeded)?,
                    )
                }
            };
            Ok((v.sequence, result, encoding))
        })()
        .map(|(s, v, g)| (s, Ok(v), Some(g)))
        .unwrap_or_else(|e| (sequence, Err(e), None));
        let report = match result {
            Ok(value) => json!({"version":1,"sequence":current,"result":value}),
            Err(e) => json!({"version":1,"sequence":current,"error":e.code()}),
        };
        let encoded = serde_json::to_vec(&report)
            .map_err(|_| "historical verifier report encoding failed")?;
        if encoded.len() > REPORT_BYTES {
            return Err("historical verifier report bound exceeded".into());
        }
        let _encoding = encoding;
        writer
            .write_all(&encoded)
            .and_then(|()| writer.write_all(b"\n"))
            .and_then(|()| writer.flush())
            .map_err(|_| "historical verifier output unavailable")?;
    }
    Ok(())
}
