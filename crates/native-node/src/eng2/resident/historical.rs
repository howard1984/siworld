//! Finite owner-only historical actions over the existing private file channel.
use super::*;
use crate::eng2::historical::{self, Capture, Control, Materials, Request};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_ACTION: usize = 65536;
const MAX_REPLY: usize = 4 * 1024 * 1024;
const REQUEST_NAME: &str = "historical-request.json";
const RESULT_NAME: &str = "historical-result.json";
const INFLIGHT_NAME: &str = "historical-inflight.json";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u16,
    sequence: u64,
    action: Action,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", deny_unknown_fields)]
enum Action {
    Header {
        height: u64,
        tip: Hash,
    },
    Begin {
        request: Box<Request>,
    },
    Read {
        capture_id: Hash,
        object: usize,
        offset: usize,
        length: usize,
    },
    ReadBatch {
        capture_id: Hash,
        ranges: Vec<historical::Range>,
    },
    Close {
        capture_id: Hash,
    },
    Cancel {
        capture_id: Hash,
    },
}
fn decode(bytes: &[u8]) -> historical::Result<Envelope> {
    if bytes.is_empty() || bytes.len() > MAX_ACTION {
        return Err(historical::Error::CapacityExceeded);
    }
    let v: Envelope =
        serde_json::from_slice(bytes).map_err(|_| historical::Error::ContextMismatch)?;
    if v.version != 1 || v.sequence == 0 {
        return Err(historical::Error::ContextMismatch);
    }
    Ok(v)
}
fn public_material(
    directory: &Path,
    name: &str,
    suffix: &str,
    limit: usize,
) -> historical::Result<Arc<[u8]>> {
    if name.len() != 64 + suffix.len()
        || !name.ends_with(suffix)
        || !name.as_bytes()[..64]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(historical::Error::ContextMismatch);
    }
    let mut file = crate::local::regular_read(&directory.join(name), true, limit)
        .map_err(|_| historical::Error::BodyUnavailable)?;
    let size = usize::try_from(
        file.metadata()
            .map_err(|_| historical::Error::BodyUnavailable)?
            .len(),
    )
    .map_err(|_| historical::Error::CapacityExceeded)?;
    if size == 0 || size > limit {
        return Err(historical::Error::CapacityExceeded);
    }
    let mut bytes = vec![0; size];
    file.read_exact(&mut bytes)
        .map_err(|_| historical::Error::BodyUnavailable)?;
    if file
        .read(&mut [0])
        .map_err(|_| historical::Error::BodyUnavailable)?
        != 0
    {
        return Err(historical::Error::CaptureFailed);
    }
    Ok(bytes.into())
}
fn materials(directory: &Path, request: &Request) -> historical::Result<Option<Materials>> {
    if request.anchor.height == 0 {
        return Ok(None);
    }
    let public = directory.join("eng2-public");
    let name = format!("checkpoint-publication-{:020}.json", request.anchor.height);
    let mut bytes = Vec::new();
    crate::local::regular_read(&public.join(name), true, 16384)
        .map_err(|_| historical::Error::BodyUnavailable)?
        .take(16385)
        .read_to_end(&mut bytes)
        .map_err(|_| historical::Error::BodyUnavailable)?;
    let p: Value = serde_json::from_slice(&bytes).map_err(|_| historical::Error::CaptureFailed)?;
    if p["height"] != request.anchor.height
        || p["checkpoint_block"] != crate::local::hex(&request.anchor.id)
        || p["genesis"] != crate::local::hex(&request.context.genesis)
        || p["network"] != crate::local::hex(&request.context.network)
        || p["rules_commitment"] != crate::local::hex(&request.context.rules)
    {
        return Err(historical::Error::ContextMismatch);
    }
    let file = |key: &str| p[key].as_str().ok_or(historical::Error::BodyUnavailable);
    // Vec-to-Arc conversion briefly owns both allocations. Include already
    // loaded artifacts and channel metadata before admitting the next input.
    let remaining = request
        .limits
        .memory_bytes
        .checked_sub(24 * 1024 * 1024)
        .ok_or(historical::Error::CapacityExceeded)?;
    let certificate = public_material(
        &public,
        file("certificate_file")?,
        ".certificate-eng2.bin",
        crate::eng2::certificate::CERTIFICATE_BYTES.min(remaining / 2),
    )?;
    let remaining = remaining
        .checked_sub(certificate.len())
        .ok_or(historical::Error::CapacityExceeded)?;
    let witness = public_material(
        &public,
        file("witness_file")?,
        ".witness-eng2.bin",
        (remaining / 2).min(64 * 1024 * 1024),
    )?;
    let remaining = remaining
        .checked_sub(witness.len())
        .ok_or(historical::Error::CapacityExceeded)?;
    let snapshot = public_material(
        &public,
        file("snapshot_file")?,
        ".snapshot-eng2.bin",
        (remaining / 2).min(64 * 1024 * 1024),
    )?;
    Ok(Some(Materials {
        certificate,
        witness,
        snapshot,
    }))
}

struct Session {
    control: Control,
    capture: Option<Capture>,
    directory: PathBuf,
    budget: p2p::Budget,
}
impl Session {
    fn apply(&mut self, action: Action) -> historical::Result<Value> {
        match action {
            Action::Header { height, tip } => {
                let h = self.control.original_header(height, tip)?;
                serde_json::to_value(h).map_err(|_| historical::Error::CaptureFailed)
            }
            Action::Begin { request } => {
                // Charge bounded file input before reading original public
                // artifacts. No native database is opened by this channel.
                let input = self
                    .budget
                    .reserve(request.limits.memory_bytes.min(128 * 1024 * 1024))
                    .map_err(|_| historical::Error::CapacityExceeded)?;
                if self.capture.is_some() {
                    return Err(historical::Error::CapacityExceeded);
                }
                let m = materials(&self.directory, &request)?;
                let capture = self.control.begin_charged(*request, m, input)?;
                let result = serde_json::to_value(capture.inventory())
                    .map_err(|_| historical::Error::CaptureFailed)?;
                self.capture = Some(capture);
                Ok(result)
            }
            Action::Read {
                capture_id,
                object,
                offset,
                length,
            } => {
                let c = self
                    .capture
                    .as_mut()
                    .ok_or(historical::Error::CaptureExpired)?;
                let result = c.read(capture_id, object, offset, length)?;
                serde_json::to_value(result).map_err(|_| historical::Error::CaptureFailed)
            }
            Action::ReadBatch { capture_id, ranges } => {
                let c = self
                    .capture
                    .as_mut()
                    .ok_or(historical::Error::CaptureExpired)?;
                let result = c.read_batch(capture_id, &ranges)?;
                serde_json::to_value(result).map_err(|_| historical::Error::CaptureFailed)
            }
            Action::Close { capture_id } => {
                if self
                    .capture
                    .as_ref()
                    .is_none_or(|c| c.inventory().capture_id != capture_id)
                {
                    return Err(historical::Error::ContextMismatch);
                }
                let result = self
                    .capture
                    .take()
                    .ok_or(historical::Error::CaptureExpired)?
                    .close()?;
                serde_json::to_value(result).map_err(|_| historical::Error::CaptureFailed)
            }
            Action::Cancel { capture_id } => {
                if self
                    .capture
                    .as_ref()
                    .is_none_or(|c| c.inventory().capture_id != capture_id)
                {
                    return Err(historical::Error::ContextMismatch);
                }
                self.capture.take();
                Ok(json!({"capture_id":capture_id,"canceled":true}))
            }
        }
    }
}
pub(crate) struct Worker {
    canceled: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.canceled.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
pub(super) fn start(
    directory: &Path,
    shared: &Arc<Shared>,
    run: &service::RunIdentity,
    executable: &str,
    node: Hash,
    genesis: &Genesis,
) -> Result<Option<Worker>, String> {
    let release = match std::env::var("SIWORLD_ENG2_HISTORY_RELEASE") {
        Ok(v) => v,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(_) => return Err("historical context unavailable".into()),
    };
    let parse = |v: &str| -> Result<Hash, String> {
        crate::eng2_operations::public_bytes(&json!(v), 32)?
            .try_into()
            .map_err(|_| "historical identity rejected".into())
    };
    let identity = historical::Identity {
        release: parse(&release)?,
        process_run: parse(&run.run_id)?,
        executable: parse(executable)?,
        source_node: node,
    };
    let maximum = historical::Limits {
        headers: historical::MAX_HEADERS,
        frame_bytes: 4 * 1024 * 1024 * 1024,
        object_bytes: 5 * 1024 * 1024 * 1024,
        memory_bytes: 128 * 1024 * 1024,
        wall: Duration::from_secs(60),
        expiry: Duration::from_secs(300),
    };
    let control = Control::new(
        shared.owner.clone(),
        identity,
        &genesis.encode()?,
        maximum,
        shared.budget.clone(),
    )
    .map_err(|e| e.code())?;
    start_control(directory, control, shared.budget.clone()).map(Some)
}
pub(crate) fn start_control(
    directory: &Path,
    control: Control,
    budget: p2p::Budget,
) -> Result<Worker, String> {
    let directory = directory.to_owned();
    let files = operations::io::Files::open(&directory)?;
    {
        let _lock = files.lock()?;
        files.remove(REQUEST_NAME, MAX_ACTION)?;
        files.remove(RESULT_NAME, MAX_REPLY)?;
        files.remove(INFLIGHT_NAME, MAX_ACTION)?;
    }
    let canceled = Arc::new(AtomicBool::new(false));
    let stop = canceled.clone();
    let thread = std::thread::Builder::new()
        .name("historical-control".into())
        .spawn(move || {
            let mut session = Session {
                control,
                capture: None,
                directory,
                budget,
            };
            let mut last_sequence = 0;
            while !stop.load(Ordering::Acquire) {
                if session
                    .capture
                    .as_ref()
                    .is_some_and(|_| !session.control.active())
                {
                    session.capture.take();
                }
                let request = (|| {
                    let _lock = files.lock()?;
                    let bytes = files.read(REQUEST_NAME, MAX_ACTION)?;
                    if let Some(bytes) = &bytes {
                        files.replace(INFLIGHT_NAME, bytes, MAX_ACTION)?;
                    }
                    files.remove(REQUEST_NAME, MAX_ACTION)?;
                    Ok::<_, String>(bytes)
                })();
                let busy = matches!(&request, Ok(Some(_)));
                if let Ok(Some(bytes)) = request {
                    let (sequence, result) = match decode(&bytes) {
                        Ok(v) if v.sequence > last_sequence => {
                            last_sequence = v.sequence;
                            (v.sequence, session.apply(v.action))
                        }
                        Ok(v) => (v.sequence, Err(historical::Error::ContextMismatch)),
                        Err(e) => (0, Err(e)),
                    };
                    let value = match result {
                        Ok(result) => json!({"version":1,"sequence":sequence,"result":result}),
                        Err(e) => json!({"version":1,"sequence":sequence,"error":e.code()}),
                    };
                    if let Ok(mut bytes) = serde_json::to_vec(&value) {
                        if bytes.len() > MAX_REPLY {
                            session.capture.take();
                            bytes = serde_json::to_vec(&json!({"version":1,"sequence":sequence,"error":"CAPACITY_EXCEEDED"})).unwrap_or_default();
                        }
                        let _ = (|| {
                            let _lock = files.lock()?;
                            files.replace(RESULT_NAME, &bytes, MAX_REPLY)?;
                            files.remove(INFLIGHT_NAME, MAX_ACTION)
                        })();
                    }
                }
                if !busy {
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
        })
        .map_err(|_| "historical control worker unavailable")?;
    Ok(Worker {
        canceled,
        thread: Some(thread),
    })
}

/// Local clients submit only the finite schema; no arbitrary command is sent.
pub fn submit_file(directory: &Path, request: &Path) -> Result<Value, String> {
    submit(directory, &request_bytes(request)?)
}
fn request_bytes(request: &Path) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    crate::local::regular_read(request, true, MAX_ACTION)?
        .take(MAX_ACTION as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "historical request unavailable")?;
    Ok(bytes)
}
#[derive(Deserialize)]
struct ReplyMarker {
    version: u16,
    sequence: u64,
}
fn reply_marker(bytes: &[u8]) -> Result<ReplyMarker, String> {
    let marker: ReplyMarker =
        serde_json::from_slice(bytes).map_err(|_| "historical result rejected")?;
    if marker.version != 1 || marker.sequence == 0 {
        return Err("historical result identity rejected".into());
    }
    Ok(marker)
}
pub fn submit(directory: &Path, bytes: &[u8]) -> Result<Value, String> {
    let envelope = decode(bytes).map_err(|e| e.code())?;
    let files = operations::io::Files::open(directory)?;
    let _lock = files.lock()?;
    if files.read(REQUEST_NAME, MAX_ACTION)?.is_some()
        || files.read(INFLIGHT_NAME, MAX_ACTION)?.is_some()
    {
        return Err("historical request pending".into());
    }
    if let Some(previous) = files.read(RESULT_NAME, MAX_REPLY)?
        && reply_marker(&previous)?.sequence >= envelope.sequence
    {
        return Err("historical request sequence is not increasing".into());
    }
    let canonical =
        serde_json::to_vec(&envelope).map_err(|_| "historical request encoding failed")?;
    files.replace(REQUEST_NAME, &canonical, MAX_ACTION)?;
    Ok(json!({"version":1,"sequence":envelope.sequence,"submitted":true}))
}
/// Submit once and return the original bounded reply bytes. Parsing only the
/// marker avoids allocating another decoded chunk array or reencoding it.
/// Timeout leaves no success claim; the existing worker retains capture expiry.
pub fn exchange_file(
    directory: &Path,
    request: &Path,
    maximum_wait_ms: u64,
) -> Result<Vec<u8>, String> {
    if !(1..=60000).contains(&maximum_wait_ms) {
        return Err("historical exchange wait bound rejected".into());
    }
    let deadline = Instant::now() + Duration::from_millis(maximum_wait_ms);
    let bytes = request_bytes(request)?;
    let sequence = decode(&bytes).map_err(|e| e.code())?.sequence;
    submit(directory, &bytes)?;
    let files = operations::io::Files::open(directory)?;
    loop {
        if Instant::now() >= deadline {
            return Err("historical exchange expired".into());
        }
        // Keep the inode linked throughout open/metadata/read. A concurrent
        // atomic replacement can otherwise unlink an already opened old inode
        // before its required single-link ownership check.
        let reply = {
            let _lock = files.lock()?;
            files.read(RESULT_NAME, MAX_REPLY)?
        };
        if let Some(bytes) = reply {
            let marker = reply_marker(&bytes)?;
            if marker.sequence == sequence {
                if Instant::now() >= deadline {
                    return Err("historical exchange expired".into());
                }
                return Ok(bytes);
            }
            if marker.sequence > sequence {
                return Err("historical result sequence differs".into());
            }
        }
        std::thread::sleep(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(2)),
        );
    }
}
pub fn result(directory: &Path, sequence: u64) -> Result<Value, String> {
    let files = operations::io::Files::open(directory)?;
    let _lock = files.lock()?;
    let bytes = files
        .read(RESULT_NAME, MAX_REPLY)?
        .ok_or("historical result unavailable")?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| "historical result rejected")?;
    if sequence == 0 || value["sequence"] != sequence {
        return Err("historical result sequence differs".into());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finite_schema_rejects_unknown_commands_and_paths() {
        for bytes in [
            br#"{"version":1,"sequence":1,"action":{"operation":"Shell","command":"id"}}"#.as_slice(),
            br#"{"version":1,"sequence":1,"action":{"operation":"Cancel","capture_id":[0],"path":"other"}}"#.as_slice(),
            br#"{"version":1,"sequence":0,"action":{"operation":"Cancel","capture_id":[]}}"#.as_slice(),
        ] { assert!(decode(bytes).is_err()); }
    }
    #[test]
    fn canonical_finite_action_roundtrip() {
        let value = Envelope {
            version: 1,
            sequence: 1,
            action: Action::Read {
                capture_id: [9; 32],
                object: 1,
                offset: 0,
                length: 65536,
            },
        };
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(matches!(
            decode(&bytes).unwrap().action,
            Action::Read { length: 65536, .. }
        ));
    }
    #[test]
    fn artifact_selector_rejects_caller_paths_before_reading() {
        for name in [
            "../other.snapshot-eng2.bin",
            "/other.snapshot-eng2.bin",
            "other",
            "a/b",
        ] {
            assert!(matches!(
                public_material(Path::new("unused"), name, ".snapshot-eng2.bin", 10),
                Err(historical::Error::ContextMismatch)
            ));
        }
    }
    #[test]
    fn reply_marker_validates_identity_without_retaining_payload() {
        let bytes =
            br#"{"version":1,"sequence":7,"result":{"bytes":[1,2,3],"unknown":[null,true]}}"#;
        assert_eq!(reply_marker(bytes).unwrap().sequence, 7);
        for bytes in [
            br#"{"version":2,"sequence":7,"result":null}"#.as_slice(),
            br#"{"version":1,"sequence":0,"result":null}"#.as_slice(),
            br#"{"version":1,"sequence":7,"sequence":8}"#.as_slice(),
            br#"{"version":1,"sequence":7,"result":[}"#.as_slice(),
        ] {
            assert!(reply_marker(bytes).is_err());
        }
        for wait in [0, 60001, u64::MAX] {
            assert!(exchange_file(Path::new("unused"), Path::new("unused"), wait).is_err());
        }
    }
}
