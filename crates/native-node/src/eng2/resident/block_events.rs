//! Bounded observations at native production and canonical durable-commit edges.
//!
//! Events are diagnostics, never admission, readiness or finality decisions.
use crate::eng2::{header::Header, store::CommitObserver};
use crate::wire::Hash;
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const SEGMENTS: usize = 4;
const SEGMENT_BYTES: u64 = 1024 * 1024;
const RECORD_BYTES: usize = 2048;

#[derive(Clone, Copy)]
enum Kind {
    Produced,
    Accepted,
}
impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Produced => "native-block-produced",
            Self::Accepted => "native-block-durably-accepted",
        }
    }
}

struct Binding {
    network: Hash,
    genesis: Hash,
    node: Option<Hash>,
    run: String,
    binary: String,
    source: Option<String>,
}
struct State {
    log: Option<Ring>,
    sequence: u64,
    written: u64,
    dropped: u64,
    error: Option<&'static str>,
    start_written: bool,
    end_written: bool,
}
pub(super) struct Recorder {
    binding: Binding,
    started: Instant,
    state: Mutex<State>,
    reported: AtomicBool,
}

impl Recorder {
    /// Binary and run bindings come from the actual resident startup. Source is
    /// a build-time declaration; an external build receipt must authenticate it.
    pub(super) fn new(
        directory: &Path,
        network: Hash,
        genesis: Hash,
        node: Option<Hash>,
        run: &str,
        binary: &str,
    ) -> Self {
        let source = option_env!("SIWORLD_BUILD_COMMIT")
            .filter(|value| hex_text(value, 40))
            .map(str::to_owned);
        let opened = if node.is_some() && hex_text(run, 64) && hex_text(binary, 64) {
            Ring::open(directory, SEGMENT_BYTES)
        } else {
            Err("native_event_binding_unavailable")
        };
        let (log, error) = match opened {
            Ok(log) => (Some(log), None),
            Err(error) => (None, Some(error)),
        };
        let result = Self {
            binding: Binding {
                network,
                genesis,
                node,
                run: run.to_owned(),
                binary: binary.to_owned(),
                source,
            },
            started: Instant::now(),
            state: Mutex::new(State {
                log,
                sequence: 0,
                written: 0,
                dropped: 0,
                error,
                start_written: false,
                end_written: false,
            }),
            reported: AtomicBool::new(false),
        };
        if let Some(error) = error {
            result.report(error);
        } else if let Ok(mut state) = result.state.lock() {
            match result.marker(&mut state, "native-event-stream-start") {
                Ok(()) => state.start_written = true,
                Err(error) => result.disable(&mut state, error),
            }
        }
        result
    }

    pub(super) fn produced(&self, header: &Header) {
        self.header(Kind::Produced, header);
    }

    fn header(&self, kind: Kind, header: &Header) {
        // Capture the edge before file locking, encoding or I/O. A wall-clock
        // failure leaves timing unknown rather than inventing a timestamp.
        let wall = wall_ms();
        let elapsed = self.started.elapsed().as_nanos().to_string();
        let identity = header
            .id()
            .ok()
            .filter(|_| header.network == self.binding.network);
        self.record(kind, header.height, identity, wall, elapsed);
    }

    fn record(
        &self,
        kind: Kind,
        height: u64,
        identity: Option<Hash>,
        wall: Option<u64>,
        elapsed: String,
    ) {
        let Ok(mut state) = self.state.lock() else {
            self.report("native_event_lock_poisoned");
            return;
        };
        let Some(sequence) = state.sequence.checked_add(1) else {
            self.fail(&mut state, "native_event_sequence_exhausted");
            return;
        };
        state.sequence = sequence;
        if state.end_written {
            self.fail(&mut state, "native_event_stream_closed");
            return;
        }
        let Some(block) = identity else {
            self.fail(&mut state, "native_event_header_unavailable");
            return;
        };
        let block_id = crate::local::hex(&block);
        let node_id = self.binding.node.map(|node| crate::local::hex(&node));
        let mut value = json!({
            "version":1,"record":"block-event","event_source":"native-runtime-hook","kind":kind.name(),
            "network_id":crate::local::hex(&self.binding.network),
            "genesis_id":crate::local::hex(&self.binding.genesis),
            "source_commit":self.binding.source,"source_commit_origin":"compile-time-declaration",
            "source_commit_externally_verified":false,"binary_sha256":self.binding.binary,
            "node_id":node_id,"run_id":self.binding.run,"sequence":sequence,
            "block_id":block_id,"height":height,"event_unix_ms":wall,
            "elapsed_monotonic_ns":elapsed,"clock_offset_ms":null,"clock_uncertainty_ms":null,
            "clock_calibration_measured":false,
            "deduplication_key":[kind.name(),node_id,self.binding.run,block_id],
        });
        match kind {
            Kind::Produced => value["produced_unix_ms"] = json!(wall),
            Kind::Accepted => value["accepted_unix_ms"] = json!(wall),
        }
        let encoded = serde_json::to_vec(&value).map_err(|_| "native_event_encoding_failed");
        let result = encoded.and_then(|mut bytes| {
            bytes.push(b'\n');
            if bytes.len() > RECORD_BYTES {
                return Err("native_event_record_limit");
            }
            state
                .log
                .as_mut()
                .ok_or("native_event_log_disabled")?
                .append(&bytes)
        });
        match result {
            Ok(()) => state.written = state.written.saturating_add(1),
            Err(error) => self.fail(&mut state, error),
        }
    }

    fn fail(&self, state: &mut State, error: &'static str) {
        state.dropped = state.dropped.saturating_add(1);
        self.disable(state, error);
    }
    fn disable(&self, state: &mut State, error: &'static str) {
        state.error.get_or_insert(error);
        // A partial write must never be followed by another JSON record in the
        // same process. Keep the diagnostic and let a later run open a new slot.
        state.log = None;
        self.report(error);
    }
    fn marker(&self, state: &mut State, kind: &str) -> Result<(), &'static str> {
        let mut bytes = serde_json::to_vec(&json!({
            "version":1,"record":"stream-marker","kind":kind,
            "event_source":"native-runtime-hook","node_id":self.binding.node.map(|node|crate::local::hex(&node)),
            "network_id":crate::local::hex(&self.binding.network),
            "genesis_id":crate::local::hex(&self.binding.genesis),
            "source_commit":self.binding.source,"source_commit_externally_verified":false,
            "binary_sha256":self.binding.binary,"run_id":self.binding.run,
            "event_attempts":state.sequence,"written_events":state.written,
            "dropped_events":state.dropped,"error_code":state.error,
            "event_unix_ms":wall_ms(),
            "elapsed_monotonic_ns":self.started.elapsed().as_nanos().to_string(),
        })).map_err(|_| "native_event_encoding_failed")?;
        bytes.push(b'\n');
        if bytes.len() > RECORD_BYTES {
            return Err("native_event_record_limit");
        }
        state
            .log
            .as_mut()
            .ok_or("native_event_log_disabled")?
            .append(&bytes)
    }
    pub(super) fn finish(&self) {
        let Ok(mut state) = self.state.lock() else {
            self.report("native_event_lock_poisoned");
            return;
        };
        if state.end_written || state.log.is_none() {
            return;
        }
        match self.marker(&mut state, "native-event-stream-end") {
            Ok(()) => state.end_written = true,
            Err(error) => self.disable(&mut state, error),
        }
    }
    fn report(&self, error: &'static str) {
        if !self.reported.swap(true, Ordering::Relaxed) {
            let _ = writeln!(
                std::io::stderr().lock(),
                "native block event recording unavailable: {error}"
            );
        }
    }
    pub(super) fn diagnostic(&self) -> Value {
        match self.state.lock() {
            Ok(state) => json!({
                "enabled":state.log.is_some(),"error_code":state.error,
                "last_sequence":state.sequence,"written_events":state.written,
                "event_attempts":state.sequence,"dropped_events":state.dropped,
                "stream_start_written":state.start_written,"stream_end_written":state.end_written,
                "segment_rollovers":state.log.as_ref().map(|log|log.rollovers),
                "retention_replaced_prior_slot":state.log.as_ref().map(|log|log.replaced_prior_slot),
                "coverage_established":false,"segment_count_limit":SEGMENTS,
                "segment_bytes_limit":SEGMENT_BYTES,"record_bytes_limit":RECORD_BYTES,
                "source_commit_available":self.binding.source.is_some(),
                "source_commit_externally_verified":false,"clock_calibration_measured":false,
            }),
            Err(_) => json!({"enabled":false,"error_code":"native_event_lock_poisoned"}),
        }
    }
}
impl CommitObserver for Recorder {
    fn committed(&self, header: &Header) {
        self.header(Kind::Accepted, header);
    }
}
fn wall_ms() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis()
        .try_into()
        .ok()
}
fn hex_text(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

struct Ring {
    directory: PathBuf,
    file: File,
    index: usize,
    bytes: u64,
    limit: u64,
    rollovers: u64,
    replaced_prior_slot: bool,
}
impl Ring {
    fn open(directory: &Path, limit: u64) -> Result<Self, &'static str> {
        let mut first_absent = None;
        // Check exactly the four owned filenames. Never enumerate or remove
        // other files, create run directories or repair an oversized old log.
        for index in 0..SEGMENTS {
            match fs::symlink_metadata(path(directory, index)) {
                Ok(metadata)
                    if metadata.is_file()
                        && !metadata.file_type().is_symlink()
                        && metadata.len() <= limit => {}
                Ok(_) => return Err("native_event_existing_log_rejected"),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    first_absent.get_or_insert(index);
                }
                Err(_) => return Err("native_event_log_metadata_failed"),
            }
        }
        // A fresh run never appends to a possibly interrupted JSON record.
        // Retention is bounded across runs; collection must precede rollover.
        let index = first_absent.unwrap_or(0);
        let file = open_slot(directory, index, true)?;
        Ok(Self {
            directory: directory.to_owned(),
            file,
            index,
            bytes: 0,
            limit,
            rollovers: 0,
            replaced_prior_slot: first_absent.is_none(),
        })
    }
    fn append(&mut self, bytes: &[u8]) -> Result<(), &'static str> {
        if bytes.len() as u64 > self.limit {
            return Err("native_event_record_limit");
        }
        if self
            .file
            .metadata()
            .map_err(|_| "native_event_log_metadata_failed")?
            .len()
            != self.bytes
        {
            return Err("native_event_log_changed");
        }
        if self.bytes + bytes.len() as u64 > self.limit {
            let next = (self.index + 1) % SEGMENTS;
            self.file = open_slot(&self.directory, next, true)?;
            self.index = next;
            self.bytes = 0;
            self.rollovers = self.rollovers.saturating_add(1);
        }
        self.file
            .write_all(bytes)
            .and_then(|()| self.file.sync_data())
            .map_err(|_| "native_event_log_write_failed")?;
        self.bytes += bytes.len() as u64;
        Ok(())
    }
}
fn path(directory: &Path, index: usize) -> PathBuf {
    directory.join(format!("native-block-events-{index}.jsonl"))
}
fn open_slot(directory: &Path, index: usize, truncate: bool) -> Result<File, &'static str> {
    let path = path(directory, index);
    #[cfg(windows)]
    let mut file = {
        let parent = siworld_miner_platform::Directory::open(directory)
            .map_err(|_| "native_event_directory_rejected")?;
        let name = path.file_name().ok_or("native_event_filename_rejected")?;
        if path
            .try_exists()
            .map_err(|_| "native_event_log_metadata_failed")?
        {
            parent.open_file(name, true)
        } else {
            parent.create_file(name)
        }
        .map_err(|_| "native_event_log_open_failed")?
    };
    #[cfg(not(windows))]
    let mut file = {
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
        }
        options
            .open(&path)
            .map_err(|_| "native_event_log_open_failed")?
    };
    let metadata = file
        .metadata()
        .map_err(|_| "native_event_log_metadata_failed")?;
    if !metadata.is_file() {
        return Err("native_event_log_shape_rejected");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err("native_event_log_permissions_rejected");
        }
    }
    if truncate {
        file.set_len(0)
            .map_err(|_| "native_event_log_reset_failed")?;
    }
    file.seek(SeekFrom::End(0))
        .map_err(|_| "native_event_log_seek_failed")?;
    Ok(file)
}

#[cfg(test)]
mod tests;
