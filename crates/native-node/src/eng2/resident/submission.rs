//! Explicit owner-only transaction submission, with no read or network capability.
use crate::{
    p2p,
    wire::{Hash, MAX_ENVELOPE_BYTES, SIDECAR_BYTES},
};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, chmodat, statat, unlinkat};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::Path,
    sync::Arc,
    thread::{self, JoinHandle},
    time::Duration,
};
use zeroize::Zeroizing;

#[cfg(test)]
mod tests;

const WORKERS: usize = 4;
const REQUEST_LIMIT: Duration = Duration::from_secs(10);
const IO_POLL: Duration = Duration::from_millis(10);
const MAX_REQUEST: usize = MAX_ENVELOPE_BYTES + SIDECAR_BYTES;
const FAILURE: &[u8] = b"{\"error\":\"Native public-data request unavailable.\"}";

/// The backend owns chain/run binding, owner-lock contention, native admission
/// and byte-exact retry policy. It must check this same deadline immediately
/// before every admission mutation. A pending result never means inclusion.
pub(crate) trait Owner: Send + Sync + 'static {
    /// Packet framing is u32LE(envelope length), envelope, then fixed sidecar.
    /// The caller retains the shared allocation charge until this call returns.
    /// Neither packet bytes nor backend error text may be logged or exported.
    fn submit(&self, packet: &[u8], deadline: &p2p::Deadline) -> Result<Hash, String>;
}

// Device and inode integer widths differ across Unix targets.
#[allow(clippy::unnecessary_cast)]
fn stat_identity(stat: &rustix::fs::Stat) -> (u64, u64) {
    (stat.st_dev as u64, stat.st_ino as u64)
}

struct SocketFile {
    directory: File,
    name: std::ffi::OsString,
    identity: (u64, u64),
}
impl Drop for SocketFile {
    fn drop(&mut self) {
        // Resolve relative to the original opened directory, even after rename.
        // Only the created socket identity is eligible for cleanup.
        if statat(&self.directory, &self.name, AtFlags::SYMLINK_NOFOLLOW).is_ok_and(|stat| {
            stat_identity(&stat) == self.identity
                && FileType::from_raw_mode(stat.st_mode) == FileType::Socket
                && stat.st_uid == rustix::process::geteuid().as_raw()
        }) {
            let _ = unlinkat(&self.directory, &self.name, AtFlags::empty());
        }
    }
}

#[cfg(target_os = "linux")]
fn restrict_open_socket(file: &SocketFile, descriptor: &rustix::fd::OwnedFd) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    let matches = |value: &rustix::fs::Stat| {
        stat_identity(value) == file.identity
            && FileType::from_raw_mode(value.st_mode) == FileType::Socket
            && value.st_uid == rustix::process::geteuid().as_raw()
    };
    let opened =
        rustix::fs::fstat(descriptor).map_err(|_| "submission socket metadata unavailable")?;
    if !matches(&opened) {
        return Err("submission socket identity or permissions changed".into());
    }
    // O_PATH pins the filesystem socket inode without connecting to it.
    // Following this process's held descriptor is intentional; a replacement
    // named symlink is never resolved by the permission-changing operation.
    let reference = format!("/proc/self/fd/{}", descriptor.as_raw_fd());
    chmodat(
        rustix::fs::CWD,
        Path::new(&reference),
        Mode::from_raw_mode(0o600),
        AtFlags::empty(),
    )
    .map_err(|_| "submission socket permissions unavailable")?;
    let held =
        rustix::fs::fstat(descriptor).map_err(|_| "submission socket metadata unavailable")?;
    let named = statat(&file.directory, &file.name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| "submission socket directory changed")?;
    if !matches(&held) || held.st_mode & 0o777 != 0o600 || !matches(&named) {
        return Err("submission socket identity or permissions changed".into());
    }
    Ok(())
}

fn restrict_socket_permissions(file: &SocketFile) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let descriptor = rustix::fs::openat(
            &file.directory,
            &file.name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "submission socket metadata unavailable")?;
        restrict_open_socket(file, &descriptor)
    }
    #[cfg(not(target_os = "linux"))]
    {
        chmodat(
            &file.directory,
            &file.name,
            Mode::from_raw_mode(0o600),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| "submission socket permissions unavailable".into())
    }
}

fn bind(path: &Path) -> Result<(UnixListener, SocketFile), String> {
    let parent = path
        .parent()
        .ok_or("submission owner directory unavailable")?;
    let name = path
        .file_name()
        .ok_or("submission socket name unavailable")?
        .to_owned();
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC).bits() as i32)
        .open(parent)
        .map_err(|_| "submission owner directory unavailable")?;
    let metadata = directory
        .metadata()
        .map_err(|_| "submission owner directory unavailable")?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err("submission requires an existing owner directory with mode 700".into());
    }
    if !matches!(
        statat(&directory, &name, AtFlags::SYMLINK_NOFOLLOW),
        Err(rustix::io::Errno::NOENT)
    ) {
        return Err("submission path already exists or is unavailable".into());
    }
    let listener = UnixListener::bind(path).map_err(|_| "submission socket unavailable")?;
    let file_metadata = path
        .symlink_metadata()
        .map_err(|_| "submission socket metadata unavailable")?;
    let identity = (file_metadata.dev(), file_metadata.ino());
    let file = SocketFile {
        directory,
        name,
        identity,
    };
    let original = statat(&file.directory, &file.name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| "submission socket directory changed")?;
    if stat_identity(&original) != identity {
        return Err("submission socket directory changed".into());
    }
    restrict_socket_permissions(&file)?;
    let current = path
        .symlink_metadata()
        .map_err(|_| "submission socket unavailable")?;
    if (current.dev(), current.ino()) != identity
        || current.uid() != metadata.uid()
        || current.permissions().mode() & 0o777 != 0o600
        || !std::os::unix::fs::FileTypeExt::is_socket(&current.file_type())
    {
        return Err("submission socket identity or permissions changed".into());
    }
    listener
        .set_nonblocking(true)
        .map_err(|_| "submission listener unavailable")?;
    Ok((listener, file))
}

/// At most four connection workers; there is no unbounded request queue.
/// Construction is explicit and never reads capability-enabling environment.
pub(crate) struct Socket {
    cancellation: p2p::Cancellation,
    listener: Option<JoinHandle<()>>,
}
impl Socket {
    pub(crate) fn bind(
        path: &Path,
        budget: p2p::Budget,
        owner: Arc<dyn Owner>,
    ) -> Result<Self, String> {
        let (listener, file) = bind(path)?;
        let cancellation = p2p::Cancellation::default();
        let stop = cancellation.clone();
        let join = thread::Builder::new()
            .name("eng2-submit-listener".into())
            .spawn(move || {
                let _file = file;
                let mut jobs: Vec<(JoinHandle<()>, p2p::Cancellation)> =
                    Vec::with_capacity(WORKERS);
                while !stop.is_cancelled() {
                    let mut at = 0;
                    while at < jobs.len() {
                        if jobs[at].0.is_finished() {
                            let _ = jobs.swap_remove(at).0.join();
                        } else {
                            at += 1;
                        }
                    }
                    match listener.accept() {
                        Ok((stream, _)) if jobs.len() < WORKERS => {
                            let deadline = p2p::Deadline::new(REQUEST_LIMIT);
                            let cancel = deadline.cancellation().clone();
                            let budget = budget.clone();
                            let owner = owner.clone();
                            if let Ok(job) = thread::Builder::new()
                                .name("eng2-submit-request".into())
                                .spawn(move || {
                                    let _ = connection(stream, &budget, owner.as_ref(), &deadline);
                                })
                            {
                                jobs.push((job, cancel));
                            }
                        }
                        Ok(_) => thread::sleep(IO_POLL),
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(IO_POLL)
                        }
                        Err(_) => break,
                    }
                }
                for (_, cancel) in &jobs {
                    cancel.cancel();
                }
                for (job, _) in jobs {
                    let _ = job.join();
                }
            })
            .map_err(|_| "submission listener worker unavailable")?;
        Ok(Self {
            cancellation,
            listener: Some(join),
        })
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(listener) = self.listener.take() {
            let _ = listener.join();
        }
    }
}

fn read_all(stream: &mut UnixStream, bytes: &mut [u8], deadline: &p2p::Deadline) -> io::Result<()> {
    let mut at = 0;
    while at < bytes.len() {
        deadline.check()?;
        match stream.read(&mut bytes[at..]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => at += count,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error),
        }
    }
    deadline.check()
}
fn write_all(stream: &mut UnixStream, bytes: &[u8], deadline: &p2p::Deadline) -> io::Result<()> {
    let mut at = 0;
    while at < bytes.len() {
        deadline.check()?;
        match stream.write(&bytes[at..]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => at += count,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error),
        }
    }
    deadline.check()
}
fn request(
    stream: &mut UnixStream,
    budget: &p2p::Budget,
    owner: &dyn Owner,
    deadline: &p2p::Deadline,
) -> Result<Hash, String> {
    let mut header = [0; 5];
    read_all(stream, &mut header, deadline).map_err(|_| "submission request unavailable")?;
    let length = u32::from_le_bytes(header[1..].try_into().expect("fixed header")) as usize;
    if header[0] != 3 || length <= SIDECAR_BYTES || length > MAX_REQUEST {
        return Err("submission request capability or size rejected".into());
    }
    let framed = length.checked_add(4).ok_or("submission size overflow")?;
    // Charge the owned wire packet and bounded native decode/copy workspace.
    // Retained mempool ownership has its independent, bounded pool allowance.
    let charge = framed
        .checked_mul(4)
        .and_then(|n| n.checked_add(65536))
        .ok_or("submission charge overflow")?;
    let _reservation = budget
        .reserve(charge)
        .map_err(|_| "submission memory unavailable")?;
    let mut packet = Zeroizing::new(Vec::new());
    packet
        .try_reserve_exact(framed)
        .map_err(|_| "submission allocation unavailable")?;
    packet.resize(framed, 0);
    packet[..4].copy_from_slice(&((length - SIDECAR_BYTES) as u32).to_le_bytes());
    read_all(stream, &mut packet[4..], deadline).map_err(|_| "submission request unavailable")?;
    deadline
        .check()
        .map_err(|_| "submission deadline elapsed")?;
    // No adapter retry cache: the backend must compare the complete packet.
    let result = owner.submit(&packet, deadline).map_err(|error| {
        let _private_error = Zeroizing::new(error);
        "submission admission unavailable".to_owned()
    });
    deadline
        .check()
        .map_err(|_| "submission deadline elapsed")?;
    result
}
fn connection(
    mut stream: UnixStream,
    budget: &p2p::Budget,
    owner: &dyn Owner,
    deadline: &p2p::Deadline,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(IO_POLL))
        .and_then(|_| stream.set_write_timeout(Some(IO_POLL)))
        .map_err(|_| "submission stream unavailable")?;
    let result = request(&mut stream, budget, owner, deadline);
    let success;
    let (status, body) = match result {
        Ok(id) => {
            success = format!(
                "{{\"status\":\"pending\",\"statement_id\":\"{}\"}}",
                crate::local::hex(&id)
            );
            (0, success.as_bytes())
        }
        Err(_) => (1, FAILURE),
    };
    let mut header = [status, 0, 0, 0, 0];
    header[1..].copy_from_slice(&(body.len() as u32).to_le_bytes());
    write_all(&mut stream, &header, deadline)
        .and_then(|_| write_all(&mut stream, body, deadline))
        .map_err(|_| "submission response unavailable".into())
}
