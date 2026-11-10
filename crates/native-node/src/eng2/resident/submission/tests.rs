use super::*;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    time::Instant,
};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let mut seed = [0; 8];
        getrandom::fill(&mut seed).unwrap();
        let path = PathBuf::from("/tmp").join(format!("e2s-{}", crate::local::hex(&seed)));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn socket(&self) -> PathBuf {
        self.0.join("s")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn body() -> Vec<u8> {
    vec![17; SIDECAR_BYTES + 12]
}
fn send(stream: &mut UnixStream, kind: u8, body: &[u8]) {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream.write_all(&[kind]).unwrap();
    stream
        .write_all(&(body.len() as u32).to_le_bytes())
        .unwrap();
    stream.write_all(body).unwrap();
}
fn response(stream: &mut UnixStream) -> (u8, serde_json::Value) {
    let mut header = [0; 5];
    stream.read_exact(&mut header).unwrap();
    let n = u32::from_le_bytes(header[1..].try_into().unwrap()) as usize;
    assert!(n <= 256);
    let mut payload = vec![0; n];
    stream.read_exact(&mut payload).unwrap();
    (header[0], serde_json::from_slice(&payload).unwrap())
}
fn call(path: &Path, kind: u8, body: &[u8]) -> (u8, serde_json::Value) {
    let mut stream = UnixStream::connect(path).unwrap();
    send(&mut stream, kind, body);
    response(&mut stream)
}
#[derive(Default)]
struct ExactOwner {
    calls: AtomicUsize,
    packet: Mutex<Option<Vec<u8>>>,
}
impl Owner for ExactOwner {
    fn submit(&self, packet: &[u8], deadline: &p2p::Deadline) -> Result<Hash, String> {
        deadline.check().map_err(|_| "expired")?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            u32::from_le_bytes(packet[..4].try_into().unwrap()) as usize,
            packet.len() - 4 - SIDECAR_BYTES
        );
        let mut original = self.packet.lock().unwrap();
        if original.as_ref().is_some_and(|previous| previous != packet) {
            return Err("synthetic backend private rejection".into());
        }
        *original = Some(packet.to_vec());
        Ok([42; 32])
    }
}
#[test]
fn framing_pending_ack_and_full_packet_retry_are_backend_owned() {
    let directory = Directory::new();
    let owner = Arc::new(ExactOwner::default());
    let budget = p2p::Budget::new(1024 * 1024);
    let socket = Socket::bind(&directory.socket(), budget.clone(), owner.clone()).unwrap();
    assert_eq!(
        fs::metadata(directory.socket())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let (status, ack) = call(&directory.socket(), 3, &body());
    assert_eq!(status, 0);
    assert_eq!(
        ack,
        serde_json::json!({"status":"pending", "statement_id":crate::local::hex(&[42; 32])})
    );
    assert_eq!(call(&directory.socket(), 3, &body()), (0, ack));
    let mut changed = body();
    *changed.last_mut().unwrap() ^= 1;
    let (status, error) = call(&directory.socket(), 3, &changed);
    assert_eq!(status, 1);
    assert_eq!(
        error,
        serde_json::from_slice::<serde_json::Value>(FAILURE).unwrap()
    );
    assert_eq!(owner.calls.load(Ordering::SeqCst), 3);
    assert_eq!(&owner.packet.lock().unwrap().as_ref().unwrap()[4..], body());
    drop(socket);
    assert!(!directory.socket().exists());
    assert_eq!(budget.available().unwrap(), 1024 * 1024);
}
#[test]
fn other_capabilities_and_invalid_lengths_never_reach_backend() {
    let directory = Directory::new();
    let owner = Arc::new(ExactOwner::default());
    let budget = p2p::Budget::new(1024 * 1024);
    let _socket = Socket::bind(&directory.socket(), budget.clone(), owner.clone()).unwrap();
    for kind in [0, 1, 2, 4, 255] {
        assert_eq!(call(&directory.socket(), kind, &[]).0, 1);
    }
    for length in [0, SIDECAR_BYTES as u32, MAX_REQUEST as u32 + 1, u32::MAX] {
        let mut stream = UnixStream::connect(directory.socket()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream.write_all(&[3]).unwrap();
        stream.write_all(&length.to_le_bytes()).unwrap();
        assert_eq!(response(&mut stream).0, 1);
    }
    let mut truncated = UnixStream::connect(directory.socket()).unwrap();
    truncated
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    truncated.write_all(&[3]).unwrap();
    truncated
        .write_all(&(body().len() as u32).to_le_bytes())
        .unwrap();
    truncated.write_all(&body()[..SIDECAR_BYTES]).unwrap();
    truncated.shutdown(std::net::Shutdown::Write).unwrap();
    assert_eq!(response(&mut truncated).0, 1);
    assert_eq!(owner.calls.load(Ordering::SeqCst), 0);
    assert_eq!(budget.available().unwrap(), 1024 * 1024);
}
#[test]
fn exhausted_shared_budget_rejects_before_body_read_or_backend() {
    let directory = Directory::new();
    let owner = Arc::new(ExactOwner::default());
    let budget = p2p::Budget::new(128);
    let _socket = Socket::bind(&directory.socket(), budget.clone(), owner.clone()).unwrap();
    let mut stream = UnixStream::connect(directory.socket()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream.write_all(&[3]).unwrap();
    stream
        .write_all(&(body().len() as u32).to_le_bytes())
        .unwrap();
    // No body is sent: a response establishes reservation precedes allocation/read.
    assert_eq!(response(&mut stream).0, 1);
    assert_eq!(owner.calls.load(Ordering::SeqCst), 0);
    assert_eq!(budget.available().unwrap(), 128);
}
#[test]
fn one_deadline_covers_scheduling_io_owner_contention_and_final_commit() {
    struct Delayed {
        clock: Arc<AtomicU64>,
        entered: mpsc::SyncSender<()>,
        gate: Mutex<mpsc::Receiver<()>>,
        committed: AtomicBool,
    }
    impl Owner for Delayed {
        fn submit(&self, _: &[u8], deadline: &p2p::Deadline) -> Result<Hash, String> {
            self.entered.send(()).unwrap();
            self.gate.lock().unwrap().recv().unwrap();
            assert_eq!(self.clock.load(Ordering::SeqCst), 10_000);
            deadline.check().map_err(|_| "expired before commit")?;
            self.committed.store(true, Ordering::SeqCst);
            Ok([42; 32])
        }
    }
    let clock = Arc::new(AtomicU64::new(0));
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (gate_tx, gate_rx) = mpsc::sync_channel(1);
    let owner = Arc::new(Delayed {
        clock: clock.clone(),
        entered: entered_tx,
        gate: Mutex::new(gate_rx),
        committed: AtomicBool::new(false),
    });
    let budget = p2p::Budget::new(1024 * 1024);
    let initial = budget.available().unwrap();
    let deadline = p2p::Deadline::test_clock(REQUEST_LIMIT, clock.clone());
    let (mut client, server) = UnixStream::pair().unwrap();
    let owner_job = owner.clone();
    let budget_job = budget.clone();
    let job = thread::spawn(move || connection(server, &budget_job, owner_job.as_ref(), &deadline));
    send(&mut client, 3, &body());
    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(budget.available().unwrap() < initial);
    clock.store(10_000, Ordering::SeqCst);
    gate_tx.send(()).unwrap();
    assert!(job.join().unwrap().is_err());
    assert!(!owner.committed.load(Ordering::SeqCst));
    assert_eq!(budget.available().unwrap(), initial);
    let mut one = [0];
    assert_eq!(client.read(&mut one).unwrap(), 0);
    // The same logical deadline rejects a request already expired before dispatch.
    let (mut client, mut server) = UnixStream::pair().unwrap();
    let expired = p2p::Deadline::test_clock(REQUEST_LIMIT, clock);
    send(&mut client, 3, &body());
    assert!(request(&mut server, &budget, owner.as_ref(), &expired).is_err());
}
#[test]
fn four_workers_bound_concurrency_and_shutdown_cancels_owner_admission() {
    struct Waiting {
        entered: mpsc::SyncSender<()>,
        active: AtomicUsize,
        committed: AtomicUsize,
    }
    impl Owner for Waiting {
        fn submit(&self, _: &[u8], deadline: &p2p::Deadline) -> Result<Hash, String> {
            assert!(self.active.fetch_add(1, Ordering::SeqCst) < WORKERS);
            self.entered.send(()).unwrap();
            while deadline.check().is_ok() {
                thread::sleep(IO_POLL);
            }
            self.active.fetch_sub(1, Ordering::SeqCst);
            deadline.check().map_err(|_| "cancelled")?;
            self.committed.fetch_add(1, Ordering::SeqCst);
            Ok([42; 32])
        }
    }
    let directory = Directory::new();
    let (tx, rx) = mpsc::sync_channel(WORKERS);
    let owner = Arc::new(Waiting {
        entered: tx,
        active: AtomicUsize::new(0),
        committed: AtomicUsize::new(0),
    });
    let budget = p2p::Budget::new(1024 * 1024);
    let socket = Socket::bind(&directory.socket(), budget.clone(), owner.clone()).unwrap();
    let mut clients = Vec::new();
    for _ in 0..WORKERS {
        let mut stream = UnixStream::connect(directory.socket()).unwrap();
        send(&mut stream, 3, &body());
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        clients.push(stream);
    }
    let mut rejected = UnixStream::connect(directory.socket()).unwrap();
    rejected
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut one = [0];
    assert_eq!(rejected.read(&mut one).unwrap(), 0);
    assert_eq!(owner.active.load(Ordering::SeqCst), WORKERS);
    let started = Instant::now();
    drop(socket);
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(owner.active.load(Ordering::SeqCst), 0);
    assert_eq!(owner.committed.load(Ordering::SeqCst), 0);
    assert_eq!(budget.available().unwrap(), 1024 * 1024);
    assert!(!directory.socket().exists());
}
#[test]
fn private_directory_and_existing_path_rules_preserve_replacements() {
    let directory = Directory::new();
    let owner = Arc::new(ExactOwner::default());
    let budget = p2p::Budget::new(1024 * 1024);
    fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o770)).unwrap();
    assert!(Socket::bind(&directory.socket(), budget.clone(), owner.clone()).is_err());
    fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(directory.socket(), b"synthetic replacement").unwrap();
    assert!(Socket::bind(&directory.socket(), budget.clone(), owner.clone()).is_err());
    assert_eq!(
        fs::read(directory.socket()).unwrap(),
        b"synthetic replacement"
    );
    fs::remove_file(directory.socket()).unwrap();
    symlink("missing", directory.socket()).unwrap();
    assert!(Socket::bind(&directory.socket(), budget.clone(), owner.clone()).is_err());
    fs::remove_file(directory.socket()).unwrap();
    let alias = Directory::new();
    fs::remove_dir(&alias.0).unwrap();
    symlink(&directory.0, &alias.0).unwrap();
    assert!(Socket::bind(&alias.socket(), budget.clone(), owner.clone()).is_err());
    fs::remove_file(&alias.0).unwrap();
    let replaced = Socket::bind(&directory.socket(), budget.clone(), owner.clone()).unwrap();
    fs::remove_file(directory.socket()).unwrap();
    fs::write(directory.socket(), b"replacement file").unwrap();
    drop(replaced);
    assert_eq!(fs::read(directory.socket()).unwrap(), b"replacement file");
    fs::remove_file(directory.socket()).unwrap();
    let socket = Socket::bind(&directory.socket(), budget, owner).unwrap();
    let moved = Directory::new();
    fs::remove_dir(&moved.0).unwrap();
    fs::rename(&directory.0, &moved.0).unwrap();
    fs::create_dir(&directory.0).unwrap();
    fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(directory.socket(), b"new directory entry").unwrap();
    drop(socket);
    assert!(!moved.socket().exists());
    assert_eq!(
        fs::read(directory.socket()).unwrap(),
        b"new directory entry"
    );
}
