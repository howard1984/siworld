//! Opt-in public file exports and the existing private reference interface.
//! No wallet custody, scan, signing, reward configuration or remote prover operation.
use crate::{
    runtime::Node,
    state::BlockVerifier,
    wire::{Hash, MAX_ENVELOPE_BYTES, SIDECAR_BYTES},
};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
mod export;
use export::PublicExport;

const MAX_REQUEST: usize = MAX_ENVELOPE_BYTES + SIDECAR_BYTES;
const MAX_RESPONSE: usize = crate::ranges::MAX_COMPACT + 48;
struct Request {
    kind: u8,
    body: Vec<u8>,
    reply: SyncSender<Result<Vec<u8>, String>>,
}
pub struct Gateway {
    socket: Option<(PathBuf, (u64, u64))>,
    export: Option<PublicExport>,
    submit_only: bool,
    retry_at: Instant,
    log_at: Instant,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
    rx: Receiver<Request>,
    cache: PathBuf,
    indexed: usize,
    ids: Vec<Hash>,
    packets: std::collections::BTreeMap<Hash, Hash>,
}
impl Gateway {
    pub fn from_environment() -> Result<Option<Self>, String> {
        let reference = std::env::var_os("SIWORLD_WALLET_GATEWAY_SOCKET");
        let submit = std::env::var_os("SIWORLD_WALLET_SUBMIT_SOCKET");
        let public = std::env::var_os("SIWORLD_WALLET_PUBLIC_EXPORT");
        Self::configured(
            reference.as_deref().map(Path::new),
            submit.as_deref().map(Path::new),
            public.as_deref().map(Path::new),
        )
    }
    fn configured(
        reference: Option<&Path>,
        submit: Option<&Path>,
        public: Option<&Path>,
    ) -> Result<Option<Self>, String> {
        if let Some(path) = submit {
            if reference.is_some() {
                return Err("Choose exactly one private wallet IPC capability.".into());
            }
            let mut gateway = Self::bind_with_access(path, true)?;
            if let Some(path) = public {
                match PublicExport::open(path) {
                    Ok(export) => {
                        gateway.export = Some(export);
                        gateway.cache = path.into();
                    }
                    Err(_) => {
                        eprintln!("Public wallet export disabled: initialization unavailable.")
                    }
                }
            }
            return Ok(Some(gateway));
        }
        match (reference, public) {
            (None, None) => Ok(None),
            (Some(path), None) => Self::bind(path).map(Some),
            (reference, Some(path)) => {
                // Export initialization is optional and must never stop the node.
                if reference.is_none()
                    && let Ok(export) = Self::export_only(path)
                {
                    return Ok(Some(export));
                }
                eprintln!("Public wallet export disabled: initialization unavailable.");
                Ok(None)
            }
        }
    }
    /// File-only capability: no socket, listener, request thread or admission path.
    fn export_only(path: &Path) -> Result<Self, String> {
        let export = PublicExport::open(path)?;
        let (_, rx) = mpsc::sync_channel(1);
        Ok(Self {
            socket: None,
            export: Some(export),
            submit_only: false,
            retry_at: Instant::now(),
            log_at: Instant::now(),
            stop: Arc::new(AtomicBool::new(false)),
            join: None,
            rx,
            cache: path.into(),
            indexed: 0,
            ids: Vec::new(),
            packets: std::collections::BTreeMap::new(),
        })
    }
    pub fn bind(path: &Path) -> Result<Self, String> {
        Self::bind_with_access(path, false)
    }
    fn bind_with_access(path: &Path, submit_only: bool) -> Result<Self, String> {
        if path.exists() || path.symlink_metadata().is_ok() {
            return Err("Wallet gateway path already exists; no replacement performed.".into());
        }
        let parent = path.parent().ok_or("Private gateway parent unavailable.")?;
        let metadata =
            std::fs::symlink_metadata(parent).map_err(|_| "Private gateway parent unavailable.")?;
        if !metadata.is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("Gateway requires an existing private directory with mode 700.".into());
        }
        let listener =
            UnixListener::bind(path).map_err(|_| "Private wallet gateway socket unavailable.")?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| "Private wallet gateway permissions unavailable.")?;
        let socket_metadata =
            std::fs::symlink_metadata(path).map_err(|_| "Private socket metadata unavailable.")?;
        let socket_identity = (socket_metadata.dev(), socket_metadata.ino());
        listener
            .set_nonblocking(true)
            .map_err(|_| "Private wallet gateway mode unavailable.")?;
        let cache = parent.join("compact-public");
        if !submit_only {
            match std::fs::create_dir(&cache) {
                Ok(()) => std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o700))
                    .map_err(|_| "Compact archive permissions unavailable.")?,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(_) => return Err("Compact archive unavailable.".into()),
            }
            let metadata =
                std::fs::symlink_metadata(&cache).map_err(|_| "Compact archive unavailable.")?;
            if !metadata.is_dir()
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err("Compact archive must remain a private directory.".into());
            }
        }
        let (tx, rx) = mpsc::sync_channel(4);
        let stop = Arc::new(AtomicBool::new(false));
        let cancel = stop.clone();
        let active = Arc::new(AtomicUsize::new(0));
        let join = thread::spawn(move || {
            let mut jobs: Vec<JoinHandle<()>> = Vec::new();
            while !cancel.load(Ordering::SeqCst) {
                let mut at = 0;
                while at < jobs.len() {
                    if jobs[at].is_finished() {
                        let _ = jobs.swap_remove(at).join();
                    } else {
                        at += 1;
                    }
                }
                match listener.accept() {
                    Ok((stream, _)) if active.load(Ordering::SeqCst) < 4 => {
                        active.fetch_add(1, Ordering::SeqCst);
                        let count = active.clone();
                        let tx = tx.clone();
                        let stopped = cancel.clone();
                        jobs.push(thread::spawn(move || {
                            let _ = connection(stream, tx, stopped);
                            count.fetch_sub(1, Ordering::SeqCst);
                        }));
                    }
                    Ok(_) => (),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20))
                    }
                    Err(_) => break,
                }
            }
            for job in jobs {
                let _ = job.join();
            }
        });
        Ok(Self {
            socket: Some((path.to_owned(), socket_identity)),
            export: None,
            submit_only,
            retry_at: Instant::now(),
            log_at: Instant::now(),
            stop,
            join: Some(join),
            rx,
            cache,
            indexed: 0,
            ids: Vec::new(),
            packets: std::collections::BTreeMap::new(),
        })
    }
    /// Process at most one bounded request on the sole canonical-state owner.
    pub fn poll<V: BlockVerifier>(&mut self, node: &mut Node<V>) {
        if let Ok(request) = self.rx.try_recv() {
            let response = self.dispatch(node, request.kind, &request.body);
            let _ = request.reply.send(response);
        }
        if (self.submit_only && self.export.is_none()) || Instant::now() < self.retry_at {
            return;
        }
        // Share one history backfill allowance across requests and export work:
        // at most one canonical anchor lookup, one new ID and one compact record.
        // Read requests never perform additional canonical history generation.
        let result: Result<(), String> = (|| {
            self.index_step(node)?;
            if self.indexed < self.ids.len() {
                self.compact(node, self.indexed)?;
                self.indexed += 1;
            }
            if self.index_complete(node)
                && self.indexed == self.ids.len()
                && let Some(export) = &mut self.export
            {
                export.publish(&node.state().config, &self.ids)?;
                export.publish_checkpoint(node.store(), &self.ids)?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.retry_at = Instant::now() + Duration::from_secs(5);
            if self.export.is_some() && Instant::now() >= self.log_at {
                // No path, node identity, private packet or underlying error is logged.
                eprintln!("Public wallet export unavailable; node operation continues.");
                self.log_at = Instant::now() + Duration::from_secs(60);
            }
        }
    }
    fn index_complete<V: BlockVerifier>(&self, node: &Node<V>) -> bool {
        self.ids.len() as u64 == node.state().height
            && self
                .ids
                .last()
                .copied()
                .unwrap_or(node.state().config.genesis_id())
                == node.state().tip
    }
    fn index_step<V: BlockVerifier>(&mut self, node: &Node<V>) -> Result<(), String> {
        if node.state().height > 1_000_000 {
            return Err("Engineering wallet index height limit.".into());
        }
        if self.index_complete(node) {
            return Ok(());
        }
        if self.ids.len() as u64 > node.state().height
            || (!self.ids.is_empty()
                && node.store().public_block_id(self.ids.len() as u64)?
                    != *self.ids.last().unwrap())
        {
            self.ids.clear();
            self.indexed = 0;
        }
        if (self.ids.len() as u64) < node.state().height {
            self.ids
                .push(node.store().public_block_id(self.ids.len() as u64 + 1)?);
        }
        if self.ids.len() as u64 == node.state().height && !self.index_complete(node) {
            return Err("Public history does not reach accepted native head.".into());
        }
        Ok(())
    }
    fn cached_compact(&self, at: usize) -> Result<Option<Vec<u8>>, String> {
        let id = self.ids[at];
        let path = self.cache.join(format!("{}.bin", crate::local::hex(&id)));
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("Compact archive metadata unavailable.".into()),
        };
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.len() > MAX_RESPONSE as u64
        {
            return Err("Compact archive record invalid.".into());
        }
        let bytes = std::fs::read(&path).map_err(|_| "Compact archive unreadable.")?;
        let record = crate::compact::CompactBlock::decode(&bytes)?;
        if record.id != id {
            return Err("Compact archive identity mismatch.".into());
        }
        Ok(Some(bytes))
    }
    fn compact<V: BlockVerifier>(&self, node: &Node<V>, at: usize) -> Result<Vec<u8>, String> {
        if let Some(bytes) = self.cached_compact(at)? {
            return Ok(bytes);
        }
        let id = self.ids[at];
        let path = self.cache.join(format!("{}.bin", crate::local::hex(&id)));
        let bytes = node.store().public_compact_block(at as u64 + 1)?;
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(|_| "Compact archive randomness unavailable.")?;
        let temp = self
            .cache
            .join(format!("{}.tmp", crate::local::hex(&random)));
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .map_err(|_| "Compact archive write unavailable.")?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|_| "Compact archive permissions unavailable.")?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| "Compact archive write failed.")?;
        std::fs::rename(&temp, &path).map_err(|_| "Compact archive commit failed.")?;
        std::fs::File::open(&self.cache)
            .and_then(|f| f.sync_all())
            .map_err(|_| "Compact archive directory commit failed.")?;
        Ok(bytes)
    }
    fn dispatch<V: BlockVerifier>(
        &mut self,
        node: &mut Node<V>,
        kind: u8,
        body: &[u8],
    ) -> Result<Vec<u8>, String> {
        if self.socket.is_none() {
            return Err("File export has no request capability.".into());
        }
        if self.submit_only && kind != 3 {
            return Err("Submission-only IPC rejects data and administrative operations.".into());
        }
        if kind == 3 {
            if body.len() <= SIDECAR_BYTES || body.len() > MAX_REQUEST {
                return Err("Native packet limit.".into());
            }
            let split = body.len() - SIDECAR_BYTES;
            let transaction = crate::wire::Transaction::decode_envelope(
                &body[..split],
                &node.state().config.network,
            )?;
            let statement = transaction
                .record
                .statement_id(&node.state().config.network);
            let packet_hash = *blake3::hash(body).as_bytes();
            if self.packets.get(&statement) == Some(&packet_hash)
                && node.mempool().contains(&statement)
            {
                return Ok(
                    json!({"status":"pending","statement_id":crate::local::hex(&statement)})
                        .to_string()
                        .into_bytes(),
                );
            }
            self.packets.retain(|id, _| node.mempool().contains(id));
            if self.packets.len() >= 2048 {
                return Err("Native admission gateway tracking capacity.".into());
            }
            let id = node
                .submit_local(&body[..split], Some(&body[split..]))
                .map_err(|_| "Native admission did not acknowledge pending.")?;
            self.packets.insert(id, packet_hash);
            return Ok(
                json!({"status":"pending","statement_id":crate::local::hex(&id)})
                    .to_string()
                    .into_bytes(),
            );
        }
        if !self.index_complete(node) || self.indexed != self.ids.len() {
            return Err("Public history backfill is incomplete.".into());
        }
        let result = match kind {
            0 if body.is_empty() => {
                json!({"network":crate::local::hex(&node.state().config.network),"genesis":crate::local::hex(&node.state().config.genesis_id()),"height":node.state().height,"compact_available_height":self.indexed,"tip":crate::local::hex(&node.state().tip)})
            }
            1 if body.len() <= 1000 => {
                let v: Value =
                    serde_json::from_slice(body).map_err(|_| "Invalid index request.")?;
                let o = v.as_object().ok_or("Invalid index request.")?;
                let start = v["from"].as_u64().ok_or("Invalid index start.")?;
                let limit = v["limit"].as_u64().ok_or("Invalid index limit.")?;
                let requested = v["tip"]
                    .as_str()
                    .ok_or("Invalid immutable chain identity.")?;
                let pinned_height =
                    if requested == crate::local::hex(&node.state().config.genesis_id()) {
                        0
                    } else {
                        self.ids
                            .iter()
                            .position(|id| crate::local::hex(id) == requested)
                            .map(|at| at as u64 + 1)
                            .ok_or("Requested immutable chain unavailable.")?
                    };
                if o.len() != 3
                    || start == 0
                    || limit == 0
                    || limit > 128
                    || start > pinned_height + 1
                {
                    return Err("Requested immutable chain unavailable.".into());
                }
                json!({"ids":self.ids.iter().take(pinned_height as usize).skip(start as usize-1).take(limit as usize).map(|id|crate::local::hex(id)).collect::<Vec<_>>()})
            }
            2 if body.len() == 32 => {
                let id: Hash = body.try_into().unwrap();
                let at = self
                    .ids
                    .iter()
                    .position(|known| *known == id)
                    .ok_or("Compact block unavailable.")?;
                return self
                    .cached_compact(at)?
                    .ok_or("Compact block unavailable.".into());
            }
            _ => return Err("Unsupported public-data operation.".into()),
        };
        Ok(result.to_string().into_bytes())
    }
}
fn connection(
    mut stream: UnixStream,
    tx: SyncSender<Request>,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .map_err(|_| "Private IPC unavailable.")?;
    stream
        .set_write_timeout(Some(Duration::from_secs(1)))
        .map_err(|_| "Private IPC unavailable.")?;
    let mut header = [0u8; 5];
    stream
        .read_exact(&mut header)
        .map_err(|_| "Private request truncated.")?;
    let n = u32::from_le_bytes(header[1..].try_into().unwrap()) as usize;
    if n > MAX_REQUEST {
        return Err("Private request limit.".into());
    }
    let mut body = vec![0; n];
    stream
        .read_exact(&mut body)
        .map_err(|_| "Private request truncated.")?;
    let (reply, rx) = mpsc::sync_channel(1);
    tx.try_send(Request {
        kind: header[0],
        body,
        reply,
    })
    .map_err(|_| "Private request capacity.")?;
    let start = std::time::Instant::now();
    let result = loop {
        if stop.load(Ordering::SeqCst) || start.elapsed() > Duration::from_secs(30) {
            return Err("Private request stopped or timed out.".into());
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(value) => break value,
            Err(mpsc::RecvTimeoutError::Timeout) => (),
            Err(_) => return Err("Private request unavailable.".into()),
        }
    };
    let (status, body) = match result {
        Ok(b) if b.len() <= MAX_RESPONSE => (0, b),
        _ => (
            1,
            b"{\"error\":\"Native public-data request unavailable.\"}".to_vec(),
        ),
    };
    stream
        .write_all(&[status])
        .and_then(|_| stream.write_all(&(body.len() as u32).to_le_bytes()))
        .and_then(|_| stream.write_all(&body))
        .map_err(|_| "Private response unavailable.".to_owned())
}
impl Drop for Gateway {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for request in self.rx.try_iter() {
            let _ = request.reply.send(Err("Gateway stopped.".into()));
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        if let Some((path, identity)) = &self.socket
            && std::fs::symlink_metadata(path).is_ok_and(|m| (m.dev(), m.ino()) == *identity)
        {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(test)]
#[path = "wallet_gateway/tests.rs"]
mod export_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        fixtures::{TestVerifier, candidate},
        state::Config,
        store::Store,
    };
    #[test]
    fn public_gateway_uses_committed_history_and_original_admission() {
        let root = std::env::temp_dir().join(format!(
            "swg-{}",
            &crate::local::hex(&getrandom_seed())[..8]
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = Store::open(
            root.join("chain.redb"),
            Config::development([9; 32], 0).unwrap(),
            &TestVerifier,
        )
        .unwrap();
        let block = candidate(store.state(), 1500);
        store.append(&block, &TestVerifier).unwrap();
        let mut node = Node::new(store, TestVerifier);
        let mut gateway = Gateway::bind(&root.join("s")).unwrap();
        assert_eq!(
            std::fs::metadata(root.join("s"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        gateway.poll(&mut node);
        let value: Value =
            serde_json::from_slice(&gateway.dispatch(&mut node, 0, b"").unwrap()).unwrap();
        assert_eq!(value["height"], 1);
        assert_eq!(value["tip"], crate::local::hex(&block.id().unwrap()));
        let id = block.id().unwrap();
        let bytes = gateway.dispatch(&mut node, 2, &id).unwrap();
        let compact = crate::compact::CompactBlock::decode(&bytes).unwrap();
        assert_eq!(compact.id, id);
        assert!(
            compact
                .block
                .transactions
                .iter()
                .all(|t| t.proof.is_empty())
        );
        let index = json!({"tip":crate::local::hex(&id),"from":1,"limit":128}).to_string();
        let list: Value =
            serde_json::from_slice(&gateway.dispatch(&mut node, 1, index.as_bytes()).unwrap())
                .unwrap();
        assert_eq!(list["ids"].as_array().unwrap().len(), 1);
        assert!(
            gateway
                .dispatch(
                    &mut node,
                    1,
                    b"{\"tip\":\"wrong\",\"from\":1,\"limit\":129}"
                )
                .is_err()
        );
        assert!(gateway.dispatch(&mut node, 2, &[0; 32]).is_err());
        assert!(
            gateway
                .dispatch(&mut node, 3, &vec![0; MAX_REQUEST + 1])
                .is_err()
        );
        let socket = root.join("s");
        let client = thread::spawn(move || {
            let mut stream = UnixStream::connect(socket).unwrap();
            stream.write_all(&[0, 0, 0, 0, 0]).unwrap();
            let mut frame = [0; 5];
            stream.read_exact(&mut frame).unwrap();
            assert_eq!(frame[0], 0);
            let n = u32::from_le_bytes(frame[1..].try_into().unwrap()) as usize;
            let mut body = vec![0; n];
            stream.read_exact(&mut body).unwrap();
            let value: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(value["height"], 1);
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while !client.is_finished() {
            assert!(std::time::Instant::now() < deadline);
            gateway.poll(&mut node);
            thread::sleep(Duration::from_millis(5));
        }
        client.join().unwrap();
        assert!(
            gateway
                .dispatch(&mut node, 3, &[0; SIDECAR_BYTES + 1])
                .is_err()
        );
        // Exercise admission and byte-identical retry through the native test verifier.
        use native::{
            codec::encode_digest,
            multi_asset::{F, Hasher},
        };
        use p3_field::PrimeCharacteristicRing;
        let mut transaction = candidate(node.state(), 300).transactions.remove(0);
        transaction.record.fee_commit =
            encode_digest(&Hasher::new().fee_commit(100, &[F::from_u32(22); 8]));
        let sidecar = crate::wire::Sidecar {
            transaction_id: transaction
                .record
                .statement_id(&node.state().config.network),
            fee: 100,
            blind: [22; 8],
        };
        let mut packet = transaction
            .encode_envelope(&node.state().config.network)
            .unwrap();
        packet.extend(sidecar.encode().unwrap());
        let acknowledgment = gateway.dispatch(&mut node, 3, &packet).unwrap();
        assert_eq!(
            gateway.dispatch(&mut node, 3, &packet).unwrap(),
            acknowledgment
        );
        assert_eq!(node.mempool().len(), 1);
        let last = packet.len() - 1;
        packet[last] ^= 1;
        assert!(gateway.dispatch(&mut node, 3, &packet).is_err());
        assert_eq!(node.mempool().len(), 1);
        let next = candidate(node.state(), 500000);
        node.import_branch(1, &[next], crate::chain::CandidatePolicy::default())
            .unwrap();
        gateway.poll(&mut node);
        let pinned: Value =
            serde_json::from_slice(&gateway.dispatch(&mut node, 1, index.as_bytes()).unwrap())
                .unwrap();
        assert_eq!(pinned["ids"].as_array().unwrap().len(), 1);
        assert_eq!(pinned["ids"][0], crate::local::hex(&id));
        drop(gateway);
        assert!(!root.join("s").exists());
        drop(node);
        std::fs::remove_dir_all(root).unwrap();
    }
    fn getrandom_seed() -> [u8; 16] {
        let mut bytes = [0; 16];
        getrandom::fill(&mut bytes).unwrap();
        bytes
    }
}
