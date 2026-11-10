//! Explicit outbound signed bootstrap. Existing custody and trusted service pins
//! are loaded; this command creates no identity, listener or mining worker.
use super::*;
use crate::eng2::{
    bootstrap::{
        Manifest, cache,
        client::{self, Candidate, Progress},
        session::ColdSession,
    },
    connector::Connector,
    import::{self, Installation},
    network,
    transport::Peer,
};
use siworld_core::pow::Work;

struct Policy {
    floor: Work,
    headers: usize,
    payload: u64,
    rounds: u64,
    seconds: u64,
    resume: bool,
}
fn decimal(value: &Value) -> Result<u64, String> {
    let text = value
        .as_str()
        .ok_or("bootstrap byte and work bounds require decimal strings")?;
    if text.is_empty()
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("canonical decimal bootstrap bound required".into());
    }
    text.parse()
        .map_err(|_| "bootstrap decimal bound overflow".into())
}
impl Policy {
    fn decode(value: &Value) -> Result<Self, String> {
        if value.as_object().map(|v| v.len()) != Some(6) || value["version"] != 1 {
            return Err("explicit versioned signed bootstrap policy required".into());
        }
        let text = value["work_floor"]
            .as_str()
            .ok_or("explicit nonzero work floor required")?;
        if text.is_empty()
            || text.len() > 155
            || text.starts_with('0')
            || !text.bytes().all(|b| b.is_ascii_digit())
        {
            return Err("canonical nonzero decimal work floor required".into());
        }
        let floor = Work::from_dec_str(text).map_err(|_| "signed bootstrap work floor overflow")?;
        let headers = value["max_headers"]
            .as_u64()
            .filter(|n| (96..=1_000_000).contains(n))
            .ok_or("signed bootstrap header cap rejected")? as usize;
        let payload = decimal(&value["max_payload_bytes"])?;
        let rounds = value["max_rounds"]
            .as_u64()
            .filter(|n| (1..=1_000_000).contains(n))
            .ok_or("signed bootstrap round cap rejected")?;
        let seconds = value["max_seconds"]
            .as_u64()
            .filter(|n| (1..=36_000).contains(n))
            .ok_or("signed bootstrap elapsed cap rejected")?;
        if payload == 0 || payload > 512 * 1024 * 1024 * 1024 || floor.is_zero() {
            return Err("signed bootstrap payload or work floor rejected".into());
        }
        // Resume is an explicit command choice, never inferred from a failed
        // prior install or by overwriting an existing candidate.
        Ok(Self {
            floor,
            headers,
            payload,
            rounds,
            seconds,
            resume: false,
        })
    }
    fn load(path: &Path) -> Result<Self, String> {
        let mut bytes = Vec::new();
        crate::local::regular_read(path, true, 4096)?
            .read_to_end(&mut bytes)
            .map_err(|_| "signed bootstrap policy read failed")?;
        Self::decode(
            &serde_json::from_slice(&bytes).map_err(|_| "signed bootstrap policy malformed")?,
        )
    }
}

struct Operation {
    started: Instant,
    rounds: u64,
    maximum_rounds: u64,
    maximum_seconds: u64,
    cancel: p2p::Cancellation,
    done: Option<std::sync::mpsc::Sender<()>>,
    timer: Option<std::thread::JoinHandle<()>>,
    connections: u64,
    maximum_connections: u64,
}
impl Operation {
    fn new(policy: &Policy) -> Result<Self, String> {
        let cancel = p2p::Cancellation::default();
        let expiry = cancel.clone();
        let (done, receive) = std::sync::mpsc::channel();
        let maximum_seconds = policy.seconds;
        let timer = std::thread::Builder::new()
            .name("eng2-bootstrap-deadline".into())
            .spawn(move || {
                if receive
                    .recv_timeout(Duration::from_secs(maximum_seconds))
                    .is_err()
                {
                    expiry.cancel();
                }
            })
            .map_err(|_| "signed bootstrap deadline worker unavailable")?;
        Ok(Self {
            started: Instant::now(),
            rounds: 0,
            maximum_rounds: policy.rounds,
            maximum_seconds,
            cancel,
            done: Some(done),
            timer: Some(timer),
            connections: 0,
            maximum_connections: policy.rounds.saturating_add(4).min(65_536),
        })
    }
    fn check(&self) -> Result<(), String> {
        if self.cancel.is_cancelled()
            || self.started.elapsed() >= Duration::from_secs(self.maximum_seconds)
            || self.rounds >= self.maximum_rounds
        {
            return Err("signed bootstrap operation budget exhausted; quarantine preserved".into());
        }
        Ok(())
    }
    fn round(&mut self) -> Result<(), String> {
        self.check()?;
        self.rounds += 1;
        Ok(())
    }
    fn connect(&mut self) -> Result<(), String> {
        self.check()?;
        if self.connections >= self.maximum_connections {
            return Err(
                "signed bootstrap connection budget exhausted; quarantine preserved".into(),
            );
        }
        self.connections += 1;
        Ok(())
    }
    fn backoff(&self, failure: u32) -> Result<(), String> {
        let until = Instant::now() + Duration::from_millis(100 * (1 << failure.min(3)));
        while Instant::now() < until {
            self.check()?;
            std::thread::sleep(Duration::from_millis(20));
        }
        self.check()
    }
}
impl Drop for Operation {
    fn drop(&mut self) {
        if let Some(done) = self.done.take() {
            let _ = done.send(());
        }
        if let Some(timer) = self.timer.take() {
            let _ = timer.join();
        }
    }
}

const RETRIES: u32 = 4;
#[derive(Default)]
struct Accounting {
    received: u64,
    sent: u64,
    sessions: u64,
    overflow: bool,
    #[cfg(test)]
    retired: Vec<(u64, u64)>,
}
struct Live {
    peer: Peer<p2p::NativeTlsChannel>,
    cold: ColdSession,
    initial: (u64, u64),
}
struct Acquisition<'a> {
    connector: &'a Connector,
    destination: &'a config::Destination,
    genesis: &'a Genesis,
    accounting: Arc<Mutex<Accounting>>,
    manifest: Option<Vec<u8>>,
    live: Option<Live>,
    rotation_bytes: u64,
}
impl<'a> Acquisition<'a> {
    fn new(
        connector: &'a Connector,
        destination: &'a config::Destination,
        genesis: &'a Genesis,
        accounting: Arc<Mutex<Accounting>>,
        manifest: Option<Vec<u8>>,
    ) -> Self {
        Self {
            connector,
            destination,
            genesis,
            accounting,
            manifest,
            live: None,
            rotation_bytes: u64::MAX,
        }
    }
    fn bind(&mut self, manifest: &Manifest) -> Result<(), String> {
        self.manifest = Some(manifest.encode()?);
        Ok(())
    }
    fn retire(&mut self) {
        if let Some(live) = self.live.take() {
            let (received, sent) = live.peer.encrypted_stream_bytes();
            // Counts cover actual encrypted I/O even when a later phase fails.
            // The partial stream is always dropped, never resumed or reused.
            if let Ok(mut counts) = self.accounting.lock() {
                match (
                    counts.received.checked_add(received),
                    counts.sent.checked_add(sent),
                    counts.sessions.checked_add(1),
                ) {
                    (Some(r), Some(s), Some(n)) => {
                        counts.received = r;
                        counts.sent = s;
                        counts.sessions = n;
                    }
                    _ => counts.overflow = true,
                }
                #[cfg(test)]
                counts.retired.push((received, sent));
            }
            drop(live);
        }
    }
    fn reusable(&self) -> bool {
        self.live.as_ref().is_some_and(|live| {
            let current = live.peer.encrypted_stream_bytes();
            live.peer.ready_for_cycle()
                && current.0.saturating_sub(live.initial.0) < self.rotation_bytes
                && current.1.saturating_sub(live.initial.1) < self.rotation_bytes
        })
    }
    fn ready(&mut self, operation: &mut Operation) -> Result<(), String> {
        if self.reusable() {
            return Ok(());
        }
        self.retire();
        for failure in 0..RETRIES {
            let cold = ColdSession::new(self.genesis)?;
            operation.connect()?;
            let peer = match self.connector.connect(
                self.destination.endpoint,
                self.destination.expected.fingerprint(),
                p2p::Role::Miner,
                operation.cancel.clone(),
            ) {
                Ok(peer) => peer,
                Err(p2p::Error::Unavailable) if failure + 1 < RETRIES => {
                    operation.backoff(failure)?;
                    continue;
                }
                Err(_) => {
                    return Err("signed bootstrap pinned service authentication unavailable".into());
                }
            };
            if !peer.ready_for_cycle() {
                return Err("fresh signed bootstrap session cannot fit one complete cycle".into());
            }
            self.live = Some(Live {
                initial: peer.encrypted_stream_bytes(),
                peer,
                cold,
            });
            // Every reconnect repeats both authentication and the entire
            // manifest round. Changed offers never replace retained bytes.
            if let Some(expected) = &self.manifest {
                operation.round()?;
                let live = self.live.as_mut().expect("authenticated session");
                let acquired =
                    live.cold
                        .round(&mut live.peer, network::Limits::default(), |pull| {
                            pull.manifest()
                        });
                match acquired {
                    Ok(completed) => {
                        let received = completed.acquired
                            .ok_or("signed bootstrap selected offer disappeared; quarantine preserved")?;
                        if received.bytes != *expected {
                            return Err("signed bootstrap selected offer changed; quarantine preserved".into());
                        }
                    }
                    Err(network::Error::Transport(p2p::Error::Unavailable))
                        if failure + 1 < RETRIES => {
                            self.retire();
                            operation.backoff(failure)?;
                            continue;
                        }
                    Err(_) => return Err("signed bootstrap exact-offer reconnection round failed; quarantine preserved".into()),
                }
            }
            return Ok(());
        }
        Err("signed bootstrap connection retry budget exhausted; quarantine preserved".into())
    }
    fn round<T>(
        &mut self,
        operation: &mut Operation,
        acquire: impl FnMut(
            &mut network::BootstrapPull<'_, p2p::NativeTlsChannel>,
        ) -> Result<T, network::Error>,
    ) -> Result<T, String> {
        let result = self.try_round(operation, acquire);
        if result.is_err() {
            self.retire();
        }
        result
    }
    fn try_round<T>(
        &mut self,
        operation: &mut Operation,
        mut acquire: impl FnMut(
            &mut network::BootstrapPull<'_, p2p::NativeTlsChannel>,
        ) -> Result<T, network::Error>,
    ) -> Result<T, String> {
        for failure in 0..RETRIES {
            operation.check()?;
            self.ready(operation)?;
            operation.round()?;
            let live = self
                .live
                .as_mut()
                .expect("authenticated complete-cycle session");
            let result = live
                .cold
                .round(&mut live.peer, network::Limits::default(), &mut acquire);
            match result {
                Ok(completed) => return Ok(completed.acquired),
                Err(network::Error::Transport(p2p::Error::Unavailable))
                    if failure + 1 < RETRIES =>
                {
                    self.retire();
                    operation.backoff(failure)?;
                }
                Err(_) => {
                    self.retire();
                    return Err(
                        "signed bootstrap acquisition round failed; quarantine preserved".into(),
                    );
                }
            }
        }
        Err("signed bootstrap round retry budget exhausted; quarantine preserved".into())
    }
}
impl Drop for Acquisition<'_> {
    fn drop(&mut self) {
        self.retire();
    }
}

pub fn bootstrap_signed(
    directory: &Path,
    configuration: &Path,
    policy_file: &Path,
    expected: &str,
    resume: bool,
) -> Result<Value, String> {
    bootstrap_signed_observed(
        directory,
        configuration,
        policy_file,
        expected,
        resume,
        Arc::new(Mutex::new(Accounting::default())),
        |_| Ok(()),
    )
}
fn bootstrap_signed_observed(
    directory: &Path,
    configuration: &Path,
    policy_file: &Path,
    expected: &str,
    resume: bool,
    accounting: Arc<Mutex<Accounting>>,
    mut observe: impl FnMut(Progress) -> Result<(), String>,
) -> Result<Value, String> {
    if std::env::var_os("GITHUB_ACTIONS").is_some()
        || matches!(std::env::var("CI").as_deref(), Ok("true") | Ok("1"))
    {
        return Err("signed bootstrap execution requires an owner-operated environment".into());
    }
    let mut policy = Policy::load(policy_file)?;
    policy.resume = resume;
    let _lease = service::Lease::acquire(directory)?;
    if directory.join("chain.redb").symlink_metadata().is_ok()
        || directory
            .join("checkpoint-import.redb")
            .symlink_metadata()
            .is_ok()
    {
        return Err("signed bootstrap never replaces a canonical or unadmitted database".into());
    }
    let genesis = Arc::new(load_genesis(directory, expected)?);
    let identity = Arc::new(
        NativeIdentity::load(directory, &genesis.peer_binding())
            .map_err(|_| "signed bootstrap requires a separately prepared existing identity")?,
    );
    let config = config::Configuration::load(directory, configuration, &genesis, &identity)?;
    if config.role != p2p::Role::Miner || config.listen.is_some() || config.checkpoint_key.is_some()
    {
        return Err(
            "signed bootstrap requires outbound-only miner mode without a checkpoint signing key"
                .into(),
        );
    }
    let destinations: Vec<_> = config.peers.iter().filter(|p| p.dial).collect();
    if destinations.is_empty() || destinations.len() > 4 {
        return Err(
            "signed bootstrap requires one through four independently pinned service destinations"
                .into(),
        );
    }
    let per_candidate = policy.payload / destinations.len() as u64;
    let budget = p2p::Budget::new(MEMORY_BYTES);
    let engine =
        super::super::execution::Engine::new(Genesis::decode(&genesis.encode()?)?, limits().chain)?;
    let body_policy = engine.body_policy();
    drop(engine);
    let connector = Connector::new(
        genesis.clone(),
        identity,
        destinations.iter().map(|p| p.expected.clone()).collect(),
        budget.clone(),
        body_policy,
    )
    .map_err(|_| "signed bootstrap connector rejected")?;
    let mut operation = Operation::new(&policy)?;
    let mut candidates = Vec::new();
    let mut bundles = Vec::new();
    for (index, destination) in destinations.iter().enumerate() {
        let mut session =
            Acquisition::new(&connector, destination, &genesis, accounting.clone(), None);
        let received = session
            .round(&mut operation, |p| p.manifest())?
            .ok_or("signed bootstrap service has no current bounded offer")?;
        let manifest = Manifest::decode(&received.bytes, &genesis, limits())?;
        drop(received);
        session.bind(&manifest)?;
        if manifest.tip_height > policy.headers as u64 {
            return Err("signed bootstrap manifest exceeds explicit complete header cap".into());
        }
        let path = directory.join(format!("signed-bootstrap-quarantine-{index}"));
        let cache_policy = cache::Policy {
            max_bytes: per_candidate,
            max_chunks_per_object: 1_048_576,
            max_body_bytes: body_policy.max_body_bytes,
        };
        let cache = if policy.resume {
            cache::Quarantine::reopen(&path, manifest, cache_policy, budget.clone())?
        } else {
            cache::Quarantine::create(&path, manifest, cache_policy, budget.clone())?
        };
        let mut candidate = Candidate::new(
            cache,
            &genesis,
            import::Policy {
                state: limits(),
                max_headers: policy.headers,
                max_verification_bytes: per_candidate
                    .checked_add(MAX_GENESIS_BYTES as u64 + 1024 * 1024)
                    .ok_or("bootstrap verification budget overflow")?,
            },
            body_policy,
        )?;
        while let Progress::Headers { next, total } = candidate.progress() {
            if next > total {
                break;
            }
            session.round(&mut operation, |p| candidate.pull_header(p))?;
        }
        bundles.push((candidate.manifest().bundle(), index));
        candidates.push(candidate.prepare(&genesis, policy.floor)?);
        // Candidate preparation may take time. Keep no idle authenticated
        // stream while other complete header histories are acquired.
        drop(session);
    }
    let mut client = client::select(candidates, policy.floor)?;
    let selected = bundles
        .iter()
        .find(|(bundle, _)| *bundle == client.manifest().bundle())
        .map(|(_, index)| *index)
        .ok_or("signed bootstrap selected service unavailable")?;
    let mut session = Acquisition::new(
        &connector,
        destinations[selected],
        &genesis,
        accounting.clone(),
        Some(client.manifest().encode()?),
    );
    while client.progress()? != Progress::Downloaded {
        session.round(&mut operation, |p| client.pull_step(p))?;
        observe(client.progress()?)?;
    }
    let download_elapsed_ms = operation.started.elapsed().as_millis();
    drop(session);
    let counts = accounting
        .lock()
        .map_err(|_| "signed bootstrap byte accounting unavailable")?;
    if counts.overflow {
        return Err("signed bootstrap byte accounting overflow".into());
    }
    let (received, sent, authenticated_sessions) = (counts.received, counts.sent, counts.sessions);
    drop(counts);
    let maximum_seconds = policy.seconds;
    let started = operation.started;
    let admitted = client.verify_and_install(&genesis, directory, || {
        operation.cancel.is_cancelled() || started.elapsed() >= Duration::from_secs(maximum_seconds)
    })?;
    let store = match admitted.installation {
        Installation::Durable(store) => store,
        Installation::DurabilityUnconfirmed => return Err("signed bootstrap canonical admission durability or reopen unconfirmed; preserve data and do not retry".into()),
    };
    let result = json!({"version":1,"phase":"durably_imported_waiting_for_native_peer_catchup","ready":false,"mining_started":false,
        "height":store.engine().state().height(),"tip":crate::local::hex(&store.engine().state().tip()),
        "checkpoint_height":store.imported_checkpoint_height(),"elapsed_ms":started.elapsed().as_millis().to_string(),"rounds":operation.rounds,
        "verification_bytes":admitted.verification_bytes.to_string(),"local_reread_bytes":admitted.local_reread_bytes.to_string(),
        "download_elapsed_ms":download_elapsed_ms.to_string(),"native_verification_ms":admitted.verification_ms.to_string(),
        "installation_ms":admitted.installation_ms.to_string(),"authenticated_reopen_ms":admitted.authenticated_reopen_ms.to_string(),
        "encrypted_received_bytes":received.to_string(),"encrypted_sent_bytes":sent.to_string(),
        "connection_attempts":operation.connections,"authenticated_sessions":authenticated_sessions,
        "network_byte_scope":"all established candidate and retry sessions in this invocation, including hybrid handshake and framing; failed pre-session handshakes, previous invocations and packet-wire bytes excluded"});
    drop(store);
    Ok(result)
}

#[cfg(test)]
#[path = "bootstrap_tests.rs"]
mod reconnect_tests;

#[cfg(all(test, unix, feature = "eng2-rehearsal"))]
#[path = "bootstrap_h96.rs"]
mod native_qualification;

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> Value {
        json!({"version":1,"work_floor":"1","max_headers":1000,"max_payload_bytes":"2147483648","max_rounds":1000,"max_seconds":3600})
    }
    #[test]
    fn policy_requires_canonical_explicit_nonzero_finite_work_and_resource_bounds() {
        let valid = policy();
        assert!(Policy::decode(&valid).is_ok());
        for (field, invalid) in [
            ("work_floor", json!("0")),
            ("work_floor", json!("01")),
            ("work_floor", json!("9".repeat(156))),
            ("work_floor", json!(1)),
            ("max_payload_bytes", json!("0")),
            ("max_payload_bytes", json!("01")),
            ("max_payload_bytes", json!("18446744073709551616")),
            ("max_headers", json!(95)),
            ("max_rounds", json!(0)),
            ("max_seconds", json!(36001)),
        ] {
            let mut value = valid.clone();
            value[field] = invalid;
            assert!(Policy::decode(&value).is_err(), "{field}");
        }
        let mut changed = valid.clone();
        changed["unknown"] = json!(false);
        assert!(Policy::decode(&changed).is_err());
        let mut bounded = Policy::decode(&valid).unwrap();
        bounded.rounds = 1;
        let mut operation = Operation::new(&bounded).unwrap();
        operation.round().unwrap();
        assert!(operation.round().is_err());
        // Dropping signals and reaps only this operation's deadline worker.
        drop(operation);
    }
}
