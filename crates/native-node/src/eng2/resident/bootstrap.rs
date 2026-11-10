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

pub fn bootstrap_signed(
    directory: &Path,
    configuration: &Path,
    policy_file: &Path,
    expected: &str,
    resume: bool,
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
    let mut sessions = Vec::new();
    for (index, destination) in destinations.iter().enumerate() {
        operation.check()?;
        // Miner ingress presents and authenticates its descriptor. It does not
        // require the service operator to pre-register the miner identity.
        let mut peer = connector
            .connect(
                destination.endpoint,
                destination.expected.fingerprint(),
                p2p::Role::Miner,
                operation.cancel.clone(),
            )
            .map_err(|_| "signed bootstrap pinned service connection unavailable")?;
        let mut cold = ColdSession::new(&genesis)?;
        operation.round()?;
        let received = cold
            .round(&mut peer, network::Limits::default(), |p| p.manifest())
            .map_err(|_| "signed bootstrap manifest round failed")?
            .acquired
            .ok_or("signed bootstrap service has no current bounded offer")?;
        let manifest = Manifest::decode(&received.bytes, &genesis, limits())?;
        drop(received);
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
            operation.round()?;
            cold.round(&mut peer, network::Limits::default(), |p| {
                candidate.pull_header(p)
            })
            .map_err(|_| "signed bootstrap complete-header round failed")?;
        }
        let bundle = candidate.manifest().bundle();
        candidates.push(candidate.prepare(&genesis, policy.floor)?);
        sessions.push((bundle, peer, cold));
    }
    let mut client = client::select(candidates, policy.floor)?;
    let bundle = client.manifest().bundle();
    let selected = sessions
        .iter()
        .position(|(id, _, _)| *id == bundle)
        .ok_or("signed bootstrap selected session unavailable")?;
    let (_, mut peer, mut cold) = sessions.swap_remove(selected);
    let mut other_received = 0u64;
    let mut other_sent = 0u64;
    for (_, peer, _) in &sessions {
        let bytes = peer.encrypted_stream_bytes();
        other_received = other_received
            .checked_add(bytes.0)
            .ok_or("bootstrap stream byte overflow")?;
        other_sent = other_sent
            .checked_add(bytes.1)
            .ok_or("bootstrap stream byte overflow")?;
    }
    drop(sessions);
    while client.progress()? != Progress::Downloaded {
        operation.round()?;
        cold.round(&mut peer, network::Limits::default(), |p| {
            client.pull_step(p)
        })
        .map_err(|_| "signed bootstrap artifact round failed")?;
    }
    let encrypted = peer.encrypted_stream_bytes();
    let received = encrypted
        .0
        .checked_add(other_received)
        .ok_or("bootstrap stream byte overflow")?;
    let sent = encrypted
        .1
        .checked_add(other_sent)
        .ok_or("bootstrap stream byte overflow")?;
    drop(peer);
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
        "encrypted_received_bytes":received.to_string(),"encrypted_sent_bytes":sent.to_string(),
        "network_byte_scope":"all candidate sessions in this invocation, including hybrid handshake and framing; previous invocations and packet-wire bytes excluded"});
    drop(store);
    Ok(result)
}

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
