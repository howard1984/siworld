//! Opt-in owner-local qualification against a completed signed native fixture.
//! All output stays in a new private directory. No proof generation is used.
use super::*;
use crate::{
    eng2::{
        certificate::{AuthorizationWitness, Certificate},
        checkpoint_exchange,
        driver::Driver,
        runtime_export::PreparedCheckpoint,
        state_components::Binding,
        transaction_exchange, wallet_history,
    },
    identity::PeerPin,
};
use redb::{Database, ReadableTable, TableDefinition};
use sha2::{Digest, Sha256};
use std::{
    net::{Ipv4Addr, SocketAddr, TcpListener},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    thread::JoinHandle,
};
const GIB: u64 = 1024 * 1024 * 1024;
const PARTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("bootstrap-chunks-v1");

fn read(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    crate::local::regular_read(path, true, maximum)?
        .read_to_end(&mut bytes)
        .map_err(|_| "encrypted fixture public read failed")?;
    Ok(bytes)
}
fn digest(path: &Path, maximum: usize) -> Result<String, String> {
    let mut file = crate::local::regular_read(path, true, maximum)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| "encrypted fixture digest read failed")?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(crate::local::hex(&hash.finalize()))
}
fn copy_public_database(source: &Path, destination: &Path) -> Result<Value, String> {
    use std::io::Write;
    let started = Instant::now();
    let mut input = crate::local::regular_read(source, true, 16 * 1024 * 1024 * 1024)?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(destination)
        .map_err(|_| "new provider public database copy unavailable")?;
    let mut hash = Sha256::new();
    let mut copied = 0u64;
    let mut buffer = [0; 65536];
    loop {
        let count = input
            .read(&mut buffer)
            .map_err(|_| "provider public database copy read failed")?;
        if count == 0 {
            break;
        }
        output
            .write_all(&buffer[..count])
            .map_err(|_| "provider public database copy write failed")?;
        hash.update(&buffer[..count]);
        copied = copied
            .checked_add(count as u64)
            .ok_or("provider public database copy size overflow")?;
    }
    output
        .sync_all()
        .map_err(|_| "provider public database copy durability failed")?;
    drop(output);
    std::fs::File::open(destination.parent().ok_or("provider copy parent missing")?)
        .and_then(|parent| parent.sync_all())
        .map_err(|_| "provider public database copy directory durability failed")?;
    let metadata = destination
        .symlink_metadata()
        .map_err(|_| "provider public database copy metadata failed")?;
    if metadata.len() != copied {
        return Err("provider public database copy length differs".into());
    }
    Ok(
        json!({"copied_public_file_bytes":copied.to_string(),"initial_logical_bytes":metadata.len().to_string(),
        "initial_allocated_bytes":(metadata.blocks()*512).to_string(),"elapsed_ms":started.elapsed().as_millis().to_string(),
        "sha256":crate::local::hex(&hash.finalize()),"custody_copied":false}),
    )
}
fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|_| "new encrypted fixture output unavailable")?;
    output
        .write_all(bytes)
        .and_then(|()| output.sync_all())
        .map_err(|_| "encrypted fixture output durability failed".into())
}
fn mkdir(path: &Path) -> Result<(), String> {
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|_| "encrypted fixture requires a new private directory".into())
}
fn free_disk(path: &Path) -> Result<u64, String> {
    let value =
        rustix::fs::statvfs(path).map_err(|_| "encrypted fixture disk observation failed")?;
    u64::try_from(value.f_bavail as u128 * value.f_frsize as u128)
        .map_err(|_| "encrypted fixture disk observation overflow".into())
}
fn directory_size(path: &Path) -> Result<(u64, u64), String> {
    let metadata = path
        .symlink_metadata()
        .map_err(|_| "fixture size metadata unavailable")?;
    if metadata.is_symlink() {
        return Err("fixture size refuses symlinks".into());
    }
    let mut result = (metadata.len(), metadata.blocks() * 512);
    if metadata.is_dir() {
        for entry in std::fs::read_dir(path).map_err(|_| "fixture directory enumeration failed")? {
            let entry = entry.map_err(|_| "fixture directory entry failed")?;
            let size = directory_size(&entry.path())?;
            result.0 = result
                .0
                .checked_add(size.0)
                .ok_or("fixture size overflow")?;
            result.1 = result
                .1
                .checked_add(size.1)
                .ok_or("fixture allocation overflow")?;
        }
    }
    Ok(result)
}
fn public_file(
    directory: &Path,
    name: &str,
    bytes: &[u8],
    manifest: &mut Vec<Value>,
) -> Result<(), String> {
    write(&directory.join(name), bytes)?;
    manifest.push(
        json!({"file":name,"bytes":bytes.len(),"sha256":crate::local::hex(&Sha256::digest(bytes))}),
    );
    Ok(())
}
fn export_public(
    store: &Store,
    directory: &Path,
    budget: &p2p::Budget,
    expected_manifest: &Value,
) -> Result<Value, String> {
    mkdir(directory)?;
    let head = wallet_history::Head::capture(store)?;
    let mut manifest = Vec::new();
    public_file(
        directory,
        "wallet-genesis.bin",
        &wallet_history::bootstrap(store, &head)?,
        &mut manifest,
    )?;
    public_file(
        directory,
        "wallet-head.json",
        &serde_json::to_vec(&head.projection(unix_ms()? / 1000)?)
            .map_err(|_| "wallet head encoding failed")?,
        &mut manifest,
    )?;
    let headers = wallet_history::header_page(store, &head, 1, 96, budget)?;
    public_file(
        directory,
        "wallet-headers-1-96.bin",
        headers.bytes(),
        &mut manifest,
    )?;
    drop(headers);
    for height in 1..=96 {
        let receipt = wallet_history::receipts(store, &head, height, budget)?;
        if height <= 72 {
            let filename = format!("receipt-{height}.bin");
            let expected = expected_manifest
                .as_array()
                .ok_or("accepted artifact manifest missing")?
                .iter()
                .find(|entry| entry["file"] == filename)
                .ok_or("accepted prefix receipt record missing")?;
            if expected["bytes"].as_u64() != Some(receipt.bytes().len() as u64)
                || expected["sha256"] != crate::local::hex(&Sha256::digest(receipt.bytes()))
            {
                return Err("public prefix receipt differs from accepted manifest".into());
            }
        }
        public_file(
            directory,
            &format!("wallet-receipt-{height}.bin"),
            receipt.bytes(),
            &mut manifest,
        )?;
    }
    let state = store.engine().state().chain();
    let snapshots: Vec<_> = state.snapshots.iter().map(|s| json!({
        "height":s.selector.height,"block_id":crate::local::hex(&s.selector.block_id),
        "commitment_root":crate::local::hex(&s.commitment_root),"recent_root":crate::local::hex(&s.recent_root)})).collect();
    let tip_snapshot = snapshots
        .last()
        .cloned()
        .ok_or("accepted wallet snapshot missing")?;
    let genesis = store.engine().genesis();
    let aggregates = json!({"network":crate::local::hex(&genesis.config().network),"genesis":crate::local::hex(&genesis.id()),
        "rules":crate::local::hex(&genesis.rules_commitment()),"profile":crate::local::hex(&crate::proofs::protocol_profile_fingerprint()),"fee_mode":genesis.fee_mode() as u8,
        "height":state.height,"tip":crate::local::hex(&state.tip),"cumulative_work_decimal":state.cumulative_work.to_string(),
        "output_count":state.tree.count,"commitment_root":crate::local::hex(&native::codec::encode_digest(&state.tree.root())),
        "tip_snapshot":tip_snapshot,"asset_count":state.assets.len(),"recent_snapshots":snapshots});
    public_file(
        directory,
        "wallet-accepted-aggregates.json",
        &serde_json::to_vec(&aggregates).map_err(|_| "wallet aggregates encoding failed")?,
        &mut manifest,
    )?;
    write(&directory.join("manifest.json"), &serde_json::to_vec(&json!({"version":1,"height":head.height(),"tip":crate::local::hex(&head.tip()),"files":manifest})).map_err(|_| "wallet export manifest failed")?)?;
    Ok(aggregates)
}
fn compare_public(store: &Store, directory: &Path, budget: &p2p::Budget) -> Result<(), String> {
    let head = wallet_history::Head::capture(store)?;
    let headers = wallet_history::header_page(store, &head, 1, 96, budget)?;
    if headers.bytes() != read(&directory.join("wallet-headers-1-96.bin"), 1024 * 1024)? {
        return Err("encrypted admitted wallet headers differ".into());
    }
    drop(headers);
    for height in 1..=96 {
        let receipt = wallet_history::receipts(store, &head, height, budget)?;
        if receipt.bytes()
            != read(
                &directory.join(format!("wallet-receipt-{height}.bin")),
                wallet_history::codec::MAX_RECEIPT_BYTES,
            )?
        {
            return Err("encrypted admitted wallet receipt differs".into());
        }
    }
    Ok(())
}

struct Server {
    endpoint: SocketAddr,
    cancel: p2p::Cancellation,
    handle: Option<JoinHandle<Result<Value, String>>>,
}
impl Server {
    fn start(
        genesis: Arc<Genesis>,
        identity: Arc<NativeIdentity>,
        owner: Arc<Mutex<Driver>>,
        budget: p2p::Budget,
    ) -> Result<Self, String> {
        let policy = owner
            .lock()
            .map_err(|_| "fixture provider owner unavailable")?
            .engine()
            .body_policy();
        let connector = Connector::new(genesis.clone(), identity, Vec::new(), budget, policy)
            .map_err(|_| "fixture provider connector unavailable")?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .map_err(|_| "fixture loopback listener unavailable")?;
        listener
            .set_nonblocking(true)
            .map_err(|_| "fixture loopback polling unavailable")?;
        let endpoint = listener
            .local_addr()
            .map_err(|_| "fixture loopback endpoint unavailable")?;
        let cancel = p2p::Cancellation::default();
        let stopping = cancel.clone();
        let handle = std::thread::spawn(move || {
            let mut sessions = 0u64;
            let mut rounds = 0u64;
            let mut received = 0u64;
            let mut sent = 0u64;
            let started = Instant::now();
            while !stopping.is_cancelled()
                && started.elapsed() < Duration::from_secs(7200)
                && sessions < 512
            {
                let socket = match listener.accept() {
                    Ok((socket, _)) => socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(20));
                        continue;
                    }
                    Err(_) => return Err("fixture provider accept failed".into()),
                };
                let mut peer = connector
                    .accept(
                        socket,
                        Instant::now(),
                        p2p::Role::Validator,
                        stopping.clone(),
                    )
                    .map_err(|_| "fixture provider hybrid authentication failed")?;
                sessions += 1;
                let mut sequence = network::Sequence::default();
                while !stopping.is_cancelled() {
                    match network::respond(
                        &mut peer,
                        &owner,
                        &mut sequence,
                        network::Limits::default(),
                    ) {
                        Ok(_) => {}
                        Err(network::Error::Transport(p2p::Error::Unavailable)) => break,
                        Err(_) => return Err("fixture provider ordinary round failed".into()),
                    }
                    match checkpoint_exchange::respond(&mut peer, &[], genesis.config().network) {
                        Ok(_) => {}
                        Err(p2p::Error::Unavailable) => break,
                        Err(_) => return Err("fixture provider checkpoint phase failed".into()),
                    }
                    match transaction_exchange::respond(&mut peer, &owner) {
                        Ok(()) => {}
                        Err(p2p::Error::Unavailable) => break,
                        Err(_) => return Err("fixture provider transaction phase failed".into()),
                    }
                    rounds += 1;
                }
                let bytes = peer.encrypted_stream_bytes();
                received = received
                    .checked_add(bytes.0)
                    .ok_or("fixture provider byte overflow")?;
                sent = sent
                    .checked_add(bytes.1)
                    .ok_or("fixture provider byte overflow")?;
            }
            Ok(
                json!({"established_sessions":sessions,"complete_rounds":rounds,"encrypted_received_bytes":received.to_string(),"encrypted_sent_bytes":sent.to_string()}),
            )
        });
        Ok(Self {
            endpoint,
            cancel,
            handle: Some(handle),
        })
    }
    fn stop(mut self) -> Result<Value, String> {
        self.cancel.cancel();
        self.handle
            .take()
            .ok_or("fixture provider worker missing")?
            .join()
            .map_err(|_| "fixture provider worker panicked")?
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
fn client_directory(
    directory: &Path,
    genesis: &Genesis,
    server: &NativeIdentity,
    endpoint: SocketAddr,
) -> Result<(), String> {
    mkdir(directory)?;
    write(&directory.join("genesis.bin"), &genesis.encode()?)?;
    // Explicit disposable fixture identities only; existing source custody is
    // never read directly, copied, exported or regenerated.
    let identity = NativeIdentity::initialize(directory, genesis.peer_binding())
        .map_err(|_| "fixture client test identity unavailable")?;
    drop(identity);
    let descriptor = server
        .descriptor()
        .map_err(|_| "fixture service descriptor unavailable")?;
    PeerPin::from_trusted_descriptor(&descriptor, &genesis.peer_binding())
        .and_then(|p| p.persist(directory))
        .map_err(|_| "fixture trusted service pin unavailable")?;
    let config = json!({"version":2,"engineering":true,"role":"miner","listen":null,"mining":false,"checkpoint_key":null,
        "peers":[{"endpoint":endpoint.to_string(),"dial":true,"fingerprint":crate::local::hex(&descriptor.fingerprint()),"descriptor":crate::local::hex(&descriptor.encode())}]});
    write(
        &directory.join("peers.json"),
        &serde_json::to_vec(&config).map_err(|_| "fixture peer config encoding failed")?,
    )?;
    write(&directory.join("policy.json"), &serde_json::to_vec(&json!({"version":1,"work_floor":"24","max_headers":96,"max_payload_bytes":"2147483648","max_rounds":5000,"max_seconds":3600})).map_err(|_| "fixture policy encoding failed")?)
}
fn metrics(accounting: &Arc<Mutex<Accounting>>) -> Result<Value, String> {
    let counts = accounting
        .lock()
        .map_err(|_| "fixture byte accounting unavailable")?;
    if counts.overflow {
        return Err("fixture byte accounting overflow".into());
    }
    Ok(
        json!({"encrypted_received_bytes":counts.received.to_string(),"encrypted_sent_bytes":counts.sent.to_string(),"established_sessions":counts.sessions}),
    )
}
fn corrupt_copy(source: &Path, destination: &Path) -> Result<(), String> {
    mkdir(destination)?;
    let bytes = read(&source.join("bootstrap-quarantine.redb"), 64 * 1024 * 1024)?;
    write(&destination.join("bootstrap-quarantine.redb"), &bytes)?;
    let db = Database::open(destination.join("bootstrap-quarantine.redb"))
        .map_err(|_| "fixture copied quarantine unavailable")?;
    let txn = db
        .begin_write()
        .map_err(|_| "fixture corruption transaction unavailable")?;
    let mut table = txn
        .open_table(PARTS)
        .map_err(|_| "fixture copied parts unavailable")?;
    let (key, mut bytes) = {
        let mut rows = table
            .iter()
            .map_err(|_| "fixture copied parts iterator unavailable")?;
        let (key, row) = rows
            .next()
            .ok_or("fixture copied part missing")?
            .map_err(|_| "fixture copied part unreadable")?;
        (key.value().to_vec(), row.value().to_vec())
    };
    let byte = bytes.last_mut().ok_or("fixture copied part empty")?;
    *byte ^= 1;
    table
        .insert(key.as_slice(), bytes.as_slice())
        .map_err(|_| "fixture copied corruption failed")?;
    drop(table);
    txn.commit()
        .map_err(|_| "fixture copied corruption commit failed".into())
}

fn qualification() -> Result<(), String> {
    if std::env::var_os("GITHUB_ACTIONS").is_some()
        || matches!(std::env::var("CI").as_deref(), Ok("true") | Ok("1"))
    {
        return Err("encrypted native fixture requires an owner-operated environment".into());
    }
    let source = PathBuf::from(
        std::env::var_os("SIWORLD_ENG2_ENCRYPTED_SOURCE")
            .ok_or("explicit accepted h96 fixture required")?,
    );
    let destination = PathBuf::from(
        std::env::var_os("SIWORLD_ENG2_ENCRYPTED_TARGET")
            .ok_or("explicit new encrypted fixture target required")?,
    );
    if !source.is_absolute()
        || source
            .canonicalize()
            .map_err(|_| "accepted fixture unavailable")?
            != source
        || !destination.is_absolute()
        || destination.exists()
        || destination
            .parent()
            .ok_or("fixture target parent missing")?
            .canonicalize()
            .map_err(|_| "fixture target parent unavailable")?
            != destination
                .parent()
                .ok_or("fixture target parent missing")?
    {
        return Err(
            "encrypted fixture requires canonical accepted source and absent private target".into(),
        );
    }
    let expected_result = std::env::var("SIWORLD_ENG2_ACCEPTED_RESULT_SHA256")
        .map_err(|_| "reviewed accepted result hash required")?;
    if digest(&source.join("signed-import-result.json"), 1024 * 1024)? != expected_result {
        return Err("accepted h96 result hash differs".into());
    }
    let binary = std::env::current_exe().map_err(|_| "fixture executable unavailable")?;
    let binary_hash = digest(&binary, 128 * 1024 * 1024)?;
    if std::env::var("SIWORLD_ENG2_BINARY_SHA256").as_deref() != Ok(binary_hash.as_str()) {
        return Err("encrypted fixture binary differs from reviewed hash".into());
    }
    let source_commit = std::env::var("SIWORLD_ENG2_SOURCE_COMMIT")
        .map_err(|_| "reviewed encrypted source commit required")?;
    if source_commit.len() != 40 || !source_commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("reviewed encrypted source commit identifier required".into());
    }
    let result: Value = serde_json::from_slice(&read(
        &source.join("signed-import-result.json"),
        1024 * 1024,
    )?)
    .map_err(|_| "accepted result malformed")?;
    if result["scope"] != "owner-local-native-signed-import-h72-h96"
        || result["fee_mode"] != "legacy-miner"
        || result["accepted_height"] != 96
        || result["checkpoint_height"] != 72
        || result["authorization_height"] != 96
        || result["source_unchanged"] != "passed"
        || result["checks"]["reopen_exact_state_and_wallet_balances"] != "passed"
    {
        return Err("accepted result does not qualify this h96 source".into());
    }
    let encoded = read(&source.join("genesis.bin"), 1024 * 1024)?;
    if crate::local::hex(&Sha256::digest(&encoded)) != result["genesis_sha256"] {
        return Err("accepted genesis digest differs".into());
    }
    let genesis = Arc::new(Genesis::decode(&encoded)?);
    let expected = crate::local::hex(&genesis.id());
    let source_directory = source.join("admitted-target");
    let database = source_directory.join("chain.redb");
    let source_before = digest(&database, 16 * 1024 * 1024 * 1024)?;
    if std::env::var("SIWORLD_ENG2_SOURCE_DATABASE_SHA256").as_deref() != Ok(source_before.as_str())
    {
        return Err("reviewed original public database hash differs".into());
    }
    let semantic_audit_sha256 = std::env::var("SIWORLD_ENG2_SEMANTIC_AUDIT_SHA256")
        .map_err(|_| "reviewed accepted semantic-audit lineage required")?;
    if semantic_audit_sha256.len() != 64
        || !semantic_audit_sha256.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("reviewed semantic-audit digest required".into());
    }
    let provider_copy_bytes = database
        .metadata()
        .map_err(|_| "accepted public database size unavailable")?
        .len();
    let minimum_launch_disk = (45 * GIB)
        .checked_add(provider_copy_bytes)
        .ok_or("provider public database copy disk admission overflow")?;
    let launch_disk = free_disk(destination.parent().ok_or("fixture parent missing")?)?;
    if launch_disk < minimum_launch_disk {
        return Err("encrypted fixture launch and provider copy disk admission refused".into());
    }
    mkdir(&destination)?;
    let started = Instant::now();
    let provider_directory = destination.join("provider-working-copy");
    mkdir(&provider_directory)?;
    let provider_database = provider_directory.join("chain.redb");
    let provider_copy = copy_public_database(&database, &provider_database)?;
    if provider_copy["sha256"] != source_before {
        return Err("new provider public database copy hash differs".into());
    }
    let loaded_identity = NativeIdentity::load(&source_directory, &genesis.peer_binding())
        .map_err(|_| "existing accepted source test identity unavailable")?;
    let store = Store::resume_qualification_copy(
        &provider_database,
        Genesis::decode(&encoded)?,
        limits().chain,
        loaded_identity,
    )?;
    if store.engine().state().height() != 96
        || crate::local::hex(&store.engine().state().tip()) != result["tip"]
        || store.imported_checkpoint_height() != Some(72)
    {
        return Err("accepted source reopened state differs".into());
    }
    let certificate_bytes = read(&source.join("checkpoint.bin"), 1024 * 1024)?;
    let witness_bytes = read(&source.join("witness.bin"), 1024 * 1024)?;
    let snapshot_bytes = read(&source.join("snapshot.bin"), 64 * 1024 * 1024)?;
    for (field, bytes) in [
        ("certificate_sha256", &certificate_bytes),
        ("witness_sha256", &witness_bytes),
        ("snapshot_sha256", &snapshot_bytes),
    ] {
        if crate::local::hex(&Sha256::digest(bytes)) != result["checkpoint_artifacts"][field] {
            return Err("accepted checkpoint artifact digest differs".into());
        }
    }
    let certificate = Certificate::decode(&certificate_bytes, genesis.config().network)
        .map_err(|_| "accepted certificate decode failed")?;
    let witness = AuthorizationWitness::decode(&witness_bytes, limits().chain.max_component_bytes)
        .map_err(|_| "accepted witness decode failed")?;
    let prepared = PreparedCheckpoint::restore(
        &store,
        certificate.statement.clone(),
        witness,
        snapshot_bytes,
        limits(),
    )?;
    let certified = prepared.certify(&store, certificate.votes, unix_ms()? / 1000)?;
    let source_identity = Arc::new(
        NativeIdentity::load(&source_directory, &genesis.peer_binding())
            .map_err(|_| "existing accepted test identity unavailable")?,
    );
    let budget = p2p::Budget::new(MEMORY_BYTES);
    let public_directory = destination.join("public-wallet-history");
    let public_aggregates = export_public(
        &store,
        &public_directory,
        &budget,
        &result["artifact_manifest"],
    )?;
    let binding = Binding {
        genesis: genesis.id(),
        rules_commitment: genesis.rules_commitment(),
        parent: store.header(96)?.parent,
    };
    let expected_components = store
        .engine()
        .state()
        .canonical_components(binding, limits().chain)?;
    let mut driver = Driver::new(store, NativeVerifier::new()?, limits())?;
    for _ in 0..72 {
        driver.refresh_bootstrap(Some(&certified), &budget)?;
    }
    if !driver.bootstrap_available() {
        return Err("actual accepted provider offer unavailable".into());
    }
    let owner = Arc::new(Mutex::new(driver));
    let server = Server::start(
        genesis.clone(),
        source_identity.clone(),
        owner.clone(),
        budget.clone(),
    )?;
    let client = destination.join("client");
    client_directory(&client, &genesis, &source_identity, server.endpoint)?;
    let first_counts = Arc::new(Mutex::new(Accounting::default()));
    let mut interrupted = false;
    let first_started = Instant::now();
    let first = bootstrap_signed_observed(
        &client,
        &client.join("peers.json"),
        &client.join("policy.json"),
        &expected,
        false,
        first_counts.clone(),
        |progress| {
            if matches!(progress, Progress::Receipts { next: 2, .. }) {
                interrupted = true;
                return Err("fixture_acquisition_interrupted_after_first_receipt".into());
            }
            Ok(())
        },
    );
    if !interrupted
        || first.as_ref().err().map(String::as_str)
            != Some("fixture_acquisition_interrupted_after_first_receipt")
        || client.join("chain.redb").exists()
        || client.join("checkpoint-import.redb").exists()
    {
        return Err("fixture acquisition interruption boundary differs".into());
    }
    let first_ms = first_started.elapsed().as_millis();
    let negative = destination.join("corrupt-client");
    client_directory(&negative, &genesis, &source_identity, server.endpoint)?;
    corrupt_copy(
        &client.join("signed-bootstrap-quarantine-0"),
        &negative.join("signed-bootstrap-quarantine-0"),
    )?;
    let negative_counts = Arc::new(Mutex::new(Accounting::default()));
    let rejected = bootstrap_signed_observed(
        &negative,
        &negative.join("peers.json"),
        &negative.join("policy.json"),
        &expected,
        true,
        negative_counts.clone(),
        |_| Ok(()),
    );
    if rejected.as_ref().err().map(String::as_str)
        != Some("bootstrap retained chunk order, hash or bound differs")
        || negative.join("chain.redb").exists()
        || negative.join("checkpoint-import.redb").exists()
    {
        return Err("corrupted transferred cache was not rejected before admission".into());
    }
    let final_counts = Arc::new(Mutex::new(Accounting::default()));
    let mut before_import_disk = None;
    let accepted = bootstrap_signed_observed(
        &client,
        &client.join("peers.json"),
        &client.join("policy.json"),
        &expected,
        true,
        final_counts.clone(),
        |progress| {
            if progress == Progress::Downloaded {
                let available = free_disk(&destination)?;
                before_import_disk = Some(available);
                if available < 45 * GIB {
                    return Err("encrypted fixture native import disk admission refused".into());
                }
            }
            Ok(())
        },
    )?;
    if accepted["ready"] != false || accepted["mining_started"] != false || accepted["height"] != 96
    {
        return Err("CLI admission exposed readiness, mining or wrong accepted height".into());
    }
    let imported = Store::resume_existing(
        &client.join("chain.redb"),
        Genesis::decode(&encoded)?,
        limits().chain,
    )?;
    if imported
        .engine()
        .state()
        .canonical_components(binding, limits().chain)?
        != expected_components
    {
        return Err("encrypted admitted canonical state differs".into());
    }
    compare_public(&imported, &public_directory, &budget)?;
    let client_identity = Arc::new(
        NativeIdentity::load(&client, &genesis.peer_binding())
            .map_err(|_| "imported fixture identity unavailable")?,
    );
    let descriptor = source_identity
        .descriptor()
        .map_err(|_| "source fixture descriptor unavailable")?;
    let pin = PeerPin::from_trusted_descriptor(&descriptor, &genesis.peer_binding())
        .map_err(|_| "fixture catchup pin unavailable")?;
    let peer = p2p::ExpectedPeer::from_pinned_descriptor(genesis.peer_binding(), descriptor, pin)
        .map_err(|_| "fixture catchup expected service unavailable")?;
    let connector = Connector::new(
        genesis.clone(),
        client_identity,
        vec![peer.clone()],
        budget.clone(),
        imported.engine().body_policy(),
    )
    .map_err(|_| "fixture catchup connector unavailable")?;
    let mut connection = connector
        .connect(
            server.endpoint,
            peer.fingerprint(),
            p2p::Role::Miner,
            p2p::Cancellation::default(),
        )
        .map_err(|_| "fixture catchup hybrid authentication failed")?;
    let imported_owner = Arc::new(Mutex::new(Driver::new(
        imported,
        NativeVerifier::new()?,
        limits(),
    )?));
    let round = network::initiate(
        &mut connection,
        &imported_owner,
        &mut network::Sequence::default(),
        network::Limits::default(),
    )
    .map_err(|_| "fixture native catchup ordinary round failed")?;
    checkpoint_exchange::initiate(&mut connection, &[], genesis.config().network)
        .map_err(|_| "fixture native catchup checkpoint phase failed")?;
    transaction_exchange::initiate(&mut connection, &imported_owner)
        .map_err(|_| "fixture native catchup transaction phase failed")?;
    if round.accepted != 0 {
        return Err("fixture catchup unexpectedly admitted extra blocks".into());
    }
    let catchup_bytes = connection.encrypted_stream_bytes();
    drop(connection);
    drop(imported_owner);
    let server_metrics = server.stop()?;
    drop(owner);
    if digest(&database, 16 * 1024 * 1024 * 1024)? != source_before {
        return Err("accepted source database changed during encrypted qualification".into());
    }
    let size = directory_size(&destination)?;
    let mut total_received = catchup_bytes.0;
    let mut total_sent = catchup_bytes.1;
    let mut total_sessions = 1u64;
    for counter in [&first_counts, &negative_counts, &final_counts] {
        let counts = counter
            .lock()
            .map_err(|_| "fixture total accounting unavailable")?;
        if counts.overflow {
            return Err("fixture total accounting overflow".into());
        }
        total_received = total_received
            .checked_add(counts.received)
            .ok_or("fixture total bytes overflow")?;
        total_sent = total_sent
            .checked_add(counts.sent)
            .ok_or("fixture total bytes overflow")?;
        total_sessions = total_sessions
            .checked_add(counts.sessions)
            .ok_or("fixture total sessions overflow")?;
    }
    let report = json!({"version":1,"scope":"owner-local-static-h96-provider-through-cli-signed-bootstrap","source_commit":source_commit,"binary_sha256":binary_hash,
        "accepted_source_result_sha256":expected_result,"accepted_original_database_sha256":source_before,"accepted_semantic_audit_sha256":semantic_audit_sha256,
        "provider_public_database_copy":provider_copy,"provider_working_database_sha256_after_close":digest(&provider_database,16*1024*1024*1024)?,
        "fee_mode":"legacy-miner","independent_signer_custody":false,"accepted_height":96,"checkpoint_height":72,"elapsed_ms":started.elapsed().as_millis().to_string(),
        "interrupted_acquisition_ms":first_ms.to_string(),"interrupted_acquisition":metrics(&first_counts)?,"corrupt_acquisition":metrics(&negative_counts)?,"resumed_acquisition":metrics(&final_counts)?,
        "cli_admission":accepted,"native_catchup_encrypted_received_bytes":catchup_bytes.0.to_string(),"native_catchup_encrypted_sent_bytes":catchup_bytes.1.to_string(),"provider":server_metrics,
        "total_client_encrypted_received_bytes":total_received.to_string(),"total_client_encrypted_sent_bytes":total_sent.to_string(),"total_client_established_sessions":total_sessions,
        "network_byte_scope":"all established interruption, copied-corruption, resumed and native-catchup sessions; encrypted handshake/framing included; failed pre-session handshakes and packet-wire bytes excluded",
        "directory_logical_bytes":size.0.to_string(),"directory_allocated_bytes":size.1.to_string(),"directory_measured_before_report":true,"launch_free_disk_bytes":launch_disk.to_string(),"before_native_import_free_disk_bytes":before_import_disk.map(|n|n.to_string()),
        "public_wallet_aggregates":public_aggregates,"checks":{"interrupted_resume":"passed","copied_corruption":"rejected_before_canonical_admission","native_tail":"passed","authenticated_reopen":"passed","all_state_components":"equal","wallet_headers_and_receipts":"equal","normal_native_catchup_round":"passed","ready_and_mining_before_catchup":false,"source_database_unchanged":true},
        "new_test_identities":2,"proof_generation":false,"remaining_gates":["moving-chain retained-offer rollover","independent deployed custody","final confidential genesis","Windows real machine","pruning/compaction","long-offline recovery"]});
    write(
        &destination.join("encrypted-cli-result.json"),
        &serde_json::to_vec(&report).map_err(|_| "encrypted fixture result encoding failed")?,
    )?;
    Ok(())
}

#[test]
#[ignore = "requires reviewed immutable h96 source, binary hash, resource guard and new private target"]
fn actual_h96_provider_crosses_cli_interrupt_resume_native_import_and_catchup() {
    qualification().unwrap();
}
