use super::*;
use std::io::Write;

fn directory() -> PathBuf {
    let mut entropy = [0u8; 16];
    getrandom::fill(&mut entropy).unwrap();
    let directory = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("eng2-resident-{}", crate::local::hex(&entropy)));
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&directory).unwrap();
    directory
}
fn write(path: &Path, bytes: &[u8]) {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).unwrap().write_all(bytes).unwrap();
}
fn genesis() -> Genesis {
    let state = super::super::snapshot::tests::bootstrap();
    Genesis::seal(
        state.chain.config.clone(),
        state.governance.clone(),
        super::super::genesis::FeeMode::LegacyMiner,
    )
    .unwrap()
}
#[test]
fn windows_runtime_requires_outbound_nonsigning_miner_and_authenticated_import() {
    assert!(check_windows_configuration(true, p2p::Role::Miner, false, false).is_ok());
    for role in [
        p2p::Role::Bootstrap,
        p2p::Role::Validator,
        p2p::Role::Wallet,
    ] {
        assert!(check_windows_configuration(true, role, false, false).is_err());
    }
    assert!(check_windows_configuration(true, p2p::Role::Miner, true, false).is_err());
    assert!(check_windows_configuration(true, p2p::Role::Miner, false, true).is_err());
    for prefix in [None, Some(0)] {
        assert!(check_windows_admission(true, prefix).is_err());
    }
    for prefix in [1, 11, 13, 71, 72, 73] {
        assert!(check_windows_admission(true, Some(prefix)).is_ok());
    }
    assert!(check_windows_admission(false, None).is_ok());
}
#[test]
fn explicit_identity_initialization_binds_genesis_and_never_overwrites() {
    let directory = directory();
    let genesis = genesis();
    let expected = crate::local::hex(&genesis.id());
    write(&directory.join("genesis.bin"), &genesis.encode().unwrap());
    assert!(initialize_identity(&directory, &"0".repeat(64)).is_err());
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
    let receipt = initialize_identity(&directory, &expected).unwrap();
    assert_eq!(receipt.as_object().unwrap().len(), 3);
    let descriptor = crate::identity::Descriptor::decode(
        &crate::eng2_operations::public_bytes(
            &receipt["descriptor"],
            crate::identity::DESCRIPTOR_BYTES,
        )
        .unwrap(),
        &genesis.peer_binding(),
    )
    .unwrap();
    assert_eq!(descriptor.binding(), genesis.peer_binding());
    assert_eq!(
        receipt["fingerprint"],
        crate::local::hex(&descriptor.fingerprint())
    );
    assert!(NativeIdentity::load(&directory, &p2p::Binding::new(genesis.config())).is_err());
    assert!(initialize_identity(&directory, &expected).is_err());
    assert_eq!(
        public_identity(&directory, &expected).unwrap()["fingerprint"],
        receipt["fingerprint"]
    );
    assert!(!directory.join("chain.redb").exists());
    fs::remove_dir_all(directory).unwrap();
}
#[test]
fn explicit_store_initialization_never_regenerates_a_missing_identity() {
    let directory = directory();
    let genesis = genesis();
    let expected = crate::local::hex(&genesis.id());
    write(&directory.join("genesis.bin"), &genesis.encode().unwrap());
    assert!(initialize_store(&directory, &expected).is_err());
    assert!(!directory.join("chain.redb").exists());
    assert!(!directory.join("native-peer-identity.secret").exists());
    assert!(run(&directory, &directory.join("missing-peers.json"), &expected).is_err());
    assert!(!directory.join("native-peer-identity.secret").exists());
    assert!(!directory.join("chain.redb").exists());
    assert!(load_genesis(&directory, &"0".repeat(64)).is_err());
    initialize_identity(&directory, &expected).unwrap();
    initialize_store(&directory, &expected).unwrap();
    assert_eq!(restart_check(&directory, &expected).unwrap()["height"], 0);
    assert!(initialize_store(&directory, &expected).is_err());
    fs::remove_dir_all(directory).unwrap();
}
#[test]
fn miner_configuration_is_outbound_only_with_explicit_existing_signer_selection() {
    let directory = directory();
    let genesis = genesis();
    let identity = NativeIdentity::initialize(&directory, genesis.peer_binding()).unwrap();
    let configuration = directory.join("peers.json");
    let mut value = json!({"version":2,"engineering":true,"role":"miner","listen":"127.0.0.1:1","mining":true,"peers":[],"checkpoint_key":null});
    write(&configuration, &serde_json::to_vec(&value).unwrap());
    assert!(config::Configuration::load(&directory, &configuration, &genesis, &identity).is_err());
    value["listen"] = Value::Null;
    value["checkpoint_key"] = Value::String("missing.secret".into());
    service::atomic_json(&configuration, &value).unwrap();
    let selected =
        config::Configuration::load(&directory, &configuration, &genesis, &identity).unwrap();
    assert_eq!(
        selected.checkpoint_key,
        Some(directory.join("missing.secret"))
    );
    // Selection is separate from loading. The requested signer is checked by
    // Host against the actual locally validated governance roster at startup.
    value.as_object_mut().unwrap().remove("checkpoint_key");
    service::atomic_json(&configuration, &value).unwrap();
    assert!(config::Configuration::load(&directory, &configuration, &genesis, &identity).is_err());
    value["checkpoint_key"] = Value::Null;
    service::atomic_json(&configuration, &value).unwrap();
    let loaded =
        config::Configuration::load(&directory, &configuration, &genesis, &identity).unwrap();
    assert!(loaded.listen.is_none() && loaded.mining);
    drop(identity);
    fs::remove_dir_all(directory).unwrap();
}
#[cfg(unix)]
#[test]
fn legacy_checkpoint_routing_only_selects_advertisements_without_peer_admission() {
    let directory = directory();
    let remote_directory = super::tests::directory();
    let genesis = genesis();
    let identity = NativeIdentity::initialize(&directory, genesis.peer_binding()).unwrap();
    let remote = NativeIdentity::initialize(&remote_directory, genesis.peer_binding()).unwrap();
    let descriptor = remote.descriptor().unwrap();
    let fingerprint = crate::local::hex(&descriptor.fingerprint());
    let path = directory.join("peers.json");
    let mut value = json!({"version":2,"engineering":true,"role":"validator","listen":null,"mining":false,"checkpoint_key":null,"peers":[]});
    service::atomic_json(&path, &value).unwrap();
    let current = config::Configuration::load(&directory, &path, &genesis, &identity).unwrap();
    assert!(current.legacy_checkpoint_peers.is_empty());
    value["legacy_checkpoint_peers"] = json!([fingerprint]);
    service::atomic_json(&path, &value).unwrap();
    let pin_path = directory.join(format!("peer-{fingerprint}.pin"));
    assert!(!pin_path.exists());
    let legacy = config::Configuration::load(&directory, &path, &genesis, &identity).unwrap();
    assert!(
        legacy
            .legacy_checkpoint_peers
            .contains(&descriptor.fingerprint())
    );
    assert!(!pin_path.exists());
    // Ingress routing must not add readiness references or outbound destinations.
    assert_eq!(legacy.peers.len(), current.peers.len());
    assert!(legacy.peers.is_empty());
    assert_ne!(legacy.digest, current.digest);
    value["peers"] = json!([{
        "endpoint":"127.0.0.1:9000", "dial":false, "fingerprint":fingerprint,
        "descriptor":crate::local::hex(&descriptor.encode())
    }]);
    service::atomic_json(&path, &value).unwrap();
    assert!(config::Configuration::load(&directory, &path, &genesis, &identity).is_err());
    value["peers"] = json!([]);
    for invalid in [
        Value::Null,
        json!(true),
        json!(["bad"]),
        json!([fingerprint, fingerprint]),
        json!([crate::local::hex(
            &identity.descriptor().unwrap().fingerprint()
        )]),
        Value::Array(
            (0u8..17)
                .map(|index| json!(crate::local::hex(&[index; 32])))
                .collect(),
        ),
    ] {
        value["legacy_checkpoint_peers"] = invalid;
        service::atomic_json(&path, &value).unwrap();
        assert!(config::Configuration::load(&directory, &path, &genesis, &identity).is_err());
    }
    drop(identity);
    drop(remote);
    fs::remove_dir_all(directory).unwrap();
    fs::remove_dir_all(remote_directory).unwrap();
}
#[cfg(unix)]
#[test]
fn observer_resident_starts_from_committed_state_and_stops_only_its_selected_run() {
    let directory = directory();
    let genesis = genesis();
    let expected = crate::local::hex(&genesis.id());
    write(&directory.join("genesis.bin"), &genesis.encode().unwrap());
    drop(NativeIdentity::initialize(&directory, genesis.peer_binding()).unwrap());
    initialize_store(&directory, &expected).unwrap();
    let configuration = directory.join("peers.json");
    write(&configuration,&serde_json::to_vec(&json!({"version":2,"engineering":true,"role":"ordinary","listen":null,"mining":false,"peers":[],"checkpoint_key":null})).unwrap());
    let thread_directory = directory.clone();
    let thread_expected = expected.clone();
    let worker =
        std::thread::spawn(move || run(&thread_directory, &configuration, &thread_expected));
    let started = Instant::now();
    let mut selected = None;
    while started.elapsed() < Duration::from_secs(15) {
        if let Ok(status) = service::exported_status(&directory) {
            assert_eq!(status["height"], 0);
            assert_eq!(status["ready"], false);
            assert_eq!(status["connections"], 0);
            assert_eq!(status["historical_proof_replay"], false);
            if status["phase"] == "networking" {
                selected = Some(status["run_id"].as_str().unwrap().to_owned());
                break;
            }
        }
        assert!(
            !worker.is_finished(),
            "observer exited before exporting its run"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    let selected = selected.expect("observer did not export a ready control record");
    assert!(service::request_stop_expected(&directory, &"0".repeat(64)).is_err());
    service::request_stop_expected(&directory, &selected).unwrap();
    worker.join().unwrap().unwrap();
    assert_eq!(
        service::exported_status(&directory).unwrap()["phase"],
        "stopped"
    );
    assert_eq!(restart_check(&directory, &expected).unwrap()["height"], 0);
    fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[test]
fn three_residents_complete_live_rounds_and_outbound_miner_restarts_without_replay() {
    use crate::identity::PeerPin;
    use std::{net::TcpListener, thread::JoinHandle};
    struct Running {
        directory: PathBuf,
        worker: Option<JoinHandle<Result<(), String>>>,
    }
    impl Running {
        fn start(directory: &Path, expected: &str) -> Self {
            let path = directory.to_owned();
            let id = expected.to_owned();
            let worker = std::thread::spawn(move || run(&path, &path.join("peers.json"), &id));
            Self {
                directory: directory.to_owned(),
                worker: Some(worker),
            }
        }
        fn ready(&self) -> Value {
            let started = Instant::now();
            while started.elapsed() < Duration::from_secs(25) {
                if let Ok(value) = service::exported_status(&self.directory)
                    && value["phase"] != "stopped"
                    && value["ready"] == true
                {
                    assert_eq!(value["height"], 0);
                    assert_eq!(value["historical_proof_replay"], false);
                    assert!(value["connections"].as_u64().unwrap() > 0);
                    assert!(value["completed_rounds"].as_u64().unwrap() > 0);
                    return value;
                }
                assert!(
                    !self.worker.as_ref().unwrap().is_finished(),
                    "resident exited before a live round"
                );
                std::thread::sleep(Duration::from_millis(25));
            }
            panic!("resident did not complete a fresh loopback round");
        }
        fn stop(&mut self) {
            if let Ok(status) = service::exported_status(&self.directory)
                && status["phase"] != "stopped"
            {
                service::request_stop_expected(&self.directory, status["run_id"].as_str().unwrap())
                    .unwrap();
            }
            if let Some(worker) = self.worker.take() {
                worker.join().unwrap().unwrap();
            }
        }
    }
    impl Drop for Running {
        fn drop(&mut self) {
            let Some(worker) = self.worker.take() else {
                return;
            };
            let mut requested = false;
            for _ in 0..100 {
                if worker.is_finished() {
                    break;
                }
                if let Ok(status) = service::exported_status(&self.directory)
                    && let Some(run) = status["run_id"].as_str()
                {
                    requested = service::request_stop_expected(&self.directory, run).is_ok();
                    if requested {
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            if requested || worker.is_finished() {
                let _ = worker.join();
            }
        }
    }
    let genesis = genesis();
    let expected = crate::local::hex(&genesis.id());
    let directories = [directory(), directory(), directory()];
    let descriptors = directories.each_ref().map(|directory| {
        write(&directory.join("genesis.bin"), &genesis.encode().unwrap());
        let identity = NativeIdentity::initialize(directory, genesis.peer_binding()).unwrap();
        let descriptor = identity.descriptor().unwrap();
        drop(identity);
        initialize_store(directory, &expected).unwrap();
        descriptor
    });
    let listeners = [
        TcpListener::bind("127.0.0.1:0").unwrap(),
        TcpListener::bind("127.0.0.1:0").unwrap(),
    ];
    let endpoints = listeners
        .each_ref()
        .map(|listener| listener.local_addr().unwrap());
    for (index, directory) in directories.iter().enumerate() {
        let mut peers = Vec::new();
        for other in 0..2 {
            if other == index {
                continue;
            }
            let descriptor = &descriptors[other];
            PeerPin::from_trusted_descriptor(descriptor, &genesis.peer_binding())
                .unwrap()
                .persist(directory)
                .unwrap();
            peers.push(json!({"endpoint":endpoints[other].to_string(),"dial":true,"fingerprint":crate::local::hex(&descriptor.fingerprint()),"descriptor":crate::local::hex(&descriptor.encode())}));
        }
        // The services pin each other but never register the miner identity.
        let configuration = json!({"version":2,"engineering":true,"role":if index==2 {"miner"} else {"validator"},"listen":if index==2 {Value::Null} else {Value::String(endpoints[index].to_string())},"mining":false,"peers":peers,"checkpoint_key":null});
        write(
            &directory.join("peers.json"),
            &serde_json::to_vec(&configuration).unwrap(),
        );
    }
    drop(listeners);
    let mut services = [
        Running::start(&directories[0], &expected),
        Running::start(&directories[1], &expected),
    ];
    let mut miner = Running::start(&directories[2], &expected);
    services[0].ready();
    services[1].ready();
    let before = miner.ready();
    assert_eq!(before["inbound_listener"], false);
    assert_eq!(before["mining_enabled"], false);
    miner.stop();
    assert_eq!(
        restart_check(&directories[2], &expected).unwrap()["height"],
        0
    );
    let mut restarted = Running::start(&directories[2], &expected);
    let after = restarted.ready();
    assert_ne!(before["run_id"], after["run_id"]);
    assert_eq!(before["tip"], after["tip"]);
    restarted.stop();
    for service in &mut services {
        service.stop();
    }
    for directory in directories {
        fs::remove_dir_all(directory).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn private_submission_reaches_native_driver_and_rejects_synthetic_proofs() {
    use std::io::Read;
    use std::os::unix::{fs::DirBuilderExt, net::UnixStream};
    // Unix socket paths have a smaller bound than ordinary filesystem paths.
    let mut entropy = [0u8; 8];
    getrandom::fill(&mut entropy).unwrap();
    let path = Path::new("/tmp")
        .canonicalize()
        .unwrap()
        .join(format!("eng2-ipc-{}", crate::local::hex(&entropy)));
    fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
    let genesis = genesis();
    let expected = crate::local::hex(&genesis.id());
    write(&path.join("genesis.bin"), &genesis.encode().unwrap());
    drop(NativeIdentity::initialize(&path, genesis.peer_binding()).unwrap());
    initialize_store(&path, &expected).unwrap();
    let store = Store::resume_existing(&path.join("chain.redb"), genesis, limits().chain).unwrap();
    let owner = Arc::new(Mutex::new(
        Driver::new(store, NativeVerifier::new().unwrap(), limits()).unwrap(),
    ));
    let (head, packet) = {
        let driver = owner.lock().unwrap();
        let head = driver.head().unwrap();
        let mut transaction =
            crate::fixtures::candidate(driver.engine().state().chain(), 2_500_000)
                .transactions
                .remove(0);
        transaction.record.fee_commit = native::codec::encode_digest(
            &native::multi_asset::Hasher::new()
                .fee_commit(0, &[native::multi_asset::F::default(); 8]),
        );
        let sidecar = crate::wire::Sidecar {
            transaction_id: transaction.record.statement_id(&head.network),
            fee: 0,
            blind: [0; 8],
        };
        (
            head,
            crate::runtime::encode_gossip(
                &transaction,
                &sidecar,
                &driver.engine().state().network(),
            )
            .unwrap(),
        )
    };
    assert!(
        submission::Owner::submit(
            owner.as_ref(),
            &packet,
            &p2p::Deadline::new(Duration::from_secs(10))
        )
        .unwrap_err()
        .contains("admission rejected")
    );
    let socket_path = path.join("submit.sock");
    let budget = p2p::Budget::new(8 * 1024 * 1024);
    let before = budget.available().unwrap();
    let socket = submission::Socket::bind(&socket_path, budget.clone(), owner.clone()).unwrap();
    let mut stream = UnixStream::connect(&socket_path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(&[3]).unwrap();
    stream
        .write_all(&((packet.len() - 4) as u32).to_le_bytes())
        .unwrap();
    stream.write_all(&packet[4..]).unwrap();
    let mut response = [0; 5];
    stream.read_exact(&mut response).unwrap();
    assert_eq!(response[0], 1);
    let mut body = vec![0; u32::from_le_bytes(response[1..].try_into().unwrap()) as usize];
    stream.read_exact(&mut body).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap(),
        json!({"error":"Native public-data request unavailable."})
    );
    drop(stream);
    drop(socket);
    assert!(!socket_path.exists());
    assert_eq!(budget.available().unwrap(), before);
    let driver = owner.lock().unwrap();
    assert_eq!(driver.head().unwrap(), head);
    assert!(driver.transaction_ids().is_empty());
    drop(driver);
    drop(owner);
    fs::remove_dir_all(path).unwrap();
}

#[cfg(unix)]
#[test]
#[ignore = "requires an explicitly supplied owner-local native rehearsal fixture"]
fn actual_native_block_relays_between_residents_and_restarts_without_replay() {
    use crate::eng2::{
        body::Body,
        header::{HEADER_BYTES, Header},
        state_components::Limits,
        store::Store,
    };
    use crate::identity::PeerPin;
    use redb::{ReadableDatabase, TableDefinition};
    use std::{net::TcpListener, thread::JoinHandle};
    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    assert!(!matches!(
        std::env::var("CI").as_deref(),
        Ok("true") | Ok("1")
    ));
    let source = PathBuf::from(
        std::env::var_os("SIWORLD_ENG2_NATIVE_FIXTURE")
            .expect("set an existing synthetic native fixture"),
    );
    assert!(source.is_absolute());
    assert_eq!(source.canonicalize().unwrap(), source);
    for name in ["genesis.bin", "chain.redb"] {
        assert!(
            fs::symlink_metadata(source.join(name))
                .unwrap()
                .file_type()
                .is_file()
        );
    }
    // Read exactly the public genesis and first canonical record. No custody
    // file is opened, copied, inspected or needed by this qualification.
    let genesis_bytes = fs::read(source.join("genesis.bin")).unwrap();
    let genesis = Genesis::decode(&genesis_bytes).unwrap();
    let record = {
        let database = redb::ReadOnlyDatabase::open(source.join("chain.redb")).unwrap();
        let transaction = database.begin_read().unwrap();
        let table = transaction
            .open_table(TableDefinition::<u64, &[u8]>::new(
                "eng2-canonical-blocks-v1",
            ))
            .unwrap();
        table.get(1).unwrap().unwrap().value().to_vec()
    };
    let header = Header::decode(&record[..HEADER_BYTES], &genesis.config().network).unwrap();
    assert_eq!(header.height, 1);
    let limits = Limits {
        max_leaves: 1_000_000,
        max_nullifiers: 1_000_000,
        max_component_bytes: 64 * 1024 * 1024,
    };
    let policy =
        super::super::execution::Engine::new(Genesis::decode(&genesis_bytes).unwrap(), limits)
            .unwrap()
            .body_policy();
    let body = Body::decode(&record[HEADER_BYTES..], header.network, 1, policy).unwrap();
    assert_eq!(body.commitment(policy).unwrap(), header.body_commitment);
    let directories = [directory(), directory()];
    let descriptors = directories.each_ref().map(|path| {
        write(&path.join("genesis.bin"), &genesis_bytes);
        let identity = NativeIdentity::initialize(path, genesis.peer_binding()).unwrap();
        let descriptor = identity.descriptor().unwrap();
        drop(identity);
        initialize_store(path, &crate::local::hex(&genesis.id())).unwrap();
        descriptor
    });
    let seed_started = Instant::now();
    {
        let store = Store::resume_existing(
            &directories[0].join("chain.redb"),
            Genesis::decode(&genesis_bytes).unwrap(),
            limits,
        )
        .unwrap();
        let mut driver = super::super::driver::Driver::new(
            store,
            NativeVerifier::new().unwrap(),
            super::limits(),
        )
        .unwrap();
        let committed = driver.accept(&header, &body).unwrap();
        assert_eq!(committed.id(), header.id().unwrap());
    }
    let seed_accept_ms = seed_started.elapsed().as_millis().to_string();
    drop(body);
    drop(record);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    PeerPin::from_trusted_descriptor(&descriptors[0], &genesis.peer_binding())
        .unwrap()
        .persist(&directories[1])
        .unwrap();
    let service_config = json!({"version":2,"engineering":true,"role":"validator","listen":endpoint.to_string(),"mining":false,"peers":[],"checkpoint_key":null});
    let miner_config = json!({"version":2,"engineering":true,"role":"miner","listen":null,"mining":false,"peers":[{"endpoint":endpoint.to_string(),"dial":true,"fingerprint":crate::local::hex(&descriptors[0].fingerprint()),"descriptor":crate::local::hex(&descriptors[0].encode())}],"checkpoint_key":null});
    for (path, value) in directories.iter().zip([service_config, miner_config]) {
        write(
            &path.join("peers.json"),
            &serde_json::to_vec(&value).unwrap(),
        );
    }
    drop(listener);
    struct Running {
        path: PathBuf,
        worker: Option<JoinHandle<Result<(), String>>>,
    }
    impl Running {
        fn start(path: &Path, expected: &str) -> Self {
            let owned = path.to_owned();
            let id = expected.to_owned();
            let worker = std::thread::spawn(move || run(&owned, &owned.join("peers.json"), &id));
            Self {
                path: path.to_owned(),
                worker: Some(worker),
            }
        }
        fn accepted(&self, expected: Hash) -> Value {
            let started = Instant::now();
            while started.elapsed() < Duration::from_secs(120) {
                if let Ok(status) = service::exported_status(&self.path)
                    && status["phase"] != "stopped"
                    && status["height"] == 1
                    && status["ready"] == true
                {
                    assert_eq!(status["tip"], crate::local::hex(&expected));
                    assert_eq!(status["historical_proof_replay"], false);
                    assert_eq!(status["mining_enabled"], false);
                    assert!(status["completed_rounds"].as_u64().unwrap() > 0);
                    return status;
                }
                assert!(
                    !self.worker.as_ref().unwrap().is_finished(),
                    "resident exited before actual native relay"
                );
                std::thread::sleep(Duration::from_millis(25));
            }
            panic!("resident did not accept the supplied native block");
        }
        fn stop(&mut self) {
            if let Some(worker) = self.worker.take() {
                if !worker.is_finished() {
                    let status = service::exported_status(&self.path).unwrap();
                    service::request_stop_expected(&self.path, status["run_id"].as_str().unwrap())
                        .unwrap();
                }
                worker.join().unwrap().unwrap();
            }
        }
    }
    impl Drop for Running {
        fn drop(&mut self) {
            if let Some(worker) = self.worker.take() {
                if let Ok(status) = service::exported_status(&self.path)
                    && let Some(run) = status["run_id"].as_str()
                {
                    let _ = service::request_stop_expected(&self.path, run);
                }
                let _ = worker.join();
            }
        }
    }
    let expected = crate::local::hex(&genesis.id());
    let relay_started = Instant::now();
    let mut service = Running::start(&directories[0], &expected);
    let mut miner = Running::start(&directories[1], &expected);
    let before = miner.accepted(header.id().unwrap());
    service.accepted(header.id().unwrap());
    let relay_ms = relay_started.elapsed().as_millis().to_string();
    assert_eq!(before["inbound_listener"], false);
    miner.stop();
    let restart_started = Instant::now();
    assert_eq!(
        restart_check(&directories[1], &expected).unwrap()["height"],
        1
    );
    let restart_ms = restart_started.elapsed().as_millis().to_string();
    let mut restarted = Running::start(&directories[1], &expected);
    let after = restarted.accepted(header.id().unwrap());
    assert_ne!(before["run_id"], after["run_id"]);
    restarted.stop();
    service.stop();
    let receipt = json!({"version":1,"native_block_height":1,"native_block_id":crate::local::hex(&header.id().unwrap()),"body_bytes":header_body_size(&directories[0],&genesis_bytes,limits),"seed_native_accept_ms":seed_accept_ms,"encrypted_relay_to_ready_ms":relay_ms,"authenticated_restart_check_ms":restart_ms,"native_proofs_generated":0,"historical_replay_on_start":false,"mining_enabled":false,"result":"passed"});
    if let Some(path) = std::env::var_os("SIWORLD_ENG2_RELAY_RECEIPT") {
        write(
            Path::new(&path),
            &serde_json::to_vec_pretty(&receipt).unwrap(),
        );
    }
    eprintln!("{}", serde_json::to_string(&receipt).unwrap());
    for path in directories {
        fs::remove_dir_all(path).unwrap();
    }

    fn header_body_size(path: &Path, genesis: &[u8], limits: Limits) -> usize {
        Store::resume_existing(
            &path.join("chain.redb"),
            Genesis::decode(genesis).unwrap(),
            limits,
        )
        .unwrap()
        .block_size(1)
        .unwrap()
    }
}

#[test]
fn unavailable_status_replaces_stale_ready_without_claiming_a_head() {
    let directory = directory();
    service::atomic_json(
        &directory.join(service::STATUS_FILE),
        &json!({"ready":true,"height":123}),
    )
    .unwrap();
    export_unavailable_status(&directory, "test-run", Instant::now(), 2).unwrap();
    let value: Value =
        serde_json::from_slice(&fs::read(directory.join(service::STATUS_FILE)).unwrap()).unwrap();
    assert_eq!(value["ready"], false);
    assert_eq!(value["state_available"], false);
    assert_eq!(value["height"], Value::Null);
    assert_eq!(value["reorganization_alarm"], "canonical_state_unavailable");
    assert_eq!(value["ready_reason_code"], "canonical_state_unavailable");
    fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[test]
fn readiness_reason_preserves_owner_and_observer_gates_ahead_of_peer_diagnostics() {
    use super::super::checkpoint_observer::{
        Observer,
        tests::{synthetic_current_conflict, synthetic_pending_authorization},
    };
    use super::peers::PeerReadiness;
    let healthy = Observer::default();
    assert_eq!(
        resident_readiness(true, "ready", &healthy, PeerReadiness::Ready),
        (true, "ready")
    );
    assert_eq!(
        resident_readiness(true, "ready", &healthy, PeerReadiness::NoConnectedPeers),
        (false, "no_connected_peers")
    );
    let hard = synthetic_current_conflict();
    assert_eq!(
        resident_readiness(true, "ready", &hard, PeerReadiness::Ready),
        (false, "checkpoint_current_quorum_conflict")
    );
    let pending = synthetic_pending_authorization();
    assert_eq!(
        resident_readiness(true, "ready", &pending, PeerReadiness::Ready),
        (false, "checkpoint_authorization_pending")
    );
    for reason in [
        "manual_recovery_required",
        "applying_validated_branch",
        "waiting_for_shared_byte_budget",
        "resuming_best_branch",
    ] {
        assert_eq!(
            resident_readiness(false, reason, &hard, PeerReadiness::NoConnectedPeers),
            (false, reason)
        );
    }
    assert_eq!(
        resident_readiness(false, "ready", &healthy, PeerReadiness::Ready),
        (false, "canonical_state_unavailable")
    );
}
