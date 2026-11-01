use super::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "wallet-web-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        Self(p.canonicalize().unwrap())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn secret_files_are_exclusive_private_and_bounded() {
    let d = Directory::new();
    let key = d.0.join("auth");
    keygen(&key).unwrap();
    assert!(keygen(&key).is_err());
    assert_eq!(read_secret(&key, 64).unwrap().len(), 64);
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_secret(&key, 64).is_err());
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&key, d.0.join("alias")).unwrap();
    assert!(read_secret(&key, 64).is_err());
}
#[test]
fn header_parser_rejects_ambiguous_http() {
    let valid=b"POST /api/login HTTP/1.1\r\nHost: 127.0.0.1:8782\r\nOrigin: http://127.0.0.1:8782\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
    assert!(parse_request(valid, "127.0.0.1:8782").is_ok());
    for bad in [
        "Host: evil",
        "Host: 127.0.0.1:8782\r\nHost: 127.0.0.1:8782",
        "Host: 127.0.0.1:8782\r\nTransfer-Encoding: chunked",
    ] {
        let data = String::from_utf8(valid.to_vec())
            .unwrap()
            .replace("Host: 127.0.0.1:8782", bad);
        assert!(parse_request(data.as_bytes(), "127.0.0.1:8782").is_err());
    }
    let query = String::from_utf8(valid.to_vec())
        .unwrap()
        .replace("/api/login", "/api/login?token=secret");
    assert!(parse_request(query.as_bytes(), "127.0.0.1:8782").is_err());
}

#[test]
fn http_reader_waits_for_delayed_and_fragmented_nonblocking_socket() {
    use std::sync::mpsc::{self, RecvTimeoutError};
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(address).unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    // Establish the test socket before forcing nonblocking request reads.
    // A completed connect can precede a nonblocking accept becoming ready.
    listener.set_nonblocking(false).unwrap();
    let (mut stream, _) = listener.accept().unwrap();
    // Force the macOS inheritance condition on other operating systems too.
    stream.set_nonblocking(true).unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        result_tx
            .send(read_request(&mut stream, &address.to_string()))
            .unwrap();
    });
    started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let initially_pending = matches!(
        result_rx.recv_timeout(Duration::from_millis(100)),
        Err(RecvTimeoutError::Timeout)
    );
    let header = format!(
        "POST /api/status HTTP/1.1\r\nHost: {address}\r\nOrigin: http://{address}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n"
    );
    let header_written = client.write_all(header.as_bytes());
    let body_pending = matches!(
        result_rx.recv_timeout(Duration::from_millis(100)),
        Err(RecvTimeoutError::Timeout)
    );
    let body_written = client.write_all(b"{}");
    let result = result_rx.recv_timeout(Duration::from_secs(IO_SECONDS + 1));
    drop(client);
    worker.join().unwrap();
    assert!(
        initially_pending,
        "reader rejected a socket before request bytes arrived"
    );
    header_written.unwrap();
    assert!(
        body_pending,
        "reader rejected a partial request before its body arrived"
    );
    body_written.unwrap();
    let request = result.unwrap().unwrap();
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/api/status");
    assert_eq!(request.body.as_slice(), b"{}");
}

#[test]
fn server_accepts_browser_assets_after_delayed_first_bytes() {
    let d = Directory::new();
    let (server, token) = configured_server(&d);
    let port = server.port();
    let worker = std::thread::spawn(move || server.run());
    let mut responses = Vec::new();
    for path in [
        "/",
        "/startup.js",
        "/wallet.js",
        "/wallet.css",
        "/startup.css",
    ] {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(IO_SECONDS + 1)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        // Let the server accept before this browser-shaped request arrives.
        std::thread::sleep(Duration::from_millis(100));
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: keep-alive\r\nsec-ch-ua: \"Chromium\";v=\"131\"\r\nsec-ch-ua-mobile: ?0\r\nsec-ch-ua-platform: \"macOS\"\r\nUser-Agent: synthetic-browser-test\r\nAccept: */*\r\nSec-Fetch-Site: same-origin\r\nSec-Fetch-Mode: no-cors\r\nSec-Fetch-Dest: script\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US,en;q=0.9\r\n\r\n"
        );
        let sent = stream.write_all(request.as_bytes());
        let mut response = Vec::new();
        let received = stream.read_to_end(&mut response);
        responses.push((sent, received, response));
    }
    // These credentials exist only in this synthetic test. The pre-fix macOS
    // reader can race immediate control writes, so bound cleanup attempts.
    let mut client = Client::new(port);
    let mut login_error = None;
    for _ in 0..20 {
        match client.login(&token) {
            Ok(()) => {
                login_error = None;
                break;
            }
            Err(error) => login_error = Some(error),
        }
    }
    assert!(
        login_error.is_none(),
        "synthetic server cleanup authentication failed"
    );
    let status = client.post("/api/status", json!({})).unwrap();
    client
        .post(
            "/api/shutdown",
            json!({"instance_id":status["instance_id"]}),
        )
        .unwrap();
    worker.join().unwrap().unwrap();
    for (sent, received, response) in responses {
        sent.unwrap();
        received.unwrap();
        assert!(
            response.starts_with(b"HTTP/1.1 200 OK\r\n"),
            "delayed browser asset request was rejected"
        );
    }
}
#[test]
fn sessions_require_cookie_csrf_and_expire() {
    let now = Instant::now();
    let mut session = Session::new(now).unwrap();
    let (cookie, csrf) = session.credentials.take().unwrap();
    assert!(session.authorize(Some(&cookie), Some(&csrf), now));
    assert!(!session.authorize(Some(&cookie), Some("wrong"), now));
    assert!(!session.authorize(
        Some(&cookie),
        Some(&csrf),
        now + Duration::from_secs(IDLE_SECONDS + 1)
    ));
}
#[test]
fn readonly_history_never_initializes_or_opens_a_live_writer() {
    let d = Directory::new();
    let p = d.0.join("chain.redb");
    let config = Config::development([77; 32], 0).unwrap();
    let verifier = NativeVerifier::new().unwrap();
    assert!(
        crate::store::read_only_history(&p, config.clone(), &verifier, 4096, 512 * 1024 * 1024)
            .is_err()
    );
    assert!(!p.exists());
    let store = crate::store::Store::open(&p, config.clone(), &verifier).unwrap();
    assert!(
        crate::store::read_only_history(&p, config.clone(), &verifier, 4096, 512 * 1024 * 1024)
            .is_err()
    );
    drop(store);
    let (state, blocks) =
        crate::store::read_only_history(&p, config, &verifier, 4096, 512 * 1024 * 1024).unwrap();
    assert_eq!(state.height, 0);
    assert!(blocks.is_empty());
}
#[test]
fn existing_mnemonic_vault_unlock_rescan_lock_and_owned_shutdown() {
    let d = Directory::new();
    let (server, token) = configured_server(&d);
    let port = server.port();
    let join = std::thread::spawn(move || server.run());
    let mut client = Client::new(port);
    assert!(client.post("/api/status", json!({})).is_err());
    client.login(&token).unwrap();
    let locked = client.post("/api/status", json!({})).unwrap();
    assert_eq!(locked["locked"], true);
    assert_eq!(locked["vault_exists"], true);
    assert!(locked.get("balance_summary").is_none());
    assert!(client.post("/api/create", json!({})).is_err());
    assert!(client.post("/api/import", json!({})).is_err());
    assert!(client.post("/api/unlock", json!({})).is_err());
    client
        .post("/api/unlock", json!({"passphrase":TEST_PASSPHRASE}))
        .unwrap();
    let unknown = client.post("/api/status", json!({})).unwrap();
    assert_eq!(unknown["locked"], false);
    assert_eq!(unknown["balance_status"], "unknown");
    assert!(unknown.get("balance_summary").is_none());
    let result = client.post("/api/rescan", json!({})).unwrap();
    assert_eq!(result["balance_status"], "verified");
    assert_eq!(result["height"], 0);
    assert_eq!(result["address_hex"].as_str().unwrap().len(), 2464);
    assert_eq!(result["balance_summary"], json!([]));
    assert_eq!(
        result["privacy_policy"],
        json!({"network_class":"engineering","enhanced_privacy":false,"background_delay":false,"maximum_delay_seconds":21600})
    );
    assert_eq!(result["immediate_spend_privacy_warning"], false);
    assert_eq!(
        result["payment_submission_blocked_by_pending_journal"],
        false
    );
    client.post("/api/lock", json!({})).unwrap();
    let status = client.post("/api/status", json!({})).unwrap();
    assert_eq!(status["locked"], true);
    for name in [
        "balance_summary",
        "height",
        "tip",
        "address_hex",
        "privacy_pending",
        "privacy_policy",
        "immediate_spend_privacy_warning",
    ] {
        assert!(status.get(name).is_none());
    }
    assert!(client.post("/api/rescan", json!({})).is_err());
    client
        .post(
            "/api/shutdown",
            json!({"instance_id":status["instance_id"]}),
        )
        .unwrap();
    join.join().unwrap().unwrap();
}

fn request(path: &str, body: Value, cookie: Option<&str>, csrf: Option<&str>) -> Request {
    let mut headers = BTreeMap::new();
    if let Some(cookie) = cookie {
        headers.insert("cookie".into(), format!("{COOKIE}={cookie}"));
    }
    if let Some(csrf) = csrf {
        headers.insert("x-wallet-csrf".into(), csrf.into());
    }
    Request {
        method: "POST".into(),
        path: path.into(),
        headers,
        body: Zeroizing::new(serde_json::to_vec(&body).unwrap()),
    }
}
const TEST_PASSPHRASE: &str = "synthetic-test-vault-passphrase";
fn configured_server_with_words(
    d: &Directory,
) -> (Server, String, crate::wallet_vault::RecoveryWords) {
    let chain = d.0.join("chain");
    let wallet = d.0.join("wallet");
    let cfg = local::initialize(&chain, 0).unwrap();
    let verifier = NativeVerifier::new().unwrap();
    drop(crate::store::Store::open(chain.join("chain.redb"), cfg.clone(), &verifier).unwrap());
    let pending = crate::wallet_vault::PendingWallet::generate(cfg.network, 0).unwrap();
    let words = pending.recovery_words();
    let positions = pending.backup_challenge();
    let split = words.expose().split(' ').collect::<Vec<_>>();
    let confirmed = pending
        .confirm_backup(positions.map(|position| split[position - 1]))
        .unwrap();
    drop(confirmed.create(&wallet, TEST_PASSPHRASE).unwrap());
    let auth = d.0.join("auth");
    keygen(&auth).unwrap();
    let token = String::from_utf8(read_secret(&auth, 64).unwrap().to_vec()).unwrap();
    (
        Server::bind(Options {
            chain_dir: chain,
            wallet_dir: wallet,
            auth_file: auth,
            port: 0,
        })
        .unwrap(),
        token,
        words,
    )
}
fn configured_server(d: &Directory) -> (Server, String) {
    let (server, token, _) = configured_server_with_words(d);
    (server, token)
}
#[test]
fn csrf_wrong_password_live_writer_and_expiry_fail_closed() {
    let d = Directory::new();
    let (mut server, token) = configured_server(&d);
    let (code, _, bytes, cookie) =
        server.handle(request("/api/login", json!({"token":token}), None, None));
    assert_eq!(code, 200);
    let result: Value = serde_json::from_slice(&bytes).unwrap();
    let csrf = result["csrf"].as_str().unwrap();
    let cookie = cookie.unwrap();
    assert_eq!(
        server
            .handle(request(
                "/api/unlock",
                json!({"passphrase":TEST_PASSPHRASE}),
                Some(&cookie),
                None
            ))
            .0,
        401
    );
    assert!(
        server
            .api("/api/create", &json!({"seed_hex":"00".repeat(32)}))
            .is_err()
    );
    assert!(!server.options.wallet_dir.join("wallet.vault").exists());
    assert!(
        !server
            .options
            .wallet_dir
            .join("mining-address.bin")
            .exists()
    );
    assert!(
        server
            .api("/api/unlock", &json!({"passphrase":"wrong-passphrase"}))
            .is_err()
    );
    assert!(server.wallet.is_none());
    server
        .api("/api/unlock", &json!({"passphrase":TEST_PASSPHRASE}))
        .unwrap();
    assert!(
        WalletVault::open(
            &server.options.wallet_dir,
            server.config.network,
            TEST_PASSPHRASE
        )
        .is_err()
    );
    server.api("/api/rescan", &json!({})).unwrap();
    assert!(server.view.is_some());
    assert!(server.wallet.is_some());
    let active = crate::store::Store::open_existing(
        server.options.chain_dir.join("chain.redb"),
        server.config.clone(),
        &NativeVerifier::new().unwrap(),
    )
    .unwrap();
    assert!(server.api("/api/rescan", &json!({})).is_err());
    assert!(server.view.is_none());
    assert!(server.wallet.is_none());
    drop(active);
    server
        .api("/api/unlock", &json!({"passphrase":TEST_PASSPHRASE}))
        .unwrap();
    server.api("/api/rescan", &json!({})).unwrap();
    server.session.as_mut().unwrap().touched =
        Instant::now() - Duration::from_secs(IDLE_SECONDS + 1);
    assert_eq!(
        server
            .handle(request("/api/status", json!({}), Some(&cookie), Some(csrf)))
            .0,
        401
    );
    assert!(server.wallet.is_none());
    assert!(server.view.is_none());
    assert!(server.address_hex.is_none());
}
#[test]
fn cookie_parser_accepts_unrelated_names_but_rejects_duplicates() {
    let token = "a".repeat(64);
    assert_eq!(
        session_cookie(&format!("other=value; {COOKIE}={token}")),
        Some(token.as_str())
    );
    assert!(session_cookie(&format!("{COOKIE}={token}; {COOKIE}={token}")).is_none());
}
#[test]
#[ignore = "one accepted native 64-slot block and independent mnemonic-vault recovery"]
fn native_reward_is_visible_before_maturity_and_survives_mnemonic_restore() {
    let d = Directory::new();
    let (mut server, _, words) = configured_server_with_words(&d);
    let recipient = WalletVault::open(
        &server.options.wallet_dir,
        server.config.network,
        TEST_PASSPHRASE,
    )
    .unwrap()
    .wallet()
    .unwrap()
    .address();
    let prover = crate::proofs::NativeProver::new().unwrap();
    let verifier = NativeVerifier::new().unwrap();
    let store = crate::store::Store::open_existing(
        server.options.chain_dir.join("chain.redb"),
        server.config.clone(),
        &verifier,
    )
    .unwrap();
    let mut node = crate::runtime::Node::new(store, verifier);
    for _ in 0..crate::wire::MIN_SLOTS {
        node.precompute_one(&prover).unwrap();
    }
    let produced = node
        .prepare_block(
            &prover,
            crate::wire::MIN_SLOTS,
            node.state().timestamp() + server.config.target_interval,
            &crate::producer::MiningSettings {
                mode: crate::state::RewardMode::Holder,
                recipient,
            },
        )
        .unwrap();
    node.commit_produced(produced).unwrap();
    drop(node);
    server
        .api("/api/unlock", &json!({"passphrase":TEST_PASSPHRASE}))
        .unwrap();
    let first = server.api("/api/rescan", &json!({})).unwrap();
    assert_eq!(first["height"], 1);
    assert_eq!(first["balance_status"], "verified");
    assert!(first["available"].as_array().unwrap().is_empty());
    assert_eq!(first["tranches"].as_array().unwrap().len(), 5);
    let summary = &first["balance_summary"][0];
    assert_ne!(summary["confirmed_owned_atoms"], "0");
    assert_eq!(
        summary["confirmed_owned_atoms"],
        summary["chain_locked_atoms"]
    );
    assert_eq!(summary["consensus_mature_atoms"], "0");
    assert_eq!(summary["policy_ready_atoms"], "0");
    server.api("/api/lock", &json!({})).unwrap();
    let restored = d.0.join("restored");
    drop(
        WalletVault::restore(
            &restored,
            server.config.network,
            0,
            Zeroizing::new(words.expose().to_owned()),
            TEST_PASSPHRASE,
        )
        .unwrap(),
    );
    drop(server);
    let mut recovered = Server::bind(Options {
        chain_dir: d.0.join("chain"),
        wallet_dir: restored,
        auth_file: d.0.join("auth"),
        port: 0,
    })
    .unwrap();
    recovered
        .api("/api/unlock", &json!({"passphrase":TEST_PASSPHRASE}))
        .unwrap();
    let second = recovered.api("/api/rescan", &json!({})).unwrap();
    for field in [
        "address_hex",
        "balance_summary",
        "locked_balances",
        "tranches",
        "tip",
    ] {
        assert_eq!(first[field], second[field]);
    }
}

#[test]
fn proof_deadline_is_checked_before_and_after_native_adapter_calls() {
    use std::cell::Cell;
    struct Slow(Cell<u32>);
    impl BlockVerifier for Slow {
        fn transaction(
            &self,
            _: &native::codec::PublicTransaction,
            _: &native::codec::ProofContext,
            _: &native::multi_asset::Digest,
            _: &native::multi_asset::Digest,
            _: &[u8],
        ) -> Result<(), String> {
            unreachable!()
        }
        fn settlement(
            &self,
            _: &[native::multi_asset::Digest],
            _: &native::settlement::RewardPlan,
            _: crate::wire::Hash,
            _: crate::wire::Hash,
            _: &[native::multi_asset::Digest],
            _: &[u8],
        ) -> Result<(), String> {
            self.0.set(self.0.get() + 1);
            std::thread::sleep(Duration::from_millis(4));
            Ok(())
        }
    }
    let inner = Slow(Cell::new(0));
    let plan = native::settlement::RewardPlan {
        block_height: 1,
        mode: native::settlement::RewardMode::Voyager,
        allocations: vec![],
    };
    let expired = DeadlineVerifier {
        inner: &inner,
        deadline: Instant::now(),
    };
    assert!(
        expired
            .settlement(&[], &plan, [1; 32], [2; 32], &[], &[])
            .is_err()
    );
    assert_eq!(inner.0.get(), 0);
    let crossing = DeadlineVerifier {
        inner: &inner,
        deadline: Instant::now() + Duration::from_millis(1),
    };
    assert!(
        crossing
            .settlement(&[], &plan, [1; 32], [2; 32], &[], &[])
            .is_err()
    );
    assert_eq!(inner.0.get(), 1);
}

#[test]
fn issuance_deadline_adapter_forwards_and_rechecks_the_issuance_path() {
    use std::cell::Cell;
    struct IssuanceAdapter(Cell<u32>);
    impl BlockVerifier for IssuanceAdapter {
        fn issuance(&self, _: &crate::issuance::IssuanceRecord) -> Result<(), String> {
            self.0.set(self.0.get() + 1);
            std::thread::sleep(Duration::from_millis(4));
            Ok(())
        }
        fn transaction(
            &self,
            _: &native::codec::PublicTransaction,
            _: &native::codec::ProofContext,
            _: &native::multi_asset::Digest,
            _: &native::multi_asset::Digest,
            _: &[u8],
        ) -> Result<(), String> {
            unreachable!()
        }
        fn settlement(
            &self,
            _: &[native::multi_asset::Digest],
            _: &native::settlement::RewardPlan,
            _: crate::wire::Hash,
            _: crate::wire::Hash,
            _: &[native::multi_asset::Digest],
            _: &[u8],
        ) -> Result<(), String> {
            unreachable!()
        }
    }
    // This synthetic adapter test checks dispatch and deadline boundaries only.
    // Native proof acceptance is exercised by the separate ignored integration.
    let (signed, witness, _) = native::issuance::sample_issuance(3);
    let record = crate::issuance::IssuanceRecord {
        signed,
        ciphertexts: witness.ciphertexts,
        proof: vec![],
        fee_commitment: [0; 48],
        fee_rho: [0; 48],
    };
    let inner = IssuanceAdapter(Cell::new(0));
    let expired = DeadlineVerifier {
        inner: &inner,
        deadline: Instant::now(),
    };
    assert!(expired.issuance(&record).is_err());
    assert_eq!(inner.0.get(), 0);
    let crossing = DeadlineVerifier {
        inner: &inner,
        deadline: Instant::now() + Duration::from_millis(1),
    };
    assert!(crossing.issuance(&record).is_err());
    assert_eq!(inner.0.get(), 1);
}
#[test]
fn passive_status_does_not_extend_session_idle_deadline() {
    let d = Directory::new();
    let (mut server, token) = configured_server(&d);
    let (_, _, bytes, cookie) =
        server.handle(request("/api/login", json!({"token":token}), None, None));
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    let csrf = v["csrf"].as_str().unwrap();
    let cookie = cookie.unwrap();
    let touched = Instant::now() - Duration::from_secs(500);
    server.session.as_mut().unwrap().touched = touched;
    assert_eq!(
        server
            .handle(request("/api/status", json!({}), Some(&cookie), Some(csrf)))
            .0,
        200
    );
    assert_eq!(server.session.as_ref().unwrap().touched, touched);
    assert_eq!(
        server
            .handle(request("/api/lock", json!({}), Some(&cookie), Some(csrf)))
            .0,
        200
    );
    assert!(server.session.as_ref().unwrap().touched > touched);
}
#[test]
fn miner_projection_requires_immutable_receipt_and_strict_status_shape() {
    let d = Directory::new();
    let (server, _) = configured_server(&d);
    let runs = server.options.chain_dir.join("service-runs");
    let run = "ab".repeat(32);
    let dir = runs.join(&run);
    fs::create_dir(&runs).unwrap();
    fs::set_permissions(&runs, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let receipt = json!({"schema_version":1,"run_id":run,"process_id":123,"network_id":local::hex(&server.config.network),"binary_sha256":"cd".repeat(32),"configuration_sha256":server.configuration_sha256,"started_unix_ms":now-1000,"observation_target_ms":86400000});
    exclusive_write(
        &dir.join("run.json"),
        &serde_json::to_vec(&receipt).unwrap(),
    )
    .unwrap();
    let mut status = receipt.clone();
    status["phase"] = json!("mining");
    status["state_available"] = json!(true);
    status["error_code"] = Value::Null;
    status["updated_unix_ms"] = json!(now);
    let path = server.options.chain_dir.join(crate::service::STATUS_FILE);
    exclusive_write(&path, &serde_json::to_vec(&status).unwrap()).unwrap();
    let projected = server.miner_status().unwrap();
    assert_eq!(projected["fresh"], true);
    assert_eq!(projected["observation"], "export_only_not_process_liveness");
    assert!(projected.get("fees").is_none());
    status["updated_unix_ms"] = json!(now + 60000);
    fs::write(&path, serde_json::to_vec(&status).unwrap()).unwrap();
    assert_eq!(server.miner_status().unwrap()["fresh"], false);
    status["updated_unix_ms"] = json!(now);
    status.as_object_mut().unwrap().remove("error_code");
    fs::write(&path, serde_json::to_vec(&status).unwrap()).unwrap();
    assert!(server.miner_status().is_err());
    status["error_code"] = Value::Null;
    status["state_available"] = json!(false);
    fs::write(&path, serde_json::to_vec(&status).unwrap()).unwrap();
    assert!(server.miner_status().is_err());
    status["state_available"] = json!(true);
    status["process_id"] = json!(124);
    fs::write(&path, serde_json::to_vec(&status).unwrap()).unwrap();
    assert!(server.miner_status().is_err());
}

#[test]
fn verified_web_policy_uses_wallet_configuration_without_enabling_payment() {
    use crate::wallet_policy::{WalletNetwork, WalletPrivacyPolicy};
    for network_class in [
        WalletNetwork::Engineering,
        WalletNetwork::Testnet,
        WalletNetwork::Mainnet,
    ] {
        let d = Directory::new();
        let (mut server, _) = configured_server(&d);
        let mut policy = WalletPrivacyPolicy::for_network(network_class);
        policy.enhanced_privacy = true;
        let custody = WalletVault::open(
            &server.options.wallet_dir,
            server.config.network,
            TEST_PASSPHRASE,
        )
        .unwrap();
        crate::wallet_policy::save(&server.options.wallet_dir, server.config.network, policy)
            .unwrap();
        drop(custody);
        server
            .api("/api/unlock", &json!({"passphrase":TEST_PASSPHRASE}))
            .unwrap();
        let before_scan = server.api("/api/status", &json!({})).unwrap();
        assert!(before_scan.get("privacy_policy").is_none());
        let result = server.api("/api/rescan", &json!({})).unwrap();
        assert_eq!(result["privacy_policy"]["enhanced_privacy"], true);
        assert_eq!(
            result["privacy_policy"]["background_delay"],
            network_class == WalletNetwork::Mainnet
        );
        assert_eq!(result["privacy_policy"]["maximum_delay_seconds"], 21600);
        assert_eq!(result["immediate_spend_privacy_warning"], false);
        assert_eq!(result["send_available"], false);
        assert!(server.api("/api/pay", &json!({})).is_err());
        server.api("/api/lock", &json!({})).unwrap();
        assert!(
            server
                .api("/api/status", &json!({}))
                .unwrap()
                .get("privacy_policy")
                .is_none()
        );
    }
}
