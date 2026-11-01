use super::*;
use std::io::Cursor;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

fn binding() -> Binding {
    Binding::new(&crate::state::Config::development([51; 32], 0).unwrap())
}
fn incoming(kind: u8, request: u64, body: &[u8]) -> Vec<u8> {
    let mut bytes = frame_header(kind, request, &binding().network, body.len())
        .unwrap()
        .to_vec();
    bytes.extend_from_slice(body);
    bytes
}
#[test]
fn hello_rejects_network_genesis_verifier_role_and_version_changes() {
    let binding = binding();
    let encoded = Hello {
        binding,
        role: Role::Validator,
    }
    .encode();
    assert!(Hello::decode(&encoded, &binding).is_ok());
    for offset in [0, 4, 6, 38, 70, 102] {
        let mut bad = encoded;
        bad[offset] ^= 255;
        assert!(Hello::decode(&bad, &binding).is_err(), "offset {offset}");
    }
}
#[test]
fn oversized_unknown_and_wrong_network_frames_fail_before_body_read() {
    for change in 0..3 {
        let binding = binding();
        let mut raw = frame_header(TRANSACTION, 1, &binding.network, 10).unwrap();
        match change {
            0 => raw[6] = 255,
            1 => raw[15] ^= 1,
            _ => raw[47..51].copy_from_slice(&u32::MAX.to_le_bytes()),
        }
        let mut session =
            Session::from_test_channel(Cursor::new(raw.to_vec()), binding, Budget::default());
        assert!(session.receive().is_err());
        assert_eq!(session.channel.position(), HEADER_BYTES as u64);
    }
}
#[test]
fn frames_are_network_bound_and_preserve_request_identity() {
    let binding = binding();
    let mut session =
        Session::from_test_channel(Cursor::new(Vec::new()), binding, Budget::default());
    session
        .send_control(TRANSACTION, 71, b"synthetic envelope and sidecar")
        .unwrap();
    let raw = session.channel.into_inner();
    let mut receiver = Session::from_test_channel(Cursor::new(raw), binding, Budget::default());
    match receiver.receive().unwrap() {
        Packet::Control {
            kind,
            request,
            body,
            ..
        } => {
            assert_eq!((kind, request), (TRANSACTION, 71));
            assert_eq!(body, b"synthetic envelope and sidecar");
        }
        _ => panic!("unexpected packet"),
    }
}
#[test]
fn unavailable_stream_is_not_an_invalid_proof() {
    struct Timeout;
    impl Read for Timeout {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::TimedOut.into())
        }
    }
    impl Write for Timeout {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::TimedOut.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut session = Session::from_test_channel(Timeout, binding(), Budget::default());
    assert_eq!(session.receive().err(), Some(Error::Unavailable));
}
#[test]
fn retained_packets_hold_shared_budget_until_dropped() {
    let budget = Budget::new(80);
    let raw = incoming(TRANSACTION, 1, b"0123456789abcdef");
    let mut first = Session::from_test_channel(Cursor::new(raw.clone()), binding(), budget.clone());
    let mut second = Session::from_test_channel(Cursor::new(raw), binding(), budget.clone());
    let retained = first.receive().unwrap();
    assert_eq!(budget.0.usage.lock().unwrap().bytes, 80);
    assert_eq!(second.receive().err(), Some(Error::ResourceExhausted));
    assert_eq!(second.channel.position(), HEADER_BYTES as u64);
    drop(retained);
    assert_eq!(budget.0.usage.lock().unwrap().bytes, 0);
    let mut retry = Session::from_test_channel(
        Cursor::new(incoming(TRANSACTION, 2, b"0123456789abcdef")),
        binding(),
        budget,
    );
    assert!(retry.receive().is_ok());
}
#[test]
fn malformed_body_and_transport_errors_release_packet_reservations() {
    let budget = Budget::new(80);
    let raw = frame_header(TRANSACTION, 1, &binding().network, 16)
        .unwrap()
        .to_vec();
    let mut session = Session::from_test_channel(Cursor::new(raw), binding(), budget.clone());
    assert_eq!(session.receive().err(), Some(Error::Unavailable));
    assert_eq!(budget.0.usage.lock().unwrap().bytes, 0);
}
#[test]
fn handshake_slots_are_shared_bounded_and_released() {
    let budget = Budget::default();
    let mut permits = Vec::new();
    for _ in 0..MAX_HANDSHAKES {
        permits.push(budget.handshake().unwrap());
    }
    let usage = budget.0.usage.lock().unwrap();
    assert_eq!(usage.bytes, HANDSHAKE_TOTAL_BYTES);
    assert_eq!(usage.handshake_bytes, HANDSHAKE_TOTAL_BYTES);
    drop(usage);
    assert!(matches!(budget.handshake(), Err(Error::ResourceExhausted)));
    drop(permits.pop());
    let replacement = budget.handshake().unwrap();
    drop(permits);
    drop(replacement);
    let usage = budget.0.usage.lock().unwrap();
    assert_eq!(
        (usage.bytes, usage.handshakes, usage.handshake_bytes),
        (0, 0, 0)
    );
}
#[test]
fn zero_and_sub_handshake_shared_budgets_admit_no_handshake() {
    for maximum in [0, HANDSHAKE_BYTES - 1] {
        let budget = Budget::new(maximum);
        assert!(matches!(budget.handshake(), Err(Error::ResourceExhausted)));
        assert_eq!(budget.available().unwrap(), maximum);
        let usage = budget.0.usage.lock().unwrap();
        assert_eq!(
            (usage.bytes, usage.handshakes, usage.handshake_bytes),
            (0, 0, 0)
        );
    }
}
#[test]
fn exhausted_shared_payload_budget_rejects_handshake_without_charging() {
    let budget = Budget::new(HANDSHAKE_BYTES);
    let payload = budget.reserve(HANDSHAKE_BYTES).unwrap();
    assert!(matches!(budget.handshake(), Err(Error::ResourceExhausted)));
    assert_eq!(budget.available().unwrap(), 0);
    let usage = budget.0.usage.lock().unwrap();
    assert_eq!(
        (usage.bytes, usage.handshakes, usage.handshake_bytes),
        (HANDSHAKE_BYTES, 0, 0)
    );
    drop(usage);
    drop(payload);
    let handshake = budget.handshake().unwrap();
    assert_eq!(budget.available().unwrap(), 0);
    drop(handshake);
    assert_eq!(budget.available().unwrap(), HANDSHAKE_BYTES);
}
#[test]
fn concurrent_handshake_and_payload_share_one_atomic_byte_budget() {
    let payload_bytes = 80;
    let maximum = HANDSHAKE_BYTES + payload_bytes;
    let budget = Budget::new(maximum);
    let wait = Duration::from_secs(5);
    let (payload_ready_tx, payload_ready_rx) = std::sync::mpsc::sync_channel(1);
    let (payload_release_tx, payload_release_rx) = std::sync::mpsc::sync_channel(1);
    let (handshake_ready_tx, handshake_ready_rx) = std::sync::mpsc::sync_channel(1);
    let (handshake_release_tx, handshake_release_rx) = std::sync::mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let shared_budget = &budget;
        let payload = scope.spawn(move || {
            let reservation = shared_budget.reserve(payload_bytes);
            payload_ready_tx.send(reservation.is_ok()).unwrap();
            let released = payload_release_rx.recv_timeout(wait).is_ok();
            drop(reservation);
            released
        });
        let shared_budget = &budget;
        let handshake = scope.spawn(move || {
            let reservation = shared_budget.handshake();
            handshake_ready_tx.send(reservation.is_ok()).unwrap();
            let released = handshake_release_rx.recv_timeout(wait).is_ok();
            drop(reservation);
            released
        });
        let payload_started = payload_ready_rx.recv_timeout(wait).unwrap_or(false);
        let handshake_started = handshake_ready_rx.recv_timeout(wait).unwrap_or(false);
        let usage = budget.0.usage.lock().unwrap();
        let held = (usage.bytes, usage.handshakes, usage.handshake_bytes);
        drop(usage);
        let available = budget.available().unwrap();
        let payload_rejected = matches!(budget.reserve(1), Err(Error::ResourceExhausted));
        let handshake_rejected = matches!(budget.handshake(), Err(Error::ResourceExhausted));
        let _ = payload_release_tx.send(());
        let _ = handshake_release_tx.send(());
        let payload_released = payload.join().unwrap();
        let handshake_released = handshake.join().unwrap();
        assert!(payload_started && handshake_started);
        assert!(payload_released && handshake_released);
        assert_eq!(held, (maximum, 1, HANDSHAKE_BYTES));
        assert_eq!(available, 0);
        assert!(payload_rejected);
        assert!(handshake_rejected);
    });
    assert_eq!(budget.available().unwrap(), maximum);
    let usage = budget.0.usage.lock().unwrap();
    assert_eq!(
        (usage.bytes, usage.handshakes, usage.handshake_bytes),
        (0, 0, 0)
    );
}
#[test]
fn dropping_handshake_preserves_live_payload_charge() {
    let payload_bytes = 80;
    let budget = Budget::new(HANDSHAKE_BYTES + payload_bytes);
    let handshake = budget.handshake().unwrap();
    let payload = budget.reserve(payload_bytes).unwrap();
    assert_eq!(budget.available().unwrap(), 0);
    drop(handshake);
    assert_eq!(budget.available().unwrap(), HANDSHAKE_BYTES);
    let usage = budget.0.usage.lock().unwrap();
    assert_eq!(
        (usage.bytes, usage.handshakes, usage.handshake_bytes),
        (payload_bytes, 0, 0)
    );
    drop(usage);
    let replacement = budget.handshake().unwrap();
    drop(payload);
    assert_eq!(budget.available().unwrap(), payload_bytes);
    drop(replacement);
    assert_eq!(budget.available().unwrap(), HANDSHAKE_BYTES + payload_bytes);
}
#[test]
fn invalid_local_block_emits_no_frame_header() {
    let binding = binding();
    let mut session =
        Session::from_test_channel(Cursor::new(Vec::new()), binding, Budget::default());
    let block = Block {
        network: binding.network,
        height: 1,
        parent: binding.genesis,
        timestamp: 1,
        target: [0xff; 32],
        nonce: 0,
        transactions: Vec::new(),
        reward_mode: crate::state::RewardMode::Voyager,
        rewards: vec![crate::wire::RewardRecord {
            commitment: [0; 48],
            ciphertext: [0; crate::wire::REWARD_CIPHERTEXT_BYTES],
        }],
        fund_spends: Vec::new(),
        issuances: Vec::new(),
        settlement_proof: vec![1],
    };
    assert_eq!(session.send_block(1, &block), Err(Error::InvalidProtocol));
    assert!(session.channel.into_inner().is_empty());
}
#[test]
fn operation_deadline_covers_header_and_body_without_resetting() {
    struct Advancing {
        data: Cursor<Vec<u8>>,
        clock: Arc<AtomicU64>,
    }
    impl Read for Advancing {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            let count = self.data.read(bytes)?;
            self.clock.fetch_add(6000, Ordering::Relaxed);
            Ok(count)
        }
    }
    impl Write for Advancing {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.data.write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let clock = Arc::new(AtomicU64::new(0));
    let channel = Advancing {
        data: Cursor::new(incoming(TRANSACTION, 3, b"body")),
        clock: clock.clone(),
    };
    let mut session = Session::from_test_channel(channel, binding(), Budget::default());
    let deadline = Deadline {
        started: Instant::now(),
        limit: CONTROL_TIMEOUT,
        cancellation: Cancellation::default(),
        elapsed: Some(clock),
    };
    assert_eq!(
        session.receive_deadline(deadline).err(),
        Some(Error::Unavailable)
    );
    assert_eq!(session.budget.0.usage.lock().unwrap().bytes, 0);
}
#[test]
fn expired_deadlines_fail_before_touching_the_channel() {
    let clock = Arc::new(AtomicU64::new(10_000));
    let mut session = Session::from_test_channel(
        Cursor::new(incoming(TRANSACTION, 1, b"body")),
        binding(),
        Budget::default(),
    );
    let deadline = Deadline {
        started: Instant::now(),
        limit: CONTROL_TIMEOUT,
        cancellation: Cancellation::default(),
        elapsed: Some(clock),
    };
    assert_eq!(
        session.receive_deadline(deadline).err(),
        Some(Error::Unavailable)
    );
    assert_eq!(session.channel.position(), 0);
}

#[test]
fn reused_exchange_deadline_does_not_reset_between_missing_proof_frames() {
    struct Advancing {
        input: Cursor<Vec<u8>>,
        clock: Arc<AtomicU64>,
    }
    impl Read for Advancing {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            let count = self.input.read(bytes)?;
            self.clock.fetch_add(3000, Ordering::Relaxed);
            Ok(count)
        }
    }
    impl Write for Advancing {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let clock = Arc::new(AtomicU64::new(0));
    let mut frames = incoming(TRANSACTION, 4, b"first");
    frames.extend(incoming(TRANSACTION, 4, b"second"));
    let mut session = Session::from_test_channel(
        Advancing {
            input: Cursor::new(frames),
            clock: clock.clone(),
        },
        binding(),
        Budget::default(),
    );
    let deadline = Deadline {
        started: Instant::now(),
        limit: CONTROL_TIMEOUT,
        cancellation: Cancellation::default(),
        elapsed: Some(clock),
    };
    drop(session.receive_before(&deadline).unwrap());
    assert_eq!(
        session.receive_before(&deadline).err(),
        Some(Error::Unavailable)
    );
    assert_eq!(session.budget.0.usage.lock().unwrap().bytes, 0);
}

#[test]
fn bounded_issuance_artifacts_only_raise_the_compact_frame_limit() {
    assert!(frame_header(COMPACT_BLOCK, 1, &binding().network, MAX_CONTROL_BYTES + 1).is_ok());
    assert_eq!(
        frame_header(TRANSACTION, 1, &binding().network, MAX_CONTROL_BYTES + 1).err(),
        Some(Error::ResourceExhausted)
    );
    assert_eq!(
        frame_header(COMPACT_BLOCK, 1, &binding().network, MAX_COMPACT_BYTES + 1).err(),
        Some(Error::ResourceExhausted)
    );
}

struct TestOnly {
    authentications: Arc<AtomicUsize>,
    expected_role: ConnectionRole,
}
impl HybridAuthenticator for TestOnly {
    type Channel = TcpStream;
    fn authenticate(
        &mut self,
        socket: TcpStream,
        admission: &AdmissionContext,
    ) -> Result<Authenticated<Self::Channel>, Error> {
        assert!(Instant::now() < admission.deadline());
        assert_eq!(admission.role(), self.expected_role);
        self.authentications.fetch_add(1, Ordering::Relaxed);
        // Socket fixtures exercise protocol integration, never hybrid security.
        Authenticated::from_verified_provider(
            socket,
            admission,
            self.expected_role,
            admission.expected_peer().descriptor(),
            test_support::parameters(),
        )
    }
}
#[test]
fn tcp_listener_and_disconnect_reconnect_use_a_fresh_authentication() {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let endpoint = listener.local_addr().unwrap();
    let binding = binding();
    let expected = test_support::expected(binding, [9; 32]);
    let server_expected = expected.clone();
    let server_count = Arc::new(AtomicUsize::new(0));
    let client_count = Arc::new(AtomicUsize::new(0));
    let observed_server = server_count.clone();
    let server = std::thread::spawn(move || {
        let mut auth = TestOnly {
            authentications: server_count,
            expected_role: ConnectionRole::Responder,
        };
        let budget = Budget::default();
        for expected in [18, 19] {
            let mut session = accept_once(
                &listener,
                &mut auth,
                &server_expected,
                Role::Validator,
                budget.clone(),
                Cancellation::default(),
            )
            .unwrap();
            match session.receive().unwrap() {
                Packet::Control {
                    kind,
                    request,
                    body,
                    ..
                } => {
                    assert_eq!((kind, request), (GET_BLOCKS, expected));
                    session.send_control(UNAVAILABLE, request, &body).unwrap();
                }
                _ => panic!("unexpected packet"),
            }
        }
    });
    let mut auth = TestOnly {
        authentications: client_count.clone(),
        expected_role: ConnectionRole::Initiator,
    };
    let budget = Budget::default();
    for request in [18, 19] {
        let mut client = connect(
            endpoint,
            &mut auth,
            &expected,
            Role::Validator,
            budget.clone(),
            Cancellation::default(),
        )
        .unwrap();
        client
            .send_control(GET_BLOCKS, request, b"locator")
            .unwrap();
        assert!(
            matches!(client.receive().unwrap(), Packet::Control { kind: UNAVAILABLE, request: actual, .. } if actual == request)
        );
        assert_eq!(client.receive().err(), Some(Error::Unavailable));
        // A failed stream is discarded; the next iteration reconnects and
        // authenticates a fresh session instead of reusing partial framing.
    }
    server.join().unwrap();
    assert_eq!(client_count.load(Ordering::Relaxed), 2);
    assert_eq!(observed_server.load(Ordering::Relaxed), 2);
}

#[test]
fn streamed_block_roundtrip_retains_the_shared_reservation() {
    let config = Config::development([51; 32], 0).unwrap();
    let state = crate::state::State::new(config).unwrap();
    let expected = crate::fixtures::candidate(&state, 1);
    let binding = binding();
    let mut sender =
        Session::from_test_channel(Cursor::new(Vec::new()), binding, Budget::default());
    sender.send_block(27, &expected).unwrap();
    let budget = Budget::default();
    let mut receiver = Session::from_test_channel(
        Cursor::new(sender.channel.into_inner()),
        binding,
        budget.clone(),
    );
    let packet = receiver.receive().unwrap();
    match &packet {
        Packet::Block { request, block, .. } => {
            assert_eq!(*request, 27);
            assert_eq!(block.as_ref(), &expected);
        }
        _ => panic!("unexpected control packet"),
    }
    assert!(budget.0.usage.lock().unwrap().bytes > expected.encoded_len().unwrap());
    drop(packet);
    assert_eq!(budget.0.usage.lock().unwrap().bytes, 0);
}

#[test]
fn failed_capability_checks_release_the_handshake_gate() {
    let binding = binding();
    let budget = Budget::default();
    let admission = test_support::admission(binding, [9; 32], ConnectionRole::Initiator);
    let auth = Authenticated::from_verified_provider(
        Cursor::new(Vec::<u8>::new()),
        &admission,
        admission.role(),
        admission.expected_peer().descriptor(),
        test_support::parameters(),
    )
    .unwrap();
    let wrong = test_support::admission(binding, [9; 32], ConnectionRole::Responder);
    assert!(matches!(
        Session::establish(auth, &wrong, Role::Validator, budget.clone()),
        Err(Error::InvalidProtocol)
    ));
    let usage = budget.0.usage.lock().unwrap();
    assert_eq!((usage.handshakes, usage.handshake_bytes), (0, 0));
}

#[test]
fn reserved_block_send_uses_the_existing_guard_without_double_charging() {
    let state = crate::state::State::new(Config::development([51; 32], 0).unwrap()).unwrap();
    let block = crate::fixtures::candidate(&state, 1);
    let bytes = block.encoded_len().unwrap() + 65536;
    let budget = Budget::new(bytes);
    let reservation = budget.reserve(bytes).unwrap();
    let mut sender = Session::from_test_channel(Cursor::new(Vec::new()), binding(), budget.clone());
    sender.send_reserved_block(9, &block, &reservation).unwrap();
    assert_eq!(budget.available().unwrap(), 0);
    assert_eq!(
        sender.channel.into_inner().len(),
        HEADER_BYTES + block.encoded_len().unwrap()
    );
    drop(reservation);
    assert_eq!(budget.available().unwrap(), bytes);
}

#[test]
fn reserved_block_send_rejects_foreign_or_small_guards_before_output() {
    let state = crate::state::State::new(Config::development([51; 32], 0).unwrap()).unwrap();
    let block = crate::fixtures::candidate(&state, 1);
    let bytes = block.encoded_len().unwrap() + 65536;
    let budget = Budget::new(bytes);
    let foreign_budget = Budget::new(bytes);
    let foreign = foreign_budget.reserve(bytes).unwrap();
    let mut sender = Session::from_test_channel(Cursor::new(Vec::new()), binding(), budget.clone());
    assert_eq!(
        sender.send_reserved_block(9, &block, &foreign),
        Err(Error::InvalidProtocol)
    );
    assert!(sender.channel.get_ref().is_empty());
    let small = budget.reserve(bytes - 1).unwrap();
    assert_eq!(
        sender.send_reserved_block(9, &block, &small),
        Err(Error::ResourceExhausted)
    );
    assert!(sender.channel.into_inner().is_empty());
}
