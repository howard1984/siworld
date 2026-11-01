use super::*;
use crate::identity::PeerPin;
use crate::p2p::{
    Binding, ExpectedPeer, GET_BLOCKS, HANDSHAKE_BYTES, Packet, Role, Session, establish_socket,
};
use std::net::{Ipv4Addr, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};

fn binding() -> Binding {
    Binding::new(&crate::state::Config::development([94; 32], 0).unwrap())
}

fn identity() -> Arc<NativeIdentity> {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "native-resident-tls-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let identity = NativeIdentity::initialize(&path.canonicalize().unwrap(), binding()).unwrap();
    std::fs::remove_dir_all(path).unwrap();
    Arc::new(identity)
}

fn expected(identity: &NativeIdentity) -> ExpectedPeer {
    let descriptor = identity.descriptor().unwrap();
    let pin = PeerPin::from_trusted_descriptor(&descriptor, &binding()).unwrap();
    ExpectedPeer::from_pinned_descriptor(binding(), descriptor, pin).unwrap()
}

fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}

fn assert_usage(budget: &Budget, bytes: usize, handshakes: usize) {
    let usage = budget.0.usage.lock().unwrap();
    assert_eq!(usage.bytes, bytes);
    assert_eq!(usage.handshakes, handshakes);
    assert_eq!(usage.handshake_bytes, handshakes * HANDSHAKE_BYTES);
}

fn session(
    socket: TcpStream,
    local: Arc<NativeIdentity>,
    peer: &NativeIdentity,
    role: ConnectionRole,
    budget: Budget,
    cancellation: Cancellation,
) -> Result<Session<NativeTlsChannel>, super::super::super::Error> {
    let context = AdmissionContext::new(expected(peer), role, cancellation);
    let mut provider = NativeTlsAuthenticator::new(local, budget.clone());
    establish_socket(socket, &mut provider, &context, Role::Validator, budget)
}

#[test]
fn actual_loopback_tls_native_hello_and_large_frames_survive_pre_admission_cap() {
    let a = identity();
    let b = identity();
    let (client, server) = pair();
    let budget = Budget::default();
    let a_peer = a.clone();
    let b_local = b.clone();
    let server_budget = budget.clone();
    let (ready_send, ready_receive) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let mut session = session(
            server,
            b_local,
            &a_peer,
            ConnectionRole::Responder,
            server_budget,
            Cancellation::default(),
        )
        .unwrap();
        ready_send.send(()).unwrap();
        for expected_request in 0..3 {
            let packet = session.receive().unwrap();
            let Packet::Control { request, body, .. } = packet else {
                panic!("expected bounded control frame");
            };
            assert_eq!(request, expected_request);
            assert_eq!(body, vec![expected_request as u8; 96 * 1024]);
            session.send_control(GET_BLOCKS, request, &body).unwrap();
        }
    });
    let mut client = session(
        client,
        a,
        &b,
        ConnectionRole::Initiator,
        budget.clone(),
        Cancellation::default(),
    )
    .unwrap();
    ready_receive.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_usage(&budget, HANDSHAKE_BYTES * 2, 0);
    for request in 0..3 {
        let body = vec![request as u8; 96 * 1024];
        client.send_control(GET_BLOCKS, request, &body).unwrap();
        let Packet::Control { body: received, .. } = client.receive().unwrap() else {
            panic!("expected bounded response");
        };
        assert_eq!(received, body);
    }
    drop(client);
    thread.join().unwrap();
    assert_usage(&budget, 0, 0);
}

#[test]
fn reconnect_requires_fresh_dual_authentication_and_releases_prior_charge() {
    let a = identity();
    let b = identity();
    let budget = Budget::default();
    for _ in 0..2 {
        let (client, server) = pair();
        let a_peer = a.clone();
        let b_local = b.clone();
        let server_budget = budget.clone();
        let thread = std::thread::spawn(move || {
            let mut session = session(
                server,
                b_local,
                &a_peer,
                ConnectionRole::Responder,
                server_budget,
                Cancellation::default(),
            )
            .unwrap();
            let Packet::Control { request, .. } = session.receive().unwrap() else {
                panic!("expected reconnect frame");
            };
            assert_eq!(request, 13);
        });
        let mut client = session(
            client,
            a.clone(),
            &b,
            ConnectionRole::Initiator,
            budget.clone(),
            Cancellation::default(),
        )
        .unwrap();
        client.send_control(GET_BLOCKS, 13, &[]).unwrap();
        drop(client);
        thread.join().unwrap();
        assert_usage(&budget, 0, 0);
    }
}

#[test]
fn independently_pinned_wrong_identity_is_rejected_without_a_session() {
    let a = identity();
    let b = identity();
    let wrong = identity();
    let (client, server) = pair();
    let budget = Budget::default();
    let a_peer = a.clone();
    let server_budget = budget.clone();
    let thread = std::thread::spawn(move || {
        session(
            server,
            b,
            &a_peer,
            ConnectionRole::Responder,
            server_budget,
            Cancellation::default(),
        )
        .is_err()
    });
    assert!(
        session(
            client,
            a,
            &wrong,
            ConnectionRole::Initiator,
            budget.clone(),
            Cancellation::default(),
        )
        .is_err()
    );
    assert!(thread.join().unwrap());
    assert_usage(&budget, 0, 0);
}

#[test]
fn stalled_tcp_peer_is_cancelled_within_one_bounded_socket_poll() {
    let a = identity();
    let b = identity();
    let (client, _held_server) = pair();
    let budget = Budget::default();
    let cancellation = Cancellation::default();
    let signal = cancellation.clone();
    let thread = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        signal.cancel();
    });
    let started = Instant::now();
    assert!(
        session(
            client,
            a,
            &b,
            ConnectionRole::Initiator,
            budget.clone(),
            cancellation,
        )
        .is_err()
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    thread.join().unwrap();
    assert_usage(&budget, 0, 0);
}

#[test]
fn expired_original_context_cannot_start_tls_after_routing() {
    let a = identity();
    let b = identity();
    let (socket, _held_peer) = pair();
    let context = AdmissionContext::new_started(
        expected(&b),
        ConnectionRole::Initiator,
        Cancellation::default(),
        Instant::now() - Duration::from_secs(6),
    );
    let budget = Budget::default();
    let mut provider = NativeTlsAuthenticator::new(a, budget.clone());
    assert!(
        establish_socket(socket, &mut provider, &context, Role::Miner, budget.clone()).is_err()
    );
    assert_usage(&budget, 0, 0);
}

#[test]
fn established_read_is_interrupted_by_node_cancellation() {
    let a = identity();
    let b = identity();
    let (client, server) = pair();
    let budget = Budget::default();
    let cancellation = Cancellation::default();
    let signal = cancellation.clone();
    let a_peer = a.clone();
    let b_local = b.clone();
    let server_budget = budget.clone();
    let (send, receive) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let _session = session(
            server,
            b_local,
            &a_peer,
            ConnectionRole::Responder,
            server_budget,
            Cancellation::default(),
        )
        .unwrap();
        receive.recv_timeout(Duration::from_secs(2)).unwrap();
    });
    let mut client = session(
        client,
        a,
        &b,
        ConnectionRole::Initiator,
        budget.clone(),
        cancellation,
    )
    .unwrap();
    let cancel = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        signal.cancel();
    });
    let started = Instant::now();
    assert!(client.receive().is_err());
    assert!(started.elapsed() < Duration::from_secs(2));
    cancel.join().unwrap();
    send.send(()).unwrap();
    drop(client);
    thread.join().unwrap();
    assert_usage(&budget, 0, 0);
}

#[test]
fn record_and_byte_reauthentication_caps_apply_in_both_directions() {
    for outgoing in [false, true] {
        let mut io = BoundedIo::new(futures::io::Cursor::new(Vec::<u8>::new()));
        io.application = true;
        let counter = if outgoing {
            &mut io.outgoing
        } else {
            &mut io.incoming
        };
        counter.bytes = super::super::CONNECTION_WIRE_BYTES - 1;
        assert_eq!(counter.allowance().unwrap(), 1);
        counter.consume(&[23]);
        assert!(counter.allowance().is_err());
        counter.bytes = 0;
        counter.header_bytes = 0;
        counter.records = super::super::CONNECTION_RECORDS;
        assert!(counter.allowance().is_err());
    }
}

#[test]
fn incomplete_tls_record_headers_cannot_reset_the_record_budget() {
    let mut counter = super::super::RecordBudget::default();
    for byte in [23, 3, 3, 0] {
        assert!(counter.allowance().is_ok());
        counter.consume(&[byte]);
        assert_eq!(counter.records, 0);
    }
    counter.consume(&[1]);
    assert_eq!(counter.records, 1);
    counter.consume(&[9]);
    assert_eq!(counter.allowance().unwrap(), 5);
    assert_eq!(counter.records, 1);
}

#[test]
fn tls_success_does_not_refresh_the_original_native_hello_deadline() {
    let a = identity();
    let b = identity();
    let (client, server) = pair();
    let a_peer = a.clone();
    let b_local = b.clone();
    let budget = Budget::default();
    let server_budget = budget.clone();
    let thread = std::thread::spawn(move || {
        let context = AdmissionContext::new(
            expected(&a_peer),
            ConnectionRole::Responder,
            Cancellation::default(),
        );
        server.set_nonblocking(true).unwrap();
        let socket = SocketIo::new(server, context.cancellation().clone());
        let config = Config::new(b_local, context, server_budget).unwrap();
        let authenticated =
            futures::executor::block_on(config.run(socket, PROTOCOL, ConnectionRole::Responder))
                .unwrap();
        // Keep TLS alive but withhold the native Hello. This is separate from
        // the exporter-bound dual-identity hello already completed above.
        std::thread::sleep(Duration::from_millis(2100));
        drop(authenticated);
    });
    let context = AdmissionContext::new_started(
        expected(&b),
        ConnectionRole::Initiator,
        Cancellation::default(),
        Instant::now() - Duration::from_secs(4),
    );
    let mut provider = NativeTlsAuthenticator::new(a, budget.clone());
    let started = Instant::now();
    assert!(
        establish_socket(
            client,
            &mut provider,
            &context,
            Role::Validator,
            budget.clone()
        )
        .is_err()
    );
    assert!(started.elapsed() < Duration::from_millis(1800));
    thread.join().unwrap();
    assert_usage(&budget, 0, 0);
}

#[test]
fn direct_provider_entry_cannot_leave_an_uncharged_tls_channel() {
    let local = identity();
    let peer = identity();
    let (socket, _held_peer) = pair();
    let context = AdmissionContext::new(
        expected(&peer),
        ConnectionRole::Initiator,
        Cancellation::default(),
    );
    let budget = Budget::default();
    let mut provider = NativeTlsAuthenticator::new(local, budget.clone());
    assert!(matches!(
        provider.authenticate(socket, &context),
        Err(Error::Unconfigured)
    ));
    assert_usage(&budget, 0, 0);
}

#[test]
fn genuine_five_second_native_hello_window_expires_on_a_silent_authenticated_peer() {
    let a = identity();
    let b = identity();
    let (client, server) = pair();
    let a_peer = a.clone();
    let b_local = b.clone();
    let budget = Budget::default();
    let server_budget = budget.clone();
    let thread = std::thread::spawn(move || {
        let context = AdmissionContext::new(
            expected(&a_peer),
            ConnectionRole::Responder,
            Cancellation::default(),
        );
        server.set_nonblocking(true).unwrap();
        let socket = SocketIo::new(server, context.cancellation().clone());
        let config = Config::new(b_local, context, server_budget).unwrap();
        let authenticated =
            futures::executor::block_on(config.run(socket, PROTOCOL, ConnectionRole::Responder))
                .unwrap();
        std::thread::sleep(Duration::from_secs(6));
        drop(authenticated);
    });
    let context = AdmissionContext::new(
        expected(&b),
        ConnectionRole::Initiator,
        Cancellation::default(),
    );
    let mut provider = NativeTlsAuthenticator::new(a, budget.clone());
    let started = Instant::now();
    assert!(
        establish_socket(
            client,
            &mut provider,
            &context,
            Role::Validator,
            budget.clone()
        )
        .is_err()
    );
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(4800));
    assert!(elapsed < Duration::from_millis(5800));
    thread.join().unwrap();
    assert_usage(&budget, 0, 0);
}
