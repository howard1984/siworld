use super::*;
use std::io::Cursor;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

fn binding() -> Binding {
    Binding::new(&crate::state::Config::development([51; 32], 0).unwrap())
}

fn assert_released(budget: &Budget) {
    let usage = budget.0.usage.lock().unwrap();
    assert_eq!(
        (usage.bytes, usage.handshakes, usage.handshake_bytes),
        (0, 0, 0)
    );
}

fn capability<S>(channel: S, admission: &AdmissionContext) -> Authenticated<S> {
    Authenticated::from_verified_provider(
        channel,
        admission,
        admission.role(),
        admission.expected_peer().descriptor(),
        test_support::parameters(),
    )
    .unwrap()
}

#[test]
fn expected_peer_requires_the_pinned_descriptor_and_network_context() {
    let expected = test_support::expected(binding(), [11; 32]);
    let other = test_support::expected(binding(), [12; 32]);
    assert!(matches!(
        ExpectedPeer::from_pinned_descriptor(binding(), other.descriptor().clone(), expected.pin,),
        Err(Error::InvalidProtocol)
    ));
    let mut different = binding();
    different.genesis[0] ^= 1;
    assert!(matches!(
        ExpectedPeer::from_pinned_descriptor(
            different,
            expected.descriptor().clone(),
            expected.pin,
        ),
        Err(Error::InvalidProtocol)
    ));
}

#[test]
fn wrong_provider_role_peer_and_binding_fail_before_hello_and_release_the_gate() {
    let admission = test_support::admission(binding(), [11; 32], ConnectionRole::Initiator);
    let other = test_support::expected(binding(), [12; 32]);
    let mut changed = binding();
    changed.verifier[0] ^= 1;
    let foreign = test_support::expected(changed, [11; 32]);
    let budget = Budget::default();
    for (role, peer) in [
        (ConnectionRole::Responder, admission.expected_peer()),
        (ConnectionRole::Initiator, &other),
        (ConnectionRole::Initiator, &foreign),
    ] {
        let permit = budget.handshake().unwrap();
        let channel = Cursor::new(Vec::<u8>::new());
        assert!(matches!(
            Authenticated::from_verified_provider(
                channel,
                &admission,
                role,
                peer.descriptor(),
                test_support::parameters(),
            ),
            Err(Error::InvalidProtocol)
        ));
        drop(permit);
        assert_released(&budget);
    }
}

#[test]
fn downgraded_parameter_metadata_cannot_construct_a_capability() {
    let admission = test_support::admission(binding(), [11; 32], ConnectionRole::Initiator);
    let budget = Budget::default();
    for changed in 0..6 {
        let mut parameters = test_support::parameters();
        match changed {
            0 => parameters.tls_version = 0x0303,
            1 => parameters.group = 0x001d,
            2 => parameters.cipher_suite = 0x1301,
            3 => parameters.alpn = b"libp2p",
            4 => parameters.resumed = true,
            _ => parameters.early_data = true,
        }
        let permit = budget.handshake().unwrap();
        assert!(matches!(
            Authenticated::from_verified_provider(
                Cursor::new(Vec::<u8>::new()),
                &admission,
                admission.role(),
                admission.expected_peer().descriptor(),
                parameters,
            ),
            Err(Error::InvalidProtocol)
        ));
        drop(permit);
        assert_released(&budget);
    }
}

struct ScriptedHello {
    input: Cursor<Vec<u8>>,
    operations: Arc<AtomicUsize>,
    clock: Arc<AtomicU64>,
    cancel_on_write: Option<Cancellation>,
}
impl Read for ScriptedHello {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.operations.fetch_add(1, Ordering::Relaxed);
        self.clock.fetch_add(1000, Ordering::Relaxed);
        self.input.read(bytes)
    }
}
impl Write for ScriptedHello {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.operations.fetch_add(1, Ordering::Relaxed);
        self.clock.fetch_add(1000, Ordering::Relaxed);
        if let Some(cancellation) = self.cancel_on_write.take() {
            cancellation.cancel();
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.operations.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

fn scripted(admission: &AdmissionContext, elapsed: u64) -> ScriptedHello {
    let clock = admission.deadline.elapsed.as_ref().unwrap().clone();
    clock.store(elapsed, Ordering::Relaxed);
    ScriptedHello {
        input: Cursor::new(
            Hello {
                binding: admission.binding(),
                role: Role::Validator,
            }
            .encode()
            .to_vec(),
        ),
        operations: Arc::new(AtomicUsize::new(0)),
        clock,
        cancel_on_write: None,
    }
}

#[test]
fn provider_and_hello_share_one_absolute_admission_budget() {
    let mut admission = test_support::admission(binding(), [11; 32], ConnectionRole::Initiator);
    let clock = Arc::new(AtomicU64::new(0));
    admission.deadline.elapsed = Some(clock.clone());
    let channel = scripted(&admission, 0);
    let operations = channel.operations.clone();
    let auth = capability(channel, &admission);
    // Deterministically account for time already spent in a provider. A reset
    // Hello deadline would incorrectly allow the write and subsequent read.
    clock.store(4000, Ordering::Relaxed);
    let budget = Budget::default();
    assert!(matches!(
        Session::establish(auth, &admission, Role::Validator, budget.clone()),
        Err(Error::Unavailable)
    ));
    assert_eq!(operations.load(Ordering::Relaxed), 1);
    assert_released(&budget);
}

#[test]
fn expired_or_cancelled_admission_does_not_touch_the_channel() {
    for cancel in [false, true] {
        let mut admission = test_support::admission(binding(), [11; 32], ConnectionRole::Responder);
        let clock = Arc::new(AtomicU64::new(0));
        admission.deadline.elapsed = Some(clock.clone());
        let channel = scripted(&admission, 0);
        let operations = channel.operations.clone();
        let auth = capability(channel, &admission);
        if cancel {
            admission.cancellation().cancel();
        } else {
            clock.store(5000, Ordering::Relaxed);
        }
        let budget = Budget::default();
        assert!(matches!(
            Session::establish(auth, &admission, Role::Validator, budget.clone()),
            Err(Error::Unavailable)
        ));
        assert_eq!(operations.load(Ordering::Relaxed), 0);
        assert_released(&budget);
    }
}

#[test]
fn cancellation_during_hello_releases_the_gate_before_another_io() {
    let mut admission = test_support::admission(binding(), [11; 32], ConnectionRole::Initiator);
    admission.deadline.elapsed = Some(Arc::new(AtomicU64::new(0)));
    let mut channel = scripted(&admission, 0);
    channel.cancel_on_write = Some(admission.cancellation().clone());
    let operations = channel.operations.clone();
    let auth = capability(channel, &admission);
    let budget = Budget::default();
    assert!(matches!(
        Session::establish(auth, &admission, Role::Validator, budget.clone()),
        Err(Error::Unavailable)
    ));
    assert_eq!(operations.load(Ordering::Relaxed), 1);
    assert_released(&budget);
}

#[test]
fn successful_admission_preserves_the_expected_peer_and_releases_the_gate() {
    let mut admission = test_support::admission(binding(), [11; 32], ConnectionRole::Initiator);
    admission.deadline.elapsed = Some(Arc::new(AtomicU64::new(0)));
    let channel = scripted(&admission, 0);
    let auth = capability(channel, &admission);
    let budget = Budget::default();
    let session = Session::establish(auth, &admission, Role::Miner, budget.clone()).unwrap();
    assert_eq!(session.peer(), admission.expected_peer().fingerprint());
    assert_eq!(session.role(), Role::Validator);
    assert_released(&budget);
}

#[test]
fn a_replacement_context_cannot_refresh_a_capability_deadline() {
    let mut admission = test_support::admission(binding(), [11; 32], ConnectionRole::Initiator);
    admission.deadline.elapsed = Some(Arc::new(AtomicU64::new(0)));
    let channel = scripted(&admission, 0);
    let operations = channel.operations.clone();
    let auth = capability(channel, &admission);
    let mut replacement = admission.clone();
    replacement.deadline.started += Duration::from_secs(1);
    let budget = Budget::default();
    assert!(matches!(
        Session::establish(auth, &replacement, Role::Validator, budget.clone()),
        Err(Error::InvalidProtocol)
    ));
    assert_eq!(operations.load(Ordering::Relaxed), 0);
    assert_released(&budget);
}

struct InvalidProvider {
    fault: u8,
    calls: usize,
}
impl HybridAuthenticator for InvalidProvider {
    type Channel = Cursor<Vec<u8>>;
    fn authenticate(
        &mut self,
        _socket: TcpStream,
        admission: &AdmissionContext,
    ) -> Result<Authenticated<Self::Channel>, Error> {
        self.calls += 1;
        let mut observed = admission.expected_peer().clone();
        let mut role = admission.role();
        let mut parameters = test_support::parameters();
        match self.fault {
            0 => role = ConnectionRole::Responder,
            1 => observed = test_support::expected(admission.binding(), [17; 32]),
            2 => {
                let mut binding = admission.binding();
                binding.genesis[0] ^= 1;
                observed = test_support::expected(binding, [11; 32]);
            }
            3 => parameters.group = 0x001d,
            _ => admission.cancellation().cancel(),
        }
        Authenticated::from_verified_provider(
            Cursor::new(Vec::new()),
            admission,
            role,
            observed.descriptor(),
            parameters,
        )
    }
}

#[test]
fn outbound_provider_rejections_and_cancellation_release_reserved_admission() {
    let expected = test_support::expected(binding(), [11; 32]);
    for fault in 0..5 {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut provider = InvalidProvider { fault, calls: 0 };
        let budget = Budget::default();
        assert_eq!(
            connect(
                listener.local_addr().unwrap(),
                &mut provider,
                &expected,
                Role::Validator,
                budget.clone(),
                Cancellation::default(),
            )
            .err(),
            Some(if fault < 4 {
                Error::InvalidProtocol
            } else {
                Error::Unavailable
            })
        );
        assert_eq!(provider.calls, 1);
        assert_released(&budget);
    }
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let cancellation = Cancellation::default();
    cancellation.cancel();
    let mut provider = InvalidProvider { fault: 0, calls: 0 };
    let budget = Budget::default();
    assert!(matches!(
        connect(
            listener.local_addr().unwrap(),
            &mut provider,
            &expected,
            Role::Validator,
            budget.clone(),
            cancellation,
        ),
        Err(Error::Unavailable)
    ));
    assert_eq!(provider.calls, 0);
    assert_released(&budget);
}
