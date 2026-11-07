use super::*;
use crate::identity::PeerPin;
use futures::io::Cursor;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

fn binding() -> super::super::Binding {
    super::super::Binding::new(&crate::state::Config::development([91; 32], 0).unwrap())
}

fn identity() -> Arc<NativeIdentity> {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "native-tls-{}-{}",
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

fn admission(peer: &NativeIdentity, role: ConnectionRole) -> AdmissionContext {
    let descriptor = peer.descriptor().unwrap();
    let pin = PeerPin::from_trusted_descriptor(&descriptor, &binding()).unwrap();
    AdmissionContext::new(
        super::super::ExpectedPeer::from_pinned_descriptor(binding(), descriptor, pin).unwrap(),
        role,
        super::super::Cancellation::default(),
    )
}

#[test]
fn exclusive_profile_disables_fallback_key_logging_and_resumption() {
    let local = identity();
    let remote = identity();
    let budget = Budget::default();
    let config = Config::new(local, admission(&remote, ConnectionRole::Initiator), budget).unwrap();
    assert_eq!(config.protocol_info().collect::<Vec<_>>(), vec![PROTOCOL]);
    for provider in [
        config.client.crypto_provider(),
        config.server.crypto_provider(),
    ] {
        assert_eq!(provider.kx_groups.len(), 1);
        assert_eq!(
            provider.kx_groups[0].name(),
            rustls::NamedGroup::X25519MLKEM768
        );
        assert_eq!(provider.cipher_suites.len(), 1);
        assert_eq!(
            provider.cipher_suites[0].suite(),
            rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        );
    }
    assert_eq!(
        config.client.alpn_protocols,
        vec![
            crate::p2p::CHECKPOINT_ALPN.to_vec(),
            PROTOCOL.as_bytes().to_vec()
        ]
    );
    assert_eq!(config.server.alpn_protocols, config.client.alpn_protocols);
    assert!(!config.client.key_log.will_log("CLIENT_TRAFFIC_SECRET_0"));
    assert!(!config.server.key_log.will_log("SERVER_TRAFFIC_SECRET_0"));
    assert!(!config.client.enable_early_data);
    assert_eq!(config.server.max_early_data_size, 0);
    assert_eq!(config.server.send_tls13_tickets, 0);
    assert!(!config.server.session_storage.can_cache());
}

#[test]
fn no_capacity_rejects_before_certificate_or_socket_work() {
    let remote = identity();
    assert!(matches!(
        Config::new(
            identity(),
            admission(&remote, ConnectionRole::Initiator),
            Budget::new(0)
        ),
        Err(Error::Budget)
    ));
}

#[test]
fn mismatched_upgrade_name_and_role_release_reservation() {
    futures::executor::block_on(async {
        let remote = identity();
        let budget = Budget::default();
        let config = Config::new(
            identity(),
            admission(&remote, ConnectionRole::Initiator),
            budget.clone(),
        )
        .unwrap();
        assert!(matches!(
            config
                .upgrade_outbound(Cursor::new(Vec::<u8>::new()), "/tls/1.0.0")
                .await,
            Err(Error::InvalidProfile)
        ));
        let config = Config::new(
            identity(),
            admission(&remote, ConnectionRole::Responder),
            budget.clone(),
        )
        .unwrap();
        assert!(matches!(
            config
                .upgrade_outbound(Cursor::new(Vec::<u8>::new()), PROTOCOL)
                .await,
            Err(Error::InvalidProfile)
        ));
        assert_eq!(budget.available().unwrap(), super::super::CONNECTION_BYTES);
    });
}

#[derive(Default)]
struct Pipe {
    bytes: VecDeque<u8>,
    waker: Option<std::task::Waker>,
    closed: bool,
}
struct Duplex {
    incoming: Arc<Mutex<Pipe>>,
    outgoing: Arc<Mutex<Pipe>>,
    fragment: usize,
    write_position: usize,
    corrupt_at: Option<usize>,
}
impl Duplex {
    fn pair(fragment: usize) -> (Self, Self) {
        let a = Arc::new(Mutex::new(Pipe::default()));
        let b = Arc::new(Mutex::new(Pipe::default()));
        (
            Self {
                incoming: a.clone(),
                outgoing: b.clone(),
                fragment,
                write_position: 0,
                corrupt_at: None,
            },
            Self {
                incoming: b,
                outgoing: a,
                fragment,
                write_position: 0,
                corrupt_at: None,
            },
        )
    }
}
impl Drop for Duplex {
    fn drop(&mut self) {
        let mut p = self.outgoing.lock().unwrap();
        p.closed = true;
        if let Some(w) = p.waker.take() {
            w.wake();
        }
    }
}
impl AsyncRead for Duplex {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut p = self.incoming.lock().unwrap();
        if out.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if p.bytes.is_empty() {
            if p.closed {
                return Poll::Ready(Ok(0));
            }
            p.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = out.len().min(self.fragment).min(p.bytes.len());
        for x in &mut out[..n] {
            *x = p.bytes.pop_front().unwrap();
        }
        Poll::Ready(Ok(n))
    }
}
impl AsyncWrite for Duplex {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let outgoing = self.outgoing.clone();
        let mut p = outgoing.lock().unwrap();
        let n = bytes.len().min(self.fragment);
        for (offset, byte) in bytes[..n].iter().copied().enumerate() {
            p.bytes
                .push_back(if self.corrupt_at == Some(self.write_position + offset) {
                    byte ^ 1
                } else {
                    byte
                });
        }
        self.write_position += n;
        if let Some(w) = p.waker.take() {
            w.wake();
        }
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn real_hybrid_tls_and_both_signatures_complete_over_fragments() {
    futures::executor::block_on(async {
        for fragment in [1, 31, 8192] {
            let a = identity();
            let b = identity();
            let budget = Budget::default();
            let ca = Config::new(
                a.clone(),
                admission(&b, ConnectionRole::Initiator),
                budget.clone(),
            )
            .unwrap();
            let cb = Config::new(
                b.clone(),
                admission(&a, ConnectionRole::Responder),
                budget.clone(),
            )
            .unwrap();
            let (sa, sb) = Duplex::pair(fragment);
            let (a, b) = futures::join!(
                ca.upgrade_outbound(sa, PROTOCOL),
                cb.upgrade_inbound(sb, PROTOCOL)
            );
            let a = a.unwrap();
            let b = b.unwrap();
            assert_eq!(a.peer, b.local);
            assert_eq!(b.peer, a.local);
            assert!(a.wire_bytes <= PRE_ADMISSION_BYTES);
            assert!(b.wire_bytes <= PRE_ADMISSION_BYTES);
            assert_eq!(
                budget.available().unwrap(),
                super::super::CONNECTION_BYTES - 2 * super::super::HANDSHAKE_BYTES
            );
            drop(a);
            drop(b);
            assert_eq!(budget.available().unwrap(), super::super::CONNECTION_BYTES);
        }
    });
}

#[test]
fn permanently_pending_io_is_cancelled_and_frees_admission_budget() {
    futures::executor::block_on(async {
        let peer = identity();
        let context = admission(&peer, ConnectionRole::Responder);
        let cancel = context.cancellation().clone();
        let budget = Budget::default();
        let config = Config::new(identity(), context, budget.clone()).unwrap();
        let (socket, _held_peer) = Duplex::pair(8192);
        let attempt = config.upgrade_inbound(socket, PROTOCOL);
        let signal = async {
            futures_timer::Delay::new(Duration::from_millis(30)).await;
            cancel.cancel();
        };
        let started = Instant::now();
        let (result, ()) = futures::join!(attempt, signal);
        assert!(matches!(result, Err(Error::Unavailable)));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(budget.available().unwrap(), super::super::CONNECTION_BYTES);
    });
}

#[test]
fn actual_classical_only_tls_offer_is_rejected_without_retry() {
    futures::executor::block_on(async {
        let a = identity();
        let b = identity();
        let budget = Budget::default();
        let mut client = Config::new(
            a.clone(),
            admission(&b, ConnectionRole::Initiator),
            budget.clone(),
        )
        .unwrap();
        let server = Config::new(
            b.clone(),
            admission(&a, ConnectionRole::Responder),
            budget.clone(),
        )
        .unwrap();
        let mut classical = rustls::crypto::aws_lc_rs::default_provider();
        classical.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
        let mut replacement = rustls::ClientConfig::builder_with_provider(Arc::new(classical))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(certificate::Verifier::new(
                *b.descriptor().unwrap().ed25519_public(),
            )))
            .with_client_cert_resolver(client.client.client_auth_cert_resolver.clone());
        replacement.alpn_protocols = vec![PROTOCOL.as_bytes().to_vec()];
        client.client = Arc::new(replacement);
        let (sa, sb) = Duplex::pair(8192);
        let (a, b) = futures::join!(
            client.upgrade_outbound(sa, PROTOCOL),
            server.upgrade_inbound(sb, PROTOCOL)
        );
        assert!(a.is_err() && b.is_err());
        assert_eq!(budget.available().unwrap(), super::super::CONNECTION_BYTES);
    });
}

#[test]
fn changed_hybrid_key_share_never_completes_dual_authentication() {
    futures::executor::block_on(async {
        for corrupt_initiator in [false, true] {
            let a = identity();
            let b = identity();
            let budget = Budget::default();
            let client = Config::new(
                a.clone(),
                admission(&b, ConnectionRole::Initiator),
                budget.clone(),
            )
            .unwrap();
            let server = Config::new(
                b.clone(),
                admission(&a, ConnectionRole::Responder),
                budget.clone(),
            )
            .unwrap();
            let (mut sa, mut sb) = Duplex::pair(8192);
            if corrupt_initiator {
                sa.corrupt_at = Some(200);
            } else {
                sb.corrupt_at = Some(200);
            }
            let (a, b) = futures::join!(
                client.upgrade_outbound(sa, PROTOCOL),
                server.upgrade_inbound(sb, PROTOCOL)
            );
            assert!(a.is_err() && b.is_err());
            assert_eq!(budget.available().unwrap(), super::super::CONNECTION_BYTES);
        }
    });
}

#[test]
fn original_absolute_deadline_expires_during_stalled_tls_io() {
    futures::executor::block_on(async {
        let peer = identity();
        let budget = Budget::default();
        let started = Instant::now();
        let config = Config::new(
            identity(),
            admission(&peer, ConnectionRole::Responder),
            budget.clone(),
        )
        .unwrap();
        let (socket, _held_peer) = Duplex::pair(8192);
        assert!(matches!(
            config.upgrade_inbound(socket, PROTOCOL).await,
            Err(Error::Unavailable)
        ));
        assert!(started.elapsed() >= Duration::from_secs(4));
        assert!(started.elapsed() < Duration::from_secs(8));
        assert_eq!(budget.available().unwrap(), super::super::CONNECTION_BYTES);
    });
}

#[test]
fn early_exporter_is_unavailable_and_cancelled_attempt_reads_nothing() {
    futures::executor::block_on(async {
        let remote = identity();
        let context = admission(&remote, ConnectionRole::Responder);
        let cancel = context.cancellation().clone();
        let budget = Budget::default();
        let config = Config::new(identity(), context, budget.clone()).unwrap();
        let connection = rustls::ClientConnection::new(
            config.client.clone(),
            rustls::pki_types::ServerName::try_from("unused.invalid").unwrap(),
        )
        .unwrap();
        assert!(
            connection
                .export_keying_material([0; 32], EXPORTER_LABEL, Some(&[0; 96]))
                .is_err()
        );
        cancel.cancel();
        let (socket, _peer) = Duplex::pair(8192);
        assert!(matches!(
            config.upgrade_inbound(socket, PROTOCOL).await,
            Err(Error::Unavailable)
        ));
        assert_eq!(budget.available().unwrap(), super::super::CONNECTION_BYTES);
    });
}

#[test]
fn wire_budget_is_checked_before_polling_more_bytes() {
    futures::executor::block_on(async {
        use futures::io::AsyncReadExt;
        let mut bounded = BoundedIo::new(Cursor::new(vec![1u8; 100]));
        bounded.limit = 5;
        let mut out = [0; 100];
        assert_eq!(bounded.read(&mut out).await.unwrap(), 5);
        assert!(bounded.read(&mut out).await.is_err());
        assert_eq!(bounded.bytes, 5);
    });
}

#[test]
fn checkpoint_alpn_negotiates_without_breaking_legacy_crypto_profile() {
    futures::executor::block_on(async {
        for legacy_client in [false, true] {
            for legacy_server in [false, true] {
                let a = identity();
                let b = identity();
                let budget = Budget::default();
                let mut client = Config::new(
                    a.clone(),
                    admission(&b, ConnectionRole::Initiator),
                    budget.clone(),
                )
                .unwrap();
                let mut server = Config::new(
                    b.clone(),
                    admission(&a, ConnectionRole::Responder),
                    budget.clone(),
                )
                .unwrap();
                if legacy_client {
                    Arc::get_mut(&mut client.client).unwrap().alpn_protocols =
                        vec![PROTOCOL.as_bytes().to_vec()];
                }
                if legacy_server {
                    Arc::get_mut(&mut server.server).unwrap().alpn_protocols =
                        vec![PROTOCOL.as_bytes().to_vec()];
                }
                let (sa, sb) = Duplex::pair(8192);
                let (a, b) = futures::join!(
                    client.upgrade_outbound(sa, PROTOCOL),
                    server.upgrade_inbound(sb, PROTOCOL)
                );
                let a = a.unwrap();
                let b = b.unwrap();
                let expected = if legacy_client || legacy_server {
                    PROTOCOL.as_bytes()
                } else {
                    crate::p2p::CHECKPOINT_ALPN
                };
                assert_eq!(a._stream.get_ref().1.alpn_protocol(), Some(expected));
                assert_eq!(b._stream.get_ref().1.alpn_protocol(), Some(expected));
                assert_eq!(a.peer, b.local);
                assert_eq!(a.local, b.peer);
                drop((a, b));
                assert_eq!(budget.available().unwrap(), super::super::CONNECTION_BYTES);
            }
        }
    });
}
