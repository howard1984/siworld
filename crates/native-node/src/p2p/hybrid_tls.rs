//! TLS qualification and exporter-bound dual identity.
//!
//! The candidate-only output is opaque. The separate native-p2p engineering
//! feature adds a bounded TCP bridge to the native session codec. Provider
//! qualification does not establish review of the full composition.
use super::{AdmissionContext, Budget, ConnectionRole, HandshakeReservation};
use crate::identity::NativeIdentity;
use crate::wire::Hash;
use futures::FutureExt;
use futures::future::{BoxFuture, Either};
use futures::io::{AsyncRead, AsyncWrite};
use futures_rustls::TlsStream;
use libp2p_core::UpgradeInfo;
use libp2p_core::upgrade::{InboundConnectionUpgrade, OutboundConnectionUpgrade};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

mod auth;
mod certificate;
#[cfg(feature = "native-p2p")]
pub(super) mod native;
#[cfg(test)]
mod tests;

const PROTOCOL: &str = "/siworld/native-hybrid/1";
const EXPORTER_LABEL: &[u8] = b"EXPORTER-SIWORLD-native-dual-auth-v1";
const TLS_HANDSHAKE_BYTES: usize = 8 * 1024;
const PRE_ADMISSION_BYTES: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Authentication,
    InvalidProfile,
    Io,
    Unavailable,
    Budget,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Authentication => "hybrid authentication rejected",
            Self::InvalidProfile => "hybrid profile rejected",
            Self::Io => "hybrid transport failed",
            Self::Unavailable => "hybrid admission unavailable",
            Self::Budget => "hybrid admission budget exhausted",
        })
    }
}
impl std::error::Error for Error {}

/// An individual attempt, not a reusable listener configuration. The reservation
/// and original absolute deadline exist before certificates or socket I/O.
pub(crate) struct Config {
    client: Arc<rustls::ClientConfig>,
    server: Arc<rustls::ServerConfig>,
    identity: Arc<NativeIdentity>,
    admission: AdmissionContext,
    _permit: HandshakeReservation,
}

#[derive(Debug)]
struct Resolver(Arc<rustls::sign::CertifiedKey>);
impl rustls::client::ResolvesClientCert for Resolver {
    fn resolve(
        &self,
        _: &[&[u8]],
        offered: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        offered
            .contains(&rustls::SignatureScheme::ED25519)
            .then(|| self.0.clone())
    }
    fn has_certs(&self) -> bool {
        true
    }
}
impl rustls::server::ResolvesServerCert for Resolver {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        hello
            .signature_schemes()
            .contains(&rustls::SignatureScheme::ED25519)
            .then(|| self.0.clone())
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    provider.cipher_suites =
        vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256];
    Arc::new(provider)
}

impl Config {
    pub(crate) fn new(
        identity: Arc<NativeIdentity>,
        admission: AdmissionContext,
        budget: Budget,
    ) -> Result<Self, Error> {
        admission.check().map_err(|_| Error::Unavailable)?;
        let permit = budget.handshake().map_err(|_| Error::Budget)?;
        Self::with_permit(identity, admission, permit)
    }

    fn with_permit(
        identity: Arc<NativeIdentity>,
        admission: AdmissionContext,
        permit: HandshakeReservation,
    ) -> Result<Self, Error> {
        admission.check().map_err(|_| Error::Unavailable)?;
        let local = identity.descriptor().map_err(|_| Error::Authentication)?;
        if local.binding() != admission.binding()
            || local.fingerprint() == admission.expected_peer().fingerprint()
        {
            return Err(Error::Authentication);
        }
        let (cert, key) = certificate::credentials(identity.clone())?;
        let resolver = Arc::new(Resolver(Arc::new(rustls::sign::CertifiedKey::new(
            vec![cert],
            key,
        ))));
        let verifier = Arc::new(certificate::Verifier::new(
            *admission.expected_peer().descriptor().ed25519_public(),
        ));
        let mut client = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| Error::InvalidProfile)?
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_client_cert_resolver(resolver.clone());
        client.alpn_protocols = vec![PROTOCOL.as_bytes().to_vec()];
        client.key_log = Arc::new(rustls::NoKeyLog);
        client.resumption = rustls::client::Resumption::disabled();
        client.enable_early_data = false;
        client.enable_sni = false;
        client.max_fragment_size = Some(8 * 1024);
        let mut server = rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| Error::InvalidProfile)?
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(resolver);
        server.alpn_protocols = client.alpn_protocols.clone();
        server.key_log = Arc::new(rustls::NoKeyLog);
        server.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        server.send_tls13_tickets = 0;
        server.max_early_data_size = 0;
        server.max_fragment_size = Some(8 * 1024);
        admission.check().map_err(|_| Error::Unavailable)?;
        Ok(Self {
            client: Arc::new(client),
            server: Arc::new(server),
            identity,
            admission,
            _permit: permit,
        })
    }

    async fn run<C>(
        self,
        socket: C,
        name: &str,
        role: ConnectionRole,
    ) -> Result<CandidateConnection<C>, Error>
    where
        C: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        self.admission.check().map_err(|_| Error::Unavailable)?;
        if name != PROTOCOL || role != self.admission.role() {
            return Err(Error::InvalidProfile);
        }
        let admission = self.admission.clone();
        let operation = async {
            let io = BoundedIo::new(socket);
            let mut stream: TlsStream<BoundedIo<C>> = match role {
                ConnectionRole::Initiator => {
                    let name = rustls::pki_types::ServerName::IpAddress(
                        std::net::Ipv4Addr::UNSPECIFIED.into(),
                    );
                    futures_rustls::TlsConnector::from(self.client)
                        .connect(name, io)
                        .await
                        .map_err(|_| Error::Io)?
                        .into()
                }
                ConnectionRole::Responder => futures_rustls::TlsAcceptor::from(self.server)
                    .accept(io)
                    .await
                    .map_err(|_| Error::Io)?
                    .into(),
            };
            admission.check().map_err(|_| Error::Unavailable)?;
            validate_negotiation(stream.get_ref().1)?;
            let mut context = [0; 96];
            let binding = admission.binding();
            context[..32].copy_from_slice(&binding.network);
            context[32..64].copy_from_slice(&binding.genesis);
            context[64..].copy_from_slice(&binding.verifier);
            let exporter = completed_exporter(&stream, &context)?;
            stream.get_mut().0.limit = PRE_ADMISSION_BYTES;
            auth::authenticate(
                &mut stream,
                &self.identity,
                admission.expected_peer(),
                role,
                &exporter,
            )
            .await?;
            admission.check().map_err(|_| Error::Unavailable)?;
            let wire_bytes = stream.get_ref().0.bytes;
            Ok(CandidateConnection {
                local: self
                    .identity
                    .descriptor()
                    .map_err(|_| Error::Authentication)?
                    .fingerprint(),
                peer: admission.expected_peer().fingerprint(),
                wire_bytes,
                _stream: stream,
                _permit: self._permit,
            })
        };
        // The timer is polled independently of socket readiness. Cancelling a
        // permanently pending read drops the whole operation and its transport;
        // no graceful-close cooperation from the remote peer is required.
        match futures::future::select(
            Box::pin(operation),
            Box::pin(wait_for_expiry(&self.admission)),
        )
        .await
        {
            Either::Left((result, _)) => result,
            Either::Right(((), pending)) => {
                drop(pending);
                Err(Error::Unavailable)
            }
        }
    }
}

fn validate_negotiation(state: &rustls::CommonState) -> Result<(), Error> {
    if state.is_handshaking()
        || state.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
        || state.negotiated_key_exchange_group().map(|x| x.name())
            != Some(rustls::NamedGroup::X25519MLKEM768)
        || state.negotiated_cipher_suite().map(|x| x.suite())
            != Some(rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256)
        || state.alpn_protocol() != Some(PROTOCOL.as_bytes())
        || !matches!(
            state.handshake_kind(),
            Some(rustls::HandshakeKind::Full | rustls::HandshakeKind::FullWithHelloRetryRequest)
        )
    {
        return Err(Error::InvalidProfile);
    }
    Ok(())
}

fn completed_exporter<C>(
    stream: &TlsStream<C>,
    context: &[u8; 96],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut output = Zeroizing::new([0; 32]);
    match stream {
        TlsStream::Client(stream) => {
            stream
                .get_ref()
                .1
                .export_keying_material(output.as_mut(), EXPORTER_LABEL, Some(context))
                .map_err(|_| Error::Authentication)?;
        }
        TlsStream::Server(stream) => {
            stream
                .get_ref()
                .1
                .export_keying_material(output.as_mut(), EXPORTER_LABEL, Some(context))
                .map_err(|_| Error::Authentication)?;
        }
    }
    Ok(output)
}

async fn wait_for_expiry(admission: &AdmissionContext) {
    loop {
        if admission.check().is_err() {
            return;
        }
        let remaining = admission
            .deadline()
            .saturating_duration_since(Instant::now());
        futures_timer::Delay::new(remaining.min(Duration::from_millis(20))).await;
    }
}

impl UpgradeInfo for Config {
    type Info = &'static str;
    type InfoIter = std::iter::Once<Self::Info>;
    fn protocol_info(&self) -> Self::InfoIter {
        std::iter::once(PROTOCOL)
    }
}
impl<C> InboundConnectionUpgrade<C> for Config
where
    C: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type Output = CandidateConnection<C>;
    type Error = Error;
    type Future = BoxFuture<'static, Result<Self::Output, Self::Error>>;
    fn upgrade_inbound(self, socket: C, name: Self::Info) -> Self::Future {
        self.run(socket, name, ConnectionRole::Responder).boxed()
    }
}
impl<C> OutboundConnectionUpgrade<C> for Config
where
    C: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type Output = CandidateConnection<C>;
    type Error = Error;
    type Future = BoxFuture<'static, Result<Self::Output, Self::Error>>;
    fn upgrade_outbound(self, socket: C, name: Self::Info) -> Self::Future {
        self.run(socket, name, ConnectionRole::Initiator).boxed()
    }
}

/// The candidate-only API exposes no I/O or exporter accessor. The separate
/// engineering bridge consumes this output after the same pinned dual auth.
pub(crate) struct CandidateConnection<C> {
    local: Hash,
    peer: Hash,
    wire_bytes: usize,
    _stream: TlsStream<BoundedIo<C>>,
    // Candidate outputs retain all transport state and therefore keep their
    // original conservative admission charge until the stream is dropped.
    _permit: HandshakeReservation,
}

// Close and repeat full authentication below both long-lived record limits.
// These caps include handshake traffic and are independent for each direction.
const CONNECTION_WIRE_BYTES: usize = 512 * 1024 * 1024;
const CONNECTION_RECORDS: usize = (1 << 20) - 1;

#[derive(Default)]
struct RecordBudget {
    header: [u8; 5],
    header_bytes: usize,
    remaining: usize,
    records: usize,
    bytes: usize,
}
impl RecordBudget {
    fn allowance(&self) -> io::Result<usize> {
        if self.bytes >= CONNECTION_WIRE_BYTES
            || (self.header_bytes == 0 && self.records >= CONNECTION_RECORDS)
        {
            return Err(io::Error::other(
                "hybrid connection reauthentication required",
            ));
        }
        let boundary = if self.header_bytes < 5 {
            5 - self.header_bytes
        } else {
            self.remaining
        };
        Ok(boundary.min(CONNECTION_WIRE_BYTES - self.bytes))
    }
    fn consume(&mut self, bytes: &[u8]) {
        self.bytes += bytes.len();
        if self.header_bytes < 5 {
            let start = self.header_bytes;
            self.header[start..start + bytes.len()].copy_from_slice(bytes);
            self.header_bytes += bytes.len();
            if self.header_bytes == 5 {
                self.records += 1;
                self.remaining = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
                if self.remaining == 0 {
                    self.header_bytes = 0;
                }
            }
        } else {
            self.remaining -= bytes.len();
            if self.remaining == 0 {
                self.header_bytes = 0;
            }
        }
    }
}

struct BoundedIo<C> {
    inner: C,
    bytes: usize,
    limit: usize,
    application: bool,
    incoming: RecordBudget,
    outgoing: RecordBudget,
    yield_read: bool,
}
impl<C> BoundedIo<C> {
    fn new(inner: C) -> Self {
        Self {
            inner,
            bytes: 0,
            limit: TLS_HANDSHAKE_BYTES,
            application: false,
            incoming: RecordBudget::default(),
            outgoing: RecordBudget::default(),
            yield_read: false,
        }
    }
    fn remaining(&self) -> io::Result<usize> {
        if self.application {
            return Ok(usize::MAX);
        }
        let remaining = self.limit.saturating_sub(self.bytes);
        if remaining == 0 {
            return Err(io::Error::other("hybrid wire budget exhausted"));
        }
        Ok(remaining)
    }
}
impl<C: AsyncRead + Unpin> AsyncRead for BoundedIo<C> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if out.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Let rustls observe complete records before fetching the next one;
        // TLS Finished must finish before the auth wire cap is selected.
        if self.yield_read {
            self.yield_read = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let n = out
            .len()
            .min(self.remaining()?)
            .min(self.incoming.allowance()?);
        let result = Pin::new(&mut self.inner).poll_read(cx, &mut out[..n]);
        if let Poll::Ready(Ok(n)) = &result {
            self.bytes = self.bytes.saturating_add(*n);
            self.incoming.consume(&out[..*n]);
            self.yield_read = true;
        }
        result
    }
}
impl<C: AsyncWrite + Unpin> AsyncWrite for BoundedIo<C> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = bytes
            .len()
            .min(self.remaining()?)
            .min(self.outgoing.allowance()?);
        let result = Pin::new(&mut self.inner).poll_write(cx, &bytes[..n]);
        if let Poll::Ready(Ok(n)) = &result {
            self.bytes = self.bytes.saturating_add(*n);
            self.outgoing.consume(&bytes[..*n]);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}
