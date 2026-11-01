//! Explicit pinned-peer engineering transport for the native session codec.
//!
//! The candidate TLS upgrade remains the only cryptographic path. The bridge
//! supplies nonblocking TCP, finite polling slices and ownership transfer; it
//! adds no fallback, identity discovery or application protocol negotiation.
use super::{BoundedIo, CandidateConnection, Config, Error as TlsError, PROTOCOL};
use crate::identity::NativeIdentity;
use crate::p2p::{
    AdmissionContext, Authenticated, Budget, Cancellation, ConnectionRole, Error, HELLO_BYTES,
    HandshakeReservation, HybridAuthenticator, NegotiatedParameters,
};
use futures::FutureExt;
use futures::future::Either;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use futures_rustls::TlsStream;
use libp2p_core::upgrade::{InboundConnectionUpgrade, OutboundConnectionUpgrade};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

#[cfg(test)]
mod tests;

const IO_POLL: Duration = Duration::from_millis(10);
const IO_SLICE: Duration = Duration::from_millis(20);
const TLS_BUFFER_BYTES: usize = 64 * 1024;
const MAX_CONNECTION_AGE: Duration = Duration::from_secs(50 * 60);

/// An independently pinned transport. Listener routing must select the peer
/// from a local allowlist before constructing the original AdmissionContext.
pub struct NativeTlsAuthenticator {
    identity: Arc<NativeIdentity>,
    budget: Budget,
}
impl NativeTlsAuthenticator {
    pub fn new(identity: Arc<NativeIdentity>, budget: Budget) -> Self {
        Self { identity, budget }
    }

    fn reserved(
        &self,
        socket: TcpStream,
        admission: &AdmissionContext,
        permit: HandshakeReservation,
    ) -> Result<(Authenticated<NativeTlsChannel>, HandshakeReservation), Error> {
        admission.check()?;
        if !Arc::ptr_eq(&permit.0, &self.budget.0) {
            return Err(Error::InvalidProtocol);
        }
        socket
            .set_nonblocking(true)
            .map_err(super::super::io_error)?;
        socket.set_nodelay(true).map_err(super::super::io_error)?;
        let socket = SocketIo::new(socket, admission.cancellation().clone());
        let config = Config::with_permit(self.identity.clone(), admission.clone(), permit)
            .map_err(map_tls)?;
        let upgrade = match admission.role() {
            ConnectionRole::Initiator => config.upgrade_outbound(socket, PROTOCOL),
            ConnectionRole::Responder => config.upgrade_inbound(socket, PROTOCOL),
        };
        let verified = futures::executor::block_on(upgrade).map_err(map_tls)?;
        let CandidateConnection {
            _stream: mut stream,
            _permit: permit,
            ..
        } = verified;
        // Bound the plaintext and encrypted output queues independently of a
        // cumulative connection lifetime cap. Fragmentation remains 8 KiB.
        match &mut stream {
            TlsStream::Client(stream) => {
                stream.get_mut().1.set_buffer_limit(Some(TLS_BUFFER_BYTES))
            }
            TlsStream::Server(stream) => {
                stream.get_mut().1.set_buffer_limit(Some(TLS_BUFFER_BYTES))
            }
        }
        let channel = NativeTlsChannel {
            stream,
            cancellation: admission.cancellation().clone(),
            started: admission.deadline.started,
            hello_read: 0,
            hello_written: 0,
        };
        let capability = Authenticated::from_verified_provider(
            channel,
            admission,
            admission.role(),
            admission.expected_peer().descriptor(),
            NegotiatedParameters {
                tls_version: 0x0304,
                group: 0x11ec,
                cipher_suite: 0x1303,
                alpn: PROTOCOL.as_bytes(),
                resumed: false,
                early_data: false,
            },
        )?;
        Ok((capability, permit))
    }
}
impl HybridAuthenticator for NativeTlsAuthenticator {
    type Channel = NativeTlsChannel;

    fn authenticate(
        &mut self,
        socket: TcpStream,
        admission: &AdmissionContext,
    ) -> Result<Authenticated<Self::Channel>, Error> {
        // Direct provider calls cannot preserve the shared guard through the
        // native Hello. Only establish_socket's reserved entry is supported.
        drop(socket);
        admission.check()?;
        Err(Error::Unconfigured)
    }

    fn authenticate_reserved(
        &mut self,
        socket: TcpStream,
        admission: &AdmissionContext,
        permit: HandshakeReservation,
    ) -> Result<(Authenticated<Self::Channel>, HandshakeReservation), Error> {
        self.reserved(socket, admission, permit)
    }
}

fn map_tls(error: TlsError) -> Error {
    match error {
        TlsError::Authentication | TlsError::InvalidProfile => Error::InvalidProtocol,
        TlsError::Budget => Error::ResourceExhausted,
        TlsError::Io | TlsError::Unavailable => Error::Unavailable,
    }
}

/// A synchronous view with bounded polling slices. The native Timed wrapper
/// retries Interrupted while checking its absolute operation deadline. The
/// TLS stream itself is retained across slices, including pending ciphertext.
/// Drop closes the socket; reconnecting always repeats full hybrid dual auth.
pub struct NativeTlsChannel {
    stream: TlsStream<BoundedIo<SocketIo>>,
    cancellation: Cancellation,
    started: Instant,
    hello_read: usize,
    hello_written: usize,
}
impl NativeTlsChannel {
    fn check(&self) -> io::Result<()> {
        if self.cancellation.is_cancelled() || self.started.elapsed() >= MAX_CONNECTION_AGE {
            let _ = self
                .stream
                .get_ref()
                .0
                .inner
                .socket
                .shutdown(std::net::Shutdown::Both);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "native connection expired",
            ));
        }
        Ok(())
    }
    fn complete_hello(&mut self) {
        if self.hello_read == HELLO_BYTES && self.hello_written == HELLO_BYTES {
            self.stream.get_mut().0.application = true;
        }
    }
}

/// A complete paired exchange must fit before the transport's hard reconnect
/// limits. No counters, TLS state or socket handles leave this interface.
impl crate::p2p::Session<NativeTlsChannel> {
    pub(crate) fn ready_for_cycle(&self) -> bool {
        const CYCLE_WIRE_BYTES: usize = 488 * 1024 * 1024;
        const CYCLE_RECORDS: usize = 65536;
        const CYCLE_LIFETIME: Duration = Duration::from_secs(380);
        let channel = &self.channel;
        if channel.check().is_err()
            || MAX_CONNECTION_AGE.saturating_sub(channel.started.elapsed()) < CYCLE_LIFETIME
        {
            return false;
        }
        let io = channel.stream.get_ref().0;
        [&io.incoming, &io.outgoing].into_iter().all(|direction| {
            super::CONNECTION_WIRE_BYTES.saturating_sub(direction.bytes) >= CYCLE_WIRE_BYTES
                && super::CONNECTION_RECORDS.saturating_sub(direction.records) >= CYCLE_RECORDS
        })
    }
}

async fn slice<F, T>(operation: F) -> io::Result<T>
where
    F: std::future::Future<Output = io::Result<T>>,
{
    match futures::future::select(Box::pin(operation), futures_timer::Delay::new(IO_SLICE)).await {
        Either::Left((result, _)) => result,
        Either::Right(((), pending)) => {
            drop(pending);
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "native socket polling slice",
            ))
        }
    }
}
impl Read for NativeTlsChannel {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.check()?;
        let maximum = if self.hello_read < HELLO_BYTES {
            bytes.len().min(HELLO_BYTES - self.hello_read)
        } else {
            bytes.len()
        };
        let n = futures::executor::block_on(slice(self.stream.read(&mut bytes[..maximum])))?;
        self.hello_read = self.hello_read.saturating_add(n).min(HELLO_BYTES);
        self.complete_hello();
        self.check()?;
        Ok(n)
    }
}
impl Write for NativeTlsChannel {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.check()?;
        let maximum = if self.hello_written < HELLO_BYTES {
            bytes.len().min(HELLO_BYTES - self.hello_written)
        } else {
            bytes.len()
        };
        let n = futures::executor::block_on(slice(self.stream.write(&bytes[..maximum])))?;
        self.hello_written = self.hello_written.saturating_add(n).min(HELLO_BYTES);
        self.complete_hello();
        self.check()?;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        futures::executor::block_on(slice(self.stream.flush()))?;
        self.check()
    }
}

/// TCP never blocks an executor poll. Timers independently wake pending socket
/// operations, so cancellation does not depend on a peer sending another byte.
struct SocketIo {
    socket: TcpStream,
    cancellation: Cancellation,
    read_retry: Option<futures_timer::Delay>,
    write_retry: Option<futures_timer::Delay>,
}
impl SocketIo {
    fn new(socket: TcpStream, cancellation: Cancellation) -> Self {
        Self {
            socket,
            cancellation,
            read_retry: None,
            write_retry: None,
        }
    }
    fn check(&self) -> io::Result<()> {
        if self.cancellation.is_cancelled() {
            let _ = self.socket.shutdown(std::net::Shutdown::Both);
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "native connection cancelled",
            ))
        } else {
            Ok(())
        }
    }
    fn retry(
        timer: &mut Option<futures_timer::Delay>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<usize>> {
        let delay = timer.get_or_insert_with(|| futures_timer::Delay::new(IO_POLL));
        if delay.poll_unpin(cx).is_ready() {
            *timer = None;
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}
impl AsyncRead for SocketIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.check()?;
        match self.socket.read(bytes) {
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Self::retry(&mut self.read_retry, cx)
            }
            result => {
                self.read_retry = None;
                Poll::Ready(result)
            }
        }
    }
}
impl AsyncWrite for SocketIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check()?;
        match self.socket.write(bytes) {
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Self::retry(&mut self.write_retry, cx)
            }
            result => {
                self.write_retry = None;
                Poll::Ready(result)
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.check())
    }
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.socket.shutdown(std::net::Shutdown::Both))
    }
}
