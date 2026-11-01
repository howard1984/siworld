//! Ordered dual authentication inside an already completed hybrid TLS stream.

use super::Error;
use crate::identity::tls_auth::{TLS_SIGNATURE_BYTES, TlsAuthentication, TlsSignatures};
use crate::identity::{DESCRIPTOR_BYTES, Descriptor, NativeIdentity};
use crate::p2p::{Binding, ConnectionRole, ExpectedPeer};
use crate::wire::Hash;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use sha2::{Digest, Sha256};

const HEADER_BYTES: usize = 11;
const HELLO_BYTES: usize = 73 + DESCRIPTOR_BYTES;
const HELLO_TUPLE: [u8; 8] = [1, 0, 4, 3, 0xec, 0x11, 3, 0x13];
const TRANSCRIPT_DOMAIN: &[u8] = b"siworld native hybrid transcript v1\0";

/// The provider supplies a local, post-handshake exporter and enforces the
/// original absolute admission deadline, cancellation and aggregate wire cap.
pub(super) async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    identity: &NativeIdentity,
    expected: &ExpectedPeer,
    role: ConnectionRole,
    exporter: &[u8; 32],
) -> Result<(), Error> {
    let descriptor = identity.descriptor().map_err(|_| Error::Authentication)?;
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(|_| Error::Authentication)?;
    authenticate_prepared(
        stream,
        expected,
        role,
        exporter,
        &descriptor,
        nonce,
        |message| identity.sign_tls_authentication(message),
    )
    .await
}

fn role_byte(role: ConnectionRole) -> u8 {
    match role {
        ConnectionRole::Initiator => 1,
        ConnectionRole::Responder => 2,
    }
}

fn header(kind: u8, length: usize) -> [u8; HEADER_BYTES] {
    let mut bytes = [0; HEADER_BYTES];
    bytes[..4].copy_from_slice(b"SWHH");
    bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
    bytes[6] = kind;
    bytes[7..].copy_from_slice(&(length as u32).to_le_bytes());
    bytes
}

struct Transcript(Sha256);
impl Transcript {
    fn new(binding: Binding, endpoints: [Hash; 2], exporter: &Hash) -> Self {
        let mut hash = Sha256::new();
        hash.update(TRANSCRIPT_DOMAIN);
        hash.update(binding.network);
        hash.update(binding.genesis);
        hash.update(binding.verifier);
        hash.update(endpoints[0]);
        hash.update(endpoints[1]);
        hash.update(exporter);
        Self(hash)
    }

    fn append(&mut self, kind: u8, body: &[u8]) {
        self.0.update(header(kind, body.len()));
        self.0.update(body);
    }

    fn digest(&self) -> Hash {
        self.0.clone().finalize().into()
    }
}

fn encode_hello(
    descriptor: &Descriptor,
    role: ConnectionRole,
    nonce: Hash,
    expected: Hash,
) -> [u8; HELLO_BYTES] {
    let mut bytes = [0; HELLO_BYTES];
    bytes[..8].copy_from_slice(&HELLO_TUPLE);
    bytes[8] = role_byte(role);
    bytes[9..41].copy_from_slice(&nonce);
    bytes[41..73].copy_from_slice(&expected);
    bytes[73..].copy_from_slice(&descriptor.encode());
    bytes
}

fn verify_hello(
    bytes: &[u8; HELLO_BYTES],
    expected: &ExpectedPeer,
    local: &Descriptor,
    remote_role: ConnectionRole,
    local_nonce: Hash,
) -> Result<(), Error> {
    if bytes[..8] != HELLO_TUPLE || bytes[8] != role_byte(remote_role) {
        return Err(Error::InvalidProfile);
    }
    let nonce: Hash = bytes[9..41].try_into().map_err(|_| Error::Authentication)?;
    if nonce == [0; 32] || nonce == local_nonce || bytes[41..73] != local.fingerprint() {
        return Err(Error::Authentication);
    }
    let remote =
        Descriptor::decode(&bytes[73..], &local.binding()).map_err(|_| Error::Authentication)?;
    if remote.fingerprint() != expected.fingerprint()
        || remote.ed25519_public() != expected.descriptor().ed25519_public()
        || remote.ml_dsa_public() != expected.descriptor().ml_dsa_public()
    {
        return Err(Error::Authentication);
    }
    Ok(())
}

async fn send<S: AsyncWrite + Unpin>(
    stream: &mut S,
    transcript: &mut Transcript,
    kind: u8,
    body: &[u8],
) -> Result<(), Error> {
    stream
        .write_all(&header(kind, body.len()))
        .await
        .map_err(|_| Error::Io)?;
    stream.write_all(body).await.map_err(|_| Error::Io)?;
    stream.flush().await.map_err(|_| Error::Io)?;
    transcript.append(kind, body);
    Ok(())
}

async fn receive<S: AsyncRead + Unpin, const LENGTH: usize>(
    stream: &mut S,
    kind: u8,
) -> Result<[u8; LENGTH], Error> {
    let mut received = [0; HEADER_BYTES];
    stream
        .read_exact(&mut received)
        .await
        .map_err(|_| Error::Io)?;
    // Reject the declared length and kind before allocating or reading a body.
    if received != header(kind, LENGTH) {
        return Err(Error::InvalidProfile);
    }
    let mut body = [0; LENGTH];
    stream.read_exact(&mut body).await.map_err(|_| Error::Io)?;
    Ok(body)
}

async fn authenticate_prepared<S, F>(
    stream: &mut S,
    expected: &ExpectedPeer,
    role: ConnectionRole,
    exporter: &Hash,
    local: &Descriptor,
    nonce: Hash,
    sign: F,
) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(&TlsAuthentication) -> Result<TlsSignatures, crate::identity::Error>,
{
    let binding = local.binding();
    let local = Descriptor::decode(&local.encode(), &binding).map_err(|_| Error::Authentication)?;
    let remote = expected.descriptor();
    let remote =
        Descriptor::decode(&remote.encode(), &binding).map_err(|_| Error::Authentication)?;
    let local_fingerprint = local.fingerprint();
    let remote_fingerprint = remote.fingerprint();
    if nonce == [0; 32]
        || local_fingerprint == [0; 32]
        || remote_fingerprint == [0; 32]
        || local_fingerprint == remote_fingerprint
        || remote_fingerprint != expected.fingerprint()
    {
        return Err(Error::Authentication);
    }
    let (endpoints, remote_role, first, signature_kind, ready_kind) = match role {
        ConnectionRole::Initiator => (
            [local_fingerprint, remote_fingerprint],
            ConnectionRole::Responder,
            true,
            3,
            5,
        ),
        ConnectionRole::Responder => (
            [remote_fingerprint, local_fingerprint],
            ConnectionRole::Initiator,
            false,
            4,
            6,
        ),
    };
    let mut transcript = Transcript::new(binding, endpoints, exporter);
    let hello = encode_hello(&local, role, nonce, remote_fingerprint);
    if first {
        send(stream, &mut transcript, 1, &hello).await?;
    }
    let received = receive::<S, HELLO_BYTES>(stream, role_byte(remote_role)).await?;
    verify_hello(&received, expected, &local, remote_role, nonce)?;
    transcript.append(role_byte(remote_role), &received);
    if !first {
        send(stream, &mut transcript, 2, &hello).await?;
    }

    let mut signer = Some(sign);
    for kind in 3..=4 {
        let sender = if kind == 3 {
            ConnectionRole::Initiator
        } else {
            ConnectionRole::Responder
        };
        let message = TlsAuthentication::new(binding, sender, endpoints, transcript.digest())
            .map_err(|_| Error::Authentication)?;
        if kind == signature_kind {
            let signatures = signer.take().ok_or(Error::Authentication)?(&message)
                .map_err(|_| Error::Authentication)?;
            send(stream, &mut transcript, kind, &signatures.encode()).await?;
        } else {
            let body = receive::<S, TLS_SIGNATURE_BYTES>(stream, kind).await?;
            let signatures = TlsSignatures::decode(&body).map_err(|_| Error::Authentication)?;
            remote
                .verify_tls_authentication(&message, &signatures)
                .map_err(|_| Error::Authentication)?;
            transcript.append(kind, &body);
        }
    }
    for kind in 5..=6 {
        let digest = transcript.digest();
        if kind == ready_kind {
            send(stream, &mut transcript, kind, &digest).await?;
        } else {
            let body = receive::<S, 32>(stream, kind).await?;
            if body != digest {
                return Err(Error::Authentication);
            }
            transcript.append(kind, &body);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{
        PeerPin,
        tls_auth::{fixture_identity, fixture_sign},
    };
    use futures::executor::block_on;
    use futures::{StreamExt, channel::mpsc};
    use std::{
        collections::VecDeque,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
    };

    struct Duplex {
        receive: mpsc::UnboundedReceiver<Vec<u8>>,
        send: mpsc::UnboundedSender<Vec<u8>>,
        pending: VecDeque<u8>,
        written: Arc<Mutex<Vec<u8>>>,
    }
    impl AsyncRead for Duplex {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            if bytes.is_empty() {
                return Poll::Ready(Ok(0));
            }
            while self.pending.is_empty() {
                match self.receive.poll_next_unpin(cx) {
                    Poll::Ready(Some(bytes)) => self.pending.extend(bytes),
                    Poll::Ready(None) => return Poll::Ready(Ok(0)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            let length = bytes.len().min(self.pending.len()).min(7);
            for byte in &mut bytes[..length] {
                *byte = self.pending.pop_front().unwrap();
            }
            Poll::Ready(Ok(length))
        }
    }
    impl AsyncWrite for Duplex {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let length = bytes.len().min(7);
            self.send
                .unbounded_send(bytes[..length].to_vec())
                .map_err(|_| std::io::ErrorKind::BrokenPipe)?;
            self.written
                .lock()
                .unwrap()
                .extend_from_slice(&bytes[..length]);
            Poll::Ready(Ok(length))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn duplex() -> (Duplex, Duplex) {
        let (first_send, second_receive) = mpsc::unbounded();
        let (second_send, first_receive) = mpsc::unbounded();
        (
            Duplex {
                receive: first_receive,
                send: first_send,
                pending: VecDeque::new(),
                written: Arc::default(),
            },
            Duplex {
                receive: second_receive,
                send: second_send,
                pending: VecDeque::new(),
                written: Arc::default(),
            },
        )
    }

    struct Stream {
        input: Vec<u8>,
        position: usize,
        output: Vec<u8>,
        fragment: usize,
    }
    impl Stream {
        fn new(input: Vec<u8>) -> Self {
            Self {
                input,
                position: 0,
                output: Vec::new(),
                fragment: 7,
            }
        }
    }
    impl AsyncRead for Stream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            let length = bytes
                .len()
                .min(self.fragment)
                .min(self.input.len() - self.position);
            bytes[..length].copy_from_slice(&self.input[self.position..self.position + length]);
            self.position += length;
            Poll::Ready(Ok(length))
        }
    }
    impl AsyncWrite for Stream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let length = bytes.len().min(self.fragment);
            self.output.extend_from_slice(&bytes[..length]);
            Poll::Ready(Ok(length))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct Fixture {
        identities: [NativeIdentity; 2],
        descriptors: [Descriptor; 2],
        expected: [ExpectedPeer; 2],
        nonces: [Hash; 2],
        exporter: Hash,
    }
    impl Fixture {
        fn new() -> Self {
            let binding = Binding {
                network: [1; 32],
                genesis: [2; 32],
                verifier: [3; 32],
            };
            let identities = [fixture_identity(binding, 4), fixture_identity(binding, 6)];
            let descriptors = [
                identities[0].descriptor().unwrap(),
                identities[1].descriptor().unwrap(),
            ];
            let pin0 = PeerPin::from_trusted_descriptor(&descriptors[0], &binding).unwrap();
            let pin1 = PeerPin::from_trusted_descriptor(&descriptors[1], &binding).unwrap();
            let expected = [
                ExpectedPeer::from_pinned_descriptor(binding, descriptors[1].clone(), pin1)
                    .unwrap(),
                ExpectedPeer::from_pinned_descriptor(binding, descriptors[0].clone(), pin0)
                    .unwrap(),
            ];
            Self {
                identities,
                descriptors,
                expected,
                nonces: [[8; 32], [9; 32]],
                exporter: [10; 32],
            }
        }
        fn frames(&self) -> Vec<Vec<u8>> {
            let endpoints = [
                self.descriptors[0].fingerprint(),
                self.descriptors[1].fingerprint(),
            ];
            let binding = self.descriptors[0].binding();
            let mut transcript = Transcript::new(binding, endpoints, &self.exporter);
            let mut frames = Vec::new();
            for (index, role) in [ConnectionRole::Initiator, ConnectionRole::Responder]
                .into_iter()
                .enumerate()
            {
                let body = encode_hello(
                    &self.descriptors[index],
                    role,
                    self.nonces[index],
                    endpoints[1 - index],
                );
                frames.push(frame(index as u8 + 1, &body));
                transcript.append(index as u8 + 1, &body);
            }
            for (index, role) in [ConnectionRole::Initiator, ConnectionRole::Responder]
                .into_iter()
                .enumerate()
            {
                let message =
                    TlsAuthentication::new(binding, role, endpoints, transcript.digest()).unwrap();
                let body = fixture_sign(&self.identities[index], &message)
                    .unwrap()
                    .encode();
                frames.push(frame(index as u8 + 3, &body));
                transcript.append(index as u8 + 3, &body);
            }
            for kind in 5..=6 {
                let body = transcript.digest();
                frames.push(frame(kind, &body));
                transcript.append(kind, &body);
            }
            frames
        }
        fn run(
            &self,
            role: ConnectionRole,
            frames: &[Vec<u8>],
            exporter: Hash,
        ) -> (Result<(), Error>, Stream) {
            let index = usize::from(role == ConnectionRole::Responder);
            let mut input = Vec::new();
            for frame in frames.iter().skip(1 - index).step_by(2) {
                input.extend_from_slice(frame);
            }
            let mut stream = Stream::new(input);
            let result = block_on(authenticate_prepared(
                &mut stream,
                &self.expected[index],
                role,
                &exporter,
                &self.descriptors[index],
                self.nonces[index],
                |message| fixture_sign(&self.identities[index], message),
            ));
            (result, stream)
        }
    }
    fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut result = header(kind, body.len()).to_vec();
        result.extend_from_slice(body);
        result
    }

    #[test]
    fn transcript_prefix_and_exact_frame_bytes_match_sha256_vectors() {
        let binding = Binding {
            network: [1; 32],
            genesis: [2; 32],
            verifier: [3; 32],
        };
        let mut transcript = Transcript::new(binding, [[4; 32], [5; 32]], &[6; 32]);
        let hexadecimal = |bytes: Hash| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        assert_eq!(
            hexadecimal(transcript.digest()),
            "1bd39a28aa3abb7060ad62be6a9289aee2aff761f655a8171ac00fa194958494"
        );
        transcript.append(5, &[7; 32]);
        assert_eq!(
            hexadecimal(transcript.digest()),
            "58f3a042e198fb45db499c6deca3ca7a956b6a7f2fce6776ea2a9713829af0f3"
        );
    }

    #[test]
    fn production_entry_completes_with_fresh_nonces_and_hedged_signatures() {
        let fixture = Fixture::new();
        let (mut first, mut second) = duplex();
        let (first_result, second_result) = block_on(futures::future::join(
            authenticate(
                &mut first,
                &fixture.identities[0],
                &fixture.expected[0],
                ConnectionRole::Initiator,
                &fixture.exporter,
            ),
            authenticate(
                &mut second,
                &fixture.identities[1],
                &fixture.expected[1],
                ConnectionRole::Responder,
                &fixture.exporter,
            ),
        ));
        first_result.unwrap();
        second_result.unwrap();
        let first = first.written.lock().unwrap();
        let second = second.written.lock().unwrap();
        assert_eq!(first.len() + second.len(), 17940);
        assert_ne!(&first[HEADER_BYTES + 9..HEADER_BYTES + 41], &[0; 32]);
        assert_ne!(
            &first[HEADER_BYTES + 9..HEADER_BYTES + 41],
            &second[HEADER_BYTES + 9..HEADER_BYTES + 41]
        );
    }

    #[test]
    fn six_frames_accept_fragmented_io_with_exact_order_and_lengths() {
        let fixture = Fixture::new();
        let frames = fixture.frames();
        assert_eq!(
            frames.iter().map(Vec::len).collect::<Vec<_>>(),
            [5543, 5543, 3384, 3384, 43, 43]
        );
        assert_eq!(frames.iter().map(Vec::len).sum::<usize>(), 17940);
        for role in [ConnectionRole::Initiator, ConnectionRole::Responder] {
            let (result, stream) = fixture.run(role, &frames, fixture.exporter);
            result.unwrap();
            assert_eq!(stream.position, stream.input.len());
            let index = usize::from(role == ConnectionRole::Responder);
            let kinds: Vec<_> = [
                if index == 0 { 1 } else { 2 },
                if index == 0 { 3 } else { 4 },
                if index == 0 { 5 } else { 6 },
            ]
            .to_vec();
            let mut position = 0;
            for kind in kinds {
                let length = match kind {
                    1 | 2 => HELLO_BYTES,
                    3 | 4 => TLS_SIGNATURE_BYTES,
                    _ => 32,
                };
                assert_eq!(
                    &stream.output[position..position + HEADER_BYTES],
                    &header(kind, length)
                );
                position += HEADER_BYTES + length;
            }
            assert_eq!(position, stream.output.len());
        }
    }

    #[test]
    fn frame_header_rejects_order_length_and_extensions_before_body_read() {
        for change in 0..5 {
            let fixture = Fixture::new();
            let mut frames = fixture.frames();
            match change {
                0 => frames[0][0] ^= 1,
                1 => frames[0][4] = 2,
                2 => frames[0][6] = 2,
                3 => frames[0][7..11].copy_from_slice(&u32::MAX.to_le_bytes()),
                _ => frames[0][7..11].copy_from_slice(&((HELLO_BYTES + 1) as u32).to_le_bytes()),
            }
            let (result, stream) =
                fixture.run(ConnectionRole::Responder, &frames, fixture.exporter);
            assert!(matches!(result, Err(Error::InvalidProfile)));
            assert_eq!(stream.position, HEADER_BYTES);
            assert!(stream.output.is_empty());
        }
    }

    #[test]
    fn hello_rejects_zero_reflected_nonces_roles_algorithms_context_and_pins() {
        let fixture = Fixture::new();
        for field in 0..10 {
            let mut frames = fixture.frames();
            let body = &mut frames[0][HEADER_BYTES..];
            match field {
                0 => body[9..41].fill(0),
                1 => body[9..41].copy_from_slice(&fixture.nonces[1]),
                2 => body[8] = 2,
                3 => body[0] = 2,
                4 => body[2] ^= 1,
                5 => body[4] ^= 1,
                6 => body[6] ^= 1,
                7 => body[41] ^= 1,
                8 => body[73 + 6] ^= 1,
                _ => body[73..].copy_from_slice(&fixture.descriptors[1].encode()),
            }
            assert!(
                fixture
                    .run(ConnectionRole::Responder, &frames, fixture.exporter)
                    .0
                    .is_err()
            );
        }
    }

    #[test]
    fn auth_rejects_missing_signatures_exporter_replay_and_wrong_ready() {
        let fixture = Fixture::new();
        for role in [ConnectionRole::Initiator, ConnectionRole::Responder] {
            let signature_index = if role == ConnectionRole::Initiator {
                3
            } else {
                2
            };
            for missing in [0..64, 64..TLS_SIGNATURE_BYTES] {
                let mut frames = fixture.frames();
                frames[signature_index][HEADER_BYTES + missing.start..HEADER_BYTES + missing.end]
                    .fill(0);
                assert!(fixture.run(role, &frames, fixture.exporter).0.is_err());
            }
            let frames = fixture.frames();
            assert!(fixture.run(role, &frames, [11; 32]).0.is_err());
            let mut frames = fixture.frames();
            frames[if role == ConnectionRole::Initiator {
                5
            } else {
                4
            }][HEADER_BYTES] ^= 1;
            assert!(fixture.run(role, &frames, fixture.exporter).0.is_err());
        }
    }

    #[test]
    fn missing_reordered_and_truncated_authentication_frames_fail() {
        let fixture = Fixture::new();
        for kind in [2usize, 4] {
            let mut frames = fixture.frames();
            frames[kind][6] += 1;
            assert!(
                fixture
                    .run(ConnectionRole::Responder, &frames, fixture.exporter)
                    .0
                    .is_err()
            );
        }
        for retained in [
            0,
            HEADER_BYTES - 1,
            HEADER_BYTES,
            HEADER_BYTES + HELLO_BYTES - 1,
        ] {
            let mut stream = Stream::new(fixture.frames()[0][..retained].to_vec());
            assert!(
                block_on(authenticate_prepared(
                    &mut stream,
                    &fixture.expected[1],
                    ConnectionRole::Responder,
                    &fixture.exporter,
                    &fixture.descriptors[1],
                    fixture.nonces[1],
                    |message| fixture_sign(&fixture.identities[1], message)
                ))
                .is_err()
            );
        }
    }
}
