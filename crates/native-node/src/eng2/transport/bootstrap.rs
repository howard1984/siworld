//! One bounded bootstrap slice per ordinary request; no additional round phase.
use super::*;
use crate::eng2::bootstrap::{Chunk, Descriptor, MAX_CHUNK_BYTES, MAX_MANIFEST_BYTES, Object};

const GET_MANIFEST: u8 = 10;
const MANIFEST: u8 = 11;
const GET_CHUNK: u8 = 12;
const CHUNK: u8 = 13;
const MISSING: u8 = 14;
const QUERY_BYTES: usize = 2 + 32 + 1 + 8 + 32 + 8 + 4;
const RESPONSE_BYTES: usize = QUERY_BYTES + 8 + 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkRequest {
    pub bundle: Hash,
    pub object: Object,
    pub offset: u64,
    pub maximum: u32,
}
impl ChunkRequest {
    fn encode(self, opcode: u8) -> Result<[u8; QUERY_BYTES], p2p::Error> {
        if self.maximum == 0 || self.maximum as usize > MAX_CHUNK_BYTES {
            return Err(p2p::Error::ResourceExhausted);
        }
        let mut bytes = [0; QUERY_BYTES];
        bytes[0] = opcode;
        bytes[1] = 1;
        bytes[2..34].copy_from_slice(&self.bundle);
        match self.object {
            Object::Snapshot => bytes[34] = 1,
            Object::Receipt { height, id } => {
                if height == 0 {
                    return Err(p2p::Error::InvalidProtocol);
                }
                bytes[34] = 2;
                bytes[35..43].copy_from_slice(&height.to_le_bytes());
                bytes[43..75].copy_from_slice(&id);
            }
        }
        bytes[75..83].copy_from_slice(&self.offset.to_le_bytes());
        bytes[83..87].copy_from_slice(&self.maximum.to_le_bytes());
        Ok(bytes)
    }
}
pub(super) fn request(bytes: &[u8]) -> Option<Request> {
    if bytes == [GET_MANIFEST, 1] {
        return Some(Request::BootstrapManifest);
    }
    if bytes.len() != QUERY_BYTES || bytes[0] != GET_CHUNK || bytes[1] != 1 {
        return None;
    }
    let object = match bytes[34] {
        1 if bytes[35..75] == [0; 40] => Object::Snapshot,
        2 if number(&bytes[35..43]) != 0 => Object::Receipt {
            height: number(&bytes[35..43]),
            id: digest(&bytes[43..75]),
        },
        _ => return None,
    };
    let query = ChunkRequest {
        bundle: digest(&bytes[2..34]),
        object,
        offset: number(&bytes[75..83]),
        maximum: u32::from_le_bytes(bytes[83..87].try_into().ok()?),
    };
    query.encode(GET_CHUNK).ok()?;
    Some(Request::BootstrapChunk(query))
}
pub struct ReceivedManifest {
    pub bytes: Vec<u8>,
    pub reservation: p2p::Reservation,
}
pub struct ReceivedChunk {
    pub chunk: Chunk,
    pub reservation: p2p::Reservation,
}
impl<S: Read + Write> Peer<S> {
    pub(crate) fn reserve_bootstrap(&self, bytes: usize) -> Result<p2p::Reservation, p2p::Error> {
        let charge = bytes
            .checked_mul(3)
            .and_then(|n| n.checked_add(65536))
            .ok_or(p2p::Error::ResourceExhausted)?;
        self.session.shared_budget().reserve(charge)
    }
    pub fn fetch_bootstrap_manifest(
        &mut self,
        request: u64,
    ) -> Result<Option<ReceivedManifest>, p2p::Error> {
        self.fetch_bootstrap_manifest_before(
            request,
            &p2p::Deadline::new(std::time::Duration::from_secs(10)),
        )
    }
    pub(crate) fn fetch_bootstrap_manifest_before(
        &mut self,
        request: u64,
        deadline: &p2p::Deadline,
    ) -> Result<Option<ReceivedManifest>, p2p::Error> {
        let reservation = self.reserve_bootstrap(MAX_MANIFEST_BYTES + 1)?;
        self.session.send_control_before(
            p2p::ENG2_MESSAGE,
            request,
            &[GET_MANIFEST, 1],
            deadline,
        )?;
        let (received, bytes, _frame_charge) = self.receive_before(deadline)?;
        if received != request {
            return Err(p2p::Error::InvalidProtocol);
        }
        if bytes == [MISSING] {
            return Ok(None);
        }
        if bytes.len() <= 1 || bytes.len() > MAX_MANIFEST_BYTES + 1 || bytes[0] != MANIFEST {
            return Err(p2p::Error::InvalidProtocol);
        }
        Ok(Some(ReceivedManifest {
            bytes: bytes[1..].to_vec(),
            reservation,
        }))
    }
    pub(crate) fn send_bootstrap_manifest(
        &mut self,
        request: u64,
        bytes: &[u8],
    ) -> Result<(), p2p::Error> {
        if bytes.is_empty() || bytes.len() > MAX_MANIFEST_BYTES {
            return Err(p2p::Error::ResourceExhausted);
        }
        let mut frame = Vec::with_capacity(bytes.len() + 1);
        frame.push(MANIFEST);
        frame.extend_from_slice(bytes);
        self.send(request, &frame)
    }
    pub(crate) fn send_bootstrap_missing(&mut self, request: u64) -> Result<(), p2p::Error> {
        self.send(request, &[MISSING])
    }
    pub(crate) fn send_bootstrap_chunk(
        &mut self,
        request: u64,
        query: ChunkRequest,
        chunk: &Chunk,
    ) -> Result<(), p2p::Error> {
        check_chunk(query, chunk)?;
        let mut bytes = Vec::with_capacity(RESPONSE_BYTES + chunk.bytes.len());
        bytes.extend_from_slice(&query.encode(CHUNK)?);
        bytes.extend_from_slice(&chunk.descriptor.length.to_le_bytes());
        bytes.extend_from_slice(&chunk.descriptor.digest);
        bytes.extend_from_slice(&chunk.bytes);
        self.send(request, &bytes)
    }
    pub fn fetch_bootstrap_chunk(
        &mut self,
        request: u64,
        query: ChunkRequest,
    ) -> Result<Option<ReceivedChunk>, p2p::Error> {
        self.fetch_bootstrap_chunk_before(
            request,
            query,
            &p2p::Deadline::new(std::time::Duration::from_secs(10)),
        )
    }
    pub(crate) fn fetch_bootstrap_chunk_before(
        &mut self,
        request: u64,
        query: ChunkRequest,
        deadline: &p2p::Deadline,
    ) -> Result<Option<ReceivedChunk>, p2p::Error> {
        let encoded = query.encode(GET_CHUNK)?;
        let reservation = self.reserve_bootstrap(RESPONSE_BYTES + query.maximum as usize)?;
        self.session
            .send_control_before(p2p::ENG2_MESSAGE, request, &encoded, deadline)?;
        let (received, bytes, _frame_charge) = self.receive_before(deadline)?;
        if received != request {
            return Err(p2p::Error::InvalidProtocol);
        }
        if bytes == [MISSING] {
            return Ok(None);
        }
        if bytes.len() <= RESPONSE_BYTES
            || bytes.len() > RESPONSE_BYTES + query.maximum as usize
            || bytes[..QUERY_BYTES] != query.encode(CHUNK)?
        {
            return Err(p2p::Error::InvalidProtocol);
        }
        let chunk = Chunk {
            descriptor: Descriptor {
                length: number(&bytes[QUERY_BYTES..QUERY_BYTES + 8]),
                digest: digest(&bytes[QUERY_BYTES + 8..RESPONSE_BYTES]),
            },
            bytes: bytes[RESPONSE_BYTES..].to_vec(),
        };
        check_chunk(query, &chunk)?;
        Ok(Some(ReceivedChunk { chunk, reservation }))
    }
}
fn check_chunk(query: ChunkRequest, chunk: &Chunk) -> Result<(), p2p::Error> {
    if chunk.bytes.is_empty()
        || chunk.bytes.len() > query.maximum as usize
        || query
            .offset
            .checked_add(chunk.bytes.len() as u64)
            .is_none_or(|end| end > chunk.descriptor.length)
        || chunk.bytes.len() as u64
            != (chunk.descriptor.length - query.offset).min(u64::from(query.maximum))
    {
        return Err(p2p::Error::InvalidProtocol);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    #[derive(Default)]
    struct Script {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl Read for Script {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            self.input.read(b)
        }
    }
    impl Write for Script {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    fn query() -> ChunkRequest {
        ChunkRequest {
            bundle: [1; 32],
            object: Object::Snapshot,
            offset: 0,
            maximum: 4,
        }
    }
    fn response(query: ChunkRequest, data: &[u8]) -> Vec<u8> {
        let mut bytes = query.encode(CHUNK).unwrap().to_vec();
        bytes.extend_from_slice(&7u64.to_le_bytes());
        bytes.extend_from_slice(blake3::hash(b"fixture").as_bytes());
        bytes.extend_from_slice(data);
        bytes
    }
    fn peer(request: u64, bytes: &[u8], maximum: usize) -> Peer<Script> {
        let (genesis, _, _) = crate::eng2::bootstrap::tests::framing_fixture();
        let binding = genesis.peer_binding();
        let mut wire = b"SWPF".to_vec();
        wire.extend_from_slice(&p2p::VERSION.to_le_bytes());
        wire.push(p2p::ENG2_MESSAGE);
        wire.extend_from_slice(&request.to_le_bytes());
        wire.extend_from_slice(&binding.network);
        wire.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        wire.extend_from_slice(bytes);
        let session = p2p::Session::from_test_channel(
            Script {
                input: Cursor::new(wire),
                output: Vec::new(),
            },
            binding,
            p2p::Budget::new(maximum),
        );
        Peer::new(
            session,
            &genesis,
            Policy {
                profile: crate::proofs::protocol_profile_fingerprint(),
                max_body_bytes: 1024,
                max_settlement_proof_bytes: 1024,
            },
        )
        .unwrap()
    }
    #[test]
    fn chunk_framing_rejects_cross_request_bundle_object_offset_length_and_resource_confusion() {
        let query = query();
        let bytes = response(query, b"fixt");
        assert_eq!(
            peer(7, &bytes, 8 * 1024 * 1024)
                .fetch_bootstrap_chunk(7, query)
                .unwrap()
                .unwrap()
                .chunk
                .bytes,
            b"fixt"
        );
        assert!(
            peer(8, &bytes, 8 * 1024 * 1024)
                .fetch_bootstrap_chunk(7, query)
                .is_err()
        );
        for offset in [0, 1, 2, 34, 35, 43, 75, 83] {
            let mut bad = bytes.clone();
            bad[offset] ^= 1;
            assert!(
                peer(7, &bad, 8 * 1024 * 1024)
                    .fetch_bootstrap_chunk(7, query)
                    .is_err()
            );
        }
        let mut impossible = bytes.clone();
        impossible[QUERY_BYTES..QUERY_BYTES + 8].copy_from_slice(&3u64.to_le_bytes());
        assert!(
            peer(7, &impossible, 8 * 1024 * 1024)
                .fetch_bootstrap_chunk(7, query)
                .is_err()
        );
        for data in [b"".as_slice(), b"fix".as_slice(), b"fixtu".as_slice()] {
            assert!(
                peer(7, &response(query, data), 8 * 1024 * 1024)
                    .fetch_bootstrap_chunk(7, query)
                    .is_err()
            );
        }
        assert!(
            peer(7, &bytes, 1024)
                .fetch_bootstrap_chunk(7, query)
                .is_err()
        );
        let mut bad = query;
        bad.maximum = 0;
        assert!(bad.encode(GET_CHUNK).is_err());
        bad.maximum = MAX_CHUNK_BYTES as u32 + 1;
        assert!(bad.encode(GET_CHUNK).is_err());
        let mut encoded = query.encode(GET_CHUNK).unwrap();
        encoded[1] = 2;
        assert!(request(&encoded).is_none());
        assert!(request(&[GET_MANIFEST, 2]).is_none());
        assert!(
            peer(7, &[MISSING], 8 * 1024 * 1024)
                .fetch_bootstrap_chunk(7, query)
                .unwrap()
                .is_none()
        );
    }
    #[cfg(feature = "eng2-runtime")]
    #[test]
    fn synthetic_bootstrap_crosses_actual_hybrid_session_and_preserves_all_three_phase_boundaries()
    {
        use crate::{
            eng2::{
                bootstrap::{
                    Provider,
                    cache::{Policy as CachePolicy, Quarantine},
                    session::ColdSession,
                },
                checkpoint_exchange,
                network::{self, Limits, Owner, Sequence},
                transaction_exchange,
            },
            identity::{NativeIdentity, PeerPin},
        };
        use std::{
            net::{Ipv4Addr, TcpListener, TcpStream},
            sync::atomic::{AtomicU64, Ordering},
            sync::{Arc, Mutex},
        };
        struct Cold {
            genesis: Hash,
            offer: Option<Arc<Provider>>,
        }
        impl Owner for Cold {
            fn head(&self) -> Result<(u64, Hash), String> {
                Ok(self.offer.as_ref().map_or((0, self.genesis), |p| {
                    (p.manifest().tip_height, p.manifest().tip_id)
                }))
            }
            fn header(&self, _: u64) -> Result<Option<Header>, String> {
                Ok(None)
            }
            fn block_size(&self, _: u64) -> Result<Option<usize>, String> {
                Ok(None)
            }
            fn block(&self, _: u64) -> Result<(Header, super::super::Body), String> {
                Err("synthetic fixture has no native body".into())
            }
            fn accept(&mut self, _: &Header, _: &super::super::Body) -> Result<(), String> {
                Err("cold transfer cannot admit blocks".into())
            }
            fn bootstrap_provider(&self) -> Result<Option<Arc<Provider>>, String> {
                Ok(self.offer.clone())
            }
            fn bootstrap_chunk(&self, q: ChunkRequest) -> Result<Option<Chunk>, String> {
                let Some(p) = &self.offer else {
                    return Ok(None);
                };
                if q.bundle != p.manifest().bundle()
                    || q.object != Object::Snapshot
                    || q.offset >= 7
                {
                    return Ok(None);
                }
                let start = q.offset as usize;
                let end = (start + q.maximum as usize).min(7);
                Ok(Some(Chunk {
                    descriptor: p.manifest().snapshot,
                    bytes: b"fixture"[start..end].to_vec(),
                }))
            }
        }
        impl transaction_exchange::Owner for Cold {
            fn transaction_ids(&self) -> Vec<Hash> {
                vec![]
            }
            fn has_transaction(&self, _: &Hash) -> bool {
                true
            }
            fn transaction_packet(&self, _: &Hash) -> Result<Option<Vec<u8>>, String> {
                Ok(None)
            }
            fn submit_transaction(
                &mut self,
                _: Hash,
                _: Hash,
                _: &[u8],
                _: &p2p::Deadline,
            ) -> Result<Hash, String> {
                Err("cold fixture cannot admit transactions".into())
            }
        }
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "bootstrap-hybrid-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let (genesis, limits, manifest) = crate::eng2::bootstrap::tests::framing_fixture();
        let genesis = Arc::new(genesis);
        let identity = |name| {
            let path = root.join(name);
            std::fs::create_dir(&path).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            Arc::new(
                NativeIdentity::initialize(&path.canonicalize().unwrap(), genesis.peer_binding())
                    .unwrap(),
            )
        };
        let a = identity("a");
        let b = identity("b");
        let expected = |id: &NativeIdentity| {
            let descriptor = id.descriptor().unwrap();
            let pin =
                PeerPin::from_trusted_descriptor(&descriptor, &genesis.peer_binding()).unwrap();
            p2p::ExpectedPeer::from_pinned_descriptor(genesis.peer_binding(), descriptor, pin)
                .unwrap()
        };
        let expected_a = expected(&a);
        let expected_b = expected(&b);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let server_genesis = genesis.clone();
        let budget = p2p::Budget::default();
        let server_budget = budget.clone();
        let body_policy = Policy {
            profile: crate::proofs::protocol_profile_fingerprint(),
            max_body_bytes: 1024,
            max_settlement_proof_bytes: 1024,
        };
        let server_thread = std::thread::spawn(move || {
            let admission = p2p::AdmissionContext::new(
                expected_a,
                p2p::ConnectionRole::Responder,
                p2p::Cancellation::default(),
            );
            let mut peer = Peer::establish(
                server,
                b,
                &admission,
                p2p::Role::Validator,
                server_budget,
                &server_genesis,
                body_policy,
            )
            .unwrap();
            let owner = Arc::new(Mutex::new(Cold {
                genesis: server_genesis.id(),
                offer: Some(Arc::new(crate::eng2::bootstrap::tests::transport_fixture())),
            }));
            let mut sequence = Sequence::default();
            for _ in 0..3 {
                network::respond(&mut peer, &owner, &mut sequence, Limits::default()).unwrap();
                assert!(
                    checkpoint_exchange::respond(&mut peer, &[], server_genesis.config().network)
                        .unwrap()
                        .is_empty()
                );
                transaction_exchange::respond(&mut peer, &owner).unwrap();
            }
            peer.encrypted_stream_bytes()
        });
        let admission = p2p::AdmissionContext::new(
            expected_b,
            p2p::ConnectionRole::Initiator,
            p2p::Cancellation::default(),
        );
        let mut peer = Peer::establish(
            client,
            a,
            &admission,
            p2p::Role::Miner,
            budget.clone(),
            &genesis,
            body_policy,
        )
        .unwrap();
        let before = peer.encrypted_stream_bytes();
        assert!(before.0 > 0 && before.1 > 0);
        let mut cold = ColdSession::new(&genesis).unwrap();
        let completed = cold
            .round(&mut peer, Limits::default(), |pull| pull.manifest())
            .unwrap();
        assert_eq!(completed.round.accepted, 0);
        assert!(completed.checkpoints.is_empty());
        let received = completed.acquired.unwrap();
        let decoded =
            crate::eng2::bootstrap::Manifest::decode(&received.bytes, &genesis, limits).unwrap();
        assert_eq!(decoded.bundle(), manifest.bundle());
        drop(received);
        let cache_path = root.join("quarantine");
        let cp = CachePolicy {
            max_bytes: 1024 * 1024,
            max_chunks_per_object: 8,
            max_body_bytes: 1024,
        };
        let mut cache =
            Quarantine::create(&cache_path, decoded.clone(), cp, budget.clone()).unwrap();
        for offset in [0, 4] {
            let q = ChunkRequest {
                bundle: decoded.bundle(),
                object: Object::Snapshot,
                offset,
                maximum: 4,
            };
            let completed = cold
                .round(&mut peer, Limits::default(), |pull| pull.chunk(q))
                .unwrap();
            assert_eq!(completed.round.accepted, 0);
            assert!(completed.checkpoints.is_empty());
            cache
                .push(Object::Snapshot, offset, &completed.acquired.unwrap().chunk)
                .unwrap();
        }
        assert_eq!(cache.snapshot().unwrap().bytes, b"fixture");
        assert_eq!(cold.admitted_head(), (0, genesis.id()));
        let after = peer.encrypted_stream_bytes();
        assert!(after.0 > before.0 + 7 && after.1 > before.1);
        let server_counts = server_thread.join().unwrap();
        assert!(server_counts.0 > 0 && server_counts.1 > 0);
        assert!(!cache_path.join("chain.redb").exists());
        drop(cache);
        drop(peer);
        std::fs::remove_dir_all(root).unwrap();
    }
}
