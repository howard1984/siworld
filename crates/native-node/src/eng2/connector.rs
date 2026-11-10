//! Existing native routing with eng-2 bindings and open miner ingress.
//!
//! Bootstrap destinations remain independently pinned. An inbound miner presents
//! a signed descriptor and completes the same encrypted hybrid authentication.

use super::{body::Policy, genesis::Genesis, transport::Peer};
use crate::{
    identity::{Descriptor, NativeIdentity},
    p2p::{self, AdmissionContext, Budget, Cancellation, ConnectionRole, ExpectedPeer, Role},
    wire::Hash,
};
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};
const PINNED_ROUTE: &[u8; 4] = b"SWP2";
const MINER_ROUTE: &[u8; 4] = b"SWP3";
const ADMISSION: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(20);

pub struct Connector {
    genesis: Arc<Genesis>,
    identity: Arc<NativeIdentity>,
    peers: BTreeMap<Hash, ExpectedPeer>,
    local: Hash,
    budget: Budget,
    policy: Policy,
}
impl Connector {
    pub fn new(
        genesis: Arc<Genesis>,
        identity: Arc<NativeIdentity>,
        peers: Vec<ExpectedPeer>,
        budget: Budget,
        policy: Policy,
    ) -> Result<Self, p2p::Error> {
        let descriptor = identity
            .descriptor()
            .map_err(|_| p2p::Error::InvalidProtocol)?;
        if descriptor.binding() != genesis.peer_binding()
            || peers.len() > 16
            || policy.profile != crate::proofs::protocol_profile_fingerprint()
            || policy.max_body_bytes == 0
            || policy.max_settlement_proof_bytes == 0
        {
            return Err(p2p::Error::InvalidProtocol);
        }
        let local = descriptor.fingerprint();
        let mut known = BTreeMap::new();
        for peer in peers {
            if !peer.independently_pinned()
                || peer.descriptor().binding() != genesis.peer_binding()
                || peer.fingerprint() == local
                || known.insert(peer.fingerprint(), peer).is_some()
            {
                return Err(p2p::Error::InvalidProtocol);
            }
        }
        Ok(Self {
            genesis,
            identity,
            peers: known,
            local,
            budget,
            policy,
        })
    }
    /// One dial, with no credential retry or unpinned bootstrap discovery.
    pub fn connect(
        &self,
        endpoint: SocketAddr,
        peer: Hash,
        role: Role,
        cancel: Cancellation,
    ) -> Result<Peer<p2p::NativeTlsChannel>, p2p::Error> {
        let expected = self.peers.get(&peer).ok_or(p2p::Error::Unconfigured)?;
        if cancel.is_cancelled() {
            return Err(p2p::Error::Unavailable);
        }
        let started = Instant::now();
        let mut socket = TcpStream::connect_timeout(&endpoint, ADMISSION)
            .map_err(|_| p2p::Error::Unavailable)?;
        configure(&socket)?;
        let _route_charge = self
            .budget
            .reserve(crate::identity::DESCRIPTOR_BYTES + 4096)?;
        let mut route = [0; 36];
        route[..4].copy_from_slice(if role == Role::Miner {
            MINER_ROUTE
        } else {
            PINNED_ROUTE
        });
        route[4..].copy_from_slice(&self.local);
        route_io(&mut socket, &mut route, true, started, &cancel)?;
        if role == Role::Miner {
            let mut descriptor = self
                .identity
                .descriptor()
                .map_err(|_| p2p::Error::InvalidProtocol)?
                .encode();
            route_io(&mut socket, &mut descriptor, true, started, &cancel)?;
        }
        let admission = AdmissionContext::new_started(
            expected.clone(),
            ConnectionRole::Initiator,
            cancel,
            started,
        );
        Peer::establish(
            socket,
            self.identity.clone(),
            &admission,
            role,
            self.budget.clone(),
            &self.genesis,
            self.policy,
        )
    }
    /// The listener owner must bound workers before calling this method. The
    /// acceptance instant is captured before routing and never refreshed.
    pub fn accept(
        &self,
        mut socket: TcpStream,
        started: Instant,
        role: Role,
        cancel: Cancellation,
    ) -> Result<Peer<p2p::NativeTlsChannel>, p2p::Error> {
        configure(&socket)?;
        let _route_charge = self
            .budget
            .reserve(crate::identity::DESCRIPTOR_BYTES + 4096)?;
        let mut route = [0; 36];
        route_io(&mut socket, &mut route, false, started, &cancel)?;
        let hint: Hash = route[4..].try_into().expect("fixed routing fingerprint");
        if hint == self.local {
            return Err(p2p::Error::InvalidProtocol);
        }
        let presented = if &route[..4] == MINER_ROUTE {
            let mut bytes = [0; crate::identity::DESCRIPTOR_BYTES];
            route_io(&mut socket, &mut bytes, false, started, &cancel)?;
            let descriptor = Descriptor::decode(&bytes, &self.genesis.peer_binding())
                .map_err(|_| p2p::Error::InvalidProtocol)?;
            if descriptor.fingerprint() != hint {
                return Err(p2p::Error::InvalidProtocol);
            }
            Some(descriptor)
        } else if &route[..4] == PINNED_ROUTE {
            None
        } else {
            return Err(p2p::Error::InvalidProtocol);
        };
        let expected = match self.peers.get(&hint) {
            Some(expected) => expected.clone(),
            None => p2p::ExpectedPeer::from_presented_descriptor(
                self.genesis.peer_binding(),
                presented.ok_or(p2p::Error::InvalidProtocol)?,
            )?,
        };
        let public_miner = !expected.independently_pinned();
        let admission =
            AdmissionContext::new_started(expected, ConnectionRole::Responder, cancel, started);
        let peer = Peer::establish(
            socket,
            self.identity.clone(),
            &admission,
            role,
            self.budget.clone(),
            &self.genesis,
            self.policy,
        )?;
        if public_miner && peer.role() != Role::Miner {
            return Err(p2p::Error::InvalidProtocol);
        }
        Ok(peer)
    }
}
fn configure(socket: &TcpStream) -> Result<(), p2p::Error> {
    socket
        .set_read_timeout(Some(POLL))
        .and_then(|_| socket.set_write_timeout(Some(POLL)))
        .map_err(|_| p2p::Error::Unavailable)
}
fn route_io(
    socket: &mut TcpStream,
    bytes: &mut [u8],
    write: bool,
    started: Instant,
    cancel: &Cancellation,
) -> Result<(), p2p::Error> {
    let mut offset = 0;
    while offset < bytes.len() {
        if cancel.is_cancelled() || started.elapsed() >= ADMISSION {
            return Err(p2p::Error::Unavailable);
        }
        let result = if write {
            socket.write(&bytes[offset..])
        } else {
            socket.read(&mut bytes[offset..])
        };
        match result {
            Ok(0) => return Err(p2p::Error::Unavailable),
            Ok(count) => offset += count,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(_) => return Err(p2p::Error::Unavailable),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{eng2::genesis::FeeMode, identity::PeerPin};
    use std::{
        net::{Ipv4Addr, TcpListener},
        sync::atomic::{AtomicU64, Ordering},
    };
    fn genesis() -> Arc<Genesis> {
        let state = crate::eng2::snapshot::tests::bootstrap();
        Arc::new(
            Genesis::seal(
                state.chain.config.clone(),
                state.governance.clone(),
                FeeMode::LegacyMiner,
            )
            .unwrap(),
        )
    }
    fn identity(g: &Genesis) -> Arc<NativeIdentity> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "eng2-connector-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let result =
            NativeIdentity::initialize(&path.canonicalize().unwrap(), g.peer_binding()).unwrap();
        std::fs::remove_dir_all(path).unwrap();
        Arc::new(result)
    }
    fn expected(identity: &NativeIdentity, g: &Genesis) -> ExpectedPeer {
        let descriptor = identity.descriptor().unwrap();
        let pin = PeerPin::from_trusted_descriptor(&descriptor, &g.peer_binding()).unwrap();
        ExpectedPeer::from_pinned_descriptor(g.peer_binding(), descriptor, pin).unwrap()
    }
    fn policy() -> Policy {
        Policy {
            profile: crate::proofs::protocol_profile_fingerprint(),
            max_body_bytes: 4 * 1024 * 1024,
            max_settlement_proof_bytes: 4096,
        }
    }
    fn exchange(role: Role, registered: bool) -> (Result<(), p2p::Error>, Result<(), p2p::Error>) {
        let g = genesis();
        let a = identity(&g);
        let b = identity(&g);
        let target = expected(&b, &g);
        let fingerprint = target.fingerprint();
        let server_peers = if registered {
            vec![expected(&a, &g)]
        } else {
            vec![]
        };
        let client =
            Connector::new(g.clone(), a, vec![target], Budget::default(), policy()).unwrap();
        let server =
            Connector::new(g.clone(), b, server_peers, Budget::default(), policy()).unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let endpoint = listener.local_addr().unwrap();
        let thread = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut peer = server.accept(
                socket,
                Instant::now(),
                Role::Validator,
                Cancellation::default(),
            )?;
            let (request, message) = peer.receive_request()?;
            if request != 1
                || message
                    != (super::super::transport::Request::Tip {
                        height: 0,
                        id: g.id(),
                    })
            {
                return Err(p2p::Error::InvalidProtocol);
            }
            Ok(())
        });
        let result = client
            .connect(endpoint, fingerprint, role, Cancellation::default())
            .and_then(|mut peer| peer.advertise_tip(1, 0, client.genesis.id()));
        (result, thread.join().unwrap())
    }
    #[test]
    fn ordinary_miner_joins_without_a_manual_peer_pin_and_completes_hybrid_auth() {
        let (a, b) = exchange(Role::Miner, false);
        a.unwrap();
        b.unwrap();
    }
    #[test]
    fn independently_pinned_service_uses_the_existing_pinned_route() {
        let (a, b) = exchange(Role::Validator, true);
        a.unwrap();
        b.unwrap();
    }
    #[test]
    fn unknown_validator_cannot_use_open_miner_ingress() {
        let (a, b) = exchange(Role::Validator, false);
        assert!(a.is_err());
        assert!(matches!(b, Err(p2p::Error::InvalidProtocol)));
    }
    #[test]
    fn cancelled_dial_and_unknown_target_do_not_create_a_socket() {
        let g = genesis();
        let a = identity(&g);
        let b = identity(&g);
        let target = expected(&b, &g);
        let fingerprint = target.fingerprint();
        let connector = Connector::new(g, a, vec![target], Budget::default(), policy()).unwrap();
        let endpoint = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let cancel = Cancellation::default();
        cancel.cancel();
        assert!(matches!(
            connector.connect(endpoint, fingerprint, Role::Miner, cancel),
            Err(p2p::Error::Unavailable)
        ));
        assert!(matches!(
            connector.connect(endpoint, [0; 32], Role::Miner, Cancellation::default()),
            Err(p2p::Error::Unconfigured)
        ));
    }
}
