use super::*;
use crate::eng2::{
    body::Policy,
    genesis::{FeeMode, Genesis},
};
use std::{collections::BTreeMap, io::Cursor, os::unix::net::UnixStream};
#[derive(Default)]
struct Model {
    packets: BTreeMap<Hash, Vec<u8>>,
    reject: bool,
    unavailable: bool,
    received: usize,
    budget: Option<p2p::Budget>,
    maximum_decoder_charge: usize,
}
impl Owner for Model {
    fn transaction_ids(&self) -> Vec<Hash> {
        self.packets.keys().copied().collect()
    }
    fn has_transaction(&self, id: &Hash) -> bool {
        self.packets.contains_key(id)
    }
    fn transaction_packet(&self, id: &Hash) -> Result<Option<Vec<u8>>, String> {
        Ok(if self.unavailable {
            None
        } else {
            self.packets.get(id).cloned()
        })
    }
    fn submit_transaction(
        &mut self,
        _peer: Hash,
        expected: Hash,
        packet: &[u8],
        deadline: &p2p::Deadline,
    ) -> Result<Hash, String> {
        deadline
            .check()
            .map_err(|_| "synthetic admission deadline elapsed")?;
        if let Some(budget) = &self.budget {
            self.maximum_decoder_charge = self
                .maximum_decoder_charge
                .max(8 * 1024 * 1024 - budget.available().unwrap());
        }
        if self.reject || packet != expected {
            return Err("synthetic admission rejected".into());
        }
        self.packets.insert(expected, packet.to_vec());
        self.received += 1;
        Ok(expected)
    }
}
fn genesis() -> Genesis {
    let state = crate::eng2::snapshot::tests::bootstrap();
    Genesis::seal(
        state.chain.config.clone(),
        state.governance.clone(),
        FeeMode::LegacyMiner,
    )
    .unwrap()
}
fn policy() -> Policy {
    Policy {
        profile: crate::proofs::protocol_profile_fingerprint(),
        max_body_bytes: 4 * 1024 * 1024,
        max_settlement_proof_bytes: 4096,
    }
}
fn model(first: u8, last: u8) -> Arc<Mutex<Model>> {
    Arc::new(Mutex::new(Model {
        packets: (first..=last).map(|i| ([i; 32], vec![i; 32])).collect(),
        ..Default::default()
    }))
}
fn rounds(a: Arc<Mutex<Model>>, b: Arc<Mutex<Model>>, count: usize) {
    // Synthetic payloads test framing/admission ownership only; actual native
    // acceptance is enforced by Driver, not this mock exchange model.
    let genesis = genesis();
    let (a_socket, b_socket) = UnixStream::pair().unwrap();
    for socket in [&a_socket, &b_socket] {
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
    }
    let budget = p2p::Budget::new(8 * 1024 * 1024);
    let remote_budget = p2p::Budget::new(8 * 1024 * 1024);
    let before = budget.available().unwrap();
    a.lock().unwrap().budget = Some(budget.clone());
    b.lock().unwrap().budget = Some(remote_budget.clone());
    let mut client = Peer::new(
        p2p::Session::from_test_channel(a_socket, genesis.peer_binding(), budget.clone()),
        &genesis,
        policy(),
    )
    .unwrap();
    let mut server = Peer::new(
        p2p::Session::from_test_channel(b_socket, genesis.peer_binding(), remote_budget.clone()),
        &genesis,
        policy(),
    )
    .unwrap();
    let worker = std::thread::spawn(move || {
        for _ in 0..count {
            respond(&mut server, &b).unwrap();
        }
    });
    for _ in 0..count {
        initiate(&mut client, &a).unwrap();
    }
    worker.join().unwrap();
    drop(client);
    assert_eq!(budget.available().unwrap(), before);
    assert_eq!(remote_budget.available().unwrap(), before);
}
#[test]
fn bounded_bidirectional_inventory_delivers_each_missing_packet_once() {
    let a = model(1, 7);
    let b = model(8, 8);
    rounds(a.clone(), b.clone(), 3);
    assert_eq!(a.lock().unwrap().packets.len(), 8);
    assert_eq!(b.lock().unwrap().packets.len(), 8);
    assert_eq!(a.lock().unwrap().received, 1);
    assert_eq!(b.lock().unwrap().received, 7);
    assert!(a.lock().unwrap().maximum_decoder_charge >= 65536 + 3 * 32);
    assert!(b.lock().unwrap().maximum_decoder_charge >= 65536 + 3 * 32);
    rounds(a.clone(), b.clone(), 1);
    assert_eq!(a.lock().unwrap().received, 1);
    assert_eq!(b.lock().unwrap().received, 7);
}
#[test]
fn stale_admission_and_concurrently_unavailable_packets_do_not_stop_rounds() {
    let a = model(1, 1);
    let b = model(2, 2);
    b.lock().unwrap().reject = true;
    rounds(a.clone(), b.clone(), 1);
    assert_eq!(b.lock().unwrap().received, 0);
    a.lock().unwrap().unavailable = true;
    rounds(a, b, 1);
}
fn frame(network: Hash, body: &[u8]) -> Vec<u8> {
    let mut bytes = b"SWPF".to_vec();
    bytes.extend_from_slice(&p2p::VERSION.to_le_bytes());
    bytes.push(p2p::ENG2_MESSAGE);
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&network);
    bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(body);
    bytes
}
#[test]
fn duplicate_oversized_and_wrong_phase_inventories_reject_before_admission_and_release_budget() {
    let genesis = genesis();
    let owner = model(1, 1);
    let mut duplicate = vec![INVENTORY, VERSION, 2, 0];
    duplicate.extend_from_slice(&[3; 64]);
    for body in [
        duplicate,
        vec![REQUEST, VERSION, 0, 0],
        vec![INVENTORY, VERSION, 129, 0],
    ] {
        let budget = p2p::Budget::new(8 * 1024 * 1024);
        let before = budget.available().unwrap();
        let channel = Cursor::new(frame(genesis.config().network, &body));
        let mut peer = Peer::new(
            p2p::Session::from_test_channel(channel, genesis.peer_binding(), budget.clone()),
            &genesis,
            policy(),
        )
        .unwrap();
        assert!(respond(&mut peer, &owner).is_err());
        drop(peer);
        assert_eq!(budget.available().unwrap(), before);
        assert_eq!(owner.lock().unwrap().received, 0);
    }
    assert!(encode_ids(INVENTORY, &[[1; 32]; 129], MAX_IDS).is_err());
}

#[test]
fn waiting_for_owner_never_outlives_its_admission_deadline() {
    let owner = model(1, 1);
    let held = owner.lock().unwrap();
    let deadline = p2p::Deadline::new(Duration::from_millis(10));
    let started = std::time::Instant::now();
    assert!(lock(&owner, &deadline).is_err());
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(held.received, 0);
}
