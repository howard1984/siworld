use super::*;
use crate::eng2::{
    body::Policy,
    certificate::{AuthorizationWitness, Certificate, Statement, Vote},
    checkpoint_wire::Proposal,
    commitment::{self, Component},
    genesis::{FeeMode, Genesis},
};
use std::{
    io::{self, Cursor},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

fn genesis() -> Genesis {
    let state = crate::eng2::snapshot::tests::bootstrap();
    Genesis::seal(
        state.chain.config.clone(),
        state.governance().clone(),
        FeeMode::LegacyMiner,
    )
    .unwrap()
}
fn policy() -> Policy {
    Policy {
        profile: crate::proofs::protocol_profile_fingerprint(),
        max_body_bytes: 4 * 1024 * 1024,
        max_settlement_proof_bytes: 3 * 1024 * 1024,
    }
}
fn packets(network: Hash) -> Vec<Vec<u8>> {
    // Synthetic framing fixtures only: no signature or native state admission
    // is claimed by this exchange, which deliberately does not own Store.
    let statement = Statement {
        network,
        checkpoint_height: 72,
        checkpoint_block: [3; 32],
        authorization_height: 96,
        authorization_block: [4; 32],
        roster_sequence: 0,
        roster_digest: [5; 32],
    };
    let descriptors = commitment::COMPONENTS.map(|id| {
        Component::from_local_encoding(id, b"synthetic packet fixture", 131072)
            .unwrap()
            .descriptor()
    });
    let witness = AuthorizationWitness {
        descriptors,
        governance: b"synthetic public witness".to_vec(),
    };
    let vote = |slot| Vote {
        slot,
        signature: [0; crate::eng2::certificate::SIGNATURE_BYTES],
    };
    [
        Incoming::Proposal(Proposal {
            statement: statement.clone(),
            witness: witness.clone(),
        }),
        Incoming::Vote {
            statement: statement.clone(),
            vote: Box::new(vote(0)),
        },
        Incoming::Certified {
            certificate: Box::new(Certificate {
                statement,
                votes: [vote(0), vote(1)],
            }),
            witness,
        },
    ]
    .iter()
    .map(|p| p.encode(131072).unwrap())
    .collect()
}
fn frame(request: u64, body: &[u8], network: Hash) -> Vec<u8> {
    declared_frame(p2p::ENG2_MESSAGE, request, body.len(), body, network)
}
fn declared_frame(kind: u8, request: u64, length: usize, body: &[u8], network: Hash) -> Vec<u8> {
    let mut bytes = b"SWPF".to_vec();
    bytes.extend_from_slice(&p2p::VERSION.to_le_bytes());
    bytes.push(kind);
    bytes.extend_from_slice(&request.to_le_bytes());
    bytes.extend_from_slice(&network);
    bytes.extend_from_slice(&(length as u32).to_le_bytes());
    bytes.extend_from_slice(body);
    bytes
}
fn envelope(index: u8, packet: &[u8]) -> Vec<u8> {
    let mut out = vec![PACKET, index];
    out.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    out.extend_from_slice(packet);
    out
}
fn batch(packets: &[Vec<u8>], network: Hash) -> Vec<u8> {
    let mut out = frame(REQUEST, &[BATCH, 1, 0, packets.len() as u8], network);
    for (index, packet) in packets.iter().enumerate() {
        out.extend_from_slice(&frame(REQUEST, &envelope(index as u8, packet), network));
    }
    out
}
struct Script {
    input: Cursor<Vec<u8>>,
    output: Arc<Mutex<Vec<u8>>>,
    clock: Option<Arc<AtomicU64>>,
    step: u64,
}
impl Read for Script {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if let Some(clock) = &self.clock {
            clock.fetch_add(self.step, Ordering::Relaxed);
        }
        self.input.read(bytes)
    }
}
impl Write for Script {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.output.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn script(
    input: Vec<u8>,
    g: &Genesis,
    budget: p2p::Budget,
    clock: Option<Arc<AtomicU64>>,
    step: u64,
) -> (Peer<Script>, Arc<Mutex<Vec<u8>>>) {
    let output = Arc::new(Mutex::new(Vec::new()));
    let session = p2p::Session::from_test_channel(
        Script {
            input: Cursor::new(input),
            output: output.clone(),
            clock,
            step,
        },
        g.peer_binding(),
        budget,
    );
    (Peer::new(session, g, policy()).unwrap(), output)
}
#[test]
fn mock_loopback_batches_retain_decoded_shared_budget_through_queue_ownership() {
    let g = genesis();
    let network = g.config().network;
    let outgoing = packets(network);
    let expected = outgoing.clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (b, _) = listener.accept().unwrap();
    drop(listener);
    for socket in [&a, &b] {
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
    }
    let budget = p2p::Budget::new(4 * 1024 * 1024);
    let before = budget.available().unwrap();
    let mut client = Peer::new(
        p2p::Session::from_test_channel(a, g.peer_binding(), budget.clone()),
        &g,
        policy(),
    )
    .unwrap();
    let mut server = Peer::new(
        p2p::Session::from_test_channel(b, g.peer_binding(), budget.clone()),
        &g,
        policy(),
    )
    .unwrap();
    let server_out = outgoing[..1].to_vec();
    let worker = std::thread::spawn(move || {
        let result = respond(&mut server, &server_out, network).unwrap();
        assert!(respond(&mut server, &[], network).unwrap().is_empty());
        result
    });
    let incoming = initiate(&mut client, &outgoing, network).unwrap();
    assert!(initiate(&mut client, &[], network).unwrap().is_empty());
    let received = worker.join().unwrap();
    assert_eq!(incoming.len(), 1);
    assert_eq!(received.len(), 3);
    for (item, packet) in received.iter().zip(&expected) {
        assert_eq!(item.message.encode(131072).unwrap(), *packet);
    }
    let charge = expected
        .iter()
        .map(|packet| 3 * packet.len() + 65536)
        .sum::<usize>()
        + 3 * expected[0].len()
        + 65536;
    assert_eq!(before - budget.available().unwrap(), charge);
    let mut queue = received;
    drop(incoming);
    assert!(budget.available().unwrap() < before);
    let owned = queue.remove(0);
    drop(queue);
    assert_eq!(
        before - budget.available().unwrap(),
        3 * expected[0].len() + 65536
    );
    drop(owned);
    assert_eq!(budget.available().unwrap(), before);
}
#[test]
fn malformed_counts_types_indices_lengths_and_networks_drop_partial_messages_and_charges() {
    let g = genesis();
    let network = g.config().network;
    let valid = packets(network).remove(1);
    let mut cases = vec![
        frame(REQUEST, &[BATCH, 1, 0, 4], network),
        frame(REQUEST, &[BATCH, 2, 0, 0], network),
        frame(1, &[BATCH, 1, 0, 0], network),
        frame(REQUEST, &[2, 1, 0, 0], network),
    ];
    for bad in [
        envelope(1, &valid),
        {
            let mut p = envelope(0, &valid);
            p[2..6].copy_from_slice(&1u32.to_le_bytes());
            p
        },
        {
            let mut p = envelope(0, &valid);
            p[6] = 0;
            p
        },
        {
            let mut p = envelope(0, &valid);
            p[0] = 2;
            p
        },
    ] {
        let mut wire = frame(REQUEST, &[BATCH, 1, 0, 1], network);
        wire.extend_from_slice(&frame(REQUEST, &bad, network));
        cases.push(wire);
    }
    let mut partial = frame(REQUEST, &[BATCH, 1, 0, 2], network);
    partial.extend_from_slice(&frame(REQUEST, &envelope(0, &valid), network));
    cases.push(partial);
    cases.push(declared_frame(
        p2p::BLOCK,
        REQUEST,
        100_000_000,
        &[],
        network,
    ));
    cases.push(declared_frame(
        p2p::ENG2_MESSAGE,
        REQUEST,
        MAX_CHECKPOINT_PACKET_BYTES + PACKET_PREFIX + 1,
        &[],
        network,
    ));
    for wire in cases {
        let budget = p2p::Budget::new(1024 * 1024);
        let before = budget.available().unwrap();
        let (mut peer, _) = script(wire, &g, budget.clone(), None, 0);
        assert!(respond(&mut peer, &[], network).is_err());
        assert_eq!(budget.available().unwrap(), before);
    }
    let budget = p2p::Budget::new(1024 * 1024);
    let (mut peer, output) = script(vec![], &g, budget, None, 0);
    assert!(initiate(&mut peer, &[], [9; 32]).is_err());
    assert!(output.lock().unwrap().is_empty());
}
#[test]
fn typed_decode_requires_additional_shared_reservation_and_refunds_on_failure() {
    let g = genesis();
    let network = g.config().network;
    let valid = packets(network).remove(1);
    let required = valid.len() * 3 + 65536 + valid.len() + PACKET_PREFIX + 64;
    let budget = p2p::Budget::new(required - 1);
    let before = budget.available().unwrap();
    let (mut peer, _) = script(
        batch(std::slice::from_ref(&valid), network),
        &g,
        budget.clone(),
        None,
        0,
    );
    assert!(matches!(
        respond(&mut peer, &[], network),
        Err(p2p::Error::ResourceExhausted)
    ));
    assert_eq!(budget.available().unwrap(), before);
}
#[test]
fn phase_deadline_is_not_restarted_for_a_frame_body_or_another_packet() {
    let g = genesis();
    let network = g.config().network;
    let outgoing = packets(network);
    for (wire, step) in [
        (batch(&[], network), 6000),
        (batch(&outgoing[..2], network), 2000),
    ] {
        let clock = Arc::new(AtomicU64::new(0));
        let deadline = p2p::Deadline::test_clock(PHASE_TIMEOUT, clock.clone());
        let budget = p2p::Budget::new(1024 * 1024);
        let before = budget.available().unwrap();
        let (mut peer, _) = script(wire, &g, budget.clone(), Some(clock), step);
        assert!(matches!(
            exchange(&mut peer, &[], network, false, &deadline),
            Err(p2p::Error::Unavailable)
        ));
        assert_eq!(budget.available().unwrap(), before);
    }
}
#[test]
fn invalid_local_payloads_and_unsolicited_block_responses_fail_without_sending_a_batch() {
    let g = genesis();
    let network = g.config().network;
    for outgoing in [
        vec![vec![]],
        vec![vec![0; MAX_CHECKPOINT_PACKET_BYTES + 1]],
        vec![vec![0; 8]],
        vec![vec![0; 8]; MAX_MESSAGES_PER_TICK + 1],
    ] {
        let budget = p2p::Budget::new(1024 * 1024);
        let before = budget.available().unwrap();
        let (mut peer, output) = script(vec![], &g, budget.clone(), None, 0);
        assert!(initiate(&mut peer, &outgoing, network).is_err());
        assert!(output.lock().unwrap().is_empty());
        assert_eq!(budget.available().unwrap(), before);
    }
    let wire = frame(REQUEST, &[3, 1, 2, 3], network);
    let budget = p2p::Budget::default();
    let (mut peer, _) = script(wire, &g, budget, None, 0);
    assert!(respond(&mut peer, &[], network).is_err());
}
