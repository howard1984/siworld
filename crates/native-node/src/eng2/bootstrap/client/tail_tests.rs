// Framing and quarantine ownership tests; these bodies grant no native admission.
use super::*;
use crate::eng2::{
    network,
    transport::{Peer, Request},
};
use std::{
    os::unix::net::UnixStream,
    sync::{Arc, Mutex},
    time::Duration,
};

struct ColdOwner;
impl network::Owner for ColdOwner {
    fn head(&self) -> Result<(u64, Hash), String> {
        Ok((0, [0; 32]))
    }
    fn header(&self, _: u64) -> Result<Option<Header>, String> {
        Ok(None)
    }
    fn block_size(&self, _: u64) -> Result<Option<usize>, String> {
        Ok(None)
    }
    fn block(&self, _: u64) -> Result<(Header, body::Body), String> {
        Err("unadmitted owner".into())
    }
    fn accept(&mut self, _: &Header, _: &body::Body) -> Result<(), String> {
        panic!("quarantine cannot admit")
    }
}
fn client(directory: &Directory, cache_body_limit: usize) -> (Genesis, Client) {
    let (genesis, candidate) = fixture_content(
        directory,
        112,
        1,
        Work::from(112u64),
        cache_body_limit,
        true,
    );
    let prepared = candidate.prepare(&genesis, Work::one()).unwrap();
    let mut client = select(vec![prepared], Work::one()).unwrap();
    client
        .candidate
        .cache
        .push(
            Object::Snapshot,
            0,
            &Chunk {
                descriptor: client.manifest().snapshot,
                bytes: b"fixture".to_vec(),
            },
        )
        .unwrap();
    for height in 1..=72 {
        let bytes = b"synthetic receipt";
        client
            .candidate
            .cache
            .push(
                Object::Receipt {
                    height,
                    id: client.plan.headers().id(height).unwrap(),
                },
                0,
                &Chunk {
                    descriptor: Descriptor {
                        length: bytes.len() as u64,
                        digest: *blake3::hash(bytes).as_bytes(),
                    },
                    bytes: bytes.to_vec(),
                },
            )
            .unwrap();
    }
    client.advance().unwrap();
    assert_eq!(
        client.progress().unwrap(),
        Progress::NativeTail {
            next: 73,
            total: 112
        }
    );
    (genesis, client)
}
fn peers(
    genesis: &Genesis,
    client: &Client,
    budget: &p2p::Budget,
) -> (Peer<UnixStream>, std::thread::JoinHandle<usize>) {
    let (a, b) = UnixStream::pair().unwrap();
    for socket in [&a, &b] {
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
    }
    let local = Peer::new(
        p2p::Session::from_test_channel(a, genesis.peer_binding(), budget.clone()),
        genesis,
        tail_policy(),
    )
    .unwrap();
    let mut remote = Peer::new(
        p2p::Session::from_test_channel(
            b,
            genesis.peer_binding(),
            p2p::Budget::new(64 * 1024 * 1024),
        ),
        genesis,
        tail_policy(),
    )
    .unwrap();
    let bodies: Vec<_> = (73..=112)
        .map(|height| {
            (
                client.plan.headers().header(height).unwrap().clone(),
                tail_body(genesis, height),
            )
        })
        .collect();
    let worker = std::thread::spawn(move || {
        let mut sent = 0;
        while let Ok((request, message)) = remote.receive_request() {
            match message {
                Request::Body { height, id } => {
                    let (header, body) = &bodies[(height - 73) as usize];
                    assert_eq!(header.id().unwrap(), id);
                    remote.send_body(request, header, body).unwrap();
                    sent += 1;
                }
                Request::Tip { height: 0, .. } => remote.finish_round(request).unwrap(),
                other => panic!("unexpected quarantine request: {other:?}"),
            }
        }
        sent
    });
    (local, worker)
}
#[test]
fn forty_successful_tail_steps_reuse_registry_capacity_after_durable_quarantine() {
    let directory = Directory::new();
    let (genesis, mut client) = client(&directory, 1024 * 1024);
    let budget = p2p::Budget::new(64 * 1024 * 1024);
    client
        .bind_body_operation(&budget, Instant::now() + Duration::from_secs(300))
        .unwrap();
    let before = budget.available().unwrap();
    let (mut peer, worker) = peers(&genesis, &client, &budget);
    let owner = Arc::new(Mutex::new(ColdOwner));
    let mut sequence = network::Sequence::default();
    for height in 73..=112 {
        let (round, progress) = network::initiate_bootstrap(
            &mut peer,
            &owner,
            &mut sequence,
            network::Limits { blocks: 1 },
            |pull| client.pull_step(pull),
        )
        .unwrap();
        assert_eq!(round.accepted, 0);
        assert_eq!(
            progress,
            if height == 112 {
                Progress::Downloaded
            } else {
                Progress::NativeTail {
                    next: height + 1,
                    total: 112,
                }
            }
        );
        assert!(
            client
                .candidate
                .cache
                .progress_at(height)
                .unwrap()
                .is_some_and(|(received, total)| received == total && total > 0)
        );
        let (accounts, metadata) = budget.retained_body_accounting();
        assert_eq!(accounts, (height - 72) as usize);
        assert!(metadata > 0);
        assert_eq!(budget.available().unwrap() + metadata, before);
    }
    drop(peer);
    assert_eq!(worker.join().unwrap(), 40);
}
#[test]
fn encode_or_cache_failure_keeps_source_queries_and_original_deadline() {
    for encode_failure in [false, true] {
        let directory = Directory::new();
        let (genesis, mut client) =
            client(&directory, if encode_failure { 1024 * 1024 } else { 1 });
        if encode_failure {
            client.candidate.body_policy.max_settlement_proof_bytes = 1;
        }
        let budget = p2p::Budget::new(64 * 1024 * 1024);
        client
            .bind_body_operation(&budget, Instant::now() + Duration::from_secs(300))
            .unwrap();
        let before = budget.available().unwrap();
        let header = client.plan.headers().header(73).unwrap().clone();
        let id = header.id().unwrap();
        let initial = budget
            .claim_body(
                genesis.peer_binding(),
                73,
                id,
                [9; 32],
                p2p::BodyMode::Legacy,
                &p2p::Deadline::new(Duration::from_secs(180)),
            )
            .unwrap();
        let expires = initial.deadline().expires_at();
        drop(initial);
        let (mut peer, worker) = peers(&genesis, &client, &budget);
        let failed_source = peer.peer();
        let result = network::initiate_bootstrap(
            &mut peer,
            &Arc::new(Mutex::new(ColdOwner)),
            &mut network::Sequence::default(),
            network::Limits { blocks: 1 },
            |pull| client.pull_step(pull),
        );
        assert!(matches!(result, Err(Error::Owner(_))));
        assert!(client.candidate.cache.progress_at(73).unwrap().is_none());
        let (accounts, metadata) = budget.retained_body_accounting();
        assert_eq!(accounts, 1);
        assert!(metadata > 0);
        assert_eq!(budget.available().unwrap() + metadata, before);
        assert!(matches!(
            budget.claim_body(
                genesis.peer_binding(),
                73,
                id,
                failed_source,
                p2p::BodyMode::Pieces,
                &p2p::Deadline::new(Duration::from_secs(180))
            ),
            Err(p2p::BodyClaimError::SourceUsed)
        ));
        let next = budget
            .claim_body(
                genesis.peer_binding(),
                73,
                id,
                [8; 32],
                p2p::BodyMode::Legacy,
                &p2p::Deadline::new(Duration::from_secs(180)),
            )
            .unwrap();
        assert_eq!(next.deadline().expires_at(), expires);
        for _ in 0..3 {
            next.begin_query([8; 32]).unwrap();
        }
        assert_eq!(
            next.begin_query([8; 32]),
            Err(p2p::Error::ResourceExhausted)
        );
        drop(next);
        drop(peer);
        assert_eq!(worker.join().unwrap(), 1);
    }
}
#[test]
fn completed_received_body_keeps_exact_owner_until_actual_drop() {
    let directory = Directory::new();
    let (genesis, client) = client(&directory, 1024 * 1024);
    let budget = p2p::Budget::new(64 * 1024 * 1024);
    let before = budget.available().unwrap();
    let (mut peer, worker) = peers(&genesis, &client, &budget);
    let header = client.plan.headers().header(73).unwrap();
    let id = header.id().unwrap();
    let received = peer.fetch_body(1, header).unwrap().unwrap();
    received.ownership.complete();
    assert!(matches!(
        budget.claim_body(
            genesis.peer_binding(),
            73,
            id,
            [8; 32],
            p2p::BodyMode::Legacy,
            &p2p::Deadline::new(Duration::from_secs(180))
        ),
        Err(p2p::BodyClaimError::Busy)
    ));
    assert!(budget.available().unwrap() < before);
    drop(received);
    let (accounts, metadata) = budget.retained_body_accounting();
    assert_eq!(accounts, 1);
    assert!(metadata > 0);
    assert_eq!(budget.available().unwrap() + metadata, before);
    assert!(matches!(
        budget.claim_body(
            genesis.peer_binding(),
            73,
            id,
            [8; 32],
            p2p::BodyMode::Legacy,
            &p2p::Deadline::new(Duration::from_secs(180)),
        ),
        Err(p2p::BodyClaimError::Expired)
    ));
    drop(peer);
    assert_eq!(worker.join().unwrap(), 1);
}
