use super::*;
use crate::eng2::{
    execution::Engine,
    genesis::{FeeMode, Genesis},
    header::Header,
    state_components,
};

#[test]
fn owner_state_machine_discovers_all_raw_materials_without_canonical_adoption() {
    let fixture = super::super::super::tests::Fixture::new();
    let bootstrap = crate::eng2::snapshot::tests::bootstrap();
    let genesis = Genesis::seal(
        bootstrap.chain.config.clone(),
        bootstrap.governance.clone(),
        FeeMode::LegacyMiner,
    )
    .unwrap();
    let engine = Engine::new(
        Genesis::decode(&genesis.encode().unwrap()).unwrap(),
        state_components::Limits {
            max_leaves: 1_000_000,
            max_nullifiers: 1_000_000,
            max_component_bytes: 64 * 1024 * 1024,
        },
    )
    .unwrap();
    let policy = engine.body_policy();
    let canonical = Store::create(
        &fixture.0.join("canonical.redb"),
        Genesis::decode(&genesis.encode().unwrap()).unwrap(),
        state_components::Limits {
            max_leaves: 1_000_000,
            max_nullifiers: 1_000_000,
            max_component_bytes: 64 * 1024 * 1024,
        },
    )
    .unwrap();
    let rules = crate::eng2::selection::HeaderRules {
        network: genesis.config().network,
        genesis: genesis.id(),
        genesis_timestamp: genesis.config().genesis_timestamp,
        genesis_target: genesis.config().genesis_target,
        target_interval: 300,
        pow_iterations: 0,
        max_headers: 128,
    };
    let mut branches = BranchStore::create(
        &fixture.path(),
        rules,
        crate::eng2::branches::Limits {
            maximum_headers: 128,
            maximum_body_bytes: 64 * 1024 * 1024,
        },
    )
    .unwrap();
    let mut records = Vec::new();
    let mut parent = genesis.id();
    for height in 1..=3 {
        let mut body = crate::eng2::body::tests::body();
        body.network = genesis.config().network;
        body.profile = policy.profile;
        body.transactions
            .sort_by_key(|tx| tx.record.statement_id(&body.network));
        body.height = height;
        body.governance.clear();
        body.fund_claims.clear();
        let header = Header {
            network: body.network,
            height,
            parent,
            timestamp: 1 + height * 300,
            target: [255; 32],
            execution_commitment: [4; 32],
            body_commitment: body.commitment(policy).unwrap(),
            nonce: 0,
        };
        parent = header.id().unwrap();
        records.push((header, body));
    }
    let mut discovery = Discovery::new(
        genesis.config().network,
        genesis.id(),
        Limits {
            maximum_candidates: 4,
            maximum_peers: 3,
            maximum_requests: 32,
            maximum_headers: 32,
            maximum_body_bytes: 64 * 1024 * 1024,
            maximum_headers_per_candidate: 32,
            maximum_attempts_per_header: 2,
            candidate_lifetime_ms: 1000,
            window_ms: 4000,
        },
        10,
    )
    .unwrap();
    let remote = (3, parent);
    let mut now = 11;
    for index in (0..3).rev() {
        let action = discovery
            .next(&mut branches, &canonical, remote, [9; 32], now)
            .unwrap();
        let DiscoveryAction::Header(request) = action else {
            panic!("exact ancestor expected")
        };
        assert_eq!(
            request.query(),
            (records[index].0.height, records[index].0.id().unwrap())
        );
        discovery
            .received(request, Some(records[index].0.clone()), now + 1)
            .unwrap();
        now += 2;
    }
    for (header, body) in &records {
        let action = discovery
            .next(&mut branches, &canonical, remote, [9; 32], now)
            .unwrap();
        let DiscoveryAction::Body {
            request,
            header: requested,
        } = action
        else {
            panic!("exact raw body expected")
        };
        assert_eq!(&requested, header);
        discovery
            .body(&mut branches, request, header, body, policy, now + 1)
            .unwrap();
        now += 2;
        assert_eq!(
            branches
                .entry(header.id().unwrap())
                .unwrap()
                .unwrap()
                .status,
            Status::BodyRetained
        );
    }
    assert!(matches!(
        discovery
            .next(&mut branches, &canonical, remote, [9; 32], now)
            .unwrap(),
        DiscoveryAction::Ready
    ));
    assert_eq!(canonical.engine().state().height(), 0);
    assert_eq!(discovery.usage().requests, 6);
    assert_eq!(discovery.usage().headers, 3);
}
