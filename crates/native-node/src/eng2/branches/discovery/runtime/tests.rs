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
        asert_half_life: siworld_core::pow::AsertHalfLife::FourHours,
        pow_iterations: 0,
        pow_algorithm: siworld_core::pow::Algorithm::SequentialBlake3,
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
        crate::p2p::Budget::default(),
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
    assert!(matches!(
        discovery
            .next_headers(&mut branches, &canonical, remote, [9; 32], now)
            .unwrap(),
        DiscoveryAction::Ready
    ));
    assert_eq!(discovery.usage().requests, 3);
    assert_eq!(discovery.usage().body_bytes, 0);
    for (header, _) in &records {
        assert_eq!(
            branches
                .entry(header.id().unwrap())
                .unwrap()
                .unwrap()
                .status,
            Status::HeaderQualified
        );
        assert!(branches.body_size(header.id().unwrap()).unwrap().is_none());
    }
    for (header, body) in &records {
        let action = discovery
            .next(&mut branches, &canonical, remote, [9; 32], now)
            .unwrap();
        let DiscoveryAction::Body {
            request,
            header: requested,
            ..
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

#[test]
fn body_handoff_waits_for_primary_release_without_consuming_a_source_ticket() {
    let fixture = super::super::super::tests::Fixture::new();
    let bootstrap = crate::eng2::snapshot::tests::bootstrap();
    let genesis = Genesis::seal(
        bootstrap.chain.config.clone(),
        bootstrap.governance.clone(),
        FeeMode::LegacyMiner,
    )
    .unwrap();
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
    let policy = canonical.engine().body_policy();
    let mut branches = BranchStore::create(
        &fixture.path(),
        crate::eng2::selection::HeaderRules {
            network: genesis.config().network,
            genesis: genesis.id(),
            genesis_timestamp: genesis.config().genesis_timestamp,
            genesis_target: genesis.config().genesis_target,
            target_interval: 300,
            asert_half_life: siworld_core::pow::AsertHalfLife::FourHours,
            pow_iterations: 0,
            pow_algorithm: siworld_core::pow::Algorithm::SequentialBlake3,
            max_headers: 128,
        },
        crate::eng2::branches::Limits {
            maximum_headers: 128,
            maximum_body_bytes: 64 * 1024 * 1024,
        },
    )
    .unwrap();
    let mut body = crate::eng2::body::tests::body();
    body.network = genesis.config().network;
    body.profile = policy.profile;
    body.height = 1;
    body.governance.clear();
    body.fund_claims.clear();
    body.transactions
        .sort_by_key(|tx| tx.record.statement_id(&body.network));
    let header = Header {
        network: body.network,
        height: 1,
        parent: genesis.id(),
        timestamp: genesis.config().genesis_timestamp + 300,
        target: genesis.config().genesis_target,
        execution_commitment: [4; 32],
        body_commitment: body.commitment(policy).unwrap(),
        nonce: 0,
    };
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
            candidate_lifetime_ms: 120_000,
            window_ms: 240_000,
        },
        10,
        crate::p2p::Budget::default(),
    )
    .unwrap();
    let remote = (1, header.id().unwrap());
    let DiscoveryAction::Header(request) = discovery
        .next(&mut branches, &canonical, remote, [9; 32], 11)
        .unwrap()
    else {
        panic!("exact header expected")
    };
    discovery
        .received(request, Some(header.clone()), 12)
        .unwrap();
    let DiscoveryAction::Body {
        request: slow,
        ownership: slow_owner,
        ..
    } = discovery
        .next(&mut branches, &canonical, remote, [9; 32], 14)
        .unwrap()
    else {
        panic!("primary raw-body request expected")
    };
    let before = discovery.usage().requests;
    assert!(matches!(
        discovery
            .next(&mut branches, &canonical, remote, [8; 32], 30_013)
            .unwrap(),
        DiscoveryAction::Deferred
    ));
    assert_eq!(discovery.usage().requests, before);
    let original_deadline = slow_owner.deadline().clone();
    discovery.deferred(slow, 30_013).unwrap();
    drop(slow_owner);
    let DiscoveryAction::Body {
        request: fast,
        ownership: fast_owner,
        ..
    } = discovery
        .next(&mut branches, &canonical, remote, [8; 32], 30_014)
        .unwrap()
    else {
        panic!("released primary permits the alternate source")
    };
    discovery
        .body(&mut branches, fast, &header, &body, policy, 30_015)
        .unwrap();
    assert!(matches!(
        discovery
            .next(&mut branches, &canonical, remote, [7; 32], 30_016)
            .unwrap(),
        DiscoveryAction::Ready
    ));
    assert_eq!(
        fast_owner.deadline().expires_at(),
        original_deadline.expires_at()
    );
    fast_owner.complete();
    drop(fast_owner);
    assert_eq!(canonical.engine().state().height(), 0);
    assert_eq!(
        branches.body_size(header.id().unwrap()).unwrap(),
        Some(body.encoded_len(policy).unwrap())
    );
    assert_eq!(
        discovery.usage().body_bytes,
        body.encoded_len(policy).unwrap() as u64
    );
    assert_eq!(discovery.usage().requests, 3);
}

#[test]
fn original_discovery_limits_bound_shared_actual_body_queries() {
    let budget = crate::p2p::Budget::new(1024 * 1024);
    let mut limits = resident_limits();
    limits.maximum_headers = 2;
    limits.maximum_headers_per_candidate = 2;
    limits.maximum_requests = 2;
    let discovery = Discovery::new([1; 32], [2; 32], limits, 0, budget.clone()).unwrap();
    let binding = crate::p2p::Binding {
        network: [1; 32],
        genesis: [2; 32],
        verifier: [3; 32],
    };
    for tag in 1u8..=2 {
        let auth = budget
            .authorize_body(
                &discovery.body_scope(),
                binding,
                1,
                [tag; 32],
                &crate::p2p::Deadline::new(crate::eng2::transport::BODY_FETCH_TIMEOUT),
            )
            .unwrap();
        let lease = budget
            .claim_body_authorized(&auth, [4; 32], crate::p2p::BodyMode::Legacy)
            .unwrap();
        lease.begin_query([4; 32]).unwrap();
        if tag == 2 {
            assert!(lease.begin_query([4; 32]).is_err());
        }
        drop(lease);
    }
    assert_eq!(
        budget
            .authorize_body(
                &discovery.body_scope(),
                binding,
                1,
                [3; 32],
                &crate::p2p::Deadline::new(crate::eng2::transport::BODY_FETCH_TIMEOUT)
            )
            .unwrap_err(),
        crate::p2p::BodyClaimError::Capacity
    );
    assert_eq!(budget.retained_body_accounting().0, 2);
}
