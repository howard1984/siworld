use super::*;
use crate::eng2::selection::{HeaderRules, VerifiedHeaders};

fn rules() -> HeaderRules {
    HeaderRules {
        network: [1; 32],
        genesis: [2; 32],
        genesis_timestamp: 1,
        genesis_target: [0xff; 32],
        target_interval: 300,
        asert_half_life: siworld_core::pow::AsertHalfLife::FourHours,
        pow_iterations: 0,
        pow_algorithm: siworld_core::pow::Algorithm::SequentialBlake3,
        max_headers: 100,
    }
}
fn chain(count: u64, tag: u8) -> VerifiedHeaders {
    let rules = rules();
    let mut headers = Vec::new();
    let mut parent = rules.genesis;
    for height in 1..=count {
        let header = Header {
            network: rules.network,
            height,
            parent,
            timestamp: 1 + 300 * height,
            target: [0xff; 32],
            execution_commitment: [tag; 32],
            body_commitment: [tag; 32],
            nonce: 0,
        };
        parent = header.id().unwrap();
        headers.push(header);
    }
    VerifiedHeaders::verify(rules, headers).unwrap()
}
#[test]
fn relay_checks_derived_work_and_never_confers_body_or_template_validity() {
    let canonical = chain(2, 3);
    let candidate = chain(3, 4);
    let mut relay = Relay::new(rules(), 0);
    assert_eq!(
        relay.offer(&canonical, &chain(1, 4), [5; 32], 0),
        Err(Error::WorkFloor)
    );
    assert_eq!(relay.offer(&canonical, &candidate, [5; 32], 1), Ok(true));
    assert_eq!(relay.offer(&canonical, &candidate, [5; 32], 2), Ok(false));
    assert!(
        relay
            .next_for_peer([5; 32], &canonical, 2)
            .unwrap()
            .is_none()
    );
    let announced = relay
        .next_for_peer([6; 32], &canonical, 2)
        .unwrap()
        .unwrap();
    assert_eq!(announced.header().height, 3);
    assert_eq!(announced.cumulative_work(), candidate.cumulative_work());
    assert!(announced.requires_validated_parent_state());
    assert_eq!(announced.first_qualified_ms(), 1);
    assert_eq!(canonical.height(), 2);
}
#[test]
fn relay_limits_peers_rate_clock_and_retention() {
    let canonical = chain(0, 3);
    let mut relay = Relay::new(rules(), 0);
    for tag in 1..=32 {
        relay
            .offer(&canonical, &chain(1, tag), [99; 32], 0)
            .unwrap();
    }
    assert_eq!(
        relay.offer(&canonical, &chain(2, 33), [99; 32], 0),
        Err(Error::Capacity)
    );
    for peer in 1..=8 {
        assert!(
            relay
                .next_for_peer([peer; 32], &canonical, 0)
                .unwrap()
                .is_some()
        );
    }
    for peer in 1..=8 {
        assert!(
            relay
                .next_for_peer([peer; 32], &canonical, 49)
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(
        relay.next_for_peer([9; 32], &canonical, 49).unwrap_err(),
        Error::Capacity
    );
    relay.disconnected([1; 32]);
    assert!(
        relay
            .next_for_peer([9; 32], &canonical, RETAIN_MS)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        relay.offer(&canonical, &chain(1, 1), [99; 32], 1),
        Err(Error::Clock)
    );
    assert_eq!(
        relay.offer(&canonical, &chain(1, 1), [99; 32], RETAIN_MS + 1),
        Err(Error::Clock)
    );
}

#[test]
fn relay_rechecks_current_work_floor_and_immutable_network_at_send_time() {
    let canonical = chain(1, 3);
    let candidate = chain(2, 4);
    let mut relay = Relay::new(rules(), 0);
    relay.offer(&canonical, &candidate, [5; 32], 0).unwrap();
    assert!(
        relay
            .next_for_peer([6; 32], &chain(3, 3), 1)
            .unwrap()
            .is_none()
    );
    let mut other_rules = rules();
    other_rules.network = [7; 32];
    let other = VerifiedHeaders::verify(other_rules, Vec::new()).unwrap();
    assert_eq!(relay.offer(&other, &other, [5; 32], 2), Err(Error::Context));
    assert_eq!(
        relay.next_for_peer([6; 32], &other, 2).unwrap_err(),
        Error::Context
    );
}
