use super::*;

fn limits() -> Limits {
    Limits {
        maximum_candidates: 4,
        maximum_peers: 3,
        maximum_requests: 80,
        maximum_headers: 64,
        maximum_body_bytes: 1024 * 1024,
        maximum_headers_per_candidate: 40,
        maximum_attempts_per_header: 2,
        candidate_lifetime_ms: 1_000,
        window_ms: 4_000,
    }
}
fn ledger() -> Ledger {
    Ledger::new([1; 32], [2; 32], limits(), 10).unwrap()
}
fn chain(count: u64) -> Vec<Header> {
    let mut parent = [2; 32];
    (1..=count)
        .map(|height| {
            let header = Header {
                network: [1; 32],
                height,
                parent,
                timestamp: height * 300,
                target: [255; 32],
                execution_commitment: [3; 32],
                body_commitment: [4; 32],
                nonce: 0,
            };
            parent = header.id().unwrap();
            header
        })
        .collect()
}
#[test]
fn thirty_block_replacement_is_independent_of_twenty_four_block_rollback() {
    let headers = chain(30);
    let tip = headers.last().unwrap().id().unwrap();
    let mut ledger = ledger();
    ledger.begin(30, tip, 10).unwrap();
    for (index, header) in headers.iter().rev().enumerate() {
        let peer = [10 + (index % 2) as u8; 32];
        let request = ledger.request(tip, peer, 11 + index as u64).unwrap();
        let cursor = ledger
            .receive(request, header.clone(), 11 + index as u64)
            .unwrap();
        assert_eq!(cursor.height, 29 - index as u64);
    }
    assert_eq!(
        ledger.cursor(tip, 50).unwrap(),
        Cursor {
            height: 0,
            id: [2; 32],
            ancestor_confirmed: true
        }
    );
    assert_eq!(ledger.path(tip, 50).unwrap(), headers);
    assert_eq!(ledger.usage().requests, 30);
    assert_eq!(
        ledger.request(tip, [10; 32], 50).unwrap_err(),
        Error::Complete
    );
}
#[test]
fn missing_reconnect_and_cross_peer_attempts_never_refund_budget() {
    let header = chain(1).remove(0);
    let tip = header.id().unwrap();
    let mut ledger = ledger();
    ledger.begin(1, tip, 10).unwrap();
    let first = ledger.request(tip, [10; 32], 11).unwrap();
    assert_eq!(
        ledger.request(tip, [11; 32], 12).unwrap_err(),
        Error::InFlight
    );
    ledger.defer(first, 12).unwrap();
    assert_eq!(
        ledger.request(tip, [10; 32], 13).unwrap_err(),
        Error::DuplicatePeer
    );
    let second = ledger.request(tip, [11; 32], 14).unwrap();
    ledger.defer(second, 15).unwrap();
    assert_eq!(
        ledger.request(tip, [12; 32], 16).unwrap_err(),
        Error::Capacity
    );
    ledger.begin(1, tip, 17).unwrap();
    assert_eq!(
        ledger.usage(),
        Usage {
            candidates: 1,
            peers: 2,
            requests: 2,
            headers: 0,
            body_bytes: 0
        }
    );
}
#[test]
fn expiry_and_duplicate_advertisements_cannot_renew_or_release_slots() {
    let mut ledger = ledger();
    let tip = chain(1)[0].id().unwrap();
    ledger.begin(1, tip, 10).unwrap();
    ledger.begin(1, tip, 1_009).unwrap();
    assert_eq!(ledger.begin(1, tip, 1_010).unwrap_err(), Error::Expired);
    assert_eq!(ledger.cursor(tip, 1_011).unwrap_err(), Error::Expired);
    assert_eq!(ledger.usage().candidates, 1);
    for tag in [20, 21, 22] {
        ledger.begin(3, [tag; 32], 1_012).unwrap();
    }
    assert_eq!(
        ledger.begin(3, [23; 32], 1_013).unwrap_err(),
        Error::Capacity
    );
    assert_eq!(
        ledger.begin(3, [24; 32], 4_010).unwrap_err(),
        Error::Expired
    );
}
#[test]
fn clock_regression_and_cross_ledger_completion_fail_closed() {
    let mut a = ledger();
    let mut b = ledger();
    let h = chain(1).remove(0);
    let tip = h.id().unwrap();
    a.begin(1, tip, 10).unwrap();
    b.begin(1, tip, 10).unwrap();
    let request = a.request(tip, [10; 32], 11).unwrap();
    assert_eq!(b.receive(request, h, 11).unwrap_err(), Error::StaleRequest);
    assert_eq!(b.cursor(tip, 10).unwrap_err(), Error::Clock);
    assert_eq!(b.cursor(tip, 12).unwrap_err(), Error::Clock);
}
#[test]
fn exact_cursor_and_invalid_parent_do_not_skip_ancestor_checks() {
    let h = chain(2).remove(1);
    let tip = h.id().unwrap();
    let mut ledger = ledger();
    ledger.begin(2, tip, 10).unwrap();
    assert_eq!(
        ledger.confirm_ancestor(tip, 1, h.parent, 10).unwrap_err(),
        Error::AncestorMismatch
    );
    let request = ledger.request(tip, [10; 32], 11).unwrap();
    assert_eq!(
        ledger.confirm_ancestor(tip, 2, tip, 11).unwrap_err(),
        Error::InFlight
    );
    let mut wrong = h.clone();
    wrong.height = 1;
    assert_eq!(
        ledger.receive(request, wrong, 12).unwrap_err(),
        Error::InvalidHeader
    );
    assert_eq!(ledger.usage().headers, 0);
    let request = ledger.request(tip, [11; 32], 13).unwrap();
    ledger.receive(request, h.clone(), 14).unwrap();
    ledger.confirm_ancestor(tip, 1, h.parent, 15).unwrap();
    assert_eq!(ledger.path(tip, 15).unwrap(), vec![h]);
}
#[test]
fn repeated_parent_and_total_limits_are_enforced_across_candidates() {
    let headers = chain(2);
    let tip = headers[1].id().unwrap();
    let mut ledger = ledger();
    ledger.begin(2, tip, 10).unwrap();
    // A corrupted/repeated parent cannot extend a previously observed path.
    ledger
        .candidates
        .get_mut(&tip)
        .unwrap()
        .seen
        .insert(headers[1].parent);
    let request = ledger.request(tip, [10; 32], 11).unwrap();
    assert_eq!(
        ledger.receive(request, headers[1].clone(), 12).unwrap_err(),
        Error::Cycle
    );
    assert_eq!(ledger.usage().headers, 0);
    let mut limit = limits();
    limit.maximum_requests = 1;
    let mut ledger = Ledger::new([1; 32], [2; 32], limit, 10).unwrap();
    ledger.begin(2, tip, 10).unwrap();
    ledger.begin(1, headers[0].id().unwrap(), 10).unwrap();
    let request = ledger.request(tip, [10; 32], 10).unwrap();
    ledger.defer(request, 11).unwrap();
    assert_eq!(
        ledger
            .request(headers[0].id().unwrap(), [11; 32], 12)
            .unwrap_err(),
        Error::Capacity
    );
}
#[test]
fn total_peer_header_and_per_candidate_bounds_are_independent() {
    let headers = chain(2);
    let tip = headers[1].id().unwrap();
    let mut limit = limits();
    limit.maximum_peers = 1;
    limit.maximum_attempts_per_header = 1;
    let mut ledger = Ledger::new([1; 32], [2; 32], limit, 10).unwrap();
    ledger.begin(2, tip, 10).unwrap();
    let r = ledger.request(tip, [10; 32], 10).unwrap();
    ledger.receive(r, headers[1].clone(), 11).unwrap();
    assert_eq!(
        ledger.request(tip, [11; 32], 12).unwrap_err(),
        Error::Capacity
    );
    let r = ledger.request(tip, [10; 32], 13).unwrap();
    ledger.receive(r, headers[0].clone(), 14).unwrap();
    let mut limit = limits();
    limit.maximum_headers_per_candidate = 1;
    let mut ledger = Ledger::new([1; 32], [2; 32], limit, 10).unwrap();
    ledger.begin(2, tip, 10).unwrap();
    let r = ledger.request(tip, [10; 32], 10).unwrap();
    ledger.receive(r, headers[1].clone(), 11).unwrap();
    assert_eq!(
        ledger.request(tip, [10; 32], 12).unwrap_err(),
        Error::Capacity
    );
    let mut limit = limits();
    limit.maximum_headers = 1;
    limit.maximum_headers_per_candidate = 1;
    let mut ledger = Ledger::new([1; 32], [2; 32], limit, 10).unwrap();
    ledger.begin(2, tip, 10).unwrap();
    ledger.begin(1, headers[0].id().unwrap(), 10).unwrap();
    let r = ledger.request(tip, [10; 32], 10).unwrap();
    ledger.receive(r, headers[1].clone(), 11).unwrap();
    assert_eq!(
        ledger
            .request(headers[0].id().unwrap(), [10; 32], 12)
            .unwrap_err(),
        Error::Capacity
    );
}

#[test]
fn body_requests_share_global_attempt_caps_and_retain_no_duplicate_bytes() {
    let h = chain(1).remove(0);
    let tip = h.id().unwrap();
    let mut ledger = ledger();
    ledger.begin(1, tip, 10).unwrap();
    let request = ledger.request(tip, [10; 32], 11).unwrap();
    ledger.receive(request, h, 12).unwrap();
    let request = ledger.request_body(tip, tip, [10; 32], 13).unwrap();
    ledger.defer(request, 14).unwrap();
    assert_eq!(
        ledger.request_body(tip, tip, [10; 32], 15).unwrap_err(),
        Error::DuplicatePeer
    );
    let request = ledger.request_body(tip, tip, [11; 32], 16).unwrap();
    assert!(request.is_body());
    ledger.body_retained(request, 100, 17).unwrap();
    assert_eq!(
        ledger.request_body(tip, tip, [12; 32], 18).unwrap_err(),
        Error::Complete
    );
    assert_eq!(ledger.usage().requests, 3);
    assert_eq!(ledger.usage().body_bytes, 100);
}
#[test]
fn only_fixed_window_expiry_resets_counts_and_invalidates_old_tickets() {
    let h = chain(1).remove(0);
    let tip = h.id().unwrap();
    let mut ledger = ledger();
    ledger.begin(1, tip, 10).unwrap();
    let request = ledger.request(tip, [10; 32], 11).unwrap();
    assert!(!ledger.renew_expired_window(4_009).unwrap());
    assert_eq!(ledger.usage().requests, 1);
    assert!(ledger.renew_expired_window(4_010).unwrap());
    ledger.begin(1, tip, 4_010).unwrap();
    assert_eq!(
        ledger.receive(request, h, 4_011).unwrap_err(),
        Error::StaleRequest
    );
    assert_eq!(ledger.usage().requests, 0);
}
