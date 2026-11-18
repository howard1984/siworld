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
fn body_hedge_fixture(count: u64) -> (Ledger, Vec<Header>, Hash) {
    let headers = chain(count);
    let tip = headers.last().unwrap().id().unwrap();
    let mut bounds = limits();
    bounds.maximum_peers = 4;
    bounds.maximum_attempts_per_header = 4;
    bounds.candidate_lifetime_ms = 120_000;
    bounds.window_ms = 240_000;
    let mut ledger = Ledger::new([1; 32], [2; 32], bounds, 10).unwrap();
    ledger.begin(count, tip, 10).unwrap();
    for (index, header) in headers.iter().rev().enumerate() {
        let now = 11 + index as u64;
        let request = ledger.request(tip, [10; 32], now).unwrap();
        ledger.receive(request, header.clone(), now).unwrap();
    }
    (ledger, headers, tip)
}
#[test]
fn body_hedge_allows_a_second_source_after_bounded_primary_wait() {
    let (mut ledger, _, tip) = body_hedge_fixture(1);
    let slow = ledger.request_body(tip, tip, [10; 32], 20).unwrap();
    assert_eq!(
        ledger.request_body(tip, tip, [11; 32], 30_019).unwrap_err(),
        Error::InFlight
    );
    let fast = ledger
        .request_body(tip, tip, [11; 32], 30_020)
        .expect("one slow body source must not exclude a bounded delayed alternative");
    ledger.body_retained(fast, 100, 30_021).unwrap();
    assert_eq!(
        ledger.request_body(tip, tip, [12; 32], 30_022).unwrap_err(),
        Error::Complete
    );
    ledger.defer(slow, 30_023).unwrap();
    assert_eq!(ledger.usage().requests, 3);
    assert_eq!(ledger.usage().body_bytes, 100);
}
#[test]
fn body_hedge_late_completion_does_not_consume_the_next_body_ticket() {
    let (mut ledger, headers, tip) = body_hedge_fixture(2);
    let first_id = headers[0].id().unwrap();
    let slow = ledger.request_body(tip, first_id, [10; 32], 20).unwrap();
    let fast = ledger
        .request_body(tip, first_id, [11; 32], 30_020)
        .unwrap();
    ledger.body_retained(fast, 100, 30_021).unwrap();
    let next = ledger.request_body(tip, tip, [12; 32], 30_022).unwrap();
    ledger.body_retained(slow, 100, 30_023).unwrap();
    ledger.body_retained(next, 200, 30_024).unwrap();
    assert_eq!(ledger.usage().requests, 5);
    // Count both completed transfers, including the late duplicate, within
    // the original node-wide byte budget.
    assert_eq!(ledger.usage().body_bytes, 400);
}
#[test]
fn body_hedge_keeps_concurrency_attempt_and_expiry_bounds() {
    let (mut ledger, _, tip) = body_hedge_fixture(1);
    let slow = ledger.request_body(tip, tip, [10; 32], 20).unwrap();
    let second = ledger.request_body(tip, tip, [11; 32], 30_020).unwrap();
    assert_eq!(
        ledger.request_body(tip, tip, [12; 32], 30_021).unwrap_err(),
        Error::InFlight
    );
    assert_eq!(ledger.usage().requests, 3);
    ledger.defer(second, 30_022).unwrap();
    let third = ledger.request_body(tip, tip, [12; 32], 30_024).unwrap();
    ledger.defer(third, 30_025).unwrap();
    let fourth = ledger.request_body(tip, tip, [13; 32], 30_026).unwrap();
    ledger.defer(fourth, 30_027).unwrap();
    assert_eq!(
        ledger.request_body(tip, tip, [14; 32], 30_028).unwrap_err(),
        Error::Capacity
    );
    assert_eq!(ledger.usage().requests, 5);
    assert_eq!(ledger.defer(slow, 120_010).unwrap_err(), Error::Expired);
    assert_eq!(ledger.usage().requests, 5);
}
#[test]
fn body_hedge_cannot_refund_request_or_completed_transfer_byte_budgets() {
    let (mut ledger, _, tip) = body_hedge_fixture(1);
    ledger.limits.maximum_requests = 2;
    let slow = ledger.request_body(tip, tip, [10; 32], 20).unwrap();
    assert_eq!(
        ledger.request_body(tip, tip, [11; 32], 30_020).unwrap_err(),
        Error::Capacity
    );
    ledger.defer(slow, 30_021).unwrap();
    assert_eq!(
        ledger.request_body(tip, tip, [12; 32], 30_022).unwrap_err(),
        Error::Capacity
    );
    assert_eq!(ledger.usage().requests, 2);

    let (mut ledger, _, tip) = body_hedge_fixture(1);
    ledger.limits.maximum_body_bytes = 150;
    let slow = ledger.request_body(tip, tip, [10; 32], 20).unwrap();
    let fast = ledger.request_body(tip, tip, [11; 32], 30_020).unwrap();
    ledger.body_retained(fast, 100, 30_021).unwrap();
    assert_eq!(
        ledger.body_retained(slow, 100, 30_022).unwrap_err(),
        Error::Capacity
    );
    assert_eq!(ledger.usage().body_bytes, 100);
    assert_eq!(ledger.remaining_body_bytes(), 50);
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
    let request = ledger.request_body(tip, tip, [10; 32], 15).unwrap();
    assert_eq!(
        ledger.request_body(tip, tip, [11; 32], 15).unwrap_err(),
        Error::InFlight
    );
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

#[test]
fn body_window_capability_requires_original_expiry_and_clock_failure_is_permanent() {
    let mut ledger = Ledger::new([1; 32], [2; 32], limits(), 100).unwrap();
    let (original, expiry, _) = ledger.body_window();
    assert!(ledger.renew_body_window(expiry - 1).unwrap().is_none());
    assert_eq!(ledger.body_window().0, original);
    let advance = ledger.renew_body_window(expiry).unwrap().unwrap();
    assert_eq!(advance.identities().0, original);
    assert_ne!(advance.identities().1, original);
    assert!(advance.remaining() > 0);
    assert!(ledger.renew_body_window(expiry - 1).is_err());
    assert!(
        ledger
            .renew_body_window(expiry + advance.remaining())
            .is_err()
    );
}

#[test]
fn released_failed_body_requests_retry_same_peer_without_refunding_attempts() {
    let (mut ledger, _, tip) = body_hedge_fixture(1);
    let initial = ledger.usage().requests;
    for index in 0..4 {
        let now = 20 + index * 2;
        let request = ledger.request_body(tip, tip, [10; 32], now).unwrap();
        assert_eq!(
            ledger.request_body(tip, tip, [10; 32], now).unwrap_err(),
            Error::InFlight
        );
        ledger.defer(request, now + 1).unwrap();
    }
    assert_eq!(ledger.usage().requests, initial + 4);
    assert_eq!(
        ledger.request_body(tip, tip, [11; 32], 30).unwrap_err(),
        Error::Capacity
    );
}

#[test]
fn body_account_reopen_resets_source_attempts_without_refunding_window_caps() {
    let (mut ledger, _, tip) = body_hedge_fixture(1);
    ledger.limits.maximum_attempts_per_header = 2;
    ledger.limits.maximum_requests = 5;
    for now in [20, 22] {
        let request = ledger
            .request_body_for_account(tip, tip, [10; 32], now, 11)
            .unwrap();
        ledger.defer(request, now + 1).unwrap();
    }
    assert_eq!(
        ledger
            .request_body_for_account(tip, tip, [10; 32], 24, 11)
            .unwrap_err(),
        Error::Capacity
    );
    for now in [25, 27] {
        let request = ledger
            .request_body_for_account(tip, tip, [10; 32], now, 12)
            .unwrap();
        ledger.defer(request, now + 1).unwrap();
    }
    assert_eq!(ledger.usage().requests, 5);
    assert_eq!(ledger.usage().peers, 1);
    assert_eq!(
        ledger
            .request_body_for_account(tip, tip, [10; 32], 29, 13)
            .unwrap_err(),
        Error::Capacity
    );
    assert_eq!(
        ledger
            .request_body_for_account(tip, tip, [10; 32], 120_010, 14)
            .unwrap_err(),
        Error::Expired
    );
    assert_eq!(ledger.usage().requests, 5);
}

#[test]
fn body_account_reopen_cannot_replace_live_tickets_or_refund_completed_bytes() {
    let (mut ledger, headers, tip) = body_hedge_fixture(2);
    let first_id = headers[0].id().unwrap();
    let original = ledger
        .request_body_for_account(tip, first_id, [10; 32], 20, 11)
        .unwrap();
    assert_eq!(
        ledger
            .request_body_for_account(tip, first_id, [11; 32], 30_020, 12)
            .unwrap_err(),
        Error::InFlight
    );
    assert_eq!(ledger.usage().requests, 3);
    // A failed old ticket is consumed before the registry-minted new account
    // can issue a ticket. It cannot later complete against the replacement.
    ledger.defer(original, 30_021).unwrap();
    let replacement = ledger
        .request_body_for_account(tip, first_id, [10; 32], 30_022, 12)
        .unwrap();
    ledger.body_retained(replacement, 100, 30_023).unwrap();
    assert_eq!(
        ledger
            .request_body_for_account(tip, first_id, [11; 32], 30_024, 13)
            .unwrap_err(),
        Error::Complete
    );
    ledger.limits.maximum_body_bytes = 150;
    let second = ledger
        .request_body_for_account(tip, tip, [10; 32], 30_025, 14)
        .unwrap();
    assert_eq!(
        ledger.body_retained(second, 51, 30_026).unwrap_err(),
        Error::Capacity
    );
    assert_eq!(ledger.usage().body_bytes, 100);
    let second = ledger
        .request_body_for_account(tip, tip, [10; 32], 30_027, 15)
        .unwrap();
    ledger.body_retained(second, 50, 30_028).unwrap();
    assert_eq!(ledger.usage().body_bytes, 150);
    assert_eq!(ledger.usage().requests, 6);
}
