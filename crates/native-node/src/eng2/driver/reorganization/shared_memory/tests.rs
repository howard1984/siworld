use super::*;
use std::sync::{Arc, Mutex, mpsc};
const MIB: usize = 1024 * 1024;

#[test]
fn owner_tick_retries_after_a_network_guard_leaves_without_waiting_under_owner_lock() {
    // Logical reservations only: no proof, native process or large buffer.
    let budget = Budget::new(640 * MIB);
    let _pool = budget.reserve(130 * MIB).unwrap();
    let _producer = budget.reserve(256 * MIB).unwrap();
    let state = Arc::new(Mutex::new(MemoryAdmission::default()));
    let network_state = state.clone();
    let network_budget = budget.clone();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let network = std::thread::spawn(move || {
        let guard = network_budget.reserve(3 * 40 * MIB + 65536).unwrap();
        // Model the actual callback followed by ReceivedBody drop outside owner.
        let owner = network_state.lock().unwrap();
        drop(owner);
        ready_tx.send(()).unwrap();
        release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        drop(guard);
    });
    ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let now = Instant::now();
    {
        let mut owner = state.lock().unwrap();
        assert!(owner.try_acquire(&budget, 40 * MIB, now).unwrap().is_none());
        assert!(owner.is_waiting());
        let row = owner.diagnostic().unwrap();
        assert_eq!(row["maximum_bytes"], 640 * MIB);
        assert_eq!(row["used_bytes_at_attempt"], 506 * MIB + 65536);
        assert_eq!(row["requested_bytes"], 160 * MIB + 65536);
        // A second owner turn cannot retry early or claim a successful switch.
        assert!(
            owner
                .try_acquire(&budget, 40 * MIB, now + Duration::from_millis(100))
                .unwrap()
                .is_none()
        );
        assert_eq!(owner.diagnostic().unwrap()["attempts"], 1);
    }
    release_tx.send(()).unwrap();
    network.join().unwrap();
    let mut owner = state.lock().unwrap();
    let replay = owner
        .try_acquire(&budget, 40 * MIB, now + RETRY_INTERVAL)
        .unwrap()
        .unwrap();
    assert!(!owner.is_waiting());
    assert_eq!(owner.diagnostic().unwrap()["attempts"], 2);
    assert_eq!(budget.available().unwrap(), 94 * MIB - 65536);
    drop(replay);
    assert_eq!(budget.available().unwrap(), 254 * MIB);
}

#[test]
fn repeated_contention_has_one_deadline_and_never_performs_an_unreserved_phase() {
    let budget = Budget::new(1);
    let mut owner = MemoryAdmission::default();
    let now = Instant::now();
    for tick in 0..4 {
        assert!(
            owner
                .try_acquire(&budget, 1, now + RETRY_INTERVAL * tick)
                .unwrap()
                .is_none()
        );
        assert!(owner.is_waiting());
    }
    assert!(matches!(
        owner.try_acquire(&budget, 1, now + WAIT_LIMIT),
        Err(Failure::Deadline)
    ));
    assert_eq!(owner.diagnostic().unwrap()["attempts"], 4);
    assert_eq!(budget.available().unwrap(), 1);
    assert!(owner.is_waiting());
}

#[test]
fn replay_charge_overflow_is_typed_and_never_becomes_contention() {
    let budget = Budget::new(640 * MIB);
    let mut owner = MemoryAdmission::default();
    assert!(matches!(
        owner.try_acquire(&budget, usize::MAX, Instant::now()),
        Err(Failure::Overflow)
    ));
    assert!(!owner.is_waiting());
    assert_eq!(owner.diagnostic().unwrap()["outcome"], "overflow");
    assert_eq!(
        owner.diagnostic().unwrap()["requested_bytes"],
        serde_json::Value::Null
    );
    assert_eq!(budget.available().unwrap(), 640 * MIB);
}
