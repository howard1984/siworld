use super::*;
use std::cell::{Cell, RefCell};

#[test]
fn injected_operation_failures_stop_the_pipeline_and_never_leak_error_text() {
    for failure in [
        Failure::WorkerPool,
        Failure::ProverInit,
        Failure::PaddingPrepare,
        Failure::PaddingProve,
        Failure::PrepareBlock,
        Failure::ProveBlock,
        Failure::WorkSearch,
        Failure::CommitBlock,
        Failure::RewardWrite,
    ] {
        let calls = Cell::new(0);
        let events = RefCell::new(Vec::new());
        let result = run_once(
            || {
                calls.set(calls.get() + 1);
                let injected: Result<(), String> =
                    Err("private-path/key-material/provider-detail".into());
                injected.map_err(|_| failure)?;
                panic!("production continued after failure")
            },
            |value| events.borrow_mut().push((value.stage(), value.code())),
            || {
                assert_eq!(events.borrow().len(), 1);
                // The service may continue validation while the failed producer
                // waits. This callback cannot invoke the consumed producer.
                events
                    .borrow_mut()
                    .push(("validation", "continued_until_cancel"));
            },
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(events.borrow().len(), 2);
        assert_eq!(events.borrow()[0], (failure.stage(), failure.code()));
        assert_eq!(result.unwrap_err(), "native_production_failed");
        assert!(!format!("{failure:?}").contains("private-path"));
    }
    assert_ne!(Failure::WorkerPool.code(), Failure::ProverInit.code());
    assert_ne!(Failure::PaddingProve.code(), Failure::ProveBlock.code());
}

#[test]
fn unannotated_error_is_unknown_independent_of_sensitive_contents() {
    for secret in [
        "prepare /private/location secret",
        "prover password",
        "commit key",
    ] {
        let mapped: Failure = secret.to_string().into();
        assert_eq!(mapped, Failure::Unknown);
        assert_eq!(mapped.stage(), "unknown");
        assert_eq!(mapped.code(), "unknown_production_failure");
    }
}

#[test]
fn successful_or_cancelled_producer_does_not_alarm_or_wait() {
    assert!(
        run_once(
            || Ok(()),
            |_| panic!("unexpected alarm"),
            || panic!("unexpected wait")
        )
        .is_ok()
    );
}

#[test]
#[should_panic(expected = "injected producer panic")]
fn panic_is_not_reported_as_a_returned_failure() {
    let _ = run_once(
        || panic!("injected producer panic"),
        |_| panic!("panic mislabeled"),
        || panic!("panic waited"),
    );
}
