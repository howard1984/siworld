//! Synthetic interface tests only; none establishes an actual native rejection.
use super::*;

#[test]
fn fetch_timing_never_changes_authenticated_frame_identity() {
    let body = b"bounded timing fixture";
    let header = header(body);
    let frame = FrameIdentity::after_authenticated_decode([9; 32], &header, body, 128).unwrap();
    let timed = frame.with_fetch_timing(FetchTiming {
        connection: 4,
        attempt: 7,
        ..FetchTiming::default()
    });
    assert_eq!(frame.frame_id(), timed.frame_id());
    assert!(timed.matches(&header));
    assert_eq!(timed.fetch.unwrap().attempt, 7);
}

#[test]
fn admission_timing_retention_and_commit_knowledge_are_bounded() {
    let mut observation = setup(Arc::new(Sink::default()));
    let body = b"bounded timing fixture";
    let header = header(body);
    let frame = FrameIdentity::after_authenticated_decode([9; 32], &header, body, 128).unwrap();
    for index in 0..12 {
        let attempt = observation.begin(&header, Some(frame));
        observation.completed(
            attempt.as_ref(),
            ValidationTiming::default(),
            if index == 11 { 3 } else { 1 },
        );
    }
    let value = observation.timing_json(Instant::now());
    assert_eq!(value["recent"].as_array().unwrap().len(), 8);
    assert_eq!(value["overwritten"], 4);
    assert_eq!(value["recent"][7]["outcome"], 3);
    assert!(diagnostic_storage_bytes() <= 8 * 1024);
}

#[test]
fn timing_completion_does_not_relabel_or_publish_product_failures() {
    let sink = Arc::new(Sink::default());
    let mut observation = setup(sink.clone());
    let body = b"bounded timing fixture";
    let header = header(body);
    let frame = FrameIdentity::after_authenticated_decode([9; 32], &header, body, 128).unwrap();
    let attempt = observation.begin(&header, Some(frame));
    let failure = Failure::other(
        "original writer failure".into(),
        OtherClass::Storage,
        Phase::Storage,
        CommitKnowledge::Unknown,
    );
    observation.completed(attempt.as_ref(), ValidationTiming::default(), 3);
    observation.rejected(attempt.as_ref(), &failure);
    assert_eq!(failure.into_original(), "original writer failure");
    assert!(sink.events.lock().unwrap().is_empty());
    observation.completed(attempt.as_ref(), ValidationTiming::default(), 4);
    assert_eq!(
        observation.timing_json(Instant::now())["recent"][1]["outcome"],
        4
    );
}
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Default)]
struct Sink {
    events: Mutex<Vec<(Hash, u64, Hash, &'static str)>>,
    fail: AtomicBool,
}
impl Observer for Sink {
    fn rejected(&self, event: &Rejection<'_>) -> Result<(), DiagnosticError> {
        if self.fail.load(Ordering::Relaxed) {
            return Err(DiagnosticError::Output);
        }
        self.events
            .lock()
            .map_err(|_| DiagnosticError::Output)?
            .push((
                event.run.run,
                event.attempt,
                event.frame.frame_id(),
                event.native.code(),
            ));
        Ok(())
    }
}
fn header(body: &[u8]) -> Header {
    Header {
        network: [1; 32],
        height: 7,
        parent: [2; 32],
        timestamp: 1,
        target: [3; 32],
        execution_commitment: [4; 32],
        body_commitment: super::super::header::body_commitment(body, 128).unwrap(),
        nonce: 0,
    }
}
fn setup(sink: Arc<Sink>) -> Observation {
    let mut observation = Observation::default();
    assert!(
        observation.attach(
            RunIdentity::from_resident(
                [1; 32],
                [2; 32],
                Some([3; 32]),
                &"4".repeat(64),
                &"5".repeat(64)
            )
            .unwrap(),
            sink
        )
    );
    observation
}
#[test]
fn synthetic_native_result_preserves_the_original_fixed_error() {
    for relation in [
        Relation::Transaction,
        Relation::LegacySettlement,
        Relation::Issuance,
    ] {
        let error = synthetic_native_failure(relation);
        assert_eq!(error.native_rejection().unwrap().relation(), relation);
        assert_eq!(error.commit(), CommitKnowledge::NotReached);
        assert_eq!(error.into_original(), relation.original_error());
    }
    assert_eq!(
        Failure::unclassified("unknown".into()).commit(),
        CommitKnowledge::Unknown
    );
}
#[test]
fn strings_and_non_native_failure_categories_cannot_create_a_native_token() {
    for class in [
        OtherClass::ProofStructure,
        OtherClass::CandidateValidation,
        OtherClass::Deferred,
        OtherClass::Timeout,
        OtherClass::Resource,
        OtherClass::WorkerUnavailable,
        OtherClass::ProtocolRead,
        OtherClass::Storage,
        OtherClass::Publication,
        OtherClass::Unclassified,
    ] {
        let original = Relation::Transaction.original_error().to_string();
        let error = Failure::other(
            original.clone(),
            class,
            Phase::Storage,
            CommitKnowledge::Unknown,
        );
        assert!(error.native_rejection().is_none());
        assert_eq!(error.into_original(), original);
    }
}
#[test]
fn complete_canonical_frame_binding_rejects_missing_or_changed_bytes() {
    let body = b"synthetic bounded body";
    let header = header(body);
    let frame = FrameIdentity::after_authenticated_decode([9; 32], &header, body, 128).unwrap();
    assert_eq!(frame.peer_id(), [9; 32]);
    assert_eq!(frame.header_id(), header.id().unwrap());
    assert_eq!(frame.body_bytes(), body.len() as u64);
    assert!(FrameIdentity::after_authenticated_decode([9; 32], &header, b"changed", 128).is_none());
    assert!(FrameIdentity::after_authenticated_decode([9; 32], &header, body, 2).is_none());
    let mut changed = header.clone();
    changed.nonce = 1;
    assert!(!frame.matches(&changed));
}
#[test]
fn run_binding_requires_complete_actual_startup_inputs() {
    assert!(
        RunIdentity::from_resident([1; 32], [2; 32], None, &"4".repeat(64), &"5".repeat(64))
            .is_none()
    );
    assert!(
        RunIdentity::from_resident(
            [1; 32],
            [2; 32],
            Some([3; 32]),
            &"A".repeat(64),
            &"5".repeat(64)
        )
        .is_none()
    );
    assert!(
        RunIdentity::from_resident([1; 32], [2; 32], Some([3; 32]), "short", &"5".repeat(64))
            .is_none()
    );
    let mut observation = setup(Arc::new(Sink::default()));
    let replacement = RunIdentity::from_resident(
        [1; 32],
        [2; 32],
        Some([3; 32]),
        &"6".repeat(64),
        &"5".repeat(64),
    )
    .unwrap();
    assert!(!observation.attach(replacement, Arc::new(Sink::default())));
    assert_eq!(observation.binding.as_ref().unwrap().run(), [0x44; 32]);
}
#[test]
fn synthetic_events_keep_run_frame_and_distinct_owner_attempts() {
    let sink = Arc::new(Sink::default());
    let mut observation = setup(sink.clone());
    let body = b"synthetic bounded body";
    let header = header(body);
    let frame = FrameIdentity::after_authenticated_decode([9; 32], &header, body, 128).unwrap();
    let first = observation.begin(&header, Some(frame)).unwrap();
    let second = observation.begin(&header, Some(frame)).unwrap();
    let failure = synthetic_native_failure(Relation::LegacySettlement);
    observation.rejected(Some(&first), &failure);
    observation.rejected(Some(&second), &failure);
    let events = sink.events.lock().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].0, [0x44; 32]);
    assert_eq!(events[0].2, frame.frame_id());
    assert_ne!(events[0].1, events[1].1);
}
#[test]
fn protocol_local_and_postcommit_failures_do_not_emit_native_rejection() {
    let sink = Arc::new(Sink::default());
    let mut observation = setup(sink.clone());
    let body = b"synthetic bounded body";
    let header = header(body);
    let frame = FrameIdentity::after_authenticated_decode([9; 32], &header, body, 128).unwrap();
    let attempt = observation.begin(&header, Some(frame)).unwrap();
    for (class, phase) in [
        (OtherClass::ProtocolRead, Phase::Protocol),
        (OtherClass::Publication, Phase::Publication),
    ] {
        for commit in [
            CommitKnowledge::NotReached,
            CommitKnowledge::Committed,
            CommitKnowledge::Unknown,
        ] {
            let failure = Failure::other(
                "native transaction proof verification failed".into(),
                class,
                phase,
                commit,
            );
            observation.rejected(Some(&attempt), &failure);
            assert_eq!(
                failure.into_original(),
                "native transaction proof verification failed"
            );
        }
    }
    assert!(sink.events.lock().unwrap().is_empty());
}
#[test]
fn native_evidence_outside_precommit_verification_does_not_emit() {
    let sink = Arc::new(Sink::default());
    let mut observation = setup(sink.clone());
    let body = b"synthetic bounded body";
    let header = header(body);
    let frame = FrameIdentity::after_authenticated_decode([9; 32], &header, body, 128).unwrap();
    let attempt = observation.begin(&header, Some(frame)).unwrap();
    for (phase, commit) in [
        (Phase::Execution, CommitKnowledge::NotReached),
        (Phase::NativeVerification, CommitKnowledge::Committed),
        (Phase::NativeVerification, CommitKnowledge::Unknown),
    ] {
        let mut failure = synthetic_native_failure(Relation::Transaction);
        failure.phase = phase;
        failure.commit = commit;
        observation.rejected(Some(&attempt), &failure);
        assert_eq!(
            failure.into_original(),
            "native transaction proof verification failed"
        );
    }
    assert!(sink.events.lock().unwrap().is_empty());
}
#[test]
fn diagnostic_output_failure_does_not_replace_or_consume_the_product_error() {
    let sink = Arc::new(Sink::default());
    sink.fail.store(true, Ordering::Relaxed);
    let mut observation = setup(sink.clone());
    let body = b"synthetic bounded body";
    let header = header(body);
    let frame = FrameIdentity::after_authenticated_decode([9; 32], &header, body, 128).unwrap();
    let attempt = observation.begin(&header, Some(frame)).unwrap();
    let failure = synthetic_native_failure(Relation::Issuance);
    observation.rejected(Some(&attempt), &failure);
    assert_eq!(observation.diagnostic(), (1, Some(DiagnosticError::Output)));
    assert_eq!(
        failure.into_original(),
        "native issuance proof verification failed"
    );
    assert!(sink.events.lock().unwrap().is_empty());
}
#[test]
fn absent_frame_and_exhausted_attempt_are_diagnostic_loss_only() {
    let sink = Arc::new(Sink::default());
    let mut observation = setup(sink.clone());
    let header = header(b"synthetic bounded body");
    assert!(observation.begin(&header, None).is_none());
    observation.sequence = u64::MAX;
    assert!(observation.begin(&header, None).is_none());
    assert_eq!(observation.diagnostic().0, 2);
    assert!(sink.events.lock().unwrap().is_empty());
}
