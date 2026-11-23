use super::*;

#[test]
fn watchdog_retries_only_work_that_cannot_have_published_a_template() {
    use crate::eng2::producer::PrepareError;
    use crate::pool::FillError;
    use crate::producer::CandidateError;

    for failure in [
        Failure::PrepareBlock(PrepareBlockError::Candidate(PrepareError::Candidate(
            CandidateError::NullifierCollision,
        ))),
        Failure::PrepareBlock(PrepareBlockError::Padding(FillError::Insufficient {
            required: 4,
        })),
        Failure::PaddingProve,
        Failure::ProveBlock,
        Failure::WorkPrepare,
        Failure::WorkSearch,
    ] {
        assert!(failure.permits_watchdog_retry(), "{failure:?}");
    }
    for failure in [
        Failure::WorkerPool,
        Failure::ProverInit,
        Failure::PaddingPrepare,
        Failure::PrepareBlock(PrepareBlockError::Pending),
        Failure::PrepareBlock(PrepareBlockError::Candidate(PrepareError::Candidate(
            CandidateError::OpeningMismatch,
        ))),
        Failure::PrepareBlock(PrepareBlockError::Candidate(PrepareError::FeeMode)),
        Failure::PrepareBlock(PrepareBlockError::Padding(FillError::PrivateTemplateActive)),
        Failure::HeaderPublish,
        Failure::CommitBlock,
        Failure::RewardWrite,
        Failure::Unknown,
    ] {
        assert!(!failure.permits_watchdog_retry(), "{failure:?}");
    }
}

#[test]
fn preparation_diagnostic_keeps_the_typed_underlying_failure() {
    use crate::eng2::producer::PrepareError;
    use crate::pool::FillError;
    use crate::producer::CandidateError;

    let failure =
        Failure::PrepareBlock(PrepareBlockError::Padding(FillError::ReservationsExhausted));
    assert_eq!(failure.stage(), "prepare");
    assert_eq!(failure.code(), "production_padding_reservations_exhausted");
    assert_ne!(
        failure.code(),
        Failure::PrepareBlock(PrepareBlockError::Pending).code()
    );
    let failure = Failure::PrepareBlock(PrepareBlockError::Candidate(PrepareError::Candidate(
        CandidateError::NullifierCollision,
    )));
    assert_eq!(failure.code(), "production_candidate_nullifier_collision");
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
