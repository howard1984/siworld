//! Bounded production diagnostics. No underlying error text is retained.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) enum Failure {
    Budget,
    WorkerPool,
    ProverInit,
    RehearsalControl,
    ProductionControl,
    Readiness,
    OwnerAccess,
    StatusUpdate,
    PaddingPrepare,
    PaddingProve,
    PaddingInsert,
    PrepareClock,
    PrepareHead,
    PrepareBlock,
    ProveBlock,
    WorkHead,
    WorkPrepare,
    WorkSearch,
    WorkProgress,
    CommitHead,
    CommitBlock,
    RewardWrite,
    Unknown,
}

impl Failure {
    pub(in super::super) fn stage(self) -> &'static str {
        match self {
            Self::Budget => "budget",
            Self::WorkerPool | Self::ProverInit => "initialization",
            Self::RehearsalControl
            | Self::ProductionControl
            | Self::Readiness
            | Self::OwnerAccess => "control",
            Self::StatusUpdate => "status",
            Self::PaddingPrepare | Self::PaddingProve | Self::PaddingInsert => "padding",
            Self::PrepareClock | Self::PrepareHead | Self::PrepareBlock => "prepare",
            Self::ProveBlock => "prove",
            Self::WorkHead | Self::WorkPrepare | Self::WorkSearch | Self::WorkProgress => "work",
            Self::CommitHead | Self::CommitBlock => "commit",
            Self::RewardWrite => "reward",
            Self::Unknown => "unknown",
        }
    }
    pub(in super::super) fn code(self) -> &'static str {
        match self {
            Self::Budget => "budget_reservation_failed",
            Self::WorkerPool => "worker_pool_initialization_failed",
            Self::ProverInit => "prover_initialization_failed",
            Self::RehearsalControl => "rehearsal_budget_control_failed",
            Self::ProductionControl => "production_control_failed",
            Self::Readiness => "readiness_check_failed",
            Self::OwnerAccess => "owner_access_failed",
            Self::StatusUpdate => "status_update_failed",
            Self::PaddingPrepare => "padding_preparation_failed",
            Self::PaddingProve => "padding_proof_failed",
            Self::PaddingInsert => "padding_insertion_failed",
            Self::PrepareClock => "block_timestamp_failed",
            Self::PrepareHead => "preparation_head_failed",
            Self::PrepareBlock => "block_preparation_failed",
            Self::ProveBlock => "block_proof_failed",
            Self::WorkHead => "work_head_failed",
            Self::WorkPrepare => "work_preparation_failed",
            Self::WorkSearch => "work_search_failed",
            Self::WorkProgress => "work_progress_failed",
            Self::CommitHead => "commit_head_failed",
            Self::CommitBlock => "block_commit_failed",
            Self::RewardWrite => "reward_receipt_write_failed",
            Self::Unknown => "unknown_production_failure",
        }
    }
}

// Unannotated String/str propagation remains explicitly unknown, never inferred
// from the last phase or an unstable substring of an underlying error.
impl From<String> for Failure {
    fn from(_: String) -> Self {
        Self::Unknown
    }
}
impl From<&str> for Failure {
    fn from(_: &str) -> Self {
        Self::Unknown
    }
}

// The producer is invoked once. After a returned error, the caller keeps the
// validation service alive until cancellation without retrying production.
// Panics are not caught or reported as returned failures.
pub(super) fn run_once(
    produce: impl FnOnce() -> Result<(), Failure>,
    alarm: impl FnOnce(Failure),
    wait_for_cancel: impl FnOnce(),
) -> Result<(), String> {
    match produce() {
        Ok(()) => Ok(()),
        Err(failure) => {
            alarm(failure);
            wait_for_cancel();
            Err("native_production_failed".into())
        }
    }
}

#[cfg(test)]
mod tests;
