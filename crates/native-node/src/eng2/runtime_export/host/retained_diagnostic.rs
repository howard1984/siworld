//! Bounded observations without an authentication or readiness capability.
use serde_json::{Value, json};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Stage {
    WorkerState,
    Complete,
    Revision,
    Install,
    Drain,
    Headers,
    Capture,
    Votes,
    Start,
    StaleWithdrawal,
}
impl Stage {
    fn code(self) -> &'static str {
        match self {
            Self::WorkerState => "worker_state",
            Self::Complete => "worker_completion",
            Self::Revision => "revision_check",
            Self::Install => "installation",
            Self::Drain => "preparation_drain",
            Self::Headers => "header_capture",
            Self::Capture => "material_capture",
            Self::Votes => "vote_binding",
            Self::Start => "worker_start",
            Self::StaleWithdrawal => "stale_result_withdrawal",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cause {
    Generation,
    Revision,
    Cursor,
    Signature,
    NativeSnapshot,
    MissingOwner,
    Worker,
    Cancelled,
    Budget,
    Read,
    MaterialChanged,
    Context,
    Unknown,
}
impl Cause {
    pub(super) fn classify(error: &str) -> Self {
        match error {
            "checkpoint retained restoration generation changed" => Self::Generation,
            "checkpoint captured canonical revision changed"
            | "checkpoint canonical revision moved backward" => Self::Revision,
            "checkpoint publication cursor malformed"
            | "checkpoint publication cursor must be an object" => Self::Cursor,
            "checkpoint publication signatures invalid"
            | "saved checkpoint vote signature invalid" => Self::Signature,
            "saved checkpoint snapshot differs from complete native reconstruction" => {
                Self::NativeSnapshot
            }
            "checkpoint reuse owner disappeared"
            | "checkpoint live reuse owner disappeared"
            | "checkpoint live reuse ownership changed" => Self::MissingOwner,
            "checkpoint worker unavailable"
            | "checkpoint worker disappeared"
            | "checkpoint archive worker panicked"
            | "checkpoint archive worker creation failed" => Self::Worker,
            "checkpoint retained restoration cancelled"
            | "checkpoint archive preparation cancelled" => Self::Cancelled,
            "checkpoint retained artifact budget unavailable"
            | "checkpoint retained reader metadata budget unavailable"
            | "checkpoint archive preparation budget unavailable"
            | "checkpoint capture context budget unavailable"
            | "checkpoint retained allocation failed" => Self::Budget,
            "checkpoint retained artifact open failed"
            | "checkpoint retained artifact read failed"
            | "checkpoint retained trailing read failed"
            | "checkpoint retained metadata unavailable" => Self::Read,
            "checkpoint retained artifact changed while reading"
            | "checkpoint retained artifact length changed"
            | "checkpoint original certificate or publication time changed" => {
                Self::MaterialChanged
            }
            "saved checkpoint has invalid captured context or byte bound"
            | "checkpoint publication cursor differs from the export context" => Self::Context,
            _ => Self::Unknown,
        }
    }
    pub(super) fn code(self) -> &'static str {
        match self {
            Self::Generation => "generation_changed",
            Self::Revision => "revision_changed",
            Self::Cursor => "cursor_malformed",
            Self::Signature => "signature_invalid",
            Self::NativeSnapshot => "native_snapshot_mismatch",
            Self::MissingOwner => "reuse_owner_changed",
            Self::Worker => "worker_unavailable",
            Self::Cancelled => "cancelled",
            Self::Budget => "budget_unavailable",
            Self::Read => "artifact_read_failed",
            Self::MaterialChanged => "material_changed",
            Self::Context => "context_invalid",
            Self::Unknown => "unknown",
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub(super) struct Failure {
    pub sequence: u64,
    pub stage: Stage,
    pub cause: Cause,
    pub generation_mismatches: u8,
    pub withdrawal: Option<Cause>,
}
impl Failure {
    pub(super) fn json(self) -> Value {
        json!({"scope":"last_retained_failure","sequence":self.sequence,"stage":self.stage.code(),"code":self.cause.code(),
            "worker_generation_changed":self.generation_mismatches&1!=0,
            "material_generation_changed":self.generation_mismatches&2!=0,
            "retirement_changed":self.generation_mismatches&4!=0,
            "withdrawal_error":self.withdrawal.map(Cause::code)})
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn arbitrary_failure_text_never_enters_diagnostics() {
        let error = "private/path secret=synthetic-only endpoint=synthetic-only";
        let json = Failure {
            sequence: 1,
            stage: Stage::Complete,
            cause: Cause::classify(error),
            generation_mismatches: 0,
            withdrawal: None,
        }
        .json();
        assert_eq!(json["code"], "unknown");
        assert!(!json.to_string().contains(error));
        assert!(json.to_string().len() < 512);
    }
}
