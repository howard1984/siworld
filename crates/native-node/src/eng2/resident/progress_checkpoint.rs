//! Checkpoint failures block progress telemetry until a complete successful tick.
//! Transfer events remain separate from readiness, signing, and health policy.
use super::header_lane::Hub;

#[derive(Default)]
pub(super) struct State {
    blocked: bool,
}

impl State {
    #[cfg(any(unix, test))]
    pub(super) fn restoration(&mut self, headers: &Hub, failed: bool) {
        if failed {
            self.failed(headers);
        }
    }

    #[cfg(any(unix, test))]
    pub(super) fn failed(&mut self, headers: &Hub) {
        self.blocked = true;
        headers.invalidate_progress_context();
    }

    // Called only after both restoration and the checkpoint tick succeed,
    // including any required bootstrap refresh.
    #[cfg(any(unix, test))]
    pub(super) fn recovered(&mut self) {
        self.blocked = false;
    }

    pub(super) fn publish(&self, headers: &Hub, owner_eligible: bool, error: Option<&str>) {
        headers.publish_progress_context(
            owner_eligible
                && !self.blocked
                && matches!(
                    error,
                    None | Some("checkpoint_retained_restoration_pending")
                ),
        );
    }
}
