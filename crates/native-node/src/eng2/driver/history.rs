use super::*;
use crate::eng2::{branches, historical, store};

impl Driver {
    pub(crate) fn historical_slot(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        self.historical_active.clone()
    }
    /// Caller holds the existing owner mutex. No path traversal, frame read,
    /// hashing, independent verification or database writer is opened here.
    pub(crate) fn capture_history(
        &self,
    ) -> historical::Result<(store::history::Read, Option<branches::history::Read>)> {
        let canonical = self.store.historical_read()?;
        let branches = self
            .reorganization
            .as_ref()
            .map(|r| r.branches.historical_read())
            .transpose()?;
        Ok((canonical, branches))
    }
}
