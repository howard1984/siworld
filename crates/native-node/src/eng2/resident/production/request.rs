//! Optional Unix public-operation input; other platforms produce plain blocks.
//! This adapter cannot introduce operation input or signing keys on Windows.
use super::*;
use crate::{
    eng2::{driver::Head, execution::CommittedBlock},
    eng2_operations::PendingOperations,
    issuance::IssuanceRecord,
};

pub(super) struct Request<'a> {
    #[cfg(unix)]
    inner: Option<operations::Submission<'a>>,
    #[cfg(not(unix))]
    _context: std::marker::PhantomData<&'a Shared>,
}
impl<'a> Request<'a> {
    pub(super) fn take(shared: &'a Shared, head: &Head) -> Self {
        #[cfg(unix)]
        {
            Self {
                inner: shared.operations.as_ref().and_then(|mailbox| {
                    match mailbox.take(head, &shared.budget) {
                        Ok(value) => value,
                        Err(_) => {
                            mailbox.alarm();
                            None
                        }
                    }
                }),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (shared, head);
            Self {
                _context: std::marker::PhantomData,
            }
        }
    }
    pub(super) fn is_some(&self) -> bool {
        #[cfg(unix)]
        {
            self.inner.is_some()
        }
        #[cfg(not(unix))]
        {
            false
        }
    }
    pub(super) fn inputs(&mut self) -> Option<(Option<PendingOperations>, Vec<IssuanceRecord>)> {
        #[cfg(unix)]
        {
            self.inner.as_mut().map(operations::Submission::inputs)
        }
        #[cfg(not(unix))]
        {
            None
        }
    }
    pub(super) fn fail(&mut self, outcome: &'static str) {
        #[cfg(unix)]
        if let Some(request) = self.inner.as_mut() {
            request.fail(outcome);
        }
        #[cfg(not(unix))]
        let _ = outcome;
    }
    pub(super) fn committed(&mut self, committed: &CommittedBlock, store: &Store) {
        #[cfg(unix)]
        if let Some(request) = self.inner.as_mut() {
            request.committed(committed, store);
        }
        #[cfg(not(unix))]
        let _ = (committed, store);
    }
}
