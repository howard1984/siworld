//! Task-owned allocation failures captured at the failed admission.
use crate::p2p::{Budget, Reservation};
#[cfg(any(test, feature = "eng2-runtime"))]
use crate::p2p::{ByteUsage, ReserveFailure};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Operation {
    #[cfg(any(test, feature = "eng2-runtime"))]
    RetainedArtifact,
    #[cfg(any(test, feature = "eng2-runtime"))]
    ReaderMetadata,
    ArchivePreparation,
    #[cfg(any(test, feature = "eng2-runtime"))]
    CaptureContext,
    #[cfg(any(test, feature = "eng2-runtime"))]
    RestoreContext,
    #[cfg(any(test, feature = "eng2-runtime"))]
    RetainedAllocation,
}
impl Operation {
    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::RetainedArtifact => "retained_artifact",
            Self::ReaderMetadata => "retained_reader_metadata",
            Self::ArchivePreparation => "archive_preparation",
            Self::CaptureContext => "capture_context",
            Self::RestoreContext => "restore_context",
            Self::RetainedAllocation => "retained_allocation",
        }
    }
    #[cfg(any(test, feature = "eng2-runtime"))]
    fn classify(message: &str) -> Option<Self> {
        match message {
            "checkpoint retained artifact budget unavailable" => Some(Self::RetainedArtifact),
            "checkpoint retained reader metadata budget unavailable" => Some(Self::ReaderMetadata),
            "checkpoint archive preparation budget unavailable" => Some(Self::ArchivePreparation),
            "checkpoint capture context budget unavailable" => Some(Self::CaptureContext),
            "checkpoint restore context budget unavailable" => Some(Self::RestoreContext),
            "checkpoint retained allocation failed" => Some(Self::RetainedAllocation),
            _ => None,
        }
    }
}
#[cfg(any(test, feature = "eng2-runtime"))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct Failure {
    pub operation: Operation,
    pub requested: Option<usize>,
    pub failure: Option<ReserveFailure>,
}
#[cfg(any(test, feature = "eng2-runtime"))]
impl Failure {
    pub(crate) fn reason(self) -> Option<&'static str> {
        match self.failure {
            Some(ReserveFailure::Exhausted(_)) => Some("exhausted"),
            Some(ReserveFailure::Overflow) => Some("overflow"),
            Some(ReserveFailure::Unavailable) => Some("unavailable"),
            None if self.operation == Operation::RetainedAllocation => Some("allocation_failed"),
            None => None,
        }
    }
    pub(crate) fn usage(self) -> Option<ByteUsage> {
        match self.failure {
            Some(ReserveFailure::Exhausted(usage)) => Some(usage),
            _ => None,
        }
    }
}
/// Carries the original error text and only the failure owned by this call.
/// Conversion at an existing String boundary preserves the exact error text.
#[derive(Debug)]
pub(crate) struct Error {
    message: String,
    #[cfg(any(test, feature = "eng2-runtime"))]
    pub budget: Option<Failure>,
}
impl Error {
    #[cfg(any(test, feature = "eng2-runtime"))]
    pub(crate) fn allocation(requested: usize) -> Self {
        Self {
            message: "checkpoint retained allocation failed".into(),
            budget: Some(Failure {
                operation: Operation::RetainedAllocation,
                requested: Some(requested),
                failure: None,
            }),
        }
    }
}
impl From<String> for Error {
    fn from(message: String) -> Self {
        #[cfg(any(test, feature = "eng2-runtime"))]
        let budget = Operation::classify(&message).map(|operation| Failure {
            operation,
            requested: None,
            failure: None,
        });
        Self {
            message,
            #[cfg(any(test, feature = "eng2-runtime"))]
            budget,
        }
    }
}
impl From<&str> for Error {
    fn from(message: &str) -> Self {
        message.to_owned().into()
    }
}
impl From<Error> for String {
    fn from(error: Error) -> Self {
        error.message
    }
}
impl std::ops::Deref for Error {
    type Target = str;
    fn deref(&self) -> &str {
        &self.message
    }
}
impl PartialEq<&str> for Error {
    fn eq(&self, other: &&str) -> bool {
        self.message == *other
    }
}
pub(crate) fn reserve(
    budget: &Budget,
    requested: usize,
    operation: Operation,
    message: &'static str,
) -> Result<Reservation, Error> {
    budget
        .reserve_observed(requested)
        .map(|(reservation, _)| reservation)
        .map_err(|failure| {
            #[cfg(not(any(test, feature = "eng2-runtime")))]
            let _ = (operation, failure);
            Error {
                message: message.into(),
                #[cfg(any(test, feature = "eng2-runtime"))]
                budget: Some(Failure {
                    operation,
                    requested: Some(requested),
                    failure: Some(failure),
                }),
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn concurrent_failures_remain_owned_by_each_call() {
        use std::sync::mpsc;
        let budget = Budget::new(1024 * 1024 * 1024);
        let held = budget.reserve(1024 * 1024 * 1024 - 7).unwrap();
        let (tx, rx) = mpsc::sync_channel(1);
        let other = budget.clone();
        let task = std::thread::spawn(move || {
            let error = reserve(
                &other,
                8,
                Operation::RetainedArtifact,
                "checkpoint retained artifact budget unavailable",
            )
            .unwrap_err();
            tx.send(error).unwrap();
        });
        let retained = rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        let unrelated = reserve(
            &budget,
            900,
            Operation::ArchivePreparation,
            "checkpoint archive preparation budget unavailable",
        )
        .unwrap_err();
        task.join().unwrap();
        drop(held);
        let observed = retained.budget.unwrap();
        assert_eq!(observed.operation, Operation::RetainedArtifact);
        assert_eq!(observed.requested, Some(8));
        assert_eq!(
            observed.usage().unwrap(),
            ByteUsage {
                maximum: 1024 * 1024 * 1024,
                used: 1024 * 1024 * 1024 - 7
            }
        );
        assert_eq!(unrelated.budget.unwrap().requested, Some(900));
        assert_eq!(budget.available().unwrap(), 1024 * 1024 * 1024);
    }
    #[test]
    fn overflow_unavailable_and_allocator_errors_never_invent_usage() {
        let budget = Budget::new(usize::MAX);
        let held = budget.reserve(1).unwrap();
        let overflow = reserve(
            &budget,
            usize::MAX,
            Operation::RetainedArtifact,
            "checkpoint retained artifact budget unavailable",
        )
        .unwrap_err()
        .budget
        .unwrap();
        assert_eq!(overflow.reason(), Some("overflow"));
        assert_eq!(overflow.usage(), None);
        let unavailable = Failure {
            operation: Operation::ReaderMetadata,
            requested: Some(64 * 1024),
            failure: Some(ReserveFailure::Unavailable),
        };
        assert_eq!(unavailable.reason(), Some("unavailable"));
        assert_eq!(unavailable.usage(), None);
        let allocator = Error::allocation(123).budget.unwrap();
        assert_eq!(allocator.operation, Operation::RetainedAllocation);
        assert_eq!(allocator.requested, Some(123));
        assert_eq!(allocator.reason(), Some("allocation_failed"));
        assert_eq!(allocator.usage(), None);
        drop(held);
    }
    #[test]
    fn string_boundaries_preserve_text_without_inventing_counters() {
        for (message, operation) in [
            (
                "checkpoint retained artifact budget unavailable",
                Operation::RetainedArtifact,
            ),
            (
                "checkpoint retained reader metadata budget unavailable",
                Operation::ReaderMetadata,
            ),
            (
                "checkpoint archive preparation budget unavailable",
                Operation::ArchivePreparation,
            ),
            (
                "checkpoint capture context budget unavailable",
                Operation::CaptureContext,
            ),
            (
                "checkpoint restore context budget unavailable",
                Operation::RestoreContext,
            ),
            (
                "checkpoint retained allocation failed",
                Operation::RetainedAllocation,
            ),
        ] {
            let error = Error::from(message);
            let failure = error.budget.unwrap();
            assert_eq!(failure.operation, operation);
            assert_eq!(failure.requested, None);
            assert_eq!(failure.usage(), None);
            assert_eq!(String::from(error), message);
        }
        let secret = "synthetic private/path credential=example";
        let error = Error::from(secret);
        assert!(error.budget.is_none());
        assert_eq!(String::from(error), secret);
        let budget = Budget::new(100);
        let guard = reserve(
            &budget,
            100,
            Operation::RetainedArtifact,
            "checkpoint retained artifact budget unavailable",
        )
        .unwrap();
        assert_eq!(budget.available().unwrap(), 0);
        drop(guard);
        assert_eq!(budget.available().unwrap(), 100);
    }
}
