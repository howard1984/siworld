//! An observational service-node budget. It never gates writes or validation.
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

pub const NODE_LIMIT_BYTES: u64 = 200_000_000_000;
static AUXILIARY_WRITER: Mutex<()> = Mutex::new(());

pub(crate) fn budget_exceeded(role: Option<crate::storage_policy::Role>, bytes: u64) -> bool {
    role.is_some_and(crate::storage_policy::Role::serves_historical_proofs)
        && bytes >= NODE_LIMIT_BYTES
}

/// Serialize auxiliary writers without imposing a capacity admission threshold.
/// File I/O failures still propagate from the actual write operation.
pub(crate) fn auxiliary_write(
    _path: &Path,
    _additional: u64,
    _status: bool,
) -> Result<MutexGuard<'static, ()>, String> {
    AUXILIARY_WRITER
        .lock()
        .map_err(|_| "storage writer lock poisoned".into())
}

#[cfg(test)]
mod fault_injection {
    use redb::{BackendError, StorageBackend, backends::FileBackend};
    use std::{
        fs::File,
        io,
        ops::Bound,
        sync::{
            Arc, Mutex,
            atomic::{AtomicU64, Ordering},
        },
    };
    const CAPACITY_ERROR: &str = "injected write failure";
    #[derive(Debug)]
    struct RoleBudget {
        limit: AtomicU64,
    }
    #[derive(Debug)]
    pub(crate) struct CappedBackend {
        inner: FileBackend,
        budget: Arc<RoleBudget>,
        growth: Mutex<()>,
    }
    impl CappedBackend {
        fn for_role(file: File, budget: Arc<RoleBudget>) -> io::Result<Self> {
            if file.metadata()?.len() > budget.limit.load(Ordering::Acquire) {
                return Err(io::Error::other(CAPACITY_ERROR));
            }
            Ok(Self {
                inner: FileBackend::new(file)
                    .map_err(|_| io::Error::other("database backend unavailable"))?,
                budget,
                growth: Mutex::new(()),
            })
        }
        #[cfg(test)]
        pub(crate) fn with_limit(file: File, limit: u64) -> io::Result<Self> {
            Self::for_role(
                file,
                Arc::new(RoleBudget {
                    limit: AtomicU64::new(limit),
                }),
            )
        }
        fn check(&self, length: u64) -> io::Result<()> {
            if length > self.budget.limit.load(Ordering::Acquire) {
                Err(io::Error::other(CAPACITY_ERROR))
            } else {
                Ok(())
            }
        }
    }
    impl StorageBackend for CappedBackend {
        fn len(&self) -> io::Result<u64> {
            self.inner.len()
        }
        fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
            self.inner.read(offset, out)
        }
        fn set_len(&self, len: u64) -> io::Result<()> {
            let _guard = self
                .growth
                .lock()
                .map_err(|_| io::Error::other("storage growth lock poisoned"))?;
            self.check(len)?;
            self.inner.set_len(len)
        }
        fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
            let _guard = self
                .growth
                .lock()
                .map_err(|_| io::Error::other("storage growth lock poisoned"))?;
            let end = offset
                .checked_add(data.len() as u64)
                .ok_or_else(|| io::Error::other(CAPACITY_ERROR))?;
            self.check(end)?;
            // redb must explicitly grow before writing, including sparse writes.
            if end > self.inner.len()? {
                return Err(io::Error::other("database write exceeds reserved length"));
            }
            self.inner.write(offset, data)
        }
        fn sync_data(&self) -> io::Result<()> {
            self.inner.sync_data()
        }
        fn close(&self) -> io::Result<()> {
            self.inner.close()
        }
        fn try_lock_range(&self, start: Bound<u64>, end: Bound<u64>) -> Result<bool, BackendError> {
            self.inner.try_lock_range(start, end)
        }
        fn try_lock_shared_range(
            &self,
            start: Bound<u64>,
            end: Bound<u64>,
        ) -> Result<bool, BackendError> {
            self.inner.try_lock_shared_range(start, end)
        }
        fn lock_range(&self, start: Bound<u64>, end: Bound<u64>) -> Result<(), BackendError> {
            self.inner.lock_range(start, end)
        }
        fn lock_shared_range(
            &self,
            start: Bound<u64>,
            end: Bound<u64>,
        ) -> Result<(), BackendError> {
            self.inner.lock_shared_range(start, end)
        }
        fn unlock_range(&self, start: Bound<u64>, end: Bound<u64>) -> Result<(), BackendError> {
            self.inner.unlock_range(start, end)
        }
        fn query_lock_range(
            &self,
            start: Bound<u64>,
            end: Bound<u64>,
        ) -> Result<bool, BackendError> {
            self.inner.query_lock_range(start, end)
        }
    }
}
#[cfg(test)]
pub(crate) use fault_injection::CappedBackend;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage_policy::Role;
    #[test]
    fn budget_alarm_is_role_scoped_at_the_exact_boundary() {
        for role in [Role::Bootstrap, Role::Validator] {
            assert!(!budget_exceeded(Some(role), NODE_LIMIT_BYTES - 1));
            assert!(budget_exceeded(Some(role), NODE_LIMIT_BYTES));
            assert!(budget_exceeded(Some(role), u64::MAX));
        }
        for role in [None, Some(Role::Miner), Some(Role::Ordinary)] {
            assert!(!budget_exceeded(role, u64::MAX));
        }
    }
}
