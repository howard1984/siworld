//! One-entry owner for private operations across cloneable configuration aliases.
//! The fence holds no RNG, seed or private backend and never clones one.
use std::sync::{Arc, Mutex, TryLockError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerError {
    Inactive,
    Active,
    Spent,
    Busy,
    Poisoned,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessError<E> {
    Owner(OwnerError),
    Backend(E),
}
#[derive(Clone, Copy)]
enum Phase {
    Ready,
    Active,
    Spent,
}

/// Only this non-Clone object may enter the attempt. Aliases cannot reopen it.
pub struct Owner {
    phase: Arc<Mutex<Phase>>,
}
/// Cloning shares one fence, with no access to the owner's entry operation.
pub struct Alias {
    phase: Arc<Mutex<Phase>>,
}
impl Clone for Alias {
    fn clone(&self) -> Self {
        Self {
            phase: Arc::clone(&self.phase),
        }
    }
}
struct Close {
    phase: Arc<Mutex<Phase>>,
}
impl Drop for Close {
    fn drop(&mut self) {
        // A panic in a private callback poisons the lock; retirement must still
        // close every alias. No poison recovery grants further private access.
        *self.phase.lock().unwrap_or_else(|e| e.into_inner()) = Phase::Spent;
    }
}
impl Owner {
    pub(crate) fn new() -> (Self, Alias) {
        let phase = Arc::new(Mutex::new(Phase::Ready));
        (
            Self {
                phase: Arc::clone(&phase),
            },
            Alias { phase },
        )
    }
    pub(crate) fn run<R>(&self, f: impl FnOnce() -> R) -> Result<R, OwnerError> {
        {
            let mut phase = self.phase.try_lock().map_err(lock_error)?;
            match *phase {
                Phase::Ready => *phase = Phase::Active,
                Phase::Active => return Err(OwnerError::Active),
                Phase::Spent => return Err(OwnerError::Spent),
            }
        }
        let _close = Close {
            phase: Arc::clone(&self.phase),
        };
        Ok(f())
    }
}
fn lock_error<T>(error: TryLockError<T>) -> OwnerError {
    match error {
        TryLockError::WouldBlock => OwnerError::Busy,
        TryLockError::Poisoned(_) => OwnerError::Poisoned,
    }
}
impl Alias {
    /// Trusted PCS adapter entry only. The backend remains encapsulated by the
    /// adapter; no method exposes an RNG, seed, clone operation or mutable PCS.
    /// Rejected access never invokes the callback or consumes private entropy.
    /// Backend preflight errors retain the upstream retry semantics. Successful
    /// final opening retires all aliases before its result leaves this call.
    pub(crate) fn access<T, E>(
        &self,
        final_open: bool,
        f: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, AccessError<E>> {
        let mut phase = self
            .phase
            .try_lock()
            .map_err(|e| AccessError::Owner(lock_error(e)))?;
        match *phase {
            Phase::Ready => return Err(AccessError::Owner(OwnerError::Inactive)),
            Phase::Spent => return Err(AccessError::Owner(OwnerError::Spent)),
            Phase::Active => {}
        }
        let result = f().map_err(AccessError::Backend);
        if final_open && result.is_ok() {
            *phase = Phase::Spent;
        }
        result
    }
}
