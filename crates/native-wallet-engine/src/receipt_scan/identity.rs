//! Closed host-local identity interface. No real custody backend is provided.
#[cfg(feature = "receipt-scan-synthetic")]
use super::Error;
use super::Result;
use crate::{eng2_light::Eng2LightState, wire::Hash};

pub(crate) mod sealed {
    pub trait Sealed {}
}

/// A backend creates fresh private scan state without exporting its seed.
pub trait WithLocalScanIdentity: sealed::Sealed {
    fn fresh(&self, genesis: &[u8], genesis_id: Hash) -> Result<Eng2LightState>;
    fn synthetic_only(&self) -> bool;
}

/// Publicly reproducible disposable identity, unavailable without opt-in.
#[cfg(feature = "receipt-scan-synthetic")]
pub struct SyntheticCustody {
    network: Hash,
}
#[cfg(feature = "receipt-scan-synthetic")]
impl SyntheticCustody {
    pub(crate) fn new(network: Hash) -> Self {
        Self { network }
    }
}
#[cfg(feature = "receipt-scan-synthetic")]
impl sealed::Sealed for SyntheticCustody {}
#[cfg(feature = "receipt-scan-synthetic")]
impl WithLocalScanIdentity for SyntheticCustody {
    fn fresh(&self, genesis: &[u8], genesis_id: Hash) -> Result<Eng2LightState> {
        let context = crate::eng2_history::Context::from_genesis(genesis, genesis_id)
            .map_err(|_| Error::Incomplete("identity_context"))?;
        if context.config().network != self.network || !context.config().fixture {
            return Err(Error::Incomplete("identity_network"));
        }
        Eng2LightState::new(genesis, genesis_id, zeroize::Zeroizing::new([42; 32]), 0)
            .map_err(|_| Error::Incomplete("identity_derivation"))
    }
    fn synthetic_only(&self) -> bool {
        true
    }
}
