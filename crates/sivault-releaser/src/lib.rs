//! Noncredential transcript metadata and releaser admission policy.
//!
//! The native journal persists admission metadata and checks an independent
//! checkpoint for best-effort restore detection. The calling protocol is
//! responsible for authentication and credential evaluation.

pub mod ipc;
#[cfg(not(target_arch = "wasm32"))]
pub mod journal;
pub mod ledger;
pub mod message;
#[cfg(not(target_arch = "wasm32"))]
pub mod opening;
#[cfg(not(target_arch = "wasm32"))]
pub mod registration;
pub mod scheduler;
#[cfg(not(target_arch = "wasm32"))]
pub mod transport;
