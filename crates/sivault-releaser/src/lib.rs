//! Noncredential transcript metadata and releaser admission policy.
//!
//! This crate implements no authentication, credential evaluation, proof,
//! wrapping, networking, or persistent storage. Authentication and a tested,
//! exclusive, rollback-resistant [`ledger::DurableAuthority`] are required
//! integration boundaries. A filesystem snapshot is not such an authority.

pub mod ledger;
pub mod message;
pub mod scheduler;
