//! Bounded transfer primitives authenticated by the existing body commitment.
//!
//! Transfer authentication does not establish native proof validity or authorize
//! canonical adoption. All assembled bodies still require normal admission.

pub mod authentication;
pub mod framing;
pub mod pipeline;
pub mod wire;
