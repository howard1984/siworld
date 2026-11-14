//! Inactive public-statement adapter for an isolated CompleteFee verifier.
//!
//! The caller selects a locally pinned factory and executable. Neither request
//! bytes nor a receipt select keys, register a network or admit a state delta.
//! Setup and verification run only inside the guarded child, outside owner locks.

mod canonical;
pub mod owner;
pub use canonical::MAX_STATEMENT_BYTES;

use super::fee_candidate::NativeCheckedFeeInputs;
use crate::proof_codec::v2::{
    self, Identity, MAX_FEE_PROOF_BYTES, ProtocolBinding, Relation, batch,
    complete_fee::{self, StatementInputs},
    fee_guard::{
        self, ChildCommand, ChildInput, ChildVerdict, DeclaredLength, FeeGuard, Outcome,
        RequestBinding, VerificationInput,
    },
};
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Allocation,
    Encoding,
    PublicStatement,
    LocalConfiguration,
    InputBinding,
    Frame,
    Setup,
    Receipt,
}

/// Configuration supplied by the fixed local adapter, not the request file.
/// Constructing this value does not authenticate or register that configuration.
/// The expected profile must already be independently pinned for these rules.
#[derive(Clone, Copy)]
pub struct TrustedFactory {
    network: [u8; 32],
    binding: ProtocolBinding,
    expected: Identity,
}
impl TrustedFactory {
    pub fn from_local_configuration(
        network: [u8; 32],
        binding: ProtocolBinding,
        expected: Identity,
    ) -> Result<Self, Error> {
        if network == [0; 32]
            || binding.genesis == [0; 32]
            || binding.rules == [0; 32]
            || binding.air != complete_fee::source_identity()
            || expected.relation != Relation::CompleteFee
            || expected.profile == [0; 32]
        {
            return Err(Error::LocalConfiguration);
        }
        Ok(Self {
            network,
            binding,
            expected,
        })
    }

    pub fn identity(&self) -> Identity {
        self.expected
    }

    /// Prepare from the private native-checked capability. This performs no
    /// preprocessing setup or proof verification and grants no admission power.
    /// `canonical_context` is captured by the canonical owner, not a peer field.
    pub fn prepare<'a, 'b>(
        &self,
        checked: &'a NativeCheckedFeeInputs<'b>,
        attempt: [u8; 32],
        canonical_context: [u8; 32],
    ) -> Result<PreparedRequest<'a, 'b>, Error> {
        if checked.native_checked().header().network != self.network
            || checked.protocol_binding() != self.binding
            || attempt == [0; 32]
            || canonical_context == [0; 32]
        {
            return Err(Error::InputBinding);
        }
        // Bind the one frame already held by the checked body. Another proof,
        // even for the same public statement, cannot replace that body field.
        let proof = checked.native_checked().body().settlement_proof.as_slice();
        let declared =
            fee_guard::preflight_declared_length(proof.len() as u64).map_err(|_| Error::Frame)?;
        v2::parse(proof, self.expected, MAX_FEE_PROOF_BYTES).map_err(|_| Error::Frame)?;
        let statement = checked.canonical_child_statement()?;
        let binding = RequestBinding {
            attempt,
            network: self.network,
            genesis: self.binding.genesis,
            rules: self.binding.rules,
            profile: self.expected.profile,
            // The existing composite profile commits to the locally trusted
            // preprocessing key and shape as well as AIR, genesis and rules.
            // Reuse that identity; introduce no separate key-selection scheme.
            verifier_keys: self.expected.profile,
            statement: fee_guard::statement_digest(&statement),
            proof: fee_guard::proof_digest(proof),
            canonical_context,
        };
        Ok(PreparedRequest {
            _checked: checked,
            declared,
            proof,
            statement,
            binding,
        })
    }

    fn preflight(&self, input: &ChildInput) -> Result<canonical::PublicStatement, Error> {
        if input.statement.is_empty()
            || input.statement.len() > MAX_STATEMENT_BYTES
            || fee_guard::preflight_declared_length(input.proof.len() as u64).is_err()
        {
            return Err(Error::InputBinding);
        }
        let binding = &input.binding;
        if binding.attempt == [0; 32]
            || binding.canonical_context == [0; 32]
            || binding.network != self.network
            || binding.genesis != self.binding.genesis
            || binding.rules != self.binding.rules
            || binding.profile != self.expected.profile
            || binding.verifier_keys != self.expected.profile
            || binding.proof != fee_guard::proof_digest(&input.proof)
            || binding.statement != fee_guard::statement_digest(&input.statement)
        {
            return Err(Error::InputBinding);
        }
        v2::parse(&input.proof, self.expected, MAX_FEE_PROOF_BYTES).map_err(|_| Error::Frame)?;
        let statement = canonical::decode(&input.statement)?;
        if statement.network() != self.network {
            return Err(Error::InputBinding);
        }
        Ok(statement)
    }

    /// Call only in the fixed guarded child. This rebuilds the existing complete
    /// preprocessing and can allocate substantially more than the input codec.
    /// Local setup/configuration failures yield no semantic rejection receipt.
    pub fn verify_child(&self, input: &ChildInput) -> Result<ChildVerdict, Error> {
        let public = self.preflight(input)?;
        let statement = public.statement(self.binding)?;
        let verifier = statement.verifier().map_err(|_| Error::Setup)?;
        if verifier.shape().identity() != self.expected
            || verifier.shape().maximum_complete_frame_bytes() > MAX_FEE_PROOF_BYTES
        {
            return Err(Error::LocalConfiguration);
        }
        match verifier.verify(&input.proof) {
            Ok(()) => Ok(ChildVerdict::Verified),
            Err(complete_fee::Error::Batch(
                batch::Error::Frame(_) | batch::Error::Body(_) | batch::Error::Verification,
            )) => Ok(ChildVerdict::Rejected),
            Err(_) => Err(Error::LocalConfiguration),
        }
    }

    /// Library entry point for a future fixed executable mode. This function
    /// spawns no subprocess, reads no key from the request and emits no logs.
    /// Selecting and pinning the executable remains the platform owner's job.
    pub fn run_child(&self, request: &Path, receipt: &Path) -> Result<(), Error> {
        let input =
            fee_guard::read_child_input_preflight(request, MAX_STATEMENT_BYTES, self.expected)
                .map_err(|_| Error::InputBinding)?;
        let verdict = self.verify_child(&input)?;
        fee_guard::write_child_receipt(receipt, input.binding, verdict).map_err(|_| Error::Receipt)
    }
}

/// Holds the native-checked input lifetime while the guard runs. A returned
/// receipt is still only a process result. The canonical owner must later
/// recheck its captured context before any independently authorized admission.
pub struct PreparedRequest<'a, 'b> {
    _checked: &'a NativeCheckedFeeInputs<'b>,
    declared: DeclaredLength,
    proof: &'a [u8],
    statement: Vec<u8>,
    binding: RequestBinding,
}
impl PreparedRequest<'_, '_> {
    pub fn binding(&self) -> RequestBinding {
        self.binding
    }
    pub fn run(&self, guard: &FeeGuard, command: &ChildCommand, private_scratch: &Path) -> Outcome {
        guard.verify(
            VerificationInput {
                declared: self.declared,
                proof: self.proof,
                statement: &self.statement,
                binding: self.binding,
            },
            command,
            private_scratch,
        )
    }
}

pub(crate) fn encode_statement(inputs: StatementInputs<'_>) -> Result<Vec<u8>, Error> {
    canonical::encode(inputs)
}

#[cfg(test)]
mod tests;
