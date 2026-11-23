//! Inactive Engine context binding for the guarded CompleteFee adapter.
//!
//! Context equality and a child verdict do not authenticate a V2 registry or
//! construct a state delta. No producer, Store or admission path calls this API.

use super::{PreparedRequest, TrustedFactory};
use crate::eng2::{
    execution::Engine,
    fee_candidate::NativeCheckedFeeInputs,
    fee_windowed_body::PreparedCandidateBody,
    header::{HEADER_BYTES, Header},
    state_components::{Binding, Limits},
};
use crate::proof_codec::v2::fee_guard::{ChildCommand, ChildVerdict, Deferred, FeeGuard, Outcome};
use crate::wire::Hash;
use std::path::Path;

/// A captured local owner context, not a registered suite or admission token.
/// The owner supplies its monotonic generation and must advance it on every
/// canonical replacement, including a replacement restoring an earlier tip.
pub struct CapturedContext {
    generation: u64,
    parent_state: Hash,
    header: [u8; HEADER_BYTES],
    body: Hash,
    context: Hash,
    limits: Limits,
}

impl Engine {
    /// Bind a structurally prepared candidate to this exact local parent.
    /// This does not verify work, transaction proofs or CompleteFee. The owner
    /// must arrange detached authenticated inputs before releasing its lock for
    /// statement preparation and the guard. This API does not detach inputs.
    pub fn capture_fee_candidate_context(
        &self,
        generation: u64,
        header: &Header,
        candidate: &PreparedCandidateBody<'_>,
    ) -> Result<CapturedContext, String> {
        let registry = candidate.registry();
        let body = candidate.body();
        if registry.network() != self.state().network()
            || registry.genesis() != self.genesis().id()
            || registry.rules() != self.genesis().rules_commitment()
            || header.network != self.state().network()
            || header.parent != self.state().tip()
            || self.state().height().checked_add(1) != Some(header.height)
            || header.height != body.body.height
            || header.body_commitment != candidate.commitment()
            || self.state().fee_mode() != self.genesis().fee_mode()
        {
            return Err("fee candidate differs from local Engine context".into());
        }
        let header = header
            .encode()
            .map_err(|_| "invalid fee candidate header")?;
        // A local fingerprint of all eleven current state components. Its
        // binding uses zero at genesis and the current tip thereafter; it is
        // not the accepted header's commitment or a peer-provided state digest.
        let parent_state = self.state().execution_commitment(
            Binding {
                genesis: self.genesis().id(),
                rules_commitment: self.genesis().rules_commitment(),
                parent: if self.state().height() == 0 {
                    [0; 32]
                } else {
                    self.state().tip()
                },
            },
            self.limits(),
        )?;
        Ok(CapturedContext {
            generation,
            parent_state,
            header,
            body: candidate.commitment(),
            context: context_digest(generation, parent_state, &header, candidate),
            limits: self.limits(),
        })
    }
}

fn context_digest(
    generation: u64,
    parent_state: Hash,
    header: &[u8; HEADER_BYTES],
    candidate: &PreparedCandidateBody<'_>,
) -> Hash {
    let registry = candidate.registry();
    let mut hash = blake3::Hasher::new_derive_key("siworld inactive fee owner context v1");
    hash.update(&generation.to_le_bytes());
    hash.update(&parent_state);
    hash.update(header);
    hash.update(&candidate.commitment());
    hash.update(&registry.suite().id());
    for identity in [registry.transaction(), registry.issuance(), registry.fee()] {
        hash.update(&[identity.relation as u8]);
        hash.update(&identity.profile);
    }
    *hash.finalize().as_bytes()
}

impl CapturedContext {
    /// Retain the checked body and bind its exact statement and sole fee frame.
    /// The retained native transaction capability is not registered V2 proof
    /// qualification; constructing this request cannot change that boundary.
    pub fn prepare<'c, 'a, 'b>(
        &'c self,
        factory: &TrustedFactory,
        checked: &'a NativeCheckedFeeInputs<'b>,
        candidate: &PreparedCandidateBody<'_>,
        attempt: Hash,
    ) -> Result<OwnerRequest<'c, 'a, 'b>, String> {
        let native = checked.native_checked();
        let mut parent_binding = native.binding();
        parent_binding.parent = if native.parent().height() == 0 {
            [0; 32]
        } else {
            native.parent().tip()
        };
        if native
            .header()
            .encode()
            .map_err(|_| "invalid checked fee header")?
            != self.header
            || !self.binds_candidate(candidate)
            || !std::ptr::eq(native.body(), &candidate.body().body)
            || native
                .parent()
                .execution_commitment(parent_binding, self.limits)?
                != self.parent_state
        {
            return Err("checked fee inputs differ from captured owner context".into());
        }
        let request = factory
            .prepare(checked, attempt, self.context)
            .map_err(|_| "fee request differs from local factory")?;
        Ok(OwnerRequest {
            captured: self,
            request,
        })
    }

    fn binds_candidate(&self, candidate: &PreparedCandidateBody<'_>) -> bool {
        candidate.commitment() == self.body
            && context_digest(self.generation, self.parent_state, &self.header, candidate)
                == self.context
    }

    fn is_current(&self, current: &CapturedContext) -> bool {
        self.generation == current.generation
            && self.parent_state == current.parent_state
            && self.header == current.header
            && self.body == current.body
            && self.context == current.context
    }
}

/// Retains one exact request. A runtime owner must arrange detached inputs and
/// release its lock before running the guard; this type cannot enforce that.
pub struct OwnerRequest<'c, 'a, 'b> {
    captured: &'c CapturedContext,
    request: PreparedRequest<'a, 'b>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerDeferred {
    Guard(Deferred),
    CanonicalContextChanged,
    ReceiptBinding,
}

/// Only a local verification result; no variant authorizes state publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecheckedResult {
    VerifiedFeeOnly,
    RejectedFeeOnly,
    Deferred(OwnerDeferred),
}

impl OwnerRequest<'_, '_, '_> {
    pub fn run(&self, guard: &FeeGuard, command: &ChildCommand, scratch: &Path) -> Outcome {
        self.request.run(guard, command, scratch)
    }

    /// Reacquire the owner lock, recapture the same candidate from the actual
    /// Engine and current generation, then consume its process outcome once.
    /// Local failures and stale canonical context never become proof rejection.
    pub fn recheck(
        self,
        engine: &Engine,
        generation: u64,
        header: &Header,
        candidate: &PreparedCandidateBody<'_>,
        outcome: Outcome,
    ) -> RecheckedResult {
        let current = match engine.capture_fee_candidate_context(generation, header, candidate) {
            Ok(current) => current,
            Err(_) => {
                return RecheckedResult::Deferred(OwnerDeferred::CanonicalContextChanged);
            }
        };
        if !self.captured.is_current(&current) {
            return RecheckedResult::Deferred(OwnerDeferred::CanonicalContextChanged);
        }
        match outcome {
            Outcome::Deferred(reason) => RecheckedResult::Deferred(OwnerDeferred::Guard(reason)),
            Outcome::Checked(receipt) => {
                if *receipt.binding() != self.request.binding() {
                    return RecheckedResult::Deferred(OwnerDeferred::ReceiptBinding);
                }
                match receipt.verdict() {
                    ChildVerdict::Verified => RecheckedResult::VerifiedFeeOnly,
                    ChildVerdict::Rejected => RecheckedResult::RejectedFeeOnly,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eng2::{
        candidate_registry::CandidateRegistry,
        fee_windowed_body::FeeWindowedBody,
        genesis::{FeeMode, Genesis},
        snapshot::tests::{bootstrap, limits},
        windowed_authorization::WindowedAuthorizationBody,
    };
    use crate::proof_codec::v2::{self, Identity, Relation};

    fn engine() -> Engine {
        let parent = bootstrap();
        let genesis = Genesis::seal(
            parent.chain.config.clone(),
            parent.governance.clone(),
            FeeMode::LegacyMiner,
        )
        .unwrap();
        Engine::new(genesis, limits().chain).unwrap()
    }

    fn fixture(engine: &Engine) -> (CandidateRegistry, FeeWindowedBody) {
        let identity = |relation, seed| Identity {
            relation,
            profile: [seed; 32],
        };
        let registry = CandidateRegistry::for_candidate_framing(
            engine.state().network(),
            engine.genesis().id(),
            engine.genesis().rules_commitment(),
            identity(Relation::Transaction, 31),
            identity(Relation::Issuance, 37),
            identity(Relation::CompleteFee, 41),
        )
        .unwrap();
        // Existing synthetic envelopes are used only for structural capture.
        // No transaction proof, work, fee payment or block execution is valid.
        let mut body = crate::eng2::body::tests::body();
        body.network = engine.state().network();
        body.height = 1;
        body.profile = registry.suite().id();
        body.fund_claims.clear();
        body.governance.clear();
        let network = body.network;
        body.transactions
            .sort_by_key(|tx| tx.record.statement_id(&network));
        for tx in &mut body.transactions {
            tx.proof = v2::encode(
                registry.transaction(),
                &[1],
                v2::MAX_TRANSACTION_PROOF_BYTES,
            )
            .unwrap();
        }
        body.settlement_proof = v2::encode(registry.fee(), &[2], v2::MAX_FEE_PROOF_BYTES).unwrap();
        let authorizations = WindowedAuthorizationBody {
            network: body.network,
            genesis: registry.genesis(),
            rules_commitment: registry.rules(),
            height: body.height,
            fund_claims: Vec::new(),
            governance: Vec::new(),
        };
        (
            registry,
            FeeWindowedBody {
                body,
                authorizations,
            },
        )
    }

    fn header(engine: &Engine, candidate: &PreparedCandidateBody<'_>) -> Header {
        Header {
            network: engine.state().network(),
            height: 1,
            parent: engine.state().tip(),
            timestamp: 1,
            target: engine.state().chain().next_target(),
            execution_commitment: [0; 32],
            body_commitment: candidate.commitment(),
            nonce: 0,
        }
    }

    #[test]
    fn genesis_capture_binds_generation_without_activating_fee_rules() {
        let engine = engine();
        let (registry, body) = fixture(&engine);
        let candidate = PreparedCandidateBody::prepare(&body, &registry).unwrap();
        let header = header(&engine, &candidate);
        let before = engine.state().chain().fingerprint();
        let captured = engine
            .capture_fee_candidate_context(7, &header, &candidate)
            .unwrap();
        let same = engine
            .capture_fee_candidate_context(7, &header, &candidate)
            .unwrap();
        let replaced = engine
            .capture_fee_candidate_context(8, &header, &candidate)
            .unwrap();
        assert!(captured.is_current(&same));
        assert!(!captured.is_current(&replaced));
        assert_eq!(engine.state().chain().fingerprint(), before);
        assert_eq!(engine.genesis().fee_mode(), FeeMode::LegacyMiner);
        assert!(!registry.suite().activation_supported());
    }

    #[test]
    fn capture_rejects_substituted_header_and_binds_fee_ciphertext() {
        let engine = engine();
        let (registry, body) = fixture(&engine);
        let candidate = PreparedCandidateBody::prepare(&body, &registry).unwrap();
        let header = header(&engine, &candidate);
        let captured = engine
            .capture_fee_candidate_context(7, &header, &candidate)
            .unwrap();
        for field in 0..3 {
            let mut changed = header.clone();
            match field {
                0 => changed.parent[0] ^= 1,
                1 => changed.height += 1,
                _ => changed.body_commitment[0] ^= 1,
            }
            assert!(
                engine
                    .capture_fee_candidate_context(7, &changed, &candidate)
                    .is_err()
            );
        }
        let mut body = body.clone();
        body.body.fee_output.ciphertext[0] ^= 1;
        let changed = PreparedCandidateBody::prepare(&body, &registry).unwrap();
        assert!(
            engine
                .capture_fee_candidate_context(7, &header, &changed)
                .is_err()
        );
        let mut changed_header = header;
        changed_header.body_commitment = changed.commitment();
        let changed = engine
            .capture_fee_candidate_context(7, &changed_header, &changed)
            .unwrap();
        assert!(!captured.is_current(&changed));
    }

    #[test]
    fn request_binding_rejects_changed_registry_with_identical_body() {
        let engine = engine();
        let (registry, body) = fixture(&engine);
        assert!(body.body.issuances.is_empty());
        let candidate = PreparedCandidateBody::prepare(&body, &registry).unwrap();
        let header = header(&engine, &candidate);
        let captured = engine
            .capture_fee_candidate_context(7, &header, &candidate)
            .unwrap();
        let changed_registry = CandidateRegistry::for_candidate_framing(
            registry.network(),
            registry.genesis(),
            registry.rules(),
            registry.transaction(),
            Identity {
                relation: Relation::Issuance,
                profile: [43; 32],
            },
            registry.fee(),
        )
        .unwrap();
        let changed = PreparedCandidateBody::prepare(&body, &changed_registry).unwrap();
        assert_eq!(candidate.commitment(), changed.commitment());
        assert!(captured.binds_candidate(&candidate));
        assert!(!captured.binds_candidate(&changed));
    }
}
