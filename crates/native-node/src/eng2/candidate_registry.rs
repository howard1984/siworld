//! Unregistered candidate semantics and locally described frame identities.
//!
//! These records cannot seal a genesis, authenticate a verifier key or grant
//! admission. In particular, backend IDs are not transaction AIR/key identities.
use super::fee_candidate::LocalFeeSuite;
use crate::proof_codec::v2::{Identity, ProtocolBinding, Relation, backend::Profile, batch};
use crate::wire::Hash;

pub const BODY_LAYOUT: &[u8; 8] = b"SW2BFWA1";

/// Genesis-independent candidate inputs. TX and issuance registration is absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateSemanticSuite {
    fee: LocalFeeSuite,
}
impl CandidateSemanticSuite {
    pub fn local() -> Self {
        Self {
            fee: LocalFeeSuite::local(),
        }
    }
    /// Complete bounded candidate record; zero qualification flags are literal.
    /// No genesis, rules or final frame profile can enter this constructor.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = b"SW2SUIT1".to_vec();
        bytes.extend_from_slice(self.fee.proof_limits());
        bytes.extend_from_slice(&self.fee.source_program());
        for profile in [
            Profile::transaction(),
            Profile::issuance(),
            batch::profile(),
        ] {
            bytes.extend_from_slice(&profile.id());
        }
        bytes.extend_from_slice(BODY_LAYOUT);
        bytes.extend_from_slice(&super::fund_claim::WINDOWED_MIN_VALIDITY_BLOCKS.to_le_bytes());
        bytes
            .extend_from_slice(&crate::eng2_governance::WINDOWED_MIN_VALIDITY_BLOCKS.to_le_bytes());
        bytes.extend_from_slice(&[0, 0]); // No registered V2 transaction or issuance verifier.
        bytes
    }
    pub fn id(&self) -> Hash {
        blake3::derive_key(
            "siworld inactive semantic suite candidate v1",
            &self.encode(),
        )
    }
    pub fn activation_supported(&self) -> bool {
        false
    }
}

/// Local framing description only, deliberately not an active registry entry.
/// The caller must not obtain expected identities from the incoming body.
#[derive(Clone, Debug)]
pub struct CandidateRegistry {
    suite: CandidateSemanticSuite,
    network: Hash,
    genesis: Hash,
    rules: Hash,
    transaction: Identity,
    issuance: Identity,
    fee: Identity,
}
impl CandidateRegistry {
    pub fn for_candidate_framing(
        network: Hash,
        genesis: Hash,
        rules: Hash,
        transaction: Identity,
        issuance: Identity,
        fee: Identity,
    ) -> Result<Self, String> {
        if [
            network,
            genesis,
            rules,
            transaction.profile,
            issuance.profile,
            fee.profile,
        ]
        .contains(&[0; 32])
            || transaction.relation != Relation::Transaction
            || issuance.relation != Relation::Issuance
            || fee.relation != Relation::CompleteFee
        {
            return Err("candidate registry context or relation differs".into());
        }
        Ok(Self {
            suite: CandidateSemanticSuite::local(),
            network,
            genesis,
            rules,
            transaction,
            issuance,
            fee,
        })
    }
    pub fn suite(&self) -> &CandidateSemanticSuite {
        &self.suite
    }
    pub fn network(&self) -> Hash {
        self.network
    }
    pub fn genesis(&self) -> Hash {
        self.genesis
    }
    pub fn rules(&self) -> Hash {
        self.rules
    }
    pub fn transaction(&self) -> Identity {
        self.transaction
    }
    pub fn issuance(&self) -> Identity {
        self.issuance
    }
    pub fn fee(&self) -> Identity {
        self.fee
    }
    /// The fee program is local; frame identity is a separate, derived input.
    /// This value still requires the trusted factory's exact preprocessing check.
    pub fn fee_binding(&self) -> ProtocolBinding {
        ProtocolBinding {
            genesis: self.genesis,
            rules: self.rules,
            air: self.suite.fee.source_program(),
        }
    }
}
