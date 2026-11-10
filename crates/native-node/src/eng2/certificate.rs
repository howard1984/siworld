//! Canonical optional checkpoint statements and signature relations.
//!
//! Checking signatures against supplied keys does not establish their current
//! authorization. Admission must also authenticate component 8 against the
//! selected header and require the independently validated current roster epoch.

use super::commitment::Descriptor;
use crate::wire::Hash;

pub const STATEMENT_BYTES: usize = 158;
pub const SIGNATURE_BYTES: usize = 3309;
pub const VERIFYING_KEY_BYTES: usize = 1952;
pub const CERTIFICATE_BYTES: usize = STATEMENT_BYTES + 2 * (1 + SIGNATURE_BYTES);
const DOMAIN: &[u8] = b"siworld eng2 checkpoint context v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    pub network: Hash,
    pub checkpoint_height: u64,
    pub checkpoint_block: Hash,
    pub authorization_height: u64,
    pub authorization_block: Hash,
    pub roster_sequence: u64,
    pub roster_digest: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vote {
    pub slot: u8,
    pub signature: [u8; SIGNATURE_BYTES],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub statement: Statement,
    pub votes: [Vote; 2],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CurrentOutcome {
    Consistent,
    Historical,
    Conflict {
        height: u64,
        selected: Hash,
        certified: Hash,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertificateError {
    Encoding,
    Network,
    Height,
    Slots,
    Keys,
    Signature,
    Witness,
    Bounds,
    AboveHead,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationWitness {
    pub descriptors: [Descriptor; 11],
    pub governance: Vec<u8>,
}

/// Component-8 bytes with a verified selected-header inclusion binding. The
/// canonical governance decoder and current active epoch must still be checked.
pub struct IncludedGovernance<'a> {
    bytes: &'a [u8],
    height: u64,
    network: Hash,
}
impl IncludedGovernance<'_> {
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn network(&self) -> Hash {
        self.network
    }
}

impl AuthorizationWitness {
    pub fn encode(&self, limit: usize) -> Result<Vec<u8>, CertificateError> {
        self.check_shape(limit)?;
        let length = u32::try_from(self.governance.len()).map_err(|_| CertificateError::Bounds)?;
        let capacity = WITNESS_PREFIX
            .checked_add(self.governance.len())
            .ok_or(CertificateError::Bounds)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| CertificateError::Bounds)?;
        bytes.extend_from_slice(b"SW2W\x01\x00");
        bytes.extend_from_slice(&length.to_le_bytes());
        for descriptor in self.descriptors {
            bytes.extend_from_slice(&descriptor.encode());
        }
        bytes.extend_from_slice(&self.governance);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8], limit: usize) -> Result<Self, CertificateError> {
        use super::commitment::DESCRIPTOR_BYTES;
        if bytes.len() < WITNESS_PREFIX || &bytes[..6] != b"SW2W\x01\x00" {
            return Err(CertificateError::Witness);
        }
        let length = usize::try_from(u32::from_le_bytes(
            bytes[6..10].try_into().expect("fixed governance length"),
        ))
        .map_err(|_| CertificateError::Bounds)?;
        if length > limit {
            return Err(CertificateError::Bounds);
        }
        if WITNESS_PREFIX.checked_add(length) != Some(bytes.len()) {
            return Err(CertificateError::Witness);
        }
        let mut descriptors = Vec::with_capacity(11);
        for bytes in bytes[10..WITNESS_PREFIX].as_chunks::<DESCRIPTOR_BYTES>().0 {
            descriptors.push(Descriptor::decode(bytes).map_err(|_| CertificateError::Witness)?);
        }
        let mut governance = Vec::new();
        governance
            .try_reserve_exact(length)
            .map_err(|_| CertificateError::Bounds)?;
        governance.extend_from_slice(&bytes[WITNESS_PREFIX..]);
        let witness = Self {
            descriptors: descriptors
                .try_into()
                .map_err(|_| CertificateError::Witness)?,
            governance,
        };
        witness.check_shape(limit)?;
        Ok(witness)
    }
    pub fn verify_binding(
        &self,
        statement: &Statement,
        chain: &super::selection::VerifiedHeaders,
        limit: usize,
    ) -> Result<IncludedGovernance<'_>, CertificateError> {
        use super::commitment::{self, Component, ComponentId};
        self.check_shape(limit)?;
        statement.encode()?;
        if statement.authorization_height > chain.height() {
            return Err(CertificateError::AboveHead);
        }
        // Genesis has no ordinary post-execution header witness. A signer uses
        // an independently validated, non-genesis authorization context.
        let header = chain
            .header(statement.authorization_height)
            .ok_or(CertificateError::Witness)?;
        if header.network != statement.network {
            return Err(CertificateError::Network);
        }
        if chain
            .id(statement.authorization_height)
            .map_err(|_| CertificateError::Witness)?
            != statement.authorization_block
        {
            return Err(CertificateError::Witness);
        }
        let governance =
            Component::from_local_encoding(ComponentId::Governance, &self.governance, limit)
                .map_err(|_| CertificateError::Bounds)?;
        if governance.descriptor() != self.descriptors[7]
            || commitment::aggregate_descriptors(
                header.network,
                header.height,
                header.parent,
                &self.descriptors,
            )
            .map_err(|_| CertificateError::Witness)?
                != header.execution_commitment
        {
            return Err(CertificateError::Witness);
        }
        Ok(IncludedGovernance {
            bytes: &self.governance,
            height: header.height,
            network: header.network,
        })
    }
    fn check_shape(&self, limit: usize) -> Result<(), CertificateError> {
        if self.governance.len() > limit || u32::try_from(self.governance.len()).is_err() {
            return Err(CertificateError::Bounds);
        }
        if self
            .descriptors
            .iter()
            .zip(super::commitment::COMPONENTS)
            .any(|(descriptor, id)| descriptor.id() != id)
        {
            return Err(CertificateError::Witness);
        }
        Ok(())
    }
}

const WITNESS_PREFIX: usize = 10 + 11 * super::commitment::DESCRIPTOR_BYTES;

impl Statement {
    pub fn signing_context() -> &'static [u8] {
        DOMAIN
    }
    pub fn encode(&self) -> Result<[u8; STATEMENT_BYTES], CertificateError> {
        if self.network == [0; 32] {
            return Err(CertificateError::Network);
        }
        if self.authorization_height < self.checkpoint_height {
            return Err(CertificateError::Height);
        }
        let mut bytes = [0; STATEMENT_BYTES];
        bytes[..6].copy_from_slice(b"SW2C\x01\x00");
        bytes[6..38].copy_from_slice(&self.network);
        bytes[38..46].copy_from_slice(&self.checkpoint_height.to_le_bytes());
        bytes[46..78].copy_from_slice(&self.checkpoint_block);
        bytes[78..86].copy_from_slice(&self.authorization_height.to_le_bytes());
        bytes[86..118].copy_from_slice(&self.authorization_block);
        bytes[118..126].copy_from_slice(&self.roster_sequence.to_le_bytes());
        bytes[126..158].copy_from_slice(&self.roster_digest);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8], network: Hash) -> Result<Self, CertificateError> {
        if bytes.len() != STATEMENT_BYTES || &bytes[..6] != b"SW2C\x01\x00" {
            return Err(CertificateError::Encoding);
        }
        if network == [0; 32] || bytes[6..38] != network {
            return Err(CertificateError::Network);
        }
        let statement = Self {
            network,
            checkpoint_height: u64::from_le_bytes(bytes[38..46].try_into().expect("fixed height")),
            checkpoint_block: bytes[46..78].try_into().expect("fixed checkpoint identity"),
            authorization_height: u64::from_le_bytes(
                bytes[78..86]
                    .try_into()
                    .expect("fixed authorization height"),
            ),
            authorization_block: bytes[86..118]
                .try_into()
                .expect("fixed authorization identity"),
            roster_sequence: u64::from_le_bytes(
                bytes[118..126].try_into().expect("fixed roster sequence"),
            ),
            roster_digest: bytes[126..158].try_into().expect("fixed roster digest"),
        };
        statement.encode()?;
        Ok(statement)
    }
}
impl Certificate {
    /// `current` must come from the complete independently reconstructed and
    /// executed staged head. A certificate or witness cannot establish it.
    pub fn evaluate_current(
        &self,
        witness: &AuthorizationWitness,
        plan: &super::admission::AdmissionPlan,
        current: &crate::eng2_governance::GovernanceState,
        limit: usize,
    ) -> Result<CurrentOutcome, CertificateError> {
        if current.network() != plan.pin().network
            || current.height() != plan.pin().tip_height
            || self.statement.network != current.network()
        {
            return Err(CertificateError::Witness);
        }
        let included = witness.verify_binding(&self.statement, plan.headers(), limit)?;
        let authorization = crate::eng2_governance::GovernanceState::decode_component(
            included.bytes(),
            included.network(),
        )
        .map_err(|_| CertificateError::Witness)?;
        if authorization.height() != included.height() {
            return Err(CertificateError::Witness);
        }
        let roster = authorization.active_roster();
        if roster.activated_height > included.height()
            || roster.epoch_sequence != self.statement.roster_sequence
            || roster.digest(included.network()) != self.statement.roster_digest
        {
            return Err(CertificateError::Witness);
        }
        self.check_signatures(roster.keys())?;
        let active = current.active_roster();
        if roster.epoch_sequence < active.epoch_sequence {
            return Ok(CurrentOutcome::Historical);
        }
        if roster.epoch_sequence != active.epoch_sequence
            || roster.digest(current.network()) != active.digest(current.network())
        {
            return Err(CertificateError::Witness);
        }
        let selected = plan
            .headers()
            .id(self.statement.checkpoint_height)
            .map_err(|_| CertificateError::Witness)?;
        Ok(if selected == self.statement.checkpoint_block {
            CurrentOutcome::Consistent
        } else {
            CurrentOutcome::Conflict {
                height: self.statement.checkpoint_height,
                selected,
                certified: self.statement.checkpoint_block,
            }
        })
    }
    pub fn encode(&self) -> Result<[u8; CERTIFICATE_BYTES], CertificateError> {
        self.check_slots()?;
        let mut bytes = [0; CERTIFICATE_BYTES];
        bytes[..STATEMENT_BYTES].copy_from_slice(&self.statement.encode()?);
        for (index, vote) in self.votes.iter().enumerate() {
            let offset = STATEMENT_BYTES + index * (1 + SIGNATURE_BYTES);
            bytes[offset] = vote.slot;
            bytes[offset + 1..offset + 1 + SIGNATURE_BYTES].copy_from_slice(&vote.signature);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8], network: Hash) -> Result<Self, CertificateError> {
        if bytes.len() != CERTIFICATE_BYTES {
            return Err(CertificateError::Encoding);
        }
        let statement = Statement::decode(&bytes[..STATEMENT_BYTES], network)?;
        let votes = core::array::from_fn(|index| {
            let offset = STATEMENT_BYTES + index * (1 + SIGNATURE_BYTES);
            Vote {
                slot: bytes[offset],
                signature: bytes[offset + 1..offset + 1 + SIGNATURE_BYTES]
                    .try_into()
                    .expect("fixed signature"),
            }
        });
        let certificate = Self { statement, votes };
        certificate.check_slots()?;
        Ok(certificate)
    }
    /// Cryptographic verification only; these keys still require authenticated
    /// current-epoch authorization before a contradiction can stop admission.
    pub fn check_signatures(
        &self,
        keys: &[[u8; VERIFYING_KEY_BYTES]; 3],
    ) -> Result<(), CertificateError> {
        use libcrux_ml_dsa::ml_dsa_65::{self, MLDSA65Signature, MLDSA65VerificationKey};
        self.check_slots()?;
        if keys
            .iter()
            .enumerate()
            .any(|(index, key)| key.iter().all(|b| *b == 0) || keys[..index].contains(key))
        {
            return Err(CertificateError::Keys);
        }
        let statement = self.statement.encode()?;
        for vote in &self.votes {
            let key = MLDSA65VerificationKey::new(keys[usize::from(vote.slot)]);
            let signature = MLDSA65Signature::new(vote.signature);
            ml_dsa_65::verify(&key, &statement, DOMAIN, &signature)
                .map_err(|_| CertificateError::Signature)?;
        }
        Ok(())
    }
    fn check_slots(&self) -> Result<(), CertificateError> {
        if self.votes[0].slot >= self.votes[1].slot || self.votes[1].slot >= 3 {
            return Err(CertificateError::Slots);
        }
        Ok(())
    }
}

#[cfg(test)]
mod epoch_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use libcrux_ml_dsa::ml_dsa_65;

    fn statement() -> Statement {
        Statement {
            network: [1; 32],
            checkpoint_height: 72,
            checkpoint_block: [2; 32],
            authorization_height: 100,
            authorization_block: [3; 32],
            roster_sequence: 4,
            roster_digest: [5; 32],
        }
    }
    fn unsigned() -> Certificate {
        Certificate {
            statement: statement(),
            votes: [
                Vote {
                    slot: 0,
                    signature: [7; SIGNATURE_BYTES],
                },
                Vote {
                    slot: 2,
                    signature: [8; SIGNATURE_BYTES],
                },
            ],
        }
    }

    fn witness_chain() -> (
        AuthorizationWitness,
        super::super::selection::VerifiedHeaders,
        Statement,
    ) {
        use super::super::{
            commitment::{self, COMPONENTS, Component, ComponentId},
            header::Header,
            selection::{HeaderRules, VerifiedHeaders},
        };
        let governance = b"synthetic component-eight bytes".to_vec();
        let components: Vec<_> = COMPONENTS
            .into_iter()
            .map(|id| {
                Component::from_local_encoding(
                    id,
                    if id == ComponentId::Governance {
                        &governance
                    } else {
                        b"other synthetic component"
                    },
                    1024,
                )
                .unwrap()
            })
            .collect();
        let descriptors = components
            .iter()
            .map(Component::descriptor)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let rules = HeaderRules {
            network: [1; 32],
            genesis: [2; 32],
            genesis_timestamp: 1,
            genesis_target: [0xff; 32],
            target_interval: 300,
            pow_iterations: 0,
            max_headers: 1000,
        };
        let mut headers = Vec::new();
        let mut parent = rules.genesis;
        for height in 1..=100 {
            let header = Header {
                network: rules.network,
                height,
                parent,
                timestamp: 1 + height * 300,
                target: [0xff; 32],
                execution_commitment: commitment::aggregate(
                    rules.network,
                    height,
                    parent,
                    &components,
                )
                .unwrap(),
                body_commitment: [7; 32],
                nonce: 0,
            };
            parent = header.id().unwrap();
            headers.push(header);
        }
        let chain = VerifiedHeaders::verify(rules, headers).unwrap();
        let mut statement = statement();
        statement.checkpoint_block = chain.id(72).unwrap();
        statement.authorization_block = chain.id(100).unwrap();
        (
            AuthorizationWitness {
                descriptors,
                governance,
            },
            chain,
            statement,
        )
    }

    #[test]
    fn authorization_witness_has_bounded_exact_framing_and_component_order() {
        let (witness, _, _) = witness_chain();
        let bytes = witness.encode(1024).unwrap();
        assert_eq!(
            AuthorizationWitness::decode(&bytes, 1024),
            Ok(witness.clone())
        );
        assert!(AuthorizationWitness::decode(&bytes[..bytes.len() - 1], 1024).is_err());
        let mut extended = bytes.clone();
        extended.push(0);
        assert!(AuthorizationWitness::decode(&extended, 1024).is_err());
        assert_eq!(
            AuthorizationWitness::decode(&bytes, 1),
            Err(CertificateError::Bounds)
        );
        let mut swapped = witness;
        swapped.descriptors.swap(1, 2);
        assert_eq!(swapped.encode(1024), Err(CertificateError::Witness));
    }

    #[test]
    fn inclusion_binding_rejects_altered_governance_or_wrong_authorization_header() {
        let (witness, chain, statement) = witness_chain();
        let included = witness.verify_binding(&statement, &chain, 1024).unwrap();
        assert_eq!(included.bytes(), witness.governance);
        assert_eq!(included.height(), 100);
        assert_eq!(included.network(), [1; 32]);
        let mut changed = witness.clone();
        changed.governance[0] ^= 1;
        assert!(changed.verify_binding(&statement, &chain, 1024).is_err());
        let mut changed = witness.clone();
        changed.descriptors[0] = super::super::commitment::Component::from_local_encoding(
            super::super::commitment::ComponentId::ChainContext,
            b"substituted state binding",
            1024,
        )
        .unwrap()
        .descriptor();
        assert!(changed.verify_binding(&statement, &chain, 1024).is_err());
        let mut altered = statement.clone();
        altered.authorization_block[0] ^= 1;
        assert!(witness.verify_binding(&altered, &chain, 1024).is_err());
        altered = statement.clone();
        altered.network[0] ^= 1;
        assert!(witness.verify_binding(&altered, &chain, 1024).is_err());
        altered = statement;
        altered.authorization_height = 101;
        assert!(matches!(
            witness.verify_binding(&altered, &chain, 1024),
            Err(CertificateError::AboveHead)
        ));
    }

    #[test]
    fn statement_has_exact_context_and_fixed_integer_layout() {
        let statement = statement();
        let bytes = statement.encode().unwrap();
        assert_eq!(&bytes[..6], b"SW2C\x01\x00");
        assert_eq!(&bytes[38..46], &72u64.to_le_bytes());
        assert_eq!(&bytes[78..86], &100u64.to_le_bytes());
        assert_eq!(&bytes[118..126], &4u64.to_le_bytes());
        assert_eq!(Statement::decode(&bytes, statement.network), Ok(statement));
    }

    #[test]
    fn rejects_context_truncation_extension_version_network_and_future_checkpoint() {
        let bytes = statement().encode().unwrap();
        assert_eq!(
            Statement::decode(&bytes[..157], [1; 32]),
            Err(CertificateError::Encoding)
        );
        let mut extended = bytes.to_vec();
        extended.push(0);
        assert_eq!(
            Statement::decode(&extended, [1; 32]),
            Err(CertificateError::Encoding)
        );
        let mut changed = bytes;
        changed[4] = 2;
        assert_eq!(
            Statement::decode(&changed, [1; 32]),
            Err(CertificateError::Encoding)
        );
        assert_eq!(
            Statement::decode(&bytes, [9; 32]),
            Err(CertificateError::Network)
        );
        let mut changed = statement();
        changed.authorization_height = 71;
        assert_eq!(changed.encode(), Err(CertificateError::Height));
    }

    #[test]
    fn certificate_has_exactly_two_canonical_distinct_slots() {
        let certificate = unsigned();
        let bytes = certificate.encode().unwrap();
        assert_eq!(
            Certificate::decode(&bytes, [1; 32]),
            Ok(certificate.clone())
        );
        assert!(Certificate::decode(&bytes[..CERTIFICATE_BYTES - 1], [1; 32]).is_err());
        let mut extended = bytes.to_vec();
        extended.push(0);
        assert!(Certificate::decode(&extended, [1; 32]).is_err());
        let mut changed = certificate.clone();
        changed.votes.swap(0, 1);
        assert_eq!(changed.encode(), Err(CertificateError::Slots));
        changed = certificate.clone();
        changed.votes[1].slot = 0;
        assert_eq!(changed.encode(), Err(CertificateError::Slots));
        changed = certificate;
        changed.votes[1].slot = 3;
        assert_eq!(changed.encode(), Err(CertificateError::Slots));
    }

    #[test]
    fn signatures_bind_every_context_field_and_the_supplied_slot_keys() {
        let pairs = [23, 24, 25].map(|seed| ml_dsa_65::generate_key_pair([seed; 32]));
        let keys = pairs.each_ref().map(|pair| *pair.verification_key.as_ref());
        let mut certificate = unsigned();
        for vote in &mut certificate.votes {
            vote.signature = *ml_dsa_65::sign(
                &pairs[usize::from(vote.slot)].signing_key,
                &certificate.statement.encode().unwrap(),
                DOMAIN,
                [31 + vote.slot; 32],
            )
            .unwrap()
            .as_ref();
        }
        assert_eq!(certificate.check_signatures(&keys), Ok(()));
        for field in 0..8 {
            let mut changed = certificate.clone();
            match field {
                0 => changed.statement.network[0] ^= 1,
                1 => changed.statement.checkpoint_height += 1,
                2 => changed.statement.checkpoint_block[0] ^= 1,
                3 => changed.statement.authorization_height += 1,
                4 => changed.statement.authorization_block[0] ^= 1,
                5 => changed.statement.roster_sequence += 1,
                6 => changed.statement.roster_digest[0] ^= 1,
                _ => changed.votes[0].signature[0] ^= 1,
            }
            assert_eq!(
                changed.check_signatures(&keys),
                Err(CertificateError::Signature)
            );
        }
        let mut duplicate = keys;
        duplicate[1] = duplicate[0];
        assert_eq!(
            certificate.check_signatures(&duplicate),
            Err(CertificateError::Keys)
        );
        let mut swapped = keys;
        swapped.swap(0, 2);
        assert_eq!(
            certificate.check_signatures(&swapped),
            Err(CertificateError::Signature)
        );
    }
}
