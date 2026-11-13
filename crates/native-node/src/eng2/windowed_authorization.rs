//! Candidate full-body framing and staged windowed fund/governance execution.
//! Legacy genesis selection, body decoding and durable admission do not call this
//! module. A future rules version must select its framing and execution together.
use super::{
    body::{Body, Policy},
    fund_claim::{AuthorizedFundClaim, DebitedFundOutput, WindowedFundClaim},
    genesis::Genesis,
};
use crate::{
    eng2_fund::FundLedger,
    eng2_governance::{GovernanceState, Inclusion, WindowedSignedAction},
    wire::Hash,
};

const MAGIC: &[u8; 8] = b"SW2BWIN2";
const PREFIX_BYTES: usize = 118;
const CLAIM_BYTES: usize = super::fund_claim::ENCODED_BYTES + 8;
const MAX_AUTH_BYTES: usize = crate::wire::MAX_FUND_SPENDS * CLAIM_BYTES
    + crate::eng2_governance::MAX_ACTIONS_PER_BLOCK * (4 + WindowedSignedAction::MAX_ENCODED_BYTES);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowedAuthorizationBody {
    pub network: Hash,
    pub genesis: Hash,
    pub rules_commitment: Hash,
    pub height: u64,
    pub fund_claims: Vec<WindowedFundClaim>,
    pub governance: Vec<WindowedSignedAction>,
}

/// Candidate ledger outputs only. This is not a committed block, verified proof
/// result, active-genesis capability or authorization to publish a wallet output.
pub struct CandidateAuthorizationState {
    fund: FundLedger,
    governance: GovernanceState,
    inclusions: Vec<Inclusion>,
    outputs: Vec<DebitedFundOutput>,
}
impl CandidateAuthorizationState {
    pub fn fund(&self) -> &FundLedger {
        &self.fund
    }
    pub fn governance(&self) -> &GovernanceState {
        &self.governance
    }
    pub fn inclusions(&self) -> &[Inclusion] {
        &self.inclusions
    }
    pub fn outputs(&self) -> &[DebitedFundOutput] {
        &self.outputs
    }
}

impl WindowedAuthorizationBody {
    pub(super) fn check(&self, body: &Body) -> Result<(), String> {
        if self.network == [0; 32]
            || self.genesis == [0; 32]
            || self.rules_commitment == [0; 32]
            || self.height == 0
            || self.network != body.network
            || self.height != body.height
            || !body.fund_claims.is_empty()
            || !body.governance.is_empty()
            || self.fund_claims.len() > crate::wire::MAX_FUND_SPENDS
            || self.governance.len() > crate::eng2_governance::MAX_ACTIONS_PER_BLOCK
        {
            return Err("windowed body context or operation count differs".into());
        }
        let mut member = None;
        for claim in &self.fund_claims {
            if claim.claim.network != self.network
                || claim.claim.height > self.height
                || self.height > claim.valid_until
                || member.is_some_and(|old| old >= claim.claim.spend.account)
            {
                return Err("windowed fund claim order or inclusion context differs".into());
            }
            WindowedFundClaim::decode(&claim.encode()?)?;
            member = Some(claim.claim.spend.account);
        }
        let mut sequence = None;
        for action in &self.governance {
            action.validate_window()?;
            if action.signed.action.network != self.network
                || !(action.valid_from..=action.valid_until).contains(&self.height)
                || sequence.is_some_and(|old| old >= action.signed.action.sequence)
            {
                return Err("windowed governance order or inclusion context differs".into());
            }
            WindowedSignedAction::decode(&action.encode()?)?;
            sequence = Some(action.signed.action.sequence);
        }
        Ok(())
    }

    /// The full envelope binds the unchanged transaction/proof body together
    /// with every authorization and the exact candidate genesis/rules context.
    pub fn encode(&self, body: &Body, policy: Policy) -> Result<Vec<u8>, String> {
        self.check(body)?;
        let base = body.encode(policy)?;
        let base_length = u32::try_from(base.len()).map_err(|_| "windowed base length overflow")?;
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&self.network);
        bytes.extend_from_slice(&self.genesis);
        bytes.extend_from_slice(&self.rules_commitment);
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes.extend_from_slice(&base_length.to_le_bytes());
        bytes.push(self.fund_claims.len() as u8);
        bytes.push(self.governance.len() as u8);
        bytes.extend_from_slice(&base);
        for claim in &self.fund_claims {
            bytes.extend_from_slice(&claim.encode()?);
        }
        for action in &self.governance {
            let encoded = action.encode()?;
            bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&encoded);
        }
        Ok(bytes)
    }

    pub fn decode(
        bytes: &[u8],
        genesis: &Genesis,
        height: u64,
        policy: Policy,
    ) -> Result<(Body, Self), String> {
        let maximum = policy
            .max_body_bytes
            .checked_add(PREFIX_BYTES + MAX_AUTH_BYTES)
            .ok_or("windowed body bound overflow")?;
        if bytes.len() < PREFIX_BYTES
            || bytes.len() > maximum
            || &bytes[..8] != MAGIC
            || bytes[8..40] != genesis.config().network
            || bytes[40..72] != genesis.id()
            || bytes[72..104] != genesis.rules_commitment()
            || bytes[104..112] != height.to_le_bytes()
            || height == 0
        {
            return Err("windowed body version, bound or sealed context differs".into());
        }
        let base_length =
            u32::from_le_bytes(bytes[112..116].try_into().expect("fixed length")) as usize;
        let claims = usize::from(bytes[116]);
        let actions = usize::from(bytes[117]);
        if base_length > policy.max_body_bytes
            || claims > crate::wire::MAX_FUND_SPENDS
            || actions > crate::eng2_governance::MAX_ACTIONS_PER_BLOCK
        {
            return Err("windowed body declared bound exceeds policy".into());
        }
        let mut reader = Reader(&bytes[PREFIX_BYTES..]);
        let body = Body::decode(
            reader.take(base_length)?,
            genesis.config().network,
            height,
            policy,
        )?;
        let mut result = Self {
            network: genesis.config().network,
            genesis: genesis.id(),
            rules_commitment: genesis.rules_commitment(),
            height,
            fund_claims: Vec::with_capacity(claims),
            governance: Vec::with_capacity(actions),
        };
        for _ in 0..claims {
            result
                .fund_claims
                .push(WindowedFundClaim::decode(reader.take(CLAIM_BYTES)?)?);
        }
        for _ in 0..actions {
            let length =
                u32::from_le_bytes(reader.take(4)?.try_into().expect("fixed action length"))
                    as usize;
            if length > WindowedSignedAction::MAX_ENCODED_BYTES {
                return Err("windowed governance declared byte bound".into());
            }
            result
                .governance
                .push(WindowedSignedAction::decode(reader.take(length)?)?);
        }
        if !reader.0.is_empty() {
            return Err("trailing windowed body bytes".into());
        }
        result.check(&body)?;
        Ok((body, result))
    }

    pub fn commitment(&self, body: &Body, policy: Policy) -> Result<Hash, String> {
        Ok(blake3::derive_key(
            "siworld eng2 windowed block body v2",
            &self.encode(body, policy)?,
        ))
    }

    /// Validate actual-height authorization and debit isolated ledger clones.
    /// Transaction/settlement proofs and enclosing atomic block publication remain
    /// the engine's responsibility. No live state or durable store is changed.
    pub fn prepare_candidate(
        &self,
        engine: &super::execution::Engine,
        body: &Body,
    ) -> Result<CandidateAuthorizationState, String> {
        let genesis = engine.genesis();
        let parent = engine.state();
        self.check(body)?;
        body.encoded_len(engine.body_policy())?;
        parent.check_context()?;
        if self.network != genesis.config().network
            || self.genesis != genesis.id()
            || self.rules_commitment != genesis.rules_commitment()
            || parent.network() != self.network
            || parent.chain.config != *genesis.config()
            || parent.height().checked_add(1) != Some(self.height)
        {
            return Err("windowed authorization candidate parent differs".into());
        }
        let mut frozen = parent.governance.clone();
        frozen.apply_block(self.height, &[])?;
        let mut governance = parent.governance.clone();
        let inclusions = governance.apply_windowed_block(self.height, &self.governance)?;
        let mut fund = parent.fund.clone();
        fund.advance(
            self.height,
            siworld_core::v1_economics::subsidy(self.height).map_err(|error| error.to_string())?,
        )?;
        let mut outputs = Vec::with_capacity(self.fund_claims.len());
        for claim in &self.fund_claims {
            outputs.push(
                AuthorizedFundClaim::verify_windowed(
                    claim,
                    genesis.config(),
                    &frozen,
                    self.height,
                )?
                .debit(&mut fund)?,
            );
        }
        Ok(CandidateAuthorizationState {
            fund,
            governance,
            inclusions,
            outputs,
        })
    }
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], String> {
        let (head, tail) = self
            .0
            .split_at_checked(count)
            .ok_or("truncated windowed body")?;
        self.0 = tail;
        Ok(head)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn candidate_checks_structural_records_constructed_in_memory() {
        let mut body = super::super::body::tests::body();
        let claim = body.fund_claims.remove(0);
        let action = body.governance.remove(0);
        body.fund_claims.clear();
        body.governance.clear();
        let envelope = WindowedAuthorizationBody {
            network: body.network,
            genesis: [1; 32],
            rules_commitment: [2; 32],
            height: body.height,
            fund_claims: vec![WindowedFundClaim {
                valid_until: claim.height + 287,
                claim,
            }],
            governance: vec![WindowedSignedAction {
                signed: action,
                valid_from: body.height,
                valid_until: body.height + 287,
            }],
        };
        envelope.check(&body).unwrap();
        let mut malformed_claim = envelope.clone();
        malformed_claim.fund_claims[0].claim.spend.amount = 0;
        assert!(malformed_claim.fund_claims[0].encode().is_ok());
        assert!(malformed_claim.check(&body).is_err());
        let mut malformed_action = envelope;
        malformed_action.governance[0].signed.action.kind =
            crate::eng2_governance::ActionKind::CancelDestination {
                proposal_sequence: 0,
            };
        assert!(malformed_action.governance[0].encode().is_ok());
        assert!(malformed_action.check(&body).is_err());
    }

    #[test]
    fn bounded_framing_binds_genesis_rules_and_rejects_legacy_or_mixed_operations() {
        let original = crate::eng2::snapshot::tests::bootstrap();
        let genesis = Genesis::seal(
            original.chain.config.clone(),
            original.governance.clone(),
            super::super::genesis::FeeMode::LegacyMiner,
        )
        .unwrap();
        let mut body = super::super::body::tests::body();
        body.network = genesis.config().network;
        body.fund_claims.clear();
        body.governance.clear();
        let policy = super::super::body::tests::policy();
        body.transactions
            .sort_by_key(|tx| tx.record.statement_id(&body.network));
        let envelope = WindowedAuthorizationBody {
            network: body.network,
            genesis: genesis.id(),
            rules_commitment: genesis.rules_commitment(),
            height: body.height,
            fund_claims: Vec::new(),
            governance: Vec::new(),
        };
        let bytes = envelope.encode(&body, policy).unwrap();
        let (decoded, authorizations) =
            WindowedAuthorizationBody::decode(&bytes, &genesis, body.height, policy).unwrap();
        assert_eq!(decoded, body);
        assert_eq!(authorizations, envelope);
        assert!(Body::decode(&bytes, body.network, body.height, policy).is_err());
        assert!(
            WindowedAuthorizationBody::decode(
                &body.encode(policy).unwrap(),
                &genesis,
                body.height,
                policy
            )
            .is_err()
        );
        for offset in [0, 8, 40, 72, 104, 112, 116, 117] {
            let mut changed = bytes.clone();
            changed[offset] ^= 0x80;
            assert!(
                WindowedAuthorizationBody::decode(&changed, &genesis, body.height, policy).is_err()
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(
            WindowedAuthorizationBody::decode(&trailing, &genesis, body.height, policy).is_err()
        );
        assert!(
            WindowedAuthorizationBody::decode(
                &bytes[..bytes.len() - 1],
                &genesis,
                body.height,
                policy
            )
            .is_err()
        );
        body.governance = super::super::body::tests::body().governance;
        assert!(envelope.encode(&body, policy).is_err());
    }
}
