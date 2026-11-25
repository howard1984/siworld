//! Canonical bounded body framing, independent of proof verification.

use super::fund_claim::PublicFundClaim;
use crate::{eng2_governance::SignedAction, issuance::IssuanceRecord, wire::*};

pub const PREFIX_BYTES: usize = 85;
const MAGIC: &[u8; 6] = b"SW2B\x01\x00";

/// Local immutable decoding policy. No production proof profile is implied.
#[derive(Clone, Copy)]
pub struct Policy {
    pub profile: Hash,
    pub max_body_bytes: usize,
    pub max_settlement_proof_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Body {
    pub network: Hash,
    pub height: u64,
    pub profile: Hash,
    pub transactions: Vec<Transaction>,
    pub reward_mode: RewardMode,
    pub rewards: Vec<RewardRecord>,
    /// Exactly one fixed-shape confidential output, including zero-fee blocks.
    pub fee_output: RewardRecord,
    pub fund_claims: Vec<PublicFundClaim>,
    pub governance: Vec<SignedAction>,
    pub issuances: Vec<IssuanceRecord>,
    pub settlement_proof: Vec<u8>,
}

impl Body {
    /// Same ordered statement binding used by the native transaction relation.
    /// Callers validate canonical framing before proving or verification.
    pub fn list_digest(&self) -> Hash {
        ordered_transaction_digest(self.network, self.height, &self.transactions)
    }

    /// Validate framing and canonical public encodings, never signatures or
    /// proof semantics. The selected native engine must verify those separately.
    pub fn encoded_len(&self, policy: Policy) -> Result<usize, String> {
        policy.check()?;
        if self.network == [0; 32]
            || self.height == 0
            || self.profile != policy.profile
            || !(MIN_SLOTS..=MAX_SLOTS).contains(&self.transactions.len())
            || !self.transactions.len().is_multiple_of(GROUP)
            || self.fund_claims.len() > MAX_FUND_SPENDS
            || self.governance.len() > crate::eng2_governance::MAX_ACTIONS_PER_BLOCK
            || self.issuances.len() > crate::issuance::RECORDS_CODEC_LIMIT
        {
            return Err("invalid versioned body context or count".into());
        }
        validate_rewards(self.reward_mode, &self.rewards)?;
        let _ = native::codec::decode_digest(&self.fee_output.commitment)
            .map_err(|_| "noncanonical fee output commitment")?;
        if self
            .rewards
            .iter()
            .any(|reward| reward.commitment == self.fee_output.commitment)
        {
            return Err("fee output duplicates miner reward".into());
        }
        if self.settlement_proof.is_empty()
            || self.settlement_proof.len() > policy.max_settlement_proof_bytes
            || u32::try_from(self.settlement_proof.len()).is_err()
        {
            return Err("versioned settlement proof byte bound".into());
        }
        let mut length = PREFIX_BYTES;
        add(&mut length, (self.rewards.len() + 1) * REWARD_RECORD_BYTES)?;
        let mut previous = None;
        for claim in &self.fund_claims {
            if claim.network != self.network
                || claim.height != self.height
                || previous.is_some_and(|member| member >= claim.spend.account)
            {
                return Err("noncanonical public fund claim order or context".into());
            }
            PublicFundClaim::decode(&claim.encode())?;
            previous = Some(claim.spend.account);
            add(&mut length, super::fund_claim::ENCODED_BYTES)?;
        }
        let mut previous = None;
        for action in &self.governance {
            if action.action.network != self.network
                || previous.is_some_and(|sequence| sequence >= action.action.sequence)
            {
                return Err("noncanonical governance action order or context".into());
            }
            let encoded = action.encode()?;
            SignedAction::decode(&encoded)?;
            previous = Some(action.action.sequence);
            add(&mut length, 4 + encoded.len())?;
        }
        let mut previous = None;
        for issuance in &self.issuances {
            let identity = issuance.signed.declaration.binding();
            if issuance.signed.declaration.network != self.network
                || previous.is_some_and(|previous| previous >= identity)
            {
                return Err("noncanonical issuance order or context".into());
            }
            previous = Some(identity);
            add(&mut length, 4 + issuance.encoded_len()?)?;
        }
        let mut previous = None;
        for transaction in &self.transactions {
            transaction.record.validate()?;
            let identity = transaction.record.statement_id(&self.network);
            if previous.is_some_and(|previous| previous >= identity)
                || transaction.proof.is_empty()
                || transaction.proof.len() > MAX_TX_PROOF
            {
                return Err("noncanonical transaction order or proof bound".into());
            }
            previous = Some(identity);
            add(&mut length, 4 + TX_PREFIX_BYTES + transaction.proof.len())?;
        }
        add(&mut length, 4 + self.settlement_proof.len())?;
        if length > policy.max_body_bytes {
            return Err("versioned body byte bound".into());
        }
        Ok(length)
    }
    pub fn encode(&self, policy: Policy) -> Result<Vec<u8>, String> {
        let length = self.encoded_len(policy)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| "cannot reserve versioned body bytes")?;
        self.emit(&mut |part| bytes.extend_from_slice(part))?;
        Ok(bytes)
    }

    pub fn decode(
        bytes: &[u8],
        network: Hash,
        height: u64,
        policy: Policy,
    ) -> Result<Self, String> {
        policy.check()?;
        if bytes.len() < PREFIX_BYTES || bytes.len() > policy.max_body_bytes {
            return Err("versioned body byte bound".into());
        }
        let mut reader = Reader(bytes);
        if reader.take(6)? != MAGIC
            || reader.array::<32>()? != network
            || reader.u64()? != height
            || reader.array::<32>()? != policy.profile
            || network == [0; 32]
            || height == 0
        {
            return Err("versioned body format, network, height or profile differs".into());
        }
        let slots = usize::from(reader.u16()?);
        let reward_mode = match reader.byte()? {
            0 => RewardMode::Voyager,
            1 => RewardMode::Holder,
            _ => return Err("unknown versioned reward mode".into()),
        };
        let rewards_count = usize::from(reader.byte()?);
        let claims_count = usize::from(reader.byte()?);
        let governance_count = usize::from(reader.byte()?);
        let issuances_count = usize::from(reader.byte()?);
        if !(MIN_SLOTS..=MAX_SLOTS).contains(&slots)
            || !slots.is_multiple_of(GROUP)
            || rewards_count != reward_count(reward_mode)
            || claims_count > MAX_FUND_SPENDS
            || governance_count > crate::eng2_governance::MAX_ACTIONS_PER_BLOCK
            || issuances_count > crate::issuance::RECORDS_CODEC_LIMIT
        {
            return Err("versioned body count bound".into());
        }
        let mut rewards = Vec::with_capacity(rewards_count);
        for _ in 0..rewards_count {
            rewards.push(reader.reward()?);
        }
        let fee_output = reader.reward()?;
        let mut fund_claims = Vec::with_capacity(claims_count);
        for _ in 0..claims_count {
            fund_claims.push(PublicFundClaim::decode(
                reader.take(super::fund_claim::ENCODED_BYTES)?,
            )?);
        }
        let mut governance = Vec::with_capacity(governance_count);
        for _ in 0..governance_count {
            governance.push(SignedAction::decode(
                reader.blob(SignedAction::MAX_ENCODED_BYTES)?,
            )?);
        }
        let mut issuances = Vec::with_capacity(issuances_count);
        for _ in 0..issuances_count {
            issuances.push(IssuanceRecord::decode(
                reader.blob(crate::issuance::MAX_RECORD_BYTES)?,
            )?);
        }
        let mut transactions = Vec::with_capacity(slots);
        for _ in 0..slots {
            transactions.push(Transaction::decode_envelope(
                reader.blob(MAX_ENVELOPE_BYTES)?,
                &network,
            )?);
        }
        let settlement_proof = reader.blob(policy.max_settlement_proof_bytes)?.to_vec();
        if !reader.0.is_empty() {
            return Err("trailing versioned body bytes".into());
        }
        let body = Self {
            network,
            height,
            profile: policy.profile,
            transactions,
            reward_mode,
            rewards,
            fee_output,
            fund_claims,
            governance,
            issuances,
            settlement_proof,
        };
        if body.encoded_len(policy)? != bytes.len() {
            return Err("versioned body length differs".into());
        }
        Ok(body)
    }

    /// Derive the exact standalone header commitment without buffering a second
    /// complete body. At most one bounded record is temporarily encoded.
    pub fn commitment(&self, policy: Policy) -> Result<Hash, String> {
        let length = self.encoded_len(policy)?;
        let mut hash = blake3::Hasher::new_derive_key("siworld eng2 canonical block body v1");
        hash.update(&(length as u64).to_le_bytes());
        self.emit(&mut |part| {
            hash.update(part);
        })?;
        Ok(*hash.finalize().as_bytes())
    }

    pub fn write_to(
        &self,
        output: &mut impl std::io::Write,
        policy: Policy,
    ) -> std::io::Result<()> {
        self.encoded_len(policy).map_err(invalid_stream)?;
        let mut error = None;
        self.emit(&mut |part| {
            if error.is_none()
                && let Err(failure) = output.write_all(part)
            {
                error = Some(failure);
            }
        })
        .map_err(invalid_stream)?;
        error.map_or(Ok(()), Err)
    }

    fn emit(&self, emit: &mut impl FnMut(&[u8])) -> Result<(), String> {
        emit(MAGIC);
        emit(&self.network);
        emit(&self.height.to_le_bytes());
        emit(&self.profile);
        emit(&(self.transactions.len() as u16).to_le_bytes());
        emit(&[
            match self.reward_mode {
                RewardMode::Voyager => 0,
                RewardMode::Holder => 1,
            },
            self.rewards.len() as u8,
            self.fund_claims.len() as u8,
            self.governance.len() as u8,
            self.issuances.len() as u8,
        ]);
        for reward in self.rewards.iter().chain([&self.fee_output]) {
            emit(&reward.commitment);
            emit(&reward.ciphertext);
        }
        for claim in &self.fund_claims {
            emit(&claim.encode());
        }
        let mut blob = |bytes: &[u8]| {
            emit(&(bytes.len() as u32).to_le_bytes());
            emit(bytes);
        };
        for action in &self.governance {
            blob(&action.encode()?);
        }
        for issuance in &self.issuances {
            blob(&issuance.encode()?);
        }
        for transaction in &self.transactions {
            blob(&transaction.encode_envelope(&self.network)?);
        }
        blob(&self.settlement_proof);
        Ok(())
    }
}

impl Policy {
    fn check(self) -> Result<(), String> {
        if self.profile == [0; 32]
            || self.max_body_bytes < PREFIX_BYTES
            || self.max_settlement_proof_bytes == 0
            || self.max_settlement_proof_bytes > u32::MAX as usize
        {
            return Err("invalid local versioned body policy".into());
        }
        Ok(())
    }
}
fn add(length: &mut usize, bytes: usize) -> Result<(), String> {
    *length = length.checked_add(bytes).ok_or("body length overflow")?;
    Ok(())
}
fn invalid_stream(message: impl ToString) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.to_string())
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], String> {
        let (bytes, rest) = self
            .0
            .split_at_checked(count)
            .ok_or("truncated body bytes")?;
        self.0 = rest;
        Ok(bytes)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        Ok(self.take(N)?.try_into().expect("bounded body field"))
    }
    fn byte(&mut self) -> Result<u8, String> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn blob(&mut self, maximum: usize) -> Result<&'a [u8], String> {
        let count = u32::from_le_bytes(self.array()?) as usize;
        if count == 0 || count > maximum {
            return Err("body record byte bound".into());
        }
        self.take(count)
    }
    fn reward(&mut self) -> Result<RewardRecord, String> {
        let reward = RewardRecord {
            commitment: self.array()?,
            ciphertext: self.array()?,
        };
        let _ = native::codec::decode_digest(&reward.commitment)
            .map_err(|_| "noncanonical body reward commitment")?;
        Ok(reward)
    }
}

#[cfg(test)]
pub(crate) mod tests;
