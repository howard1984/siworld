//! Unselected fee-first body containing one complete fee frame and windowed operations.
//! Structural framing is not transaction/proof verification or ledger admission.
use super::{
    body::{Body, Policy},
    candidate_registry::{BODY_LAYOUT, CandidateRegistry},
    fee_candidate::receive::{FeeFirstLengths, read_fee_first_payload},
    fund_claim::WindowedFundClaim,
    windowed_authorization::WindowedAuthorizationBody,
};
use crate::proof_codec::v2::{
    self, MAX_FEE_PROOF_BYTES, MAX_ISSUANCE_PROOF_BYTES, MAX_TRANSACTION_PROOF_BYTES,
};
use crate::{eng2_governance::WindowedSignedAction, issuance::IssuanceRecord, wire::*};
use std::io::{Read, Take, Write};

pub const PREFIX_BYTES: usize = 164;
const PAYLOAD_PREFIX_BYTES: usize = 7;
const CLAIM_BYTES: usize = super::fund_claim::ENCODED_BYTES + 8;

/// Body is only an in-memory carrier here: its legacy operations must be empty,
/// and its settlement_proof is the sole CompleteFee frame, emitted first.
/// The legacy encoded body or windowed wrapper is never embedded on this wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeWindowedBody {
    pub body: Body,
    pub authorizations: WindowedAuthorizationBody,
}

/// Immutable framing view shared by future producer and validator adapters.
/// It freezes one full-body commitment, not a parent or ledger-state capability.
pub struct PreparedCandidateBody<'a> {
    body: &'a FeeWindowedBody,
    registry: &'a CandidateRegistry,
    commitment: Hash,
}
impl<'a> PreparedCandidateBody<'a> {
    pub fn prepare(
        body: &'a FeeWindowedBody,
        registry: &'a CandidateRegistry,
    ) -> Result<Self, String> {
        let commitment = body.commitment(registry)?;
        Ok(Self {
            body,
            registry,
            commitment,
        })
    }
    pub fn body(&self) -> &FeeWindowedBody {
        self.body
    }
    pub fn registry(&self) -> &CandidateRegistry {
        self.registry
    }
    pub fn commitment(&self) -> Hash {
        self.commitment
    }
}

pub fn maximum_bytes() -> Result<usize, String> {
    crate::wire::MAX_BLOCK_BYTES
        .checked_add(MAX_FEE_PROOF_BYTES)
        .and_then(|n| n.checked_add(PREFIX_BYTES))
        .and_then(|n| n.checked_add(MAX_FUND_SPENDS * CLAIM_BYTES))
        .and_then(|n| {
            n.checked_add(
                crate::eng2_governance::MAX_ACTIONS_PER_BLOCK
                    * (4 + WindowedSignedAction::MAX_ENCODED_BYTES),
            )
        })
        .ok_or("candidate body maximum overflows".into())
}
fn policy(registry: &CandidateRegistry) -> Result<Policy, String> {
    Ok(Policy {
        profile: registry.suite().id(),
        max_body_bytes: maximum_bytes()?,
        max_settlement_proof_bytes: MAX_FEE_PROOF_BYTES,
    })
}
impl FeeWindowedBody {
    pub fn encoded_len(&self, registry: &CandidateRegistry) -> Result<usize, String> {
        let b = &self.body;
        self.authorizations.check(b)?;
        if b.network != registry.network()
            || self.authorizations.genesis != registry.genesis()
            || self.authorizations.rules_commitment != registry.rules()
        {
            return Err("candidate body local registry context differs".into());
        }
        let base = b.encoded_len(policy(registry)?)?;
        v2::parse(&b.settlement_proof, registry.fee(), MAX_FEE_PROOF_BYTES)
            .map_err(|_| "candidate requires exactly one CompleteFee frame")?;
        for tx in &b.transactions {
            v2::parse(
                &tx.proof,
                registry.transaction(),
                MAX_TRANSACTION_PROOF_BYTES,
            )
            .map_err(|_| "candidate transaction frame identity differs")?;
        }
        for issuance in &b.issuances {
            v2::parse(
                &issuance.proof,
                registry.issuance(),
                MAX_ISSUANCE_PROOF_BYTES,
            )
            .map_err(|_| "candidate issuance frame identity differs")?;
        }
        let mut length = base
            .checked_sub(super::body::PREFIX_BYTES + 4)
            .and_then(|n| n.checked_add(PREFIX_BYTES + PAYLOAD_PREFIX_BYTES))
            .and_then(|n| n.checked_add(self.authorizations.fund_claims.len() * CLAIM_BYTES))
            .ok_or("candidate body length overflows")?;
        for action in &self.authorizations.governance {
            length = length
                .checked_add(4 + action.encode()?.len())
                .ok_or("candidate body length overflows")?;
        }
        if length > maximum_bytes()? {
            return Err("candidate body byte bound".into());
        }
        Ok(length)
    }
    pub fn encode(&self, registry: &CandidateRegistry) -> Result<Vec<u8>, String> {
        let n = self.encoded_len(registry)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(n)
            .map_err(|_| "candidate body allocation")?;
        self.emit(registry, n, &mut |part| bytes.extend_from_slice(part))?;
        Ok(bytes)
    }
    pub fn commitment(&self, registry: &CandidateRegistry) -> Result<Hash, String> {
        let n = self.encoded_len(registry)?;
        let mut h =
            blake3::Hasher::new_derive_key("siworld inactive fee windowed body candidate v1");
        self.emit(registry, n, &mut |part| {
            h.update(part);
        })?;
        Ok(*h.finalize().as_bytes())
    }
    pub fn write_to(
        &self,
        output: &mut impl Write,
        registry: &CandidateRegistry,
    ) -> std::io::Result<()> {
        let n = self.encoded_len(registry).map_err(invalid)?;
        let mut error = None;
        self.emit(registry, n, &mut |part| {
            if error.is_none()
                && let Err(e) = output.write_all(part)
            {
                error = Some(e);
            }
        })
        .map_err(invalid)?;
        error.map_or(Ok(()), Err)
    }
    fn emit(
        &self,
        registry: &CandidateRegistry,
        total: usize,
        emit: &mut impl FnMut(&[u8]),
    ) -> Result<(), String> {
        let b = &self.body;
        let payload = total - PREFIX_BYTES - b.settlement_proof.len();
        emit(BODY_LAYOUT);
        emit(&b.network);
        emit(&registry.genesis());
        emit(&registry.rules());
        emit(&registry.suite().id());
        emit(&b.height.to_le_bytes());
        emit(&(total as u64).to_le_bytes());
        emit(&(b.settlement_proof.len() as u32).to_le_bytes());
        emit(&(payload as u64).to_le_bytes());
        emit(&b.settlement_proof);
        emit(&(b.transactions.len() as u16).to_le_bytes());
        emit(&[
            match b.reward_mode {
                RewardMode::Voyager => 0,
                RewardMode::Holder => 1,
            },
            b.rewards.len() as u8,
            self.authorizations.fund_claims.len() as u8,
            self.authorizations.governance.len() as u8,
            b.issuances.len() as u8,
        ]);
        for reward in b.rewards.iter().chain([&b.fee_output]) {
            emit(&reward.commitment);
            emit(&reward.ciphertext);
        }
        for claim in &self.authorizations.fund_claims {
            emit(&claim.encode()?);
        }
        let mut blob = |part: &[u8]| {
            emit(&(part.len() as u32).to_le_bytes());
            emit(part);
        };
        for action in &self.authorizations.governance {
            blob(&action.encode()?);
        }
        for issuance in &b.issuances {
            blob(&issuance.encode()?);
        }
        for tx in &b.transactions {
            blob(&tx.encode_envelope(&b.network)?);
        }
        Ok(())
    }

    /// Read a selected candidate envelope, never a buffered legacy body. The
    /// caller supplies the transport-declared outer length, local registry and deadline.
    /// Header rejection precedes fee allocation; each payload record has a
    /// declaration checked against both its own cap and the remaining payload.
    pub fn read_from<R: Read>(
        reader: &mut R,
        declared_total: u64,
        registry: &CandidateRegistry,
        height: u64,
    ) -> Result<Self, String> {
        if declared_total < PREFIX_BYTES as u64
            || declared_total > maximum_bytes()? as u64
            || height == 0
        {
            return Err("candidate outer body bound".into());
        }
        let prefix = array::<PREFIX_BYTES>(reader)?;
        if &prefix[..8] != BODY_LAYOUT
            || prefix[8..40] != registry.network()
            || prefix[40..72] != registry.genesis()
            || prefix[72..104] != registry.rules()
            || prefix[104..136] != registry.suite().id()
            || prefix[136..144] != height.to_le_bytes()
            || prefix[144..152] != declared_total.to_le_bytes()
        {
            return Err("candidate body version or local context differs".into());
        }
        let fee =
            u32::from_le_bytes(prefix[152..156].try_into().expect("fixed fee declaration")) as u64;
        let payload = u64::from_le_bytes(
            prefix[156..164]
                .try_into()
                .expect("fixed payload declaration"),
        );
        let lengths = FeeFirstLengths::check(
            fee,
            payload,
            declared_total - PREFIX_BYTES as u64,
            maximum_bytes()? - PREFIX_BYTES,
        )
        .map_err(|_| "candidate body declared lengths differ")?;
        let received = read_fee_first_payload(reader, lengths, registry.fee(), |input| {
            read_payload(input, registry, height)
        })
        .map_err(|e| format!("candidate fee-first reception: {e:?}"))?;
        let (fee, (mut body, authorizations)) = received.into_parts();
        body.settlement_proof = fee;
        let result = Self {
            body,
            authorizations,
        };
        if result.encoded_len(registry)? as u64 != declared_total {
            return Err("candidate canonical length differs".into());
        }
        Ok(result)
    }
}
fn read_payload<R: Read>(
    input: &mut Take<&mut R>,
    registry: &CandidateRegistry,
    height: u64,
) -> Result<(Body, WindowedAuthorizationBody), String> {
    let count = array::<PAYLOAD_PREFIX_BYTES>(input)?;
    let slots = u16::from_le_bytes(count[..2].try_into().expect("fixed slot count")) as usize;
    let mode = match count[2] {
        0 => RewardMode::Voyager,
        1 => RewardMode::Holder,
        _ => return Err("candidate reward mode".into()),
    };
    let rewards = usize::from(count[3]);
    let claims = usize::from(count[4]);
    let actions = usize::from(count[5]);
    let issuances = usize::from(count[6]);
    if !(MIN_SLOTS..=MAX_SLOTS).contains(&slots)
        || !slots.is_multiple_of(GROUP)
        || rewards != reward_count(mode)
        || claims > MAX_FUND_SPENDS
        || actions > crate::eng2_governance::MAX_ACTIONS_PER_BLOCK
        || issuances > crate::issuance::RECORDS_CODEC_LIMIT
    {
        return Err("candidate payload count bound".into());
    }
    let mut body = Body {
        network: registry.network(),
        height,
        profile: registry.suite().id(),
        transactions: Vec::with_capacity(slots),
        reward_mode: mode,
        rewards: Vec::with_capacity(rewards),
        fee_output: RewardRecord {
            commitment: [0; 48],
            ciphertext: [0; REWARD_CIPHERTEXT_BYTES],
        },
        fund_claims: Vec::new(),
        governance: Vec::new(),
        issuances: Vec::with_capacity(issuances),
        settlement_proof: Vec::new(),
    };
    for _ in 0..rewards {
        body.rewards.push(read_reward(input)?);
    }
    body.fee_output = read_reward(input)?;
    let mut authorizations = WindowedAuthorizationBody {
        network: registry.network(),
        genesis: registry.genesis(),
        rules_commitment: registry.rules(),
        height,
        fund_claims: Vec::with_capacity(claims),
        governance: Vec::with_capacity(actions),
    };
    for _ in 0..claims {
        authorizations
            .fund_claims
            .push(WindowedFundClaim::decode(&array::<CLAIM_BYTES>(input)?)?);
    }
    for _ in 0..actions {
        authorizations
            .governance
            .push(WindowedSignedAction::decode(&blob(
                input,
                WindowedSignedAction::MAX_ENCODED_BYTES,
            )?)?);
    }
    for _ in 0..issuances {
        body.issuances.push(IssuanceRecord::decode(&blob(
            input,
            crate::issuance::MAX_RECORD_BYTES,
        )?)?);
    }
    for _ in 0..slots {
        body.transactions.push(Transaction::decode_envelope(
            &blob(input, MAX_ENVELOPE_BYTES)?,
            &registry.network(),
        )?);
    }
    Ok((body, authorizations))
}
fn array<const N: usize>(reader: &mut impl Read) -> Result<[u8; N], String> {
    let mut out = [0; N];
    reader
        .read_exact(&mut out)
        .map_err(|_| "truncated candidate body")?;
    Ok(out)
}
fn blob<R: Read>(reader: &mut Take<&mut R>, maximum: usize) -> Result<Vec<u8>, String> {
    let n = u32::from_le_bytes(array::<4>(reader)?) as usize;
    if n == 0 || n > maximum || n as u64 > reader.limit() {
        return Err("candidate record declaration bound".into());
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(n)
        .map_err(|_| "candidate record allocation")?;
    bytes.resize(n, 0);
    reader
        .read_exact(&mut bytes)
        .map_err(|_| "truncated candidate record")?;
    Ok(bytes)
}
fn read_reward(reader: &mut impl Read) -> Result<RewardRecord, String> {
    let record = RewardRecord {
        commitment: array(reader)?,
        ciphertext: array(reader)?,
    };
    let _ = native::codec::decode_digest(&record.commitment)
        .map_err(|_| "noncanonical candidate reward")?;
    Ok(record)
}
fn invalid(message: impl ToString) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.to_string())
}

#[cfg(test)]
mod tests;
