//! Fixed-capacity public data encoding for a local verifier process.
//!
//! Decoding establishes canonical syntax only. It does not authenticate a block,
//! select a protocol registration, or grant a ledger-transition capability.

use super::Error;
use crate::proof_codec::v2::{
    ProtocolBinding,
    complete_fee::{CAPACITY, FeeSchedule, SettlementPolicy, Statement, StatementInputs},
};
use native::{
    encryption::{PaymentAddress, PaymentCiphertext},
    multi_asset::{Digest, F},
    settlement::{RewardAllocation, RewardMode, RewardPlan},
};
use p3_field::{PrimeCharacteristicRing, PrimeField32};

const MAGIC: &[u8; 8] = b"SWFCPU01";
const DIGEST_BYTES: usize = 12 * 4;
const PUBLIC_KEY_BYTES: usize = 1184;
const PAYMENT_BYTES: usize = 1088 + 208 + 16 + 1;
const FIXED_BYTES: usize = 16
    + 2 * 32
    + 3 * 8
    + 2
    + 2 * DIGEST_BYTES
    + PUBLIC_KEY_BYTES
    + CAPACITY * DIGEST_BYTES
    + DIGEST_BYTES
    + PAYMENT_BYTES;
const REWARD_BYTES: usize = 2 * 8 + DIGEST_BYTES;
pub const MAX_STATEMENT_BYTES: usize = FIXED_BYTES + 5 * REWARD_BYTES;

pub(crate) struct PublicStatement {
    policy: SettlementPolicy,
    network: [u8; 32],
    transaction_list_digest: [u8; 32],
    address: PaymentAddress,
    fees: Vec<Digest>,
    rewards: Vec<Digest>,
    fee_commitment: Digest,
    payment: PaymentCiphertext,
}

impl PublicStatement {
    pub(crate) fn network(&self) -> [u8; 32] {
        self.network
    }

    pub(crate) fn statement(&self, binding: ProtocolBinding) -> Result<Statement, Error> {
        Statement::from_authenticated(
            StatementInputs {
                policy: &self.policy,
                network: self.network,
                transaction_list_digest: self.transaction_list_digest,
                address: &self.address,
                fee_commitments: &self.fees,
                reward_commitments: &self.rewards,
                fee_commitment: self.fee_commitment,
                ciphertext: &self.payment,
            },
            binding,
        )
        .map_err(|_| Error::PublicStatement)
    }
}

pub(crate) fn encode(inputs: StatementInputs<'_>) -> Result<Vec<u8>, Error> {
    let count = inputs.policy.plan.mode.note_count();
    if inputs.policy.max_slots != CAPACITY
        || inputs.fee_commitments.len() != CAPACITY
        || inputs.reward_commitments.len() != count
        || inputs.policy.plan.validate().is_err()
        || inputs.policy.fee_owner != inputs.address.owner()
        || inputs.network == [0; 32]
        || inputs.transaction_list_digest == [0; 32]
    {
        return Err(Error::PublicStatement);
    }
    let size = FIXED_BYTES + count * REWARD_BYTES;
    let mut out = Vec::new();
    out.try_reserve_exact(size).map_err(|_| Error::Allocation)?;
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&1u16.to_le_bytes());
    out.push(inputs.policy.plan.mode as u8);
    out.push(0);
    out.extend_from_slice(&(size as u32).to_le_bytes());
    out.extend_from_slice(&inputs.network);
    out.extend_from_slice(&inputs.transaction_list_digest);
    for value in [
        inputs.policy.plan.block_height,
        inputs.policy.fees.standard(),
        inputs.policy.fees.priority(),
    ] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.extend_from_slice(&(CAPACITY as u16).to_le_bytes());
    put_digest(&mut out, &inputs.policy.fee_owner);
    put_digest(&mut out, &inputs.address.owner());
    out.extend_from_slice(inputs.address.encapsulation_key());
    for digest in inputs.fee_commitments {
        put_digest(&mut out, digest);
    }
    for (allocation, commitment) in inputs
        .policy
        .plan
        .allocations
        .iter()
        .zip(inputs.reward_commitments)
    {
        out.extend_from_slice(&allocation.amount.to_le_bytes());
        out.extend_from_slice(&allocation.unlock_height.to_le_bytes());
        put_digest(&mut out, commitment);
    }
    put_digest(&mut out, &inputs.fee_commitment);
    out.extend_from_slice(&inputs.ciphertext.kem_ciphertext);
    out.extend_from_slice(&inputs.ciphertext.body);
    out.extend_from_slice(&inputs.ciphertext.tag);
    out.push(inputs.ciphertext.view_tag);
    debug_assert_eq!(out.len(), size);
    Ok(out)
}

fn put_digest(out: &mut Vec<u8>, digest: &Digest) {
    for field in digest {
        out.extend_from_slice(&field.as_canonical_u32().to_le_bytes());
    }
}

pub(crate) fn decode(bytes: &[u8]) -> Result<PublicStatement, Error> {
    // A fixed header determines one of two exact sizes before vector allocation.
    if bytes.len() < 16 || bytes.len() > MAX_STATEMENT_BYTES {
        return Err(Error::Encoding);
    }
    if &bytes[..8] != MAGIC || bytes[8..10] != 1u16.to_le_bytes() || bytes[11] != 0 {
        return Err(Error::Encoding);
    }
    let mode = match bytes[10] {
        0 => RewardMode::Voyager,
        1 => RewardMode::Holder,
        _ => return Err(Error::Encoding),
    };
    let count = mode.note_count();
    let size = FIXED_BYTES + count * REWARD_BYTES;
    if bytes.len() != size || u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize != size
    {
        return Err(Error::Encoding);
    }
    let mut input = Cursor { bytes, offset: 16 };
    let network = input.take()?;
    let transaction_list_digest = input.take()?;
    let height = input.integer()?;
    let standard = input.integer()?;
    let priority = input.integer()?;
    // FeeSchedule owns its invariants. Reconstruct its canonical representative,
    // rather than accepting a new schedule constructor or reducing field words.
    let fees = FeeSchedule::from_previous_standard(
        standard.checked_mul(10).ok_or(Error::PublicStatement)?,
    )
    .map_err(|_| Error::PublicStatement)?;
    if fees.priority() != priority || input.take::<2>()? != (CAPACITY as u16).to_le_bytes() {
        return Err(Error::PublicStatement);
    }
    let fee_owner = input.digest()?;
    let owner = input.digest()?;
    if owner != fee_owner || network == [0; 32] || transaction_list_digest == [0; 32] {
        return Err(Error::PublicStatement);
    }
    let address = PaymentAddress::new(owner, input.take()?).map_err(|_| Error::PublicStatement)?;
    let mut commitments = Vec::with_capacity(CAPACITY);
    for _ in 0..CAPACITY {
        commitments.push(input.digest()?);
    }
    let mut allocations = Vec::with_capacity(count);
    let mut rewards = Vec::with_capacity(count);
    for _ in 0..count {
        allocations.push(RewardAllocation {
            amount: input.integer()?,
            unlock_height: input.integer()?,
        });
        rewards.push(input.digest()?);
    }
    let fee_commitment = input.digest()?;
    let payment = PaymentCiphertext {
        kem_ciphertext: input.take()?,
        body: input.take()?,
        tag: input.take()?,
        view_tag: input.take::<1>()?[0],
    };
    if input.offset != bytes.len() {
        return Err(Error::Encoding);
    }
    let plan = RewardPlan {
        block_height: height,
        mode,
        allocations,
    };
    plan.validate().map_err(|_| Error::PublicStatement)?;
    Ok(PublicStatement {
        policy: SettlementPolicy {
            plan,
            fee_owner,
            fees,
            max_slots: CAPACITY,
        },
        network,
        transaction_list_digest,
        address,
        fees: commitments,
        rewards,
        fee_commitment,
        payment,
    })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl Cursor<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let end = self.offset.checked_add(N).ok_or(Error::Encoding)?;
        let bytes = self.bytes.get(self.offset..end).ok_or(Error::Encoding)?;
        self.offset = end;
        Ok(bytes.try_into().unwrap())
    }
    fn integer(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.take()?))
    }
    fn digest(&mut self) -> Result<Digest, Error> {
        let mut digest = [F::ZERO; 12];
        for value in &mut digest {
            let word = u32::from_le_bytes(self.take()?);
            if word >= F::ORDER_U32 {
                return Err(Error::Encoding);
            }
            *value = F::from_u32(word);
        }
        Ok(digest)
    }
}
