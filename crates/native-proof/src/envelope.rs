//! Bounded native transaction/settlement framing and private fee-opening sidecars.
//!
//! The fixed context selects local verifier metadata; it never carries a key.
//! Decoding establishes canonical structure, not cryptographic proof validity.

use crate::codec::{
    CodecError, FORMAT_VERSION, PUBLIC_TRANSACTION_BYTES, ProofContext, PublicTransaction,
    SUITE_ID, decode_digest, encode_digest,
};
use crate::common::{Digest, F, FEE_BLIND_LEN, Hasher};
use crate::fee_settlement::{FeeOpening, SettlementSlot};
use crate::proof_codec::{MAX_NATIVE_PROOF_BODY_LEN, ProofDecodeError, ProofShape};
use crate::snapshots::{SnapshotId, TransactionId};
use p3_field::{PrimeCharacteristicRing, PrimeField32};

const MAGIC: &[u8; 4] = b"SWTX";
const SIDECAR_MAGIC: &[u8; 4] = b"SWFS";
const PUBLIC_OFFSET: usize = 4 + 2 + SUITE_ID.len() + 32 + 8 + 32;
const FEE_OFFSET: usize = PUBLIC_OFFSET + PUBLIC_TRANSACTION_BYTES;
const PROOF_LENGTH_OFFSET: usize = FEE_OFFSET + 48;
pub const FIXED_ENVELOPE_BYTES: usize = PROOF_LENGTH_OFFSET + 4;
pub const MAX_ENVELOPE_BYTES: usize = FIXED_ENVELOPE_BYTES + MAX_NATIVE_PROOF_BODY_LEN;
pub const FEE_SIDECAR_BYTES: usize = 4 + 2 + 32 + 8 + 4 * FEE_BLIND_LEN;
pub const MAX_ENVELOPE_WITH_SIDECAR_BYTES: usize = MAX_ENVELOPE_BYTES + FEE_SIDECAR_BYTES;
pub const FIXED_SETTLEMENT_ENVELOPE_BYTES: usize = 159;
pub const MAX_SETTLEMENT_ENVELOPE_BYTES: usize =
    FIXED_SETTLEMENT_ENVELOPE_BYTES + MAX_NATIVE_PROOF_BODY_LEN;
pub const SETTLEMENT_CAPACITY: usize = 576;
pub const NATIVE_ENVELOPE_SCHEMA: &str = "SWTX:version-u16:suite27:network32:snapshot-height-u64:snapshot-block32:public1742:fee-commit48:proof-length-u32:proof";
pub const SETTLEMENT_ENVELOPE_SCHEMA: &str = "SWST:version-u16:suite27:network32:height-u64:slots-u16:ordered-list32:miner-cm48:proof-length-u32:proof";
pub const FEE_SIDECAR_SCHEMA: &str = "SWFS:version-u16:txid32:fee-u64:blind8-canonical-le32";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    Length,
    Magic,
    Version,
    Suite,
    Network,
    Public(CodecError),
    FeeCommitment(CodecError),
    Proof(ProofDecodeError),
    SlotCount,
    BlockContext,
    PublicStatement,
    DuplicateTransaction,
}

/// A borrowed proof body with canonical, fixed-size statement fields.
/// Canonical snapshot membership and cryptographic verification are separate
/// admission steps. The network is selected locally when decoding peer bytes.
pub struct NativeEnvelope<'a> {
    network: [u8; 32],
    snapshot: SnapshotId,
    transaction: PublicTransaction,
    fee_commit: Digest,
    proof_body: &'a [u8],
}

impl<'a> NativeEnvelope<'a> {
    pub fn from_parts(
        network: [u8; 32],
        snapshot: SnapshotId,
        transaction: PublicTransaction,
        fee_commit: Digest,
        proof_body: &'a [u8],
        shape: &ProofShape,
    ) -> Result<Self, EnvelopeError> {
        PublicTransaction::decode(&transaction.encode()).map_err(EnvelopeError::Public)?;
        shape
            .validate_encoding(proof_body)
            .map_err(EnvelopeError::Proof)?;
        Ok(Self {
            network,
            snapshot,
            transaction,
            fee_commit,
            proof_body,
        })
    }

    pub fn decode(
        bytes: &'a [u8],
        expected_network: &[u8; 32],
        shape: &ProofShape,
    ) -> Result<Self, EnvelopeError> {
        if !(FIXED_ENVELOPE_BYTES..=MAX_ENVELOPE_BYTES).contains(&bytes.len()) {
            return Err(EnvelopeError::Length);
        }
        if &bytes[..4] != MAGIC {
            return Err(EnvelopeError::Magic);
        }
        if bytes[4..6] != FORMAT_VERSION.to_le_bytes() {
            return Err(EnvelopeError::Version);
        }
        if &bytes[6..6 + SUITE_ID.len()] != SUITE_ID {
            return Err(EnvelopeError::Suite);
        }
        let network_offset = 6 + SUITE_ID.len();
        let network: [u8; 32] = bytes[network_offset..network_offset + 32]
            .try_into()
            .expect("fixed network");
        if &network != expected_network {
            return Err(EnvelopeError::Network);
        }
        let height_offset = network_offset + 32;
        let snapshot = SnapshotId {
            height: u64::from_le_bytes(
                bytes[height_offset..height_offset + 8]
                    .try_into()
                    .expect("fixed height"),
            ),
            block_id: bytes[height_offset + 8..PUBLIC_OFFSET]
                .try_into()
                .expect("fixed block ID"),
        };
        let transaction = PublicTransaction::decode(&bytes[PUBLIC_OFFSET..FEE_OFFSET])
            .map_err(EnvelopeError::Public)?;
        let fee_commit = decode_digest(
            bytes[FEE_OFFSET..PROOF_LENGTH_OFFSET]
                .try_into()
                .expect("fixed digest"),
        )
        .map_err(EnvelopeError::FeeCommitment)?;
        let body_len = u32::from_le_bytes(
            bytes[PROOF_LENGTH_OFFSET..FIXED_ENVELOPE_BYTES]
                .try_into()
                .expect("fixed proof length"),
        ) as usize;
        if body_len > MAX_NATIVE_PROOF_BODY_LEN || body_len != bytes.len() - FIXED_ENVELOPE_BYTES {
            return Err(EnvelopeError::Length);
        }
        Self::from_parts(
            network,
            snapshot,
            transaction,
            fee_commit,
            &bytes[FIXED_ENVELOPE_BYTES..],
            shape,
        )
    }

    /// Revalidate the same proof schema used by the peer decoder before emitting
    /// bytes. An encoder cannot produce an envelope its decoder would reject.
    pub fn encode(&self, shape: &ProofShape) -> Result<Vec<u8>, EnvelopeError> {
        shape
            .validate_encoding(self.proof_body)
            .map_err(EnvelopeError::Proof)?;
        let mut bytes = Vec::with_capacity(FIXED_ENVELOPE_BYTES + self.proof_body.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes.extend_from_slice(SUITE_ID);
        bytes.extend_from_slice(&self.network);
        bytes.extend_from_slice(&self.snapshot.height.to_le_bytes());
        bytes.extend_from_slice(&self.snapshot.block_id);
        bytes.extend_from_slice(&self.transaction.encode());
        bytes.extend_from_slice(&encode_digest(&self.fee_commit));
        bytes.extend_from_slice(&(self.proof_body.len() as u32).to_le_bytes());
        bytes.extend_from_slice(self.proof_body);
        Ok(bytes)
    }

    pub fn transaction(&self) -> &PublicTransaction {
        &self.transaction
    }
    pub fn fee_commit(&self) -> &Digest {
        &self.fee_commit
    }
    pub fn proof_body(&self) -> &'a [u8] {
        self.proof_body
    }
    pub fn snapshot_id(&self) -> SnapshotId {
        self.snapshot
    }
    pub fn context(&self) -> ProofContext {
        ProofContext::for_snapshot(self.network, self.snapshot.height, self.snapshot.block_id)
    }
    pub fn transaction_id(&self) -> TransactionId {
        statement_id(
            &self.network,
            self.snapshot,
            &self.transaction,
            &self.fee_commit,
        )
    }
}

/// Identity of the canonical statement. Randomized proof encodings, proof
/// lengths and private fee sidecars deliberately do not enter this digest.
pub fn statement_id(
    network: &[u8; 32],
    snapshot: SnapshotId,
    transaction: &PublicTransaction,
    fee_commit: &Digest,
) -> TransactionId {
    let mut hash = blake3::Hasher::new_derive_key("siworld native transaction identity v1");
    hash.update(&(SUITE_ID.len() as u16).to_le_bytes());
    hash.update(SUITE_ID);
    hash.update(&FORMAT_VERSION.to_le_bytes());
    hash.update(network);
    hash.update(&snapshot.height.to_le_bytes());
    hash.update(&snapshot.block_id);
    hash.update(&transaction.encode());
    hash.update(&encode_digest(fee_commit));
    *hash.finalize().as_bytes()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeSidecarError {
    Length,
    Magic,
    Version,
    NoncanonicalField,
    Missing,
    TransactionBinding,
    Commitment,
}

/// An authenticated opening, without inferred transaction-class or tier flags.
/// The native transaction proof checks the private anchor's fee schedule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedFeeOpening {
    pub fee: u64,
    pub blind: [F; FEE_BLIND_LEN],
}

/// Private relay witness, without signatures, encryption wrappers or tier flags.
/// Connection confidentiality belongs to the authenticated hybrid transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeOpeningSidecar {
    transaction_id: TransactionId,
    fee: u64,
    blind: [F; FEE_BLIND_LEN],
}

impl FeeOpeningSidecar {
    pub fn new(transaction_id: TransactionId, fee: u64, blind: [F; FEE_BLIND_LEN]) -> Self {
        Self {
            transaction_id,
            fee,
            blind,
        }
    }
    pub fn transaction_id(&self) -> TransactionId {
        self.transaction_id
    }
    pub fn fee(&self) -> u64 {
        self.fee
    }
    pub fn encode(&self) -> [u8; FEE_SIDECAR_BYTES] {
        let mut bytes = [0; FEE_SIDECAR_BYTES];
        bytes[..4].copy_from_slice(SIDECAR_MAGIC);
        bytes[4..6].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[6..38].copy_from_slice(&self.transaction_id);
        bytes[38..46].copy_from_slice(&self.fee.to_le_bytes());
        for (dst, value) in bytes[46..]
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(&self.blind)
        {
            *dst = value.as_canonical_u32().to_le_bytes();
        }
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, FeeSidecarError> {
        if bytes.len() != FEE_SIDECAR_BYTES {
            return Err(FeeSidecarError::Length);
        }
        if &bytes[..4] != SIDECAR_MAGIC {
            return Err(FeeSidecarError::Magic);
        }
        if bytes[4..6] != FORMAT_VERSION.to_le_bytes() {
            return Err(FeeSidecarError::Version);
        }
        let mut blind = [F::ZERO; FEE_BLIND_LEN];
        for (dst, value) in blind.iter_mut().zip(bytes[46..].as_chunks::<4>().0) {
            let value = u32::from_le_bytes(*value);
            if value >= F::ORDER_U32 {
                return Err(FeeSidecarError::NoncanonicalField);
            }
            *dst = F::from_u32(value);
        }
        Ok(Self::new(
            bytes[6..38].try_into().expect("fixed transaction ID"),
            u64::from_le_bytes(bytes[38..46].try_into().expect("fixed fee")),
            blind,
        ))
    }
}

/// Validate only transaction identity and commitment opening. A transaction's
/// private anchor can carry an older fee schedule, so the block's current base
/// fee must not be used to classify or reject this opening. The native proof
/// checks zero/standard/priority semantics under its private anchored schedule.
pub fn validate_fee_sidecar(
    envelope: &NativeEnvelope<'_>,
    sidecar: Option<&FeeOpeningSidecar>,
) -> Result<ValidatedFeeOpening, FeeSidecarError> {
    let sidecar = sidecar.ok_or(FeeSidecarError::Missing)?;
    if sidecar.transaction_id != envelope.transaction_id() {
        return Err(FeeSidecarError::TransactionBinding);
    }
    if Hasher::new().fee_commit(sidecar.fee, &sidecar.blind) != *envelope.fee_commit() {
        return Err(FeeSidecarError::Commitment);
    }
    Ok(ValidatedFeeOpening {
        fee: sidecar.fee,
        blind: sidecar.blind,
    })
}

/// Context reconstructed by a validated candidate-block builder. A peer's
/// envelope is compared with this complete local context before proof decoding.
/// The list digest binds the declared count, order and transaction identities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementEnvelopeContext {
    pub network: [u8; 32],
    pub block_height: u64,
    pub block_slots: u16,
    pub transaction_list_digest: [u8; 32],
    pub miner_note_commitment: Digest,
}

impl SettlementEnvelopeContext {
    pub fn from_transactions(
        network: [u8; 32],
        block_height: u64,
        transaction_ids: &[TransactionId],
        miner_note_commitment: Digest,
    ) -> Result<Self, EnvelopeError> {
        Ok(Self {
            network,
            block_height,
            block_slots: transaction_ids
                .len()
                .try_into()
                .map_err(|_| EnvelopeError::SlotCount)?,
            transaction_list_digest: ordered_transaction_digest(
                &network,
                block_height,
                transaction_ids,
            )?,
            miner_note_commitment,
        })
    }

    fn validate(&self) -> Result<(), EnvelopeError> {
        validate_slot_count(self.block_slots as usize)
    }

    /// Build the fixed-576 AIR statement from exactly the declared block's
    /// trusted ordered fee commitments. Internal unused AIR rows use canonical
    /// zero-fee tails; they are not additional block transaction positions.
    /// Issuance, context and the miner commitment must also come from the trusted
    /// candidate block. No peer-selected public values are accepted here.
    pub fn public_inputs(
        &self,
        received: &[Digest],
        issuance: u64,
    ) -> Result<Vec<F>, EnvelopeError> {
        self.validate()?;
        if received.len() != self.block_slots as usize {
            return Err(EnvelopeError::SlotCount);
        }
        let tails = zero_fee_tail(self)?;
        let mut public =
            Vec::with_capacity(crate::fee_settlement_air::public_len(SETTLEMENT_CAPACITY));
        for commitment in received {
            public.extend_from_slice(commitment);
        }
        for tail in tails {
            public.extend_from_slice(&tail.commitment);
        }
        public.extend_from_slice(&crate::common::limbs(issuance));
        public.extend_from_slice(&crate::common::limbs(self.block_height));
        for bytes in [&self.network, &self.transaction_list_digest] {
            for pair in bytes.as_chunks::<2>().0 {
                public.push(F::from_u32(u16::from_le_bytes(*pair) as u32));
            }
        }
        public.extend_from_slice(&self.miner_note_commitment);
        crate::fee_settlement_air::validate_settlement_public(SETTLEMENT_CAPACITY, &public)
            .map_err(|_| EnvelopeError::PublicStatement)?;
        Ok(public)
    }
}

fn validate_slot_count(count: usize) -> Result<(), EnvelopeError> {
    if !(64..=SETTLEMENT_CAPACITY).contains(&count) || !count.is_multiple_of(16) {
        return Err(EnvelopeError::SlotCount);
    }
    Ok(())
}

pub fn ordered_transaction_digest(
    network: &[u8; 32],
    block_height: u64,
    transaction_ids: &[TransactionId],
) -> Result<[u8; 32], EnvelopeError> {
    validate_slot_count(transaction_ids.len())?;
    let mut seen = std::collections::BTreeSet::new();
    let mut hash =
        blake3::Hasher::new_derive_key("siworld native settlement ordered transactions v1");
    hash.update(network);
    hash.update(&block_height.to_le_bytes());
    hash.update(&(transaction_ids.len() as u16).to_le_bytes());
    for id in transaction_ids {
        if !seen.insert(*id) {
            return Err(EnvelopeError::DuplicateTransaction);
        }
        hash.update(id);
    }
    Ok(*hash.finalize().as_bytes())
}

/// Reproducible internal zero-opening rows for the fixed-capacity settlement
/// AIR. BLAKE3 XOF rejection sampling produces eight uniform canonical fields.
/// These public, context-specific tails are outside the declared block slots;
/// they must never be used as indistinguishable on-chain transaction padding.
pub fn zero_fee_tail(
    context: &SettlementEnvelopeContext,
) -> Result<Vec<SettlementSlot>, EnvelopeError> {
    context.validate()?;
    let h = Hasher::new();
    let mut tails = Vec::with_capacity(SETTLEMENT_CAPACITY - context.block_slots as usize);
    for index in context.block_slots as usize..SETTLEMENT_CAPACITY {
        let mut hash = blake3::Hasher::new_derive_key("siworld native settlement zero fee tail v1");
        hash.update(&context.network);
        hash.update(&context.block_height.to_le_bytes());
        hash.update(&context.block_slots.to_le_bytes());
        hash.update(&(index as u16).to_le_bytes());
        let mut reader = hash.finalize_xof();
        let mut blind = [F::ZERO; FEE_BLIND_LEN];
        for field in &mut blind {
            loop {
                let mut bytes = [0; 4];
                reader.fill(&mut bytes);
                let value = u32::from_le_bytes(bytes);
                if value < F::ORDER_U32 {
                    *field = F::from_u32(value);
                    break;
                }
            }
        }
        tails.push(SettlementSlot::from_opening(&h, FeeOpening::dummy(blind)));
    }
    Ok(tails)
}

pub struct SettlementEnvelope<'a> {
    context: SettlementEnvelopeContext,
    proof_body: &'a [u8],
}
impl<'a> SettlementEnvelope<'a> {
    pub fn from_parts(
        context: SettlementEnvelopeContext,
        proof_body: &'a [u8],
        shape: &ProofShape,
    ) -> Result<Self, EnvelopeError> {
        context.validate()?;
        shape
            .validate_encoding(proof_body)
            .map_err(EnvelopeError::Proof)?;
        Ok(Self {
            context,
            proof_body,
        })
    }
    pub fn decode(
        bytes: &'a [u8],
        expected: &SettlementEnvelopeContext,
        shape: &ProofShape,
    ) -> Result<Self, EnvelopeError> {
        expected.validate()?;
        if !(FIXED_SETTLEMENT_ENVELOPE_BYTES..=MAX_SETTLEMENT_ENVELOPE_BYTES).contains(&bytes.len())
        {
            return Err(EnvelopeError::Length);
        }
        if &bytes[..4] != b"SWST" {
            return Err(EnvelopeError::Magic);
        }
        if bytes[4..6] != FORMAT_VERSION.to_le_bytes() {
            return Err(EnvelopeError::Version);
        }
        if &bytes[6..33] != SUITE_ID {
            return Err(EnvelopeError::Suite);
        }
        let context = SettlementEnvelopeContext {
            network: bytes[33..65].try_into().expect("fixed network"),
            block_height: u64::from_le_bytes(bytes[65..73].try_into().expect("fixed height")),
            block_slots: u16::from_le_bytes(bytes[73..75].try_into().expect("fixed slots")),
            transaction_list_digest: bytes[75..107]
                .try_into()
                .expect("fixed ordered list digest"),
            miner_note_commitment: decode_digest(
                bytes[107..155].try_into().expect("fixed miner commitment"),
            )
            .map_err(EnvelopeError::FeeCommitment)?,
        };
        context.validate()?;
        if &context != expected {
            return Err(EnvelopeError::BlockContext);
        }
        let length =
            u32::from_le_bytes(bytes[155..159].try_into().expect("fixed proof length")) as usize;
        if length > MAX_NATIVE_PROOF_BODY_LEN
            || length != bytes.len() - FIXED_SETTLEMENT_ENVELOPE_BYTES
        {
            return Err(EnvelopeError::Length);
        }
        Self::from_parts(context, &bytes[159..], shape)
    }
    pub fn encode(&self, shape: &ProofShape) -> Result<Vec<u8>, EnvelopeError> {
        self.context.validate()?;
        shape
            .validate_encoding(self.proof_body)
            .map_err(EnvelopeError::Proof)?;
        let mut bytes = Vec::with_capacity(FIXED_SETTLEMENT_ENVELOPE_BYTES + self.proof_body.len());
        bytes.extend_from_slice(b"SWST");
        bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes.extend_from_slice(SUITE_ID);
        bytes.extend_from_slice(&self.context.network);
        bytes.extend_from_slice(&self.context.block_height.to_le_bytes());
        bytes.extend_from_slice(&self.context.block_slots.to_le_bytes());
        bytes.extend_from_slice(&self.context.transaction_list_digest);
        bytes.extend_from_slice(&encode_digest(&self.context.miner_note_commitment));
        bytes.extend_from_slice(&(self.proof_body.len() as u32).to_le_bytes());
        bytes.extend_from_slice(self.proof_body);
        Ok(bytes)
    }
    pub fn context(&self) -> &SettlementEnvelopeContext {
        &self.context
    }
    pub fn proof_body(&self) -> &'a [u8] {
        self.proof_body
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::FriParams;
    use crate::common::{F, FEE_BASE, FEE_BLIND_LEN, Hasher, acc_witnesses, sample_slot};
    use crate::encryption::{ChangeCiphertext, PaymentCiphertext};
    use crate::transaction::TransactionProver;
    use p3_field::{PrimeCharacteristicRing, PrimeField32};
    use std::sync::OnceLock;

    type SettlementFixture = (
        ProofShape,
        Vec<u8>,
        SettlementEnvelopeContext,
        Vec<Digest>,
        Vec<F>,
    );

    fn settlement_fixture() -> &'static SettlementFixture {
        use crate::fee_settlement::{FeeOpening, SettlementSlot};
        use crate::fee_settlement_air::{FixedSettlementWitness, SettlementProver};
        static FIXTURE: OnceLock<SettlementFixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let h = Hasher::new();
            let mut slots: Vec<_> = (0..64)
                .map(|i| {
                    SettlementSlot::from_opening(
                        &h,
                        FeeOpening::dummy(core::array::from_fn(|k| {
                            F::from_u32(100 + i * FEE_BLIND_LEN as u32 + k as u32)
                        })),
                    )
                })
                .collect();
            let context = SettlementEnvelopeContext::from_transactions(
                [9; 32],
                1000,
                &(0..64).map(|i| [i; 32]).collect::<Vec<_>>(),
                h.miner_note_cm(100, 1000, &[F::from_u32(800); 12], &[F::from_u32(900); 12]),
            )
            .unwrap();
            slots.extend(zero_fee_tail(&context).unwrap());
            let witness = FixedSettlementWitness {
                slots,
                issuance_reward: 100,
                miner_amount: 100,
                block_height: 1000,
                network: [9; 32],
                transaction_list_digest: context.transaction_list_digest,
                miner_owner: [F::from_u32(800); 12],
                miner_rseed: [F::from_u32(900); 12],
            };
            let prover = SettlementProver::new(576, FriParams::fast());
            let (proof, public) = prover.prove(&witness);
            prover.verify(&proof, &public).unwrap();
            (
                ProofShape::from_trusted(&prover.air, &prover.vk, &prover.cfg).unwrap(),
                postcard::to_allocvec(&proof).unwrap(),
                context,
                witness.slots[..64].iter().map(|s| s.commitment).collect(),
                public,
            )
        })
    }

    #[test]
    fn settlement_envelope_roundtrips_and_reconstructs_trusted_public_statement() {
        let (shape, body, context, commitments, public) = settlement_fixture();
        let envelope = SettlementEnvelope::from_parts(context.clone(), body, shape).unwrap();
        let bytes = envelope.encode(shape).unwrap();
        assert_eq!(FIXED_SETTLEMENT_ENVELOPE_BYTES, 159);
        assert_eq!(&bytes[..4], b"SWST");
        assert_eq!(bytes.len(), 159 + body.len());
        assert_eq!(u16::from_le_bytes(bytes[73..75].try_into().unwrap()), 64);
        let decoded = SettlementEnvelope::decode(&bytes, context, shape).unwrap();
        assert_eq!(decoded.context(), context);
        assert_eq!(decoded.proof_body().as_ptr(), bytes[159..].as_ptr());
        assert_eq!(context.public_inputs(commitments, 100).unwrap(), *public);
        assert!(context.public_inputs(&commitments[..63], 100).is_err());
    }

    #[test]
    fn settlement_envelope_rejects_wrong_block_context_and_noncanonical_framing() {
        let (shape, body, context, _, _) = settlement_fixture();
        let bytes = SettlementEnvelope::from_parts(context.clone(), body, shape)
            .unwrap()
            .encode(shape)
            .unwrap();
        for offset in [0, 4, 6, 33, 65, 73, 75, 107] {
            let mut wrong = bytes.clone();
            wrong[offset] ^= 1;
            assert!(SettlementEnvelope::decode(&wrong, context, shape).is_err());
        }
        for end in [0, 158, bytes.len() - 1] {
            assert!(SettlementEnvelope::decode(&bytes[..end], context, shape).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(SettlementEnvelope::decode(&trailing, context, shape).is_err());
        let mut oversized = bytes.clone();
        oversized[155..159].copy_from_slice(&524289u32.to_le_bytes());
        assert!(SettlementEnvelope::decode(&oversized, context, shape).is_err());
        let mut noncanonical = bytes;
        noncanonical[107..111].copy_from_slice(&F::ORDER_U32.to_le_bytes());
        assert!(SettlementEnvelope::decode(&noncanonical, context, shape).is_err());
        for count in [0, 16, 63, 65, 592] {
            let mut wrong = context.clone();
            wrong.block_slots = count;
            assert!(SettlementEnvelope::from_parts(wrong, body, shape).is_err());
        }
    }

    #[test]
    fn ordered_transaction_digest_binds_count_order_and_block_context() {
        let ids: Vec<_> = (0..64).map(|i| [i; 32]).collect();
        let digest = ordered_transaction_digest(&[9; 32], 1000, &ids).unwrap();
        let mut swapped = ids.clone();
        swapped.swap(0, 1);
        assert_ne!(
            digest,
            ordered_transaction_digest(&[9; 32], 1000, &swapped).unwrap()
        );
        assert_ne!(
            digest,
            ordered_transaction_digest(&[10; 32], 1000, &ids).unwrap()
        );
        assert_ne!(
            digest,
            ordered_transaction_digest(&[9; 32], 1001, &ids).unwrap()
        );
        let mut longer = ids.clone();
        longer.extend((64..80).map(|i| [i; 32]));
        assert_ne!(
            digest,
            ordered_transaction_digest(&[9; 32], 1000, &longer).unwrap()
        );
        let mut duplicate = ids;
        duplicate[1] = duplicate[0];
        assert!(ordered_transaction_digest(&[9; 32], 1000, &duplicate).is_err());
    }

    #[test]
    fn internal_zero_fee_tails_are_reproducible_and_context_separated() {
        let ids: Vec<_> = (0..64).map(|i| [i; 32]).collect();
        let context =
            SettlementEnvelopeContext::from_transactions([9; 32], 1000, &ids, [F::ONE; 12])
                .unwrap();
        let first = zero_fee_tail(&context).unwrap();
        assert_eq!(first.len(), 512);
        assert_eq!(first, zero_fee_tail(&context).unwrap());
        let mut seen = std::collections::BTreeSet::new();
        for slot in &first {
            assert_eq!(slot.opening.fee, 0);
            assert_eq!(
                slot.commitment,
                Hasher::new().fee_commit(0, &slot.opening.blind)
            );
            assert!(seen.insert(encode_digest(&slot.commitment)));
        }
        let mut changed = context.clone();
        changed.network[0] ^= 1;
        assert_ne!(first[0], zero_fee_tail(&changed).unwrap()[0]);
        changed = context.clone();
        changed.block_height += 1;
        assert_ne!(first[0], zero_fee_tail(&changed).unwrap()[0]);
        changed = context;
        changed.block_slots = 80;
        assert_ne!(first[16], zero_fee_tail(&changed).unwrap()[0]);
        changed.block_slots = 576;
        assert!(zero_fee_tail(&changed).unwrap().is_empty());
    }

    pub(crate) struct Fixture {
        pub shape: ProofShape,
        pub body: Vec<u8>,
        pub alternate_body: Vec<u8>,
        pub transaction: PublicTransaction,
        pub snapshot: SnapshotId,
        pub fee_commit: Digest,
        pub blind: [F; FEE_BLIND_LEN],
    }

    pub(crate) fn fixture() -> &'static Fixture {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let witness = acc_witnesses(vec![sample_slot(901, false)], 1000, FEE_BASE, 902)
                .0
                .remove(0);
            let fields = witness.slot.public_inputs(&Hasher::new());
            let transaction = PublicTransaction {
                nf: fields.nf,
                cm: fields.cm_out,
                payment: PaymentCiphertext {
                    kem_ciphertext: [1; 1088],
                    body: [2; 208],
                    tag: [3; 16],
                    view_tag: 4,
                },
                change: ChangeCiphertext {
                    nonce: [5; 12],
                    body: [6; 208],
                    tag: [7; 16],
                    view_tag: 8,
                },
            };
            let snapshot = SnapshotId {
                height: 1001,
                block_id: [11; 32],
            };
            let context = ProofContext::for_snapshot([9; 32], snapshot.height, snapshot.block_id);
            let witness = transaction.bind_witness(&witness, &context).unwrap();
            let prover = TransactionProver::new(FriParams::fast());
            let shape = ProofShape::from_trusted(&prover.air, &prover.vk, &prover.cfg).unwrap();
            let (proof, statement) = prover.prove(&witness);
            prover.verify(&proof, &statement).unwrap();
            let (alternate, alternate_statement) = prover.prove(&witness);
            prover.verify(&alternate, &alternate_statement).unwrap();
            Fixture {
                shape,
                body: postcard::to_allocvec(&proof).unwrap(),
                alternate_body: postcard::to_allocvec(&alternate).unwrap(),
                transaction,
                snapshot,
                fee_commit: fields.fee_commit,
                blind: witness.slot.fee_blind,
            }
        })
    }

    pub(crate) fn envelope<'a>(f: &'a Fixture, body: &'a [u8]) -> NativeEnvelope<'a> {
        NativeEnvelope::from_parts(
            [9; 32],
            f.snapshot,
            f.transaction.clone(),
            f.fee_commit,
            body,
            &f.shape,
        )
        .unwrap()
    }

    #[test]
    fn canonical_envelope_roundtrips_exact_layout_without_copying_proof() {
        let f = fixture();
        let envelope = envelope(f, &f.body);
        let bytes = envelope.encode(&f.shape).unwrap();
        assert_eq!(FIXED_ENVELOPE_BYTES, 1899);
        assert_eq!(MAX_ENVELOPE_BYTES, 526187);
        assert_eq!(&bytes[..4], b"SWTX");
        assert_eq!(&bytes[6..33], SUITE_ID);
        assert_eq!(&bytes[33..65], &[9; 32]);
        assert_eq!(&bytes[105..1847], &f.transaction.encode());
        assert_eq!(bytes.len(), FIXED_ENVELOPE_BYTES + f.body.len());
        let decoded = NativeEnvelope::decode(&bytes, &[9; 32], &f.shape).unwrap();
        assert_eq!(decoded.transaction(), &f.transaction);
        assert_eq!(decoded.snapshot_id(), f.snapshot);
        assert_eq!(decoded.fee_commit(), &f.fee_commit);
        assert_eq!(
            decoded.context().snapshot(),
            Some((f.snapshot.height, f.snapshot.block_id))
        );
        assert_eq!(
            decoded.proof_body().as_ptr(),
            bytes[FIXED_ENVELOPE_BYTES..].as_ptr()
        );
        assert_eq!(decoded.transaction_id(), envelope.transaction_id());
    }

    #[test]
    fn rejects_wrong_context_noncanonical_fields_and_nonexact_length() {
        let f = fixture();
        let bytes = envelope(f, &f.body).encode(&f.shape).unwrap();
        assert_eq!(
            NativeEnvelope::decode(&bytes, &[10; 32], &f.shape).err(),
            Some(EnvelopeError::Network)
        );
        for offset in [0, 4, 6] {
            let mut invalid = bytes.clone();
            invalid[offset] ^= 1;
            assert!(NativeEnvelope::decode(&invalid, &[9; 32], &f.shape).is_err());
        }
        for offset in [105, 1847] {
            let mut invalid = bytes.clone();
            invalid[offset..offset + 4].copy_from_slice(&F::ORDER_U32.to_le_bytes());
            assert!(NativeEnvelope::decode(&invalid, &[9; 32], &f.shape).is_err());
        }
        for end in [0, 64, 1847, FIXED_ENVELOPE_BYTES - 1, bytes.len() - 1] {
            assert!(NativeEnvelope::decode(&bytes[..end], &[9; 32], &f.shape).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(NativeEnvelope::decode(&trailing, &[9; 32], &f.shape).is_err());
        let mut oversized = bytes;
        oversized[1895..1899].copy_from_slice(&524289u32.to_le_bytes());
        assert!(NativeEnvelope::decode(&oversized, &[9; 32], &f.shape).is_err());
    }

    #[test]
    fn encoder_and_decoder_reject_malformed_proof_structure() {
        let f = fixture();
        assert!(
            NativeEnvelope::from_parts(
                [9; 32],
                f.snapshot,
                f.transaction.clone(),
                f.fee_commit,
                &[0xff; 16],
                &f.shape
            )
            .is_err()
        );
        let mut bytes = envelope(f, &f.body).encode(&f.shape).unwrap();
        bytes[FIXED_ENVELOPE_BYTES] = 0;
        assert!(NativeEnvelope::decode(&bytes, &[9; 32], &f.shape).is_err());
        let mut duplicate = f.transaction.clone();
        duplicate.nf[1] = duplicate.nf[0];
        assert_eq!(
            NativeEnvelope::from_parts(
                [9; 32],
                f.snapshot,
                duplicate,
                f.fee_commit,
                &f.body,
                &f.shape
            )
            .err(),
            Some(EnvelopeError::Public(CodecError::DuplicateNullifier))
        );
    }

    #[test]
    fn transaction_identity_excludes_proof_randomness_and_sidecar() {
        let f = fixture();
        assert_ne!(f.body, f.alternate_body);
        let first = envelope(f, &f.body);
        let second = envelope(f, &f.alternate_body);
        assert_eq!(first.transaction_id(), second.transaction_id());
        let mut transaction = f.transaction.clone();
        transaction.change.tag[0] ^= 1;
        assert_ne!(
            first.transaction_id(),
            statement_id(&[9; 32], f.snapshot, &transaction, &f.fee_commit)
        );
        assert_ne!(
            first.transaction_id(),
            statement_id(&[10; 32], f.snapshot, &f.transaction, &f.fee_commit)
        );
        let mut snapshot = f.snapshot;
        snapshot.height += 1;
        assert_ne!(
            first.transaction_id(),
            statement_id(&[9; 32], snapshot, &f.transaction, &f.fee_commit)
        );
        snapshot = f.snapshot;
        snapshot.block_id[0] ^= 1;
        assert_ne!(
            first.transaction_id(),
            statement_id(&[9; 32], snapshot, &f.transaction, &f.fee_commit)
        );
        let mut fee = f.fee_commit;
        fee[0] += F::ONE;
        assert_ne!(
            first.transaction_id(),
            statement_id(&[9; 32], f.snapshot, &f.transaction, &fee)
        );
    }

    #[test]
    fn sidecar_has_exact_canonical_encoding_without_private_flags() {
        let f = fixture();
        let envelope = envelope(f, &f.body);
        let sidecar = FeeOpeningSidecar::new(envelope.transaction_id(), FEE_BASE, f.blind);
        let bytes = sidecar.encode();
        assert_eq!(FEE_SIDECAR_BYTES, 78);
        assert_eq!(bytes.len(), 78);
        assert_eq!(FeeOpeningSidecar::decode(&bytes).unwrap(), sidecar);
        let opening = validate_fee_sidecar(&envelope, Some(&sidecar)).unwrap();
        assert_eq!(opening.fee, FEE_BASE);
        for end in [0, 6, bytes.len() - 1] {
            assert!(FeeOpeningSidecar::decode(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(FeeOpeningSidecar::decode(&trailing).is_err());
        let mut noncanonical = bytes;
        noncanonical[46..50].copy_from_slice(&F::ORDER_U32.to_le_bytes());
        assert!(FeeOpeningSidecar::decode(&noncanonical).is_err());
        for offset in [0, 4] {
            let mut wrong_context = bytes;
            wrong_context[offset] ^= 1;
            assert!(FeeOpeningSidecar::decode(&wrong_context).is_err());
        }
    }

    #[test]
    fn rejects_missing_mismatched_and_false_fee_openings() {
        let f = fixture();
        let envelope = envelope(f, &f.body);
        assert_eq!(
            validate_fee_sidecar(&envelope, None).err(),
            Some(FeeSidecarError::Missing)
        );
        let sidecar = FeeOpeningSidecar::new([0; 32], FEE_BASE, f.blind);
        assert_eq!(
            validate_fee_sidecar(&envelope, Some(&sidecar)).err(),
            Some(FeeSidecarError::TransactionBinding)
        );
        let sidecar = FeeOpeningSidecar::new(envelope.transaction_id(), 0, f.blind);
        assert_eq!(
            validate_fee_sidecar(&envelope, Some(&sidecar)).err(),
            Some(FeeSidecarError::Commitment)
        );
        let sidecar = FeeOpeningSidecar::new(
            envelope.transaction_id(),
            FEE_BASE,
            [F::ZERO; FEE_BLIND_LEN],
        );
        assert_eq!(
            validate_fee_sidecar(&envelope, Some(&sidecar)).err(),
            Some(FeeSidecarError::Commitment)
        );
    }
}
