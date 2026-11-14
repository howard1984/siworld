//! Inactive fixed-capacity confidential-fee relation.
//!
//! Callers supply authenticated ordered block data. No constructor authenticates
//! peer data, activates a network profile, or grants ledger-transition authority.
mod arx_closed;
mod fee_local_complete;
mod fee_local_sum;
mod fixed_public;
mod fixed_window;
mod kem_arx_closed;
mod kem_closed;
mod kem_reference;
mod ntt_closed;
mod payment_closed;
mod policy;
mod poly1305_closed;
mod prefix;

use super::{
    ProtocolBinding,
    backend::{PrivateAttempt, PublicPreprocessing},
    batch::{self, CompleteFeeBatchShape, CompleteFeeBatchVerifier},
};
use ::native::{
    encryption::{EncryptionContext, PaymentAddress, PaymentCiphertext},
    multi_asset::{Digest, F},
};
pub use fee_local_sum::{
    FeeLocalSumWitness, LegacyFeeOpening, LegacyPrivateSettlement, LegacySettlementSlot,
    legacy_fee_commit,
};
use fixed_public::{FixedPublicAir, StatementError, TrustedStatementBinding};
use p3_batch_stark::{ProverData, StarkInstance};
use p3_field::PrimeCharacteristicRing;
pub use policy::{FeeSchedule, SettlementPolicy};

pub const CAPACITY: usize = 576;
pub const BASE_ROWS: usize = 1024;
pub const EXTENDED_DEGREE_BITS: usize = 11;

#[derive(Debug)]
pub enum Error {
    Statement,
    Geometry,
    Witness(String),
    Batch(batch::Error),
    Setup,
    Entropy,
    PrivateAttempt,
    Proving,
}
impl From<StatementError> for Error {
    fn from(_: StatementError) -> Self {
        Self::Statement
    }
}
impl From<batch::Error> for Error {
    fn from(error: batch::Error) -> Self {
        Self::Batch(error)
    }
}

pub fn fee_destination_digest(address: &PaymentAddress) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("siworld eng2 confidential fee destination v1");
    h.update(&fee_local_complete::canonical_address(address));
    *h.finalize().as_bytes()
}

/// Public inputs reconstructed by a full-block caller from authenticated state.
/// Fee commitments retain transaction order, including proved padding entries.
pub struct StatementInputs<'a> {
    pub policy: &'a SettlementPolicy,
    pub network: [u8; 32],
    pub transaction_list_digest: [u8; 32],
    pub address: &'a PaymentAddress,
    pub fee_commitments: &'a [Digest],
    pub reward_commitments: &'a [Digest],
    pub fee_commitment: Digest,
    pub ciphertext: &'a PaymentCiphertext,
}

/// A public relation and statement; this contains no private witness or PCS key.
/// It must be recreated in the verifier process, never decoded from a proof.
pub struct Statement {
    air: FixedPublicAir,
    public: Vec<F>,
    binding: ProtocolBinding,
}
impl Statement {
    pub fn from_authenticated(
        inputs: StatementInputs<'_>,
        binding: ProtocolBinding,
    ) -> Result<Self, Error> {
        if inputs.fee_commitments.len() != CAPACITY
            || inputs.policy.max_slots != CAPACITY
            || inputs.network == [0; 32]
            || inputs.transaction_list_digest == [0; 32]
            || inputs.policy.fee_owner != inputs.address.owner()
            || binding.air != source_identity()
            || binding.genesis == [0; 32]
            || binding.rules == [0; 32]
        {
            return Err(Error::Statement);
        }
        let context = EncryptionContext::new(inputs.network);
        let kem = kem_closed::KemClosedAir {
            public_key: *inputs.address.encapsulation_key(),
            ciphertext: inputs.ciphertext.kem_ciphertext,
        };
        let mut base = prefix::public_hash(kem.public_key_hash());
        base.push(F::from_u8(inputs.ciphertext.view_tag));
        base.extend(
            fee_local_sum::fee_local_settlement_public_v4(
                inputs.policy,
                inputs.network,
                inputs.transaction_list_digest,
                fee_destination_digest(inputs.address),
                inputs.fee_commitments,
                inputs.reward_commitments,
                inputs.fee_commitment,
            )
            .map_err(Error::Witness)?,
        );
        base.extend(
            fee_local_complete::canonical_address(inputs.address)
                .as_chunks::<2>()
                .0
                .iter()
                .map(|bytes| F::from_u16(u16::from_le_bytes(*bytes))),
        );
        let original = fee_local_complete::FeeLocalCompleteAir {
            payment: payment_closed::PaymentClosedAir {
                kem: kem_arx_closed::KemArxClosedAir(kem),
                poly: poly1305_closed::Poly1305Air {
                    aad: payment_closed::aad(&context, &inputs.fee_commitment),
                    body: inputs.ciphertext.body,
                    tag: inputs.ciphertext.tag,
                },
                address: inputs.address.clone(),
                context,
                commitment: inputs.fee_commitment,
                view_tag: inputs.ciphertext.view_tag,
            },
            settlement: fee_local_sum::FeeLocalSumAir::new(CAPACITY).with_min_height(BASE_ROWS),
        };
        let trusted =
            TrustedStatementBinding(fixed_public::canonical_statement_binding(&original, &base)?);
        let public = fixed_public::public_inputs(&original, &base, trusted)?;
        let air = FixedPublicAir::new(original)?;
        Ok(Self {
            air,
            public,
            binding,
        })
    }
    pub fn public_values(&self) -> &[F] {
        &self.public
    }
    /// Setup currently rebuilds the complete local preprocessing commitment.
    /// Cold-memory qualification remains required before runtime activation.
    pub fn verifier(self) -> Result<Verifier, Error> {
        let inner = CompleteFeeBatchVerifier::from_authenticated_air(
            self.air,
            EXTENDED_DEGREE_BITS,
            self.binding,
        )?;
        Ok(Verifier {
            inner,
            public: self.public,
        })
    }
}

pub struct Verifier {
    inner: CompleteFeeBatchVerifier<FixedPublicAir>,
    public: Vec<F>,
}
impl Verifier {
    pub fn shape(&self) -> &CompleteFeeBatchShape {
        self.inner.shape()
    }
    /// The caller must pre-read the 48-byte header before allocating the frame.
    pub fn verify(&self, frame: &[u8]) -> Result<(), Error> {
        self.inner.verify(frame, &self.public).map_err(Into::into)
    }
}

/// Generate a single proof attempt using fresh dual hiding randomness. The
/// entire call, including trace generation and setup, needs an external guard.
pub fn prove(
    witness: &FeeLocalSumWitness,
    address: &PaymentAddress,
    coins: [u8; 32],
    binding: ProtocolBinding,
) -> Result<Vec<u8>, Error> {
    if witness.settlement.slots.len() != CAPACITY {
        return Err(Error::Geometry);
    }
    let (original, trace, base) =
        fee_local_complete::generate(witness, address, coins).map_err(Error::Witness)?;
    let ciphertext = original.payment.ciphertext();
    let fees: Vec<_> = witness
        .settlement
        .slots
        .iter()
        .map(|s| s.commitment)
        .collect();
    let h = ::native::multi_asset::Hasher::new();
    let rewards: Vec<_> = witness
        .settlement
        .rewards
        .iter()
        .map(|note| h.note_cm(note))
        .collect();
    let statement = Statement::from_authenticated(
        StatementInputs {
            policy: &witness.policy,
            network: witness.network,
            transaction_list_digest: witness.transaction_list_digest,
            address,
            fee_commitments: &fees,
            reward_commitments: &rewards,
            fee_commitment: h.note_cm(&witness.settlement.fee_note),
            ciphertext: &ciphertext,
        },
        binding,
    )?;
    if statement.public[..fixed_public::BASE_PUBLIC] != base {
        return Err(Error::Statement);
    }
    let trace = fixed_public::extend_trace(trace, &statement.public)?;
    let public_setup = PublicPreprocessing::new(batch::profile());
    let data = ProverData::from_airs_and_degrees(
        public_setup.config(),
        core::slice::from_ref(&statement.air),
        &[EXTENDED_DEGREE_BITS],
    )
    .map_err(|_| Error::Setup)?;
    let shape = CompleteFeeBatchShape::from_trusted(
        &statement.air,
        &data.common,
        public_setup.config(),
        EXTENDED_DEGREE_BITS,
        statement.binding,
    )?;
    if shape.maximum_complete_frame_bytes() > super::MAX_FEE_PROOF_BYTES {
        return Err(Error::Geometry);
    }
    let attempt = PrivateAttempt::from_os(batch::profile()).map_err(|_| Error::Entropy)?;
    let proof = attempt
        .run(|cfg| {
            p3_batch_stark::prove_batch(
                cfg,
                &[StarkInstance {
                    air: &statement.air,
                    trace: &trace,
                    public_values: statement.public,
                }],
                &data,
            )
        })
        .map_err(|_| Error::PrivateAttempt)?
        .map_err(|_| Error::Proving)?;
    shape.encode(&proof).map_err(Into::into)
}

/// Exact local source closure; this is a build identity, not source authentication.
pub fn source_identity() -> [u8; 32] {
    let mut h =
        blake3::Hasher::new_derive_key("siworld inactive complete fee dual hiding relation v2");
    h.update(b"capacity576;rows1024;extended2048;main7668;pre881;public15322;dual-salt9;input-cap1;fri-cap2;blowup5;queries80;grinding0;frame48;max5242880");
    for source in [
        include_bytes!("mod.rs").as_slice(),
        include_bytes!("policy.rs").as_slice(),
        include_bytes!("arx_closed.rs").as_slice(),
        include_bytes!("fee_local_complete.rs").as_slice(),
        include_bytes!("fee_local_sum.rs").as_slice(),
        include_bytes!("fixed_public.rs").as_slice(),
        include_bytes!("fixed_window.rs").as_slice(),
        include_bytes!("kem_arx_closed.rs").as_slice(),
        include_bytes!("kem_closed.rs").as_slice(),
        include_bytes!("kem_reference.rs").as_slice(),
        include_bytes!("ntt_closed.rs").as_slice(),
        include_bytes!("payment_closed.rs").as_slice(),
        include_bytes!("poly1305_closed.rs").as_slice(),
        include_bytes!("prefix.rs").as_slice(),
        include_bytes!("../batch.rs").as_slice(),
        include_bytes!("../native.rs").as_slice(),
        include_bytes!("../../../proof_codec.rs").as_slice(),
        include_bytes!("../../v2.rs").as_slice(),
        include_bytes!("../backend/mod.rs").as_slice(),
        include_bytes!("../backend/pcs.rs").as_slice(),
        include_bytes!("../backend/owner.rs").as_slice(),
        include_bytes!("../backend/entropy.rs").as_slice(),
        include_bytes!("../../../../../bench-d8/src/air.rs").as_slice(),
        include_bytes!("../../../../../bench-d8/src/common.rs").as_slice(),
        include_bytes!("../../../../../bench-multi-asset/src/lib.rs").as_slice(),
        include_bytes!("../../../../../bench-multi-asset/src/multi_asset.rs").as_slice(),
        include_bytes!("../../../../../bench-multi-asset/src/settlement.rs").as_slice(),
        include_bytes!("../../../../../bench-multi-asset/src/encryption.rs").as_slice(),
    ] {
        h.update(&(source.len() as u64).to_le_bytes());
        h.update(source);
    }
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests;
