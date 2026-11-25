//! Fixed native transaction public encoding and proof-statement adapter.
//!
//! The codec is isolated from the retained node and is not a consensus format.
//! It binds bytes to the native relation, not encryption correctness.

use crate::Cfg;
use crate::common::{AccWitness, Digest, F, Hasher};
use crate::encryption::{ChangeCiphertext, PaymentCiphertext};
use crate::transaction::{TransactionProver, statement_for};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_uni_stark::Proof;

pub const PUBLIC_TRANSACTION_BYTES: usize = 1742;
pub const FORMAT_VERSION: u16 = 1;
pub const SUITE_ID: &[u8] = b"siworld-native-d8-w24-12-v1";
/// A stable descriptor of this isolated codec, not a registered consensus suite.
pub const CODEC_SCHEMA: &str = "native-v1:le32-canonical-koalabear:nf[2][48]:cm[2][48]:kem768[1088]:payment[208]:change[208]:tags[2][16]:change_nonce[12]:view_tags[2]";
/// Snapshot context changes the derived statement, not the fixed public encoding.
pub const PROOF_CONTEXT_SCHEMA: &str =
    "native-v1:network[32]:suite:version:canonical-snapshot[presence:u8,height:le64,block-id:32]";
const SNAPSHOT_CONTEXT_DOMAIN: &[u8] = b"siworld native transaction canonical snapshot v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodecError {
    Length,
    NoncanonicalDigest,
    DuplicateNullifier,
    UnsupportedVersion,
    WitnessMismatch,
}

/// Trusted context selected by the verifier, not by an untrusted proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofContext {
    pub network: [u8; 32],
    version: u16,
    snapshot: Option<(u64, [u8; 32])>,
}
impl ProofContext {
    /// Unbound context for isolated fixtures. Canonical transaction admission
    /// must select a snapshot identity with `bind_snapshot` before verification.
    pub fn new(network: [u8; 32]) -> Self {
        Self {
            network,
            version: FORMAT_VERSION,
            snapshot: None,
        }
    }
    pub fn for_snapshot(network: [u8; 32], height: u64, block_id: [u8; 32]) -> Self {
        Self::new(network).bind_snapshot(height, block_id)
    }
    /// Replace any supplied snapshot binding with the verifier's selected
    /// canonical identity. This method does not establish canonical membership.
    pub fn bind_snapshot(&self, height: u64, block_id: [u8; 32]) -> Self {
        Self {
            snapshot: Some((height, block_id)),
            ..*self
        }
    }
    pub fn snapshot(&self) -> Option<(u64, [u8; 32])> {
        self.snapshot
    }
    pub fn from_version(network: [u8; 32], version: u16) -> Result<Self, CodecError> {
        if version != FORMAT_VERSION {
            return Err(CodecError::UnsupportedVersion);
        }
        Ok(Self {
            network,
            version,
            snapshot: None,
        })
    }
    pub fn version(&self) -> u16 {
        self.version
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicTransaction {
    pub nf: [Digest; 2],
    pub cm: [Digest; 2],
    pub payment: PaymentCiphertext,
    pub change: ChangeCiphertext,
}

pub fn encode_digest(digest: &Digest) -> [u8; 48] {
    let mut bytes = [0; 48];
    for (dst, value) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(digest) {
        dst.copy_from_slice(&value.as_canonical_u32().to_le_bytes());
    }
    bytes
}

pub fn decode_digest(bytes: &[u8; 48]) -> Result<Digest, CodecError> {
    let mut digest = [F::ZERO; 12];
    for (dst, value) in digest.iter_mut().zip(bytes.as_chunks::<4>().0.iter()) {
        let value = u32::from_le_bytes(*value);
        if value >= F::ORDER_U32 {
            return Err(CodecError::NoncanonicalDigest);
        }
        *dst = F::from_u32(value);
    }
    Ok(digest)
}

impl PublicTransaction {
    pub fn encode(&self) -> [u8; PUBLIC_TRANSACTION_BYTES] {
        let mut bytes = [0; PUBLIC_TRANSACTION_BYTES];
        for (index, digest) in self.nf.iter().chain(&self.cm).enumerate() {
            bytes[index * 48..(index + 1) * 48].copy_from_slice(&encode_digest(digest));
        }
        bytes[192..1280].copy_from_slice(&self.payment.kem_ciphertext);
        bytes[1280..1488].copy_from_slice(&self.payment.body);
        bytes[1488..1696].copy_from_slice(&self.change.body);
        bytes[1696..1712].copy_from_slice(&self.payment.tag);
        bytes[1712..1728].copy_from_slice(&self.change.tag);
        bytes[1728..1740].copy_from_slice(&self.change.nonce);
        bytes[1740] = self.payment.view_tag;
        bytes[1741] = self.change.view_tag;
        bytes
    }

    /// Bounded decoding performs no proof allocations or verification work.
    /// Arbitrary ciphertext bytes are valid syntax; authentication needs a key.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let bytes: &[u8; PUBLIC_TRANSACTION_BYTES] =
            bytes.try_into().map_err(|_| CodecError::Length)?;
        let mut digests = [[F::ZERO; 12]; 4];
        for (index, digest) in digests.iter_mut().enumerate() {
            *digest = decode_digest(
                bytes[index * 48..(index + 1) * 48]
                    .try_into()
                    .expect("48 bytes"),
            )?;
        }
        if digests[0] == digests[1] {
            return Err(CodecError::DuplicateNullifier);
        }
        Ok(Self {
            nf: [digests[0], digests[1]],
            cm: [digests[2], digests[3]],
            payment: PaymentCiphertext {
                kem_ciphertext: bytes[192..1280].try_into().expect("1088 bytes"),
                body: bytes[1280..1488].try_into().expect("208 bytes"),
                tag: bytes[1696..1712].try_into().expect("16 bytes"),
                view_tag: bytes[1740],
            },
            change: ChangeCiphertext {
                body: bytes[1488..1696].try_into().expect("208 bytes"),
                tag: bytes[1712..1728].try_into().expect("16 bytes"),
                nonce: bytes[1728..1740].try_into().expect("12 bytes"),
                view_tag: bytes[1741],
            },
        })
    }

    /// Bind the fixed encoding, network/suite and canonical snapshot identity.
    /// The separate presence byte distinguishes an unbound fixture from the
    /// all-zero snapshot. Height is little-endian u64, followed by 32 block-ID
    /// bytes. This digest uses the existing AIR limbs; no columns are added.
    pub fn ciphertext_digest(&self, context: &ProofContext) -> [u8; 32] {
        let mut hash = blake3::Hasher::new_derive_key("siworld native transaction public data v1");
        hash.update(&(SUITE_ID.len() as u16).to_le_bytes());
        hash.update(SUITE_ID);
        hash.update(&context.version.to_le_bytes());
        hash.update(&context.network);
        hash.update(&(SNAPSHOT_CONTEXT_DOMAIN.len() as u16).to_le_bytes());
        hash.update(SNAPSHOT_CONTEXT_DOMAIN);
        hash.update(&[u8::from(context.snapshot.is_some())]);
        let (height, block_id) = context.snapshot.unwrap_or((0, [0; 32]));
        hash.update(&height.to_le_bytes());
        hash.update(&block_id);
        hash.update(&self.encode());
        *hash.finalize().as_bytes()
    }

    pub fn bind_witness(
        &self,
        witness: &AccWitness,
        context: &ProofContext,
    ) -> Result<AccWitness, CodecError> {
        if self.nf[0] == self.nf[1] {
            return Err(CodecError::DuplicateNullifier);
        }
        let fields = witness.slot.public_inputs(&Hasher::new());
        if fields.nf != self.nf || fields.cm_out != self.cm {
            return Err(CodecError::WitnessMismatch);
        }
        let mut bound = witness.clone();
        bound.d_ct = self.ciphertext_digest(context);
        Ok(bound)
    }

    /// Build the production statement from the public transaction and its
    /// fee commitment. The fee opening is never accepted as a public field.
    pub fn statement(
        &self,
        context: &ProofContext,
        fee_commit: &Digest,
        accepted_root: &Digest,
    ) -> Vec<F> {
        statement_for(
            &self.nf,
            &self.cm,
            &self.ciphertext_digest(context),
            fee_commit,
            accepted_root,
        )
    }

    /// The caller selects a trusted prepared verifier and a valid root snapshot.
    /// This interface does not accept a peer-provided public statement or key.
    pub fn verify(
        &self,
        prover: &TransactionProver,
        proof: &Proof<Cfg>,
        context: &ProofContext,
        fee_commit: &Digest,
        accepted_root: &Digest,
    ) -> Result<(), String> {
        if self.nf[0] == self.nf[1] {
            return Err("duplicate nullifier".into());
        }
        prover.verify(proof, &self.statement(context, fee_commit, accepted_root))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{FEE_BASE, acc_witnesses, sample_slot};
    use p3_field::PrimeCharacteristicRing;

    fn fixture() -> (PublicTransaction, AccWitness, ProofContext) {
        let w = acc_witnesses(vec![sample_slot(61, false)], 1000, FEE_BASE, 62)
            .0
            .remove(0);
        let fields = w.slot.public_inputs(&Hasher::new());
        (
            PublicTransaction {
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
            },
            w,
            ProofContext::new([9; 32]),
        )
    }

    #[test]
    fn exact_layout_and_canonical_round_trip() {
        let (tx, _, _) = fixture();
        let wire = tx.encode();
        assert_eq!(wire.len(), 1742);
        assert_eq!(PublicTransaction::decode(&wire), Ok(tx));
        assert_eq!(&wire[192..1280], &[1; 1088]);
        assert_eq!(&wire[1280..1488], &[2; 208]);
        assert_eq!(&wire[1488..1696], &[6; 208]);
        assert_eq!(&wire[1696..1712], &[3; 16]);
        assert_eq!(&wire[1712..1728], &[7; 16]);
        assert_eq!(&wire[1728..1740], &[5; 12]);
        assert_eq!(&wire[1740..], &[4, 8]);
    }

    #[test]
    fn rejects_length_noncanonical_fields_and_duplicate_nullifiers() {
        let (tx, _, _) = fixture();
        let wire = tx.encode();
        assert_eq!(
            PublicTransaction::decode(&wire[..1741]),
            Err(CodecError::Length)
        );
        assert_eq!(
            PublicTransaction::decode(&[wire.as_slice(), &[0]].concat()),
            Err(CodecError::Length)
        );
        for limb in 0..48 {
            let mut bad = wire;
            bad[limb * 4..limb * 4 + 4].copy_from_slice(&F::ORDER_U32.to_le_bytes());
            assert_eq!(
                PublicTransaction::decode(&bad),
                Err(CodecError::NoncanonicalDigest)
            );
        }
        let mut bad = tx;
        bad.nf[1] = bad.nf[0];
        assert_eq!(
            PublicTransaction::decode(&bad.encode()),
            Err(CodecError::DuplicateNullifier)
        );
    }

    #[test]
    fn every_wire_byte_and_context_is_bound_to_statement() {
        let (tx, w, ctx) = fixture();
        let fields = w.slot.public_inputs(&Hasher::new());
        let original = tx.statement(&ctx, &fields.fee_commit, &w.anchors_root(&Hasher::new()));
        let wire = tx.encode();
        for i in 0..wire.len() {
            let mut changed = wire;
            changed[i] ^= 1;
            if let Ok(changed) = PublicTransaction::decode(&changed) {
                assert_ne!(
                    changed.statement(&ctx, &fields.fee_commit, &w.anchors_root(&Hasher::new())),
                    original,
                    "wire byte {i}"
                );
            }
        }
        let mut other = ctx;
        other.network[0] ^= 1;
        assert_ne!(tx.ciphertext_digest(&ctx), tx.ciphertext_digest(&other));
        assert!(ProofContext::from_version([9; 32], 2).is_err());
    }

    #[test]
    fn witness_adapter_rejects_mismatched_public_fields() {
        let (mut tx, w, ctx) = fixture();
        let bound = tx.bind_witness(&w, &ctx).unwrap();
        assert_eq!(bound.d_ct, tx.ciphertext_digest(&ctx));
        assert_eq!(bound.slot.fee, w.slot.fee);
        tx.cm[1][5] += F::ONE;
        assert!(matches!(
            tx.bind_witness(&w, &ctx),
            Err(CodecError::WitnessMismatch)
        ));
    }

    #[test]
    fn snapshot_presence_and_all_identity_bytes_change_the_statement_digest() {
        let (tx, _, unbound) = fixture();
        let height = 0x0123_4567_89ab_cdefu64;
        let block_id = [17; 32];
        let bound = ProofContext::for_snapshot(unbound.network, height, block_id);
        assert_eq!(unbound.snapshot(), None);
        assert_eq!(bound.snapshot(), Some((height, block_id)));
        assert_eq!(unbound.bind_snapshot(height, block_id), bound);
        assert_ne!(tx.ciphertext_digest(&unbound), tx.ciphertext_digest(&bound));
        // Presence is bound even when every identity byte is zero.
        assert_ne!(
            tx.ciphertext_digest(&unbound),
            tx.ciphertext_digest(&ProofContext::for_snapshot(unbound.network, 0, [0; 32]),)
        );
        for byte in 0..40 {
            let mut changed_height = height.to_le_bytes();
            let mut changed_id = block_id;
            if byte < 8 {
                changed_height[byte] ^= 1;
            } else {
                changed_id[byte - 8] ^= 1;
            }
            let changed = bound.bind_snapshot(u64::from_le_bytes(changed_height), changed_id);
            assert_ne!(
                tx.ciphertext_digest(&bound),
                tx.ciphertext_digest(&changed),
                "snapshot byte {byte}"
            );
        }
        assert_eq!(tx.encode().len(), PUBLIC_TRANSACTION_BYTES);
    }

    #[test]
    fn orphan_proof_cannot_be_reused_with_an_identical_root_snapshot() {
        let (tx, witness, base_context) = fixture();
        let original = base_context.bind_snapshot(19, [21; 32]);
        let same_height_fork = base_context.bind_snapshot(19, [22; 32]);
        let later_snapshot = base_context.bind_snapshot(20, [21; 32]);
        let witness = tx.bind_witness(&witness, &original).unwrap();
        let prover = TransactionProver::new(crate::FriParams::fast());
        let (proof, statement) = prover.prove(&witness);
        let root = witness.anchors_root(&Hasher::new());
        let fields = witness.slot.public_inputs(&Hasher::new());
        assert_eq!(
            statement,
            tx.statement(&original, &fields.fee_commit, &root)
        );
        tx.verify(&prover, &proof, &original, &fields.fee_commit, &root)
            .unwrap();
        for changed in [same_height_fork, later_snapshot, base_context] {
            assert!(
                tx.verify(&prover, &proof, &changed, &fields.fee_commit, &root)
                    .is_err()
            );
            assert_eq!(
                tx.statement(&changed, &fields.fee_commit, &root).len(),
                statement.len()
            );
        }
    }

    #[test]
    fn actual_native_proof_uses_decoded_fields_not_peer_statement() {
        let (tx, w, ctx) = fixture();
        let w = tx.bind_witness(&w, &ctx).unwrap();
        let p = TransactionProver::new(crate::FriParams::fast());
        let (proof, public) = p.prove(&w);
        let root = w.anchors_root(&Hasher::new());
        let fields = w.slot.public_inputs(&Hasher::new());
        assert_eq!(public, tx.statement(&ctx, &fields.fee_commit, &root));
        tx.verify(&p, &proof, &ctx, &fields.fee_commit, &root)
            .unwrap();
        let mut wire = tx.encode();
        wire[1501] ^= 1;
        let changed = PublicTransaction::decode(&wire).unwrap();
        assert!(
            changed
                .verify(&p, &proof, &ctx, &fields.fee_commit, &root)
                .is_err()
        );
        assert!(
            tx.verify(
                &p,
                &proof,
                &ProofContext::new([0; 32]),
                &fields.fee_commit,
                &root
            )
            .is_err()
        );
        let mut changed_fee = fields.fee_commit;
        changed_fee[0] += F::ONE;
        assert!(tx.verify(&p, &proof, &ctx, &changed_fee, &root).is_err());
    }
}
