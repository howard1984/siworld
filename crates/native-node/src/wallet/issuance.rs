//! Three-note issuance preparation and declaration-bound ordinary SIP fee payment.
//! The fee uses the frozen transaction relation: only its free output randomness
//! is declaration-derived; the AIR still derives rho from input nullifiers.
use super::{FeeTier, PreparedTransfer, Wallet, decode_payment, random_fields, same_note};
use crate::issuance::{
    CIPHERTEXT_BYTES, INITIAL_NOTES, IssuanceRecord, IssuanceVerifier, TESTNET_ISSUANCE_FEE_ATOMS,
    fee_rseed,
};
use crate::state::{Config, State};
use crate::wire::{DigestBytes, Hash};
use native::codec::encode_digest;
use native::encryption::{
    EncryptionContext, PaymentAddress, PaymentEncryptionOpening, encrypt_payment_with_opening,
};
use native::issuance::{
    AssetMetadata, ISSUER_KEY_BYTES, ISSUER_SIGNATURE_BYTES, IssuanceDeclaration, IssuanceWitness,
    SignedIssuance, derive_asset_id,
};
use native::issuance_air::IssuanceProver;
use native::multi_asset::{F, Hasher, Note, SIP_ASSET_ID};
use p3_field::PrimeCharacteristicRing;
use zeroize::Zeroize;

pub const ISSUER_SIGNATURE_CONTEXT: &[u8] = b"siworld asset issuance v1";
pub struct InitialOutput {
    pub recipient: PaymentAddress,
    pub amount: u64,
}
pub struct IssuanceRequest {
    pub issuer_key: [u8; ISSUER_KEY_BYTES],
    pub sequence: u64,
    pub public_supply: u64,
    pub metadata: AssetMetadata,
    pub outputs: [InitialOutput; INITIAL_NOTES],
}
/// Public opening of the issuance-fee output, not an authorization or proof.
#[derive(Clone)]
pub struct IssuanceFeeReceipt {
    pub declaration: Hash,
    pub commitment: DigestBytes,
    pub rho: DigestBytes,
}
pub struct PreparedIssuanceFee {
    transfer: PreparedTransfer,
    receipt: IssuanceFeeReceipt,
}
impl PreparedIssuanceFee {
    pub fn receipt(&self) -> &IssuanceFeeReceipt {
        &self.receipt
    }
    pub fn transfer(&self) -> &PreparedTransfer {
        &self.transfer
    }
    pub fn into_transfer(self) -> PreparedTransfer {
        self.transfer
    }
}
fn clear_note(note: &mut Note) {
    note.asset_id.0.zeroize();
    note.owner.fill(F::ZERO);
    note.rho.fill(F::ZERO);
    note.rseed.fill(F::ZERO);
    note.value.zeroize();
    note.unlock_height.zeroize();
}
struct PrivateNotes(Vec<Note>);
impl Drop for PrivateNotes {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(clear_note);
    }
}
struct PrivateWitness(IssuanceWitness);
impl Drop for PrivateWitness {
    fn drop(&mut self) {
        self.0.notes.iter_mut().for_each(clear_note);
    }
}
pub struct PreparedIssuance {
    witness: PrivateWitness,
    recipients: [PaymentAddress; INITIAL_NOTES],
    openings: [PaymentEncryptionOpening; INITIAL_NOTES],
}
impl Wallet {
    /// Prepare exact fixed-width ciphertexts, zero unlock heights and an issuer
    /// signature message. This does not itself pay or consume the issuance fee.
    pub fn prepare_issuance(
        &self,
        config: &Config,
        request: IssuanceRequest,
    ) -> Result<PreparedIssuance, String> {
        config.validate()?;
        if config.network != self.keys.network {
            return Err("issuance wallet network mismatch".into());
        }
        let policy = config
            .issuance
            .as_ref()
            .ok_or("issuance policy is not configured")?;
        policy.validate()?;
        if request.metadata.name.len() + 1 > usize::from(policy.max_metadata_bytes)
            || request.public_supply == 0
        {
            return Err("issuance metadata limit or zero supply".into());
        }
        let sum = request.outputs.iter().try_fold(0u64, |sum, output| {
            sum.checked_add(output.amount)
                .ok_or("issuance amount sum overflow")
        })?;
        if sum != request.public_supply {
            return Err("issuance output sum differs from declared supply".into());
        }
        let asset = derive_asset_id(&config.network, &request.issuer_key, request.sequence);
        let h = Hasher::new();
        let ec = EncryptionContext::new(config.network);
        let recipients = request
            .outputs
            .each_ref()
            .map(|output| output.recipient.clone());
        let mut notes = PrivateNotes(Vec::with_capacity(INITIAL_NOTES));
        let mut ciphertexts = Vec::with_capacity(INITIAL_NOTES);
        let mut openings = Vec::with_capacity(INITIAL_NOTES);
        for output in request.outputs {
            notes.0.push(Note {
                asset_id: asset,
                owner: output.recipient.owner(),
                value: output.amount,
                unlock_height: 0,
                rho: random_fields()?,
                rseed: random_fields()?,
            });
            let note = notes.0.last().expect("just appended issuance note");
            let commitment = h.note_cm(note);
            let (ciphertext, opening) = encrypt_payment_with_opening(&output.recipient, note, &ec)
                .map_err(|_| "issuance recipient encryption failed")?;
            let recovered = opening
                .verify_payment(&output.recipient, &commitment, &ciphertext, &ec)
                .map_err(|_| "issuance recipient self-check failed")?;
            if !same_note(&recovered, note) {
                return Err("issuance recipient plaintext differs from prepared note".into());
            }
            let mut bytes = [0; CIPHERTEXT_BYTES];
            bytes[..1088].copy_from_slice(&ciphertext.kem_ciphertext);
            bytes[1088..1296].copy_from_slice(&ciphertext.body);
            bytes[1296..1312].copy_from_slice(&ciphertext.tag);
            bytes[1312] = ciphertext.view_tag;
            ciphertexts.push(bytes.to_vec());
            openings.push(opening);
        }
        let declaration = IssuanceDeclaration {
            network: config.network,
            version: 1,
            issuer_key: request.issuer_key,
            sequence: request.sequence,
            asset_id: asset,
            public_supply: request.public_supply,
            metadata: request.metadata,
            issuance_fee_atoms: TESTNET_ISSUANCE_FEE_ATOMS,
            note_commitments: notes.0.iter().map(|note| h.note_cm(note)).collect(),
            note_ciphertext_digests: ciphertexts
                .iter()
                .map(|bytes| *blake3::hash(bytes).as_bytes())
                .collect(),
        };
        declaration
            .validate(&config.network, 1, policy.policy())
            .map_err(|e| format!("invalid prepared issuance: {e:?}"))?;
        let witness = PrivateWitness(IssuanceWitness {
            declaration,
            notes: core::mem::take(&mut notes.0),
            ciphertexts,
        });
        witness
            .0
            .check()
            .map_err(|e| format!("invalid prepared issuance witness: {e:?}"))?;
        Ok(PreparedIssuance {
            witness,
            recipients,
            openings: openings
                .try_into()
                .map_err(|_| "issuance opening count mismatch")?,
        })
    }
    /// Prepare a real SIP transfer to the explicitly configured fund owner.
    /// The issuance declaration is committed through output rseed; rho remains
    /// exactly the ordinary transaction AIR's nullifier-derived output value.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_issuance_fee(
        &self,
        state: &State,
        selected: [Option<DigestBytes>; 2],
        destination: &PaymentAddress,
        declaration: &IssuanceDeclaration,
        tier: FeeTier,
        now: u64,
    ) -> Result<PreparedIssuanceFee, String> {
        let policy = state
            .config
            .issuance
            .as_ref()
            .ok_or("issuance policy is not configured")?;
        policy.validate()?;
        declaration
            .validate(&state.config.network, 1, policy.policy())
            .map_err(|e| format!("invalid fee declaration: {e:?}"))?;
        if encode_digest(&destination.owner()) != policy.fee_owner {
            return Err("issuance fee recipient differs from configured fund owner".into());
        }
        let binding = declaration.binding();
        let transfer = self.prepare_transfer_with_randomness(
            state,
            selected,
            destination,
            SIP_ASSET_ID,
            TESTNET_ISSUANCE_FEE_ATOMS,
            tier,
            now,
            Some(fee_rseed(binding)),
        )?;
        let note = transfer
            .witness()
            .slot
            .output_note(&Hasher::new(), &transfer.public().nf, 0);
        let receipt = IssuanceFeeReceipt {
            declaration: binding,
            commitment: encode_digest(&transfer.public().cm[0]),
            rho: encode_digest(&note.rho),
        };
        Ok(PreparedIssuanceFee { transfer, receipt })
    }
}
impl PreparedIssuance {
    pub fn declaration(&self) -> &IssuanceDeclaration {
        &self.witness.0.declaration
    }
    pub fn signature_message(&self) -> Vec<u8> {
        self.declaration().canonical_bytes()
    }
    pub fn attach_signature(
        self,
        signature: [u8; ISSUER_SIGNATURE_BYTES],
    ) -> Result<SignedPreparedIssuance, String> {
        let signed = SignedIssuance {
            declaration: self.witness.0.declaration.clone(),
            signature: Some(signature),
        };
        signed
            .verify_signature()
            .map_err(|e| format!("invalid issuance signature: {e:?}"))?;
        Ok(SignedPreparedIssuance {
            signed,
            witness: self.witness,
            recipients: self.recipients,
            openings: self.openings,
        })
    }
}
pub struct SignedPreparedIssuance {
    signed: SignedIssuance,
    witness: PrivateWitness,
    recipients: [PaymentAddress; INITIAL_NOTES],
    openings: [PaymentEncryptionOpening; INITIAL_NOTES],
}
impl SignedPreparedIssuance {
    /// Prove fixed-supply minting and independently verify against the pinned
    /// local key. The supplied fee receipt is still checked by admission/block
    /// validation against a canonical historical payment or a verified ordinary
    /// transaction included in the same block.
    pub fn prove(
        self,
        prover: &IssuanceProver,
        fee: &IssuanceFeeReceipt,
        config: &Config,
    ) -> Result<WalletIssuance, String> {
        self.prove_with(
            fee,
            config,
            |witness| {
                let (proof, _) = prover
                    .prove(witness)
                    .map_err(|_| "native issuance proving failed")?;
                postcard::to_allocvec(&proof).map_err(|_| "issuance proof encoding failed".into())
            },
            |record| IssuanceVerifier::new()?.verify(record),
        )
    }
    /// Generate and independently verify V2 under the authenticated genesis domain.
    pub fn prove_for_genesis(
        self,
        prover: &crate::proofs::NativeProver,
        fee: &IssuanceFeeReceipt,
        genesis: &crate::proofs::NativeProofGenesis,
    ) -> Result<WalletIssuance, String> {
        let verifier = crate::proofs::NativeVerifier::for_genesis(genesis)?;
        self.prove_with(
            fee,
            genesis.config(),
            |witness| prover.issuance(witness),
            |record| verifier.verify_issuance(record),
        )
    }
    fn prove_with(
        self,
        fee: &IssuanceFeeReceipt,
        config: &Config,
        generate: impl FnOnce(&IssuanceWitness) -> Result<Vec<u8>, String>,
        verify: impl FnOnce(&IssuanceRecord) -> Result<(), String>,
    ) -> Result<WalletIssuance, String> {
        if self.signed.declaration != self.witness.0.declaration
            || fee.declaration != self.signed.declaration.binding()
        {
            return Err("issuance witness or fee declaration mismatch".into());
        }
        self.witness
            .0
            .check()
            .map_err(|e| format!("issuance witness self-check: {e:?}"))?;
        for index in 0..INITIAL_NOTES {
            let ciphertext = self.witness.0.ciphertexts[index]
                .as_slice()
                .try_into()
                .map_err(|_| "issuance ciphertext width")?;
            let note = self.openings[index]
                .verify_payment(
                    &self.recipients[index],
                    &self.signed.declaration.note_commitments[index],
                    &decode_payment(ciphertext),
                    &EncryptionContext::new(config.network),
                )
                .map_err(|_| "issuance opening self-check failed")?;
            if !same_note(&note, &self.witness.0.notes[index]) {
                return Err("issuance opening note mismatch".into());
            }
        }
        let proof = generate(&self.witness.0)?;
        let record = IssuanceRecord {
            signed: self.signed,
            ciphertexts: self.witness.0.ciphertexts.clone(),
            proof,
            fee_commitment: fee.commitment,
            fee_rho: fee.rho,
        };
        record.validate(config)?;
        verify(&record)?;
        Ok(WalletIssuance {
            record,
            openings: self.openings,
        })
    }
}
/// Protect every per-output encryption opening before publishing the record.
/// These openings disclose a single initial note, never a wallet master key.
#[must_use = "Protect the initial-note payment openings before publication"]
pub struct WalletIssuance {
    pub record: IssuanceRecord,
    openings: [PaymentEncryptionOpening; INITIAL_NOTES],
}
impl WalletIssuance {
    pub fn payment_opening(&self, index: usize) -> Option<&PaymentEncryptionOpening> {
        self.openings.get(index)
    }
}
