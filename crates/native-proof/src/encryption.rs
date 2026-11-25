//! Fixed-format wallet encryption for the experimental native D8 transaction.
//!
//! Output owners and senders authenticate plaintext and reconstruct commitments.
//! Public ciphertext binding does not prove encryption correctness inside the AIR.

use crate::common::{Digest, F, Hasher, Note, felt_from_canonical};
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use libcrux_ml_kem::mlkem768::{self, MlKem768Ciphertext, MlKem768PrivateKey, MlKem768PublicKey};
use p3_field::PrimeField32;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const FORMAT_VERSION: u16 = 1;
pub const DIGEST_BYTES: usize = 48;
pub const ENCAPSULATION_KEY_LEN: usize = 1_184;
pub const KEM_CIPHERTEXT_LEN: usize = 1_088;
pub const PLAINTEXT_LEN: usize = 208;
pub const NOTE_FIELDS_LEN: usize = 112;
pub const AEAD_TAG_LEN: usize = 16;
pub const CHANGE_NONCE_LEN: usize = 12;
pub const PAYMENT_INDEX: u8 = 0;
pub const CHANGE_INDEX: u8 = 1;

const AAD_DOMAIN: &[u8] = b"siworld route-a output aad v1\0";
const PAYMENT_KEY_DOMAIN: &str = "siworld route-a payment-key-v1";
const PAYMENT_VIEW_DOMAIN: &str = "siworld route-a payment-view-v1";
const CHANGE_KEY_DOMAIN: &str = "siworld route-a change-v1";
const CHANGE_VIEW_DOMAIN: &str = "siworld route-a change-view-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncryptionError {
    Entropy,
    InvalidPublicKey,
    UnsupportedVersion,
    Authentication,
    InvalidPlaintext,
    CommitmentMismatch,
    OwnerMismatch,
}

impl fmt::Display for EncryptionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Entropy => "operating-system randomness unavailable",
            Self::InvalidPublicKey => "invalid ML-KEM-768 public key",
            Self::UnsupportedVersion => "unsupported output encryption version",
            Self::Authentication => "output authentication failed",
            Self::InvalidPlaintext => "noncanonical output plaintext",
            Self::CommitmentMismatch => "output commitment mismatch",
            Self::OwnerMismatch => "payment owner differs from address owner",
        })
    }
}

impl std::error::Error for EncryptionError {}

/// Public proof/relay context, excluded from the 1,742-byte transaction payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncryptionContext {
    pub network: [u8; 32],
    pub version: u16,
}

impl EncryptionContext {
    pub fn new(network: [u8; 32]) -> Self {
        Self {
            network,
            version: FORMAT_VERSION,
        }
    }

    fn check(&self) -> Result<(), EncryptionError> {
        if self.version == FORMAT_VERSION {
            Ok(())
        } else {
            Err(EncryptionError::UnsupportedVersion)
        }
    }
}

/// Public fixed-width recipient fields. There is no serialized payment nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentCiphertext {
    pub kem_ciphertext: [u8; KEM_CIPHERTEXT_LEN],
    pub body: [u8; PLAINTEXT_LEN],
    pub tag: [u8; AEAD_TAG_LEN],
    pub view_tag: u8,
}

/// Public fixed-width change fields; the explicit nonce is part of the binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangeCiphertext {
    pub nonce: [u8; CHANGE_NONCE_LEN],
    pub body: [u8; PLAINTEXT_LEN],
    pub tag: [u8; AEAD_TAG_LEN],
    pub view_tag: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentAddress {
    owner: Digest,
    encapsulation_key: [u8; ENCAPSULATION_KEY_LEN],
}

impl PaymentAddress {
    pub fn new(
        owner: Digest,
        encapsulation_key: [u8; ENCAPSULATION_KEY_LEN],
    ) -> Result<Self, EncryptionError> {
        let public_key = MlKem768PublicKey::from(&encapsulation_key);
        if !mlkem768::validate_public_key(&public_key) {
            return Err(EncryptionError::InvalidPublicKey);
        }
        Ok(Self {
            owner,
            encapsulation_key,
        })
    }

    pub fn owner(&self) -> Digest {
        self.owner
    }
    pub fn encapsulation_key(&self) -> &[u8; ENCAPSULATION_KEY_LEN] {
        &self.encapsulation_key
    }
}

/// An owned view key. Zeroization covers owned buffers, not dependency copies.
pub struct RecipientViewKey {
    address: PaymentAddress,
    private_key: MlKem768PrivateKey,
}

impl RecipientViewKey {
    pub fn generate(owner: Digest) -> Result<Self, EncryptionError> {
        let mut seed = Zeroizing::new([0u8; libcrux_ml_kem::KEY_GENERATION_SEED_SIZE]);
        getrandom::fill(seed.as_mut()).map_err(|_| EncryptionError::Entropy)?;
        let (mut private_key, public_key) = mlkem768::generate_key_pair(*seed).into_parts();
        let address = match PaymentAddress::new(owner, *public_key.as_slice()) {
            Ok(address) => address,
            Err(error) => {
                private_key[0..MlKem768PrivateKey::len()].zeroize();
                return Err(error);
            }
        };
        Ok(Self {
            address,
            private_key,
        })
    }

    pub fn address(&self) -> PaymentAddress {
        self.address.clone()
    }

    pub fn decrypt_payment(
        &self,
        commitment: &Digest,
        ciphertext: &PaymentCiphertext,
        context: &EncryptionContext,
    ) -> Result<Note, EncryptionError> {
        context.check()?;
        let kem = MlKem768Ciphertext::from(&ciphertext.kem_ciphertext);
        let shared_secret = Zeroizing::new(mlkem768::decapsulate(&self.private_key, &kem));
        decrypt_payment_with_shared_secret(
            self.address.owner,
            commitment,
            ciphertext,
            context,
            &shared_secret,
        )
    }
}

impl Zeroize for RecipientViewKey {
    fn zeroize(&mut self) {
        self.private_key[0..MlKem768PrivateKey::len()].zeroize();
    }
}
impl Drop for RecipientViewKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for RecipientViewKey {}
impl fmt::Debug for RecipientViewKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecipientViewKey(REDACTED)")
    }
}

/// Wallet-derived 256-bit sender change secret; no implicit clone is provided.
pub struct SenderChangeSecret([u8; 32]);
impl SenderChangeSecret {
    /// The caller owns erasure of any source copy used to construct this value.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn generate() -> Result<Self, EncryptionError> {
        let mut value = Self([0; 32]);
        getrandom::fill(&mut value.0).map_err(|_| EncryptionError::Entropy)?;
        Ok(value)
    }
}
impl Zeroize for SenderChangeSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl Drop for SenderChangeSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for SenderChangeSecret {}
impl fmt::Debug for SenderChangeSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SenderChangeSecret(REDACTED)")
    }
}

/// A single payment's encapsulation coins, retained privately for a receipt.
///
/// Disclosing this opening reveals the payment plaintext to its holder. It does
/// not establish address ownership or transaction inclusion. Wallet persistence
/// and receipt transport are outside this experimental helper's scope.
#[must_use = "V1 real-wallet payment openings must be persisted securely before broadcast"]
pub struct PaymentEncryptionOpening([u8; 32]);

impl PaymentEncryptionOpening {
    /// The caller owns erasure of any source copy used to construct this value.
    pub fn from_encapsulation_coins(coins: [u8; 32]) -> Self {
        Self(coins)
    }

    /// Explicit disclosure for one selected payment, never a wallet master key.
    pub fn expose_encapsulation_coins(&self) -> &[u8; 32] {
        &self.0
    }

    /// Rebuild the KEM ciphertext, authenticate and reconstruct the public note.
    pub fn verify_payment(
        &self,
        address: &PaymentAddress,
        commitment: &Digest,
        ciphertext: &PaymentCiphertext,
        context: &EncryptionContext,
    ) -> Result<Note, EncryptionError> {
        context.check()?;
        let (expected, shared_secret) =
            mlkem768::encapsulate(&MlKem768PublicKey::from(&address.encapsulation_key), self.0);
        let shared_secret = Zeroizing::new(shared_secret);
        if expected.as_slice() != &ciphertext.kem_ciphertext {
            return Err(EncryptionError::Authentication);
        }
        decrypt_payment_with_shared_secret(
            address.owner,
            commitment,
            ciphertext,
            context,
            &shared_secret,
        )
    }
}

impl Zeroize for PaymentEncryptionOpening {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl Drop for PaymentEncryptionOpening {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for PaymentEncryptionOpening {}
impl fmt::Debug for PaymentEncryptionOpening {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PaymentEncryptionOpening(REDACTED)")
    }
}

/// Lower-level discard-opening helper for padding and test fixtures.
/// V1 real-wallet payments must use `encrypt_payment_with_opening` and persist
/// the opening in protected wallet storage before broadcasting the transaction.
pub fn encrypt_payment(
    address: &PaymentAddress,
    note: &Note,
    context: &EncryptionContext,
) -> Result<PaymentCiphertext, EncryptionError> {
    encrypt_payment_with_opening(address, note, context).map(|(ciphertext, _)| ciphertext)
}

/// Fresh OS coins produce a new payment key for the fixed zero nonce.
/// The sender uses the encapsulation secret to check the full plaintext and
/// reconstructed commitment before any ciphertext is returned for publication.
/// V1 real-wallet callers must persist the returned opening in protected wallet
/// storage and run `check_output_pair_before_broadcast` on the completed pair.
/// These helpers do not implement storage or transaction broadcasting.
pub fn encrypt_payment_with_opening(
    address: &PaymentAddress,
    note: &Note,
    context: &EncryptionContext,
) -> Result<(PaymentCiphertext, PaymentEncryptionOpening), EncryptionError> {
    context.check()?;
    if address.owner != note.owner {
        return Err(EncryptionError::OwnerMismatch);
    }
    let commitment = Hasher::new().note_cm(note);
    let mut coins = Zeroizing::new([0u8; 32]);
    getrandom::fill(coins.as_mut()).map_err(|_| EncryptionError::Entropy)?;
    let (kem_ciphertext, shared_secret) =
        mlkem768::encapsulate(&MlKem768PublicKey::from(&address.encapsulation_key), *coins);
    let shared_secret = Zeroizing::new(shared_secret);
    let key = derive_secret(PAYMENT_KEY_DOMAIN, shared_secret.as_ref());
    let mut body = encode_note(note);
    let tag = seal(
        &key,
        &[0; 12],
        &aad(context, PAYMENT_INDEX, &commitment),
        &mut body,
    )?;
    let ciphertext = PaymentCiphertext {
        kem_ciphertext: *kem_ciphertext.as_slice(),
        body: *body,
        tag,
        view_tag: view_tag(PAYMENT_VIEW_DOMAIN, &shared_secret),
    };
    decrypt_payment_with_shared_secret(
        address.owner,
        &commitment,
        &ciphertext,
        context,
        &shared_secret,
    )?;
    Ok((
        ciphertext,
        PaymentEncryptionOpening::from_encapsulation_coins(*coins),
    ))
}

pub fn encrypt_change(
    secret: &SenderChangeSecret,
    note: &Note,
    context: &EncryptionContext,
) -> Result<ChangeCiphertext, EncryptionError> {
    context.check()?;
    let commitment = Hasher::new().note_cm(note);
    let key = change_key(secret, &commitment);
    let mut nonce = [0u8; CHANGE_NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| EncryptionError::Entropy)?;
    let mut body = encode_note(note);
    let tag = seal(
        &key,
        &nonce,
        &aad(context, CHANGE_INDEX, &commitment),
        &mut body,
    )?;
    let ciphertext = ChangeCiphertext {
        nonce,
        body: *body,
        tag,
        view_tag: view_tag(CHANGE_VIEW_DOMAIN, &key),
    };
    decrypt_change(secret, note.owner, &commitment, &ciphertext, context)?;
    Ok(ciphertext)
}

pub fn decrypt_change(
    secret: &SenderChangeSecret,
    owner: Digest,
    commitment: &Digest,
    ciphertext: &ChangeCiphertext,
    context: &EncryptionContext,
) -> Result<Note, EncryptionError> {
    context.check()?;
    let key = change_key(secret, commitment);
    if view_tag(CHANGE_VIEW_DOMAIN, &key) != ciphertext.view_tag {
        return Err(EncryptionError::Authentication);
    }
    let mut plaintext = Zeroizing::new(ciphertext.body);
    open(
        &key,
        &ciphertext.nonce,
        &aad(context, CHANGE_INDEX, commitment),
        &mut plaintext,
        &ciphertext.tag,
    )?;
    decode_note(owner, commitment, &plaintext)
}

/// A fully built output pair that has not passed the final local encryption check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputPairCiphertexts {
    pub commitments: [Digest; 2],
    pub payment: PaymentCiphertext,
    pub change: ChangeCiphertext,
}

/// An immutable pair authenticated under the supplied wallet keys and context.
/// This establishes local encryption consistency, not proof or ledger validity.
#[must_use = "Use the checked output pair when constructing the broadcast transaction"]
pub struct CheckedOutputPair {
    pair: OutputPairCiphertexts,
    context: EncryptionContext,
}

impl CheckedOutputPair {
    pub fn commitments(&self) -> &[Digest; 2] {
        &self.pair.commitments
    }

    pub fn payment(&self) -> &PaymentCiphertext {
        &self.pair.payment
    }

    pub fn change(&self) -> &ChangeCiphertext {
        &self.pair.change
    }

    pub fn context(&self) -> &EncryptionContext {
        &self.context
    }
}

/// Check the completed pair after construction and before the broadcast stage.
/// Both supplied notes must reconstruct their commitments; payment and change
/// must authenticate and reconstruct those same commitments under this context.
/// Only immutable checked fields are returned. Wallet opening persistence is a
/// separate mandatory precondition that this in-memory helper cannot enforce.
pub fn check_output_pair_before_broadcast(
    pair: OutputPairCiphertexts,
    notes: &[Note; 2],
    address: &PaymentAddress,
    opening: &PaymentEncryptionOpening,
    change_secret: &SenderChangeSecret,
    context: &EncryptionContext,
) -> Result<CheckedOutputPair, EncryptionError> {
    context.check()?;
    let hasher = Hasher::new();
    if notes.each_ref().map(|note| hasher.note_cm(note)) != pair.commitments {
        return Err(EncryptionError::CommitmentMismatch);
    }
    opening.verify_payment(address, &pair.commitments[0], &pair.payment, context)?;
    decrypt_change(
        change_secret,
        notes[1].owner,
        &pair.commitments[1],
        &pair.change,
        context,
    )?;
    Ok(CheckedOutputPair {
        pair,
        context: *context,
    })
}

/// Private witness data with the same public encryption fields as other outputs.
/// This type is not a transaction encoder or an empty-transaction proof builder.
pub struct DummyOutputEncryption {
    pub notes: [Note; 2],
    pub payment: PaymentCiphertext,
    pub change: ChangeCiphertext,
}

/// Create genuine encryption to fresh throwaway keys, never random ciphertext
/// padding. The caller supplies output rhos derived by the transaction relation
/// and remains responsible for its input nullifiers and proof.
pub fn encrypt_dummy_outputs(
    rhos: [Digest; 2],
    context: &EncryptionContext,
) -> Result<DummyOutputEncryption, EncryptionError> {
    context.check()?;
    let hasher = Hasher::new();
    let recipient = RecipientViewKey::generate(hasher.owner(&random_digest()?))?;
    let change_owner = hasher.owner(&random_digest()?);
    let change_secret = SenderChangeSecret::generate()?;
    encrypt_dummy_outputs_to(
        &recipient.address(),
        change_owner,
        &change_secret,
        rhos,
        context,
    )
}

fn encrypt_dummy_outputs_to(
    address: &PaymentAddress,
    change_owner: Digest,
    change_secret: &SenderChangeSecret,
    rhos: [Digest; 2],
    context: &EncryptionContext,
) -> Result<DummyOutputEncryption, EncryptionError> {
    context.check()?;
    let notes = [
        Note {
            owner: address.owner,
            value: 0,
            unlock_height: 0,
            rho: rhos[0],
            rseed: random_digest()?,
        },
        Note {
            owner: change_owner,
            value: 0,
            unlock_height: 0,
            rho: rhos[1],
            rseed: random_digest()?,
        },
    ];
    let payment = encrypt_payment(address, &notes[0], context)?;
    let change = encrypt_change(change_secret, &notes[1], context)?;
    Ok(DummyOutputEncryption {
        notes,
        payment,
        change,
    })
}

fn random_digest() -> Result<Digest, EncryptionError> {
    let mut digest = [F::default(); 12];
    let mut bytes = Zeroizing::new([0u8; 4]);
    for field in &mut digest {
        loop {
            getrandom::fill(bytes.as_mut()).map_err(|_| EncryptionError::Entropy)?;
            if let Some(value) = felt_from_canonical(u32::from_le_bytes(*bytes)) {
                *field = value;
                break;
            }
        }
    }
    Ok(digest)
}

fn decrypt_payment_with_shared_secret(
    owner: Digest,
    commitment: &Digest,
    ciphertext: &PaymentCiphertext,
    context: &EncryptionContext,
    shared_secret: &[u8; 32],
) -> Result<Note, EncryptionError> {
    context.check()?;
    if view_tag(PAYMENT_VIEW_DOMAIN, shared_secret) != ciphertext.view_tag {
        return Err(EncryptionError::Authentication);
    }
    let key = derive_secret(PAYMENT_KEY_DOMAIN, shared_secret);
    let mut plaintext = Zeroizing::new(ciphertext.body);
    open(
        &key,
        &[0; 12],
        &aad(context, PAYMENT_INDEX, commitment),
        &mut plaintext,
        &ciphertext.tag,
    )?;
    decode_note(owner, commitment, &plaintext)
}

fn change_key(secret: &SenderChangeSecret, commitment: &Digest) -> Zeroizing<[u8; 32]> {
    let mut kdf = Zeroizing::new(blake3::Hasher::new_derive_key(CHANGE_KEY_DOMAIN));
    kdf.update(&secret.0);
    kdf.update(&encode_digest(commitment));
    kdf.update(&[CHANGE_INDEX]);
    let output = Zeroizing::new(kdf.finalize());
    Zeroizing::new(*output.as_bytes())
}

fn derive_secret(domain: &str, material: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut kdf = Zeroizing::new(blake3::Hasher::new_derive_key(domain));
    kdf.update(material);
    let output = Zeroizing::new(kdf.finalize());
    Zeroizing::new(*output.as_bytes())
}

fn view_tag(domain: &str, material: &[u8; 32]) -> u8 {
    derive_secret(domain, material)[0]
}

fn aad(context: &EncryptionContext, index: u8, commitment: &Digest) -> Vec<u8> {
    let mut data = Vec::with_capacity(AAD_DOMAIN.len() + 2 + 32 + 1 + DIGEST_BYTES);
    data.extend_from_slice(AAD_DOMAIN);
    data.extend_from_slice(&context.version.to_le_bytes());
    data.extend_from_slice(&context.network);
    data.push(index);
    data.extend_from_slice(&encode_digest(commitment));
    data
}

fn seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    associated_data: &[u8],
    body: &mut [u8; PLAINTEXT_LEN],
) -> Result<[u8; AEAD_TAG_LEN], EncryptionError> {
    let aead = ChaCha20Poly1305::new(<&Key>::try_from(key.as_slice()).expect("fixed key size"));
    let tag = aead
        .encrypt_inout_detached(
            <&Nonce>::try_from(nonce.as_slice()).expect("fixed nonce size"),
            associated_data,
            body.as_mut_slice().into(),
        )
        .map_err(|_| EncryptionError::Authentication)?;
    Ok(tag.into())
}

fn open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    associated_data: &[u8],
    body: &mut [u8; PLAINTEXT_LEN],
    tag: &[u8; AEAD_TAG_LEN],
) -> Result<(), EncryptionError> {
    let aead = ChaCha20Poly1305::new(<&Key>::try_from(key.as_slice()).expect("fixed key size"));
    let tag = <&Tag>::try_from(tag.as_slice()).expect("fixed tag size");
    aead.decrypt_inout_detached(
        <&Nonce>::try_from(nonce.as_slice()).expect("fixed nonce size"),
        associated_data,
        body.as_mut_slice().into(),
        tag,
    )
    .map_err(|_| EncryptionError::Authentication)
}

fn encode_digest(digest: &Digest) -> [u8; DIGEST_BYTES] {
    let mut bytes = [0; DIGEST_BYTES];
    for (field, target) in digest.iter().zip(bytes.as_chunks_mut::<4>().0.iter_mut()) {
        target.copy_from_slice(&field.as_canonical_u32().to_le_bytes());
    }
    bytes
}

fn decode_digest(bytes: &[u8]) -> Result<Digest, EncryptionError> {
    if bytes.len() != DIGEST_BYTES {
        return Err(EncryptionError::InvalidPlaintext);
    }
    let mut digest = [F::default(); 12];
    for (target, bytes) in digest.iter_mut().zip(bytes.as_chunks::<4>().0.iter()) {
        let word = u32::from_le_bytes(*bytes);
        *target = felt_from_canonical(word).ok_or(EncryptionError::InvalidPlaintext)?;
    }
    Ok(digest)
}

fn encode_note(note: &Note) -> Zeroizing<[u8; PLAINTEXT_LEN]> {
    let mut plaintext = Zeroizing::new([0; PLAINTEXT_LEN]);
    plaintext[0..8].copy_from_slice(&note.value.to_le_bytes());
    plaintext[8..16].copy_from_slice(&note.unlock_height.to_le_bytes());
    plaintext[16..16 + DIGEST_BYTES].copy_from_slice(&encode_digest(&note.rho));
    plaintext[16 + DIGEST_BYTES..NOTE_FIELDS_LEN].copy_from_slice(&encode_digest(&note.rseed));
    plaintext
}

fn decode_note(
    owner: Digest,
    commitment: &Digest,
    plaintext: &[u8; PLAINTEXT_LEN],
) -> Result<Note, EncryptionError> {
    if plaintext[NOTE_FIELDS_LEN..].iter().any(|byte| *byte != 0) {
        return Err(EncryptionError::InvalidPlaintext);
    }
    let note = Note {
        owner,
        value: u64::from_le_bytes(plaintext[0..8].try_into().expect("fixed value width")),
        unlock_height: u64::from_le_bytes(plaintext[8..16].try_into().expect("fixed height width")),
        rho: decode_digest(&plaintext[16..16 + DIGEST_BYTES])?,
        rseed: decode_digest(&plaintext[16 + DIGEST_BYTES..NOTE_FIELDS_LEN])?,
    };
    if Hasher::new().note_cm(&note) != *commitment {
        return Err(EncryptionError::CommitmentMismatch);
    }
    Ok(note)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{DIGEST, F};
    use p3_field::PrimeCharacteristicRing;

    fn digest(value: u32) -> Digest {
        [F::from_u32(value); DIGEST]
    }

    fn note(owner: Digest) -> Note {
        Note {
            owner,
            value: 456_789,
            unlock_height: 37,
            rho: digest(3),
            rseed: digest(4),
        }
    }

    fn context() -> EncryptionContext {
        EncryptionContext::new([11; 32])
    }

    fn assert_note_eq(left: &Note, right: &Note) {
        assert_eq!(left.owner, right.owner);
        assert_eq!(left.value, right.value);
        assert_eq!(left.unlock_height, right.unlock_height);
        assert_eq!(left.rho, right.rho);
        assert_eq!(left.rseed, right.rseed);
    }

    #[test]
    fn fixed_payload_dimensions_match_selected_layout() {
        assert_eq!(DIGEST_BYTES, 48);
        assert_eq!(NOTE_FIELDS_LEN, 112);
        assert_eq!(PLAINTEXT_LEN - NOTE_FIELDS_LEN, 96);
        assert_eq!(
            4 * DIGEST_BYTES
                + KEM_CIPHERTEXT_LEN
                + 2 * PLAINTEXT_LEN
                + 2 * AEAD_TAG_LEN
                + CHANGE_NONCE_LEN
                + 2,
            1_742
        );
    }

    #[test]
    fn payment_and_change_roundtrip_reconstruct_commitments() {
        let recipient = RecipientViewKey::generate(digest(1)).unwrap();
        let payment_note = note(recipient.address().owner());
        let payment_cm = Hasher::new().note_cm(&payment_note);
        let payment = encrypt_payment(&recipient.address(), &payment_note, &context()).unwrap();
        let recovered = recipient
            .decrypt_payment(&payment_cm, &payment, &context())
            .unwrap();
        assert_note_eq(&payment_note, &recovered);

        let sender = SenderChangeSecret::new([7; 32]);
        let change_note = note(digest(2));
        let change_cm = Hasher::new().note_cm(&change_note);
        let change = encrypt_change(&sender, &change_note, &context()).unwrap();
        let recovered =
            decrypt_change(&sender, change_note.owner, &change_cm, &change, &context()).unwrap();
        assert_note_eq(&change_note, &recovered);
    }

    #[test]
    fn sender_checks_payment_and_retains_a_single_payment_opening() {
        let recipient = RecipientViewKey::generate(digest(1)).unwrap();
        let address = recipient.address();
        let original_note = note(address.owner());
        let commitment = Hasher::new().note_cm(&original_note);
        let (ciphertext, opening) =
            encrypt_payment_with_opening(&address, &original_note, &context()).unwrap();

        // The sender can reconstruct the note without the recipient's view key.
        drop(recipient);
        let recovered = opening
            .verify_payment(&address, &commitment, &ciphertext, &context())
            .unwrap();
        assert_note_eq(&original_note, &recovered);

        // Export is explicit and reveals only this payment's encapsulation coins.
        let exported = Zeroizing::new(*opening.expose_encapsulation_coins());
        let disclosed = PaymentEncryptionOpening::from_encapsulation_coins(*exported);
        assert_note_eq(
            &original_note,
            &disclosed
                .verify_payment(&address, &commitment, &ciphertext, &context())
                .unwrap(),
        );
    }

    #[test]
    fn payment_opening_rejects_reuse_and_changed_public_data() {
        let recipient = RecipientViewKey::generate(digest(1)).unwrap();
        let address = recipient.address();
        let original_note = note(address.owner());
        let commitment = Hasher::new().note_cm(&original_note);
        let (ciphertext, opening) =
            encrypt_payment_with_opening(&address, &original_note, &context()).unwrap();
        let (second, second_opening) =
            encrypt_payment_with_opening(&address, &original_note, &context()).unwrap();
        assert!(
            opening
                .verify_payment(&address, &commitment, &second, &context())
                .is_err()
        );
        assert!(
            second_opening
                .verify_payment(&address, &commitment, &ciphertext, &context())
                .is_err()
        );
        let mut wrong_coins = Zeroizing::new(*opening.expose_encapsulation_coins());
        wrong_coins[0] ^= 1;
        assert!(
            PaymentEncryptionOpening::from_encapsulation_coins(*wrong_coins)
                .verify_payment(&address, &commitment, &ciphertext, &context())
                .is_err()
        );
        let mut changed = ciphertext.clone();
        changed.kem_ciphertext[0] ^= 1;
        assert!(
            opening
                .verify_payment(&address, &commitment, &changed, &context())
                .is_err()
        );
        changed = ciphertext.clone();
        changed.body[0] ^= 1;
        assert!(
            opening
                .verify_payment(&address, &commitment, &changed, &context())
                .is_err()
        );
        changed = ciphertext.clone();
        changed.tag[0] ^= 1;
        assert!(
            opening
                .verify_payment(&address, &commitment, &changed, &context())
                .is_err()
        );
        changed = ciphertext.clone();
        changed.view_tag ^= 1;
        assert!(
            opening
                .verify_payment(&address, &commitment, &changed, &context())
                .is_err()
        );
        assert!(
            opening
                .verify_payment(&address, &digest(9), &ciphertext, &context())
                .is_err()
        );
        assert!(
            opening
                .verify_payment(
                    &address,
                    &commitment,
                    &ciphertext,
                    &EncryptionContext::new([12; 32]),
                )
                .is_err()
        );
        let wrong_recipient = RecipientViewKey::generate(address.owner()).unwrap();
        assert!(
            opening
                .verify_payment(
                    &wrong_recipient.address(),
                    &commitment,
                    &ciphertext,
                    &context()
                )
                .is_err()
        );
        let wrong_owner = PaymentAddress::new(digest(2), *address.encapsulation_key()).unwrap();
        assert!(
            opening
                .verify_payment(&wrong_owner, &commitment, &ciphertext, &context())
                .is_err()
        );
    }

    #[test]
    fn prebroadcast_pair_check_rejects_changes_after_encryption() {
        let recipient = RecipientViewKey::generate(digest(1)).unwrap();
        let address = recipient.address();
        let notes = [note(address.owner()), note(digest(2))];
        let commitments = notes.each_ref().map(|note| Hasher::new().note_cm(note));
        let change_secret = SenderChangeSecret::generate().unwrap();
        let (payment, opening) =
            encrypt_payment_with_opening(&address, &notes[0], &context()).unwrap();
        let change = encrypt_change(&change_secret, &notes[1], &context()).unwrap();
        let pair = OutputPairCiphertexts {
            commitments,
            payment,
            change,
        };
        let check = |pair, notes: &[Note; 2], context: &EncryptionContext| {
            check_output_pair_before_broadcast(
                pair,
                notes,
                &address,
                &opening,
                &change_secret,
                context,
            )
        };
        let checked = check(pair.clone(), &notes, &context()).unwrap();
        assert_eq!(checked.commitments(), &pair.commitments);
        assert_eq!(checked.payment(), &pair.payment);
        assert_eq!(checked.change(), &pair.change);
        assert_eq!(checked.context(), &context());

        for index in 0..2 {
            let mut changed = pair.clone();
            if index == PAYMENT_INDEX as usize {
                changed.payment.body[0] ^= 1;
            } else {
                changed.change.body[0] ^= 1;
            }
            assert!(check(changed, &notes, &context()).is_err());
            let mut changed = pair.clone();
            if index == PAYMENT_INDEX as usize {
                changed.payment.tag[0] ^= 1;
            } else {
                changed.change.tag[0] ^= 1;
            }
            assert!(check(changed, &notes, &context()).is_err());
            let mut changed = pair.clone();
            changed.commitments[index][0] += F::ONE;
            assert!(check(changed, &notes, &context()).is_err());
            let mut wrong_notes = notes.clone();
            wrong_notes[index].value += 1;
            assert!(check(pair.clone(), &wrong_notes, &context()).is_err());
        }
        assert!(check(pair.clone(), &notes, &EncryptionContext::new([12; 32])).is_err());
        let mut unsupported = context();
        unsupported.version += 1;
        assert!(check(pair.clone(), &notes, &unsupported).is_err());
        assert!(
            check_output_pair_before_broadcast(
                pair,
                &notes,
                &address,
                &opening,
                &SenderChangeSecret::generate().unwrap(),
                &context(),
            )
            .is_err()
        );
    }

    #[test]
    fn dummy_outputs_use_valid_encryption_and_the_same_public_format() {
        use crate::codec::PublicTransaction;

        let recipient = RecipientViewKey::generate(digest(1)).unwrap();
        let change_secret = SenderChangeSecret::generate().unwrap();
        let rhos = [digest(7), digest(8)];
        let dummy = encrypt_dummy_outputs_to(
            &recipient.address(),
            digest(2),
            &change_secret,
            rhos,
            &context(),
        )
        .unwrap();
        let commitments = dummy
            .notes
            .each_ref()
            .map(|note| Hasher::new().note_cm(note));
        for (index, note) in dummy.notes.iter().enumerate() {
            assert_eq!(note.value, 0);
            assert_eq!(note.rho, rhos[index]);
        }
        assert_note_eq(
            &dummy.notes[0],
            &recipient
                .decrypt_payment(&commitments[0], &dummy.payment, &context())
                .unwrap(),
        );
        assert_note_eq(
            &dummy.notes[1],
            &decrypt_change(
                &change_secret,
                dummy.notes[1].owner,
                &commitments[1],
                &dummy.change,
                &context(),
            )
            .unwrap(),
        );

        let real_note = note(recipient.address().owner());
        let real = PublicTransaction {
            nf: [digest(3), digest(4)],
            cm: [Hasher::new().note_cm(&real_note); 2],
            payment: encrypt_payment(&recipient.address(), &real_note, &context()).unwrap(),
            change: encrypt_change(&change_secret, &real_note, &context()).unwrap(),
        };
        let dummy_public = PublicTransaction {
            nf: real.nf,
            cm: commitments,
            payment: dummy.payment,
            change: dummy.change,
        };
        assert_eq!(real.encode().len(), dummy_public.encode().len());
        assert_eq!(PublicTransaction::decode(&real.encode()).unwrap(), real);
        assert_eq!(
            PublicTransaction::decode(&dummy_public.encode()).unwrap(),
            dummy_public,
        );

        // Fresh throwaway keys and note seeds are used by the public helper.
        let first = encrypt_dummy_outputs(rhos, &context()).unwrap();
        let second = encrypt_dummy_outputs(rhos, &context()).unwrap();
        assert_ne!(first.notes[0].owner, second.notes[0].owner);
        assert_ne!(first.notes[1].owner, second.notes[1].owner);
        assert_ne!(first.notes[0].rseed, second.notes[0].rseed);
        assert_ne!(first.payment.kem_ciphertext, second.payment.kem_ciphertext);
        assert_ne!(first.change.nonce, second.change.nonce);
    }

    #[test]
    fn every_public_encryption_field_is_authenticated() {
        let recipient = RecipientViewKey::generate(digest(1)).unwrap();
        let original_note = note(recipient.address().owner());
        let cm = Hasher::new().note_cm(&original_note);
        let original = encrypt_payment(&recipient.address(), &original_note, &context()).unwrap();
        for position in 0..KEM_CIPHERTEXT_LEN {
            let mut changed = original.clone();
            changed.kem_ciphertext[position] ^= 1;
            assert!(
                recipient
                    .decrypt_payment(&cm, &changed, &context())
                    .is_err()
            );
        }
        for position in 0..PLAINTEXT_LEN {
            let mut changed = original.clone();
            changed.body[position] ^= 1;
            assert!(
                recipient
                    .decrypt_payment(&cm, &changed, &context())
                    .is_err()
            );
        }
        for position in 0..AEAD_TAG_LEN {
            let mut changed = original.clone();
            changed.tag[position] ^= 1;
            assert!(
                recipient
                    .decrypt_payment(&cm, &changed, &context())
                    .is_err()
            );
        }
        let mut changed = original.clone();
        changed.view_tag ^= 1;
        assert!(
            recipient
                .decrypt_payment(&cm, &changed, &context())
                .is_err()
        );

        let sender = SenderChangeSecret::new([7; 32]);
        let original = encrypt_change(&sender, &original_note, &context()).unwrap();
        for position in 0..CHANGE_NONCE_LEN {
            let mut changed = original.clone();
            changed.nonce[position] ^= 1;
            assert!(
                decrypt_change(&sender, original_note.owner, &cm, &changed, &context()).is_err()
            );
        }
        for position in 0..PLAINTEXT_LEN {
            let mut changed = original.clone();
            changed.body[position] ^= 1;
            assert!(
                decrypt_change(&sender, original_note.owner, &cm, &changed, &context()).is_err()
            );
        }
        for position in 0..AEAD_TAG_LEN {
            let mut changed = original.clone();
            changed.tag[position] ^= 1;
            assert!(
                decrypt_change(&sender, original_note.owner, &cm, &changed, &context()).is_err()
            );
        }
        let mut changed = original.clone();
        changed.view_tag ^= 1;
        assert!(decrypt_change(&sender, original_note.owner, &cm, &changed, &context()).is_err());
    }

    #[test]
    fn context_commitment_and_key_mismatch_are_rejected() {
        let recipient = RecipientViewKey::generate(digest(1)).unwrap();
        let wrong_recipient = RecipientViewKey::generate(digest(2)).unwrap();
        let original_note = note(recipient.address().owner());
        let cm = Hasher::new().note_cm(&original_note);
        let payment = encrypt_payment(&recipient.address(), &original_note, &context()).unwrap();
        assert!(
            wrong_recipient
                .decrypt_payment(&cm, &payment, &context())
                .is_err()
        );
        assert!(
            recipient
                .decrypt_payment(&cm, &payment, &EncryptionContext::new([12; 32]))
                .is_err()
        );
        let mut wrong_version = context();
        wrong_version.version += 1;
        assert!(
            recipient
                .decrypt_payment(&cm, &payment, &wrong_version)
                .is_err()
        );
        for position in 0..DIGEST {
            let mut wrong_cm = cm;
            wrong_cm[position] += F::ONE;
            assert!(
                recipient
                    .decrypt_payment(&wrong_cm, &payment, &context())
                    .is_err()
            );
        }
        assert!(encrypt_payment(&recipient.address(), &note(digest(2)), &context()).is_err());

        let sender = SenderChangeSecret::new([7; 32]);
        let change = encrypt_change(&sender, &original_note, &context()).unwrap();
        assert!(
            decrypt_change(
                &SenderChangeSecret::new([8; 32]),
                original_note.owner,
                &cm,
                &change,
                &context()
            )
            .is_err()
        );
        assert!(decrypt_change(&sender, digest(2), &cm, &change, &context()).is_err());
        assert!(
            decrypt_change(
                &sender,
                original_note.owner,
                &cm,
                &change,
                &EncryptionContext::new([12; 32])
            )
            .is_err()
        );
        assert!(
            decrypt_change(&sender, original_note.owner, &cm, &change, &wrong_version).is_err()
        );
        assert!(encrypt_change(&sender, &original_note, &wrong_version).is_err());
    }

    #[test]
    fn fresh_randomness_changes_kem_ciphertext_and_change_nonce() {
        let recipient = RecipientViewKey::generate(digest(1)).unwrap();
        let original_note = note(recipient.address().owner());
        let first = encrypt_payment(&recipient.address(), &original_note, &context()).unwrap();
        let second = encrypt_payment(&recipient.address(), &original_note, &context()).unwrap();
        assert_ne!(first.kem_ciphertext, second.kem_ciphertext);
        assert_ne!(first.body, second.body);
        let sender = SenderChangeSecret::new([7; 32]);
        let first = encrypt_change(&sender, &original_note, &context()).unwrap();
        let second = encrypt_change(&sender, &original_note, &context()).unwrap();
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.body, second.body);
    }

    #[test]
    fn note_decoder_rejects_padding_noncanonical_fields_and_wrong_commitment() {
        let original_note = note(digest(1));
        let cm = Hasher::new().note_cm(&original_note);
        let encoded = encode_note(&original_note);
        assert_note_eq(
            &original_note,
            &decode_note(original_note.owner, &cm, &encoded).unwrap(),
        );
        for position in NOTE_FIELDS_LEN..PLAINTEXT_LEN {
            let mut malformed = encoded.clone();
            malformed[position] = 1;
            assert!(decode_note(original_note.owner, &cm, &malformed).is_err());
        }
        for offset in [16, 16 + DIGEST_BYTES] {
            for position in 0..DIGEST {
                let mut malformed = encoded.clone();
                let start = offset + 4 * position;
                malformed[start..start + 4].copy_from_slice(&u32::MAX.to_le_bytes());
                assert!(decode_note(original_note.owner, &cm, &malformed).is_err());
            }
        }
        assert!(decode_note(digest(2), &cm, &encoded).is_err());
    }

    #[test]
    fn secret_types_zeroize_owned_buffers_and_redact_debug() {
        fn erased_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        erased_on_drop::<RecipientViewKey>();
        erased_on_drop::<SenderChangeSecret>();
        erased_on_drop::<PaymentEncryptionOpening>();
        let mut recipient = RecipientViewKey::generate(digest(1)).unwrap();
        assert_eq!(format!("{recipient:?}"), "RecipientViewKey(REDACTED)");
        recipient.zeroize();
        assert!(recipient.private_key.as_ref().iter().all(|byte| *byte == 0));
        let mut sender = SenderChangeSecret::new([7; 32]);
        assert_eq!(format!("{sender:?}"), "SenderChangeSecret(REDACTED)");
        sender.zeroize();
        assert!(sender.0.iter().all(|byte| *byte == 0));
        let mut opening = PaymentEncryptionOpening::from_encapsulation_coins([7; 32]);
        assert_eq!(format!("{opening:?}"), "PaymentEncryptionOpening(REDACTED)");
        opening.zeroize();
        assert!(
            opening
                .expose_encapsulation_coins()
                .iter()
                .all(|byte| *byte == 0)
        );
    }

    #[test]
    fn invalid_mlkem_public_keys_are_rejected() {
        assert!(PaymentAddress::new(digest(1), [255; ENCAPSULATION_KEY_LEN]).is_err());
    }
}
