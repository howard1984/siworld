//! Recoverable wallet view keys for the frozen native payment ciphertext format.
//!
//! The proof suite's source files remain immutable. This wallet-only decoder
//! uses the existing native version, domains, AAD, canonical note layout and
//! commitment reconstruction. It does not introduce a new encryption format.
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use libcrux_ml_kem::mlkem768::{self, MlKem768Ciphertext, MlKem768PrivateKey};
use native::codec::{decode_digest, encode_digest};
use native::encryption::{
    EncryptionContext, EncryptionError, FORMAT_VERSION, NOTE_FIELDS_LEN, PLAINTEXT_LEN,
    PaymentAddress, PaymentCiphertext,
};
use native::multi_asset::{AssetId, Digest, Hasher, Note};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const PAYMENT_KEY_DOMAIN: &str = "siworld multi-asset payment-key-v1";
const PAYMENT_VIEW_DOMAIN: &str = "siworld multi-asset payment-view-v1";
const AAD_DOMAIN: &[u8] = b"siworld multi-asset output aad v1\0";

pub(crate) struct RecoverableViewKey {
    address: PaymentAddress,
    private_key: MlKem768PrivateKey,
}
impl RecoverableViewKey {
    /// Consume and erase caller-derived independent ML-KEM key entropy.
    /// Callers erase source copies. Dependency/register copies are not covered.
    pub(crate) fn from_seed(
        owner: Digest,
        seed: Zeroizing<[u8; libcrux_ml_kem::KEY_GENERATION_SEED_SIZE]>,
    ) -> Result<Self, EncryptionError> {
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
    pub(crate) fn address(&self) -> PaymentAddress {
        self.address.clone()
    }
    pub(crate) fn decrypt_payment(
        &self,
        commitment: &Digest,
        ciphertext: &PaymentCiphertext,
        context: &EncryptionContext,
    ) -> Result<Note, EncryptionError> {
        if context.version != FORMAT_VERSION {
            return Err(EncryptionError::UnsupportedVersion);
        }
        let kem = MlKem768Ciphertext::from(&ciphertext.kem_ciphertext);
        let shared = Zeroizing::new(mlkem768::decapsulate(&self.private_key, &kem));
        if derive_secret(PAYMENT_VIEW_DOMAIN, shared.as_ref())[0] != ciphertext.view_tag {
            return Err(EncryptionError::Authentication);
        }
        let key = derive_secret(PAYMENT_KEY_DOMAIN, shared.as_ref());
        let aead = ChaCha20Poly1305::new(
            <&Key>::try_from(key.as_slice()).expect("fixed wallet key width"),
        );
        let tag = <&Tag>::try_from(ciphertext.tag.as_slice()).expect("fixed wallet tag width");
        let mut plaintext = Zeroizing::new(ciphertext.body);
        aead.decrypt_inout_detached(
            <&Nonce>::try_from([0u8; 12].as_slice()).expect("fixed payment nonce width"),
            &aad(context, commitment),
            plaintext.as_mut_slice().into(),
            tag,
        )
        .map_err(|_| EncryptionError::Authentication)?;
        decode_note(self.address.owner(), commitment, &plaintext)
    }
}
impl Zeroize for RecoverableViewKey {
    fn zeroize(&mut self) {
        self.private_key[0..MlKem768PrivateKey::len()].zeroize();
    }
}
impl Drop for RecoverableViewKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for RecoverableViewKey {}

fn derive_secret(domain: &str, material: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hash = Zeroizing::new(blake3::Hasher::new_derive_key(domain));
    hash.update(material);
    let digest = Zeroizing::new(hash.finalize());
    Zeroizing::new(*digest.as_bytes())
}
fn aad(context: &EncryptionContext, commitment: &Digest) -> Vec<u8> {
    let mut data = Vec::with_capacity(AAD_DOMAIN.len() + 2 + 32 + 1 + 48);
    data.extend_from_slice(AAD_DOMAIN);
    data.extend_from_slice(&context.version.to_le_bytes());
    data.extend_from_slice(&context.network);
    data.push(0); // The frozen payment output index; change uses indices 1 and 2.
    data.extend_from_slice(&encode_digest(commitment));
    data
}
fn decode_note(
    owner: Digest,
    commitment: &Digest,
    bytes: &[u8; PLAINTEXT_LEN],
) -> Result<Note, EncryptionError> {
    if bytes[NOTE_FIELDS_LEN..].iter().any(|byte| *byte != 0) {
        return Err(EncryptionError::InvalidPlaintext);
    }
    let digest = |bytes: &[u8]| {
        decode_digest(bytes.try_into().expect("fixed wallet digest width"))
            .map_err(|_| EncryptionError::InvalidPlaintext)
    };
    let note = Note {
        owner,
        value: u64::from_le_bytes(bytes[..8].try_into().expect("fixed wallet amount width")),
        unlock_height: u64::from_le_bytes(
            bytes[8..16].try_into().expect("fixed wallet height width"),
        ),
        rho: digest(&bytes[16..64])?,
        rseed: digest(&bytes[64..112])?,
        asset_id: AssetId(
            bytes[112..144]
                .try_into()
                .expect("fixed wallet asset width"),
        ),
    };
    if Hasher::new().note_cm(&note) != *commitment {
        return Err(EncryptionError::CommitmentMismatch);
    }
    Ok(note)
}

#[cfg(all(test, siworld_native_node))]
mod tests;
