use super::{PUBLIC_BYTES, PublicKey, Result, unhex};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Key, Tag, XChaCha20Poly1305, XNonce};
use libcrux_ml_dsa::ml_dsa_65::{self, MLDSA65SigningKey, MLDSA65VerificationKey};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"SWFKEY01";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 82;
pub const VAULT_LEN: usize = HEADER_LEN + 32 + 16;
const MEMORY_KIB: u32 = 65_536;
const AAD: &[u8] =
    b"SIWORLD offline development fund seed v1:argon2id-v19:m65536:t3:p1:xchacha20poly1305";
const SELF_TEST_CONTEXT: &[u8] = b"SIWORLD fund key custody self-test v1";

/// Deliberately has no Debug, Clone, Display or serialization implementation.
pub(crate) struct Seed(Zeroizing<[u8; 32]>);
impl Seed {
    pub fn generate() -> Result<Self> {
        let mut seed = Self(Zeroizing::new([0u8; 32]));
        getrandom::fill(seed.0.as_mut()).map_err(|_| "OS randomness unavailable")?;
        Ok(seed)
    }
}
struct SigningKey(MLDSA65SigningKey);
impl Drop for SigningKey {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();
    }
}

pub fn public_key(seed: &Seed) -> PublicKey {
    let pair = ml_dsa_65::generate_key_pair(*seed.0);
    let _secret = SigningKey(pair.signing_key);
    PublicKey::from_raw(pair.verification_key.as_ref())
}

pub fn validate_new_passphrase(passphrase: &str) -> Result<()> {
    if !(16..=1024).contains(&passphrase.len()) {
        return Err("new passphrase requires 16 to 1024 UTF-8 bytes".into());
    }
    Ok(())
}

fn derive(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if passphrase.is_empty() || passphrase.len() > 1024 {
        return Err("passphrase requires 1 to 1024 UTF-8 bytes".into());
    }
    let params = Params::new(MEMORY_KIB, 3, 1, Some(32)).map_err(|_| "invalid KDF profile")?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    let mut memory = Zeroizing::new(vec![Block::default(); MEMORY_KIB as usize]);
    argon
        .hash_password_into_with_memory(passphrase.as_bytes(), salt, key.as_mut(), &mut memory)
        .map_err(|_| "key derivation failed")?;
    Ok(key)
}

fn aad(header: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(AAD.len() + header.len());
    bytes.extend_from_slice(AAD);
    bytes.extend_from_slice(header);
    bytes
}

pub fn encrypt(seed: &Seed, passphrase: &str, public: &PublicKey) -> Result<[u8; VAULT_LEN]> {
    let mut encoded = [0u8; VAULT_LEN];
    encoded[..8].copy_from_slice(MAGIC);
    encoded[8..10].copy_from_slice(&VERSION.to_le_bytes());
    getrandom::fill(&mut encoded[10..50]).map_err(|_| "OS randomness unavailable")?;
    encoded[50..HEADER_LEN].copy_from_slice(&unhex::<32>(&public.fingerprint)?);
    let key = derive(passphrase, &encoded[10..26])?;
    let cipher = XChaCha20Poly1305::new(<&Key>::try_from(key.as_ref()).expect("fixed key"));
    let mut plaintext = Zeroizing::new(*seed.0);
    let tag = cipher
        .encrypt_inout_detached(
            <&XNonce>::try_from(&encoded[26..50]).expect("fixed nonce"),
            &aad(&encoded[..HEADER_LEN]),
            plaintext.as_mut_slice().into(),
        )
        .map_err(|_| "seed encryption failed")?;
    encoded[HEADER_LEN..HEADER_LEN + 32].copy_from_slice(plaintext.as_ref());
    encoded[HEADER_LEN + 32..].copy_from_slice(tag.as_ref());
    Ok(encoded)
}

pub fn decrypt(encoded: &[u8], passphrase: &str) -> Result<Seed> {
    if encoded.len() != VAULT_LEN
        || &encoded[..8] != MAGIC
        || encoded[8..10] != VERSION.to_le_bytes()
    {
        return Err("unsupported or malformed encrypted fund key".into());
    }
    let key = derive(passphrase, &encoded[10..26])?;
    let cipher = XChaCha20Poly1305::new(<&Key>::try_from(key.as_ref()).expect("fixed key"));
    let mut seed = Seed(Zeroizing::new([0u8; 32]));
    seed.0
        .copy_from_slice(&encoded[HEADER_LEN..HEADER_LEN + 32]);
    cipher
        .decrypt_inout_detached(
            <&XNonce>::try_from(&encoded[26..50]).expect("fixed nonce"),
            &aad(&encoded[..HEADER_LEN]),
            seed.0.as_mut_slice().into(),
            <&Tag>::try_from(&encoded[HEADER_LEN + 32..]).expect("fixed tag"),
        )
        .map_err(|_| "incorrect passphrase or damaged encrypted fund key")?;
    let public = public_key(&seed);
    if encoded[50..HEADER_LEN] != unhex::<32>(&public.fingerprint)? {
        return Err("encrypted fund key identity mismatch".into());
    }
    Ok(seed)
}

pub fn self_test(seed: &Seed) -> Result<()> {
    let pair = ml_dsa_65::generate_key_pair(*seed.0);
    let secret = SigningKey(pair.signing_key);
    let mut challenge = Zeroizing::new([0u8; 32]);
    let mut randomness = Zeroizing::new([0u8; 32]);
    getrandom::fill(challenge.as_mut()).map_err(|_| "OS randomness unavailable")?;
    getrandom::fill(randomness.as_mut()).map_err(|_| "OS randomness unavailable")?;
    let signature = ml_dsa_65::sign(
        &secret.0,
        challenge.as_ref(),
        SELF_TEST_CONTEXT,
        *randomness,
    )
    .map_err(|_| "local ML-DSA-65 signature failed")?;
    let verifying_key: &[u8; PUBLIC_BYTES] = pair.verification_key.as_ref();
    ml_dsa_65::verify(
        &MLDSA65VerificationKey::new(*verifying_key),
        challenge.as_ref(),
        SELF_TEST_CONTEXT,
        &signature,
    )
    .map_err(|_| "local ML-DSA-65 self-verification failed".into())
}
