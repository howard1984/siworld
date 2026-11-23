//! Offline-format primitives. STREAM nonce sequencing is supplied by RustCrypto.

use crate::{Error, Result};
use aead::{
    KeyInit, Payload,
    stream::{NewStream, StreamBE32, StreamPrimitive},
};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{XChaCha20Poly1305, XNonce, aead::Aead};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use precis_profiles::{OpaqueString, precis_core::profile::PrecisFastInvocation};
use sha2::Sha256;
use zeroize::Zeroizing;

pub const CHUNK_SIZE: usize = 65_536;
pub const PIECE_SIZE: u64 = 1 << 30;
pub type Secret = Zeroizing<[u8; 32]>;

pub fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::getrandom(&mut bytes).map_err(|_| Error::Random)?;
    Ok(bytes)
}

pub fn password_bytes(password: &str) -> Result<Zeroizing<String>> {
    if password.len() > 4096 {
        return Err(Error::InvalidPassword);
    }
    let normalized = OpaqueString::enforce(password).map_err(|_| Error::InvalidPassword)?;
    if normalized.is_empty() || normalized.len() > 1024 {
        return Err(Error::InvalidPassword);
    }
    Ok(Zeroizing::new(normalized.into_owned()))
}

pub fn stretch(password: &str, salt: &[u8; 16]) -> Result<Secret> {
    let password = password_bytes(password)?;
    let parameters = Params::new(65_536, 3, 1, Some(32)).map_err(|_| Error::InvalidFormat)?;
    let mut key = Zeroizing::new([0; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters)
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|_| Error::Authentication)?;
    Ok(key)
}

pub fn derive(key: &[u8; 32], safe: &[u8; 16], label: &[u8]) -> Secret {
    let mut result = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(safe), key)
        .expand(label, result.as_mut())
        .expect("32-byte HKDF output");
    result
}

pub fn seal(key: &[u8; 32], nonce: &[u8; 24], ad: &[u8], bytes: &[u8]) -> Result<Vec<u8>> {
    XChaCha20Poly1305::new(key.into())
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: bytes,
                aad: ad,
            },
        )
        .map_err(|_| Error::Authentication)
}

pub fn unseal(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ad: &[u8],
    bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    XChaCha20Poly1305::new(key.into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: bytes,
                aad: ad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Authentication)
}

pub fn mac(key: &[u8; 32], bytes: &[u8]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC key size");
    m.update(bytes);
    m.finalize().into_bytes().into()
}

pub fn verify_mac(key: &[u8; 32], bytes: &[u8], tag: &[u8]) -> Result<()> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC key size");
    m.update(bytes);
    m.verify_slice(tag).map_err(|_| Error::Authentication)
}

pub fn encrypt_chunk(
    key: &[u8; 32],
    prefix: &[u8; 19],
    index: u32,
    last: bool,
    ad: &[u8],
    plain: &[u8],
) -> Result<Vec<u8>> {
    if plain.len() > CHUNK_SIZE {
        return Err(Error::Limit);
    }
    StreamBE32::<XChaCha20Poly1305>::new(key.into(), prefix.into())
        .encrypt(
            index,
            last,
            Payload {
                msg: plain,
                aad: ad,
            },
        )
        .map_err(|_| Error::Authentication)
}

pub fn decrypt_chunk(
    key: &[u8; 32],
    prefix: &[u8; 19],
    index: u32,
    last: bool,
    ad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if ciphertext.len() < 16 || ciphertext.len() > CHUNK_SIZE + 16 {
        return Err(Error::InvalidFormat);
    }
    StreamBE32::<XChaCha20Poly1305>::new(key.into(), prefix.into())
        .decrypt(
            index,
            last,
            Payload {
                msg: ciphertext,
                aad: ad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Authentication)
}
