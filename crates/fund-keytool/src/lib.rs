//! Offline custody for a single development-fund authorization key.
//! No network client, proof dependency, private-key export or signing RPC exists.
//! This version stores only an authenticated encrypted 256-bit key-generation
//! seed. Process compromise and dependency-internal copies remain outside the
//! owned-buffer erasure guarantee.
#[cfg(not(unix))]
compile_error!("siworld-fund-keytool requires Unix protected local storage");

mod crypto;
mod storage;
#[cfg(test)]
mod tests;

use serde::{Deserialize, Serialize};
use std::path::Path;

pub const PUBLIC_BYTES: usize = 1952;
pub const MAX_PUBLIC_BYTES: usize = 8192;
const VAULT_NAME: &str = "seed.vault";
const PUBLIC_NAME: &str = "public.json";
const FINGERPRINT_CONTEXT: &str =
    "SIWORLD offline development fund ML-DSA-65 public key fingerprint v1";
type Result<T> = std::result::Result<T, String>;

/// Public submission only. No secret type implements Debug or serialization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicKey {
    pub version: u16,
    pub algorithm: String,
    pub public_key_hex: String,
    pub fingerprint: String,
}
impl PublicKey {
    fn from_raw(key: &[u8; PUBLIC_BYTES]) -> Self {
        Self {
            version: 1,
            algorithm: "ML-DSA-65".into(),
            public_key_hex: hex(key),
            fingerprint: hex(&blake3::derive_key(FINGERPRINT_CONTEXT, key)),
        }
    }
    /// Exact field order, lowercase hex, compact JSON and one final LF.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec(self).map_err(|_| "cannot encode public key")?;
        bytes.push(b'\n');
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_PUBLIC_BYTES {
            return Err("public key record exceeds its limit".into());
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| "invalid public key JSON")?;
        if value.version != 1 || value.algorithm != "ML-DSA-65" {
            return Err("unsupported public key version or algorithm".into());
        }
        let key = unhex::<PUBLIC_BYTES>(&value.public_key_hex)?;
        if key.iter().all(|byte| *byte == 0)
            || value.fingerprint != Self::from_raw(&key).fingerprint
            || value.canonical_bytes()? != bytes
        {
            return Err("noncanonical or inconsistent public key record".into());
        }
        Ok(value)
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 15)] as char);
    }
    out
}
fn unhex<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 {
        return Err("invalid public hex width".into());
    }
    let mut out = [0u8; N];
    let nibble = |byte: u8| match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("public hex must use lowercase ASCII".to_owned()),
    };
    for (slot, pair) in out.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        *slot = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(out)
}

/// Generate a new OS-random key into a new, owner-only directory.
/// Never reuses a seed from a file, argument, environment or remote service.
pub fn generate(directory: &Path, passphrase: &str) -> Result<PublicKey> {
    crypto::validate_new_passphrase(passphrase)?;
    let seed = crypto::Seed::generate()?;
    create(directory, &seed, passphrase)
}

fn create(directory: &Path, seed: &crypto::Seed, passphrase: &str) -> Result<PublicKey> {
    crypto::validate_new_passphrase(passphrase)?;
    let expected = crypto::public_key(seed);
    let encoded = crypto::encrypt(seed, passphrase, &expected)?;
    // Authenticate and rederive before publishing any record.
    let check = crypto::decrypt(&encoded, passphrase)?;
    if crypto::public_key(&check) != expected {
        return Err("encrypted seed identity verification failed".into());
    }
    let owner = storage::Directory::create(directory)?;
    owner.write_once(VAULT_NAME, &encoded)?;
    owner.write_once(PUBLIC_NAME, &expected.canonical_bytes()?)?;
    let (readback, _) = load(&owner, passphrase)?;
    if readback != expected {
        return Err("persisted key identity verification failed".into());
    }
    Ok(expected)
}

fn load(owner: &storage::Directory, passphrase: &str) -> Result<(PublicKey, crypto::Seed)> {
    let encoded = owner.read(VAULT_NAME, crypto::VAULT_LEN)?;
    if encoded.len() != crypto::VAULT_LEN {
        return Err("invalid encrypted seed length".into());
    }
    let seed = crypto::decrypt(&encoded, passphrase)?;
    let public = crypto::public_key(&seed);
    let stored = PublicKey::decode(&owner.read(PUBLIC_NAME, MAX_PUBLIC_BYTES)?)?;
    if stored != public {
        return Err("public record differs from the authenticated private seed".into());
    }
    Ok((public, seed))
}

/// Authenticate the private vault before returning only its public record.
pub fn public(directory: &Path, passphrase: &str) -> Result<PublicKey> {
    let owner = storage::Directory::open(directory)?;
    let (public, _) = load(&owner, passphrase)?;
    Ok(public)
}

/// Local fresh-challenge sign/verify self-test. No signature leaves the process.
pub fn verify(directory: &Path, passphrase: &str) -> Result<PublicKey> {
    let owner = storage::Directory::open(directory)?;
    let (public, seed) = load(&owner, passphrase)?;
    crypto::self_test(&seed)?;
    Ok(public)
}

/// Freshly reencrypt the same seed to a new directory and verify persisted data.
/// No plaintext recovery material is serialized or exported.
pub fn backup(
    directory: &Path,
    passphrase: &str,
    destination: &Path,
    backup_passphrase: &str,
) -> Result<PublicKey> {
    crypto::validate_new_passphrase(backup_passphrase)?;
    let owner = storage::Directory::open(directory)?;
    let (expected, seed) = load(&owner, passphrase)?;
    crypto::self_test(&seed)?;
    let actual = create(destination, &seed, backup_passphrase)?;
    if actual != expected {
        return Err("backup does not match source public key".into());
    }
    Ok(actual)
}

/// Bounded syntactic and fingerprint validation. This does not prove possession.
pub fn check_public(path: &Path) -> Result<PublicKey> {
    PublicKey::decode(&storage::read_public(path, MAX_PUBLIC_BYTES)?)
}
