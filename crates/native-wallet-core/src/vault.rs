//! The native SWNVLT01 format, including header authentication and exact KDF.
use argon2::{Algorithm, Argon2, Block, Params, Version};
use bip39::{Language, Mnemonic};
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Key, Tag, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

pub const VAULT_LEN: usize = 132;
const HEADER: usize = 48;
const AAD: &[u8] =
    b"siworld native wallet entropy vault v1:argon2id-v19:m65536:t3:p1:xchacha20poly1305";

/// Recovery material stays in a dedicated worker. No formatting or serde traits.
pub struct Material {
    pub network: [u8; 32],
    pub account: u32,
    pub entropy: Zeroizing<[u8; 32]>,
}
impl Material {
    pub fn generate(network: [u8; 32], account: u32) -> Result<Self, String> {
        valid_network(network)?;
        let mut entropy = Zeroizing::new([0; 32]);
        getrandom::fill(entropy.as_mut())
            .map_err(|_| "Secure browser randomness is unavailable.")?;
        Ok(Self {
            network,
            account,
            entropy,
        })
    }
    pub fn restore(
        network: [u8; 32],
        account: u32,
        words: Zeroizing<String>,
    ) -> Result<Self, String> {
        valid_network(network)?;
        if words.len() > 256
            || words.split(' ').count() != 24
            || words.bytes().any(|b| !b.is_ascii_lowercase() && b != b' ')
        {
            return Err(
                "Enter exactly 24 lowercase English recovery words separated by single spaces."
                    .into(),
            );
        }
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &words)
            .map_err(|_| "Invalid recovery words or checksum.")?;
        let bytes = Zeroizing::new(mnemonic.to_entropy());
        let entropy = Zeroizing::new(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| "V1 recovery requires 256 bits of entropy.")?,
        );
        Ok(Self {
            network,
            account,
            entropy,
        })
    }
    pub fn words(&self) -> Zeroizing<String> {
        Zeroizing::new(
            Mnemonic::from_entropy_in(Language::English, self.entropy.as_ref())
                .expect("256-bit entropy")
                .to_string(),
        )
    }
    pub fn seal(&self, password: &str) -> Result<Vec<u8>, String> {
        if !(12..=1024).contains(&password.len()) {
            return Err("Use a device password of 12 to 1024 UTF-8 bytes.".into());
        }
        let mut out = vec![0u8; VAULT_LEN];
        out[..8].copy_from_slice(b"SWNVLT01");
        getrandom::fill(&mut out[8..HEADER])
            .map_err(|_| "Secure browser randomness is unavailable.")?;
        let key = derive(password, &out[8..24])?;
        let cipher = XChaCha20Poly1305::new(<&Key>::try_from(key.as_ref()).expect("key width"));
        let mut data = Zeroizing::new([0u8; 68]);
        data[..32].copy_from_slice(&self.network);
        data[32..36].copy_from_slice(&self.account.to_le_bytes());
        data[36..].copy_from_slice(self.entropy.as_ref());
        let tag = cipher
            .encrypt_inout_detached(
                <&XNonce>::try_from(&out[24..HEADER]).expect("nonce width"),
                &aad(&out[..HEADER]),
                data.as_mut_slice().into(),
            )
            .map_err(|_| "Wallet encryption failed.")?;
        out[HEADER..HEADER + 68].copy_from_slice(data.as_ref());
        out[HEADER + 68..].copy_from_slice(tag.as_ref());
        Ok(out)
    }
    pub fn open(bytes: &[u8], password: &str, expected: [u8; 32]) -> Result<Self, String> {
        valid_network(expected)?;
        if bytes.len() != VAULT_LEN || &bytes[..8] != b"SWNVLT01" {
            return Err("Invalid native V1 encrypted wallet file.".into());
        }
        let key = derive(password, &bytes[8..24])?;
        let cipher = XChaCha20Poly1305::new(<&Key>::try_from(key.as_ref()).expect("key width"));
        let mut data = Zeroizing::new([0u8; 68]);
        data.copy_from_slice(&bytes[HEADER..HEADER + 68]);
        cipher
            .decrypt_inout_detached(
                <&XNonce>::try_from(&bytes[24..HEADER]).expect("nonce width"),
                &aad(&bytes[..HEADER]),
                data.as_mut_slice().into(),
                <&Tag>::try_from(&bytes[HEADER + 68..]).expect("tag width"),
            )
            .map_err(|_| "Incorrect device password or damaged wallet file.")?;
        let network = data[..32].try_into().expect("network width");
        if network != expected {
            return Err("Encrypted wallet belongs to a different network.".into());
        }
        Ok(Self {
            network,
            account: u32::from_le_bytes(data[32..36].try_into().expect("account width")),
            entropy: Zeroizing::new(data[36..].try_into().expect("entropy width")),
        })
    }
}
pub fn challenge() -> Result<[usize; 3], String> {
    let mut out = [0; 3];
    for i in 0..3 {
        loop {
            let mut b = [0];
            getrandom::fill(&mut b).map_err(|_| "Secure browser randomness is unavailable.")?;
            if b[0] < 240 {
                let n = usize::from(b[0] % 24) + 1;
                if !out[..i].contains(&n) {
                    out[i] = n;
                    break;
                }
            }
        }
    }
    Ok(out)
}
fn valid_network(network: [u8; 32]) -> Result<(), String> {
    if network == [0; 32] {
        Err("A nonzero native network ID is required.".into())
    } else {
        Ok(())
    }
}
pub(crate) fn derive(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    if password.is_empty() || password.len() > 1024 {
        return Err("Device password must contain 1 to 1024 UTF-8 bytes.".into());
    }
    let params = Params::new(65_536, 3, 1, Some(32)).map_err(|_| "Invalid native KDF profile.")?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    let mut memory = Zeroizing::new(vec![Block::default(); 65_536]);
    argon
        .hash_password_into_with_memory(password.as_bytes(), salt, key.as_mut(), &mut memory)
        .map_err(|_| "Device password derivation failed.")?;
    Ok(key)
}
fn aad(header: &[u8]) -> Vec<u8> {
    let mut bytes = AAD.to_vec();
    bytes.extend(header);
    bytes
}
