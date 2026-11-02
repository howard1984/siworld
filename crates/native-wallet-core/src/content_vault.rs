//! Local encrypted content packages. This is not a consensus or chain format.
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Key, Tag, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

const HEADER: usize = 48;
const PADDED: usize = 4096;
pub const ENVELOPE_LEN: usize = HEADER + PADDED + 16;
const AAD: &[u8] = b"siworld local content vault v1:argon2id-v19:m65536:t3:p1:xchacha20poly1305";

/// Secret-bearing values have no formatting or serialization implementation.
pub struct Content {
    pub network: [u8; 32],
    pub account: u32,
    pub created_at: u64,
    pub kind: u8,
    pub title: Zeroizing<String>,
    pub secret: Zeroizing<String>,
}

fn validate(data: &Content) -> Result<(), String> {
    if data.network == [0; 32]
        || data.title.trim().is_empty()
        || data.title.chars().count() > 80
        || data.title.len() > 320
        || data.secret.is_empty()
        || data.secret.len() > 2048
        || data.kind > 2
        || data.created_at > 8_640_000_000_000_000
    {
        return Err("Invalid content type, title, context or secret size.".into());
    }
    if data.kind == 2 {
        let text = data.secret.strip_prefix("0x").unwrap_or(&data.secret);
        let normalized = Zeroizing::new(text.to_ascii_lowercase());
        let bytes = Zeroizing::new(crate::hex_array::<32>(&normalized)?);
        let order = crate::hex_array::<32>(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        )?;
        if *bytes == [0; 32] || *bytes >= order {
            return Err("Enter a valid 32-byte EVM private key.".into());
        }
    }
    Ok(())
}

fn aad(header: &[u8]) -> Vec<u8> {
    let mut data = AAD.to_vec();
    data.extend(header);
    data
}

pub fn seal(data: &Content, password: &str) -> Result<Vec<u8>, String> {
    validate(data)?;
    if !(12..=1024).contains(&password.len()) {
        return Err("Use an independent passphrase of 12 to 1024 UTF-8 bytes.".into());
    }
    let mut bytes = vec![0; ENVELOPE_LEN];
    bytes[..8].copy_from_slice(b"SWNCNT01");
    getrandom::fill(&mut bytes[8..HEADER]).map_err(|_| "Secure randomness is unavailable.")?;
    let key = crate::vault::derive(password, &bytes[8..24])?;
    let cipher = XChaCha20Poly1305::new(<&Key>::try_from(key.as_ref()).expect("key width"));
    let mut plain = Zeroizing::new(vec![0u8; PADDED]);
    plain[..32].copy_from_slice(&data.network);
    plain[32..36].copy_from_slice(&data.account.to_le_bytes());
    plain[36..44].copy_from_slice(&data.created_at.to_le_bytes());
    plain[44] = data.kind;
    plain[45..47].copy_from_slice(&(data.title.len() as u16).to_le_bytes());
    plain[47..49].copy_from_slice(&(data.secret.len() as u16).to_le_bytes());
    let end = 49 + data.title.len();
    plain[49..end].copy_from_slice(data.title.as_bytes());
    plain[end..end + data.secret.len()].copy_from_slice(data.secret.as_bytes());
    let tag = cipher
        .encrypt_inout_detached(
            <&XNonce>::try_from(&bytes[24..HEADER]).expect("nonce width"),
            &aad(&bytes[..HEADER]),
            plain.as_mut_slice().into(),
        )
        .map_err(|_| "Content encryption failed.")?;
    bytes[HEADER..HEADER + PADDED].copy_from_slice(&plain);
    bytes[HEADER + PADDED..].copy_from_slice(tag.as_ref());
    Ok(bytes)
}

pub fn open(
    bytes: &[u8],
    password: &str,
    network: [u8; 32],
    account: u32,
) -> Result<Content, String> {
    if bytes.len() != ENVELOPE_LEN || &bytes[..8] != b"SWNCNT01" {
        return Err("Invalid local V1 content package. Wallet seed backups are separate.".into());
    }
    let key = crate::vault::derive(password, &bytes[8..24])?;
    let cipher = XChaCha20Poly1305::new(<&Key>::try_from(key.as_ref()).expect("key width"));
    let mut plain = Zeroizing::new(bytes[HEADER..HEADER + PADDED].to_vec());
    cipher
        .decrypt_inout_detached(
            <&XNonce>::try_from(&bytes[24..HEADER]).expect("nonce width"),
            &aad(&bytes[..HEADER]),
            plain.as_mut_slice().into(),
            <&Tag>::try_from(&bytes[HEADER + PADDED..]).expect("tag width"),
        )
        .map_err(|_| "Incorrect Vault passphrase or damaged content package.")?;
    if plain[..32] != network || plain[32..36] != account.to_le_bytes() {
        return Err("Content package belongs to a different network or account.".into());
    }
    let title_len = usize::from(u16::from_le_bytes(plain[45..47].try_into().expect("width")));
    let secret_len = usize::from(u16::from_le_bytes(plain[47..49].try_into().expect("width")));
    if title_len > 320
        || secret_len > 2048
        || plain[49 + title_len + secret_len..].iter().any(|b| *b != 0)
    {
        return Err("Invalid content payload length or padding.".into());
    }
    let text = |bytes: &[u8]| {
        std::str::from_utf8(bytes)
            .map(|s| Zeroizing::new(s.to_owned()))
            .map_err(|_| "Invalid content text encoding.")
    };
    let data = Content {
        network,
        account,
        created_at: u64::from_le_bytes(plain[36..44].try_into().expect("width")),
        kind: plain[44],
        title: text(&plain[49..49 + title_len])?,
        secret: text(&plain[49 + title_len..49 + title_len + secret_len])?,
    };
    validate(&data)?;
    Ok(data)
}
