//! Independent client-side encrypted snapshots. This format has no chain identity.
use chacha20poly1305::{
    Key, Tag, XChaCha20Poly1305, XNonce,
    aead::{AeadInOut, KeyInit},
};
use ed25519_dalek::{Signature, Signer, SigningKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const SNAPSHOT_BYTES: usize = 512 * 1024;
const HEADER: usize = 48;
const RECOVERY_BYTES: usize = 256;
const DOMAIN: &[u8] =
    b"siworld independent vault sync v1:argon2id-v19:m65536:t3:p1:xchacha20poly1305";

pub struct Account {
    locator: [u8; 32],
    secret: Zeroizing<[u8; 32]>,
    pub revision: u64,
    pub digest: [u8; 32],
}
pub fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn crypt_aad(header: &[u8], extra: &[u8]) -> Vec<u8> {
    [DOMAIN, header, extra].concat()
}
fn seal(
    magic: &[u8; 8],
    size: usize,
    plain: &[u8],
    pass: &str,
    extra: &[u8],
) -> Result<Vec<u8>, String> {
    if !(12..=1024).contains(&pass.len()) || plain.len() > size - HEADER - 20 {
        return Err("Invalid Vault passphrase or payload size.".into());
    }
    let mut out = vec![0; size];
    out[..8].copy_from_slice(magic);
    getrandom::fill(&mut out[8..HEADER]).map_err(|_| "Secure randomness unavailable.")?;
    let key = crate::vault::derive(pass, &out[8..24])?;
    let cipher = XChaCha20Poly1305::new(<&Key>::try_from(key.as_ref()).unwrap());
    let mut padded = Zeroizing::new(vec![0; size - HEADER - 16]);
    padded[..4].copy_from_slice(&(plain.len() as u32).to_le_bytes());
    padded[4..4 + plain.len()].copy_from_slice(plain);
    let tag = cipher
        .encrypt_inout_detached(
            <&XNonce>::try_from(&out[24..HEADER]).unwrap(),
            &crypt_aad(&out[..HEADER], extra),
            padded.as_mut_slice().into(),
        )
        .map_err(|_| "Vault encryption failed.")?;
    out[HEADER..size - 16].copy_from_slice(&padded);
    out[size - 16..].copy_from_slice(&tag);
    Ok(out)
}
fn open(
    magic: &[u8; 8],
    size: usize,
    bytes: &[u8],
    pass: &str,
    extra: &[u8],
) -> Result<Zeroizing<Vec<u8>>, String> {
    if bytes.len() != size || &bytes[..8] != magic || !(12..=1024).contains(&pass.len()) {
        return Err("Invalid encrypted Vault envelope.".into());
    }
    let key = crate::vault::derive(pass, &bytes[8..24])?;
    let cipher = XChaCha20Poly1305::new(<&Key>::try_from(key.as_ref()).unwrap());
    let mut plain = Zeroizing::new(bytes[HEADER..size - 16].to_vec());
    cipher
        .decrypt_inout_detached(
            <&XNonce>::try_from(&bytes[24..HEADER]).unwrap(),
            &crypt_aad(&bytes[..HEADER], extra),
            plain.as_mut_slice().into(),
            <&Tag>::try_from(&bytes[size - 16..]).unwrap(),
        )
        .map_err(|_| "Incorrect Vault passphrase or damaged snapshot.")?;
    let len = u32::from_le_bytes(plain[..4].try_into().unwrap()) as usize;
    if len > plain.len() - 4 || plain[4 + len..].iter().any(|b| *b != 0) {
        return Err("Invalid Vault payload or padding.".into());
    }
    Ok(Zeroizing::new(plain[4..4 + len].to_vec()))
}
fn extra(locator: &[u8; 32], revision: u64, previous: &[u8; 32]) -> Vec<u8> {
    [
        locator.as_slice(),
        &revision.to_le_bytes(),
        previous.as_slice(),
    ]
    .concat()
}
impl Account {
    pub fn create() -> Result<Self, String> {
        let mut locator = [0; 32];
        let mut secret = Zeroizing::new([0; 32]);
        getrandom::fill(&mut locator).map_err(|_| "Secure randomness unavailable.")?;
        getrandom::fill(secret.as_mut()).map_err(|_| "Secure randomness unavailable.")?;
        Ok(Self {
            locator,
            secret,
            revision: 0,
            digest: [0; 32],
        })
    }
    pub fn locator(&self) -> [u8; 32] {
        self.locator
    }
    pub fn public_key(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.secret)
            .verifying_key()
            .to_bytes()
    }
    pub fn recovery(&self, pass: &str) -> Result<Vec<u8>, String> {
        let mut data = Zeroizing::new(Vec::with_capacity(104));
        data.extend(self.locator);
        data.extend(self.secret.iter());
        data.extend(self.revision.to_le_bytes());
        data.extend(self.digest);
        seal(b"SWVREC01", RECOVERY_BYTES, &data, pass, b"recovery")
    }
    pub fn restore(bytes: &[u8], pass: &str) -> Result<Self, String> {
        let data = open(b"SWVREC01", RECOVERY_BYTES, bytes, pass, b"recovery")?;
        if data.len() != 104 {
            return Err("Invalid independent Vault recovery data.".into());
        }
        Ok(Self {
            locator: data[..32].try_into().unwrap(),
            secret: Zeroizing::new(data[32..64].try_into().unwrap()),
            revision: u64::from_le_bytes(data[64..72].try_into().unwrap()),
            digest: data[72..].try_into().unwrap(),
        })
    }
    /// The binary snapshot wraps all per-item context, including network/account.
    pub fn snapshot(&self, packages: &[Vec<u8>], pass: &str) -> Result<Vec<u8>, String> {
        if packages.len() > 100
            || packages.iter().any(|p| {
                p.len() != crate::content_vault::ENVELOPE_LEN + 36 || &p[36..44] != b"SWNCNT01"
            })
        {
            return Err("Invalid binary Vault collection.".into());
        }
        let mut data = Zeroizing::new(Vec::new());
        data.extend((packages.len() as u16).to_le_bytes());
        for p in packages {
            data.extend(p);
        }
        let revision = self
            .revision
            .checked_add(1)
            .ok_or("Vault revision overflow.")?;
        seal(
            b"SWVSNP01",
            SNAPSHOT_BYTES,
            &data,
            pass,
            &extra(&self.locator, revision, &self.digest),
        )
    }
    pub fn read_snapshot(
        &self,
        bytes: &[u8],
        pass: &str,
        revision: u64,
        previous: [u8; 32],
    ) -> Result<Vec<Vec<u8>>, String> {
        if revision < self.revision
            || (revision == self.revision && digest(bytes) != self.digest)
            || revision == 0
        {
            return Err("Vault rollback or substituted revision rejected.".into());
        }
        let data = open(
            b"SWVSNP01",
            SNAPSHOT_BYTES,
            bytes,
            pass,
            &extra(&self.locator, revision, &previous),
        )?;
        if data.len() < 2 {
            return Err("Invalid Vault collection.".into());
        }
        let count = u16::from_le_bytes(data[..2].try_into().unwrap()) as usize;
        let width = crate::content_vault::ENVELOPE_LEN + 36;
        if count > 100
            || data.len() != 2 + count * width
            || data[2..]
                .chunks_exact(width)
                .any(|p| &p[36..44] != b"SWNCNT01")
        {
            return Err("Invalid Vault collection shape.".into());
        }
        Ok(data[2..].chunks_exact(width).map(|p| p.to_vec()).collect())
    }
    pub fn accept(&mut self, revision: u64, digest: [u8; 32]) -> Result<(), String> {
        if revision < self.revision || (revision == self.revision && digest != self.digest) {
            return Err("Vault rollback rejected.".into());
        }
        self.revision = revision;
        self.digest = digest;
        Ok(())
    }
    pub fn sign_request(
        &self,
        origin: &str,
        method: &str,
        challenge: &str,
        revision: u64,
        body: &[u8],
        previous: &str,
    ) -> Result<[u8; 64], String> {
        if origin.len() > 200
            || origin.contains(['\n', '\r'])
            || !(origin.starts_with("https://") || origin.starts_with("http://localhost:"))
            || !["GET", "PUT", "POST"].contains(&method)
            || challenge.len() != 64
            || previous.len() != 64
        {
            return Err("Invalid Vault authentication context.".into());
        }
        let _: [u8; 32] = crate::hex_array(challenge)?;
        let _: [u8; 32] = crate::hex_array(previous)?;
        let text = format!(
            "SWVAUTH1\n{origin}\n{method}\n{}\n{challenge}\n{revision}\n{}\n{previous}\n",
            crate::hex(&self.locator),
            crate::hex(&digest(body))
        );
        Ok(SigningKey::from_bytes(&self.secret)
            .sign(text.as_bytes())
            .to_bytes())
    }
    pub fn sign_revision(&self, revision: u64, digest: &[u8; 32], previous: &[u8; 32]) -> [u8; 64] {
        let text = revision_message(&self.locator, revision, digest, previous);
        SigningKey::from_bytes(&self.secret).sign(&text).to_bytes()
    }
    pub fn verify_revision(
        &self,
        revision: u64,
        digest: &[u8; 32],
        previous: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<(), String> {
        SigningKey::from_bytes(&self.secret)
            .verifying_key()
            .verify_strict(
                &revision_message(&self.locator, revision, digest, previous),
                &Signature::from_bytes(signature),
            )
            .map_err(|_| "Vault revision signature failed.".into())
    }
}
fn revision_message(
    locator: &[u8; 32],
    revision: u64,
    digest: &[u8; 32],
    previous: &[u8; 32],
) -> Vec<u8> {
    format!(
        "SWVREV1\n{}\n{revision}\n{}\n{}\n",
        crate::hex(locator),
        crate::hex(digest),
        crate::hex(previous)
    )
    .into_bytes()
}
