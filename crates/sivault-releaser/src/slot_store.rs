//! Persistent material for a single, already authenticated enrollment.
//! A fresh private directory is required for provisioning. An incomplete
//! enrollment is unusable; it must never be retried as a fresh allowance
//! for the same slot.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use libcrux_ml_dsa::ml_dsa_65::MLDSA65VerificationKey;
use sha2::{Digest, Sha256};
use sivault_core::{
    controlled_channel::ReleaserIdentity,
    controlled_credential::ReleaserVerifier,
    crypto::{self, Secret},
};
use zeroize::Zeroizing;

use crate::{
    journal::{Journal, MarkerStore},
    ledger::{AuthorityError, Releaser, SlotIdentity},
    message::Id,
    opening::{OpeningRecord, ReleaseMaterial},
};

type Result<T> = std::result::Result<T, AuthorityError>;
const MAGIC: &[u8; 8] = b"SVRLS001";
const FILE: &str = "material-v1";
const JOURNAL: &str = "journal";
const MAX_SIZE: usize = 8192;
const KEYS_LEN: usize = 2 + 64 + 32 + 2 * MLDSA65VerificationKey::len() + 96;

pub struct SlotMaterial {
    pub port: u16,
    pub release: ReleaseMaterial,
    pub owner_key: MLDSA65VerificationKey,
    pub identity_kem_seed: Zeroizing<[u8; 64]>,
    pub identity_signing_seed: Secret,
}

impl SlotMaterial {
    pub fn identity(&self) -> ReleaserIdentity {
        ReleaserIdentity::from_seeds(&self.identity_kem_seed, &self.identity_signing_seed)
    }
}

/// Provision only after the owner signature and local acceptance have been
/// verified. The password protects releaser storage, not a controlled safe.
pub fn provision<M: MarkerStore>(
    path: &Path,
    marker: M,
    material: &SlotMaterial,
    allowance: u64,
    password: &str,
) -> Result<Releaser<Journal<M>>> {
    provision_with_head(path, marker, material, allowance, password).map(|(releaser, _)| releaser)
}

pub fn provision_with_head<M: MarkerStore>(
    path: &Path,
    marker: M,
    material: &SlotMaterial,
    allowance: u64,
    password: &str,
) -> Result<(Releaser<Journal<M>>, Id)> {
    if allowance == 0 || material.port == 0 {
        return Err(AuthorityError::InvalidEvidence);
    }
    let bytes = seal(material, password)?;
    let mut directory = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        directory.mode(0o700);
    }
    directory
        .create(path)
        .map_err(|_| AuthorityError::Unavailable)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path.join(FILE))
        .map_err(|_| AuthorityError::Unavailable)?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| AuthorityError::Unavailable)?;
    #[cfg(unix)]
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| AuthorityError::Unavailable)?;
    let scope = &material.release.scope;
    let instance = Id(crypto::random().map_err(|_| AuthorityError::Unavailable)?);
    let journal = Journal::provision_material(
        &path.join(JOURNAL),
        marker,
        scope.slot,
        instance,
        allowance,
        scope.record,
        digest(&bytes),
    )?;
    #[cfg(unix)]
    {
        File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(|_| AuthorityError::Unavailable)?;
        let parent = path.parent().ok_or(AuthorityError::Unavailable)?;
        File::open(parent)
            .and_then(|file| file.sync_all())
            .map_err(|_| AuthorityError::Unavailable)?;
    }
    let head = journal.protected_head();
    Ok((recover(journal, scope.slot)?, head))
}

pub fn open<M: MarkerStore>(
    path: &Path,
    marker: M,
    password: &str,
) -> Result<(SlotMaterial, Releaser<Journal<M>>)> {
    let mut bytes = Vec::new();
    File::open(path.join(FILE))
        .and_then(|file| file.take(MAX_SIZE as u64 + 1).read_to_end(&mut bytes))
        .map_err(|_| AuthorityError::Unavailable)?;
    let material = unseal(&bytes, password)?;
    let slot = material.release.scope.slot;
    let journal = Journal::open(&path.join(JOURNAL), marker, slot)?;
    journal.require_material(digest(&bytes))?;
    let releaser = recover(journal, slot)?;
    Ok((material, releaser))
}

pub(crate) fn remove_revoked_material(path: &Path) -> Result<()> {
    match fs::remove_file(path.join(FILE)) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(_) => return Err(AuthorityError::Unavailable),
    }
    #[cfg(unix)]
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| AuthorityError::Unavailable)?;
    Ok(())
}

fn recover<M: MarkerStore>(
    journal: Journal<M>,
    slot: SlotIdentity,
) -> Result<Releaser<Journal<M>>> {
    let mut releaser = Releaser::new(journal);
    releaser
        .recover(slot)
        .map_err(|_| AuthorityError::InvalidEvidence)?;
    Ok(releaser)
}

fn seal(material: &SlotMaterial, password: &str) -> Result<Vec<u8>> {
    let mut plain = Zeroizing::new(Vec::with_capacity(MAX_SIZE));
    plain.extend_from_slice(&material.port.to_be_bytes());
    plain.extend_from_slice(material.identity_kem_seed.as_ref());
    plain.extend_from_slice(material.identity_signing_seed.as_ref());
    plain.extend_from_slice(material.owner_key.as_slice());
    let release = &material.release;
    plain.extend_from_slice(release.folder_key.as_slice());
    plain.extend_from_slice(&release.verifier.stored_key);
    plain.extend_from_slice(release.verifier.server_key.as_ref());
    plain.extend_from_slice(release.share.as_ref());
    serde_json::to_writer(&mut *plain, &release.scope)
        .map_err(|_| AuthorityError::InvalidEvidence)?;
    let salt = crypto::random::<16>().map_err(|_| AuthorityError::Unavailable)?;
    let nonce = crypto::random::<24>().map_err(|_| AuthorityError::Unavailable)?;
    let key = crypto::stretch(password, &salt).map_err(|_| AuthorityError::InvalidEvidence)?;
    let mut bytes = Vec::from(*MAGIC);
    bytes.extend_from_slice(&salt);
    bytes.extend_from_slice(&nonce);
    let ciphertext =
        crypto::seal(&key, &nonce, &bytes, &plain).map_err(|_| AuthorityError::InvalidEvidence)?;
    bytes.extend_from_slice(&ciphertext);
    if bytes.len() > MAX_SIZE {
        return Err(AuthorityError::InvalidEvidence);
    }
    Ok(bytes)
}

fn unseal(bytes: &[u8], password: &str) -> Result<SlotMaterial> {
    const HEADER: usize = MAGIC.len() + 16 + 24;
    if bytes.len() <= HEADER || bytes.len() > MAX_SIZE || !bytes.starts_with(MAGIC) {
        return Err(AuthorityError::InvalidEvidence);
    }
    let salt = bytes[8..24]
        .try_into()
        .map_err(|_| AuthorityError::InvalidEvidence)?;
    let nonce = bytes[24..HEADER]
        .try_into()
        .map_err(|_| AuthorityError::InvalidEvidence)?;
    let key = crypto::stretch(password, &salt).map_err(|_| AuthorityError::InvalidEvidence)?;
    let plain = crypto::unseal(&key, &nonce, &bytes[..HEADER], &bytes[HEADER..])
        .map_err(|_| AuthorityError::InvalidEvidence)?;
    if plain.len() <= KEYS_LEN {
        return Err(AuthorityError::InvalidEvidence);
    }
    let mut cursor = plain.as_slice();
    let mut port = [0; 2];
    cursor
        .read_exact(&mut port)
        .map_err(|_| AuthorityError::InvalidEvidence)?;
    let port = u16::from_be_bytes(port);
    if port == 0 {
        return Err(AuthorityError::InvalidEvidence);
    }
    let mut identity_kem_seed = Zeroizing::new([0; 64]);
    cursor
        .read_exact(&mut *identity_kem_seed)
        .map_err(|_| AuthorityError::InvalidEvidence)?;
    let identity_signing_seed = secret(&mut cursor)?;
    let owner_key = verification_key(&mut cursor)?;
    let folder_key = verification_key(&mut cursor)?;
    let mut stored_key = [0; 32];
    cursor
        .read_exact(&mut stored_key)
        .map_err(|_| AuthorityError::InvalidEvidence)?;
    let server_key = secret(&mut cursor)?;
    let share = secret(&mut cursor)?;
    let scope: OpeningRecord =
        serde_json::from_slice(cursor).map_err(|_| AuthorityError::InvalidEvidence)?;
    Ok(SlotMaterial {
        port,
        release: ReleaseMaterial {
            scope,
            folder_key,
            verifier: ReleaserVerifier {
                stored_key,
                server_key,
            },
            share,
        },
        owner_key,
        identity_kem_seed,
        identity_signing_seed,
    })
}

fn secret(reader: &mut &[u8]) -> Result<Secret> {
    let mut value = Secret::new([0; 32]);
    reader
        .read_exact(&mut *value)
        .map_err(|_| AuthorityError::InvalidEvidence)?;
    Ok(value)
}

fn verification_key(reader: &mut &[u8]) -> Result<MLDSA65VerificationKey> {
    let mut bytes = [0; MLDSA65VerificationKey::len()];
    reader
        .read_exact(&mut bytes)
        .map_err(|_| AuthorityError::InvalidEvidence)?;
    Ok(MLDSA65VerificationKey::new(bytes))
}

fn digest(bytes: &[u8]) -> Id {
    Id(Sha256::digest(bytes).into())
}
