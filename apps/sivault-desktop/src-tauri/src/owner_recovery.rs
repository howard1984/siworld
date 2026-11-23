use super::{OwnerState, prompt_material, unavailable};
use crate::{
    adapter::{BridgeError, Result},
    locale, password,
};
use sivault_core::{
    crypto::{self, Secret},
    owner::{OwnerIdentity, RecoveryPositions},
};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};
use tauri::{AppHandle, Manager};
use zeroize::Zeroizing;

// This is private desktop profile data, not a folder or wire record.
const PROFILE_FILE: &str = "owner-recovery-v1.profile";
const PROFILE_SALT: &[u8; 16] = b"sivault/recov/v1";
const PROFILE_LABEL: &[u8] = b"sivault/desktop-owner-recovery-profile/v1";
const PROFILE_BYTES: usize = 24 + 3 + 16;

fn profile(directory: &Path, entropy: &Secret, identifier: &[u8; 32]) -> Result<RecoveryPositions> {
    let path = directory.join(PROFILE_FILE);
    let key = crypto::derive(entropy, PROFILE_SALT, PROFILE_LABEL);
    let mut ad = PROFILE_LABEL.to_vec();
    ad.extend(identifier);
    match File::open(&path) {
        Ok(file) => {
            let mut record = Vec::with_capacity(PROFILE_BYTES);
            file.take(PROFILE_BYTES as u64 + 1)
                .read_to_end(&mut record)
                .map_err(|_| unavailable())?;
            if record.len() != PROFILE_BYTES {
                return Err(unavailable());
            }
            let nonce = record[..24].try_into().map_err(|_| unavailable())?;
            let plain =
                crypto::unseal(&key, nonce, &ad, &record[24..]).map_err(|_| unavailable())?;
            let positions = plain.as_slice().try_into().map_err(|_| unavailable())?;
            RecoveryPositions::from_positions(positions).map_err(|_| unavailable())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let positions = RecoveryPositions::generate().map_err(|_| unavailable())?;
            let nonce = crypto::random::<24>().map_err(|_| unavailable())?;
            let record = crypto::seal(&key, &nonce, &ad, &positions.positions())
                .map_err(|_| unavailable())?;
            let mut file = tempfile::NamedTempFile::new_in(directory).map_err(|_| unavailable())?;
            file.write_all(&nonce)
                .and_then(|_| file.write_all(&record))
                .and_then(|_| file.as_file().sync_all())
                .map_err(|_| unavailable())?;
            file.persist_noclobber(path).map_err(|_| unavailable())?;
            #[cfg(unix)]
            File::open(directory)
                .and_then(|dir| dir.sync_all())
                .map_err(|_| unavailable())?;
            Ok(positions)
        }
        Err(_) => Err(unavailable()),
    }
}

pub(super) fn show(app: &AppHandle) -> Result<bool> {
    let state = app.state::<OwnerState>();
    let _setup = state.setup.try_lock().map_err(|_| unavailable())?;
    let (identifier, epoch) = {
        let active = state.lifecycle.lock().map_err(|_| unavailable())?;
        let owner = active
            .identity
            .as_ref()
            .filter(|_| !active.exiting)
            .ok_or_else(unavailable)?;
        (owner.identifier(), active.epoch)
    };
    let Some(material) = prompt_material(app, false)? else {
        return Ok(false);
    };
    if OwnerIdentity::derive(&material.entropy).identifier() != identifier {
        return Err(BridgeError::new(
            "OWNER_WRONG_IDENTITY",
            locale::OWNER_WRONG_IDENTITY,
        ));
    }
    let directory = app.path().app_local_data_dir().map_err(|_| unavailable())?;
    let positions = {
        let active = state.lifecycle.lock().map_err(|_| unavailable())?;
        if active.epoch != epoch || active.exiting {
            return Ok(false);
        }
        profile(&directory, &material.entropy, &identifier)?
    };
    let phrase = material.words();
    let words = positions.select(&phrase).map_err(|_| unavailable())?;
    let mut body = Zeroizing::new(String::with_capacity(
        locale::OWNER_RECOVERY_LIMITS.len() + 128,
    ));
    use std::fmt::Write as _;
    for (position, word) in positions.positions().into_iter().zip(words) {
        writeln!(&mut *body, "{position}: {word}").map_err(|_| unavailable())?;
    }
    body.push('\n');
    body.push_str(locale::OWNER_RECOVERY_LIMITS);
    drop(phrase);
    drop(material);
    password::show_recovery_words(app, body, move |app| {
        let state = app.state::<OwnerState>();
        state
            .lifecycle
            .lock()
            .is_ok_and(|current| current.epoch == epoch && !current.exiting)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_profile_is_stable_and_binds_the_assigned_positions() {
        let directory = tempfile::tempdir().unwrap();
        let phrase = Zeroizing::new([21; 32]);
        let identity = OwnerIdentity::derive(&phrase).identifier();
        let first = profile(directory.path(), &phrase, &identity).unwrap();
        let second = profile(directory.path(), &phrase, &identity).unwrap();
        assert!(first == second);
        let wrong = Zeroizing::new([22; 32]);
        assert!(profile(directory.path(), &wrong, &identity).is_err());
        assert!(profile(directory.path(), &phrase, &[23; 32]).is_err());
        std::fs::write(directory.path().join(PROFILE_FILE), [0; PROFILE_BYTES]).unwrap();
        assert!(profile(directory.path(), &phrase, &identity).is_err());
    }
}
