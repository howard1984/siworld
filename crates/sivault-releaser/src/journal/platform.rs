//! Desktop credential-store checkpoints. The lock directory must be the
//! application's single per-user, machine-local directory, not the safe or
//! journal backup directory. All releaser workers must use that location.

use std::{
    fmt::Write,
    fs::{File, OpenOptions, TryLockError},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use super::{AuthorityError, Checkpoint, Id, MarkerStore, Result, SlotIdentity};

const SERVICE: &str = "io.siworld.sivault.releaser-checkpoint.v1";
const MARKER_LEN: usize = 64;

pub struct PlatformMarker {
    lock_dir: PathBuf,
}

impl PlatformMarker {
    pub fn new(lock_dir: &Path) -> Result<Self> {
        if !lock_dir.is_absolute() || !lock_dir.is_dir() {
            return Err(AuthorityError::Unavailable);
        }
        Ok(Self {
            lock_dir: lock_dir.to_path_buf(),
        })
    }

    fn lock(&self, account: &str) -> Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.lock_dir.join(account))
            .map_err(|_| AuthorityError::Unavailable)?;
        file.try_lock().map_err(|err| match err {
            TryLockError::WouldBlock => AuthorityError::NotExclusive,
            TryLockError::Error(_) => AuthorityError::Unavailable,
        })?;
        Ok(file)
    }
}

impl MarkerStore for PlatformMarker {
    fn load(&mut self, slot: SlotIdentity) -> Result<Option<Checkpoint>> {
        let account = account(slot);
        let _lock = self.lock(&account)?;
        native::read(&account).map(|bytes| bytes.map(decode))
    }

    fn compare_and_store(
        &mut self,
        slot: SlotIdentity,
        expected: Option<Checkpoint>,
        next: Checkpoint,
    ) -> Result<()> {
        let account = account(slot);
        let _lock = self.lock(&account)?;
        if native::read(&account)?.map(decode) != expected {
            return Err(AuthorityError::Stale);
        }
        let bytes = encode(next);
        native::write(&account, bytes, expected.is_none())?;
        if native::read(&account)? != Some(bytes) {
            return Err(AuthorityError::InvalidEvidence);
        }
        Ok(())
    }
}

fn account(slot: SlotIdentity) -> String {
    let mut digest = Sha256::new();
    digest.update(b"sivault/ledger-marker/v1\0");
    digest.update(slot.suite.to_be_bytes());
    for id in [slot.network, slot.safe, slot.slot, slot.ledger] {
        digest.update(id.0);
    }
    let mut result = String::with_capacity(64);
    for byte in digest.finalize() {
        write!(&mut result, "{byte:02x}").expect("formatting into String");
    }
    result
}

fn encode(checkpoint: Checkpoint) -> [u8; MARKER_LEN] {
    let mut bytes = [0; MARKER_LEN];
    bytes[..32].copy_from_slice(&checkpoint.instance.0);
    bytes[32..].copy_from_slice(&checkpoint.head.0);
    bytes
}

fn decode(bytes: [u8; MARKER_LEN]) -> Checkpoint {
    Checkpoint {
        instance: Id(bytes[..32].try_into().expect("fixed checkpoint width")),
        head: Id(bytes[32..].try_into().expect("fixed checkpoint width")),
    }
}

#[cfg(target_os = "macos")]
mod native {
    use security_framework::{
        access_control::{ProtectionMode, SecAccessControl},
        passwords::{PasswordOptions, generic_password, set_generic_password_options},
    };
    use security_framework_sys::base::errSecItemNotFound;

    use super::{AuthorityError, MARKER_LEN, Result, SERVICE};

    fn options(account: &str) -> PasswordOptions {
        let mut options = PasswordOptions::new_generic_password(SERVICE, account);
        options.use_protected_keychain();
        options.set_access_synchronized(Some(false));
        options
    }

    pub(super) fn read(account: &str) -> Result<Option<[u8; MARKER_LEN]>> {
        match generic_password(options(account)) {
            Ok(bytes) => bytes
                .try_into()
                .map(Some)
                .map_err(|_| AuthorityError::InvalidEvidence),
            Err(error) if error.code() == errSecItemNotFound => Ok(None),
            Err(_) => Err(AuthorityError::Unavailable),
        }
    }

    pub(super) fn write(account: &str, bytes: [u8; MARKER_LEN], create: bool) -> Result<()> {
        let mut options = options(account);
        if create {
            let control = SecAccessControl::create_with_protection(
                Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
                0,
            )
            .map_err(|_| AuthorityError::Unavailable)?;
            options.set_access_control(control);
        }
        set_generic_password_options(&bytes, options).map_err(|_| AuthorityError::Unavailable)
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod native {
    use std::{io, ptr::NonNull, slice};

    use windows_sys::Win32::{
        Foundation::ERROR_NOT_FOUND,
        Security::Credentials::{
            CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredFree, CredReadW,
            CredWriteW,
        },
    };

    use super::{AuthorityError, MARKER_LEN, Result, SERVICE};

    fn target(account: &str) -> Vec<u16> {
        format!("{SERVICE}/{account}")
            .encode_utf16()
            .chain([0])
            .collect()
    }

    struct Credential(NonNull<CREDENTIALW>);

    impl Drop for Credential {
        fn drop(&mut self) {
            // SAFETY: CredReadW allocated this buffer and it is freed once.
            unsafe { CredFree(self.0.as_ptr().cast()) };
        }
    }

    pub(super) fn read(account: &str) -> Result<Option<[u8; MARKER_LEN]>> {
        let name = target(account);
        let mut raw = std::ptr::null_mut();
        // SAFETY: The UTF-16 string is terminated and the output pointer is writable.
        if unsafe { CredReadW(name.as_ptr(), CRED_TYPE_GENERIC, 0, &mut raw) } == 0 {
            return match io::Error::last_os_error().raw_os_error() {
                Some(code) if code == ERROR_NOT_FOUND as i32 => Ok(None),
                _ => Err(AuthorityError::Unavailable),
            };
        }
        let owned = Credential(NonNull::new(raw).ok_or(AuthorityError::InvalidEvidence)?);
        // SAFETY: The successful read supplied an initialized CREDENTIALW.
        let entry = unsafe { owned.0.as_ref() };
        if entry.CredentialBlobSize as usize != MARKER_LEN
            || entry.CredentialBlob.is_null()
            || entry.Persist != CRED_PERSIST_LOCAL_MACHINE
        {
            return Err(AuthorityError::InvalidEvidence);
        }
        // SAFETY: The blob is owned by the credential and its length was checked.
        let bytes = unsafe { slice::from_raw_parts(entry.CredentialBlob, MARKER_LEN) };
        Ok(Some(bytes.try_into().expect("fixed checkpoint width")))
    }

    pub(super) fn write(account: &str, mut bytes: [u8; MARKER_LEN], _: bool) -> Result<()> {
        let mut name = target(account);
        let mut user: Vec<u16> = "SIVault".encode_utf16().chain([0]).collect();
        let entry = CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            TargetName: name.as_mut_ptr(),
            UserName: user.as_mut_ptr(),
            CredentialBlobSize: MARKER_LEN as u32,
            CredentialBlob: bytes.as_mut_ptr(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            ..CREDENTIALW::default()
        };
        // SAFETY: The initialized structure and all its buffers live through the call.
        if unsafe { CredWriteW(&entry, 0) } == 0 {
            return Err(AuthorityError::Unavailable);
        }
        Ok(())
    }
}
