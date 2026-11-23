use crate::adapter::{BridgeError, Result};
use sivault_core::owner::OwnerIdentity;
use std::sync::Mutex;
use tauri::{AppHandle, Manager};

#[derive(Default)]
struct Lifecycle {
    identity: Option<OwnerIdentity>,
    epoch: u64,
    exiting: bool,
}

#[derive(Default)]
pub struct OwnerState {
    lifecycle: Mutex<Lifecycle>,
    #[cfg(any(target_os = "macos", windows))]
    setup: Mutex<()>,
}

impl OwnerState {
    pub fn clear(&self, exiting: bool) {
        let mut state = self.lifecycle.lock().unwrap_or_else(|e| e.into_inner());
        state.identity = None;
        state.epoch = state.epoch.wrapping_add(1);
        state.exiting |= exiting;
    }

    pub(crate) fn with_identity<T>(&self, action: impl FnOnce(&OwnerIdentity) -> Result<T>) -> Result<T> {
        let state = self.lifecycle.lock().map_err(|_| unavailable())?;
        let identity = state.identity.as_ref().filter(|_| !state.exiting).ok_or_else(unavailable)?;
        action(identity)
    }
}

fn unavailable() -> BridgeError {
    BridgeError::new("OWNER_UNAVAILABLE", crate::locale::OWNER_UNAVAILABLE)
}

#[tauri::command]
pub async fn owner_prepare(app: AppHandle) -> Result<bool> {
    tauri::async_runtime::spawn_blocking(move || app.state::<OwnerState>().prepare(&app))
        .await
        .map_err(|_| unavailable())?
}

#[tauri::command]
pub fn owner_identifier(state: tauri::State<'_, OwnerState>) -> Result<String> {
    state.with_identity(|identity| {
        use std::fmt::Write;
        let mut value = String::with_capacity(64);
        for byte in identity.identifier() {
            write!(&mut value, "{byte:02x}").expect("string write");
        }
        Ok(value)
    })
}

impl OwnerState {
    #[cfg(not(any(target_os = "macos", windows)))]
    pub(crate) fn prepare(&self, _: &AppHandle) -> Result<bool> {
        Err(unavailable())
    }

    #[cfg(any(target_os = "macos", windows))]
    pub(crate) fn prepare(&self, app: &AppHandle) -> Result<bool> {
        use crate::locale as l;
        use std::io::{Read, Write};

        let _setup = self.setup.try_lock().map_err(|_| unavailable())?;
        let epoch = {
            let state = self.lifecycle.lock().map_err(|_| unavailable())?;
            if state.exiting {
                return Err(unavailable());
            }
            if state.identity.is_some() {
                return Ok(true);
            }
            state.epoch
        };
        let data = app.path().app_local_data_dir().map_err(|_| unavailable())?;
        let pin_path = data.join("owner-control-v1.id");
        let pinned = match std::fs::File::open(&pin_path) {
            Ok(file) => {
                let mut pin = Vec::new();
                file.take(33)
                    .read_to_end(&mut pin)
                    .map_err(|_| unavailable())?;
                Some(<[u8; 32]>::try_from(pin).map_err(|_| unavailable())?)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(unavailable()),
        };
        let Some(identity) = prompt_identity(app, pinned.is_none())? else {
            return Ok(false);
        };
        let identifier = identity.identifier();
        let mut state = self.lifecycle.lock().map_err(|_| unavailable())?;
        if state.exiting || state.epoch != epoch {
            return Ok(false);
        }
        if let Some(pinned) = pinned {
            if pinned != identifier {
                return Err(BridgeError::new(
                    "OWNER_WRONG_IDENTITY",
                    l::OWNER_WRONG_IDENTITY,
                ));
            }
        } else {
            std::fs::create_dir_all(&data).map_err(|_| unavailable())?;
            let mut pin = tempfile::NamedTempFile::new_in(&data).map_err(|_| unavailable())?;
            pin.write_all(&identifier).map_err(|_| unavailable())?;
            pin.as_file().sync_all().map_err(|_| unavailable())?;
            pin.persist_noclobber(pin_path).map_err(|_| unavailable())?;
        }
        state.identity = Some(identity);
        Ok(true)
    }
}

#[cfg(any(target_os = "macos", windows))]
fn prompt_identity(app: &AppHandle, first: bool) -> Result<Option<OwnerIdentity>> {
    use crate::{locale as l, password};
    use siworld_native_wallet_core::vault::{Material, challenge};
    use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogResult};

    // Material is used only for BIP39 entropy and backup checks, never wallet derivation.
    const PHRASE_SCOPE: [u8; 32] = *b"sivault/owner/phrase-entropy/v1!";
    let create = if first {
        match app
            .dialog()
            .message(l::OWNER_CHOOSE)
            .title(l::OWNER_IDENTITY)
            .buttons(MessageDialogButtons::YesNoCancelCustom(
                l::OWNER_CREATE.into(),
                l::OWNER_RESTORE.into(),
                l::CANCEL.into(),
            ))
            .blocking_show_with_result()
        {
            MessageDialogResult::Yes => true,
            MessageDialogResult::No => false,
            MessageDialogResult::Custom(value) if value == l::OWNER_CREATE => true,
            MessageDialogResult::Custom(value) if value == l::OWNER_RESTORE => false,
            _ => return Ok(None),
        }
    } else {
        false
    };
    let material = if create {
        Material::generate(PHRASE_SCOPE, 0).map_err(|_| unavailable())?
    } else {
        #[cfg(target_os = "macos")]
        let words = password::on_main(app, || {
            password::native_secret(l::OWNER_IDENTITY, l::OWNER_ENTER_WORDS, false)
        })?;
        #[cfg(windows)]
        let words = password::windows_prompt(
            app,
            zeroize::Zeroizing::new(l::OWNER_ENTER_WORDS.into()),
            false,
        )?;
        let Some(words) = words else {
            return Ok(None);
        };
        Material::restore(PHRASE_SCOPE, 0, words)
            .map_err(|error| BridgeError::new("OWNER_INVALID_PHRASE", error))?
    };
    if first {
        let positions = challenge().map_err(|_| unavailable())?;
        let words = material.words();
        let Some(answer) = password::backup_prompt(app, l::OWNER_BACKUP, positions, words.clone())?
        else {
            return Ok(None);
        };
        if !crate::wallet::backup_matches(&words, positions, &answer) {
            return Err(BridgeError::new("OWNER_BAD_BACKUP", l::OWNER_BAD_BACKUP));
        }
    }
    Ok(Some(OwnerIdentity::derive(&material.entropy)))
}
