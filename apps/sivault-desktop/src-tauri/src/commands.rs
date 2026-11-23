use crate::adapter::{BridgeError, EntryInfo, Result, SafeAdapter, SafeInfo};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::DialogExt;

#[derive(Default, Clone)]
pub struct Bridge(Arc<Mutex<SafeAdapter>>);

async fn blocking<T: Send + 'static>(
    app: AppHandle,
    action: impl FnOnce(&AppHandle, &mut SafeAdapter) -> Result<T> + Send + 'static,
) -> Result<T> {
    let bridge = app.state::<Bridge>().inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut state = bridge.0.lock().map_err(|_| {
            BridgeError::new("STATE_UNAVAILABLE", "Restart the application to continue.")
        })?;
        action(&app, &mut state)
    })
    .await
    .map_err(|_| BridgeError::new("OPERATION_INTERRUPTED", "The operation was interrupted."))?
}

#[tauri::command]
pub async fn safe_create(
    app: AppHandle,
    name: String,
    fixed: Option<bool>,
    decoy: Option<bool>,
) -> Result<Option<SafeInfo>> {
    blocking(app, move |app, state| {
        if name.trim().is_empty()
            || name == "."
            || name == ".."
            || name.contains(['/', '\\'])
            || name.len() > 120
        {
            return Err(BridgeError::new("INVALID_NAME", "Enter a valid safe name."));
        }
        let file = app
            .dialog()
            .file()
            .set_title(crate::locale::SAFE_CREATE_LOCATION)
            .blocking_pick_folder();
        let Some(file) = file else {
            return Ok(None);
        };
        let path = file
            .into_path()
            .map_err(|_| BridgeError::new("INVALID_PATH", "Choose a local file."))?;
        let Some(password) = crate::password::prompt(app, true)? else {
            return Ok(None);
        };
        let path = path.join(format!("{name}.sivault"));
        if fixed == Some(true) {
            let secondary = if decoy == Some(true) {
                let Some(secondary) = crate::password::prompt_secondary(app)? else {
                    return Ok(None);
                };
                Some(secondary)
            } else {
                None
            };
            state
                .create_fixed(
                    &path,
                    &name,
                    &password,
                    secondary.as_ref().map(|password| password.as_str()),
                )
                .map(Some)
        } else {
            state.create(&path, &name, &password).map(Some)
        }
    })
    .await
}

#[tauri::command]
pub async fn safe_update_decoy(app: AppHandle, session_id: String) -> Result<bool> {
    blocking(app, move |app, state| {
        state.check_decoy_management(&session_id)?;
        let Some(file) = app
            .dialog()
            .file()
            .set_title(crate::locale::SAFE_DECOY_IMPORT)
            .blocking_pick_file()
        else {
            return Ok(false);
        };
        let path = file
            .into_path()
            .map_err(|_| BridgeError::new("INVALID_PATH", "Choose a local file."))?;
        state.update_decoy(&session_id, &path)?;
        Ok(true)
    })
    .await
}

#[tauri::command]
pub async fn safe_create_controlled(
    app: AppHandle,
    name: String,
    address: String,
    identifier: String,
    allowance: u64,
) -> Result<Option<SafeInfo>> {
    blocking(app, move |app, state| {
        if name.trim().is_empty()
            || name == "."
            || name == ".."
            || name.contains(['/', '\\'])
            || name.len() > 120
        {
            return Err(BridgeError::new("INVALID_NAME", "Enter a valid safe name."));
        }
        let peer = crate::releaser::LocalPeer::parse(&address, &identifier)?;
        let owner = app.state::<crate::owner::OwnerState>();
        if !owner.prepare(app)? {
            return Ok(None);
        }
        let Some(directory) = app
            .dialog()
            .file()
            .set_title(crate::locale::SAFE_CREATE_LOCATION)
            .blocking_pick_folder()
        else {
            return Ok(None);
        };
        let directory = directory
            .into_path()
            .map_err(|_| BridgeError::new("INVALID_PATH", "Choose a local file."))?;
        let Some(password) = crate::password::prompt(app, true)? else {
            return Ok(None);
        };
        let path = directory.join(format!("{name}.sivault"));
        let safe = owner.with_identity(|identity| {
            crate::controlled::create(&path, &password, &peer, allowance, identity)
        })?;
        Ok(Some(state.activate(&path, &name, safe, false)))
    })
    .await
}

#[tauri::command]
pub async fn safe_manage_controlled(
    app: AppHandle,
    revoke_label: Option<String>,
    current: u64,
    additional: u64,
) -> Result<bool> {
    use sivault_releaser::administration::Change;
    use tauri_plugin_dialog::MessageDialogButtons;

    blocking(app, move |app, _| {
        let owner = app.state::<crate::owner::OwnerState>();
        let Some(folder) = app
            .dialog()
            .file()
            .set_title(crate::locale::CONTROLLED_SELECT)
            .blocking_pick_folder()
        else {
            return Ok(false);
        };
        let path = folder
            .into_path()
            .map_err(|_| BridgeError::new("INVALID_PATH", "Choose a local safe file."))?;
        let (change, confirm) = if let Some(label) = revoke_label {
            if label.is_empty() || path.file_stem().and_then(|s| s.to_str()) != Some(label.as_str())
            {
                return Err(BridgeError::new(
                    "REVOKE_LABEL_MISMATCH",
                    crate::locale::REVOKE_LABEL_MISMATCH,
                ));
            }
            (Change::Revoke, crate::locale::revoke_confirmation(&label))
        } else {
            let total = current
                .checked_add(additional)
                .filter(|_| additional > 0)
                .ok_or_else(|| {
                    BridgeError::new(
                        "CONTROLLED_COMMAND_FAILED",
                        crate::locale::CONTROLLED_COMMAND_FAILED,
                    )
                })?;
            (
                Change::Refill {
                    current,
                    additional,
                },
                crate::locale::refill_confirmation(current, total),
            )
        };
        if !app
            .dialog()
            .message(confirm)
            .title(crate::locale::CONTROLLED_MANAGE)
            .buttons(MessageDialogButtons::OkCancel)
            .blocking_show()
            || !owner.prepare(app)?
        {
            return Ok(false);
        }
        owner.with_identity(|owner| crate::controlled::manage(&path, owner, change))?;
        Ok(true)
    })
    .await
}

#[tauri::command]
pub async fn safe_open(app: AppHandle, read_only: bool) -> Result<Option<SafeInfo>> {
    blocking(app, move |app, state| {
        let file = app
            .dialog()
            .file()
            .set_title(crate::locale::SAFE_OPEN_LOCATION)
            .blocking_pick_folder();
        let Some(file) = file else {
            return Ok(None);
        };
        let path = file
            .into_path()
            .map_err(|_| BridgeError::new("INVALID_PATH", "Choose a local safe file."))?;
        let Some(password) = crate::password::prompt(app, false)? else {
            return Ok(None);
        };
        state.open(&path, &password, read_only).map(Some)
    })
    .await
}

#[tauri::command]
pub async fn safe_unlock(app: AppHandle, id: String, read_only: bool) -> Result<Option<SafeInfo>> {
    blocking(app, move |app, state| {
        let Some(password) = crate::password::prompt(app, false)? else {
            return Ok(None);
        };
        state.unlock(&id, &password, read_only).map(Some)
    })
    .await
}

#[tauri::command]
pub async fn safe_list(
    app: AppHandle,
    session_id: String,
    parent: Option<String>,
) -> Result<Vec<EntryInfo>> {
    blocking(app, move |_, state| {
        state.list(&session_id, parent.as_deref())
    })
    .await
}

#[tauri::command]
pub async fn safe_import(
    app: AppHandle,
    session_id: String,
    parent: Option<String>,
) -> Result<usize> {
    blocking(app, move |app, state| {
        state.check_writable(&session_id)?;
        let files = app
            .dialog()
            .file()
            .set_title(crate::locale::SAFE_IMPORT_LOCATION)
            .blocking_pick_files();
        let Some(files) = files else {
            return Ok(0);
        };
        let mut count = 0;
        for file in files {
            let path = file
                .into_path()
                .map_err(|_| BridgeError::new("INVALID_PATH", "Choose a local file."))?;
            state.import(&session_id, &path, parent.as_deref())?;
            count += 1;
        }
        Ok(count)
    })
    .await
}

#[tauri::command]
pub async fn safe_export(app: AppHandle, session_id: String, entry_id: String) -> Result<bool> {
    blocking(app, move |app, state| {
        let name = state.export_name(&session_id, &entry_id)?;
        let file = app
            .dialog()
            .file()
            .set_title(crate::locale::SAFE_EXPORT_LOCATION)
            .set_file_name(name)
            .blocking_save_file();
        let Some(file) = file else {
            return Ok(false);
        };
        let path = file
            .into_path()
            .map_err(|_| BridgeError::new("INVALID_PATH", "Choose a local destination."))?;
        state.export(&session_id, &entry_id, &path)?;
        Ok(true)
    })
    .await
}

#[tauri::command]
pub async fn safe_create_directory(
    app: AppHandle,
    session_id: String,
    name: String,
    parent: Option<String>,
) -> Result<EntryInfo> {
    blocking(app, move |_, state| {
        state.create_directory(&session_id, &name, parent.as_deref())
    })
    .await
}

#[tauri::command]
pub async fn safe_lock(app: AppHandle, session_id: String) -> Result<()> {
    blocking(app, move |app, state| {
        state.lock(&session_id)?;
        app.state::<crate::owner::OwnerState>().clear(false);
        app.state::<crate::releaser::ReleaserState>().stop(false);
        Ok(())
    })
    .await
}
