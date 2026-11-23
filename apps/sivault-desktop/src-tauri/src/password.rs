use crate::adapter::{BridgeError, Result};
use tauri::AppHandle;
use zeroize::Zeroizing;

#[cfg(target_os = "macos")]
pub fn prompt_releaser(app: &AppHandle) -> Result<Option<Zeroizing<String>>> {
    on_main(app, || {
        native_secret(
            crate::locale::RELEASER_PASSWORD,
            crate::locale::PASSWORD,
            false,
        )
    })
}

#[cfg(windows)]
pub fn prompt_releaser(app: &AppHandle) -> Result<Option<Zeroizing<String>>> {
    windows_prompt(
        app,
        Zeroizing::new(crate::locale::RELEASER_PASSWORD.into()),
        false,
    )
}

#[cfg(target_os = "macos")]
pub fn prompt(app: &AppHandle, create: bool) -> Result<Option<Zeroizing<String>>> {
    let title = if create {
        crate::locale::SAFE_SET_PASSWORD
    } else {
        crate::locale::SAFE_ENTER_PASSWORD
    };
    on_main(app, move || {
        native_secret(title, crate::locale::PASSWORD, create)
    })
}

#[cfg(target_os = "macos")]
pub(crate) fn on_main<T: Send + 'static>(
    app: &AppHandle,
    action: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    app.run_on_main_thread(move || {
        let _ = tx.send(objc2::rc::autoreleasepool(|_| action()));
    })
    .map_err(|_| unavailable())?;
    rx.recv().map_err(|_| unavailable())?
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn prompt(_: &AppHandle, _: bool) -> Result<Option<Zeroizing<String>>> {
    Err(unavailable())
}

#[cfg(target_os = "windows")]
pub fn prompt(app: &AppHandle, create: bool) -> Result<Option<Zeroizing<String>>> {
    let title = if create {
        crate::locale::SAFE_SET_PASSWORD
    } else {
        crate::locale::SAFE_ENTER_PASSWORD
    };
    windows_prompt(app, Zeroizing::new(title.into()), create)
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_prompt(
    app: &AppHandle,
    title: Zeroizing<String>,
    confirm: bool,
) -> Result<Option<Zeroizing<String>>> {
    use tauri::Manager;
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let root = app.clone();
    app.run_on_main_thread(move || {
        let result = (|| {
            let window = root.get_webview_window("main").ok_or_else(unavailable)?;
            let owner = window.hwnd().map_err(|_| unavailable())?.0;
            let Some(value) = windows_dialog::prompt(owner, &title)? else {
                return Ok(None);
            };
            if confirm {
                let Some(confirmation) =
                    windows_dialog::prompt(owner, crate::locale::PASSWORD_CONFIRM)?
                else {
                    return Ok(None);
                };
                if *value != *confirmation {
                    return Err(BridgeError::new(
                        "PASSWORD_MISMATCH",
                        "Passwords do not match.",
                    ));
                }
            }
            Ok(Some(value))
        })();
        let _ = tx.send(result);
    })
    .map_err(|_| unavailable())?;
    rx.recv().map_err(|_| unavailable())?
}

#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
mod windows_dialog {
    use super::*;
    use windows_sys::Win32::Foundation::{ERROR_CANCELLED, ERROR_SUCCESS, HWND};
    use windows_sys::Win32::Security::Credentials::{
        CREDUI_FLAGS_ALWAYS_SHOW_UI, CREDUI_FLAGS_DO_NOT_PERSIST, CREDUI_FLAGS_GENERIC_CREDENTIALS,
        CREDUI_FLAGS_KEEP_USERNAME, CREDUI_INFOW, CredUIPromptForCredentialsW,
    };

    pub(super) fn prompt(owner: HWND, title: &str) -> Result<Option<Zeroizing<String>>> {
        let wide = |text: &str| text.encode_utf16().chain([0]).collect::<Vec<_>>();
        let caption = wide("SIVault");
        let title = Zeroizing::new(wide(title));
        let target = wide("SIVault/NativeCredential");
        let mut username = [0_u16; 128];
        let label = wide("SIVault");
        username[..label.len()].copy_from_slice(&label);
        let mut password = Zeroizing::new([0_u16; 257]);
        let mut save = 0;
        let ui = CREDUI_INFOW {
            cbSize: std::mem::size_of::<CREDUI_INFOW>() as u32,
            hwndParent: owner,
            pszMessageText: title.as_ptr(),
            pszCaptionText: caption.as_ptr(),
            hbmBanner: std::ptr::null_mut(),
        };
        // The dialog is synchronous; the buffers remain valid with the indicated lengths.
        let result = unsafe {
            CredUIPromptForCredentialsW(
                &ui,
                target.as_ptr(),
                std::ptr::null(),
                0,
                username.as_mut_ptr(),
                username.len() as u32,
                password.as_mut_ptr(),
                password.len() as u32,
                &mut save,
                CREDUI_FLAGS_ALWAYS_SHOW_UI
                    | CREDUI_FLAGS_DO_NOT_PERSIST
                    | CREDUI_FLAGS_GENERIC_CREDENTIALS
                    | CREDUI_FLAGS_KEEP_USERNAME,
            )
        };
        match result {
            ERROR_CANCELLED => Ok(None),
            ERROR_SUCCESS => {
                let len = password
                    .iter()
                    .position(|unit| *unit == 0)
                    .ok_or_else(unavailable)?;
                if len == 0 {
                    return Err(BridgeError::new("EMPTY_PASSWORD", "Enter a password."));
                }
                if len == password.len() - 1 {
                    return Err(BridgeError::new(
                        "PASSWORD_INPUT_LIMIT",
                        "Use fewer than 256 UTF-16 code units in this dialog.",
                    ));
                }
                let value = String::from_utf16(&password[..len]).map_err(|_| unavailable())?;
                Ok(Some(Zeroizing::new(value)))
            }
            _ => Err(unavailable()),
        }
    }
}

fn unavailable() -> BridgeError {
    BridgeError::new(
        "NATIVE_PASSWORD_UNAVAILABLE",
        "Native password entry is not available.",
    )
}

#[cfg(target_os = "macos")]
pub(crate) fn native_secret(
    title: &str,
    label: &str,
    confirm_input: bool,
) -> Result<Option<Zeroizing<String>>> {
    use objc2::MainThreadMarker;
    use objc2_app_kit::{
        NSAccessibility, NSAlert, NSAlertFirstButtonReturn, NSSecureTextField, NSView,
    };
    use objc2_foundation::{NSPoint, NSRect, NSSize, NSString};

    let mtm = MainThreadMarker::new().ok_or_else(unavailable)?;
    let rect = |y, h| NSRect::new(NSPoint::new(0.0, y), NSSize::new(260.0, h));
    let field = |label, y| {
        let input = NSSecureTextField::initWithFrame(mtm.alloc(), rect(y, 26.0));
        let label = NSString::from_str(label);
        input.setPlaceholderString(Some(&label));
        input.setAccessibilityLabel(Some(&label));
        input
    };
    let alert = NSAlert::new(mtm);
    alert.setMessageText(&NSString::from_str(title));
    alert.addButtonWithTitle(&NSString::from_str(crate::locale::CONTINUE));
    alert.addButtonWithTitle(&NSString::from_str(crate::locale::CANCEL));

    let view = NSView::initWithFrame(
        mtm.alloc(),
        rect(0.0, if confirm_input { 60.0 } else { 26.0 }),
    );
    let password = field(label, if confirm_input { 34.0 } else { 0.0 });
    view.addSubview(&password);
    let confirm = confirm_input.then(|| {
        let input = field(crate::locale::PASSWORD_CONFIRM, 0.0);
        view.addSubview(&input);
        input
    });
    alert.setAccessoryView(Some(&view));
    alert.layout();
    alert.window().setInitialFirstResponder(Some(&password));

    let accepted = alert.runModal() == NSAlertFirstButtonReturn;
    let read = |input: &NSSecureTextField| {
        let value = accepted.then(|| Zeroizing::new(input.stringValue().to_string()));
        input.setStringValue(&NSString::from_str(""));
        value
    };
    let result = read(&password);
    let confirmation = confirm.as_deref().and_then(read);
    if let Some(value) = &result {
        if value.is_empty() {
            return Err(BridgeError::new("EMPTY_PASSWORD", "Enter a password."));
        }
        if confirmation
            .as_ref()
            .is_some_and(|other| **other != **value)
        {
            return Err(BridgeError::new(
                "PASSWORD_MISMATCH",
                "Passwords do not match.",
            ));
        }
    }
    Ok(result)
}
