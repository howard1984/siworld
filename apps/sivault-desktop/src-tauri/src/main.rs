#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod adapter;
mod commands;
mod controlled;
mod locale;
mod owner;
mod password;
mod releaser;
mod wallet;
#[cfg(feature = "dev-wallet-chain")]
mod wallet_chain;
mod wallet_endpoint;

#[cfg(all(feature = "desktop-e2e", not(debug_assertions)))]
compile_error!("desktop-e2e requires debug assertions");

#[cfg(all(feature = "desktop-e2e", debug_assertions, any(target_os = "macos", windows)))]
#[path = "../tests/support/controlled_driver.rs"]
mod controlled_driver;

use tauri::Manager;

fn main() {
    #[cfg(all(feature = "desktop-e2e", debug_assertions, any(target_os = "macos", windows)))]
    if controlled_driver::dispatch() {
        return;
    }
    if wallet::dispatch_worker() {
        return;
    }
    let builder = tauri::Builder::default();
    #[cfg(feature = "dev-wallet-chain")]
    let builder = builder.manage(wallet_endpoint::DirectoryCache::default());
    builder
        .plugin(tauri_plugin_dialog::init())
        .manage(commands::Bridge::default())
        .manage(owner::OwnerState::default())
        .manage(releaser::ReleaserState::default())
        .manage(wallet::Worker::default())
        .invoke_handler(tauri::generate_handler![
            commands::safe_create,
            commands::safe_create_controlled,
            commands::safe_manage_controlled,
            commands::safe_open,
            commands::safe_unlock,
            commands::safe_list,
            commands::safe_import,
            commands::safe_export,
            commands::safe_create_directory,
            commands::safe_lock,
            owner::owner_prepare,
            owner::owner_identifier,
            owner::owner_show_recovery,
            releaser::releaser_status,
            releaser::releaser_authorize,
            releaser::releaser_set_running,
            releaser::releaser_verify,
            wallet::wallet_status,
            wallet::wallet_access,
            wallet::wallet_send,
            wallet::wallet_retry_payment,
            wallet_endpoint::wallet_endpoint,
            wallet_endpoint::wallet_set_endpoint,
            wallet_endpoint::wallet_probe_endpoint,
            wallet_endpoint::wallet_refresh_directory,
        ])
        .build(tauri::generate_context!())
        .expect("desktop application failed to start")
        .run(|app, event| match event {
            tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit => {
                app.state::<owner::OwnerState>().clear(true);
                app.state::<releaser::ReleaserState>().stop(true);
            }
            tauri::RunEvent::WindowEvent {
                label,
                event: tauri::WindowEvent::CloseRequested { .. },
                ..
            } if label == "main" => {
                app.state::<owner::OwnerState>().clear(false);
                app.state::<releaser::ReleaserState>().stop(false);
            }
            _ => {}
        });
}
