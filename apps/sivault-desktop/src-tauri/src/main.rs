#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod adapter;
mod commands;
mod locale;
mod password;
mod wallet;
#[cfg(feature = "dev-wallet-chain")]
mod wallet_chain;
mod wallet_endpoint;

fn main() {
    if wallet::dispatch_worker() {
        return;
    }
    let builder = tauri::Builder::default();
    #[cfg(feature = "dev-wallet-chain")]
    let builder = builder.manage(wallet_endpoint::DirectoryCache::default());
    builder
        .plugin(tauri_plugin_dialog::init())
        .manage(commands::Bridge::default())
        .manage(wallet::Worker::default())
        .invoke_handler(tauri::generate_handler![
            commands::safe_create,
            commands::safe_open,
            commands::safe_unlock,
            commands::safe_list,
            commands::safe_import,
            commands::safe_export,
            commands::safe_create_directory,
            commands::safe_lock,
            wallet::wallet_status,
            wallet::wallet_access,
            wallet::wallet_send,
            wallet::wallet_retry_payment,
            wallet_endpoint::wallet_endpoint,
            wallet_endpoint::wallet_set_endpoint,
            wallet_endpoint::wallet_probe_endpoint,
            wallet_endpoint::wallet_refresh_directory,
        ])
        .run(tauri::generate_context!())
        .expect("desktop application failed to start");
}
