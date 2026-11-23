pub const SAFE_CREATE_LOCATION: &str = "Choose location for new safe";
pub const SAFE_OPEN_LOCATION: &str = "Open standard safe folder";
pub const SAFE_IMPORT_LOCATION: &str = "Import files into safe";
pub const SAFE_EXPORT_LOCATION: &str = "Export unencrypted file";
#[cfg(any(target_os = "macos", windows))]
pub const RELEASER_PASSWORD: &str = "Unlock releaser storage";
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub const SAFE_SET_PASSWORD: &str = "Set safe password";
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub const SAFE_ENTER_PASSWORD: &str = "Enter safe password";
#[cfg(target_os = "macos")]
pub const PASSWORD: &str = "Password";
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub const PASSWORD_CONFIRM: &str = "Confirm password";
#[cfg(target_os = "macos")]
pub const CONTINUE: &str = "Continue";
#[cfg(target_os = "macos")]
pub const CANCEL: &str = "Cancel";
#[cfg(any(target_os = "macos", windows))]
pub const WALLET_UNLOCK: &str = "Unlock wallet";
#[cfg(target_os = "macos")]
pub const WALLET_PASSWORD: &str = "Wallet password";
#[cfg(target_os = "macos")]
pub const WALLET_RESTORE: &str = "Restore wallet";
#[cfg(target_os = "macos")]
pub const WALLET_WORDS: &str = "24 recovery words";
#[cfg(any(target_os = "macos", windows))]
pub const WALLET_SET_PASSWORD: &str = "Set wallet password";
#[cfg(any(target_os = "macos", windows))]
pub const WALLET_BACKUP: &str = "Write down these recovery words in order";
#[cfg(any(target_os = "macos", windows))]
pub const WALLET_BACKUP_CONFIRM: &str = "Confirm wallet recovery words";

#[cfg(windows)]
pub const WALLET_WINDOWS_RESTORE: &str = "Enter 24 recovery words in the password field.";

#[cfg(all(feature = "dev-wallet-chain", any(target_os = "macos", windows)))]
pub const WALLET_CONFIRM_SEND: &str = "Confirm development-chain payment";
#[cfg(all(feature = "dev-wallet-chain", any(target_os = "macos", windows)))]
pub const WALLET_SEND: &str = "Send";
#[cfg(all(feature = "dev-wallet-chain", any(target_os = "macos", windows)))]
pub const WALLET_CANCEL: &str = "Cancel";
#[cfg(all(feature = "dev-wallet-chain", any(target_os = "macos", windows)))]
pub fn wallet_payment_details(address: &str, amount: u64, fee: u64) -> String {
    format!("Recipient: {address}\nAmount: {amount} SIP atoms\nNetwork fee: {fee} SIP atoms")
}

#[cfg(any(target_os = "macos", windows))]
pub fn wallet_backup_positions(positions: [usize; 3]) -> String {
    format!("Words {}, {}, {}", positions[0], positions[1], positions[2])
}
pub const OWNER_IDENTITY: &str = "Controlled safe owner identity";
pub const OWNER_CHOOSE: &str =
    "Create an owner recovery phrase or restore an existing 24-word phrase.";
pub const OWNER_CREATE: &str = "Create phrase";
pub const OWNER_RESTORE: &str = "Restore phrase";
pub const OWNER_BACKUP: &str = "Write down your owner recovery phrase";
pub const OWNER_ENTER_WORDS: &str = "Enter the 24 owner recovery words";
pub const OWNER_BAD_BACKUP: &str = "The recovery words did not match the requested positions.";
pub const OWNER_WRONG_IDENTITY: &str = "That phrase does not match this installation's owner.";
pub const OWNER_UNAVAILABLE: &str = "The owner identity is unavailable.";
