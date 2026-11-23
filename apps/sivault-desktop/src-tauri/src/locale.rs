pub const SAFE_CREATE_LOCATION: &str = "Choose location for new safe";
pub const SAFE_OPEN_LOCATION: &str = "Open safe folder";
pub const CONTROLLED_SELECT: &str = "Select an enrolled controlled safe";
pub const CONTROLLED_MANAGE: &str = "Confirm controlled safe command";
pub const CONTROLLED_COMMAND_FAILED: &str = "The releaser did not confirm this command.";
pub const REVOKE_LABEL_MISMATCH: &str = "The entered label does not match the selected safe.";
pub fn revoke_confirmation(label: &str) -> String {
    format!("Permanently revoke {label}? This cannot be undone. After the releaser deletes its live share, the safe cannot be recovered through that releaser. This does not recall plaintext or keys already received.")
}
pub fn refill_confirmation(current: u64, total: u64) -> String {
    format!("Increase the total attempt allowance from {current} to {total}? Attempts already used still count.")
}
pub const SAFE_IMPORT_LOCATION: &str = "Import files into safe";
pub const SAFE_EXPORT_LOCATION: &str = "Export unencrypted file";
#[cfg(any(target_os = "macos", windows))]
pub const RELEASER_PASSWORD: &str = "Unlock releaser storage";
#[cfg(any(target_os = "macos", windows))]
pub const RELEASER_SET_PASSWORD: &str = "Set a separate releaser storage password";
#[cfg(any(target_os = "macos", windows))]
pub const APPROVE_ENROLLMENT: &str = "Allow one controlled safe enrollment";
#[cfg(any(target_os = "macos", windows))]
pub fn enrollment_approval(owner: &str, allowance: u64) -> String {
    format!("Owner identifier: {owner}\nAttempt allowance: {allowance}\nVerify the owner identifier independently before allowing one enrollment.")
}
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
#[cfg(any(target_os = "macos", windows))]
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
#[cfg(any(target_os = "macos", windows))]
pub const OWNER_RECOVERY_TITLE: &str = "Your three assigned recovery words";
#[cfg(any(target_os = "macos", windows))]
pub const OWNER_RECOVERY_LIMITS: &str = concat!(
    "Recovery is not enabled in this build. Offline safes have no password recovery.\n\n",
    "Three assigned words from the 2,048-word list have at most 33 bits of strength. ",
    "An attacker with the safe folder and a matching releaser's retained records and keys ",
    "can search offline without the attempt limit. This is feasible for a funded attacker. ",
    "These words are not a strong standalone secret. Compromise can also expose these ",
    "three words of your owner phrase."
);
