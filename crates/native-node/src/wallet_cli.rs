//! Explicit local terminal custody frontend. Secret material never enters
//! stdout, command arguments, environment options, files or public telemetry.
//! The terminal itself and the operating system must be trusted by its owner.

use crate::wallet_vault::{PendingWallet, RecoveryDescriptor, UnlockedWallet, WalletVault};
use native::codec::encode_digest;
use std::fs::{File, OpenOptions};
use std::io::{IsTerminal, Write};
use std::path::Path;
use zeroize::Zeroizing;

pub const HELP: &str = "wallet-create WALLET_DIR NETWORK_DIR [ACCOUNT]  Create an encrypted wallet after a local mnemonic-backup challenge\nwallet-restore WALLET_DIR NETWORK_DIR [ACCOUNT] Restore from hidden 24-word input to a new directory\nwallet-address WALLET_DIR NETWORK_DIR          Authenticate and export the public address and recovery descriptor\nwallet-configure-miner WALLET_DIR NETWORK_DIR voyager|holder  Authenticate and set the next template's reward destination";
const TERMINAL_ERROR: &str =
    "wallet custody requires a trusted interactive terminal on stdin and stderr";
const ADDRESS_BYTES: usize = 1232;

struct Request<'a> {
    wallet: &'a Path,
    network: &'a Path,
    account: u32,
    reward_mode: Option<crate::state::RewardMode>,
}
fn parse<'a>(command: &str, args: &'a [String]) -> Result<Request<'a>, String> {
    let count_valid = match command {
        "wallet-create" | "wallet-restore" => matches!(args.len(), 2 | 3),
        "wallet-address" => args.len() == 2,
        "wallet-configure-miner" => args.len() == 3,
        _ => false,
    };
    if !count_valid || args[0].is_empty() || args[1].is_empty() {
        return Err("expected WALLET_DIR NETWORK_DIR, an optional create/restore account, or an explicit miner mode".into());
    }
    let reward_mode = if command == "wallet-configure-miner" {
        Some(crate::state::RewardMode::from_name(&args[2]).map_err(|e| e.to_string())?)
    } else {
        None
    };
    let account = if reward_mode.is_none()
        && let Some(value) = args.get(2)
    {
        if value.is_empty()
            || value.bytes().any(|byte| !byte.is_ascii_digit())
            || (value.len() > 1 && value.starts_with('0'))
        {
            return Err("wallet account requires a canonical unsigned 32-bit decimal".into());
        }
        value
            .parse::<u32>()
            .map_err(|_| "wallet account exceeds its limit")?
    } else {
        0
    };
    Ok(Request {
        wallet: Path::new(&args[0]),
        network: Path::new(&args[1]),
        account,
        reward_mode,
    })
}
fn require_terminal(stdin: bool, stderr: bool) -> Result<(), String> {
    if stdin && stderr {
        Ok(())
    } else {
        Err(TERMINAL_ERROR.into())
    }
}
/// Pure invocation checks run before filesystem access or secret prompts.
fn prepare_request<'a>(
    command: &str,
    args: &'a [String],
    stdin_terminal: bool,
    stderr_terminal: bool,
) -> Result<Request<'a>, String> {
    let request = parse(command, args)?;
    require_terminal(stdin_terminal, stderr_terminal)?;
    Ok(request)
}
fn terminal() -> Result<File, String> {
    let tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| "cannot open the controlling local terminal")?;
    if !tty.is_terminal() {
        return Err("controlling device is not a terminal".into());
    }
    Ok(tty)
}

/// Deliberately has no formatting, cloning or serialization implementation.
struct SecretInput(Zeroizing<String>);
impl SecretInput {
    fn expose(&self) -> &str {
        &self.0
    }
    fn into_owned(self) -> Zeroizing<String> {
        self.0
    }
}
fn hidden(prompt: &str, maximum: usize) -> Result<SecretInput, String> {
    let value = Zeroizing::new(
        rpassword::prompt_password(prompt).map_err(|_| "cannot read hidden local wallet input")?,
    );
    if value.len() > maximum {
        return Err("wallet input exceeds its byte limit".into());
    }
    Ok(SecretInput(value))
}
fn passphrase(confirm: bool) -> Result<SecretInput, String> {
    let value = hidden(
        if confirm {
            "New wallet passphrase: "
        } else {
            "Wallet passphrase: "
        },
        1024,
    )?;
    if value.expose().is_empty() || (confirm && value.expose().len() < 12) {
        return Err("new wallet passphrases require 12 to 1024 UTF-8 bytes".into());
    }
    if confirm {
        let repeated = hidden("Confirm wallet passphrase: ", 1024)?;
        if value.expose() != repeated.expose() {
            return Err("wallet passphrases do not match".into());
        }
    }
    Ok(value)
}
fn create(
    request: &Request<'_>,
    network: crate::wire::Hash,
    tty: &mut File,
) -> Result<UnlockedWallet, String> {
    let passphrase = passphrase(true)?;
    let pending = PendingWallet::generate(network, request.account)?;
    let descriptor = pending.descriptor();
    {
        let words = pending.recovery_words();
        write!(tty, "\nRecord these 24 words privately and in order. Never submit them to a node or support service.\nRecovery version: {}\nNetwork: {}\nAccount: {}\n\n{}\n\n", descriptor.version, crate::local::hex(&descriptor.network), descriptor.account, words.expose())
            .map_err(|_| "cannot render the private recovery view")?;
        tty.flush()
            .map_err(|_| "cannot flush the private recovery view")?;
        let acknowledgement = hidden("Press Enter after recording the backup: ", 0);
        // Erase the display and terminal scrollback where supported before
        // obtaining new answers. A terminal or screen recorder may retain it.
        tty.write_all(b"\x1b[2J\x1b[3J\x1b[H")
            .and_then(|()| tty.flush())
            .map_err(|_| "cannot hide the private recovery view")?;
        acknowledgement?;
    }
    let challenge = pending.backup_challenge();
    let first = hidden(&format!("Backup word {}: ", challenge[0]), 32)?;
    let second = hidden(&format!("Backup word {}: ", challenge[1]), 32)?;
    let third = hidden(&format!("Backup word {}: ", challenge[2]), 32)?;
    pending
        .confirm_backup([first.expose(), second.expose(), third.expose()])?
        .create(request.wallet, passphrase.expose())
}

fn public_record(
    descriptor: RecoveryDescriptor,
    address: &[u8; ADDRESS_BYTES],
) -> Result<String, String> {
    serde_json::to_string(&serde_json::json!({
        "version": descriptor.version,
        "network": crate::local::hex(&descriptor.network),
        "account": descriptor.account,
        "address_hex": crate::local::hex(address),
    }))
    .map_err(|_| "cannot encode public wallet descriptor".into())
}
fn miner_status(
    network: crate::wire::Hash,
    mode: crate::state::RewardMode,
) -> Result<String, String> {
    serde_json::to_string(&serde_json::json!({
        "version": 1,
        "network": crate::local::hex(&network),
        "reward_mode": mode.name(),
        "status": "mining_preferences_saved",
        "applies_to": "next_block_template",
    }))
    .map_err(|_| "cannot encode public miner configuration status".into())
}

/// `args` excludes the command name. Reject noninteractive use before generating
/// entropy. Success writes public JSON only; recovery words go directly to TTY.
pub fn run(command: &str, args: &[String]) -> Result<(), String> {
    let request = prepare_request(
        command,
        args,
        std::io::stdin().is_terminal(),
        std::io::stderr().is_terminal(),
    )?;
    let mut tty = terminal()?;
    let network = crate::local::load(request.network)?.network;
    let unlocked = match command {
        "wallet-create" => create(&request, network, &mut tty)?,
        "wallet-restore" => {
            writeln!(tty, "Restore only with the original recorded network and account. Selected network: {}; account: {}", crate::local::hex(&network), request.account)
                .map_err(|_| "cannot display the public recovery context")?;
            let words = hidden("Enter the 24 recovery words in order: ", 256)?;
            let passphrase = passphrase(true)?;
            WalletVault::restore(
                request.wallet,
                network,
                request.account,
                words.into_owned(),
                passphrase.expose(),
            )?
        }
        "wallet-address" | "wallet-configure-miner" => {
            let passphrase = passphrase(false)?;
            WalletVault::open(request.wallet, network, passphrase.expose())?
        }
        _ => return Err("unsupported wallet command".into()),
    };
    let keys = unlocked.keys()?;
    let recipient = keys.address();
    let encoded = if let Some(mode) = request.reward_mode {
        crate::mining::save(
            request.network,
            network,
            &crate::producer::MiningSettings { mode, recipient },
        )?;
        miner_status(network, mode)?
    } else {
        let mut address = [0u8; ADDRESS_BYTES];
        address[..48].copy_from_slice(&encode_digest(&recipient.owner()));
        address[48..].copy_from_slice(recipient.encapsulation_key());
        public_record(unlocked.descriptor(), &address)?
    };
    std::io::stdout()
        .lock()
        .write_all(format!("{encoded}\n").as_bytes())
        .map_err(|_| "cannot write public wallet descriptor".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn command_shapes_and_accounts_are_exact_and_bounded() {
        for command in ["wallet-create", "wallet-restore"] {
            assert_eq!(
                parse(command, &arguments(&["wallet", "network"]))
                    .unwrap()
                    .account,
                0
            );
            assert_eq!(
                parse(command, &arguments(&["wallet", "network", "4294967295"]))
                    .unwrap()
                    .account,
                u32::MAX
            );
            for account in ["-1", "+1", "01", " 1", "1 ", "4294967296", "password", ""] {
                assert!(parse(command, &arguments(&["wallet", "network", account])).is_err());
            }
        }
        assert!(parse("wallet-address", &arguments(&["wallet", "network"])).is_ok());
        assert!(parse("wallet-address", &arguments(&["wallet", "network", "0"])).is_err());
        for args in [
            vec![],
            arguments(&["wallet"]),
            arguments(&["", "network"]),
            arguments(&["wallet", ""]),
            arguments(&["wallet", "network", "0", "secret"]),
        ] {
            assert!(parse("wallet-create", &args).is_err());
        }
        assert!(parse("wallet-export-seed", &arguments(&["wallet", "network"])).is_err());
    }

    #[test]
    fn no_noninteractive_secret_custody_is_admitted() {
        assert!(require_terminal(true, true).is_ok());
        for terminals in [(false, false), (true, false), (false, true)] {
            assert!(require_terminal(terminals.0, terminals.1).is_err());
            for (command, args) in [
                ("wallet-create", arguments(&["wallet", "network"])),
                ("wallet-restore", arguments(&["wallet", "network"])),
                ("wallet-address", arguments(&["wallet", "network"])),
                (
                    "wallet-configure-miner",
                    arguments(&["wallet", "network", "holder"]),
                ),
            ] {
                assert_eq!(
                    prepare_request(command, &args, terminals.0, terminals.1).err(),
                    Some(TERMINAL_ERROR.to_owned())
                );
            }
        }
    }

    #[test]
    fn miner_configuration_requires_one_explicit_mode_and_exact_arguments() {
        for (name, mode) in [
            ("voyager", crate::state::RewardMode::Voyager),
            ("holder", crate::state::RewardMode::Holder),
        ] {
            let args = arguments(&["wallet", "network", name]);
            let request = parse("wallet-configure-miner", &args).unwrap();
            assert_eq!(request.reward_mode, Some(mode));
            assert_eq!(request.account, 0);
        }
        for mode in [
            "",
            "default",
            "automatic",
            "Voyager",
            "HOLDER",
            "0",
            "holder ",
        ] {
            assert!(
                parse(
                    "wallet-configure-miner",
                    &arguments(&["wallet", "network", mode])
                )
                .is_err()
            );
        }
        for args in [
            vec![],
            arguments(&["wallet"]),
            arguments(&["wallet", "network"]),
            arguments(&["", "network", "holder"]),
            arguments(&["wallet", "", "holder"]),
            arguments(&["wallet", "network", "holder", "0"]),
        ] {
            assert!(parse("wallet-configure-miner", &args).is_err());
        }
    }

    #[test]
    fn miner_configuration_status_is_public_and_omits_wallet_material() {
        let encoded = miner_status([7; 32], crate::state::RewardMode::Holder).unwrap();
        let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 5);
        assert_eq!(value["version"], 1);
        assert_eq!(value["network"], crate::local::hex(&[7; 32]));
        assert_eq!(value["reward_mode"], "holder");
        assert_eq!(value["status"], "mining_preferences_saved");
        assert_eq!(value["applies_to"], "next_block_template");
        for field in [
            "address",
            "owner",
            "seed",
            "mnemonic",
            "passphrase",
            "wallet",
        ] {
            assert!(!encoded.contains(field));
        }
    }

    #[test]
    fn stdout_descriptor_contains_only_public_recovery_context_and_address() {
        let descriptor = RecoveryDescriptor {
            version: 1,
            network: [7; 32],
            account: 19,
        };
        let encoded = public_record(descriptor, &[9; ADDRESS_BYTES]).unwrap();
        let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 4);
        assert_eq!(value["version"], 1);
        assert_eq!(value["network"], crate::local::hex(&[7; 32]));
        assert_eq!(value["account"], 19);
        assert_eq!(
            value["address_hex"].as_str().unwrap().len(),
            ADDRESS_BYTES * 2
        );
        assert!(!encoded.contains("mnemonic"));
        assert!(!encoded.contains("passphrase"));
        assert!(!encoded.contains("seed"));
    }
}
