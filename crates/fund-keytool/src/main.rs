//! Interactive local CLI. Secret values are accepted only by hidden TTY input.
use siworld_fund_keytool as keytool;
use std::io::{IsTerminal, Write};
use std::path::Path;
use zeroize::Zeroizing;

struct Passphrase(Zeroizing<String>);
impl std::ops::Deref for Passphrase {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}
fn password(prompt: &str, confirm: bool) -> Result<Passphrase, String> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Err("a local interactive terminal is required for secret input".into());
    }
    let value = Zeroizing::new(
        rpassword::prompt_password(prompt).map_err(|_| "cannot read hidden passphrase")?,
    );
    if value.len() > 1024 || value.is_empty() {
        return Err("passphrase requires 1 to 1024 UTF-8 bytes".into());
    }
    if confirm {
        let confirmation = Zeroizing::new(
            rpassword::prompt_password("Confirm passphrase: ")
                .map_err(|_| "cannot read hidden confirmation")?,
        );
        if *value != *confirmation {
            return Err("passphrases do not match".into());
        }
        if value.len() < 16 {
            return Err("new passphrase requires at least 16 UTF-8 bytes".into());
        }
    }
    Ok(Passphrase(value))
}
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let command = args.first().and_then(|value| value.to_str()).unwrap_or("");
    let public = match (command, args.len()) {
        ("generate", 2) => {
            let passphrase = password("New key passphrase: ", true)?;
            keytool::generate(Path::new(&args[1]), &passphrase)?
        }
        ("public", 2) | ("verify", 2) => {
            let passphrase = password("Key passphrase: ", false)?;
            if command == "verify" {
                keytool::verify(Path::new(&args[1]), &passphrase)?
            } else {
                keytool::public(Path::new(&args[1]), &passphrase)?
            }
        }
        ("backup", 3) => {
            let original = password("Source key passphrase: ", false)?;
            let replacement = password("New backup passphrase: ", true)?;
            keytool::backup(
                Path::new(&args[1]),
                &original,
                Path::new(&args[2]),
                &replacement,
            )?
        }
        ("check-public", 2) => keytool::check_public(Path::new(&args[1]))?,
        ("--help" | "-h", 1) => {
            println!(
                "siworld-fund-keytool: offline development-fund key custody\n\ngenerate DIRECTORY              Create a new encrypted ML-DSA-65 seed\npublic DIRECTORY                Authenticate and export only public JSON\nverify DIRECTORY                Authenticate and locally sign/verify a fresh challenge\nbackup DIRECTORY BACKUP_DIRECTORY  Reencrypt the same key in a new directory\ncheck-public FILE               Validate bounded canonical public JSON\n\nPasswords use hidden local terminal prompts, never arguments or environment.\nNo plaintext private export, remote service or production signing command exists."
            );
            return Ok(());
        }
        _ => return Err("invalid command; use --help".into()),
    };
    // The only successful stdout payload is canonical public submission data.
    std::io::stdout()
        .lock()
        .write_all(&public.canonical_bytes()?)
        .map_err(|_| "cannot write public key record".into())
}
fn main() {
    if let Err(message) = run() {
        eprintln!("fund key operation failed: {message}");
        std::process::exit(1);
    }
}
