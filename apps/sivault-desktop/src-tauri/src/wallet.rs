use crate::adapter::{BridgeError, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Manager};
use zeroize::Zeroizing;

const WORKER: &str = "--sivault-wallet-worker";
const FILE: &str = "engineering-wallet.swnvlt";
const AVAILABLE: bool = cfg!(any(target_os = "macos", all(windows, debug_assertions)));
const ENGINEERING_NETWORK: &str =
    "06fa3ed71960f2d6add484afba453091a2536e718234df1187f33c0f7dcf5b5d";
const ENGINEERING_GENESIS: &str =
    "9cdb6925e53ff9b6ff12051a00d86ab965f33c3e2e806c4b9cd2f13f3984591d";

pub(crate) struct WalletScope {
    pub network: [u8; 32],
    pub genesis: [u8; 32],
    profile: Option<&'static str>,
}

impl WalletScope {
    pub(crate) fn load() -> Result<Self> {
        if cfg!(debug_assertions) {
            if let Some(spec) = std::env::var_os("SIVAULT_DEV_WALLET") {
                return Self::development(spec.to_str().ok_or_else(unavailable)?);
            }
        }
        Self::from_pins(ENGINEERING_NETWORK, ENGINEERING_GENESIS, None)
    }

    fn from_pins(network: &str, genesis: &str, profile: Option<&'static str>) -> Result<Self> {
        use siworld_native_wallet_core::{hex, hex_array};
        let net = hex_array(network).map_err(|_| unavailable())?;
        let genesis_id = hex_array(genesis).map_err(|_| unavailable())?;
        if hex(&net) != network || hex(&genesis_id) != genesis {
            return Err(unavailable());
        }
        Ok(Self {
            network: net,
            genesis: genesis_id,
            profile,
        })
    }

    pub(crate) fn development(spec: &str) -> Result<Self> {
        let mut fields = spec.split(':');
        let network = fields.next().ok_or_else(unavailable)?;
        let genesis = fields.next().ok_or_else(unavailable)?;
        let profile = match fields.next() {
            Some("a") => "a.swnvlt",
            Some("b") => "b.swnvlt",
            _ => return Err(unavailable()),
        };
        if fields.next().is_some()
            || network == ENGINEERING_NETWORK
            || genesis == ENGINEERING_GENESIS
        {
            return Err(unavailable());
        }
        Self::from_pins(network, genesis, Some(profile))
    }

    pub(crate) fn is_development(&self) -> bool {
        self.profile.is_some()
    }

    pub(crate) fn directory(&self, directory: &Path) -> PathBuf {
        use siworld_native_wallet_core::hex;
        if self.is_development() {
            let override_root = std::env::var_os("SIVAULT_DEV_WALLET_DATA")
                .map(PathBuf::from)
                .filter(|path| path.is_absolute());
            override_root
                .as_deref()
                .unwrap_or(directory)
                .join("isolated-wallets")
                .join(hex(&self.network))
                .join(hex(&self.genesis))
        } else {
            directory.to_path_buf()
        }
    }

    fn custody_file(&self, directory: &Path) -> PathBuf {
        self.directory(directory).join(self.profile.unwrap_or(FILE))
    }
}

#[derive(Default, Clone)]
pub struct Worker(Arc<Mutex<()>>);

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Create,
    Restore,
    Unlock,
}

impl Operation {
    fn arg(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Restore => "restore",
            Self::Unlock => "unlock",
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicWallet {
    address: String,
    short_address: String,
    #[serde(default)]
    published: bool,
    #[cfg(feature = "dev-wallet-chain")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    chain: Option<crate::wallet_chain::Summary>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum Reply {
    Open {
        wallet: PublicWallet,
    },
    #[cfg(feature = "dev-wallet-chain")]
    Sent {
        payment: crate::wallet_chain::PaymentStatus,
    },
    Cancelled,
    Error {
        code: String,
    },
}

fn unavailable() -> BridgeError {
    BridgeError::new("WALLET_UNAVAILABLE", "The wallet process is not available.")
}

#[tauri::command]
pub async fn wallet_status(app: AppHandle) -> Result<bool> {
    if !AVAILABLE {
        return Err(unavailable());
    }
    let directory = app.path().app_data_dir().map_err(|_| unavailable())?;
    match fs::symlink_metadata(WalletScope::load()?.custody_file(&directory)) {
        Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        _ => Err(unavailable()),
    }
}

#[tauri::command]
pub async fn wallet_access(app: AppHandle, operation: Operation) -> Result<Option<PublicWallet>> {
    let Reply::Open { mut wallet } = attempt(&app, operation.arg(), None).await? else {
        return Ok(None);
    };
    wallet.published =
        crate::wallet_endpoint::publish(&app, &wallet.address, &wallet.short_address)
            .await
            .unwrap_or(false);
    Ok(Some(wallet))
}

#[cfg(feature = "dev-wallet-chain")]
#[tauri::command]
pub async fn wallet_send(
    app: AppHandle,
    recipient: String,
    amount: String,
    fee: String,
) -> Result<Option<crate::wallet_chain::PaymentStatus>> {
    use crate::wallet_chain::SendRequest;
    let atoms = |text: &str| -> Result<u64> {
        if text.len() <= 20 {
            if let Ok(value) = text.parse::<u64>() {
                if value.to_string() == text {
                    return Ok(value);
                }
            }
        }
        Err(BridgeError::new(
            "WALLET_AMOUNT",
            "Use a whole number of SIP atoms.",
        ))
    };
    let amount = atoms(&amount)?;
    let fee = atoms(&fee)?;
    if amount == 0 || recipient.len() > 2048 + 10 {
        return Err(BridgeError::new(
            "WALLET_PAYMENT",
            "Enter a recipient and positive amount.",
        ));
    }
    let (origin, address, descriptor) =
        crate::wallet_endpoint::resolve_recipient(&app, &recipient).await?;
    let payload = serde_json::to_string(&SendRequest {
        address,
        descriptor,
        amount,
        fee,
    })
    .map_err(|_| unavailable())?;
    match attempt(&app, "send", Some((format!("http://{origin}"), payload))).await? {
        Reply::Sent { payment } => Ok(Some(payment)),
        Reply::Cancelled => Ok(None),
        _ => Err(unavailable()),
    }
}

#[cfg(not(feature = "dev-wallet-chain"))]
#[tauri::command]
pub async fn wallet_send() -> Result<()> {
    Err(unavailable())
}

#[cfg(feature = "dev-wallet-chain")]
#[tauri::command]
pub async fn wallet_retry_payment(
    app: AppHandle,
) -> Result<Option<crate::wallet_chain::PaymentStatus>> {
    match attempt(&app, "retry_payment", None).await? {
        Reply::Sent { payment } => Ok(Some(payment)),
        Reply::Cancelled => Ok(None),
        _ => Err(unavailable()),
    }
}

#[cfg(not(feature = "dev-wallet-chain"))]
#[tauri::command]
pub async fn wallet_retry_payment() -> Result<()> {
    Err(unavailable())
}

async fn attempt(
    app: &AppHandle,
    operation: &'static str,
    action: Option<(String, String)>,
) -> Result<Reply> {
    if !AVAILABLE {
        return Err(unavailable());
    }
    let worker = app.state::<Worker>().inner().clone();
    let directory = app.path().app_data_dir().map_err(|_| unavailable())?;
    let broker_app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = worker.0.try_lock().map_err(|_| unavailable())?;
        let scope = WalletScope::load()?;
        let path = scope.custody_file(&directory);
        fs::create_dir_all(path.parent().ok_or_else(unavailable)?).map_err(|_| unavailable())?;
        let exe = std::env::current_exe().map_err(|_| unavailable())?;
        let mut command = Command::new(exe);
        #[cfg(feature = "dev-wallet-chain")]
        {
            command.env_remove("SIVAULT_DEV_WALLET_ORIGIN");
            if scope.is_development() {
                if let Some(endpoint) = crate::wallet_endpoint::load(&scope.directory(&directory))
                    .ok()
                    .flatten()
                {
                    command.env("SIVAULT_DEV_WALLET_ORIGIN", format!("http://{endpoint}"));
                }
            }
            if let Some((origin, _)) = &action {
                command.env("SIVAULT_DEV_WALLET_ORIGIN", origin);
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            command.creation_flags(CREATE_NO_WINDOW);
        }
        let mut child = command
            .arg(WORKER)
            .arg(operation)
            .arg(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| unavailable())?;
        let result = (|| {
            let mut input = child.stdout.take().ok_or_else(unavailable)?;
            let mut output = child.stdin.take().ok_or_else(unavailable)?;
            if let Some((_, ref payload)) = action {
                write_secret(&mut output, Some(payload)).map_err(|_| unavailable())?;
            }
            broker(&broker_app, &mut input, &mut output)
        })();
        if result.is_err() {
            let _ = child.kill();
        }
        if !child.wait().map_err(|_| unavailable())?.success() {
            return Err(unavailable());
        }
        match result? {
            Reply::Error { code } => Err(match code.as_str() {
                "back_up" => {
                    BridgeError::new("WALLET_BACKUP", "Recovery confirmation did not match.")
                }
                "invalid_recovery" => BridgeError::new(
                    "WALLET_RECOVERY",
                    "The recovery words or checksum are invalid.",
                ),
                "invalid_password" => BridgeError::new(
                    "WALLET_PASSWORD",
                    "The password did not meet policy or did not unlock this wallet.",
                ),
                "already_exists" => {
                    BridgeError::new("WALLET_EXISTS", "An encrypted wallet already exists.")
                }
                "payment_network" => BridgeError::new(
                    "WALLET_NETWORK",
                    "The isolated chain could not be verified. Refresh and try again.",
                ),
                "payment_funds" => BridgeError::new(
                    "WALLET_FUNDS",
                    "There are not enough spendable funds for this payment and fee.",
                ),
                "payment_fee" => {
                    BridgeError::new("WALLET_FEE", "The fee changed. Refresh before sending.")
                }
                "payment_pending" => BridgeError::new(
                    "WALLET_PENDING",
                    "A previous payment has not been verified on-chain.",
                ),
                "payment_proof" => BridgeError::new(
                    "WALLET_PROOF",
                    "Payment proof generation failed. No payment was submitted.",
                ),
                "payment_journal" => BridgeError::new(
                    "WALLET_JOURNAL",
                    "The private payment journal is unavailable.",
                ),
                "payment_recipient" => BridgeError::new(
                    "WALLET_RECIPIENT",
                    "The resolved address could not be verified.",
                ),
                _ => unavailable(),
            }),
            reply => Ok(reply),
        }
    })
    .await
    .map_err(|_| unavailable())?
}

pub fn dispatch_worker() -> bool {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new(WORKER)) {
        return false;
    }
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let reply = match (args.next(), args.next(), args.next()) {
        (Some(op), Some(path), None) if AVAILABLE => run_worker(
            op.to_str().unwrap_or(""),
            Path::new(&path),
            &mut input,
            &mut output,
        ),
        _ => error("unavailable"),
    };
    let _ = output.write_all(b"D");
    let _ = serde_json::to_writer(&mut output, &reply);
    let _ = output.flush();
    true
}

fn error(code: &'static str) -> Reply {
    Reply::Error { code: code.into() }
}

#[cfg(any(target_os = "macos", windows))]
fn read_secret(input: &mut impl Read) -> std::io::Result<Option<Zeroizing<String>>> {
    let mut length = [0_u8; 2];
    input.read_exact(&mut length)?;
    let length = u16::from_be_bytes(length) as usize;
    if length == 0 {
        return Ok(None);
    }
    if length > 4096 {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let mut bytes = Zeroizing::new(vec![0_u8; length]);
    input.read_exact(&mut bytes)?;
    let value = std::str::from_utf8(&bytes).map_err(|_| std::io::ErrorKind::InvalidData)?;
    Ok(Some(Zeroizing::new(value.to_owned())))
}

fn write_secret(output: &mut impl Write, value: Option<&str>) -> std::io::Result<()> {
    let bytes = value.unwrap_or("").as_bytes();
    if bytes.len() > 4096 {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    output.write_all(&(bytes.len() as u16).to_be_bytes())?;
    output.write_all(bytes)?;
    output.flush()
}

fn broker(app: &AppHandle, input: &mut impl Read, output: &mut impl Write) -> Result<Reply> {
    for _ in 0..4 {
        let mut tag = [0_u8];
        input.read_exact(&mut tag).map_err(|_| unavailable())?;
        if tag == *b"D" {
            let mut reply = Vec::new();
            input
                .take(8193)
                .read_to_end(&mut reply)
                .map_err(|_| unavailable())?;
            if reply.len() > 8192 {
                return Err(unavailable());
            }
            return serde_json::from_slice(&reply).map_err(|_| unavailable());
        }
        #[cfg(all(feature = "dev-wallet-chain", any(target_os = "macos", windows)))]
        if tag == *b"T" {
            use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
            let details = read_secret(input)
                .map_err(|_| unavailable())?
                .ok_or_else(unavailable)?;
            let accepted = app
                .dialog()
                .message(details.to_string())
                .title(crate::locale::WALLET_CONFIRM_SEND)
                .buttons(MessageDialogButtons::OkCancelCustom(
                    crate::locale::WALLET_SEND.to_owned(),
                    crate::locale::WALLET_CANCEL.to_owned(),
                ))
                .blocking_show();
            write_secret(output, accepted.then_some("confirmed")).map_err(|_| unavailable())?;
            continue;
        }
        let value = broker_prompt(app, tag[0], input)?;
        write_secret(output, value.as_deref().map(String::as_str)).map_err(|_| unavailable())?;
    }
    Err(unavailable())
}

#[cfg(not(any(target_os = "macos", windows)))]
fn broker_prompt(_: &AppHandle, _: u8, _: &mut impl Read) -> Result<Option<Zeroizing<String>>> {
    Err(unavailable())
}

#[cfg(target_os = "macos")]
fn broker_prompt(
    app: &AppHandle,
    tag: u8,
    input: &mut impl Read,
) -> Result<Option<Zeroizing<String>>> {
    use crate::{
        locale as l,
        password::{native_secret, on_main},
    };
    match tag {
        b'P' => on_main(app, || {
            native_secret(l::WALLET_SET_PASSWORD, l::WALLET_PASSWORD, true)
        }),
        b'U' => on_main(app, || {
            native_secret(l::WALLET_UNLOCK, l::WALLET_PASSWORD, false)
        }),
        b'R' => on_main(app, || {
            native_secret(l::WALLET_RESTORE, l::WALLET_WORDS, false)
        }),
        b'B' => {
            let (positions, words) = read_backup(input)?;
            on_main(app, move || {
                use objc2::MainThreadMarker;
                use objc2_app_kit::{NSAlert, NSAlertFirstButtonReturn};
                use objc2_foundation::NSString;
                let mtm = MainThreadMarker::new().ok_or_else(unavailable)?;
                let alert = NSAlert::new(mtm);
                alert.setMessageText(&NSString::from_str(l::WALLET_BACKUP));
                alert.setInformativeText(&NSString::from_str(&words));
                alert.addButtonWithTitle(&NSString::from_str(l::CONTINUE));
                alert.addButtonWithTitle(&NSString::from_str(l::CANCEL));
                let accepted = alert.runModal() == NSAlertFirstButtonReturn;
                alert.setInformativeText(&NSString::from_str(""));
                drop(words);
                if !accepted {
                    return Ok(None);
                }
                let label = l::wallet_backup_positions(positions);
                native_secret(l::WALLET_BACKUP_CONFIRM, &label, false)
            })
        }
        _ => Err(unavailable()),
    }
}

#[cfg(windows)]
fn broker_prompt(
    app: &AppHandle,
    tag: u8,
    input: &mut impl Read,
) -> Result<Option<Zeroizing<String>>> {
    use crate::{locale as l, password::windows_prompt};
    let (title, confirm) = match tag {
        b'P' => (Zeroizing::new(l::WALLET_SET_PASSWORD.into()), true),
        b'U' => (Zeroizing::new(l::WALLET_UNLOCK.into()), false),
        b'R' => (Zeroizing::new(l::WALLET_WINDOWS_RESTORE.into()), false),
        b'B' => {
            let (positions, words) = read_backup(input)?;
            let mut title = Zeroizing::new(String::with_capacity(words.len() + 160));
            title.push_str(l::WALLET_BACKUP);
            title.push_str("\n\n");
            title.push_str(&words);
            title.push_str("\n\n");
            title.push_str(l::WALLET_BACKUP_CONFIRM);
            title.push_str(": ");
            title.push_str(&l::wallet_backup_positions(positions));
            (title, false)
        }
        _ => return Err(unavailable()),
    };
    windows_prompt(app, title, confirm)
}

#[cfg(any(target_os = "macos", windows))]
fn read_backup(input: &mut impl Read) -> Result<([usize; 3], Zeroizing<String>)> {
    let mut positions = [0_u8; 3];
    input
        .read_exact(&mut positions)
        .map_err(|_| unavailable())?;
    if !positions.iter().all(|i| (1..=24).contains(i)) {
        return Err(unavailable());
    }
    let words = read_secret(input)
        .map_err(|_| unavailable())?
        .ok_or_else(unavailable)?;
    Ok((positions.map(usize::from), words))
}

#[cfg(not(any(target_os = "macos", windows)))]
fn run_worker(_: &str, _: &Path, _: &mut impl Read, _: &mut impl Write) -> Reply {
    error("unavailable")
}

#[cfg(any(target_os = "macos", windows))]
fn run_worker(op: &str, path: &Path, input: &mut impl Read, output: &mut impl Write) -> Reply {
    #[cfg(feature = "dev-wallet-chain")]
    if matches!(op, "send" | "retry_payment") {
        return match send_worker(path, input, output, op == "retry_payment") {
            Ok(Some(payment)) => Reply::Sent { payment },
            Ok(None) => Reply::Cancelled,
            Err(code) => error(code),
        };
    }
    match custody(op, path, input, output) {
        Ok(Some(wallet)) => Reply::Open { wallet },
        Ok(None) => Reply::Cancelled,
        Err(code) => error(code),
    }
}

#[cfg(all(feature = "dev-wallet-chain", any(target_os = "macos", windows)))]
fn send_worker(
    path: &Path,
    input: &mut impl Read,
    output: &mut impl Write,
    retry: bool,
) -> std::result::Result<Option<crate::wallet_chain::PaymentStatus>, &'static str> {
    use siworld_native_wallet_core::vault::{Material, VAULT_LEN};
    let scope = WalletScope::load().map_err(|_| "unavailable")?;
    if !scope.is_development() {
        return Err("unavailable");
    }
    let origin = std::env::var("SIVAULT_DEV_WALLET_ORIGIN").map_err(|_| "payment_network")?;
    let endpoint = crate::wallet_endpoint::parse(&origin)
        .map_err(|_| "payment_network")?
        .ok_or("payment_network")?;
    let payment = if retry {
        None
    } else {
        let payload = read_secret(input)
            .map_err(|_| "unavailable")?
            .ok_or("unavailable")?;
        Some(serde_json::from_str(&payload).map_err(|_| "unavailable")?)
    };
    let mut bytes = Vec::new();
    open_custody_file(path)
        .and_then(|file| file.take((VAULT_LEN + 1) as u64).read_to_end(&mut bytes))
        .map_err(|_| "unavailable")?;
    let Some(password) = request(input, output, b'U')? else {
        return Ok(None);
    };
    let material =
        Material::open(&bytes, &password, scope.network).map_err(|_| "invalid_password")?;
    drop(password);
    let Some(payment) = payment else {
        return crate::wallet_chain::retry(endpoint, &scope, &material, path);
    };
    crate::wallet_chain::send(endpoint, &scope, &material, path, payment, |payment| {
        let details =
            crate::locale::wallet_payment_details(&payment.address, payment.amount, payment.fee);
        output.write_all(b"T").map_err(|_| "unavailable")?;
        write_secret(output, Some(&details)).map_err(|_| "unavailable")?;
        Ok(read_secret(input)
            .map_err(|_| "unavailable")?
            .is_some_and(|value| *value == "confirmed"))
    })
}

#[cfg(any(target_os = "macos", windows))]
fn request(
    input: &mut impl Read,
    output: &mut impl Write,
    tag: u8,
) -> std::result::Result<Option<Zeroizing<String>>, &'static str> {
    output
        .write_all(&[tag])
        .and_then(|_| output.flush())
        .map_err(|_| "unavailable")?;
    read_secret(input).map_err(|_| "unavailable")
}

#[cfg(any(target_os = "macos", windows))]
fn open_custody_file(path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
    }
    Ok(file)
}

#[cfg(any(target_os = "macos", windows))]
fn custody(
    op: &str,
    path: &Path,
    input: &mut impl Read,
    output: &mut impl Write,
) -> std::result::Result<Option<PublicWallet>, &'static str> {
    use siworld_native_wallet_core::{
        address,
        identity::Identity,
        recipient::{Descriptor, Network},
        vault::Material,
    };

    let scope = WalletScope::load().map_err(|_| "unavailable")?;
    let network = scope.network;
    let material = match op {
        "unlock" => {
            let meta = fs::symlink_metadata(path).map_err(|_| "unavailable")?;
            if !meta.is_file() {
                return Err("unavailable");
            }
            let mut bytes = Vec::new();
            open_custody_file(path)
                .map_err(|_| "unavailable")?
                .take((siworld_native_wallet_core::vault::VAULT_LEN + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| "unavailable")?;
            let Some(password) = request(input, output, b'U')? else {
                return Ok(None);
            };
            Material::open(&bytes, &password, network).map_err(|_| "invalid_password")?
        }
        "create" | "restore" => {
            match fs::symlink_metadata(path) {
                Ok(_) => return Err("already_exists"),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err("unavailable"),
            }
            let new = if op == "create" {
                let new = Material::generate(network, 0).map_err(|_| "unavailable")?;
                if !confirm_backup(&new, input, output)? {
                    return Ok(None);
                }
                new
            } else {
                let Some(words) = request(input, output, b'R')? else {
                    return Ok(None);
                };
                Material::restore(network, 0, words).map_err(|_| "invalid_recovery")?
            };
            let Some(password) = request(input, output, b'P')? else {
                return Ok(None);
            };
            let encrypted = new.seal(&password).map_err(|_| "invalid_password")?;
            let checked =
                Material::open(&encrypted, &password, network).map_err(|_| "unavailable")?;
            let directory = path.parent().ok_or("unavailable")?;
            let mut temp = tempfile::NamedTempFile::new_in(directory).map_err(|_| "unavailable")?;
            temp.write_all(&encrypted).map_err(|_| "unavailable")?;
            temp.as_file().sync_all().map_err(|_| "unavailable")?;
            temp.persist_noclobber(path).map_err(|_| "unavailable")?;
            #[cfg(target_os = "macos")]
            fs::File::open(directory)
                .and_then(|handle| handle.sync_all())
                .map_err(|_| "unavailable")?;
            checked
        }
        _ => return Err("unavailable"),
    };
    let identity = Identity::derive(&material.entropy, network, material.account)
        .map_err(|_| "unavailable")?;
    let address = address::full(network, identity.address()).map_err(|_| "unavailable")?;
    let short_address = Descriptor::new_v2(Network::Testnet, scope.genesis, identity.address())
        .map_err(|_| "unavailable")?
        .short_address()
        .encode();
    Ok(Some(PublicWallet {
        address,
        short_address,
        published: false,
        #[cfg(feature = "dev-wallet-chain")]
        chain: std::env::var("SIVAULT_DEV_WALLET_ORIGIN")
            .ok()
            .and_then(|origin| crate::wallet_endpoint::parse(&origin).ok().flatten())
            .and_then(|endpoint| {
                crate::wallet_chain::summarize(endpoint, &scope, &material, path).ok()
            }),
    }))
}

#[cfg(any(target_os = "macos", windows))]
fn confirm_backup(
    material: &siworld_native_wallet_core::vault::Material,
    input: &mut impl Read,
    output: &mut impl Write,
) -> std::result::Result<bool, &'static str> {
    let positions = siworld_native_wallet_core::vault::challenge().map_err(|_| "unavailable")?;
    let words = material.words();
    output
        .write_all(b"B")
        .and_then(|_| output.write_all(&positions.map(|n| n as u8)))
        .map_err(|_| "unavailable")?;
    write_secret(output, Some(&words)).map_err(|_| "unavailable")?;
    let Some(answer) = read_secret(input).map_err(|_| "unavailable")? else {
        return Ok(false);
    };
    let supplied: Vec<_> = answer.split(' ').collect();
    if supplied.len() != positions.len()
        || positions
            .iter()
            .zip(supplied)
            .any(|(p, word)| words.split(' ').nth(p - 1) != Some(word))
    {
        return Err("back_up");
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_replies_reject_unexpected_fields() {
        let input = br#"{"status":"open","wallet":{"address":"test","short_address":"short","password":"unexpected"}}"#;
        assert!(serde_json::from_slice::<Reply>(input).is_err());
        assert!(serde_json::from_slice::<Reply>(br#"{"status":"cancelled"}"#).is_ok());
    }

    #[cfg(any(target_os = "macos", windows))]
    #[test]
    fn synthetic_restore_and_unlock_preserve_receiving_address() {
        use siworld_native_wallet_core::{network, vault::Material};
        let network =
            network("06fa3ed71960f2d6add484afba453091a2536e718234df1187f33c0f7dcf5b5d").unwrap();
        let fixture = Material::generate(network, 0).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(FILE);
        let password = "Synthetic custody fixture 42";
        let mut restore = Vec::new();
        write_secret(&mut restore, Some(&fixture.words())).unwrap();
        write_secret(&mut restore, Some(password)).unwrap();
        let mut prompts = Vec::new();
        let Reply::Open { wallet: restored } =
            run_worker("restore", &path, &mut restore.as_slice(), &mut prompts)
        else {
            panic!("fixture recovery failed");
        };
        assert_eq!(prompts, b"RP");
        assert_eq!(&fs::read(&path).unwrap()[..8], b"SWNVLT01");

        let mut unlock = Vec::new();
        write_secret(&mut unlock, Some(password)).unwrap();
        prompts.clear();
        let Reply::Open { wallet: opened } =
            run_worker("unlock", &path, &mut unlock.as_slice(), &mut prompts)
        else {
            panic!("fixture unlock failed");
        };
        assert_eq!(prompts, b"U");
        assert_eq!(restored.address, opened.address);
        assert_eq!(restored.short_address, opened.short_address);
        assert!(opened.short_address.starts_with("tsi1p"));
        assert_eq!(opened.short_address.len(), 63);
    }
}
