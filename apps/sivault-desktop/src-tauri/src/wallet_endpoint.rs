use crate::adapter::{BridgeError, Result};
use crate::wallet::WalletScope;
use serde::Deserialize;
use siworld_native_wallet_core::{
    hex, hex_array,
    recipient::{
        Directory, MAX_DIRECTORY_ENTRIES, MAX_DIRECTORY_PAGE, Network, ShortAddress, Snapshot,
        V2_LEN,
    },
};
use std::fs::{self, File};
use std::io::{ErrorKind, Read, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
#[cfg(feature = "dev-wallet-chain")]
use std::{sync::Mutex, time::Instant};
use tauri::{AppHandle, Manager};

const FILE: &str = "wallet-endpoint";
const MAX_LEN: usize = 64;
const MAX_HEAD_BYTES: usize = 20_000;

#[cfg(feature = "dev-wallet-chain")]
#[derive(Default)]
pub struct DirectoryCache(Mutex<Option<(SocketAddr, Instant, Directory)>>);

#[cfg(feature = "dev-wallet-chain")]
impl DirectoryCache {
    fn replace(&self, addr: SocketAddr, directory: Directory) -> Result<()> {
        *self.0.lock().map_err(|_| probe_error())? = Some((addr, Instant::now(), directory));
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Head {
    version: u8,
    network: String,
    genesis: String,
    rules: String,
    profile: String,
    fee_mode: u8,
    pub(crate) height: u64,
    pub(crate) tip: String,
    pub(crate) published_unix_seconds: u64,
}

impl Head {
    pub(crate) fn well_formed(&self) -> bool {
        self.version == 2
            && self.fee_mode == 0
            && self.height <= 100_000
            && (1..=(1 << 53) - 1).contains(&self.published_unix_seconds)
            && (self.height != 0 || self.tip == self.genesis)
            && [
                &self.network,
                &self.genesis,
                &self.rules,
                &self.profile,
                &self.tip,
            ]
            .iter()
            .all(|hash| {
                hash.len() == 64
                    && hash
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
    }
}

fn probe_error() -> BridgeError {
    BridgeError::new(
        "WALLET_ENDPOINT_PROBE",
        "The endpoint did not return a valid engineering wallet response.",
    )
}

async fn probe(addr: SocketAddr) -> Result<()> {
    let head: Head = get_head(&client()?, addr).await?;
    let scope = WalletScope::load()?;
    if scope.is_development() && !head.matches(&scope) {
        return Err(probe_error());
    }
    Ok(())
}

impl Head {
    pub(crate) fn matches(&self, scope: &WalletScope) -> bool {
        use siworld_native_wallet_core::hex;
        self.network == hex(&scope.network) && self.genesis == hex(&scope.genesis)
    }
}

fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|_| probe_error())
}

async fn get_head(client: &reqwest::Client, addr: SocketAddr) -> Result<Head> {
    let response = client
        .get(format!("http://{addr}/api/v2/wallet/head"))
        .send()
        .await
        .map_err(|_| probe_error())?;
    let body = bounded(response, MAX_HEAD_BYTES).await?;
    let head: Head = serde_json::from_slice(&body).map_err(|_| probe_error())?;
    if !head.well_formed() {
        return Err(probe_error());
    }
    Ok(head)
}

async fn bounded(mut response: reqwest::Response, max: usize) -> Result<Vec<u8>> {
    if response.status() != reqwest::StatusCode::OK
        || response
            .content_length()
            .is_some_and(|len| len > max as u64)
    {
        return Err(probe_error());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| probe_error())? {
        if chunk.len() > max - body.len() {
            return Err(probe_error());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn invalid() -> BridgeError {
    BridgeError::new(
        "WALLET_ENDPOINT_INVALID",
        "Enter a loopback HTTP origin with an explicit port.",
    )
}

fn storage_error() -> BridgeError {
    BridgeError::new(
        "WALLET_ENDPOINT_STORAGE",
        "Wallet endpoint settings are unavailable.",
    )
}

pub(crate) fn parse(value: &str) -> Result<Option<SocketAddr>> {
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > MAX_LEN {
        return Err(invalid());
    }
    let addr: SocketAddr = value
        .strip_prefix("http://")
        .and_then(|authority| authority.parse().ok())
        .ok_or_else(invalid)?;
    if !addr.ip().is_loopback()
        || addr.port() == 0
        || matches!(addr, SocketAddr::V6(v6) if v6.scope_id() != 0)
        || format!("http://{addr}") != value
    {
        return Err(invalid());
    }
    Ok(Some(addr))
}

pub(crate) fn load(directory: &Path) -> Result<Option<SocketAddr>> {
    let path = directory.join(FILE);
    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_file() && meta.len() <= MAX_LEN as u64 => {}
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        _ => return Err(storage_error()),
    }
    let mut contents = String::new();
    File::open(path)
        .and_then(|file| {
            file.take((MAX_LEN + 1) as u64)
                .read_to_string(&mut contents)
        })
        .map_err(|_| storage_error())?;
    parse(&contents)
}

fn save(directory: &Path, origin: &str) -> Result<()> {
    parse(origin)?;
    fs::create_dir_all(directory).map_err(|_| storage_error())?;
    let mut temp = tempfile::NamedTempFile::new_in(directory).map_err(|_| storage_error())?;
    temp.write_all(origin.as_bytes())
        .map_err(|_| storage_error())?;
    temp.as_file().sync_all().map_err(|_| storage_error())?;
    temp.persist(directory.join(FILE))
        .map_err(|_| storage_error())?;
    Ok(())
}

#[tauri::command]
pub fn wallet_endpoint(app: AppHandle) -> Result<Option<String>> {
    let directory = app.path().app_data_dir().map_err(|_| storage_error())?;
    Ok(load(&WalletScope::load()?.directory(&directory))?.map(|addr| format!("http://{addr}")))
}

#[tauri::command]
pub fn wallet_set_endpoint(app: AppHandle, origin: String) -> Result<()> {
    let directory = app.path().app_data_dir().map_err(|_| storage_error())?;
    save(&WalletScope::load()?.directory(&directory), &origin)
}

#[tauri::command]
pub async fn wallet_probe_endpoint(app: AppHandle) -> Result<()> {
    let directory = app.path().app_data_dir().map_err(|_| storage_error())?;
    probe(load(&WalletScope::load()?.directory(&directory))?.ok_or_else(invalid)?).await
}

pub(crate) async fn publish(app: &AppHandle, address: &str, short: &str) -> Result<bool> {
    use siworld_native_wallet_core::{
        address::resolve,
        recipient::{Descriptor, Network},
    };
    let scope = WalletScope::load()?;
    if !scope.is_development() {
        return Ok(false);
    }
    let directory = app.path().app_data_dir().map_err(|_| storage_error())?;
    let Some(addr) = load(&scope.directory(&directory))? else {
        return Ok(false);
    };
    let client = client()?;
    if !get_head(&client, addr).await?.matches(&scope) {
        return Err(probe_error());
    }
    let recipient = resolve(address, scope.network, None).map_err(|_| probe_error())?;
    let descriptor = Descriptor::new_v2(Network::Testnet, scope.genesis, &recipient)
        .map_err(|_| probe_error())?;
    if descriptor.short_address().encode() != short {
        return Err(probe_error());
    }
    let mut packet = short.as_bytes().to_vec();
    packet.extend_from_slice(descriptor.encode());
    let url = format!("http://{addr}/api/v2/wallet/directory");
    let response = client
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
        .body(packet)
        .send()
        .await
        .map_err(|_| probe_error())?;
    let reply: serde_json::Value =
        serde_json::from_slice(&bounded(response, 64).await?).map_err(|_| probe_error())?;
    if reply != serde_json::json!({"published": true}) {
        return Ok(false);
    }
    let local = sync_directory(&client, &url, scope.genesis).await?;
    let published = local.resolve_native(short) == Ok(&recipient);
    #[cfg(feature = "dev-wallet-chain")]
    app.state::<DirectoryCache>().replace(addr, local)?;
    Ok(published)
}

#[cfg(feature = "dev-wallet-chain")]
#[tauri::command]
pub async fn wallet_refresh_directory(app: AppHandle) -> Result<()> {
    let scope = WalletScope::load()?;
    if !scope.is_development() {
        return Ok(());
    }
    let directory = app.path().app_data_dir().map_err(|_| storage_error())?;
    let addr = load(&scope.directory(&directory))?.ok_or_else(invalid)?;
    let client = client()?;
    if !get_head(&client, addr).await?.matches(&scope) {
        return Err(probe_error());
    }
    let url = format!("http://{addr}/api/v2/wallet/directory");
    let local = sync_directory(&client, &url, scope.genesis).await?;
    app.state::<DirectoryCache>().replace(addr, local)
}

#[cfg(not(feature = "dev-wallet-chain"))]
#[tauri::command]
pub async fn wallet_refresh_directory() -> Result<()> {
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryHead {
    id: String,
    count: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryPage {
    next: Option<usize>,
    entries: Vec<(String, String)>,
}

async fn directory_get<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    max: usize,
) -> Result<T> {
    let response = client.get(url).send().await.map_err(|_| probe_error())?;
    serde_json::from_slice(&bounded(response, max).await?).map_err(|_| probe_error())
}

async fn sync_directory(
    client: &reqwest::Client,
    url: &str,
    genesis: [u8; 32],
) -> Result<Directory> {
    let head: DirectoryHead = directory_get(client, url, 256).await?;
    let id = hex_array(&head.id).map_err(|_| probe_error())?;
    if head.count > MAX_DIRECTORY_ENTRIES || head.id != hex(&id) {
        return Err(probe_error());
    }
    let mut directory = Directory::new(Network::Testnet, genesis);
    let mut last = None;
    for offset in (0..head.count).step_by(MAX_DIRECTORY_PAGE) {
        let page: DirectoryPage = directory_get(
            client,
            &format!(
                "{url}/page?id={}&count={}&offset={offset}&limit={MAX_DIRECTORY_PAGE}",
                head.id, head.count
            ),
            180_000,
        )
        .await?;
        let count = MAX_DIRECTORY_PAGE.min(head.count - offset);
        let end = offset + count;
        if page.entries.len() != count || page.next != (end < head.count).then_some(end) {
            return Err(probe_error());
        }
        for (address, descriptor) in page.entries {
            let short = ShortAddress::parse(&address).map_err(|_| probe_error())?;
            if last.is_some_and(|id| short.id <= id) || address != short.encode() {
                return Err(probe_error());
            }
            let bytes = hex_array::<V2_LEN>(&descriptor).map_err(|_| probe_error())?;
            directory
                .insert_expected(short, &bytes)
                .map_err(|_| probe_error())?;
            last = Some(short.id);
        }
    }
    if directory.snapshot()
        != (Snapshot {
            id,
            count: head.count,
        })
    {
        return Err(probe_error());
    }
    Ok(directory)
}

#[cfg(feature = "dev-wallet-chain")]
pub(crate) async fn resolve_recipient(
    app: &AppHandle,
    recipient: &str,
) -> Result<(SocketAddr, String, String)> {
    use siworld_native_wallet_core::{address, recipient::Descriptor};
    let scope = WalletScope::load()?;
    if !scope.is_development() {
        return Err(probe_error());
    }
    let directory = app.path().app_data_dir().map_err(|_| storage_error())?;
    let addr = load(&scope.directory(&directory))?.ok_or_else(invalid)?;
    let descriptor = if recipient.starts_with("sivf1") {
        let bytes = address::resolve(recipient, scope.network, None).map_err(|_| {
            BridgeError::new(
                "WALLET_RECIPIENT",
                "The full address is invalid for this network.",
            )
        })?;
        Descriptor::new_v2(Network::Testnet, scope.genesis, &bytes).map_err(|_| probe_error())?
    } else {
        let short = ShortAddress::parse(recipient)
            .map_err(|_| BridgeError::new("WALLET_RECIPIENT", "The short address is invalid."))?;
        if short.network != Network::Testnet {
            return Err(BridgeError::new(
                "WALLET_RECIPIENT",
                "The address is for a different network.",
            ));
        }
        let cache = app.state::<DirectoryCache>();
        let cache = cache.0.lock().map_err(|_| probe_error())?;
        let (_, _, local) = cache.as_ref().filter(|(origin, loaded, _)| {
            *origin == addr && loaded.elapsed() <= Duration::from_secs(90)
        }).ok_or_else(|| BridgeError::new(
            "WALLET_DIRECTORY", "The address directory is not synchronized. You can paste the full address instead.",
        ))?;
        local.descriptor(recipient).cloned().map_err(|_| BridgeError::new(
            "WALLET_RECIPIENT_MISSING",
            "The recipient has not published this address. You can paste the full address instead.",
        ))?
    };
    Ok((
        addr,
        descriptor.short_address().encode(),
        hex(descriptor.encode()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;

    #[test]
    fn only_literal_loopback_http_origins_are_accepted() {
        for origin in ["http://127.0.0.1:8180", "http://[::1]:8180"] {
            assert!(parse(origin).unwrap().is_some(), "{origin}");
        }
        for origin in [
            "http://localhost:8180",
            "http://0.0.0.0:8180",
            "http://192.0.2.1:8180",
            "https://127.0.0.1:8180",
            "http://127.0.0.1",
            "http://127.0.0.1:0",
            "http://127.0.0.1:8180/",
            "http://127.0.0.1:8180?x",
            "http://127.0.0.1:8180#x",
            "http://user@127.0.0.1:8180",
            "http://[::1%1]:8180",
            "http://127.0.0.1:08180",
        ] {
            assert!(parse(origin).is_err(), "{origin}");
        }
    }

    #[test]
    fn endpoint_can_be_replaced_or_cleared_without_touching_custody() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path();
        assert_eq!(load(path).unwrap(), None);
        save(path, "http://127.0.0.1:8180").unwrap();
        assert!(save(path, "http://192.0.2.1:8180").is_err());
        assert_eq!(load(path).unwrap().unwrap().port(), 8180);
        save(path, "http://127.0.0.1:8181").unwrap();
        assert_eq!(load(path).unwrap().unwrap().port(), 8181);
        save(path, "").unwrap();
        assert_eq!(load(path).unwrap(), None);
        assert_eq!(fs::read_dir(path).unwrap().count(), 1);
    }

    fn serve_once(status: &'static str, headers: &'static str, body: String) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut reader = BufReader::new(&mut stream);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert_eq!(line, "GET /api/v2/wallet/head HTTP/1.1\r\n");
            while line != "\r\n" && !line.is_empty() {
                line.clear();
                reader.read_line(&mut line).unwrap();
            }
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nConnection: close\r\n{headers}\r\n{body}"
            );
        });
        addr
    }

    #[test]
    fn probe_accepts_only_bounded_wallet_head_responses() {
        let id = "a".repeat(64);
        let valid = serde_json::json!({
            "version": 2, "network": id, "genesis": id, "rules": id, "profile": id,
            "fee_mode": 0, "height": 0, "tip": id, "published_unix_seconds": 1000,
        });
        let redirected = serve_once(
            "302 Found",
            "Location: http://127.0.0.1:1/\r\n",
            String::new(),
        );
        let invalid = serve_once("200 OK", "", "{}".into());
        let oversized = serve_once("200 OK", "", "x".repeat(MAX_HEAD_BYTES + 1));
        let valid = serve_once("200 OK", "", valid.to_string());
        tauri::async_runtime::block_on(async {
            assert!(probe(redirected).await.is_err());
            assert!(probe(invalid).await.is_err());
            assert!(probe(oversized).await.is_err());
            assert!(probe(valid).await.is_ok());
        });
    }
}
