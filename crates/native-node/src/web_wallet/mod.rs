//! Loopback-only engineering wallet. Independent idle-history replay is required
//! before balances are shown; network sending and asset issuance are unavailable.
use crate::{
    local,
    proofs::NativeVerifier,
    state::{BlockVerifier, Config},
    wallet_vault::{PaymentStatus, UnlockedWallet, WalletVault},
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::{Zeroize, Zeroizing};
const HEADER_LIMIT: usize = 8192;
const BODY_LIMIT: usize = 8192;
const IDLE_SECONDS: u64 = 600;
const SESSION_SECONDS: u64 = 3600;
const COOKIE: &str = "sw_wallet_session";
const IO_SECONDS: u64 = 5;
const MAX_BLOCKS: u64 = 64;
const MAX_HISTORY_BYTES: usize = 4 * 1024 * 1024 * 1024;

struct DeadlineVerifier<'a, V> {
    inner: &'a V,
    deadline: Instant,
}
impl<V> DeadlineVerifier<'_, V> {
    fn check(&self) -> Result<(), String> {
        if Instant::now() >= self.deadline {
            Err("wallet session expired during verification".into())
        } else {
            Ok(())
        }
    }
}
impl<V: BlockVerifier> BlockVerifier for DeadlineVerifier<'_, V> {
    fn issuance(&self, record: &crate::issuance::IssuanceRecord) -> Result<(), String> {
        self.check()?;
        let result = self.inner.issuance(record);
        self.check()?;
        result
    }
    fn transaction(
        &self,
        public: &native::codec::PublicTransaction,
        context: &native::codec::ProofContext,
        fee: &native::multi_asset::Digest,
        root: &native::multi_asset::Digest,
        proof: &[u8],
    ) -> Result<(), String> {
        self.check()?;
        let result = self.inner.transaction(public, context, fee, root, proof);
        self.check()?;
        result
    }
    fn settlement(
        &self,
        fees: &[native::multi_asset::Digest],
        plan: &native::settlement::RewardPlan,
        network: crate::wire::Hash,
        list_hash: crate::wire::Hash,
        rewards: &[native::multi_asset::Digest],
        proof: &[u8],
    ) -> Result<(), String> {
        self.check()?;
        let result = self
            .inner
            .settlement(fees, plan, network, list_hash, rewards, proof);
        self.check()?;
        result
    }
}

pub struct Options {
    pub chain_dir: PathBuf,
    pub wallet_dir: PathBuf,
    pub auth_file: PathBuf,
    pub port: u16,
}
fn random_hex() -> Result<Zeroizing<String>, String> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|_| "OS entropy unavailable")?;
    Ok(Zeroizing::new(local::hex(bytes.as_slice())))
}
fn digest(text: &str) -> blake3::Hash {
    blake3::hash(text.as_bytes())
}
fn private_directory(path: &Path) -> Result<(), String> {
    let m = fs::symlink_metadata(path).map_err(|_| "private directory unavailable")?;
    if !m.is_dir() || m.file_type().is_symlink() {
        return Err("expected a real private directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if m.permissions().mode() & 0o077 != 0 {
            return Err("directory permissions must be private".into());
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        Err("operating-system privacy policy is not implemented".into())
    }
}
fn read_secret(path: &Path, max: usize) -> Result<Zeroizing<Vec<u8>>, String> {
    let parent = path.parent().ok_or("private file needs explicit parent")?;
    private_directory(parent)?;
    let file = local::regular_read(path, true, max)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = file
            .metadata()
            .map_err(|_| "private file metadata unavailable")?;
        let p = fs::metadata(parent).map_err(|_| "private parent unavailable")?;
        if m.nlink() != 1 || m.uid() != p.uid() {
            return Err("private file owner or aliases invalid".into());
        }
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take((max + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "private file read failed")?;
    if bytes.len() > max {
        return Err("private file limit".into());
    }
    Ok(bytes)
}
fn exclusive_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    private_directory(path.parent().ok_or("private file needs explicit parent")?)?;
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o
        .open(path)
        .map_err(|_| "refusing to replace private file")?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|_| "private file durability failed")?;
    File::open(path.parent().ok_or("private parent missing")?)
        .and_then(|p| p.sync_all())
        .map_err(|_| "private directory durability failed".to_owned())
}
/// Create one random local access token exclusively; never prints it.
pub fn keygen(auth: &Path) -> Result<(), String> {
    private_directory(auth.parent().ok_or("auth parent missing")?)?;
    exclusive_write(auth, random_hex()?.as_bytes())
}

struct Lease {
    path: PathBuf,
    contents: String,
}
impl Lease {
    fn new(dir: &Path, instance: &str) -> Result<Self, String> {
        let path = dir.join(".wallet-web-owner");
        let contents = format!("{} {instance}\n", std::process::id());
        exclusive_write(&path, contents.as_bytes())?;
        Ok(Self { path, contents })
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if fs::read(&self.path).ok().as_deref() == Some(self.contents.as_bytes()) {
            let _ = fs::remove_file(&self.path);
        }
    }
}
struct Session {
    cookie: blake3::Hash,
    csrf: blake3::Hash,
    created: Instant,
    touched: Instant,
    credentials: Option<(String, String)>,
}
impl Session {
    fn new(now: Instant) -> Result<Self, String> {
        let cookie = random_hex()?;
        let csrf = random_hex()?;
        Ok(Self {
            cookie: digest(&cookie),
            csrf: digest(&csrf),
            created: now,
            touched: now,
            credentials: Some((cookie.to_string(), csrf.to_string())),
        })
    }
    fn alive(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.created) <= Duration::from_secs(SESSION_SECONDS)
            && now.saturating_duration_since(self.touched) <= Duration::from_secs(IDLE_SECONDS)
    }
    fn authorize(&self, cookie: Option<&str>, csrf: Option<&str>, now: Instant) -> bool {
        if !self.alive(now)
            || cookie.is_none_or(|v| digest(v) != self.cookie)
            || csrf.is_none_or(|v| digest(v) != self.csrf)
        {
            return false;
        }
        true
    }
}
struct Request {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Zeroizing<Vec<u8>>,
}
impl Drop for Request {
    fn drop(&mut self) {
        for value in self.headers.values_mut() {
            value.zeroize();
        }
    }
}
fn session_cookie(value: &str) -> Option<&str> {
    let mut found = None;
    for field in value.split(';') {
        let (name, value) = field.trim().split_once('=')?;
        if name == COOKIE {
            if found.is_some() || value.len() != 64 {
                return None;
            }
            found = Some(value);
        }
    }
    found
}
fn parse_request(bytes: &[u8], host: &str) -> Result<Request, String> {
    let end = bytes
        .windows(4)
        .position(|v| v == b"\r\n\r\n")
        .ok_or("incomplete HTTP header")?;
    if end + 4 > HEADER_LIMIT {
        return Err("HTTP header limit".into());
    }
    let h = std::str::from_utf8(&bytes[..end]).map_err(|_| "invalid HTTP header")?;
    let mut lines = h.split("\r\n");
    let first = lines.next().ok_or("missing HTTP request")?;
    let p: Vec<_> = first.split(' ').collect();
    if p.len() != 3
        || p[2] != "HTTP/1.1"
        || !matches!(p[0], "GET" | "POST")
        || !p[1].starts_with('/')
        || p[1].contains(['?', '#', '%'])
    {
        return Err("unsupported HTTP request".into());
    }
    let mut headers = BTreeMap::new();
    for line in lines {
        let (k, v) = line.split_once(':').ok_or("invalid HTTP field")?;
        if k.is_empty()
            || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || v.bytes().any(|b| b < 32 && b != b'\t')
        {
            return Err("invalid HTTP field".into());
        }
        if headers
            .insert(k.to_ascii_lowercase(), v.trim().to_owned())
            .is_some()
        {
            return Err("duplicate HTTP field".into());
        }
    }
    if headers.get("host").map(String::as_str) != Some(host)
        || headers.contains_key("transfer-encoding")
        || headers.contains_key("expect")
    {
        return Err("HTTP authority or framing rejected".into());
    }
    let origin = format!("http://{host}");
    if headers.get("origin").is_some_and(|v| v != &origin) {
        return Err("HTTP origin rejected".into());
    }
    let body = bytes.get(end + 4..).ok_or("invalid HTTP body")?;
    let length = match headers.get("content-length") {
        Some(v) if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) => {
            v.parse::<usize>().map_err(|_| "HTTP length overflow")?
        }
        None => 0,
        _ => return Err("invalid HTTP length".into()),
    };
    if length > BODY_LIMIT || body.len() != length {
        return Err("HTTP body length rejected".into());
    }
    if p[0] == "POST"
        && (headers.get("origin") != Some(&origin)
            || headers.get("content-type").map(String::as_str) != Some("application/json"))
    {
        return Err("JSON and same-origin POST required".into());
    }
    if p[0] == "GET" && length != 0 {
        return Err("GET body rejected".into());
    }
    Ok(Request {
        method: p[0].into(),
        path: p[1].into(),
        headers,
        body: Zeroizing::new(body.to_vec()),
    })
}
fn read_request(stream: &mut TcpStream, host: &str) -> Result<Request, String> {
    // Accepted sockets may inherit the listener's nonblocking mode. This reader
    // uses blocking reads bounded by one request deadline on every platform.
    stream
        .set_nonblocking(false)
        .map_err(|_| "HTTP blocking mode unavailable")?;
    let deadline = Instant::now() + Duration::from_secs(IO_SECONDS);
    let mut bytes = Zeroizing::new(Vec::new());
    let mut header_end = None;
    let mut total = None;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("HTTP request deadline".into());
        }
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| "HTTP timeout unavailable")?;
        let mut chunk = [0; 1024];
        let n = stream.read(&mut chunk).map_err(|_| "HTTP read failed")?;
        if n == 0 {
            return Err("incomplete HTTP request".into());
        }
        bytes.extend_from_slice(&chunk[..n]);
        chunk.zeroize();
        if bytes.len() > HEADER_LIMIT + BODY_LIMIT {
            return Err("HTTP request limit".into());
        }
        if header_end.is_none() {
            header_end = bytes
                .windows(4)
                .position(|v| v == b"\r\n\r\n")
                .map(|v| v + 4);
            if header_end.is_none() && bytes.len() > HEADER_LIMIT {
                return Err("HTTP header limit".into());
            }
            if let Some(end) = header_end {
                let h = std::str::from_utf8(&bytes[..end]).map_err(|_| "invalid HTTP")?;
                let lengths: Vec<_> = h
                    .split("\r\n")
                    .filter_map(|v| v.split_once(':'))
                    .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                    .collect();
                let len = match lengths.as_slice() {
                    [] => 0,
                    [(_, v)] => v.trim().parse::<usize>().map_err(|_| "invalid length")?,
                    _ => return Err("duplicate length".into()),
                };
                if len > BODY_LIMIT {
                    return Err("HTTP body limit".into());
                }
                total = Some(end + len);
            }
        }
        if total.is_some_and(|n| bytes.len() >= n) {
            return parse_request(&bytes, host);
        }
    }
}
fn wipe(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe),
        Value::Object(o) => o.values_mut().for_each(wipe),
        _ => (),
    }
}
fn fields(value: &Value, allowed: &[&str]) -> Result<(), String> {
    let object = value.as_object().ok_or("JSON object required")?;
    if object.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err("unexpected request field".into());
    }
    Ok(())
}

fn response(
    stream: &mut TcpStream,
    status: u16,
    mime: &str,
    body: &[u8],
    cookie: Option<&str>,
) -> Result<(), String> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        429 => "Too Many Requests",
        _ => "Internal Server Error",
    };
    let extra=Zeroizing::new(cookie.map(|v|format!("Set-Cookie: {COOKIE}={v}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_SECONDS}\r\n")).unwrap_or_default());
    let header = Zeroizing::new(format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nCross-Origin-Opener-Policy: same-origin\r\nCross-Origin-Resource-Policy: same-origin\r\nContent-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'\r\n{extra}\r\n",
        body.len(),
        extra = extra.as_str()
    ));
    stream
        .set_write_timeout(Some(Duration::from_secs(IO_SECONDS)))
        .map_err(|_| "HTTP timeout unavailable")?;
    stream
        .write_all(header.as_bytes())
        .and_then(|_| stream.write_all(body))
        .map_err(|_| "HTTP response failed".into())
}

pub struct Server {
    listener: TcpListener,
    options: Options,
    config: Config,
    configuration_sha256: String,
    auth: blake3::Hash,
    instance: String,
    _lease: Lease,
    session: Option<Session>,
    wallet: Option<UnlockedWallet>,
    address_hex: Option<Zeroizing<String>>,
    view: Option<Value>,
    login_window: Instant,
    login_attempts: u8,
    shutdown: bool,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.lock();
    }
}
impl Server {
    pub fn bind(options: Options) -> Result<Self, String> {
        private_directory(&options.wallet_dir)?;
        let wallet =
            fs::canonicalize(&options.wallet_dir).map_err(|_| "wallet directory unavailable")?;
        let auth_path =
            fs::canonicalize(&options.auth_file).map_err(|_| "authentication file unavailable")?;
        if auth_path.starts_with(&wallet) {
            return Err("authentication token must be stored outside the wallet directory".into());
        }
        let auth = read_secret(&options.auth_file, 64)?;
        let auth = std::str::from_utf8(&auth).map_err(|_| "invalid authentication token")?;
        if auth.len() != 64 || !auth.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("authentication token must be 64 hexadecimal characters".into());
        }
        let auth = digest(auth);
        let config = local::load(&options.chain_dir)?;
        let configuration_sha256 = local::hex(&Sha256::digest(
            read_secret(
                &options.chain_dir.join("engineering-network.bin"),
                1024 * 1024,
            )?
            .as_slice(),
        ));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, options.port))
            .map_err(|_| "local wallet port unavailable")?;
        let instance = random_hex()?.to_string();
        let lease = Lease::new(&options.wallet_dir, &instance)?;
        Ok(Self {
            listener,
            options,
            config,
            configuration_sha256,
            auth,
            instance,
            _lease: lease,
            session: None,
            wallet: None,
            address_hex: None,
            view: None,
            login_window: Instant::now(),
            login_attempts: 0,
            shutdown: false,
        })
    }
    pub fn port(&self) -> u16 {
        self.listener
            .local_addr()
            .expect("bound wallet listener")
            .port()
    }
    fn clear_view(&mut self) {
        if let Some(mut view) = self.view.take() {
            wipe(&mut view);
        }
    }
    fn lock(&mut self) {
        self.wallet = None;
        self.address_hex = None;
        self.clear_view();
    }
    fn unlock(&mut self, body: &Value) -> Result<(), String> {
        self.lock();
        fields(body, &["passphrase"])?;
        let passphrase = body["passphrase"]
            .as_str()
            .ok_or("wallet passphrase required")?;
        if passphrase.is_empty() || passphrase.len() > 1024 {
            return Err("wallet passphrase must contain 1 to 1024 UTF-8 bytes".into());
        }
        let vault = WalletVault::open(&self.options.wallet_dir, self.config.network, passphrase)?;
        let address = vault.wallet()?.address();
        let mut bytes = native::codec::encode_digest(&address.owner()).to_vec();
        bytes.extend_from_slice(address.encapsulation_key());
        self.address_hex = Some(Zeroizing::new(local::hex(&bytes)));
        self.wallet = Some(vault);
        Ok(())
    }
    fn status(&self) -> Value {
        let mut v = json!({"process_id":std::process::id(),"instance_id":self.instance,"network":local::hex(&self.config.network),"locked":self.wallet.is_none(),"vault_exists":self.options.wallet_dir.join("seed.vault").is_file(),"balance_status":"unknown","send_available":false,"issuance_available":false,"creation_available":false,"reason":"This local wallet displays verified balances; payment submission is not connected."});
        if self.wallet.is_some()
            && let Some(address) = &self.address_hex
        {
            v["address_hex"] = json!(address.as_str());
        }
        if let Some(view) = &self.view {
            for (k, value) in view.as_object().expect("wallet view object") {
                v[k] = value.clone();
            }
        }
        v
    }
    fn api(&mut self, path: &str, body: &Value) -> Result<Value, String> {
        let result = (|| match path {
            "/api/status" => {
                fields(body, &[])?;
                Ok(self.status())
            }
            "/api/unlock" => {
                self.unlock(body)?;
                Ok(self.status())
            }
            "/api/lock" => {
                fields(body, &[])?;
                self.lock();
                Ok(self.status())
            }
            "/api/rescan" => {
                fields(body, &[])?;
                self.clear_view();
                let mut vault = self.wallet.take().ok_or("wallet is locked")?;
                let deadline = self
                    .session
                    .as_ref()
                    .map(|s| {
                        (s.created + Duration::from_secs(SESSION_SECONDS))
                            .min(s.touched + Duration::from_secs(IDLE_SECONDS))
                    })
                    .unwrap_or_else(|| Instant::now() + Duration::from_secs(IDLE_SECONDS));
                let _source_lease = crate::service::Lease::acquire(&self.options.chain_dir)?;
                let native = NativeVerifier::new()?;
                let verifier = DeadlineVerifier {
                    inner: &native,
                    deadline,
                };
                verifier.check()?;
                let (state, blocks) = crate::store::read_only_history(
                    &self.options.chain_dir.join("chain.redb"),
                    self.config.clone(),
                    &verifier,
                    MAX_BLOCKS,
                    MAX_HISTORY_BYTES,
                )?;
                verifier.check()?;
                // Keep the exclusive vault owner alive through both authenticated
                // reconciliations. A failed scan drops custody and every view.
                let mut wallet = vault.wallet()?;
                wallet.set_privacy_policy(crate::wallet_policy::load(
                    &self.options.wallet_dir,
                    self.config.network,
                )?);
                let report = wallet.reconcile(self.config.clone(), &blocks, &verifier)?;
                report.check_head(state.height, state.tip, state.fingerprint())?;
                report.check_supply()?;
                let journal = vault.reconcile_payments(self.config.clone(), &blocks, &verifier)?;
                journal.check_head(state.height, state.tip, state.fingerprint())?;
                journal.check_supply()?;
                let balances = wallet.balance_details(&state)?;
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| "wallet clock is before the supported epoch")?
                    .as_secs();
                let (pending, next_policy_time) =
                    crate::wallet_balance_view::privacy_pending(&wallet, &state, now)?;
                let (privacy_policy, immediate_spend_warning) =
                    crate::wallet_balance_view::privacy_policy_view(&wallet, &state, now)?;
                let summary = crate::wallet_balance_view::summarize(
                    &balances.available,
                    &balances.locked,
                    &pending,
                )?;
                let mut payment_blocked = false;
                for id in vault.payment_ids() {
                    if !matches!(
                        vault.payment_status(id)?,
                        PaymentStatus::Accepted | PaymentStatus::Conflicted
                    ) {
                        payment_blocked = true;
                    }
                }
                verifier.check()?;
                let amounts = |items: &std::collections::BTreeMap<
                    native::multi_asset::AssetId,
                    u128,
                >| {
                    items.iter().map(|(asset,amount)|json!({"asset_id":local::hex(&asset.0),"atoms":amount.to_string()})).collect::<Vec<_>>()
                };
                let balance_summary = summary
                    .iter()
                    .map(|row| {
                        json!({
                            "asset_id":local::hex(&row.asset.0),
                            "confirmed_owned_atoms":row.confirmed_owned.to_string(),
                            "consensus_mature_atoms":row.consensus_mature.to_string(),
                            "chain_locked_atoms":row.chain_locked.to_string(),
                            "privacy_pending_atoms":row.privacy_pending.to_string(),
                            "policy_ready_atoms":row.policy_ready.to_string(),
                        })
                    })
                    .collect::<Vec<_>>();
                let view = json!({"balance_status":"verified","height":state.height,"tip":local::hex(&state.tip),"available":amounts(&balances.available),"locked_balances":amounts(&balances.locked),"tranches":balances.tranches.iter().map(|t|json!({"asset_id":local::hex(&t.asset.0),"atoms":t.amount.to_string(),"unlock_height":t.unlock_height,"estimated_timestamp":t.estimated_timestamp})).collect::<Vec<_>>(),"next_unlock_height":balances.next_unlock_height,"balance_summary":balance_summary,"privacy_policy":privacy_policy,"immediate_spend_privacy_warning":immediate_spend_warning,"privacy_pending":amounts(&pending),"next_privacy_policy_unix_seconds":next_policy_time,"payment_submission_blocked_by_pending_journal":payment_blocked});
                verifier.check()?;
                self.view = Some(view);
                self.wallet = Some(vault);
                Ok(self.status())
            }
            "/api/miner-status" => {
                fields(body, &[])?;
                self.miner_status()
            }
            "/api/shutdown" => {
                fields(body, &["instance_id"])?;
                if body["instance_id"].as_str() != Some(&self.instance) {
                    return Err("wallet instance mismatch".into());
                }
                self.lock();
                self.shutdown = true;
                Ok(json!({"stopping":true,"instance_id":self.instance}))
            }
            _ => Err("unknown wallet API".into()),
        })();
        if result.is_err() {
            self.lock();
        }
        result
    }
    fn miner_status(&self) -> Result<Value, String> {
        let status = crate::service::exported_status(&self.options.chain_dir)?;
        let phase = status["phase"].as_str().ok_or("miner phase unavailable")?;
        if status["schema_version"] != 1
            || status["network_id"].as_str() != Some(&local::hex(&self.config.network))
            || !matches!(
                phase,
                "starting"
                    | "replaying"
                    | "preparing"
                    | "refilling"
                    | "mining"
                    | "networking"
                    | "committing"
                    | "stopping"
                    | "stopped"
                    | "error"
            )
        {
            return Err("miner status context mismatch".into());
        }
        let updated = status["updated_unix_ms"]
            .as_u64()
            .ok_or("miner freshness unavailable")?;
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "system time unavailable")?
                .as_millis(),
        )
        .map_err(|_| "system time overflow")?;
        let run = status["run_id"]
            .as_str()
            .ok_or("miner identity unavailable")?;
        let pid = status["process_id"]
            .as_u64()
            .filter(|pid| *pid > 0 && *pid <= u64::from(u32::MAX))
            .ok_or("miner process identity invalid")?;
        if run.len() != 64
            || !run
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || status["configuration_sha256"].as_str() != Some(&self.configuration_sha256)
        {
            return Err("miner run or configuration identity mismatch".into());
        }
        let state_available = status["state_available"]
            .as_bool()
            .ok_or("miner state availability missing")?;
        let failure = status
            .get("error_code")
            .ok_or("miner failure status missing")?;
        if (!failure.is_null()
            && failure
                .as_str()
                .is_none_or(|v| v.is_empty() || v.len() > 64))
            || (matches!(phase, "mining" | "preparing" | "refilling" | "networking")
                && !state_available)
        {
            return Err("miner status shape inconsistent".into());
        }
        let runs = self.options.chain_dir.join("service-runs");
        private_directory(&runs)?;
        let run_directory = runs.join(run);
        private_directory(&run_directory)?;
        let receipt: Value =
            serde_json::from_slice(&read_secret(&run_directory.join("run.json"), 16384)?)
                .map_err(|_| "miner run receipt invalid")?;
        for name in [
            "schema_version",
            "run_id",
            "process_id",
            "network_id",
            "binary_sha256",
            "configuration_sha256",
            "started_unix_ms",
            "observation_target_ms",
        ] {
            if status.get(name).is_none() || receipt.get(name) != status.get(name) {
                return Err("miner export differs from immutable run receipt".into());
            }
        }
        let binary = status["binary_sha256"]
            .as_str()
            .ok_or("miner binary identity missing")?;
        if binary.len() != 64
            || !binary
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || status["started_unix_ms"]
                .as_u64()
                .is_none_or(|v| v == 0 || v > updated)
        {
            return Err("miner receipt identity malformed".into());
        }
        let fresh = updated <= now && now - updated <= 15000;
        Ok(
            json!({"phase":phase,"fresh":fresh,"age_ms":now.saturating_sub(updated),"has_failure":!failure.is_null(),"process_id":pid,"run_id":run,"network":local::hex(&self.config.network),"observation":"export_only_not_process_liveness"}),
        )
    }
    fn handle(&mut self, request: Request) -> (u16, &'static str, Vec<u8>, Option<String>) {
        let now = Instant::now();
        if self.session.as_ref().is_some_and(|s| !s.alive(now)) {
            self.session = None;
            self.lock();
        }
        if request.method == "GET" {
            if request.path == "/miner-startup" {
                let html = include_str!("assets/index.html")
                    .replace("data-profile=\"wallet\"", "data-profile=\"miner\"");
                return (200, "text/html; charset=utf-8", html.into_bytes(), None);
            }
            let asset = match request.path.as_str() {
                "/" => Some((
                    "text/html; charset=utf-8",
                    include_bytes!("assets/index.html").as_slice(),
                )),
                "/wallet.css" => Some((
                    "text/css; charset=utf-8",
                    include_bytes!("assets/wallet.css").as_slice(),
                )),
                "/wallet.js" => Some((
                    "text/javascript; charset=utf-8",
                    include_bytes!("assets/wallet.js").as_slice(),
                )),
                "/startup.css" => Some((
                    "text/css; charset=utf-8",
                    include_bytes!("assets/startup.css").as_slice(),
                )),
                "/startup.js" => Some((
                    "text/javascript; charset=utf-8",
                    include_bytes!("assets/startup.js").as_slice(),
                )),
                _ => None,
            };
            return match asset {
                Some((mime, bytes)) => (200, mime, bytes.to_vec(), None),
                None => (404, "text/plain", b"Not found".to_vec(), None),
            };
        }
        let mut body: Value = match serde_json::from_slice(&request.body) {
            Ok(v) => v,
            Err(_) => {
                self.lock();
                return (
                    400,
                    "application/json",
                    b"{\"error\":\"Invalid JSON\"}".to_vec(),
                    None,
                );
            }
        };
        let mut result = (|| {
            if request.path == "/api/login" {
                fields(&body, &["token", "expected_process_id"])?;
                if now.saturating_duration_since(self.login_window) > Duration::from_secs(30) {
                    self.login_window = now;
                    self.login_attempts = 0;
                }
                self.login_attempts = self.login_attempts.saturating_add(1);
                if self.login_attempts > 5 {
                    return Ok((429, json!({"error":"Login temporarily rate limited"}), None));
                }
                let token = body["token"].as_str().ok_or("access token required")?;
                if digest(token) != self.auth {
                    return Ok((401, json!({"error":"Authentication failed"}), None));
                }
                if body.get("expected_process_id").is_some()
                    && body["expected_process_id"].as_u64() != Some(u64::from(std::process::id()))
                {
                    return Ok((
                        401,
                        json!({"error":"Wallet process identity mismatch"}),
                        None,
                    ));
                }
                self.lock();
                let mut session = Session::new(now)?;
                let (cookie, csrf) = session
                    .credentials
                    .take()
                    .ok_or("session credentials unavailable")?;
                self.session = Some(session);
                return Ok((
                    200,
                    json!({"csrf":csrf,"process_id":std::process::id(),"instance_id":self.instance}),
                    Some(cookie),
                ));
            }
            let cookie = request
                .headers
                .get("cookie")
                .and_then(|v| session_cookie(v));
            let csrf = request.headers.get("x-wallet-csrf").map(String::as_str);
            if !self
                .session
                .as_mut()
                .is_some_and(|s| s.authorize(cookie, csrf, now))
            {
                return Ok((
                    401,
                    json!({"error":"Session authentication required"}),
                    None,
                ));
            }
            if !matches!(request.path.as_str(), "/api/status" | "/api/miner-status")
                && let Some(session) = self.session.as_mut()
            {
                session.touched = now;
            }
            self.api(&request.path, &body).map(|v| (200, v, None))
        })();
        if self
            .session
            .as_ref()
            .is_some_and(|s| !s.alive(Instant::now()))
        {
            self.session = None;
            self.lock();
            result = Ok((401, json!({"error":"Wallet session expired"}), None));
        }
        wipe(&mut body);
        let (code, mut value, cookie) = match result {
            Ok(v) => v,
            Err(error) => {
                self.lock();
                (400, json!({"error":error}), None)
            }
        };
        let serialized = serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec());
        wipe(&mut value);
        (code, "application/json", serialized, cookie)
    }
    pub fn run(mut self) -> Result<(), String> {
        self.listener
            .set_nonblocking(true)
            .map_err(|_| "wallet listener unavailable")?;
        while !self.shutdown {
            if self
                .session
                .as_ref()
                .is_some_and(|s| !s.alive(Instant::now()))
            {
                self.session = None;
                self.lock();
            }
            match self.listener.accept() {
                Ok((mut stream, peer)) => {
                    if !peer.ip().is_loopback() {
                        continue;
                    }
                    let host = format!("127.0.0.1:{}", self.port());
                    match read_request(&mut stream, &host) {
                        Ok(request) => {
                            let (code, mime, mut bytes, cookie) = self.handle(request);
                            let _ = response(&mut stream, code, mime, &bytes, cookie.as_deref());
                            bytes.zeroize();
                        }
                        Err(_) => {
                            let _ = response(
                                &mut stream,
                                400,
                                "application/json",
                                b"{\"error\":\"Request rejected\"}",
                                None,
                            );
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                Err(_) => return Err("wallet listener failed".into()),
            }
        }
        self.lock();
        Ok(())
    }
}

struct Client {
    port: u16,
    cookie: Zeroizing<String>,
    csrf: Zeroizing<String>,
}
impl Client {
    fn new(port: u16) -> Self {
        Self {
            port,
            cookie: Zeroizing::new(String::new()),
            csrf: Zeroizing::new(String::new()),
        }
    }
    #[cfg(test)]
    fn login(&mut self, token: &str) -> Result<(), String> {
        self.login_owned(token, None)
    }
    fn login_owned(&mut self, token: &str, expected: Option<u32>) -> Result<(), String> {
        let mut body = json!({"token":token});
        if let Some(pid) = expected {
            body["expected_process_id"] = json!(pid);
        }
        let mut value = self.post("/api/login", body)?;
        self.csrf = Zeroizing::new(
            value["csrf"]
                .as_str()
                .ok_or("missing CSRF response")?
                .to_owned(),
        );
        wipe(&mut value);
        Ok(())
    }
    fn post(&mut self, path: &str, mut body: Value) -> Result<Value, String> {
        let mut stream = TcpStream::connect_timeout(
            &std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, self.port)),
            Duration::from_secs(IO_SECONDS),
        )
        .map_err(|_| "local wallet unavailable")?;
        stream
            .set_read_timeout(Some(Duration::from_secs(IO_SECONDS)))
            .map_err(|_| "wallet timeout unavailable")?;
        stream
            .set_write_timeout(Some(Duration::from_secs(IO_SECONDS)))
            .map_err(|_| "wallet timeout unavailable")?;
        let bytes = Zeroizing::new(serde_json::to_vec(&body).map_err(|_| "invalid local request")?);
        wipe(&mut body);
        let header = Zeroizing::new(format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nOrigin: http://127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCookie: {COOKIE}={}\r\nX-Wallet-CSRF: {}\r\nConnection: close\r\n\r\n",
            self.port,
            self.port,
            bytes.len(),
            *self.cookie,
            *self.csrf
        ));
        stream
            .write_all(header.as_bytes())
            .and_then(|_| stream.write_all(&bytes))
            .map_err(|_| "local wallet request failed")?;
        let mut response = Zeroizing::new(Vec::new());
        stream
            .take(1024 * 1024)
            .read_to_end(&mut response)
            .map_err(|_| "local wallet response failed")?;
        let end = response
            .windows(4)
            .position(|v| v == b"\r\n\r\n")
            .ok_or("invalid local response")?;
        let headers =
            std::str::from_utf8(&response[..end]).map_err(|_| "invalid local response")?;
        if !headers.starts_with("HTTP/1.1 200 ") {
            return Err("local wallet rejected request".into());
        }
        for line in headers.split("\r\n") {
            if let Some(value) = line.strip_prefix("Set-Cookie: ") {
                let token = value
                    .strip_prefix(&format!("{COOKIE}="))
                    .and_then(|v| v.split(';').next())
                    .ok_or("invalid session cookie")?;
                self.cookie = Zeroizing::new(token.to_owned());
            }
        }
        serde_json::from_slice(&response[end + 4..]).map_err(|_| "invalid local wallet JSON".into())
    }
}
/// Stop only the authenticated process explicitly owned by the supervisor.
pub fn stop(auth_file: &Path, port: u16, expected_process_id: u32) -> Result<(), String> {
    let bytes = read_secret(auth_file, 64)?;
    let token = std::str::from_utf8(&bytes).map_err(|_| "invalid access token")?;
    let mut client = Client::new(port);
    client.login_owned(token, Some(expected_process_id))?;
    let status = client.post("/api/status", json!({}))?;
    if status["process_id"].as_u64() != Some(u64::from(expected_process_id)) {
        return Err("wallet process identity mismatch; shutdown refused".into());
    }
    client.post(
        "/api/shutdown",
        json!({"instance_id":status["instance_id"]}),
    )?;
    Ok(())
}
#[cfg(all(test, unix))]
mod tests;
