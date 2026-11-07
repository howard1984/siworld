use serde_json::{Value, json};
use siworld_miner_cli::{Hashrate, Wizard};
use siworld_miner_platform as platform;
use siworld_native_node::{
    identity::NativeIdentity,
    local, mining, p2p,
    producer::MiningSettings,
    proofs::NativeVerifier,
    service,
    state::{Config, RewardMode},
    store::Store,
    wallet_vault::{PendingWallet, WalletVault},
};
use siworld_native_wallet_core::{address, hex_array};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const BUNDLE_LIMIT: usize = 2 * 1024 * 1024;

fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "System clock precedes epoch")?
        .as_millis()
        .try_into()
        .map_err(|_| "System clock exceeds supported range".into())
}
fn read_json(path: &Path, maximum: usize, private: bool) -> Result<Value, String> {
    let file = if private {
        platform::read_private(path, false)?
    } else {
        File::open(path).map_err(|_| "Network bundle unavailable")?
    };
    if file
        .metadata()
        .map_err(|_| "File metadata unavailable")?
        .len()
        > maximum as u64
    {
        return Err("JSON byte limit exceeded".into());
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "JSON read unavailable")?;
    if bytes.len() > maximum {
        return Err("JSON byte limit exceeded".into());
    }
    serde_json::from_slice(&bytes).map_err(|_| "Invalid local JSON".into())
}
fn hidden(prompt: &str, maximum: usize) -> Result<Zeroizing<String>, String> {
    let value = Zeroizing::new(
        rpassword::prompt_password(prompt).map_err(|_| "Trusted console input unavailable")?,
    );
    if value.len() > maximum {
        return Err("Input exceeds its byte limit".into());
    }
    Ok(value)
}
fn prompt(text: &str, maximum: usize) -> Result<String, String> {
    Ok(hidden(text, maximum)?.to_string())
}
fn console() -> Result<platform::Console, String> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Err(
            "\u{9996}\u{6b21}\u{8bbe}\u{7f6e}\u{9700}\u{8981}\u{53ef}\u{4fe1}\u{4ea4}\u{4e92}\u{7ec8}\u{7aef} / First setup requires an interactive trusted terminal"
                .into(),
        );
    }
    platform::Console::open()
}
fn spinner<T>(action: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    if !std::io::stderr().is_terminal() {
        eprintln!("Preparing native miner...");
        return action();
    }
    let done = Arc::new(AtomicBool::new(false));
    let completed = done.clone();
    let draw = std::thread::spawn(move || {
        for frame in ["|", "/", "-", "\\"].into_iter().cycle() {
            if completed.load(Ordering::SeqCst) {
                break;
            }
            eprint!("\r[{frame}] SIWORLD | Preparing native miner... ");
            let _ = std::io::stderr().flush();
            std::thread::sleep(Duration::from_millis(100));
        }
    });
    let result = action();
    done.store(true, Ordering::SeqCst);
    let _ = draw.join();
    eprintln!(
        "\r[{}] SIWORLD | Preparation {}.          ",
        if result.is_ok() { "+" } else { "!" },
        if result.is_ok() { "complete" } else { "failed" }
    );
    result
}
fn hardware() -> Result<(), String> {
    platform::check_memory(platform::visible_memory()?)?;
    let cpus = std::thread::available_parallelism()
        .map_err(|_| "CPU count unavailable")?
        .get();
    if cpus < 4 {
        return Err(
            "CPU \u{4e0d}\u{8db3}：\u{81f3}\u{5c11}\u{9700}\u{8981} 4 \u{4e2a}\u{903b}\u{8f91}\u{5904}\u{7406}\u{5668} / At least 4 logical CPUs are required".into(),
        );
    }
    Ok(())
}
fn root() -> Result<PathBuf, String> {
    let parent = std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA unavailable")?;
    let parent = PathBuf::from(parent);
    if !parent.is_absolute() {
        return Err("LOCALAPPDATA must be absolute".into());
    }
    Ok(parent.join("SIWORLD"))
}

/// Only a locally trusted release bundle can introduce network rules and pins.
/// No peer response, address or runtime calibration selects a new genesis.
fn initialize(root: &Path, bundle_path: &Path) -> Result<PathBuf, String> {
    let network = root.join("network");
    if !root
        .try_exists()
        .map_err(|_| "Data directory unavailable")?
    {
        platform::Directory::create(root)?;
    }
    platform::Directory::open(root)?;
    if network
        .try_exists()
        .map_err(|_| "Network directory unavailable")?
    {
        let _ = local::load(&network)?;
        let binding = p2p::Binding::new(&local::load(&network)?);
        NativeIdentity::load(&network, &binding)
            .map_err(|_| "Existing peer identity missing or invalid; preserve data")?;
        // A missing or damaged database is never silently reinitialized.
        if !network.join("chain.redb").is_file() {
            return Err("Existing chain database missing; preserve data".into());
        }
        return Ok(network);
    }
    let bundle = read_json(bundle_path, BUNDLE_LIMIT, false)?;
    let object = bundle
        .as_object()
        .ok_or("Network bundle must be an object")?;
    if object.len() != 4 || bundle["version"] != 1 {
        return Err("Unsupported network bundle schema".into());
    }
    let rules = bundle["rules_hex"]
        .as_str()
        .ok_or("Network rules missing")?;
    let rules = hex_array::<{ siworld_native_node::state::CONFIG_RULE_BYTES }>(rules)?;
    let config = Config::decode_rules(&rules)?;
    if config.fixture
        || config.fund_allocation.is_none()
        || bundle["genesis"] != local::hex(&config.genesis_id())
    {
        return Err("Release bundle must identify the reviewed ASERT engineering network".into());
    }
    let peers = bundle["peers"]
        .as_array()
        .ok_or("Pinned bootstrap peers missing")?;
    if peers.is_empty() || peers.len() > 16 {
        return Err("One to sixteen pinned bootstrap peers are required".into());
    }
    // Validate all public descriptor bindings before creating private state.
    let binding = p2p::Binding::new(&config);
    for peer in peers {
        if peer.as_object().map(|v| v.len()) != Some(3) {
            return Err("Invalid bootstrap peer entry".into());
        }
        let fingerprint = hex_array::<32>(
            peer["fingerprint"]
                .as_str()
                .ok_or("Bootstrap fingerprint missing")?,
        )?;
        let descriptor = hex_array::<{ siworld_native_node::identity::DESCRIPTOR_BYTES }>(
            peer["descriptor"]
                .as_str()
                .ok_or("Bootstrap descriptor missing")?,
        )?;
        let descriptor = siworld_native_node::identity::Descriptor::decode(&descriptor, &binding)
            .map_err(|_| "Bootstrap descriptor rejected")?;
        if descriptor.fingerprint() != fingerprint {
            return Err("Bootstrap fingerprint mismatch".into());
        }
        let endpoint: std::net::SocketAddr = peer["endpoint"]
            .as_str()
            .ok_or("Bootstrap endpoint missing")?
            .parse()
            .map_err(|_| "Invalid bootstrap endpoint")?;
        if endpoint.port() == 0 || endpoint.ip().is_unspecified() || endpoint.ip().is_multicast() {
            return Err("Invalid bootstrap endpoint".into());
        }
    }
    local::initialize_config(&network, config)?;
    let identity = NativeIdentity::initialize(&network, binding)
        .map_err(|_| "Private peer identity creation failed")?;
    let own = identity
        .descriptor()
        .map_err(|_| "Public peer descriptor unavailable")?;
    service::atomic_json(
        &root.join("pairing-public.json"),
        &json!({"version":siworld_native_node::identity::VERSION,
        "fingerprint":local::hex(&own.fingerprint()),"descriptor":local::hex(&own.encode())}),
    )?;
    for (index, peer) in peers.iter().enumerate() {
        let file = network.join(format!("bootstrap-{index}.json"));
        service::atomic_json(
            &file,
            &json!({"version":siworld_native_node::identity::VERSION,"fingerprint":peer["fingerprint"],"descriptor":peer["descriptor"]}),
        )?;
        #[cfg(feature = "network")]
        service::network::pin_peer(
            &network,
            &file,
            peer["fingerprint"].as_str().expect("validated fingerprint"),
        )?;
    }
    service::atomic_json(
        &network.join("peers.json"),
        &json!({"version":1,"engineering":true,"listen":null,"mining":true,"peers":peers}),
    )?;
    let mut store = Store::open(
        network.join("chain.redb"),
        local::load(&network)?,
        &NativeVerifier::new()?,
    )?;
    store.configure_storage(siworld_native_node::storage_policy::Role::Miner)?;
    Ok(network)
}

fn new_address(
    root: &Path,
    network: [u8; 32],
    tty: &mut platform::Console,
) -> Result<[u8; 1232], String> {
    if root
        .join("wallet")
        .try_exists()
        .map_err(|_| "Existing wallet directory unavailable")?
    {
        let password = hidden(
            "\u{89e3}\u{9501}\u{5df2}\u{6709}\u{672c}\u{673a}\u{94b1}\u{5305} / Unlock saved local wallet: ",
            1024,
        )?;
        let wallet = WalletVault::open(&root.join("wallet"), network, &password)?;
        let address = wallet.keys()?.address();
        let mut bytes = [0u8; 1232];
        bytes[..48].copy_from_slice(&native::codec::encode_digest(&address.owner()));
        bytes[48..].copy_from_slice(address.encapsulation_key());
        writeln!(tty,"\u{5df2}\u{6062}\u{590d}\u{5df2}\u{6709}\u{5730}\u{5740}\u{ff0c}\u{4e0d}\u{4f1a}\u{751f}\u{6210}\u{6216}\u{8986}\u{76d6}\u{94b1}\u{5305} / Reusing saved address; no wallet is generated or overwritten.").map_err(|_|"Console unavailable")?;
        return Ok(bytes);
    }
    let password = hidden(
        "\u{8bbe}\u{7f6e}\u{94b1}\u{5305}\u{5bc6}\u{7801}\u{ff08}\u{81f3}\u{5c11}12\u{5b57}\u{8282}\u{ff09} / New wallet password (12+ bytes): ",
        1024,
    )?;
    if password.len() < 12 {
        return Err("Wallet password requires at least 12 UTF-8 bytes".into());
    }
    if *password
        != *hidden(
            "\u{786e}\u{8ba4}\u{5bc6}\u{7801} / Confirm password: ",
            1024,
        )?
    {
        return Err("Wallet passwords do not match".into());
    }
    let pending = PendingWallet::generate(network, 0)?;
    {
        let words = pending.recovery_words();
        writeln!(tty,"\n\u{79bb}\u{7ebf}\u{8bb0}\u{5f55}\u{4ee5}\u{4e0b}24\u{8bcd}\u{ff0c}\u{7981}\u{6b62}\u{53d1}\u{9001}\u{7ed9}\u{4efb}\u{4f55}\u{4eba}\u{3002}\nRecord these 24 words offline; never send them to anyone.\nRecovery version: 1 | Account: 0 | Network: {}\n\n{}\n", local::hex(&network), words.expose()).map_err(|_| "Private backup view unavailable")?;
        tty.flush()
            .map_err(|_| "Private backup view flush failed")?;
        hidden(
            "\u{8bb0}\u{5f55}\u{5b8c}\u{6210}\u{540e}\u{6309}\u{56de}\u{8f66} / Press Enter after recording: ",
            0,
        )?;
        platform::clear_console()?;
    }
    let positions = pending.backup_challenge();
    let a = hidden(
        &format!("\u{5907}\u{4efd}\u{8bcd} / Backup word {}: ", positions[0]),
        32,
    )?;
    let b = hidden(
        &format!("\u{5907}\u{4efd}\u{8bcd} / Backup word {}: ", positions[1]),
        32,
    )?;
    let c = hidden(
        &format!("\u{5907}\u{4efd}\u{8bcd} / Backup word {}: ", positions[2]),
        32,
    )?;
    let confirmed = pending.confirm_backup([&a, &b, &c])?;
    let wallet = confirmed.create(&root.join("wallet"), &password)?;
    let address = wallet.keys()?.address();
    let mut bytes = [0u8; 1232];
    bytes[..48].copy_from_slice(&native::codec::encode_digest(&address.owner()));
    bytes[48..].copy_from_slice(address.encapsulation_key());
    platform::Directory::open(root)?.write_once(
        "receiving-address.txt",
        address::full(network, &bytes)?.as_bytes(),
    )?;
    Ok(bytes)
}

fn wizard(root: &Path, directory: &Path) -> Result<(), String> {
    let mut tty = console()?;
    let mut wizard = Wizard::default();
    writeln!(tty,"SIWORLD | Windows native CLI | \u{5de5}\u{7a0b}\u{7f51} / Engineering network\nReward mode has no default. Holder includes long locks; Voyager uses its current protocol allocation.").map_err(|_|"Console unavailable")?;
    let mode = loop {
        let value = prompt(
            "\u{9009}\u{62e9} holder \u{6216} voyager / Select holder or voyager: ",
            16,
        )?;
        match wizard.mode(&value) {
            Ok(()) => break value,
            Err(error) => eprintln!("{error}"),
        }
    };
    let mode = RewardMode::from_name(&mode).map_err(|e| e.to_string())?;
    let network = local::load(directory)?.network;
    let address = loop {
        match prompt(
            "\u{8f93}\u{5165} new \u{6216} existing / Type new or existing address: ",
            16,
        )?
        .as_str()
        {
            "new" => break new_address(root, network, &mut tty)?,
            "existing" => {
                let text = hidden(
                    "\u{7c98}\u{8d34}\u{5b8c}\u{6574}\u{6536}\u{6b3e}\u{5730}\u{5740} / Paste full receiving address: ",
                    4096,
                )?;
                match address::resolve(&text, network, None) {
                    Ok(address) => break address,
                    Err(error) => {
                        eprintln!(
                            "\u{5730}\u{5740}\u{65e0}\u{6548}\u{6216}\u{7f51}\u{7edc}\u{4e0d}\u{7b26} / Invalid address or network: {error}"
                        )
                    }
                }
            }
            _ => {
                eprintln!("\u{8bf7}\u{9009}\u{62e9} new \u{6216} existing / Choose new or existing")
            }
        }
    };
    wizard.address_validated()?;
    loop {
        let input = prompt(
            "\u{786e}\u{8ba4}\u{79bb}\u{7ebf}\u{5907}\u{4efd}\u{ff0c}\u{8f93}\u{5165} BACKEDUP / Confirm offline backup; type BACKEDUP: ",
            16,
        )?;
        if wizard.acknowledge(&input).is_ok() {
            break;
        }
        eprintln!("\u{5fc5}\u{987b}\u{8f93}\u{5165} BACKEDUP / Type BACKEDUP exactly");
    }
    writeln!(tty,"\nMode: {} | SIP | Outbound-only | 4 proving workers\nData: %LOCALAPPDATA%\\SIWORLD\n\u{9996}\u{6b21}\u{540c}\u{6b65}\u{53ef}\u{80fd}\u{8f83}\u{957f}\u{ff1b}\u{672a}\u{5b8c}\u{6210}\u{8ba4}\u{8bc1}\u{548c}\u{540c}\u{6b65}\u{524d}\u{4e0d}\u{4f1a}\u{5f00}\u{59cb}PoW\u{3002}\nInitial verification can take time; PoW waits for authenticated synchronization.\nThe bootstrap operator must separately pin pairing-public.json; no wallet secrets are required.",mode.name()).map_err(|_|"Console unavailable")?;
    loop {
        let input = prompt(
            "\u{542f}\u{52a8}\u{6316}\u{77ff}\u{8bf7}\u{8f93}\u{5165} START / Type START to start mining: ",
            16,
        )?;
        if wizard.acknowledge(&input).is_ok() {
            break;
        }
        eprintln!("\u{5fc5}\u{987b}\u{8f93}\u{5165} START / Type START exactly");
    }
    let owner = native::codec::decode_digest(
        address[..48]
            .try_into()
            .map_err(|_| "Invalid receiving owner length")?,
    )
    .map_err(|_| "Invalid recipient owner")?;
    let recipient = native::encryption::PaymentAddress::new(
        owner,
        address[48..]
            .try_into()
            .map_err(|_| "Invalid receiving key length")?,
    )
    .map_err(|_| "Invalid receiving key")?;
    mining::save(directory, network, &MiningSettings { mode, recipient })
}

fn idle_lease(directory: &Path) -> Result<File, String> {
    let path = directory.join(service::LEASE_FILE);
    let file = match platform::create_private(&path) {
        Ok(file) => file,
        Err(_) => platform::read_private(&path, true)?,
    };
    file.try_lock().map_err(
        |_| "An existing miner is active or still stopping; wait for its clean stop before setup",
    )?;
    Ok(file)
}

fn stop(directory: &Path, run: &str) -> Result<(), String> {
    if service::stop_requested(directory, run)? {
        return Ok(());
    }
    match service::request_stop_expected(directory, run) {
        Ok(()) => Ok(()),
        Err(error) => {
            if service::stop_requested(directory, run).unwrap_or(false) {
                Ok(())
            } else {
                Err(error)
            }
        }
    }
}
fn monitor(directory: &Path) -> Result<(), String> {
    platform::install_stop_handler()?;
    let started_wall = now()?;
    let mut child =
        Command::new(std::env::current_exe().map_err(|_| "Executable identity unavailable")?)
            .arg("--worker")
            .arg(std::process::id().to_string())
            .env("RAYON_NUM_THREADS", "4")
            .env("SIWORLD_COMPOSITION_HIDING_WORKERS", "2")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|_| "Miner worker could not start")?;
    let mut rate = Hashrate::default();
    let mut stopping = false;
    let mut last_render = Instant::now();
    let mut run_id: Option<String> = None;
    eprintln!(
        "\u{6b63}\u{5728}\u{540c}\u{6b65} / Synchronizing. Ctrl+C requests a clean stop; keep this terminal open."
    );
    let outcome = (|| -> Result<(), String> {
        loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|_| "Worker process observation failed")?
            {
                rate.reset();
                if !status.success() {
                    return Err("Miner exited with an error; preserve %LOCALAPPDATA%\\SIWORLD for diagnosis".into());
                }
                let final_status = service::exported_status(directory)?;
                if final_status["run_id"].as_str() != run_id.as_deref()
                    || final_status["phase"] != "stopped"
                {
                    return Err("Worker exited without a verified stopped result".into());
                }
                eprintln!(
                    "\u{5df2}\u{5e72}\u{51c0}\u{505c}\u{6b62}\u{ff1b}\u{6570}\u{636e}\u{548c}\u{5956}\u{52b1}\u{4fdd}\u{7559} / Cleanly stopped; data and rewards retained."
                );
                return Ok(());
            }
            if let Ok(status) = service::exported_status(directory) {
                if status["process_id"].as_u64() == Some(u64::from(child.id()))
                    && status["started_unix_ms"]
                        .as_u64()
                        .is_some_and(|t| t >= started_wall)
                {
                    if let Some(run) = status["run_id"].as_str() {
                        run_id = Some(run.to_owned());
                    }
                }
            }
            if platform::stop_requested()
                && !stopping
                && let Some(run) = &run_id
            {
                match stop(directory, run) {
                    Ok(()) => {
                        stopping = true;
                        rate.reset();
                        eprintln!(
                            "\u{6b63}\u{5728}\u{5e72}\u{51c0}\u{505c}\u{6b62}\u{ff1b}\u{7b49}\u{5f85}\u{5f53}\u{524d}\u{8bc1}\u{660e}\u{548c}\u{6700}\u{7ec8}\u{9a8c}\u{8bc1}\u{3002}\nClean stop pending; waiting for current proof and final verification. Do not start another instance."
                        );
                    }
                    Err(error) => eprintln!("Stop request pending: {error}"),
                }
            }
            if last_render.elapsed() >= Duration::from_secs(5) {
                let observation =
                    read_json(&directory.join("miner-private-status.json"), 65_536, true);
                match observation {
                    Ok(value) if value["run_id"].as_str() == run_id.as_deref() && !stopping => {
                        let time = now().unwrap_or(u64::MAX);
                        let measured = rate.observe(&value, time);
                        match siworld_miner_cli::render(&value, measured, time) {
                            Ok(text) => eprint!("{text}"),
                            Err(_) => {
                                eprintln!("Private reward status unavailable; no balance inferred.")
                            }
                        }
                    }
                    _ => {
                        rate.reset();
                        eprintln!(
                            "\u{5f53}\u{524d}\u{72b6}\u{6001}\u{5f85}\u{9a8c}\u{8bc1} / Current status unavailable; replay, peer synchronization or clean stop may still be in progress."
                        );
                    }
                }
                last_render = Instant::now();
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    })();
    if outcome.is_err() && child.try_wait().ok().flatten().is_none() {
        eprintln!(
            "\u{524d}\u{53f0}\u{89c2}\u{5bdf}\u{5931}\u{8d25}\u{ff1b}\u{6b63}\u{5728}\u{8bf7}\u{6c42}\u{5e72}\u{51c0}\u{505c}\u{6b62} / Frontend observation failed; requesting a clean stop."
        );
        loop {
            if let Ok(Some(_)) = child.try_wait() {
                break;
            }
            if let Ok(status) = service::exported_status(directory)
                && status["process_id"].as_u64() == Some(u64::from(child.id()))
                && let Some(run) = status["run_id"].as_str()
            {
                let _ = stop(directory, run);
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    outcome
}

pub fn run(args: Vec<OsString>) -> Result<(), String> {
    if args.as_slice() == [OsString::from("--check-hardware")] {
        hardware()?;
        println!("Hardware admission passed");
        return Ok(());
    }
    let root = root()?;
    let directory = root.join("network");
    if args.as_slice() == [OsString::from("--status")] {
        let value = read_json(&directory.join("miner-private-status.json"), 65_536, true)?;
        print!("{}", siworld_miner_cli::render(&value, None, now()?)?);
        return Ok(());
    }
    hardware()?;
    if let [flag, parent] = args.as_slice()
        && flag == OsStr::new("--worker")
    {
        let parent = parent
            .to_str()
            .ok_or("Invalid parent PID")?
            .parse::<u32>()
            .map_err(|_| "Invalid parent PID")?;
        let parent = platform::ProcessWatch::open(parent)?;
        platform::install_stop_handler()?;
        let finished = Arc::new(AtomicBool::new(false));
        let signal = finished.clone();
        let observed = directory.clone();
        let watch = std::thread::spawn(move || {
            while !signal.load(Ordering::SeqCst) {
                if platform::stop_requested() || !parent.is_running() {
                    if let Ok(status) = service::exported_status(&observed)
                        && status["process_id"].as_u64() == Some(u64::from(std::process::id()))
                        && let Some(run) = status["run_id"].as_str()
                    {
                        let _ = stop(&observed, run);
                    }
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        });
        #[cfg(feature = "network")]
        let result = service::run_cli_miner(&directory, &directory.join("peers.json"));
        #[cfg(not(feature = "network"))]
        let result: Result<(), String> =
            Err("This diagnostic build has no mining transport".into());
        finished.store(true, Ordering::SeqCst);
        let _ = watch.join();
        return result;
    }
    let bundle = match args.as_slice() {
        [] => std::env::current_exe()
            .map_err(|_| "Executable path unavailable")?
            .parent()
            .and_then(Path::parent)
            .ok_or("Package root unavailable")?
            .join("engineering-network.json"),
        [flag, path] if flag == OsStr::new("--network-bundle") => PathBuf::from(path),
        _ => return Err("Use --help for supported miner arguments".into()),
    };
    if !root
        .try_exists()
        .map_err(|_| "Data directory unavailable")?
    {
        platform::Directory::create(&root)?;
    }
    platform::Directory::open(&root)?;
    // The foreground lease spans setup and observation; a second wizard cannot
    // modify the destination of a running worker owned by this frontend.
    let frontend_lock = match platform::create_private(&root.join("miner-frontend.lock")) {
        Ok(file) => file,
        Err(_) => platform::read_private(&root.join("miner-frontend.lock"), true)?,
    };
    frontend_lock
        .try_lock()
        .map_err(|_| "Another miner frontend is active; use --status")?;
    if !cfg!(feature = "network") {
        return Err("This diagnostic build cannot initialize or start mining".into());
    }
    let directory = spinner(|| initialize(&root, &bundle))?;
    let idle = idle_lease(&directory)?;
    wizard(&root, &directory)?;
    drop(idle);
    monitor(&directory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    fn temporary() -> PathBuf {
        std::env::temp_dir().join(format!(
            "siworld-windows-shell-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ))
    }
    #[test]
    fn active_worker_lease_prevents_reconfiguration() {
        let root = temporary();
        let d = platform::Directory::create(&root).unwrap();
        let first = idle_lease(&root).unwrap();
        assert!(idle_lease(&root).is_err());
        assert!(std::fs::remove_file(root.join(service::LEASE_FILE)).is_err());
        drop(first);
        drop(idle_lease(&root).unwrap());
        drop(d);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn missing_database_or_invalid_bundle_never_resets_existing_state() {
        let root = temporary();
        let d = platform::Directory::create(&root).unwrap();
        let bundle = root.join("synthetic-invalid-bundle.json");
        std::fs::write(&bundle, b"{\"version\":1}").unwrap();
        assert!(initialize(&root, &bundle).is_err());
        assert!(!root.join("network").exists());
        platform::Directory::create(&root.join("network")).unwrap();
        assert!(initialize(&root, &bundle).is_err());
        assert!(root.join("network").exists());
        drop(d);
        std::fs::remove_dir_all(root).unwrap();
    }
}
