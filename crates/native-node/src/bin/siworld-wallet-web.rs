//! Loopback-only native engineering wallet launcher.
use siworld_native_node::web_wallet::{self, Options, Server};
use std::{collections::BTreeMap, path::PathBuf};
fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let command=args.next().ok_or("usage: siworld-wallet-web keygen AUTH_FILE | serve --chain-dir DIR --wallet-dir DIR --auth-file FILE --port PORT | stop --auth-file FILE --port PORT --expected-process-id PID")?;
    if command == "keygen" {
        let auth = PathBuf::from(args.next().ok_or("missing external authentication file")?);
        if args.next().is_some() {
            return Err("unexpected argument".into());
        }
        return web_wallet::keygen(&auth);
    }
    let mut values = BTreeMap::new();
    while let Some(key) = args.next() {
        if !key.starts_with("--")
            || values
                .insert(key, args.next().ok_or("missing option value")?)
                .is_some()
        {
            return Err("invalid or duplicate option".into());
        }
    }
    let port = values
        .remove("--port")
        .unwrap_or_else(|| "8782".into())
        .parse::<u16>()
        .map_err(|_| "invalid port")?;
    let auth = PathBuf::from(values.remove("--auth-file").ok_or("missing --auth-file")?);
    if command == "stop" {
        let expected = values
            .remove("--expected-process-id")
            .ok_or("missing --expected-process-id")?
            .parse()
            .map_err(|_| "invalid process ID")?;
        if !values.is_empty() {
            return Err("unexpected option".into());
        }
        return web_wallet::stop(&auth, port, expected);
    }
    if command != "serve" || port == 0 {
        return Err("invalid command or port".into());
    }
    let options = Options {
        chain_dir: PathBuf::from(values.remove("--chain-dir").ok_or("missing --chain-dir")?),
        wallet_dir: PathBuf::from(
            values
                .remove("--wallet-dir")
                .ok_or("missing --wallet-dir")?,
        ),
        auth_file: auth,
        port,
    };
    if !values.is_empty() {
        return Err("unexpected option".into());
    }
    let server = Server::bind(options)?;
    println!(
        "Local engineering wallet: http://127.0.0.1:{}/",
        server.port()
    );
    server.run()
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
