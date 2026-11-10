//! Explicit offline native proof rehearsal; never starts network services.
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 6
        || args[1] != "--fee-mode"
        || args[2] != "legacy-miner"
        || args[3] != "--blocks"
        || args[5] != "--json"
    {
        return Err("usage: siworld-eng2-rehearsal NEW_DIRECTORY --fee-mode legacy-miner --blocks 27 --json".into());
    }
    let blocks = args[4]
        .to_str()
        .ok_or("invalid block count")?
        .parse()
        .map_err(|_| "invalid block count")?;
    let result = siworld_native_node::eng2::rehearsal::run(
        std::path::Path::new(&args[0]),
        blocks,
        siworld_native_node::eng2::genesis::FeeMode::LegacyMiner,
    )?;
    println!(
        "{}",
        serde_json::to_string(&result).map_err(|_| "result encoding failed")?
    );
    Ok(())
}
