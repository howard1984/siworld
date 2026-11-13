//! Explicit offline native proof rehearsal; never starts network services.
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), String> {
    if std::env::var_os("GITHUB_ACTIONS").is_some() || std::env::var("CI").as_deref() == Ok("true")
    {
        return Err("native rehearsal execution requires an owner-operated environment".into());
    }
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    #[cfg(unix)]
    if args.len() == 8 && args[0] == "--partition-driver-case" && args[7] == "--json" {
        let pin_a = args[2]
            .to_str()
            .ok_or("invalid first corpus manifest SHA-256")?;
        let pin_b = args[4]
            .to_str()
            .ok_or("invalid second corpus manifest SHA-256")?;
        let depth = args[6]
            .to_str()
            .ok_or("invalid Driver case depth")?
            .parse()
            .map_err(|_| "invalid Driver case depth")?;
        println!(
            "{}",
            siworld_native_node::eng2::rehearsal::partition::driver_case(
                std::path::Path::new(&args[1]),
                pin_a,
                std::path::Path::new(&args[3]),
                pin_b,
                std::path::Path::new(&args[5]),
                depth
            )?
        );
        return Ok(());
    }
    if args.len() == 3 && args[0] == "--partition-init" && args[2] == "--json" {
        println!(
            "{}",
            siworld_native_node::eng2::rehearsal::partition::initialize(std::path::Path::new(
                &args[1]
            ))?
        );
        return Ok(());
    }
    if args.len() == 5 && args[0] == "--partition-node" && args[4] == "--json" {
        let index = args[3]
            .to_str()
            .ok_or("invalid partition reward index")?
            .parse()
            .map_err(|_| "invalid partition reward index")?;
        println!(
            "{}",
            siworld_native_node::eng2::rehearsal::partition::initialize_node(
                std::path::Path::new(&args[1]),
                std::path::Path::new(&args[2]),
                index
            )?
        );
        return Ok(());
    }
    if args.len() == 4 && args[0] == "--partition-height" && args[3] == "--json" {
        let height = args[2]
            .to_str()
            .ok_or("invalid partition height")?
            .parse()
            .map_err(|_| "invalid partition height")?;
        println!(
            "{}",
            siworld_native_node::eng2::rehearsal::partition::set_production_ceiling(
                std::path::Path::new(&args[1]),
                height
            )?
        );
        return Ok(());
    }

    if args.len() == 5 && args[0] == "--partition-replay-prefix" && args[4] == "--json" {
        let height = args[3]
            .to_str()
            .ok_or("invalid replay prefix height")?
            .parse()
            .map_err(|_| "invalid replay prefix height")?;
        println!(
            "{}",
            siworld_native_node::eng2::rehearsal::partition::replay_prefix(
                std::path::Path::new(&args[1]),
                std::path::Path::new(&args[2]),
                height
            )?
        );
        return Ok(());
    }
    if args.len() == 4 && args[0] == "--partition-audit" && args[3] == "--json" {
        println!(
            "{}",
            siworld_native_node::eng2::rehearsal::partition::audit(
                std::path::Path::new(&args[1]),
                std::path::Path::new(&args[2])
            )?
        );
        return Ok(());
    }
    if args.len() == 4 && args[0] == "--check-continuation" && args[3] == "--json" {
        println!(
            "{}",
            siworld_native_node::eng2::rehearsal::check_continuation(
                std::path::Path::new(&args[1]),
                std::path::Path::new(&args[2])
            )?
        );
        return Ok(());
    }
    if args.len() == 8
        && args[0] == "--continue"
        && args[3] == "--fee-mode"
        && args[4] == "legacy-miner"
        && args[5] == "--blocks"
        && args[6] == "28"
        && args[7] == "--json"
    {
        println!(
            "{}",
            siworld_native_node::eng2::rehearsal::continue_run(
                std::path::Path::new(&args[1]),
                std::path::Path::new(&args[2])
            )?
        );
        return Ok(());
    }
    if args.len() != 6
        || args[1] != "--fee-mode"
        || args[2] != "legacy-miner"
        || args[3] != "--blocks"
        || args[5] != "--json"
    {
        return Err("usage: siworld-eng2-rehearsal NEW_DIRECTORY --fee-mode legacy-miner --blocks 28 --json; or --check-continuation SOURCE NEW_DIRECTORY --json; or --continue SOURCE NEW_DIRECTORY --fee-mode legacy-miner --blocks 28 --json; or --partition-init NEW_CAMPAIGN --json; or --partition-node CAMPAIGN NEW_NODE INDEX --json; or --partition-height NODE HEIGHT --json; or --partition-audit NODE NEW_OUTPUT --json; or --partition-replay-prefix EXPORT EMPTY_NODE HEIGHT --json; or --partition-driver-case A_EXPORT A_MANIFEST_SHA256 B_EXPORT B_MANIFEST_SHA256 NEW_DIRECTORY DEPTH --json (Unix owner only)".into());
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
