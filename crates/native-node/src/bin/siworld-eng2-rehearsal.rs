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
    #[cfg(all(unix, feature = "eng2-runtime"))]
    if args.len() == 5
        && args[4] == "--json"
        && (args[0] == "--isolated-production-init" || args[0] == "--isolated-production-request")
    {
        let directory = std::path::Path::new(&args[1]);
        let source = std::path::Path::new(&args[2]);
        let pin = args[3]
            .to_str()
            .ok_or("invalid isolated production SHA-256")?;
        let result = if args[0] == "--isolated-production-init" {
            siworld_native_node::eng2::isolated_production::initialize(directory, source, pin)?
        } else {
            siworld_native_node::eng2::isolated_production::submit(directory, source, pin)?
        };
        println!("{result}");
        return Ok(());
    }
    if args.len() == 8 && args[0] == "--qualification-audit-history" && args[7] == "--json" {
        println!(
            "{}",
            siworld_native_node::eng2::rehearsal::partition::qualification::full_history::export(
                std::path::Path::new(&args[1]),
                std::path::Path::new(&args[2]),
                (
                    std::path::Path::new(&args[3]),
                    args[4].to_str().ok_or("invalid history budget SHA-256")?
                ),
                (
                    std::path::Path::new(&args[5]),
                    args[6].to_str().ok_or("invalid history binding SHA-256")?
                ),
            )?
        );
        return Ok(());
    }
    if args.len() == 11 && args[0] == "--qualification-compare-history" && args[10] == "--json" {
        println!("{}", siworld_native_node::eng2::rehearsal::partition::qualification::persisted_state::compare_history(
            std::path::Path::new(&args[1]),
            (std::path::Path::new(&args[2]), args[3].to_str().ok_or("invalid history manifest SHA-256")?),
            (std::path::Path::new(&args[4]), args[5].to_str().ok_or("invalid history expectations SHA-256")?),
            (std::path::Path::new(&args[6]), args[7].to_str().ok_or("invalid history binding SHA-256")?),
            (std::path::Path::new(&args[8]), args[9].to_str().ok_or("invalid history budget SHA-256")?),
        )?);
        return Ok(());
    }
    if args.len() == 9 && args[0] == "--qualification-compare-state" && args[8] == "--json" {
        println!(
            "{}",
            siworld_native_node::eng2::rehearsal::partition::qualification::persisted_state::compare(
                std::path::Path::new(&args[1]),
                (
                    std::path::Path::new(&args[2]),
                    args[3].to_str().ok_or("invalid comparison manifest SHA-256")?
                ),
                (
                    std::path::Path::new(&args[4]),
                    args[5].to_str().ok_or("invalid expectations SHA-256")?
                ),
                (
                    std::path::Path::new(&args[6]),
                    args[7].to_str().ok_or("invalid comparison binding SHA-256")?
                )
            )?
        );
        return Ok(());
    }
    #[cfg(feature = "native-p2p")]
    if args.len() == 7 && args[0] == "--qualification-send-input" && args[6] == "--json" {
        println!(
            "{}",
            siworld_native_node::eng2::rehearsal::partition::qualification::invalid_peer::send(
                std::path::Path::new(&args[1]),
                std::path::Path::new(&args[2]),
                args[3].to_str().ok_or("invalid sender plan SHA-256")?,
                std::path::Path::new(&args[4]),
                args[5].to_str().ok_or("invalid sender binding SHA-256")?
            )?
        );
        return Ok(());
    }
    if args.len() == 6 && args[0] == "--qualification-audit" && args[5] == "--json" {
        println!(
            "{}",
            siworld_native_node::eng2::rehearsal::partition::qualification::audit(
                std::path::Path::new(&args[1]),
                std::path::Path::new(&args[2]),
                std::path::Path::new(&args[3]),
                args[4].to_str().ok_or("invalid binding SHA-256")?
            )?
        );
        return Ok(());
    }
    if args.len() == 8 && args[0] == "--qualification-replay-prefix" && args[7] == "--json" {
        let height = args[4]
            .to_str()
            .ok_or("invalid qualification prefix height")?
            .parse()
            .map_err(|_| "invalid qualification prefix height")?;
        println!(
            "{}",
            siworld_native_node::eng2::rehearsal::partition::qualification::replay_prefix(
                std::path::Path::new(&args[1]),
                args[2].to_str().ok_or("invalid source manifest SHA-256")?,
                std::path::Path::new(&args[3]),
                height,
                std::path::Path::new(&args[5]),
                args[6].to_str().ok_or("invalid binding SHA-256")?
            )?
        );
        return Ok(());
    }
    #[cfg(unix)]
    if args.len() == 10 && args[0] == "--qualification-driver-case" && args[9] == "--json" {
        let depth = args[6]
            .to_str()
            .ok_or("invalid qualification Driver depth")?
            .parse()
            .map_err(|_| "invalid qualification Driver depth")?;
        println!(
            "{}",
            siworld_native_node::eng2::rehearsal::partition::qualification::driver_case(
                (
                    std::path::Path::new(&args[1]),
                    args[2].to_str().ok_or("invalid first manifest SHA-256")?,
                    std::path::Path::new(&args[3]),
                    args[4].to_str().ok_or("invalid second manifest SHA-256")?
                ),
                std::path::Path::new(&args[5]),
                depth,
                std::path::Path::new(&args[7]),
                args[8].to_str().ok_or("invalid binding SHA-256")?
            )?
        );
        return Ok(());
    }
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
        return Err("usage: siworld-eng2-rehearsal NEW_DIRECTORY --fee-mode legacy-miner --blocks 28 --json; or --check-continuation SOURCE NEW_DIRECTORY --json; or --continue SOURCE NEW_DIRECTORY --fee-mode legacy-miner --blocks 28 --json; or --partition-init NEW_CAMPAIGN --json; or --partition-node CAMPAIGN NEW_NODE INDEX --json; or --partition-height NODE HEIGHT --json; or --isolated-production-init EMPTY_NODE MANIFEST MANIFEST_SHA256 --json; or --isolated-production-request NODE REQUEST REQUEST_SHA256 --json (Unix eng2-runtime owner build); or --partition-audit NODE NEW_OUTPUT --json; or --partition-replay-prefix EXPORT EMPTY_NODE HEIGHT --json; or --qualification-audit-history NODE NEW_OUTPUT BUDGET BUDGET_SHA256 BINDING BINDING_SHA256 --json; or --qualification-compare-history NODE EXPORT MANIFEST_SHA256 EXPECTATIONS EXPECTATIONS_SHA256 BINDING BINDING_SHA256 BUDGET BUDGET_SHA256 --json; or --qualification-compare-state NODE EXPORT MANIFEST_SHA256 EXPECTATIONS EXPECTATIONS_SHA256 BINDING BINDING_SHA256 --json; or --qualification-send-input IDENTITY_NODE PLAN PLAN_SHA256 BINDING BINDING_SHA256 --json (native-p2p owner build); or --qualification-audit NODE NEW_OUTPUT BINDING BINDING_SHA256 --json; or --qualification-replay-prefix EXPORT MANIFEST_SHA256 EMPTY_NODE HEIGHT BINDING BINDING_SHA256 --json; or --qualification-driver-case A_EXPORT A_MANIFEST_SHA256 B_EXPORT B_MANIFEST_SHA256 NEW_DIRECTORY DEPTH BINDING BINDING_SHA256 --json (Unix owner only); or --partition-driver-case A_EXPORT A_MANIFEST_SHA256 B_EXPORT B_MANIFEST_SHA256 NEW_DIRECTORY DEPTH --json (Unix owner only)".into());
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
