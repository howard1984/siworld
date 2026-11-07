//! Write-once engineering checkpoint key tool; stdout contains public data only.
use siworld_native_node::{identity::checkpoint_authority::Authority, local, p2p::Binding};
use std::path::Path;
fn run() -> Result<(), String> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments.len() != 3 || !matches!(arguments[0].as_str(), "initialize" | "public") {
        return Err("expected initialize|public NODE_DIRECTORY PRIVATE_AUTHORITY_DIRECTORY".into());
    }
    let config = local::load(Path::new(&arguments[1]))?;
    let binding = Binding::new(&config);
    let directory = Path::new(&arguments[2]);
    let authority = if arguments[0] == "initialize" {
        Authority::initialize(directory, binding)
    } else {
        Authority::load(directory, binding)
    }
    .map_err(|_| "checkpoint authority initialization or load failed; existing files preserved")?;
    println!(
        "{}",
        serde_json::json!({"schema":1,"purpose":"engineering-checkpoint-only", "algorithm":"ML-DSA-65",
      "network":local::hex(&binding.network),"genesis":local::hex(&binding.genesis),"verifier":local::hex(&binding.verifier),
      "public_key":local::hex(&authority.public_key())})
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
