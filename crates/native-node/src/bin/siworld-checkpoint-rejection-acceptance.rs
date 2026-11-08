//! Explicit offline engineering acceptance; never starts a node or listener.
use serde_json::json;

fn main() {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let result = if args.len() == 5 && args[4] == "--json" {
        #[cfg(unix)]
        {
            args[1]
                .to_str()
                .ok_or_else(|| "invalid_expected_run".to_owned())
                .and_then(|run| {
                    siworld_native_node::checkpoint_rejection_acceptance::run(
                        std::path::Path::new(&args[0]),
                        run,
                        std::path::Path::new(&args[2]),
                        std::path::Path::new(&args[3]),
                    )
                })
        }
        #[cfg(not(unix))]
        {
            Err::<serde_json::Value, _>("acceptance_requires_unix".to_owned())
        }
    } else {
        Err("usage: siworld-checkpoint-rejection-acceptance DATA EXPECTED_FINAL_RUN_ID CURRENT_CERT OLD_VALID_CERT --json".to_owned())
    };
    match result {
        Ok(receipt) => println!("{receipt}"),
        Err(code) => {
            println!(
                "{}",
                json!({"schema":1,"status":"failed","error":code,
                "preserve_fixture":true,"cleanup_performed":false})
            );
            std::process::exit(1);
        }
    }
}
