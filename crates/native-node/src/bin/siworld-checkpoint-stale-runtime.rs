//! Isolated real-time alarm exercise; never opens an existing node or network.
fn main() {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    #[cfg(unix)]
    let result = if args.len() == 1 {
        siworld_native_node::checkpoint_stale_runtime::run(std::path::Path::new(&args[0]))
    } else {
        Err("expected one absent isolated output directory".to_owned())
    };
    #[cfg(not(unix))]
    let result: Result<serde_json::Value, String> = {
        let _ = args;
        Err("isolated runtime requires Unix".to_owned())
    };
    match result {
        Ok(value) => println!("{value}"),
        Err(error) => {
            println!("{}", serde_json::json!({"status":"failed","error":error}));
            std::process::exit(1);
        }
    }
}
