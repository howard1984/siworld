#![forbid(unsafe_code)]
#[cfg(windows)]
mod windows;
fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        print!("{}", siworld_miner_cli::HELP);
        return;
    }
    #[cfg(windows)]
    let result = windows::run(args);
    #[cfg(not(windows))]
    let result: Result<(), String> =
        Err("This package supports native Windows 10/11 x86_64 only".into());
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
