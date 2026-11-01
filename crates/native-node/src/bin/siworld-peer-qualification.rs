//! Explicit disposable-fixture qualification entry point. Never use real wallets.
fn main() {
    if siworld_native_node::service::network::qualification::run(std::env::args().skip(1).collect())
        .is_err()
    {
        eprintln!("isolated peer qualification rejected; preserve all artifacts");
        std::process::exit(1);
    }
}
