//! Bounded public-record authentication for an unprivileged archive receiver.
use siworld_native_node::{compact::CompactBlock, ranges::MAX_COMPACT};
use std::io::{Read, Write};
fn run() -> Result<(), ()> {
    if std::env::args_os().len() != 1 {
        return Err(());
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((MAX_COMPACT + 49) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    let record = CompactBlock::decode(&bytes).map_err(|_| ())?;
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let result = serde_json::json!({"id":hex(&record.id),"network":hex(&record.block.network),
        "height":record.block.height,"parent":hex(&record.block.parent),
        "sha256":format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(&bytes))});
    std::io::stdout()
        .write_all(result.to_string().as_bytes())
        .map_err(|_| ())
}
fn main() {
    if run().is_err() {
        eprintln!("Compact authentication rejected.");
        std::process::exit(1);
    }
}
