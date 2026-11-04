//! Bounded public-record authentication for an unprivileged archive receiver.
use siworld_native_node::{
    commitment::CommitmentBlock, compact::CompactBlock, ranges::MAX_COMPACT,
};
use std::io::{Read, Write};
fn run() -> Result<(), ()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if !args.is_empty() && args != ["--commitments"] && args != ["--tree-stats"] {
        return Err(());
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((MAX_COMPACT + 49) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if !args.is_empty() {
        let projected = CommitmentBlock::project(&bytes).map_err(|_| ())?;
        let record = CommitmentBlock::decode(&projected).map_err(|_| ())?;
        let result = if args == ["--commitments"] {
            projected
        } else {
            serde_json::to_vec(&serde_json::json!({"height":record.height,
                "downloaded_bytes":projected.len(), "output_count":record.outputs.len(),
                "authentication_ciphertext_bytes":record.authentication_ciphertext_bytes,
                "timestamp":record.timestamp, "id":crate_hex(&record.id)}))
            .map_err(|_| ())?
        };
        return std::io::stdout().write_all(&result).map_err(|_| ());
    }
    let record = CompactBlock::decode(&bytes).map_err(|_| ())?;
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let result = serde_json::json!({"id":hex(&record.id),"network":hex(&record.block.network),
        "height":record.block.height,"parent":hex(&record.block.parent),
        "sha256":format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(&bytes))});
    std::io::stdout()
        .write_all(result.to_string().as_bytes())
        .map_err(|_| ())
}
fn crate_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn main() {
    if run().is_err() {
        eprintln!("Compact authentication rejected.");
        std::process::exit(1);
    }
}
