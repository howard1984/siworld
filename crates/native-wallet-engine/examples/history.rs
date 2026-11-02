//! Synthetic header-valid compact histories; not full transaction-valid chains.
#[path = "../tests/common/mod.rs"]
mod common;
use siworld_native_wallet_engine::{compact::CompactBlock, local::hex, wire::PublicRecord};
fn main() {
    let root = std::path::PathBuf::from(std::env::args().nth(1).expect("Fresh output directory"));
    if root.exists() {
        panic!("Use a fresh history output directory");
    }
    std::fs::create_dir_all(&root).unwrap();
    for slots in [64, 576] {
        let folder = root.join(slots.to_string());
        std::fs::create_dir(&folder).unwrap();
        let (config, mut block) = common::fixture_slots(slots);
        for tx in &mut block.transactions {
            tx.proof = vec![7; 588832];
        }
        block.settlement_proof = vec![9; 520203];
        let mut parent = config.genesis_id();
        let mut ids = Vec::new();
        let mut bytes = 0usize;
        for height in 1..=288u32 {
            block.height = height as u64;
            block.timestamp = height as u64 * 300 + 1;
            block.parent = parent;
            for (index, tx) in block.transactions.iter_mut().enumerate() {
                let mut body = [0; 2027];
                for j in 0..5 {
                    body[j * 48..(j + 1) * 48].copy_from_slice(&common::digest(
                        10 + height * 10000 + index as u32 * 5 + j as u32,
                    ));
                }
                tx.record = PublicRecord::new(
                    tx.record.snapshot,
                    body,
                    common::digest(10000000 + height * 1000 + index as u32),
                )
                .unwrap();
            }
            block
                .transactions
                .sort_by_key(|t| t.record.statement_id(&config.network));
            if height > 1 {
                for (i, reward) in block.rewards.iter_mut().enumerate() {
                    reward.commitment = common::digest(300000000 + height * 10 + i as u32);
                    reward.ciphertext.fill(0);
                }
            }
            let compact = CompactBlock::export(&block).unwrap();
            let id = CompactBlock::decode(&compact).unwrap().id;
            assert_eq!(id, block.id().unwrap());
            let name = hex(&id);
            std::fs::write(folder.join(format!("{name}.bin")), &compact).unwrap();
            ids.push(name);
            bytes += compact.len();
            parent = id;
        }
        std::fs::write(folder.join("chain.json"),serde_json::to_vec(&serde_json::json!({"network":hex(&config.network),"genesis":hex(&config.genesis_id()),"ids":ids})).unwrap()).unwrap();
        println!(
            "{}",
            serde_json::json!({"slots":slots,"blocks":288,"total_compact_bytes":bytes})
        );
    }
}
