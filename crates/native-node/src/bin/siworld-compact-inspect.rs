//! Bounded public-record authentication for an unprivileged archive receiver.
use siworld_native_node::{
    commitment::CommitmentBlock,
    compact::CompactBlock,
    ranges::MAX_COMPACT,
    wire::{Hash, MAX_ENVELOPE_BYTES, SIDECAR_BYTES, Sidecar, TX_PREFIX_BYTES, Transaction},
};
use std::io::{Read, Write};

/// Stateless framing and fee-opening validation; proof verification and chain
/// admission remain the responsibility of the validating node.
fn transaction_packet(bytes: &[u8], network: &Hash) -> Result<(), ()> {
    if !(TX_PREFIX_BYTES + 1 + SIDECAR_BYTES..=MAX_ENVELOPE_BYTES + SIDECAR_BYTES)
        .contains(&bytes.len())
    {
        return Err(());
    }
    let (envelope, sidecar) = bytes.split_at(bytes.len() - SIDECAR_BYTES);
    let transaction = Transaction::decode_envelope(envelope, network).map_err(|_| ())?;
    Sidecar::decode(sidecar)
        .and_then(|opening| opening.check_opening(&transaction.record, network))
        .map_err(|_| ())
}

fn run() -> Result<(), ()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--transaction-packet") {
        if args.len() != 2 || args[1].len() != 64 {
            return Err(());
        }
        let mut network = [0; 32];
        for (index, byte) in network.iter_mut().enumerate() {
            *byte = u8::from_str_radix(args[1].get(index * 2..index * 2 + 2).ok_or(())?, 16)
                .map_err(|_| ())?;
        }
        let mut bytes = Vec::new();
        std::io::stdin()
            .take((MAX_ENVELOPE_BYTES + SIDECAR_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| ())?;
        transaction_packet(&bytes, &network)?;
        return std::io::stdout().write_all(b"valid\n").map_err(|_| ());
    }
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
        eprintln!("Input validation rejected.");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use native::{
        codec::encode_digest,
        multi_asset::{F, Hasher},
    };
    use p3_field::PrimeCharacteristicRing;
    use siworld_native_node::wire::{PUBLIC_BYTES, PublicRecord, Snapshot};

    // Synthetic public fields and opaque proof bytes are not a valid payment.
    fn packet() -> Vec<u8> {
        let network = [9; 32];
        let mut body = [0; PUBLIC_BYTES];
        body[..4].copy_from_slice(&3u32.to_le_bytes());
        body[48..52].copy_from_slice(&4u32.to_le_bytes());
        let record = PublicRecord::new(
            Snapshot {
                height: 11,
                block_id: [3; 32],
            },
            body,
            encode_digest(&Hasher::new().fee_commit(7, &[F::from_u32(5); 8])),
        )
        .unwrap();
        let opening = Sidecar {
            transaction_id: record.statement_id(&network),
            fee: 7,
            blind: [5; 8],
        };
        let mut packet = Transaction {
            record,
            proof: vec![1, 2, 3],
        }
        .encode_envelope(&network)
        .unwrap();
        packet.extend_from_slice(&opening.encode().unwrap());
        packet
    }

    #[test]
    fn matching_opening_accepts_only_the_selected_network() {
        assert!(transaction_packet(&packet(), &[9; 32]).is_ok());
        assert!(transaction_packet(&packet(), &[8; 32]).is_err());
    }

    #[test]
    fn changed_fee_blind_identity_and_noncanonical_opening_are_rejected() {
        let original = packet();
        let start = original.len() - SIDECAR_BYTES;
        for offset in [start, start + 4, start + 6, start + 38, start + 46] {
            let mut changed = original.clone();
            changed[offset] ^= 1;
            assert!(transaction_packet(&changed, &[9; 32]).is_err());
        }
        let mut changed = original;
        changed[start + 46..start + 50].fill(255);
        assert!(transaction_packet(&changed, &[9; 32]).is_err());
    }

    #[test]
    fn envelope_bounds_and_canonical_fields_are_checked() {
        let original = packet();
        for offset in [0, 4, 6, TX_PREFIX_BYTES - 4] {
            let mut changed = original.clone();
            changed[offset] ^= 1;
            assert!(transaction_packet(&changed, &[9; 32]).is_err());
        }
        for size in [0, TX_PREFIX_BYTES, original.len() - 1] {
            assert!(transaction_packet(&original[..size], &[9; 32]).is_err());
        }
        assert!(
            transaction_packet(&vec![0; MAX_ENVELOPE_BYTES + SIDECAR_BYTES + 1], &[9; 32]).is_err()
        );
        let mut changed = original;
        changed[105..109].fill(255);
        assert!(transaction_packet(&changed, &[9; 32]).is_err());
    }
}
