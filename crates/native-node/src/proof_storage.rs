//! Separate expiring proof bodies from permanently authenticated public bytes.
//! Splitting is a storage operation, never evidence of transaction validity.
use crate::{
    compact::CompactBlock,
    wire::{Block, Hash, MAX_BLOCK_BYTES, MAX_SETTLEMENT_PROOF, MAX_TX_PROOF},
};

const MAGIC: &[u8; 8] = b"SWPB0001";

pub struct SplitBlock {
    pub permanent: Vec<u8>,
    pub proofs: Vec<u8>,
}
impl SplitBlock {
    /// The storage owner must accept the block through the common transition
    /// before making these records part of canonical history.
    pub fn encode(block: &Block) -> Result<Self, String> {
        block.validate_shape()?;
        let permanent = CompactBlock::export(block)?;
        let mut proofs = MAGIC.to_vec();
        proofs.extend_from_slice(&block.id()?);
        let emit = |out: &mut Vec<u8>, proof: &[u8]| -> Result<(), String> {
            let length = u32::try_from(proof.len()).map_err(|_| "proof storage length overflow")?;
            out.extend_from_slice(&length.to_le_bytes());
            out.extend_from_slice(proof);
            Ok(())
        };
        for transaction in &block.transactions {
            emit(&mut proofs, &transaction.proof)?;
        }
        for issuance in &block.issuances {
            emit(&mut proofs, &issuance.proof)?;
        }
        emit(&mut proofs, &block.settlement_proof)?;
        if proofs.len() > MAX_BLOCK_BYTES {
            return Err("proof storage byte limit".into());
        }
        Ok(Self { permanent, proofs })
    }
}

pub fn restore(permanent: &[u8], proofs: &[u8]) -> Result<Block, String> {
    if proofs.len() < 40 || proofs.len() > MAX_BLOCK_BYTES || &proofs[..8] != MAGIC {
        return Err("invalid stored proof bundle".into());
    }
    let compact = CompactBlock::decode(permanent)?;
    if proofs[8..40] != compact.id {
        return Err("proof bundle belongs to another block".into());
    }
    let mut block = compact.block;
    let mut at = 40usize;
    let mut take = |maximum: usize| -> Result<Vec<u8>, String> {
        let end = at.checked_add(4).ok_or("proof offset overflow")?;
        let length = u32::from_le_bytes(
            proofs
                .get(at..end)
                .ok_or("truncated proof length")?
                .try_into()
                .expect("bounded length"),
        ) as usize;
        at = end;
        let end = at.checked_add(length).ok_or("proof offset overflow")?;
        if length == 0 || length > maximum {
            return Err("stored proof length limit".into());
        }
        let proof = proofs.get(at..end).ok_or("truncated proof body")?.to_vec();
        at = end;
        Ok(proof)
    };
    for transaction in &mut block.transactions {
        transaction.proof = take(MAX_TX_PROOF)?;
    }
    for issuance in &mut block.issuances {
        issuance.proof = take(crate::issuance::MAX_PROOF_BYTES)?;
    }
    block.settlement_proof = take(MAX_SETTLEMENT_PROOF)?;
    if at != proofs.len() || block.id()? != compact.id {
        return Err("stored proof bundle does not reproduce the canonical block".into());
    }
    block.validate_shape()?;
    Ok(block)
}

pub fn public_identity(permanent: &[u8]) -> Result<(u64, Hash), String> {
    let compact = CompactBlock::decode(permanent)?;
    Ok((compact.block.height, compact.id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        fixtures,
        state::{Config, State},
    };

    fn block() -> Block {
        fixtures::candidate(
            &State::new(Config::development([42; 32], 0).unwrap()).unwrap(),
            100,
        )
    }
    #[test]
    fn split_restores_exact_canonical_bytes_and_identity() {
        let block = block();
        let split = SplitBlock::encode(&block).unwrap();
        let restored = restore(&split.permanent, &split.proofs).unwrap();
        assert_eq!(restored.encode().unwrap(), block.encode().unwrap());
        assert_eq!(
            public_identity(&split.permanent).unwrap(),
            (block.height, block.id().unwrap())
        );
    }
    #[test]
    fn proof_free_bytes_preserve_ciphertexts_nullifiers_rewards_and_fee_commitments() {
        let block = block();
        let split = SplitBlock::encode(&block).unwrap();
        let public = CompactBlock::decode(&split.permanent).unwrap().block;
        assert_eq!(public.rewards, block.rewards);
        assert_eq!(public.fund_spends, block.fund_spends);
        for (actual, original) in public.transactions.iter().zip(&block.transactions) {
            assert_eq!(actual.record, original.record);
            assert!(actual.proof.is_empty());
        }
        assert!(public.settlement_proof.is_empty());
        assert!(public.validate_shape().is_err());
    }
    #[test]
    fn mismatched_corrupt_truncated_and_trailing_bundles_fail() {
        let split = SplitBlock::encode(&block()).unwrap();
        for at in [8, 44, split.proofs.len() - 1] {
            let mut changed = split.proofs.clone();
            changed[at] ^= 1;
            assert!(restore(&split.permanent, &changed).is_err());
        }
        assert!(restore(&split.permanent, &split.proofs[..split.proofs.len() - 1]).is_err());
        let mut trailing = split.proofs.clone();
        trailing.push(0);
        assert!(restore(&split.permanent, &trailing).is_err());
    }
    #[test]
    fn large_proof_bodies_are_absent_from_permanent_storage() {
        let mut block = block();
        for tx in &mut block.transactions {
            tx.proof = vec![7; 64 * 1024];
        }
        block.settlement_proof = vec![8; 64 * 1024];
        let split = SplitBlock::encode(&block).unwrap();
        assert!(split.permanent.len() * 10 < split.proofs.len());
        assert_eq!(
            restore(&split.permanent, &split.proofs)
                .unwrap()
                .encode()
                .unwrap(),
            block.encode().unwrap()
        );
    }
}
