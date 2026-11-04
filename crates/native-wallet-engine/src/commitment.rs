//! Minimal historical tree input authenticated to the existing worked block.
//! Adjacent ciphertext bytes required by BLAKE3 chunks are never parsed here.
use crate::{
    compact::HEADER,
    ranges::{MAX_COMPACT, RangeProof, Sparse},
    wire::*,
};
use native::codec::decode_digest;
use siworld_core::v1_economics::RewardMode;

pub struct CommitmentBlock {
    pub network: Hash,
    pub height: u64,
    pub parent: Hash,
    pub timestamp: u64,
    pub target: Hash,
    pub nonce: u64,
    pub seed: Hash,
    pub id: Hash,
    pub outputs: Vec<DigestBytes>,
    pub authentication_ciphertext_bytes: usize,
}
struct Reader<'a> {
    sparse: &'a Sparse,
    at: usize,
    ranges: Vec<(usize, usize)>,
    ciphertexts: Vec<(usize, usize)>,
}
impl Reader<'_> {
    fn take(&mut self, length: usize) -> Result<Vec<u8>, String> {
        let bytes = self.sparse.read(self.at, length)?;
        self.ranges.push((self.at, length));
        self.skip(length)?;
        Ok(bytes)
    }
    fn skip(&mut self, length: usize) -> Result<(), String> {
        self.at = self
            .at
            .checked_add(length)
            .ok_or("Tree input offset overflow.")?;
        if self.at > self.sparse.length {
            return Err("Tree input length exceeds source.".into());
        }
        Ok(())
    }
    fn u32(&mut self) -> Result<usize, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize)
    }
    fn ciphertext(&mut self, length: usize) -> Result<(), String> {
        self.ciphertexts.push((self.at, length));
        self.skip(length)
    }
    fn commitment(&mut self, out: &mut Vec<DigestBytes>) -> Result<(), String> {
        let cm: DigestBytes = self.take(48)?.try_into().unwrap();
        let _ = decode_digest(&cm).map_err(|_| "Invalid historical output commitment.")?;
        out.push(cm);
        Ok(())
    }
}
impl CommitmentBlock {
    fn parse(
        sparse: &Sparse,
        nonce: u64,
        seed: Hash,
    ) -> Result<(Self, Vec<(usize, usize)>), String> {
        let mut r = Reader {
            sparse,
            at: 0,
            ranges: Vec::new(),
            ciphertexts: Vec::new(),
        };
        let h = r.take(HEADER)?;
        if &h[..4] != b"SWNB" || h[4..6] != BLOCK_VERSION.to_le_bytes() || &h[6..33] != SUITE_ID {
            return Err("Historical block profile mismatch.".into());
        }
        let network: Hash = h[33..65].try_into().unwrap();
        let slots = u16::from_le_bytes(h[145..147].try_into().unwrap()) as usize;
        if !(MIN_SLOTS..=MAX_SLOTS).contains(&slots)
            || !slots.is_multiple_of(GROUP)
            || h[148] as usize > MAX_FUND_SPENDS
            || h[149] as usize > crate::issuance::RECORDS_CODEC_LIMIT
        {
            return Err("Historical block count limit.".into());
        }
        let mode = RewardMode::from_byte(h[147]).map_err(|e| e.to_string())?;
        let mut outputs = Vec::with_capacity(3 * slots + 5);
        for _ in 0..slots {
            let size = r.u32()?;
            let prefix = r.take(65)?;
            if &prefix[..4] != b"SWTX"
                || prefix[4..6] != FORMAT_VERSION.to_le_bytes()
                || &prefix[6..33] != SUITE_ID
                || prefix[33..65] != network
            {
                return Err("Historical transaction profile mismatch.".into());
            }
            r.skip(40 + 96)?; // Snapshot and nullifiers are not historical tree inputs.
            for _ in 0..3 {
                r.commitment(&mut outputs)?;
            }
            r.ciphertext(PUBLIC_BYTES - 240)?;
            r.skip(48)?; // Confidential fee commitment.
            let proof = r.u32()?;
            if proof == 0 || proof > MAX_TX_PROOF || size != TX_PREFIX_BYTES + proof {
                return Err("Historical transaction framing mismatch.".into());
            }
            r.skip(proof)?;
        }
        // Native tree order places issuance commitments before reward/fund outputs.
        let mut rewards = Vec::new();
        for _ in 0..reward_count(mode) {
            r.commitment(&mut rewards)?;
            r.ciphertext(REWARD_CIPHERTEXT_BYTES)?;
        }
        for _ in 0..h[148] {
            r.skip(161)?;
            r.commitment(&mut rewards)?;
            r.ciphertext(REWARD_CIPHERTEXT_BYTES)?;
            r.skip(crate::fund_spend::ENCODED_BYTES - 1522)?;
        }
        for _ in 0..h[149] {
            let size = r.u32()?;
            let start = r.at;
            let prefix = r.take(38)?;
            if &prefix[..4] != b"SWIS"
                || prefix[4..6] != 1u16.to_le_bytes()
                || prefix[6..38] != network
            {
                return Err("Historical issuance profile mismatch.".into());
            }
            r.skip(2000)?;
            let name = u16::from_le_bytes(r.take(2)?.try_into().unwrap()) as usize;
            if name + 1 > crate::issuance::METADATA_CODEC_LIMIT {
                return Err("Historical metadata limit.".into());
            }
            r.skip(name + 9)?;
            for _ in 0..crate::issuance::INITIAL_NOTES {
                r.commitment(&mut outputs)?;
                r.skip(32)?;
                r.ciphertext(crate::issuance::CIPHERTEXT_BYTES)?;
            }
            r.skip(crate::fund_spend::SIGNATURE_BYTES + 96)?;
            let proof = r.u32()?;
            if proof == 0
                || proof > crate::issuance::MAX_PROOF_BYTES
                || size != r.at - start + proof
            {
                return Err("Historical issuance framing mismatch.".into());
            }
            r.skip(proof)?;
        }
        outputs.extend(rewards);
        let settlement = r.u32()?;
        if settlement == 0 || settlement > MAX_SETTLEMENT_PROOF {
            return Err("Historical settlement limit.".into());
        }
        r.skip(settlement)?;
        if r.at != sparse.length {
            return Err("Historical source length mismatch.".into());
        }
        let mut identity =
            blake3::Hasher::new_derive_key("siworld native engineering block identity v2");
        identity.update(&seed);
        identity.update(&nonce.to_le_bytes());
        let result = Self {
            network,
            height: u64::from_le_bytes(h[65..73].try_into().unwrap()),
            parent: h[73..105].try_into().unwrap(),
            timestamp: u64::from_le_bytes(h[105..113].try_into().unwrap()),
            target: h[113..145].try_into().unwrap(),
            nonce,
            seed,
            id: *identity.finalize().as_bytes(),
            outputs,
            authentication_ciphertext_bytes: sparse.disclosed_overlap(&r.ciphertexts),
        };
        Ok((result, r.ranges))
    }
    /// Archive-side projection from authenticated compact data, without full proofs.
    pub fn project(compact: &[u8]) -> Result<Vec<u8>, String> {
        if compact.len() < 65 || compact.len() > MAX_COMPACT + 48 || &compact[..8] != b"SWLC0001" {
            return Err("Compact tree source unavailable.".into());
        }
        let nonce = u64::from_le_bytes(compact[8..16].try_into().unwrap());
        let seed = compact[16..48].try_into().unwrap();
        let sparse = RangeProof::verify(&compact[48..], seed)?;
        let (_, ranges) = Self::parse(&sparse, nonce, seed)?;
        let proof = RangeProof::project(&compact[48..], seed, &ranges)?;
        let mut result = b"SWLT0001".to_vec();
        result.extend(&compact[8..48]);
        result.extend(proof);
        Ok(result)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 65 || bytes.len() > MAX_COMPACT + 48 || &bytes[..8] != b"SWLT0001" {
            return Err("Historical tree record unavailable.".into());
        }
        let nonce = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let seed = bytes[16..48].try_into().unwrap();
        let sparse = RangeProof::verify(&bytes[48..], seed)?;
        let (result, ranges) = Self::parse(&sparse, nonce, seed)?;
        sparse.require_exact_ranges(&ranges)?;
        Ok(result)
    }
}
