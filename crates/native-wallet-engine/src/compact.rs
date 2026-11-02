//! Proof-free public records authenticated to the unchanged native worked seed.
use crate::{
    issuance::IssuanceRecord,
    ranges::{MAX_COMPACT, RangeProof, Sparse},
    wire::*,
};
use native::codec::{PublicTransaction, decode_digest};
use siworld_core::v1_economics::RewardMode;

pub const HEADER: usize = BLOCK_HEADER_BYTES - 8;
const NONCE: usize = 145;
pub struct CompactBlock {
    pub block: Block,
    pub id: Hash,
    pub seed: Hash,
}
fn u32at(data: &[u8]) -> usize {
    u32::from_le_bytes(data.try_into().unwrap()) as usize
}
fn id(seed: Hash, nonce: u64) -> Hash {
    let mut h = blake3::Hasher::new_derive_key("siworld native engineering block identity v2");
    h.update(&seed);
    h.update(&nonce.to_le_bytes());
    *h.finalize().as_bytes()
}
struct Reader<F> {
    at: usize,
    ranges: Vec<(usize, usize)>,
    read: F,
}
impl<F: Fn(usize, usize) -> Result<Vec<u8>, String>> Reader<F> {
    fn take(&mut self, n: usize) -> Result<Vec<u8>, String> {
        let b = (self.read)(self.at, n)?;
        self.ranges.push((self.at, n));
        self.at = self.at.checked_add(n).ok_or("Compact offset overflow.")?;
        Ok(b)
    }
    fn skip(&mut self, n: usize) -> Result<(), String> {
        self.at = self.at.checked_add(n).ok_or("Compact offset overflow.")?;
        Ok(())
    }
}
fn parse(
    read: impl Fn(usize, usize) -> Result<Vec<u8>, String>,
    length: usize,
    nonce: u64,
) -> Result<(Block, Vec<(usize, usize)>), String> {
    let mut r = Reader {
        at: 0,
        ranges: Vec::new(),
        read,
    };
    let h = r.take(HEADER)?;
    if &h[..4] != b"SWNB" || h[4..6] != BLOCK_VERSION.to_le_bytes() || &h[6..33] != SUITE_ID {
        return Err("Compact block profile mismatch.".into());
    }
    let network = h[33..65].try_into().unwrap();
    let slots = u16::from_le_bytes(h[145..147].try_into().unwrap()) as usize;
    if !(MIN_SLOTS..=MAX_SLOTS).contains(&slots)
        || slots % GROUP != 0
        || h[148] as usize > MAX_FUND_SPENDS
        || h[149] as usize > crate::issuance::RECORDS_CODEC_LIMIT
    {
        return Err("Compact record count limit.".into());
    }
    let mode = RewardMode::from_byte(h[147]).map_err(|e| e.to_string())?;
    let mut transactions = Vec::with_capacity(slots);
    let mut previous = None;
    for _ in 0..slots {
        let size = u32at(&r.take(4)?);
        let p = r.take(TX_PREFIX_BYTES)?;
        let proof = u32at(&p[TX_PREFIX_BYTES - 4..]);
        if proof == 0
            || proof > MAX_TX_PROOF
            || size != TX_PREFIX_BYTES + proof
            || &p[..4] != b"SWTX"
            || p[4..6] != FORMAT_VERSION.to_le_bytes()
            || &p[6..33] != SUITE_ID
            || p[33..65] != network
        {
            return Err("Invalid authenticated compact transaction frame.".into());
        }
        let record = PublicRecord::new(
            Snapshot {
                height: u64::from_le_bytes(p[65..73].try_into().unwrap()),
                block_id: p[73..105].try_into().unwrap(),
            },
            p[105..105 + PUBLIC_BYTES].try_into().unwrap(),
            p[105 + PUBLIC_BYTES..TX_PREFIX_BYTES - 4]
                .try_into()
                .unwrap(),
        )?;
        let key = record.statement_id(&network);
        if previous.is_some_and(|v| v >= key) {
            return Err("Noncanonical compact transaction order.".into());
        }
        previous = Some(key);
        transactions.push(Transaction {
            record,
            proof: Vec::new(),
        });
        r.skip(proof)?;
    }
    let mut rewards = Vec::new();
    for _ in 0..reward_count(mode) {
        let bytes = r.take(REWARD_RECORD_BYTES)?;
        rewards.push(RewardRecord {
            commitment: bytes[..48].try_into().unwrap(),
            ciphertext: bytes[48..].try_into().unwrap(),
        });
    }
    let mut fund_spends = Vec::new();
    for _ in 0..h[148] {
        fund_spends.push(crate::fund_spend::FundSpend::decode(
            &r.take(crate::fund_spend::ENCODED_BYTES)?,
        )?);
    }
    let mut issuances = Vec::new();
    for _ in 0..h[149] {
        let size = u32at(&r.take(4)?);
        let mut prefix = r.take(2040)?;
        let name = u16::from_le_bytes(prefix[2038..2040].try_into().unwrap()) as usize;
        if name > crate::issuance::METADATA_CODEC_LIMIT {
            return Err("Compact issuance metadata limit.".into());
        }
        prefix.extend(r.take(9637 + name - 2040)?);
        let proof = u32at(&prefix[prefix.len() - 4..]);
        if proof == 0 || proof > crate::issuance::MAX_PROOF_BYTES || size != prefix.len() + proof {
            return Err("Compact issuance length mismatch.".into());
        }
        r.skip(proof)?;
        // Decode canonical public/signature fields; no historical proof is downloaded.
        let n = prefix.len();
        prefix[n - 4..].copy_from_slice(&1u32.to_le_bytes());
        prefix.push(0);
        let mut record = IssuanceRecord::decode(&prefix)?;
        record.proof.clear();
        issuances.push(record);
    }
    let settlement = u32at(&r.take(4)?);
    if settlement == 0 || settlement > MAX_SETTLEMENT_PROOF {
        return Err("Compact settlement framing limit.".into());
    }
    r.skip(settlement)?;
    if r.at != length {
        return Err("Compact block length mismatch.".into());
    }
    for reward in &rewards {
        let _ =
            decode_digest(&reward.commitment).map_err(|_| "Invalid compact reward commitment.")?;
    }
    Ok((
        Block {
            network,
            height: u64::from_le_bytes(h[65..73].try_into().unwrap()),
            parent: h[73..105].try_into().unwrap(),
            timestamp: u64::from_le_bytes(h[105..113].try_into().unwrap()),
            target: h[113..145].try_into().unwrap(),
            nonce,
            transactions,
            reward_mode: mode,
            rewards,
            fund_spends,
            issuances,
            settlement_proof: Vec::new(),
        },
        r.ranges,
    ))
}
impl CompactBlock {
    pub fn canonical_id(bytes: &[u8]) -> Result<Hash, String> {
        if bytes.len() < BLOCK_HEADER_BYTES
            || bytes.len() > MAX_BLOCK_BYTES
            || &bytes[..4] != b"SWNB"
        {
            return Err("Canonical source block unavailable.".into());
        }
        let nonce = u64::from_le_bytes(bytes[NONCE..NONCE + 8].try_into().unwrap());
        let mut h = blake3::Hasher::new_derive_key(crate::ranges::DOMAIN);
        h.update(&bytes[..NONCE]);
        h.update(&bytes[NONCE + 8..]);
        Ok(id(*h.finalize().as_bytes(), nonce))
    }
    pub fn export_canonical(bytes: &[u8]) -> Result<Vec<u8>, String> {
        let _ = Self::canonical_id(bytes)?;
        let nonce = u64::from_le_bytes(bytes[NONCE..NONCE + 8].try_into().unwrap());
        let mut raw = Vec::with_capacity(bytes.len() - 8);
        raw.extend_from_slice(&bytes[..NONCE]);
        raw.extend_from_slice(&bytes[NONCE + 8..]);
        let seed = *blake3::Hasher::new_derive_key(crate::ranges::DOMAIN)
            .update(&raw)
            .finalize()
            .as_bytes();
        let (_, ranges) = parse(
            |a, n| {
                raw.get(a..a + n)
                    .map(|b| b.to_vec())
                    .ok_or("Invalid source compact range.".into())
            },
            raw.len(),
            nonce,
        )?;
        let proof = RangeProof::create(&raw, &ranges)?;
        let mut out = b"SWLC0001".to_vec();
        out.extend_from_slice(&nonce.to_le_bytes());
        out.extend_from_slice(&seed);
        out.extend(proof);
        Ok(out)
    }
    pub fn export(block: &Block) -> Result<Vec<u8>, String> {
        Self::export_canonical(&block.encode()?)
    }
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        if data.len() < 65 || data.len() > MAX_COMPACT + 48 || &data[..8] != b"SWLC0001" {
            return Err("Invalid compact response.".into());
        }
        let nonce = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let seed = data[16..48].try_into().unwrap();
        let sparse: Sparse = RangeProof::verify(&data[48..], seed)?;
        let (block, ranges) = parse(|a, n| sparse.read(a, n), sparse.length, nonce)?;
        sparse.require_exact_ranges(&ranges)?;
        // PublicTransaction decoding authenticates canonical field encodings, not proofs.
        for tx in &block.transactions {
            PublicTransaction::decode(&tx.record.body)
                .map_err(|_| "Invalid compact public transaction.")?;
        }
        Ok(Self {
            id: id(seed, nonce),
            block,
            seed,
        })
    }
}
