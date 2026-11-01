//! Canonical engineering-network framing for native V1 transactions and blocks.
//!
//! Decoding checks byte structure, canonical public values, and local network
//! selection. It does not establish snapshot membership or proof validity.
//! Issuance carries signed declarations, fixed three-note proofs and public fee receipts.

use native::codec::{PublicTransaction, decode_digest, encode_digest};
use native::multi_asset::{F, Hasher};
use p3_field::{PrimeCharacteristicRing, PrimeField32};

pub use native::codec::{FORMAT_VERSION, SUITE_ID};
pub use siworld_core::v1_economics::RewardMode;

pub type Hash = [u8; 32];
pub type DigestBytes = [u8; 48];

pub const MAX_TX_PROOF: usize = 655_360;
/// Maximum settlement-proof body accepted on the native V1 wire.
///
/// Full-capacity measurements must stay at or below 589,824 bytes to leave
/// ten percent of this ceiling unused. The 640 KiB admission limit is
/// independent of the leaf limit and applies before any proof allocation.
pub const MAX_SETTLEMENT_PROOF: usize = 655_360;
pub const MIN_SLOTS: usize = 64;
pub const MAX_SLOTS: usize = 576;
pub const GROUP: usize = 16;
pub const PUBLIC_BYTES: usize = 2027;
pub const REWARD_CIPHERTEXT_BYTES: usize = 1313;
pub const SIDECAR_BYTES: usize = 78;
pub const TX_PREFIX_BYTES: usize = 4 + 2 + 27 + 32 + 40 + PUBLIC_BYTES + 48 + 4;
pub const MAX_ENVELOPE_BYTES: usize = TX_PREFIX_BYTES + MAX_TX_PROOF;
pub const BLOCK_VERSION: u16 = 4;
pub const BLOCK_HEADER_BYTES: usize = 4 + 2 + 27 + 32 + 8 + 32 + 8 + 32 + 8 + 2 + 1 + 1 + 1;
pub const MAX_FUND_SPENDS: usize = 8;
pub const REWARD_RECORD_BYTES: usize = 48 + REWARD_CIPHERTEXT_BYTES;
pub const MAX_REWARDS: usize = 5;
pub const BLOCK_FIXED_BYTES: usize = BLOCK_HEADER_BYTES + REWARD_RECORD_BYTES + 4;
pub const MAX_BLOCK_BYTES: usize = BLOCK_FIXED_BYTES
    + (MAX_REWARDS - 1) * REWARD_RECORD_BYTES
    + MAX_FUND_SPENDS * crate::fund_spend::ENCODED_BYTES
    + MAX_SLOTS * (4 + MAX_ENVELOPE_BYTES)
    + MAX_SETTLEMENT_PROOF
    + crate::issuance::RECORDS_CODEC_LIMIT * (4 + crate::issuance::MAX_RECORD_BYTES);

const TX_MAGIC: &[u8; 4] = b"SWTX";
const BLOCK_MAGIC: &[u8; 4] = b"SWNB";
const SIDECAR_MAGIC: &[u8; 4] = b"SWFS";
const NETWORK_OFFSET: usize = 4 + 2 + 27;
const SNAPSHOT_OFFSET: usize = NETWORK_OFFSET + 32;
const PUBLIC_OFFSET: usize = SNAPSHOT_OFFSET + 40;
const FEE_OFFSET: usize = PUBLIC_OFFSET + PUBLIC_BYTES;
const PROOF_LENGTH_OFFSET: usize = FEE_OFFSET + 48;
const _: [(); 27] = [(); SUITE_ID.len()];
const _: [(); PUBLIC_BYTES] = [(); native::codec::PUBLIC_TRANSACTION_BYTES];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub height: u64,
    pub block_id: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicRecord {
    pub snapshot: Snapshot,
    pub body: [u8; PUBLIC_BYTES],
    pub fee_commit: DigestBytes,
}

impl PublicRecord {
    pub fn new(
        snapshot: Snapshot,
        body: [u8; PUBLIC_BYTES],
        fee_commit: DigestBytes,
    ) -> Result<Self, String> {
        let record = Self {
            snapshot,
            body,
            fee_commit,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), String> {
        PublicTransaction::decode(&self.body)
            .map_err(|_| "noncanonical transaction public fields".to_owned())?;
        let _ = decode_digest(&self.fee_commit)
            .map_err(|_| "noncanonical transaction fee commitment".to_owned())?;
        Ok(())
    }

    /// Canonical statement identity; randomized proofs and private fee openings
    /// are deliberately excluded. The suite is selected by this implementation.
    pub fn statement_id(&self, network: &Hash) -> Hash {
        let mut hash = blake3::Hasher::new_derive_key("siworld native transaction identity v1");
        hash.update(&(SUITE_ID.len() as u16).to_le_bytes());
        hash.update(SUITE_ID);
        hash.update(&FORMAT_VERSION.to_le_bytes());
        hash.update(network);
        hash.update(&self.snapshot.height.to_le_bytes());
        hash.update(&self.snapshot.block_id);
        hash.update(&self.body);
        hash.update(&self.fee_commit);
        *hash.finalize().as_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub record: PublicRecord,
    pub proof: Vec<u8>,
}

impl Transaction {
    pub fn encode_envelope(&self, network: &Hash) -> Result<Vec<u8>, String> {
        self.record.validate()?;
        validate_proof_len(self.proof.len(), MAX_TX_PROOF, "transaction")?;
        let mut bytes = Vec::with_capacity(TX_PREFIX_BYTES + self.proof.len());
        emit_envelope(self, network, &mut |part| bytes.extend_from_slice(part));
        Ok(bytes)
    }

    pub fn decode_envelope(bytes: &[u8], network: &Hash) -> Result<Self, String> {
        let (record, proof) = borrowed_envelope(bytes, network)?;
        Ok(Self {
            record,
            proof: proof.to_vec(),
        })
    }
}

fn emit_envelope(tx: &Transaction, network: &Hash, emit: &mut impl FnMut(&[u8])) {
    emit(TX_MAGIC);
    emit(&FORMAT_VERSION.to_le_bytes());
    emit(SUITE_ID);
    emit(network);
    emit(&tx.record.snapshot.height.to_le_bytes());
    emit(&tx.record.snapshot.block_id);
    emit(&tx.record.body);
    emit(&tx.record.fee_commit);
    // All callers validate this cap before converting the length to u32.
    emit(&(tx.proof.len() as u32).to_le_bytes());
    emit(&tx.proof);
}

pub(crate) fn borrowed_envelope<'a>(
    bytes: &'a [u8],
    network: &Hash,
) -> Result<(PublicRecord, &'a [u8]), String> {
    if !(TX_PREFIX_BYTES..=MAX_ENVELOPE_BYTES).contains(&bytes.len()) {
        return Err("transaction envelope byte limit".into());
    }
    if &bytes[..4] != TX_MAGIC {
        return Err("transaction envelope magic".into());
    }
    if bytes[4..6] != FORMAT_VERSION.to_le_bytes() {
        return Err("unsupported transaction envelope version".into());
    }
    if &bytes[6..NETWORK_OFFSET] != SUITE_ID {
        return Err("unsupported transaction envelope suite".into());
    }
    if &bytes[NETWORK_OFFSET..SNAPSHOT_OFFSET] != network {
        return Err("transaction envelope network mismatch".into());
    }
    let snapshot = Snapshot {
        height: u64::from_le_bytes(
            bytes[SNAPSHOT_OFFSET..SNAPSHOT_OFFSET + 8]
                .try_into()
                .expect("fixed snapshot height"),
        ),
        block_id: bytes[SNAPSHOT_OFFSET + 8..PUBLIC_OFFSET]
            .try_into()
            .expect("fixed snapshot block ID"),
    };
    // Decode fixed public values before retaining or copying an opaque proof.
    let record = PublicRecord::new(
        snapshot,
        bytes[PUBLIC_OFFSET..FEE_OFFSET]
            .try_into()
            .expect("fixed transaction public body"),
        bytes[FEE_OFFSET..PROOF_LENGTH_OFFSET]
            .try_into()
            .expect("fixed transaction fee commitment"),
    )?;
    let proof_len = u32::from_le_bytes(
        bytes[PROOF_LENGTH_OFFSET..TX_PREFIX_BYTES]
            .try_into()
            .expect("fixed transaction proof length"),
    ) as usize;
    validate_proof_len(proof_len, MAX_TX_PROOF, "transaction")?;
    if proof_len != bytes.len() - TX_PREFIX_BYTES {
        return Err("transaction proof length mismatch".into());
    }
    Ok((record, &bytes[TX_PREFIX_BYTES..]))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RewardRecord {
    pub commitment: DigestBytes,
    pub ciphertext: [u8; REWARD_CIPHERTEXT_BYTES],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub network: Hash,
    pub height: u64,
    pub parent: Hash,
    pub timestamp: u64,
    pub target: Hash,
    pub nonce: u64,
    pub transactions: Vec<Transaction>,
    pub reward_mode: RewardMode,
    pub rewards: Vec<RewardRecord>,
    pub fund_spends: Vec<crate::fund_spend::FundSpend>,
    pub issuances: Vec<crate::issuance::IssuanceRecord>,
    pub settlement_proof: Vec<u8>,
}

impl Block {
    pub fn validate_shape(&self) -> Result<(), String> {
        if self.timestamp == 0 || self.target == [0; 32] {
            return Err("invalid engineering block time or target".into());
        }
        validate_slots(self.transactions.len())?;
        validate_proof_len(
            self.settlement_proof.len(),
            MAX_SETTLEMENT_PROOF,
            "settlement",
        )?;
        validate_rewards(self.reward_mode, &self.rewards)?;
        validate_fund_spends(&self.fund_spends)?;
        if self.issuances.len() > crate::issuance::RECORDS_CODEC_LIMIT {
            return Err("issuance count limit".into());
        }
        for issuance in &self.issuances {
            issuance.validate_shape()?;
        }
        let mut previous = None;
        for tx in &self.transactions {
            tx.record.validate()?;
            validate_proof_len(tx.proof.len(), MAX_TX_PROOF, "transaction")?;
            check_order(&mut previous, tx.record.statement_id(&self.network))?;
        }
        if self.encoded_len()? > MAX_BLOCK_BYTES {
            return Err("block byte limit".into());
        }
        Ok(())
    }

    pub fn encoded_len(&self) -> Result<usize, String> {
        let mut length = BLOCK_HEADER_BYTES
            .checked_add(
                self.rewards
                    .len()
                    .checked_mul(REWARD_RECORD_BYTES)
                    .ok_or("reward byte length overflow")?,
            )
            .and_then(|n| {
                self.fund_spends
                    .len()
                    .checked_mul(crate::fund_spend::ENCODED_BYTES)
                    .and_then(|size| n.checked_add(size))
            })
            .and_then(|n| n.checked_add(4))
            .and_then(|n| n.checked_add(self.settlement_proof.len()))
            .ok_or("block byte length overflow")?;
        for issuance in &self.issuances {
            length = length
                .checked_add(4)
                .and_then(|n| {
                    issuance
                        .encoded_len()
                        .ok()
                        .and_then(|size| n.checked_add(size))
                })
                .ok_or("issuance byte length overflow")?;
        }
        for tx in &self.transactions {
            length = length
                .checked_add(4 + TX_PREFIX_BYTES)
                .and_then(|length| length.checked_add(tx.proof.len()))
                .ok_or("block byte length overflow")?;
        }
        Ok(length)
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate_shape()?;
        let mut bytes = Vec::with_capacity(self.encoded_len()?);
        self.emit_encoding(true, &mut |part| bytes.extend_from_slice(part));
        Ok(bytes)
    }

    /// Writes the existing canonical format without buffering a second block.
    pub fn write_to(&self, output: &mut impl std::io::Write) -> std::io::Result<()> {
        self.validate_shape().map_err(invalid_stream)?;
        let mut error = None;
        self.emit_encoding(true, &mut |part| {
            if error.is_none()
                && let Err(e) = output.write_all(part)
            {
                error = Some(e);
            }
        });
        error.map_or(Ok(()), Err)
    }

    /// Reads at most one bounded canonical block. Only one transaction envelope
    /// is copied at a time; the caller must reserve the declared block budget.
    /// I/O errors retain their kind, so a local timeout is not proof invalidity.
    pub fn read_from(
        input: &mut impl std::io::Read,
        length: usize,
        network: &Hash,
    ) -> std::io::Result<Self> {
        use std::io::Read;
        if !(BLOCK_FIXED_BYTES..=MAX_BLOCK_BYTES).contains(&length) {
            return Err(invalid_stream("block stream byte limit"));
        }
        let mut input = input.take(length as u64);
        let mut header = [0; BLOCK_HEADER_BYTES];
        input.read_exact(&mut header)?;
        let mut r = Reader::new(&header);
        if r.take(4).map_err(invalid_stream)? != BLOCK_MAGIC
            || r.u16().map_err(invalid_stream)? != BLOCK_VERSION
            || r.take(SUITE_ID.len()).map_err(invalid_stream)? != SUITE_ID
        {
            return Err(invalid_stream("block stream format mismatch"));
        }
        let found_network: Hash = r.array().map_err(invalid_stream)?;
        if &found_network != network {
            return Err(invalid_stream("block network mismatch"));
        }
        let height = r.u64().map_err(invalid_stream)?;
        let parent = r.array().map_err(invalid_stream)?;
        let timestamp = r.u64().map_err(invalid_stream)?;
        let target = r.array().map_err(invalid_stream)?;
        let nonce = r.u64().map_err(invalid_stream)?;
        let count = usize::from(r.u16().map_err(invalid_stream)?);
        let reward_mode = RewardMode::from_byte(r.array::<1>().map_err(invalid_stream)?[0])
            .map_err(invalid_stream)?;
        let fund_count = usize::from(r.array::<1>().map_err(invalid_stream)?[0]);
        if fund_count > MAX_FUND_SPENDS {
            return Err(invalid_stream("fund expenditure count limit"));
        }
        let issuance_count = usize::from(r.array::<1>().map_err(invalid_stream)?[0]);
        if issuance_count > crate::issuance::RECORDS_CODEC_LIMIT {
            return Err(invalid_stream("issuance count limit"));
        }
        validate_slots(count).map_err(invalid_stream)?;
        if timestamp == 0
            || target == [0; 32]
            || length < BLOCK_FIXED_BYTES + count * (4 + TX_PREFIX_BYTES + 1) + 1
        {
            return Err(invalid_stream("invalid or truncated streamed block"));
        }
        let mut transactions = Vec::with_capacity(count);
        let mut previous = None;
        for _ in 0..count {
            let mut size = [0; 4];
            input.read_exact(&mut size)?;
            let size = u32::from_le_bytes(size) as usize;
            if !(TX_PREFIX_BYTES + 1..=MAX_ENVELOPE_BYTES).contains(&size)
                || size as u64 > input.limit()
            {
                return Err(invalid_stream("streamed envelope byte limit"));
            }
            let mut bytes = vec![0; size];
            input.read_exact(&mut bytes)?;
            let tx = Transaction::decode_envelope(&bytes, network).map_err(invalid_stream)?;
            check_order(&mut previous, tx.record.statement_id(network)).map_err(invalid_stream)?;
            transactions.push(tx);
        }
        let mut rewards = Vec::with_capacity(reward_count(reward_mode));
        for _ in 0..reward_count(reward_mode) {
            let mut reward = RewardRecord {
                commitment: [0; 48],
                ciphertext: [0; REWARD_CIPHERTEXT_BYTES],
            };
            input.read_exact(&mut reward.commitment)?;
            input.read_exact(&mut reward.ciphertext)?;
            rewards.push(reward);
        }
        let mut fund_spends = Vec::with_capacity(fund_count);
        for _ in 0..fund_count {
            let mut bytes = [0; crate::fund_spend::ENCODED_BYTES];
            input.read_exact(&mut bytes)?;
            fund_spends.push(crate::fund_spend::FundSpend::decode(&bytes).map_err(invalid_stream)?);
        }
        let mut issuances = Vec::with_capacity(issuance_count);
        for _ in 0..issuance_count {
            let mut size = [0; 4];
            input.read_exact(&mut size)?;
            let size = u32::from_le_bytes(size) as usize;
            if size > crate::issuance::MAX_RECORD_BYTES || size as u64 > input.limit() {
                return Err(invalid_stream("issuance stream byte limit"));
            }
            let mut bytes = vec![0; size];
            input.read_exact(&mut bytes)?;
            issuances
                .push(crate::issuance::IssuanceRecord::decode(&bytes).map_err(invalid_stream)?);
        }
        let mut size = [0; 4];
        input.read_exact(&mut size)?;
        let size = u32::from_le_bytes(size) as usize;
        validate_proof_len(size, MAX_SETTLEMENT_PROOF, "settlement").map_err(invalid_stream)?;
        if size as u64 != input.limit() {
            return Err(invalid_stream("streamed settlement length mismatch"));
        }
        let mut settlement_proof = vec![0; size];
        input.read_exact(&mut settlement_proof)?;
        let block = Self {
            network: found_network,
            height,
            parent,
            timestamp,
            target,
            nonce,
            transactions,
            reward_mode,
            rewards,
            fund_spends,
            issuances,
            settlement_proof,
        };
        block.validate_shape().map_err(invalid_stream)?;
        Ok(block)
    }

    fn emit_encoding(&self, include_nonce: bool, emit: &mut impl FnMut(&[u8])) {
        emit(BLOCK_MAGIC);
        emit(&BLOCK_VERSION.to_le_bytes());
        emit(SUITE_ID);
        emit(&self.network);
        emit(&self.height.to_le_bytes());
        emit(&self.parent);
        emit(&self.timestamp.to_le_bytes());
        emit(&self.target);
        if include_nonce {
            emit(&self.nonce.to_le_bytes());
        }
        emit(&(self.transactions.len() as u16).to_le_bytes());
        emit(&[self.reward_mode.to_byte()]);
        emit(&[self.fund_spends.len() as u8]);
        emit(&[self.issuances.len() as u8]);
        for tx in &self.transactions {
            emit(&((TX_PREFIX_BYTES + tx.proof.len()) as u32).to_le_bytes());
            emit_envelope(tx, &self.network, emit);
        }
        for reward in &self.rewards {
            emit(&reward.commitment);
            emit(&reward.ciphertext);
        }
        for spend in &self.fund_spends {
            emit(&spend.encode());
        }
        for issuance in &self.issuances {
            // Every caller validates shape before encoding.
            let bytes = issuance.encode().expect("validated issuance record");
            emit(&(bytes.len() as u32).to_le_bytes());
            emit(&bytes);
        }
        emit(&(self.settlement_proof.len() as u32).to_le_bytes());
        emit(&self.settlement_proof);
    }

    pub fn decode(bytes: &[u8], network: &Hash) -> Result<Self, String> {
        if !(BLOCK_FIXED_BYTES..=MAX_BLOCK_BYTES).contains(&bytes.len()) {
            return Err("block byte limit".into());
        }
        let mut reader = Reader::new(bytes);
        if reader.take(4)? != BLOCK_MAGIC {
            return Err("block magic".into());
        }
        if reader.u16()? != BLOCK_VERSION {
            return Err("unsupported block version".into());
        }
        if reader.take(SUITE_ID.len())? != SUITE_ID {
            return Err("unsupported block suite".into());
        }
        let found_network = reader.array()?;
        if &found_network != network {
            return Err("block network mismatch".into());
        }
        let height = reader.u64()?;
        let parent = reader.array()?;
        let timestamp = reader.u64()?;
        let target = reader.array()?;
        if timestamp == 0 || target == [0; 32] {
            return Err("invalid engineering block time or target".into());
        }
        let nonce = reader.u64()?;
        let count = usize::from(reader.u16()?);
        let reward_mode =
            RewardMode::from_byte(reader.array::<1>()?[0]).map_err(|e| e.to_string())?;
        let fund_count = usize::from(reader.array::<1>()?[0]);
        if fund_count > MAX_FUND_SPENDS {
            return Err("fund expenditure count limit".into());
        }
        let issuance_count = usize::from(reader.array::<1>()?[0]);
        if issuance_count > crate::issuance::RECORDS_CODEC_LIMIT {
            return Err("issuance count limit".into());
        }
        validate_slots(count)?;
        // This lower bound and every declared length are checked before any
        // transaction vector or proof body is allocated. The first pass also
        // rejects late malformed entries before retaining earlier proof bodies.
        let minimum = BLOCK_FIXED_BYTES + count * (4 + TX_PREFIX_BYTES + 1) + 1;
        if bytes.len() < minimum {
            return Err("truncated block transaction list".into());
        }
        let transactions_start = reader.position;
        let mut previous = None;
        for _ in 0..count {
            let (record, _) = borrowed_envelope(reader.transaction()?, network)?;
            check_order(&mut previous, record.statement_id(network))?;
        }
        let mut rewards = Vec::with_capacity(reward_count(reward_mode));
        for _ in 0..reward_count(reward_mode) {
            rewards.push(RewardRecord {
                commitment: reader.array()?,
                ciphertext: reader.array()?,
            });
        }
        validate_rewards(reward_mode, &rewards)?;
        let mut fund_spends = Vec::with_capacity(fund_count);
        for _ in 0..fund_count {
            fund_spends.push(crate::fund_spend::FundSpend::decode(
                reader.take(crate::fund_spend::ENCODED_BYTES)?,
            )?);
        }
        validate_fund_spends(&fund_spends)?;
        let mut issuances = Vec::with_capacity(issuance_count);
        for _ in 0..issuance_count {
            let size = reader.u32()? as usize;
            if size > crate::issuance::MAX_RECORD_BYTES {
                return Err("issuance byte limit".into());
            }
            issuances.push(crate::issuance::IssuanceRecord::decode(reader.take(size)?)?);
        }
        let settlement_len = reader.u32()? as usize;
        validate_proof_len(settlement_len, MAX_SETTLEMENT_PROOF, "settlement")?;
        let settlement = reader.take(settlement_len)?;
        if reader.position != bytes.len() {
            return Err("trailing block bytes".into());
        }
        let mut reader = Reader {
            bytes,
            position: transactions_start,
        };
        let mut transactions = Vec::with_capacity(count);
        for _ in 0..count {
            transactions.push(Transaction::decode_envelope(
                reader.transaction()?,
                network,
            )?);
        }
        Ok(Self {
            network: found_network,
            height,
            parent,
            timestamp,
            target,
            nonce,
            transactions,
            reward_mode,
            rewards,
            fund_spends,
            issuances,
            settlement_proof: settlement.to_vec(),
        })
    }

    pub fn statement_ids(&self) -> Vec<Hash> {
        self.transactions
            .iter()
            .map(|tx| tx.record.statement_id(&self.network))
            .collect()
    }

    /// Settlement statement binding, using the fixed native ordered-list domain.
    /// Callers validate shape before using this digest for admission or proving.
    pub fn list_digest(&self) -> Hash {
        let mut hash =
            blake3::Hasher::new_derive_key("siworld native settlement ordered transactions v1");
        hash.update(&self.network);
        hash.update(&self.height.to_le_bytes());
        hash.update(&(self.transactions.len() as u16).to_le_bytes());
        for tx in &self.transactions {
            hash.update(&tx.record.statement_id(&self.network));
        }
        *hash.finalize().as_bytes()
    }

    /// Hash all canonical header/body/proof bytes except nonce exactly once.
    /// A mining search caches this seed; it never rehashes proof bodies per try.
    pub fn pow_seed(&self) -> Result<Hash, String> {
        self.validate_shape()?;
        let mut hash = blake3::Hasher::new_derive_key("siworld native engineering pow seed v2");
        self.emit_encoding(false, &mut |part| {
            hash.update(part);
        });
        Ok(*hash.finalize().as_bytes())
    }

    /// Authenticate the proof-carrying header/body seed and the final nonce.
    /// Transaction identity remains proof-independent under its existing domain.
    pub fn id(&self) -> Result<Hash, String> {
        let mut hash =
            blake3::Hasher::new_derive_key("siworld native engineering block identity v2");
        hash.update(&self.pow_seed()?);
        hash.update(&self.nonce.to_le_bytes());
        Ok(*hash.finalize().as_bytes())
    }
}

fn validate_slots(count: usize) -> Result<(), String> {
    if !(MIN_SLOTS..=MAX_SLOTS).contains(&count) || !count.is_multiple_of(GROUP) {
        return Err("block slot count must be 64 through 576 in groups of 16".into());
    }
    Ok(())
}

fn validate_proof_len(length: usize, maximum: usize, kind: &str) -> Result<(), String> {
    if length == 0 || length > maximum {
        return Err(format!("{kind} proof byte limit"));
    }
    Ok(())
}

fn check_order(previous: &mut Option<Hash>, current: Hash) -> Result<(), String> {
    if previous.is_some_and(|previous| previous >= current) {
        return Err("transaction statement IDs must be strictly ascending".into());
    }
    *previous = Some(current);
    Ok(())
}

/// Fixed-size private fee opening, without tier flags, signatures, or another
/// encryption wrapper. Authenticated transport supplies connection privacy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sidecar {
    pub transaction_id: Hash,
    pub fee: u64,
    pub blind: [u32; 8],
}

impl Sidecar {
    pub fn encode(&self) -> Result<[u8; SIDECAR_BYTES], String> {
        let _ = self.fields()?;
        let mut bytes = [0; SIDECAR_BYTES];
        bytes[..4].copy_from_slice(SIDECAR_MAGIC);
        bytes[4..6].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[6..38].copy_from_slice(&self.transaction_id);
        bytes[38..46].copy_from_slice(&self.fee.to_le_bytes());
        for (index, field) in self.blind.iter().enumerate() {
            bytes[46 + index * 4..50 + index * 4].copy_from_slice(&field.to_le_bytes());
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != SIDECAR_BYTES {
            return Err("fee sidecar byte length".into());
        }
        if &bytes[..4] != SIDECAR_MAGIC {
            return Err("fee sidecar magic".into());
        }
        if bytes[4..6] != FORMAT_VERSION.to_le_bytes() {
            return Err("unsupported fee sidecar version".into());
        }
        let sidecar = Self {
            transaction_id: bytes[6..38].try_into().expect("fixed transaction ID"),
            fee: u64::from_le_bytes(bytes[38..46].try_into().expect("fixed fee amount")),
            blind: core::array::from_fn(|index| {
                u32::from_le_bytes(
                    bytes[46 + index * 4..50 + index * 4]
                        .try_into()
                        .expect("fixed fee blind field"),
                )
            }),
        };
        let _ = sidecar.fields()?;
        Ok(sidecar)
    }

    fn fields(&self) -> Result<[F; 8], String> {
        if self.blind.iter().any(|value| *value >= F::ORDER_U32) {
            return Err("noncanonical fee sidecar blind".into());
        }
        Ok(self.blind.map(F::from_u32))
    }

    /// The transaction AIR determines the hidden fee tier. Admission only checks
    /// this opening against its own canonical transaction identity and F_i.
    pub fn check_opening(&self, record: &PublicRecord, network: &Hash) -> Result<(), String> {
        record.validate()?;
        if self.transaction_id != record.statement_id(network) {
            return Err("fee sidecar transaction mismatch".into());
        }
        let blind = self.fields()?;
        if encode_digest(&Hasher::new().fee_commit(self.fee, &blind)) != record.fee_commit {
            return Err("fee sidecar opening mismatch".into());
        }
        Ok(())
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
        let end = self
            .position
            .checked_add(length)
            .ok_or("wire byte length overflow")?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or("truncated wire bytes")?;
        self.position = end;
        Ok(bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        self.take(N)?
            .try_into()
            .map_err(|_| "fixed wire byte length".into())
    }

    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn transaction(&mut self) -> Result<&'a [u8], String> {
        let length = self.u32()? as usize;
        if !(TX_PREFIX_BYTES + 1..=MAX_ENVELOPE_BYTES).contains(&length) {
            return Err("block transaction envelope byte limit".into());
        }
        self.take(length)
    }
}

pub fn validate_fund_spends(spends: &[crate::fund_spend::FundSpend]) -> Result<(), String> {
    if spends.len() > MAX_FUND_SPENDS
        || spends
            .iter()
            .any(|s| usize::from(s.account) >= siworld_core::v1_economics::MAX_FUND_WALLETS)
        || spends
            .windows(2)
            .any(|pair| pair[0].account >= pair[1].account)
    {
        return Err("noncanonical fund expenditure list".into());
    }
    for spend in spends {
        crate::fund_spend::FundSpend::decode(&spend.encode())?;
    }
    Ok(())
}
pub const fn reward_count(mode: RewardMode) -> usize {
    match mode {
        RewardMode::Voyager => 1,
        RewardMode::Holder => 5,
    }
}
pub fn validate_rewards(mode: RewardMode, rewards: &[RewardRecord]) -> Result<(), String> {
    if rewards.len() != reward_count(mode) {
        return Err("reward count does not match mode".into());
    }
    let mut commitments = std::collections::BTreeSet::new();
    for reward in rewards {
        let _ = decode_digest(&reward.commitment).map_err(|_| "noncanonical reward commitment")?;
        if !commitments.insert(reward.commitment) {
            return Err("duplicate reward commitment".into());
        }
    }
    Ok(())
}

fn invalid_stream(message: impl ToString) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use native::codec::{decode_digest, encode_digest};
    use native::multi_asset::{F, Hasher};
    use p3_field::{PrimeCharacteristicRing, PrimeField32};

    fn record(seed: u32) -> PublicRecord {
        let mut body = [0; PUBLIC_BYTES];
        body[..4].copy_from_slice(&(seed * 2 + 1).to_le_bytes());
        body[48..52].copy_from_slice(&(seed * 2 + 2).to_le_bytes());
        PublicRecord::new(
            Snapshot {
                height: 11,
                block_id: [3; 32],
            },
            body,
            encode_digest(&Hasher::new().fee_commit(0, &[F::from_u32(7); 8])),
        )
        .unwrap()
    }

    fn transaction(seed: u32) -> Transaction {
        Transaction {
            record: record(seed),
            proof: vec![1, 2, 3],
        }
    }

    fn block() -> Block {
        let network = [9; 32];
        let mut transactions: Vec<_> = (0..MIN_SLOTS as u32).map(transaction).collect();
        transactions.sort_by_key(|tx| tx.record.statement_id(&network));
        Block {
            network,
            height: 12,
            parent: [8; 32],
            timestamp: 3601,
            target: [0xff; 32],
            nonce: 21,
            transactions,
            reward_mode: RewardMode::Voyager,
            rewards: vec![RewardRecord {
                commitment: [0; 48],
                ciphertext: [4; REWARD_CIPHERTEXT_BYTES],
            }],
            fund_spends: Vec::new(),
            issuances: Vec::new(),
            settlement_proof: vec![4, 5, 6],
        }
    }

    #[test]
    fn transaction_fixed_prefix_and_roundtrip() {
        let tx = transaction(1);
        let bytes = tx.encode_envelope(&[9; 32]).unwrap();
        assert_eq!(TX_PREFIX_BYTES, 2184);
        assert_eq!(bytes.len(), 2184 + tx.proof.len());
        assert_eq!(&bytes[..4], b"SWTX");
        assert_eq!(&bytes[6..33], SUITE_ID);
        assert_eq!(Transaction::decode_envelope(&bytes, &[9; 32]).unwrap(), tx);
    }

    #[test]
    fn transaction_rejects_unknown_header_wrong_network_and_trailing_bytes() {
        let bytes = transaction(1).encode_envelope(&[9; 32]).unwrap();
        for offset in [0, 4, 6, 33] {
            let mut bad = bytes.clone();
            bad[offset] ^= 1;
            assert!(Transaction::decode_envelope(&bad, &[9; 32]).is_err());
        }
        assert!(Transaction::decode_envelope(&bytes, &[8; 32]).is_err());
        for length in [0, 1, TX_PREFIX_BYTES - 1, bytes.len() - 1] {
            assert!(Transaction::decode_envelope(&bytes[..length], &[9; 32]).is_err());
        }
        let mut bad = bytes;
        bad.push(0);
        assert!(Transaction::decode_envelope(&bad, &[9; 32]).is_err());
    }

    #[test]
    fn all_public_and_fee_limbs_must_be_canonical_and_nullifiers_distinct() {
        let original = record(1);
        for limb in 0..60 {
            let mut bad = original.clone();
            bad.body[limb * 4..limb * 4 + 4].copy_from_slice(&F::ORDER_U32.to_le_bytes());
            assert!(bad.validate().is_err(), "public limb {limb}");
        }
        for limb in 0..12 {
            let mut bad = original.clone();
            bad.fee_commit[limb * 4..limb * 4 + 4].copy_from_slice(&F::ORDER_U32.to_le_bytes());
            assert!(bad.validate().is_err(), "fee limb {limb}");
        }
        let mut bad = original;
        let nf = bad.body[..48].to_vec();
        bad.body[48..96].copy_from_slice(&nf);
        assert!(bad.validate().is_err());
        assert!(PublicRecord::new(bad.snapshot, bad.body, bad.fee_commit).is_err());
    }

    #[test]
    fn decoder_rejects_public_and_fee_before_opaque_proof_allocation() {
        let mut bytes = transaction(1).encode_envelope(&[9; 32]).unwrap();
        bytes[PUBLIC_OFFSET..PUBLIC_OFFSET + 4].copy_from_slice(&F::ORDER_U32.to_le_bytes());
        bytes[TX_PREFIX_BYTES - 4..TX_PREFIX_BYTES].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(
            Transaction::decode_envelope(&bytes, &[9; 32])
                .unwrap_err()
                .contains("public")
        );
        let mut bytes = transaction(1).encode_envelope(&[9; 32]).unwrap();
        bytes[FEE_OFFSET..FEE_OFFSET + 4].copy_from_slice(&F::ORDER_U32.to_le_bytes());
        assert!(
            Transaction::decode_envelope(&bytes, &[9; 32])
                .unwrap_err()
                .contains("fee")
        );
    }

    #[test]
    fn statement_identity_binds_every_public_byte_and_context() {
        let original = record(1);
        let network = [9; 32];
        let id = original.statement_id(&network);
        for index in 0..PUBLIC_BYTES {
            let mut changed = original.clone();
            changed.body[index] ^= 1;
            assert_ne!(changed.statement_id(&network), id, "public byte {index}");
        }
        for index in 0..48 {
            let mut changed = original.clone();
            changed.fee_commit[index] ^= 1;
            assert_ne!(changed.statement_id(&network), id, "fee byte {index}");
        }
        let mut changed = original.clone();
        changed.snapshot.height += 1;
        assert_ne!(changed.statement_id(&network), id);
        changed = original.clone();
        changed.snapshot.block_id[0] ^= 1;
        assert_ne!(changed.statement_id(&network), id);
        assert_ne!(original.statement_id(&[8; 32]), id);
    }

    #[test]
    fn statement_identity_excludes_proof_and_private_sidecar() {
        let original = transaction(1);
        let mut changed = original.clone();
        changed.proof = vec![99; 17];
        assert_eq!(
            original.record.statement_id(&[9; 32]),
            changed.record.statement_id(&[9; 32])
        );
        let id = original.record.statement_id(&[9; 32]);
        let first = Sidecar {
            transaction_id: id,
            fee: 0,
            blind: [7; 8],
        };
        let second = Sidecar {
            transaction_id: id,
            fee: 1,
            blind: [8; 8],
        };
        assert_ne!(first.encode().unwrap(), second.encode().unwrap());
        assert_eq!(original.record.statement_id(&[9; 32]), id);
    }

    #[test]
    fn transaction_proof_caps_and_u32_lengths_are_enforced() {
        let mut tx = transaction(1);
        tx.proof = vec![1; MAX_TX_PROOF];
        let bytes = tx.encode_envelope(&[9; 32]).unwrap();
        assert_eq!(
            Transaction::decode_envelope(&bytes, &[9; 32])
                .unwrap()
                .proof
                .len(),
            MAX_TX_PROOF
        );
        tx.proof.push(0);
        assert!(tx.encode_envelope(&[9; 32]).is_err());
        tx.proof.clear();
        assert!(tx.encode_envelope(&[9; 32]).is_err());
        for length in [0, MAX_TX_PROOF as u32 + 1, u32::MAX] {
            let mut bad = transaction(1).encode_envelope(&[9; 32]).unwrap();
            bad[TX_PREFIX_BYTES - 4..TX_PREFIX_BYTES].copy_from_slice(&length.to_le_bytes());
            assert!(Transaction::decode_envelope(&bad, &[9; 32]).is_err());
        }
    }

    #[test]
    fn block_roundtrip_preserves_canonical_order_and_fixed_reward() {
        let original = block();
        let bytes = original.encode().unwrap();
        assert_eq!(Block::decode(&bytes, &original.network).unwrap(), original);
        assert_eq!(
            Block::decode(&bytes, &original.network)
                .unwrap()
                .encode()
                .unwrap(),
            bytes
        );
        assert_eq!(original.statement_ids().len(), MIN_SLOTS);
        let mut reference =
            blake3::Hasher::new_derive_key("siworld native engineering block identity v2");
        reference.update(&original.pow_seed().unwrap());
        reference.update(&original.nonce.to_le_bytes());
        assert_eq!(original.id().unwrap(), *reference.finalize().as_bytes());
    }

    #[test]
    fn encoder_and_decoder_reject_swapped_or_duplicate_statement_ids() {
        let mut original = block();
        let bytes = original.encode().unwrap();
        original.transactions.swap(0, 1);
        assert!(original.validate_shape().is_err());
        assert!(original.encode().is_err());
        let stride = 4 + TX_PREFIX_BYTES + 3;
        let mut swapped = bytes.clone();
        let first = swapped[BLOCK_HEADER_BYTES..BLOCK_HEADER_BYTES + stride].to_vec();
        let second = swapped[BLOCK_HEADER_BYTES + stride..BLOCK_HEADER_BYTES + 2 * stride].to_vec();
        swapped[BLOCK_HEADER_BYTES..BLOCK_HEADER_BYTES + stride].copy_from_slice(&second);
        swapped[BLOCK_HEADER_BYTES + stride..BLOCK_HEADER_BYTES + 2 * stride]
            .copy_from_slice(&first);
        assert!(Block::decode(&swapped, &[9; 32]).is_err());
        let mut duplicate = bytes;
        duplicate[BLOCK_HEADER_BYTES + stride..BLOCK_HEADER_BYTES + 2 * stride]
            .copy_from_slice(&first);
        assert!(Block::decode(&duplicate, &[9; 32]).is_err());
        let mut original = block();
        original.transactions[1] = original.transactions[0].clone();
        assert!(original.encode().is_err());
    }

    #[test]
    fn block_capacity_headers_lengths_and_reward_limbs_are_rejected() {
        let original = block();
        let bytes = original.encode().unwrap();
        for offset in [0, 4, 6, 33] {
            let mut bad = bytes.clone();
            bad[offset] ^= 1;
            assert!(Block::decode(&bad, &[9; 32]).is_err());
        }
        assert!(Block::decode(&bytes, &[8; 32]).is_err());
        for count in [0u16, 63, 65, 577, u16::MAX] {
            let mut bad = bytes.clone();
            // Slot count precedes mode, fund count and issuance count in v4.
            bad[BLOCK_HEADER_BYTES - 5..BLOCK_HEADER_BYTES - 3]
                .copy_from_slice(&count.to_le_bytes());
            assert!(Block::decode(&bad, &[9; 32]).is_err(), "slot count {count}");
        }
        let mut bad = bytes.clone();
        bad[BLOCK_HEADER_BYTES..BLOCK_HEADER_BYTES + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Block::decode(&bad, &[9; 32]).is_err());
        let reward_offset = BLOCK_HEADER_BYTES + MIN_SLOTS * (4 + TX_PREFIX_BYTES + 3);
        for limb in 0..12 {
            let mut bad = bytes.clone();
            let offset = reward_offset + limb * 4;
            bad[offset..offset + 4].copy_from_slice(&F::ORDER_U32.to_le_bytes());
            assert!(Block::decode(&bad, &[9; 32]).is_err());
        }
        for end in [0, BLOCK_HEADER_BYTES - 1, reward_offset, bytes.len() - 1] {
            assert!(Block::decode(&bytes[..end], &[9; 32]).is_err());
        }
        let mut bad = bytes;
        bad.push(0);
        assert!(Block::decode(&bad, &[9; 32]).is_err());
        let mut original = block();
        original.transactions.pop();
        assert!(original.encode().is_err());
    }

    #[test]
    fn block_capacity_accepts_all_groups_up_to_576() {
        let mut value = block();
        value.transactions = (0..MAX_SLOTS as u32).map(transaction).collect();
        value
            .transactions
            .sort_by_key(|tx| tx.record.statement_id(&value.network));
        for count in (MIN_SLOTS..=MAX_SLOTS).step_by(GROUP) {
            let mut sized = value.clone();
            sized.transactions.truncate(count);
            assert_eq!(
                Block::decode(&sized.encode().unwrap(), &sized.network)
                    .unwrap()
                    .transactions
                    .len(),
                count
            );
        }
        value.transactions.push(transaction(1000));
        assert!(value.encode().is_err());
    }

    #[test]
    fn nested_proof_declarations_cannot_overflow_or_escape_their_envelope() {
        let original = block();
        let bytes = original.encode().unwrap();
        for length in [0, MAX_TX_PROOF as u32 + 1, u32::MAX] {
            let mut bad = bytes.clone();
            let offset = BLOCK_HEADER_BYTES + 4 + TX_PREFIX_BYTES - 4;
            bad[offset..offset + 4].copy_from_slice(&length.to_le_bytes());
            assert!(Block::decode(&bad, &original.network).is_err());
        }
        let mut bad = original.clone();
        bad.transactions.last_mut().unwrap().proof.clear();
        assert!(bad.encode().is_err());
        let mut bad = original;
        bad.transactions.last_mut().unwrap().proof = vec![1; MAX_TX_PROOF + 1];
        assert!(bad.encode().is_err());
    }

    #[test]
    fn fixed_width_u64_fields_roundtrip_without_platform_narrowing() {
        let mut tx = transaction(1);
        tx.record.snapshot.height = u64::MAX;
        let bytes = tx.encode_envelope(&[9; 32]).unwrap();
        assert_eq!(
            Transaction::decode_envelope(&bytes, &[9; 32])
                .unwrap()
                .record
                .snapshot
                .height,
            u64::MAX
        );
        let mut value = block();
        value.height = u64::MAX;
        value.nonce = u64::MAX;
        let decoded = Block::decode(&value.encode().unwrap(), &value.network).unwrap();
        assert_eq!(decoded.height, u64::MAX);
        assert_eq!(decoded.nonce, u64::MAX);
        let sidecar = Sidecar {
            transaction_id: [0; 32],
            fee: u64::MAX,
            blind: [0; 8],
        };
        assert_eq!(
            Sidecar::decode(&sidecar.encode().unwrap()).unwrap(),
            sidecar
        );
    }

    #[test]
    fn settlement_proof_caps_and_declared_length_are_enforced() {
        assert_eq!(MAX_SETTLEMENT_PROOF, 655_360);
        let mut value = block();
        value.settlement_proof = vec![1; MAX_SETTLEMENT_PROOF];
        let bytes = value.encode().unwrap();
        assert_eq!(
            Block::decode(&bytes, &value.network)
                .unwrap()
                .settlement_proof
                .len(),
            MAX_SETTLEMENT_PROOF
        );
        value.settlement_proof.push(1);
        assert!(value.encode().is_err());
        value.settlement_proof.clear();
        assert!(value.encode().is_err());
        for length in [0, MAX_SETTLEMENT_PROOF as u32 + 1, u32::MAX] {
            let mut bytes = block().encode().unwrap();
            let offset = bytes.len() - 3 - 4;
            bytes[offset..offset + 4].copy_from_slice(&length.to_le_bytes());
            assert!(Block::decode(&bytes, &[9; 32]).is_err());
        }
    }

    #[test]
    fn block_identity_binds_proofs_reward_nonce_and_parent_but_list_digest_does_not() {
        let original = block();
        let id = original.id().unwrap();
        let list = original.list_digest();
        for change in 0..6 {
            let mut changed = original.clone();
            match change {
                0 => changed.transactions[0].proof[0] ^= 1,
                1 => changed.settlement_proof[0] ^= 1,
                2 => changed.rewards[0].ciphertext[0] ^= 1,
                3 => changed.rewards[0].commitment[0] ^= 1,
                4 => changed.nonce += 1,
                _ => changed.parent[0] ^= 1,
            }
            assert_ne!(changed.id().unwrap(), id);
            assert_eq!(changed.list_digest(), list);
        }
        let mut changed = original.clone();
        changed.height += 1;
        assert_ne!(changed.list_digest(), list);
        changed = original.clone();
        changed.network[0] ^= 1;
        assert_ne!(changed.list_digest(), list);
        changed = original.clone();
        changed.transactions.swap(0, 1);
        assert_ne!(changed.list_digest(), list);
        changed = original;
        changed.transactions.truncate(16);
        assert_ne!(changed.list_digest(), list);
    }

    #[test]
    fn sidecar_exact_format_canonical_blinds_and_opening_binding() {
        let record = record(1);
        let network = [9; 32];
        let sidecar = Sidecar {
            transaction_id: record.statement_id(&network),
            fee: 0,
            blind: [7; 8],
        };
        assert!(sidecar.check_opening(&record, &network).is_ok());
        let bytes = sidecar.encode().unwrap();
        assert_eq!(bytes.len(), 78);
        assert_eq!(Sidecar::decode(&bytes).unwrap(), sidecar);
        assert!(Sidecar::decode(&bytes[..77]).is_err());
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(Sidecar::decode(&trailing).is_err());
        for offset in [0, 4] {
            let mut bad = bytes;
            bad[offset] ^= 1;
            assert!(Sidecar::decode(&bad).is_err());
        }
        for limb in 0..8 {
            let mut bad = bytes;
            let offset = 46 + limb * 4;
            bad[offset..offset + 4].copy_from_slice(&F::ORDER_U32.to_le_bytes());
            assert!(Sidecar::decode(&bad).is_err());
            let mut bad = sidecar.clone();
            bad.blind[limb] = F::ORDER_U32;
            assert!(bad.encode().is_err());
            assert!(bad.check_opening(&record, &network).is_err());
        }
        let mut bad = sidecar.clone();
        bad.fee = 1;
        assert!(bad.check_opening(&record, &network).is_err());
        bad = sidecar.clone();
        bad.transaction_id[0] ^= 1;
        assert!(bad.check_opening(&record, &network).is_err());
        bad = sidecar.clone();
        bad.blind[0] += 1;
        assert!(bad.check_opening(&record, &network).is_err());
        assert!(sidecar.check_opening(&record, &[8; 32]).is_err());
        assert!(decode_digest(&record.fee_commit).is_ok());
    }

    #[test]
    fn pow_seed_binds_header_and_body_but_excludes_nonce() {
        let original = block();
        let seed = original.pow_seed().unwrap();
        let id = original.id().unwrap();
        let mut changed = original.clone();
        changed.nonce += 1;
        assert_eq!(changed.pow_seed().unwrap(), seed);
        assert_ne!(changed.id().unwrap(), id);
        for kind in 0..6 {
            let mut changed = original.clone();
            match kind {
                0 => changed.timestamp += 1,
                1 => changed.target[31] ^= 1,
                2 => changed.parent[0] ^= 1,
                3 => changed.transactions[0].proof[0] ^= 1,
                4 => changed.rewards[0].ciphertext[0] ^= 1,
                _ => changed.settlement_proof[0] ^= 1,
            }
            assert_ne!(changed.pow_seed().unwrap(), seed, "binding {kind}");
            assert_ne!(changed.id().unwrap(), id, "identity {kind}");
        }
        let mut bytes = original.encode().unwrap();
        bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
        assert!(Block::decode(&bytes, &original.network).is_err());
        for mut invalid in [original.clone(), original] {
            invalid.target = [0; 32];
            assert!(invalid.encode().is_err());
            invalid.target = [0xff; 32];
            invalid.timestamp = 0;
            assert!(invalid.encode().is_err());
        }
    }
    #[test]
    fn reward_mode_and_all_five_records_round_trip_and_reject_wrong_shapes() {
        let mut holder = block();
        holder.reward_mode = RewardMode::Holder;
        holder.rewards = (0..5)
            .map(|index| {
                let mut commitment = [0; 48];
                commitment[..4].copy_from_slice(&(index as u32 + 1).to_le_bytes());
                RewardRecord {
                    commitment,
                    ciphertext: [index; REWARD_CIPHERTEXT_BYTES],
                }
            })
            .collect();
        let encoded = holder.encode().unwrap();
        assert_eq!(Block::decode(&encoded, &holder.network).unwrap(), holder);
        let mut stream = std::io::Cursor::new(&encoded);
        assert_eq!(
            Block::read_from(&mut stream, encoded.len(), &holder.network).unwrap(),
            holder
        );
        let mut unknown = encoded.clone();
        unknown[BLOCK_HEADER_BYTES - 3] = 2;
        assert!(Block::decode(&unknown, &holder.network).is_err());
        let mut truncated = holder.clone();
        truncated.rewards.pop();
        assert!(truncated.encode().is_err());
        let mut duplicate = holder.clone();
        duplicate.rewards[4] = duplicate.rewards[0].clone();
        assert!(duplicate.encode().is_err());
        let mut swapped_mode = holder;
        swapped_mode.reward_mode = RewardMode::Voyager;
        assert!(swapped_mode.encode().is_err());
    }
}
