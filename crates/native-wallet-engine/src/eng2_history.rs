//! Public receipt records bound to a caller-authenticated engineering-v2 header.
//! This codec supplies neither chain selection nor wallet synchronization.
use crate::{
    fund_spend::FundSpend,
    issuance::IssuanceRecord,
    ranges::{MAX_COMPACT, RangeProof, Sparse},
    state::Config,
    wallet::{OwnedNote, Wallet},
    wire::*,
};
use native::codec::{PublicTransaction, decode_digest, encode_digest};

pub use crate::wallet_eng2_header::{HEADER_BYTES, Header};

pub const BODY_DOMAIN: &str = "siworld eng2 canonical block body v1";
pub const MAX_BODY_BYTES: usize = MAX_BLOCK_BYTES + REWARD_RECORD_BYTES + 4 * 1024 * 1024;
const BINDING_BYTES: usize = 129;
const PREFIX_BYTES: usize = 8 + BINDING_BYTES + HEADER_BYTES;
pub const MAX_RECEIPT_BYTES: usize = PREFIX_BYTES + MAX_COMPACT;
const RULES_DOMAIN: &str = "siworld eng2 internal immutable rules v1";
const RULES_SUFFIX: &[u8] = b"native-header:2;execution-components:2;fund:direct24-month8766x48;governance:4032-roster24;issuance-fee:public-governed-destination-v1";
const MAX_GOVERNANCE_BYTES: usize = 16384;
const MAX_GOVERNANCE_ACTIONS: usize = 32;
const FUND_UNSIGNED_BYTES: usize =
    crate::fund_spend::ENCODED_BYTES - crate::fund_spend::SIGNATURE_BYTES;
const FUND_CLAIM_BYTES: usize = 46 + crate::fund_spend::ENCODED_BYTES + 32;

/// The expected genesis identifier must come from an independent local pin.
/// Hash binding authenticates the complete bootstrap bytes; this is not an
/// execution or governance-state validator for an unpinned network.
#[derive(Clone)]
pub struct Context {
    config: Config,
    genesis: Hash,
    rules: Hash,
    profile: Hash,
    fee_mode: u8,
}
impl Context {
    pub fn from_genesis(bytes: &[u8], expected: Hash) -> Result<Self, String> {
        let end = 41 + crate::state::CONFIG_RULE_BYTES;
        let prefix = end + 4;
        if bytes.len() < prefix + 8
            || bytes.len() > prefix + 131072
            || &bytes[..8] != b"SWE2GEN1"
            || bytes[8] != 0
            || bytes[9..41] != crate::proofs::protocol_profile_fingerprint()
            || expected == [0; 32]
        {
            return Err("wallet genesis encoding, fee mode or native profile rejected".into());
        }
        let config = Config::decode_rules(&bytes[41..end])?;
        if config.encode_rules().as_slice() != &bytes[41..end] {
            return Err("wallet genesis configuration is noncanonical".into());
        }
        let length =
            u32::from_le_bytes(bytes[end..prefix].try_into().expect("fixed length")) as usize;
        if length != bytes.len() - prefix || &bytes[prefix..prefix + 8] != b"SWG2GOV2" {
            return Err("wallet genesis governance framing rejected".into());
        }
        let profile = crate::proofs::protocol_profile_fingerprint();
        let mut hash = blake3::Hasher::new_derive_key(RULES_DOMAIN);
        hash.update(&[bytes[8]]);
        hash.update(&config.encode_rules());
        hash.update(&profile);
        hash.update(&(length as u64).to_le_bytes());
        hash.update(&bytes[prefix..]);
        hash.update(RULES_SUFFIX);
        let rules = *hash.finalize().as_bytes();
        let genesis = blake3::derive_key("siworld eng2 internal genesis v1", &rules);
        if genesis != expected {
            return Err("wallet genesis differs from independently pinned identifier".into());
        }
        Ok(Self {
            config,
            genesis,
            rules,
            profile,
            fee_mode: bytes[8],
        })
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    pub fn genesis(&self) -> Hash {
        self.genesis
    }
    pub fn rules(&self) -> Hash {
        self.rules
    }
    pub fn profile(&self) -> Hash {
        self.profile
    }
    pub fn fee_mode(&self) -> u8 {
        self.fee_mode
    }
    fn binding(&self) -> Vec<u8> {
        let mut value = Vec::with_capacity(BINDING_BYTES);
        for field in [
            &self.config.network,
            &self.genesis,
            &self.rules,
            &self.profile,
        ] {
            value.extend_from_slice(field);
        }
        value.push(self.fee_mode);
        value
    }
}

/// Authenticated public data only. Native transaction and issuance proofs are
/// omitted; at most adjacent BLAKE3 chunks remain as authentication bytes.
/// The fixed LegacyMiner fee slot is checked as zero and is not a tree output.
pub struct ReceiptBlock {
    header: Header,
    body_bytes: usize,
    transactions: Vec<PublicRecord>,
    rewards: Vec<RewardRecord>,
    fund_outputs: Vec<FundSpend>,
    issuances: Vec<IssuanceRecord>,
    reward_mode: RewardMode,
}
struct Reader<F> {
    at: usize,
    length: usize,
    ranges: Vec<(usize, usize)>,
    read: F,
}
impl<F: Fn(usize, usize) -> Result<Vec<u8>, String>> Reader<F> {
    fn take(&mut self, n: usize) -> Result<Vec<u8>, String> {
        let value = (self.read)(self.at, n)?;
        self.ranges.push((self.at, n));
        self.skip(n)?;
        Ok(value)
    }
    fn skip(&mut self, n: usize) -> Result<(), String> {
        self.at = self
            .at
            .checked_add(n)
            .ok_or("wallet body offset overflow")?;
        if self.at > self.length {
            return Err("wallet body range exceeds declared length".into());
        }
        Ok(())
    }
    fn u32(&mut self) -> Result<usize, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("fixed length")) as usize)
    }
    fn reward(&mut self) -> Result<RewardRecord, String> {
        let bytes = self.take(REWARD_RECORD_BYTES)?;
        let commitment = bytes[..48].try_into().expect("fixed commitment");
        let _ = decode_digest(&commitment).map_err(|_| "wallet reward commitment rejected")?;
        Ok(RewardRecord {
            commitment,
            ciphertext: bytes[48..].try_into().expect("fixed ciphertext"),
        })
    }
}
fn parse(
    context: &Context,
    header: Header,
    length: usize,
    read: impl Fn(usize, usize) -> Result<Vec<u8>, String>,
) -> Result<(ReceiptBlock, Vec<(usize, usize)>), String> {
    let mut r = Reader {
        at: 0,
        length,
        ranges: Vec::new(),
        read,
    };
    let body_length = u64::from_le_bytes(r.take(8)?.try_into().expect("fixed body length"));
    if body_length != length.saturating_sub(8) as u64 || body_length > MAX_BODY_BYTES as u64 {
        return Err("wallet authenticated body length rejected".into());
    }
    let prefix = r.take(85)?;
    if &prefix[..6] != b"SW2B\x01\x00"
        || prefix[6..38] != context.config.network
        || u64::from_le_bytes(prefix[38..46].try_into().expect("fixed height")) != header.height
        || prefix[46..78] != context.profile
        || header.height == 0
        || header.network != context.config.network
    {
        return Err("wallet body network, height or profile rejected".into());
    }
    let count = usize::from(u16::from_le_bytes(
        prefix[78..80].try_into().expect("fixed count"),
    ));
    let mode = match prefix[80] {
        0 => RewardMode::Voyager,
        1 => RewardMode::Holder,
        _ => return Err("wallet reward mode rejected".into()),
    };
    let rewards_count = prefix[81] as usize;
    let funds_count = prefix[82] as usize;
    let governance_count = prefix[83] as usize;
    let issuances_count = prefix[84] as usize;
    if !(MIN_SLOTS..=MAX_SLOTS).contains(&count)
        || !count.is_multiple_of(GROUP)
        || rewards_count != reward_count(mode)
        || funds_count > MAX_FUND_SPENDS
        || governance_count > MAX_GOVERNANCE_ACTIONS
        || issuances_count > crate::issuance::RECORDS_CODEC_LIMIT
    {
        return Err("wallet public record count rejected".into());
    }
    let rewards = (0..rewards_count)
        .map(|_| r.reward())
        .collect::<Result<Vec<_>, _>>()?;
    let fee_slot = r.reward()?;
    if fee_slot.commitment != [0; 48] || fee_slot.ciphertext != [0; REWARD_CIPHERTEXT_BYTES] {
        return Err("wallet fixed legacy fee slot rejected".into());
    }
    let mut fund_outputs = Vec::with_capacity(funds_count);
    for _ in 0..funds_count {
        let bytes = r.take(FUND_CLAIM_BYTES)?;
        if &bytes[..6] != b"SW2F\x01\x00"
            || bytes[6..38] != context.config.network
            || u64::from_le_bytes(bytes[38..46].try_into().expect("fixed fund height"))
                != header.height
        {
            return Err("wallet public fund claim context rejected".into());
        }
        let mut spend = Vec::with_capacity(crate::fund_spend::ENCODED_BYTES);
        spend.extend_from_slice(&bytes[46..46 + FUND_UNSIGNED_BYTES]);
        spend.extend_from_slice(&bytes[46 + FUND_UNSIGNED_BYTES + 32..]);
        let spend = FundSpend::decode(&spend)?;
        if fund_outputs
            .last()
            .is_some_and(|last: &FundSpend| last.account >= spend.account)
        {
            return Err("wallet public fund order rejected".into());
        }
        fund_outputs.push(spend);
    }
    for _ in 0..governance_count {
        let size = r.u32()?;
        if size == 0 || size > MAX_GOVERNANCE_BYTES {
            return Err("wallet governance frame bound".into());
        }
        r.skip(size)?;
    }
    let mut issuances = Vec::with_capacity(issuances_count);
    let issuance_fixed = crate::issuance::MAX_RECORD_BYTES
        - crate::issuance::METADATA_CODEC_LIMIT
        - crate::issuance::MAX_PROOF_BYTES;
    for _ in 0..issuances_count {
        let size = r.u32()?;
        if size > crate::issuance::MAX_RECORD_BYTES {
            return Err("wallet issuance frame bound".into());
        }
        let mut public = r.take(2040)?;
        let name = usize::from(u16::from_le_bytes(
            public[2038..2040]
                .try_into()
                .expect("fixed metadata length"),
        ));
        if name + 1 > crate::issuance::METADATA_CODEC_LIMIT {
            return Err("wallet issuance metadata bound".into());
        }
        public.extend(r.take(issuance_fixed + name - 2040)?);
        let end = public.len();
        let proof = u32::from_le_bytes(
            public[end - 4..]
                .try_into()
                .expect("fixed issuance proof length"),
        ) as usize;
        if proof == 0 || proof > crate::issuance::MAX_PROOF_BYTES || size != end + proof {
            return Err("wallet issuance proof framing rejected".into());
        }
        r.skip(proof)?;
        // Reuse the existing public issuance decoder, then remove its placeholder.
        public[end - 4..].copy_from_slice(&1u32.to_le_bytes());
        public.push(0);
        let mut issuance = IssuanceRecord::decode(&public)?;
        issuance.proof.clear();
        if issuance.signed.declaration.network != context.config.network
            || issuances.last().is_some_and(|last: &IssuanceRecord| {
                last.signed.declaration.binding() >= issuance.signed.declaration.binding()
            })
        {
            return Err("wallet issuance network or order rejected".into());
        }
        issuances.push(issuance);
    }
    let mut transactions = Vec::with_capacity(count);
    for _ in 0..count {
        let size = r.u32()?;
        if !(TX_PREFIX_BYTES + 1..=MAX_ENVELOPE_BYTES).contains(&size) {
            return Err("wallet transaction frame bound".into());
        }
        let p = r.take(TX_PREFIX_BYTES)?;
        let proof = u32::from_le_bytes(
            p[TX_PREFIX_BYTES - 4..]
                .try_into()
                .expect("fixed proof length"),
        ) as usize;
        if &p[..4] != b"SWTX"
            || p[4..6] != FORMAT_VERSION.to_le_bytes()
            || &p[6..33] != SUITE_ID
            || p[33..65] != context.config.network
            || proof == 0
            || proof > MAX_TX_PROOF
            || size != TX_PREFIX_BYTES + proof
        {
            return Err("wallet transaction envelope rejected".into());
        }
        let record = PublicRecord::new(
            Snapshot {
                height: u64::from_le_bytes(p[65..73].try_into().expect("fixed snapshot height")),
                block_id: p[73..105].try_into().expect("fixed snapshot identity"),
            },
            p[105..105 + PUBLIC_BYTES]
                .try_into()
                .expect("fixed public transaction"),
            p[105 + PUBLIC_BYTES..TX_PREFIX_BYTES - 4]
                .try_into()
                .expect("fixed fee commitment"),
        )?;
        if transactions.last().is_some_and(|last: &PublicRecord| {
            last.statement_id(&context.config.network)
                >= record.statement_id(&context.config.network)
        }) {
            return Err("wallet transaction order rejected".into());
        }
        r.skip(proof)?;
        transactions.push(record);
    }
    let proof = r.u32()?;
    if proof == 0 || proof > MAX_SETTLEMENT_PROOF {
        return Err("wallet settlement frame bound".into());
    }
    r.skip(proof)?;
    if r.at != length {
        return Err("wallet canonical body has trailing data".into());
    }
    Ok((
        ReceiptBlock {
            header,
            body_bytes: body_length as usize,
            transactions,
            rewards,
            fund_outputs,
            issuances,
            reward_mode: mode,
        },
        r.ranges,
    ))
}
impl ReceiptBlock {
    /// Canonical body length authenticated by the header commitment.
    /// This excludes the eight-byte length prefix used only by the range proof.
    pub fn body_bytes(&self) -> usize {
        self.body_bytes
    }
    pub fn header(&self) -> &Header {
        &self.header
    }
    pub fn transactions(&self) -> &[PublicRecord] {
        &self.transactions
    }
    pub fn rewards(&self) -> &[RewardRecord] {
        &self.rewards
    }
    pub fn fund_outputs(&self) -> &[FundSpend] {
        &self.fund_outputs
    }
    pub fn issuances(&self) -> &[IssuanceRecord] {
        &self.issuances
    }
    pub fn reward_mode(&self) -> RewardMode {
        self.reward_mode
    }
    /// The caller must authenticate this exact header in its selected chain.
    /// Matching a body commitment alone does not prove execution or chain choice.
    pub fn decode(
        context: &Context,
        expected_header: &[u8; HEADER_BYTES],
        bytes: &[u8],
    ) -> Result<Self, String> {
        if bytes.len() < PREFIX_BYTES + 17
            || bytes.len() > MAX_RECEIPT_BYTES
            || &bytes[..8] != b"SWE2WLT1"
            || bytes[8..8 + BINDING_BYTES] != context.binding()
            || &bytes[8 + BINDING_BYTES..PREFIX_BYTES] != expected_header
        {
            return Err("wallet receipt envelope or pinned context rejected".into());
        }
        let header = Header::decode(expected_header, &context.config.network)
            .map_err(|_| "wallet expected header rejected")?;
        let sparse: Sparse = RangeProof::verify_bound(
            &bytes[PREFIX_BYTES..],
            header.body_commitment,
            BODY_DOMAIN,
            MAX_BODY_BYTES + 8,
        )?;
        let (block, ranges) = parse(context, header, sparse.length, |at, n| sparse.read(at, n))?;
        sparse.require_exact_ranges(&ranges)?;
        Ok(block)
    }
    /// Construction remains internal: externally publishable input must come
    /// from the accepted Store adapter, never an admitted or pending block.
    #[allow(dead_code)] // Native export uses this constructor; portable wallet builds decode.
    pub(crate) fn export(
        context: &Context,
        header: &[u8; HEADER_BYTES],
        body: &[u8],
    ) -> Result<Vec<u8>, String> {
        let decoded = Header::decode(header, &context.config.network)
            .map_err(|_| "wallet source header rejected")?;
        decoded
            .verify_body(body, MAX_BODY_BYTES)
            .map_err(|_| "wallet source body commitment rejected")?;
        let mut raw = Vec::with_capacity(8 + body.len());
        raw.extend_from_slice(&(body.len() as u64).to_le_bytes());
        raw.extend_from_slice(body);
        let (_, ranges) = parse(context, decoded, raw.len(), |at, n| {
            raw.get(at..at + n)
                .map(|v| v.to_vec())
                .ok_or_else(|| "wallet source range unavailable".into())
        })?;
        let proof = RangeProof::create_bound(&raw, &ranges, BODY_DOMAIN, MAX_BODY_BYTES + 8)?;
        let mut bytes = Vec::with_capacity(PREFIX_BYTES + proof.len());
        bytes.extend_from_slice(b"SWE2WLT1");
        bytes.extend(context.binding());
        bytes.extend_from_slice(header);
        bytes.extend(proof);
        Ok(bytes)
    }
    pub fn contains_statement(&self, id: &Hash) -> bool {
        self.transactions
            .iter()
            .any(|record| record.statement_id(&self.header.network) == *id)
    }
    /// Exact native commitment-tree append order; the unused fee slot is absent.
    pub fn outputs(&self) -> Result<Vec<DigestBytes>, String> {
        let mut result = Vec::new();
        for record in &self.transactions {
            result.extend(
                PublicTransaction::decode(&record.body)
                    .map_err(|_| "wallet transaction fields rejected")?
                    .cm
                    .map(|cm| encode_digest(&cm)),
            );
        }
        for record in &self.issuances {
            result.extend(
                record
                    .signed
                    .declaration
                    .note_commitments
                    .iter()
                    .map(encode_digest),
            );
        }
        result.extend(self.rewards.iter().map(|record| record.commitment));
        result.extend(self.fund_outputs.iter().map(|record| record.commitment));
        Ok(result)
    }
    /// Reuse receipt decryption only. The private carrier is never passed to
    /// legacy header validation, state execution or LightWallet::append.
    pub fn scan_receipts(&self, wallet: &Wallet) -> Result<Vec<OwnedNote>, String> {
        let carrier = Block {
            network: self.header.network,
            height: self.header.height,
            parent: self.header.parent,
            timestamp: self.header.timestamp,
            target: self.header.target,
            nonce: self.header.nonce,
            transactions: self
                .transactions
                .iter()
                .map(|record| Transaction {
                    record: record.clone(),
                    proof: Vec::new(),
                })
                .collect(),
            reward_mode: self.reward_mode,
            rewards: self.rewards.clone(),
            fund_spends: self.fund_outputs.clone(),
            issuances: self.issuances.clone(),
            settlement_proof: Vec::new(),
        };
        wallet.scan_light_receipts(
            &[carrier],
            &[self
                .header
                .id()
                .map_err(|_| "wallet header identity rejected")?],
        )
    }
}

pub const MAX_HEADER_PAGE: usize = 128;
/// A context-bound page is not a selected chain. The caller must verify PoW,
/// difficulty and continuity with preceding pages and a fresh accepted-head pin.
pub struct HeaderPage {
    pub accepted_height: u64,
    pub accepted_tip: Hash,
    pub from: u64,
    pub headers: Vec<Header>,
}
impl HeaderPage {
    pub fn decode(
        context: &Context,
        expected_head: (u64, Hash),
        bytes: &[u8],
    ) -> Result<Self, String> {
        const PREFIX: usize = 8 + BINDING_BYTES + 8 + 32 + 8 + 2;
        if bytes.len() < PREFIX
            || bytes.len() > PREFIX + MAX_HEADER_PAGE * HEADER_BYTES
            || &bytes[..8] != b"SWE2WHP1"
            || bytes[8..8 + BINDING_BYTES] != context.binding()
        {
            return Err("wallet header page context or byte bound rejected".into());
        }
        let mut at = 8 + BINDING_BYTES;
        let accepted_height =
            u64::from_le_bytes(bytes[at..at + 8].try_into().expect("fixed head height"));
        at += 8;
        let accepted_tip: Hash = bytes[at..at + 32].try_into().expect("fixed head identity");
        at += 32;
        let from = u64::from_le_bytes(bytes[at..at + 8].try_into().expect("fixed page start"));
        at += 8;
        let count = usize::from(u16::from_le_bytes(
            bytes[at..at + 2].try_into().expect("fixed page count"),
        ));
        at += 2;
        if (accepted_height, accepted_tip) != expected_head
            || from == 0
            || from > accepted_height
            || !(1..=MAX_HEADER_PAGE).contains(&count)
            || count as u64 > accepted_height - from + 1
            || bytes.len() != at + count * HEADER_BYTES
        {
            return Err("wallet header page head, range or length rejected".into());
        }
        let mut headers: Vec<Header> = Vec::with_capacity(count);
        for index in 0..count {
            let header = Header::decode(&bytes[at..at + HEADER_BYTES], &context.config.network)
                .map_err(|_| "wallet page header rejected")?;
            at += HEADER_BYTES;
            if header.height != from + index as u64
                || (header.height == 1 && header.parent != context.genesis)
                || headers
                    .last()
                    .is_some_and(|last| last.id().ok() != Some(header.parent))
            {
                return Err("wallet page header continuity rejected".into());
            }
            headers.push(header);
        }
        let last = headers.last().expect("nonempty bounded page");
        if last.height == accepted_height && last.id().ok() != Some(accepted_tip) {
            return Err("wallet page accepted head identity rejected".into());
        }
        Ok(Self {
            accepted_height,
            accepted_tip,
            from,
            headers,
        })
    }
}
