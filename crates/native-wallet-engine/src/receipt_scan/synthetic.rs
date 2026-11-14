//! Disposable receipt-authentication fixtures, with no native proof validity.
//! Expected amounts are handwritten case constants, never scanner outputs.
use super::{
    Error, Expectations, ExpectedNote, Result,
    accounting::Totals,
    history::{Frame, FrozenEng2History, FrozenHistory},
    identity::SyntheticCustody,
    origin::{Origin, OriginKind},
};
use crate::{
    eng2_history::{BODY_DOMAIN, Context, Header, HeaderPage, ReceiptBlock},
    eng2_light::native_profile,
    state::Config,
    wallet::Wallet,
    wire::*,
};
use native::{
    codec::{PublicTransaction, encode_digest},
    encryption::{EncryptionContext, encrypt_payment},
    multi_asset::{AssetId, Digest, F, Hasher, Note, SIP_ASSET_ID},
};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use siworld_core::pow;
use std::{collections::BTreeMap, sync::OnceLock};
use zeroize::Zeroizing;

pub const SECOND_ASSET: AssetId = AssetId([6; 32]);
pub const ZERO_ASSET: AssetId = AssetId([8; 32]);
#[derive(Clone, Copy)]
pub enum Branch {
    Original,
    Replacement,
    ConflictReplacement,
}
pub struct Scenario {
    pub history: FrozenHistory,
    pub custody: SyntheticCustody,
    pub expected: Expectations,
}
struct Intent {
    label: u32,
    amount: u64,
    asset: AssetId,
    unlock: u64,
}
impl Intent {
    fn note(&self, wallet: &Wallet) -> Note {
        Note {
            asset_id: self.asset,
            owner: wallet.address().owner(),
            value: self.amount,
            unlock_height: self.unlock,
            rho: [F::from_u32(self.label); 12],
            rseed: [F::from_u32(self.label + 1); 12],
        }
    }
}
fn common() -> Intent {
    Intent {
        label: 900001,
        amount: 100,
        asset: SIP_ASSET_ID,
        unlock: 2,
    }
}
fn orphan() -> Intent {
    Intent {
        label: 900011,
        amount: 7,
        asset: SIP_ASSET_ID,
        unlock: 0,
    }
}
fn moved() -> Intent {
    Intent {
        label: 900021,
        amount: 13,
        asset: SIP_ASSET_ID,
        unlock: 0,
    }
}
fn old_asset() -> Intent {
    Intent {
        label: 900031,
        amount: 40,
        asset: SECOND_ASSET,
        unlock: 4,
    }
}
fn new_asset() -> Intent {
    Intent {
        label: 900041,
        amount: 11,
        asset: SECOND_ASSET,
        unlock: 0,
    }
}
fn new_sip() -> Intent {
    Intent {
        label: 900051,
        amount: 5,
        asset: SIP_ASSET_ID,
        unlock: 4,
    }
}
fn digest(value: u32) -> DigestBytes {
    let mut fields = [F::ZERO; 12];
    fields[0] = F::from_u32(value);
    encode_digest(&fields)
}
fn genesis(config: &Config) -> (Vec<u8>, Hash) {
    let profile = native_profile();
    let governance = b"SWG2GOV2";
    let mut rules = blake3::Hasher::new_derive_key("siworld eng2 internal immutable rules v1");
    rules.update(&[0]);
    rules.update(&config.encode_rules());
    rules.update(&profile);
    rules.update(&(governance.len() as u64).to_le_bytes());
    rules.update(governance);
    rules.update(b"native-header:2;execution-components:2;fund:direct24-month8766x48;governance:4032-roster24;issuance-fee:public-governed-destination-v1");
    let id = blake3::derive_key(
        "siworld eng2 internal genesis v1",
        rules.finalize().as_bytes(),
    );
    let mut bytes = b"SWE2GEN1".to_vec();
    bytes.push(0);
    bytes.extend(profile);
    bytes.extend(config.encode_rules());
    bytes.extend((governance.len() as u32).to_le_bytes());
    bytes.extend(governance);
    (bytes, id)
}
fn disposable_wallet(network: Hash) -> Result<Wallet> {
    Wallet::from_seed(network, Zeroizing::new([42; 32]), 0)
        .map_err(|_| Error::Incomplete("synthetic_wallet"))
}
/// Independently derive the public disposable key's expected nullifier.
/// No observed receipt or scan result participates in this computation.
fn expected_nullifier(network: Hash, note: &Note) -> DigestBytes {
    let mut h = blake3::Hasher::new_derive_key("siworld native wallet spend key v1");
    h.update(&[42; 32]);
    h.update(&network);
    h.update(&0u32.to_le_bytes());
    let mut reader = h.finalize_xof();
    let mut key: Digest = [F::ZERO; 12];
    let mut count = 0;
    while count < key.len() {
        let mut bytes = [0u8; 64];
        reader.fill(&mut bytes);
        for word in bytes.chunks_exact(4) {
            let value = u32::from_le_bytes(word.try_into().expect("fixed synthetic word"));
            if value < F::ORDER_U32 {
                key[count] = F::from_u32(value);
                count += 1;
                if count == key.len() {
                    break;
                }
            }
        }
    }
    encode_digest(&Hasher::new().nullifier(&key, &note.rho))
}
fn reward(intent: &Intent, wallet: &Wallet, network: Hash) -> Result<RewardRecord> {
    let note = intent.note(wallet);
    let encrypted = encrypt_payment(&wallet.address(), &note, &EncryptionContext::new(network))
        .map_err(|_| Error::Incomplete("synthetic_encryption"))?;
    let mut ciphertext = [0; REWARD_CIPHERTEXT_BYTES];
    ciphertext[..1088].copy_from_slice(&encrypted.kem_ciphertext);
    ciphertext[1088..1296].copy_from_slice(&encrypted.body);
    ciphertext[1296..1312].copy_from_slice(&encrypted.tag);
    ciphertext[1312] = encrypted.view_tag;
    Ok(RewardRecord {
        commitment: encode_digest(&Hasher::new().note_cm(&note)),
        ciphertext,
    })
}
fn frame(
    config: &Config,
    context: &Context,
    height: u64,
    parent: Hash,
    parent_timestamp: u64,
    rewards: &[(usize, Intent)],
    spends_common: bool,
) -> Result<Frame> {
    let wallet = disposable_wallet(config.network)?;
    let mut reward_records = (0..5)
        .map(|i| RewardRecord {
            commitment: digest(2_000_000 + height as u32 * 10 + i),
            ciphertext: [0; REWARD_CIPHERTEXT_BYTES],
        })
        .collect::<Vec<_>>();
    for (ordinal, intent) in rewards {
        reward_records[*ordinal] = reward(intent, &wallet, config.network)?;
    }
    let mut transactions = Vec::new();
    for slot in 0..MIN_SLOTS {
        let base = 100_000 + height as u32 * 10_000 + slot as u32 * 10;
        let mut fields = [0; PUBLIC_BYTES];
        for offset in 0..5 {
            fields[offset * 48..(offset + 1) * 48].copy_from_slice(&digest(base + offset as u32));
        }
        if slot == 0 && spends_common {
            fields[..48]
                .copy_from_slice(&expected_nullifier(config.network, &common().note(&wallet)));
        }
        let _ = PublicTransaction::decode(&fields)
            .map_err(|_| Error::Incomplete("synthetic_transaction_fields"))?;
        transactions.push(Transaction {
            record: PublicRecord::new(
                Snapshot {
                    height: height - 1,
                    block_id: parent,
                },
                fields,
                digest(base + 5),
            )
            .map_err(|_| Error::Incomplete("synthetic_public_record"))?,
            proof: vec![7],
        });
    }
    transactions.sort_by_key(|tx| tx.record.statement_id(&config.network));
    let mut body = b"SW2B\x01\x00".to_vec();
    body.extend(config.network);
    body.extend(height.to_le_bytes());
    body.extend(context.profile());
    body.extend((MIN_SLOTS as u16).to_le_bytes());
    body.extend([1, 5, 0, 0, 0]);
    for record in reward_records {
        body.extend(record.commitment);
        body.extend(record.ciphertext);
    }
    body.extend([0; REWARD_RECORD_BYTES]);
    for transaction in transactions {
        let bytes = transaction
            .encode_envelope(&config.network)
            .map_err(|_| Error::Incomplete("synthetic_transaction_encoding"))?;
        body.extend((bytes.len() as u32).to_le_bytes());
        body.extend(bytes);
    }
    body.extend(1u32.to_le_bytes());
    body.push(9);
    let mut raw = (body.len() as u64).to_le_bytes().to_vec();
    raw.extend_from_slice(&body);
    let mut header = Header {
        network: config.network,
        height,
        parent,
        timestamp: config.genesis_timestamp + height * config.target_interval,
        target: pow::asert_target(
            &config.genesis_target,
            config.genesis_timestamp,
            config.target_interval,
            height - 1,
            parent_timestamp,
        ),
        execution_commitment: [9; 32],
        body_commitment: blake3::derive_key(BODY_DOMAIN, &raw),
        nonce: 0,
    };
    let seed = header
        .pow_seed()
        .map_err(|_| Error::Incomplete("synthetic_header"))?;
    header.nonce = (0..256)
        .find(|n| {
            pow::meets_target(
                &pow::pow_hash(&seed, *n, config.pow_iterations),
                &header.target,
            )
        })
        .ok_or(Error::Incomplete("bounded_synthetic_work"))?;
    let encoded = header
        .encode()
        .map_err(|_| Error::Incomplete("synthetic_header"))?;
    let receipt = ReceiptBlock::export(context, &encoded, &body)
        .map_err(|_| Error::Incomplete("synthetic_receipt_export"))?;
    Ok(Frame {
        header: encoded.to_vec().into_boxed_slice(),
        receipt: receipt.into_boxed_slice(),
    })
}
// Reuse the exact public ancestor within one disposable campaign process.
// Random encryption makes hashes differ across fresh processes; no native
// acceptance or externally reproducible artifact hash is inferred from it.
fn common_frame(config: &Config, context: &Context, id: Hash) -> Result<Frame> {
    static FIRST: OnceLock<Result<Frame>> = OnceLock::new();
    FIRST
        .get_or_init(|| {
            frame(
                config,
                context,
                1,
                id,
                config.genesis_timestamp,
                &[(0, common())],
                false,
            )
        })
        .clone()
}
fn header(frame: &Frame, network: Hash) -> Result<Header> {
    Header::decode(&frame.header, &network).map_err(|_| Error::Incomplete("synthetic_header"))
}
fn expected_note(
    history: &FrozenHistory,
    intent: Intent,
    height: u64,
    ordinal: u32,
    spent: bool,
) -> Result<(DigestBytes, ExpectedNote)> {
    let context = Context::from_genesis(history.genesis(), history.genesis_id())
        .map_err(|_| Error::Incomplete("synthetic_context"))?;
    let wallet = disposable_wallet(context.config().network)?;
    let note = intent.note(&wallet);
    let cm = encode_digest(&Hasher::new().note_cm(&note));
    let block = header(
        &history.frames[height as usize - 1],
        context.config().network,
    )?
    .id()
    .map_err(|_| Error::Incomplete("synthetic_header"))?;
    Ok((
        cm,
        ExpectedNote {
            origin: Origin {
                height,
                block,
                kind: OriginKind::Reward { ordinal },
                commitment: cm,
            },
            asset: intent.asset,
            amount: intent.amount,
            unlock_height: intent.unlock,
            nullifier: expected_nullifier(context.config().network, &note),
            spent,
        },
    ))
}
fn amount_totals(counts: [u64; 5], amounts: [u128; 5]) -> Totals {
    Totals {
        received_notes: counts[0],
        spent_notes: counts[1],
        unspent_notes: counts[2],
        mature_notes: counts[3],
        locked_notes: counts[4],
        received_atoms: amounts[0],
        spent_atoms: amounts[1],
        unspent_atoms: amounts[2],
        mature_atoms: amounts[3],
        locked_atoms: amounts[4],
    }
}
/// Complete three-block branches. Amounts below are fixed case arithmetic.
pub fn reorg_case(branch: Branch, spend_height: u64) -> Result<Scenario> {
    if spend_height != 3 && spend_height != 4 {
        return Err(Error::Incomplete("synthetic_spend_height"));
    }
    let config =
        Config::development([3; 32], 0).map_err(|_| Error::Incomplete("synthetic_config"))?;
    let (genesis, id) = genesis(&config);
    let context =
        Context::from_genesis(&genesis, id).map_err(|_| Error::Incomplete("synthetic_context"))?;
    let first = common_frame(&config, &context, id)?;
    let h1 = header(&first, config.network)?;
    let original = matches!(branch, Branch::Original);
    let second_rewards = if original {
        vec![(0, orphan()), (2, moved())]
    } else {
        vec![(0, new_asset())]
    };
    let second = frame(
        &config,
        &context,
        2,
        h1.id().map_err(|_| Error::Incomplete("synthetic_header"))?,
        h1.timestamp,
        &second_rewards,
        false,
    )?;
    let h2 = header(&second, config.network)?;
    let third_rewards = if original {
        vec![(0, old_asset())]
    } else {
        vec![(0, new_sip()), (4, moved())]
    };
    let spend = original || matches!(branch, Branch::ConflictReplacement);
    let third = frame(
        &config,
        &context,
        3,
        h2.id().map_err(|_| Error::Incomplete("synthetic_header"))?,
        h2.timestamp,
        &third_rewards,
        spend,
    )?;
    let tip = header(&third, config.network)?
        .id()
        .map_err(|_| Error::Incomplete("synthetic_header"))?;
    let history = FrozenHistory::synthetic(genesis, id, vec![first, second, third], tip)?;
    let mut balances = BTreeMap::new();
    let mut notes = BTreeMap::new();
    notes.extend([expected_note(&history, common(), 1, 0, spend)?]);
    if original {
        // SIP:100+7+13 received;100 spent. Asset:40,unlock4.
        balances.insert(
            SIP_ASSET_ID,
            amount_totals([3, 1, 2, 2, 0], [120, 100, 20, 20, 0]),
        );
        balances.insert(
            SECOND_ASSET,
            if spend_height == 3 {
                amount_totals([1, 0, 1, 0, 1], [40, 0, 40, 0, 40])
            } else {
                amount_totals([1, 0, 1, 1, 0], [40, 0, 40, 40, 0])
            },
        );
        notes.extend([
            expected_note(&history, orphan(), 2, 0, false)?,
            expected_note(&history, moved(), 2, 2, false)?,
            expected_note(&history, old_asset(), 3, 0, false)?,
        ]);
    } else {
        // SIP:100+5+13 received; replacement optionally spends100.
        let spent = if spend { 100 } else { 0 };
        let mature = if spend_height == 3 {
            if spend { 13 } else { 113 }
        } else {
            118 - spent
        };
        let locked = if spend_height == 3 { 5 } else { 0 };
        balances.insert(
            SIP_ASSET_ID,
            amount_totals(
                [
                    3,
                    u64::from(spend),
                    if spend { 2 } else { 3 },
                    if spend_height == 3 {
                        if spend { 1 } else { 2 }
                    } else {
                        if spend { 2 } else { 3 }
                    },
                    u64::from(spend_height == 3),
                ],
                [118, spent, 118 - spent, mature, locked],
            ),
        );
        balances.insert(
            SECOND_ASSET,
            amount_totals([1, 0, 1, 1, 0], [11, 0, 11, 11, 0]),
        );
        notes.extend([
            expected_note(&history, new_asset(), 2, 0, false)?,
            expected_note(&history, new_sip(), 3, 0, false)?,
            expected_note(&history, moved(), 3, 4, false)?,
        ]);
    }
    balances.insert(ZERO_ASSET, Totals::default());
    let expected = Expectations {
        history_manifest: history.manifest_sha256(),
        spend_height,
        balances,
        notes,
    };
    Ok(Scenario {
        history,
        custody: SyntheticCustody::new(config.network),
        expected,
    })
}
/// Full prefix fixtures beyond the old64-block and128-header page boundaries.
pub fn padding_prefix(height: u64) -> Result<Scenario> {
    if !(1..=129).contains(&height) {
        return Err(Error::Incomplete("synthetic_prefix_bound"));
    }
    let config =
        Config::development([3; 32], 0).map_err(|_| Error::Incomplete("synthetic_config"))?;
    let (genesis, id) = genesis(&config);
    let context =
        Context::from_genesis(&genesis, id).map_err(|_| Error::Incomplete("synthetic_context"))?;
    let mut frames = Vec::new();
    let mut parent = id;
    let mut timestamp = config.genesis_timestamp;
    for h in 1..=height {
        let rewards = if h == 1 { vec![(0, common())] } else { vec![] };
        let f = if h == 1 {
            common_frame(&config, &context, id)?
        } else {
            frame(&config, &context, h, parent, timestamp, &rewards, false)?
        };
        let header = header(&f, config.network)?;
        parent = header
            .id()
            .map_err(|_| Error::Incomplete("synthetic_header"))?;
        timestamp = header.timestamp;
        frames.push(f);
    }
    let history = FrozenHistory::synthetic(genesis, id, frames, parent)?;
    let mut balances = BTreeMap::new();
    balances.insert(
        SIP_ASSET_ID,
        if height < 2 {
            amount_totals([1, 0, 1, 0, 1], [100, 0, 100, 0, 100])
        } else {
            amount_totals([1, 0, 1, 1, 0], [100, 0, 100, 100, 0])
        },
    );
    let notes = BTreeMap::from([expected_note(&history, common(), 1, 0, false)?]);
    let expected = Expectations {
        history_manifest: history.manifest_sha256(),
        spend_height: height,
        balances,
        notes,
    };
    Ok(Scenario {
        history,
        custody: SyntheticCustody::new(config.network),
        expected,
    })
}
pub fn authenticate_header_pages(history: &FrozenHistory) -> Result<()> {
    let context = Context::from_genesis(history.genesis(), history.genesis_id())
        .map_err(|_| Error::Rejected("page_context"))?;
    let mut parent = history.genesis_id();
    for (page_index, rows) in history.frames.chunks(128).enumerate() {
        let from = page_index as u64 * 128 + 1;
        let mut bytes = b"SWE2WHP1".to_vec();
        for value in [
            context.config().network,
            context.genesis(),
            context.rules(),
            context.profile(),
        ] {
            bytes.extend(value);
        }
        bytes.push(0);
        bytes.extend(history.height().to_le_bytes());
        bytes.extend(history.tip());
        bytes.extend(from.to_le_bytes());
        bytes.extend((rows.len() as u16).to_le_bytes());
        for row in rows {
            bytes.extend_from_slice(&row.header);
        }
        let page = HeaderPage::decode(&context, (history.height(), history.tip()), &bytes)
            .map_err(|_| Error::Rejected("header_page"))?;
        for header in page.headers {
            if header.parent != parent {
                return Err(Error::Rejected("cross_page_parent"));
            }
            parent = header.id().map_err(|_| Error::Rejected("page_header"))?;
        }
    }
    if parent != history.tip() {
        return Err(Error::Rejected("page_tip"));
    }
    Ok(())
}
#[derive(Clone, Copy)]
pub enum Fault {
    MissingFirst,
    MissingMiddle,
    MissingLast,
    Reordered,
    DuplicateHeight,
    TailMismatch,
    Context,
    Profile,
    ReceiptCorrupt,
    SnapshotPinChange,
}
/// Constructs corrupted immutable input for rejection tests, not accepted data.
pub fn with_fault(source: &FrozenHistory, fault: Fault) -> FrozenHistory {
    let mut value = source.clone();
    let mut rows = value.frames.to_vec();
    match fault {
        Fault::MissingFirst => {
            rows.remove(0);
        }
        Fault::MissingMiddle => {
            rows.remove(rows.len() / 2);
        }
        Fault::MissingLast => {
            rows.pop();
        }
        Fault::Reordered => {
            rows.swap(0, 1);
        }
        Fault::DuplicateHeight => {
            rows[1] = rows[0].clone();
        }
        Fault::TailMismatch => {
            value.tip[0] ^= 1;
        }
        Fault::Context => {
            value.genesis[41] ^= 1;
        }
        Fault::Profile => {
            value.genesis[9] ^= 1;
        }
        Fault::ReceiptCorrupt => {
            rows[0].receipt[8] ^= 1;
        }
        Fault::SnapshotPinChange => {}
    }
    value.frames = rows.into_boxed_slice();
    value.seal();
    if matches!(fault, Fault::SnapshotPinChange) {
        value.after[0] ^= 1;
    }
    value
}
