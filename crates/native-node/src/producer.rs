//! Local block preparation for a disposable native engineering network.
//! Candidate blocks still require the shared durable state transition.

use crate::pool::Padding;
use crate::proofs::NativeProver;
use crate::state::{State, base_fee, tail_slots};
use crate::wire::{Block, GROUP, MAX_SLOTS, MIN_SLOTS, PublicRecord, RewardRecord, Transaction};
use native::codec::{ProofContext, PublicTransaction, decode_digest, encode_digest};
use native::confidential_fees::{FeeOpening, SettlementSlot};
use native::encryption::{
    EncryptionContext, PaymentAddress, PaymentCiphertext, PaymentEncryptionOpening,
    RecipientViewKey, SenderChangeSecret, decrypt_change_at, encrypt_change_at,
    encrypt_payment_with_opening,
};
use native::multi_asset::{
    AccWitness, AnchorTree, F, Hasher, InputWitness, Note, OutputWitness, SIP_ASSET_ID,
    SlotWitness, TREE_DEPTH,
};
use native::settlement::FixedSettlementWitness;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use siworld_core::v1_economics::RewardMode;
use std::collections::BTreeSet;
use zeroize::Zeroizing;

const REWARD_ENTRY_BYTES: usize = 48 + 48 + 48 + 1184 + 32;
pub const MAX_REWARD_SECRET_BYTES: usize = 48 + 5 * REWARD_ENTRY_BYTES;
const REWARD_SECRET_MAGIC: &[u8; 4] = b"SWRM";
const REWARD_SECRET_VERSION: u16 = 2;

pub struct ProducedBlock {
    pub block: Block,
    /// Private engineering-wallet recovery material. Never log or relay it.
    pub reward_secret: Zeroizing<Vec<u8>>,
}

/// Synthetic proof fixture with real reward encryption and receipt binding.
#[cfg(all(test, unix))]
pub(crate) fn production_fixture(state: &State, seed: u32) -> ProducedBlock {
    let keys =
        crate::wallet::WalletKeys::from_seed(state.config.network, Zeroizing::new([42; 32]), 0)
            .expect("synthetic production wallet");
    let rewards = prepare_rewards(
        state,
        0,
        &MiningSettings {
            mode: RewardMode::Voyager,
            recipient: keys.address(),
        },
    )
    .expect("synthetic production rewards");
    let mut block = crate::fixtures::candidate(state, seed);
    block.rewards = rewards.records;
    ProducedBlock {
        block,
        reward_secret: rewards.secret,
    }
}

struct PreparedTransaction {
    witness: AccWitness,
    public: PublicTransaction,
    record: PublicRecord,
    opening: FeeOpening,
}
#[cfg(test)]
impl PreparedTransaction {
    fn opening_commitment(&self) -> native::multi_asset::Digest {
        Hasher::new().fee_commit(self.opening.fee, &self.opening.blind)
    }
}

/// Explicit template-local settings. There is no default reward mode.
/// The supplied payment address must belong to a separately backed-up wallet.
#[derive(Clone)]
pub struct MiningSettings {
    pub mode: RewardMode,
    pub recipient: PaymentAddress,
}
struct PreparedRewards {
    records: Vec<RewardRecord>,
    notes: Vec<Note>,
    secret: Zeroizing<Vec<u8>>,
}

fn fields_from_entropy<const N: usize>(
    fill: &mut impl FnMut(&mut [u8]) -> Result<(), String>,
) -> Result<[F; N], String> {
    let mut out = [F::ZERO; N];
    let mut filled = 0;
    let mut entropy = Zeroizing::new([0u8; 64]);
    while filled < N {
        fill(entropy.as_mut())?;
        for word in entropy.as_chunks::<4>().0 {
            let raw = u32::from_le_bytes(*word);
            if raw < F::ORDER_U32 {
                out[filled] = F::from_u32(raw);
                filled += 1;
                if filled == N {
                    break;
                }
            }
        }
    }
    Ok(out)
}

fn random_fields<const N: usize>() -> Result<[F; N], String> {
    fields_from_entropy(&mut |bytes| {
        getrandom::fill(bytes).map_err(|_| "operating-system randomness unavailable".to_owned())
    })
}

fn context(state: &State) -> ProofContext {
    let snapshot = state.tip_snapshot().selector;
    ProofContext::for_snapshot(state.config.network, snapshot.height, snapshot.block_id)
}

fn same_note(left: &Note, right: &Note) -> bool {
    left.asset_id == right.asset_id
        && left.owner == right.owner
        && left.value == right.value
        && left.unlock_height == right.unlock_height
        && left.rho == right.rho
        && left.rseed == right.rseed
}

fn check_count(count: usize) -> Result<(), String> {
    if !(MIN_SLOTS..=MAX_SLOTS).contains(&count) || !count.is_multiple_of(GROUP) {
        return Err("engineering block positions must be 64 through 576 in groups of 16".into());
    }
    Ok(())
}

/// Prepare an empty position against the actual canonical tip. Both zero-value
/// inputs still get fresh independent nullifiers; all outputs use the complete
/// native encryption format and are locally decrypted before proof generation.
fn prepare_empty(state: &State, roots: &AnchorTree) -> Result<PreparedTransaction, String> {
    let h = Hasher::new();
    let snapshot = state.tip_snapshot();
    if encode_digest(&roots.root()) != snapshot.recent_root {
        return Err("local recent-root tree does not match the canonical tip snapshot".into());
    }
    let anchor =
        decode_digest(&snapshot.commitment_root).map_err(|_| "invalid local commitment root")?;
    let input = || -> Result<InputWitness, String> {
        Ok(InputWitness {
            asset_id: SIP_ASSET_ID,
            nk: random_fields()?,
            rho: random_fields()?,
            rseed: random_fields()?,
            value: 0,
            unlock_height: 0,
            dummy: true,
            path: vec![([F::ZERO; 12], false); TREE_DEPTH],
        })
    };
    let output = || -> Result<OutputWitness, String> {
        Ok(OutputWitness {
            asset_id: SIP_ASSET_ID,
            owner: h.owner(&random_fields()?),
            value: 0,
            unlock_height: 0,
            rseed: random_fields()?,
        })
    };
    let blind = random_fields()?;
    let mut witness = AccWitness {
        slot: SlotWitness {
            anchor,
            inputs: [input()?, input()?],
            outputs: [output()?, output()?, output()?],
            fee: 0,
            fee_blind: blind,
            fee_is_priority: false,
        },
        d_ct: [0; 32],
        anchor_height: snapshot.selector.height,
        base_fee: base_fee(snapshot.selector.height),
        anchor_path: roots.path(snapshot.selector.height),
    };
    let fields = witness.slot.public_inputs(&h);
    let notes: [Note; 3] = core::array::from_fn(|i| witness.slot.output_note(&h, &fields.nf, i));
    let recipient = RecipientViewKey::generate(notes[0].owner)
        .map_err(|_| "empty-output KEM key generation failed")?;
    let change_secret =
        SenderChangeSecret::generate().map_err(|_| "empty-output change key generation failed")?;
    let ec = EncryptionContext::new(state.config.network);
    let (payment, opening) = encrypt_payment_with_opening(&recipient.address(), &notes[0], &ec)
        .map_err(|_| "empty-output payment encryption failed")?;
    let public = PublicTransaction {
        nf: fields.nf,
        cm: fields.cm_out,
        payment,
        change: [
            encrypt_change_at(&change_secret, &notes[1], &ec, 1)
                .map_err(|_| "empty-output change encryption failed")?,
            encrypt_change_at(&change_secret, &notes[2], &ec, 2)
                .map_err(|_| "empty-output change encryption failed")?,
        ],
    };
    let decoded = recipient
        .decrypt_payment(&public.cm[0], &public.payment, &ec)
        .map_err(|_| "empty-output payment self-check failed")?;
    let receipt = opening
        .verify_payment(&recipient.address(), &public.cm[0], &public.payment, &ec)
        .map_err(|_| "empty-output receipt self-check failed")?;
    if !same_note(&decoded, &notes[0]) || !same_note(&receipt, &notes[0]) {
        return Err("empty-output payment note self-check failed".into());
    }
    for i in 0..2 {
        let decoded = decrypt_change_at(
            &change_secret,
            notes[i + 1].owner,
            &public.cm[i + 1],
            &public.change[i],
            &ec,
            (i + 1) as u8,
        )
        .map_err(|_| "empty-output change self-check failed")?;
        if !same_note(&decoded, &notes[i + 1]) {
            return Err("empty-output change note self-check failed".into());
        }
    }
    witness = public
        .bind_witness(&witness, &context(state))
        .map_err(|_| "empty-position statement binding failed")?;
    witness.check(&h, &roots.root()).map_err(str::to_owned)?;
    let record = PublicRecord::new(
        snapshot.selector,
        public.encode(),
        encode_digest(&fields.fee_commit),
    )?;
    Ok(PreparedTransaction {
        witness,
        public,
        record,
        opening: FeeOpening::dummy(blind),
    })
}

fn encode_payment(payment: &PaymentCiphertext) -> [u8; 1313] {
    let mut out = [0; 1313];
    out[..1088].copy_from_slice(&payment.kem_ciphertext);
    out[1088..1296].copy_from_slice(&payment.body);
    out[1296..1312].copy_from_slice(&payment.tag);
    out[1312] = payment.view_tag;
    out
}

fn decode_payment(bytes: &[u8; 1313]) -> PaymentCiphertext {
    PaymentCiphertext {
        kem_ciphertext: bytes[..1088].try_into().expect("fixed KEM ciphertext"),
        body: bytes[1088..1296].try_into().expect("fixed encrypted note"),
        tag: bytes[1296..1312]
            .try_into()
            .expect("fixed authentication tag"),
        view_tag: bytes[1312],
    }
}

fn prepare_rewards(
    state: &State,
    total_fees: u64,
    settings: &MiningSettings,
) -> Result<PreparedRewards, String> {
    let plan = state.reward_plan(settings.mode)?;
    let h = Hasher::new();
    let ec = EncryptionContext::new(state.config.network);
    let mut records = Vec::with_capacity(plan.allocations.len());
    let mut notes = Vec::with_capacity(plan.allocations.len());
    let mut secret = Zeroizing::new(Vec::with_capacity(
        48 + REWARD_ENTRY_BYTES * plan.allocations.len(),
    ));
    secret.extend_from_slice(REWARD_SECRET_MAGIC);
    secret.extend_from_slice(&REWARD_SECRET_VERSION.to_le_bytes());
    secret.extend_from_slice(&state.config.network);
    secret.extend_from_slice(&plan.block_height.to_le_bytes());
    secret.push(settings.mode.to_byte());
    secret.push(plan.allocations.len() as u8);
    for (index, allocation) in plan.allocations.iter().enumerate() {
        let note = Note {
            asset_id: SIP_ASSET_ID,
            owner: settings.recipient.owner(),
            value: allocation
                .amount
                .checked_add(if index == 0 { total_fees } else { 0 })
                .ok_or("miner reward amount overflows")?,
            unlock_height: allocation.unlock_height,
            rho: h.reward_rho(plan.block_height, index),
            rseed: random_fields()?,
        };
        let commitment = h.note_cm(&note);
        let (payment, opening) = encrypt_payment_with_opening(&settings.recipient, &note, &ec)
            .map_err(|_| "reward encryption failed")?;
        let checked = opening
            .verify_payment(&settings.recipient, &commitment, &payment, &ec)
            .map_err(|_| "reward payment self-check failed")?;
        if !same_note(&checked, &note) {
            return Err("reward note self-check failed".into());
        }
        secret.extend_from_slice(&encode_digest(&commitment));
        secret.extend_from_slice(&encode_digest(&note.owner));
        secret.extend_from_slice(&encode_digest(&note.rseed));
        secret.extend_from_slice(settings.recipient.encapsulation_key());
        secret.extend_from_slice(opening.expose_encapsulation_coins());
        records.push(RewardRecord {
            commitment: encode_digest(&commitment),
            ciphertext: encode_payment(&payment),
        });
        notes.push(note);
    }
    Ok(PreparedRewards {
        records,
        notes,
        secret,
    })
}

/// Authenticate each local encryption receipt against its ordered block reward.
/// Spending keys remain in the seed-backed wallet, never in these receipts.
pub fn validate_reward_secret(block: &Block, secret: &[u8]) -> Result<(), String> {
    let count = match block.reward_mode {
        RewardMode::Voyager => 1,
        RewardMode::Holder => 5,
    };
    if block.rewards.len() != count
        || secret.len() != 48 + count * REWARD_ENTRY_BYTES
        || &secret[..4] != REWARD_SECRET_MAGIC
        || secret[4..6] != REWARD_SECRET_VERSION.to_le_bytes()
        || secret[6..38] != block.network
        || secret[38..46] != block.height.to_le_bytes()
        || secret[46] != block.reward_mode.to_byte()
        || usize::from(secret[47]) != count
    {
        return Err("local reward recovery record binding mismatch".into());
    }
    let h = Hasher::new();
    for (index, record) in block.rewards.iter().enumerate() {
        let entry = &secret[48 + index * REWARD_ENTRY_BYTES..48 + (index + 1) * REWARD_ENTRY_BYTES];
        if entry[..48] != record.commitment {
            return Err("reward receipt commitment mismatch".into());
        }
        let digest = |offset| {
            decode_digest(entry[offset..offset + 48].try_into().expect("fixed digest"))
                .map_err(|_| "noncanonical reward receipt digest".to_owned())
        };
        let owner = digest(48)?;
        let rseed = digest(96)?;
        let address = PaymentAddress::new(
            owner,
            entry[144..1328].try_into().expect("fixed public key"),
        )
        .map_err(|_| "invalid reward recovery address")?;
        let opening = PaymentEncryptionOpening::from_encapsulation_coins(
            entry[1328..1360]
                .try_into()
                .expect("fixed encapsulation coins"),
        );
        let commitment =
            decode_digest(&record.commitment).map_err(|_| "invalid reward commitment")?;
        let note = opening
            .verify_payment(
                &address,
                &commitment,
                &decode_payment(&record.ciphertext),
                &EncryptionContext::new(block.network),
            )
            .map_err(|_| "reward recovery authentication failed")?;
        if note.owner != owner
            || note.rseed != rseed
            || note.asset_id != SIP_ASSET_ID
            || note.rho != h.reward_rho(block.height, index)
            || note.unlock_height < block.height
        {
            return Err("reward recovery note mismatch".into());
        }
    }
    Ok(())
}

/// Generate one complete native proof with fresh OS entropy and real output
/// encryption. The caller must independently verify it before queue admission.
pub fn prepare_padding(state: &State, prover: &NativeProver) -> Result<Padding, String> {
    let roots = state.recent_roots()?.tree(&Hasher::new());
    let prepared = prepare_empty(state, &roots)?;
    let proof = prover.transaction(&prepared.witness, &prepared.public, &context(state))?;
    Ok(Padding {
        transaction: Transaction {
            record: prepared.record,
            proof,
        },
        opening: prepared.opening,
    })
}

struct PreparedCandidate {
    block: Block,
    settlement: FixedSettlementWitness,
    reward_secret: Zeroizing<Vec<u8>>,
}

/// Validate all prepared positions and fee openings before preparing the
/// reward or invoking a prover. Transaction proofs were independently checked
/// at admission; the final block still requires the shared state transition.
fn prepare_candidate(
    state: &State,
    mut positions: Vec<Padding>,
    timestamp: u64,
    settings: &MiningSettings,
) -> Result<PreparedCandidate, String> {
    check_count(positions.len())?;
    if timestamp <= state.median_time_past() {
        return Err("candidate timestamp must exceed median time past".into());
    }
    let height = state
        .height
        .checked_add(1)
        .ok_or("engineering block height exhausted")?;
    let count = positions.len();
    let h = Hasher::new();
    positions
        .sort_unstable_by_key(|value| value.transaction.record.statement_id(&state.config.network));
    let mut spends = BTreeSet::new();
    let mut commitments = BTreeSet::new();
    let mut identities = BTreeSet::new();
    let mut slots = Vec::with_capacity(MAX_SLOTS);
    let mut transactions = Vec::with_capacity(count);
    let mut total_fees = 0u64;
    for value in positions {
        state.snapshot(value.transaction.record.snapshot)?;
        if value.transaction.proof.is_empty()
            || value.transaction.proof.len() > crate::wire::MAX_TX_PROOF
        {
            return Err("prepared transaction proof byte limit".into());
        }
        let public = PublicTransaction::decode(&value.transaction.record.body)
            .map_err(|_| "invalid prepared transaction public fields")?;
        for nf in public.nf {
            let nf = encode_digest(&nf);
            if state.spent.contains(&nf) || !spends.insert(nf) {
                return Err("prepared position nullifier collision".into());
            }
        }
        for cm in public.cm {
            let cm = encode_digest(&cm);
            if state.commitments.contains(&cm) || !commitments.insert(cm) {
                return Err("prepared position output collision".into());
            }
        }
        if !identities.insert(value.transaction.record.statement_id(&state.config.network)) {
            return Err("prepared position identity collision".into());
        }
        let commitment = h.fee_commit(value.opening.fee, &value.opening.blind);
        if encode_digest(&commitment) != value.transaction.record.fee_commit {
            return Err("prepared position opening mismatch".into());
        }
        // The transaction relation already checks its private anchored fee
        // schedule. Settlement consumes only the exact opening; reference-model
        // tier/classification flags must not reinterpret older valid proofs.
        total_fees = total_fees
            .checked_add(value.opening.fee)
            .ok_or("prepared position fee sum overflows")?;
        slots.push(SettlementSlot {
            commitment,
            opening: value.opening,
        });
        transactions.push(value.transaction);
    }
    slots.extend(tail_slots(state.config.network, height, count)?);
    let reward = prepare_rewards(state, total_fees, settings)?;
    let block = Block {
        network: state.config.network,
        height,
        parent: state.tip,
        timestamp,
        target: state.next_target(),
        nonce: 0,
        transactions,
        reward_mode: settings.mode,
        rewards: reward.records,
        fund_spends: Vec::new(),
        issuances: Vec::new(),
        settlement_proof: Vec::new(),
    };
    let witness = FixedSettlementWitness {
        plan: state.reward_plan(settings.mode)?,
        network: block.network,
        transaction_list_digest: block.list_digest(),
        rewards: reward
            .notes
            .iter()
            .map(|note| native::settlement::RewardNoteWitness {
                asset_id: note.asset_id,
                owner: note.owner,
                rseed: note.rseed,
                amount: note.value,
            })
            .collect(),
        slots,
    };
    witness
        .check(&h)
        .map_err(|_| "invalid prepared fee settlement")?;
    Ok(PreparedCandidate {
        block,
        settlement: witness,
        reward_secret: reward.secret,
    })
}

/// Assemble current-height settlement around previously verified positions.
/// Transaction proofs and snapshot identities are preserved. Every committed
/// fee enters the SIP miner reward with checked integer addition.
pub fn assemble(
    state: &State,
    prover: &NativeProver,
    positions: Vec<Padding>,
    timestamp: u64,
    settings: &MiningSettings,
) -> Result<ProducedBlock, String> {
    let mut prepared = prepare_candidate(state, positions, timestamp, settings)?;
    prepared.block.settlement_proof = prover.settlement(&prepared.settlement)?;
    prepared.block.validate_shape()?;
    validate_reward_secret(&prepared.block, &prepared.reward_secret)?;
    Ok(ProducedBlock {
        block: prepared.block,
        reward_secret: prepared.reward_secret,
    })
}

/// One-shot fixture/engineering operation. Continuous production instead reuses
/// a resident prover and queue and exports work progress while hashing.
pub fn produce(
    state: &State,
    prover: &NativeProver,
    count: usize,
    settings: &MiningSettings,
) -> Result<ProducedBlock, String> {
    check_count(count)?;
    let mut prepared = Vec::with_capacity(count);
    for _ in 0..count {
        prepared.push(prepare_padding(state, prover)?);
    }
    let timestamp = if state.config.fixture {
        state
            .timestamp()
            .checked_add(1)
            .ok_or("engineering timestamp exhausted")?
    } else {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "system clock precedes epoch")?
            .as_secs()
            .max(
                state
                    .median_time_past()
                    .checked_add(1)
                    .ok_or("engineering timestamp exhausted")?,
            )
    };
    let mut produced = assemble(state, prover, prepared, timestamp, settings)?;
    let seed = produced.block.pow_seed()?;
    while !siworld_core::pow::meets_target(
        &siworld_core::pow::pow_hash(&seed, produced.block.nonce, state.config.pow_iterations),
        &produced.block.target,
    ) {
        produced.block.nonce = produced
            .block
            .nonce
            .checked_add(1)
            .ok_or("engineering nonce space exhausted")?;
    }
    Ok(produced)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Config;

    #[test]
    fn entropy_sampling_rejects_out_of_field_words_without_reduction() {
        let mut calls = 0;
        let fields = fields_from_entropy::<2>(&mut |bytes| {
            calls += 1;
            bytes.fill(0xff);
            if calls == 2 {
                bytes[..4].copy_from_slice(&0u32.to_le_bytes());
                bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(fields, [F::ZERO, F::ONE]);
    }

    #[test]
    fn prepared_zero_transactions_have_valid_distinct_locally_bound_witnesses() {
        let state = State::new(Config::development([31; 32], 0).unwrap()).unwrap();
        let h = Hasher::new();
        let roots = state.recent_roots().unwrap().tree(&h);
        let first = prepare_empty(&state, &roots).unwrap();
        let second = prepare_empty(&state, &roots).unwrap();
        for tx in [&first, &second] {
            tx.witness.check(&h, &roots.root()).unwrap();
            assert_eq!(tx.record.snapshot, state.tip_snapshot().selector);
            assert_eq!(tx.public.encode(), tx.record.body);
            assert_eq!(tx.witness.slot.fee, 0);
            assert_eq!(tx.witness.slot.inputs.len(), 2);
            assert_eq!(tx.witness.slot.outputs.len(), 3);
            assert!(
                tx.witness
                    .slot
                    .inputs
                    .iter()
                    .all(|input| input.dummy && input.value == 0)
            );
            assert_eq!(
                tx.public
                    .statement(&context(&state), &tx.opening_commitment(), &roots.root(),),
                native::multi_asset_transaction::statement_for(
                    &tx.public.nf,
                    &tx.public.cm,
                    &tx.witness.d_ct,
                    &tx.opening_commitment(),
                    &roots.root(),
                    state.height,
                )
            );
        }
        assert_ne!(first.public.nf, second.public.nf);
        assert_ne!(first.public.cm, second.public.cm);
        assert_ne!(
            first.public.payment.kem_ciphertext,
            second.public.payment.kem_ciphertext
        );
        assert_ne!(
            first.record.statement_id(&state.config.network),
            second.record.statement_id(&state.config.network)
        );
    }

    fn settings(mode: RewardMode) -> MiningSettings {
        let keys =
            crate::wallet::WalletKeys::from_seed([32; 32], Zeroizing::new([42; 32]), 0).unwrap();
        MiningSettings {
            mode,
            recipient: keys.address(),
        }
    }

    #[test]
    fn every_reward_is_seed_recoverable_with_unique_indexed_nullifiers() {
        let state = State::new(Config::development([32; 32], 0).unwrap()).unwrap();
        let keys =
            crate::wallet::WalletKeys::from_seed(state.config.network, Zeroizing::new([42; 32]), 0)
                .unwrap();
        for mode in [RewardMode::Voyager, RewardMode::Holder] {
            let rewards = prepare_rewards(
                &state,
                9,
                &MiningSettings {
                    mode,
                    recipient: keys.address(),
                },
            )
            .unwrap();
            let block = Block {
                network: state.config.network,
                height: 1,
                parent: state.tip,
                timestamp: 2,
                target: state.next_target(),
                nonce: 0,
                transactions: Vec::new(),
                fund_spends: Vec::new(),
                issuances: Vec::new(),
                reward_mode: mode,
                rewards: rewards.records,
                settlement_proof: Vec::new(),
            };
            validate_reward_secret(&block, &rewards.secret).unwrap();
            assert_eq!(
                block.rewards.len(),
                if mode == RewardMode::Holder { 5 } else { 1 }
            );
            let mut unique = BTreeSet::new();
            for (index, note) in rewards.notes.iter().enumerate() {
                assert!(unique.insert(encode_digest(&Hasher::new().reward_rho(1, index))));
                assert_eq!(
                    note.unlock_height,
                    state.reward_plan(mode).unwrap().allocations[index].unlock_height
                );
                assert_eq!(note.owner, keys.address().owner());
            }
            for index in 0..block.rewards.len() {
                let mut changed = block.clone();
                changed.rewards[index].ciphertext[0] ^= 1;
                assert!(validate_reward_secret(&changed, &rewards.secret).is_err());
            }
            let mut changed = block.clone();
            changed.reward_mode = if mode == RewardMode::Holder {
                RewardMode::Voyager
            } else {
                RewardMode::Holder
            };
            assert!(validate_reward_secret(&changed, &rewards.secret).is_err());
        }
    }

    #[test]
    fn invalid_position_counts_are_rejected_before_preparation_or_proving() {
        for count in [0, 63, 65, 577, usize::MAX] {
            assert!(check_count(count).is_err());
        }
        for count in [64, 80, 576] {
            check_count(count).unwrap();
        }
    }

    fn fee_positions(state: &State, fees: &[u64]) -> Vec<Padding> {
        fees.iter()
            .enumerate()
            .map(|(index, fee)| {
                let seed = 10_000 + index as u32 * 100;
                let mut body = [0; crate::wire::PUBLIC_BYTES];
                for field in 0..5 {
                    let mut digest = [F::ZERO; 12];
                    digest[0] = F::from_u32(seed + field as u32);
                    body[field * 48..(field + 1) * 48].copy_from_slice(&encode_digest(&digest));
                }
                let blind = core::array::from_fn(|i| F::from_u32(seed + 10 + i as u32));
                Padding {
                    transaction: Transaction {
                        record: PublicRecord::new(
                            state.tip_snapshot().selector,
                            body,
                            encode_digest(&Hasher::new().fee_commit(*fee, &blind)),
                        )
                        .unwrap(),
                        proof: vec![1],
                    },
                    opening: FeeOpening {
                        fee: *fee,
                        blind,
                        dummy: false,
                        priority: false,
                    },
                }
            })
            .collect()
    }

    #[test]
    fn candidate_settlement_credits_exact_private_fees_without_reinterpreting_flags() {
        let state = State::new(Config::development([41; 32], 0).unwrap()).unwrap();
        let fingerprint = state.fingerprint();
        let mut fees = vec![0; 64];
        fees[0] = 7;
        fees[1] = 19;
        fees[2] = 123_456_789;
        for (dummy, priority) in [(false, false), (false, true), (true, false), (true, true)] {
            let mut positions = fee_positions(&state, &fees);
            positions[2].opening.dummy = dummy;
            positions[2].opening.priority = priority;
            let prepared = prepare_candidate(
                &state,
                positions,
                state.timestamp() + 1,
                &settings(RewardMode::Voyager),
            )
            .unwrap();
            prepared.settlement.check(&Hasher::new()).unwrap();
            let plan = state.reward_plan(RewardMode::Voyager).unwrap();
            assert_eq!(prepared.settlement.plan, plan);
            assert_eq!(
                prepared.settlement.rewards[0].amount,
                plan.allocations[0].amount + fees.iter().sum::<u64>()
            );
            assert_eq!(prepared.settlement.rewards[0].asset_id, SIP_ASSET_ID);
            assert_eq!(prepared.settlement.slots.len(), MAX_SLOTS);
            let fees_by_id: std::collections::BTreeMap<_, _> = fee_positions(&state, &fees)
                .into_iter()
                .map(|position| {
                    (
                        position
                            .transaction
                            .record
                            .statement_id(&state.config.network),
                        position.opening.fee,
                    )
                })
                .collect();
            for (transaction, slot) in prepared
                .block
                .transactions
                .iter()
                .zip(&prepared.settlement.slots)
            {
                assert_eq!(
                    slot.opening.fee,
                    fees_by_id[&transaction.record.statement_id(&state.config.network)]
                );
                assert_eq!(
                    encode_digest(&slot.commitment),
                    transaction.record.fee_commit
                );
            }
            assert_eq!(
                prepared.settlement.transaction_list_digest,
                prepared.block.list_digest()
            );
            validate_reward_secret(&prepared.block, &prepared.reward_secret).unwrap();
            assert_eq!(state.fingerprint(), fingerprint);
        }
    }

    #[test]
    fn fee_sum_and_subsidy_overflow_fail_without_state_changes() {
        let state = State::new(Config::development([42; 32], 0).unwrap()).unwrap();
        let fingerprint = state.fingerprint();
        for first in [
            u64::MAX,
            u64::MAX - state.reward_plan(RewardMode::Voyager).unwrap().allocations[0].amount,
        ] {
            let mut fees = vec![0; 64];
            fees[0] = first;
            fees[1] = 1;
            assert!(
                prepare_candidate(
                    &state,
                    fee_positions(&state, &fees),
                    state.timestamp() + 1,
                    &settings(RewardMode::Voyager)
                )
                .is_err()
            );
            assert_eq!(state.fingerprint(), fingerprint);
        }
        assert!(prepare_rewards(&state, u64::MAX, &settings(RewardMode::Voyager)).is_err());
        assert_eq!(state.fingerprint(), fingerprint);
    }

    #[test]
    fn mismatched_private_openings_and_malformed_prepared_proofs_fail_before_proving() {
        let state = State::new(Config::development([43; 32], 0).unwrap()).unwrap();
        let fingerprint = state.fingerprint();
        for mutation in 0..4 {
            let mut positions = fee_positions(&state, &[0; 64]);
            match mutation {
                0 => positions[0].opening.fee = 1,
                1 => positions[0].opening.blind[7] += F::ONE,
                2 => positions[0].transaction.proof.clear(),
                _ => positions[0]
                    .transaction
                    .proof
                    .resize(crate::wire::MAX_TX_PROOF + 1, 1),
            }
            assert!(
                prepare_candidate(
                    &state,
                    positions,
                    state.timestamp() + 1,
                    &settings(RewardMode::Voyager)
                )
                .is_err()
            );
            assert_eq!(state.fingerprint(), fingerprint);
        }
    }

    #[test]
    #[ignore = "explicit actual native block persistence and recovery check"]
    fn actual_block_persists_replays_and_recovers_the_reward() {
        use crate::{local, proofs::NativeVerifier, store::Store};
        struct FreshDirectory(std::path::PathBuf);
        impl Drop for FreshDirectory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let mut entropy = [0; 16];
        getrandom::fill(&mut entropy).unwrap();
        let path = std::env::temp_dir()
            .join(format!("siworld-native-proof-e2e-{}", local::hex(&entropy),));
        let config = local::initialize(&path, 0).unwrap();
        let directory = FreshDirectory(path);
        let verifier = NativeVerifier::new().unwrap();
        let mut store =
            Store::open(directory.0.join("chain.redb"), config.clone(), &verifier).unwrap();
        let prover = NativeProver::new().unwrap();
        let produced = produce(store.state(), &prover, 64, &settings(RewardMode::Voyager)).unwrap();
        let id = produced.block.id().unwrap();
        validate_reward_secret(&produced.block, &produced.reward_secret).unwrap();
        local::save_reward(&directory.0, &id, &produced.reward_secret).unwrap();
        store.append(&produced.block, &verifier).unwrap();
        let fingerprint = store.state().fingerprint();
        assert_eq!(store.state().height, 1);
        assert_eq!(store.state().tree.count, 64 * 3 + 1);
        drop(produced);
        drop(prover);
        drop(store);
        let loaded = local::load(&directory.0).unwrap();
        assert_eq!(loaded, config);
        let restarted =
            Store::open_existing(directory.0.join("chain.redb"), loaded, &verifier).unwrap();
        assert_eq!(restarted.state().fingerprint(), fingerprint);
        let accepted = restarted.block(1).unwrap();
        assert_eq!(accepted.id().unwrap(), id);
        let recovered = local::read_reward(&directory.0, &id).unwrap();
        validate_reward_secret(&accepted, &recovered).unwrap();
        let mut changed = accepted;
        changed.rewards[0].ciphertext[0] ^= 1;
        assert!(validate_reward_secret(&changed, &recovered).is_err());
        drop(restarted);
    }
}
