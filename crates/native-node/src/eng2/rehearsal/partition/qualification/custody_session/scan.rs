use super::*;
use crate::{
    eng2::{
        store::Observation,
        wallet_history::codec::{Context as ReceiptContext, HEADER_BYTES, ReceiptBlock},
    },
    eng2_light::Eng2LightState,
    p2p::Budget,
};
use native::codec::{PublicTransaction, encode_digest};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expectations {
    version: u32,
    height: u64,
    tip: String,
    evaluation_height: u64,
    roles: Value,
    assets: Value,
    asset_registry_sha256: String,
    forbidden_commitments: Vec<String>,
    forbidden_nullifiers: Vec<String>,
}
fn identifiers(values: &[String]) -> Result<BTreeSet<String>> {
    if values.len() > 10000 {
        return Err("custody_orphan_bound_rejected".into());
    }
    let mut set = BTreeSet::new();
    for value in values {
        let b = crate::eng2_operations::public_bytes(&json!(value), 48)?;
        if b.len() != 48 || !set.insert(value.clone()) {
            return Err("custody_orphan_identity_rejected".into());
        }
    }
    Ok(set)
}
fn origin(receipt: &ReceiptBlock, commitment: &[u8; 48]) -> Result<Value> {
    let mut found = Vec::new();
    for (i, record) in receipt.transactions().iter().enumerate() {
        let public = PublicTransaction::decode(&record.body)
            .map_err(|_| "custody_receipt_transaction_rejected")?;
        for (j, cm) in public.cm.iter().enumerate() {
            if encode_digest(cm) == *commitment {
                found.push(json!({"kind":"transaction","record":i,"output":j,"statement":crate::local::hex(&record.statement_id(&receipt.header().network))}));
            }
        }
    }
    for (i, record) in receipt.issuances().iter().enumerate() {
        for (j, cm) in record
            .signed
            .declaration
            .note_commitments
            .iter()
            .enumerate()
        {
            if encode_digest(cm) == *commitment {
                found.push(json!({"kind":"issuance","record":i,"output":j,"declaration":crate::local::hex(&record.signed.declaration.binding())}));
            }
        }
    }
    for (i, record) in receipt.rewards().iter().enumerate() {
        if record.commitment == *commitment {
            found.push(json!({"kind":"reward","record":i,"output":0}));
        }
    }
    for (i, record) in receipt.fund_outputs().iter().enumerate() {
        if record.commitment == *commitment {
            found.push(json!({"kind":"fund","record":i,"output":0}));
        }
    }
    if found.len() != 1 {
        return Err("custody_owned_origin_ambiguous_or_missing".into());
    }
    Ok(found.remove(0))
}
#[derive(Default)]
struct Total {
    received: u128,
    spent: u128,
    unspent: u128,
    available: u128,
    notes: u64,
    spent_notes: u64,
}
fn roles(
    wallets: &[&crate::wallet::Wallet],
    origins: &BTreeMap<String, Value>,
    height: u64,
    forbidden: &BTreeSet<String>,
    forbidden_nf: &BTreeSet<String>,
) -> Result<Value> {
    if wallets.len() != 5 {
        return Err("custody_scan_actor_count_rejected".into());
    }
    let mut result = Vec::new();
    for (i, light) in wallets.iter().enumerate() {
        let mut notes = Vec::new();
        let mut sums: BTreeMap<String, Total> = BTreeMap::new();
        let mut unique = BTreeSet::new();
        for row in light.receipts() {
            let cm = crate::local::hex(&row.commitment);
            if forbidden.contains(&cm)
                || forbidden_nf.contains(&crate::local::hex(&row.nullifier))
                || !unique.insert(cm.clone())
            {
                return Err("custody_orphan_or_duplicate_owned_note".into());
            }
            let asset = crate::local::hex(&row.note().asset_id.0);
            let amount = u128::from(row.note().value);
            let t = sums.entry(asset.clone()).or_default();
            t.received = t
                .received
                .checked_add(amount)
                .ok_or("custody_balance_overflow")?;
            t.notes = t.notes.checked_add(1).ok_or("custody_balance_overflow")?;
            if row.spent {
                t.spent = t
                    .spent
                    .checked_add(amount)
                    .ok_or("custody_balance_overflow")?;
                t.spent_notes = t
                    .spent_notes
                    .checked_add(1)
                    .ok_or("custody_balance_overflow")?;
            } else {
                t.unspent = t
                    .unspent
                    .checked_add(amount)
                    .ok_or("custody_balance_overflow")?;
                if row.note().unlock_height <= height {
                    t.available = t
                        .available
                        .checked_add(amount)
                        .ok_or("custody_balance_overflow")?;
                }
            }
            notes.push(json!({"commitment":cm,"nullifier":crate::local::hex(&row.nullifier),"height":row.height,"block_id":crate::local::hex(&row.block_id),"output_index":row.output_index,"origin":origins.get(&cm).ok_or("custody_owned_origin_missing")?,"asset":asset,"value_atoms":row.note().value.to_string(),"unlock_height":row.note().unlock_height,"spent":row.spent,"mature_at_evaluation_height":row.note().unlock_height<=height}));
        }
        notes.sort_by_key(|n| n["commitment"].as_str().unwrap_or_default().to_owned());
        let balances:Vec<_>=sums.into_iter().map(|(asset,t)|Ok(json!({"asset":asset,"received_atoms":t.received.to_string(),"spent_atoms":t.spent.to_string(),"unspent_atoms":t.unspent.to_string(),"available_atoms":t.available.to_string(),"locked_atoms":t.unspent.checked_sub(t.available).ok_or("custody_balance_underflow")?.to_string(),"received_notes":t.notes,"spent_notes":t.spent_notes,"unspent_notes":t.notes.checked_sub(t.spent_notes).ok_or("custody_balance_underflow")?}))).collect::<Result<Vec<_>>>()?;
        result.push(json!({"role":NAMES[i],"address_hex":crate::local::hex(&canonical_address(&light.address())),"notes":notes,"balances":balances}));
    }
    Ok(json!(result))
}
fn compare(actual: &Value, expected: &Value) -> Result<()> {
    if actual != expected {
        return Err("custody_independent_wallet_expectation_mismatch".into());
    }
    Ok(())
}
fn check_head(observation: &Observation, head: &Head) -> Result<()> {
    if observation.engine().state().height() != head.height
        || crate::local::hex(&observation.engine().state().tip()) != head.tip
        || observation.full_frame_count()? != head.height
    {
        return Err("custody_independent_source_head_differs".into());
    }
    Ok(())
}
pub(super) fn run(
    plan: &Plan,
    prerequisites: &Prerequisites,
    custody: &CustodySet,
    passwords: &passwords::Passwords,
    guard: &Guard<'_>,
    out: &mut Output,
) -> Result<Value> {
    if plan.business.is_some() {
        return Err("custody_scan_plan_rejected".into());
    }
    let node = plan
        .node_directory
        .as_ref()
        .ok_or("custody_node_required")?;
    let head = plan.head.as_ref().ok_or("custody_head_required")?;
    if !(1..=16384).contains(&head.height) {
        return Err("custody_complete_history_height_rejected".into());
    }
    let input = plan
        .expectations
        .as_ref()
        .ok_or("custody_scan_expectations_required")?;
    let encoded = load(input, 16 * 1024 * 1024)?;
    let expected: Expectations =
        serde_json::from_slice(&encoded).map_err(|_| "custody_scan_expectations_rejected")?;
    if expected.version != 1
        || expected.height != head.height
        || expected.tip != head.tip
        || expected.evaluation_height != head.height
    {
        return Err("custody_scan_expectation_head_differs".into());
    }
    let forbidden = identifiers(&expected.forbidden_commitments)?;
    let forbidden_nf = identifiers(&expected.forbidden_nullifiers)?;
    let genesis = genesis(plan, prerequisites, custody)?;
    let bytes = genesis.encode()?;
    let qualification = plan
        .qualification
        .as_ref()
        .ok_or("custody_qualification_required")?;
    let context = Context::load(&qualification.path, &qualification.sha256)?;
    context.check_genesis(&genesis)?;
    let _lease = crate::service::Lease::acquire(node)?;
    super::super::full_history::check_database(node)?;
    guard.check()?;
    let observation = Observation::open_full_history(
        &node.join("chain.redb"),
        Genesis::decode(&bytes)?,
        crate::eng2::resident::limits().chain,
        head.height,
    )?;
    check_head(&observation, head)?;
    let receipt_context = ReceiptContext::from_genesis(&bytes, genesis.id())?;
    let binding_bytes = load(&plan.initialization, 4096)?;
    let binding = RehearsalBinding::decode(&binding_bytes, hash(&plan.initialization.sha256)?)?;
    let mut vaults = Vec::with_capacity(5);
    let mut wallets = Vec::with_capacity(5);
    for (i, spec) in plan.actors.iter().enumerate() {
        guard.check()?;
        let vault = WalletVault::open_isolated_rehearsal(
            &spec.directory,
            &passwords.0[i],
            &binding,
            ROLES[i],
        )?;
        wallets.push(Eng2LightState::from_existing_wallet(
            &bytes,
            genesis.id(),
            vault.wallet()?,
        )?);
        vaults.push(vault);
    }
    let memory = Budget::new(
        usize::try_from(plan.resources.maximum_decode_bytes)
            .map_err(|_| "custody_memory_width_rejected")?,
    );
    let _metadata = memory
        .reserve(64 * 1024 * 1024)
        .map_err(|_| "custody_scan_metadata_reservation_unavailable")?;
    let mut total = 0u64;
    let mut frames = Vec::new();
    let mut origins = BTreeMap::new();
    for height in 1..=head.height {
        guard.check()?;
        let size = observation.full_frame_size(height)?;
        total = total
            .checked_add(size as u64)
            .filter(|n| *n <= plan.resources.maximum_total_frame_bytes)
            .ok_or("custody_complete_history_budget_exhausted")?;
        if size as u64 > plan.resources.maximum_frame_bytes {
            return Err("custody_frame_bound_exhausted".into());
        }
        let charge = size
            .checked_mul(4)
            .and_then(|n| n.checked_add(4 * crate::eng2_history::MAX_RECEIPT_BYTES + 65536))
            .ok_or("custody_frame_allocation_overflow")?;
        let _frame = memory
            .reserve(charge)
            .map_err(|_| "custody_frame_reservation_unavailable")?;
        let frame = observation.full_frame(height)?;
        if frame.len() != size {
            return Err("custody_frozen_frame_size_differs".into());
        }
        let raw: &[u8; HEADER_BYTES] = frame
            .get(..HEADER_BYTES)
            .ok_or("custody_frame_header_missing")?
            .try_into()
            .map_err(|_| "custody_frame_header_width")?;
        let receipt = ReceiptBlock::export(&receipt_context, raw, &frame[HEADER_BYTES..])?;
        let decoded = ReceiptBlock::decode(&receipt_context, raw, &receipt)?;
        if decoded.header().height != height {
            return Err("custody_receipt_height_differs".into());
        }
        for cm in decoded.outputs()? {
            if forbidden.contains(&crate::local::hex(&cm)) {
                return Err("custody_orphan_commitment_in_accepted_prefix".into());
            }
        }
        for record in decoded.transactions() {
            for nf in PublicTransaction::decode(&record.body)
                .map_err(|_| "custody_transaction_public_rejected")?
                .nf
            {
                if forbidden_nf.contains(&crate::local::hex(&encode_digest(&nf))) {
                    return Err("custody_orphan_nullifier_in_accepted_prefix".into());
                }
            }
        }
        for wallet in &mut wallets {
            wallet.append(raw, &receipt)?;
            for note in wallet
                .wallet()
                .receipts()
                .iter()
                .filter(|n| n.height == height)
            {
                let cm = crate::local::hex(&note.commitment);
                if forbidden.contains(&cm)
                    || origins
                        .insert(cm, origin(&decoded, &note.commitment)?)
                        .is_some()
                {
                    return Err("custody_orphan_or_repeated_owned_commitment".into());
                }
            }
        }
        if origins.len() > 10000 {
            return Err("custody_owned_note_bound_exhausted".into());
        }
        frames.push(json!({"height":height,"frame_bytes":size,"frame_sha256":sha(&frame),"receipt_sha256":sha(&receipt)}));
    }
    guard.check()?;
    for wallet in &wallets {
        wallet.check_head(head.height, hash(&head.tip)?, None)?;
    }
    let views: Vec<_> = wallets.iter().map(Eng2LightState::wallet).collect();
    let observed_roles = roles(&views, &origins, head.height, &forbidden, &forbidden_nf)?;
    let registry = wallets[0].asset_registry();
    let assets:Vec<_>=registry.iter().map(|(id,a)|json!({"asset":crate::local::hex(id),"height":a.height,"public_supply":a.public_supply.to_string(),"declaration":crate::local::hex(&a.declaration)})).collect();
    let mut registry_hash = Sha256::new();
    registry.visit_encoding(&mut |b| registry_hash.update(b));
    let actual_registry_sha = crate::local::hex(&registry_hash.finalize());
    for wallet in &wallets[1..] {
        if wallet.asset_registry() != registry {
            return Err("custody_wallet_registry_divergence".into());
        }
    }
    out.json("observed-roles.json", &observed_roles)?;
    out.json("observed-assets.json", &assets)?;
    out.json("complete-prefix.json", &frames)?;
    compare(&observed_roles, &expected.roles)?;
    compare(&json!(assets), &expected.assets)?;
    if actual_registry_sha != expected.asset_registry_sha256 {
        return Err("custody_asset_registry_expectation_mismatch".into());
    }
    let fresh = Observation::open_full_history(
        &node.join("chain.redb"),
        Genesis::decode(&bytes)?,
        crate::eng2::resident::limits().chain,
        head.height,
    )?;
    check_head(&fresh, head)?;
    if load(input, 16 * 1024 * 1024)? != encoded {
        return Err("custody_scan_expectations_changed".into());
    }
    guard.check()?;
    Ok(
        json!({"operation":"scan","height":head.height,"tip":head.tip,"full_frame_count":head.height,"total_frame_bytes":total,"actual_vault_wallets":5,"independent_full_prefix_wallet_scan":true,"owned_note_and_balance_expectations_equal":true,"orphan_commitments_and_nullifiers_absent":true,"asset_registry_sha256":actual_registry_sha,"native_consensus_replay_performed_by_this_command":false,"g1_passed":false,"g2_passed":false}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn real_decrypted_notes_preserve_zero_values_maturity_spends_and_orphan_exclusion() {
        use crate::{
            state::{Config, State},
            wallet::Wallet,
            wire::{Block, REWARD_CIPHERTEXT_BYTES, RewardMode, RewardRecord},
        };
        use native::{
            encryption::{EncryptionContext, encrypt_payment},
            multi_asset::{F, Hasher, Note, SIP_ASSET_ID},
        };
        use p3_field::PrimeCharacteristicRing;
        use zeroize::Zeroizing;
        // Receipt-only carrier: no proof, nonce search or accepted Store is used.
        let config = Config::development([3; 32], 0).unwrap();
        let mut state = State::new(config.clone()).unwrap();
        let mut wallets: Vec<_> = (42..47)
            .map(|seed| Wallet::from_seed(config.network, Zeroizing::new([seed; 32]), 0).unwrap())
            .collect();
        let mut origins = BTreeMap::new();
        let mut rewards = Vec::new();
        for (i, (value, unlock)) in [(50, 2), (0, 0)].into_iter().enumerate() {
            let note = Note {
                owner: wallets[0].address().owner(),
                value,
                unlock_height: unlock,
                rho: [F::from_u32(90 + i as u32); 12],
                rseed: [F::from_u32(100 + i as u32); 12],
                asset_id: SIP_ASSET_ID,
            };
            let payment = encrypt_payment(
                &wallets[0].address(),
                &note,
                &EncryptionContext::new(config.network),
            )
            .unwrap();
            let mut ciphertext = [0; REWARD_CIPHERTEXT_BYTES];
            ciphertext[..1088].copy_from_slice(&payment.kem_ciphertext);
            ciphertext[1088..1296].copy_from_slice(&payment.body);
            ciphertext[1296..1312].copy_from_slice(&payment.tag);
            ciphertext[1312] = payment.view_tag;
            let commitment = encode_digest(&Hasher::new().note_cm(&note));
            origins.insert(
                crate::local::hex(&commitment),
                json!({"kind":"reward","record":i,"output":0}),
            );
            rewards.push(RewardRecord {
                commitment,
                ciphertext,
            });
        }
        let block = Block {
            network: config.network,
            height: 1,
            parent: state.tip,
            timestamp: 301,
            target: config.genesis_target,
            nonce: 0,
            transactions: vec![],
            reward_mode: RewardMode::Holder,
            rewards,
            fund_spends: vec![],
            issuances: vec![],
            settlement_proof: vec![],
        };
        for wallet in &mut wallets {
            wallet
                .scan_light_data(&state, std::slice::from_ref(&block), &[[7; 32]], false)
                .unwrap();
        }
        let empty = BTreeSet::new();
        let views: Vec<_> = wallets.iter().collect();
        let locked = roles(&views, &origins, 1, &empty, &empty).unwrap();
        assert_eq!(locked[0]["notes"].as_array().unwrap().len(), 2);
        assert_eq!(locked[0]["balances"][0]["received_atoms"], "50");
        assert_eq!(locked[0]["balances"][0]["received_notes"], 2);
        assert_eq!(locked[0]["balances"][0]["available_atoms"], "0");
        assert_eq!(locked[0]["balances"][0]["locked_atoms"], "50");
        assert!(locked[1]["notes"].as_array().unwrap().is_empty());
        let mature = roles(&views, &origins, 2, &empty, &empty).unwrap();
        assert_eq!(mature[0]["balances"][0]["available_atoms"], "50");
        let cm = crate::local::hex(&wallets[0].receipts()[0].commitment);
        let nf = crate::local::hex(&wallets[0].receipts()[0].nullifier);
        assert!(roles(&views, &origins, 2, &BTreeSet::from([cm]), &empty).is_err());
        assert!(roles(&views, &origins, 2, &empty, &BTreeSet::from([nf])).is_err());
        assert!(roles(&views, &BTreeMap::new(), 2, &empty, &empty).is_err());
        state.spent.insert(wallets[0].receipts()[0].nullifier);
        wallets[0]
            .scan_light_data(&state, std::slice::from_ref(&block), &[[7; 32]], false)
            .unwrap();
        let views: Vec<_> = wallets.iter().collect();
        let spent = roles(&views, &origins, 2, &empty, &empty).unwrap();
        assert_eq!(spent[0]["balances"][0]["spent_atoms"], "50");
        assert_eq!(spent[0]["balances"][0]["unspent_atoms"], "0");
        assert_eq!(spent[0]["balances"][0]["spent_notes"], 1);
        assert_ne!(spent, mature);
    }
    #[test]
    fn orphan_identity_sets_reject_aliases_duplicates_and_wrong_width() {
        let good = "01".repeat(48);
        assert!(identifiers(std::slice::from_ref(&good)).is_ok());
        assert!(identifiers(&[good.clone(), good]).is_err());
        assert!(identifiers(&["01".repeat(47)]).is_err());
        assert!(identifiers(&["AA".repeat(48)]).is_err());
    }
}
