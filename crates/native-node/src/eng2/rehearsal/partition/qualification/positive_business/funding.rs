//! Five ordinary payments from existing mature rewards, in one real native block.
//! Predictions precede proof and append; no wallet scan creates expectations.
use super::*;
use crate::eng2::genesis::Genesis;

const PAYMENTS: usize = 5;
const PURPOSES: [&str; PAYMENTS] = [
    "standard",
    "priority",
    "consolidation-0",
    "consolidation-1",
    "issuance",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FundingInput {
    purpose: String,
    commitment: String,
    nullifier: String,
    reward_height: u64,
    input_atoms: u64,
    amount_atoms: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FundingPlan {
    version: u32,
    campaign_id: String,
    genesis_id: String,
    isolated_directory: String,
    start_height: u64,
    start_tip: String,
    deadline_seconds: u64,
    max_nonce_attempts: u64,
    max_output_bytes: u64,
    history_budget: PublicInput,
    consolidation_max_note_value: u64,
    expected_before: Vec<WalletExpectation>,
    expected_after: Vec<WalletExpectation>,
    payments: Vec<FundingInput>,
}
fn validate(plan: &FundingPlan, campaign: &str, genesis: &str, node: &Path) -> Result<(), String> {
    let mut commitments = BTreeSet::new();
    let mut nullifiers = BTreeSet::new();
    let mut reward_heights = BTreeSet::new();
    let fee = crate::state::base_fee(plan.start_height);
    if plan.version != 1
        || !hex(campaign, 32)
        || plan.campaign_id != campaign
        || plan.genesis_id != genesis
        || !hex(genesis, 32)
        || plan.isolated_directory != node.to_str().ok_or("funding path encoding rejected")?
        || !(1..=super::super::full_history::MAX_HISTORY_HEIGHT - MAX_STEPS as u64)
            .contains(&plan.start_height)
        || !hex(&plan.start_tip, 32)
        || !(1..=3600).contains(&plan.deadline_seconds)
        || !(1..=1_000_000).contains(&plan.max_nonce_attempts)
        || !(1_048_576..=17_179_869_184).contains(&plan.max_output_bytes)
        || plan.consolidation_max_note_value == 0
        || !expected_shape(&plan.expected_before)
        || !expected_shape(&plan.expected_after)
        || plan
            .expected_before
            .iter()
            .zip(&plan.expected_after)
            .any(|(a, b)| a.address != b.address)
        || plan.payments.len() != PAYMENTS
        || plan.payments.iter().zip(PURPOSES).any(|(p, purpose)| {
            p.purpose != purpose
                || !hex(&p.commitment, 48)
                || !hex(&p.nullifier, 48)
                || !commitments.insert(&p.commitment)
                || !nullifiers.insert(&p.nullifier)
                || !reward_heights.insert(p.reward_height)
                || !mature_reward(p.reward_height, plan.start_height)
                || p.amount_atoms == 0
                || p.amount_atoms
                    .checked_add(fee)
                    .is_none_or(|n| n > p.input_atoms)
                || purpose.starts_with("consolidation-")
                    && p.amount_atoms > plan.consolidation_max_note_value
        })
        || plan
            .payments
            .get(2)
            .zip(plan.payments.get(3))
            .is_none_or(|(a, b)| {
                a.amount_atoms
                    .checked_add(b.amount_atoms)
                    .is_none_or(|n| n <= crate::state::base_fee(plan.start_height + 3))
            })
    {
        return Err("funding plan context, maturity or bounded inputs rejected".into());
    }
    Ok(())
}

fn funding_gate(
    started: Instant,
    plan: &FundingPlan,
    custody: &mut impl Custody,
    name: &str,
) -> Result<(), String> {
    if started.elapsed().as_secs() >= plan.deadline_seconds {
        return Err("funding deadline exhausted".into());
    }
    custody.before_phase(name)
}
fn mature_reward(height: u64, head: u64) -> bool {
    height > 0
        && height
            .checked_add(siworld_core::v1_economics::COINBASE_MATURITY)
            .is_some_and(|unlock| unlock <= head)
}
fn exact_components(store: &Store, reference: &Engine) -> Result<(), String> {
    let (header, _) = store.block(store.engine().state().height())?;
    let binding = Binding {
        genesis: store.engine().genesis().id(),
        rules_commitment: store.engine().genesis().rules_commitment(),
        parent: header.parent,
    };
    if store
        .engine()
        .state()
        .canonical_components(binding, store.engine().limits())?
        != reference
            .state()
            .canonical_components(binding, reference.limits())?
    {
        return Err("funding actual state differs from complete native replay".into());
    }
    Ok(())
}
fn reward_input(
    plan: &FundingInput,
    wallet: &Wallet,
    store: &Store,
) -> Result<DigestBytes, String> {
    let receipt = wallet
        .receipts()
        .iter()
        .find(|n| crate::local::hex(&n.commitment) == plan.commitment)
        .ok_or("funding original reward note missing")?;
    let state = store.engine().state().chain();
    let (header, body) = store.block(plan.reward_height)?;
    if receipt.spent
        || receipt.note().asset_id != SIP_ASSET_ID
        || receipt.note().value != plan.input_atoms
        || receipt.note().value == 0
        || receipt.height != plan.reward_height
        || receipt.output_index != 3
        || receipt.block_id != header.id().map_err(|_| "funding reward header rejected")?
        || !mature_reward(receipt.height, state.height)
        || receipt.note().unlock_height
            != receipt.height + siworld_core::v1_economics::COINBASE_MATURITY
        || body
            .rewards
            .first()
            .is_none_or(|r| r.commitment != receipt.commitment)
        || crate::local::hex(&receipt.nullifier) != plan.nullifier
        || state.spent.contains(&receipt.nullifier)
    {
        return Err("funding input is not the pinned unspent mature canonical reward".into());
    }
    Ok(receipt.commitment)
}
fn prediction(
    prepared: &PreparedTransfer,
    input: &FundingInput,
    payer: &Wallet,
    state: &State,
) -> Result<Value, String> {
    let witness = &prepared.witness().slot;
    if prepared.record().snapshot.height != state.height
        || witness.fee != crate::state::base_fee(state.height)
        || witness.fee_is_priority
        || witness.inputs[0].dummy
        || witness.inputs[0].value != input.input_atoms
        || !witness.inputs[1].dummy
        || witness.inputs[1].value != 0
        || crate::local::hex(&encode_digest(&prepared.public().nf[0])) != input.nullifier
        || witness.outputs[0].owner != payer.address().owner()
        || witness.outputs[0].asset_id != SIP_ASSET_ID
        || witness.outputs[0].value != input.amount_atoms
        || witness.outputs[0].unlock_height != 0
    {
        return Err("funding original payment differs from pinned intent".into());
    }
    let nullifier =
        payer.planned_payment_nullifier(prepared.public(), prepared.payment_opening())?;
    Ok(
        json!({"purpose":input.purpose,"reward_commitment":input.commitment,
        "reward_nullifier":input.nullifier,"reward_height":input.reward_height,
        "input_atoms":input.input_atoms,"statement":crate::local::hex(&prepared.record().statement_id(&state.config.network)),
        "payer_commitment":crate::local::hex(&encode_digest(&prepared.public().cm[0])),
        "payer_nullifier":crate::local::hex(&nullifier),"amount_atoms":input.amount_atoms,
        "fee_atoms":witness.fee,"unlock_height":0,
        "change_commitments":prepared.public().cm[1..].iter().map(|cm|crate::local::hex(&encode_digest(cm))).collect::<Vec<_>>(),
        "change_atoms":witness.outputs[1..].iter().map(|n|n.value).collect::<Vec<_>>()}),
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn generate(
    store: &mut Store,
    node: &Path,
    destination: &Path,
    plan_path: &Path,
    pin: &str,
    qualification: (&Path, &str),
    campaign: &str,
    actors: &mut Actors<'_>,
    custody: &mut impl Custody,
) -> Result<Value, String> {
    if std::env::var_os("CI").is_some() || std::env::var_os("GITHUB_ACTIONS").is_some() {
        return Err("funding requires owner-local execution".into());
    }
    let context = Context::load(qualification.0, qualification.1)?;
    let encoded = read(plan_path, MAX_PLAN)?;
    context.check_manifest_pin(&encoded, pin)?;
    let plan: FundingPlan =
        serde_json::from_slice(&encoded).map_err(|_| "funding plan schema rejected")?;
    validate(
        &plan,
        campaign,
        &crate::local::hex(&store.engine().genesis().id()),
        node,
    )?;
    context.check_genesis(store.engine().genesis())?;
    if store.engine().genesis().fee_mode() != FeeMode::LegacyMiner
        || store.engine().state().height() != plan.start_height
        || crate::local::hex(&store.engine().state().tip()) != plan.start_tip
        || destination.starts_with(node)
        || node.starts_with(destination)
    {
        return Err("funding actual parent or output context differs".into());
    }
    actors.require_fresh(&plan.expected_before)?;
    store.ensure_exportable()?;
    let started = Instant::now();
    let prefix = prefix::FrozenPrefix::prepare_existing(
        &context,
        store,
        prefix::PrefixRequest {
            history_budget: &plan.history_budget,
            height: plan.start_height,
            tip: &plan.start_tip,
            deadline_seconds: plan.deadline_seconds,
            max_output_bytes: plan.max_output_bytes,
            directory: node,
        },
        destination,
        started,
        &mut |name| funding_gate(started, &plan, custody, name),
    )?;
    let mut output = Output::create(destination, private_directory(node)?, plan.max_output_bytes)?;
    output.write("plan.json", &encoded)?;
    output.write("history-budget.json", prefix.budget_bytes())?;
    funding_gate(
        started,
        &plan,
        custody,
        "before_funding_complete_history_verifier",
    )?;
    let verifier = NativeVerifier::for_genesis(store.engine().genesis())?;
    let mut reference = Engine::new(
        Genesis::decode(&store.engine().genesis().encode()?)?,
        store.engine().limits(),
    )?;
    for height in 1..=plan.start_height {
        funding_gate(started, &plan, custody, "before_funding_original_frame")?;
        let _charge = prefix.before_frame(store, height)?;
        let (header, body) = store.block(height)?;
        let bytes = frame(store, height)?;
        prefix.check_frame(&header, bytes.len())?;
        reference.apply(&header, &body, &verifier)?;
        actors.scan(reference.state().chain(), &header, &body, height != 1)?;
        output.write(&format!("block-{height:04}.frame"), &bytes)?;
    }
    exact_components(store, &reference)?;
    actors.require_head(store.engine().state().chain())?;
    if wallets(actors, plan.start_height)? != plan.expected_before {
        return Err("funding original balances differ from independent plan".into());
    }
    // Reject all bad or immature sources before reserving any original payment.
    let selected = plan
        .payments
        .iter()
        .map(|input| reward_input(input, actors.reward, store))
        .collect::<Result<Vec<_>, _>>()?;
    let recipient = actors.payer.address();
    let mut prepared = Vec::with_capacity(PAYMENTS);
    let mut predictions = Vec::with_capacity(PAYMENTS);
    for (index, (input, selected)) in plan.payments.iter().zip(selected).enumerate() {
        funding_gate(
            started,
            &plan,
            custody,
            "before_funding_prepare_and_reserve",
        )?;
        let state = store.engine().state().chain();
        let payment = actors.reward.prepare_transfer(
            state,
            [Some(selected), None],
            &recipient,
            SIP_ASSET_ID,
            input.amount_atoms,
            FeeTier::Standard,
            state.timestamp(),
        )?;
        predictions.push(prediction(&payment, input, actors.payer, state)?);
        custody.protect_prepared_payment(&format!("funding-{index}"), &recipient, &payment)?;
        prepared.push(payment);
    }
    for key in ["payer_commitment", "payer_nullifier", "statement"] {
        let mut identities = BTreeSet::new();
        for prediction in &predictions {
            let identity = prediction[key]
                .as_str()
                .ok_or("funding predicted payment identity missing")?;
            if !identities.insert(identity) {
                return Err("funding predicted payment identities are not distinct".into());
            }
        }
    }
    let predicted=serde_json::to_vec(&json!({"version":1,"campaign_id":campaign,"qualification":context.receipt(),
        "genesis_id":plan.genesis_id,"parent_height":plan.start_height,"parent_tip":plan.start_tip,
        "funding_height":plan.start_height+1,"plan_sha256":pin,"payer_address":crate::local::hex(&canonical_address(&recipient)),
        "reward_address":crate::local::hex(&canonical_address(&actors.reward.address())),
        "predictions":predictions,"formed_before_proof_and_append":true,
        "source":"independently-pinned-intent-and-original-prepared-payments","independent_wallet_scan_performed":false}))
        .map_err(|_|"funding prediction encoding failed")?;
    output.write("predictions.json", &predicted)?;
    funding_gate(
        started,
        &plan,
        custody,
        "before_funding_native_prover_setup",
    )?;
    let prover = NativeProver::for_genesis(store.engine().genesis())?;
    let mut payments = Vec::with_capacity(PAYMENTS);
    for payment in prepared {
        funding_gate(
            started,
            &plan,
            custody,
            "before_funding_native_payment_proof",
        )?;
        payments.push((payment.prove(&prover)?, FeeTier::Standard));
    }
    prefix.check_head(store)?;
    prefix.check_input_unchanged()?;
    if read(plan_path, MAX_PLAN)? != encoded
        || read(&destination.join("predictions.json"), MAX_PLAN)? != predicted
    {
        return Err("funding intent or pre-append predictions changed".into());
    }
    let network = store.engine().state().network();
    let timestamp = store
        .engine()
        .state()
        .chain()
        .timestamp()
        .checked_add(300)
        .ok_or("funding timestamp overflow")?;
    let statements = payments
        .iter()
        .map(|(payment, _)| {
            payment
                .transaction
                .record
                .statement_id(&store.engine().state().network())
        })
        .collect::<Vec<_>>();
    let custody = RefCell::new(custody);
    let produced = native_business::append_business_block(
        store,
        &prover,
        &verifier,
        native_business::BusinessInputs {
            payments,
            issuances: Vec::new(),
            operations: None,
        },
        timestamp,
        &crate::producer::MiningSettings {
            mode: crate::wire::RewardMode::Voyager,
            recipient: actors.reward.address(),
        },
        plan.max_nonce_attempts,
        |payment| {
            let id = payment.transaction.record.statement_id(&network);
            let index = statements
                .iter()
                .position(|expected| *expected == id)
                .ok_or("funding payment is not predicted")?;
            custody
                .borrow_mut()
                .protect_payment(&format!("funding-{index}"), &recipient, payment)
        },
        |_| Err("funding cannot contain issuance".into()),
        |block| custody.borrow_mut().protect_reward(block),
        |name| funding_gate(started, &plan, &mut **custody.borrow_mut(), name),
    )?;
    let height = plan.start_height + 1;
    let (header, body) = store.block(height)?;
    output.write(&format!("block-{height:04}.frame"), &produced.frame)?;
    if produced.transactions != statements || produced.frame != frame(store, height)? {
        return Err("funding appended bytes differ from predicted transactions".into());
    }
    reference.apply(&header, &body, &verifier)?;
    exact_components(store, &reference)?;
    actors.scan(reference.state().chain(), &header, &body, true)?;
    actors.require_head(store.engine().state().chain())?;
    for p in &predictions {
        if !actors.payer.receipts().iter().any(|r| {
            crate::local::hex(&r.commitment) == p["payer_commitment"]
                && crate::local::hex(&r.nullifier) == p["payer_nullifier"]
                && r.height == height
                && !r.spent
                && r.note().value == p["amount_atoms"].as_u64().unwrap_or(0)
                && r.note().asset_id == SIP_ASSET_ID
                && r.note().unlock_height == 0
        }) {
            return Err("funding canonical payer note differs from pre-append prediction".into());
        }
    }
    if wallets(actors, height)? != plan.expected_after {
        return Err(
            "funding final balances differ from independent plan; accepted prefix retained".into(),
        );
    }
    prefix.check_input_unchanged()?;
    funding_gate(
        started,
        &plan,
        &mut **custody.borrow_mut(),
        "before_funding_closeout",
    )?;
    let result = json!({"version":1,"scope":"existing-reward-to-payer-funding","campaign_id":campaign,
        "plan_sha256":pin,"predictions_sha256":crate::local::hex(&Sha256::digest(&predicted)),
        "new_blocks":1,"payer_notes":PAYMENTS,"final_height":height,
        "final_tip":crate::local::hex(&store.engine().state().tip()),
        "native_verified_and_explicitly_appended":true,"all11_actual_component_bytes_equal_independent_native_replay":true,
        "payment_openings_in_existing_encrypted_reward_journal":true,"new_reward_opening_memory_only":true,
        "independent_owned_balance_scan_performed":false,"g1_passed":false,"g2_passed":false});
    output.json("completed.json", &result)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> FundingPlan {
        let fee = crate::state::base_fee(29);
        let wallets = ROLES
            .iter()
            .enumerate()
            .map(|(i, role)| WalletExpectation {
                role: (*role).into(),
                address: format!("{:08x}{}", i + 1, "00".repeat(1228)),
                balances: Vec::new(),
            })
            .collect::<Vec<_>>();
        FundingPlan {
            version: 1,
            campaign_id: "01".repeat(32),
            genesis_id: "02".repeat(32),
            isolated_directory: "/isolated-node".into(),
            start_height: 29,
            start_tip: "03".repeat(32),
            deadline_seconds: 600,
            max_nonce_attempts: 1,
            max_output_bytes: 16 * 1024 * 1024,
            history_budget: PublicInput {
                path: "/history-budget.json".into(),
                sha256: "04".repeat(32),
            },
            consolidation_max_note_value: 10 * fee,
            expected_before: wallets.clone(),
            expected_after: wallets,
            payments: PURPOSES
                .iter()
                .enumerate()
                .map(|(i, purpose)| FundingInput {
                    purpose: (*purpose).into(),
                    commitment: format!("{:02x}", i + 1).repeat(48),
                    nullifier: format!("{:02x}", i + 10).repeat(48),
                    reward_height: i as u64 + 1,
                    input_atoms: 100 * fee,
                    amount_atoms: 10 * fee,
                })
                .collect(),
        }
    }
    fn checked(plan: &FundingPlan) -> Result<(), String> {
        validate(
            plan,
            &"01".repeat(32),
            &"02".repeat(32),
            Path::new("/isolated-node"),
        )
    }
    #[test]
    fn five_original_rewards_require_real_height_maturity_and_distinct_inputs() {
        assert!(checked(&plan()).is_ok());
        assert!(!mature_reward(1, 24));
        assert!(mature_reward(1, 25));
        assert!(!mature_reward(0, 25));
        assert!(!mature_reward(u64::MAX, u64::MAX));
        let mut p = plan();
        p.start_height = 28;
        assert!(checked(&p).is_err());
        let mut p = plan();
        p.payments.pop();
        assert!(checked(&p).is_err());
        let mut p = plan();
        p.payments[1].commitment = p.payments[0].commitment.clone();
        assert!(checked(&p).is_err());
        let mut p = plan();
        p.payments[1].nullifier = p.payments[0].nullifier.clone();
        assert!(checked(&p).is_err());
        let mut p = plan();
        p.payments[1].reward_height = p.payments[0].reward_height;
        assert!(checked(&p).is_err());
    }
    #[test]
    fn funding_rejects_unbound_roles_insufficient_value_and_unusable_small_notes() {
        let mut p = plan();
        p.campaign_id = "05".repeat(32);
        assert!(checked(&p).is_err());
        let mut p = plan();
        p.genesis_id = "05".repeat(32);
        assert!(checked(&p).is_err());
        let mut p = plan();
        p.payments.swap(0, 1);
        assert!(checked(&p).is_err());
        let mut p = plan();
        p.expected_after[0].address = p.expected_after[4].address.clone();
        assert!(checked(&p).is_err());
        let mut p = plan();
        p.payments[0].amount_atoms = u64::MAX;
        assert!(checked(&p).is_err());
        let mut p = plan();
        p.payments[2].amount_atoms = p.consolidation_max_note_value + 1;
        assert!(checked(&p).is_err());
        let mut p = plan();
        p.payments[2].amount_atoms = 1;
        p.payments[3].amount_atoms = 1;
        assert!(checked(&p).is_err());
    }
    #[test]
    fn funding_schema_does_not_accept_creation_or_unbounded_work_inputs() {
        let value = json!({"version":1,"seed":"unaccepted"});
        assert!(serde_json::from_value::<FundingPlan>(value).is_err());
        let mut p = plan();
        p.max_nonce_attempts = 0;
        assert!(checked(&p).is_err());
        let mut p = plan();
        p.max_nonce_attempts = 1_000_001;
        assert!(checked(&p).is_err());
        let mut p = plan();
        p.deadline_seconds = 3601;
        assert!(checked(&p).is_err());
    }
}
