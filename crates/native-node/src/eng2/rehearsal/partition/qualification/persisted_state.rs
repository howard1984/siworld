//! Authenticate one stopped owner's actual state against independent native replay.
//!
//! Public operation inclusion and exact ledger values are observable here. A
//! transaction statement does not disclose whether its slots contain payments;
//! wallet balances require a separate authenticated wallet scan.
use super::super::{MAX_HEIGHT, actual_state, bounded_bytes, replay};
use super::{Context, full_history};
use crate::{
    eng2::{execution::Engine, genesis::Genesis, state_components::Limits, store::Observation},
    eng2_governance::canonical_address,
    proofs::NativeVerifier,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeSet, path::Path, time::Instant};

const MAX_EXPECTATIONS: usize = 128 * 1024;
const MAX_MANIFEST: usize = 2 * 1024 * 1024;
const MAX_ASSERTIONS: usize = 128;
const DEADLINE_SECONDS: u64 = 900;

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Economics {
    issued: String,
    burned: String,
    miner_credited: String,
    fund_credited: String,
    holder_pool: String,
    locked_total: String,
    locked_schedule: Vec<Locked>,
}
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Locked {
    height: u64,
    atoms: String,
}
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Fund {
    member: u8,
    entitlement: String,
    direct_unlocked: String,
    vesting_unlocked: String,
    spent: String,
    spend_count: u64,
    destination: String,
}
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Asset {
    id: String,
    height: u64,
    public_supply: u64,
    declaration: String,
}
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PendingFee {
    amount_atoms: u64,
    proposal_sequence: u64,
    included_height: u64,
    effective_height: u64,
}
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PublicState {
    height: u64,
    tip: String,
    economics: Economics,
    fund_total_entitlement: String,
    funds: Vec<Fund>,
    governance_sequence: u64,
    issuance_fee_atoms: u64,
    pending_issuance_fee: Option<PendingFee>,
    fee_destination: String,
    assets: Vec<Asset>,
    leaf_count: usize,
    nullifier_count: usize,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum Kind {
    FundClaimSha256,
    GovernanceActionSha256,
    IssuanceDeclaration,
    TransactionStatement,
}
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
struct OperationKey {
    kind: Kind,
    identity: String,
}
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
struct Included {
    height: u64,
    operation: OperationKey,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expectations {
    version: u32,
    state: PublicState,
    included_operations: Vec<Included>,
    // Absence is checked throughout the entire accepted canonical prefix, not
    // just at the old inclusion height of an orphaned operation.
    absent_operations: Vec<OperationKey>,
    present_nullifiers: Vec<String>,
    absent_nullifiers: Vec<String>,
}

fn canonical_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn parse_expectations(bytes: &[u8]) -> Result<Expectations, String> {
    parse_expectations_inner(bytes, MAX_HEIGHT)
}
fn parse_expectations_inner(bytes: &[u8], maximum_height: u64) -> Result<Expectations, String> {
    let value: Expectations = serde_json::from_slice(bytes)
        .map_err(|_| "persisted state expectations schema rejected")?;
    if value.version != 1
        || !(1..=maximum_height).contains(&value.state.height)
        || !canonical_hex(&value.state.tip, 32)
        || value.included_operations.len() > MAX_ASSERTIONS
        || value.absent_operations.len() > MAX_ASSERTIONS
        || value.present_nullifiers.len() > MAX_ASSERTIONS
        || value.absent_nullifiers.len() > MAX_ASSERTIONS
    {
        return Err("persisted state expectations bounds rejected".into());
    }
    let mut included = BTreeSet::new();
    for item in &value.included_operations {
        if !(1..=value.state.height).contains(&item.height)
            || !canonical_hex(&item.operation.identity, 32)
            || !included.insert(item)
        {
            return Err("persisted inclusion assertions rejected".into());
        }
    }
    let mut absent = BTreeSet::new();
    for item in &value.absent_operations {
        if !canonical_hex(&item.identity, 32)
            || !absent.insert(item)
            || value
                .included_operations
                .iter()
                .any(|i| i.operation == *item)
        {
            return Err("persisted absence assertions rejected".into());
        }
    }
    let mut nullifiers = BTreeSet::new();
    for item in value
        .present_nullifiers
        .iter()
        .chain(&value.absent_nullifiers)
    {
        if !canonical_hex(item, 48) || !nullifiers.insert(item) {
            return Err("persisted nullifier assertions rejected".into());
        }
    }
    Ok(value)
}

fn nullifier_key(value: &str) -> [u8; 48] {
    // parse_expectations has already checked the exact lowercase hex width.
    let digit = |b: u8| {
        if b.is_ascii_digit() {
            b - b'0'
        } else {
            b - b'a' + 10
        }
    };
    let mut result = [0; 48];
    for (part, out) in value.as_bytes().as_chunks::<2>().0.iter().zip(&mut result) {
        *out = digit(part[0]) * 16 + digit(part[1]);
    }
    result
}

fn public_state(engine: &Engine) -> Result<PublicState, String> {
    let state = engine.state();
    let economic = state.economics();
    let governance = state.governance();
    let members = engine
        .genesis()
        .config()
        .fund_allocation
        .as_ref()
        .ok_or("persisted fund allocation missing")?
        .basis_points()
        .len();
    let mut funds = Vec::with_capacity(members);
    for index in 0..members {
        let member = u8::try_from(index).map_err(|_| "persisted member index overflow")?;
        let balance = state.fund().balance(member)?;
        funds.push(Fund {
            member,
            entitlement: balance.entitlement.to_string(),
            direct_unlocked: balance.direct_unlocked.to_string(),
            vesting_unlocked: balance.vesting_unlocked.to_string(),
            spent: balance.spent.to_string(),
            spend_count: balance.spend_count,
            destination: crate::local::hex(&canonical_address(
                governance.active_fund_destination(member)?,
            )),
        });
    }
    Ok(PublicState {
        height: state.height(),
        tip: crate::local::hex(&state.tip()),
        economics: Economics {
            issued: economic.issued().to_string(),
            burned: economic.burned().to_string(),
            miner_credited: economic.miner_credited().to_string(),
            fund_credited: economic.fund_credited().to_string(),
            holder_pool: economic.pool().to_string(),
            locked_total: economic.locked_total().to_string(),
            locked_schedule: economic
                .locked_schedule()
                .iter()
                .map(|(&height, atoms)| Locked {
                    height,
                    atoms: atoms.to_string(),
                })
                .collect(),
        },
        fund_total_entitlement: state.fund().total_entitlement().to_string(),
        funds,
        governance_sequence: governance.sequence(),
        issuance_fee_atoms: governance.issuance_fee_atoms(),
        pending_issuance_fee: governance.pending_issuance_fee().map(|fee| PendingFee {
            amount_atoms: fee.amount_atoms,
            proposal_sequence: fee.proposal_sequence,
            included_height: fee.included_height,
            effective_height: fee.effective_height,
        }),
        fee_destination: crate::local::hex(&canonical_address(governance.active_fee_destination())),
        assets: state
            .chain()
            .assets
            .iter()
            .map(|(id, asset)| Asset {
                id: crate::local::hex(id),
                height: asset.height,
                public_supply: asset.public_supply,
                declaration: crate::local::hex(&asset.declaration),
            })
            .collect(),
        leaf_count: state.chain().leaves.len(),
        nullifier_count: state.chain().spent.len(),
    })
}

fn check_operation(
    expectations: &Expectations,
    found: &mut [bool],
    height: u64,
    kind: Kind,
    identity: String,
) -> Result<(), String> {
    let key = OperationKey { kind, identity };
    if expectations.absent_operations.contains(&key) {
        return Err("excluded operation remains in actual canonical history".into());
    }
    for (item, seen) in expectations.included_operations.iter().zip(found) {
        if item.height == height && item.operation == key {
            *seen = true;
        }
    }
    Ok(())
}

/// One in-process assertion accumulator for an entire genesis-to-head audit.
/// Segment boundaries never reset inclusion flags or exclusion checks.
#[cfg(unix)]
pub(super) struct SessionAssertions {
    expected: Expectations,
    found: Vec<bool>,
}
#[cfg(unix)]
impl SessionAssertions {
    pub(super) fn load(bytes: &[u8], height: u64) -> Result<Self, String> {
        let expected = parse_expectations_inner(bytes, height)?;
        if expected.state.height != height {
            return Err("session expectations require the exact final height".into());
        }
        let found = vec![false; expected.included_operations.len()];
        Ok(Self { expected, found })
    }
    pub(super) fn observe(&mut self, body: &crate::eng2::body::Body) -> Result<(), String> {
        for claim in &body.fund_claims {
            self.record(
                body.height,
                Kind::FundClaimSha256,
                crate::local::hex(&Sha256::digest(claim.encode())),
            )?;
        }
        for action in &body.governance {
            self.record(
                body.height,
                Kind::GovernanceActionSha256,
                crate::local::hex(&Sha256::digest(action.encode()?)),
            )?;
        }
        for issuance in &body.issuances {
            self.record(
                body.height,
                Kind::IssuanceDeclaration,
                crate::local::hex(&issuance.signed.declaration.binding()),
            )?;
        }
        for transaction in &body.transactions {
            self.record(
                body.height,
                Kind::TransactionStatement,
                crate::local::hex(&transaction.record.statement_id(&body.network)),
            )?;
        }
        Ok(())
    }
    fn record(&mut self, height: u64, kind: Kind, identity: String) -> Result<(), String> {
        check_operation(&self.expected, &mut self.found, height, kind, identity)
    }
    pub(super) fn progress(&self) -> Value {
        json!({"included_operations_seen":self.found,
            "excluded_operations_checked_on_every_replayed_block":true})
    }
    fn require_inclusions(&self) -> Result<(), String> {
        if self.found.iter().any(|seen| !seen) {
            return Err("session canonical operation assertion was not reached".into());
        }
        Ok(())
    }
    pub(super) fn finish(&self, actual: &Engine, reference: &Engine) -> Result<Value, String> {
        self.require_inclusions()?;
        let observed = public_state(actual)?;
        if observed != self.expected.state || public_state(reference)? != observed {
            return Err("session exact public business state differs".into());
        }
        let spent = &actual.state().chain().spent;
        if self
            .expected
            .present_nullifiers
            .iter()
            .any(|key| !spent.contains(&nullifier_key(key)))
            || self
                .expected
                .absent_nullifiers
                .iter()
                .any(|key| spent.contains(&nullifier_key(key)))
        {
            return Err("session final nullifier assertions differ".into());
        }
        Ok(json!({"public_business_state":observed,
            "included_operations":self.expected.included_operations,
            "absent_operations_checked_through_entire_prefix":self.expected.absent_operations,
            "present_nullifiers":self.expected.present_nullifiers,
            "absent_nullifiers":self.expected.absent_nullifiers,
            "wallet_scan_performed":false,"wallet_balances_verified":false,
            "transaction_payment_classification_verified":false,
            "full_business_acceptance_passed":false}))
    }
}

/// Observe the existing database with its identity and accepted-state seal.
/// Both opens use a strictly read-only backend without rollback maintenance.
/// Independently verify unchanged public frames; never import, repair, append,
/// generate a proof, start a node, or read wallet spending/viewing material.
pub fn compare(
    directory: &Path,
    source: (&Path, &str),
    expectations: (&Path, &str),
    binding: (&Path, &str),
) -> Result<Value, String> {
    compare_inner(directory, source, expectations, binding, None)
}

/// Compare complete paged history under an independent finite, SHA-pinned
/// budget. Pages never replace the genesis prefix or accepted-state seal.
pub fn compare_history(
    directory: &Path,
    source: (&Path, &str),
    expectations: (&Path, &str),
    binding: (&Path, &str),
    budget: (&Path, &str),
) -> Result<Value, String> {
    compare_inner(directory, source, expectations, binding, Some(budget))
}
fn compare_inner(
    directory: &Path,
    source: (&Path, &str),
    expectations: (&Path, &str),
    binding: (&Path, &str),
    budget_input: Option<(&Path, &str)>,
) -> Result<Value, String> {
    let started = Instant::now();
    let context = Context::load(binding.0, binding.1)?;
    if directory.canonicalize().ok().as_deref() != Some(directory)
        || source.0.canonicalize().ok().as_deref() != Some(source.0)
        || directory.starts_with(source.0)
        || source.0.starts_with(directory)
    {
        return Err("separate canonical actual node and frame export required".into());
    }
    let expectations_bytes = bounded_bytes(expectations.0, MAX_EXPECTATIONS)?;
    context.check_manifest_pin(&expectations_bytes, expectations.1)?;
    let budget = budget_input
        .map(|input| full_history::Budget::load(&context, input))
        .transpose()?;
    let expected = if let Some((budget, _)) = &budget {
        parse_expectations_inner(&expectations_bytes, budget.height)?
    } else {
        parse_expectations(&expectations_bytes)?
    };
    if budget
        .as_ref()
        .is_some_and(|(budget, _)| budget.height != expected.state.height)
    {
        return Err("full history expectation height differs from exact budget".into());
    }
    let encoded = bounded_bytes(&source.0.join("genesis.bin"), 1024 * 1024)?;
    let selected = Genesis::decode(&encoded)?;
    context.check_genesis(&selected)?;
    if bounded_bytes(&directory.join("genesis.bin"), 1024 * 1024)? != encoded {
        return Err("actual node and pinned export genesis differ".into());
    }
    let manifest_maximum = if budget.is_some() {
        full_history::MAX_INDEX_BYTES
    } else {
        MAX_MANIFEST
    };
    let manifest_bytes = bounded_bytes(&source.0.join("manifest.json"), manifest_maximum)?;
    context.check_manifest_pin(&manifest_bytes, source.1)?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| "persisted state source manifest rejected")?;
    let complete = budget
        .as_ref()
        .map(|(budget, _)| {
            full_history::Source::open(
                &manifest,
                &selected,
                &context,
                *budget,
                budget_input.ok_or("full history budget absent")?.1,
            )
        })
        .transpose()?;
    let records = if complete.is_none() {
        Some(replay::manifest_records_inner(
            &manifest,
            &selected,
            expected.state.height,
            Some(&context),
        )?)
    } else {
        None
    };
    let walk = |visitor: &mut dyn FnMut(&Value) -> Result<(), String>| -> Result<(), String> {
        if let Some(complete) = &complete {
            complete.walk(source.0, started, visitor)
        } else {
            for record in records.ok_or("comparison records missing")? {
                if started.elapsed().as_secs() >= DEADLINE_SECONDS {
                    return Err("persisted state comparison deadline".into());
                }
                visitor(record)?;
            }
            Ok(())
        }
    };
    let _lease = crate::service::Lease::acquire(directory)?;
    let limits = Limits {
        max_leaves: 1_000_000,
        max_nullifiers: 1_000_000,
        max_component_bytes: 64 * 1024 * 1024,
    };
    if complete.is_some() {
        full_history::check_database(directory)?;
    }
    let database = directory.join("chain.redb");
    let open = || {
        if let Some((budget, _)) = &budget {
            Observation::open_full_history(
                &database,
                Genesis::decode(&encoded)?,
                limits,
                budget.height,
            )
        } else {
            Observation::open(&database, Genesis::decode(&encoded)?, limits)
        }
    };
    let store = open()?;
    if store.engine().state().height() != expected.state.height {
        return Err("authenticated actual height differs from independent expectations".into());
    }
    let verifier = NativeVerifier::for_genesis(&Genesis::decode(&encoded)?)?;
    let mut reference = Engine::new(Genesis::decode(&encoded)?, limits)?;
    let mut found = vec![false; expected.included_operations.len()];
    let mut final_header = None;
    let mut final_record = None;
    walk(&mut |record| {
        let (header, body) =
            replay::read_frame(source.0, record, &selected, reference.body_policy())?;
        reference.apply(&header, &body, &verifier)?;
        if complete.is_some() {
            actual_state::observe(&reference, &reference, &header, record)?;
        }
        if store
            .header(header.height)?
            .encode()
            .map_err(|_| "actual header encoding rejected")?
            != header
                .encode()
                .map_err(|_| "reference header encoding rejected")?
        {
            return Err("actual complete header prefix differs from pinned native replay".into());
        }
        for claim in &body.fund_claims {
            check_operation(
                &expected,
                &mut found,
                header.height,
                Kind::FundClaimSha256,
                crate::local::hex(&Sha256::digest(claim.encode())),
            )?;
        }
        for action in &body.governance {
            check_operation(
                &expected,
                &mut found,
                header.height,
                Kind::GovernanceActionSha256,
                crate::local::hex(&Sha256::digest(action.encode()?)),
            )?;
        }
        for issuance in &body.issuances {
            check_operation(
                &expected,
                &mut found,
                header.height,
                Kind::IssuanceDeclaration,
                crate::local::hex(&issuance.signed.declaration.binding()),
            )?;
        }
        for transaction in &body.transactions {
            check_operation(
                &expected,
                &mut found,
                header.height,
                Kind::TransactionStatement,
                crate::local::hex(&transaction.record.statement_id(&body.network)),
            )?;
        }
        final_header = Some(header);
        final_record = Some(record.clone());
        Ok(())
    })?;
    if found.iter().any(|seen| !seen) {
        return Err("expected canonical operation missing".into());
    }
    let header = final_header.ok_or("persisted comparison prefix empty")?;
    let record = final_record
        .as_ref()
        .ok_or("persisted comparison oracle missing")?;
    let observation = actual_state::observe(store.engine(), &reference, &header, record)?;
    let observed = public_state(store.engine())?;
    if observed != expected.state || public_state(&reference)? != observed {
        return Err(
            "actual public business ledgers differ from independent exact expectations".into(),
        );
    }
    let actual_nullifiers = &store.engine().state().chain().spent;
    if expected
        .present_nullifiers
        .iter()
        .any(|key| !actual_nullifiers.contains(&nullifier_key(key)))
        || expected
            .absent_nullifiers
            .iter()
            .any(|key| actual_nullifiers.contains(&nullifier_key(key)))
    {
        return Err("actual nullifier inclusion or orphan removal differs".into());
    }
    drop(store);
    let reopened = open()?;
    actual_state::observe(reopened.engine(), &reference, &header, record)?;
    if public_state(reopened.engine())? != observed {
        return Err("actual business state changed on second authenticated reopen".into());
    }
    if bounded_bytes(&source.0.join("genesis.bin"), 1024 * 1024)? != encoded
        || bounded_bytes(&source.0.join("manifest.json"), manifest_maximum)? != manifest_bytes
        || bounded_bytes(expectations.0, MAX_EXPECTATIONS)? != expectations_bytes
    {
        return Err("pinned comparison inputs changed during observation".into());
    }
    walk(&mut |record| {
        replay::read_frame(source.0, record, &selected, reopened.engine().body_policy())?;
        Ok(())
    })?;
    if let (Some(input), Some((budget, original))) = (budget_input, budget.as_ref()) {
        if bounded_bytes(input.0, 4096)? != *original {
            return Err("full history budget changed during comparison".into());
        }
        budget.tick(started)?;
    }
    let has = |kind| {
        expected
            .included_operations
            .iter()
            .any(|item| item.operation.kind == kind)
    };
    Ok(
        json!({"scope":"owner-nonfixture-authenticated-persisted-state-comparison",
        "qualification":context.receipt(),"source_manifest_sha256":source.1,
        "complete_paged_history":complete.is_some(),"entire_prefix_from_genesis":true,
        "all_replayed_component_oracles_checked":complete.is_some(),
        "expectations_sha256":expectations.1,"authenticated_read_only_opens":2,
        "rollback_maintenance_performed":false,"database_repair_performed":false,
        "full_complete_header_prefix_equal_native_reference":true,
        "actual_state":observation,"public_business_state":observed,
        "included_operations":expected.included_operations,
        "absent_operations_checked_through_entire_prefix":expected.absent_operations,
        "present_nullifiers":expected.present_nullifiers,"absent_nullifiers":expected.absent_nullifiers,
        "nonempty_asserted_coverage":{"fund_claim":has(Kind::FundClaimSha256),
            "governance_action":has(Kind::GovernanceActionSha256),
            "asset_issuance":has(Kind::IssuanceDeclaration),
            "transaction_statement":has(Kind::TransactionStatement)},
        "transaction_payment_classification_verified":false,
        "wallet_scan_performed":false,"wallet_balances_verified":false,
        "full_business_acceptance_passed":false,"g1_passed":false,"g2_passed":false,
        "proofs_generated":false,"nodes_started":false,
        "elapsed_ms":started.elapsed().as_millis().to_string()}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn persisted_assertions_reject_ambiguous_or_unbounded_schema() {
        // A public-state projection cannot stand in for the exact ledger schema.
        assert!(parse_expectations(br#"{"version":1,"state":{"height":1}}"#).is_err());
        assert!(
            serde_json::from_str::<OperationKey>(r#"{"kind":"wallet_payment","identity":"00"}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<OperationKey>(
                r#"{"kind":"transaction_statement","identity":"00","secret":"excluded"}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<OperationKey>(
                r#"{"kind":"transaction_statement","kind":"issuance_declaration","identity":"00"}"#
            )
            .is_err()
        );
    }
    #[cfg(unix)]
    #[test]
    fn session_assertions_persist_across_boundaries_and_exclude_the_entire_prefix() {
        let key = |byte| OperationKey {
            kind: Kind::TransactionStatement,
            identity: format!("{byte:02x}").repeat(32),
        };
        // Only the operation accumulator is exercised; this projection is never
        // parsed as a qualified ledger, executed or passed as state evidence.
        let expected = Expectations {
            version: 1,
            state: PublicState {
                height: 97,
                tip: "01".repeat(32),
                economics: Economics {
                    issued: "0".into(),
                    burned: "0".into(),
                    miner_credited: "0".into(),
                    fund_credited: "0".into(),
                    holder_pool: "0".into(),
                    locked_total: "0".into(),
                    locked_schedule: Vec::new(),
                },
                fund_total_entitlement: "0".into(),
                funds: Vec::new(),
                governance_sequence: 0,
                issuance_fee_atoms: 0,
                pending_issuance_fee: None,
                fee_destination: String::new(),
                assets: Vec::new(),
                leaf_count: 0,
                nullifier_count: 0,
            },
            included_operations: vec![
                Included {
                    height: 1,
                    operation: key(1),
                },
                Included {
                    height: 97,
                    operation: key(2),
                },
            ],
            absent_operations: vec![key(3)],
            present_nullifiers: Vec::new(),
            absent_nullifiers: Vec::new(),
        };
        let mut assertions = SessionAssertions {
            expected,
            found: vec![false; 2],
        };
        assertions
            .record(1, Kind::TransactionStatement, key(1).identity)
            .unwrap();
        let first_boundary = assertions.progress();
        assert_eq!(
            first_boundary["included_operations_seen"],
            json!([true, false])
        );
        assert!(assertions.require_inclusions().is_err());
        assertions
            .record(96, Kind::TransactionStatement, key(2).identity)
            .unwrap();
        assert!(assertions.require_inclusions().is_err());
        assertions
            .record(97, Kind::TransactionStatement, key(2).identity)
            .unwrap();
        assertions.require_inclusions().unwrap();
        assert_eq!(
            assertions.progress()["included_operations_seen"],
            json!([true, true])
        );
        assert!(
            assertions
                .record(98, Kind::TransactionStatement, key(3).identity)
                .is_err()
        );
        assert_eq!(
            first_boundary["included_operations_seen"],
            json!([true, false])
        );
    }
}
