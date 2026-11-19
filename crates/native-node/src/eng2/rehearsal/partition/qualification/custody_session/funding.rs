//! Explicit funding of existing isolated actors; no key or balance initialization.
use super::super::positive_business::custody_caller::{
    ExistingVault, IsolatedActors, RetainedMaterial,
};
use super::*;

pub(super) fn run(
    plan: &Plan,
    binding: &RehearsalBinding,
    prerequisites: &Prerequisites,
    custody: &CustodySet,
    passwords: &passwords::Passwords,
    guard: &Guard<'_>,
    out: &mut Output,
) -> Result<Value> {
    if plan.business.is_some() || plan.expectations.is_some() {
        return Err("custody_funding_plan_rejected".into());
    }
    let node = plan
        .node_directory
        .as_ref()
        .ok_or("custody_node_required")?;
    let selected = genesis(plan, prerequisites, custody)?;
    let qualification = plan
        .qualification
        .as_ref()
        .ok_or("custody_qualification_required")?;
    let context = Context::load(&qualification.path, &qualification.sha256)?;
    context.check_genesis(&selected)?;
    let input = plan.funding.as_ref().ok_or("custody_funding_required")?;
    let bytes = load(input, 128 * 1024)?;
    guard.check()?;
    let _lease = crate::service::Lease::acquire(node)?;
    let mut store = Store::resume_existing(
        &node.join("chain.redb"),
        selected,
        crate::eng2::resident::limits().chain,
    )?;
    let head = plan.head.as_ref().ok_or("custody_head_required")?;
    if store.engine().state().height() != head.height
        || crate::local::hex(&store.engine().state().tip()) != head.tip
    {
        return Err("custody_actual_funding_head_differs".into());
    }
    let addresses = custody
        .addresses
        .iter()
        .map(|a| address(a))
        .collect::<Result<Vec<_>>>()?;
    let specifications = std::array::from_fn(|i| ExistingVault {
        directory: &plan.actors[i].directory,
        passphrase: &passwords.0[i],
        expected_account: 0,
        expected_address: &addresses[i],
    });
    let mut gate = |_: &str| guard.check();
    let mut actors = IsolatedActors::open_existing(
        binding.network(),
        specifications,
        &[node.as_path(), out.path.as_path()],
        &mut gate,
    )?;
    let campaign = binding.receipt()["campaign_id"]
        .as_str()
        .ok_or("custody_campaign_required")?
        .to_owned();
    let mut retained = RetainedMaterial::default();
    let generated = actors.fund_existing(
        &mut store,
        node,
        &out.path.join("funding"),
        &input.path,
        &input.sha256,
        (&qualification.path, &qualification.sha256),
        &campaign,
        &mut retained,
        &mut gate,
    );
    // Keep custody sessions and original openings alive through ordinary closeout.
    let accepted = json!({"height":store.engine().state().height(),
        "tip":crate::local::hex(&store.engine().state().tip()),
        "retained_material_counts":retained.counts(),"memory_openings_crash_recoverable":false,
        "automatic_retry":false,"canonical_rollback":false});
    out.json("accepted-prefix-closeout.json", &accepted)?;
    if generated.is_err() {
        out.json(
            "failure.json",
            &json!({"operation":"funding","failed":true,
            "accepted_prefix_retained":true,"automatic_retry":false}),
        )?;
        return Err("custody_funding_generation_failed".into());
    }
    guard.check()?;
    if load(input, 128 * 1024)? != bytes {
        return Err("custody_funding_input_changed".into());
    }
    Ok(json!({"operation":"funding","generator":generated?,
        "actual_accepted_prefix":accepted,"independent_owned_balance_scan_performed":false,
        "full_business_acceptance_passed":false}))
}
