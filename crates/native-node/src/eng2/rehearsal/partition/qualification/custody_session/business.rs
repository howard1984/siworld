use super::super::positive_business::custody_caller::{
    ExistingVault, IsolatedActors, RetainedMaterial,
};
use super::*;
use crate::wallet::issuance::ISSUER_SIGNATURE_CONTEXT;
use native::issuance::AssetMetadata;
use native::multi_asset::AssetId;

fn expectation(value: &Value, issuer_key: &str) -> Result<IssuerExpectation> {
    let step = value["steps"]
        .as_array()
        .filter(|v| v.len() == 4)
        .and_then(|v| v.last())
        .ok_or("custody_business_issuance_required")?;
    if step["kind"] != "issuance" {
        return Err("custody_business_issuance_required".into());
    }
    let spec = &step["issuance"];
    if spec["issuer_key"].as_str() != Some(issuer_key) {
        return Err("custody_issuer_plan_differs".into());
    }
    let amounts = spec["amounts"]
        .as_array()
        .filter(|a| a.len() == crate::issuance::INITIAL_NOTES)
        .ok_or("custody_issuance_amounts_rejected")?;
    let mut supply = 0u64;
    for n in amounts {
        supply = supply
            .checked_add(n.as_u64().ok_or("custody_issuance_amounts_rejected")?)
            .ok_or("custody_issuance_supply_overflow")?;
    }
    Ok(IssuerExpectation {
        sequence: spec["sequence"]
            .as_u64()
            .ok_or("custody_issuance_sequence_rejected")?,
        asset_id: AssetId(hash(
            spec["expected_asset_id"]
                .as_str()
                .ok_or("custody_issuance_asset_rejected")?,
        )?),
        public_supply: supply,
        metadata: AssetMetadata {
            name: spec["name"]
                .as_str()
                .ok_or("custody_issuance_metadata_rejected")?
                .to_owned(),
            decimals: spec["decimals"]
                .as_u64()
                .and_then(|n| u8::try_from(n).ok())
                .ok_or("custody_issuance_metadata_rejected")?,
        },
        issuance_fee_atoms: crate::issuance::TESTNET_ISSUANCE_FEE_ATOMS,
    })
}

pub(super) fn run(
    plan: &Plan,
    binding: &RehearsalBinding,
    prerequisites: &Prerequisites,
    custody: &CustodySet,
    passwords: &passwords::Passwords,
    guard: &Guard<'_>,
    out: &mut Output,
) -> Result<Value> {
    if plan.expectations.is_some() {
        return Err("custody_business_plan_rejected".into());
    }
    let node = plan
        .node_directory
        .as_ref()
        .ok_or("custody_node_required")?;
    canonical_private(node)?;
    let genesis = genesis(plan, prerequisites, custody)?;
    let qualification = plan
        .qualification
        .as_ref()
        .ok_or("custody_qualification_required")?;
    let context = Context::load(&qualification.path, &qualification.sha256)?;
    context.check_genesis(&genesis)?;
    let business = plan.business.as_ref().ok_or("custody_business_required")?;
    let bytes = load(business, 128 * 1024)?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| "custody_business_plan_rejected")?;
    let key = authority(&custody.issuer_key)?;
    let expected = expectation(&value, &custody.issuer_key)?;
    guard.check()?;
    let _lease = crate::service::Lease::acquire(node)?;
    let mut store = Store::resume_existing(
        &node.join("chain.redb"),
        genesis,
        crate::eng2::resident::limits().chain,
    )?;
    let head = plan.head.as_ref().ok_or("custody_head_required")?;
    if store.engine().state().height() != head.height
        || crate::local::hex(&store.engine().state().tip()) != head.tip
        || value["start_height"] != head.height
        || value["start_tip"] != head.tip
        || value["isolated_directory"].as_str() != node.to_str()
    {
        return Err("custody_actual_business_head_differs".into());
    }
    let policy = store
        .engine()
        .state()
        .chain()
        .config
        .issuance
        .as_ref()
        .ok_or("custody_native_issuance_policy_required")?
        .policy();
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
    let mut signer = IssuerSigner::open(&plan.issuer_directory, binding, key)?;
    let mut sign = |context: &[u8], declaration: &native::issuance::IssuanceDeclaration| {
        guard.check()?;
        if context != ISSUER_SIGNATURE_CONTEXT {
            return Err("custody_issuer_context_rejected".into());
        }
        signer.sign(declaration, &expected, policy)
    };
    let mut retained = RetainedMaterial::default();
    let generated = actors.generate(
        &mut store,
        node,
        &out.path.join("business"),
        &business.path,
        &business.sha256,
        (&qualification.path, &qualification.sha256),
        &mut retained,
        &mut gate,
        &mut sign,
    );
    // Retain all memory openings across the ordinary error and bounded read-only closeout.
    let accepted = json!({"height":store.engine().state().height(),"tip":crate::local::hex(&store.engine().state().tip()),"retained_material_counts":retained.counts(),"memory_openings_crash_recoverable":false,"automatic_retry":false,"canonical_rollback":false});
    let closeout = out.json("accepted-prefix-closeout.json", &accepted);
    if generated.is_err() {
        let _=out.json("failure.json",&json!({"operation":"business","failed":true,"accepted_prefix_retained":true,"automatic_retry":false}));
        closeout?;
        guard.check()?;
        return Err("custody_business_generation_failed".into());
    }
    closeout?;
    guard.check()?;
    if load(business, 128 * 1024)? != bytes {
        return Err("custody_business_input_changed".into());
    }
    Ok(
        json!({"operation":"business","generator":generated?,"actual_accepted_prefix":accepted,"independent_owned_balance_scan_performed":false,"full_business_acceptance_passed":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> Value {
        json!({"steps":[{},{},{},{"kind":"issuance","issuance":{
        "issuer_key":"01".repeat(1952),"amounts":[100,0,0],"sequence":7,
        "expected_asset_id":"02".repeat(32),"name":"Example Asset","decimals":4}}]})
    }
    #[test]
    fn independent_issuer_economics_reject_wrong_key_supply_overflow_and_widths() {
        let key = "01".repeat(1952);
        let value = plan();
        let expected = expectation(&value, &key).unwrap();
        assert_eq!(expected.public_supply, 100);
        assert_eq!(expected.sequence, 7);
        assert!(expectation(&value, &"03".repeat(1952)).is_err());
        for (field, replacement) in [
            ("amounts", json!([u64::MAX, 1, 0])),
            ("amounts", json!([1, 2])),
            ("amounts", json!([1, -1, 0])),
            ("decimals", json!(256)),
            ("expected_asset_id", json!("02".repeat(31))),
        ] {
            let mut changed = plan();
            changed["steps"][3]["issuance"][field] = replacement;
            assert!(expectation(&changed, &key).is_err());
        }
        let mut changed = plan();
        changed["steps"][3]["kind"] = json!("standard");
        assert!(expectation(&changed, &key).is_err());
    }
}
