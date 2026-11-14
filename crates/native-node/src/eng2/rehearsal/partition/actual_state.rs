//! Compare an actual owner state with independent complete native replay.
use super::*;
use crate::eng2::{header::Header, state_components::Binding};

pub(super) const COMPONENTS: [&str; 11] = [
    "context",
    "tree",
    "nullifiers",
    "roots",
    "holder_pool",
    "development_fund",
    "fee_destination",
    "governance",
    "issuance_and_burn",
    "locked_rewards",
    "assets",
];

/// The reference must have reached this height through Engine::apply with the
/// native verifier. Neither an execution commitment alone nor a replay of the
/// old branch substitutes for comparing all actual component bytes.
pub(super) fn observe(
    actual: &Engine,
    reference: &Engine,
    header: &Header,
    record: &Value,
) -> Result<Value, String> {
    let id = header
        .id()
        .map_err(|_| "observer header identity rejected")?;
    let work = actual.state().chain().cumulative_work.to_big_endian();
    let binding = Binding {
        genesis: actual.genesis().id(),
        rules_commitment: actual.genesis().rules_commitment(),
        parent: header.parent,
    };
    if actual.genesis().encode()? != reference.genesis().encode()?
        || actual.state().height() != header.height
        || reference.state().height() != header.height
        || actual.state().tip() != id
        || reference.state().tip() != id
        || actual.state().chain().cumulative_work != reference.state().chain().cumulative_work
        || record["height"] != header.height
        || record["id"] != crate::local::hex(&id)
        || record["parent"] != crate::local::hex(&header.parent)
        || record["execution_commitment"] != crate::local::hex(&header.execution_commitment)
        || record["cumulative_work"] != crate::local::hex(&work)
        || actual
            .state()
            .execution_commitment(binding, actual.limits())?
            != header.execution_commitment
        || reference
            .state()
            .execution_commitment(binding, reference.limits())?
            != header.execution_commitment
    {
        return Err("actual state differs from native reference or pinned oracle".into());
    }
    let actual_parts = actual
        .state()
        .canonical_components(binding, actual.limits())?;
    let expected_parts = reference
        .state()
        .canonical_components(binding, reference.limits())?;
    let oracle = record["components"]
        .as_object()
        .ok_or("component oracle missing")?;
    if oracle.len() != COMPONENTS.len() {
        return Err("component oracle must contain exactly eleven components".into());
    }
    let mut components = serde_json::Map::new();
    for ((name, part), expected) in COMPONENTS.into_iter().zip(actual_parts).zip(expected_parts) {
        let observed = json!({"bytes":part.len(),
            "blake3":crate::local::hex(blake3::hash(&part).as_bytes())});
        if part != expected || oracle.get(name) != Some(&observed) {
            return Err(format!(
                "actual component differs from native reference or oracle: {name}"
            ));
        }
        components.insert(name.to_owned(), observed);
    }
    Ok(json!({"height":header.height,"id":crate::local::hex(&id),
        "parent":crate::local::hex(&header.parent),
        "execution_commitment":crate::local::hex(&header.execution_commitment),
        "cumulative_work":crate::local::hex(&work),"components":components,
        "actual_component_bytes_equal_native_reference":true,
        "actual_component_digests_equal_pinned_oracle":true}))
}
