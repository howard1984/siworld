//! Public issuance-fee view from an actual engine and an independently pinned head.
//! No HTTP route, file export, proof verification or persistence is performed here.
use crate::{eng2::execution::Engine, eng2_governance::GovernanceState, wire::Hash};
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProjectionHead {
    pub network: Hash,
    pub genesis: Hash,
    pub height: u64,
    pub tip: Hash,
}
/// Return only the issuance_fee object for explicit explorer projection v2.
/// The host supplies the canonical export index identity and publishes the full
/// snapshot only after its accepted block/state has been saved durably.
pub fn issuance_fee_projection(engine: &Engine, expected: ProjectionHead) -> Result<Value, String> {
    let state = engine.state();
    if expected.network != state.network()
        || expected.genesis != engine.genesis().id()
        || expected.height != state.height()
        || expected.tip != state.tip()
        || state.governance().height() != state.height()
        || state.governance().network() != state.network()
        || state.height() > 1_000_000
    {
        return Err("issuance-fee projection differs from the canonical export head".into());
    }
    encode(state.governance())
}
fn encode(governance: &GovernanceState) -> Result<Value, String> {
    // Reuse consensus canonical validation; no missing amount is defaulted.
    governance.canonical_component_bytes()?;
    let parameters = governance.issuance_fee_parameters();
    let pending = governance.pending_issuance_fee().map(|row| {
        json!({
            "amount_atoms":row.amount_atoms.to_string(),
            "proposal_sequence":row.proposal_sequence.to_string(),
            "included_height":row.included_height,
            "effective_height":row.effective_height,
        })
    });
    Ok(
        json!({"current_atoms":governance.issuance_fee_atoms().to_string(),
        "minimum_atoms":parameters.minimum_atoms.to_string(),
        "maximum_atoms":parameters.maximum_atoms.to_string(),"pending":pending}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::eng2::{
        genesis::{FeeMode, Genesis},
        snapshot::tests::{bootstrap, limits},
    };
    #[test]
    fn actual_engine_view_requires_exact_network_genesis_height_and_tip() {
        let original = bootstrap();
        let genesis = Genesis::seal(
            original.chain.config.clone(),
            original.governance().clone(),
            FeeMode::LegacyMiner,
        )
        .unwrap();
        let engine = Engine::new(genesis, limits().chain).unwrap();
        let head = ProjectionHead {
            network: engine.state().network(),
            genesis: engine.genesis().id(),
            height: 0,
            tip: engine.state().tip(),
        };
        let value = issuance_fee_projection(&engine, head).unwrap();
        assert_eq!(
            value["current_atoms"],
            engine.state().governance().issuance_fee_atoms().to_string()
        );
        assert_eq!(value["minimum_atoms"], "100000000");
        assert_eq!(value["maximum_atoms"], "1000000000000");
        assert!(value["pending"].is_null());
        assert_eq!(value.as_object().unwrap().len(), 4);
        for wrong in [
            ProjectionHead {
                network: [9; 32],
                ..head
            },
            ProjectionHead {
                genesis: [9; 32],
                ..head
            },
            ProjectionHead { height: 1, ..head },
            ProjectionHead {
                tip: [9; 32],
                ..head
            },
        ] {
            assert!(issuance_fee_projection(&engine, wrong).is_err());
        }
    }
    #[test]
    fn pending_rule_view_preserves_exact_sequence_and_does_not_replace_active_fee() {
        use crate::eng2_governance::{
            Action, ActionKind, Authorization, SIGNATURE_CONTEXT, SignedAction, SignerRole,
        };
        use libcrux_ml_dsa::ml_dsa_65;
        let original = bootstrap();
        let mut state = original.governance().clone();
        let action = Action {
            network: state.network(),
            sequence: 9_007_199_254_740_993,
            kind: ActionKind::ProposeIssuanceFee {
                amount_atoms: 7_500_000_000,
            },
        };
        let signed = SignedAction {
            signatures: vec![Authorization {
                role: SignerRole::Founder,
                signature: *ml_dsa_65::sign(
                    &ml_dsa_65::generate_key_pair([1; 32]).signing_key,
                    &action.signing_bytes(SignerRole::Founder).unwrap(),
                    SIGNATURE_CONTEXT,
                    [19; 32],
                )
                .unwrap()
                .as_ref(),
            }],
            action,
        };
        state.apply_block(1, &[signed]).unwrap();
        let value = encode(&state).unwrap();
        assert_eq!(value["current_atoms"], "5000000000");
        assert_eq!(value["pending"]["amount_atoms"], "7500000000");
        assert_eq!(value["pending"]["proposal_sequence"], "9007199254740993");
        assert_eq!(value["pending"]["included_height"], 1);
        assert_eq!(value["pending"]["effective_height"], 4033);
    }
}
