//! Public preparation and explicit local-rehearsal signing for windowed formats.
//! These tools do not activate a genesis, admit a block or change ledger state.
use super::*;
use crate::{eng2::fund_claim::WindowedFundClaim, eng2_governance::WindowedSignedAction};

fn claim_digest(claim: &WindowedFundClaim) -> Result<Hash> {
    Ok(blake3::derive_key(
        "siworld eng2 public fund claim review v2",
        &claim.signing_message()?,
    ))
}
fn action_digest(action: &WindowedSignedAction, role: SignerRole) -> Result<Hash> {
    Ok(blake3::derive_key(
        "siworld eng2 governance window role review v2",
        &action.signing_bytes(role)?,
    ))
}

pub(super) fn execute(value: &Value) -> Result<Value> {
    match value["operation"].as_str() {
        Some("windowed-claim-prepare") => {
            fields(
                value,
                &[
                    "operation",
                    "network",
                    "valid_from",
                    "valid_until",
                    "member",
                    "amount_atoms",
                    "counter",
                    "destination_hex",
                    "authority_hex",
                    "rseed_hex",
                ],
            )?;
            let mut legacy = value.clone();
            let object = legacy.as_object_mut().ok_or("expected public request")?;
            let from = object.remove("valid_from").ok_or("missing start height")?;
            object.remove("valid_until");
            object.insert("height".into(), from);
            object.insert("operation".into(), json!("claim-prepare"));
            let prepared = super::claim_prepare(&legacy)?;
            let claim = WindowedFundClaim {
                claim: PublicFundClaim::decode(&public_bytes(
                    &prepared["claim_hex"],
                    crate::eng2::fund_claim::ENCODED_BYTES,
                )?)?,
                valid_until: decimal(&value["valid_until"])?,
            };
            Ok(
                json!({"claim_hex":hex(&claim.encode()?),"signing_message_hex":hex(&claim.signing_message()?),
                "signature_context_hex":hex(WindowedFundClaim::signature_context()),"review_digest":hex(&claim_digest(&claim)?),
                "signature_verified":false,"state_changed":false,"submitted":false,"active_genesis_selected":false}),
            )
        }
        Some("windowed-claim-attach") => {
            fields(
                value,
                &["operation", "claim_hex", "authority_hex", "signature_hex"],
            )?;
            let mut claim = WindowedFundClaim::decode(&public_bytes(
                &value["claim_hex"],
                crate::eng2::fund_claim::ENCODED_BYTES + 8,
            )?)?;
            require(claim.claim.spend.signature == [0; crate::fund_spend::SIGNATURE_BYTES])?;
            let authority = fixed(&value["authority_hex"])?;
            claim.claim.spend.signature = fixed(&value["signature_hex"])?;
            claim.claim.spend.verify_signed_message(
                claim.claim.network,
                &authority,
                &claim.signing_message()?,
                WindowedFundClaim::signature_context(),
            )?;
            Ok(
                json!({"claim_hex":hex(&claim.encode()?),"signature_verified":true,"entitlement_verified":false,
                "recipient_current_state_verified":false,"state_changed":false,"submitted":false,"active_genesis_selected":false}),
            )
        }
        Some("windowed-governance-prepare") => {
            fields(
                value,
                &[
                    "operation",
                    "network",
                    "sequence",
                    "action",
                    "valid_from",
                    "valid_until",
                ],
            )?;
            let mut legacy = value.clone();
            let object = legacy.as_object_mut().ok_or("expected public request")?;
            object.remove("valid_from");
            object.remove("valid_until");
            object.insert("operation".into(), json!("governance-prepare"));
            let prepared = super::governance_prepare(&legacy)?;
            let action = WindowedSignedAction {
                signed: SignedAction {
                    action: Action::decode_unsigned(&public_bytes(
                        &prepared["request_hex"],
                        8192,
                    )?)?,
                    signatures: Vec::new(),
                },
                valid_from: decimal(&value["valid_from"])?,
                valid_until: decimal(&value["valid_until"])?,
            };
            let roles = governance_roles(&action.signed.action.kind);
            Ok(
                json!({"request_hex":hex(&action.unsigned_bytes()?),"required_roles":prepared["required_roles"],
                "messages":roles.iter().map(|(name,role)|Ok(json!({"role":name,"message_hex":hex(&action.signing_bytes(*role)?),
                    "review_digest":hex(&action_digest(&action,*role)?)}))).collect::<Result<Vec<_>>>()?,
                "signature_context_hex":hex(WindowedSignedAction::signature_context()),"activation_delay_blocks":prepared["activation_delay_blocks"],
                "state_changed":false,"submitted":false,"active_genesis_selected":false}),
            )
        }
        Some("windowed-governance-wrap") => {
            fields(value, &["operation", "request_hex", "signatures"])?;
            let mut action = WindowedSignedAction::decode_unsigned(&public_bytes(
                &value["request_hex"],
                24 + 8192,
            )?)?;
            let signatures = value["signatures"]
                .as_array()
                .ok_or("expected detached signature list")?;
            require(!signatures.is_empty() && signatures.len() <= 2)?;
            action.signed.signatures = signatures
                .iter()
                .map(|entry| {
                    fields(entry, &["role", "signature_hex"])?;
                    let role = match entry["role"].as_str() {
                        Some("founder") => SignerRole::Founder,
                        Some("revocation") => SignerRole::Revocation,
                        _ => return Err("unknown owner role".into()),
                    };
                    Ok(Authorization {
                        role,
                        signature: fixed(&entry["signature_hex"])?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let encoded = action.encode()?;
            WindowedSignedAction::decode(&encoded)?;
            Ok(
                json!({"signed_action_hex":hex(&encoded),"signature_verified":false,"chain_state_verified":false,
                "state_changed":false,"submitted":false,"active_genesis_selected":false}),
            )
        }
        _ => Err("unsupported windowed public operation".into()),
    }
}

pub fn sign_claim(
    input: &[u8],
    expected_network: Hash,
    expected_authority: [u8; crate::fund_spend::VERIFYING_KEY_BYTES],
    seed: zeroize::Zeroizing<[u8; 32]>,
) -> Result<Value> {
    let value = canonical(input)?;
    fields(&value, &["operation", "claim_hex", "confirmed_digest"])?;
    require(value["operation"] == "windowed-claim-sign" && expected_network != [0; 32])?;
    let mut claim = WindowedFundClaim::decode(&public_bytes(
        &value["claim_hex"],
        crate::eng2::fund_claim::ENCODED_BYTES + 8,
    )?)?;
    require(
        claim.claim.network == expected_network
            && claim.claim.spend.verifying_key == expected_authority
            && claim.claim.spend.signature == [0; crate::fund_spend::SIGNATURE_BYTES]
            && fixed::<32>(&value["confirmed_digest"])? == claim_digest(&claim)?,
    )?;
    claim.claim.spend.signature = sign_local(
        seed,
        expected_authority,
        &claim.signing_message()?,
        WindowedFundClaim::signature_context(),
    )?;
    claim.claim.spend.verify_signed_message(
        expected_network,
        &expected_authority,
        &claim.signing_message()?,
        WindowedFundClaim::signature_context(),
    )?;
    Ok(
        json!({"claim_hex":hex(&claim.encode()?),"signature_verified":true,"state_changed":false,
        "submitted":false,"active_genesis_selected":false}),
    )
}

pub fn sign_governance(
    input: &[u8],
    expected_network: Hash,
    expected_role: SignerRole,
    expected_authority: [u8; governance::PUBLIC_KEY_BYTES],
    seed: zeroize::Zeroizing<[u8; 32]>,
) -> Result<Value> {
    use libcrux_ml_dsa::ml_dsa_65;
    let value = canonical(input)?;
    fields(&value, &["operation", "request_hex", "confirmed_digest"])?;
    require(value["operation"] == "windowed-governance-sign" && expected_network != [0; 32])?;
    let action =
        WindowedSignedAction::decode_unsigned(&public_bytes(&value["request_hex"], 24 + 8192)?)?;
    require(
        action.signed.action.network == expected_network
            && governance_roles(&action.signed.action.kind)
                .iter()
                .any(|(_, role)| *role == expected_role)
            && fixed::<32>(&value["confirmed_digest"])? == action_digest(&action, expected_role)?,
    )?;
    let message = action.signing_bytes(expected_role)?;
    let signature = sign_local(
        seed,
        expected_authority,
        &message,
        WindowedSignedAction::signature_context(),
    )?;
    ml_dsa_65::verify(
        &ml_dsa_65::MLDSA65VerificationKey::new(expected_authority),
        &message,
        WindowedSignedAction::signature_context(),
        &ml_dsa_65::MLDSA65Signature::new(signature),
    )
    .map_err(|_| "windowed governance signature verification failed")?;
    let role = match expected_role {
        SignerRole::Founder => "founder",
        SignerRole::Revocation => "revocation",
        SignerRole::Checkpoint(_) => {
            return Err("checkpoint role cannot authorize governance".into());
        }
    };
    Ok(
        json!({"request_hex":hex(&action.unsigned_bytes()?),"role":role,"authority_hex":hex(&expected_authority),
        "signature_hex":hex(&signature),"signature_verified":true,"state_changed":false,
        "submitted":false,"active_genesis_selected":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use libcrux_ml_dsa::ml_dsa_65;
    use zeroize::Zeroizing;
    fn public(value: Value) -> Value {
        super::super::execute(&serde_json::to_vec(&value).unwrap()).unwrap()
    }

    #[test]
    fn prepared_window_role_digest_and_detached_signature_reach_governance_transition() {
        let network = [7; 32];
        let prepared = public(
            json!({"operation":"windowed-governance-prepare","network":hex(&network),
            "sequence":"1","valid_from":"2","valid_until":"289",
            "action":{"type":"propose-issuance-fee","amount_atoms":"100000000"}}),
        );
        let authority = *ml_dsa_65::generate_key_pair([1; 32])
            .verification_key
            .as_ref();
        let request = json!({"operation":"windowed-governance-sign","request_hex":prepared["request_hex"],
            "confirmed_digest":prepared["messages"][0]["review_digest"]});
        let signature = sign_governance(
            &serde_json::to_vec(&request).unwrap(),
            network,
            SignerRole::Founder,
            authority,
            Zeroizing::new([1; 32]),
        )
        .unwrap();
        let wrapped = public(
            json!({"operation":"windowed-governance-wrap","request_hex":prepared["request_hex"],
            "signatures":[{"role":"founder","signature_hex":signature["signature_hex"]}]}),
        );
        let action = WindowedSignedAction::decode(
            &public_bytes(
                &wrapped["signed_action_hex"],
                WindowedSignedAction::MAX_ENCODED_BYTES,
            )
            .unwrap(),
        )
        .unwrap();
        let key = |seed| {
            *ml_dsa_65::generate_key_pair([seed; 32])
                .verification_key
                .as_ref()
        };
        let address = |seed| {
            crate::wallet::WalletKeys::from_seed(network, Zeroizing::new([seed; 32]), 0)
                .unwrap()
                .address()
        };
        let mut state = governance::GovernanceState::new(
            network,
            key(1),
            key(2),
            [3, 4, 5].map(key),
            address(6),
            vec![address(8)],
        )
        .unwrap();
        while state.height() < 288 {
            state.apply_block(state.height() + 1, &[]).unwrap();
        }
        let event = state
            .apply_windowed_block(289, std::slice::from_ref(&action))
            .unwrap()
            .remove(0);
        assert_eq!(event.included_height, 289);
        assert_eq!(event.effective_height, 289 + governance::OWNER_DELAY_BLOCKS);
        let accepted = state.clone();
        assert!(state.apply_windowed_block(290, &[action]).is_err());
        assert_eq!(state, accepted);
        assert!(!prepared["active_genesis_selected"].as_bool().unwrap());
        assert!(
            super::super::sign_governance(
                &serde_json::to_vec(&request).unwrap(),
                network,
                SignerRole::Founder,
                authority,
                Zeroizing::new([1; 32])
            )
            .is_err()
        );
        let mut altered = request;
        altered["confirmed_digest"] = json!(hex(&[0; 32]));
        assert!(
            sign_governance(
                &serde_json::to_vec(&altered).unwrap(),
                network,
                SignerRole::Founder,
                authority,
                Zeroizing::new([1; 32])
            )
            .is_err()
        );
    }

    #[test]
    fn prepared_claim_keeps_signed_window_and_selected_authority() {
        let network = [7; 32];
        let address = crate::wallet::WalletKeys::from_seed(network, Zeroizing::new([8; 32]), 0)
            .unwrap()
            .address();
        let authority = *ml_dsa_65::generate_key_pair([83; 32])
            .verification_key
            .as_ref();
        let prepared = public(
            json!({"operation":"windowed-claim-prepare","network":hex(&network),
            "valid_from":"1","valid_until":"288","member":0,"amount_atoms":"17","counter":"0",
            "destination_hex":hex(&governance::canonical_address(&address)),"authority_hex":hex(&authority),
            "rseed_hex":hex(&[1;48])}),
        );
        let input = json!({"operation":"windowed-claim-sign","claim_hex":prepared["claim_hex"],"confirmed_digest":prepared["review_digest"]});
        let signed = sign_claim(
            &serde_json::to_vec(&input).unwrap(),
            network,
            authority,
            Zeroizing::new([83; 32]),
        )
        .unwrap();
        let claim = WindowedFundClaim::decode(
            &public_bytes(
                &signed["claim_hex"],
                crate::eng2::fund_claim::ENCODED_BYTES + 8,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(claim.claim.height, 1);
        assert_eq!(claim.valid_until, 288);
        claim
            .claim
            .spend
            .verify_signed_message(
                network,
                &authority,
                &claim.signing_message().unwrap(),
                WindowedFundClaim::signature_context(),
            )
            .unwrap();
        assert!(
            sign_claim(
                &serde_json::to_vec(&input).unwrap(),
                [8; 32],
                authority,
                Zeroizing::new([83; 32])
            )
            .is_err()
        );
        assert!(
            super::super::sign_claim(
                &serde_json::to_vec(&input).unwrap(),
                network,
                authority,
                Zeroizing::new([83; 32])
            )
            .is_err()
        );
    }
}
