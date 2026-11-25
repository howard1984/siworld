use libcrux_ml_dsa::ml_dsa_65;
use native::{codec::encode_digest, multi_asset::F};
use p3_field::PrimeCharacteristicRing;
use serde_json::{Value, json};
use siworld_native_node::{
    eng2_governance::{Action, SIGNATURE_CONTEXT, SignedAction, SignerRole},
    eng2_operations::{PendingOperations, execute, hex},
    wallet::WalletKeys,
};

fn run(value: Value) -> Result<Value, String> {
    execute(&serde_json::to_vec(&value).unwrap())
}
fn address() -> String {
    let address = WalletKeys::from_seed([17; 32], zeroize::Zeroizing::new([31; 32]), 0)
        .unwrap()
        .address();
    hex(&siworld_native_node::eng2_governance::canonical_address(
        &address,
    ))
}
fn key(seed: u8) -> [u8; 1952] {
    *ml_dsa_65::generate_key_pair([seed; 32])
        .verification_key
        .as_ref()
}
fn prepare_claim() -> Value {
    json!({"operation":"claim-prepare", "network":hex(&[17;32]), "height":"25", "member":0,
        "amount_atoms":"1", "counter":"0", "destination_hex":address(),
        "authority_hex":hex(&key(83)), "rseed_hex":hex(&encode_digest(&[F::from_u32(9);12]))})
}
#[test]
fn claim_message_attaches_a_real_signature_without_creating_or_debiting_state() {
    let prepared = run(prepare_claim()).unwrap();
    assert_eq!(prepared["submitted"], false);
    assert_eq!(prepared["state_changed"], false);
    let message =
        siworld_native_node::eng2_operations::public_bytes(&prepared["signing_message_hex"], 10000)
            .unwrap();
    let pair = ml_dsa_65::generate_key_pair([83; 32]);
    let signature = ml_dsa_65::sign(
        &pair.signing_key,
        &message,
        siworld_native_node::eng2::fund_claim::SIGNATURE_CONTEXT,
        [84; 32],
    )
    .unwrap();
    let signed = run(
        json!({"operation":"claim-attach", "claim_hex":prepared["claim_hex"],
        "authority_hex":hex(&key(83)), "signature_hex":hex(signature.as_ref())}),
    )
    .unwrap();
    assert_eq!(signed["signature_verified"], true);
    assert_eq!(signed["state_changed"], false);
    let bytes =
        siworld_native_node::eng2_operations::public_bytes(&signed["claim_hex"], 10000).unwrap();
    let claim = siworld_native_node::eng2::fund_claim::PublicFundClaim::decode(&bytes).unwrap();
    assert_eq!(claim.height, 25);
    assert_eq!(claim.spend.amount, 1);
    assert!(
        run(
            json!({"operation":"claim-attach", "claim_hex":prepared["claim_hex"],
        "authority_hex":hex(&key(84)), "signature_hex":hex(signature.as_ref())})
        )
        .is_err()
    );
}
#[test]
fn governance_messages_bind_full_sequence_and_current_role() {
    for (kind, roles) in [
        (
            json!({"type":"cancel-destination","proposal_sequence":"1"}),
            vec!["revocation"],
        ),
        (
            json!({"type":"cancel-joint","proposal_sequence":"1"}),
            vec!["founder", "revocation"],
        ),
        (
            json!({"type":"rotate-owners","founder_hex":hex(&key(7)),"revocation_hex":hex(&key(8))}),
            vec!["founder", "revocation"],
        ),
        (
            json!({"type":"propose-destination","target":"fund","member":0,"address_hex":address()}),
            vec!["founder"],
        ),
    ] {
        let prepared = run(
            json!({"operation":"governance-prepare","network":hex(&[17;32]),
            "sequence":"9007199254740993","action":kind}),
        )
        .unwrap();
        assert_eq!(prepared["sequence"], "9007199254740993");
        assert_eq!(prepared["required_roles"], json!(roles));
        let request =
            siworld_native_node::eng2_operations::public_bytes(&prepared["request_hex"], 8192)
                .unwrap();
        let action = Action::decode_unsigned(&request).unwrap();
        assert_eq!(action.sequence, 9007199254740993);
        let role = if roles[0] == "founder" {
            SignerRole::Founder
        } else {
            SignerRole::Revocation
        };
        assert_eq!(
            prepared["messages"][0]["message_hex"],
            hex(&action.signing_bytes(role).unwrap())
        );
    }
}
#[test]
fn wrapped_governance_is_not_misrepresented_as_authenticated_or_submitted() {
    let prepared = run(
        json!({"operation":"governance-prepare","network":hex(&[17;32]),"sequence":"2",
        "action":{"type":"cancel-joint","proposal_sequence":"1"}}),
    )
    .unwrap();
    let wrapped = run(
        json!({"operation":"governance-wrap","request_hex":prepared["request_hex"],
        "signatures":[{"role":"founder","signature_hex":hex(&[1;3309])}]}),
    )
    .unwrap();
    assert_eq!(wrapped["signature_verified"], false);
    assert_eq!(wrapped["submitted"], false);
    let bytes =
        siworld_native_node::eng2_operations::public_bytes(&wrapped["signed_action_hex"], 16384)
            .unwrap();
    let action = SignedAction::decode(&bytes).unwrap();
    assert_eq!(action.signatures.len(), 1);
    assert_eq!(SIGNATURE_CONTEXT, b"siworld eng2 governance v1");
}
#[test]
fn pending_bundle_is_bounded_canonical_and_does_not_accept_another_network() {
    let network = hex(&[17; 32]);
    let encoded = serde_json::to_vec(&json!({"version":1,"network":network,"height":"25",
        "fund_claims":[],"governance":[]}))
    .unwrap();
    let pending = PendingOperations::decode(&encoded, [17; 32], 25).unwrap();
    assert_eq!(pending.encode().unwrap(), encoded);
    assert!(PendingOperations::decode(&encoded, [18; 32], 25).is_err());
    assert!(PendingOperations::decode(&encoded, [17; 32], 26).is_err());
    let mut trailing = encoded.clone();
    trailing.push(b' ');
    assert!(PendingOperations::decode(&trailing, [17; 32], 25).is_err());
    let mut wrong: Value = serde_json::from_slice(&encoded).unwrap();
    wrong["fund_claims"] = json!(vec!["00"; 9]);
    assert!(PendingOperations::decode(&serde_json::to_vec(&wrong).unwrap(), [17; 32], 25).is_err());
}
#[test]
fn commands_reject_ambiguous_numbers_extra_fields_and_zero_context() {
    let prepared = prepare_claim();
    for (field, value) in [
        ("height", json!(25)),
        ("counter", json!("00")),
        ("amount_atoms", json!("0")),
        ("network", json!(hex(&[0; 32]))),
        ("member", json!(32)),
    ] {
        let mut invalid = prepared.clone();
        invalid[field] = value;
        assert!(run(invalid).is_err(), "{field}");
    }
    let mut extra = prepared;
    extra["password"] = json!("must not be accepted");
    assert!(run(extra).is_err());
}

#[test]
fn private_claim_pipe_requires_independent_network_key_and_exact_review_digest() {
    let prepared = run(prepare_claim()).unwrap();
    let command = json!({"operation":"claim-sign","claim_hex":prepared["claim_hex"],
        "confirmed_digest":prepared["review_digest"]});
    let bytes = serde_json::to_vec(&command).unwrap();
    let sign = siworld_native_node::eng2_operations::sign_claim;
    let signed = sign(&bytes, [17; 32], key(83), zeroize::Zeroizing::new([83; 32])).unwrap();
    assert_eq!(signed["signature_verified"], true);
    assert_eq!(signed["submitted"], false);
    assert!(sign(&bytes, [18; 32], key(83), zeroize::Zeroizing::new([83; 32])).is_err());
    assert!(sign(&bytes, [17; 32], key(84), zeroize::Zeroizing::new([83; 32])).is_err());
    assert!(sign(&bytes, [17; 32], key(83), zeroize::Zeroizing::new([84; 32])).is_err());
    let mut wrong = command;
    wrong["confirmed_digest"] = json!(hex(&[0; 32]));
    assert!(
        sign(
            &serde_json::to_vec(&wrong).unwrap(),
            [17; 32],
            key(83),
            zeroize::Zeroizing::new([83; 32])
        )
        .is_err()
    );
}

#[test]
fn real_cli_private_framing_outputs_only_public_signature_and_fixed_failures() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let prepared = run(prepare_claim()).unwrap();
    let public = serde_json::to_vec(
        &json!({"operation":"claim-sign","claim_hex":prepared["claim_hex"],
        "confirmed_digest":prepared["review_digest"]}),
    )
    .unwrap();
    let mut framed = (public.len() as u32).to_be_bytes().to_vec();
    framed.extend(&public);
    framed.extend(32u32.to_be_bytes());
    framed.extend([83; 32]);
    for valid in [true, false] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_siworld-eng2-operations"))
            .args(["--sign-claim-pipe", &hex(&[17; 32]), &hex(&key(83))])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = framed.clone();
        if !valid {
            input.push(99);
        }
        child.stdin.take().unwrap().write_all(&input).unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.success(), valid);
        assert!(output.stderr.is_empty());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(!text.contains(&hex(&[83; 32])));
        let response: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(response["ok"], valid);
        if valid {
            assert_eq!(response["result"]["signature_verified"], true);
        } else {
            assert_eq!(response["error"], "public_operation_rejected");
        }
    }
}
#[test]
fn attach_only_changes_a_matching_empty_candidate_and_rejects_atomically() {
    use siworld_native_node::eng2::body::Body;
    use siworld_native_node::wire::{RewardMode, RewardRecord};
    let prepared = run(
        json!({"operation":"governance-prepare","network":hex(&[17;32]),"sequence":"2",
        "action":{"type":"cancel-joint","proposal_sequence":"1"}}),
    )
    .unwrap();
    let wrapped = run(
        json!({"operation":"governance-wrap","request_hex":prepared["request_hex"],
        "signatures":[{"role":"founder","signature_hex":hex(&[1;3309])}]}),
    )
    .unwrap();
    let encoded = serde_json::to_vec(&json!({"version":1,"network":hex(&[17;32]),"height":"25",
        "fund_claims":[],"governance":[wrapped["signed_action_hex"]]}))
    .unwrap();
    let mut body = Body {
        network: [17; 32],
        height: 26,
        profile: [1; 32],
        transactions: vec![],
        reward_mode: RewardMode::Voyager,
        rewards: vec![],
        fee_output: RewardRecord {
            commitment: [0; 48],
            ciphertext: [0; 1313],
        },
        fund_claims: vec![],
        governance: vec![],
        issuances: vec![],
        settlement_proof: vec![],
    };
    let before = body.clone();
    assert!(
        PendingOperations::decode(&encoded, [17; 32], 25)
            .unwrap()
            .attach_to(&mut body)
            .is_err()
    );
    assert_eq!(body, before);
    body.height = 25;
    PendingOperations::decode(&encoded, [17; 32], 25)
        .unwrap()
        .attach_to(&mut body)
        .unwrap();
    assert_eq!(body.governance.len(), 1);
    let before = body.clone();
    assert!(
        PendingOperations::decode(&encoded, [17; 32], 25)
            .unwrap()
            .attach_to(&mut body)
            .is_err()
    );
    assert_eq!(body, before);
    // Synthetic signatures are only framing inputs, never an authorization receipt.
}

#[test]
fn issuance_fee_governance_preparation_uses_exact_public_atoms_and_roles() {
    for (action, role, delay) in [
        (
            json!({"type":"propose-issuance-fee","amount_atoms":"5000000000"}),
            "founder",
            4032,
        ),
        (
            json!({"type":"cancel-issuance-fee","proposal_sequence":"1"}),
            "revocation",
            0,
        ),
    ] {
        let result = run(json!({"operation":"governance-prepare","network":hex(&[17;32]),"sequence":"2","action":action})).unwrap();
        assert_eq!(result["required_roles"], json!([role]));
        assert_eq!(result["activation_delay_blocks"], delay);
        assert_eq!(result["state_changed"], false);
        let request =
            siworld_native_node::eng2_operations::public_bytes(&result["request_hex"], 8192)
                .unwrap();
        assert_eq!(Action::decode_unsigned(&request).unwrap().sequence, 2);
    }
    for amount in [
        json!(5000000000u64),
        json!("05000000000"),
        json!("0"),
        json!("99999999"),
        json!("1000000000001"),
    ] {
        assert!(
            run(
                json!({"operation":"governance-prepare","network":hex(&[17;32]),"sequence":"2",
            "action":{"type":"propose-issuance-fee","amount_atoms":amount}})
            )
            .is_err()
        );
    }
}

fn governance_sign_command(prepared: &Value, role_index: usize) -> Vec<u8> {
    serde_json::to_vec(
        &json!({"operation":"governance-sign","request_hex":prepared["request_hex"],
        "confirmed_digest":prepared["messages"][role_index]["review_digest"]}),
    )
    .unwrap()
}

#[test]
fn headless_governance_signatures_bind_each_required_role_without_claiming_inclusion() {
    use siworld_native_node::eng2_operations::{public_bytes, sign_governance};
    for action in [
        json!({"type":"propose-issuance-fee","amount_atoms":"4000000000"}),
        json!({"type":"cancel-issuance-fee","proposal_sequence":"1"}),
        json!({"type":"propose-destination","target":"fund","member":0,"address_hex":address()}),
        json!({"type":"cancel-destination","proposal_sequence":"1"}),
        json!({"type":"rotate-owners","founder_hex":hex(&key(7)),"revocation_hex":hex(&key(8))}),
        json!({"type":"replace-checkpoint-signers","replacements":[{"slot":0,"key_hex":hex(&key(9))}]}),
        json!({"type":"cancel-joint","proposal_sequence":"1"}),
    ] {
        let prepared = run(
            json!({"operation":"governance-prepare","network":hex(&[17;32]),
            "sequence":"9007199254740993","action":action}),
        )
        .unwrap();
        let decoded =
            Action::decode_unsigned(&public_bytes(&prepared["request_hex"], 8192).unwrap())
                .unwrap();
        let mut signatures = Vec::new();
        if prepared["messages"].as_array().unwrap().len() == 2 {
            assert_ne!(
                prepared["messages"][0]["review_digest"],
                prepared["messages"][1]["review_digest"]
            );
            assert!(
                sign_governance(
                    &governance_sign_command(&prepared, 0),
                    [17; 32],
                    SignerRole::Revocation,
                    key(2),
                    zeroize::Zeroizing::new([2; 32])
                )
                .is_err()
            );
        }
        for (index, message) in prepared["messages"].as_array().unwrap().iter().enumerate() {
            let (role, seed) = match message["role"].as_str().unwrap() {
                "founder" => (SignerRole::Founder, 1),
                "revocation" => (SignerRole::Revocation, 2),
                _ => unreachable!(),
            };
            assert_eq!(
                public_bytes(&message["review_digest"], 32).unwrap().len(),
                32
            );
            let signed = sign_governance(
                &governance_sign_command(&prepared, index),
                [17; 32],
                role,
                key(seed),
                zeroize::Zeroizing::new([seed; 32]),
            )
            .unwrap();
            assert_eq!(signed["role"], message["role"]);
            assert_eq!(signed["authority_hex"], hex(&key(seed)));
            assert_eq!(signed["signature_verified"], true);
            assert_eq!(signed["chain_state_verified"], false);
            assert_eq!(signed["state_changed"], false);
            assert_eq!(signed["submitted"], false);
            let signature = public_bytes(&signed["signature_hex"], 3309)
                .unwrap()
                .try_into()
                .unwrap();
            ml_dsa_65::verify(
                &ml_dsa_65::MLDSA65VerificationKey::new(key(seed)),
                &decoded.signing_bytes(role).unwrap(),
                SIGNATURE_CONTEXT,
                &ml_dsa_65::MLDSA65Signature::new(signature),
            )
            .unwrap();
            assert!(
                ml_dsa_65::verify(
                    &ml_dsa_65::MLDSA65VerificationKey::new(key(seed)),
                    &decoded.signing_bytes(role).unwrap(),
                    siworld_native_node::eng2::fund_claim::SIGNATURE_CONTEXT,
                    &ml_dsa_65::MLDSA65Signature::new(signature)
                )
                .is_err()
            );
            signatures.push(json!({"role":signed["role"],"signature_hex":signed["signature_hex"]}));
        }
        let wrapped=run(json!({"operation":"governance-wrap","request_hex":prepared["request_hex"],"signatures":signatures})).unwrap();
        assert_eq!(wrapped["signature_verified"], false);
        assert_eq!(wrapped["submitted"], false);
        assert_eq!(
            SignedAction::decode(&public_bytes(&wrapped["signed_action_hex"], 16384).unwrap())
                .unwrap()
                .action,
            decoded
        );
    }
}

#[test]
fn headless_governance_rejects_wrong_context_role_identity_and_review() {
    use siworld_native_node::eng2_operations::sign_governance;
    let prepared = run(
        json!({"operation":"governance-prepare","network":hex(&[17;32]),"sequence":"1",
        "action":{"type":"propose-issuance-fee","amount_atoms":"4000000000"}}),
    )
    .unwrap();
    let bytes = governance_sign_command(&prepared, 0);
    for (network, role, authority, seed) in [
        ([18; 32], SignerRole::Founder, key(1), 1),
        ([17; 32], SignerRole::Revocation, key(2), 2),
        ([17; 32], SignerRole::Checkpoint(0), key(3), 3),
        ([17; 32], SignerRole::Founder, key(2), 1),
        ([17; 32], SignerRole::Founder, key(1), 2),
    ] {
        assert!(
            sign_governance(
                &bytes,
                network,
                role,
                authority,
                zeroize::Zeroizing::new([seed; 32])
            )
            .is_err()
        );
    }
    let mut wrong: Value = serde_json::from_slice(&bytes).unwrap();
    wrong["confirmed_digest"] = json!(hex(&[0; 32]));
    assert!(
        sign_governance(
            &serde_json::to_vec(&wrong).unwrap(),
            [17; 32],
            SignerRole::Founder,
            key(1),
            zeroize::Zeroizing::new([1; 32])
        )
        .is_err()
    );
    let mut changed = prepared.clone();
    let mut request =
        siworld_native_node::eng2_operations::public_bytes(&changed["request_hex"], 8192).unwrap();
    request[40] ^= 2;
    changed["request_hex"] = json!(hex(&request));
    assert!(
        sign_governance(
            &governance_sign_command(&changed, 0),
            [17; 32],
            SignerRole::Founder,
            key(1),
            zeroize::Zeroizing::new([1; 32])
        )
        .is_err()
    );
    let mut extra: Value = serde_json::from_slice(&bytes).unwrap();
    extra["seed"] = json!("rejected public field");
    assert!(
        sign_governance(
            &serde_json::to_vec(&extra).unwrap(),
            [17; 32],
            SignerRole::Founder,
            key(1),
            zeroize::Zeroizing::new([1; 32])
        )
        .is_err()
    );
}

#[test]
fn real_governance_cli_pipe_keeps_private_framing_and_fixed_errors() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let prepared = run(
        json!({"operation":"governance-prepare","network":hex(&[17;32]),"sequence":"1",
        "action":{"type":"propose-issuance-fee","amount_atoms":"4000000000"}}),
    )
    .unwrap();
    let public = governance_sign_command(&prepared, 0);
    for case in 0..5 {
        let mut framed = (public.len() as u32).to_be_bytes().to_vec();
        framed.extend(&public);
        framed.extend(if case == 3 { 31u32 } else { 32u32 }.to_be_bytes());
        framed.extend(if case == 2 { [2; 32] } else { [1; 32] });
        if case == 1 {
            framed.push(99);
        }
        let mut child = Command::new(env!("CARGO_BIN_EXE_siworld-eng2-operations"))
            .args([
                "--sign-governance-pipe",
                &hex(&[17; 32]),
                if case == 4 { "checkpoint-0" } else { "founder" },
                &hex(&key(1)),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let written = child.stdin.take().unwrap().write_all(&framed);
        if case == 0 {
            written.unwrap();
        }
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.success(), case == 0);
        assert!(output.stderr.is_empty());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(!text.contains(&hex(&[1; 32])));
        assert!(!text.contains(&hex(&[2; 32])));
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["ok"], case == 0);
        if case == 0 {
            assert_eq!(value["result"]["signature_verified"], true);
        } else {
            assert_eq!(value["error"], "public_operation_rejected");
        }
    }
}
