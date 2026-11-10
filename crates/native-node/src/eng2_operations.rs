//! Bounded public operation files for the separately activated local network.
//!
//! Preparation and detached signature assembly never authorize a state change.
//! The shared native block engine validates and atomically commits the candidate.
use crate::{
    eng2::{body::Body, fund_claim::PublicFundClaim},
    eng2_governance::{
        self as governance, Action, ActionKind, Authorization, DestinationTarget, SignedAction,
        SignerRole, SlotReplacement,
    },
    fund_spend::FundSpend,
    wire::Hash,
};
use native::{
    codec::{decode_digest, encode_digest},
    encryption::{EncryptionContext, encrypt_payment_with_opening},
    multi_asset::{Hasher, Note, SIP_ASSET_ID},
};
use serde_json::{Value, json};

pub mod projection;
pub mod records;

pub const MAX_INPUT_BYTES: usize = 1_400_000;
type Result<T> = std::result::Result<T, String>;
fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err("public operation input is invalid or noncanonical".into())
    }
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
pub fn public_bytes(value: &Value, maximum: usize) -> Result<Vec<u8>> {
    let text = value.as_str().ok_or("expected public hexadecimal bytes")?;
    require(!text.is_empty() && text.len() <= maximum * 2 && text.len().is_multiple_of(2))?;
    fn digit(byte: u8) -> Result<u8> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err("public bytes must use lowercase hexadecimal".into()),
        }
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok(digit(pair[0])? * 16 + digit(pair[1])?))
        .collect()
}
fn fixed<const N: usize>(value: &Value) -> Result<[u8; N]> {
    public_bytes(value, N)?
        .try_into()
        .map_err(|_| "public field has the wrong exact width".into())
}
fn fields(value: &Value, expected: &[&str]) -> Result<()> {
    let object = value
        .as_object()
        .ok_or("expected a public operation object")?;
    require(object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key)))
}
fn decimal(value: &Value) -> Result<u64> {
    let text = value
        .as_str()
        .ok_or("integer fields require canonical decimal strings")?;
    require(
        !text.is_empty()
            && text.len() <= 20
            && text.bytes().all(|x| x.is_ascii_digit())
            && (text.len() == 1 || !text.starts_with('0')),
    )?;
    text.parse()
        .map_err(|_| "public decimal integer exceeds its bound".into())
}
fn network(value: &Value) -> Result<Hash> {
    let value = fixed(value)?;
    require(value != [0; 32])?;
    Ok(value)
}
fn member(value: &Value) -> Result<u8> {
    let member = value.as_u64().ok_or("expected a bounded fund member")?;
    require(member < governance::MAX_FUND_MEMBERS as u64)?;
    Ok(member as u8)
}
fn canonical(input: &[u8]) -> Result<Value> {
    require(!input.is_empty() && input.len() <= MAX_INPUT_BYTES)?;
    let value: Value =
        serde_json::from_slice(input).map_err(|_| "invalid public operation JSON")?;
    require(serde_json::to_vec(&value).map_err(|_| "cannot encode public operation")? == input)?;
    Ok(value)
}

/// Unauthenticated inputs; these are not admission or execution capabilities.
pub struct PendingOperations {
    network: Hash,
    height: u64,
    claims: Vec<PublicFundClaim>,
    actions: Vec<SignedAction>,
}
impl PendingOperations {
    pub fn decode(input: &[u8], expected_network: Hash, expected_height: u64) -> Result<Self> {
        let value = canonical(input)?;
        fields(
            &value,
            &["version", "network", "height", "fund_claims", "governance"],
        )?;
        require(
            value["version"].as_u64() == Some(1)
                && network(&value["network"])? == expected_network
                && decimal(&value["height"])? == expected_height
                && expected_height > 0,
        )?;
        let claims = value["fund_claims"]
            .as_array()
            .ok_or("expected public fund claim list")?;
        let actions = value["governance"]
            .as_array()
            .ok_or("expected public governance list")?;
        require(
            claims.len() <= crate::wire::MAX_FUND_SPENDS
                && actions.len() <= governance::MAX_ACTIONS_PER_BLOCK,
        )?;
        let claims = claims
            .iter()
            .map(|claim| {
                PublicFundClaim::decode(&public_bytes(
                    claim,
                    crate::eng2::fund_claim::ENCODED_BYTES,
                )?)
            })
            .collect::<Result<Vec<_>>>()?;
        let actions = actions
            .iter()
            .map(|action| SignedAction::decode(&public_bytes(action, 16384)?))
            .collect::<Result<Vec<_>>>()?;
        require(
            claims
                .iter()
                .all(|claim| claim.network == expected_network && claim.height == expected_height)
                && claims
                    .windows(2)
                    .all(|pair| pair[0].spend.account < pair[1].spend.account)
                && actions
                    .iter()
                    .all(|action| action.action.network == expected_network)
                && actions
                    .windows(2)
                    .all(|pair| pair[0].action.sequence < pair[1].action.sequence),
        )?;
        Ok(Self {
            network: expected_network,
            height: expected_height,
            claims,
            actions,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&json!({"version":1,"network":hex(&self.network),"height":self.height.to_string(),
            "fund_claims":self.claims.iter().map(|claim|hex(&claim.encode())).collect::<Vec<_>>(),
            "governance":self.actions.iter().map(|action|action.encode().map(|bytes|hex(&bytes))).collect::<Result<Vec<_>>>()?}))
            .map_err(|_|"cannot encode public operation bundle".into())
    }
    /// Fill only an empty, matching candidate body. Signature checks, proof
    /// verification, ledger debits, state adoption and records belong to engine.
    pub fn attach_to(self, body: &mut Body) -> Result<()> {
        require(
            body.network == self.network
                && body.height == self.height
                && body.fund_claims.is_empty()
                && body.governance.is_empty(),
        )?;
        body.fund_claims = self.claims;
        body.governance = self.actions;
        Ok(())
    }
}

fn claim_prepare(value: &Value) -> Result<Value> {
    fields(
        value,
        &[
            "operation",
            "network",
            "height",
            "member",
            "amount_atoms",
            "counter",
            "destination_hex",
            "authority_hex",
            "rseed_hex",
        ],
    )?;
    let network = network(&value["network"])?;
    let height = decimal(&value["height"])?;
    let amount = decimal(&value["amount_atoms"])?;
    require(height > 0 && amount > 0)?;
    let account = member(&value["member"])?;
    let counter = decimal(&value["counter"])?;
    let address = governance::decode_address(&public_bytes(
        &value["destination_hex"],
        governance::ADDRESS_BYTES,
    )?)?;
    let authority = fixed(&value["authority_hex"])?;
    require(authority != [0; crate::fund_spend::VERIFYING_KEY_BYTES])?;
    let note = Note {
        asset_id: SIP_ASSET_ID,
        owner: address.owner(),
        value: amount,
        unlock_height: 0,
        rho: crate::fund_spend::canonical_rho(network, account, counter),
        rseed: decode_digest(&fixed(&value["rseed_hex"])?)
            .map_err(|_| "noncanonical public note randomness")?,
    };
    let (payment, opening) =
        encrypt_payment_with_opening(&address, &note, &EncryptionContext::new(network))
            .map_err(|_| "could not encrypt the public fund note")?;
    let mut ciphertext = [0; 1313];
    ciphertext[..1088].copy_from_slice(&payment.kem_ciphertext);
    ciphertext[1088..1296].copy_from_slice(&payment.body);
    ciphertext[1296..1312].copy_from_slice(&payment.tag);
    ciphertext[1312] = payment.view_tag;
    let claim = PublicFundClaim {
        network,
        height,
        spend: FundSpend {
            account,
            counter,
            amount,
            owner: encode_digest(&note.owner),
            rho: encode_digest(&note.rho),
            rseed: encode_digest(&note.rseed),
            commitment: encode_digest(&Hasher::new().note_cm(&note)),
            ciphertext,
            verifying_key: authority,
            signature: [0; crate::fund_spend::SIGNATURE_BYTES],
        },
        encapsulation_coins: *opening.expose_encapsulation_coins(),
    };
    Ok(
        json!({"claim_hex":hex(&claim.encode()),"signing_message_hex":hex(&claim.signing_message()),
        "signature_context_hex":hex(crate::eng2::fund_claim::SIGNATURE_CONTEXT),"review_digest":hex(&claim_review_digest(&claim)),"signature_verified":false,
        "entitlement_verified":false,"recipient_current_state_verified":false,"state_changed":false,"submitted":false}),
    )
}
fn claim_attach(value: &Value) -> Result<Value> {
    fields(
        value,
        &["operation", "claim_hex", "authority_hex", "signature_hex"],
    )?;
    let mut claim = PublicFundClaim::decode(&public_bytes(
        &value["claim_hex"],
        crate::eng2::fund_claim::ENCODED_BYTES,
    )?)?;
    require(claim.spend.signature == [0; crate::fund_spend::SIGNATURE_BYTES])?;
    let authority = fixed(&value["authority_hex"])?;
    claim.spend.signature = fixed(&value["signature_hex"])?;
    claim.spend.verify_signed_message(
        claim.network,
        &authority,
        &claim.signing_message(),
        crate::eng2::fund_claim::SIGNATURE_CONTEXT,
    )?;
    Ok(
        json!({"claim_hex":hex(&claim.encode()),"signature_verified":true,"entitlement_verified":false,
        "recipient_current_state_verified":false,"state_changed":false,"submitted":false}),
    )
}
fn governance_roles(kind: &ActionKind) -> Vec<(&'static str, SignerRole)> {
    match kind {
        ActionKind::ProposeDestination { .. } | ActionKind::ProposeIssuanceFee { .. } => {
            vec![("founder", SignerRole::Founder)]
        }
        ActionKind::CancelDestination { .. } | ActionKind::CancelIssuanceFee { .. } => {
            vec![("revocation", SignerRole::Revocation)]
        }
        _ => vec![
            ("founder", SignerRole::Founder),
            ("revocation", SignerRole::Revocation),
        ],
    }
}
fn governance_review_digest(action: &Action, role: SignerRole) -> Result<Hash> {
    Ok(blake3::derive_key(
        "siworld eng2 governance action role review v1",
        &action.signing_bytes(role)?,
    ))
}
fn governance_prepare(value: &Value) -> Result<Value> {
    fields(value, &["operation", "network", "sequence", "action"])?;
    let input = &value["action"];
    let kind = match input["type"].as_str().ok_or("missing governance type")? {
        "propose-issuance-fee" => {
            fields(input, &["type", "amount_atoms"])?;
            ActionKind::ProposeIssuanceFee {
                amount_atoms: decimal(&input["amount_atoms"])?,
            }
        }
        "cancel-issuance-fee" => {
            fields(input, &["type", "proposal_sequence"])?;
            ActionKind::CancelIssuanceFee {
                proposal_sequence: decimal(&input["proposal_sequence"])?,
            }
        }
        "cancel-destination" => {
            fields(input, &["type", "proposal_sequence"])?;
            ActionKind::CancelDestination {
                proposal_sequence: decimal(&input["proposal_sequence"])?,
            }
        }
        "cancel-joint" => {
            fields(input, &["type", "proposal_sequence"])?;
            ActionKind::CancelJointChange {
                proposal_sequence: decimal(&input["proposal_sequence"])?,
            }
        }
        "rotate-owners" => {
            fields(input, &["type", "founder_hex", "revocation_hex"])?;
            ActionKind::RotateOwnerKeys {
                founder: Box::new(fixed(&input["founder_hex"])?),
                revocation: Box::new(fixed(&input["revocation_hex"])?),
            }
        }
        "propose-destination" => {
            let target = match input["target"].as_str() {
                Some("fees") => {
                    fields(input, &["type", "target", "address_hex"])?;
                    DestinationTarget::Fees
                }
                Some("fund") => {
                    fields(input, &["type", "target", "member", "address_hex"])?;
                    DestinationTarget::FundMember(member(&input["member"])?)
                }
                _ => return Err("unknown governance destination target".into()),
            };
            ActionKind::ProposeDestination {
                target,
                address: Box::new(fixed(&input["address_hex"])?),
            }
        }
        "replace-checkpoint-signers" => {
            fields(input, &["type", "replacements"])?;
            let entries = input["replacements"]
                .as_array()
                .ok_or("expected replacement slots")?;
            require(!entries.is_empty() && entries.len() <= 3)?;
            let replacements = entries
                .iter()
                .map(|entry| {
                    fields(entry, &["slot", "key_hex"])?;
                    let slot = entry["slot"].as_u64().ok_or("invalid fixed signer slot")?;
                    require(slot < 3)?;
                    Ok(SlotReplacement {
                        slot: slot as u8,
                        key: fixed(&entry["key_hex"])?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            ActionKind::ReplaceCheckpointSigners { replacements }
        }
        _ => return Err("unsupported governance action type".into()),
    };
    let action = Action {
        network: network(&value["network"])?,
        sequence: decimal(&value["sequence"])?,
        kind,
    };
    let bytes = action.unsigned_bytes()?;
    Action::decode_unsigned(&bytes)?;
    let roles = governance_roles(&action.kind);
    let delay = match action.kind {
        ActionKind::ReplaceCheckpointSigners { .. } => governance::ROSTER_DELAY_BLOCKS,
        ActionKind::CancelDestination { .. }
        | ActionKind::CancelJointChange { .. }
        | ActionKind::CancelIssuanceFee { .. } => 0,
        _ => governance::OWNER_DELAY_BLOCKS,
    };
    Ok(
        json!({"request_hex":hex(&bytes),"sequence":action.sequence.to_string(),"required_roles":roles.iter().map(|(name,_)|*name).collect::<Vec<_>>(),
        "messages":roles.iter().map(|(name,role)|Ok(json!({"role":name,"message_hex":hex(&action.signing_bytes(*role)?),"review_digest":hex(&governance_review_digest(&action,*role)?)}))).collect::<Result<Vec<_>>>()?,
        "signature_context_hex":hex(governance::SIGNATURE_CONTEXT),"activation_delay_blocks":delay,
        "chain_state_verified":false,"state_changed":false,"submitted":false}),
    )
}
fn governance_wrap(value: &Value) -> Result<Value> {
    fields(value, &["operation", "request_hex", "signatures"])?;
    let action = Action::decode_unsigned(&public_bytes(&value["request_hex"], 8192)?)?;
    let input = value["signatures"]
        .as_array()
        .ok_or("expected public signatures")?;
    require(!input.is_empty() && input.len() <= 2)?;
    let signatures = input
        .iter()
        .map(|item| {
            fields(item, &["role", "signature_hex"])?;
            let role = match item["role"].as_str() {
                Some("founder") => SignerRole::Founder,
                Some("revocation") => SignerRole::Revocation,
                _ => return Err("unknown management role".into()),
            };
            Ok(Authorization {
                role,
                signature: fixed(&item["signature_hex"])?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let signed = SignedAction { action, signatures };
    let bytes = signed.encode()?;
    SignedAction::decode(&bytes)?;
    Ok(
        json!({"signed_action_hex":hex(&bytes),"signature_verified":false,"chain_state_verified":false,"state_changed":false,"submitted":false}),
    )
}
/// Canonical public commands only. No private keys, network, node operation or
/// file writes are accepted. A bundle must enter the real shared block engine.
pub fn execute(input: &[u8]) -> Result<Value> {
    let value = canonical(input)?;
    match value["operation"].as_str() {
        Some("claim-prepare") => claim_prepare(&value),
        Some("claim-attach") => claim_attach(&value),
        Some("governance-prepare") => governance_prepare(&value),
        Some("governance-wrap") => governance_wrap(&value),
        Some("bundle-check") => {
            fields(&value, &["operation", "network", "height", "bundle"])?;
            let bundle = PendingOperations::decode(
                &serde_json::to_vec(&value["bundle"]).map_err(|_| "invalid public bundle")?,
                network(&value["network"])?,
                decimal(&value["height"])?,
            )?;
            Ok(
                json!({"bundle":serde_json::from_slice::<Value>(&bundle.encode()?).map_err(|_|"invalid public bundle")?,"signature_verified":false,"state_changed":false,"submitted":false}),
            )
        }
        _ => Err("unsupported public operation".into()),
    }
}

fn claim_review_digest(claim: &PublicFundClaim) -> Hash {
    blake3::derive_key(
        "siworld eng2 public fund claim review v1",
        &claim.signing_message(),
    )
}
/// Internal local-rehearsal signer. The independently selected public identity
/// is separate from the imported request; the seed is separate private input.
/// This is not an encrypted key store or a production custody adapter.
pub fn sign_claim(
    input: &[u8],
    expected_network: Hash,
    expected_authority: [u8; crate::fund_spend::VERIFYING_KEY_BYTES],
    seed: zeroize::Zeroizing<[u8; 32]>,
) -> Result<Value> {
    let value = canonical(input)?;
    fields(&value, &["operation", "claim_hex", "confirmed_digest"])?;
    require(
        value["operation"] == "claim-sign"
            && expected_network != [0; 32]
            && expected_authority != [0; crate::fund_spend::VERIFYING_KEY_BYTES],
    )?;
    let mut claim = PublicFundClaim::decode(&public_bytes(
        &value["claim_hex"],
        crate::eng2::fund_claim::ENCODED_BYTES,
    )?)?;
    require(
        claim.network == expected_network
            && claim.spend.verifying_key == expected_authority
            && claim.spend.signature == [0; crate::fund_spend::SIGNATURE_BYTES]
            && fixed::<32>(&value["confirmed_digest"])? == claim_review_digest(&claim),
    )?;
    claim.spend.signature = sign_local(
        seed,
        expected_authority,
        &claim.signing_message(),
        crate::eng2::fund_claim::SIGNATURE_CONTEXT,
    )?;
    claim.spend.verify_signed_message(
        expected_network,
        &expected_authority,
        &claim.signing_message(),
        crate::eng2::fund_claim::SIGNATURE_CONTEXT,
    )?;
    Ok(
        json!({"claim_hex":hex(&claim.encode()),"signature_verified":true,"entitlement_verified":false,
        "recipient_current_state_verified":false,"state_changed":false,"submitted":false}),
    )
}

// The private frame selects an already existing local-rehearsal identity. Its
// expected public key is supplied independently of the imported public request.
fn sign_local(
    seed: zeroize::Zeroizing<[u8; 32]>,
    expected_authority: [u8; governance::PUBLIC_KEY_BYTES],
    message: &[u8],
    context: &[u8],
) -> Result<[u8; governance::SIGNATURE_BYTES]> {
    use libcrux_ml_dsa::ml_dsa_65;
    use zeroize::{Zeroize, Zeroizing};
    struct Key(ml_dsa_65::MLDSA65SigningKey);
    impl Drop for Key {
        fn drop(&mut self) {
            self.0.as_mut_slice().zeroize();
        }
    }
    let pair = ml_dsa_65::generate_key_pair(*seed);
    let key = Key(pair.signing_key);
    require(*pair.verification_key.as_ref() == expected_authority)?;
    let mut randomness = Zeroizing::new([0; 32]);
    getrandom::fill(randomness.as_mut())
        .map_err(|_| "local operation signing entropy unavailable")?;
    Ok(*ml_dsa_65::sign(&key.0, message, context, *randomness)
        .map_err(|_| "local operation signing failed")?
        .as_ref())
}
/// Headless local-rehearsal signing, not production custody or chain admission.
/// The review digest binds the full action and role. The independently selected
/// public key is checked against the private frame; current owner authority and
/// inclusion remain the responsibility of the shared native block engine.
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
    require(
        value["operation"] == "governance-sign"
            && expected_network != [0; 32]
            && expected_authority != [0; governance::PUBLIC_KEY_BYTES],
    )?;
    let action = Action::decode_unsigned(&public_bytes(&value["request_hex"], 8192)?)?;
    let roles = governance_roles(&action.kind);
    let (name, role) = roles
        .iter()
        .find(|(_, role)| *role == expected_role)
        .ok_or("selected owner role cannot authorize this action")?;
    let digest = governance_review_digest(&action, *role)?;
    require(
        action.network == expected_network && fixed::<32>(&value["confirmed_digest"])? == digest,
    )?;
    let message = action.signing_bytes(*role)?;
    let signature = sign_local(
        seed,
        expected_authority,
        &message,
        governance::SIGNATURE_CONTEXT,
    )?;
    ml_dsa_65::verify(
        &ml_dsa_65::MLDSA65VerificationKey::new(expected_authority),
        &message,
        governance::SIGNATURE_CONTEXT,
        &ml_dsa_65::MLDSA65Signature::new(signature),
    )
    .map_err(|_| "local governance signature verification failed")?;
    Ok(
        json!({"request_hex":hex(&action.unsigned_bytes()?),"role":name,"authority_hex":hex(&expected_authority),
        "signature_hex":hex(&signature),"review_digest":hex(&digest),"signature_verified":true,
        "chain_state_verified":false,"state_changed":false,"submitted":false}),
    )
}
