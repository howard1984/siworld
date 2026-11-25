//! Local engineering custody adapter; private authority bytes never leave it.
use super::*;
use crate::{
    eng2::fund_claim::{ENCODED_BYTES, PublicFundClaim},
    eng2_governance::{Action, SignerRole},
    eng2_operations::{self, MAX_INPUT_BYTES, public_bytes},
};

/// Independent public expectations, never inferred from the imported request.
#[derive(Clone, Copy)]
pub struct SigningPins {
    pub network: [u8; 32],
    pub purpose: Purpose,
    pub index: u8,
    pub authority_sha256: [u8; 32],
    pub request_sha256: [u8; 32],
}

/// Sign one reviewed public operation in process using an existing engineering
/// authority. No key generation, secret export, file write or submission occurs.
pub fn sign_operation(directory: &Path, request_path: &Path, pins: SigningPins) -> Result<Value> {
    pins.purpose.check(pins.index)?;
    let role = match pins.purpose {
        Purpose::Founder => Some(SignerRole::Founder),
        Purpose::Revocation => Some(SignerRole::Revocation),
        Purpose::FundClaim => None,
        _ => return Err("material purpose cannot sign this operation".into()),
    };
    if pins.network == [0; 32] || pins.authority_sha256 == [0; 32] || pins.request_sha256 == [0; 32]
    {
        return Err("independent signing pins are required".into());
    }
    let request = storage::read_public(request_path, MAX_INPUT_BYTES)?;
    if Sha256::digest(&request).as_slice() != pins.request_sha256 {
        return Err("reviewed public request digest differs".into());
    }
    let value: Value =
        serde_json::from_slice(&request).map_err(|_| "public signing request is invalid")?;
    let payload = if role.is_some() {
        let bytes = public_bytes(&value["request_hex"], 8192)?;
        if Action::decode_unsigned(&bytes)?.network != pins.network {
            return Err("public operation network differs".into());
        }
        bytes
    } else {
        let bytes = public_bytes(&value["claim_hex"], ENCODED_BYTES)?;
        let claim = PublicFundClaim::decode(&bytes)?;
        if claim.network != pins.network || claim.spend.account != pins.index {
            return Err("public claim network or member differs".into());
        }
        bytes
    };
    let custody = storage::Directory::open(directory)?;
    let pending = custody.read("pending.secret", PENDING_BYTES)?;
    if &pending[..8] != MAGIC
        || pending[8..40] != pins.network
        || pending[40] != pins.purpose as u8
        || pending[41] != pins.index
        || pending[74..] != blake3::derive_key(PENDING_CONTEXT, &pending[..74])
    {
        return Err("prepared signing context differs".into());
    }
    let seed = Zeroizing::new(
        <[u8; 32]>::try_from(&pending[42..74]).map_err(|_| "pending seed width invalid")?,
    );
    let (public, fingerprint) = public_parameters(
        pins.network,
        pins.purpose,
        pins.index,
        Zeroizing::new(*seed),
    )?;
    if *custody.read("public.json", public.len())? != public
        || fingerprint != crate::local::hex(&pins.authority_sha256)
    {
        return Err("prepared public signing authority differs".into());
    }
    let parameters: Value =
        serde_json::from_slice(&public).map_err(|_| "prepared public authority encoding failed")?;
    let authority = public_bytes(&parameters["public_key_hex"], 1952)?
        .try_into()
        .map_err(|_| "prepared public authority width differs")?;
    let signed = match role {
        Some(role) => {
            eng2_operations::sign_governance(&request, pins.network, role, authority, seed)?
        }
        None => eng2_operations::sign_claim(&request, pins.network, authority, seed)?,
    };
    let signature = if role.is_some() {
        signed["signature_hex"].clone()
    } else {
        let claim = PublicFundClaim::decode(&public_bytes(&signed["claim_hex"], ENCODED_BYTES)?)?;
        json!(crate::local::hex(&claim.spend.signature))
    };
    let mut result = receipt(
        pins.network,
        pins.purpose,
        pins.index,
        &public,
        &fingerprint,
        if role.is_some() {
            "sign-governance"
        } else {
            "sign-claim"
        },
    );
    result["public_request_sha256"] = json!(crate::local::hex(&pins.request_sha256));
    result["unsigned_payload_sha256"] = json!(sha(&payload));
    result["signature_hex"] = signature;
    result["review_digest"] = value["confirmed_digest"].clone();
    result["signature_verified"] = json!(true);
    result["chain_state_verified"] = json!(false);
    result["state_changed"] = json!(false);
    result["submitted"] = json!(false);
    if role.is_some() {
        result["role"] = json!(pins.purpose.name());
    } else {
        result["entitlement_verified"] = json!(false);
        result["recipient_current_state_verified"] = json!(false);
    }
    Ok(result)
}
