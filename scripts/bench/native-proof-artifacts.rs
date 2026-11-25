//! Reproduce public native relation keys without generating transaction proofs.
use p3_air::BaseAir;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use siworld_multi_asset_experiment::{
    FriParams,
    issuance_air::{IssuanceAir, IssuanceProver},
    multi_asset_transaction::TransactionProver,
    security::{instance_report, params_json, settlement_report, transaction_report},
    settlement::SettlementProver,
};

fn legacy_params(kind: &str) -> Result<FriParams, String> {
    let (log_blowup, num_queries) = match kind {
        "transaction" => (7, 41),
        "settlement" | "issuance" => (8, 36),
        _ => return Err("unknown native relation".into()),
    };
    Ok(FriParams {
        log_blowup,
        num_queries,
        query_pow_bits: 20,
        commit_pow_bits: 0,
        batch_pow_bits: 20,
        max_log_arity: 1,
    })
}

/// A historical profile retains its original reproduction parameters. Revised
/// profiles select every relation from the independently validated measurements.
fn parameters_from_profile(kind: &str, profile: &Value) -> Result<FriParams, String> {
    if !["transaction", "settlement", "issuance"].contains(&kind) {
        return Err("unknown native relation".into());
    }
    if profile["schema"].as_u64() == Some(1) {
        return legacy_params(kind);
    }
    if profile["schema"].as_u64() != Some(2)
        || profile["status"] != "engineering-frozen"
        || profile["relation_revision"] != "native-v1-economics-1"
        || profile["cryptographic_approval"] != false
        || profile["network_activation"] != false
        || profile["acceptance"] != false
    {
        return Err("unsupported frozen native profile identity".into());
    }
    let value = if kind == "transaction" {
        &profile["parameters"]
    } else {
        &profile["repeated_measurements"][kind]["parameters"]
    };
    let object = value
        .as_object()
        .ok_or("missing frozen native parameters")?;
    if object.len() != 7 {
        return Err("incomplete frozen native parameters".into());
    }
    let field = |name: &str| -> Result<u32, String> {
        value[name]
            .as_u64()
            .and_then(|number| u32::try_from(number).ok())
            .ok_or_else(|| format!("invalid frozen native parameter: {name}"))
    };
    let p = FriParams {
        log_blowup: field("log_blowup")?,
        num_queries: field("num_queries")?,
        query_pow_bits: field("query_pow_bits")?,
        commit_pow_bits: field("commit_pow_bits")?,
        batch_pow_bits: field("batch_pow_bits")?,
        max_log_arity: field("max_log_arity")?,
    };
    if !(5..=8).contains(&p.log_blowup)
        || !(1..=128).contains(&p.num_queries)
        || ![20, 24].contains(&p.query_pow_bits)
        || p.batch_pow_bits != p.query_pow_bits
        || p.commit_pow_bits != 0
        || p.max_log_arity != 1
        || field("log_final_poly_len")? != 0
    {
        return Err("unsupported frozen native parameter coordinate".into());
    }
    Ok(p)
}

fn params(kind: &str) -> Result<FriParams, String> {
    let profile: Value = serde_json::from_str(include_str!(
        "../../crates/bench-multi-asset/artifacts/v1-transaction-profile.json"
    ))
    .map_err(|_| "invalid frozen transaction profile".to_owned())?;
    parameters_from_profile(kind, &profile)
}

// These offline artifact bytes identify a fixed native relation. They are not
// an activated block/transaction wire format or a peer-supplied verifier key.
fn encode_key(
    kind: u8,
    capacity: u32,
    p: FriParams,
    width: usize,
    degree: usize,
    commitment: &[u8],
) -> Result<Vec<u8>, String> {
    if !(1..=3).contains(&kind) || commitment.is_empty() || commitment.len() > 4096 {
        return Err("invalid native public-key shape".into());
    }
    let mut out = b"SWMP\x01\x00".to_vec();
    out.push(kind);
    out.extend_from_slice(&capacity.to_le_bytes());
    for word in [
        p.log_blowup,
        p.num_queries,
        p.query_pow_bits,
        p.commit_pow_bits,
        p.batch_pow_bits,
        p.max_log_arity,
    ] {
        out.extend_from_slice(&word.to_le_bytes());
    }
    for word in [width, degree, commitment.len()] {
        out.extend_from_slice(
            &u32::try_from(word)
                .map_err(|_| "key dimension overflow")?
                .to_le_bytes(),
        );
    }
    out.extend_from_slice(commitment);
    Ok(out)
}

fn bundle(kind: &str, p: FriParams) -> Result<Value, String> {
    let security = match kind {
        "transaction" => transaction_report(p)?,
        "settlement" => settlement_report(p)?,
        "issuance" => {
            let air = IssuanceAir::new(3).with_min_height(p.hiding_min_height());
            instance_report(&air, air.height, p)?
        }
        _ => return Err("unknown native relation".into()),
    };
    if security["screen"]["passes_selected_model"] != true {
        return Err("native relation fails the selected security screen".into());
    }
    let (id, capacity, width, degree, commitment) = match kind {
        "transaction" => {
            let prover = TransactionProver::new(p);
            if prover.vk.width != prover.air.preprocessed_width() {
                return Err("transaction preprocessing width mismatch".into());
            }
            (
                1,
                0,
                prover.vk.width,
                prover.vk.degree_bits,
                postcard::to_allocvec(&prover.vk.commitment).map_err(|e| e.to_string())?,
            )
        }
        "settlement" => {
            let prover = SettlementProver::new(576, p);
            (
                2,
                576,
                prover.vk.width,
                prover.vk.degree_bits,
                postcard::to_allocvec(&prover.vk.commitment).map_err(|e| e.to_string())?,
            )
        }
        "issuance" => {
            let prover = IssuanceProver::new(3, p);
            (
                3,
                3,
                prover.vk.width,
                prover.vk.degree_bits,
                postcard::to_allocvec(&prover.vk.commitment).map_err(|e| e.to_string())?,
            )
        }
        _ => return Err("unknown native relation".into()),
    };
    let bytes = encode_key(id, capacity, p, width, degree, &commitment)?;
    Ok(
        json!({"kind":kind,"capacity":capacity,"parameters":params_json(p),
        "security":security,"public_verifier_key":{"encoding":"SWMP-v1",
        "hex":bytes.iter().map(|b|format!("{b:02x}")).collect::<String>(),
        "sha256":format!("{:x}",Sha256::digest(&bytes)),"width":width,"degree_bits":degree},
        "cryptographic_approval":false,"network_activation":false}),
    )
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let (kind, output, parameters, candidate) = match args.as_slice() {
        [kind, output] => (kind, output, params(kind)?, false),
        [mode, kind, b, q, g, output] if mode == "--candidate" => {
            let parse = |value: &String| value.parse::<u32>().map_err(|_| "invalid candidate integer".to_owned());
            let (b, q, g) = (parse(b)?, parse(q)?, parse(g)?);
            if !(5..=8).contains(&b) || !(1..=128).contains(&q) || ![20, 24].contains(&g) {
                return Err("unsupported candidate coordinate".into());
            }
            (kind, output, FriParams { log_blowup: b, num_queries: q,
                query_pow_bits: g, commit_pow_bits: 0, batch_pow_bits: g, max_log_arity: 1 }, true)
        }
        _ => return Err("usage: native-proof-artifacts KIND OUTPUT | --candidate KIND BLOWUP QUERIES GRINDING OUTPUT".into()),
    };
    let mut result = bundle(kind, parameters)?;
    if candidate {
        result["status"] = json!("candidate-pending-review");
        result["acceptance"] = json!(false);
    }
    let mut bytes = serde_json::to_vec_pretty(&result).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    use std::io::Write;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|e| e.to_string())?
        .write_all(&bytes)
        .map_err(|e| e.to_string())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_candidate_relation_is_rejected_before_setup() {
        assert_eq!(
            bundle("peer-defined", params("transaction").unwrap()).unwrap_err(),
            "unknown native relation"
        );
    }

    fn revised_profile() -> Value {
        let parameters = json!({"log_blowup":6,"num_queries":53,"query_pow_bits":24,
            "commit_pow_bits":0,"batch_pow_bits":24,"max_log_arity":1,"log_final_poly_len":0});
        let related = params_json(legacy_params("settlement").unwrap());
        json!({"schema":2,"status":"engineering-frozen","relation_revision":"native-v1-economics-1",
            "cryptographic_approval":false,"network_activation":false,"acceptance":false,
            "parameters":parameters,"repeated_measurements":{
                "settlement":{"parameters":related},"issuance":{"parameters":related}}})
    }

    #[test]
    fn revised_reproduction_uses_the_measured_selected_profile() {
        let profile = revised_profile();
        let transaction = parameters_from_profile("transaction", &profile).unwrap();
        assert_eq!(transaction.log_blowup, 6);
        assert_eq!(transaction.num_queries, 53);
        assert_eq!(transaction.query_pow_bits, 24);
        for kind in ["settlement", "issuance"] {
            assert_eq!(
                parameters_from_profile(kind, &profile).unwrap().log_blowup,
                8
            );
        }
        assert_eq!(
            parameters_from_profile("transaction", &json!({"schema":1}))
                .unwrap()
                .log_blowup,
            7
        );
    }

    #[test]
    fn revised_reproduction_rejects_unreviewed_identity_and_invalid_fri_fields() {
        for field in [
            "schema",
            "status",
            "relation_revision",
            "cryptographic_approval",
            "acceptance",
        ] {
            let mut invalid = revised_profile();
            invalid[field] = json!(true);
            assert!(
                parameters_from_profile("transaction", &invalid).is_err(),
                "{field}"
            );
        }
        for field in [
            "log_blowup",
            "num_queries",
            "query_pow_bits",
            "commit_pow_bits",
            "batch_pow_bits",
            "max_log_arity",
            "log_final_poly_len",
        ] {
            let mut invalid = revised_profile();
            invalid["parameters"][field] = json!(true);
            assert!(
                parameters_from_profile("transaction", &invalid).is_err(),
                "{field}"
            );
        }
        let mut invalid = revised_profile();
        invalid["parameters"]["batch_pow_bits"] = json!(20);
        assert!(parameters_from_profile("transaction", &invalid).is_err());
        assert!(parameters_from_profile("peer-defined", &revised_profile()).is_err());
    }

    #[test]
    fn relation_kind_capacity_and_all_fri_fields_are_bound() {
        let p = params("settlement").unwrap();
        let original = encode_key(2, 576, p, 587, 11, &[1, 2]).unwrap();
        assert_ne!(original, encode_key(3, 576, p, 587, 11, &[1, 2]).unwrap());
        assert_ne!(original, encode_key(2, 575, p, 587, 11, &[1, 2]).unwrap());
        let mut changed = p;
        changed.batch_pow_bits += 1;
        assert_ne!(
            original,
            encode_key(2, 576, changed, 587, 11, &[1, 2]).unwrap()
        );
        assert!(encode_key(0, 576, p, 587, 11, &[1, 2]).is_err());
        assert!(encode_key(2, 576, p, 587, 11, &[]).is_err());
        assert!(params("peer-defined").is_err());
    }
}
