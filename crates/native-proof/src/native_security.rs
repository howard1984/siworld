//! Actual native V1 transaction and fixed-capacity settlement security screens.
//! Raw pinned p3-security terms and the selected external quantum ledger remain
//! separate. Passing this screen is not an independent cryptographic approval.
use crate::{
    Cfg, FriParams, common::F, fee_settlement_air::SettlementAir, transaction::TransactionAir,
};
use p3_air::{
    Air,
    symbolic::{AirLayout, SymbolicAirBuilder},
};
use p3_commit::Pcs;
use p3_matrix::Matrix;
use p3_security::{
    GrindingSites, InstanceShape, RegimeReport, StarkAirParams,
    fri::{self, FriRegime},
    report::Regime,
    stark::{conjectured_security_report, proven_security_report},
};
use p3_uni_stark::{OpeningShape, StarkGenericConfig};
use serde_json::{Value, json};
type EF = <Cfg as StarkGenericConfig>::Challenge;
const ACCOUNTING: &str = "single-proof-johnson-halving-bht-v1";

pub fn transaction_report(p: FriParams) -> Result<Value, String> {
    let air = TransactionAir::new().with_min_height(p.hiding_min_height());
    report(&air, air.slot.height, p)
}
pub fn settlement_report(p: FriParams) -> Result<Value, String> {
    let air = SettlementAir::new(576).with_min_height(p.hiding_min_height());
    report(&air, air.height, p)
}
pub fn application_binding() -> Value {
    json!({"algorithm":"BLAKE3-256","digest_bytes":32,
        "nominal_classical_collision_bits":128,
        "nominal_bht_collision_bits":256. / 3.,
        "included_in_p3_security_report":false,
        "model_status":"nominal-collision-model-requires-review"})
}

fn number(value: f64) -> Value {
    if value == f64::INFINITY {
        json!("positive_infinity")
    } else {
        assert!(value.is_finite());
        json!(value)
    }
}

fn union(values: impl Iterator<Item = f64>) -> f64 {
    let values: Vec<_> = values.filter(|v| v.is_finite()).collect();
    let m = values.iter().copied().fold(f64::INFINITY, f64::min);
    m - values.iter().map(|v| (m - v).exp2()).sum::<f64>().log2()
}

fn breakdown(report: &RegimeReport) -> Value {
    json!({"regime":format!("{:?}",report.regime),
        "minimum_term_bits":number(report.security_bits()),
        "weakest_term":report.binding().label,
        "terms":report.terms().iter().map(|t|json!({"label":t.label,
            "bits":number(t.bits.bits())})).collect::<Vec<_>>()})
}

pub fn params_json(p: FriParams) -> Value {
    json!({"log_blowup":p.log_blowup,"num_queries":p.num_queries,
        "query_pow_bits":p.query_pow_bits,"commit_pow_bits":p.commit_pow_bits,
        "batch_pow_bits":p.batch_pow_bits,"max_log_arity":p.max_log_arity,
        "log_final_poly_len":0})
}
/// Extract symbolic dimensions directly from each actual AIR. No preprocessing
/// commitment, key generation, proof or recursive circuit is built here.
fn report<A>(air: &A, base_trace_rows: usize, p: FriParams) -> Result<Value, String>
where
    A: Air<SymbolicAirBuilder<F, EF>>,
{
    if !base_trace_rows.is_power_of_two()
        || air
            .preprocessed_trace()
            .ok_or("missing preprocessing")?
            .height()
            != base_trace_rows
    {
        return Err("inconsistent actual AIR trace shape".into());
    }
    let cfg = p.config();
    let mut layout = AirLayout::from_air(air);
    layout.preprocessed_width = air.preprocessed_width();
    let domain = <<Cfg as StarkGenericConfig>::Pcs as Pcs<
        EF,
        <Cfg as StarkGenericConfig>::Challenger,
    >>::natural_domain_for_degree(cfg.pcs(), base_trace_rows);
    let a = StarkAirParams::from_air::<F, EF, _>(air, layout, domain, 2, true);
    let functions = p3_uni_stark::num_batched_openings(
        layout.main_width,
        !air.main_next_row_columns().is_empty(),
        layout.preprocessed_width,
        !air.preprocessed_next_row_columns().is_empty(),
        a.num_quotient_chunks,
        8,
        OpeningShape::hiding(8),
    );
    let shape = InstanceShape {
        log_trace_length: base_trace_rows.ilog2() as usize + cfg.is_zk(),
        modulus_bits: 247,
        collision_resistance: 185,
        num_batched_functions: functions,
    };
    let fri = FriRegime {
        log_blowup: p.log_blowup as usize,
        num_queries: p.num_queries as usize,
        log_final_poly_len: 0,
        max_log_arity: p.max_log_arity as usize,
        commit_pow_bits: p.commit_pow_bits as usize,
        query_pow_bits: p.query_pow_bits as usize,
    };
    let grinding = GrindingSites {
        out_of_domain: cfg.ood_proof_of_work_bits(),
        lookup_challenge: cfg.lookup_proof_of_work_bits(),
        batch_combination: p.batch_pow_bits as usize,
    };
    let conjectured = conjectured_security_report(&fri, &a, &shape, &[], &grinding);
    let proven = proven_security_report(&fri, &a, &shape, &[], &grinding);
    let johnson = proven.ldr.as_ref().ok_or("no Johnson report")?;
    let m = match johnson.regime {
        Regime::ListDecoding { m } => m,
        _ => return Err("Johnson report has another regime".into()),
    };
    let folding = fri::commit_phase_error_ldr_m(&fri, &shape, m)
        .ok_or("no FRI folding bound")?
        .bits();
    let query = fri::query_phase_error(
        p3_security::proximity::alpha_ldr_m(fri.log_blowup, m),
        fri.num_queries,
        fri.query_pow_bits,
    )
    .bits();
    let folds = shape.log_trace_length + 1;
    let raw = |label| {
        johnson
            .terms()
            .iter()
            .find(|t| t.label == label)
            .map(|t| t.bits.bits())
            .expect("required Johnson term")
    };
    let mut quantum: Vec<_> = johnson
        .terms()
        .iter()
        .filter(|t| !matches!(t.label, "commitment-collision" | "low-degree-test"))
        .map(|t| t.bits.bits() / 2.)
        .collect();
    quantum.push(query / 2.);
    quantum.push(folding / 2. - (folds as f64).log2());
    let q_union = union(quantum.into_iter());
    let conjectured_union = union(conjectured.terms().iter().map(|t| t.bits.bits()));
    let johnson_union = union(johnson.terms().iter().map(|t| t.bits.bits()));
    let bht = raw("commitment-collision") * 2. / 3.;
    let passes = conjectured_union >= 128.
        && johnson_union >= 100.
        && q_union >= 80.
        && raw("deep-ali") / 2. >= 80.
        && folding / 2. - (folds as f64).log2() >= 80.
        && bht >= 80.;
    Ok(
        json!({"p3_security_version":"0.9.0-rc.2","accounting":ACCOUNTING,
        "fri":params_json(p),"grinding_sites":grinding,
        "application_binding":application_binding(),
        "shape":{"status":"actual-extracted","base_trace_rows":base_trace_rows,
            "main_width":layout.main_width,"preprocessed_width":layout.preprocessed_width,
            "public_values":layout.num_public_values,"num_constraints":a.num_constraints,
            "max_constraint_degree":a.max_constraint_degree,
            "num_quotient_chunks":a.num_quotient_chunks,
            "num_batched_functions":functions,"log_committed_trace_length":shape.log_trace_length,
            "challenge_field_bits_floor":247,"classical_collision_bits_floor":185},
        "conjectured":breakdown(&conjectured),"proven_johnson":breakdown(johnson),
        "proven_unique_decoding":breakdown(&proven.udr),
        "johnson_fri_terms":[{"label":"fri-folding","bits":number(folding)},
            {"label":"fri-query","bits":number(query)}],"fri_folding_rounds":folds,
        "challenge_domain_terms":[{"label":"ood-deep-ali-domain","bits":number(raw("deep-ali"))},
            {"label":"fri-folding-domain","bits":number(folding-2.*(folds as f64).log2())}],
        "screen":{"passes_selected_model":passes,"classical_conjectured_union_bits":conjectured_union,
            "classical_johnson_union_bits":johnson_union,"quantum_johnson_challenge_union_bits":q_union,
            "bht_collision_bits":bht,"johnson_m":m,"proof_multiplicity":1},
        "application_binding_limitations":[
            "BLAKE3-256 is an external application byte binding, excluded from raw p3-security terms",
            "Nominal classical collision bits 128 and BHT bits 256/3 require model review",
            "The complete relation/PCS/application-hash composition remains unreviewed"],
        "setup_performed":false,"cryptographic_approval":false,"network_activation":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_native_layers_pass_the_selected_screen() {
        for report in [
            transaction_report(FriParams::transaction_candidate()).unwrap(),
            settlement_report(FriParams::transaction_candidate()).unwrap(),
        ] {
            assert_eq!(report["screen"]["passes_selected_model"], true);
            assert!(
                report["screen"]["quantum_johnson_challenge_union_bits"]
                    .as_f64()
                    .unwrap()
                    >= 80.
            );
            assert!(
                report["screen"]["classical_conjectured_union_bits"]
                    .as_f64()
                    .unwrap()
                    >= 128.
            );
            assert_eq!(report["setup_performed"], false);
        }
    }
}
