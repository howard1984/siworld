//! Actual-shape D8 experiment analysis. Conservative envelopes are not an acceptance theorem.

use crate::common::F;
use p3_air::{BaseAir, symbolic::AirLayout};
use p3_batch_stark::symbolic::{
    get_log_num_quotient_chunks, get_max_constraint_degree, get_symbolic_constraints,
};
use p3_circuit_prover::CircuitVerifier;
use p3_commit::Pcs;
use p3_lookup::LogUpGadget;
use p3_security::{
    GrindingSites, InstanceShape, RegimeReport, StarkAirParams,
    error::ErrorBits,
    fri::{self, FriRegime},
    ldt::LowDegreeTest,
    logup::{LogUpAir, security_term},
    report::SecurityTerm,
    stark::{conjectured_security_report, proven_security_report},
};
use p3_uni_stark::{OpeningShape, StarkGenericConfig};
use serde_json::{Value, json};

use crate::{Cfg, FriParams, SlotProver};

type EF = <Cfg as StarkGenericConfig>::Challenge;

// Floor log2(p^8) and the ideal classical collision exponent. Rounding down
// is conservative; neither integer is the field's binary encoding length.
const FIELD_BITS: usize = 247;
const COLLISION_BITS: usize = 185;

struct FixedJohnson(FriRegime, usize);
impl LowDegreeTest for FixedJohnson {
    fn log_blowup(&self) -> usize {
        self.0.log_blowup
    }
    fn proven_error_udr(&self, air: &StarkAirParams, shape: &InstanceShape) -> ErrorBits {
        fri::proven_error_udr(&self.0, air, shape)
    }
    fn best_ldr(&self, air: &StarkAirParams, shape: &InstanceShape) -> Option<(usize, ErrorBits)> {
        Some((self.1, fri::proven_error_ldr_m(&self.0, air, shape, self.1)))
    }
    fn conjectured_error(&self, shape: &InstanceShape) -> ErrorBits {
        fri::conjectured_error(&self.0, shape)
    }
    fn conjectured_terms(&self, shape: &InstanceShape) -> Vec<SecurityTerm> {
        self.0.conjectured_terms(shape)
    }
}
fn error_union(terms: impl Iterator<Item = f64>) -> f64 {
    let values: Vec<_> = terms.collect();
    let minimum = values.iter().copied().fold(f64::INFINITY, f64::min);
    minimum
        - values
            .iter()
            .map(|v| (minimum - v).exp2())
            .sum::<f64>()
            .log2()
}
fn checkpoint_screen(
    fri: &FriRegime,
    air: &StarkAirParams,
    shape: &InstanceShape,
    lookup: &LogUpAir,
    grinding: &GrindingSites,
) -> Value {
    let extras: Vec<_> = security_term(lookup, shape, grinding).into_iter().collect();
    let conjectured = conjectured_security_report(fri, air, shape, &extras, grinding);
    let folds = shape.log_trace_length + 1;
    let loss = 19f64.log2();
    let score = |term: &SecurityTerm, quantum: bool| {
        let raw = if quantum {
            if term.label == "commitment-collision" {
                123.
            } else {
                term.bits.bits() / 2.
            }
        } else {
            term.bits.bits()
        };
        raw - if matches!(term.label, "ldt-commit-phase" | "fri-folding") {
            (folds as f64).log2()
        } else {
            0.
        }
    };
    let mut best: Option<(f64, Value)> = None;
    for m in 3..=32 {
        let proven = proven_security_report(&FixedJohnson(*fri, m), air, shape, &extras, grinding);
        let Some(raw) = proven.ldr else { continue };
        let mut johnson: Vec<_> = raw
            .terms()
            .iter()
            .copied()
            .filter(|t| t.label != "low-degree-test")
            .collect();
        let Some(folding) = fri::commit_phase_error_ldr_m(fri, shape, m) else {
            continue;
        };
        johnson.push(SecurityTerm::new("fri-folding", folding));
        johnson.push(SecurityTerm::new(
            "fri-query",
            fri::query_phase_error(
                p3_security::proximity::alpha_ldr_m(fri.log_blowup, m),
                fri.num_queries,
                fri.query_pow_bits,
            ),
        ));
        let c = error_union(conjectured.terms().iter().map(|t| score(t, false))) - loss;
        let j = error_union(johnson.iter().map(|t| score(t, false))) - loss;
        let q = error_union(conjectured.terms().iter().map(|t| score(t, true)))
            .min(error_union(johnson.iter().map(|t| score(t, true))))
            - loss;
        if best.as_ref().is_some_and(|(b, _)| *b >= q) {
            continue;
        }
        let ledger = |label: &str| {
            let aliases: &[&str] = match label {
                "ood" | "deep" => &["deep-ali"],
                "ali" => &["air-composition"],
                "fri_fold" => &["fri-folding", "ldt-commit-phase"],
                "merkle_collision" | "commitment_collision" => &["commitment-collision"],
                _ => &[],
            };
            let cs = conjectured
                .terms()
                .iter()
                .chain(&johnson)
                .filter(|t| aliases.contains(&t.label));
            let rows: Vec<_> = cs.collect();
            let classical = rows
                .iter()
                .map(|t| score(t, false))
                .fold(f64::INFINITY, f64::min)
                - loss;
            let quantum = rows
                .iter()
                .map(|t| score(t, true))
                .fold(f64::INFINITY, f64::min)
                - loss;
            json!({"classical_bits":classical,"quantum_bits":quantum,"source_labels":aliases,"combined_deep_ali_bound":matches!(label,"ood"|"deep")})
        };
        let weakest = conjectured
            .terms()
            .iter()
            .chain(&johnson)
            .min_by(|a, b| score(a, true).total_cmp(&score(b, true)))
            .map(|t| t.label)
            .unwrap_or("none");
        let value = json!({"bounds":{"conjectured":c,"johnson":j,"quantum_challenges":q,"bht_collision":123.-loss},"johnson_m":m,"weakest_term":weakest,"nineteen_proof_loss":loss,"folding_round_upper_bound":folds,"error_terms":{"ood":ledger("ood"),"deep":ledger("deep"),"ali":ledger("ali"),"fri_fold":ledger("fri_fold"),"merkle_collision":ledger("merkle_collision"),"commitment_collision":ledger("commitment_collision")},"conjectured_terms":conjectured.terms().iter().map(|t|json!({"label":t.label,"classical_bits":score(t,false),"quantum_bits":score(t,true)})).collect::<Vec<_>>(),"johnson_terms":johnson.iter().map(|t|json!({"label":t.label,"classical_bits":score(t,false),"quantum_bits":score(t,true)})).collect::<Vec<_>>(),"approved":false,"model":"selected conservative halving ledger; not a QROM or composition theorem"});
        best = Some((q, value));
    }
    best.map(|(_, v)| v).unwrap_or(Value::Null)
}

pub fn checkpoint_reports(leaf: &Value, merge: &Value, root: &Value) -> Result<Value, String> {
    let mut composition = serde_json::Map::new();
    let mut bounds = serde_json::Map::new();
    let rows = [(leaf, 16usize), (merge, 2), (root, 1)];
    for (key, minimum) in [
        ("conjectured", 128.),
        ("johnson", 100.),
        ("quantum_challenges", 100.),
        ("bht_collision", 100.),
    ] {
        let mut values = Vec::new();
        for (report, count) in rows {
            let bits = report["report"]["screen"]["bounds"][key]
                .as_f64()
                .ok_or("invalid actual security report")?;
            if bits < minimum {
                return Err(format!(
                    "actual D8 shape fails {key}: {bits}; checkpoint blocked"
                ));
            }
            values.push(bits + 19f64.log2() - (count as f64).log2());
        }
        bounds.insert(key.into(), json!(error_union(values.into_iter())));
    }
    composition.insert("bounds".into(), json!(bounds));
    composition.insert("proof_count".into(), json!(19));
    composition.insert(
        "weakest_term".into(),
        json!("union of actual layer ledgers"),
    );
    let mut terms = serde_json::Map::new();
    for term in [
        "ood",
        "deep",
        "ali",
        "fri_fold",
        "merkle_collision",
        "commitment_collision",
    ] {
        let mut row = serde_json::Map::new();
        for basis in ["classical_bits", "quantum_bits"] {
            let values = rows.iter().map(|(r, n)| {
                r["report"]["screen"]["error_terms"][term][basis]
                    .as_f64()
                    .expect("finite screen")
                    + 19f64.log2()
                    - (*n as f64).log2()
            });
            row.insert(basis.into(), json!(error_union(values)));
        }
        terms.insert(term.into(), json!(row));
    }
    composition.insert("error_terms".into(), json!(terms));
    Ok(
        json!({"suite":"KoalaBear-D8-Poseidon2-W24-digest12","p3_security":"0.9.0-rc.2","layers":{"leaf":leaf["report"]["screen"],"merge8":merge["report"]["screen"],"root":root["report"]["screen"]},"composition":composition,"raw_actual_reports":{"leaf":leaf,"merge8":merge,"root":root},"approved":false}),
    )
}

fn number(bits: f64) -> Value {
    if bits.is_finite() {
        json!(bits)
    } else if bits == f64::INFINITY {
        json!("positive_infinity")
    } else {
        panic!("invalid security estimate")
    }
}

fn breakdown(report: &RegimeReport) -> Value {
    json!({
        "regime": format!("{:?}", report.regime),
        "minimum_term_bits": number(report.security_bits()),
        "weakest_term": report.binding().label,
        "terms": report.terms().iter().map(|t| json!({
            "label": t.label, "bits": number(t.bits.bits()),
        })).collect::<Vec<_>>(),
    })
}

fn reports(
    params: FriParams,
    cfg: &Cfg,
    air: StarkAirParams,
    shape: InstanceShape,
    lookup: LogUpAir,
) -> Value {
    let fri = FriRegime {
        log_blowup: params.log_blowup as usize,
        num_queries: params.num_queries as usize,
        log_final_poly_len: 0,
        max_log_arity: params.max_log_arity as usize,
        commit_pow_bits: params.commit_pow_bits as usize,
        query_pow_bits: params.query_pow_bits as usize,
    };
    let grinding = GrindingSites {
        out_of_domain: cfg.ood_proof_of_work_bits(),
        lookup_challenge: cfg.lookup_proof_of_work_bits(),
        batch_combination: params.batch_pow_bits as usize,
    };
    let extras: Vec<_> = security_term(&lookup, &shape, &grinding)
        .into_iter()
        .collect();
    let conjectured = conjectured_security_report(&fri, &air, &shape, &extras, &grinding);
    let proven = proven_security_report(&fri, &air, &shape, &extras, &grinding);
    json!({
        "fri": {"log_blowup": fri.log_blowup, "num_queries": fri.num_queries,
            "log_final_poly_len": fri.log_final_poly_len, "max_log_arity": fri.max_log_arity,
            "batch_pow_bits": params.batch_pow_bits, "commit_pow_bits": fri.commit_pow_bits, "query_pow_bits": fri.query_pow_bits},
        "grinding_sites": grinding,
        "shape": {"log_committed_trace_length": shape.log_trace_length,
            "challenge_field_bits_floor": shape.modulus_bits,
            "classical_collision_bits_floor": shape.collision_resistance,
            "num_batched_functions": shape.num_batched_functions,
            "num_constraints": air.num_constraints,
            "max_constraint_degree": air.max_constraint_degree,
            "num_quotient_chunks": air.num_quotient_chunks,
            "max_combo": air.max_combo,
            "lookup_denominators_per_row": lookup.num_interactions,
            "max_lookup_message_width": lookup.max_message_width},
        "conjectured": breakdown(&conjectured),
        "proven_johnson": proven.ldr.as_ref().map(breakdown),
        "proven_unique_decoding": breakdown(&proven.udr),
        "screen": checkpoint_screen(&fri, &air, &shape, &lookup, &grinding),
        "acceptance": false,
    })
}

/// Derive leaf dimensions from its actual AIR and committed preprocessing key.
pub fn leaf(prover: &SlotProver, params: FriParams) -> Value {
    let air = &prover.air;
    let mut layout = AirLayout::from_air(air);
    layout.preprocessed_width = prover.vk.width;
    let domain = <<Cfg as StarkGenericConfig>::Pcs as Pcs<
        EF,
        <Cfg as StarkGenericConfig>::Challenger,
    >>::natural_domain_for_degree(prover.cfg.pcs(), air.height);
    let air_shape = StarkAirParams::from_air::<F, EF, _>(air, layout, domain, 2, true);
    let functions = p3_uni_stark::num_batched_openings(
        layout.main_width,
        !air.main_next_row_columns().is_empty(),
        layout.preprocessed_width,
        !air.preprocessed_next_row_columns().is_empty(),
        air_shape.num_quotient_chunks,
        8,
        OpeningShape::hiding(8),
    );
    let shape = InstanceShape {
        log_trace_length: air.degree_bits() + prover.cfg.is_zk(),
        modulus_bits: FIELD_BITS,
        collision_resistance: COLLISION_BITS,
        num_batched_functions: functions,
    };
    json!({"base_trace_rows": air.height,
        "preprocessed_degree_bits": prover.vk.degree_bits,
        "main_width": layout.main_width, "preprocessed_width": layout.preprocessed_width,
        "public_values": layout.num_public_values,
        "report": reports(params, &prover.cfg, air_shape, shape,
            LogUpAir { num_interactions: 0, max_message_width: 0 })})
}

/// Extract every actual batch table, then overestimate a single common-domain
/// envelope. This intentionally charges all constraints, quotient chunks and
/// lookup factors at the largest trace height, with the global opening count.
/// Applicability of a multi-instance/recursive theorem remains a review item.
pub fn recursive(verifier: &CircuitVerifier<Cfg>, params: FriParams) -> Result<Value, String> {
    let airs = verifier.table_airs::<8>().map_err(|e| format!("{e:?}"))?;
    let common = verifier.common_data();
    let degrees = verifier.relation().trace_degree_bits();
    let zk = verifier.config().is_zk();
    if airs.len() != degrees.len() || airs.len() != common.lookups.len() {
        return Err("batch table metadata length mismatch".into());
    }
    let mut tables = Vec::new();
    let (mut constraints, mut degree, mut chunks, mut functions, mut denoms, mut width) =
        (0, 0, 0, 0, 0, 0);
    for (i, air) in airs.iter().enumerate() {
        let committed_log = degrees[i];
        let base_log = committed_log.checked_sub(zk).ok_or("invalid ZK degree")?;
        let prep = common
            .preprocessed
            .as_ref()
            .and_then(|p| p.instances[i].as_ref());
        let prep_width = prep.map_or(0, |p| p.width);
        let mut layout = AirLayout::from_air(air);
        layout.preprocessed_width = prep_width;
        let lookups = &common.lookups[i];
        let (base, extension) =
            get_symbolic_constraints::<F, EF, _, _>(air, layout, lookups, &LogUpGadget);
        let nconstraints = base.len() + extension.len();
        let max_degree = get_max_constraint_degree::<F, EF, _, _>(
            air,
            layout,
            1 << base_log,
            lookups,
            &LogUpGadget,
        )
        .max(air.max_constraint_degree().unwrap_or(0));
        let quotient_chunks = 1
            << (get_log_num_quotient_chunks::<F, EF, _, _>(
                air,
                layout,
                1 << base_log,
                lookups,
                zk,
                &LogUpGadget,
            ) + zk);
        let openings = p3_batch_stark::num_batched_openings(
            layout.main_width,
            !air.main_next_row_columns().is_empty(),
            prep_width,
            !air.preprocessed_next_row_columns().is_empty(),
            quotient_chunks,
            lookups.len(),
            8,
            OpeningShape::hiding(8),
        );
        // Count every tuple even for exclusive flags: conservative if the AIR
        // really enforces exclusivity, and never an underestimate if it does not.
        let table_denoms: usize = lookups.iter().map(|l| l.elements.len()).sum();
        let message_width = lookups
            .iter()
            .flat_map(|l| &l.elements)
            .map(Vec::len)
            .max()
            .unwrap_or(0);
        constraints += nconstraints;
        degree = degree.max(max_degree);
        chunks += quotient_chunks;
        functions += openings;
        denoms += table_denoms;
        width = width.max(message_width);
        tables.push(json!({"index": i, "base_trace_rows": 1usize << base_log,
            "log_committed_trace_length": committed_log,
            "main_width": layout.main_width, "preprocessed_width": prep_width,
            "preprocessed_degree_bits": prep.map(|p| p.degree_bits),
            "public_values": layout.num_public_values,
            "base_constraints": base.len(), "extension_constraints": extension.len(),
            "max_constraint_degree": max_degree,
            "num_quotient_chunks": quotient_chunks, "num_lookups": lookups.len(),
            "lookup_denominator_upper_bound": table_denoms,
            "max_lookup_message_width": message_width,
            "batched_opening_contribution": openings}));
    }
    let shape = InstanceShape {
        log_trace_length: *degrees.iter().max().ok_or("empty batch")?,
        modulus_bits: FIELD_BITS,
        collision_resistance: COLLISION_BITS,
        num_batched_functions: functions,
    };
    Ok(
        json!({"tables": tables, "exact_sum_quotient_chunks": chunks,
        "envelope_method": "all constraints/chunks/lookups at maximum committed height; exact summed opening powers; conservative screening only",
        "report": reports(params, verifier.config(), StarkAirParams {
            num_constraints: constraints, max_constraint_degree: degree,
            // The estimator requires a power-of-two quotient split. Round the
            // envelope up, preserving exact per-table counts in the ledger.
            num_quotient_chunks: chunks.next_power_of_two(), max_combo: 2,
        }, shape, LogUpAir { num_interactions: denoms, max_message_width: width })}),
    )
}

/// Sum repeated error bounds without an independence assumption.
pub fn union_bits(terms: &[(f64, usize)]) -> f64 {
    let minimum = terms
        .iter()
        .map(|(bits, _)| *bits)
        .fold(f64::INFINITY, f64::min);
    if minimum == f64::INFINITY {
        return minimum;
    }
    minimum
        - terms
            .iter()
            .map(|(bits, count)| *count as f64 * (minimum - bits).exp2())
            .sum::<f64>()
            .log2()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composition_charges_every_proof_and_error_term() {
        assert!(
            (union_bits(&[(100.0, 16), (100.0, 2), (100.0, 1)]) - (100.0 - 19f64.log2())).abs()
                < 1e-10
        );
        assert!(union_bits(&[(0.0, 1), (128.0, 19)]) <= 0.0);
    }

    #[test]
    fn d8_ideal_hash_cap_does_not_imply_composition_approval() {
        let params = FriParams {
            num_queries: 92,
            ..FriParams::candidate()
        };
        let cfg = params.config();
        let r = reports(
            params,
            &cfg,
            StarkAirParams {
                num_constraints: 100,
                max_constraint_degree: 3,
                num_quotient_chunks: 8,
                max_combo: 2,
            },
            InstanceShape {
                log_trace_length: 8,
                modulus_bits: FIELD_BITS,
                collision_resistance: COLLISION_BITS,
                num_batched_functions: 1000,
            },
            LogUpAir {
                num_interactions: 0,
                max_message_width: 0,
            },
        );
        assert!(r["conjectured"]["minimum_term_bits"].as_f64().unwrap() >= 128.0);
        assert!(r["proven_johnson"].is_object());
        assert_eq!(r["acceptance"], false);
        assert_eq!(number(f64::INFINITY), "positive_infinity");
    }
}
