//! Conditional D8 shape-envelope screen, not an implemented-suite claim.
use p3_security::{
    GrindingSites, InstanceShape, StarkAirParams,
    error::ErrorBits,
    fri::{self, FriRegime},
    ldt::LowDegreeTest,
    logup::{LogUpAir, security_term},
    report::{RegimeReport, SecurityTerm},
    stark::{conjectured_security_report, proven_security_report},
};
use serde_json::{Value, json};

struct FixedJohnson(FriRegime, usize);
impl LowDegreeTest for FixedJohnson {
    fn log_blowup(&self) -> usize {
        self.0.log_blowup
    }
    fn proven_error_udr(&self, a: &StarkAirParams, s: &InstanceShape) -> ErrorBits {
        fri::proven_error_udr(&self.0, a, s)
    }
    fn best_ldr(&self, a: &StarkAirParams, s: &InstanceShape) -> Option<(usize, ErrorBits)> {
        Some((self.1, fri::proven_error_ldr_m(&self.0, a, s, self.1)))
    }
    fn conjectured_error(&self, s: &InstanceShape) -> ErrorBits {
        fri::conjectured_error(&self.0, s)
    }
    fn conjectured_terms(&self, s: &InstanceShape) -> Vec<SecurityTerm> {
        self.0.conjectured_terms(s)
    }
}
fn union(v: impl Iterator<Item = f64>) -> f64 {
    let v: Vec<_> = v.collect();
    let m = v.iter().copied().fold(f64::INFINITY, f64::min);
    m - v.iter().map(|x| (m - x).exp2()).sum::<f64>().log2()
}
fn multiplicity(t: &SecurityTerm, folds: usize) -> usize {
    if matches!(t.label, "ldt-commit-phase" | "fri-folding") {
        folds
    } else {
        1
    }
}
fn classical(t: &SecurityTerm, folds: usize) -> f64 {
    t.bits.bits() - (multiplicity(t, folds) as f64).log2()
}
fn quantum(t: &SecurityTerm, folds: usize) -> f64 {
    let bits = if t.label == "commitment-collision" {
        123.
    } else {
        t.bits.bits() / 2.
    };
    bits - (multiplicity(t, folds) as f64).log2()
}
fn breakdown(terms: &[SecurityTerm], regime: &str, folds: usize) -> Value {
    let weakest = terms
        .iter()
        .min_by(|a, b| classical(a, folds).total_cmp(&classical(b, folds)))
        .unwrap();
    json!({"regime":regime,"weakest_term":weakest.label,
        "minimum_term_bits":classical(weakest,folds),
        "union_bits":union(terms.iter().map(|t|classical(t,folds))),
        "quantum_screen_union_bits":union(terms.iter().map(|t|quantum(t,folds))),
        "terms":terms.iter().map(|t|json!({"label":t.label,
            "per_round_classical_bits":t.bits.bits(),"multiplicity":multiplicity(t,folds),
            "classical_bits":classical(t,folds),"quantum_screen_bits":quantum(t,folds)})).collect::<Vec<_>>()})
}
fn split_johnson(
    r: &RegimeReport,
    fri: &FriRegime,
    shape: &InstanceShape,
    m: usize,
) -> Vec<SecurityTerm> {
    let mut terms: Vec<_> = r
        .terms()
        .iter()
        .copied()
        .filter(|t| t.label != "low-degree-test")
        .collect();
    terms.push(SecurityTerm::new(
        "fri-folding",
        fri::commit_phase_error_ldr_m(fri, shape, m).unwrap(),
    ));
    terms.push(SecurityTerm::new(
        "fri-query",
        fri::query_phase_error(
            p3_security::proximity::alpha_ldr_m(fri.log_blowup, m),
            fri.num_queries,
            fri.query_pow_bits,
        ),
    ));
    terms
}
fn main() {
    let mut layers = Vec::new();
    // Planning envelopes, not measured D8 dimensions. All six recursive tables
    // are charged at the maximum hiding-extended height and summed widths.
    for (name, log, functions, constraints, chunks, denoms, msg, widths, prep) in [
        ("leaf", 11, 4096, 8192, 16, 0, 0, vec![1024], vec![256]),
        (
            "eight_input",
            21,
            8192,
            65536,
            128,
            128,
            32,
            vec![8, 32, 160, 336, 8, 16],
            vec![12, 16, 128, 64, 20, 18],
        ),
        (
            "root",
            21,
            8192,
            65536,
            128,
            128,
            32,
            vec![8, 32, 160, 336, 8, 16],
            vec![12, 16, 128, 64, 20, 18],
        ),
    ] {
        let shape = InstanceShape {
            log_trace_length: log,
            modulus_bits: 247,
            collision_resistance: 185,
            num_batched_functions: functions,
        };
        let air = StarkAirParams {
            num_constraints: constraints,
            max_constraint_degree: 7,
            num_quotient_chunks: chunks,
            max_combo: 2,
        };
        let lookup = LogUpAir {
            num_interactions: denoms,
            max_message_width: msg,
        };
        let mut selected = Vec::new();
        let mut best_rejected = None;
        let mut best_score = f64::NEG_INFINITY;
        // Additional batching grinding is explicitly a proposed protocol site;
        // zero-site alternatives are retained for comparison and never credited
        // with work that the recursive verifier does not check.
        for batch_pow in [0, 16] {
            for blowup in [2, 3, 4] {
                for arity in [1, 2] {
                    if log + blowup > 24 {
                        continue;
                    }
                    let mut passing = None;
                    for queries in (96..=256).step_by(4) {
                        let fri = FriRegime {
                            log_blowup: blowup,
                            num_queries: queries,
                            log_final_poly_len: 0,
                            max_log_arity: arity,
                            commit_pow_bits: if name == "leaf" { 0 } else { 16 },
                            query_pow_bits: 16,
                        };
                        let grinding = GrindingSites {
                            out_of_domain: 0,
                            lookup_challenge: 0,
                            batch_combination: batch_pow,
                        };
                        let extras: Vec<_> = security_term(&lookup, &shape, &grinding)
                            .into_iter()
                            .collect();
                        let c = conjectured_security_report(&fri, &air, &shape, &extras, &grinding);
                        for m in 3..=32 {
                            let raw = proven_security_report(
                                &FixedJohnson(fri, m),
                                &air,
                                &shape,
                                &extras,
                                &grinding,
                            )
                            .ldr
                            .unwrap();
                            let j = split_johnson(&raw, &fri, &shape, m);
                            // Binary folds plus a terminal challenge safely cover mixed arities.
                            let folds = log + 1;
                            let cb = union(c.terms().iter().map(|t| classical(t, folds)));
                            let jb = union(j.iter().map(|t| classical(t, folds)));
                            let qb = union(j.iter().map(|t| quantum(t, folds)))
                                .min(union(c.terms().iter().map(|t| quantum(t, folds))));
                            // Reserve a full 19-proof union loss at every layer so any
                            // mixture of selected profiles also meets the screen.
                            let loss = 19f64.log2();
                            let pass = cb - loss >= 128. && jb - loss >= 100. && qb - loss >= 100.;
                            let row = json!({"log_blowup":blowup,"queries":queries,"query_grinding":16,
                        "commit_grinding":fri.commit_pow_bits,"folding_round_upper_bound":folds,"ood_grinding":0,"lookup_grinding":0,
                        "batch_grinding":batch_pow,"max_log_arity":arity,"final_poly_log":0,
                        "johnson_m":m,"conjectured":breakdown(c.terms(), "Conjectured",folds),"johnson":breakdown(&j, &format!("Johnson m={m}"),folds),
                        "nineteen_proof_margin_bits":loss,"quantum_after_union_bits":qb-loss,
                        "screen_pass_conditional_on_shape_and_sites":pass,
                        "implemented":false,"approved":false});
                            if batch_pow == 0 && qb > best_score {
                                best_score = qb;
                                best_rejected = Some(row.clone());
                            }
                            if pass {
                                passing = Some(row);
                                break;
                            }
                        }
                        if passing.is_some() {
                            break;
                        }
                    }
                    if let Some(row) = passing {
                        selected.push(row);
                    }
                }
            }
            if selected.len() >= 3 {
                break;
            }
        }
        layers.push(json!({"layer":name,"shape_status":"estimated conservative planning envelope; not actual D8 extraction",
            "log_committed_trace_length":log,"base_trace_rows_max":1usize<<(log-1),
            "main_widths_upper_estimates":widths,"preprocessed_widths_upper_estimates":prep,
            "constraints_upper_estimate":constraints,"max_degree_upper_estimate":7,
            "quotient_chunks_upper_estimate":chunks,"batched_functions_upper_estimate":functions,
            "lookup_denominators_upper_estimate":denoms,"lookup_message_width_upper_estimate":msg,
            "candidates":selected.into_iter().take(3).collect::<Vec<_>>(),"best_no_batch_grinding_comparison":best_rejected}));
    }
    println!("{}",serde_json::to_string_pretty(&json!({"p3_security":"0.9.0-rc.2",
        "suite":"KoalaBear D8 / standard Poseidon2 W24 / digest12",
        "field_bits_floor":247,"classical_collision_bits_floor":185,"bht_bits_floor":123,
        "status":"conditional experimental planning screen; not approval, QROM theorem or actual circuit evidence",
        "quantum_model":"halve each non-hash term including grinding; BHT separately; sum all terms, folding rounds and 19 proofs",
        "layers":layers})).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn union_charges_terms_and_multiplicity() {
        assert!((union([200., 200.].into_iter()) - 199.).abs() < 1e-10);
        assert!(union([0., 200.].into_iter()) <= 0.);
    }
    #[test]
    fn bht_does_not_inherit_classical_collision_bits() {
        let t = SecurityTerm::new("commitment-collision", ErrorBits::from_log2(185.));
        assert_eq!(quantum(&t, 21), 123.);
    }
    #[test]
    fn recursive_batching_grinding_cannot_be_assumed_at_an_unchecked_site() {
        let shape = InstanceShape {
            log_trace_length: 21,
            modulus_bits: 247,
            collision_resistance: 185,
            num_batched_functions: 8192,
        };
        let air = StarkAirParams {
            num_constraints: 65536,
            max_constraint_degree: 7,
            num_quotient_chunks: 128,
            max_combo: 2,
        };
        let fri = FriRegime {
            log_blowup: 2,
            num_queries: 216,
            log_final_poly_len: 0,
            max_log_arity: 1,
            commit_pow_bits: 16,
            query_pow_bits: 16,
        };
        let lookup = LogUpAir {
            num_interactions: 128,
            max_message_width: 32,
        };
        for batch_pow in [0, 16] {
            let sites = GrindingSites {
                out_of_domain: 0,
                lookup_challenge: 0,
                batch_combination: batch_pow,
            };
            let extra: Vec<_> = security_term(&lookup, &shape, &sites).into_iter().collect();
            let raw = proven_security_report(&FixedJohnson(fri, 8), &air, &shape, &extra, &sites)
                .ldr
                .unwrap();
            let terms = split_johnson(&raw, &fri, &shape, 8);
            let bits = union(terms.iter().map(|t| quantum(t, 22))) - 19f64.log2();
            assert_eq!(bits >= 100., batch_pow == 16);
            assert!(terms.iter().any(|t| t.label == "batch-combination"));
            assert!(terms.iter().any(|t| t.label == "fri-folding"));
            assert!(terms.iter().any(|t| t.label == "fri-query"));
        }
    }
    #[test]
    fn folding_multiplicity_is_charged_after_quantum_halving() {
        let t = SecurityTerm::new("fri-folding", ErrorBits::from_log2(220.));
        assert_eq!(classical(&t, 16), 216.);
        assert_eq!(quantum(&t, 16), 106.);
    }
}
