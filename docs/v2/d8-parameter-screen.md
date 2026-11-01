# D8 Parameter Planning Screen

> **Paused V2 research.** Recursive aggregation and historical proof compression are outside native V1. These experimental parameters, timings and resource limits do not qualify the [current V1 route](../v1-overview.md).

Status: experimental planning candidates conditional on estimated shapes and
specified transcript sites. These tables are not approved parameters or actual
D8 circuit reports. The isolated D8 suite has passing primitive, opening-batch
grinding, native/full/prepared recursive-proof and eight-input application
correctness tests, including nonempty statement binding and canonical
verifier/proof artifact round trips. This coverage uses lower-cost fixtures;
it does not establish the final profile's actual-shape security bounds,
production memory budget or checkpoint performance. A final-profile attempt
was stopped by a cgroup OOM at the 5-GiB limit during eight-input verifier-circuit
construction/preprocessing, before eight-input proving. Preserve that failure
evidence. The next experiment uses a 10-GiB process-tree hard ceiling with zero
swap; production memory remains undecided until actual peak measurements.
No result under the larger ceiling is established here. Re-extract every shape
and checked grinding site from the final implementation before measuring a profile. Do not
deploy from this table.

The calculator pins `p3-security = 0.9.0-rc.2`. Run:

```sh
cargo run --release --locked --manifest-path crates/bench-stark/Cargo.toml \
  -p siworld-bench-plonky3 --features security-report --bin d8-security-screen
```

## Model and shape assumptions

The suite uses KoalaBear D8, standard Poseidon2 W24 and digest12. Round down
field size to 247 bits, ideal classical collision resistance to 185 and BHT
resistance to 123. These ideal ceilings still require permutation/capacity
review. Halve every non-hash term, including the total grinding contribution,
for a conservative selected-model screen. Use BHT for commitment collisions.
This is not a QROM theorem. DEEP-ALI is the estimator's combined OOD/DEEP term.

For Johnson, evaluate one consistent list parameter m across ALI, DEEP, FRI
and batching. Split FRI folding and query errors and sum them, instead of
treating the estimator's weakest-round minimum as an exact error sum. Sum all
terms by log-sum-exp; reserve another log2(19)=4.247928 bits at **every layer**
for 16 leaves, two merges and one root. Thus any selection below passes this
19-proof envelope, conditional on every shape/site assumption. No independence
is assumed. All algebraic/query terms are quantum-halved, a stricter screen
than halving only the named challenge rounds.

The folding contribution is charged up to `log_trace_length + 1` times,
covering binary/mixed folds and a terminal challenge. The loss is applied
**after** halving in the quantum ledger. The tables show aggregate error bits
after this multiplicity charge, not only the strongest or initial round.

The search covers log blowup 2/3/4, 96–256 queries in increments of four, binary
and quaternary maximum folding, and Johnson m=3–32. Grinding is 16 bits before
queries and zero before OOD and lookups. Leaves have zero commit grinding;
recursive candidates use 16 bits before each FRI commit and another 16 bits
immediately before opening batching. The unmodified pinned recursive suite
lacks that additional site, although the native prover supports it. The
isolated patch implements nonce/difficulty plumbing and native/full/prepared
recursive transcript checks. Positive-difficulty runtime correctness and
rejection tests pass at source baseline
`fb9153de6cc3624a7b8c70a7551d0e8855b7f65a`; their lower-cost fixtures do not
replace the final configuration's actual-shape screen or performance checkpoint. See the
[grinding prerequisite](d8-w24-recursion.md#opening-batch-grinding-prerequisite).
No security credit is permitted until all validators check it. If infeasible,
re-screen aggregate and root parameters with zero batch difficulty and report
actual circuit-shape changes before measuring a replacement. This is an
experimental dependency proposal, not a consensus decision.

Estimated conservative envelopes use the D4 table inventory as an anchor and
allow larger widths/heights for D8, wider digests and more verifier queries.
They are planning assumptions, not measured maxima or proven cost bounds. Each
recursive table is conservatively charged at the maximum committed height,
with summed constraints/chunks/lookups/openings. Table-row and width changes
outside this envelope invalidate the selection. The root uses the same envelope
as a planning allowance, not a claim that root and merge costs are equal.

| Layer | Maximum base rows per table | Hiding-extended rows | Main widths | Preprocessed widths | Constraints | Max degree | Quotient chunks | Batched openings | Lookup factors/row; max width |
| --- | ---: | ---: | --- | --- | ---: | ---: | ---: | ---: | --- |
| leaf | 1024 | 2048 | [1024] | [256] | 8192 | 7 | 16 | 4096 | 0; 0 |
| eight_input | 1048576 | 2097152 | [8, 32, 160, 336, 8, 16] | [12, 16, 128, 64, 20, 18] | 65536 | 7 | 128 | 8192 | 128; 32 |
| root | 1048576 | 2097152 | [8, 32, 160, 336, 8, 16] | [12, 16, 128, 64, 20, 18] | 65536 | 7 | 128 | 8192 | 128; 32 |

These are separate main/preprocessing widths, not combined physical column
counts; extension auxiliary columns and quotient commitments are charged via
the envelope's opening/chunk counts. Leaf base rows allow hiding padding for
the larger query counts. LDE domain log size must not exceed KoalaBear's
24-bit two-adicity; the calculator rejects larger combinations. A log-21
recursive commitment therefore excludes log blowup 4. The estimated lookup
multiplicity also obeys `128 * 2^20 < 2130706433`; recompute this condition
from actual table interaction multiplicities. Maximum folding arity
means factor 2 or 4, with final polynomial log length zero and a potentially
smaller terminal fold; it is not a new Merkle branching format.

## Candidate summaries

All values are bits. Classical columns sum every term for one proof, before
the reserved 19-proof loss. The quantum column includes that loss. Each passes
classical conjectured ≥128, Johnson ≥100, quantum-halved non-hash ≥100 and BHT
≥100 **only under the declared envelope and proposed sites**. The narrow
margins are not permission to round up, omit terms or tolerate larger shapes.

| Layer/profile | log blowup | Queries | Query/commit/batch grinding | Maximum fold | Johnson m | Conjectured union | Johnson union | Quantum after 19-proof union | BHT after 19-proof union |
| --- | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| leaf/1 | 2 | 220 | 16/0/0 | 2 | 7 | 185.0000 | 185.0000 | 100.1777 | 118.7521 |
| leaf/2 | 2 | 220 | 16/0/0 | 4 | 7 | 185.0000 | 185.0000 | 100.0446 | 118.7521 |
| leaf/3 | 3 | 148 | 16/0/0 | 2 | 4 | 185.0000 | 185.0000 | 100.1366 | 118.7521 |
| eight_input/1 | 2 | 208 | 16/16/16 | 2 | 12 | 185.0000 | 185.0000 | 100.1444 | 118.7521 |
| eight_input/2 | 2 | 208 | 16/16/16 | 4 | 12 | 185.0000 | 185.0000 | 100.0788 | 118.7521 |
| eight_input/3 | 3 | 140 | 16/16/16 | 2 | 7 | 185.0000 | 185.0000 | 100.2516 | 118.7521 |
| root/1 | 2 | 208 | 16/16/16 | 2 | 12 | 185.0000 | 185.0000 | 100.1444 | 118.7521 |
| root/2 | 2 | 208 | 16/16/16 | 4 | 12 | 185.0000 | 185.0000 | 100.0788 | 118.7521 |
| root/3 | 3 | 140 | 16/16/16 | 2 | 7 | 185.0000 | 185.0000 | 100.2516 | 118.7521 |

## Per-term ledger

Each cell is `classical / selected quantum` bits. Errors are bounded by
`2^(-bits)` under the corresponding estimator/model assumptions. An omitted
lookup term means the leaf has no lookup argument. The weakest classical term
and the weakest transformed term are distinguished below.

### leaf profile 1

| Error source | Conjectured | Johnson |
| --- | ---: | ---: |
| air-composition | 234.0000 / 117.0000 | 230.0931 / 115.0466 |
| deep-ali | 231.9125 / 115.9562 | 228.0056 / 114.0028 |
| ldt-query-phase | 451.6067 / 225.8034 | — |
| ldt-commit-phase | 230.4149 / 113.4149 | — |
| batch-combination | 222.0004 / 111.0002 | 209.8639 / 104.9320 |
| commitment-collision | 185.0000 / 123.0000 | 185.0000 / 123.0000 |
| fri-folding | — | 218.2786 / 107.3468 |
| fri-query | — | 214.1022 / 107.0511 |

Weakest classical term: conjectured `commitment-collision`, Johnson `commitment-collision`. Weakest Johnson quantum term: `batch-combination`.

### leaf profile 2

| Error source | Conjectured | Johnson |
| --- | ---: | ---: |
| air-composition | 234.0000 / 117.0000 | 230.0931 / 115.0466 |
| deep-ali | 231.9125 / 115.9562 | 228.0056 / 114.0028 |
| ldt-query-phase | 451.6067 / 225.8034 | — |
| ldt-commit-phase | 228.8299 / 112.6225 | — |
| batch-combination | 222.0004 / 111.0002 | 209.8639 / 104.9320 |
| commitment-collision | 185.0000 / 123.0000 | 185.0000 / 123.0000 |
| fri-folding | — | 216.6937 / 106.5543 |
| fri-query | — | 214.1022 / 107.0511 |

Weakest classical term: conjectured `commitment-collision`, Johnson `commitment-collision`. Weakest Johnson quantum term: `batch-combination`.

### leaf profile 3

| Error source | Conjectured | Johnson |
| --- | ---: | ---: |
| air-composition | 234.0000 / 117.0000 | 230.3301 / 115.1650 |
| deep-ali | 231.9125 / 115.9562 | 228.2426 / 114.1213 |
| ldt-query-phase | 456.1936 / 228.0968 | — |
| ldt-commit-phase | 229.4149 / 112.9150 | — |
| batch-combination | 221.0004 / 110.5002 | 210.0748 / 105.0374 |
| commitment-collision | 185.0000 / 123.0000 | 185.0000 / 123.0000 |
| fri-folding | — | 218.4895 / 107.4523 |
| fri-query | — | 212.8511 / 106.4255 |

Weakest classical term: conjectured `commitment-collision`, Johnson `commitment-collision`. Weakest Johnson quantum term: `batch-combination`.

### eight_input profile 1

| Error source | Conjectured | Johnson |
| --- | ---: | ---: |
| air-composition | 231.0000 / 115.5000 | 226.3561 / 113.1781 |
| deep-ali | 218.9888 / 109.4944 | 214.3449 / 107.1725 |
| ldt-query-phase | 427.8463 / 213.9232 | — |
| ldt-commit-phase | 235.5406 / 115.5406 | — |
| batch-combination | 227.0002 / 113.5001 | 212.6536 / 106.3268 |
| logup-fingerprint | 213.9125 / 106.9563 | 213.9125 / 106.9563 |
| commitment-collision | 185.0000 / 123.0000 | 185.0000 / 123.0000 |
| fri-folding | — | 221.1940 / 108.3673 |
| fri-query | — | 211.7501 / 105.8751 |

Weakest classical term: conjectured `commitment-collision`, Johnson `commitment-collision`. Weakest Johnson quantum term: `fri-query`.

### eight_input profile 2

| Error source | Conjectured | Johnson |
| --- | ---: | ---: |
| air-composition | 231.0000 / 115.5000 | 226.3561 / 113.1781 |
| deep-ali | 218.9888 / 109.4944 | 214.3449 / 107.1725 |
| ldt-query-phase | 427.8463 / 213.9232 | — |
| ldt-commit-phase | 233.9556 / 114.7481 | — |
| batch-combination | 227.0002 / 113.5001 | 212.6536 / 106.3268 |
| logup-fingerprint | 213.9125 / 106.9563 | 213.9125 / 106.9563 |
| commitment-collision | 185.0000 / 123.0000 | 185.0000 / 123.0000 |
| fri-folding | — | 219.6090 / 107.5748 |
| fri-query | — | 211.7501 / 105.8751 |

Weakest classical term: conjectured `commitment-collision`, Johnson `commitment-collision`. Weakest Johnson quantum term: `fri-query`.

### eight_input profile 3

| Error source | Conjectured | Johnson |
| --- | ---: | ---: |
| air-composition | 231.0000 / 115.5000 | 226.5931 / 113.2966 |
| deep-ali | 218.9888 / 109.4944 | 214.5819 / 107.2909 |
| ldt-query-phase | 432.3994 / 216.1997 | — |
| ldt-commit-phase | 234.5406 / 115.0406 | — |
| batch-combination | 226.0002 / 113.0001 | 212.8645 / 106.4322 |
| logup-fingerprint | 213.9125 / 106.9563 | 213.9125 / 106.9563 |
| commitment-collision | 185.0000 / 123.0000 | 185.0000 / 123.0000 |
| fri-folding | — | 221.4049 / 108.4727 |
| fri-query | — | 212.0650 / 106.0325 |

Weakest classical term: conjectured `commitment-collision`, Johnson `commitment-collision`. Weakest Johnson quantum term: `fri-query`.

### root profile 1

| Error source | Conjectured | Johnson |
| --- | ---: | ---: |
| air-composition | 231.0000 / 115.5000 | 226.3561 / 113.1781 |
| deep-ali | 218.9888 / 109.4944 | 214.3449 / 107.1725 |
| ldt-query-phase | 427.8463 / 213.9232 | — |
| ldt-commit-phase | 235.5406 / 115.5406 | — |
| batch-combination | 227.0002 / 113.5001 | 212.6536 / 106.3268 |
| logup-fingerprint | 213.9125 / 106.9563 | 213.9125 / 106.9563 |
| commitment-collision | 185.0000 / 123.0000 | 185.0000 / 123.0000 |
| fri-folding | — | 221.1940 / 108.3673 |
| fri-query | — | 211.7501 / 105.8751 |

Weakest classical term: conjectured `commitment-collision`, Johnson `commitment-collision`. Weakest Johnson quantum term: `fri-query`.

### root profile 2

| Error source | Conjectured | Johnson |
| --- | ---: | ---: |
| air-composition | 231.0000 / 115.5000 | 226.3561 / 113.1781 |
| deep-ali | 218.9888 / 109.4944 | 214.3449 / 107.1725 |
| ldt-query-phase | 427.8463 / 213.9232 | — |
| ldt-commit-phase | 233.9556 / 114.7481 | — |
| batch-combination | 227.0002 / 113.5001 | 212.6536 / 106.3268 |
| logup-fingerprint | 213.9125 / 106.9563 | 213.9125 / 106.9563 |
| commitment-collision | 185.0000 / 123.0000 | 185.0000 / 123.0000 |
| fri-folding | — | 219.6090 / 107.5748 |
| fri-query | — | 211.7501 / 105.8751 |

Weakest classical term: conjectured `commitment-collision`, Johnson `commitment-collision`. Weakest Johnson quantum term: `fri-query`.

### root profile 3

| Error source | Conjectured | Johnson |
| --- | ---: | ---: |
| air-composition | 231.0000 / 115.5000 | 226.5931 / 113.2966 |
| deep-ali | 218.9888 / 109.4944 | 214.5819 / 107.2909 |
| ldt-query-phase | 432.3994 / 216.1997 | — |
| ldt-commit-phase | 234.5406 / 115.0406 | — |
| batch-combination | 226.0002 / 113.0001 | 212.8645 / 106.4322 |
| logup-fingerprint | 213.9125 / 106.9563 | 213.9125 / 106.9563 |
| commitment-collision | 185.0000 / 123.0000 | 185.0000 / 123.0000 |
| fri-folding | — | 221.4049 / 108.4727 |
| fri-query | — | 212.0650 / 106.0325 |

Weakest classical term: conjectured `commitment-collision`, Johnson `commitment-collision`. Weakest Johnson quantum term: `fri-query`.

## Blocking comparison and next extraction

Without the proposed batch-grinding site, the strongest recursive comparison
found in this search reaches only 96.78 quantum bits after the complete
envelope loss. It fails the selected target; increasing queries does not
remove that batching bottleneck. Leaf profiles need no new batching grind in
this screen. The recursive candidates require a reviewed, verified extra site
or a different justified argument/shape. No existing q92 inheritance is valid.

The passing eight-input application smoke proof uses two queries and four
batch/query grinding bits. It does not validate the final checkpoint's
148/140-query, 16-bit grinding profile or its complete N=16 composition.

For that final profile, record actual tables, constraints, degrees, quotient
chunks, hiding extensions, preprocessing keys, opening powers, lookup shapes,
FRI schedules and every checked grinding site. The isolated checkpoint worker
extracts these actual shapes after preparing leaf, merge and root circuits,
then repeats the fixed-version screen and composition arithmetic before
warm-trial admission. Final-profile startup is currently blocked by the
preparation OOM before that extraction: no final actual-shape/security bundle,
three-trial warm median, measured root cost or complete N=16 latency evidence
is available. The planning envelopes above therefore remain assumptions,
not actual-shape evidence or a quantum security theorem.

The checkpoint selects experimental log-blowup 3, binary-folding profiles with
148 leaf queries and 140 merge/root queries. Query grinding is 16 bits at all
layers, commit grinding is zero for the leaf and 16 bits for merge/root, and
batch grinding is 16 bits at all layers. The leaf's extra batch difficulty is
stronger than its zero-batch planning row; every layer must still pass a new
actual-shape report rather than inherit the planning totals. Freeze the final
configuration and regenerated artifacts before the three trials.

Only then measure passing profiles under the hard limit. Opening-batch
grinding is a mandatory pre-checkpoint task. Freeze and measure
the implemented final configuration on minimum-qualified hardware rather
than timing a reduced-difficulty substitute. Apply the joint checkpoint gates:
at most 135 seconds within the current 10-GiB experimental ceiling permits
continued experiments; more than 135 and at most 180 seconds under that ceiling
requires parallel optimization; more than 180 seconds, more than 10 GiB or OOM
pauses progression. The ceiling is 10,737,418,240 bytes with zero swap, not a
production acceptance budget. Select the production budget after actual peak
measurements. Give each stage's memory breakdown the same prominence as its time, with measured and estimated
components distinguished. See the [checkpoint procedure](d8-w24-recursion.md#early-performance-checkpoint).
N=32 is the first separately scoped assessment after that checkpoint passes;
there is no N=32 screening in the current work.

A single commitment-collision term is the estimator's ideal cap, not a complete
count of adaptive hash oracle calls; multi-target hash/transcript and recursion
composition losses remain independent review requirements.
