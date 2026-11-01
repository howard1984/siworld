# D8 W24 Recursive Suite Implementation Plan

> **Paused V2 research.** Recursive aggregation and historical proof compression are outside native V1. These experimental parameters, timings and resource limits do not qualify the [current V1 route](../v1-overview.md).

Status: paused V2 experimental implementation with passing primitive, reusable-recursion
and eight-input application correctness tests. A final-profile checkpoint attempt
was stopped by a cgroup OOM at the 5-GiB limit during eight-input verifier-circuit
construction/preprocessing, before eight-input proving. That failure remains
retained evidence. The paused follow-up proposal specified a 10-GiB
process-tree ceiling with zero swap; it is not an active V1 requirement. Actual-shape
screening, performance measurement and security review remain pending. The target is
KoalaBear D8, standard Plonky3 Poseidon2 W24 and 12-base-element digests.
The paused N=16 research target is 180 seconds. That experiment specified
10 GiB = 10,737,418,240 bytes across the complete proof process tree. This
ceiling is not a production acceptance budget; select that budget only after
actual peak-memory characterization. This proving target does not change the
consensus block interval. The baseline is Plonky3 `0.9.0-rc.2` and recursion revision
`3a69ba61f713c8400b14eb3d8f0e52caa13512c7`, with the separately maintained
experimental dependency patch. Passing correctness fixtures do not establish
a checkpoint pass or security approval.

The recursive aggregation baseline currently retains two correctness failures:
the level-one anchor-membership check and the root fee-accumulation check both
return `Lookup(TerminalSumNonZero)`. These are deferred V2 investigation items
and are outside the current V1 native transaction-proof and fee-settlement
scope. This change does not repair or activate the recursive path.

## Upstream gaps and isolated implementation

The unmodified pinned dependency has no D8/12-element suite entry and rejects
the packed W24 binary Merkle geometry. Its native Merkle siblings are 12 lifted
scalars, each with seven zero extension coefficients. The isolated patch adds
an experimental suite registry/configuration, scalar W24 binary compression,
D8 backend dispatch, transcript handling and artifact encoding. It does not
relax the old unsupported packed geometry or select the D8/W32 prototype.

The direct compile failure against the unmodified revision is understood and
must remain explicit in review material. It reports six unresolved API
references, grouped into four primary public surfaces:

| Missing stock API | First application use | Required patch surface |
| --- | --- | --- |
| `ExperimentalKoalaBearD8Poseidon2W24RandomCodewordConfig` and `experimental_koala_bear_d8_poseidon2_w24_random_codeword` | `bench-d8/src/lib.rs` imports and `Cfg` construction | D8 degree-8 random-codeword factory, scalar W24 permutation lift, MMCS/prover/verifier dispatch and artifact assembly |
| `Poseidon2Config::KOALA_BEAR_D1_W24` (and its challenger role) | `bench-d8/src/agg.rs` backend and Poseidon2 calls | Scalar W24 constants, circuit AIR variants, eight-coefficient witness bus and challenger/table registration |
| `SuiteIdV1::ExperimentalKoalaBearD8Poseidon2W24RandomCodewordFri` | `bench-d8/src/lib.rs` descriptor | Registry ID/spec metadata, suite decoding and descriptor/artifact dispatch |
| `FriConfigV1::with_batch_pow_bits` (plus its batch-work accessor) and `FriVerifierParams::{try,with}_mmcs_and_batch` | `bench-d8/src/lib.rs` descriptor | Positive opening-batch grinding in native, recursive and prepared parameters, including canonical artifact encoding |

The first two rows also require degree-8 branches in FRI planning and
recursive verifier-circuit dispatch. The unmodified implementation has no
equivalent path, so replacing the imports with an existing D4 suite would
change extension degree, digest width and transcript geometry rather than
provide a D8 implementation. The patch is therefore an isolated dependency
adapter; it does not alter the retained node dependency graph.

Native/circuit transcript equivalence, opening-batch grinding, scalar-coefficient
rejection and reusable D8 recursive-proof tests pass. An eight-input
application proof also verifies under a lower-cost correctness configuration,
including rejection of changed public digests and a changed last-child
statement. The final-profile checkpoint remains a separate gate. These tests do
not establish independent security approval or performance feasibility. The retained
seven-node N=2 deployment and its dependencies remain unchanged.

## Scalar geometry

A W24 permutation contains 24 base-field state elements, with rate 12 and
capacity 12. Packing those elements into three D8 lanes would split the
rate/capacity boundary through the middle lane. The isolated implementation
instead keeps 24 scalar circuit values and lifts the scalar D1 W24 permutation
AIR into a D8 circuit. Its witness bus binds all eight extension coefficients,
including the canonical zero coefficients of scalar values. Binary compression
binds all 24 scalar inputs and returns exactly the designated 12 scalar outputs.
A one-D8-element digest would drop four base elements; a two-D8-element external
digest would change the format. Neither is permitted.

The challenger uses a dedicated W24 table with constraints for its initial
capacity and squeeze chain. Ordinary MMCS permutations use a separate table,
so interleaving them cannot supply a different challenger capacity. This
scalar AIR is an initial implementation, not a claim of optimal table width
or proving cost. Native/circuit transcript and interleaving tests pass for the
covered fixtures; complete N=16 composition under the final checkpoint
profile still requires separate validation.

The earlier `d8-geometry` scaffold retains explicit three-lane packing and
canonical internal padding as a separate correctness tool. It is not the
checkpoint permutation representation. Keep the external digest at 12 scalars
throughout MMCS proofs, caps, artifacts, serialization and transcripts. Do not
force unused actual permutation outputs to zero. Native lifted siblings and
circuit coefficients must match exactly.

## Work packages and estimates

Estimates are engineering days for one developer familiar with the dependency,
including tests and review fixes within each package. They are planning ranges,
not completion promises; security findings can change them. Audit availability
is separate. The sequential subtotal is 17–31 engineering days, conditional on
the early performance checkpoint permitting further work.

| Package | Estimate | Deliverable and blocking tests |
| --- | ---: | --- |
| Scalar W24 geometry | 3–5 days | Typed geometry, coefficient extraction/recomposition, standard permutation tables, native/circuit binary compression; mutations of all 24 inputs, 12 digest limbs and eight extension coefficients, wrong padding and malformed geometry |
| Recursive suite and FRI | 3–5 days | D8 AIR/table/recomposition dispatch, registry/config codec, transcript observation/squeezing, cap/MMCS targets and canonical artifacts; native/circuit transcript equivalence, wrong suite/key/cap and noncanonical proof rejection |
| Opening-batch grinding | 2–4 days | Native nonce generation and recursive verification with identical transcript order; configuration/shape/key binding, serialization, positive-difficulty and zero-difficulty rejection tests; required before checkpoint |
| SIP relation port | 4–7 days | Consistent leaf/anchor/note/nullifier/hash/codecs, eight-input and root circuits, reviewed additive-set/output layouts; trigger the early performance checkpoint at the first verified eight-input merge with opening-batch grinding and the final checkpoint configuration; independent native oracle, all public-field mutations and complete N=16 proof verification |
| Security screening and measurements | 2–4 days | Actual shape extraction, pinned conjectured and Johnson reports, composition/quantum screening, only passing profiles receive three full N=16 experimental runs under the 10-GiB ceiling; production budget selection follows measured peaks |
| Production integration and freeze | 3–6 days | Shared transition/verification interfaces, worker/network binding, resource admission, isolated engineering-network fixtures, reproducible complete sources/artifacts/keys for audit |

Plan the first eight-input checkpoint for engineering day 13, with an estimated
window of days 10–18 from the start of implementation. This comprises 3–5 days
for scalar geometry, 3–5 for the recursive suite, 2–4 for opening-batch grinding,
and the first 2–4 days of the SIP port for the leaf and eight-input relation.
The remaining 2–3 SIP-port days cover the root and full rejection coverage.
Opening-batch grinding is on the critical path; it is not deferred until after
timing. Run the checkpoint immediately when the first merge verifies under the
final checkpoint configuration, even if earlier than day 10; do not wait for
the planned date. These are engineering-effort estimates, not calendar deadlines.
Dependency failures, CI findings and the checkpoint stop conditions can delay
or suspend progression.

Write failing tests for new validation behavior before implementing it. Keep
work in an isolated dependency experiment; do not modify frozen measurements
or the live N=2 deployment. Reuse W32 field-generic patterns only after reviewing
their applicability. Do not inherit W32 constants or digest assumptions.

## Application and transcript review

Inventory every W16/8-element hash use: proof commitments, challenge duplex,
leaf statement, additive set hash, anchor/note trees, miner/fund notes,
nullifiers, addresses, ciphertext plaintext codecs and block/state bindings.
A wider digest does not automatically port these interfaces. Preserve domain
separation and canonical encodings in native and circuit code.

The old 48-element set accumulator and 70-element root layout are D4 prototype
facts. The isolated D8 application implements six digest-width squeezes as a
72-element set accumulator and a 102-element root layout, with native and
circuit code using the same experimental geometry. It also constrains all 16
ciphertext limbs and the zero-padded W24 absorption tail. These choices are
experimental, require set-hash and encoding review, and are not adopted
consensus constants. The live N=2 statement and keys are unchanged.

The two-worker hiding kernel must retain independent fresh randomness and the
same masking guarantees as serial execution. Pin every source delta in the
final review identity. Validate cancellation, errors and buffer lifetimes.

## Opening-batch grinding prerequisite

The pinned native `p3-fri` already implements this site: its PCS transcript
absorbs claimed evaluations in commitment, matrix and opening-point order,
generates the batch PoW witness, and only then samples the extension-field
batching challenge `alpha`. The native proof carries `batch_pow_witness`, and
native verification checks it before redrawing `alpha`. This is opening-batch
grinding, separate from per-fold commitment grinding and final query grinding;
work at one site cannot be credited at another.

The unmodified pinned recursive implementation supports only zero batch PoW
bits. The isolated patch carries positive batch difficulty through native and
recursive parameters, descriptor and prepared-shape identities, witness layouts
and native/circuit challenge replay. The batch witness check precedes `alpha`;
zero difficulty requires the canonical zero witness and does not absorb an
extra element. Positive-difficulty descriptors are distinct from the retained
zero-difficulty encoding. Prepared input layouts change, so prepared artifacts
and keys must be regenerated even when a descriptor has zero difficulty.

Targeted native/full/prepared equivalence and rejection tests pass, including
positive batch work, canonical zero witnesses, claim mutations and all eight
opening coefficients. Retain the following requirements when freezing the site
for the first eight-input checkpoint:

1. Reuse native `PcsProverTranscript::batch_phase` for nonce generation at the
   configured difficulty. Preserve the native witness type, canonical encoding
   and failure behavior; do not add an unbound or off-transcript nonce search.
2. Carry the batch difficulty through checked native and recursive parameters,
   suite/config codecs, PCS domain-separator shape, prepared-shape identity and
   verifying-key/artifact identity. Validate field/word limits as for the other
   PoW sites. Allocate and constrain the witness in full and prepared recursive
   paths, including private-input and serialization layouts.
3. Match the exact pinned native transcript: bind the PCS seed and claimed
   evaluations, replay the batch witness check, sample `alpha`, then enter the
   separately seeded FRI low-degree transcript. Preserve existing commitment
   and query grinding positions. Compare native and circuit transcript states
   and challenges; never rely only on successful end-to-end proof verification.
4. Write rejection tests before implementation for changed validation behavior.
   Test missing, altered, insufficient-work and noncanonical witnesses; wrong
   difficulty, suite, seed, key and prepared shape; reordered or changed claims;
   a witness selected to fail after claim mutation; and a skipped or moved
   grinding step. A PoW nonce is not a one-time identifier: do not assert that
   every reused nonce necessarily fails the difficulty on a different transcript.
   Preserve canonical zero-witness behavior at zero difficulty without absorbing
   an extra transcript element. Exercise native, recursive and prepared/reused
   verifier paths with identical accepted and rejected fixtures.
5. Re-extract each affected circuit's table heights, main/preprocessed columns,
   constraint degree, quotient chunks, lookup dimensions and batched-opening
   count. Regenerate pinned `p3-security` reports from the actual configuration,
   retaining per-layer and 19-proof composition losses. Record the native search
   cost and recursive verification cost separately in phase measurements.

Freeze the checkpoint source/dependency revisions, W24 permutation and digest
layout, per-layer FRI/folding and all three grinding difficulties, transcript
codec, two-worker hiding patch, eight-input circuit artifact and verifying key
before the three measured trials. Freeze the binary and its build configuration
as well. The intended recursive candidates currently require 16 batch PoW bits;
the final actual-shape screen must verify that credit against the frozen
configuration and every checked verification path. Positive-difficulty
correctness tests cover the implemented plumbing, not the final profile's
performance or security margins. Reduced or zero-difficulty smoke configurations do
not establish the performance checkpoint. A later change to any frozen item
requires a new three-trial checkpoint before relying on its projection.

If implementation is shown to be infeasible, record the concrete failed
requirement and stop checkpoint progression. Re-screen aggregate and root
parameters with batch difficulty fixed to zero using the pinned `p3-security`
version and all unchanged security targets; query or commitment grinding cannot
replace missing batch credit by relabeling it. Broaden the search or reduce the
actual batched relation only with an explicit design. For every replacement
candidate report old/new table heights, column counts, degree, quotient chunks,
lookup dimensions and batched-opening count, then rebuild and measure that
configuration. The current planning-envelope zero-batch search does not meet
the quantum target; it does not prove that every alternative is impossible.
No passing replacement means pause and report rather than weaken the target.

## Early performance checkpoint

Immediately after the first D8/W24 eight-input merge produces a proof that
verifies with the opening-batch grinding prerequisite completed and checkpoint
configuration frozen, trigger this checkpoint before production integration.
Do not measure a configuration that still omits a planned grinding site or
delay the feasibility decision for unrelated integration work. This is an
engineering measurement; it does not replace security review or production
acceptance.

The current checkpoint worker includes leaf, eight-input and root preparation
code. If this complete setup fits the hard limit, prefer three measured full
N=16 schedules in one resident process over a root-cost proxy. Startup first
prepares the leaf and verifies bootstrap leaf and eight-input proofs, then
prepares the root, extracts actual shapes and screens them before granting
warm trials. A bootstrap proof is cold setup evidence, not one of the three
measured trials. A failure, OOM or security-screen rejection during setup
blocks warm trials and is itself a checkpoint failure to report. The retained
5-GiB final-profile attempt reached its cgroup limit and was OOM-terminated during
eight-input verifier-circuit construction/preprocessing. Eight-input proving
has not begun at that boundary. The phase includes circuit construction,
relation/AIR preparation and preprocessing commitment; its evidence does not
identify the individual allocation responsible. The checkpoint is paused.
Lower-cost correctness proofs do not establish that this setup fits the limit.

Run three trials on the same qualified target machine, using one proof job
and two native workers per proof. Complete input-independent circuit/key
preparation before timing and keep it resident in the worker boundary. Record
cold startup separately. Fix the suite, intended eight-input relation,
parameters, input proofs and verifying key across all three trials; retain
fresh hiding randomness for each proof. Record hardware, compiler,
source/dependency revisions, configuration and artifact identities. Preliminary
parameters remain unapproved; reduced smoke parameters cannot establish this
checkpoint. Real and padding leaves must use identical parameters.

For each trial report time and peak memory with equal prominence. Record
eight-input proving wall time, separate startup and standalone verification
times, and complete process-tree charged-memory peaks, including resident
preparation. Distinguish sampled per-phase charged-memory peaks from the
kernel's lifetime peak: samples are lower bounds, and the lifetime peak governs
hard-limit compliance. Serialized proof sizes describe retained encodings,
not allocator footprint. Apply the [minimum hardware checks](../linux-proof-measurement.md#baseline-and-comparison-hardware)
on one live machine for all three trials and record its actual model and
allocation. Retained EPYC 9V45 results describe a comparison measurement environment.
Start isolated merge timing with eight leaf
proofs available; include their generation in the N=16 projection. Verify every
resulting proof. Keep all three observations and report median proving time
and median memory peak, together with observed maxima. Enforce the current
10-GiB experimental process-tree ceiling with zero swap, including during startup.
This does not select a production memory budget. An OOM,
incorrect proof or observed cap violation blocks progression and must not be
discarded as an outlier.

### N=16 latency and memory projection

Project the N=16 `16 -> 2 -> 1` schedule with one proof job and two native
workers, so the two eight-input merges execute serially. Apply the
[recursive timing boundary](proof-composition.md#timing-boundary-and-retained-result-interpretation),
including all sixteen leaf proofs in controlled trials:

```text
T_N16_est = T_leaf16 + 2 * median(T_merge8) + T_root_est + T_timed_overhead_est
```

Use D8 leaf timings under the same schedule and configuration. Timed overhead
includes only per-candidate admission, witness, queueing, handoff and output
work between final-package arrival and root completion. Exclude input-independent
startup preparation from latency, retain its memory, and record cold time
separately. PoW, propagation and standalone root verification have separate
timings. Do not double count stage costs or reuse D4 timings. Until a root
measurement exists, one additional median eight-input merge may serve as an
explicitly labeled provisional root-time proxy; it is not a measured root
time or a proven upper bound. Document the assumed root shape.

Project the simultaneous charged-memory peak, not a sum of independent stage
peaks or three times the isolated merge peak. One explicit accounting model is:

```text
M_ready_peak_est = M_resident_all + max(
    W_leaf16 + R_leaf,
    W_merge8 + R_merge,
    W_root_est + R_root,
    W_transition_est + R_transition)
M_N16_est = max(M_startup_peak_est, M_ready_peak_est)
```

`M_resident_all` includes every prepared leaf, aggregation and root circuit/key
and fixed service allocation. `W` is additional active workspace, and `R` is
other concurrently retained proofs, buffers and allocator/cache retention not
already charged to the resident baseline or workspace. Include sixteen leaf
proofs, retention of the first merge while the second runs, both children
while the root runs, and allocation overlap at handoffs. Measure the baseline
and incremental workspace consistently; an isolated peak already containing
the baseline must not have it added a second time. Use the three-trial medians
for the projection and retain observed maxima and uncertainty separately. A
maximum over the cap cannot be hidden by a passing median.

Include the following breakdown for every trial and the projected N=16 service:

| Phase | Time evidence | Memory evidence |
| --- | --- | --- |
| Cold startup and readiness | Preparation-to-ready duration, excluded from proving latency | Lifetime and startup charged-memory peaks; each prepared circuit/key allocation and ready resident baseline |
| Sixteen leaves | All leaf proving time within the arrival-to-root boundary | Active leaf workspace, still-resident circuits/keys, retained input/proof buffers and phase charged peak |
| First eight-input merge | First merge proving time | Active merge workspace, remaining leaf proofs, resident circuits/keys and phase charged peak |
| Second eight-input merge | Second merge proving time | Active merge workspace, first merge proof and remaining leaf buffers, resident circuits/keys and phase charged peak |
| Root | Measured root time or explicitly labeled proxy | Root workspace/residency, both child proofs, output buffers and charged peak; distinguish shape-based estimates |
| Handoffs, serialization and cancellation | Timed overhead within the proving interval; separate teardown duration | Allocation overlap, allocator/cache retention and charged peaks, including releases after each handoff |

For each memory component state whether it is measured or estimated, its scope,
and whether the resident baseline is already included. Reconcile component
estimates with simultaneous sampled charged memory and the kernel lifetime
peak; do not claim exact component attribution from a process-wide peak alone.
Report all three individual phase peaks, medians, maxima and unresolved
attribution. An absent estimate or unmeasured phase cannot be replaced with zero.

Estimate not-yet-built root residency and workspace from its explicit shape
and memory model; eight-input timing alone does not establish root memory.
`M_startup_peak_est` includes preparation of every circuit that must be resident
in the final service. List every measured and estimated term. Missing cost
or residency terms leave the projection incomplete and cannot establish a
passing checkpoint. Revise latency and memory with actual root measurements
when available; this estimate is not a worst-case memory proof.

### Continuation thresholds

Apply the decision to projected total N=16 proof latency and peak memory, not
to the isolated merge. The next experiment uses a hard ceiling of
**10 GiB = 10,737,418,240 bytes**, with zero swap. This ceiling bounds the
experiment; it is not production acceptance. The production memory budget
remains undecided until actual peak measurements are available. Report
remaining experimental memory margin and uncertainty alongside timing margin.

| Projected N=16 latency and peak memory | Required action |
| --- | --- |
| At most 135 seconds and at most 10 GiB | Continue experimental implementation; production resource acceptance remains open. |
| More than 135 and at most 180 seconds, with peak memory at most 10 GiB | Continue experimental work and investigate leaf parameters and circuit optimizations in parallel, retaining all security requirements. |
| More than 180 seconds or more than 10 GiB | Pause progression and report the observations, available medians/maxima, projections and assumptions. Resume only after a decision on the target, hardware, optimization or N. |

An observed OOM or incorrect proof also blocks progression. The checkpoint
does not authorize a hardware or capacity change. N remains 16. N=32 is the
first separately scoped assessment after this checkpoint passes; do not perform
that assessment before the pass or increase network capacity as part of this work.
Early timing headroom does not establish acceptance or justify weaker security.

## Acceptance sequence

First obtain a working D8 hiding leaf and recursive verifier with complete
limb/transcript rejection coverage and opening-batch grinding support. Freeze
the final checkpoint configuration, run the early performance checkpoint at the
first verified eight-input merge, and follow its continuation decision.
Extract actual leaf, eight-input and root shapes before granting full warm
trials, and screen profiles under all requirements in the
[review scope](proof-security-review.md), including 16/2/1
composition losses. A missing theorem or term cannot be treated as a pass.

Only profiles passing the security screen receive three N=16 experimental trials
with one proof job and two native workers on qualified target hardware. Each
trial begins from a ready service with prepared circuits resident. Record
last-package-to-root latency, every proving phase, separate cold startup and
post-proof timings, whole-worker charged-memory peaks, actual enforced 10-GiB
experimental ceiling, zero swap and OOM events. The production memory budget
remains undecided and requires actual peak measurements. Select parameters from
complete security and performance evidence; do not lower security to reach 180
seconds. The existing D4 leaf-B and uniform-q92 timing medians are below 180
seconds but do not qualify: D4/W16 fails the required security targets and
those records lack the new timing and hard-limit evidence.

Freeze a complete reproducible review bundle after correctness and screening.
External review covers the final suite, parameters, composition and hiding
kernel. Production-path trials on qualified miner hardware follow finding
closure. A separate resettable N=16 network uses independent genesis, keys and
directories; the retained seven-node N=2 network remains unchanged. Make N=32
the first separately scoped assessment after the early checkpoint passes, and
defer historical
height-activation design until before mainnet.

## Preliminary parameter work

The [planning parameter screen](d8-parameter-screen.md) uses explicit estimated
shape envelopes. Three profiles per layer meet its conservative arithmetic
requirements conditionally. Recursive profiles require an additional 16-bit
opening-batch grinding site, absent from the unmodified pinned recursive
suite and covered by native/full/prepared runtime tests in the isolated patch.
The frozen actual configuration must retain every checked prerequisite above.
These are experimental candidates, not activation parameters. Actual-shape
extraction and independent composition review remain mandatory.

## Isolated checkpoint implementation

The `bench-d8` workspace contains the D8 leaf relation, eight-input aggregation,
root relation and resident checkpoint worker. It uses the experimental
recursion patch with standard W24 constants, 12-element scalar digests and the
72/102-element application layouts. The required correctness groups pass at
source baseline `fb9153de6cc3624a7b8c70a7551d0e8855b7f65a`:

| Test group | Passing coverage |
| --- | --- |
| Opening-batch grinding | Seven native/recursive parameter, transcript, witness and rejection tests |
| D8 integration | Seven suite, transcript, compression, statement-preprocessor and reusable-proof tests, including nonempty statement binding and canonical verifier/proof artifact round trips |
| Challenger AIR | Initial capacity and squeeze-chain constraints |
| Full/prepared recursion | Positive opening-batch grinding through full and reusable prepared paths |
| Application relations | Eleven selected checks, including an eight-input proof with public-digest mutation and last-child statement rejection, ciphertext limbs and padding |

These tests use lower-cost correctness fixtures. The eight-input application
fixture uses two queries and four batch/query grinding bits, rather than the
final checkpoint's 148/140-query and 16-bit grinding configuration. They
establish behavior only for the covered fixtures, not actual-shape security
acceptance, compliance with a selected production memory budget or performance
feasibility. The retained 5-GiB attempt stopped at preparation before eight-input
proving; the 10-GiB follow-up has no established result yet. No final
actual-shape/security bundle, three-trial warm median, measured root cost or
complete N=16 latency evidence is available. No continuation gate has passed.

### Native D8 CI coverage boundary

The `native-transaction` CI job prepares the isolated patched workspace and
checks the CPU admission path, formatting, targeted transaction/codec/
encryption/fee-settlement rejection tests, scanner unit tests, clippy, a
release build and registry dependency-pin equality. Its scanner invocation is
`--security-only --log-blowup 4 --queries 80 --grinding 16`, which extracts the
transaction AIR shape and diagnostic report without setup or proving. The job
also runs one low-cost native hiding proof test that generates and verifies a
proof and rejects a modified batch-grinding witness. It does not run the
`d8-checkpoint` worker, complete production-parameter security screening, a
full production-parameter proof generation/verification pair, 4-worker timing,
cgroup peak-memory collection, or the N=16 16-to-2-to-1 composition. The
checkpoint helper separately runs low-cost recursion and application
correctness fixtures before building the worker; those fixtures also do not
constitute final-profile performance or acceptance evidence.

The worker freezes source/dependency and build identities, actual circuit
shapes, parameter reports, preprocessing artifacts and verifying keys before
three warm trials. Input-independent setup remains resident inside the same
10-GiB experimental cgroup for startup and all trials, with zero swap. Each
trial regenerates hiding proofs with fresh randomness, executes all 16 leaves,
two serial eight-input merges and the root, and verifies the resulting proof. The root phase ends only after
canonical proof-artifact export, including the proof check inherent in that
API. The canonical byte buffer remains retained through standalone verification
and trial-result handoff. Standalone verification is measured separately after
the proof interval. Leaf/merge serialized-size diagnostics use temporary buffers
after verification and do not measure simultaneous retained serialized buffers;
native proof objects remain charged to the cgroup. Handoff-memory samples cover
the complement of proving intervals inside the timed boundary, including
adjacent phase readings. They report sampled total cgroup charge, not exact
allocation ownership. The worker records startup, readiness, leaf, merge, root,
verification and teardown phase boundaries. The controller must validate the
frozen reports and runtime configuration before granting
trials. Failed or incomplete setup cannot be relabeled a ready-service result.

The native/circuit-equivalence, coefficient/capacity binding, ciphertext-padding,
positive opening-batch grinding and end-to-end eight-input rejection tests are
pre-measurement gates. Reduced-difficulty smoke proofs test correctness only;
they are not security or performance acceptance. The isolated workspace and
patch change no node dependency, retained network configuration or live key.

### Native D8 transaction diagnostic

The isolated patched workspace also now generates and verifies the native
confidential transaction proof end to end. Eight transaction tests pass,
including canonical public-field binding and rejection of a changed statement.
The complete 15-row transaction-AIR scan passes the selected 80-bit screening
conditions. This result is separate from the paused recursive N=16 checkpoint
and does not change the retained network.

The diagnostic candidate is `log_blowup = 8`, `queries = 36`,
`grinding = 20`, `batch_pow_bits = 20`, `commit_pow_bits = 0`, and
`max_log_arity = 1`. Its measured transaction shape is 128 base trace rows,
1,007 main columns, 139 preprocessed columns, 2,000 constraints, eight
quotient chunks and 97 public values. Three macOS trials with four native
workers measured approximately 0.709--0.853 seconds for generation (median
approximately 0.744 seconds), approximately 11.6 milliseconds for single-core
verification, and approximately 415,000--419,000 proof bytes. Every observed
proof is below the adopted 524,288-byte comparison threshold.

The corresponding PCS estimator report gives 185 classical conjectured bits
and 163.8 classical Johnson bits for this actual transaction AIR. The separate
selected quantum ledger gives 81.9 bits for the halved Johnson challenge union
and 123.3 ideal BHT bits for the PCS commitment. The external BLAKE3-256
ciphertext-byte binding has a nominal BHT exponent of 85.3 bits and is excluded
from the PCS report. These calculations do not establish full-protocol security
or cryptographic approval; see [collision accounting](../bht-security-accounting.md).
macOS supplied no Linux cgroup peak
memory evidence; the trials therefore do not establish a memory budget or
production acceptance. `production_selection_allowed` remains `false` until
the qualified Linux build, cgroup measurement, pinned artifact bundle and
independent review gates pass.
