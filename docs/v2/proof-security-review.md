# Recursive Proof Security Review Scope

> **Paused V2 research.** Recursive aggregation and historical proof compression are outside native V1. These experimental parameters, timings and resource limits do not qualify the [current V1 route](../v1-overview.md).

Status: requirements and review preparation. The selected target is KoalaBear
D8, standard Plonky3 Poseidon2 W24 and 12-element digests. It is not yet a working
registered recursive suite at the pinned dependency revision. No security
approval, parameter activation or production acceptance is implied.

## Acceptance requirements

Apply every requirement separately to the leaf, eight-input aggregation, root
and complete N=16 `16 -> 2 -> 1` recursive composition, including all losses.

| Model | Minimum | Required accounting |
| --- | ---: | --- |
| Classical conjectured | 128 bits | Complete instance-specific bound, including algebraic, batching, lookup, FRI and commitment terms |
| Classical proven | 100 bits | Johnson/list-decoding bound, explicitly distinguished from unique decoding |
| Quantum challenge terms | 100 bits | OOD, DEEP, ALI and FRI folding after the selected quantum Fiat–Shamir halving model and composition losses |
| Quantum commitment collisions | 100 bits | Merkle and commitment hashes under BHT, with explicit oracle/memory assumptions |

The quantum halving model is a required screening model, not a proof that a
classical estimator composes in the quantum random-oracle model. An independent
human review must justify its applicability, grinding treatment, multi-target
losses, transcript adaptivity and recursive composition. Missing terms or an
unresolved security-limiting finding block adoption.

## Suite and implementation identity

Use KoalaBear `p = 2^31 - 2^24 + 1`, extension degree 8, the standard Plonky3
width-24 Poseidon2 permutation and a 12-base-element digest. Do not substitute
W32, 16-element digests, custom round constants or a truncated D8 digest.
Pin the permutation rounds/constants, sponge rate/capacity, binary compression,
all domain tags, native/circuit transcript encodings, cap geometry and codecs.

The baseline dependencies are Plonky3 `0.9.0-rc.2` and recursion revision
`3a69ba61f713c8400b14eb3d8f0e52caa13512c7`. A D8 implementation will need a
reviewed source delta and new artifact/key identities. The baseline contains
no registered D8/12-element suite; the existing W24 binary Merkle circuit
rejects its packing geometry. See the [implementation plan](d8-w24-recursion.md).

Twelve KoalaBear elements have approximately 371.86 bits of digest space:
ideal generic collision exponents are 185.93 classical and 123.95 under BHT.
The D8 challenge field has approximately 247.91 bits. These are ceilings from
ideal models, not security conclusions: degree, folding, capacity, permutation
cryptanalysis and composition losses must still be accounted for.

## Internal D4 analysis boundary

D4/W16 uses eight-element digests, approximately 247.91 digest bits, with an
ideal BHT collision exponent of only 82.64 bits. Its ideal classical collision
exponent is 123.95 bits. It fails the required targets regardless of the query
score. D4 challenge-domain terms also require the actual degree/shape analysis.
The internal conclusion is: **D4/W16 does not meet the post-quantum target**.
Do not send q42, q92 or leaf B for external parameter approval.

The historical configurations are q42 `(2,42,16)`, q92 `(2,92,16)` and B with
leaf `(4,46,16)` and q92 parent/root parameters, expressed as log blowup,
queries and query grinding. B is measurement-method validation only. Preserve
its [measurements](proof-composition.md) and frozen evidence;
do not treat `4 * 46 + 16 = 200` as a complete security estimate.

Generate internal reports with exactly pinned `p3-security`. Record actual AIR
and committed trace dimensions, constraint degrees/counts, hiding extensions,
quotient chunks, preprocessing, opening points, total batched functions,
lookups and enforced grinding sites. List every conjectured and Johnson term,
the weakest term and the complete-composition envelope. Distinguish any
conservative batch envelope from an exact multi-instance theorem. Never report
the best unique-decoding score as the requested Johnson score.

## Final D8 review tasks

1. Preliminary profiles may be screened against explicit estimated shape envelopes.
   Final selection requires D8 correctness and actual-shape extraction.
   Keep all real and padding leaves on identical parameters, relation, key,
   hiding and serialization. Pin child verifiers in parent circuits. Screen
   aggregation/root parameters as well: the legacy q92 query count has no
   exemption from the per-layer and complete-composition targets.
2. Review OOD, DEEP, ALI, batching, FRI folding and LogUp arguments, including
   finite-field restrictions, challenge order and every grinding site. Do not
   double-count grinding or credit a site not checked recursively.
3. Analyze 16 leaves, two eight-input proofs and one root without assuming
   independent failure events. Include additive-set multiplicity, anchor
   membership, fee carries, miner binding, native uniqueness and all public
   statement fields. Wider hashes require a reviewed set-hash layout.
4. Review zero knowledge independently: random-codeword masking, hiding rows,
   fresh OS entropy, parallel RNG derivation and lifetime/erasure of witnesses
   and seeds. Review the two-worker native hiding kernel and error paths.
5. Prove native/circuit agreement for all 24 permutation inputs, 12 digest
   outputs and eight extension coefficients; challenge observation/squeezing,
   padding, caps, malformed encodings and wrong-suite/key rejection.
6. Freeze complete sources, dependency checksums, compiler/build instructions,
   configuration, artifacts and verification keys. Include reproducible
   `p3-security` reports and tests. An excerpt-only intake is not a final audit
   snapshot. Assess changes after the freeze and repeat affected review.

## Measurement and integration gates

Only profiles passing the full screen proceed to three N=16 `16 -> 2 -> 1`
experimental runs on qualified target hardware, one proof at a time and two native
workers. The latency target is at most 180 seconds from last-package arrival to
root-proof completion, including leaf proving. Prepare all input-independent
circuits at service startup and keep them resident; record cold startup
separately and exclude its duration from latency. Startup and resident memory
remain inside the next experiment's enforced 10-GiB process-tree ceiling
(10,737,418,240 bytes), with zero swap. This is not a production acceptance
budget; select that budget after actual peak measurements. Record
leaf, each eight-input node, root, standalone verification, cold startup and
both lifetime and interval memory peaks. Give stage time and memory equal
prominence: separate prepared residency, active workspaces, retained proofs and
buffers, allocation overlap at handoffs and startup. Mark every projected term
as measured or estimated and reconcile it with simultaneous charged memory.
Report every attempt. Uncapped characterization cannot pass that gate.

The early checkpoint uses three same-machine trials after opening-batch
grinding is complete and the configuration is frozen. At most 135 seconds
within the 10-GiB experimental ceiling permits continued experiments; more than
135 and at most 180 seconds under that ceiling requires parallel optimization;
more than 180 seconds or more than 10 GiB pauses progression. An OOM or incorrect
proof also blocks progression. A result under this ceiling does not close
production resource acceptance; its memory budget remains undecided.
Historical Linux measurements used an EPYC 7763 Ubuntu 24.04 VM exposing two
cores and four vCPUs, with EPYC 9V45 as a comparison environment. These models
are not hardware requirements. Current qualification uses the minimum
configuration: x86-64-v3 CPU/OS support, at least four available vCPUs and
16 GiB for validators or 32 GiB for miners, with no scalar fallback. See the
[hardware qualification requirements](../linux-proof-measurement.md#baseline-and-comparison-hardware).

Retained D4/W16 leaf-B and uniform-q92 setup-excluding timing medians are
29.591 and 64.04 seconds, below 180 seconds numerically. D4/W16 fails the
required security targets, so these are not acceptance results. N=32 is the
first separately scoped assessment after the D8 early checkpoint passes and is
excluded from this work.

Independent review covers the final D8 suite and profiles, not a prior D4
measurement. After findings close, integrate and validate the full production
path on qualified miner hardware using the [acceptance plan](../prover-acceptance.md).
Keep existing N=2 history separate. Neither benchmark verification nor estimator
output alone establishes production or post-quantum acceptance.
