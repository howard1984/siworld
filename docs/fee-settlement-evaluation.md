# Confidential Fee Settlement Evaluation

Status: engineering-frozen fixed-576 settlement proof profile for the
[revised monetary relation](v1-economics.md). The
[source-bound manifest](../crates/bench-multi-asset/artifacts/v1-native-proof-profiles.json)
records parameters, actual-AIR reports and public preprocessing identities.
Fresh EPYC measurements cover the public mode, reward-plan binding, SIP asset
and one/five reward-note relation. The benchmark uses synthetic plan allocations;
nodes must recompute the plan from trusted state and independently validate
pool, burn and fund transitions. Required CI, key reproduction,
complete native integration, independent verifier resources and independent
review remain separate gates. No network activation is implied.

## Revised fixed-576 measurement

[Hosted run 40746559683, attempt 2](https://github.com/siworld-labs/siworld/actions/runs/40746559683/attempts/2)
measured source `7eecc60b9a1b0e7d6b348952daae06cd145abf3a` on Ubuntu 24.04,
AMD EPYC 7763, two exposed physical cores and four vCPUs. The release baseline
is `x86-64-v3`. Settlement uses blowup 8, 36 queries, 20-bit query/opening-batch
grinding, zero commitment grinding, binary folding and final-polynomial log
length zero. The native node admission cap is now 655,360 bytes; this
document distinguishes the earlier synthetic samples, the fixed-576 priority-fee
measurement and the separate maximum-claim envelope diagnostic below.

| Extracted AIR dimension | Value |
| --- | ---: |
| Base rows | 1,024 |
| Main columns | 581 |
| Preprocessed columns | 609 |
| Public values | 7,050 |
| Constraints | 19,703 |
| Maximum degree | 3 |
| Classical conjectured union (bits) | 185.000000 |
| Classical Johnson union (bits) | 163.974037303 |
| Quantum-halved Johnson challenge union (bits) | 81.983705354 |
| Selected W24 BHT collision ledger (bits) | 123.333333333 |

| Workers | Three generation times (s) | Generation median (s) | Verification median (ms) | Observed proof bytes | Maximum charged peak (bytes) |
| ---: | --- | ---: | ---: | ---: | ---: |
| 4 | 5.523829281 / 5.616304295 / 5.424077424 | 5.523829281 | 20.130663 | 514,635–520,203 | 3,161,432,064 |
| 1 | 11.954381874 / 11.282064820 / 11.290169489 | 11.290169489 | 19.914259 | 499,130–516,699 | 3,158,740,992 |

All six fresh process-tree scopes completed with `memory.max=5368709120`,
`memory.swap.max=0` and zero recorded memory-event deltas. Setup is separately
timed. Charged peaks cover complete setup/prove/verify processes, descendants
and recorder. The one-worker verifier timer is not a verifier-only process,
and its peak cannot establish independent verifier memory. No per-phase
charged-memory peak is inferred. The 5-GiB scope is a diagnostic boundary,
not a miner hardware requirement.

The [complete evaluation](v1-multi-asset-evaluation.md) records setup and process
wall medians, all three proof relations and the full transaction grid. The
native fund registry supports 32 immutable keys and eight signed claims per
block; launch recipients and basis-point shares remain unconfigured. This measurement supplies no production allocation
or proof of complete-block processing. The old two-output tables below remain
explicitly diagnostic evidence only.

## Fixed-576 priority-fee measurements

[Run 41000973551](https://github.com/siworld-labs/siworld/actions/runs/41000973551)
measured source `7e0ccdf3ed722cbaa3fffd53bba1380c0554a72a` on AMD EPYC
7763 with four workers and three fresh process-tree scopes. Every one of the
576 settlement fee positions used the priority tier. The witness had five
Holder reward notes with synthetic allocations; consensus reward accounting
remains a separate node responsibility. Parameters remained log blowup 8,
36 queries and 20-bit query/opening-batch grinding. Setup was timed separately
from proof generation. All three generated proofs were verified.

| Trial | Proof body (bytes) | Generation (seconds) | Charged cgroup peak (bytes) |
| --- | ---: | ---: | ---: |
| 1 | 514,539 | 5.472528286 | 3,159,597,056 |
| 2 | 513,675 | 5.475584285 | 3,159,633,920 |
| 3 | 507,387 | 5.490914676 | 3,159,834,624 |

The maximum observed body is 514,539 bytes, below the 589,824-byte measurement
ceiling by 75,285 bytes. It leaves 140,821 bytes, or 21.49%, unused under the
655,360-byte wire cap. Charged peaks are cgroup v2 `memory.peak` for setup,
proving, verification, descendants and recorder; they are not process RSS or
verifier-only memory. All memory-event deltas were zero. These samples do not
prove a maximum over randomized proof outputs.

A separate successful job in that run verified eight actual ML-DSA-65 fund
claim signatures, totaling 54,264 encoded bytes, and rejected a ninth claim.
Its synthetic 576-position maximum-size envelope encoded to 381,600,975 bytes;
the compact envelope encoded to 2,890,196 bytes. The logical receive reservation
was 382,324,055 bytes. Claims are independent envelope records and do not add
inputs to the settlement AIR or change its statement. This diagnostic used
opaque proof fills: transaction, settlement and issuance proofs were not
verified, full block state was not applied, and RSS was not measured. It must
not be described as accepted full-block execution with 576 real proofs.

The [machine-readable measurement record](../crates/bench-multi-asset/artifacts/v1-native-fixed576-settlement.json)
preserves source, parameters, timing, memory scope and these limits. A newer
head run on EPYC 9V74 also passed the proof-body limit, but its timing is not
an EPYC 7763 baseline. Combined real-proof full-block state acceptance with
eight valid claims remains a separate integration gate.

## Fixed requirements

Each transaction publishes one fee commitment in its proof statement. The
commitment is a twelve-element KoalaBear digest encoded as twelve canonical
little-endian `u32` values, so it adds **48 public statement bytes per
transaction**. The native three-output body is 2,027 bytes. Adding the fee
commitment and 40-byte snapshot selector gives 2,115 permanent bytes per
position before proof, relay and block-level overhead. The earlier two-output
1,742-byte body is separate diagnostic evidence. The commitment, proof
envelope, and any private-relay sidecar must be counted separately in capacity
and denial-of-service budgets.

The private opening contains the fee and eight independently sampled canonical
KoalaBear blinding elements (32 encoded bytes, about 247.91 bits of entropy).
The fixed sidecar does not carry a tier or padding flag. A verified mempool entry retains
that opening for miner ordering and settlement. The fixed-size sidecar carries the transaction
binding and opening; it has no standalone signature or second encryption
layer. Nodes recompute the public commitment and transaction binding before
forwarding or retaining it. Sidecar transport confidentiality and peer
authentication come from the planned X25519 + ML-KEM connection handshake.
Missing sidecars, mismatched openings, and sidecars bound to another
transaction are discarded before state mutation and recorded in bounded
peer-abuse diagnostics. The opening is never written to a block or exposed as
a public block field.

The settlement relation is a native, non-recursive STARK. For every fixed
position it checks the commitment opening and adds fees with checked integer
carries. The transaction proof enforces the private anchor's fee schedule and
zero-fee padding rule; settlement must not impose the current fee schedule on
an older anchored transaction. All fees enter reward note zero; the AIR binds
the public mode, node-recomputed consensus reward plan and every one/five SIP
reward note, including its unlock height. Pool, burn and fund updates are
independently checked by the shared node transition. The proof binds ordered
compact references and capacity,
so an omitted, duplicated or reordered transaction cannot reuse a valid proof.

Transaction, settlement and native issuance proofs and private fee-opening
sidecars are retained for three elapsed days after final confirmation, then
deleted under durable finality/retention metadata. Public fee commitments and
proof-free settlement declarations remain permanent. V1 has no archive-node
role; checkpoint bootstrap has an explicit trust policy.

Zero-valued dummy inputs skip commitment-tree membership checks in the
transaction AIR. They still derive a fresh nullifier and remain subject to
the same uniqueness and fixed-shape checks as real inputs. A real transaction
with a zero fee and a dummy transaction with a nonzero fee are invalid.

## Required measurements

The revised settlement AIR has fixed capacity 576, including deterministic
internal zero-fee rows when a block has fewer active positions. The fresh
576-position profile above is the maximum-capacity isolated measurement.
Workload evaluations with 64, 128, 256, 384 and 512 active positions remain
separate evidence; they do not select different public keys. Measure each
workload three times after one-time setup and dependency loading.
The report records the median and all three samples for:

* AIR rows, main columns, preprocessed columns, constraint count and maximum
  degree;
* native proof-generation and verification wall time;
* canonical proof bytes;
* peak charged memory for the prover process and children; and
* single-proof verification wall time and peak charged memory.

The measurement process must run in an independent cgroup and record
`memory.max`, `memory.swap.max`, `memory.peak`, and `memory.events`. No formal
proof-memory ceiling is selected by this evaluation; an initial diagnostic may
run to the qualified machine's available capacity. Any limit used for a sample
must be reported, and a limit breach or a proof-size limit breach must be
visible in the result rather than silently omitted. The report must retain the
exact suite, verifier key hash, compiler profile, worker count, capacity, and
input digest list used by each sample.

The earlier variable-capacity diagnostic validator prints its private-bundle
schema with `python3 scripts/check-fee-settlement-evaluation.py --schema`.
It requires six capacities and three trials per capacity, with AIR/key/binary
identities. That schema validates the older diagnostic series below; current
economic-profile qualification uses the source-bound transaction/relation
manifest and the 39-scope measurement record linked above.

Use the extracted revised dimensions and measurements above for the current
relation. Older diagnostic witness counts and variable-capacity AIRs below do
not describe its mode-dependent reward statement or fixed public key.

## Two-output diagnostic baseline

This section preserves measurements of the earlier two-output diagnostic
relation. The current three-output SIP-reward relation and its measured profile
are described in the [multi-asset evaluation](v1-multi-asset-evaluation.md).
These baseline samples do not replace source-bound current-profile evidence.

The baseline contains a transaction fee-commitment relation, a native
reference design, and a fixed-capacity settlement AIR/prover in
`crates/bench-d8/src/fee_settlement_air.rs`. The AIR uses one W24 Poseidon2
fee-commitment row per slot, four 16-bit fee limbs with range checks, checked
tier carries, and a checked running sum bound to the miner amount. It is a
research implementation and does not activate Scheme B on the node or
consensus path.

The three-trial harness is `fee-settlement-bench`. Run it inside the qualified
independent cgroup with the patched D8 dependency:

```
cargo run --release --locked --manifest-path crates/bench-d8/Cargo.toml \
  --features parallel --bin fee-settlement-bench -- \
  --output .local/fee-settlement-measurements.json
```

The default profile is the transaction-candidate diagnostic selected by the
80-bit transaction scan (`log_blowup=8`, `queries=36`, query grinding 20,
batch grinding 20, commit grinding 0, maximum log arity 1). It is an
experimental profile and is not cryptographic approval. The legacy recursive
planning profile can be selected only for comparison with
`--legacy-candidate`; `--fast` remains a non-secure smoke-test profile.

It covers capacities 64, 128, 256, 384, 512, and 576, excludes one-time setup
from timings, and records native generation, verification, proof bytes, and
cgroup/VmHWM observations. The resulting private bundle must pass
`scripts/check-fee-settlement-evaluation.py`; no generated bundle belongs in
the public repository. Existing transaction proof timings cannot be used as a
settlement measurement because they do not prove the private sum or bind the
miner reward note.

### Diagnostic transaction-candidate run

The following three-trial run used the default transaction-candidate profile on
the local macOS diagnostic host. Values are medians; proof bytes and timings
are native measurements after one-time setup. The host did not expose a
delegated Linux cgroup, so charged-memory values are unavailable and this run
does not satisfy the qualified-host acceptance gate. The process used ten
Rayon workers; a separate four-worker comparison is retained as private
diagnostic evidence and neither run is a qualified-host result.

| Capacity | AIR rows | Main / preprocessed columns | Constraints | Generation (ms) | Verification (ms) | Proof bytes | Charged-memory evidence |
|---:|---:|---:|---:|---:|---:|---:|:---|
| 64  | 128  | 329 / 67  | 1,107 | 321 | 7  | 267,425 | unavailable |
| 128 | 128  | 329 / 131 | 1,875 | 249 | 8  | 276,647 | unavailable |
| 256 | 256  | 329 / 259 | 3,411 | 631 | 9  | 326,931 | unavailable |
| 384 | 512  | 329 / 387 | 4,947 | 1,009 | 11 | 380,191 | unavailable |
| 512 | 512  | 329 / 515 | 6,483 | 927 | 12 | 411,903 | unavailable |
| 576 | 1,024| 329 / 579 | 7,251 | 2,142 | 22 | 456,315 | unavailable |

The individual samples were retained in the private measurement bundle. The
576-position proof was 448,059--459,627 bytes across the three trials and
is below the earlier 524,288-byte settlement-proof maximum. Settlement
proofs have their own capacity budget; their size does not select or replace
the transaction proof limit. The benchmark now resolves the process's cgroup v2
membership from `/proc/self/cgroup` before reading `memory.max`,
`memory.swap.max`, `memory.peak`, and `memory.events`; a fallback to `VmHWM`
is labeled as non-cgroup diagnostic evidence.

The reference model and native AIR tests exercise the four required rejection
cases: a commitment sum different from the miner reward fee component, a
forged opening that does not recompute the published commitment, a padding
position with a nonzero fee, and a real position with a zero fee. Until
the revised relation's complete integration and review gates are satisfied,
these two-output samples remain historical diagnostics. They are not
production-readiness or activation evidence for the current profile.

No Ubuntu 24.04 cgroup result from the historical EPYC 7763 measurement environment is included in this
two-output baseline table. Current-profile measurements are recorded separately
in the [multi-asset evaluation](v1-multi-asset-evaluation.md). The macOS series above cannot supply Linux kernel charged-memory
evidence. The hosted native cgroup workflow provides a separate three-trial
process-tree diagnostic series on Ubuntu 24.04, with kernel `memory.peak`,
`memory.events`, exact limit readback and actual CPU identity retained in its
sanitized artifact. A fresh hosted allocation must satisfy the
[minimum configuration](v1-deployment.md#minimum-host-configuration), without
a CPU-model requirement, and does not establish isolated verifier-memory bounds. See
[the measurement procedure](linux-proof-measurement.md#hosted-native-diagnostics).
