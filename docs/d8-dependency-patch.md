# D8 Dependency Patch and Review Boundary

The [monetary revision](v1-economics.md) is included in the engineering-frozen
`native-v1-economics-1` proof profiles. Revised lock/reward relations have new
actual-AIR reports, source-bound public keys and hosted measurements. Release
validation, independent review and native network activation remain separate
gates. Further relation changes require renewed qualification.

Status: experimental source implementation with fixed project-fork revisions.
The native application directly pins the source revision and registry lock graph;
the earlier local-path adapter is retired. The upstream proposal is
[Plonky3-recursion #479](https://github.com/Plonky3/Plonky3-recursion/pull/479). No retained node
is changed by this work. Parameter freeze for the isolated native V1 proof is
separate from node/network activation and independent cryptographic review.

## Source lineage

The source delta is in **Plonky3-recursion**, based on
`3a69ba61f713c8400b14eb3d8f0e52caa13512c7`. Base Plonky3 registry packages,
including `p3-security`, remain pinned to `0.9.0-rc.2`. Base Plonky3 already
provides KoalaBear D8, standard Poseidon2 W24 constants and native opening-batch
grinding; this patch does not modify those registry packages or Cargo caches.

Two complete revisions separate upstream-neutral APIs from compatibility:

| Source line | Fixed revision | Scope |
| --- | --- | --- |
| Native suite | `cb50fe9bb2dcd76fc7de1b71d0cd3f099eb235db` | Experimental suite, batch work, typed bounded hiding workers |
| Downstream compatibility | `d3d15b2b5d1325fb38ebc8979c1cae04b761e71f` | Same APIs plus bounded downstream environment compatibility; no-std serial behavior preserved |

The exact dependency history is retained in the `dependencies/plonky3-recursion` branch of [the project repository](https://github.com/howard1984/siworld/tree/dependencies/plonky3-recursion). Cargo and the source-lineage adapter continue to select the fixed revision and verify its tree; the transport location does not change the dependency source.
The source patch, base revision and complete dependency lock graph remain pinned
together in `crates/bench-d8/dependency-lineage.toml`. Cargo uses the full
downstream revision rather than a mutable branch name. The build checks its
exact source tree and the separate upstream-base-to-downstream audit patch.
Operation does not depend on upstream acceptance.
Unmodified upstream code keeps its existing license notices; every modified
surface is included in the [audit registry](../.github/audit-registry.json).

## API coverage

| Surface absent from the stock dependency | Added implementation and required coverage |
| --- | --- |
| D8 random-codeword factory | `ExperimentalKoalaBearD8Poseidon2W24RandomCodewordConfig` and factory with native parameter geometry |
| W24 scalar permutation/challenger | `Poseidon2Config::KOALA_BEAR_D1_W24`, dedicated challenger table and constrained eight-coefficient scalar lift |
| Suite identity | Experimental `SuiteIdV1` value `0xF824`, twelve-element digest codec and artifact/backend dispatch |
| Opening-batch work | `FriConfigV1::with_batch_pow_bits`, native/full/prepared transcript order, runtime witnesses, descriptor serialization and nonce rejection |
| FRI verifier parameters | `FriVerifierParams::try_with_mmcs_and_batch` and checked compatibility constructors; zero-work encoding remains stable |
| Hiding execution policy | Typed one/two-worker opt-in, serial default, unsupported-policy rejection and independent RNG/kernel review |

The native transaction and settlement proofs use `p3-uni-stark`; their proving
path does not invoke the recursive batch-prover worker pool. Four Rayon workers
in the native diagnostic must not be confused with recursive two-worker hiding
isolation. The compatibility environment hook is excluded from the upstream
proposal. Existing suites are not silently replaced.

## Test and audit scope

Focused worker-policy tests cover valid and invalid choices, exact pool size,
non-hiding caller-pool preservation and rejection of two workers without
parallel support. The dependency also contains fixtures for native/circuit
transcript equivalence, interleaved MMCS/challenger work, both binary-compression
directions, suite/descriptor identity, all scalar coefficients, positive batch
work and changed nonce/opening rejection through full and prepared paths.
Test presence is distinct from observing all upstream checks on a new revision.
The final implementation passed 14 descriptor tests, seven batch-work API
tests (one overlaps the descriptor group), a full-width scalar witness-bus
rejection test, and upstream-neutral worker policy tests with parallel support
(three) and without it (two). These are focused correctness checks. The new
W24 registry entries append after all existing wire tags. Zero-work native
proof/descriptor decoding remains compatible, but rebuilt recursive circuits,
verification keys and prepared artifacts may change identity and require
regeneration and pinning.

No recursive performance benchmark is required to evaluate the native V1 route.

External review must include the modified dependency sources, native AIRs,
application byte bindings, all Fiat–Shamir work sites, descriptor/key binding,
scalar coefficient constraints, RNG derivation and opt-in hiding parallelism.
The raw and selected-model [security ledgers](bht-security-accounting.md) are
inputs to review, not an independent soundness theorem.

## Remaining engineering estimate

| Work package | Engineering days | Completion evidence |
| --- | ---: | --- |
| Fixed source distribution, direct Cargo pins and adapter retirement | Implemented; release validation pending | Immutable remote revision and unchanged registry graph; observe clean remote build |
| Native/full/prepared adversarial and feature-matrix regression | 2–3 | Observed positive/negative tests, legacy suite/zero-work compatibility |
| Frozen audit snapshot and native application integration | 1–2 | Source, lock, codec, descriptor, key, report and executable identities |
| Upstream review follow-up | 1–3, parallel | PR #479 submitted; review responses and required upstream checks pending; merge is not a release dependency |

These are effort estimates for remaining verification and distribution work,
not a production-readiness claim. Cryptographic review duration is separate.

## Proof-parameter freeze and activation

The native proof freeze records fixed dependency revisions, the implemented
transaction and fixed-576 settlement AIRs, trusted verifier identities,
canonical public/proof/envelope/sidecar codecs, actual-instance security reports
and successful resource measurements. It does not depend on an upstream merge or
completion of the node/wallet/network implementation. A diagnostic scanner row
alone is insufficient; its source, shape and artifacts must match the checked
freeze manifest. Independent cryptographic review remains separate.
The [two-output engineering freeze bundle](../crates/bench-d8/artifacts/v1-native-freeze.json)
remains unchanged baseline evidence. The
[multi-asset transaction engineering profile](../crates/bench-multi-asset/artifacts/v1-transaction-profile.json)
separately binds the three-output relation, dependency graph, public verifier
key and selected actual-instance security report. Its 39 hosted trials comprise
24 transaction grid trials, three selected one-worker transaction trials and
12 settlement/issuance trials split across one/four-worker processes. Its fixed
source boundary excludes unreferenced layout experiments.

The selected transaction profile is `log_blowup=7`, 41 queries and 20-bit
query/batch grinding, with zero commitment grinding, binary folding and
`log_final_poly_len=0`. Its selected quantum Johnson ledger is approximately
81.692 bits. The scan compares blowup 5–8 with grinding 20/24. Every one of
three generation trials must complete within two seconds using four workers
on a host meeting the [minimum configuration](v1-deployment.md#minimum-host-configuration).
The recorded EPYC measurements describe their environment, not a CPU-model
requirement. Among passing configurations, the smallest maximum observed
proof body wins. Its admission cap is at least 10% above that sample maximum,
rounded up to 64 KiB: 655,360 bytes (640 KiB) for the selected profile. The
selected one/four-worker samples reached 588,832 bytes; the cap retains more
than 10% above that maximum. This policy does not claim a mathematical
proof-size bound. The [transaction format](route-a-v1.md) specifies the current
snapshot-bound envelope with a 2,184-byte prefix and 78-byte private sidecar.
Settlement and issuance retain independent 524,288-byte proof caps.
Block capacity remains 576; minimum uplink follows complete bounded wire
accounting: 43 Mbps minimum, at least 15% unused link capacity, and 100 Mbps
recommended. The [node and network plan](v1-node-network-plan.md) defines initial
byte/CPU/in-flight policies and the remaining shared transition, compact relay,
retention, synchronization and hybrid-transport milestones.

This transaction freeze does not update the retained legacy node or activate
a native network. The native engineering runtime has explicit key, codec,
snapshot and admission adapters; complete wallet/network integration and
release qualification remain separate. A passing resource diagnostic does not
qualify durable wallet recovery or 4,096-canonical-snapshot lifecycle handling
under sustained operation and reorganization.
Node admission still needs isolated single-core verifier-memory and
malformed-input work measurements. Generation memory from a combined
setup/prove/verify process cannot establish a verifier-memory bound. These
remaining measurements may revise local operational policies without changing
the frozen proof parameters. They and independent review precede activation,
not recording the proof-parameter freeze.
