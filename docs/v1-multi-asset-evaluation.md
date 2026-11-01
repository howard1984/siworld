# Native Multi-Asset Proof Profile and Measurements

Status: engineering-frozen proof parameters for the revised native V1
transaction, fixed-576 settlement and three-note issuance relations. These
relations include trusted snapshot-height input locks and Voyager/Holder
reward settlement. The [profile](../crates/bench-multi-asset/artifacts/v1-transaction-profile.json)
and [relation manifest](../crates/bench-multi-asset/artifacts/v1-native-proof-profiles.json)
bind source, parameters, actual-AIR security and public preprocessing identities.
Reproduce those identities using [the public procedure](native-proof-profiles.md).
Required CI, independent review and node/network acceptance remain distinct
release gates. No public-network activation or whole-system approval is implied.

The suite is KoalaBear D8, standard Poseidon2 W24 and twelve-element digests.
All three relations run natively without recursive aggregation.

## Selected transaction profile

The selected profile is `log_blowup=7`, 41 queries, 20-bit query grinding,
20-bit opening-batch grinding, zero commitment grinding, binary folding and
final-polynomial log length zero. Each of its three four-worker generation
trials is below two seconds. It minimizes the largest observed proof body
among the measured profiles passing the generation and body-size limits.

| Selected-profile measurement | Value |
| --- | ---: |
| Four-worker generation trials, seconds | 1.531155438 / 1.429902190 / 1.462877730 |
| Four-worker generation median, seconds | 1.462877730 |
| Four-worker proof bodies, bytes | 581,392–585,808 |
| One-worker proof bodies, bytes | 585,520–588,832 |
| Maximum body across both worker groups, bytes | 588,832 |
| Body admission cap, bytes | 655,360 (640 KiB) |
| Cap above maximum observed body | 11.2983% |
| Maximum charged process-tree memory across both groups, bytes | 525,234,176 |
| One-worker verification median, milliseconds | 17.006900 |
| Classical conjectured union, bits | 185.000000 |
| Classical Johnson union, bits | 163.384583911 |
| Quantum-halved Johnson challenge union, bits | 81.692218869 |
| Selected W24 commitment BHT ledger, bits | 123.333333333 |

The cap is at least 10% above the maximum selected body from all six processes,
rounded up to 64 KiB. It is an enforced admission policy, not a mathematical
upper bound for every randomized valid proof. Reject oversized encodings;
never truncate a proof or reduce security to fit. Settlement and issuance have
independent 524,288-byte caps. The earlier two-output `bench-d8` decoder retains
its own 512-KiB limit and does not admit this revised relation.

Three samples do not bound grinding tails or shared-host contention. The
576-position maximum and security requirements are unchanged. A smaller cap,
different parameters or lower bandwidth requirement needs a new measured,
source-bound revision.

## Measurement environment and scope

[Hosted run 40746559683, attempt 2](https://github.com/siworld-labs/siworld/actions/runs/40746559683/attempts/2)
measured source commit `7eecc60b9a1b0e7d6b348952daae06cd145abf3a`.
The runner reported Ubuntu 24.04, AMD EPYC 7763, two exposed physical cores,
four vCPUs and four affinity CPUs under Microsoft virtualization. AVX2 was
present; AVX-512 was absent. This is the exposed reference profile, not a
claim of exclusive access to the physical host or a reserved persistent VM.
It is retained measurement metadata, not a required CPU model. Current
qualification uses the [minimum deployment configuration](v1-deployment.md)
and records each actual allocation without changing these historical samples.

The release uses fixed `x86-64-v3`, pinned dependencies and the CPU admission
guard. Grid processes use four Rayon workers and two hiding workers; separate
one-worker processes use one Rayon worker and one hiding worker. All 39 distinct
fresh process-tree scopes completed under `memory.max=5368709120` and
`memory.swap.max=0`. All recorded `memory.events` deltas, including `max`,
`oom`, `oom_kill`, `oom_group_kill` and the optional `sock_throttled` counter,
were zero. Visible scope and parent `cpu.max` values were `max 100000`.

The 39 scopes comprise 24 transaction-grid trials, three selected-transaction
one-worker trials, six settlement trials and six issuance trials. The selected
four-worker transaction group reuses its three grid trials. It is not three
additional measurements.

Generation times cover complete native proof generation after separately
timed one-time preprocessing. Integrated service readiness must prepare and
retain that state. Charged memory covers each whole fresh setup/prove/verify
process tree, descendants and recorder. One-worker verification timings are
from one-worker processes that also set up and generate a fresh proof. They
are not isolated verifier-only processes, so their charged peaks do not
establish verifier-only memory bounds. The 5-GiB diagnostic scope is not a
miner RAM requirement. Malformed-input, concurrent-verifier and sustained
whole-node qualification remain outstanding.

## Complete eight-profile scan

Every row uses the minimum query count passing the actual-AIR screen at the
specified blowup and grinding. Query and opening-batch grinding match;
commitment grinding is zero, folding is binary and final-polynomial log length
is zero. All rows have classical conjectured union 185 bits and selected W24
BHT collision ledger 123.333333 bits. The profile retains complete raw security
terms for every coordinate. Proof ranges and charged peaks cover each row's
three four-worker processes.

| log blowup | Queries | Query/batch grinding | Three generation times (s) | Observed proof bytes | Maximum cgroup peak (bytes) | Classical Johnson union (bits) | Quantum Johnson union (bits) | All three <=2 s | All bodies <=655,360 B |
| ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | --- | --- |
| 5 | 57 | 20 | 0.381136980 / 0.330040015 / 0.597747517 | 673,870–682,175 | 141,983,744 | 162.339544 | 81.169759 | Yes | No |
| 5 | 55 | 24 | 6.565152268 / 2.450732438 / 2.887922762 | 663,955–670,435 | 142,503,936 | 161.345174 | 80.672578 | No | No |
| 6 | 47 | 20 | 0.656968671 / 0.786891786 / 0.789807081 | 616,660–618,099 | 270,434,304 | 160.867694 | 80.433832 | Yes | Yes |
| 6 | 46 | 24 | 2.093739935 / 8.442857996 / 2.039747374 | 599,629–602,989 | 269,934,592 | 161.870509 | 80.935233 | No | Yes |
| 7 | 41 | 20 | 1.531155438 / 1.429902190 / 1.462877730 | 581,392–585,808 | 525,234,176 | 163.384584 | 81.692219 | Yes | Yes |
| 7 | 39 | 24 | 3.568666051 / 3.083717843 / 7.587626991 | 551,460–564,996 | 525,758,464 | 160.390214 | 80.195081 | No | Yes |
| 8 | 36 | 20 | 2.422350935 / 2.596701033 / 2.834584320 | 547,987–560,131 | 1,036,673,024 | 163.898659 | 81.949155 | No | Yes |
| 8 | 35 | 24 | 4.896359696 / 3.367161692 / 5.419455035 | 537,725–544,205 | 1,036,406,784 | 163.901474 | 81.950563 | No | Yes |

All eight profiles pass the selected 80-bit quantum security screen. Blowup
5 with grinding 20 passes time but exceeds the transaction body limit. The
24-bit-grinding profiles and blowup 8/grinding 20 fail the three-trial time
criterion. Blowups 6 and 7 with grinding 20 pass both time and raw body limits;
blowup 7 has the smaller maximum body and retains the required admission margin.
Median-only qualification is not used.

## Actual relation shapes and permanent encoding

Dimensions are extracted from the complete revised AIRs with pinned
`p3-security=0.9.0-rc.2`. Base rows are distinct from the committed hiding domain.

| Relation/profile | Base rows | Main columns | Preprocessed columns | Public values | Constraints | Maximum degree |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Transaction, b7/q41/g20 | 256 | 1,392 | 247 | 101 | 2,898 | 3 |
| Settlement, 576 positions, b8/q36/g20 | 1,024 | 581 | 609 | 7,050 | 19,703 | 3 |
| Issuance, three notes, b8/q36/g20 | 128 | 438 | 10 | 72 | 577 | 3 |

The selected transaction has eight quotient chunks, 3,438 batched functions and
committed trace log length 9. The challenge-field floor is 247 bits and selected
classical commitment-collision floor is 185 bits. The public body remains
2,027 bytes; adding its 48-byte fee commitment and 40-byte snapshot selector
gives 2,115 permanent bytes per position. Unlock fields fit existing note and
ciphertext padding. Envelope, sidecar, reward, fund and issuance records are
separate components.

## Complete selected-profile security ledger

The following values are raw error exponents in bits. Error probabilities are
combined before reporting union exponents. The quantum ledger halves every
Johnson Fiat–Shamir challenge exponent, including query/enforced grinding and
batch combination, and accounts for the folding-round union.

| Report/model | Error term | Bits |
| --- | --- | ---: |
| Classical conjectured | `air-composition` | 235.499158 |
| Classical conjectured | `deep-ali` | 234.829762 |
| Classical conjectured | `ldt-query-phase` | 305.011966 |
| Classical conjectured | `ldt-commit-phase` | 230.999978 |
| Classical conjectured | `batch-combination` | 239.253066 |
| Classical conjectured | `commitment-collision` | 185.000000 |
| Classical Johnson | `air-composition` | 223.996343 |
| Classical Johnson | `deep-ali` | 223.326947 |
| Classical Johnson | `low-degree-test` | 163.384584 |
| Classical Johnson | `batch-combination` | 206.826763 |
| Classical Johnson | `commitment-collision` | 185.000000 |
| Johnson FRI | `fri-folding` | 198.573697 |
| Johnson FRI | `fri-query` | 163.384584 |
| Challenge-domain ledger | `ood-deep-ali-domain` | 223.326947 |
| Challenge-domain ledger | `fri-folding-domain` | 191.929841 |

The FRI query term is the weakest challenge term. The folding-domain entry
already includes its folding-round adjustment and is not a second independent
folding error. The classical conjectured union is
184.99999999999997 bits; classical Johnson union is
163.38458391106965 bits; quantum Johnson challenge union is
81.6922188692167 bits. Johnson uses `m=256` and proof multiplicity one.
The selected W24 commitment ledger converts its 185-bit classical collision
term to `185 * 2 / 3 = 123.33333333333333` BHT bits.

External BLAKE3-256 ciphertext/asset-ID binding is separately modeled at 128
classical collision bits and `256 / 3 = 85.33333333333333` nominal BHT bits.
Those application-hash quantities are not raw `p3-security` outputs. Transcript
binding, hiding, application hashes and protocol composition still require
independent security review.

## Transaction, settlement and issuance measurements

All six worker groups below contain three fresh measurements. Four-worker
transaction results reuse the selected grid group. Settlement has fixed
capacity 576 and binds the public mode, trusted reward plan, SIP asset and
one/five reward notes. The benchmark supplies synthetic plan allocations; it
is not an oracle for canonical pool accounting. Nodes derive the plan from
trusted parent state and independently validate pool, burn and fund updates.
Issuance has three initial notes and checks an actual
ML-DSA-65 signature, but its benchmark SIP-payment callback remains synthetic.
Actual issuance-fee consumption and registry/note insertion require one durable
atomic node transition.

| Relation | Workers | Three generation times (s) | Generation median (s) | Verification median (ms) | Observed proof bytes | Maximum cgroup peak (bytes) |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| Transaction | 4 | 1.531155438 / 1.429902190 / 1.462877730 | 1.462877730 | 17.076357 | 581,392–585,808 | 525,234,176 |
| Transaction | 1 | 2.728648957 / 2.810005525 / 2.519086686 | 2.728648957 | 17.006900 | 585,520–588,832 | 523,964,416 |
| Settlement | 4 | 5.523829281 / 5.616304295 / 5.424077424 | 5.523829281 | 20.130663 | 514,635–520,203 | 3,161,432,064 |
| Settlement | 1 | 11.954381874 / 11.282064820 / 11.290169489 | 11.290169489 | 19.914259 | 499,130–516,699 | 3,158,740,992 |
| Issuance | 4 | 0.601598109 / 0.639979907 / 0.717943136 | 0.639979907 | 8.641459 | 274,353–280,401 | 211,423,232 |
| Issuance | 1 | 1.686880130 / 1.161136898 / 1.241751044 | 1.241751044 | 8.528751 | 270,177–285,585 | 210,460,672 |

Setup, generation and verification below are separately timed phases; process
wall time additionally includes fixture preparation and recorder overhead.
Only whole-process-tree charged-memory peaks are measured. Do not infer or
add independent phase-memory values from these overlapping lifetimes.

| Relation | Workers | Setup median (s) | Generation median (s) | Verification median (ms) | Process wall median (s) |
| --- | ---: | ---: | ---: | ---: | ---: |
| Transaction | 4 | 0.156945554 | 1.462877730 | 17.076357 | 1.671611009 |
| Transaction | 1 | 0.344289976 | 2.728648957 | 17.006900 | 3.122668811 |
| Settlement | 4 | 2.944648847 | 5.523829281 | 20.130663 | 8.635607165 |
| Settlement | 1 | 6.418153023 | 11.290169489 | 19.914259 | 17.907049265 |
| Issuance | 4 | 0.018623985 | 0.639979907 | 8.641459 | 0.717024445 |
| Issuance | 1 | 0.036971171 | 1.241751044 | 8.528751 | 1.318278895 |

| Security ledger (bits) | Transaction | Settlement | Issuance |
| --- | ---: | ---: | ---: |
| Classical conjectured union | 185.000000000 | 185.000000000 | 185.000000000 |
| Classical Johnson union | 163.384583911 | 163.974037303 | 163.797515631 |
| Quantum Johnson challenge union | 81.692218869 | 81.983705354 | 81.898719983 |
| Selected W24 commitment BHT ledger | 123.333333333 | 123.333333333 | 123.333333333 |

The fresh run qualifies the selected isolated 576-position settlement proof;
it does not establish measured active-capacity workloads at 64–512 positions,
whole-block processing or an independent verifier-memory bound. The current
native fund registry supports 32 immutable keys and eight signed claims per
block. Launch recipients and independent basis-point shares remain unconfigured; the measurements select no production allocation.

## Network, retention and remaining gates

With unchanged proof caps and 576 positions, the explicit economic-record
[wire model](v1-network-budget.md) charges 1,369,369,494 bytes per 300 seconds,
or **36.51651984 Mbps**, including three relay copies and bounded transport,
control, recovery and issuance allowances. A **43-Mbps minimum uplink** leaves
15.077861% unused in that model; deployment recommends **100 Mbps**. These are
conditional planning figures. Actual transport counters, queue growth and
issuance byte/work/rate limits require separate qualification.

The [storage ledger](v1-storage-and-sync.md) retains transaction, settlement
and issuance proofs plus sidecars for three elapsed days after final
confirmation; permanent public records are never pruned. Unchanged proof caps
preserve the nominal 336.180-GB rolling allowance. Actual database, WAL,
compaction, backup restoration, wallet recovery and elapsed three-day deletion
remain integrated acceptance work.

The engineering profile does not activate a new network or modify the retained
seven-node network. Required CI and public-key reproduction, standalone
verification CPU/memory and malformed-input limits, concurrency/in-flight
budgets, complete valid-block processing, configured fund allocation and
issuance-fee policy, durable wallet integration, hybrid transport and independent
security review are separate gates.
