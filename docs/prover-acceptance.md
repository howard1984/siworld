# Native V1 Testnet Acceptance

Status: engineering acceptance requirements for the independent native-proof
testnet. The two-input/three-output transaction, fixed-576 settlement and
three-initial-note issuance proof relations have source-bound
`native-v1-economics-1` profiles, fresh actual-AIR reports and 39 EPYC 7763
reference trials. Public-key reproduction and complete CI remain release
checks. Earlier generation measurements and pre-revision service observations
are separate baseline evidence.
The earlier single-asset freeze is an unchanged diagnostic baseline; node,
wallet, transport, independent-verifier and recovery integration remain incomplete. A passed
standalone benchmark is not testnet acceptance. Operating thresholds below
are qualification targets, not claims of achieved behavior.

## Scope and network isolation

Follow [current decisions](00-decisions.md), the [native transaction
specification](route-a-v1.md), [confidential settlement](fee-settlement.md) and
the [node integration plan](v1-node-network-plan.md). Use a new genesis,
network identity, independent directories and keys, with synthetic funds.
Import no retained-network notes, proofs, wallet state or payment journals.
Preserve the existing seven-node N=2 network and its deployment guard.

V1 uses native transaction proofs and one independent fixed-576 settlement
proof. Blocks contain 64 through 576 positions in groups of 16, with a
300-second target, depth-24 finality and `MAX_REORG_DEPTH=24`. These rules
apply only to the new network. Coinbase maturity is a separate rule.

Recursive leaf/merge/root timings, the 180-second recursive proof target,
10-GiB recursive experiments and 99/100/101 reorganization tests are not V1
acceptance criteria. [Recursive research](v2/d8-w24-recursion.md) is paused V2
work. N=32 and retained-history verifier migration are excluded.

## Gate 1: proof identity and independent review

Reproduce the economic source-bound public keys and actual-AIR reports;
artifact checks must reject changed sources. Verify the
[three-relation manifest](../crates/bench-multi-asset/artifacts/v1-native-proof-profiles.json)
using [the fixed profile procedure](native-proof-profiles.md). Its shapes are
exactly two-input/three-output transaction, 576-position settlement and
three-initial-note issuance. This does not adopt issuance policy or qualify
smaller-capacity keys. Independent review and complete runtime acceptance
remain separate from key/source reproduction.

Reproduce the [multi-asset transaction profile](../crates/bench-multi-asset/artifacts/v1-transaction-profile.json)
from pinned source and dependencies. Run `scripts/freeze-multi-asset.py --check`
with a newly generated `profile-artifacts` public-key/report JSON; source-only
checking cannot reproduce the preprocessing commitment. The matched
[actual-AIR scan](v1-multi-asset-evaluation.md) qualifies native transaction
generation, not standalone verifier resources or complete block acceptance.
Require old keys to reject the new relation and bind all trusted envelope and
decoder identities before activation. Independently reproduce the unchanged
prior [baseline bundle](../crates/bench-d8/artifacts/v1-native-freeze.json) with
`python3 scripts/check-v1-freeze.py`; its old codec cannot admit the new profile.

The prior two-output native profile is KoalaBear D8, standard Poseidon2 W24, twelve-element
digests, random-codeword hiding, log blowup 8, 36 queries, query grinding 20,
opening-batch grinding 20, commitment grinding zero, binary folding and
`log_final_poly_len=0`. Pin `p3-security=0.9.0-rc.2` and the reviewed
[dependency revision](d8-dependency-patch.md).

Require classical conjectured security of at least 128 bits, quantum-halved
Johnson Fiat–Shamir terms of at least 80 bits including enforced grinding,
challenge-domain terms of at least 80 bits after halving, and at least
80-bit BHT commitment collision resistance. Apply the screen to each native
AIR and review their protocol composition. The selected transaction's approximately 81.692-bit quantum-halved Johnson
ledger and 123.333-bit [BHT conversion](bht-security-accounting.md) are model
accounting, not independent cryptographic approval. Review application hashes,
transcript binding, hiding, fee privacy, dependency changes and wallet key
lifecycle separately. Close security-limiting findings before public launch.

Trusted keys come from the local network manifest, never a peer. Reject
wrong-network, wrong-suite, unknown-key and legacy proofs. Source, AIR, codec,
key or parameter drift requires renewed freeze checks and affected acceptance.

## Gate 2: shared state transition and wallet correctness

Production, inbound validation, historical replay and audit must call the same
integer-only, deterministic, atomic transition. Write rejection tests before
implementing each consensus rule. Cover every public field, digest limb,
noncanonical encoding, every input, duplicate nullifiers, one-time-key reuse,
amount/fee carries, issuance and partial-failure rollback.

Validate complete ordered blocks at 64, 80, 544 and 576 positions. Reject
counts outside the range or not divisible by 16. Bind each statement exactly
once to settlement and all mode-dependent miner reward commitments. Derive the fixed AIR's
unused internal tails canonically; do not add extra chain positions. Verify
transaction proofs independently of settlement, with private anchored fee
schedules and no public fee total or miner amount.

Exercise both fee tiers, forged/missing/mismatched sidecars, fee openings,
nonzero padding fees, zero real-transaction fees and reward mismatch. Sidecars
are required for local pool admission/production, not public block validation.
No public statistic may classify real or padding transactions or fee tiers.

Accept the newest 4,096 canonical snapshot identities: age 4,095 passes and
age 4,096 fails. Test orphaning, same-root/different-block substitutions,
shortened-chain refill and historical validation at the historical window.
Eviction releases both nullifier reservations and triggers wallet reproof.

Test reorganization depths 23 and 24, reject depth 25, and test the exact
finalized boundary without off-by-one ambiguity. Verify reward reversal,
snapshot refill, orphaned admission/padding eviction and shared roots/work.
A deeper fork requires explicit recovery, not silent rollback or rule changes.

Wallet acceptance covers durable change keys, protected receipt material,
backup/restore, sender self-check of all three outputs, recipient AEAD and note
commitment checks, interrupted submission and exactly-once reconciliation.
V1 proves ciphertext-byte binding; it does not prove encryption correctness.
Padding must perform genuine ephemeral-recipient ML-KEM encryption and use
fresh nullifiers with identical public shape. Retain a private usable queue
target of 64 and cap of 128 under its byte budget; never expose its size.

## Gate 3: isolated verification and bounded admission

Enforce the existing [admission ledger](v1-node-network-plan.md#admission-and-local-resource-policy)
before allocation: wire limits, decoder budget, byte and entry reservations,
per-peer limits, two isolated verifier workers, TTLs, caches and bounded block
reconstruction. Count owned metadata and retained copies as well as payloads.

Independent verification loads only public verifier artifacts. Each worker
has 128 MiB charged memory, zero swap, a 250-ms CPU allowance and a two-second
wall watchdog. Record CPU sampling/overshoot and cleanup. Maximum serial CPU
allowance is 144 seconds for 576 transactions, 144.25 including settlement.
This allowance is neither an observed valid-block duration nor a consensus
timeout. Local exhaustion means retryable unavailability, not invalidity.

Fuzz framing, nested declared lengths, canonical re-encoding, partial streams,
duplicate floods and invalid proofs while measuring allocation/CPU behavior.
Exercise cancellation and worker crashes; release every reservation, close
owned streams and leave no child process. Resume bounded valid traffic after
abuse. An overload must not reject a valid block as cryptographically invalid.

## Gate 4: deployed transport, relay and synchronization

Use the [V1 network design](v1-network-design.md) for authenticated hybrid
handshakes, source-hiding relay and explicit-trust checkpoints. Its mechanisms
require implementation and independent review; classical Noise alone fails
this gate. Test actual TCP listeners, not only in-memory messages.

Cover algorithm negotiation, both identity bindings, transcript mutation,
key substitution, downgrade, replay, malformed KEM data, key confirmation,
interrupted/half-open handshakes, reconnect and bounded cleanup. No classical
fallback is permitted for V1 transaction, wallet or sidecar connections.

Compact reconstruction authenticates the complete ordered statement list and
all retrieved bodies. Test missing, duplicated, withheld, reordered and
corrupted responses, bounded requests, reconnect and simultaneous candidates.
Do not treat short inventories as evidence that proof traffic disappeared.

The default new-node path uses the release checkpoint, its complete
snapshot/state payload and authenticated cumulative PoW, followed by validation
of every later block. Wrong-network, incomplete, stale and conflicting
checkpoints fail closed. A checkpoint quorum remains a trust assumption;
matching peer roots or header work does not prove already deleted historical
transactions. Full proof replay from genesis is a future optional archive or
V2 history-compression upgrade and is not a V1 launch gate.

## Gate 5: deployment resources and timing

Use the [minimum deployment configuration](v1-deployment.md): x86-64-v3 with
CPU/OS-state checks, at least four available vCPUs, 16 GB RAM for validators
and 32 GB for miners. Require at least 15 GiB / 30 GiB of system-visible
memory respectively, including visible deployment cgroup limits. The Linux
measurement adapter requires Ubuntu 24.04
and cgroup v2. Record actual CPU model, exposed core/vCPU counts, memory,
virtualization, ISA, compiler, dependency and resource-controller identities;
CPU model is not an admission requirement. Existing EPYC 7763 results describe
their measurement environment. Every deployment still needs its own workload
results, and macOS/Windows need qualified adapters.

The hosted 5-GiB zero-swap generation scopes are measurement boundaries, not
a formal miner RAM requirement. Select and enforce separate node, prover,
verifier, maintenance and host budgets before integrated qualification.
Include startup/key loading, resident state, all descendants, pool metadata,
redb/page cache, serialization, allocator retention and platform/VM reserves.
Simultaneous resource caps must fit the host; low sampled RSS is insufficient.

On each supported hardware class run three trials of transaction generation,
settlement generation and independent verification with the same frozen
commit/profile. Use four workers for the native generation comparison and
one for independent verifier measurements. Record native hiding-worker
settings, process-tree limits, CPU quota/throttling, peak charged memory,
`memory.events`, swap, wall/CPU time and proof bytes. Report every attempt,
individual values, medians and maxima. No OOM, restart or silent retry passes.

The selected transaction-generation gate is at most two seconds in all three
four-worker trials on minimum-qualified hardware. The economic b7/q41/g20
transaction trials range from 1.429902190 to 1.531155438 seconds, with a
1.462877730-second median. Their maximum charged process-tree peak is
525,234,176 bytes. Transaction proof bodies must fit 655,360 bytes;
settlement bodies use a 655,360-byte cap and issuance retains a separate
524,288-byte cap. The 640-KiB
transaction cap gives more than 10% margin over the 588,832-byte selected
maximum across one- and four-worker measurements;
it is not a deterministic size theorem. Measure independent transaction and
settlement verification separately. Cold start and readiness are separate timing markers; startup
memory remains inside the lifetime resource boundary.

Hardware qualification additionally checks fixed-576 settlement bodies against
655,360 bytes and the stricter 589,824-byte (90-percent) measurement threshold.
This does not change runtime decoder limits or replace the maximal-fee and
combined complete-block acceptance gates.

Then run three actual end-to-end trials for each capacity class, including a
576-position block of distinct, conflict-free valid statements and its bound
settlement. Repeating one proof 576 times is only a verifier microbenchmark.
Record wallet creation/proving, admission, queueing, assembly, settlement,
PoW waiting, publication, propagation, full validation, durable acceptance and
recipient reconciliation separately. Report p50/p95/p99 and maxima over the
sustained run; three samples alone do not estimate tail latency.

The 300-second block interval is a stochastic protocol target, not an
upper bound on every PoW wait. Measure non-PoW service work and propagation
separately and demonstrate that queues do not grow without bound at the
offered maximum load. Match complete public state roots and cumulative work
at the same block identity, with explicit idle/completed-state availability.
Height equality or a cached busy response is insufficient.

At the 43-Mbps uplink floor, the capped multi-asset three-copy transaction
and settlement payload requires 30.345178 Mbps. The
[complete economic wire model](v1-network-budget.md) requires 36.52910683 Mbps
after control, transport, reciprocal ACK, bounded issuance, all five reward
records, eight signed fund claim slots, retransmission and recovery costs.
The floor leaves 15.048589% capacity unused; recommend 100 Mbps.
Reconcile every assumption against packet/application counters and qualify
both bandwidth profiles using the actual hybrid listener, concurrent ingress,
losses, missing bodies and handshake churn. Report overload without silently
reducing the fixed 576-position capacity or weakening proof security.

## Gate 6: sustained observation, retention and recovery

Use at least seven V1 validating processes across at least three independent
hosts, with two independently hosted miners, plus a separately budgeted
monitoring service and object-storage backup. A same-host seven-container run is a regression
stage, not independent-host acceptance. Do not include retained nodes in this
count. Operate all ordinary services and authenticated private telemetry.

First qualify each hardware profile for 72 continuous hours at maximum-size
576-position load and the 300-second target. Then require seven continuous
days of independent-host operation, including at least 72 hours at that load.
These observations can overlap after the configuration is frozen. Use
conflict-free synthetic transactions, valid padding and settlement; exercise
the wire maximum separately when actual proofs are smaller, clearly labeling
transport-only synthetic stress rather than claiming valid full-size blocks.
Reset the affected
observation window after a material fix. Tests must retain diagnostic evidence
without publishing transaction classification or user-linked fields.

Pass only with stable admitted queues, bounded memory/cache behavior, no
unplanned OOM/restart, no sustained unexplained root/work divergence, and
completed-state availability. Report peaks and slopes by phase and process
epoch. Missing state-category measurements or unexplained growth blocks
resource qualification; a short flat interval is not a total-state bound.

Service-node retention means at least 86,400 elapsed seconds after observed
depth-24 finality. Miner and ordinary stores retain 96 canonical proof blocks.
At the target rate, include the 24 unresolved blocks when sizing the proof
store: the nominal service window is 312 blocks. Require accelerated
boundary/crash tests and at least one real 24-hour service retention/deletion
lifecycle before claiming this gate closed. Short burn-in cannot substitute for
that lifecycle. Delete eligible online proof bodies and sidecars after the full
24-hour interval; uncertainty in clock/finality fails toward longer
retention. Publish and authenticate checkpoints every six hours and verify complete tail
availability before enabling service expiry. Preserve all public records and
accepted state. Test clock changes,
partial deletion, restart and disk pressure; never shorten retention to recover
free space.

| Recovery case | Qualification target |
| --- | --- |
| Accepted durable block/state and wallet journal | RPO zero for acknowledged durable records; a crash may lose unacknowledged work only |
| Ordinary restart with intact durable state | Return to the pre-stop validated tip and read service within 10 minutes; replay only the required authenticated tail |
| Partition with at most 24 missing blocks | Catch up within 30 minutes on the qualified 100-Mbps full-duplex reference while live traffic continues; verify measured spare bandwidth and CPU suffice |
| Lower-bandwidth catch-up | Publish a separate bound from missing bytes, measured spare bandwidth, serial verification and disk cost; do not promise the 100-Mbps result at 43 Mbps |
| Beyond-finality fork or corrupt/missing state | Halt affected production, preserve evidence and require explicit authenticated recovery; no automatic rollback to an old database |
| Monitoring | Sample every five seconds, mark stale after 15 seconds, alert on persistent actionable failures; never use monitor timeouts as consensus verdicts |

Recovery trials include process kill, interrupted writes, exhausted disk,
unavailable peers/checkpoints and replacement hardware from a verified object
storage backup. Checkpoint bootstrap time and future archive-replay time are
measured separately; neither inherits the ordinary-restart target. Do not mine
until verified state, current snapshots, keys and usable padding satisfy
readiness again.

## Release evidence

Identify the exact release/source, build/dependency manifests, trusted verifier
bundle and independent-review disposition. Preserve private raw resource,
retention, synchronization and recovery evidence; publish only independently
written technical summaries and permitted synthetic fixtures. Link each gate
to a reproducible test and result and list unsupported platforms and open
findings. A live panel supplements evidence; it cannot approve a release.

No mainnet, real funds, retained-network migration, recursive V2 activation or
automatic expansion beyond 576 positions is authorized by this plan.

## Multi-asset and supply-audit acceptance

Add test-first rejection cases for cross-asset balance mixing, non-SIP fees,
forged IDs, unsigned/wrong-chain/invalid-signature issuance, duplicate issuer
sequences, incorrect issuance-to-note linkage and minted supply above the
public declaration. Cover SIP-only, token-plus-SIP-fee, asset change, two-asset
inputs and zero-output padding with the same fixed public shape. Verify
exactly-once supply and registry rollback across depth 23/24 reorganizations.
Measure the new rows/columns and p3-security terms; no old proof size or timing
can satisfy this gate.

Run the total-SIP-issuance audit over every height and reject tampered subsidy,
fund credit, signature, fund counter and curve totals. Verify asset declarations
and issuance relations separately without deriving private holdings. Restore
a mnemonic-only wallet and rescan every historical ciphertext, including
payments before the bootstrap checkpoint; reconstruct every unspent SIP and
asset note and reconcile spends against permanent nullifiers. Checkpoint
bootstrap authenticates state but must not hide or omit the old ciphertext
segments required by wallet recovery.

## Monetary revision acceptance

Write rejection cases before implementing each shared consensus transition.
The following scope is required; this list does not claim tests have passed.

- Recompute every atom of Voyager and Holder subsidy allocation, the one/five
  reward-note count, reserved SIP asset IDs, indices, unlock heights and
  note-zero fee sum. Reject any unrecognized mode or reward mutation.
- Cover empty pool, Holder draw before current-block injection, Voyager no-draw,
  sub-4,032 balances, exact division and retained remainders. Reject a reward
  that draws from the current block's credit. Track burn independently and
  enforce the supply invariant at every accepted height.
- In the real transaction AIR, reject a spend one block before its input
  unlock; accept at the trusted snapshot height. Reject forged lock heights,
  substituted snapshot heights and a newer tip with an old snapshot.
- Verify exact tail entry and both adjacent rewards, never below one SIP per
  300-second block. Distinct engineering genesis may compress lock timing
  without substituting production parameters.
- After the configured wallet count/ratios are adopted, test every wallet
  allocation and independent budget. Cover 24-block maturity, per-credit
  daily vesting over 1,461 days, integer remainders/final release, independent
  counters, wrong/absent ML-DSA signatures, replay and overdraft rejection.
  A payout may not consume another wallet's unlocked entitlement.
- Across depth-23/24 reorganizations, atomically restore pool, claims, burn,
  every reward schedule, fund unlocked/spent state and authenticated roots;
  reject depth 25 without partial mutation.
- Simulate 20 protocol years with deterministic pseudorandom mode choices,
  conservation at every block, independent curve sums and reported pool,
  reward, burn and fund counters. Do not present that simulation as elapsed
  network observation.
- Restore locked notes and unlock heights from seed-only ciphertext scans.
  Check available/locked displays, next unlock and local randomized delayed
  consolidation without changing consensus locks or exposing note timing.

Re-screen every affected actual AIR for classical conjectured security at
least 128 bits, quantum-halved Johnson/challenge terms at least 80 bits and
selected BHT collision resistance at least 80 bits. Report all three measured
four-worker generation trials, body bytes, one-worker verifier-call timing,
charged process-tree peak memory and events. Require a separate
verification-only process before qualifying verifier memory or CPU guards;
the completed setup/prove/verify scopes do not supply that evidence. Retain a two-second transaction generation target,
655,360-byte body cap and 576 positions. Reconcile complete network/storage
bytes, preserving at least the agreed measurement margin before refreezing.
