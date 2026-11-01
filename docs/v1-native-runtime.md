# Native V1 Engineering Runtime

Status: the continuous single-node service and native node-integration library
are implemented engineering components. The library adds bounded admission,
authenticated-stream protocol interfaces, full-proof synchronization,
verified-work fork selection, wallet primitives and a public subsidy audit.
The integration has dedicated compilation, rejection and native-proof CI
checks; complete CI for the current revision remains a release check. A real
24-hour observation and final offline replay of the current revision remain
required evidence; this document does not report their completion. No production hybrid-handshake provider or network
service command is supplied. The runtime does not activate a public network,
replace an existing database or change the retained seven-node legacy network.
Independent security review remains pending. The current native settlement
decoder and wire cap are 655,360 bytes. The full-load evidence below satisfies
the settlement body-size margin on its measured source revision; genuine
wallet completion and current-revision CI remain separate release checks.

## Scope

The [economic relations](v1-economics.md) use revision
`native-v1-economics-1`. Fresh actual-AIR reports and 39 EPYC 7763 trials cover
its proof profiles; public-key reproduction and complete CI remain release
checks. The retained continuous-service observation uses frozen pre-revision
artifacts and must not be restarted or reinterpreted as acceptance of revised
economics. The current revision requires its own runtime replay/observation
and explicitly activated independent network.

`crates/native-node` composes the native transaction, fixed-capacity
settlement and three-note issuance relations with a versioned block codec, canonical ordering, a common
state transition, and replay-verified local persistence. It uses D8/W24 with
12-element digests throughout; it does not truncate them into legacy digests.
The implementation imports the fixed native relation manifests and rejects
unrecognized keys, profiles, malformed proof vectors, and noncanonical fields.

Transactions have two inputs and three outputs. A block contains 64–576 slots,
in groups of 16, in strict ascending proof-independent BLAKE3 statement-ID
order. Duplicate IDs and nullifiers, including the second input, are rejected.
The statement binds the network, version, canonical snapshot identity, all
public transaction bytes and the fee commitment. Proof and sidecar bytes do
not change that identity. The block ID additionally authenticates proof bodies,
all reward ciphertexts, public mode, signed fund payouts, parent, timestamp,
target and nonce. The ordered settlement-list digest
excludes proof bodies.

The producer and replay validator call the same state transition. Every
transaction proof and the independent settlement proof must verify before
accepted state changes. Output commitments and all SIP reward notes are appended
to the depth-40 commitment tree. The block carries one Voyager reward note
or five Holder notes. Its common transition updates the Holder pool, cumulative
burn, scheduled reward locks and independent development-fund vesting/spending
with the accepted state. Real input unlocks are checked against the trusted
selected snapshot height, rather than the receiving node's latest height.
Accepted snapshot identities expire after
4096 canonical entries; an absent or removed identity is invalid even when
another snapshot has the same root. The chain library verifies complete
candidate branches and selects strictly greater cumulative verified work;
advertised height or work is never authoritative. Equal work retains the
current branch. A reorganization may detach at most 24 canonical blocks;
a deeper divergence requires explicit recovery rather than automatic adoption.

The fixed 576-row settlement relation reconstructs unused zero-fee rows from
the network, block height, position count and row index with an explicit
engineering domain. These rows are internal relation inputs, not extra chain
transactions or public real/dummy classification flags. Native multi-asset hash
domains are used throughout.

## Local persistence and reward recovery

A new independent engineering directory contains its explicit network configuration,
`chain.redb` and private reward recovery receipts. Initialization refuses an
existing directory. The ASERT service uses engineering configuration revision 5,
which binds a fresh network identity, genesis timestamp, immutable calibrated
target, 300-second target interval and sequential BLAKE3 work iterations.
The 62,736-byte canonical rules reserve 32 full public-key/share slots and
bind the team residue index, numeric configuration revision and economic-rule
version 3 (Holder claim before current-block injection). Existing local format
markers remain unchanged; old-length or old-revision records are rejected.
A main-network genesis manifest/import CLI remains an activation prerequisite; the complete registry is currently supplied through
the validated library configuration API. This engineering format version is unrelated to the deferred recursive V2
roadmap. Earlier engineering directories are preserved and are not migrated
automatically. There is no reset or migration operation. Replay reconstructs
accepted state by verifying every stored block and checking its recorded state
fingerprint. Each append commits the canonical block, accepted height and
fingerprint in one durable database transaction before exposing the new state.
Branch adoption uses one redb transaction for the replacement canonical rows,
head, fingerprint and retained detached records. Detached blocks remain
checksummed evidence and are never treated as accepted-chain authority.
Missing rows, changed metadata, wrong-network data and failed proofs fail closed.
Unclean databases requiring redb repair are preserved and refused pending
explicit recovery review; automatic crash-repair tooling is not an M1 claim.

The local producer uses operating-system entropy and actual ML-KEM/ChaCha
output encryption. It authenticates and reconstructs output commitments before
proving. Reward recovery material is saved privately and synced before the
accepted block is committed. A receipt records private output/opening material for all one/five reward
notes and must never be published. Rewards are encrypted to the explicitly
configured, backed-up recipient wallet; receipts do not replace its seed
backup. The separate wallet API does not establish protected durable wallet
recovery merely by accepting a recipient address.

## Fixed-profile measurement evidence

The following measurements use source revision
`f39e1ce55493d1079e5ed2416baa5d8e9c8699b5`, Ubuntu 24.04, four Rayon
workers and two composition-hiding workers. Each proof trial ran in a fresh
5-GiB memory scope with swap disabled. All trials exited successfully, retained
no descendants and reported zero memory-event deltas. Generation timing excludes
setup; `memory.peak` covers the complete setup/prove/verify process tree and
recorder. It is not an independent verifier-memory measurement or a miner
hardware requirement.

The [fixed transaction diagnostic](https://github.com/siworld-labs/siworld/actions/runs/40999077368)
used an actual AMD EPYC 7763 exposing four vCPUs and two physical cores. It
reproduced the frozen keys and used only 7/41/20:

| Trial | Proof body (bytes) | Generation (seconds) | Verification (milliseconds) | Memory peak (bytes) |
| --- | ---: | ---: | ---: | ---: |
| 1 | 583,072 | 1.303 | 17.008 | 525,484,032 |
| 2 | 574,432 | 1.304 | 16.656 | 525,488,128 |
| 3 | 583,648 | 1.370 | 16.898 | 525,455,360 |

These samples meet the 655,360-byte and two-second numerical limits on that
runner. The run was explicitly dispatched in diagnostic mode and preserves
`baseline_qualified: false` and `engineering_target_pass: false`; it does not
replace a successful strict baseline workflow. The reproduced p3-security
single-proof report gives a quantum-halved Johnson/challenge union estimate
of 81.6922 bits and a BHT commitment-collision estimate of 123.3333 bits.
The separately modeled BLAKE3-256 application binding has a nominal BHT
collision estimate of 85.3333 bits and is outside the p3 report. These are
engineering model estimates pending independent review.

The [full-load settlement run](https://github.com/siworld-labs/siworld/actions/runs/40998924075)
used an actual AMD EPYC 9V74, fixed 8/36/20, 576 priority-fee slots and five
Holder reward notes:

| Trial | Proof body (bytes) | Generation (seconds) | Verification (milliseconds) | Memory peak (bytes) |
| --- | ---: | ---: | ---: | ---: |
| 1 | 504,891 | 4.688 | 16.260 | 3,159,597,056 |
| 2 | 511,131 | 4.724 | 16.466 | 3,159,846,912 |
| 3 | 511,323 | 4.841 | 16.445 | 3,159,867,392 |

The maximum body is below 589,824 bytes and leaves 21.9783% of the active
655,360-byte cap unused. This is three observed witnesses, not a mathematical
maximum over all proof randomness. Eight signed ML-DSA-65 fund claims are
checked outside the settlement AIR in a separate maximum-envelope test. That
codec test uses opaque proof fills; it is not full-block proof acceptance.
The settlement samples are not an EPYC 7763 baseline.

## Admission, synchronization and fork handling

`runtime::Node` composes a persistent store, verified mempool, padding pool
and one shared transport budget. Local wallet submission follows the same
proof and sidecar checks as a remote identity. Admission inspects borrowed
framing before copying proofs, resolves canonical snapshots, checks both
nullifiers and all outputs, validates the sidecar against the transaction
identity and fee commitment, then independently verifies the frozen relation.
Verified entries are retained until canonical inclusion or explicit eviction;
private fee sorting does not change canonical block ordering. Candidate
assembly checks every opening and adds the private fee sum to reward note
zero with checked integer arithmetic. Fees are not split, burned or deposited
into the Holder pool. Each template captures an explicit Voyager/Holder setting;
changed settings affect subsequent templates only.

`Node::prepare_block` returns a move-only `PreparedBlock` bound to the node
instance, production generation and accepted-state fingerprint. Branch adoption
or a successful local commit invalidates earlier candidates, including a
candidate whose parent height could later recur. `Node::commit_produced`
authenticates its reward receipt, writes it through the store's opened parent
directory, syncs the file and directory, and then invokes `Store::append`.
Receipt writes reject changed database/directory identities, nonprivate Unix
ownership or permissions, hard-linked databases, symlinks and existing receipt
names. Receipt failure leaves the accepted head unchanged; a rejected append
preserves the receipt as evidence. This API is a prerequisite for resident
networking. The standalone CLI and continuous service still use their existing
path-based receipt helper and are not yet routed through this API. Non-Unix
store-owned receipt commits fail closed; macOS extended ACL qualification
remains unresolved.

The verified pool permits 512 MiB and 2,048 entries, with 16 MiB/64 entries
per opaque peer and at most 4,096 peer identities. These are logical owned-byte
bounds, not process RSS guarantees. The API distinguishes cryptographic
invalidity from local resource unavailability. Isolated verifier workers,
unverified ingress queues and the planned abuse caches are not implemented
by this in-process pool.

The streaming protocol binds network, genesis and frozen verifier manifest
before role-specific requests. A session requires an `Authenticated` channel
from an in-crate hybrid provider; no production provider is implemented and
no plaintext or classical fallback constructor is public. The provider must
supply reviewed X25519 + ML-KEM key exchange, dual Ed25519/ML-DSA identity
binding, transcript/key confirmation, authenticated records, nonce/sequence
limits, rekeying, deadlines and secret cleanup. Current TCP helpers cannot
establish production sessions until that provider exists. Session failure
requires fresh authentication on reconnect.

The library serves bounded block batches, transaction envelopes with private
sidecars and compact references. Synchronization pins peer identity, ancestor,
request sequence and continuation to one attempt; a canonical change invalidates
that attempt. Downloaded candidates are replayed through the common transition
before adoption. Compact recovery uses statement and proof digests together,
requests no more than 16 missing transactions, and does not disclose sidecars
in block-recovery responses. Network activation and deployed-listener failure
tests remain outstanding.

The compact announcement handler automatically requests missing exact
statement/proof pairs in batches of at most 16. It retains accounted proof
buffers, reconstructs the advertised block identity and invokes the shared
verified-work transition before acknowledging that identity. The sender serves
requested artifacts from its owned block, including miner-generated padding
whose proof is absent from the ordinary mempool. Recovery envelopes omit fee
sidecars and are never submitted as ordinary transaction gossip.

One monotonic 180-second deadline covers the entire missing-artifact exchange;
it is not renewed for each envelope. A caller-supplied authenticated connection
factory can retry temporary refusal or transport timeout on at most three fresh
sessions. Wrong request IDs, substituted statement/proof pairs, repeated artifact
requests, altered skeletons and incorrect completion identities are rejected
without retry. A retry of an accepted tip compares the entire skeleton with the
stored accepted block. Missing data and exhausted local memory remain
availability failures, not cryptographic invalidity verdicts.

Compact encoding version 3 preserves the bounded issuance records and proofs
from native block encoding version 4. Compact frames have a separate byte cap
for those records; the 1-MiB ordinary-control limit is unchanged. These are
authenticated-stream library operations. A production handshake provider,
permanent connection scheduler and deployed relay qualification are still
required before network activation.

Canonical locator and synchronization-base lookups reserve one maximum block
plus bookkeeping before decoding stored proofs. Exhaustion is retryable and
does not invalidate the peer or alter pending transactions.

One shared 640-MiB logical transport budget covers retained receive buffers,
with at most 16 handshakes and a 4-MiB aggregate handshake allowance. Candidate
validation additionally defaults to 32 blocks, 640 MiB of logical state/body
accounting and 1 GiB of retained detached evidence. Reconstructing a non-tip
ancestor is limited to height 4,096 because it currently replays from genesis;
this guard is local resource policy, not a checkpoint or consensus horizon.
Beyond it, reorganization returns resource unavailability until a qualified
checkpoint/replay mechanism is provided. Extending the current tip does not
require this ancestor reconstruction. Detached retention does not implement
the required three-day proof deletion lifecycle.

## Wallet and public subsidy audit

The wallet API derives separate spend, deterministic ML-KEM view and 256-bit
sender-change keys from a supplied 32-byte seed, network and account index.
After independently replaying a complete supplied canonical history, it
checks authenticated recipient/change ciphertexts and reconstructed note
commitments, derives spent status and atomically replaces private receipts.
Replaying a replacement chain removes orphan receipts and restores orphan
spends. It reports available/locked balances and unlock tranches with estimated
dates and the next unlock height. Private deterministic scheduling delays use
of matured locked notes; opt-in small-SIP consolidation shares that delay
without changing consensus maturity. These library primitives do not provide
a deployed wallet UI or background scheduler. The wallet can prepare fixed
two-input/three-output SIP or issued-asset
transfers, pay standard or priority fees only in SIP, recheck all output
encodings before proving and return the transaction, matching sidecar and
private payment opening. Seed bytes and supported private buffers are erased
on drop; dependency-internal and native-field copies are outside that guarantee.

These APIs accept seeds rather than implement mnemonic backup. Protected
seed/payment-opening persistence, valid-chain funding into seed-derived
addresses, wallet transport and recovery from pruned
public-history segments remain separate work. A native-proof test using
synthetic funding is not full-chain M2 acceptance.

The `audit` command acquires the engineering-directory lease and independently
replays canonical proof-carrying blocks. It checks each height's integer SIP
subsidy, Voyager/Holder rewards, pool deposits/claims, cumulative burn,
scheduled locks and independent fund credits, vesting and signed spending
against accepted counters. It checks the supply invariant at every height and
binds its report to the exact height, tip and state fingerprint. Output contains
only public economic records. The same replay validates asset declarations,
ML-DSA signatures, frozen issuance proofs, declaration-bound fee receipts and
one-time registry insertion. Its issued-asset summary records the public supply,
issuance height and declaration binding for each asset. Private holdings and
local reward recovery receipts remain outside this public audit. Authenticated
checkpoint inputs and recovery after proof pruning remain separate gates.

## Engineering commands

### Controlled Linux package

On a qualified Linux x86_64 host:

```sh
python3 scripts/build-native-runtime.py --output .local/native-runtime-release
mkdir -p .local/native-engineering
.local/native-runtime-release/bin/siworld-native-node init .local/native-engineering/network-a 0
.local/native-runtime-release/bin/siworld-native-node configure-miner .local/native-engineering/network-a holder .local/native-engineering/recipient-address.bin
.local/native-runtime-release/bin/siworld-native-node mine .local/native-engineering/network-a 64
.local/native-runtime-release/bin/siworld-native-node check .local/native-engineering/network-a
.local/native-runtime-release/bin/siworld-native-node audit .local/native-engineering/network-a
.local/native-runtime-release/bin/siworld-native-node status .local/native-engineering/network-a
```

The controlled Linux build uses x86-64-v3 and places the optimized worker behind
an independently compiled baseline CPU-admission launcher. Unsupported CPUs are
rejected; there is no scalar fallback. Direct source builds on other platforms
are development diagnostics and do not establish deployment qualification.

The address file must already contain the backed-up wallet's canonical
1,232-byte public address with private file permissions. `configure-miner`
requires `voyager` or `holder`; no default is supplied. It changes only future
templates. The `init`/`mine` example is an inexpensive correctness fixture. Its optional
work-bit selector is limited to 0–24, and continuous service refuses fixture
configurations. Fixture results do not qualify ASERT timing or a sustained run.
The current subsidy and fee helper functions are reused for engineering
accounting; public activation and epoch recalibration require their own
protocol decisions and integration tests.

### Independent ASERT service

Create a different, absent directory for a future continuous-service run.
Initialization alone does not make the network ready to produce:

```sh
.local/native-runtime-release/bin/siworld-native-node init-service .local/native-engineering/asert-a
.local/native-runtime-release/bin/siworld-native-node configure-miner .local/native-engineering/asert-a holder .local/native-engineering/recipient-address.bin
```

ASERT engineering initialization supplies a deterministic 24-wallet synthetic
registry: 23 shares of 400 basis points and one development-team share of 800.
The keys are publicly reproducible test material with no custody security.
This permits isolated engineering production without waiting for real recipients.
These shares and keys are not a main-network allocation. Real public keys,
shares and their authenticated configuration import remain prerequisites for
main-network activation. Eight signed claims may enter each engineering block;
accrual itself creates no payout note. Older engineering configurations are
rejected without migration. The cheap `init` fixture retains its two-wallet
synthetic allocation for bounded unit tests.
After those independent prerequisites are met, `run DIRECTORY` requires
`RAYON_NUM_THREADS=4` and `SIWORLD_COMPOSITION_HIDING_WORKERS=2`.

`init-service` performs one bounded initialization-only work-rate calibration
and durably fixes its resulting target in the new configuration. Resume does
not recalibrate or change these rules. The shared integer-only ASERT transition
checks each block's timestamp, required target and sequential BLAKE3 work;
the target interval is 300 seconds. A local sleep does not substitute for work,
and stochastic block intervals need not equal exactly five minutes.

`run` acquires an exclusive engineering-directory lease, replays existing
history and reward receipts, then prepares one resident prover. A private
queue independently verifies generated positions before reserving their
identities, inputs, outputs and bytes. The service produces 64-position blocks
and replenishes the queue during work search, subject to its 128-entry and
65-MiB limits. Expired, orphaned or conflicting snapshot entries are removed;
consumed reservations prevent candidate reuse. The queue size and position
classifications are not exported. This continuous service remains a
padding-only observation service. Wallet admission and candidate composition
are separate library APIs, not new commands on the observed service.

The service remains running after its observation timer reaches 24 hours. The
following commands read the private export or request an explicit run-bound
graceful stop:

```sh
.local/native-runtime-release/bin/siworld-native-node service-status .local/native-engineering/asert-a
.local/native-runtime-release/bin/siworld-native-node stop .local/native-engineering/asert-a
```

A stop request is checked at safe boundaries and during work batches; an
in-progress proof may finish before shutdown. Graceful shutdown closes the
writer, replays all accepted blocks and verifies every local reward receipt.
It preserves the database, run receipts and event history. Error paths preserve
their evidence and do not automatically retry or restore earlier state.
`check` always acquires the engineering lease and fully replays the database
and reward receipts; use it after the service exits. `status` returns the
private export when one exists, including a stopped run's final export;
otherwise it acquires the lease and replays an idle store. An exported status
is not an independent replay. Use `service-status` for explicit live inspection.

### Real 24-hour observation

The service writes an atomic `service-status.json`, append-only
`service-events.jsonl`, and immutable per-run receipts beneath `service-runs/`.
These files are private; monitoring never opens the live database. Status binds
the run, process, binary and configuration identities, accepted state
fingerprint, cumulative work, phases, heartbeats and actual work progress.
It excludes private openings, individual fees, addresses, timed nullifiers,
position classifications and queue counts.

Start the observer in a separate supervised process on the same authorized
host, using the stable executable actually running the service. For the Linux
package this is the `libexec` worker, rather than the CPU-admission launcher:

```sh
python3 scripts/observe-native-service.py watch \
  --network-dir .local/native-engineering/asert-a \
  --binary .local/native-runtime-release/libexec/siworld-native-node \
  --config .local/native-engineering/asert-a/engineering-network.bin \
  --output .local/native-engineering/asert-a-observation
```

The output directory must be absent. The observer creates private evidence,
checks OS process identity, freezes the binary/configuration hashes and run
identity, and independently measures 86,400 actual monotonic seconds after
readiness. Five-second samples cannot have gaps longer than 15 seconds. A new
collector does not inherit earlier elapsed service time. A changed run,
unexpected exit, stale heartbeat, stalled actual work, state inconsistency,
proof error or available cgroup OOM-counter increase makes the observation
incomplete. A long block gap below two hours with continuing real PoW progress
is permitted. During ready observation, two hours without an increased accepted
height makes the window incomplete even if hashing counters keep advancing.
This is an operational investigation threshold, not a consensus rule or a
deterministic promise about the 300-second target.
On hosts without cgroup counters, their absence is recorded and sampled RSS
must not be represented as a charged-memory or OOM bound.

Read the saved summary without accessing the service:

```sh
python3 scripts/observe-native-service.py inspect \
  --output .local/native-engineering/asert-a-observation
```

An `observing` summary older than 15 seconds is rejected. Observer completion
always retains `final_replay_required=true`. After a complete window, request
graceful stop, wait for a successful exit, run `check` offline and compare the
final height, tip and state fingerprint with the accepted observation and
shutdown receipts. Preserve any failure and begin a new clean window only
after review; do not credit gaps, restarts or accelerated clocks. A single-node
24-hour window is a pre-deployment engineering gate. It does not replace
maximum-load, independent-host, retention or recovery acceptance.

## Validation and remaining gates

```sh
cargo fmt --manifest-path crates/native-node/Cargo.toml --check
cargo test --locked --manifest-path crates/native-node/Cargo.toml --lib
cargo clippy --locked --manifest-path crates/native-node/Cargo.toml --all-targets -- -D warnings
```

The new integration suite includes invalid-envelope and sidecar rejection,
wrong-network/framing and reconnect behavior, multi-batch synchronization,
verified-work branch choice, depth-24/depth-25 reorganization boundaries,
atomic failure, detached-record reopen, wallet rescan and public-audit checks.
Some tests use deterministic synthetic verifiers to isolate state and transport
behavior. Separately selected native-proof tests exercise frozen proving and
verification; the wallet proof test uses synthetic funding history. The new
suite is covered by the dedicated native runtime CI job. None of these
correctness checks substitutes for actual hybrid-provider tests,
target-hardware performance or sustained-load acceptance.

Native issuance admission verifies the ML-DSA-65 declaration, frozen three-note
proof and a 50-SIP payment output to an explicitly configured dedicated fund
owner. Declaration-derived commitment randomness binds the receipt; its actual
transaction-derived rho is disclosed. A receipt must exist in canonical history
or a proof-verified transaction in the candidate block and can authorize only
one issuance. The registry, receipt consumption and minted commitments change
atomically with the canonical block and recover through verified replay.
The bounded local `submitissuance` dispatcher queues a declaration only after
its fee is canonical or admitted; it does not start an RPC listener. Pending
admissions are volatile. Production destination and limits remain unconfigured,
so issuance fails closed there; the mainnet fee remains undecided.
Production hybrid identity/record protection, a listening network service,
verifier-worker isolation, pruning/checkpoint bootstrap, real three-day
retention, Dandelion++, operational fund-key/allocation configuration,
mnemonic/protected wallet persistence and panel controls remain incomplete.
The native block transition and audit already validate bounded signed fund
payouts; this does not configure production fund custody. The library interfaces and
candidate limits above must not be treated as deployment qualification.
Those gates remain in the [node/network plan](v1-node-network-plan.md).
The retained seven-node legacy network and its keys/data are not inputs to this
runtime.
