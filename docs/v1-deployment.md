# Native V1 Deployment and Observability

The [monetary relations](v1-economics.md) have source-bound
`native-v1-economics-1` proof profiles and fresh reference-host evidence.
Public-key reproduction and complete CI remain release checks. The resource
tables include the current maximum of five reward notes and eight native
signed fund claims through explicit economic-record planning modes. The
32-wallet immutable genesis registry is a separate one-time record. Wire allowances and database overhead remain conditional;
they do not establish measured revised-network acceptance or SSD lifetime.

Status: qualification design for the independent native V1 engineering network.
The economic transaction profile has actual-AIR security and reference-host
measurements. The prior two-output profile remains a diagnostic baseline. Node integration, operating profiles, network capacity and supported
deployment platforms remain subject to acceptance. This document does not change the retained seven-node network.
[Decisions](00-decisions.md), [native transaction design](route-a-v1.md) and the
[node integration plan](v1-node-network-plan.md) define protocol requirements.

## Resettable engineering release

`siworld-eng-1` uses the native resident pinned-peer driver behind the explicit
`native-p2p` feature. One guarded executable supplies validator, miner and wallet
CLI commands. Build on Linux x86-64 from the pinned release source:

```sh
python3 scripts/build-native-runtime.py --engineering-network --output .local/engineering-release
.local/engineering-release/bin/siworld-native-node --check-cpu
.local/engineering-release/bin/siworld-native-node --help
```

The baseline launcher checks x86-64-v3 before executing the optimized worker.
Build receipts bind the worker digest, repository ISA configuration and selected
features. Tagged engineering assets also contain source commit and checksums.
A release tag does not attest to sustained network or maximum-load acceptance.

On a designated operations host, run `engineering-keys CUSTODY_DIRECTORY` once.
It creates independent random ML-DSA-65 test fund and checkpoint seeds, private
owner-only files and a public manifest. It refuses existing paths and never
prints private seeds. Run `init-engineering-genesis DIRECTORY CUSTODY_DIRECTORY`
when sealing the chain. This initializes ASERT work once, retains the production
300-second interval and economic timings, and configures one test fund account
at 10,000 basis points with team index zero. It creates no premine. The reserved
2-of-3 checkpoint public roster is explicitly inactive until authenticated
checkpoint startup exists; it has no current consensus or bootstrap authority.

Import only immutable public rules using
`init-peer DIRECTORY GENESIS_DIRECTORY EXPECTED_GENESIS_ID`. Independently check
the genesis identifier, export each host's public identity and persist peer pins
with `peer-pin` before `run-network`. Private identity seeds, custody, databases,
receipts and prior service records must not be copied between hosts. Validators
set `mining: false`; the separately provisioned miner sets `mining: true` and
explicitly configures Holder rewards to a locally retained wallet. Preserve old
chain directories and gracefully stop prior writers before a service switch.
Peer configuration and host inventories stay in private operations storage.
Only the approved P2P TCP port is exposed; wallet services remain loopback-only.

Manual wallet transfers are not delayed by default. Engineering background
delay is disabled; the 24-block reward maturity and Holder locks remain intact.
Start real low-value standard/priority transfers only after actual mature funds
exist. A command exit alone never establishes payment acceptance or receipt.
Private transaction coverage checks must not publish real/padding counts, fee
tiers, private balances or note-to-time associations as per-block telemetry.

Private service exports include the accepted public block timestamp and the last
block-template assembly duration, including settlement proving and excluding
proof-of-work search. This is a scoped runtime observation, not a separate
settlement benchmark. Operations monitoring pairs those values with process and
cgroup memory, disk usage, height, tip and authenticated peer count. It must not
add per-block real/padding counts or fee-tier telemetry.

Known incomplete work includes Dandelion++, authenticated checkpoint startup,
three-day proof pruning, production transport qualification, OIDC operations
roles and miner template pipelining. The engineering transport uses pinned
Ed25519/ML-DSA-65 identities with the hybrid TLS candidate; it does not establish
permissionless discovery or sustained Internet acceptance. Until pruning exists,
monitor actual disk growth and preserve records; do not claim a bounded
three-day on-disk history. Existing smaller engineering disks are a temporary
operating constraint, not the documented 500-GB deployment qualification.

## Roles and fault domains

Every full validator applies the same consensus rules and independently verifies
transactions and settlement. A miner adds block production and padding-proof
preparation to that role. There is no privileged main node, master database or
control-panel vote in consensus. Bootstrap services provide peer discovery,
not trusted state, proof validity or finality decisions.

| Role | Responsibilities | Operational separation |
| --- | --- | --- |
| Full validator | Verify, apply, relay and retain the required proof window | Baseline independently operated consensus participant |
| Miner/full validator | Full validation, block assembly, padding and settlement generation | Separate proving processes and keys from monitoring |
| Bootstrap node | Supply authenticated peer-discovery records | At least two independent operators or fault domains |
| Monitoring collector/panel | Receive bounded status telemetry and display incidents | Private service outside consensus; no spend/miner keys |

Distribute validation and mining across independently operated hosts and
networks. Multiple containers on one machine remain one failure domain.
V1 has no archive-node role and does not retain historical proof bodies after
the online retention window. Bootstrap and checkpoint services provide
discovery and an explicitly trusted starting point; neither has consensus
authority.

## Platform qualification

The historical measurement environment is Ubuntu 24.04, AMD EPYC 7763, two
exposed cores and four vCPUs in a Microsoft virtual machine. Host exclusivity
is unknown; the CPU model is not a deployment requirement.
Use the fixed `x86-64-v3` release baseline with AVX2 and its startup check;
`target-cpu=native` is not a reproducible release configuration. Record actual
CPU, effective CPU quota, RAM, storage, hypervisor and dependency/source hashes.
A four-vCPU label alone does not establish equivalent physical CPU capacity.

macOS on Apple Silicon and Windows are qualification targets, not accepted
V1 node/miner platforms. A future macOS ARM release needs its own native build,
crypto vectors, resource-isolation policy, storage/recovery and sustained-load
results. A future Windows release needs equivalent native verification and
process-limit tests; Linux under WSL2 remains a Linux VM with separately
measured storage, network and memory overhead. Do not label either path
supported by transferring the Linux benchmark. Wallet-only qualification is
independent of full-node qualification.

## Minimum host configuration

Require x86-64-v3 CPU and operating-system support, at least four online and
affinity-available vCPUs, and the role memory below. CPU vendor/model, exact
physical-core topology and virtualization are recorded without model-based
admission. The current collection adapter uses Ubuntu 24.04 and cgroup v2.
These admission floors do not establish maximum-load or sustained integrated
acceptance. The independent 5-GiB zero-swap proof scope remains a measurement
budget and does not replace the deployment memory requirement.

| Role | Minimum configuration |
| --- | --- |
| Full validator | At least four vCPUs, 16 GB RAM, 500 GB usable local SSD minimum; 1 TB recommended |
| Miner/full validator | At least four vCPUs, 32 GB RAM, 500 GB usable local SSD minimum; 1 TB recommended |
| Bootstrap or telemetry collector | Separate host; size after peer/load and retention tests |

The advertised RAM profiles are 16 GB and 32 GB. Memory qualification uses
Linux `MemTotal` in bytes: at least 15 GiB for validators or 30 GiB for miners.
Visible deployment cgroup limits must also meet that role's admission floor
before proof scopes are created. A nominal provider label alone does not
qualify a smaller visible allocation. The workflow runs both validator and
miner roles; an insufficient runner fails before optimized proof execution.
An explicitly authorized larger or self-hosted runner can be selected at
dispatch. Standard hosted labels do not guarantee the 30-GiB visible miner
minimum.

The hardware suite reproduces the frozen public keys, runs three transaction
trials at each of one and four workers, and runs three four-worker fixed-576
settlement trials. It records actual CPU model, exposed core/vCPU counts,
memory capacity, full ISA evidence, visible quotas, proof bytes and charged
process-tree peaks. Transaction bodies must fit 655,360 bytes and all three
four-worker generation times must be at most two seconds. Settlement bodies
must fit 655,360 bytes and the 589,824-byte measurement threshold. No
settlement-generation time limit is introduced. Each fresh proof process tree
must remain within 5 GiB with zero swap and no limit/OOM events.
The settlement fixture is the existing native-scan Holder witness; the separate
maximal-priority-fee witness and combined complete-block gate remain required.
These checks do not change runtime decoder or consensus caps.

SSD capacity means usable capacity after filesystem/array overhead, before
allocating separate backups. Disk redundancy does not replace backups. Measure
power-loss behavior, synchronous commits, write amplification and compaction.
The conditional planning minimum uplink is **43 Mbps**, with **100 Mbps sustained uplink**
recommended. Keep all 576 positions. The engineering-frozen transaction proof
cap is 655,360 bytes (640 KiB), with more than 10% margin above the selected
588,832-byte observed maximum. Settlement uses a 655,360-byte cap and
issuance retains a separate 524,288-byte cap. The source-bound measurement
profiles retain the historical 524,288-byte settlement admission value; the
current decoder cap does not change their hashes or establish full-capacity
maximum-fee/claim qualification.
The [complete conditional wire budget](v1-network-budget.md) charges three
application copies, settlement and bounded issuance, control, authenticated
framing, IPv6/TCP/link serialization, reciprocal ACKs, handshakes, 2%
retransmission and 5% missing-body recovery. After these costs, reserve at
least 15% of the selected minimum link's capacity:
`minimum_link_mbps = ceil(wire_mbps / 0.85)`. Transaction, settlement and
issuance proof caps are independent. Reproduce the economic format with
`python3 scripts/v1-network-budget.py --native-protocol --economic-rewards`.
It includes a 61,235-byte compact fixed record (five reward notes and eight
signed fund payouts), the settlement proof once in the compact body and all
remaining allowances. Its full wire model uses 36.52910683 Mbps;
43 Mbps leaves 6.471 Mbps (15.048589%) spare, while 100 Mbps leaves 63.471 Mbps.
The integrated four-issuance envelope needs 44 Mbps for the same reserve;
one issuance remains within 43 Mbps. Pin the actual admission setting and
repeat the model before activation.
The unflagged and native-only modes use their generic or single-reward layouts
with current independent cap defaults. They do not reproduce earlier numeric
evidence unchanged or size the revised format. Historical native single-reward
numbers require an explicit 524,288-byte settlement cap; `--legacy-baseline`
restores all three 524,288-byte caps and the earlier link/reserve settings.
Measure packet counters and queue growth
before accepting maximum-load operation, and schedule bulk backup/checkpoint
transfers separately.

Account for all simultaneous consumers. Current planned payload/worker ceilings
must be reconciled with the retained 640-KiB transaction proof-cap target in the
[native admission policy](route-a-v1.md). Count the verified pool, unverified
queue, verifier workers, compact reconstruction, padding payload and caches
under their independent byte ceilings. These are
policy ceilings, not resident-memory measurements; metadata, decoder copies,
network buffers, database caches, accepted state and allocator overhead are
additional. Avoid double counting shared ownership and count actual duplicate
buffers. Persisted state and caches need separately measured growth limits.

Reserve at least 4 GiB for the OS, monitoring, filesystem activity and service
restart on candidate hosts. Measure the node with its largest legitimate pools,
cold database opening, replay, pruning and compaction. Measure prover setup,
key loading, steady generation and teardown separately and together with node
work. Miner tests must include concurrent settlement and permitted padding
refill. Isolated proof measurements do not bound that aggregate. Require the
selected profile's charged process-tree peak, including preparation and
verification. The [reference measurements](v1-multi-asset-evaluation.md) report
525,234,176 bytes for transaction generation, 3,161,432,064 for fixed-576
settlement and 211,423,232 for three-note issuance in four-worker scopes.
These include fresh setup, proving, verification and the recorder; none is an
independent verifier-memory measurement.
Neither a clean single-process run nor spare page cache establishes long-term
memory safety.

## Storage ledger and capacity gate

Use [V1 Storage, Retention and Bootstrap](v1-storage-and-sync.md) and reproduce
the explicit planning model with
`python3 scripts/v1-storage-budget.py --economic-rewards`.
The three-output codec has 2,115 permanent bytes/position. At the 640-KiB
transaction cap, ordinary transaction proofs, settlement proofs and sidecars
require 335.831 GB at the nominal 888-block window; an additional capped
issuance proof/block brings the rolling budget to 336.296 GB. Include 64 KiB
permanent block records and 16 KiB permanent issuance records/block, 25% of all permanent bytes for indexes/state, 16 GB database
working space, a one-time 64-KiB fund genesis registry, 20 GB system/recovery
files, and 20% device free:

| Workload | Device year 1 | Device year 3 | Device year 5 |
| --- | ---: | ---: | ---: |
| Maximum 576 positions/block | 678.922 GB | 1,106.024 GB | 1,533.127 GB |
| 10,000/day, minimum 64-position blocks | 128.560 GB | 199.937 GB | 271.313 GB |
| 50,000/day, adaptive grouping | 246.391 GB | 393.923 GB | 541.455 GB |
| 50,000/day, uniform 176 positions | 248.952 GB | 398.143 GB | 547.335 GB |

**500 GB usable SSD is the installation minimum; 1 TB is recommended** for
both miners and validators. That minimum does not qualify continuous maximum
load: year-one used bytes are 543.137 GB before the 20% free reserve. A 1-TB
device reaches the modeled free-space threshold after approximately **2.50 full
load years**; year three needs 1,106.024 GB, rather than fitting 1 TB.

At 10,000/day, 500 GB has modeled headroom beyond five years: the year-five
device requirement is 271.313 GB. At 50,000/day, adaptive packing needs
541.455 GB in year five and uniform 176-position blocks need 547.335 GB;
both exceed 500 GB including the free reserve. Do not promise five years on
500 GB for every early workload. These conditional horizons depend on the
final measured overheads, packing and workload. Publish actual growth and expand storage before reserves are
consumed; retain 576 positions and the complete three-day proof window.

The 64-KiB block reserve covers the maximum five-note/eight-claim economic
format plus provisional persistent-record overhead. The immutable genesis
registry supports 1–32 fund wallets with positive basis-point shares totaling
10,000, public ML-DSA-65 keys and an explicit development-team residue wallet.
Its section occupies 62,530 bytes and is covered once by the 64-KiB registry
allowance. Actual shares and keys are required before activation; V1 has no
key/share replacement mechanism. Per-wallet credits accrue in the ledger
without emitting an output each block; up to eight signed claims can be
included in one block. Each claim spends only its own wallet's released
unspent balance. The unflagged storage script uses the 8-KiB block-record
layout with current cap defaults; historical numeric evidence requires
explicit original caps or `--legacy-baseline`.

The block/issuance ceilings and database allowance remain proposed engineering
budgets: final encoding must bound headers/PoW, settlement declarations,
reward/fund records and ML-DSA signatures, metadata and initial issued notes.
Measure exact tree/index/redb/WAL/compaction peaks and replace the allowances;
they are not actual measured overheads. Unbounded issuance has no finite
worst case. A compaction scheme needing a full database copy can exceed the
16-GB working reserve and must be changed or separately provisioned. Never
prune public data or unexpired proofs to enforce a capacity target. Faster
blocks increase elapsed-time retention storage.

All nodes retain headers/PoW, commitments/tree state, ciphertexts, nullifiers,
fee commitments, proof-free settlement declarations, reward notes, signed fund
records, issuance records and recent-root snapshots permanently. No V1 archive
role is selected. Permissionless issuance needs bounded metadata and per-block
bytes/work so the added permanent-storage term remains finite.

Alert at candidate 20% free, suspend local production and admission at 15%,
and stop consensus writes safely before an emergency 10% reserve is consumed
if durable persistence cannot continue. Calibrate thresholds using measured
maximum atomic-operation, compaction and recovery peaks. Disk pressure is
local unavailability, not evidence that a valid block is cryptographically
invalid. Backups are separately budgeted and do not replace free-space reserve.

## Resource qualification and recovery

Qualify each candidate hardware profile with 72 continuous hours at maximum
valid load, and a seven-day independent-host soak containing at least
72 hours of maximum load. The windows may overlap once the configuration is
frozen. Report steady memory slope, component disk growth,
write amplification, CPU/queue saturation and actual framing/recovery traffic.
The soak is not evidence for three-day deletion: observe the real elapsed
retention lifecycle as well as accelerated crash/clock/pruning regressions.

Project-operated object storage must back up permanent public data without
becoming an archive for deleted proof bodies. Upload each finalized block
segment (or at least every six hours) with immutable versioning, publish a
signed daily manifest, and create a weekly full checkpoint snapshot. Restore
into an isolated node by verifying object hashes and signatures, replaying
ordered blocks and PoW, rebuilding indexes and comparing state roots, work and
nullifier/commitment roots before promotion. Run a monthly restore check and a
quarterly replacement-host recovery test. Backups must not be the only copy;
the node set remains the source of permanent public data.

Wallet creation must require an explicit mnemonic backup and a successful
local restore check. A restored wallet scans permanent ciphertexts and public
commitments from genesis or an authenticated wallet birth height, including
segments older than its bootstrap checkpoint, verifies note ownership and asset
metadata, and reconciles balances and pending payment journals exactly once.

On reference hosts with measured 100-Mbps access, initial recovery targets are
return to the durable tip within ten minutes after a clean restart, and catchup
of at most 24 missing blocks within 30 minutes. Measure available residual
bandwidth under concurrent relay before accepting those targets. For lower
bandwidth, derive the catchup allowance from missing bytes divided by measured
spare bandwidth plus verification/replay work; do not promise 30 minutes on a
connection with only the modeled minimum headroom. Require zero loss of
durably accepted records.
Database corruption halts participation and requires verified backup/recovery;
it must not silently rewind accepted history.

## Real-time private monitoring

Provide an authenticated, read-only status feed from each node over outbound
connections to a separate collector. Use distinct telemetry credentials,
bounded queues and expiry; collector failure must not block validation or
mining. Protect any deployed temporary transport with authenticated encryption;
the production connection path still requires the reviewed hybrid handshake.
Use five-second samples and server-pushed panel updates as initial targets;
mark a feed stale after 15 seconds and unavailable after 30 seconds. Sequence
numbers are scoped to an authenticated node process epoch and a fresh
collector-issued session challenge. Enforce increasing sequence numbers within
that session, rotate sessions after either endpoint restarts, and reject old
sessions. Compute receipt age with the collector's monotonic clock; sender
timestamps alone cannot establish freshness. Repeated state with a new sequence
does not itself prove current node progress.

The private panel should show configured opaque node label, role, release
identity, uptime/restart counter, chain height and public roots/work agreement,
explicit state-busy/idle status, finality/sync lag, connection-health classes,
aggregate CPU and charged process memory, memory events, disk headroom,
proof-retention lag, verification latency and aggregate traffic rates.
Busy or unavailable nodes do not establish completed-state equality. Compare
roots only at a common height and confirm propagation lag before declaring
divergence; one slow block does not establish a sustained stall.

Do not emit addresses, nullifiers with times, individual fees/openings,
real/padding classifications, real/dummy counts or padding-pool counts.
Keep low-level diagnostic retention private, bounded and access controlled.
Show durable incident episodes, recovery transitions and acknowledgments.
Display the new network separately from retained-network status.

Bind the panel to loopback/private access by default, authenticate operators,
and enforce session expiry. A remote operator uses authenticated private
access, not a public unauthenticated control endpoint. Monitoring credentials
cannot sign blocks, spend, alter peers or launch recovery. If administrative
controls are later added, use a separate audited authorization boundary.

The native proof components and isolated benchmark evidence exist. The roles,
host profiles, capacity acceptance, telemetry feed and panel integration above
remain planned work. Accept them only after independent-host end-to-end tests,
including observer loss, stale sessions, node restart, peak load and recovery.

## Multi-asset proof performance gate

Keep 576 positions per block and the 80-bit quantum security requirement.
Select the smallest measured proof body among profiles whose three
four-worker generation trials on a minimum-qualified host each complete
within two seconds. Set the body cap at least 10% above the largest observed
selected-profile proof, rounded up to 64 KiB. The selected economic b7/q41/g20
profile generated in 1.429902190–1.531155438 seconds across three reference-host
trials, with a 1.462877730-second median and a 525,234,176-byte charged
process-tree peak. The 655,360-byte cap exceeds the largest selected
588,832-byte body across one- and four-worker measurements by more than 10%.
The complete economic wire ledger retains the conditional 43-Mbps floor.
Refer to the [complete measurement record](v1-multi-asset-evaluation.md) for
the pinned security report and measurement scope. Enforce this byte cap in the
wallet and node, and account for it independently in network, memory and
retention budgets. The proof-size bound remains an admission rule rather than
a guarantee that every randomized valid proof will fit it.

Circuit-width and opening-size optimization proceeds separately. The selected
profile remains fixed until replacement security, timing, memory and size
evidence justifies an explicit revision. The prior two-output and prior
multi-asset scans remain reproducible diagnostic evidence, not alternate
production parameter profiles. Neither parameter selection nor isolated
measurements qualify whole-node sustained operation.

## Backup checkpoint freshness

A weekly full snapshot alone is insufficient once proofs expire after
three days. Export an authenticated, consistent confirmed-state checkpoint
(full or a complete authenticated delta chain) at least every six hours,
together with the public-data manifest. Weekly full snapshots remain a
compaction/recovery convenience. Before replaying a restored checkpoint's
proof tail, confirm every required proof is still available. If not, obtain a
newer quorum-authenticated checkpoint under the explicit trust policy, or
stop recovery; public records and PoW cannot replace deleted proof validity.
The checkpoint binds the asset registry, fund state, permanent-data manifests
and complete accepted root window. Never synthesize missing state or silently
trust an unauthenticated peer.
