# Current Protocol Decisions

Status: native V1 transaction, fixed-capacity settlement and three-note
issuance proof parameters have source-bound engineering profiles for the
`native-v1-economics-1` relation. Revised actual-AIR reports and 39 isolated
process measurements qualify the selected engineering parameters. Required CI
must reproduce the installed public keys and exercise the native adapters.
Independent security review, node/network integration and activation remain
separate gates; no audit approval or active-network change is implied.

The current integration candidate changes economic ordering and the native
custody/identity dependency graph. Native application qualification remains
separate from the unchanged AIR profiles. Preserve the measured proof sources,
dependency revisions, benchmark configuration and source guards; do not update
frozen hash records merely to accept unmeasured changes. Economic rule version
3 changes no AIR relation or selected FRI parameter. Its source-bound accounting
reference and strict per-wallet checks are separate from proof measurements.

## Network and proof architecture

Preserve the existing seven-node N=2 legacy recursive classical engineering
testnet, verifier, history and keys.
Native V1 uses a separate resettable engineering network with independent
genesis, directories, keys and network identity. No existing notes or proofs
are imported. V1 uses per-transaction native STARK proofs; recursion and
historical proof compression are V2 work. N=32 is outside the current scope.

Use KoalaBear D8, standard Poseidon2 W24 and twelve-element digests. Require
classical conjectured security of at least 128 bits and quantum-halved Johnson
Fiat–Shamir terms, including query and enforced grinding terms, of at least
80 bits. Challenge-domain and selected BHT collision terms must also meet
80 bits. The revised actual-AIR ledgers report quantum-halved Johnson
challenge unions of 81.692219 bits for transactions, 81.983705 for fixed-576
settlement and 81.898720 for three-note issuance. The classical conjectured
ledger is approximately 185 bits and the selected commitment BHT ledger is
123.333333 bits. These are engineering model results pending independent
review. All future parameter changes must retain at least 80 bits.
The [collision ledger](bht-security-accounting.md) distinguishes raw classical
reports from quantum model conversions and application hashes.

## Subsidy, reward modes and fund allocation

Amounts use SIP: one SIP is 100,000,000 atoms. Native V1 pays an initial
3,394,524,515 atoms per 300-second block. Blocks 1 through 4,032 use that
amount; block 4,033 first applies `DECAY_Q32 / 2^32`. Subsequent epochs contain
4,032 blocks. The native floor is 100,000,000 atoms per block; the equivalent
60-second tail constant is 20,000,000 atoms. Retained legacy issuance behavior
is not changed by this versioned native rule.

Subsidy allocates 3% to the public Holder pool, 10% to development-fund
wallets and the residual to the miner base. Each fund wallet has its own
explicit share, credit history, released entitlement and spent counter. Its
50% direct portion matures after 24 blocks; its other 50% releases in daily
height-based steps over 1,461 days, with 288 blocks per day. Each credit vests
independently; cumulative released atoms use integer floors, releasing all
remaining atoms on the last day. A wallet may spend only its own released
unspent entitlement, authenticated by its existing ML-DSA-65 authorization.
Fund wallets do not share expenditure allowances.

The immutable genesis registry supports 1–32 wallets. Positive shares are
basis points totaling exactly 10,000; canonical parameters include each
ML-DSA-65 public key and an explicit development-team wallet index. First
compute `T = floor(subsidy / 10)`, then `floor(T * share[i] / 10000)` for each
wallet; credit the residue to the team wallet. No V1 key or share replacement
mechanism exists. Main-network activation requires an approved real registry;
its importer and activation validation remain unimplemented. The resettable `siworld-eng-1` ASERT engineering genesis uses one independent
random test account with 10,000 basis points and team index zero. Generate its
ML-DSA-65 test custody only on an operations host. The older 24-key reproducible
registry remains an isolated fixture and must not fund a running engineering
chain. Test keys and shares never select a main-network allocation.

Each wallet accumulates entitlement without a per-block output. Up to eight
signed claims may enter one block, with independent wallet counters and
released-minus-spent checks. This throughput limit does not limit the genesis
registry to eight wallets. The native configuration/ledger encodings are
versioned and reject older engineering stores without migration. The retained
legacy `DevFundKeys` and its payout interface are not native V1 registry rules.

The public block mode is explicitly selected without a miner default:

- Voyager: floor(5% of miner base) is burned, floor(20%) enters the Holder pool
  and the residual becomes one reward note maturing after 24 blocks.
- Holder: four notes each receive floor(10% of miner base), unlocking after
  52,560 / 105,120 / 157,680 / 210,240 blocks. The residual, confidential fees
  and pool payment form the fifth note, which matures after 24 blocks.

Compute a Holder payment as floor(pre-block pool balance / 4,032), subtract it,
and only then inject the block's 3% allocation. Same-block credits cannot fund
the current claim. Voyager never draws from the pool; its 3% protocol credit
and additional mode allocation are retained in the post-block pool. Economic
rule version 3 binds this order into the native genesis and state identity.
Fees are
transfers and all enter reward note zero; fees do not participate in subsidy
splits. Template creation snapshots the selected mode, so preference changes
cannot modify an already prepared candidate. Reward note nonces bind height
and ordered note index, preventing repeated nullifiers across tranches.

Cumulative issued subsidy equals cumulative miner subsidy-note credits plus
Holder pool balance, burned subsidy and fund entitlements. Count neither fees
nor fund transfers as issuance. Block acceptance and reorganizations atomically
include pool, burn, fund and future unlock schedules. Public locked/circulating
figures describe scheduled subsidy/fund accounting, not an exact sum of private
unspent balances. The [economic specification](v1-economics.md) defines the
integer formulas, projections and test requirements.

## Root snapshots and output-encryption boundary

Accept the newest 4,096 canonical-chain snapshots of the recent-root tree.
The newest snapshot has age zero; age 4,095 is accepted and age 4,096 is
rejected. At the 300-second target this is approximately 14.22 days. A snapshot
is selected by canonical block identity and resolved to a locally trusted root;
a peer-supplied root is never authoritative. Bind the snapshot height and block
identity into the existing public-data digest, so a proof cannot be reused under
a replacement identity even if its tree root is identical. Remove noncanonical
snapshots on reorganization. Evict pending transactions that reference an expired or removed
snapshot, release their nullifier reservations, and require wallet reproof.
Historical validation uses the canonical snapshot window at the block being
validated, rather than the live tip or elapsed wall time.

This retention window is distinct from the depth-12 recent-root tree, which
already contains 4,096 anchor entries. The existing AIR depth remains unchanged.
Allowing older tree snapshots also permits anchors older than the current
anchor ring: at the full boundary an anchor may be 8,190 blocks behind the tip.
Fee-schedule staleness and snapshot metadata storage must account for both
windows. Reorganizations that shorten the chain require authoritative history
to refill the accepted window; missing history fails closed.

V1 proves ciphertext-byte binding, not ML-KEM or ChaCha20 encryption correctness.
The AIR binds every encoded ciphertext byte through the public-data digest.
The recipient verifies AEAD authentication and reconstructs the note commitment.
The sender must locally open and check all three outputs before broadcast, using the
payment encapsulation secret for the recipient output, and retain per-payment
encapsulation randomness in protected wallet storage for selective payment
receipts. Receipts are private disclosures, never public transaction fields or
logs; they must not reveal a wallet master or change secret.

Padding uses actual ML-KEM encryption to a fresh valid ephemeral recipient key,
plus the same fixed-format change encryption. Random byte padding is forbidden.
Real and padding outputs share lengths and codecs. These checks do not prove
computational indistinguishability. A malicious sender can still prove a
byte-bound, undecryptable output: it is unusable by its recipient, but does not
change the consensus value-conservation or spend-validity relation. Complete
encryption-correctness circuits remain future research.

## Capacity and resource boundaries

The block target is 300 seconds with 64 through 576 positions in groups of 16.
Keep the maximum at 576; there is no capacity-reduction fallback. Prioritize
transaction proving within two seconds using four workers on a host meeting
the minimum hardware configuration.
Select from log blowups 5 through 8 and query/batch grinding 20 or 24, using
three fresh trials per configuration. All three generation times must pass;
rank passing configurations by their largest observed serialized proof.

The selected transaction profile uses `log_blowup=7`, 41 queries, query
and opening-batch grinding 20, commitment grinding zero, binary folding and
`log_final_poly_len=0`. The revised AIR has 256 base rows, 1,392 main columns,
247 preprocessing columns and 101 public values. The
[actual-AIR evaluation](v1-multi-asset-evaluation.md) and source-bound profiles
record all eight configurations and three trials per configuration on an
Ubuntu 24.04 EPYC 7763 VM exposing two physical cores and four vCPUs. This is
the recorded measurement environment, not a CPU-model requirement.

The selected four-worker generation trials are 1.531155438, 1.429902190 and
1.462877730 seconds. The largest proof across the selected one/four-worker
samples is 588,832 bytes; `MAX_LEAF_PROOF_LEN = 655,360` bytes (640 KiB)
provides 11.298299% headroom. The four-worker whole-process-tree charged peak
is 525,234,176 bytes. Single-worker verification median is 17.006900 ms,
measured within a process that also performs fresh setup and proving; it does
not establish standalone verifier memory or worst-case latency. This is a
three-sample engineering qualification, not independent cryptographic approval.

Settlement uses blowup 8, 36 queries and the same grinding/folding settings.
Its four-worker generation median is 5.523829281 seconds and maximum charged
peak is 3,161,432,064 bytes. Three-note issuance uses those same FRI settings;
its four-worker generation median is 0.639979907 seconds and charged peak is
211,423,232 bytes. Settlement uses a 655,360-byte cap and issuance retains a
separate 524,288-byte issuance cap.
The 5-GiB cgroup boundary is a measurement condition, not a miner RAM
requirement. All scopes use zero swap and preserve the kernel memory-event
record. The 39 distinct scopes consist of 24 grid trials, three selected
single-worker transaction trials and six trials for each related relation.

An enforced admission cap is not a mathematical encoded-size bound. The
retained two-output decoder and network are unchanged. Current native
source/key/profile guards, worker isolation and deployed-network resource
qualification remain mandatory before activation.

The implemented public body is 2,027 bytes; its fee commitment and snapshot
selector bring permanent bytes to 2,115 per position. The native codec's
2,184-byte relay prefix and 78-byte sidecar bring the capped combined payload to
657,622 bytes. Full three-copy traffic for 576 positions, settlement, bounded
issuance, inventories, requests, AEAD/multiplexing, IPv6/TCP/link framing,
reciprocal ACKs, handshakes, retransmission and recovery must use the explicit
economic-record model:
`python3 scripts/v1-network-budget.py --native-protocol --economic-rewards`.
Its maximum compact fixed record is 61,235 bytes for five reward notes and
eight native signed fund claims; settlement appears once inside the
compact body. The model charges 1,369,841,506 bytes per target interval, or
36.52910683 Mbps. Require at least 43 Mbps sustained uplink, computed as
`ceil(wire_mbps / 0.85)`; 15.048589% remains unused at that floor. Deployment
recommends 100 Mbps. The [full wire budget](v1-network-budget.md) remains
conditional planning, not measured throughput. Earlier unflagged/native-only
reports remain historical evidence. Recompute if the revised scan changes
proof caps, and measure the actual transport before network acceptance.

The adopted layout reuses range-check lanes for snapshot-height limbs and
omits unused inverse witnesses for two identity asset comparisons. All other
asset comparisons and balance equations remain enforced. The separate
[layout prototype](multi-asset-air-optimization.md) is unreferenced experimental
work; it is not the measured 1,392-column implementation. Re-screen and
measure any further optimization before replacing its profile or reducing
proof/bandwidth limits.

## Confidential fees and retention

Use confidential fee commitments with native fixed-capacity settlement.
Nodes validate fee-opening sidecars against the transaction and commitment
before admission; no additional sidecar signature or encryption layer is
selected. Planned hybrid X25519 + ML-KEM transport handles connection secrecy.
Transaction, settlement and native issuance proof bodies follow local role
storage policy: bootstrap and validator nodes retain at least 24 elapsed
hours after observed finality and provide synchronization within that window;
miner and ordinary nodes retain the latest 96 blocks and disable historical
proof service. The 24-block consensus reorganization limit is unchanged.
Private sidecars follow bounded admission expiry. Public data remains permanent
on every node; no V1 archive-node role is selected. Openings use eight independent canonical KoalaBear elements,
approximately 247.91 bits of entropy. The corrected settlement AIR keeps the
fee total and miner amount private and proves the mode-selected reward-note
commitments, height/index-derived nonces and authenticated unlock plan. Network, height and the ordered
transaction list enter its public context. Transaction proofs enforce private
anchor fee schedules; settlement opens and sums commitments without imposing
one current tier on old-snapshot transactions. See [fee settlement](fee-settlement.md).

## Prior profile and provisional operational resource policy

The prior two-output baseline used `log_blowup=8`, 36 queries, query grinding 20,
opening-batch grinding 20, commitment grinding 0, binary folding and
`log_final_poly_len=0`. The bundle records actual AIR shapes, fixed
`p3-security=0.9.0-rc.2` reports, source/dependency hashes and canonical public
verifier artifacts. Source, envelope, key or parameter drift fails CI.
A new profile requires review. The dependency revision is fixed in
[its lineage](d8-dependency-patch.md); upstream merging is not required.

Independent verifiers load public keys without prover setup. The local policy
is 128 MiB charged memory, zero swap, 250 ms CPU per proof, a two-second wall
watchdog and two concurrent workers. CPU accounting is sampled at intervals
of at most 10 ms; overshoot fails the resource check. This is not a fractional
kernel CPU quota. The serial allowance is 144 seconds for 576 transaction
checks, or 144.25 seconds including settlement. Actual measurements are
reported separately; repeated-proof work is not valid stateful block validation.
Local exhaustion is retryable unavailability, never consensus invalidity.

Verified pool: 512 MiB/2,048 entries. Unverified queue: 64 MiB/128 entries.
Per peer: 2 MiB/four unverified and 16 MiB/64 verified entries. Apply byte
limits first, including owned metadata, and reserve before reading. The codec
has a separate 4-MiB declared-vector budget, not an RSS bound. Negative and
abuse caches are 1 MiB each; reconstruction is 640 MiB/two blocks. TTLs and
admission rules are in [the integration plan](v1-node-network-plan.md).

Maintain at least 64 usable pregenerated padding transactions when ready,
with at most 128 entries and 65 MiB of serialized payload. At the new wire
maximum the byte cap permits at most 103 entries before metadata; 64 entries
need 42,087,808 bytes and fit. Account metadata separately. Use fresh nullifiers, genuine ephemeral-recipient ML-KEM encryption
and the same proof profile. Expiry, orphaning, inclusion and confirmed/pending
nullifier conflicts invalidate entries before selection and release their
reservations. Refill below 64; shortages delay production rather than permit
invalid padding or exceeding caps.

## Node and network implementation

The [integration plan](v1-node-network-plan.md) covers the shared atomic block
transition, bounded admission, compact relay, role-based proof retention,
permanent public-data storage, checkpoint-plus-PoW synchronization, authenticated X25519 + ML-KEM transport and
Dandelion++. Use groups of 16, 64–576 positions and `MAX_REORG_DEPTH=24`.
The fixed settlement AIR has 576 openings; smaller blocks derive canonical
zero-fee internal tails without additional chain transactions. Checkpoint
bootstrap has an explicit trust assumption after historical proof deletion.
The original N1–N7 planning range is 33–56 engineering days including
dual-identity transport work; wallet durability and private monitoring add
separate 6–10 and 3–5 day estimates. These are scope estimates, not remaining
work or completed acceptance. They exclude review, infrastructure and elapsed
observation windows. The current implementation boundary is recorded below.
New-network launch requires [native V1 acceptance](prover-acceptance.md).
The retained seven-node network, history and keys remain unchanged.

## Deployment qualification and visibility

The 5-GiB zero-swap generation measurements do not set a formal miner RAM
requirement. The [qualification profiles](v1-deployment.md) start at four
vCPUs/16 GB for validators and at least four vCPUs/32 GB for
miners, with host capacity qualified separately from the role-specific node-file budget, plus separately
budgeted backups. These profiles
are unqualified until sustained integrated measurements pass. Linux x86-64-v3
is the measured platform; macOS and Windows need their own adapters and
qualification. Keep the 43-Mbps uplink floor; prefer 100-Mbps links for margin
and qualify actual full-capacity relay/recovery at both bandwidth classes.

### Hardware qualification decision: 2026-11-01

Hardware qualification changes from a specified CPU model to minimum
configuration checks. Require x86-64-v3 CPU and operating-system support,
at least four online and affinity-available vCPUs, and advertised RAM of
16 GB for validators or 32 GB for miners. Memory admission uses system-visible
capacity: at least 15 GiB for validators or 30 GiB for miners. Visible
inherited CPU or memory limits must not reduce that allocation below these
admission floors. The advertised labels do not replace the visible-memory
checks. CPU vendor, model, exact core topology and virtualization are
measurement metadata, not admission requirements. The Linux collection
adapter currently requires Ubuntu 24.04 and cgroup v2; other operating
systems need qualified adapters.

Record actual CPU model, core/vCPU counts, memory capacity, ISA features and
visible allocation limits for every measurement. Retain existing EPYC 7763
records as measurement environments without changing their recorded values.
Frozen proof parameters, public keys and source identities remain unchanged.
All three four-worker transaction generation trials must still complete
within 2,000,000,000 ns, and every transaction proof body must be at most
655,360 bytes. The hardware suite also checks three fixed-576 settlement
proofs against a 655,360-byte ceiling and its 589,824-byte (90-percent)
measurement threshold. Keep the independent 5-GiB process-tree memory
boundary, zero swap and failure on resource-limit events. This qualification
does not change runtime proof decoders or consensus limits, replace maximal
fee/full-block acceptance, or establish sustained node resource acceptance.

At the target block rate, proofs and sidecars including the nominal depth-24
finality tail require 118,158,124,032 rolling bytes at the separate caps.
The 2,115-byte position codec adds 128,061,388,800 permanent bytes/year at
full load. The [finite storage model](v1-storage-and-sync.md) also reserves
64 KiB/block for economic permanent block records, 16 KiB/block for issuance records,
25% of permanent records for indexes/state, 16 GB database working space,
20 GB system files and 20% device free. These remain proposed allowances
pending actual database and encoded-record measurements.

Reproduce the economic-format model with
`python3 scripts/v1-storage-budget.py --economic-rewards`; the unflagged
8-KiB-block-record scenario is retained only as earlier planning evidence.
With the free-space reserve, the 24-hour service-window model needs
406.249/833.352/1,260.454 GB at full load for years 1/3/5. These are workload
estimates. The 200-GB service-node budget is an operational alarm threshold,
not a write ceiling or an ingestion gate. Budget pressure must not shorten proof
retention, delete permanent records, or stop validation. Permanent growth and
physical disk exhaustion remain capacity-planning risks.
The [component model](v1-storage-and-sync.md) gives the conditional 10k/50k
workload estimates and separates the host device from managed node files.
The five-note/eight-claim reserve is independent of the 32-wallet genesis
registry. A one-time 64-KiB registry reserve is also included. Production
remains fail-closed without explicit genesis-bound public keys, exact
basis-point shares and a team residue index. Never shorten retention or
prune permanent public data to meet a disk target.

Every validator independently enforces consensus. Miners add production;
bootstrap nodes add discovery; project-operated object storage backs up public
data without retaining deleted proofs. There is no privileged
main node. Use an independent private collector/panel with outbound read-only
telemetry, five-second samples and stale marking after 15 seconds. Monitoring
failure cannot stop consensus. Exclude addresses, timed nullifiers, fees,
real/padding classifications and padding-queue counts.

Qualification requires a 72-hour maximum-load hardware run and a seven-day
independent-host soak containing at least 72 hours at maximum load; windows
may overlap on the frozen configuration. Observe a real 24-hour-after-finality
retention lifecycle as well as accelerated deletion/recovery tests. The
[acceptance matrix](prover-acceptance.md#gate-6-sustained-observation-retention-and-recovery)
defines RPO zero for durable records, ten-minute ordinary restart and a
30-minute at-most-24-block catch-up target on the 100-Mbps reference.
Lower-bandwidth recovery requires its own measured spare-bandwidth budget.
These are test targets, not completed measurements.

## Transport identity and checkpoint trust

The [V1 network design](v1-network-design.md) selects ephemeral X25519 plus
ML-KEM-768, with Ed25519 and ML-DSA-65 identity signatures both required over
the bound identity/transcript. Use a reviewed hybrid combiner, key confirmation
and fixed protocol profile, with no classical fallback. These choices still
require implementation and independent security review. A classical PeerId
alone does not bind the post-quantum identity.

Dandelion++ is the selected source-relay path. Its routing/timer parameters
and library/combiner profile must be frozen after adversarial evaluation.
Hybrid transport protects content, not network endpoints; Dandelion++ does
not guarantee anonymity against global observation or malicious first hops.
Fee-sidecar recipients learn openings and can identify a zero fee; the
on-chain commitment does not hide that information from its recipient.

Pruned bootstrap uses opt-in trust in a fixed, genesis-pinned two-of-three
independent checkpoint-authority roster, with dual identity signatures and
authenticated cumulative work. A release checkpoint plus PoW is the default
new-node synchronization path; full proof replay from genesis is a future
upgrade. Checkpoint
manifests bind network, block/work, verifiers, complete state and snapshot
window. Reject conflicts and never automatically roll back accepted history.
The quorum is an explicit trust policy, not a proof of deleted history or
Byzantine-consensus safety. Authority setup creates no keys or genesis as part
of this design; identity custody and review remain launch requirements.

## V1 assets, durable public data and issuance audit

V1 supports permissionless issued assets in the same privacy pool as SIP.
Notes bind a private asset ID into their commitment and ciphertext. All
transactions have two inputs and three outputs, including SIP-only and padding
transactions. The AIR balances every private asset independently; fees are
paid only in SIP. Issuance publishes declared supply, name and precision and
uses a domain-separated ML-DSA-65 signature verified natively by the node.
The isolated native implementation covers ID derivation and fixed-supply issuance-to-note binding in
[the multi-asset design](v1-multi-asset.md). Testnet asset issuance requires
exactly **50 SIP (5,000,000,000 atoms)**, credited entirely to a dedicated
development-fund account. Native issuance integration binds a proof-verified
canonical or same-block SIP output to the signed declaration and configured destination,
consumes that receipt once, and applies registry changes with the block state.
That account is not yet configured: issuance admission must remain closed
until its authenticated destination and explicit engineering limits are set.
An absent destination must not select a default account or waive the fee.
The mainnet issuance fee remains undecided. Asset-aware minimum outputs,
metadata/note limits and per-block issuance byte/CPU budgets remain open
protocol values; do not settle them implicitly in consensus code.
No private transfer asset ID or holding is published. The unresolved values
and qualification evidence are recorded in [the open-question register](11-risks-open-questions.md).

All nodes permanently retain headers/PoW, output commitments and tree state,
ciphertexts, nullifiers, fee commitments, proof-free settlement declarations,
miner reward notes, development-fund spend records with ML-DSA signatures,
asset issuance records and recent-root snapshots. Only transaction proofs,
settlement proofs and native issuance proofs expire according to the local
role policy: 24 elapsed hours after observed finality for bootstrap and
validator nodes, and the latest 96 blocks for miner and ordinary nodes.
Bootstrap and validator stores alarm at 200,000,000,000 bytes of managed file
content. This threshold does not block database growth, auxiliary writes,
block ingestion, or verification. It never permits permanent-data deletion or
expiry inside the retention window. Miner and ordinary proof windows default
to 96 blocks, are locally configurable, and cannot be set below 24 blocks.
Service checkpoint publication is required every six hours. The engineering
transition uses two independent ML-DSA-65 checkpoint authorities with a 2-of-2
quorum, separate from peer and fund keys. Its keys are engineering-only release
configuration and do not change genesis or mainnet checkpoint trust. A service
must retain every proof after the latest valid checkpoint. A checkpoint older
than 18 hours raises an alarm and suspends pruning; fresh valid publication
restores eligibility. Authenticated remote bootstrap, permanent-data
reconstruction and tail delivery remain qualification gates before service
expiry. Private sidecars use bounded admission expiry.
There is no V1 archive role. Release-pinned checkpoint plus PoW is the default
new-node path; full historical proof validation is a future upgrade.

V1 requires an integer-only height-by-height SIP issuance audit using the
shared reward schedule and fund transition. The native offline command and
library now independently replay canonical proofs, check SIP subsidies and
direct/locked fund credits and bind the report to the accepted height, tip and
state fingerprint. Signed fund spending is included by the economic transition when existing
verification keys and allocation are explicitly configured. Canonical replay
also verifies signed asset declarations, issuance proofs, declaration-bound
fee receipts and one-time registry insertion, and reports each asset's public
supply, issuance height and declaration binding. Private holdings and wallet
receipt checks remain outside that public audit; authenticated checkpoint
inputs and recovery after proof pruning require separate qualification.
Project-operated permanent-public-data backups
and mandatory mnemonic backup/full ciphertext rescan are described in
[deployment](v1-deployment.md) and [the storage model](v1-storage-and-sync.md).

## Multi-asset implementation and proof qualification

The isolated [multi-asset crate](../crates/bench-multi-asset/README.md) implements
native asset conservation, the fixed three-output codec, ML-DSA-authenticated
fixed-supply issuance and SIP-only settlement rewards. The economic revision
adds trusted snapshot-height lock eligibility and mode-selected reward notes.
Ordinary transaction and issuance outputs use unlock height zero; consensus
reward notes obtain their locks from the authenticated reward plan.

The current [transaction profile](../crates/bench-multi-asset/artifacts/v1-transaction-profile.json)
and [relation manifest](../crates/bench-multi-asset/artifacts/v1-native-proof-profiles.json)
bind the revised relation to exact source identities, security reports,
measurements and public preprocessing keys. Their engineering qualification
preserves the two-second four-worker transaction criterion, 655,360-byte cap
with at least 10% observed-body margin, 80-bit quantum-halved Johnson target
and 576 positions. Required CI re-creates all three public keys and checks
native proof round trips and rejection behavior. Keep the independent
655,360-byte settlement and 524,288-byte issuance limits. Any subsequent source or parameter
change requires a new source-bound profile and reviewed measurements.

Independent verifier qualification, valid-block timing, configured testnet
issuance-fee collection, durable wallet recovery, retention and network
acceptance remain separate gates. A successful isolated proof does not
activate a public network.


## Native engineering integration boundary

The separate [engineering runtime](v1-native-runtime.md) integrates
native transaction and fixed-576 settlement verification with strict ascending
BLAKE3 statement-ID ordering, all-input reuse checks, the canonical snapshot
window and an atomic append/replay transition. It creates independent disposable
engineering directories and imports no retained chain, key or wallet data.
The runtime must use the revised source-bound keys; retained earlier service
observations do not qualify the new economic relation.

Continuous production uses a new independent ASERT engineering directory with
configuration revision 5 with economic-rule version 3 bound in canonical rules,
fresh network identity and genesis, immutable
initially calibrated work rules and a 300-second target interval. Producer and
validator share the integer-only timestamp, ASERT target and sequential BLAKE3
work checks. A resident prover and bounded private pre-generation queue supply
64-position blocks. Existing engineering directories and the retained
seven-node network are not migrated or changed. Public genesis activation and
epoch recalibration remain separate decisions.

Before the first development-network deployment stage, require one genuine
24-hour single-node observation on the frozen binary and configuration, without
abnormal exit, OOM, proof failure, state inconsistency or stalled actual work.
The observer independently measures monotonic time, checks process ownership
and reads private exports without opening the live database. A stochastic long
block interval below two hours is permitted with fresh PoW progress. Once
ready, two hours without accepted-height progress makes the observation
incomplete independently of hashing progress. This operational threshold is not
a consensus validity rule or a deterministic block-interval guarantee. Any restart or evidence
gap invalidates continuity; prior elapsed wall time cannot complete a new
window. Completion also requires graceful shutdown and an independent offline
full replay/reward-recovery check matching the final accepted state. This
document records the requirement, not a completed observation or deployment.
The 72-hour maximum-load and seven-day independent-host acceptance requirements
remain additional gates.

The native node library composes the same store/transition with a bounded
verified mempool, padding preparation, real-transaction candidate assembly and
private fee settlement. Admission checks the canonical snapshot, both pending
nullifiers, all outputs, matching sidecar and independent frozen proof before
insertion. The verified-pool policy is 512 MiB/2,048 entries, 16 MiB/64 entries
per opaque peer and at most 4,096 peer identities. These logical limits do not
supply isolated workers, ingress queues or a process-memory guarantee.

Miner ingress does not require operator registration or a miner allowlist.
An inbound miner presents its signed, network-bound descriptor before the
unchanged hybrid TLS handshake. Descriptor possession signatures do not grant a
session: TLS certificate verification, Ed25519 and ML-DSA transcript signatures,
exporter binding and the native Miner Hello must all succeed. The service keeps
only bounded temporary scheduling state and releases it after socket closure.
Outbound bootstrap destinations remain independently pinned. A presented miner
identity grants no checkpoint-signing or local control authority. Legacy pinned
peer routing remains supported; public miner routing requires a service upgrade.

The authenticated-stream interface binds network, genesis and frozen verifier
manifest, with bounded framing and declared peer roles, full-proof batches and exact-proof
compact recovery. Sync attempts pin peer/base/ancestor/continuation and retain
budget reservations until adoption or discard. The opt-in engineering driver
uses X25519 + ML-KEM, Ed25519 + ML-DSA and authenticated record protection.
Independent transport review and Dandelion++ remain requirements before
main-network activation.

Block encoding v4 and compact encoding v3 include bounded signed issuance
records and the fixed three-note native proof. The trusted transport identity
also binds the issuance verifier profile. Compact recovery requests missing
statement/proof pairs in batches of at most sixteen, checks their exact
identities and imports only the reconstructed complete block. Each exchange
has a shared 180-second monotonic deadline; at most three attempts use fresh
authenticated sessions. Invalid protocol data is not a retry condition.
These library interfaces do not enable a production listener.

The existing 43-Mbps capacity model includes one issuance per block. If the
explicit engineering configuration permits four maximum issuance records,
the integrated compact-envelope model requires 44 Mbps to retain 15% link
headroom. Keep the 100-Mbps deployment recommendation and pin the actual
issuance limit before activation; the codec bound of four is not an adopted
network policy. See the [network budget](v1-network-budget.md#integrated-issuance-envelope).

Fork choice compares cumulative verified work only; equal work retains the
current chain. Candidate blocks replay through the common transition and may
detach at most 24 blocks. Replacement canonical rows, accepted head/fingerprint
and checksummed detached evidence commit atomically. The default policy permits
32 candidate blocks, a 640-MiB logical candidate budget and 1 GiB of retained
detached evidence. Transport has its own shared 640-MiB logical budget; the two
budgets do not establish a combined process-memory bound. Non-tip ancestor reconstruction starts from the authenticated local replay
base when proof expiry is configured, otherwise from genesis. Its 4,096-block
replay-work guard is resource policy, not invalidity or a consensus horizon.
Tip extension does not need that replay. The engineering implementation adds
release-pinned 2-of-2 coordination and quarantined permanent-data reconstruction
with a fully verified proof tail. Live checkpoint bootstrap and long-offline
recovery remain acceptance gates before explicit service expiry qualification.

Seed-wallet APIs derive independent spend, deterministic ML-KEM view and
256-bit change keys per network/account, authenticate output recovery after
complete canonical replay, reconcile orphan receipts/spends and prepare fixed
SIP or asset transfers with SIP-only standard/priority fees. Native proving
returns the transaction, matching sidecar and private payment opening.
Mnemonic backup, protected persistence, valid-chain seed-wallet funding,
pruned-public-history rescan and full M2 workflow acceptance remain incomplete.
Seed-backed mining destinations and ordered per-note encryption receipts are
required for recovery. Current proof artifacts qualify the revised relation;
they do not complete these wallet integration requirements.

The dedicated native runtime CI job compiles the integration and runs
synthetic-verifier state/transport tests and native-proof tests. Tests with
synthetic funding do not establish end-to-end valid-chain wallet acceptance or
production cryptographic transport. Unsupported issuance operations remain
absent until the dedicated testnet fund account, atomic fee collection and
resource bounds are configured and implemented. Role-based proof retention, checkpoint bootstrap, configured fund operation, protected wallet durability,
transport privacy and sustained network acceptance remain separate gates.
No library test changes the frozen single-node observation or the retained
seven-node network.
