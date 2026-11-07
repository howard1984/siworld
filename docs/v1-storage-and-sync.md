# V1 Storage, Retention and Bootstrap

Status: selected retention policy and conditional component model for the
[V1 economic revision](v1-economics.md). The tables use the explicit
`--economic-rewards` planning mode: five reward notes and eight native signed
fund claims are covered by a provisional 64-KiB permanent block-record
allowance. A separate 64-KiB one-time genesis-registry allowance covers up to
32 immutable fund wallets. The `native-v1-economics-1` proof profiles have fresh reference-host
evidence; the record allowances are not measured database overhead. Final issuance limits, persistent records and long-run
whole-node resource qualification remain incomplete. Transaction, settlement
and issuance proof limits are independent.

## Retention classes

Every node permanently retains the following public data without pruning:

- block headers, proof of work and cumulative-work metadata;
- output commitments and commitment-tree state;
- ciphertexts and view tags;
- the nullifier set;
- fee commitments;
- per-block settlement declarations without settlement proofs;
- miner reward notes;
- development-fund expenditure records and ML-DSA signatures;
- public asset issuance records, declared supplies and metadata; and
- recent-root tree snapshots and canonical block identities.

Only transaction, settlement and native issuance proof bodies expire. Signed
issuance declarations and initial note commitments remain permanent. Local
storage roles select retention without changing block validity or fork choice:

| Local role | Proof retention | Historical proof synchronization |
| --- | --- | --- |
| Bootstrap | At least 86,400 elapsed seconds after observed finality | Available within the retained window |
| Validator | At least 86,400 elapsed seconds after observed finality | Available within the retained window |
| Miner | Latest 96 canonical blocks | Disabled |
| Ordinary | Latest 96 canonical blocks | Disabled |

The consensus reorganization bound remains 24 blocks. The 96-block local
window does not increase that bound. Private fee-opening sidecars retain their
existing bounded admission lifecycle and are not added to permanent storage.

Persist finality and deletion metadata. Extend retention on clock or recovery
uncertainty; age alone cannot remove an unfinalized block's proof. Service
expiry uses the first local observation of finality for the exact block ID,
never the producer's timestamp. Restart downtime does not advance the certain
retention clock. At a five-minute target and depth-24 finality, 312 blocks is a
nominal service-store sizing example, not permission to expire by height.

The native store can atomically replace expired canonical and detached proof
records with authenticated compact public records and a sealed local replay
base. Reopening authenticates the compact prefix and local seal, then verifies
all retained proof-bearing blocks through the unchanged transition. Local
reward receipts remain independently checked. This local base records prior
verification by the same node; it does not satisfy the remote checkpoint quorum
or authorize trust in another node's history.

Maintenance batches are bounded. Database free pages are reusable immediately;
file size can remain at its high-water mark until exclusive offline redb
compaction. See [native storage operation](native-proof-storage.md). The engineering
implementation includes two-authority publication and quarantined checkpoint
reconstruction over the pinned-peer transport. Its live delivery, fresh-node
installation and long-offline recovery remain acceptance gates. Service proof
expiry requires explicit local qualification after those gates; an authenticated
checkpoint and its complete proof tail must be available to recovering nodes.

Unconfirmed transactions use bounded mempool TTL/expiry and byte admission;
they do not create an unbounded disk spill. Orphaned data follows the
reorganization/recovery policy, rather than being mistaken for finalized data.
No V1 archive-node role or long-term proof-body backup is selected. The existing
seven-node network and retained private engineering evidence remain unchanged.

## Bootstrap and wallet recovery

Default new-node synchronization uses the confirmed checkpoint distributed
with the release, authenticated by the genesis-pinned checkpoint quorum and
bound to network identity, height, block ID, cumulative PoW, state roots,
recent-root snapshots, public-data manifest and trusted verifier artifacts.
The node verifies PoW and normal transaction/state validity after that starting
point. Follow [the checkpoint trust design](v1-network-design.md); a matching
peer root or PoW does not prove deleted historical transactions.

A release bundles a confirmed checkpoint and pins the authentication policy.
If that bundled checkpoint is too old to validate its complete proof tail,
fetch a newer confirmed checkpoint authenticated under the same pinned roster
and network/verifier policy. Six-hour checkpoint publication is independent of binary release cadence and
must keep the latest usable checkpoint within the service proof window. Refuse bootstrap if no authenticated
checkpoint with an available proof tail can be obtained; old release data plus
PoW alone cannot bridge deleted proofs.

Pre-checkpoint state is an explicit trust assumption in the release/checkpoint
process. Full genesis-to-tip verification of deleted historical proofs is a
future optional proof-archive or V2 compression upgrade, not a V1 capability.
Wrong-network, stale, conflicting, incomplete or unauthenticated checkpoints
fail closed. Never restore an older state over accepted history automatically.

Wallet creation requires mnemonic backup confirmation and a successful local
recovery check before readiness. Restore derives spending/view/change keys
from the backed-up material and scans permanent ciphertexts from genesis, or an
authenticated wallet birth height, including segments older than the node's
bootstrap checkpoint. Authenticate those segments against the permanent-data
manifest, check AEAD and note commitments, recover SIP and asset IDs/amounts,
and reconcile spends against permanent nullifiers. A state checkpoint does not
allow skipping old ciphertexts when recovering an old unspent note. Test
offline recovery across proof deletion, checkpoints, reorganization and backup
restoration; no finite offline duration may silently omit a receipt.

## Encoding and component model

The isolated multi-asset codec implements one recipient ML-KEM output and
two symmetric sender-change outputs. Each 208-byte encrypted plaintext contains
144 meaningful bytes, including the 32-byte asset ID and committed unlock
height, and 64 padding bytes.
The encoded public transaction body is exactly 2,027 bytes. Adding the 48-byte
fee commitment and 40-byte canonical snapshot selector gives a
2,115-byte permanent-position planning ledger. Native body/envelope and block
codecs implement these wire encodings; final persistent record layout and
measured database overhead remain integration work.

Use decimal GB, 365-day years, 288 target blocks/day and 576 positions/block.
Use the engineering-frozen **655,360-byte (640-KiB) transaction proof cap** independently
of the 655,360-byte settlement and 524,288-byte issuance caps, plus 78-byte sidecars. The nominal rolling window
is 312 blocks; it does not accumulate again each year. A larger proof cap adds
rolling storage while the permanent 2,115-byte position ledger is unchanged.

At that planning transaction cap, the nominal full-load rolling store is:

| Rolling component (312 blocks) | Bytes |
| --- | ---: |
| Transaction proofs | 117,776,056,320 |
| Settlement proofs | 204,472,320 |
| Sidecars | 14,017,536 |
| Ordinary transaction, settlement and sidecar subtotal | 117,994,546,176 |
| Additional issuance proof allowance | 163,577,856 |
| Total rolling allowance | 118,158,124,032 |

The finite issuance scenario reserves one additional capped native issuance
proof/block beyond ordinary positions. The total rolling allowance is
**118.158 GB**. This overcounts if issuance occupies an ordinary transaction
position. The retained cap sizes rolling storage; new lock fields fit the
fixed note/body padding, so permanent per-position bytes are unchanged.
The source-bound measurements fit their recorded admission caps; their frozen
settlement profile retains its historical 524,288-byte value. The current
655,360-byte settlement decoder cap is an independent policy and sizes the
rolling budget here. Neither the samples nor that policy establish a maximum
randomized proof length, maximum-fee/claim qualification or a measured
persistent-record bound.

Permanent position records add 128.061 GB/year at maximum load. To include
the other categories explicitly, the revised planning scenario uses:

| Category | Finite planning allowance | Qualification requirement |
| --- | ---: | --- |
| Permanent block records | 64 KiB/block | Cover up to five reward notes and eight 6,783-byte signed fund claims; extract headers/PoW, settlement declaration, public economic records, snapshot metadata and container overhead from final persistent encoding |
| Immutable fund genesis registry | 64 KiB once | Cover the 62,530-byte section holding a count, development-team index and 32 fixed share/public-key slots; not repeated in each block |
| Permanent issuance records | 16 KiB/block | Bound metadata, issuer key/signature, initial commitments and record count; this is an average budget ceiling to adopt, not an enacted consensus rule |
| Issuance proof bodies | One additional 512-KiB proof/block in the rolling window | Freeze actual native issuance proof size and byte/work admission limits |
| Indexes and accepted state | 25% of all permanent position, block, issuance and genesis-registry bytes | Measure real commitment/nullifier/asset trees, redb pages, allocator/file and index overhead |
| Database working space | 16 GB above steady records/state | Measure WAL, crash recovery and worst atomic-write/compaction peaks; use in-place/segmented compaction or increase this allowance if a full copy is required |
| System and service recovery | 20 GB | Measure OS, package, bounded logs and service artifacts; independent backups are additional |
| Device free reserve | 20% | Preserve free space after all modeled used bytes |

The immutable genesis registry accepts 1–32 fund wallets with positive
basis-point shares totaling 10,000 and ML-DSA-65 public keys. A designated
development-team wallet receives fund-allocation residue. All wallet credits
accumulate in independent ledgers; blocks do not issue one output per wallet.
The eight-claim block cap limits actual signed withdrawals independently of
registry size. Exact shares and keys remain launch inputs, and production
fails closed without them. V1 provides no key/share replacement mechanism.

The block/issuance allowances are sizing assumptions requiring final byte
ceilings and tests. ML-DSA-65's 1,952-byte public key and 3,309-byte signature
fit the issuance allowance only with bounded metadata and initial outputs.
Permissionless issuance without per-record/per-block byte and CPU limits has
no finite worst-case storage or network bound. The full record/state layout
and database working peak have not yet been measured; do not label the
allowances as actual database overhead or finalized consensus limits.

| Maximum load | Permanent positions | Block allowance | Issuance allowance | Index/state allowance | Used capacity | Device with 20% free |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Year 1 | 128.061 GB | 6.889 GB | 1.722 GB | 34.168 GB | 324.999 GB | 406.249 GB |
| Year 3 | 384.184 GB | 20.667 GB | 5.167 GB | 102.505 GB | 666.681 GB | 833.352 GB |
| Year 5 | 640.307 GB | 34.446 GB | 8.611 GB | 170.841 GB | 1,008.363 GB | 1,260.454 GB |

Used capacity includes the one-time 64-KiB genesis registry, rolling allowance, 16-GB database working space
and 20-GB system allowance. Required device capacity divides used bytes by
0.8 to preserve the free-space reserve; it is not additional retained data.

At lower synthetic demand, retain the 300-second target and minimum
64-position blocks; do not omit empty blocks. At 10,000/day this still stores
18,432 encoded positions/day. The finite scenario keeps the same per-block
issuance/block allowances even at low demand:

| Workload | Rolling store | Used year 1 | Used year 3 | Used year 5 |
| --- | ---: | ---: | ---: | ---: |
| Maximum 576 positions/block | 118.158 GB | 324.999 GB | 666.681 GB | 1,008.363 GB |
| 10,000/day, minimum 64-position blocks | 13.456 GB | 78.007 GB | 135.108 GB | 192.209 GB |
| 50,000/day, adaptive grouping | 35.877 GB | 130.890 GB | 248.915 GB | 366.941 GB |
| 50,000/day, uniform 176 positions | 36.359 GB | 132.036 GB | 251.389 GB | 370.743 GB |

| Workload | Device year 1 | Device year 3 | Device year 5 |
| --- | ---: | ---: | ---: |
| Maximum 576 positions/block | 406.249 GB | 833.352 GB | 1,260.454 GB |
| 10,000/day, minimum 64-position blocks | 97.508 GB | 168.885 GB | 240.261 GB |
| 50,000/day, adaptive grouping | 163.612 GB | 311.144 GB | 458.676 GB |
| 50,000/day, uniform 176 positions | 165.045 GB | 314.237 GB | 463.428 GB |

Reproduce these tables with
`python3 scripts/v1-storage-budget.py --economic-rewards`, using
`--transaction-proof-cap-bytes` to specify a different transaction body limit.
Settlement and issuance limits have separate arguments; do not raise them
implicitly when changing the transaction limit. The unflagged command uses
the 8-KiB block-record layout with current independent cap defaults, so it does
not reproduce earlier numeric evidence unchanged. `--legacy-baseline`
restores all three 524,288-byte caps while keeping the current 24-hour service window. These historical layouts do
not size the economic reward format; `--legacy-baseline` cannot be combined with
`--economic-rewards`. Rolling positions round up to complete groups of sixteen. Low-demand cases assume steady traffic and
the stated packing; arbitrary bursts or faster block production can need the
full rolling reserve. A dedicated `extra_permanent_bytes` term permits adding
measured costs beyond these allowances without hiding them.

Bootstrap and validator stores use a 200-GB managed-file-content alarm
threshold. Crossing it does not stop validation or ingestion and never changes
proof retention or permanent-data lifetime. It is not a disk quota. A finite
physical device still needs free-space monitoring and capacity planning.
Miner and ordinary stores retain 96 blocks by default, configurable down to
24 blocks, and do not expose historical proof service.

These are conditional planning horizons, not promises independent of actual
record sizes, workload or database layout. Replace allowances with measured
evidence before deployment qualification. Monitor growth and maintain healthy
redundant services. Never reclaim permanent public data or unexpired proofs to
avoid an orderly local storage stop.

## Backup and monitoring

Project-operated object storage backs up permanent public data only; it is not
an archive for expired proofs or sidecars. Upload finalized segments at least
every six hours with immutable object hashes/versioning, publish signed six-hourly
manifests and create weekly full checkpoint snapshots. The backup RPO is at
most six hours; acknowledged local durable records still require RPO zero.

Restore into a fresh isolated directory: verify manifest signatures, hashes,
network and checkpoint identity; fetch all ordered public segments; rebuild
indexes/state and audit emission; compare roots and cumulative work; validate
the post-checkpoint proof tail; run wallet rescanning before promotion.
Never overwrite a newer accepted database. Run monthly isolated restore tests
and quarterly replacement-host tests, recording missing objects, recovery
duration and public-root reconciliation. Credentials and wallet secrets are
not public backup inputs.

Monitor total encoded bytes/positions, proof-age/deletion lag, separate permanent
data/index/state growth, free-space reserve, backup lag and recovery failures.
Never emit real/padding counts, hidden fees, peer addresses or timed nullifiers.
One real 24-hour-after-finality lifecycle is required by
[V1 acceptance](prover-acceptance.md), alongside accelerated crash/clock tests.

## Supply audit implementation requirement

The native integer-only height-by-height SIP auditor uses the shared subsidy
schedule and [monetary transition](v1-economics.md). It replays nominal 87/10/3
allocations and explicit immutable per-wallet basis-point shares, mode-specific rewards,
Holder pool deposits/claims,
cumulative burn, locked subsidy schedules, per-credit fund maturity/vesting,
valid ML-DSA expenditures and counters, and cumulative SIP emission against
the curve. Check supply conservation at every height. Public lock/circulation
figures are scheduled subsidy measures, not private unspent holdings. Transfers and fee recycling are not new issuance.
For each fund wallet, expose its public key, share, cumulative unlocked amount,
cumulative spent amount and available balance. Apply the claim cap per block
without sharing a spending allowance across wallets.
The native audit includes signed fund spending and canonical asset issuance.
The shared transition verifies signed declarations, the native issuance-to-note
supply relation, dedicated declaration-bound fee receipts and one-time registry
insertion. The public summary records declared supplies, issuance heights and
declaration bindings; it does not infer private holdings or reveal ordinary
transaction fee openings.

Authenticate audit inputs through the permanent record/checkpoint manifest.
Report the first bad height and reproducible cumulative totals. Tests must
reject altered subsidy, fund credits, payout signatures/counters, duplicate
issuance and over-minting, and reconcile reorganization rollback. The native
replay audit does not close authenticated checkpoint-input, proof-pruning or
deployed recovery gates. A size table or unauthenticated
JSON sum does not constitute a supply audit.

## Backup checkpoint freshness

A weekly full snapshot alone is insufficient once service proofs expire after
24 hours. Export an authenticated, consistent confirmed-state checkpoint
(full or a complete authenticated delta chain) at least every six hours,
together with the public-data manifest. Weekly full snapshots remain a
compaction/recovery convenience. Before replaying a restored checkpoint's
proof tail, confirm every required proof is still available. If not, obtain a
newer quorum-authenticated checkpoint under the explicit trust policy, or
stop recovery; public records and PoW cannot replace deleted proof validity.
The checkpoint binds the asset registry, fund state, permanent-data manifests
and complete accepted root window. Never synthesize missing state or silently
trust an unauthenticated peer.
