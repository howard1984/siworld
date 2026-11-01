# Native V1 Node and Network Integration

Integrate [the monetary rules](v1-economics.md) through the same block
transition for production, validation, replay, forks and audit. Bind the
explicit reward mode at template creation; reconstruct every reward note,
Holder pool/burn/fund update and trusted snapshot-height lock check. Reorg
rollback must restore all economic counters and schedules atomically.
[Wallet protection](v1-wallet-protection.md) and [V2 authorization](v2/multisignature.md)
are separate work; threshold seed backup does not add V1 on-chain multisignature.

Status: implementation inventory and remaining activation plan for the
independent native-proof engineering network. The native library contains
bounded admission, authenticated-stream protocol interfaces, full-proof sync,
verified-work fork choice, atomic reorganization, seed-derived wallet
primitives and a public subsidy audit. A production hybrid provider and
listening network service are not implemented. Remote CI covers compilation,
protocol rejection and separately selected native-proof integration tests; no
network acceptance is implied. The `native-v1-economics-1` profiles have
fresh actual-AIR and 39-trial reference-host evidence; public-key reproduction
and complete CI remain release checks. The retained seven-node
legacy network remains unchanged.

## Proof parameters and activation

Proof-parameter freeze records the implemented relation, dependency revisions,
trusted verifier, canonical codecs, security reports and successful resource
measurements. It is distinct from independent cryptographic review and from
node, wallet or network activation. Durable wallet receipt integration and the
remaining node work below do not, by themselves, prevent that freeze. They
remain prerequisites for accepting user transactions on the new network.

The [multi-asset transaction engineering profile](../crates/bench-multi-asset/artifacts/v1-transaction-profile.json)
selects KoalaBear D8, standard Poseidon2 W24, twelve-element digests, log
blowup 7, 41 queries, query/batch grinding 20 and commitment grinding zero.
Folding is binary and final polynomial log length is zero. It binds matching
source, actual-AIR security, canonical public preprocessing and the qualified
EPYC evidence: 24 grid trials plus 15 selected/related-relation trials. All
three selected four-worker generation times meet two seconds; their median
is 1.462877730 seconds and maximum is 1.531155438 seconds. The largest
selected proof across one- and four-worker trials is 588,832 bytes.
Independent review, new decoder/envelope qualification, standalone verifier
limits and node activation remain separate gates. The unchanged
[old bundle](../crates/bench-d8/artifacts/v1-native-freeze.json) describes the
two-output baseline only.

No V1 node path may use a verification key, suite or proof parameters supplied
by a peer. Resource exhaustion, a local timeout and an unavailable peer are
not cryptographic invalidity and must not become consensus rejection rules.

## Canonical transaction ledger

The native three-output relay envelope implements a 2,184-byte prefix and one
bounded proof body. All integer framing is little-endian and encodings are
canonical. Earlier diagnostic codecs remain baseline evidence only.

| Field | Bytes |
| --- | ---: |
| Magic and format version | 6 |
| Fixed suite descriptor | 27 |
| Network identity | 32 |
| Snapshot height and block identity | 40 |
| Public transaction body | 2,027 |
| Confidential fee commitment | 48 |
| Proof-body length | 4 |
| **Fixed envelope prefix** | **2,184** |
| Transaction proof-body maximum | 655,360 |
| **Maximum envelope** | **657,544** |

The separate fee sidecar is 78 bytes: four-byte magic, two-byte version,
32-byte transaction identity, eight-byte fee and eight canonical field-element
blinding limbs occupying 32 bytes. These limbs provide approximately 247.91
bits of entropy when sampled uniformly, or approximately 123.95 bits under a
generic quantum search accounting; a 32-byte encoding is not a claim of 256
bits of entropy. It carries no signature, encryption wrapper,
dummy flag or fee-tier flag. The receiver checks the transaction identity and
fee opening against the commitment; the transaction proof establishes fee
validity under its private anchor's schedule. The current block fee schedule
cannot classify an older anchored fee. These
private values must never enter public logs or chain data.

The transaction identity is a domain-separated BLAKE3 digest of the canonical
statement: network, suite, snapshot identity, public body and fee commitment.
It excludes the proof length, proof randomness and sidecar. A new proof for the
same statement therefore preserves the identity. The native block codec must
order these identities strictly ascending and reject equal IDs. This is an
M1 (N1) requirement, implemented with swapped-order and duplicate-ID rejection
tests in the [engineering runtime](v1-native-runtime.md). Library admission
uses the same identity. Public-network activation remains a separate gate.
A verification cache also keys on the proof digest and locally trusted verifier identity; statement
identity alone cannot authenticate a replacement proof.

The maximum envelope plus sidecar is **657,622 bytes** before stream framing.
The permanent record is **2,115 bytes**: 2,027 public bytes, 48 fee-commitment
bytes and a 40-byte snapshot selector. Both formats are implemented in the
native codec and used by library admission; network resource qualification
remains pending.
Version, suite and
network context may be amortized in the authenticated block header. A full
32-byte compact reference is additional transmission data when sent, rather
than an additional independent permanent transaction field. The transaction
identity is reconstructible from the authenticated canonical record.

## Admission and local resource policy

The policy below separates implemented in-process bounds from operational
guards still required before activation. It does not measure the retained node
or change its existing 64-MiB mempool ceiling. Logical bounds apply to owned
bytes, including sidecars and internal bookkeeping, and are not allocator/RSS
guarantees. Entry counts supplement byte limits. Reserve before reading or
copying a declared body and release reservations on every failure.

| Resource | Initial local policy | Implementation status |
| --- | --- | --- |
| Verified transaction pool | 512 MiB and at most 2,048 entries | Native admission library |
| Per-peer verified contribution | 16 MiB and at most 64 entries; at most 4,096 opaque peer identities | Native admission library |
| Unverified ingress queue | 64 MiB and at most 128 entries | Required worker-service integration |
| Per-peer unverified ingress | 2 MiB and at most four entries | Required worker-service integration |
| Concurrent transaction verification | Two isolated workers, one proof per worker | Required worker-service integration |
| Verifier worker sandbox | 128 MiB charged memory, zero swap, 250-ms CPU allowance per job | Selected guard; not provided by the in-process pool |
| Local deadlines | Ten seconds to receive a reserved transaction body; five seconds of queue residence; two-second verification wall deadline | Worker-service qualification remains required |
| Negative-result cache | 1 MiB, at most 8,192 entries, 300-second local expiry | Not implemented |
| Peer-abuse state | 1 MiB, at most 4,096 opaque peer identities, 600-second local expiry | Expiring abuse cache not implemented |
| Shared transport buffers | 640 MiB; 16 concurrent handshakes with 4 MiB aggregate handshake allowance | Native protocol library; logical accounting only |
| Branch candidate validation | 32 blocks and 640 MiB logical state/body budget; 1 GiB retained detached evidence | Native chain/store library |
| Missing-data block reconstruction | 640 MiB and at most two candidate blocks | Selected deployment policy; durable bounded spooling remains required |
| Padding proof pool | Target at least 64 usable entries; maximum 128 entries and 65 MiB | Native pool and continuous single-node service |

The worker memory and CPU values are selected initial operational guards.
Isolated verifier measurements, malformed-input tests and target-host load
tests validate their applicability before activation. Combined setup/prove/
verify cgroup peaks do not establish the verifier's own memory requirement.
A worker killed by its limit produces a retryable local resource result, not
an invalid-proof verdict. Candidate-block validation must reschedule or report
unavailability rather than reject a cryptographically valid block because a
local deadline expired.

At maximum wire size, the 512-MiB transaction budget holds at most 816
transactions before bookkeeping; the 64-MiB queue holds at most 102 and the
2-MiB per-peer ingress cap at most three. Entry limits remain secondary to
owned bytes. The 64-entry padding readiness target needs 42,087,808 wire bytes.
The 65-MiB padding byte cap permits at most 103 maximum-size entries before
metadata, even though the entry-count ceiling is 128. Do not grow the byte
budget automatically to reach that ceiling.

Two fully buffered maximum-size block payloads exceed the 640-MiB
reconstruction budget. The protocol currently streams one framed block into
bounded owned structures and keeps its reservation while staged. Deployment
still requires bounded durable spooling and backpressure before supporting
two full candidates concurrently. Reserve metadata and temporary copies within
the same budget. Pool shortages delay production or admission; they do not
allow oversized allocations or invalid padding.

The admission library implements snapshot, sidecar, proof and pending-conflict
checks below, including preflight before proof copying. Its synchronous verifier
adapter has no worker sandbox or resource timeout. A separately isolated worker
must implement the explicit unavailable/invalid result interface; local limits
must never be inferred as cryptographic rejection.

Required admission order is:

1. Validate the outer fixed header, declared lengths, network and fixed local
   suite before allocating the full body. Reserve both global and peer bytes.
2. Resolve the selected canonical snapshot from trusted state. Reject expired,
   orphaned or unknown selectors before proof decoding.
3. Decode canonical public data, the bounded proof and fixed sidecar. Check
   the sidecar identity and fee opening against the public commitment before
   scheduling proof work. A matching opening is not proof validity.
4. Verify the proof using the locally prepared shape, trusted root and frozen
   verifier. Bound concurrency separately from the number of queued jobs.
5. Recheck current snapshot membership, confirmed nullifier conflicts and both
   pending nullifier reservations. Atomically insert the verified object and
   both reservations, or release every reservation without changing state.

Use a separate small bounded duplicate cache for in-flight statement/proof
pairs. An entry becomes a negative cryptographic result only after a complete
verification failure. Do not penalize a peer for local resource exhaustion or
ordinary missing data. Cache keys include network, verifier and snapshot
context; expiry or a reorganization invalidates affected positive and negative
entries. Peer diagnostics use bounded opaque identities and error classes,
without addresses, private openings, individual fees or timed nullifiers.

Proof parsing first walks the pinned schema without allocation, then performs
dependency decoding. Its 4-MiB declared-vector budget bounds declared vector
payloads and headers, not total allocations or RSS. Decoder scratch, canonical
re-encoding, allocator overhead and cryptographic verification remain inside
the worker resource guard. Fuzzing must measure those costs rather than infer
them from the wire maximum.

## Block production and validation

The block codec permits groups of 16, with 64 through 576 positions. A
consensus-visible position always contains the same transaction shape.
Producer and validator use the same integer-only atomic transition for the
ordered transaction statements, nullifiers, outputs and settlement. Native
issuance admission is still disabled pending its dedicated fund destination,
atomic fee collection and resource rules; the isolated issuance relation does
not activate this path.
The settlement proof is verified independently of all transaction proofs.
Its statement must bind every position exactly once and every one/five
mode-dependent SIP reward output; compact references cannot substitute for
this binding.
For a block below 576 positions, the fixed settlement AIR's remaining rows
use canonical zero-fee commitments derived from network, height, declared
block-position count and row index. The verifier reconstructs this tail; it does not add
transactions to the block. The public reward values are complete note commitments, with
the amount and fee total private. Each transaction proof authorizes its own
private anchored fee schedule; settlement opens and sums those fees without
imposing a single current block schedule on all positions.

Miners prepare ordinary valid zero-input padding proofs without owning notes.
Maintain the 64-entry target and 128-entry cap above, replenishing under the
same fixed proof parameters and resource controls. Every padding transaction
uses actual ephemeral-recipient encryption and fresh unique nullifiers. Its
proof, ciphertext and fee-commitment encoding is identical to an ordinary
transaction's encoding. Pool entries are private operational state; do not
publish counts or public classification labels.

Snapshot expiry or orphaning evicts affected padding and pending entries and
releases both nullifier reservations atomically. A same-root replacement with
a different block identity still requires a new proof. Inclusion removes the
entry from the usable pool; failed candidates may return it only after all
current snapshot and nullifier checks pass. A shortage of usable padding
delays production or triggers bounded regeneration; it does not permit an
undersized block or invalid placeholder.

At the 300-second target, finality is depth 24 and `MAX_REORG_DEPTH=24` for the
new route. The chain library reconstructs the local ancestor, replays every
candidate block, then selects strictly greater verified cumulative work. Equal
work retains the current chain. A shorter branch can win by doing more verified
work; a taller advertised chain cannot bypass validation. Adoption updates
canonical records, head, fingerprint and checksummed detached evidence in one
redb transaction before changing accepted memory. Detached records are evidence,
not chain authority or an implementation of time-based proof retention.

Tests cover depth 23/24/25 boundaries, late validation failure, snapshot/pool
reconciliation, detached evidence and durable reopen; the new integration suite
requires execution evidence. Ancestor reconstruction currently replays from
genesis and defaults to a height-4,096 work guard. A non-tip ancestor beyond
that guard returns local resource unavailability; it is not a checkpoint or a
consensus horizon. Tip extension does not need that reconstruction. A qualified
checkpoint/replay mechanism remains necessary for long-lived deployment.
Deeper-than-24 divergence requires explicit recovery. The retained route's
existing policy is unchanged.

## Compact relay and capacity

Initially use full 32-byte statement identifiers in inventories. Short IDs
require a separately reviewed collision-recovery scheme. Authenticate the
complete ordered list, retrieve missing public records and proofs under the
same byte/admission limits, and verify all data before applying a block.
The implemented compact reference
binds both statement ID and proof digest, preventing an unverified replacement
proof from reusing an accepted statement. Library recovery omits sidecars.
Request no more than 16 missing transactions per response; reserve their
declared bytes before accepting the response. Limit reconstruction to the
640-MiB/two-block budget above, including retained downloaded bodies and
bookkeeping. The production proof store and bounded disk spooling remain
required;
additional complete-body copies must not escape the shared accounting.

Missing sidecars prevent a local producer from constructing settlement. A
validator does not require a sidecar to check an already constructed block:
the public fee commitments and settlement proof establish its validity.
Sidecar recovery is a private relay operation over the hybrid connection;
it must not publish fee openings to an explorer or public block endpoint.

The capped multi-asset transaction plus sidecar is 657,622 bytes. At 576
positions and three copies, transaction and settlement payload is 30.345178
Mbps. The [complete conditional wire budget](v1-network-budget.md) includes
inventory/requests, AEAD/multiplexing, IPv6/TCP/link framing, reciprocal ACKs,
handshakes, keepalive, bounded issuance, retransmission and recovery costs:
36.51651984 Mbps with all five reward records and eight signed fund-claim
slots. At 43 Mbps the remaining fraction is 15.077861%. Reserve at least 15%
of link capacity after those costs;
`ceil(wire_mbps / 0.85)` gives a 43-Mbps minimum. Recommend 100 Mbps.
Measure the deployed listener before acceptance.

Set the new transaction profile's `MAX_LEAF_PROOF_LEN` to 655,360 bytes,
independently of the 655,360-byte settlement and 524,288-byte issuance caps. Preserve
576 positions and the 80-bit quantum screen. The old 512-KiB prepared decoder
is baseline-only. The native library uses the
new trusted shape/key/limit with envelope and admission rejection tests; its
worker isolation and adversarial resource qualification remain separate gates.
Future layout optimization does not block this engineering
freeze and cannot reduce bandwidth requirements without new measurements.

## Full-proof synchronization and retention

The engineering sync library exchanges genesis-anchored locators of at most
64 entries and contiguous batches of at most 16 proof-carrying blocks. A sync
attempt binds the peer, local base, ancestor, request identifiers and expected
continuation. Metadata/range changes, wrong genesis or concurrent canonical
changes abort the attempt without a partial adoption. Reservations stay owned
until adoption or discard. Every candidate uses verified work and the same
store transition; each successful adoption establishes a fresh base for the
next batch. This full-proof engineering path does not authenticate checkpoints
or provide pruned-history bootstrap.

The retention and checkpoint behavior below remains required design work; no
three-day deletion or trusted-checkpoint importer is implemented by the chain
library.

Keep transaction, settlement and native issuance proofs and received private
fee sidecars until three elapsed days after final confirmation, then delete
them from the online proof store. The nominal depth-24 finality delay is two hours, so a
target-rate node retains 888 blocks in steady state: 24 unresolved blocks plus
864 finalized blocks. Persist finality and retention metadata and extend the
window when clocks, reorganization state or recovery are uncertain. Never use a
fixed block count to shorten the elapsed-time requirement.

Every node permanently retains public data without pruning: block headers and
PoW, output commitments and commitment-tree state, ciphertexts, nullifiers,
fee commitments, per-block settlement declarations without proofs, miner reward
notes, development-fund records and ML-DSA signatures, public asset issuance
records and recent-root snapshots. Proof deletion must not remove these records, accepted state,
snapshot selectors or the trusted verifier manifest. Keep proof and sidecar
stores bounded separately from memory pools and test interrupted deletion,
restart, clock adjustment and reorganization near finality.

V1 has no archive-node role and does not retain proof bodies beyond the three-day
window. A release checkpoint distributed with the node and authenticated PoW is
the default new-node synchronization path. The checkpoint binds the network and
genesis identity, block identity, cumulative work, accepted state commitments,
complete snapshot window, verifier manifest and permanent-data roots. Verify
every later block with the normal transition. Full proof replay from genesis,
using an optional proof archive or asynchronous V2 history compression, is a
future upgrade and is not a V1 launch dependency. Checkpoint bootstrap is an
explicit trust assumption; unauthenticated peer agreement, matching roots or
header work cannot prove deleted transaction proofs. Test wrong-network, stale,
conflicting, incomplete and unavailable checkpoints fail closed.

At 576 positions per 300 seconds, three-day post-finality retention including
the nominal finality delay uses 335,714,239,488 bytes for capped transaction
proofs, settlement proofs and sidecars. Reserving one additional capped native
issuance proof per block adds 465,567,744 bytes, for a conditional total of
336,179,807,232 bytes. The 2,115-byte multi-asset position adds
128,061,388,800 permanent bytes/year. Use [the storage component
model](v1-storage-and-sync.md) for year-1/3/5 and 10k/50k demand estimates.
Measure indexes, full state, amortized records, issuance, WAL/compaction and
recovery space before qualifying the 500-GB floor or 1-TB recommendation.

Project-operated object storage backs up permanent public data but is not an
archive for deleted proofs. Upload finalized block segments at least every six
hours with immutable versioning, publish a signed daily manifest, and create a
weekly full checkpoint snapshot. Restore into an isolated node by verifying
object hashes/signatures, replaying blocks and PoW, rebuilding indexes, and
comparing roots, work and state before promotion. Run monthly restore checks and
quarterly replacement-host recovery tests. Wallet creation requires an explicit
mnemonic backup; a restored wallet rescans all permanent ciphertexts from genesis or
an authenticated wallet birth height, including pre-checkpoint segments,
verifies note and asset ownership, and reconciles balances and payment journals
exactly once.

The engineering wallet library already derives network/account-separated spend,
ML-KEM view and 256-bit change keys from a supplied seed. It independently
replays complete supplied canonical history, authenticates ciphertexts and
note commitments, reconciles orphan receipts/spends, and prepares two-input/
three-output SIP or asset payments with SIP-only standard/priority fees. It
returns a matching private sidecar and payment opening after native proving.
Mnemonic creation/backup, protected key/opening storage, valid-chain seed-wallet
funding, network relay and pruned-public-history rescan are not yet integrated.
The issuance API and seed-wallet scan recover initial issued notes through the
shared transition; the native-proof test uses synthetic funding and does not
complete M2.

The offline `audit` command and library bind replay to the exact accepted
head. The economic audit recomputes modes, all reward notes, pool/burn,
per-credit independent fund unlock/spend state and conservation using the
shared transition. Its report includes signed fund spending and binds the
accepted height, tip and fingerprint; earlier audit output does not qualify
this expanded scope. Canonical replay also checks signed asset declarations,
native issuance proofs, dedicated fee receipts and one-time registry insertion;
its public summary includes declared supplies, issuance heights and declaration
bindings. Private holdings and reward-recovery receipts remain outside this
report's scope. Launch-time issuance configuration, authenticated checkpoint
inputs and deployed recovery remain separate gates.

## Transport privacy work

The [network design](v1-network-design.md) selects dual Ed25519/ML-DSA-65
identity authentication for ephemeral X25519 plus ML-KEM-768 and Dandelion++.
Its proposed TLS/provider profile and routing parameters require review and
freezing before deployment. Pruned bootstrap uses explicit opt-in two-of-three
checkpoint trust with genesis-pinned authority identities; the release
checkpoint-plus-PoW path is the V1 default. Full proof replay remains a future
independently verifying alternative. Neither production hybrid authentication
nor checkpoint bootstrap is implemented or independently approved by selecting
this design.

The retained networking path uses libp2p 0.57.1 with TCP, DNS, Noise, Yamux
and request-response; its live service constructs `noise::Config::new` and
floods announcements. It has no implemented hybrid handshake or Dandelion++
path and is not a native V1 transport.

The native protocol library instead exposes bounded streaming sessions over an
`Authenticated` channel capability. It binds network, genesis, trusted verifier
manifest and peer role, requires fresh authentication after framing/I/O failure,
and supplies TCP accept/connect adapters with aggregate handshake reservations.
No production `HybridAuthenticator` is supplied, its capability constructor is
crate-private, and no public listening CLI is enabled. A provider must supply
reviewed identity binding and authenticated record protection, deadlines,
sequence/nonce limits, key confirmation, cleanup and rekeying. Synthetic
providers and loopback protocol tests do not qualify the cryptographic channel.
The output encryption's ML-KEM dependency does not upgrade a connection.

The [proposed hybrid profile](v1-hybrid-handshake.md) uses a maintained TLS 1.3
implementation with exactly X25519MLKEM768, its standard TLS key schedule and
record protection, followed by exporter-bound Ed25519 and ML-DSA-65 identity
authentication. A dedicated versioned native upgrade must enforce that profile
without a second application combiner or direct traffic-key derivation from
component secrets. Review its dependency revisions, certificate policy, full
transcript binding, decapsulation failure behavior, key confirmation, replay
resistance and secret cleanup before activation. Do not fall back to classical
Noise for V1 wallet, sidecar or node traffic after hybrid negotiation fails.
Authentication requires its own quantum-security review; hybrid key exchange
alone does not upgrade a classical long-term signature.

Hybrid encryption addresses recorded-content confidentiality. It cannot hide
the network endpoints from a passive observer. The selected Dandelion++
path must separately address origin-to-transaction correlation before launch.
This requires bounded stem/fluff queues, loop/failure handling, randomized
relay selection and reconnect behavior without emitting source addresses or
transaction-time associations in diagnostics.

Use actual TCP listeners in end-to-end tests for successful negotiation,
wrong-network and unsupported-version rejection, downgrade attempts, malformed
KEM input, failed key confirmation, transcript mutation, interrupted handshake,
half-open connections, reconnect and bounded resource cleanup. Synthetic
in-memory messages alone do not cover the deployed transport.

## Implementation milestones

Current source status is distinct from the exit conditions below. N1's native
codec/transition and continuous single-node service are implemented. N2 has the
verified-pool and padding APIs, without worker isolation or ingress services.
N3 has authenticated-stream protocol interfaces, sync and exact-proof compact
recovery, without a production provider/listening service or qualified wire
measurements. Verified-work forks and atomic depth-24 reorganization are
implemented with local replay limits. N8 has seed-derived scanning/transfer
primitives without protected durability or full valid-chain M2 acceptance.
The offline audit covers SIP subsidy, pool/burn, scheduled locks,
independent fund credit/vesting/spending and canonical asset issuance. The dedicated native
runtime CI job covers compilation, rejection tests and separately selected
native-proof integration tests. The frozen pre-revision service observation is not replaced or restarted by
this library work and does not qualify `native-v1-economics-1`.

Estimates are engineering days for one engineer familiar with the codebase,
excluding independent review, infrastructure procurement and elapsed soak or
retention windows. Parallel work can shorten elapsed time; security findings
can extend it. N1–N7 sum to 33–56 days; wallet durability and private monitoring
are separate N8/N9 work, for a combined planning range of 42–71 days.

| Milestone | Work | Estimate | Exit condition |
| --- | --- | ---: | --- |
| M1 (N1) | Versioned block/public-record codec, strict proof-independent BLAKE3 statement-ID ordering and common producer/validator transition | 4–7 days | Groups, counts, swapped/duplicate ID rejection, proof/sidecar-independent identity, fee settlement, integer bounds and atomic rejection tests pass |
| N2 | Admission service, isolated verifier workers, quotas and padding proof pool | 4–7 days | Byte accounting, adversarial decode, exhaustion, expiry and reorg tests pass |
| N3 | Compact inventories, bounded missing-data recovery and block reconstruction | 3–5 days | Collision/missing-data/reconnect tests and full-capacity relay measurement pass |
| N4 | Reviewed hybrid handshake, dual identities and actual-listener failure tests | 10–17 days | Identity binding/rotation, negotiation, downgrade, key confirmation, erasure and reconnect tests pass; Tokyo1 package can be issued |
| N5 | Three-day proof retention, permanent public-data backup and explicit-trust checkpoint bootstrap | 4–7 days | Recovery/pruning tests and verified checkpoint-plus-PoW synchronization pass |
| N6 | Dandelion++ integration and source-privacy analysis | 5–8 days | Bounded stem/fluff routing, failures and leakage review pass |
| N7 | Independent engineering-network acceptance harness and execution | 3–5 days | Reproducible native acceptance and fault injection; elapsed observation windows complete separately |
| N8 | Durable wallet integration and recovery | 6–10 days | Change keys, receipts, output self-check, reproof and exactly-once backup/recovery tests pass |
| N9 | Private multi-host telemetry and live panel | 3–5 days | Authenticated read-only feeds, five-second samples, stale markers and durable incidents pass loss/restart tests |

N1/N2 may proceed after proof-parameter freeze. N3 depends on their codecs;
N4 can develop against their authenticated records. N5/N6 follow the native
AIR/scan work and can proceed in parallel with node integration. N7 requires
N1–N6, N8/N9 and independent review of the relevant security changes.
Apply the [native acceptance matrix](prover-acceptance.md), including
[host/storage qualification](v1-deployment.md), 72-hour maximum-load hardware
trials, seven-day independent-host observation, real retention lifecycle and
explicit recovery targets. No short standalone proof run closes those gates.
None of these milestones imports or migrates retained seven-node state.

## Activation sequence and host handover

Complete the authenticated transport provider and durable wallet path before
shipping a network-node service package. The retained legacy Ed25519
transport does not establish a persistent native dual identity. The native service
must persist an independently generated ML-DSA-65 identity alongside its
Ed25519 identity, bind both keys to the handshake transcript and authenticate
ephemeral X25519 plus ML-KEM-768. Identity storage, rotation and recovery must
not silently generate a replacement identity on damaged or missing state.

The wallet path must prove a complete accepted-chain cycle: backed-up seed,
configured mining recipient, mature reward recovery, SIP transfer with both
fee tiers, issued-asset transfer, restart and mnemonic-only restoration.
The [wallet custody implementation](v1-wallet-storage.md) now supplies an
encrypted seed vault and payment journal, mnemonic restoration and explicit
interactive create, restore, address and miner-configuration commands. An
opt-in genuine native-proof test implements a genesis-funded reward, payment,
database replay and receiving-wallet restoration cycle. Its source and a passing
build do not establish a completed run: retain an observed result for the exact
executed source. The complete two-fee-tier, issuance and asset-transfer flow,
local web interface and independent-host network acceptance remain pending.
Publish only public chain and operation status; wallet seeds, note openings,
individual fees and recipient classifications stay private.

Native economics already use the shared integer transition for 87/10/3
allocation, Voyager/Holder mode, pool claim-before-injection, one-SIP tail,
snapshot-height locks and independent configured fund-wallet allowances.
Fund ratios and production recipients remain explicit activation inputs.
Do not substitute a shared fund allowance or restore the superseded fixed
5%/5% split. SIP is the display and code denomination; fixed pre-existing
protocol domain strings and serialized field names retain their byte values.

A deployment handover requires the following artifacts from one qualified
commit. Until the network service exists, there is no deployable native P2P
port or listener command to supply.

| Handover item | Required evidence |
| --- | --- |
| Version | Immutable commit, package checksums, frozen relation manifest and observed required CI results |
| Binaries | Baseline CPU-admission launcher, optimized native worker and their exact names and hashes |
| Configuration | Explicit engineering network/genesis, peers, identities, reward mode, backed-up recipient and fund allocation |
| Service | Validated startup/shutdown commands, service account, durable data paths and resource limits |
| Networking | Implemented authenticated listener port, firewall policy, handshake profile and reconnect tests |
| Status | Read-only script reporting accepted height/tip, verified work, freshness and service/resource health |
| Recovery | Graceful stop/restart, wallet restoration and canonical-state/reorganization checks with preserved data |

An integration PR or isolated proof benchmark does not authorize deployment,
change an existing node or qualify the public testnet. Stage a new independent
network only after the relevant service and reward-cycle gates pass.

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
