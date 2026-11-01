# Native Transaction Proof Design

The [monetary revision](v1-economics.md) is included in the engineering-frozen
transaction, fixed-576 settlement and three-note issuance profiles. Notes bind
unlock heights; each nonzero input must be unlocked at its trusted referenced
snapshot height. Settlement binds public Voyager/Holder mode, the trusted
reward plan, one/five SIP reward notes and fee allocation. Nodes recompute that
plan and independently validate pool, burn and fund transitions. Required CI,
public-key reproduction, independent
review and complete node/network acceptance remain separate gates.

Status: selected native two-input/three-output transaction design,
with isolated codec, issuance and SIP-reward settlement implementations in
`crates/bench-multi-asset`. The [multi-asset profile](../crates/bench-multi-asset/artifacts/v1-transaction-profile.json)
and [actual measurements](v1-multi-asset-evaluation.md) bind the selected
parameters, actual-AIR security, source and public verifier key. Node/decoder
and durable-wallet integration, independent review and activation remain
separate gates.

The prior two-output [engineering freeze bundle](../crates/bench-d8/artifacts/v1-native-freeze.json)
remains an unchanged diagnostic baseline. Its key and parameter freeze do not
freeze or accept the new multi-asset relation. V1 uses Scheme B confidential
fee settlement, documented in [fee-settlement.md](fee-settlement.md).

## Scope and network boundary

V1 uses one native STARK proof per fixed-shape transaction. Wallets relay
transactions with proofs; nodes verify each proof before mempool admission.
Blocks identify transactions with compact references and retain their public
data without duplicating the proof body. Recursive aggregation and historical
proof compression are deferred to V2. Recursive merge and wrapper work is
paused while the native transaction route is evaluated.

The retained seven-node N=2 network is unchanged. The new route requires an
independent, resettable engineering network, new genesis, network identity,
directories and keys. It imports no retained notes, tickets, proofs or state.
No network launch is authorized by this specification. Historical verifier
activation is deferred until before mainnet.

The engineering block target is 300 seconds, with 64 through 576 transaction
positions in groups of 16. The conditional network model requires 43 Mbps;
100 Mbps is recommended. Revised proof and transport qualification remain
activation gates. Node integration,
block validity changes, pruning and checkpoint synchronization follow the
[node and network integration plan](v1-node-network-plan.md). Proof parameters
may be frozen before those implementations are complete; activation requires
their separate acceptance gates.

## Suite and security requirements

Use KoalaBear D8, standard Plonky3 Poseidon2 W24 and 12-base-element digests.
Canonical digest encoding is 48 bytes: twelve little-endian u32 elements, each
strictly below the KoalaBear modulus. D4/W16 proxy measurements cannot select
production parameters or resource limits.

Pin `p3-security` to `0.9.0-rc.2`. For the actual transaction AIR, require:

| Term | Screening requirement |
| --- | --- |
| Classical conjectured | At least 128 bits for the complete instance |
| Fiat–Shamir terms | At least 80 bits after halving the Johnson-bound term, including FRI queries and each enforced grinding site |
| Challenge-domain terms | At least 80 bits after halving, including OOD, DEEP, ALI and FRI folding |
| Merkle and commitment collisions | At least 80 bits under the selected BHT model |

Every parameter profile must retain at least 80 bits under the actual
relation-specific screen; passing that screen does not complete production
acceptance. See the [multi-asset evaluation](v1-multi-asset-evaluation.md) and
[BHT accounting](bht-security-accounting.md) for the separate collision model.

Record every term, the weakest term, model assumptions, actual AIR dimensions,
constraint degrees, hiding rows, quotient chunks and batched-opening geometry.
A query/grinding arithmetic score is not a complete bound. Do not count a
nonce unless the production verifier enforces it at the specified transcript
position. Estimator screening is not an independent quantum soundness theorem;
external review must assess the selected accounting and implementation.

## Native relation and integration boundary

The native D8 transaction implementation constrains private spend-key/note
fields, ownership, note commitments, input membership, nullifiers,
conservation, value ranges, output rho and unlock heights. Recent-root
membership is checked within the native relation and the fee is bound by a
private opening to its public commitment. This relation is distinct from the
older recursive accumulator leaf, which exposes fee limbs and delegates
recent-root membership to its parent. The selected canonical snapshot lifetime
still requires node integration against trusted chain state.

The native relation binds a ciphertext digest but does not constrain ML-KEM
encapsulation coins or shared secrets, the sender change secret/KDF, AEAD keys,
nonce generation, plaintext encryption or authentication-tag computation.
These private encryption fields are not proven consistent with output note
openings. Public-data mutation tests establish substitution resistance only.
Native stateful nullifier checks, bounded decoding, wallet erasure and transport
source privacy also remain separate requirements. Iterative code and test
milestones do not establish complete AIR coverage or production acceptance.

### Isolated implementation boundary

The two-output diagnostic baseline includes a prepared proof-shape decoder that validates
canonical fields, fixed vector dimensions, FRI paths and complete byte
consumption before dependency deserialization. The body limit is 524,288 bytes;
a separate 4-MiB declared-vector budget bounds requested payloads and vector
headers, not process RSS. Structural acceptance always requires subsequent
cryptographic verification against the locally reconstructed statement. The
new profile must bind the decoder to its own dimensions and verifier identity
before admission; the old prepared decoder does not qualify that integration.

The baseline canonical snapshot pool resolves trusted roots, checks proofs, reserves both
nullifiers and applies atomic expiry/reorganization eviction. Its caller still
validates canonical blocks, enforces reorganization depth and confirmed-state
conflicts, and supplies authoritative refill history. Integration into the node,
byte/CPU/in-flight quota enforcement remain node integration work. The
[integration plan](v1-node-network-plan.md) specifies the envelope ledger and
initial local budgets; those budgets are not measured verifier-memory bounds.

Native encryption helpers perform recipient and indexed-change encryption,
local decryption and commitment checks, retain a zeroizing per-payment opening,
and generate genuine ephemeral-key ciphertexts. The three-output measurement
path uses the implemented multi-asset codec with synthetic notes and temporary
keys. Durable protected receipt storage, recoverable change-key management,
receipt disclosure controls and the complete wallet broadcast path remain
integration requirements.

## Fixed transaction relation

Each V1 transaction has two inputs and three outputs, with per-asset
conservation and SIP-only fees. This relation is implemented in the isolated
crate under [the multi-asset design](v1-multi-asset.md). It constrains
both inputs independently, including ownership, nullifier derivation, value
ranges and unlock conditions. A positive-amount input must prove commitment-tree
membership; a zero-amount input uses a canonical dummy witness and skips the
membership check so a miner can construct padding without owning a note. The
zero-amount input still derives a nullifier, and nullifier uniqueness is
enforced within the transaction, across the block and against prior state. The
relation must enforce value conservation, output-seed derivation and
standard/priority fee rules. Native mempool and consensus checks also reject
conflicts across transactions and prior state; those stateful checks cannot be
replaced by the transaction AIR.

The note commitment tree has depth 40. The recent-root tree has depth 12 and
4,096 leaves. An anchor leaf commits to the commitment root, anchor height and
fee-schedule data with a fixed domain tag. Membership in this tree moves into
the transaction AIR. The anchor entry, height, fee witness and membership path
are private. The public proof statement contains the recent-root tree root,
network/suite/format identity, transaction public-data binding and any fee
settlement binding required by the final design. It does not expose the
individual anchor entry or path.

### Canonical snapshot lifetime

Accept the newest 4,096 canonical-chain snapshots, inclusive: the snapshot
4,095 blocks behind the tip is accepted; the one 4,096 blocks behind it is
rejected. At the 300-second target the window spans approximately 14.22 days.
This is a deterministic block-based rule, not a wall-clock timeout. A proof
selects a snapshot by canonical block identity; the verifier resolves the
recent-root-tree root from trusted chain state before verifying the proof.
A root supplied by a peer is not a trust source. The public-data digest binds
the selected height and 32-byte block identity with explicit domain and presence
framing. The verifier reconstructs that context from its canonical selection;
same-root replacement snapshots still require a new proof. This changes the
statement values, not the AIR columns or path depth.

The accepted snapshot window and the tree's 4,096 anchor leaves are separate
bounds. The existing depth-12 AIR path is unchanged. Since an accepted older
snapshot contains older anchors, the combined boundary can admit an anchor
8,190 blocks behind the live tip, approximately 28.44 days. Fee schedules are
committed by the anchor entry and may have corresponding staleness. Capacity,
fee-policy and wallet-expiry analysis must include this effect.

On expiry or reorganization, remove unavailable snapshot identities and evict
all pending transactions referencing them; release their nullifier reservations
and return a reproof condition to the wallet. Do not silently reinterpret an
old identity as a replacement at the same height. A shorter-chain reorganization
may require previously expired snapshots to refill the window from authoritative
canonical history; incomplete history fails closed. Validation and historical
replay use the snapshot window at the candidate block's canonical parent, not
the current live window. Reproof uses fresh proof randomness and the canonical
transaction/nullifier conflict rules.

The implemented three-output codec has a 2,027-byte body, a 48-byte fee
commitment and a 40-byte canonical snapshot selector, totaling 2,115 permanent
bytes per position. Count unamortized envelope bytes separately in
relay/admission budgets.
Tests must accept the 4,096th-newest snapshot, reject the 4,097th, reject orphaned
identities, preserve state on invalid chain replacement and evict affected
pending transactions atomically.

### Fee settlement and padding privacy: Scheme B V1 direction

The implemented recursive relation permits zero fees for all-dummy slots and
standard or priority fees for other slots; the aggregate proof binds the
miner's collected fee total. Native per-transaction proofs remove that
aggregate settlement mechanism. Publishing a zero/nonzero fee, individual fee
amount, fee opening or independently recognizable fee claim identifies filler
transactions or fee tiers. Equal byte lengths alone do not prevent this leak.

V1 selects Scheme B as its fee-settlement direction. Each transaction exposes
only a randomized fee commitment `F_i`; a real transaction commits the private
standard or priority fee and a padding transaction commits zero. Wallets place
the fee opening in a bounded mempool sidecar so a block producer can order
transactions and build settlement; the opening is never written in clear to
the block or chain. A separate native,
non-recursive block proof binds every `F_i` to its opening and proves that the
private sum equals the fee component of the miner reward note. Real and padding
transactions share the same public shape, including dummy nullifiers.

The selected sidecar has no standalone signature or second encryption layer:
nodes recompute `F_i` and
the transaction binding on receipt, while confidentiality and peer
authentication come from the planned X25519 + ML-KEM connection handshake.
Missing sidecars, mismatched openings, and sidecars bound to another
transaction are discarded before state mutation and recorded as bounded peer
abuse. The settlement design requires a fixed sidecar codec, frozen AIR layout,
security report and qualified-host 64--576 capacity measurements,
with a three-trial 576-position result reporting proof bytes, generation and
verification time, and per-stage peak memory. The four required rejection
cases are explicit:
wrong commitment sum versus the miner reward, forged fee opening, non-zero
padding fee, and zero-fee real transaction. A ciphertext or unbound private
fee witness is insufficient. The implemented 2,027-byte body excludes the
48-byte fee commitment, fee sidecar, proof statement and relay-envelope context;
the complete ledger must include each component.
Standard and priority amounts remain reward-linked: standard is
`floor(reward / 1,000)` and priority is four times standard. Variable bids are
outside scope. The parameter freeze must bind the implemented private fee
relation and its rejection tests. Collection, non-duplication, padding
indistinguishability and private witness delivery remain activation and
independent-review requirements; completing the node path is not a prerequisite
for recording the proof parameters.

## Encryption and ciphertext binding

The recipient output uses one ML-KEM-768 ciphertext per transaction. Both change
outputs use ChaCha20-Poly1305 under 256-bit keys derived from sender secret
material with a domain-separated BLAKE3 KDF. The sender secret must use its own
wallet derivation domain and must not reuse an ML-KEM shared secret.

The selected change derivation is:

```text
change_key = BLAKE3-derive_key(
    "siworld multi-asset change-v1",
    sender_change_secret || change_commitment || output_index)
```

The result is exactly 32 bytes. Use a fresh 12-byte change nonce and authenticate
network, format version, output index and commitment as associated data. Freeze
canonical associated-data framing, nonce generation, recipient KDF domains and
secret erasure behavior before activation. The recipient's fresh KEM secret
may use the existing one-use zero-nonce construction only under a separately
pinned domain and key-use rule.

A public node without an encryption key cannot verify a ChaCha20-Poly1305 tag.
Canonical decoding checks lengths and field encodings, not decryptability.
Binding every ciphertext byte and view tag to a public digest in the AIR
prevents substitution after proving, but does not prove that the ciphertext
encrypts the corresponding valid output note. Recipient-side tag verification
and rebuilt-commitment checking remain necessary.

V1 selects public-data substitution resistance. Complete ML-KEM and
ChaCha20-Poly1305 encryption correctness is outside the AIR and remains future
research. AEAD associated data must not be described as node-verifiable
encryption correctness. The recipient verifies the tag, decodes the note and
recomputes its output commitment before accepting a payment.

Before broadcast, the sender must decrypt and check all three locally constructed
outputs and compare the recovered note commitments. For the recipient output,
the sender uses the shared secret obtained during encapsulation; it does not
possess or require the recipient's private decapsulation key. A failed self-check
must not produce a broadcastable transaction. Retain per-payment encapsulation
coins and the bound recipient/context in protected wallet storage so a selective
payment receipt can reproduce the KEM ciphertext and validate the opened note.
Do not publish or log receipts, coins or plaintexts. Receipt disclosure reveals
that payment and is not an anonymity-preserving public record. Never disclose
wallet master or change-secret material as a receipt.

Padding outputs must execute actual ML-KEM encryption against a fresh valid
ephemeral public key and the same change-encryption algorithm. Do not substitute
random bytes for a ciphertext. Test recipient decryption and commitment checking,
self-check failure before broadcast, receipt mismatch rejection, and identical
public lengths and encoding for real and padding outputs. Equal format is not
an independent indistinguishability proof.

Consensus verifies the byte-bound spend/value relation without an AEAD key.
A sender-created encryption error can make that output unusable for its intended
recipient, while the transaction remains subject to the same commitment,
conservation and nullifier checks. It does not make ciphertext decryptability a
consensus rule or cause unrelated state to become invalid.

## Implemented public-data codec

The isolated three-output codec encodes a 2,027-byte public body, excluding
the native proof and proof/relay-envelope context. Its fields are:

| Field | Count | Bytes each | Total bytes |
| --- | ---: | ---: | ---: |
| Input nullifier | 2 | 48 | 96 |
| Output commitment | 3 | 48 | 144 |
| Recipient ML-KEM-768 ciphertext | 1 | 1,088 | 1,088 |
| Encrypted padded note body | 3 | 208 | 624 |
| Poly1305 authentication tag | 3 | 16 | 48 |
| Symmetric change nonce | 2 | 12 | 24 |
| Output view tag | 3 | 1 | 3 |
| **Total** | | | **2,027** |

A fee commitment adds 48 bytes and the canonical snapshot selector adds 40,
for 2,115 permanent bytes per position. The provisional transaction proof-cap
target is 655,360 bytes. With the native 2,184-byte envelope prefix and 78-byte
sidecar, the maximum combined transaction payload is 657,622 bytes, before
the four-byte gossip length prefix. The body and envelope encodings are
implemented and tested; persistent-record overhead remains to be measured. A 32-byte private asset ID consumes
existing note padding, leaving 144 meaningful bytes and 64 zero-padding bytes
inside each 208-byte plaintext. See [the multi-asset design](v1-multi-asset.md).

### Retained formats and baseline separation

The two-output diagnostic codec remains in `crates/bench-d8` with its original
freeze bundle and reproducible measurements. It does not define the new
three-output byte ledger. The unchanged seven-node network retains its own
32-byte digests, two 1,344-byte ciphertexts and 2,818-byte slot. Neither format
is silently reinterpreted as multi-asset history.

The new codec rejects truncation, trailing bytes and noncanonical field
encodings. Public nodes verify the byte binding, while key holders verify
AEAD tags and reconstructed commitments. Production envelope decoding,
resource quotas and node admission remain integration work.

## Rejection tests before implementation

Write failing tests before adding each validation rule. The minimum matrix is:

1. Mutate every public field independently, including every nullifier and
   commitment limb, ciphertext byte ranges, view tags, public recent-root value,
   network/suite/format identity and fee-settlement binding.
2. Test both input paths, wrong anchor entry, wrong path sibling, wrong index,
   wrong root snapshot, expired snapshot, wrong fee schedule and inconsistent
   anchor height. The private path must never be accepted merely because the
   public root was supplied by the transaction.
3. Test invalid standard/priority tier selection, wrong fee arithmetic, carry
   and range failures, and any fee claim credited twice.
4. Repeat a nullifier within one transaction, across a candidate block and
   against confirmed state. Test mempool conflicts and reorg re-admission.
5. Alter ciphertext/public-data binding after proving. Separately test recipient
   AEAD rejection and commitment reconstruction; do not conflate it with a
   public node's proof check.
6. Test truncated, extended, noncanonical, wrong-suite and oversized encodings,
   wrong trusted key and invalid proof before any state mutation.

Shared production, validation and replay transitions must remain integer-only,
deterministic and atomic. Invalid input leaves state unchanged. Proof inputs
must never select an untrusted verification key. Use synthetic fixtures and
independent network identities.

## Revised transaction profile and capacity gate

The revised actual-AIR scan measures log blowups 5–8 and query/opening-batch
grinding 20/24, using each coordinate's minimum query count passing the 80-bit
screen. All eight configurations have three fresh four-worker processes on an
EPYC 7763 Ubuntu 24.04 two-exposed-core/four-vCPU reference VM. Four Rayon
workers and two hiding workers are fixed. Setup is separately timed; generation
includes the complete native proof. Three samples do not bound grinding tails.

The selected profile is log blowup 7, 41 queries, query/opening-batch grinding
20, zero commitment grinding, binary folding and final-polynomial log length
zero. Its generation trials are 1.531155438 / 1.429902190 / 1.462877730 seconds,
with a 1.462877730-second median. Four-worker proof bodies are 581,392–585,808
bytes and the maximum charged process-tree peak is 525,234,176 bytes. Separate
one-worker verification has a 17.006900-ms median; that process also prepares
and generates a proof, so its memory is not an independent verifier bound.
The [profile](../crates/bench-multi-asset/artifacts/v1-transaction-profile.json)
records the 1,392-main-column AIR, complete errors, source and key identity.
Quantum-halved Johnson challenge union is 81.692218869 bits, classical
conjectured union is 185 bits and selected W24 BHT ledger is 123.333333333 bits.

`MAX_LEAF_PROOF_LEN` remains **655,360 bytes (640 KiB)**. The largest selected
body across all six four-/one-worker measurements is 588,832 bytes, leaving
11.2983% margin. The cap rounds up the required 10% margin to 64 KiB; it is
an admission policy, not a deterministic proof-length theorem. Reject an
oversized encoding; never weaken security or truncate data. Settlement and
settlement uses a 655,360-byte cap and issuance retains a separate 524,288-byte
cap. The old two-output decoder's
512-KiB limit is unchanged and cannot admit the revised shape. Native decoder,
wallet and standalone-verifier resource qualification precede activation.

The canonical public body remains 2,027 bytes, with 48 fee-commitment bytes
and a 40-byte snapshot selector: 2,115 permanent bytes per position. The
native 2,184-byte prefix gives a 657,544-byte maximum transaction envelope;
with its 78-byte private sidecar the relay payload is 657,622 bytes.

Keep the block maximum at 576 positions. Reproduce the economic-format
[wire model](v1-network-budget.md) with
`python3 scripts/v1-network-budget.py --native-protocol --economic-rewards`.
It includes three copies, a 61,235-byte compact fixed record for five reward
notes and eight native signed fund claims, the settlement proof once
inside the compact body, bounded issuance, inventory/requests, AEAD/multiplexing,
IPv6/TCP/link framing, reciprocal ACKs, handshakes, retransmission and recovery.
The conditional load is **1,369,369,494 bytes / 300 seconds**, or
**36.51651984 Mbps**. `ceil(36.51651984 / 0.85)` gives a **43-Mbps** uplink floor,
leaving **15.077861%** unused; recommend 100 Mbps. This is a planning result,
not measured transport acceptance. The unflagged and native-only script modes
preserve earlier format evidence. Qualify the actual provider and offered
load before launch, and rerun both resource models if revised proof caps change.

Use `python3 scripts/v1-storage-budget.py --economic-rewards` for the matching
[storage model](v1-storage-and-sync.md). It keeps the nominal 336.180-GB rolling
proof allowance and 2,115 permanent bytes/position, and raises the provisional
permanent block reserve to 64 KiB for economic reward/fund records. Including
indexes/state, system/working space and 20% device free, maximum-load device
needs at years 1/3/5 are **678.776 / 1,105.879 / 1,532.981 GB**. A 1-TB device
reaches that reserve after approximately **2.50 full-load years**. Keep the
500-GB installation minimum and 1-TB recommendation as workload-qualified
profiles: 10,000/day needs 271.168 GB at year five, while 50,000/day needs
541.310 GB with adaptive packing or 547.189 GB at uniform 176 positions.
A general five-year claim for 500 GB is unsupported. Actual persistent
overhead and growth still require measurement; never prune permanent data or
unexpired proofs to fit a device target.

The native registry supports 1–32 immutable wallets, while eight claims may
enter a block. Launch keys, exact basis-point shares and team residue index
remain explicit activation inputs. The storage model also reserves 64 KiB
once for the public genesis registry; it is not repeated per block.

Source, dependencies, actual AIR dimensions, key, parameters and the measured
binary identity are bound by the engineering profile. Node/wallet integration
and independent cryptographic review are separate from parameter freeze.
The [layout optimization](multi-asset-air-optimization.md) proceeds independently;
a smaller result requires a new screen, measurements and key/profile freeze
before reducing the bandwidth requirement. Local byte/CPU limits remain
necessary; resource exhaustion is retryable unavailability, not invalidity.

## Node and block design boundary

The following changes are proposed and are not implemented by this document:

- Verify complete native transaction proofs on mempool admission; cache success
  under the exact transaction, proof, root snapshot and trusted-key identity.
  A cached result never bypasses current nullifier or root-lifetime checks.
- Use groups of 16 with 64 through 576 total positions and a 300-second target.
  Producers generate valid filler transactions without publishing real/filler
  counts or fee classes. The fee/padding relation and its privacy review are
  prerequisites for activation.
- Relay compact block inventories with collision-safe transaction identifiers
  and bounded missing-transaction/proof retrieval. Reconstruct and authenticate
  the complete block before applying it. Missing data is not proof validity.
- Set the new route's local `MAX_REORG_DEPTH` to 24. Test depth 23/24/25,
  root-window boundaries and conflict re-admission. A deeper fork requires
  explicit checkpoint recovery rather than silent partial rollback.
- Retain transaction, settlement and native issuance proofs and private fee
  sidecars until three elapsed days **after final confirmation**, then delete
  them from the online proof store. At a 300-second target, depth 24 is two hours nominally,
  so the steady-state retention window is 888 blocks: 24 unresolved blocks and
  864 finalized blocks. Finality is a deterministic depth rule rather than a
  wall-clock guarantee; persist finality/retention metadata and extend the
  window after uncertain clocks, reorganizations or recovery. Never shorten it
  by a nominal block count.
- Preserve public data on every node without pruning: block headers and PoW,
  output commitments and commitment-tree state, ciphertexts, nullifiers, fee
  commitments, block settlement declarations without proofs, miner reward
  notes, development-fund records and ML-DSA signatures, and recent-root
  snapshots, plus signed public asset-issuance declarations. The implemented
  three-output permanent position record is 2,115 bytes. A permissionless
  asset registry must bound metadata size, records per block, initial notes
  per issuance and issuance work so permanent storage remains measurable.
- V1 has no archive-node role. New nodes use a release checkpoint authenticated
  with genesis/network identity, cumulative PoW, accepted-state commitments,
  complete snapshot window, verifier manifest and permanent-data roots, then
  validate every later block. Full proof replay from genesis, using an optional
  proof archive or asynchronous V2 history compression, is a future upgrade.
  Checkpoint bootstrap is an explicit trust assumption; header work or matching
  peer roots cannot prove proofs that have been deleted. Test stale, conflicting,
  incomplete and wrong-network checkpoints fail closed.
- Back up permanent public data to versioned object storage at least every six
  hours, publish a signed daily manifest and create a weekly full checkpoint
  snapshot. Restore in an isolated node by verifying object hashes/signatures,
  replaying blocks and PoW, rebuilding indexes and comparing roots/work before
  promotion. Run monthly restore checks and quarterly replacement-host tests.
  Wallet creation requires explicit mnemonic backup confirmation and a local
  recovery check. Restored wallets rescan permanent ciphertexts from genesis or
  an authenticated wallet birth height, including pre-checkpoint segments,
  and reconcile notes, nullifiers and payment journals exactly once. The node's
  bootstrap checkpoint does not bound the wallet's recovery history.

## Remaining implementation milestones

The isolated multi-asset AIR, native transaction/issuance/settlement proofs,
fixed public codec and encryption primitives are implemented in the new
engineering crate. The earlier snapshot-pool and bounded-decoder work remains
a baseline whose integration must be updated for this profile.
Their security and resource reports must match the exact frozen source,
dependency, relation and verifier identities. A surrogate AIR, diagnostic row
or unrelated CI smoke test cannot replace those artifacts.

The [node and network integration plan](v1-node-network-plan.md) gives concrete
admission budgets and remaining milestones: shared block transition,
verification service and padding pool, compact relay, three-day retention,
public-data backup and checkpoint-plus-PoW synchronization, hybrid transport,
source-hiding relay and
new-network acceptance. The [network design](v1-network-design.md) fixes the
engineering identity, source-relay and explicit checkpoint-trust direction;
the [deployment profiles](v1-deployment.md) and [acceptance gates](prover-acceptance.md)
define resource and recovery qualification. Milestone estimates span 3–17
engineering days, with wallet and monitoring work listed separately; review,
infrastructure and elapsed observation windows are excluded. Node implementation follows
proof-parameter freeze and does not redefine its boundary. Network privacy is
required before launching the independent engineering network. N=32 and
recursive V2 work remain outside this V1 implementation scope.

## Multi-asset reopening

The private asset ID, third output and issuance-supply relation change the
transaction AIR, encrypted plaintext, statement digest and trusted verifier key.
The isolated implementation includes the actual three-output codec, per-asset
balance AIR, native fixed-supply issuance proof with ML-DSA-65 verification, and
a SIP-only reward constraint inside the settlement AIR. The two-output baseline
is unchanged. The revised unlock-height and economic reward relations have
fresh actual-AIR reports and a 39-scope EPYC measurement record. Their
engineering parameter freeze does not complete required CI/key reproduction,
node/wallet integration, independent review or sustained testnet acceptance.

See the [actual multi-asset evaluation](v1-multi-asset-evaluation.md),
[V1 Multi-Asset Transaction Format](v1-multi-asset.md), and
[V1 Storage, Retention and Bootstrap](v1-storage-and-sync.md). The native shared
transition integrates issuance proofs, the persistent registry and
declaration-bound fee receipts; replay and reorganization restore them together.
Testnet issuance requires exactly
**50 SIP (5,000,000,000 atoms)**, credited entirely to a dedicated
development-fund account. That account is not yet configured; issuance
admission remains closed and must fail closed until the authenticated
destination and explicit metadata/per-block limits are configured. A receipt
must identify a verified canonical or same-block SIP payment output and is
consumed once. No default recipient, fee waiver or miner
share is permitted. The mainnet issuance fee remains undecided. A valid
signature cannot replace the supply proof or verified SIP fee payment.

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
