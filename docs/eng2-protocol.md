# Engineering network 2 protocol requirements

Status: requirements for a separately versioned engineering network. Component
implementations and tests do not activate these rules on an existing network.
A selected genesis must identify the exact implemented transition, fee mode and
proof profile. Only features verified by the corresponding complete network
rehearsal may be activated. No active network silently switches to an incomplete
fee or synchronization candidate.

## Activation profiles

The internal engineering network may bind the existing miner-fee rules for
ordinary and priority transfers if the new confidential-fee relation has not
qualified. Its public issuance fee policy is selected separately and explicitly.
This is an explicit genesis choice, not a fallback after proof verification fails. Incomplete requirements
below do not describe active internal-network behavior.

The subsequent public testnet requires all execution-commitment, confidential-fee,
development-fund and governance rules below. Fee qualification covers every
public proof transcript, body and compact encoding, state commitment, export and
explorer projection together. A fixed-size ciphertext or a frontend field filter
does not establish that public chain data hides fees. For ordinary and priority
transfer fees, both the individual amount and the per-block aggregate must remain hidden from public chain and explorer observers.
Asset issuance and its fee are public. The existing off-chain relay/producer
model supplies fee openings to participants preparing settlement witnesses; this
is not a claim of fee secrecy from those participants.

Public-testnet admission initially uses signed checkpoints, with measured
fresh-node catchup. Automatic synchronization, parallel proof catchup, the
offline QR interface and second-phase explorer features are deferred until
after that launch. Their designs and additional acceptance requirements are
listed separately below; they are not prerequisites for the internal genesis.

## Execution and header authentication

Each header authenticates the post-execution state commitment as part of its
proof of work. Validators independently reconstruct eleven ordered components:
chain context and work, commitment tree, nullifiers, recent roots, Holder pool,
development fund, fee destination, governance, issuance and burn counters,
scheduled reward locks, and the asset registry. Peer-supplied component digests
cannot replace state reconstruction.

Ordinary block execution must not re-encode, sort or clone permanent history to
derive these commitments. The commitment-tree component binds its actual
append-tree root and leaf count. The nullifier component binds a deterministic,
incrementally updated authenticated-set root and count. Snapshot import still
rebuilds both structures from every canonical value and compares the derived
roots against the selected header. An unverified cached root cannot replace
this reconstruction. Exact component encodings and hash domains must be frozen
with the versioned implementation before activation.

Production and validation use the same integer-only staged transition. Activate
previously scheduled changes first; freeze the policy for the new height; verify
and execute the ordered body; derive every component; then commit atomically.
A newly included proposal cannot change its own block's policy. Failed proofs,
governance actions or accounting checks leave the parent state unchanged.
Parallel proof verification cannot change execution order or bypass context
binding. The existing 300-second target and four-hour ASERT half-life remain.

## Confidential transaction fees

For the existing height-dependent ordinary base fee b, use floor(b / 10) atoms
for standard transfers and four times that rounded value for priority transfers.
Padding pays zero. Settlement directs the entire private fee sum to the active
payment address and credits the miner only with subsidy and any allowed Holder
pool allocation. A fixed-shape destination output is present even for zero fees.
Neither individual fees nor a per-block or period fee total is public.

The proof must bind the full active payment address, note commitment and encrypted
note so that the designated recipient can recover the payment. A commitment to
an arbitrary ciphertext is insufficient. The versioned encryption-correctness
relation, its composition, security parameters, decoder limits and resource
measurements remain activation gates. Existing proof profiles cannot be reused
as evidence for a different relation.

### Public asset issuance fee

Genesis sets the public issuance fee to 50 SIP and fixes its inclusive bounds at
1 through 10,000 SIP. All arithmetic uses integer atoms, with 100,000,000 atoms
per SIP. The entire payment goes to the same active dedicated destination used
for transaction fees; no part is paid to the miner. Changing that destination
also affects future issuance payments according to the active policy.

The founder key alone may propose a new amount within those genesis bounds.
Inclusion publicly records the proposed amount and a 4,032-block activation
height. The revocation key alone may cancel it strictly before activation.
Wrong-role signatures, out-of-bounds amounts and replay reject atomically. The
current amount and pending policy are included in the execution commitment.
The explorer displays the current public issuance fee and pending amount and
activation height, while continuing to exclude ordinary and priority fee amounts
and aggregates.

The native public receipt binds the signed declaration, exact active amount,
SIP asset, zero unlock height, canonical rho and declaration-derived rseed. Its
commitment must occur in an independently verified ordinary transaction output
in canonical history or the current block and may pay for only one issuance.
The block engine freezes the applicable policy before including new proposals;
prepayment does not preserve an obsolete amount or destination after activation.
The public note opening permits its spending owner to recover the payment even
without decrypting the corresponding transaction ciphertext. This authenticates
payment to the active spending owner; it does not prove encryption correctness
for the destination's ML-KEM key. A wallet must still check canonical membership,
spent nullifiers and reorganization status before crediting a public receipt.

## Development fund

Keep the existing subsidy allocation and configured member shares. For each
member credit C, release floor(C / 2) after 24 blocks. Let L = C - floor(C / 2).
The remaining cumulative release after n periods is floor(L * min(n, 48) / 48),
where one period is 8,766 blocks counted from the credit height. The first
monthly release is at h + 8,766 and the final release is at h + 48 * 8,766 for
credit height h. The last period releases every residual atom. All arithmetic
is checked integer arithmetic.

One fund ledger owns entitlement, released and spent amounts and expenditure
counters. A payment-address change preserves that member's accumulated credit
and spend history. Claims require actual member authorization, an increasing
counter, sufficient released balance and the current payment destination.
Payment addresses are not interchangeable with ML-DSA verification keys.
Fund payouts and transaction fees are transfers, not additional issuance.

## Governance authorization and cancellation

Genesis fixes distinct founder and revocation ML-DSA-65 keys. Every action binds
the network, type, exact payload, signer role and a monotonically increasing
sequence. Public inclusion records contain changes and effective heights. They exclude
private payment amounts; a public issuance-fee change includes its new amount.

| Pending change | Proposal authorization | Delay after inclusion | Cancellation before activation |
| --- | --- | --- | --- |
| Fee payment address | Founder | 4,032 blocks | Revocation alone |
| Fund member payment address | Founder | 4,032 blocks | Revocation alone |
| Public asset issuance fee amount | Founder | 4,032 blocks | Revocation alone |
| Founder and revocation keys | Both current management keys | 4,032 blocks | Both current management keys |
| One or more checkpoint signer slots | Both current management keys | 24 blocks | Both current management keys |

A revocation-only cancellation of a jointly authorized change is rejected.
Cancellation at or after activation is rejected. A cancellation is a new signed
action with its own sequence; it identifies the original proposal precisely.
Wrong-role signatures, payload modification and replay are rejected atomically.

The checkpoint roster always has exactly three slots and threshold two. These
values cannot change. Signers cannot authorize their own replacement. The active
and pending roster are committed in state. Actual inclusion of a replacement
must emit an operator notification. Before signing, a replacement independently
validates as a full node through the current head.

The deferred offline tool shares native canonical action decoding and signing domains.
It displays the network, action, sequence, role and activation rule before
signing, and exchanges bounded multipart QR requests and public signatures.
Private keys do not enter QR messages, logs or network requests.

## Deferred automatic synchronization and proof retention

The following automatic-admission and retention rules are a deferred design.
The current resident does not select this synchronization mode and still keeps
complete proof-bearing canonical bodies. Implemented alarm/export fields do
not perform proof deletion. Signed fresh-node admission and permanent receipt
retention must be qualified independently; implementation of this design
cannot be inferred from the existing storage policy constants.

A joining node verifies all headers and difficulty rules from pinned genesis,
then selects the greatest verified cumulative work after consulting at least
three distinct sources. Insufficient sources, unresolved equal-work alternatives
or a tail below the positive local work floor prevent automatic admission.

For selected tip H > 312, reconstruct state at H - 312 and compare the resulting
execution commitment with that exact header. Fully validate every subsequent
block through H before adoption. Short histories start at pinned genesis.
The pre-anchor state is authenticated by the selected work chain; this procedure
does not re-execute every historical transition before the anchor.

Signatures provide optional additional checks. Missing signatures or unavailable
signers do not block automatic synchronization. A valid contradictory checkpoint
from the currently authorized epoch alarms and stops synchronization. Invalid
signatures and removed-key backdating cannot manufacture that conflict.

Service proof retention covers the real 24-hour finality window and the inclusive
anchor-through-tip interval, plus reorganization and admitted-transfer pins.
The inclusive long-history interval contains 313 heights. Signature publication
is no longer a deletion boundary. Miner retention defaults to 96 blocks and is
configurable down to 24. Permanent data remains protected; capacity limits only
raise alerts.

## Network rehearsal

Use an owner-controlled private network with a separate genesis and disposable
keys. The internal activation sequence exercises actual block production, a
transfer, independently reconstructed state commitments, committed governance
records and a fund claim for every feature selected in its genesis. Record any
omitted feature explicitly. Fund-claim evidence must use real proved blocks to
reach release height; advancing a simulated height is not a successful claim.

The complete public-testnet rehearsal additionally tests both fee tiers,
recipient recovery, subsidy-only miner settlement,
supply conservation, fund release and a successful claim. Issue one asset and
verify payment to the dedicated fee recipient. Verify delayed issuance-fee
activation, cancellation before activation and rejection outside the genesis
bounds. Independently compare execution commitments at every block and reject each mismatched component.

Verify every governance authorization and cancellation boundary, including
revocation-only cancellation of key rotation and signer replacement being
rejected, and jointly signed cancellation before activation succeeding. Test
activation, late cancellation and sequence replay separately.

Before public launch, a genuinely fresh miner must join through a valid signed
checkpoint. Record actual download volume, disk occupancy and catchup time;
module tests and another network's result cannot replace that measurement.

After automatic synchronization is implemented, verify joining with all signers absent, a valid conflicting checkpoint,
low-work rejection and three-source admission. Keep one real node offline for
strictly more than 86,400 seconds, then recover through an automatic checkpoint.
Record the actual offline interval, catchup duration, downloaded bytes, disk
occupancy and result. Do not substitute a changed clock or another network's
recovery result. The ordinary eight-core catchup target of 30 minutes requires a
source-bound machine measurement; unit tests do not establish it.


## Exact competing-block exchange primitives

The [canonical reorganization design](eng2-reorganization.md) defines the
separate savepoint, execution and activity-gate requirements for adoption.

The engineering transport defines an optional exact header request (opcode
`0x0f`) containing a nonzero height and a 32-byte block ID. The response must
match the request number, network, height and computed header ID. An exact
missing response (`0x10`) repeats both height and ID; a height-only missing
response cannot complete this request. The existing body request already binds
height and ID, and body chunks retain the existing authenticated framing,
commitment checks and allocation reservations.

The network owner may expose an independent raw-branch header, persisted body
length and complete raw body. Canonical lookup has priority only when its ID
matches the request. Raw body size is read and node-wide memory is reserved
before extracting or decoding the body. Exact header requests consume the same
bounded round request allowance as other ordinary requests. These interfaces
do not qualify proof-of-work, execute native proofs, update the canonical head,
or initiate a reorganization.

A live session confirms extension support with the existing `GET_HEADER(0)`
request before any exact-header opcode is sent. A legacy peer responds with
`UNAVAILABLE(0)` and remains usable for ordinary canonical exchange. An enabled
peer responds with opcode `0x11`, capability version `1`, and an exact-exchange
flag. The response is bound to the request number and has strict length,
version, and flag checks. Confirmation is cached only in that live session;
reconnection requires another probe. The handshake alone does not establish
support.

When the driver enables branch discovery, an unknown equal-height or lower-height
remote head, or a mismatching parent during forward synchronization, starts a
bounded exact-ancestor walk. One node-owned ledger retains candidates, expiry,
authenticated peer identities, attempts, header storage and body-byte accounting
across rounds and connections. Duplicate advertisements do not extend candidate
lifetimes. Only expiry of the fixed node-wide window resets accounting. A
linear request ticket reserves an object attempt before capability probing, so
negative probes and reconnects cannot replenish the allowance. At most one
probe precedes an object attempt; wire requests are therefore bounded by twice
the ledger object-request limit. Both probe and object count against the same
round allowance. A round with only one wire slot left defers new capability
probing before reserving an object attempt. A live-session scheduling hint for
an unchanged local/remote tip pair lets the next round enter discovery directly,
rather than spending that slot on the same mismatching canonical header. This
hint neither qualifies a header nor resets the ledger.

The discovery owner checks an ancestor against the canonical store, qualifies
the complete header path and accumulated work, and retains each missing raw
body separately from canonical state. Socket I/O occurs outside the owner lock.
Transport memory remains reserved until body retention completes. Discovery
readiness means that raw materials exist; it does not establish native proof
validity or authorize adoption. Full execution and state-commitment checks
remain part of the separate append-based switching path. The rollback depth
limit does not impose the same length limit on a replacement branch.

Ordinary committed blocks enter the independent archive through an indexed
capability-checked insertion, without revalidating all historical headers.
A process-local revision changes only when committed header eligibility
changes, allowing the driver to reuse an unchanged bounded selection scan.
The archive writes immediate transactions with quick-repair allocator snapshots;
strict reopen rejects a request for full repair. Local component and disposable
fixture tests do not establish deployment, distributed convergence, propagation
latency, or the twelve-hour multi-miner acceptance result.
