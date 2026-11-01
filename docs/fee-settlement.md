# Confidential Fee Settlement for Route A V1

Status: selected V1 confidential settlement with engineering-frozen native
proof parameters for the [revised monetary relation](v1-economics.md).
Scheme B is native and non-recursive; no network activation is implied.
The [transaction profile](../crates/bench-multi-asset/artifacts/v1-transaction-profile.json)
is b7/q41/g20 with a 655,360-byte cap. The separate fixed-576 settlement uses
b8/q36/g20 and a 655,360-byte cap. The
[source-bound manifest](../crates/bench-multi-asset/artifacts/v1-native-proof-profiles.json)
binds the revised public preprocessing identities and actual-AIR reports.
Settlement binds the public mode, trusted consensus reward plan and one/five
reward notes, including SIP asset and unlock height. The node independently
validates pool, burn and fund transitions. Fresh measurements are recorded in the
[actual multi-asset evaluation](v1-multi-asset-evaluation.md). Required CI and
public-key reproduction remain release checks.
Independent review and node integration remain activation gates, and the
retained seven-node network is unchanged.

## Goals and boundaries

Route A broadcasts one native proof with each fixed-shape transaction. Nodes
verify the proof before mempool admission, and a block carries compact
references to those transactions. The required V1 transaction has two inputs and three outputs with
private per-asset balances and SIP-only fees. The isolated multi-asset AIR and
codec implement this shape; the earlier two-output code is an unchanged
baseline. Real and padding transactions use the same public byte length and the
same proof envelope shape. A real transaction commits either the standard or
priority fee; a padding transaction commits zero. The commitment, rather than
the fee amount, is the on-chain fee field. Its hiding and the uniform encoding
are intended to limit fee-based classification; they do not by themselves
establish computational indistinguishability. Sidecar recipients learn fee
openings, and producers recognize their own padding.

The settlement mechanism must meet four requirements:

1. The proof must establish the selected fee rule without publishing the tier
   or amount for an individual transaction. The public statement contains only
   a randomized fee commitment.
2. A block must credit the miner with its exact mode-dependent subsidy and
   Holder claim, plus all included fees in note zero, exactly once. The public
   pool, burn and fund updates follow the shared integer transition.
3. A node must reject omission, duplication, overflow, replay, and forged
   settlement data before changing state.
4. No public field may classify a slot as real or padding, or make an
   individual fee identifiable through a deterministic value.

This design uses a separate native block-level settlement proof. It does not
recurse over transaction proofs and does not replace transaction proof
verification. The proof is the selected V1 direction for making the private
sum publicly checkable. Its actual AIR shape, proof size, generation cost,
memory cost and security have isolated diagnostic evidence. Full production
witness/payout preparation, block validation, independent review and node
integration remain required before activation.

## Private fee binding in a transaction proof

Let `b` be the base fee committed by the accepted anchor snapshot. For a
transaction with tier bit `t` and dummy bit `d`, the private fee is:

```text
f = 0                         if d = 1
f = b * (1 + 3 * t)            if d = 0 and t is 0 or 1
```

The transaction AIR receives `f`, `d`, `t`, and an independently sampled blinding value
`r` as private witness data. The implementation encodes `r` as eight uniformly
sampled canonical KoalaBear elements: approximately 247.91 bits of entropy,
or approximately 123.95 bits against generic quantum search. The 32-byte wire
encoding does not provide a full 256 bits of entropy. Complete commitment
hiding, transcript separation and randomness handling remain review subjects.
It computes a fixed-width field digest:

```text
F = Poseidon2_W24(
      fee_u16_limbs[4] || blinding_field_elements[8] || 136 || 1 || zero[10])[0..12]
```

The permutation input is the native one-block overwrite sponge: a twelve-
element rate, multi-asset fee-domain tag 136, block count 1 and ten zero
capacity elements. The earlier two-output diagnostic used tag 6; it is not
the new multi-asset commitment domain.
Network, snapshot and transaction bytes are not part of this fee-commitment
preimage. The transaction proof separately binds `F` to its canonical public
data and fixed proof context, including the selected snapshot identity. The
sidecar transaction identity binds the same complete statement.
The accepted canonical recent-root snapshot commits the fee schedule. Accept only
the newest 4,096 canonical snapshots; remove orphaned or expired snapshots and
evict affected pending transactions for wallet reproof. This window is separate
from the depth-12 anchor tree and may accept correspondingly older fee schedules.
Historical replay uses the window at the block being validated. The domain tag,
field-limb order, padding, and transcript framing are fixed before an AIR
freeze. The chosen D8/W24/12-element suite is used for this relation; a
separate hash circuit must not be introduced implicitly.

The proof statement publishes only `F` in a fixed-size statement slot and omits
the fee limbs, tier bit, dummy bit, and `r`. With the D8/W24/12-element suite,
the canonical commitment occupies 48 bytes (twelve little-endian 32-bit
elements). This is an incremental proof-statement/relay-envelope field; it is
not part of the implemented 2,027-byte three-output body. The 48-byte `F` field
must nevertheless remain in the retained on-chain transaction statement after
the proof body is pruned. Together with the 40-byte canonical snapshot selector
the implemented permanent per-position record is 2,115 bytes before amortized
block context. The isolated AIR proves the following; node acceptance remains
separate work:

- the two inputs and three outputs satisfy independent per-asset balances and SIP-only fees;
- every positive-amount input proves ownership and commitment-tree membership;
  a zero-amount dummy input uses the canonical dummy witness and skips that
  membership check;
- nullifiers are derived for every input, including zero-amount dummy inputs;
  transaction-level uniqueness is checked in the relation, while mempool and
  consensus admission check conflicts against the candidate and prior state;
- `d` and `t` are boolean and the formula above holds with checked carries;
- `F` is the specified Poseidon2 digest of the private fee and blinding, and
  the transaction proof binds it to the canonical public statement;
- the accepted anchor snapshot supplies `b` and the recent-root membership.

The same relation is used for real and padding transactions. A padding witness
uses zero-amount dummy inputs, zero-valued outputs and `f = 0`; it does not
carry a special public marker. Its nullifiers remain protocol values and must
be unique just like real transaction nullifiers. A wallet samples `r`
independently for every transaction,
including any transaction that happens to use the same tier. Reusing `r` is a
wallet error and must be rejected by the wallet; the protocol does not use the
value of `F` as a fee identifier.

The transaction proof and sidecar identity bind `F` to the transaction and
network context. The raw commitment alone is not context bound. A proof or
sidecar cannot be moved to a different public transaction, network, suite or
snapshot without changing the authenticated statement. Wallets must sample
fresh blinding for every commitment; equality of reused commitments can be
linkable. The implemented three-output public body is 2,027 bytes. The
1,742-byte two-output diagnostic remains a separate baseline. `F` belongs to the fixed proof statement/envelope and must be included in the
proof-size, relay, and denial-of-service ledger; it is not silently added to
the public transaction bytes.

### Supplying a settlement witness to the miner

A transaction proof deliberately does not reveal `f` or `r`. A miner therefore
cannot create the block settlement proof from the public proof alone. This is a
real protocol dependency, not an implementation detail. Scheme B places a
fixed-size fee-opening sidecar alongside the transaction in the mempool. The
sidecar contains the transaction identity, `f` and the eight-element `r` and
uses the same canonical encoding for real and padding transactions. It has a
four-byte magic, two-byte version, 32-byte identity, eight-byte fee and 32-byte
blinding encoding, totaling **78 bytes**. Dummy and priority flags are not
wire fields. The individual anchor and its fee schedule are private, so a
relay cannot infer the exact fee tier from the current block schedule.
The sidecar is available to
the block producer for ordering and settlement; the opening is never written
to the block or public chain.

Sidecars do not carry an additional signature or application-level encryption
layer. Any node that receives one recomputes the fee commitment `F_i` and
checks the transaction identity before forwarding or using it for settlement.
The identity is a domain-separated digest of the canonical statement including
network, suite, snapshot selector, public data and `F`; it excludes the proof
body and sidecar. This identity differs from the AIR's separate public-data digest and avoids
a circular commitment definition.
Missing sidecars, an opening that does not match `F_i`, and a sidecar bound to
another transaction are rejected before mempool or consensus state changes,
and the bounded relay-abuse diagnostic records the peer. Confidentiality and
peer authentication for sidecar transport come from the planned X25519 +
ML-KEM connection handshake; the sidecar protocol does not introduce a second
key schedule. The handshake and reconnect design remains a separate network
gate.

If a valid sidecar is unavailable, mempool admission or local block production
fails rather than guessing an opening or weakening the settlement proof.
A validator checking an already constructed block needs its public commitments
and settlement proof, not the private fee openings. Sidecar unavailability must
not invalidate an otherwise valid block. Handshake coverage and node
integration tests remain activation gates.

## Block settlement statement

For a block with `M` fixed positions, the miner supplies fee openings for
every position, including generated padding. The public statement binds the
network/suite identity, block height, public Voyager/Holder mode, reward
allocation amounts and unlock heights, ordered transaction identity/fee-
commitment digest, and every reward-note commitment. Validators recompute this
reward plan from the canonical parent state using the
[shared integer monetary transition](v1-economics.md). The AIR does not receive
or independently update the pool balance, cumulative burn or fund state; the
node validates those transitions before reconstructing the proof statement.
Peer-provided plans or pool figures cannot override accepted state.

Let `R[j]` be the deterministic subsidy-plus-pool-claim amounts produced by
that transition: one note for Voyager and five for Holder. The AIR proves:

```text
F_i = Poseidon2_fee_v1(f_i || r_i)         for every i
T = sum(i = 0..M-1) f_i                  checked integer sum
reward_amount[0] = R[0] + T              checked integer sum
reward_amount[j] = R[j]                  for all j > 0
reward_commitment[j] = NoteCommit(full_reward_note[j])
```

Each full reward note binds the reserved SIP asset ID, amount, owner,
height-derived unlock, distinct reward index/randomness and seed. A host-only
SIP or lock check is insufficient. All fees go to note zero and never enter
the subsidy percentages, pool or burn. Note zero, including the Holder claim
and fees, matures at `height + 24`; Holder notes 1–4 use the selected
52,560/105,120/157,680/210,240-block offsets. The mode-dependent reward count
and exact subsidy allocations must be checked independently of secret fees.

`T`, individual fees and note openings remain private. The public transcript
binds the network, block height
and ordered transaction-list digest. The block transition reconstructs these
values, the ordered fee commitments, all mode-dependent reward allocations
and unlock heights from trusted candidate data.
The reward ciphertext belongs to the authenticated block/output codec and its
wallet self-check, rather than a claim of in-AIR encryption correctness.
The public block therefore
does not expose a fee total, a paid-slot count, or a per-transaction fee.
The phrase "sum of commitments" means that the proof opens each `F_i` to its
private fee witness and proves the integer sum of those openings; the digest
values themselves are not arithmetically added.

The settlement AIR has fixed capacity 576. A block has `M` positions in groups
of 16, from 64 through 576; its unused internal AIR rows use deterministic
zero-fee commitments derived from network, height, declared block-position
count and row index. The block verifier reconstructs those commitments and the prover
uses their known zero openings. These rows are not additional transactions in
the block. Within its `M` positions, ordinary padding transactions use the same
format and fee-opening relation as every other transaction. Neither statement
nor proof reveals which of the `M` positions is padding.

This proof is intentionally described as a block-level relation rather than a
recursive aggregation of the transaction proofs. It may reuse their public
statements, but it must not accept a transaction merely because the settlement
proof claims its fee. Each transaction proof is still verified independently
and the settlement proof must bind to the resulting statement digest.
The transaction AIR is the authority for zero-fee padding and standard/priority
fees under each private anchor's schedule. Settlement only opens canonical
u64 fees and proves their sum; imposing one current block fee schedule here
would incorrectly reject transactions using valid older anchors. A block must
never accept an unverified transaction on the strength of settlement alone.

### Required settlement evaluation

The selected V1 settlement relation uses a fixed 576-position AIR. Capacity
measurements cover 64, 128, 256, 384, 512 and 576 active block positions while
preserving the fixed relation and private padding rules.
The report must include the row and column shape, constraint count and degree,
proof and envelope bytes, verifier time, peak charged memory, and generation
time on the qualified machine. The 576-position case is the acceptance gate:
run it three times with the same fixed configuration and report the median and
each stage's peak memory. Include witness decoding, fee ordering, settlement
proving, and payout construction in the generation measurement; one-time
circuit preparation may be excluded only when it is performed at service
startup and remains resident. A result that exceeds the V1 time or memory
budget pauses the route and does not silently lower the privacy or proof
requirements.

The per-transaction accounting must list the 48-byte `F_i` commitment and the
fixed-size fee-opening sidecar separately from the implemented 2,027-byte public
transaction body, totaling 2,075 bytes with the fee commitment. The permanent
snapshot selector adds 40 bytes, for a 2,115-byte per-position record. Use the
transaction body admission cap of 655,360 bytes (640 KiB); the independent
settlement body cap is 655,360 bytes and issuance remains 524,288 bytes. The prior
`bench-d8` decoder is unchanged; the multi-asset envelope and node decoder
must enforce the new transaction limit before activation. Mempool byte caps,
concurrent-verification limits and complete relay capacity require the
production codec ledger and qualified transaction/576-position settlement
measurements. The
[node integration plan](v1-node-network-plan.md) specifies the proposed
2,184-byte envelope prefix, 78-byte sidecar and initial local byte/CPU policies.
The revised AIR binds the reserved SIP asset ID and every reward unlock
height inside the circuit. Its extracted shape is 1,024 base rows, 581 main
columns, 609 preprocessed columns, 7,050 public values and 19,703 degree-three
constraints. Earlier assetless reward commitments do not describe this relation.

## Mempool and block validation flow

1. Decode the fixed transaction bytes and proof envelope with bounded lengths.
   Reject unsupported network, suite, format, or proof sizes before expensive
   work.
2. Recompute the canonical transaction binding, validate the sidecar identity
   and fee opening against `F`, then verify the native proof against the trusted
   verifier key. The verifier obtains `F` from the locally decoded statement,
   never from a peer-selected statement. Missing or mismatched sidecars fail
   local admission before expensive proof work; block validation does not
   require a private sidecar.
3. Check duplicate nullifiers against the candidate state and the mempool's
   reservation table. Admission is atomic: a failure changes neither table.
4. Retain the verified transaction binding, `F`, proof digest, and nullifier
   reservations. The miner's private mempool sidecar retains the fee opening
   for ordering and settlement. A node validates the sidecar's transaction
   binding and commitment before retaining it; the node does not log `f` or
   classify the slot.
5. The miner obtains a validated sidecar for every position. It reconstructs
   the mode, subsidy, pool claim and one/five reward outputs from the common
   economic transition, includes each output exactly once and produces the
   fixed-capacity settlement proof. Missing or context-mismatched sidecar data aborts
   block production.
6. A receiving node verifies the header, compact references, every transaction
   proof, and the settlement proof. It checks that every `F_i` and transaction
   binding occurs exactly once, that every referenced transaction is present,
   and that all nullifiers are unique and unused in the parent state.
7. The node verifies the miner output commitment against the settlement proof
   and authenticates the reward ciphertext through the block/output codec.
   The recipient performs AEAD and note-opening checks; the settlement AIR
   does not prove ciphertext correctness. The node applies the common
   integer-only state transition, then releases reservations and persists
   the block.

The producer and validator call the same transition function. Any failure
leaves the state, mempool reservations, fee accounting, and wallet journals
unchanged.

## Rejection and abuse cases

The implementation test plan must reject each case below before state mutation:

- changing any public transaction byte, compact reference, proof statement,
  `F_i`, anchor snapshot, network identity, or suite identifier;
- substituting a proof for a different statement while retaining `F_i`, or
  replacing `F_i` while retaining a proof for the old statement; a fresh valid
  proof for the identical statement preserves its transaction identity;
- omitting a position, adding a second copy, reordering references without
  rebuilding the bound settlement proof, or using a transaction in two
  positions;
- using a duplicate nullifier within one transaction, in two transactions in
  the block, in the mempool, or against confirmed state;
- selecting a fee other than zero, `b`, or `4*b`, changing the anchor fee
  schedule, or setting a non-boolean tier/dummy witness;
- producing a zero-amount input with a non-canonical dummy witness, or requiring
  a commitment-tree path for that input; zero-amount dummy inputs must skip
  membership while still producing a unique nullifier;
- claiming a non-zero private fee for a padding transaction, or a zero fee
  for a real transaction, including attempts to alter either opening after
  mempool admission;
- supplying a forged fee opening, a commitment that does not match its opening,
  or a settlement sum that differs from the fee portion of the miner reward;
- overflowing a fee limb, the per-position total, or `miner_issuance_share + T`,
  including carries at every boundary;
- claiming reward amounts/counts that differ from the selected mode, adding
  fees outside note zero, claiming twice, changing a lock height or moving
  any reward to another block height;
- transplanting a settlement proof into a different network, block or suite,
  or binding a fee opening to a different transaction statement or snapshot;
  an unchanged pending transaction may be selected for a later candidate
  block when its snapshot and nullifiers remain valid;
- omitting a sidecar, supplying a sidecar whose opening does not match `F_i`,
  or supplying a sidecar bound to another transaction;
- truncating, extending, or making any proof, transaction, settlement, or
  ciphertext encoding noncanonical; and
- presenting a valid transaction proof but a settlement proof generated from a
  different transaction set or capacity.

Tests must include malformed proofs and oversized inputs so that proof
allocation is bounded. They must exercise the maximum configured capacity and
the largest allowed `b` without relying on host integer overflow behavior.

## Privacy and accounting properties

The protocol exposes the transaction's ordinary public data, proof size, and
relay timing. It does not expose `f_i`, `t_i`, `d_i`, `T`, or a paid-slot
count. `F_i` is a randomized binding digest and is expected to be
computationally hiding under the selected Poseidon2 model; it is not a fee
amount and must not be treated as one by metrics or APIs. Wallets, relays, and
miners must not log or export `f_i` with transaction identifiers.

The fee-binding digest and settlement proof add fixed proof/envelope bytes and
verification work. Capacity, bandwidth, and mempool budgets must include those
bytes, plus the fixed sidecar and retransmissions. The implemented 2,027-byte
transaction body alone is not a complete relay budget.

Settlement proofs and sidecars are retained for three elapsed days after final
confirmation to support reorg handling, checkpoint recovery, and
operational recovery. After that period, nodes delete the proof bodies and
sidecars. The public fee commitments `F_i` remain permanently with the
confirmed transaction; no fee opening is retained in the permanent record.

## Revised profile and activation gates

The engineering freeze includes revised transaction, settlement and issuance
AIRs, pinned `p3-security=0.9.0-rc.2` reports and 39 distinct fresh process-tree
measurements. Settlement uses three four-worker and three one-worker processes;
its one-worker verification timing is measured inside setup/prove/verify, not
an independent verifier-only process. Earlier single-note measurements do not
qualify this revised reward relation.

The engineering transaction-profile freeze records the implemented AIR,
parameters, public preprocessing commitment, fixed implementation/dependency
identities, matching security reports and successful generation measurements.
It does not finalize the multi-asset envelope/decoder or qualify a complete
node or wallet. Full protocol qualification additionally requires the
following evidence:

- a fixed AIR layout replacing clear fee limbs with the private fee witness
  and `F` statement fields;
- a fixed-size sidecar codec that gives the block prover enough information to
  construct the private sum without exposing fee tiers on the public chain;
- a hash-based, quantum-accounted `NoteCommit` and `Poseidon2_fee_v1` domain
  specification, including the eight-element blinding representation and
  its actual entropy;
- a fixed-size settlement-proof construction and its cost at capacities 64
  through 576;
- a 576-position three-trial evaluation covering circuit size, proof bytes,
  generation time, verifier time, and per-stage peak memory;
- p3-security reports for the transaction and settlement relations under the
  selected quantum target;
- a proof/envelope byte ledger and DoS limits incorporating `F` and the
  settlement proof; and
- independent tests for duplicate, omission, overflow, replay, forged payout,
  forged openings, wrong commitment sums, non-zero padding fees, zero-fee real
  transactions, zero-amount dummy-input membership skips, missing sidecars,
  sidecar/transaction mismatches, sidecar commitment mismatches, and
  state-atomicity failures.

Independent cryptographic review, hybrid-handshake integration, bounded
admission, the shared block transition and private witness delivery remain
activation gates after parameter freeze. The
[node and network plan](v1-node-network-plan.md) describes their implementation
milestones. Clear fee limbs in the older recursive AIR remain measurement
fixtures and are not the native V1 settlement statement. No part of this work
is enabled on the retained network.

The selected transaction b7/q41/g20 profile has a 1.462877730-second
four-worker generation median; every trial is below two seconds. Its
655,360-byte cap is 11.2983% above the largest selected body across both worker
groups. Fixed-576 settlement b8/q36/g20 generates in 5.523829281 seconds median
(maximum 5.616304295), with bodies no larger than 520,203 bytes and a maximum
charged process-tree peak of 3,161,432,064 bytes. Its one-worker verification
median is 19.914259 ms; quantum-halved Johnson challenge union is
81.983705354 bits. The separate 655,360-byte settlement cap and complete
mode-selected one/five-note SIP reward relation remain fixed. The
[multi-asset evaluation](v1-multi-asset-evaluation.md) records actual dimensions,
all transaction scan trials, security terms and separate settlement evidence.
These engineering profiles are not cryptographic approval or activated
consensus. External ML-DSA issuance authentication is paired with a separate
native fixed-supply proof and an SIP fee-payment verification gate; real
payment consumption, node issuance atomicity and issuance fee policy remain
open.
