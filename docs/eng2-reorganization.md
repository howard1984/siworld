# Bounded canonical reorganization

The engineering resident retains competing headers and original block bodies in a separate `branches.redb` database. Canonical savepoint restoration never rolls back this archive, first-arrival order, branch invalidity marks, peer identities, or checkpoint signing journals. Complete header validation includes proof of work, links, timestamps, difficulty and cumulative work. Equal cumulative work prefers the header path received first. Header qualification alone does not establish native block validity.

## Acquisition and selection

Authenticated sessions negotiate exact-identity header exchange through a backward-compatible capability probe. Node-owned discovery accounting survives round and connection changes. The local policy bounds candidates, peers, requests, total headers, raw body bytes and candidate lifetimes. Socket I/O occurs outside the canonical owner lock. A missing body is pending work; it does not authorize canonical restoration or permanent invalidation.

The resident seeds accepted header order before admitting competitors. An ordinary successful append retains its complete raw material using indexed lookups. A raw-archive failure after the canonical commit pauses production and records an alarm; it does not relabel the committed block as rejected. Switching clears the local pending-transaction and padding pools. A wallet can rebroadcast an original still-valid signed packet after authenticated synchronization; automatic orphan-transaction reinsertion remains outside this scope. Candidate selection is cached between header or invalidity changes. A selection revision still requires a bounded scan of the retained header tree; selection is not a constant-time operation.

## Restore and append

For a preferred branch with at most 24 removed blocks:

1. Fix the common ancestor and complete original and replacement raw material. Missing original material or a missing retained savepoint requires manual recovery.
2. Execute the entire fixed replacement from the authenticated ancestor in an in-memory engine before restoring durable state. Bind the result to the Store instance, canonical revision, old head, exact header identities and body commitments.
3. Withdraw the mutable wallet head, revoke completed peer-head readiness, discard queued production work, and advance the template generation before restoring.
4. Restore the ancestor in one canonical transaction. Reconstruct and authenticate all state components against the ancestor header execution commitment. Commit and capture a fresh ancestor savepoint.
5. Reuse ordinary complete append transactions, one block and one savepoint at a time. Intermediate prefixes are valid committed chain states. Pause production, checkpoint signing, wallet publication and bootstrap publication while applying them.
6. Authenticate the final state and require fresh completed peer evidence for its exact head before resuming production or wallet publication.

The canonical database retains 25 states. Full replacement prevalidation is necessary even for a one-block rollback: a much longer replacement could otherwise evict the ancestor before a late invalid block is discovered. The current local prevalidation budget is 256 replacement blocks, 4 GiB of combined original/replacement encoded bodies and a cooperative 900-second deadline. Length metadata is checked before copying or decoding replay material. A shared reservation covers four times the largest body plus fixed scratch throughout planning and replay; it accounts for proof-byte working buffers, not total verifier or process memory. These are local resource policies, not consensus validity rules or preemptive verifier termination.

An explicitly classified native-invalid replacement is marked invalid before restoration, leaving the original canonical chain untouched. Unexpected material, storage, verifier availability, re-execution or fingerprint failures close activity gates and require manual recovery. They do not permanently mark a branch consensus-invalid. Depth above 24 also stops automatic switching and raises an alarm. Automatic isolated checkpoint recovery is outside this implementation.

## Restart and outputs

Canonical and raw-archive transactions use redb immediate durability and allocator snapshots for quick crash recovery. Strict repair-abort policy and authenticated canonical restart checks remain enabled. A process crash may leave any complete replacement prefix. Startup authenticates that prefix, notices a better retained branch and keeps production and publication paused until ordinary append synchronization completes. No whole-switch transaction, separate candidate database or switch recovery journal is used. Checkpoint snapshot archives commit after savepoint capture. Startup, ancestor restoration and replacement append recreate the authenticated current archive at a positive checkpoint boundary, covering a crash between the canonical commit and its separate archive write.

A template generation prevents stale work from surviving a head change followed by another change. A currently executing proof is not preempted; its result is discarded when the owner observes a changed generation. PoW checks the active generation and exact parent between bounded search batches and again before commit.

Wallet publication removes the mutable head cursor before restoration while retaining immutable historical generations. Signing ticks and outgoing checkpoint proposals are paused without deleting anti-double-sign records. A checkpoint whose authorization header was removed is explicitly retired after validating its original artifacts, signatures and a retained header path to the canonical prefix within 24 links. Retirement grants no current signing or bootstrap capability. The mutable cursor is withdrawn while immutable publication records preserve the original publication time; withdrawing an advertisement must not refresh its staleness clock after restart. The original strict checkpoint-opening path still rejects obsolete authorizations. An unavailable canonical Store replaces stale ready status with `state_available=false`, `ready=false` and a manual-recovery alarm, without asserting an unauthenticated height or tip.

The resident reports reorganization depth and ancestor. Depth above six or the fourth completed reorganization in a rolling hour raises an alarm. These in-process frequency counters do not establish a cross-restart monitoring history.

## Qualification limits

Offline modules and explicit owner-operated tests are separate from deployment and multi-miner qualification. Existing old-profile proofs can test complete native execution without generating new proofs, but they do not qualify a new proof profile. Full depth coverage, fault injection across nodes, state and wallet reconciliation, propagation measurements and a continuous 12-hour multi-miner run remain separate acceptance gates. Hardware recommendations do not substitute for these measurements.

## Isolated native branch production

The owner-local `eng2-rehearsal` build provides explicit setup commands for
fresh competing branches. `--partition-init NEW_CAMPAIGN --json` creates a
private synthetic seed and minimum-difficulty genesis. `--partition-node
CAMPAIGN NEW_NODE INDEX --json` creates an independently authenticated empty
store and distinct reward destination beneath that campaign. Neither command
starts a process, connects to a peer, or imports existing chain data.

The rehearsal and runtime features together support `--partition-height NODE
HEIGHT --json` through the rehearsal executable. This selects a local production
ceiling from zero through 96. New nodes start at zero. The resident retains its
ordinary authenticated peer-readiness checks, validates incoming blocks and
continues networking when production reaches the ceiling. The ceiling is checked
before proof work, nonce-search slices and durable block commit. Invalid or
removed controls fail closed after a bounded campaign has started. Consensus
rules and proof profiles are unchanged; the control requires a fixture genesis,
maximum target and zero configured PoW iterations. Ordinary runtime builds do
not compile this control.

Partition qualification must record the exact source and binary hashes, the
common ancestor, both independently produced branches, transport fault schedule,
and per-block native execution and durable acceptance. Use the loopback relay
operator separately to create and heal partitions. A head comparison alone does
not establish full-state or wallet equivalence. The setup commands do not grant
G1 or G2 qualification and must not be used to reinitialize an existing network.

After an owned synthetic node stops, `--partition-audit NODE NEW_OUTPUT --json`
acquires its service lease and opens the canonical database read-only. It
independently verifies every retained native block, compares the resulting tip
and execution commitment with the durable head, and exports exact public block
frames. The manifest records per-block parent, cumulative work, execution root
and all eleven canonical state-component hashes. It does not scan a wallet or
claim G1/G2 acceptance. The command rejects nonfixture controls, imported or
missing proof history, more than 96 blocks, an existing output directory and a
node whose resident still holds the lease. The source canonical database and
index are not rewritten by this audit.

## Native material prefix replay

The owner-local rehearsal command
`--partition-replay-prefix EXPORT EMPTY_NODE HEIGHT --json` loads a prefix of
unchanged public frames exported by `--partition-audit`. The destination must
already have its own identity, an authenticated empty store, the exact same
synthetic genesis, and production paused at height zero. Heights are bounded
by the 96-block rehearsal ceiling.

The command checks the export manifest, genesis, rules, proof profile, ordered
frame names, sizes and SHA-256 digests. It independently verifies the entire
selected prefix before the first append, then rereads each frame and passes it
through ordinary native `Store::append`. Each append retains the normal durable
transaction and rollback-point creation. An authenticated reopen must match
the verified prefix head. No proof or block is generated or modified. If source
files change during append, any already committed blocks remain an ordinary
valid prefix; the command does not roll back or replace an existing database.

One naturally mined pair of branches can supply several replay cases without
changing signed or proved bytes. With a common block at height one, retain A
through height 26 and B through height 27. For rollback depth `d`, select A
through `1 + d` and B through `2 + d`; the latter has greater work under minimum
fixed difficulty. The depths 1, 6, 7, 23, 24 and 25 therefore use the same
immutable branch materials. The original partition and material generation
must be recorded separately from this replay matrix.

Preparing node stores does not qualify peer discovery, authenticated branch
transfer, connection restoration, reorganization or propagation. Those checks
must run through normal peer connections after the prepared nodes start, with
independent native audits and state comparisons afterward. A replay matrix is
not evidence of six independently mined live partitions, and it does not reduce
the storage required by the participating canonical databases.

## Full-frame local Driver cases

On Unix, an owner-operated build with `eng2-rehearsal` exposes:

```text
siworld-eng2-rehearsal --partition-driver-case A_EXPORT A_MANIFEST_SHA256 B_EXPORT B_MANIFEST_SHA256 NEW_DIRECTORY DEPTH --json
```

Both manifest SHA-256 values must come from completed independent native corpus
acceptance. The exports must retain all unchanged native frames at heights 26
and 27 respectively, share the exact first block and diverge at height 2. The
command accepts only depths 1, 6, 7, 23, 24 and 25. For depth `d`, the old prefix
ends at `d + 1` and the competing prefix ends at `d + 2`. Header verification
independently computes 512-bit cumulative work and requires greater competing
work. Each selected frame is decoded with the native bounds and its pinned
length, SHA-256, identity, parent and execution commitment are checked.

The destination must be absent and separate from both public exports. The
command creates an independent identity, an authenticated empty store and a
local production ceiling of zero. It admits the old prefix through ordinary
`Driver::accept`, retains the complete competing frames in the independent
branch archive, and invokes the normal Driver prevalidation, ancestor restore
and one append per owner turn. It creates no proofs and starts no network or
mining process. Source genesis, manifests and complete frame hashes are checked
before and after the case; source databases and custody are never opened.

After each old-prefix append, ancestor restore and replacement append, the
observer compares all eleven actual canonical component byte strings against
an independent Engine advanced with native verification. It also compares each
component length and BLAKE3 digest with the pinned audit record, plus exact
height, block identity, parent, execution commitment and full cumulative work.
Each observation is written to a separate create-only file. A final authenticated
store reopen repeats the comparison after releasing the mutable Driver owner.
Intermediate store reopen, process crashes, peer healing, wallet scanning and
checkpoint authority journals are separate acceptance work.

Depth 25 must reject before the restore barrier, preserve the old height-26
state, keep owner activities paused and report the manual-recovery depth alarm.
This refusal case checks the competing header work and unchanged complete frame
material; replacement native execution is supplied by the independently
accepted corpus rather than a forced depth-25 Driver execution. A successful
case writes `case-complete.json`; an incomplete directory must be preserved as
failed evidence and cannot be adopted for another case. The internal 900-second
deadline is cooperative, so an external owner-controlled resource and process
supervisor remains necessary. These case receipts do not establish complete
network qualification.

### Test-only named crash recovery entrypoints

A Unix library test build with `eng2-rehearsal` also has two ignored, explicitly
selected entrypoints:

```text
eng2::rehearsal::partition::driver_case::crash_cases::full_frame_driver_crash_child
eng2::rehearsal::partition::driver_case::crash_cases::full_frame_driver_resume
```

They require `SIWORLD_FULL_FRAME_SOURCE_A`, `SIWORLD_FULL_FRAME_MANIFEST_A_SHA256`,
`SIWORLD_FULL_FRAME_SOURCE_B`, `SIWORLD_FULL_FRAME_MANIFEST_B_SHA256`,
`SIWORLD_FULL_FRAME_DIRECTORY`, `SIWORLD_FULL_FRAME_DEPTH` and
`SIWORLD_FULL_FRAME_BINARY_SHA256`. The binary fingerprint must identify the
executing test harness, independently pinned before invocation. Named edges
use the existing `SIWORLD_REORG_CRASH_POINT`, `SIWORLD_REORG_CRASH_HEIGHT` and
`SIWORLD_REORG_CRASH_MARKER` parameters. The marker must be a canonical sibling
path outside the case and both source exports.

The crash child additionally requires `SIWORLD_REORG_CRASH_CHILD=1` and
`SIWORLD_REORG_CRASH_FULL_FRAME=1`. It exclusively writes its invocation binding
beside the future marker. A test-only atomic gate leaves all initial A-prefix
append hooks disarmed. The gate is armed only after normal A admission and full
B material retention, immediately before the first reorganization tick. Existing
store commit hooks then park at the selected named replacement boundary. An
external owner must retain the exact child handle, verify its exclusive fsynced
marker, send SIGKILL only to that child and reap it. These entrypoints do not
send signals or adopt existing processes.

The recovery entrypoint requires the same invocation binding and marker, an
existing incomplete case and `SIWORLD_REORG_CRASH_CHILD` absent or different
from `1`. It never arms crash hooks. The expected durable prefix is determined
by the selected commit edge: old A before the restore commit, shared height 1
after that commit, B at height `h - 1` before append `h`, or B at height `h`
after its commit. Before reconstructing the Driver or opening the branch archive,
recovery authenticates that exact store prefix and compares its complete header
sequence and all eleven actual components with independently executed native
replay and the pinned audit oracle.

Recovery opens the existing independent branch archive and uses ordinary Driver
turns to reach the retained best B branch. It verifies each observed B prefix
and the final authenticated store reopen. Recovery observations are create-only;
a second invocation must fail rather than overwrite prior acceptance evidence.
No source database, wallet or seed is opened, no old header is rewritten, and no
new proof or mining process is created. Failed quick-repair opens remain failed
acceptance evidence; the helper does not enable full database repair. The named
crash entries accept depths 1, 6, 7, 23 and 24. Depth 25 remains a separate
restore-before refusal case. No parent batch controller, process-kill result,
power-loss result or complete crash matrix is implied by these entrypoints.

## Nonfixture history qualification

The owner-operated rehearsal executable provides separate qualification commands
for existing nonfixture engineering history. These commands neither initialize a
network nor generate proofs, mine blocks or start residents. The synthetic
partition commands and their fixture production controls retain their existing
requirements. The qualification commands reject fixture genesis and zero PoW
iterations; they do not create a production-ceiling marker.

Each invocation takes a public binding JSON file and its independently supplied
SHA-256. The file has exactly these fields:

```json
{
  "version": 1,
  "network_id": "<64 lowercase hexadecimal characters>",
  "genesis_id": "<64 lowercase hexadecimal characters>",
  "rules_commitment": "<64 lowercase hexadecimal characters>",
  "proof_profile": "<64 lowercase hexadecimal characters>",
  "source_commit": "<40 lowercase hexadecimal characters>",
  "binary_sha256": "<64 lowercase hexadecimal characters>"
}
```

Identity values must be nonzero. Unknown and duplicate fields are rejected. The
binding is limited to 8 KiB. The executable must have been built with
`SIWORLD_BUILD_COMMIT` matching `source_commit`, and its actual SHA-256 and
compiled proof profile must match the supplied pins. The selected genesis must
match the network, genesis and rules pins. A compiled source declaration does
not prove build provenance: the owner must independently bind the source
archive, toolchain, build manifest and executable. Receipts explicitly record
`source_commit_externally_verified=false`. Separate executables from the same
source, such as an audit executable and a test harness, have separate binding
files and binary hashes.

```text
siworld-eng2-rehearsal --qualification-audit NODE NEW_OUTPUT BINDING BINDING_SHA256 --json
siworld-eng2-rehearsal --qualification-replay-prefix EXPORT MANIFEST_SHA256 EMPTY_NODE HEIGHT BINDING BINDING_SHA256 --json
siworld-eng2-rehearsal --qualification-driver-case A_EXPORT A_MANIFEST_SHA256 B_EXPORT B_MANIFEST_SHA256 NEW_DIRECTORY DEPTH BINDING BINDING_SHA256 --json
```

The audit requires a canonical absolute node directory, acquires its exclusive
service lease and opens its canonical database read-only. It requires complete
retained native history through at most 96 blocks, independently verifies every
block and compares the final head and execution commitment with durable
metadata. It exports the exact unchanged frames and an independently pinnable
manifest, including the eleven component digests at every height. The output
must be a fresh separate directory. This read-only replay audit does not
authenticate the source's accepted-state restart seal. It reads public block
history and does not load source identity custody.

Prefix replay requires an existing authenticated empty stopped destination with
its own local identity. The source manifest SHA-256 is checked before mutation.
The manifest must have the nonfixture audit scope and the same declared source,
network, genesis, rules and proof profile. Every prefix is prevalidated through
ordinary native execution, then appended through the ordinary Store path. The
actual eleven component byte vectors are compared with an independent native
reference at each committed prefix and after an authenticated final reopen. No
source database, identity or synthetic campaign seed is copied. The destination
service lease remains held throughout replay and reopen. Starting or bounding
subsequent production is a separate owner operation.

The Unix Driver case retains the existing six depths: 1, 6, 7, 23, 24 and 25.
It requires exact audited A26/B27 histories with a shared H1 and distinct H2.
Each selected replacement prefix must have independently verified greater
cumulative work. Original full frames are retained and passed through the
normal native prevalidation, ancestor restore and incremental append path.
Depth 25 must stop before restoration with the existing manual-recovery alarm.
Each case creates only its own fresh identity and authenticated Store, records
a separate qualification binding, compares actual component bytes with native
replay and the pinned oracle, and performs a final authenticated reopen. It
never creates a synthetic production marker or starts a network process.

These commands do not expose the test-only crash hooks in a resident executable.
Existing ignored Store crash entrypoints still require their original fixture
context. Live resident fault injection, authenticated malformed-peer inputs,
nonempty business-state and wallet reconciliation, peer healing and a complete
continuous multi-miner run remain separate requirements. No command result
asserts G1 or G2 acceptance.


## Owner-local resident commit faults

On Unix, a build selecting both `eng2-runtime` and `eng2-rehearsal` contains an
optional local commit-fault controller. Ordinary builds and runs without
`SIWORLD_ENG2_OWNER_FAULT=1` do not enable it. Invalid environment selections
fail startup. The selected source declaration and actual executable SHA-256 are
required; the controller supports nonfixture history only. The node directory
and its sibling parent must be canonical private directories owned by the same
user. The controller belongs only to the resident's canonical Store.

After the actual resident run ID is available, the owner may create
`owner-fault-request.json` in that node directory. The private single-link file
is limited to 8 KiB and uses a strict schema: `version` (1), `run_id`,
`network_id`, `genesis_id`, `rules_commitment`, `proof_profile`, `source_commit`,
`binary_sha256`, `old_tip`, `candidate`, `ancestor_id`, `ancestor_height`,
`point`, `height` and `marker_name`. Hashes and the run ID use lowercase
hexadecimal; the source commit has 40 characters and other identities have 64.
The marker name is one sibling filename, at most 128 ASCII letters, digits,
periods, underscores or hyphens, excluding `.` and `..`.

The eight point names are `restore_before_commit`, `restore_after_commit`,
`restore_after_publish`, `restore_after_capture`, `append_before_commit`,
`append_after_commit`, `append_after_publish` and `append_after_capture`.
A restore point uses the selected ancestor height; an append point uses a
height in the fully prevalidated replacement. Only the exact selected branch
arms the request, after full native prevalidation and the normal output barrier.
A create-only SHA-bound claim is durably written before arming, preventing reuse
of the same request. Ordinary A construction and unrelated switches remain
unarmed. Depth 25 retains its existing refusal before restoration.

At the chosen edge the canonical Store is already unavailable for publication.
The controller creates and fsyncs the fresh sibling rendezvous, including actual
run, PID, request hash, selected branch and commit edge, then parks for at most
120 seconds. It never sends a signal. The external owner must independently
verify process ownership and the exact rendezvous, send SIGKILL to the retained
resident child, and observe its signal termination. The rendezvous itself does
not prove that a kill occurred. Expiry or an unreached selected boundary fails
closed as a local fault-case error. It does not mark a branch consensus-invalid.

Recovery must omit the fault environment selection and reuse the same identity
and database. Retain requests, claims and rendezvous as private evidence. Normal
authenticated restart and branch synchronization remain responsible for recovery;
this controller neither restores a database copy nor permits allocator repair.
Boundary coverage and actual full-state reconciliation remain separate results.

## Authenticated explicit frame submission

A rehearsal build selecting `native-p2p` provides an owner-operated sender:

```text
siworld-eng2-rehearsal --qualification-send-input IDENTITY_NODE PLAN PLAN_SHA256 BINDING BINDING_SHA256 --json
```

It loads an existing stopped local identity under its service lease, an existing
independently installed receiver pin and a matching signed receiver descriptor.
It creates no identity, pin or listener. The standard source/genesis/profile/
executable binding applies. The plan is strict JSON, limited to 16 KiB, with
`version` (1), `endpoint`, `receiver_descriptor`, `receiver_fingerprint`,
`receiver_role` (`bootstrap` or `validator`), `receiver_height`, `receiver_tip`,
`local_fingerprint`, `frame`, `frame_sha256` and `input_kind` (`valid_control` or
`negative_input`). The plan's independently supplied SHA-256 is mandatory.
Descriptor and frame are explicit public input paths. The frame must have a
canonical native header extending the exact receiver head in the plan and fit
the ordinary body bound. Encoded frame memory is reserved before allocation.

The sender uses the existing Connector and real pinned hybrid authentication,
checks the receiver role and live head, advertises the input header, and serves
only matching ordinary header/body requests. It sends the explicitly pinned body
bytes, including deliberately invalid inputs, through the existing bounded
application framing. It does not change receiver validation or generate a new
proof. At most one frame and four requests are served within a shared 180-second
application deadline. The external owner must separately supervise the process
and authorize the exact isolated destination and input material.

Input classification is a declaration, not a validation result. A sender receipt
records the actual handshake and transmission, but explicitly does not prove
input invalidity, native receiver rejection or unchanged receiver state. A closed
connection has an unknown cause. Receiver admission diagnostics and authenticated
state comparisons must establish those conclusions independently. New malformed
input copies must remain separate from valid fork corpora and accepted history.

## Authenticated competing-branch submission

```text
siworld-eng2-rehearsal --qualification-send-branch IDENTITY_NODE PLAN PLAN_SHA256 BINDING BINDING_SHA256 --json
```

This sender uses the same existing stopped identity, installed receiver pin,
qualification binding and canonical native header framing as single-frame
submission. It reads supplied branch artifacts and never creates or edits them.
The receiver retains ordinary discovery, body decoding and native admission.

The strict plan is limited to 64 KiB and contains these fields:

| Fields | Meaning |
| --- | --- |
| `version` | 1, independently versioned for this command |
| `endpoint`, `receiver_descriptor`, `receiver_fingerprint`, `receiver_role`, `local_fingerprint` | Explicit authenticated destination and existing sender identity; roles are `bootstrap` or `validator` |
| `receiver_height`, `receiver_tip` | Exact receiver baseline before submission |
| `source_fingerprint`, `source_manifest`, `source_manifest_sha256` | Declared original branch source and an independently pinned public provenance artifact, limited to 1 MiB |
| `ancestor_height`, `ancestor_id`, `rollback_depth` | Common ancestor and exact receiver distance, from 1 through 25 blocks |
| `candidate_height`, `candidate_tip` | Exact advertised competing tip, higher than the pinned receiver baseline |
| `frames` | 1 through 64 ascending contiguous `{path, sha256, bytes}` complete raw frames, starting immediately after the ancestor and ending at the candidate tip |
| `total_frame_bytes` | Exact sum of declared frame lengths, at most 16 GiB |
| `maximum_transmitted_body_bytes` | Cumulative body transmission allowance, including repeated requests, at most 16 GiB |
| `maximum_rounds` | From 1 through 16 ordinary rounds |
| `input_kind` | Declared `valid_control` or `negative_input` |

All identity and SHA-256 fields use canonical 32-byte hexadecimal values. Input
paths are limited to 2048 bytes and duplicate frame paths are refused. Every
frame must fit the selected native body policy. The sender reserves memory before
reading each frame, verifies its exact length and SHA-256, then checks all header
heights, parent links and the exact candidate tip. It retains only the bounded
header inventory between reads; every requested body is read and pinned again.

Before advertising, the sender checks the receiver's live tip, queries its
canonical common-ancestor header (or checks the bound genesis at height zero),
and checks that the next canonical header differs from the candidate's first
header. A second live-tip query must match the original baseline. These checks
bind the stated rollback depth to the observed divergence before submission;
they do not lock the remote node or establish its eventual head.

The sender answers ordinary height queries, exact-identity header queries and
exact body queries only from the supplied inventory. It answers the normal exact
exchange capability probe. Each completed block round is followed by the normal
checkpoint exchange with an empty outgoing batch and a bounded transaction
inventory exchange requesting no transactions. This permits discovery to retain
its normal cursor across rounds. At most 1024 block-phase messages are received;
all application operations share the remaining 180-second deadline, including
input preflight. The owner must supervise process resources independently.

A receipt inventories frame identities and hashes, actual completed header and
body transmissions, completed rounds and successful body-chunk writes. An error
after advertising is retained as an exchange outcome with the preceding events.
The source manifest's bytes are SHA-256 verified, but the source fingerprint and
creation provenance remain declarations requiring independent inspection.
Checkpoint messages are decoded and discarded locally; no certificate or
transaction is issued or admitted by the sender. Transmission does not prove
input invalidity, receiver rejection, unchanged receiver state or gate acceptance.
The owner must retain the real partition history and independent receiver state
and diagnostics for those conclusions. A negative artifact must be newly created
branch material, separate from accepted history; this sender cannot establish its
creation history from bytes alone.

## Authenticated persisted-state comparison

```text
siworld-eng2-rehearsal --qualification-compare-state NODE EXPORT MANIFEST_SHA256 EXPECTATIONS EXPECTATIONS_SHA256 BINDING BINDING_SHA256 --json
```

This owner-local operation holds the stopped node's service lease and opens its
database through `redb::ReadOnlyDatabase`, using the existing identity and the
same accepted-state authentication as normal restart. It separately
replays every original public frame through the native Engine and NativeVerifier.
The complete canonical header prefix and all eleven actual final component bytes
must match that replay and the independently pinned audit manifest. A second
authenticated read-only open must produce identical state. Both observations
omit rollback capture, pruning and all other write transactions. Missing clean
allocator state or authentication material causes refusal; the observer does not
repair the database or regenerate a missing savepoint. Normal resident recovery
retains its existing rollback maintenance. The command does not import, append,
mine or generate a proof. Source, node and export context must agree with
the nonfixture qualification binding; the node and export directories are separate.

The independently SHA-pinned expectations use version 1 and a strict nested JSON
schema, limited to 128 KiB. `state` specifies `height`, `tip`, `economics`,
`fund_total_entitlement`, `funds`, `governance_sequence`, `issuance_fee_atoms`,
`pending_issuance_fee`, `fee_destination`, `assets`, `leaf_count` and
`nullifier_count`. Economic counters are canonical decimal strings:
`issued`, `burned`, `miner_credited`, `fund_credited`, `holder_pool` and
`locked_total`; `locked_schedule` lists ascending `{height, atoms}` entries.
Each fund account lists its `member`, decimal `entitlement`, `direct_unlocked`,
`vesting_unlocked`, `spent`, numeric `spend_count` and complete hexadecimal
`destination`. Funds include every configured member in order. Assets list
`id`, `height`, `public_supply` and `declaration` in registry order. A pending fee
is null or has `amount_atoms`, `proposal_sequence`, `included_height` and
`effective_height`. Destinations contain the complete canonical address bytes.

`included_operations` contains `{height, operation: {kind, identity}}` assertions.
`absent_operations` contains `{kind, identity}` assertions checked across the
entire canonical prefix. Supported kinds are `fund_claim_sha256` (SHA-256 of the
complete canonical claim), `governance_action_sha256` (SHA-256 of the complete
signed action), `issuance_declaration` (native declaration binding) and
`transaction_statement` (native statement identity). These identities use 32-byte
lowercase hexadecimal. `present_nullifiers` and `absent_nullifiers` contain
48-byte lowercase hexadecimal values. Each assertion array is bounded to 128
entries; contradictory or duplicate assertions are rejected. Complete history
remains limited to 96 blocks with a cooperative 900-second deadline.

Exact public counters and operation inclusion establish only the stated public
observations. A transaction statement can contain padding; inclusion does not
classify it as a real payment or establish a fee opening. The receipt records
which nonempty operation classes were explicitly asserted. Wallet scanning and
received, spent, unspent and balance reconciliation require independent wallet
evidence bound to the same head. This command does not read wallet material and
always leaves wallet balance verification, full business acceptance and G1/G2
acceptance false. It uses the Engine's actually supported fee modes and cannot
substitute an independently proved candidate settlement for a supported complete
block transition.
