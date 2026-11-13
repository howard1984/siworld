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
