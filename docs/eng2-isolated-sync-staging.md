# Isolated synchronization staging

Status: resumable authenticated acquisition. Native versioned proof verification,
ordered execution, certificate evaluation and live-head adoption remain required
before this path can activate automatic synchronization.

## Binding and isolation

`eng2::staging::Session` receives an actual source-selected `AdmissionPlan`, an
immutable local genesis `SnapshotState`, the pinned rules commitment, explicit
local resource policy and an anchor descriptor from `eng2::archive::Archive`.
Creation requires a new private directory and creates one `staging.redb` file.
An existing directory or database is preserved and rejected by creation.

The durable session binding contains the network, genesis, rules commitment,
anchor and selected tip identities, cumulative and tail work, local work floor,
complete selected-header digest, explicit proof profile and all decoding and
transfer limits. Reopen requires an identical binding. File opening uses the
existing guarded regular-file implementation and platform privacy checks. redb
repair is disabled; damaged or incompatible data is rejected without automatic
reinitialization.

This directory is independent of the live chain store. Acquisition and restart
checks cannot modify the bootstrap, publish a chain head, change retention or
start a network service. No execution-success assertion is accepted from callers.

## Durable acquisition

The session can pull actual bounded snapshot and body chunks from an archive
through its selected-header-pinned transfer lease. The archive checks the exact
authenticated peer, reservation interval, selected window and requested range.
The receiver independently binds the transfer to its selected plan. A failed or
expired read preserves received bytes so a caller can resume with a valid lease.

Each object has one immutable descriptor, a contiguous received-byte counter and
a chunk count. Chunks must be nonempty, ordered, within the local byte limit and
within the declared object length. Total declared reservations, total received
payload bytes and chunks per object have independent limits. Objects that cannot
fit the configured maximum chunk size and count are rejected before reservation.
The implementation ceilings are 1 MiB per chunk and 1,048,576 chunks per object;
deployments must explicitly choose the lower limits appropriate to their budget.
These are resource limits, rather than consensus rules or a disk-cap guarantee.

Ordinary partial appends update counters and one chunk within one immediately
durable transaction. They do not rescan the full partial object. On the final
chunk, the receiver reconstructs and checks the complete object before committing
that chunk, its completed bytes, counters and partial-record removal atomically.
An invalid final chunk leaves the previous durable progress intact.

Snapshot completion checks the declared transport length and digest, then runs
`ImportedAnchor::reconstruct` over every raw component. The actual eleven-component
state is re-created and authenticated against the selected work-verified header;
transport descriptors and cached roots cannot substitute for reconstruction.

Body completion checks the exact selected header's full body commitment and
canonical `Body` decoding with the configured network, height, proof profile and
byte limits. Canonical framing does not establish signature or native proof
validity. There is no default production proof profile or settlement-proof limit.

## Restart and execution boundary

Reopen scans object descriptors, contiguous chunk order, chunk counts, completed
and partial record consistency, reservation bounds and total received-byte
accounting. It reconstructs the complete anchor again and rechecks every completed
body against its selected header and decoding policy. Missing, inconsistent or
corrupted state remains on disk and causes an error.

Progress advances through `AcquiringAnchor`, `AcquiringTail` and
`AwaitingNativeVerification`. The last phase means only that the anchor and all
selected tail body bytes are available and authenticated for execution. It does
not mean that any settlement proof has passed or any block has been admitted.
The native versioned verifier must subsequently resolve actual proof contexts,
verify every proof and authorization, derive the shared checked chain delta and
typed ledger changes, compare execution commitments, evaluate the current
certificate policy and commit live adoption through the normal durable boundary.
The staging module currently has no live-adoption API.

## Native preparation boundary

`Session::prepare_anchor_successor` connects a completed acquired body and the
actual reconstructed anchor to `eng2::execution::PreparedBlock`. It rechecks the
stored body's selected-header commitment without buffering another complete body.
Preparation borrows the permanent parent state, checks the full body and header
work, runs shared chain preparation, activates old governance operations and
freezes the current destination. New signed governance actions run against a
separate bounded candidate. Actual subsidy, pool and fund accounting advance in
isolated typed ledgers; fund claims require immutable-key authorization, complete
recipient recovery and a successful debit before their outputs can be inserted.

`PreparedBlock::verify_transactions` calls the actual fixed-profile native
transaction and issuance verifier on every exact prepared context. Only that call
can construct `NativeTransactions`. That type exposes the locally derived
settlement policy, complete activated destination, ordered fee commitments,
miner commitments and fixed fee output needed by the separate native settlement
relation. It does not authorize settlement or expose a state-publication method.
The original and versioned bodies share the exact ordered transaction-statement
digest; randomized proof bytes are excluded, while each statement binds its fee
commitment and selected snapshot. Existing native block encodings are unchanged.

Synthetic framing fixtures remain invalid input to these actual authentication
and proof checks. A successful cache transfer cannot promote their signatures or
proofs into execution authority. Native settlement verification, complete
execution-commitment comparison and durable adoption are still outstanding.
