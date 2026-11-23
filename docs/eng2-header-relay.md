# Header relay and padding scheduling

Headers contain 190 canonical bytes. Execution and body commitments in a header
remain unexecuted claims until the complete body passes native admission.
`Store::append` remains the canonical state transition. The immutable target
interval remains 300 seconds.

## Optional authenticated lanes

Resident peers probe the reserved header height `u64::MAX` on their ordinary
authenticated session. Existing responders return `UNAVAILABLE` for that height;
the resident then retains the ordinary synchronization protocol. An upgraded
responder returns the exact version-one lane capability. The existing height-zero
exact-block capability and its encoding are unchanged.

Only after a positive probe does the ordinary initiator dial two additional
connections to the same independently pinned endpoint. Both complete the existing
descriptor, hybrid authentication, immutable network/genesis binding and native
hello. Their first reserved-height request selects a header or body lane. The
receiver requires a unique lane for an independently pinned identity with an
active ordinary connection. No new listener port, peer-discovery mechanism,
plaintext relay or checkpoint identity is introduced. Public miner ingress does
not independently authorize extra lanes.

There are at most eight ordinary sessions and sixteen optional lanes, within
24 retained peer workers sharing the existing node budget. Each peer worker owns its
socket, authentication reservation, stack reservation and join handle. Existing
handshake, encrypted-session lifetime, record and byte limits still apply.
Admission pressure defers new workers; partial or failed streams close rather
than return to a reusable pool. Reconnection uses the existing bounded backoff.
Optional lanes never refresh ordinary block/checkpoint/transaction readiness.

The header lane exchanges at most eight framed headers per direction per turn,
with a 50-millisecond minimum cycle interval and a two-second framing deadline.
It contains no body payload. Header processing uses a separate mutex and cache;
long native body validation does not hold that cache while awaiting the canonical
owner. This is a transport separation, not a measured propagation bound.

## Header qualification and miner reaction

The resident cache seeds at most 25 recent contexts from actual accepted
canonical Store records, deriving their work from the accepted cumulative-work
value and their targets. No remote work value or remote timestamp defines a
context. The cache retains at most 128 qualified headers, with a 512-KiB logical
reservation, at most 32 new qualification attempts per second and 30-second
retention. Qualification checks immutable network, known parent and height,
median time, derived ASERT target, native PoW and checked cumulative work. The
same fixed genesis rules apply to canonical and competing paths.

Lower-work qualified prefixes may be cached to complete known ancestry. Only
headers whose locally derived cumulative work is at least the current canonical
tip's work are eligible for relay. Relay excludes the origin, deduplicates each
peer's retained transmissions and rechecks the work floor before selecting a
batch. A connection failure resets that peer's transmission cursors. Missing
ancestry remains for ordinary bounded discovery; an advertised height alone
cannot qualify a header.

After finding local PoW, the producer checks its existing owner-side activity,
parent, checkpoint, rehearsal and production-policy gates. Before the full local
append, it publishes that qualified header with a budgeted cache of the same
immutable candidate body. Body-lane readers can serve it without waiting for the
append's native verifier. The cache independently binds body encoding and
commitment to that header, retains the shared byte reservation through the last
reader, and never makes the candidate canonical. Local publication does not
cancel that same candidate's commit. Full admission, expiration or rejection
releases cache ownership; existing readers retain their own ownership. A header
cache update failure after a durable canonical commit records
`header_relay_error=header_context_update_failed`, cancels optional downloads and
pauses optional lanes and mining until restart. It cannot change the already
successful native admission into a failed or uncommitted result; ordinary full
validation remains available. Resource pressure defers this optional local publication, with a numeric status counter;
the canonical path still performs its original full admission.

A strictly greater-work qualified header received from another identity pauses mining. Nonce search checks
cancellation before each hash and retains ownership of its immutable body until
that candidate is discarded or the same candidate's search continues. A
header-only signal cannot create a valid child template: transactions, economics,
governance, rewards and settlement require fully verified parent execution state.
Status distinguishes `awaiting_validated_parent_state` from an executable tip.

Raw body retention does not remove that waiting condition. It ends after actual
canonical work catches up, rejection of that header and its cached descendants,
or expiration of the bounded unfulfilled announcement. Ordinary readiness and
canonical activity gates remain required before mining resumes. An expired or
invalid speculative branch never becomes canonical state through a timeout.

`VerifiedHeaders::verify_extension` separately exposes immutable-prefix suffix
qualification using the original full-path rules. `header_relay::Relay` remains
a bounded full-path scheduler interface. Resident operation uses the recent
accepted-context cache above to avoid cloning the full header history per offer.

## Multi-peer body acquisition

Independent body lanes take alternating bounded request turns, so an outbound-only
miner can both acquire and serve material through the same authenticated socket.
A heartbeat reads the actual committed header-cache tip without acquiring another
body's validation lock. Each turn contains one request and an exactly matched
completion; unexpected messages or sequences close that lane.

Before an unsolicited body request, the lane reads the peer's authenticated
canonical tip. A forwarded header alone does not establish body availability.
Source selection requires an exact qualified tip and a known parent path to the
candidate, or a parsed propagation offer for that exact independently qualified
header and network binding. A height alone, unknown tip or different branch
cannot qualify the source. These announcements are scheduling hints; they grant
no execution validity or canonical, checkpoint or wallet authority.

At most eight peer hints are retained. An idle or unqualified hint can yield its
slot to a known candidate's holder. A definite whole-body `UNAVAILABLE` response
withdraws the current session's hint. Body-lane disconnect cleanup removes only
that session's hint, so late cleanup cannot remove a newer session's announcement.
Repeated announcements and session replacement do not refund queries or bytes,
renew an existing body's absolute deadline, or bypass the exact-body registry.
A peer that falsely announces availability can still consume its ordinary
bounded account.

The node has at most four active downloads, at most two sources for one header
and four distinct source attempts per retained header. Qualified ancestors needed
by an eligible competing tip are scheduled before descendants. A retained lease
owns each download and releases its in-flight slot only when the lease drops,
including after header expiration or eviction. The status field
`body_download_leases` counts these retained downloads and admission jobs; cache
removal alone cannot free a slot. A 180-second
absolute download deadline and an individual cancellation flag apply to the
request and all chunks, including each chunk's framed payload. Receiving a frame
header does not renew that deadline or substitute a ten-second control-payload
deadline. Decoded body buffers keep the original shared memory
reservation through every consumer. The ordinary legacy body's ten-second
initial response and absolute 180-second chunk deadline are preserved. Other
control messages retain their existing ten-second payload limit.

An inactive qualified header still expires after 30 seconds. A later tip hash
cannot recreate an evicted header; a fresh known-parent header or ordinary
discovery is required. When actual canonical acceptance changes the head, the
cache republishes that exact header, including when it was forwarded before its
body arrived. Repeating a notification for the same head does not renew the
publication age or exact-body account. This preserves the existing cache and
transfer bounds; it does not establish a network-wide discovery or convergence
latency bound.

The optional `sync_progress` status object describes the highest-work uncompleted
remote header in this qualified cache. It reports the candidate and canonical
height, block identity and cumulative work, candidate age and cache sequence, and
at most two body attempts. Each attempt reports its index, absolute age, deadline
activity, received and announced byte counts, phase, and age of the last actual
chunk or completed decode. Waiting for a response supplies no progress event;
repeated or decreasing byte counts cannot refresh progress. A completed decode
is reported as `decoded_awaiting_admission`, not native validation success.
The object is null when no eligible header is available or the cache diagnostic
fails. It is not evidence about ordinary peer-round downloads, and cannot grant
readiness, block validity, canonical selection or checkpoint-signing permission.
Consumers must bind it to the process and run identities, compare canonical
identity with the same status sample, and account for missing, cancelled, stalled
or changed attempts conservatively. A new attempt is not a new availability
episode.

The canonical owner independently qualifies retained raw header extensions before
storing competing bodies. Raw archive status confers no execution validity. A
forward child invokes complete native admission; a competing path uses the
existing complete prevalidation, authenticated restore and append-based switch.
Only those established paths can change canonical state. Native verification
itself remains synchronous and has no mid-proof interruption API.

Authenticated decode moves each body, its buffer reservation, bounded header
path and download lease into a separate admission queue. At most four jobs,
including the active job, can retain download leases. One additional retained
worker uses an explicitly reserved stack and the same node budget. Socket turns
finish without waiting for native verification; the admission worker alone
acquires the canonical owner for header retention and complete admission. Queue
pressure drops the unqueued job with its owned buffers and lease. Shutdown joins
the admission worker and drains pending jobs after peer workers have returned.
The in-progress native verifier remains synchronous and must return before its
worker can be joined.

The first completed retained body cancels duplicate downloads; partial cancelled
streams close and are not reused. Actual canonical commit also cancels obsolete
copies of that block. Header rejection cancels and removes its cached descendant
requests. Expiration and cache eviction cancel their retained downloads. None of
these operations manufactures state, rewards, wallet data or checkpoint evidence.

## Padding ownership

The resident padding pipeline retains one background proof task while nonce
search continues. It fills the existing bounded private pool's spare capacity.
Before assembly it first consumes any completed result and starts another refill
only if ready positions remain below the existing minimum. Ready stock gives
foreground assembly priority over launching a new proof. Nonce search allows
background refill again. This ordering does not interrupt a proof already in
progress when the phase changes.
Transaction and settlement proof operations share one existing prover workspace
and the same four-thread pool; there is no concurrent second proof workspace.
A task cannot detach: shutdown or production failure joins its retained thread.
A proof operation has no mid-proof cancellation interface, so shutdown or a
settlement operation can wait for an already started padding proof to return.

Padding binds its actual network, snapshot height and block identity, recent-root
witness and anchored fee schedule. It is not rebound to a new head. Completion
requires the same reorganization generation and production-policy revision, an
available canonical snapshot and the original independent pool insertion verifier.
Canonical extensions may retain an unused valid snapshot; expired snapshots,
replaced branches and changed policies discard task output.

A prepared padding transaction and its complete proof are allocated once. Taking
an entry removes it from stock and records consumed identity/input/output
reservations before candidate construction. Failure, a changed head, cancellation
or an orphan discards that candidate; the resident has no reinsertion path.
Repeated nonce search may reuse only that same immutable candidate body. Every
new preparation obtains fresh input and output randomness, and every native proof
uses its own proof attempt and private salts. A shared public prover workspace
is not a license to reuse a proof attempt, mask, salt or disclosed transaction.
Re-proving or re-salting the same public nullifiers or commitments would still be
linkable and is not stock replenishment.

The consumed table is a bounded in-memory API defense rather than a persistent
global disclosure registry. When an undisclosed template is abandoned and all
its workers have returned, the resident releases only its reservation metadata.
Proofs and witnesses removed from stock are never reinserted. At the first
publication attempt, including an uncertain outcome, its reservations become
permanent until canonical spends absorb them. Neither unused padding stock nor
allocated-proof replay is restored on resident restart.

A stock shortfall identified during pruning can be deferred at most three times
for the same head. The producer refills the reported shortfall before trying
again, even if the pending transaction count suggests the candidate is full.
A consumed reservation limit, invalid slot count or other preparation invariant
fails closed without retrying the producer. The validating node remains
available.

A mining-enabled resident can set `pow_search_threads` in the local configuration.
The value is an integer from 1 through 256. If omitted, it is one fewer than the
OS-provided available parallelism, with a minimum of one and maximum of 256.
The worker pool does not alter process affinity or CPU quota. Workers search
disjoint bounded ranges of the same immutable header seed. A winner cancels the
other lanes; progress includes every actual attempt, including work cancelled
after starting. The coordinator retains one body and checks the parent and local
production policy again before publishing or committing a result.

Native status reports `pow_stall` as `mining_pow_counter_stalled` when an eligible
miner has made no PoW progress for five minutes. The age and episode allow an
observer to deduplicate repeated samples of the same incident. Ordinary sync
and assembly can account for a stall; readiness and the production phase remain
separate observations. Intended pauses, unavailable owner state, and shutdown
reset the observation interval. An independent watchdog logs the incident and
requests cancellation once per episode. The producer retries only after the old
round and its background refill worker have exited and the unpublished template
has been released. It does not retry ambiguous publication or commit failures.
`pow_restart_waiting_for_worker` identifies cancellation that has not finished;
a proof already in progress can delay recovery.

## Measurements

The existing bounded native event stream records qualified and forwarded header
edges with actual run, binary, node and header bindings. These events do not
claim body acceptance or measured clock error. Production records assembly time
from selection of ready positions through fully verified current-parent template
creation, excluding nonce search and prior stock refill. Template events identify
the parent and body commitment; a template's nonce-zero header identity is not a
mined block identity. Existing production, durable acceptance and frame/validation
timings remain separate observations.

Optional body lanes emit one `native-body-fetch-observed` record for every
completed, unavailable or failed download attempt before that lane can close.
The independently allocated connection ordinal and per-connection attempt bind
the record to the actual peer, header ID and body commitment. `fetch_timing`
contains actual process-local query start, completed validated BODY_START control,
chunk completion, decode completion and operation end instants, relative to the
same recorder's monotonic origin. Missing or failed edges remain null. The
BODY_START edge is not a raw socket first-byte measurement. The event wall time
marks recording of the completed attempt; it is not backdated to earlier edges.
Clock offset and uncertainty remain unknown until independently measured. These
records preserve transport/decode evidence separately from full native admission.

Qualification still requires actual participating-process coverage, measured clock
uncertainty, stale-work interruption timing, complete assembly samples and a fixed
fork-rate denominator with induced faults reported separately. No local boundary
test establishes global header latency, a 30-second assembly bound, a fork-rate
result or the resource footprint of a colocated nonmining service. Those results
require the selected final build and actual fleet acceptance.
