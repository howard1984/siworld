# Authenticated body transfer

The engineering version 2 header commits to the canonical body with BLAKE3 in
derive-key mode using context `siworld eng2 canonical block body v1`. Its input
is the eight-byte little-endian canonical body length followed by the canonical
body. The header does not contain a transaction identifier Merkle root.

The transfer primitives preserve that exact commitment. They do not change the
header, canonical body, transaction relation, settlement relation, state
transition, work accounting, or fork selection. The resident body lane negotiates
support and uses the existing authenticated channel and port. Native admission
remains mandatory after transfer.

## Subtree descriptor

Split the original BLAKE3 input into 4,096-byte pieces. Each piece is an aligned
subtree of four BLAKE3 chunks. Only the last piece can be short. The descriptor
contains the body length and the non-root chaining value of each piece, in
input order. The descriptor length must equal the count derived from the
bounded body length; trailing or missing chaining values are invalid.

Reconstruct the standard BLAKE3 tree using the largest power of two strictly
smaller than the number of subtrees for each left branch. Internal merges use
derive-key-material mode with the context key obtained only through BLAKE3's
context-hashing operation. Only the top merge uses root finalization. Compare
the resulting root to the existing header body commitment.

The first piece is mandatory during descriptor authentication. Its first eight
bytes must equal the advertised body length. Verify that piece's chaining
value before exposing its bytes or authenticating the descriptor. For an input
contained in one piece, check the original complete root hash directly, since
root output cannot be reconstructed from a single non-root chaining value.

For every subsequent piece, require its exact index, exact expected length and
non-root chaining value. Hash it at input offset `index * 4096`, including the
original eight-byte length prefix only at index zero. The authenticated body
range excludes that prefix. An authenticated range is bound to the exact header
identity; it cannot be reused as an authorization for a different block.

## Admission and resource invariants

Before decoding any descriptor, bound its wire bytes, claimed body length,
subtree count and allocation against the existing global and authenticated-peer
budgets. Charge descriptors, framing, failed responses, repeated responses and
payloads. The transfer scheduler must reserve the body allocation once and
retain its reservation through native admission. A peer-supplied transaction
boundary or length grants no allocation or proof execution authority.

Use one absolute deadline from the initial transfer admission through every
request, retry, piece, assembly and admission step. Progress does not renew it.
Count retries against the same finite request and byte ceilings. Cancelled or
expired transfers cannot publish a body. Resident retry policy may later open a
new exact account after every owner and pin releases the expired one; it never
extends the expired account's deadline. Source accounting identifies configured peer
identities and byte counts; it excludes endpoints and transaction observations.

One source attempt is a two-phase exchange on one authenticated connection:
request and authenticate the descriptor and index pieces, then send the missing
piece runs and consume their bounded response stream. The descriptor source's
second phase retains the same attempt sequence. Its entire allowed wire budget
is reserved before the first phase, including both queries, descriptor, index
pieces, run indices, piece payloads and all framing. There is at most one second
phase. A failed descriptor consumes the source's only attempt and cannot be
continued or restarted. Other sources each receive one bounded piece-run query.
All phases share the original deadline. At most four source attempts and one
attempt per configured peer are permitted for one retained candidate.
Record source attempts and actual query messages separately: the successful
descriptor source may send two queries in its one attempt. Independently enforce
at most four actual application query messages, including every descriptor,
continuation and other source's batch. A continuation can therefore reduce the
remaining available source count. Neither counter excludes a failed descriptor,
failed batch or continuation failure. The fifth actual query is rejected before
wire reservation or transmission, even if fewer than four sources were used.

An authenticated piece establishes byte membership only. It does not establish
canonical framing, transaction proof validity, settlement proof validity or
state transition validity. Decode the complete assembled canonical body and
use the existing `accept_received` and `Store::append` path. Work cannot be
credited before complete native acceptance. A reorganization must retain exact
block identity and parent context checks during final admission.

The envelope-reuse helper requires the entire locally verified envelope to match
byte for byte, preserve its existing verification qualifications, and authenticate the
reconstructed transfer piece against the descriptor. No public request may
query private transaction identifiers. Transfer scheduling must not expose
Dandelion stem contents, first-observed transaction times or individual fees.
The resident adapter currently has no production caller of this reuse helper;
complete transaction-pool envelope reuse is not implemented by this adapter.

## Resident scheduling and verification

Metadata, continuation and piece batches use the current socket turn's request
identifier. The candidate's internal query sequence remains separate and bounded
by four. Each turn performs one exchange and echoes its outer request in
`RoundDone`. There is no unsolicited body stream. Four shared candidate slots
retain their ownership claim, assembly, download cancellation and original memory
reservations. Workers release the transfer mutex before socket I/O. A completed
body and its claim move together into the existing admission queue. Cancellation
keeps the claim until every actual I/O owner releases it.

The distinct public genesis profile negotiates propagation capability version 2.
The legacy profile retains capability version 1 and its metadata/continuation
exchange. The authenticated session binds the capability to the genesis and
verifier; a version-1 response cannot enable streaming in a version-2 session.

In version 2, a qualified fixed miner offer grants one bounded credit for the
descriptor, piece zero and the ordered remaining pieces. Metadata declares only
piece zero. The receiver authenticates its length and descriptor against the
header commitment, installs the candidate in the shared registry, then checks
each remaining piece before installation. The entire credited stream consumes
one application query and retains the original deadline. After two seconds without
an authenticated piece, or eight seconds of streaming, the receiver can pull
missing tail pieces in parallel from configured peers with live, session-bound
evidence of the exact branch. These pulls use the same transfer and query budget;
the push counts toward the three-lane limit. Parallel pulls receive mutually
disjoint assignments. The ordered push can overlap a pull: every response is
independently charged and authenticated, and only the first copy contributes
unique authenticated body bytes. Completion interrupts redundant reads without
cancelling the body owner or downstream forwarding. Malformed responses retain
partial byte charges and cannot install unauthenticated bytes.

Version-2 miners can require exactly three dialable, independently pinned
services with `require_three_direct_push_targets: true` and three peers tagged
`fixed_relay_role: "service"`. Each service selects the reciprocal pinned
miner. A miner prioritizes these connections within its worker limit and tries
its local direct push before issuing body pulls on each selected lane. Per-destination `native-miner-direct-push` observations show
declared body size, sent application bytes and the outcome. `body_sent` means
the local send finished; the receiver's native acceptance is recorded separately.
No send is guaranteed for a disconnected peer or an exhausted relay quota.
Configuration validation counts selected peers and requires all dialable routes
to fit within the connection limit. Deployment must verify that the three peers
are the intended service roster.

A version-2 service may explicitly configure another independently pinned
service with `fixed_relay_role: "service"`. Miner and service selections remain
distinct and the authenticated remote role must match the selected category.
An active candidate can be offered once to each selected service. Forwarding
exports its authenticated descriptor and complete pieces only. The sender copies
one bounded piece at a time under the shared memory budget, releases the transfer
mutex before socket I/O, and waits for missing pieces within the original
candidate deadline. Receiver credit and the existing fixed-peer wire fences
bound every forwarding exchange. Neither a partial service relay nor completion
of its stream changes full decode, native verification or admission requirements.
Forwarding retains a shared reference to the authenticated encoded buffer,
independently of the local candidate owner. Local completion transfers the
decoded-body reservation into full native verification and admission while
downstreams retain the single encoded allocation. A slow downstream does not
hold the local admission claim or delay submission to native verification.
The original candidate deadline bounds the remaining forwarding exchange.

The body-ownership key includes network, genesis, verifier, height and header
identity. Legacy, piece and fallback paths share one query ceiling and the
original absolute deadline. Failed or reconnected sources consume another
attempt and query within the same finite account limits. Failed piece I/O selects
whole-body fallback for that exact account and its subsequent reopenings.
A healthy slow stream is not preempted solely because it exceeds the
handoff interval. Native admission cannot be preempted. Durable canonical
acceptance marks the exact account terminal; its actual I/O slot remains held
until the last actual owner releases it.
The registry separates 32 actual I/O owner slots from a bounded exact-account
book. Releasing an I/O owner does not refund its source attempts or queries.
The book retains at most the original 2,048 header accounts. The original
1,024-query ceiling also applies to cold bootstrap before a resident window
exists. The first resident window inherits those consumed queries; only lawful
renewal by the original discovery ledger resets the aggregate count. Account
and pin allocations are charged before insertion. An expired nonterminal resident
account may reopen only after all candidate pins and actual owners release it.
Successive reopenings wait 15, 30, 60 and then 120 seconds after expiry, with at
most eight reopenings per exact block in a rolling hour. Each new account has at
most 180 seconds and fresh source-attempt accounting; the resident window's
consumed queries and wire bytes remain charged. Reopening history survives a
discovery-window rollover. Canonical acceptance remains terminal within the
retained lifecycle. Original discovery-window renewal may retire expired
accounts only after their owners, pins and recent reopening history are gone.
Bootstrap acquisition uses its selected operation's original end and cannot use
this resident retry policy. Reconnection, mode changes and candidate-cache
eviction cannot reset an existing account. A closed operation cannot publish
progress, queue a body or write the quarantine cache. Successful quarantine
storage completes transport ownership but grants no native admission authority.

The owner captures an immutable validation context before metadata I/O. It binds
the candidate to its parent, genesis, protocol profile, rules and snapshot state.
Authenticated ranges can start bounded native proof work before the entire body
arrives. At transfer completion, receipt collection takes a nonblocking snapshot
of completed work and closes further speculation; it does not wait for missing
proofs on the body socket. Early and final native decoders share four permits.
Final batches acquire their capacity before using the existing Rayon pool.
Speculative worker stacks are charged to the original memory budget.

A typed receipt binds exact proof bytes, public statement and owner context.
Cancellation, parent replacement, errors and reorganization barriers invalidate
the old context. Every missing or unusable receipt falls back to the original
final verifier. Full state transition and settlement checks remain required.
Neither an authenticated piece nor an early receipt grants block acceptance,
checkpoint signing authority or canonical work.

Fixed relay is disabled unless an existing pinned peer has an explicit
`fixed_relay_role` of `miner` or `service`. The authenticated remote role must
match the opposite local role on version 1; version 2 additionally permits the
explicit service-to-service selection above. The policy selects only from the original pinned
peer set. A service can retain an inbound-only fixed miner identity alongside
an existing destination with the same endpoint reference. Entries with `dial`
set to false are excluded from both ordinary and optional lane dialing. Original
rate reservations persist across metadata and continuation;
failed operations do not refund them. Per-frame wire checks run before socket
writes or payload allocations, and actual partial bytes remain counted. These
are application-stream byte counts; underlying TLS record formatting is not
measured. Transaction dissemination and Dandelion behavior are unchanged.

The existing bounded block-event ring records production, qualified headers,
transfer stages, configured peer fingerprints and per-source query/byte counters.
Piece transfers preserve source counters on metadata failure, decode, cancellation
and exhaustion. A complete canonical decode also creates the typed frame identity
used by the existing native admission observer. These diagnostics do not imply
acceptance. The ring retains its original four 1 MiB segments and 2,048-byte record
limit. Missing or overwritten evidence remains unknown; cross-host propagation
time requires independently established clock uncertainty.

## Validation scope

Unit tests compare subtree reconstruction against the unchanged complete
header hasher around BLAKE3 block, chunk, piece and tree boundaries. Corruption,
length substitutions, wrong roots, wrong indices and invalid bounds must fail
closed. Transfer authentication alone provides no measurement of real network
propagation or native proof verification latency.
