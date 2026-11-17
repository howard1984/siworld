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
expired transfers cannot publish a body or restart under a fresh deadline for
the same retained candidate. Source accounting identifies configured peer
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

The body-ownership key includes network, genesis, verifier, height and header
identity. Legacy, piece and fallback paths share one query ceiling and the
original absolute deadline. Failed or reconnected sources do not acquire a new
attempt. A healthy slow stream is not preempted solely because it exceeds the
handoff interval. Native admission cannot be preempted. Durable canonical
acceptance marks the exact account terminal; its actual I/O slot remains held
until the last actual owner releases it.
The registry separates 32 actual I/O owner slots from a bounded exact-account
book. Releasing an I/O owner does not refund its source attempts or queries.
The book retains at most the original 2,048 header accounts. The original
1,024-query ceiling also applies to cold bootstrap before a resident window
exists. The first resident window inherits those consumed queries; only lawful
renewal by the original discovery ledger resets the aggregate count. Account
and pin allocations are charged before insertion. Original discovery-window renewal may
retire expired accounts only after all candidate pins and actual owners release
them. Bootstrap acquisition uses its selected operation's original end instead
of creating a discovery window. Reconnection, mode changes and candidate-cache
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
match the opposite local role. The policy selects only from the original pinned
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
