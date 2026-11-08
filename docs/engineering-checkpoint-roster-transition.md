# Engineering checkpoint authority transition

Status: release-pinned scheduling and native transition admission are
implemented. The compiled roster schedules a transition by its first sequence.
Deployment and live acceptance remain separate operational prerequisites.
The transition begins at sequence `83065`, corresponding to
`2026-11-09T06:00:00Z` for the six-hour engineering interval. Earlier sequences
retain the original two-authority roster and digest.

## Trust policy and compatibility

The original two public keys, binding and version-one roster digest remain
unchanged. A release may additionally pin one distinct nonzero ML-DSA-65 public
key and a nonzero first sequence for the three-authority roster. Its version-two
roster commitment binds the legacy roster digest, exact cutover sequence, two
required signatures, three members, and the third key. Keys and activation are
compiled trust policy; certificates and peers cannot install or modify them.

Statements below the cutover require the exact original roster digest and
signers zero and one. Statements at or above it require the new roster digest
and exactly two authorized, distinct signer indexes in ascending order. The
valid pairs are zero/one, zero/two and one/two. The statement and two-signature
certificate encodings are unchanged. An old binary rejects the new roster; it
cannot silently treat a new certificate as a legacy certificate.

Historical legacy certificates remain authenticatable for an existing saved
cursor or a historical checkpoint. Every Store admission also applies its
persisted sequence/height/digest cursor, so a new-roster acceptance cannot be
rolled back to a legacy certificate. Fresh bootstrap still independently
reconstructs permanent state and fully verifies its proof tail. The candidate
summary, cached reissue and local signing paths all choose the release-pinned
roster for the statement sequence. Roster authentication alone never changes
chain state, permits proof deletion, or substitutes for state validation.

## Coordination and persisted votes

Before the cutover the original leader-zero/countersigner-one behavior remains.
After the cutover any surviving pair can form a certificate from the same
independently reconstructed local statement. Proposal creation is staggered by
public index: index zero may propose at the publication boundary, index one
after sixty seconds, and index two after one hundred twenty seconds. Any other
authorized signer can countersign an authenticated proposal immediately after
its independent canonical-state match. The publication schedule remains six
hours; the issue time remains that interval's boundary.

A countersigner sorts the two distinct votes before admission. An authority
recovers its existing public vote from the write-once journal after a restart,
validates it against the pinned roster and advertises that same vote. It never
overrides a protected sequence to change a height, state, issue time or roster.
The durable acceptance cursor also constrains signing before any journal write:
an authority with no previous vote cannot sign an older sequence, a lower height,
or a different statement at an already accepted sequence. Signing the identical
accepted statement remains idempotent. Queued proposals superseded by a newly
accepted certificate are retired before countersigning.
Conflicting proposals preserve the original vote, raise an alert and leave
ordinary block validation running. Different local chain views can therefore
prevent a publication for that interval; this mechanism does not claim general
Byzantine agreement or guaranteed availability under inconsistent local views.
A later interval may proceed once independent canonical views agree.

## Activation prerequisites

Generate the third engineering test key only on its authorized origin. Collect
only its public key through the reviewed transport; private bytes remain there.
The fully measured selection route reconciles every authority's real accepted
cursor and all authenticated public signing journals, including prepared votes
not yet combined into certificates. Its future cutover must exceed every such
sequence and leave enough time for reviewed source, required CI, matching
packages, distribution and sequential rollout.

A conditional selection route may preserve an unknown Miner accepted cursor
and journal inventory while using the authenticated complete journals of both
original authorities to bound the legacy quorum's emitted votes. This route
also requires reviewed original-key custody and signing-source evidence and a
registered third key from an exclusive initialization. The reviewed origin
operation generated that key, made no signing requests and did not adopt or
enroll it; its authority-subdirectory inventory was complete at registration.
These scoped facts do not establish complete inventory of the enclosing root
or absolute historical nonuse. Explicit remaining build and rollout allowances,
clock tolerance and native admission on all three actual nodes are required.
The route does not establish an all-authority sequence floor, cursor zero,
historical absence or complete Miner writer lineage. Wall time alone cannot
bound signed sequences. Long-running acceptance exercises remain separate from
maintenance and release scheduling; their evidence is required before claiming
those acceptance results.

Each node must pass `checkpoint-transition-check` after any required one-time
restart qualification and immediately before its own proof deletion, key
adoption, configuration activation or service start. The command authenticates
its actual accepted certificate and all local public signing journals under the
final compiled roster; every sequence must be below the cutover. Malformed,
foreign, conflicting, unauthenticated or out-of-range evidence rejects admission
and preserves the records. A reached boundary requires reconciliation. All
three nodes must pass before transition completion is reported; their stops
and admissions may occur sequentially.

Pin the public key and cutover in the release roster, review the exact combined
source and package, and verify all required checks before rollout. Preserve all
legacy certificates, journals, data and peer identities. Checkpoint delivery
qualification is keyed to the complete configured roster commitment; the new
policy requires explicit renewed qualification rather than inheriting an old
roster's pruning authorization. Verify same-chain state and all three pairings
with the exact deployed package before reporting the new roster available.

No genesis, block validity, transaction economics, proof circuit, retention
window or production checkpoint-age policy changes in this transition.

## Offline transition admission

`checkpoint-transition-check DIRECTORY --json` checks the actual local data
before the compiled transition's first interval. It requires the exclusive
service lease and an existing authenticated restart record at the exact committed
head. A legacy database must complete its separately authorized qualification
before this command; the command never performs qualification or proof replay.

The command authenticates the database's actual accepted certificate under the
compiled roster and checks its confirmed canonical block and saved state
fingerprint. An absent certificate is reported only after reading the actual
table and accepted row. The command also inventories every local public vote
journal, verifies its exact filename, record shape, binding, pinned signer and
signature, and computes a BLAKE3 inventory digest. It does not open or hash an
authority secret. Both the accepted sequence and every journal sequence must
be strictly below the compiled first sequence. Malformed, foreign, conflicting
or out-of-range evidence fails without replacing or clearing any record.

A missing compiled transition, active service, missing or stale restart record,
backward clock movement, or a boundary reached before completion rejects
admission. The JSON includes the exact head, state fingerprint, work, receipt
count, accepted cursor or authenticated absence, journal count and maximum,
inventory digest, compiled first sequence, and start/completion times. Both
proof-audit flags remain false. A successful check changes no logical database,
certificate, journal, retention policy or enrollment state; the existing lease
file is used for exclusion. The existing redb open path may update physical
header or allocator bookkeeping; whole-file byte identity is not an invariant.

Run this command after any required one-time restart qualification and before
proof deletion, authority adoption, configuration activation or service start.
Operational admission must also check that the same verified package and
compiled cutover are installed everywhere with enough remaining rollout time.
Failure requires reconciliation; it does not authorize rewriting history.
Normal `restart-check` remains available after the transition and is separate
from this first-deployment gate.
