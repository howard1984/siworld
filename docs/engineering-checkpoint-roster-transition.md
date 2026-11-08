# Engineering checkpoint authority transition

Status: transition support is implemented; the published engineering release
roster remains the original two-authority roster. No third authority or cutover
sequence is activated by this document or by a network message.

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
Before selecting a cutover, reconcile every authority's real accepted cursor and
all persisted public signing-journal sequence metadata, including prepared votes
not yet combined into certificates. Choose a future cutover strictly greater
than every such sequence, allowing the same reviewed package to be installed
before that interval. An anticipated sequence inferred only from wall time is
insufficient. This support code does not select or activate that value.

Pin the public key and cutover in the release roster, review the exact combined
source and package, and verify all required checks before rollout. Preserve all
legacy certificates, journals, data and peer identities. Checkpoint delivery
qualification is keyed to the complete configured roster commitment; the new
policy requires explicit renewed qualification rather than inheriting an old
roster's pruning authorization. Verify same-chain state and all three pairings
with the exact deployed package before reporting the new roster available.

No genesis, block validity, transaction economics, proof circuit, retention
window or production checkpoint-age policy changes in this transition.
