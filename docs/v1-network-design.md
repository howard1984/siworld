# Native V1 Transport and Checkpoint Design

Status: selected engineering design for the independent, resettable V1 network.
These mechanisms require implementation, adversarial testing and independent
review. They are not cryptographic approval or authorization to start a network.
The retained seven-node network, its identities, keys and history are unchanged.

## Authenticated hybrid transport

V1 wallet-to-relay and node-to-node connections use one versioned libp2p
upgrade with ephemeral X25519 and ML-KEM-768. Both contributions are required.
Legacy Noise is not an alternative after negotiation failure; unsupported V1
peers disconnect with a bounded error. Public bootstrap discovery does not
authorize sending transactions or fee sidecars over an unauthenticated channel.

Use Ed25519 and ML-DSA-65 identity keys. Each participant signs the canonical
identity descriptor and handshake transcript with both keys; both signatures
must verify. Bind both public keys, network/genesis identity, protocol version,
offered and selected algorithms, initiator/responder roles, fresh session
material and the complete ordered transcript. Exclude ambiguous encodings.

Persist the hybrid identity descriptor and authenticate its distribution.
libp2p's classical PeerId is a routing identifier, not a replacement for the
post-quantum identity. A descriptor received from the same untrusted connection
does not establish continuity with a previously trusted identity. Pin the hybrid
descriptor for known peers; authenticate descriptor updates and fail closed on
unexpected key changes. A new self-certified peer is not thereby trustworthy.
Identity rotation and revocation require reviewed, versioned signed records.

Select a published, reviewed hybrid combiner and maintained implementation after
dependency review. Freeze its exact construction, KDF/hash, domain separation,
transcript encoding, library revisions and test vectors before implementation
acceptance. Do not replace that review with an ad hoc concatenation or XOR rule.
The selected combiner must retain confidentiality under its documented hybrid
assumptions if one key-establishment contribution is compromised.

Require bidirectional key confirmation before application streams open.
Authentication and confirmation cover the final transcript and negotiated
record layer. Fresh ephemeral keys and session nonces prevent replay between
connections. Destroy ephemeral private material and temporary shared secrets
after deriving traffic keys; prohibit secret serialization and secret logging.
Specify authenticated record sequencing, nonce limits, rekeying, truncation and
close behavior with the selected implementation. Decapsulation/confirmation
errors expose one generic wire failure; detailed local classes contain no keys,
network addresses, individual fees or transaction/time associations.

ML-KEM-768 uses 1,184-byte encapsulation keys and 1,088-byte ciphertexts.
ML-DSA-65 uses 1,952-byte public keys and 3,309-byte signatures; Ed25519 adds
32-byte public keys and 64-byte signatures. Two identity descriptors with both
signatures plus one KEM exchange and two X25519 public keys already require
approximately 13 KiB before framing and negotiation metadata. Certificate chains
are outside the initial format. Do not reuse classical Noise size assumptions.

Initial engineering limits are 16 KiB per frame, 32 KiB aggregate handshake
wire bytes, a five-second wall deadline and 16 concurrent unfinished handshakes.
Reserve 256 KiB of owned handshake state per connection and 4 MiB globally
before reading bodies. Apply a global admission rate and bounded per-source
rate buckets before signature/KEM work; select rates using measured CPU costs.
The wire and owned-byte limits are not RSS bounds. Measure both successful and
malformed-handshake charged memory, CPU and cleanup; adjust the documented
limits before launch if the reviewed implementation cannot satisfy them.
Do not penalize a peer for local admission exhaustion or clock/watchdog delay.

## Source-hiding relay

Select Dandelion++ for the initial engineering implementation. Run its stem and
fluff phases exclusively over authenticated hybrid peers. Maintain diversity
across independently operated hosts; multiple peers on one host are not
independent relay choices. Relays do not receive wallet spend secrets.

Use a reviewed Dandelion++ algorithm rather than describing an arbitrary relay
chain as equivalent. Pin the routing-epoch rule, stem/fluff selection probability,
embargo distribution, loop behavior and failure recovery in a protocol profile.
Those values remain experimental until simulation and real-listener tests
demonstrate bounded delay and resource use under the expected peer population.
Fluff fallback follows only the reviewed embargo and route-failure policy;
it must not become an unbounded direct-broadcast retry path. No fallback may
use classical transport. Explicit failure may leave a transaction temporarily
unavailable.

Stem queues, embargo queues, deduplication and retry state share the existing
global/per-peer transaction byte limits. Reserve bytes before retaining a proof
or sidecar; timers do not permit extra copies. Bound fanout, pending timers,
in-flight stream bytes and retries independently. Reconnect, absent routes and
loop detection must release reservations and avoid uncontrolled fluff storms.
Diagnostics expose aggregate classes and bounded opaque peer handles only.

Hybrid encryption prevents later decryption of recorded link content under its
assumptions. It does not conceal connection endpoints. Dandelion++ reduces
certain source-correlation opportunities; it does not guarantee anonymity against
a malicious first hop, colluding relays, endpoint compromise, broad Sybil control
or a global timing observer. Evaluation must report these limits explicitly.

Fee-opening sidecars disclose fees to their recipients. A recipient can identify
a zero opening despite the commitment's on-chain hiding. Dandelion++ and hybrid
encryption do not remove that disclosure. Keep sidecars off public endpoints and
logs; model malicious sidecar recipients as a separate privacy adversary.
An unchanged sidecar design must not be described as hiding real/padding classes
from every participating relay. Review this boundary before network launch.

## Explicit-trust checkpoint bootstrap

The default V1 new-node synchronization path uses a confirmed checkpoint
distributed with the release plus verified PoW. Checkpoints are signed by two
of three designated, independently operated authorities. The operator must
explicitly accept that roster and trust mode before installation. Pin the
roster, threshold and hybrid authority keys in the independent network's
genesis configuration. Do not create production
keys or a formal genesis as part of this document change. Roster changes require
a separate authenticated policy; a downloaded checkpoint cannot choose its keys.

Each authority signature includes ML-DSA-65; use the same dual-signature identity
binding policy as transport. Verify two distinct roster identities and their
signatures over one identical canonical manifest. A quorum is an operational
trust policy, not a proof that omitted historical transactions were valid.

The canonical manifest binds format, network/genesis, checkpoint height and
block identity, cumulative work, accepted-state commitments, trusted verifier
manifest, payload length/content digest, snapshot-window digest and expiry.
Export the exact canonical state needed by the forward transition: public note
state, nullifier state, commitment/root trees and all required metadata. Include
the newest 4,096 canonical snapshot selectors and their authenticated roots,
or the complete shorter prefix near genesis. Bind all payload chunks and their
ordering. Check completeness, canonical encoding and derived commitments before
atomic installation. Never import private fee openings or wallet secrets.

Authorities sign only a checkpoint at least 24 blocks below their independently
validated canonical tip. Their policy persists signed height/hash history and
forbids signing conflicting ancestry. Export only after crash-consistent state
and finality checks. A checkpoint becomes the bootstrap node's immutable
finalized base; it cannot authorize a rollback of already accepted history.

Publish a confirmed checkpoint at least every six hours, within the service
proof-retention window, with a signed expiry no longer than 24 hours. Expiry is a local availability policy, not consensus time.
Uncertain clocks, expired manifests, missing payload chunks or an insufficient
quorum fail closed. Binary releases pin the authority/network/verifier policy
and an initial confirmed checkpoint, not an assumption that an old bundled
checkpoint can always replay to the tip. When its required proof tail has
expired, fetch a fresh checkpoint under that pinned policy or stop bootstrap.
Checkpoint publication does not require a new binary release. An otherwise valid signature set does not establish that
the checkpoint is the newest available checkpoint. State this limitation in
bootstrap UI and require explicit trust acknowledgment before installation.

Reject wrong-network, wrong-verifier, malformed, stale-to-local-state and
conflicting manifests. Persist observed authority equivocation evidence and
halt automatic checkpoint selection on incompatible quorum-signed ancestry.
Do not select a conflict merely because it advertises greater cumulative work.
A two-of-three rule is not Byzantine-consensus safety: a malicious overlapping
signer plus divergent honest signers can produce incompatible quorums. A common
malicious quorum can certify invalid history. Detection cannot undo that trust.

Validate header rules and work from a trusted network anchor and authenticate
the checkpoint payload, but do not treat fetched headers as proof of deleted
transaction validity or checkpoint canonicality. Validate every later block and
its native transaction/settlement proofs with the shared state transition.
Reorganizations cannot cross the trusted finalized base; they require explicit
recovery rather than silent replacement. Do not erase old accepted state before
the replacement has been fully validated and an operator authorizes recovery.

Full replay from genesis using complete historical transaction and settlement
proofs is deferred to a future optional proof archive or V2 history-compression
upgrade. V1 has no archive-node role and does not offer that replay capability
after proofs expire. Multiple unauthenticated peers or matching roots do not
replace the explicit checkpoint trust assumption. Report the release-checkpoint
synchronization mode and trust basis on the dashboard.

## Acceptance tests

| Area | Required cases |
| --- | --- |
| Identity | Either signature invalid/missing; PQ-key substitution; PeerId match with wrong hybrid descriptor; rotation and revocation |
| Handshake | Actual TCP listeners; wrong network/role/version; algorithm stripping; transcript mutation; KEM failure; confirmation failure; replay |
| Cleanup | Half-open sockets; fragmented/oversized frames; slow readers; timeout/reconnect; concurrency/rate exhaustion; secret and reservation cleanup |
| Relay | Stem/fluff success; route rotation; loops; malicious withholding; first-hop loss; partition/reconnect; duplicate storms; bounded timers/bytes |
| Privacy | Endpoint visibility; colluding peers; timing correlation; fee-sidecar recipients; no address/fee/nullifier-time logs |
| Checkpoint | Zero/one/duplicate authorities; wrong roster; either identity signature invalid; wrong network/verifier/work/state/window; incomplete chunks |
| Freshness | Expiry; uncertain clock; older than local accepted state; conflicting quorum ancestry; authority equivocation; no automatic rollback |
| Synchronization | Release-checkpoint bootstrap; short genesis window; later block rejection; 23/24/25-depth forks; missing/corrupt public segments; pre-checkpoint wallet ciphertext recovery |

## Effort and sequencing

N5's original 6–10 engineering days assumed an unresolved authentication profile.
Budget an additional 4–7 engineering days for dual identities, descriptor
distribution/rotation, ML-DSA integration, transcript vectors and admission
profiling. The revised N5 estimate is 10–17 days, excluding independent review
and possible hybrid-library changes. Do not count that increment twice.
N6 remains 5–8 days for the initial Dandelion++ path; adversarial evaluation can
extend it. N4 remains 4–7 days if checkpoint authorities and infrastructure
for permanent public-data backups are supplied. Authority deployment, secure
custody and operator procedures are additional infrastructure work. Review the combiner and identity design before
freezing the transport profile. No testnet starts until the privacy, checkpoint
and full-network acceptance gates pass.
