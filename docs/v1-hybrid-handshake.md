# Proposed Native V1 Hybrid Handshake Profile

Status: proposed composition for cryptographic and dependency review. This is
not an adopted standard, an enabled transport, or network acceptance evidence.
The identity module supplies private key custody and dual-signed descriptors;
it does not supply this handshake. Do not create an authenticated application
channel until the complete reviewed provider and acceptance tests exist.

## Unresolved Noise construction

The native libp2p transport requirement includes X25519 plus ML-KEM-768 in the
authenticated key-exchange transcript and requires both Ed25519 and ML-DSA-65
identity signatures. The TLS construction below is a composition proposal,
not an implementation of a hybrid Noise handshake. The transport construction,
key schedule, transcript encoding and wire profile remain unreviewed and must
be resolved before native networking is enabled.

The retained workspace locks `libp2p-noise` 0.47.0 and `snow` 0.10.0. The
libp2p Noise configuration fixes `Noise_XX_25519_ChaChaPoly_SHA256`; its prologue
interface only commits public context to that handshake. Adding an ML-KEM
public key or ciphertext to a prologue does not mix the KEM shared secret into
the chaining key or traffic keys. Hybrid Noise integration therefore requires
a reviewed KEM-capable construction and provider, including dependency changes
if necessary. Do not implement an ad hoc combiner, relabel the TLS proposal as
Noise, or accept classical Noise as a native fallback. The retained network is
a separate protocol and is unchanged by this requirement.

## Construction and review boundary

Use a maintained TLS 1.3 implementation with the X25519MLKEM768 group from
[RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html) and the TLS protocol
specified by [RFC 9846](https://www.rfc-editor.org/info/rfc9846/).
Require `TLS_CHACHA20_POLY1305_SHA256` and exactly X25519MLKEM768. The latter
encodes the ML-KEM contribution before X25519: client share 1,216 bytes,
server share 1,120 bytes and combined secret 64 bytes. An all-zero X25519
result must abort. The provider performs the standard TLS key schedule;
SIWORLD must not implement a second hybrid combiner, concatenate traffic keys,
XOR secrets, or derive application keys directly from either component.

The rationale is reuse of a published hybrid exchange with the TLS
HKDF-SHA256 schedule, bidirectional Finished verification and maintained record
protection. The exact security assumptions and error handling still require
review of the selected implementation. TLS authentication with only Ed25519
does not meet the V1 dual-identity requirement. The additional exporter-bound
authentication described below is a SIWORLD proposal; the TLS RFCs do not
approve its composition, its pin-distribution policy or its implementation.

Candidate dependency selection must demonstrate the exact hybrid group, strict
key checks, exporter API, record limits, key erasure and cancellation behavior.
Pin the library, cryptographic provider and all transitive revisions, collect
advisories/licenses and reproduce known-answer vectors before adoption. If no
reviewable implementation fits the resource caps, revise the proposal and
measure it; do not silently substitute a custom exchange or classical group.

## TLS restrictions

Use an exclusive libp2p upgrade name `/siworld/native-hybrid/1` and the identical
ALPN value. Require TLS 1.3 on the first connection attempt. Offer no legacy
Noise upgrade, plaintext alternative, older TLS version or classical-only
group. Reject a different selected group, cipher suite, ALPN or version.
The upgrade must not retry under weaker parameters after any failure.

Disable PSKs, session tickets/resumption, 0-RTT, renegotiation and post-handshake
identity authentication. Every connection establishes fresh X25519 and ML-KEM
material. The initiator generates the ephemeral ML-KEM key pair; the responder
encapsulates once. Both generate fresh X25519 keys and independent connection
nonces. ML-KEM decapsulation or TLS Finished failures use one generic wire
failure. Neither branch may continue using just the other shared secret.

Require mutual Ed25519 TLS authentication with one bounded self-signed leaf
certificate per endpoint and no downloaded chain. A dedicated verifier pins
the exact Ed25519 public key from the independently authenticated dual identity;
it verifies TLS CertificateVerify and the required certificate constraints.
It is not an accept-all certificate verifier. Network identity does not depend
on public web PKI names or fetching OCSP/AIA material. The certificate template,
DER bound, validity policy and strict SPKI parsing must be specified and tested
with the selected TLS implementation before enabling this proposal.
The current compact pin file stores a fingerprint, not the full public keys;
the future provider must also load and verify the corresponding public
descriptor before dialing or accepting. A pin file alone is insufficient TLS
configuration, and a descriptor supplied by an unauthenticated connection must
not fill that gap.

## Mandatory dual-identity authentication

Only the following authentication messages may cross the protected TLS channel
until both endpoints finish this stage. They are never sent in plaintext.
TLS Finished must already have verified in both directions. Obtain 32 bytes
from the TLS exporter with label `EXPORTER-SIWORLD-native-dual-auth-v1` and
context equal to the canonical 96-byte network/genesis/verifier binding. The
exporter is derived from the completed TLS handshake; do not use an early
exporter or a channel binding supplied by the remote peer.

The operator or an authenticated discovery policy supplies the expected full
descriptor fingerprint for each endpoint. A classical PeerId, DNS name or a
self-signed descriptor received on this connection is not that policy. Reject
unknown or changed pins in this initial profile. A future permissionless peer
discovery and pin-rotation policy requires a separate review.

Every message has this exact 11-byte header: magic `SWHH`, little-endian u16
version 1, u8 message kind and little-endian u32 payload length. No extension,
padding, duplicate or trailing byte is allowed at this layer. TLS itself may
fragment a message. A frame length is checked before any allocation or body
read. Connection initiator/responder roles are separate from a node's mining
or validation role.

Messages must occur in this order:

| Kind | Sender | Payload bytes | Payload |
| --- | --- | ---: | --- |
| 1 | Initiator | 5,532 | Initiator hello |
| 2 | Responder | 5,532 | Responder hello |
| 3 | Initiator | 3,373 | Ed25519 signature then ML-DSA-65 signature |
| 4 | Responder | 3,373 | Ed25519 signature then ML-DSA-65 signature |
| 5 | Initiator | 32 | Transcript hash before this ready message |
| 6 | Responder | 32 | Transcript hash before this ready message |

A hello contains four little-endian u16 values (profile 1, TLS version
`0x0304`, group `0x11ec`, cipher `0x1303`), u8 connection role (1 or 2), a
nonzero 32-byte fresh nonce, the expected remote fingerprint (32 bytes), and
the 5,459-byte descriptor from [the identity format](v1-native-identity.md).
Both descriptors must verify both possession signatures, match the trusted
network/genesis/verifier binding and match the expected local and remote pins.
The two endpoints and the two nonces must be distinct. The negotiated TLS
parameters must match the hello tuple exactly; a peer cannot choose algorithms
by changing these application fields.

Start SHA-256 with the bytes `siworld native hybrid transcript v1`, a zero byte,
the trusted 96-byte binding, initiator fingerprint, responder fingerprint and
the 32-byte local TLS exporter output. Append every exact header and payload
in the stated order. Transport fragmentation does not enter this transcript.
The exporter commits to the TLS handshake context and exchanged ephemeral
material; the application transcript additionally commits to both descriptors,
expected pins, offered/selected fixed suite, connection roles and fresh nonces.

For kind 3 or 4, both signatures cover the bytes
`siworld native hybrid authentication v1`, a zero byte, the u8 sender role and
the SHA-256 transcript hash immediately before that message. ML-DSA uses context
`siworld native hybrid v1`. Strict Ed25519 and ML-DSA-65 verification are both
required against the sender's pinned descriptor. Kind 4 therefore covers kind 3
as well as both hellos. Each signature covers the complete ordered prefix;
neither signs its own bytes. Descriptor possession signatures cannot substitute
for these fresh channel-bound authentication signatures.

Verify a signature message before appending it to the accepted transcript.
After both authentication messages verify, exchange kinds 5 and 6 inside the
TLS channel and compare their exact transcript hashes before appending them.
These acknowledgments, together with bidirectional TLS Finished, confirm the
authenticated endpoint's view of the completed binding. Missing, reordered,
replayed or incorrect acknowledgments close the channel. Only then can the
provider construct the existing crate-private `Authenticated` capability and
open native protocol streams. Neither the parser nor a transcript-shape helper
can create that capability.

## Records, limits and cleanup

The TLS implementation owns record authentication, sequence numbers, nonce
construction and key updates. Application code must not select nonces or reset
record sequence counters. Corrupt records, sequence exhaustion, truncation,
unexpected close and missing `close_notify` produce a failed session; a partial
native frame is never committed as a request. A new connection starts a fresh
handshake. No sidecar or transaction is accepted before authentication.

Proposed operational limits are a TLS plaintext fragment limit of 8 KiB, at
most 8 KiB of TLS handshake wire bytes, at most 16 KiB for an authentication
frame, at most 32 KiB of total pre-admission wire bytes and one five-second
monotonic deadline from accepted/dialed socket to both ready messages. The six
application frames total 17,940 plaintext bytes; the remaining wire budget
must include TLS record headers, tags, certificates, alerts and fragmentation.
The TLS budget is a measured bound, not an assumption that every provider's
default buffering satisfies it. Close on excessive fragmentation or budget
exhaustion before retaining additional bytes.

Keep the existing 16 unfinished-handshake limit and reserve 256 KiB of owned
state per handshake, at most 4 MiB across unfinished handshakes, before reading.
These reservations consume the same shared `Budget` maximum as retained native
payloads; the 4 MiB category cap is not additional capacity. Exhausted or zero
shared capacity rejects admission before reading, and dropping the handshake
guard releases both its shared bytes and category allowance. Reserve TLS-owned
buffers, certificate parsing, descriptors and any queue entries against that
reservation.
Apply bounded global/per-source admission before public-key work and measure
CPU/RSS for both valid and malformed traffic. Use aggregate local failure codes;
do not publish addresses, private keys, individual fees or transaction/time
associations. Local exhaustion and scheduling delays are not peer misconduct.

Request a standard TLS traffic-key update before either direction reaches
`2^20` protected records or 1 GiB of plaintext under one traffic key, whichever
comes first; respect any stricter library limit. Close and establish a new full
hybrid handshake at least hourly, since traffic-key updates alone add no fresh
X25519/ML-KEM entropy. Incomplete update, stalled update, unsupported update or
counter overflow closes the connection. The reviewed provider must bound
in-flight frames and updates and prevent overlapping update storms.

Erase ephemeral private keys, decapsulation keys, component shared secrets,
handshake secrets, exporter buffers, superseded traffic keys and partial secret
buffers on success, timeout, cancellation and every error path. Persist only
the long-lived service identity. Do not log TLS secrets or enable a key-log
callback in public or engineering builds used for wallet traffic.

## Acceptance gates

Before production activation, complete an independent review of this
composition, authenticated pin distribution and dependency revisions; freeze
canonical positive and negative vectors; and demonstrate:

- Different network, genesis, verifier, endpoint pins, roles, nonces, descriptors,
  algorithm tuple or exporter rejects the connection.
- Classical-only negotiation, unknown upgrades and downgraded retry fail closed.
- Both signatures are independently necessary; recording another session's
  descriptor or authentication messages cannot authenticate a new connection.
- Missing/incorrect TLS Finished and either ready message prevent application
  admission; no unauthenticated byte reaches transaction/sidecar processing.
- Decapsulation errors, malformed public keys and signature failures have
  generic wire behavior; cancellation frees all reservations and secret buffers.
- Real listeners enforce wall deadlines, bounded fragmentation, concurrency,
  record limits, updates and reconnect without unbounded retained buffers.
- Independent hosts synchronize and relay compact blocks, recover partitions
  and select/reorganize valid forks using the native consensus path.

The current identity tests and transport-interface tests satisfy none of the
unimplemented cryptographic-provider or independent-host gates by themselves.

## Implemented admission boundary

The transport interface requires an `ExpectedPeer` containing a full verified
descriptor and a matching independently authenticated `PeerPin`, bound to the
local network, genesis and verifier manifest. The caller supplies this trusted
configuration before dialing or accepting. The constructor verifies possession
signatures and pin equality; it cannot establish that the caller obtained the
pin through a trusted channel. Peer discovery and pin distribution remain
separate requirements.

`AdmissionContext` adds an explicit initiator/responder role, cooperative
cancellation and one absolute five-second deadline. The outbound helper starts
that budget before its TCP dial; the inbound helper starts it after accept.
Both pass the original context to the provider and native Hello exchange. A
capability tied to a different role, peer, context, deadline or cancellation
instance cannot be admitted, so constructing a new context does not extend an
existing capability's budget. Handshake reservations are released on rejection,
cancellation, timeout and successful admission.

The crate-private capability constructor compares the provider's observed
descriptor and connection role with that context and rejects parameter metadata
that indicates a different TLS version, group, cipher, ALPN, resumption or early
data. Those comparisons are interface guards. Parameter values supplied by a
provider are assertions, not cryptographic verification, and do not prove a
completed TLS handshake, exporter binding, fresh dual signatures or key
confirmation. No production provider is supplied or enabled by these guards.

Cancellation and deadline checks occur at I/O boundaries. The cooperative token
cannot interrupt a blocked socket or listener by itself, and static socket
timeouts do not establish the whole admission wall-clock guarantee. A reviewed
provider and resident listener must supply actual interruption and bounded I/O,
including reads performed internally by TLS. The one-shot blocking listener is
not a cancellation-aware resident service.

## Candidate transcript and lifecycle primitives

The internal identity API has a separate candidate-domain signature primitive
for a future reviewed provider. Both signatures bind the network, genesis,
verifier, sender connection role, ordered endpoint fingerprints, two distinct
nonzero connection nonces, a provider-derived transport binding and the exact
preceding transcript hash. It uses the existing strict Ed25519 and hedged
ML-DSA-65 implementations and a fixed 3,373-byte signature encoding. Descriptor
possession signatures cannot substitute for these signatures. This API neither
generates the nonces nor verifies their freshness, the key exchange, the
provider's hashes or its pin-distribution policy. It cannot create an
`Authenticated` capability. Its candidate domain and encoding do not freeze or
implement the six-frame TLS proposal above or a hybrid Noise wire profile.

The provider-independent peer scheduler accepts at most 64 configured pinned
fingerprints and retains at most 16 pending attempts and 16 established
sessions, including attempts awaiting actual closure. It uses caller-supplied
monotonic elapsed milliseconds, a five-second admission deadline, an hourly
session lifetime and exponential retry delay capped at 60 seconds with bounded
scheduling jitter. Authenticated protocol misconduct or explicit trusted local
policy disables automatic retry until reconfiguration. Unauthenticated claims
and record-authentication failures cannot quarantine a legitimate configured
pin: they close the attempt and back off under the same fixed transport policy.
Temporary unavailability and local resource exhaustion also retain the same
peer identity and back off. A generation bound to one scheduler instance rejects
stale worker completions. For simultaneous pending connections, the smaller
pinned fingerprint is the preferred initiator. Superseded attempts remain
charged until the driver acknowledges I/O and worker cleanup.

Configured-peer metadata and attempt metadata reserve 256 and 512 logical
bytes respectively from the shared transport `Budget`. These reservations are
in addition to the provider's handshake and payload reservations in that same
budget; they are not a process RSS bound. The scheduler owns no sockets,
cryptographic provider, database or worker threads. Returning cancellation
work does not close a socket or interrupt blocked I/O. A resident driver must
perform those operations, preserve the single consensus owner, and pass actual
listener, reconnect, shutdown and resource-exhaustion tests before activation.

## Dependency compatibility assessment

The following versions were inspected as source candidates. They are not a
provider selection or evidence of an enabled connection. The native-node crate
has its own workspace and does not currently depend on these TLS libraries;
versions in the separate repository workspace lockfile do not activate a
native provider.

| Component | Inspected version | Available interface | Required integration or review |
| --- | --- | --- | --- |
| `rustls` | 0.23.46 | Explicit `CryptoProvider` cipher/group lists, TLS 1.3-only builder, X25519MLKEM768, negotiated-group inspection, exporter, traffic-key refresh, custom certificate verifiers and signers | Pin the exact provider, constrain every offered algorithm, implement certificate policy and dual authentication, test receive limits and cancellation |
| `aws-lc-rs` / `aws-lc-sys` | 1.18.2 / 0.46.0 | ML-KEM-768 and X25519 used by the rustls hybrid group | Review transitive native code, supported-target build receipts, vectors, secret cleanup, advisories and licenses |
| `libp2p-tls` | 0.7.0 | Asynchronous libp2p connection-upgrade example using rustls and `futures-rustls` | Its stock protocol, identity policy, certificates, fallback groups and key logging do not implement this profile; use a dedicated reviewed native upgrade |
| `futures-rustls` | 0.26.0 | TLS streams compatible with the asynchronous I/O traits used by libp2p upgrades | Prove bounded scheduling and cancellation through the selected stream adapter |
| `tokio-rustls` | 0.26.6 | TLS streams, access to rustls state and initialization hooks for Tokio I/O | Alternative for a direct Tokio socket layer, not directly compatible with the synchronous native `Read + Write` interface or libp2p's futures I/O traits |
| `rcgen` | 0.13.2 | Ed25519 certificate algorithm and `RemoteKeyPair` signing interface | Specify bounded canonical certificate content and use a narrow signer without exporting the identity seed |

In the inspected rustls source, the hybrid implementation checks the exact
share lengths, uses the ML-KEM component first and supports TLS 1.3. Its test
`hybrid_kx_component_share_not_offered_unless_supported_separately` demonstrates
that restricting the provider's groups to X25519MLKEM768 removes a separately
offered X25519 share. Merely enabling `prefer-post-quantum` changes preference;
it does not prohibit classical negotiation. The candidate adapter must configure
an exclusive group list and reject an unexpected negotiated group.

The stock `libp2p-tls` 0.7.0 constructors use ALPN `libp2p`, upgrade name
`/tls/1.0.0`, ephemeral P-256 certificate keys, libp2p identity extensions and
default key-exchange groups. They also install `rustls::KeyLogFile`, which can
write traffic secrets when `SSLKEYLOGFILE` is configured. These are concrete
configuration differences, not the proposed native provider. A native upgrade
must explicitly retain `NoKeyLog` and test that setting `SSLKEYLOGFILE` cannot
create a key-log file. It must require both native identity signatures before
returning an authenticated capability, even after successful TLS authentication.

The inspected rustls `set_buffer_limit` API limits outbound application-data
buffering. `max_fragment_size` controls emitted plaintext records. Neither is
a receive-side certificate, handshake-allocation or total wire-byte limit.
The provider must count incoming and outgoing encrypted bytes, bound read
buffers before handing bytes to TLS, and account for the implementation's
handshake deframing and certificate parsing allocations. The proposed 8 KiB
handshake and 32 KiB admission limits require adversarial measurements of that
adapter; setting the two rustls options alone is insufficient. A nonblocking
driver or an explicitly bounded unbuffered driver must enforce the absolute
deadline while network reads are stalled.

The candidate versions include native C cryptographic code. Linux and macOS
builds need a reviewed C toolchain; the standard non-FIPS aws-lc-rs build does
not require CMake. Windows assembly/toolchain and prebuilt-NASM policies need
separate receipts. No FIPS certification claim follows from these features.
An exact native-workspace lockfile, enabled-feature report, license inventory,
advisory scan and supported-target build matrix remain adoption gates.

## Resident runtime integration plan

The current transport boundary provides bounded native sessions and one-shot
`accept_once` / `connect` helpers. `Node` provides local admission, bounded
synchronization and the compact-block references/missing-data/proof exchange.
These interfaces are not a resident peer service. The continuous single-node
producer does not supply peer lifecycle management or the proposed TLS
provider.

The first resident orchestration slice remains disabled without a reviewed
provider. Its responsibilities are:

1. Load the persistent local identity, independently authenticated full peer
   descriptors and expected pins before accepting traffic. Reject missing,
   changed, duplicate or cross-network entries without generating replacement
   identities. Use the typed expected-peer and admission contexts for each
   provider instance; a mining/validation role is different from a handshake
   role.
2. Keep one owner of `Node`, its database and block-production state. Connection
   tasks exchange bounded owned messages with that owner. They do not acquire a
   global node mutex while waiting for network I/O, share database writers or
   start a second producer against the same store. Proof workers return results
   with the state preconditions needed by the owner, which rechecks those
   preconditions before applying the common consensus transition.
3. Bound accepted sockets, unfinished handshakes, established sessions,
   multiplexed streams, command queues and proof work through the same global
   reservation budget. Reservations follow queued data through decoding,
   verification and commit, and are returned on disconnect, timeout or shutdown.
   Limit the listener backlog and reject excess admission before public-key
   work. Kernel socket buffers and TLS/library allocations require separate
   measured accounting; logical reservations do not by themselves cap RSS.
4. Preserve the admission context's absolute deadline through socket
   authentication and native Hello. The helpers no longer reset the budget
   between those phases. A per-read socket timeout and before/after time checks
   cannot cancel a blocked operation. Dial attempts, accepted sockets and all
   cancellation paths need actual interruption and explicit bounded policies.
5. Separate asynchronous transport I/O from consensus mutation. Adapt the
   native framing and sync state machines to asynchronous streams or use an
   explicitly bounded bridge; do not call synchronous `Read + Write` operations
   on a libp2p runtime thread. A slow 180-second block transfer must not prevent
   status reads, shutdown, unrelated peer admission or local template updates.
6. Track peer connection states, deduplicate simultaneous dials, bound retries
   and apply backoff. Retry unavailable connections with fresh authentication;
   do not retry malformed frames or authentication failures under a weaker
   transport. Maintain only aggregate public status, such as connection counts,
   sync state and categorized failures.
7. On shutdown, stop admission, cancel connections and outstanding work, finish
   or abort the current atomic transition, flush the store and release its
   ownership lease. Restart recovers the same chain and identity, never a
   replacement genesis, wallet or identity generated as an error recovery step.

The orchestration tests may use a test-only provider to exercise scheduling,
ownership and cleanup. Such a provider must not be linked as a production
authentication alternative. Real networking activation additionally requires
the complete provider and the acceptance gates above.

Required resident-service regression tests include:

- Simultaneous inbound/outbound connections, duplicate dial resolution,
  disconnection/reconnect and bounded backoff with no identity replacement.
- Stalled sockets during TLS, each dual-authentication frame, native Hello,
  control messages, sync batches and compact-block proof fetch; one absolute
  deadline, cancellation and complete reservation cleanup in every phase.
- Exhausted handshake, stream, queue, verification and global memory budgets;
  a slow or malformed peer cannot block a healthy peer or status/shutdown work.
- Real-provider negotiation with only the frozen group/cipher/version/ALPN,
  unknown/changed pins, exporter mismatch, signature substitution, key update,
  hourly reconnect, truncation and key-log environment rejection.
- Packet arrivals during local production, stale verification results,
  interrupted atomic commits and restart with the same tip/state fingerprint.
- Independent-host transaction/sidecar admission, compact relay, partition
  recovery, competing forks and reorganization through the common native
  consensus transition, including wallet reward rescan after a reorganization.

Three-day proof pruning, permanent public-data storage and checkpoint restore
remain separate persistence gates. A resident-service test cannot establish
their retention or recovery guarantees.
