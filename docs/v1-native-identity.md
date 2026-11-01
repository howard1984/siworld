# Native V1 Peer Identity Storage

Status: implemented identity prerequisite for the independent V1 runtime. This
module does not implement the hybrid handshake, authenticated record layer,
resident listener, identity rotation, or peer discovery. Its cryptographic
construction and dependencies remain in the external review scope. The retained
network and its identities are unchanged.

## Credentials and explicit initialization

Each native peer has two independently generated service credentials: an
Ed25519 signing key and an ML-DSA-65 signing key. They are separate from wallet
seeds and development-fund keys. The identity API accepts the trusted local
network, genesis and verifier binding. All three identifiers must be nonzero.

`NativeIdentity::initialize` is an explicit write-once operation. It generates
two independent 32-byte seeds from operating-system entropy and writes one
versioned private record. `NativeIdentity::load` only loads an existing record;
it never creates, repairs, migrates, or replaces credentials. A missing,
truncated, oversized, corrupt or differently bound record prevents use. Retain
the original file for diagnosis and restore a verified private backup rather
than silently changing the peer identity.

The 198-byte secret record contains `SWIK`, a little-endian version, the three
32-byte context identifiers, the two 32-byte seeds, and a 32-byte BLAKE3
checksum. The checksum detects accidental corruption; it does not authenticate
the file against an attacker who controls the operating-system account.
Backups of this file are secret credentials. No public export or serialization
API exposes the seeds. `Debug` redacts the identity; retained ML-DSA signing-key
bytes and temporary seed buffers are erased on drop. Ed25519 key cleanup uses
the dependency's enabled `zeroize` feature. The operating system and dependency
internals remain part of the secret-custody boundary.

Persistence currently supports Unix only and fails closed elsewhere. The
existing identity directory must be owned by the effective user and have no
group or other permissions. Its path is traversed using directory descriptors
and `O_NOFOLLOW` for every component; symbolic-link components and parent
traversal are rejected. Files are opened relative to that directory, with
no-follow and nonblocking flags. Reads require a regular, owner-matching,
private file with one link and the exact expected length. New files use mode
`0600`, an exclusive random temporary name, file synchronization, atomic
no-overwrite linking, temporary cleanup and directory synchronization. Existing
destinations, including symlinks, are never replaced. A durability error after
installation may leave a complete record; inspect it with the read-only loader
before attempting any further initialization. A hostile process running as the
same user or a privileged operating-system attacker is outside this mechanism.

## Canonical public descriptor

The public descriptor is exactly 5,459 bytes. No variable-length fields,
certificate chains, addresses or optional signatures are accepted.

| Offset | Bytes | Field |
| --- | ---: | --- |
| 0 | 4 | `SWID` magic |
| 4 | 2 | Little-endian version 1 |
| 6 | 32 | Network identifier |
| 38 | 32 | Genesis identifier |
| 70 | 32 | Frozen verifier identifier |
| 102 | 32 | Ed25519 public key |
| 134 | 1,952 | ML-DSA-65 public key |
| 2,086 | 64 | Ed25519 signature |
| 2,150 | 3,309 | ML-DSA-65 signature |

Both signatures cover the identical message: the bytes of
`siworld native peer identity descriptor v1` followed by a zero byte, then the
complete 2,086-byte unsigned body. ML-DSA also uses the FIPS 204 context
`siworld native peer identity v1`. Ed25519 verification uses strict verification;
zero keys and either failed or missing signature are rejected. The trusted local
network, genesis and verifier binding must match before acceptance. Verification
is bounded by the fixed encoding and does not read trailing bytes.

The public fingerprint is BLAKE3 `derive_key` with context
`siworld native peer identity fingerprint v1` over the unsigned body. It binds
both public keys and the complete network context. Signatures are excluded so
fresh ML-DSA signing randomness does not change an identity's pin.

## Known-peer pins and trust boundary

Authenticate a descriptor through an independently trusted channel before
calling `PeerPin::from_trusted_descriptor`. A descriptor obtained from a new
connection only proves possession of its stated keys; it does not establish the
peer's name, continuity, authorization, independence or trustworthiness. A
classical libp2p PeerId alone cannot establish the ML-DSA binding.

Pins are immutable 134-byte records: `SWIP`, version 1, the same 96-byte
context binding and the 32-byte fingerprint. Their filenames are
`peer-<lowercase-fingerprint-hex>.pin`; labels and addresses do not enter the
record. Pin persistence uses the same protected no-overwrite storage. Loading
requires the expected context and independently supplied fingerprint.
`PeerPin::verify` verifies both descriptor signatures again and rejects a
different key pair or context. Updating or rotating a pin has no implicit API;
it requires a future reviewed, authenticated rotation policy.

Descriptor verification and pin matching must not construct an authenticated
application channel. A future provider must additionally bind the dual identity
to a fresh, ordered handshake transcript and selected algorithms, complete the
reviewed X25519 plus ML-KEM-768 exchange and both directions of key confirmation,
and enforce authenticated records, sequence numbers, nonce limits, cleanup and
rekeying. There is no classical or plaintext fallback.

## Verification and remaining integration

The module tests cover restart stability, explicit initialization, duplicate
initialization, every single-byte secret-record corruption, truncated and
oversized records, wrong context, both signature failures, changed keys,
canonical length/version checks, randomized-signature pin stability, immutable
pin persistence, private permissions, symbolic links, hard links and nonregular
records. Synthetic test keys are used only inside tests.

The next integration stages are a separately reviewed handshake profile and
test vectors; real initiator/responder and deadline/resource tests; resident
libp2p listener/outbound orchestration; bounded peer admission and reconnect;
then independent-host synchronization, compact relay, partition and reorg
tests. Identity storage alone does not satisfy network deployment acceptance.
