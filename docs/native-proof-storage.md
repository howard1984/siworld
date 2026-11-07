# Native Proof Storage

Status: local storage implementation; remote checkpoint bootstrap and automatic
long-offline recovery remain incomplete. This policy does not change transaction
validity, proof profiles, rewards, difficulty or the 24-block reorganization rule.

## Role selection

`storage-role DIRECTORY ROLE` requires the exclusive service lease, an existing
persistent peer identity, and successful store verification. Roles are
`bootstrap`, `validator`, `miner` and `ordinary`. Explicit role changes before
any proof expiry are supported. Changes after expiry require separately verified
proof backfill and migration; starting a service never infers a replacement role.
New CLI miner stores default to `miner`; fresh generic identity initialization
selects `ordinary`. Existing stores retain their policy until explicitly migrated.
Operators can explicitly migrate at startup using `SIWORLD_STORAGE_ROLE` and,
for local roles, `SIWORLD_STORAGE_KEEP_BLOCKS`; both are validated before expiry.

Bootstrap and validator stores retain proofs at least 24 elapsed hours after the
first local finality observation. Miner and ordinary stores retain 96 canonical
blocks by default; `storage-keep-blocks DIRECTORY BLOCKS` can increase or lower
that window, with a minimum of 24 blocks. Clock discontinuities extend retention. Unobserved downtime is not
credited as certain service retention time. Private fee-opening sidecars are not
written by this storage subsystem.

At the 300-second target, the 24-hour finalized-proof window plus the existing
24-block finality tail is nominally 312 blocks. Expiry follows elapsed time,
not that estimated count. Checkpoint publication is due every 21,600 seconds
(six hours), leaving headroom inside the 86,400-second proof window.
Authenticated remote publication and tail delivery remain deployment gates;
this cadence helper does not itself publish a checkpoint.

## Durable layout and recovery

Expired records retain the authenticated compact representation of all public
fields, including ciphertexts, reward notes, signatures, asset declarations and
canonical block identity. The existing compact range proof authenticates those
fields to the original worked seed. The local replay base includes economic and
asset state, commitment-tree state, nullifiers, timestamp rules, snapshot roots,
cumulative work and the accepted-state fingerprint.

The existing peer identity signs the local base using domain-separated Ed25519
and ML-DSA-65 signatures. The base, compact-prefix digest, accounting and replaced
records commit in one durable redb transaction. Failure leaves the previous
records and base intact. Reopening checks the local signatures and complete
compact prefix, then verifies the complete retained proof tail. Recent forks
reconstruct from that base and cannot cross the existing finality boundary.
Detached records below the base retain their compact public fields and local
reward evidence while their proof bodies can expire. Expiry reconstructs public
effects from authenticated compact records and compares every resulting state
fingerprint with the fingerprint saved during independent block verification.
It does not repeat expensive proof verification on the canonical-state owner.

A local identity seal is not a remote checkpoint-authority quorum. This decoder
must never be used to accept unauthenticated peer snapshots. The engineering
network's original genesis-reserved checkpoint authorities remain inactive; the
engineering transition uses a separate release configuration. Non-fixture bootstrap and validator expiry is currently blocked in code until
checkpoint delivery and retained-tail availability have been qualified. Metrics
report `checkpoint_delivery_unavailable`; a local replay seal cannot remove this
gate. Finality observation continues while checkpoint delivery is unqualified or
stale. Explicit qualification requires a fresh confirmed canonical certificate
from the release-pinned quorum; later expiry pauses after an 18-hour checkpoint
age and never crosses the latest accepted checkpoint height. An offline node beyond all retained proof windows cannot
yet automatically recover from a remote checkpoint in this implementation.

## Maintenance and disk accounting

The network owner runs a bounded maintenance batch approximately once per minute
when a storage policy has explicitly been configured, accelerating to a five-second
interval while an expiry backlog remains. Each canonical batch is
limited to four blocks and one maximum encoded block in total input bytes. The
standalone producer maintains configured storage between production cycles.
There is no background database owner or concurrent state mutation.

`storage-expire DIRECTORY` applies one offline batch. `storage-compact DIRECTORY`
requires the exclusive service lease, reclaims free redb pages, and reopens and
checks the resulting accepted state. Neither command should run against a live
owner. `storage-maintain DIRECTORY miner|ordinary BLOCKS` performs verified
open, configuration, bounded expiry batches, compaction and reward verification
in one exclusive session instead of reopening the complete history for each batch.
Expiry allows page reuse but does not promise that the physical file
shrinks. Offline compaction may need additional free disk space and can take a
long time; preserve the store on any error.

Service and offline JSON expose role, policy activation, local replay-base
height, retained/expired proof counts, canonical and detached proof-body bytes,
database logical/allocated bytes, and node-directory logical/allocated file
bytes. Directory accounting reads metadata only and rejects symbolic links.
Allocated bytes are unavailable on platforms without a supported allocation
query. These categories are not a measured fresh-miner download volume. Large
legacy stores without proof accounting report unknown proof bytes rather than
attributing their entire database file to proofs.

## Capacity and fault isolation

Bootstrap and validator stores report a budget alarm at 200 GB
(200,000,000,000 bytes) of logical node-directory file content. The threshold is
observational: it does not cap database extension or auxiliary writes, pause
block ingestion, stop verification, or authorize deleting protected records.
There is no separate database or auxiliary ceiling. Actual I/O failures remain
local storage errors; they cannot select a different chain or relax validity.
Miner and ordinary roles do not receive this service-node budget alarm.

The budget does not measure an entire filesystem. Reports expose file logical
and allocated bytes separately, and host monitoring must collect filesystem
capacity and free space. A physical full disk can still prevent durable writes;
a budget alarm is not a guarantee against that condition. Failed commits leave
the previous accepted state intact. Corrupt or unreadable stores fail closed
without reinitialization or implicit repair.

## Engineering checkpoint transition

The engineering transition uses two independent dedicated ML-DSA-65 authorities
with a 2-of-2 quorum. Keys are generated locally on the two service hosts and
remain in owner-only directories. The public key roster must be pinned in the
engineering release configuration; peer-supplied keys cannot extend it. Test
keys do not define mainnet trust and must be retired before mainnet.

Statements bind network, genesis, verifier profile, authority roster, increasing
sequence, publication time, height, block identity and cumulative work. They
also bind the complete state encoding and permanent-prefix digests, commitment
root, nullifier and recent-root digests, Holder reward pool, development fund,
issuance and burn totals, locked rewards and schedule, and asset registry.
Checkpoint height is a multiple of 72 with at least 24 confirmations.
Publication is due every six hours. An 18-hour publication age limit controls
pruning eligibility, never block verification.

The authentication component rejects missing, duplicate, unknown and invalid
signatures, wrong context, future publications and cursor rollback/equivocation.
The local attestation path independently replays a canonical ancestor and
compares the complete statement before accepting it. A mismatch returns an
urgent diagnostic and never replaces local state. Dedicated signer journals
refuse a different statement at an already signed sequence.

Status: certificate authentication, local comparison and dedicated key tooling
are implemented. Release roster pinning, independent host deployment, scheduled
publication, P2P/export delivery, fresh-node permanent-data reconstruction,
automatic long-offline recovery and urgent alert delivery remain qualification
gates. Service proof expiry remains disabled until those gates are satisfied.
A certificate with valid signatures alone cannot authorize network admission,
state replacement or proof expiry. No production disk-reclamation or recovery
measurement follows from synthetic tests.

## Validation boundaries

Storage tests use synthetic proof verifiers to exercise retention boundaries,
transaction rollback, corrupt seals/public records, reward preservation, recent
forks, clock uncertainty, reopen consistency and physical page reclamation.
Synthetic disk measurements do not establish real proof compression ratios,
Windows download size or production throughput. Those require native-proof,
remote bootstrap and operating-system acceptance measurements.
