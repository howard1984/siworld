# Native Proof Storage

Status: engineering implementation with deployment and operating-system acceptance
gates. This policy does not change transaction
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
The engineering coordinator schedules proposals independently of block production.
Each authority builds its statement from independently verified local records;
both votes are required before publication.

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
reward evidence while their proof bodies can expire.

A local identity seal is not a remote checkpoint-authority quorum. This decoder
must never be used to accept unauthenticated peer snapshots. The engineering
network's original genesis-reserved checkpoint authorities remain inactive; the
engineering transition uses a separate release configuration. Non-fixture bootstrap and validator expiry is currently blocked in code until
checkpoint delivery and retained-tail availability have been qualified. Metrics
report `checkpoint_delivery_unavailable`; a local replay seal cannot remove this
gate. Engineering checkpoint recovery reconstructs a quarantined store from
authenticated permanent public records and a fully verified proof tail before
atomically adopting it. A certificate alone cannot install serialized state.

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
`storage-maintain-resume DIRECTORY miner|ordinary BLOCKS` requires an authenticated
seal at the exact committed head and checks indexed rewards before policy changes.
It refuses missing or mismatched restart evidence without falling back to a full
historical proof replay. Compaction still verifies every retained proof and checks
that the accepted state and indexed rewards remain unchanged. Service roles are
not admitted through this command.
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

An explicit `checkpoint-stale-acceptance` build permits a process-local
`SIWORLD_CHECKPOINT_STALE_SECONDS` override between 1,200 and 64,800 seconds for
an isolated acceptance instance. The default remains 64,800 seconds; production
builds reject this override. The coordinator's pruning alarm and the store's
service proof-deletion and qualification gates use the same configured policy.
The effective value is exported as `checkpoint_max_age_seconds`. It is not
persisted, supplied by peers, or used for certificate validity, checkpoint
bootstrap eligibility, the six-hour publication schedule, or proof windows.
A shortened acceptance threshold still requires a genuinely newer publication
to resume pruning; it does not create an additional publication within the same
six-hour sequence. Real-time acceptance evidence must identify the build,
configuration, elapsed time, and distinct publications used.

On Unix, a build with both `native-p2p` and `checkpoint-stale-acceptance`
supports a separately registered nonmining outbound validator specimen. A private
`checkpoint-stale-acceptance.json` manifest pins its directory identity, public
peer identity, network/genesis/verifier, exact executable/configuration/peer
configuration digests, and 1,200-second local threshold. The environment value
`SIWORLD_CHECKPOINT_STALE_ACCEPTANCE` must equal the manifest SHA-256. Authority
material, an inbound listener, mining, external transport identity reuse, wallet
gateway activation, a previously qualified specimen, and inherited probe state
are rejected. A shortened age in the resident acceptance build requires this
explicit binding.

The existing resident owner and authenticated P2P continue verifying blocks and
receiving real release certificates. Routine maintenance records finality while
preserving all proof rows. `checkpoint-stale-probe DIRECTORY EXPECTED_RUN_ID
fresh|stale|resume` writes one private request per phase; it cannot overwrite or
repeat a request. The fresh probe requires one full observed day and at least
five eligible retained proofs, then runs one normal bounded expiry batch. The
stale probe requires both actual elapsed and publication ages above 1,200
seconds, a subsequently validated head, the stale alarm, and an unchanged
reserved proof row. A genuinely newer accepted certificate permits a positive
resume probe. Each probe preserves permanent state and the nonproducing local
reward index. Private receipts distinguish pending, failed, and completed probes.
No production signer outage, shortened retention window, or synthetic clock is
part of this route.

The authentication component rejects missing, duplicate, unknown and invalid
signatures, wrong context, future publications and cursor rollback/equivocation.
The local attestation path independently replays a canonical ancestor and
compares the complete statement before accepting it. A mismatch returns an
urgent diagnostic and never replaces local state. Dedicated signer journals
refuse a different statement at an already signed sequence.

The engineering release pins two public verification keys to one exact network,
genesis and verifier binding. The coordinator loads a private authority only on
its origin host. A bounded background builder reconstructs confirmed state and
compares every stored fingerprint before voting; write-once vote journals prevent
signing a different statement at the same sequence. Checkpoint transport extends
the pinned-peer protocol with a separate negotiated profile while preserving the
legacy profile for older peers. Accepted certificates also enter the public export
only after all referenced compact records and the canonical index are durable.
The export transport supplies claims, not signing authority.

Fresh and long-offline nodes download ordered permanent records into a private
quarantine, reconstruct the complete state, compare the statement, then fully
verify the proof tail against the greatest observed cumulative-work goal.
Disconnection or goal replacement cannot authorize incomplete adoption. Mining
remains disabled during checkpoint catchup. Private progress exports include
height, payload bytes and a rate-based time estimate. A completed recovery writes
a durable receipt with measured payload bytes, monotonic elapsed time and final
state identity; an unavailable receipt raises a diagnostic without undoing an
already verified adoption.

Recovery of an existing service store preserves its historical full-proof rows
in place under an authenticated protection index. Offline time is not credited
toward retention. Those rows remain available and counted until their new local
finality observation and checkpoint cutoff both permit expiry. No permanent
public records are deleted.

Non-fixture service expiry remains behind explicit local qualification after
delivery and recovery acceptance. `checkpoint-qualify-service DIRECTORY` requires
an idle exclusive lease and independent store replay. A running native-P2P owner
can instead consume `checkpoint-qualify-live DIRECTORY EXPECTED_RUN_ID`; the
request requires fresh status for that exact run and is stored privately. Neither
network claims nor a service restart creates qualification. Invalid requests and
checkpoint status export failures leave canonical validation running.

`checkpoint-signing-live DIRECTORY EXPECTED_RUN_ID paused|active` controls only
the current owner's engineering proposal and vote paths. It requires the same
fresh run binding and private request contract. Paused authorities continue
receiving complete certificates and validating blocks; they suppress local
proposal advertisements and create no votes. A new owner run defaults active
and rejects old pending intent. The private receipt records the actual pause
state. This control supports elapsed-time publication-outage acceptance without
changing the host clock, chain validity or service-expiry qualification.

Deployment, full-native-proof fresh download, real elapsed retention and
long-offline recovery remain acceptance gates. A certificate with valid
signatures alone cannot authorize network admission, state replacement or proof
expiry. Synthetic tests do not establish production disk-reclamation, Windows
download volume or recovery throughput.

## Validation boundaries

Storage tests use synthetic proof verifiers to exercise retention boundaries,
transaction rollback, corrupt seals/public records, reward preservation, recent
forks, clock uncertainty, reopen consistency and physical page reclamation.
Synthetic disk measurements do not establish real proof compression ratios,
Windows download size or production throughput. Those require native-proof,
remote bootstrap and operating-system acceptance measurements.
