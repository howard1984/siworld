# Versioned engineering resident runtime

`siworld-eng2-node` is an explicitly selected engineering entry point. Building
it requires the owner-operated `eng2-runtime` feature. Development workflows do
not enable this feature or execute this binary. Unix supports resident service
roles. The Windows runtime boundary permits only an outbound miner opened from
a durable authenticated signed import; Windows package and real-machine
qualification remain separate requirements.

## Explicit state and identity

Each directory contains a canonical `genesis.bin`, an existing peer identity
bound to that genesis and an independently selected peer configuration. Commands
require `--expected-genesis ID`; a mismatched identifier fails before startup.
No command regenerates peer or checkpoint keys, migrates an older network's
state, or falls back to historical proof replay.

`identity-init DIRECTORY --expected-genesis ID` explicitly creates a fresh
versioned peer identity in the existing private directory. It checks the sealed
genesis and independent identifier before acquiring a writable lease or drawing
new independent peer seeds. Existing identities are never overwritten, imported
from an older network or recreated by this command. The receipt contains only
the same public version, fingerprint and signed descriptor fields returned by
`identity-public`; it can be checked and pinned by peers. Checkpoint authority
and wallet materials are separate and are not read. This command creates no
chain database, listener or mining process. A failure after key publication may
leave the new identity present; use `identity-public` to inspect it rather than
regenerating it.

`init-store DIRECTORY --expected-genesis ID` creates a new height-zero store
only after loading the existing versioned identity. It refuses an existing
store. `qualify-restart DIRECTORY --expected-genesis ID` is a separate explicit
native audit that enables authenticated restart for an existing unqualified
store. It is never called implicitly by `run`.

Normal startup verifies the identity signature over the committed restart seal,
the exact state image, permanent leaf and nullifier rows, sealed head and
accepted header ancestry back to genesis. Header and body-length metadata live
in a separate compact table, whose ordered row digest is bound by the restart
seal. Reading the header prefix does not fetch historical proof-body values. It does not decode historical proof
bodies or execute their state transitions. A missing or inconsistent cache is
an error requiring a separate audit, rather than permission to rebuild state.
`restart-check` performs this same local-state authentication without starting
networking or production.

## Connection configuration

The configuration object has exactly seven fields: `version: 2`,
`engineering: true`, `role`, `listen`, `mining`, `peers` and `checkpoint_key`.
Roles are `bootstrap`, `validator`, `miner` and `ordinary`. A miner has no
listener and always initiates connections. Only a miner may enable production.
A bootstrap, validator or miner may explicitly select an existing checkpoint
key; the host separately validates that key against the verified local roster.

Each configured peer specifies an endpoint, a `dial` boolean, a fingerprint and
a descriptor matching an independently persisted service pin. Duplicate
identities, endpoints, self-connections and unpinned targets are rejected.
Ordinary miners may connect to service nodes without manual registration. They
still complete the encrypted hybrid handshake and all consensus verification.
Services do not admit an unknown validator through the open miner route.

At most eight connection workers share the node's byte-admission budget.
Listening service pairs select one deterministic dialer. Failed connections use
bounded backoff. A live connection alone does not establish readiness: a fresh
completed bidirectional round must also show that the selected peer's available
extension was exhausted. An exact full batch requires another round. Readiness
expires after 30 seconds without a completed round and is revoked on disconnect.

## Explicit signed bootstrap

`bootstrap-signed DIRECTORY PEER_CONFIG POLICY_FILE --expected-genesis ID`
acquires a signed checkpoint and its complete native proof tail before creating
canonical state. `resume-signed` uses the same arguments and explicitly reopens
an existing quarantine. Both commands require an already prepared identity and
one through four independently pinned service destinations. They use the open
miner ingress and complete its encrypted hybrid authentication; service
operators do not register individual miners. The configuration must select
`miner`, with no listener and no checkpoint signing key. Neither command starts
mining or creates keys.

The policy file is a bounded regular file with exactly these six fields:

```json
{
  "version": 1,
  "work_floor": "1",
  "max_headers": 1000,
  "max_payload_bytes": "2147483648",
  "max_rounds": 1000,
  "max_seconds": 3600
}
```

These values illustrate the encoding; they are not deployment defaults or a
recommended work floor. `work_floor` must be an independently selected nonzero
canonical decimal 512-bit accumulated-work value. `max_payload_bytes` is also a
canonical decimal string, between 1 and 512 GiB inclusive. Complete header caps
range from 96 through 1,000,000; round caps from 1 through 1,000,000; elapsed caps
from 1 through 36,000 seconds. Each ordinary/checkpoint/transaction round counts
against the shared operation budget. Deadline cancellation reaches the owned
connection and is checked by the native importer between verification steps;
synchronous proof verification is not preemptible.

Before each complete cycle, the client checks the native transport's existing
wire, record and connection-age budget. It closes expired or insufficient
sessions and repeats full hybrid authentication. Every replacement connection
requests its exact selected bundle and must return the byte-identical manifest
before cached acquisition continues. A provider retains valid peer-bound
transfers across checkpoint publication within its fixed two-hour lease;
expired, invalidated or unavailable bundles preserve the client's quarantine.
Partial or failed streams are always discarded. Only transient
transport unavailability is retried, with at most four attempts per retry stage
and cancellation-aware backoff from 100 through 800 milliseconds. All attempts
share the original elapsed/round budget and an additional connection cap of
`min(max_rounds + 4, 65536)`. Each candidate's header connection is closed before
the next candidate is acquired, so an idle session cannot age during selection.

The logical payload cap is divided equally among configured destinations.
Each candidate's complete header bytes and snapshot are checked before creating
or reopening quarantine storage; accepted receipt and proof-body chunks remain
under that candidate's cumulative cap. This bounds logical cached payload, not
redb physical allocation, process memory, or packet-wire bytes. Operators must
separately provision space for database overhead, native import and canonical
installation. Candidate directories remain separate and bind the exact
manifest, limits and received chunk hashes. Resume rejects a changed offer or
policy rather than replacing previous bytes. A new bootstrap refuses an
existing quarantine; both commands refuse an existing canonical or unadmitted
import database. A failed admission with unconfirmed durability requires
preserving the directory for inspection, not retrying over it.

Every candidate supplies complete work-verified headers before selection. The
client compares only the supplied candidate set, rejects equal-work conflicting
heads and applies the explicit work floor. This does not prove that an unknown
fork has less work. After selection, the client downloads the state snapshot,
permanent receipts and the complete native proof tail, verifies the signed
checkpoint and state transitions, then installs and authenticates a canonical
reopen. Quarantine headers alone never establish readiness.

Successful output reports `ready: false` and `mining_started: false`, together
with the admitted height, checkpoint height, verification/reread bytes and
elapsed time. Acquisition, native verification, installation and authenticated
reopen have separate elapsed-millisecond fields. Encrypted byte counters sum all
candidate sessions in that invocation, including retired or failed application streams and their hybrid
handshakes and framing. They exclude handshakes that failed before a session
was established, prior resume invocations and packet-wire overhead. Connection
attempt and established-session counts are reported separately. A subsequent explicit `run`
requires ordinary native peer catch-up before readiness or proving. On Windows,
`run` rejects listener, service and checkpoint-signing roles, and refuses a
store without an authenticated positive checkpoint import boundary. No command
falls back to the earlier network, initializes an identity or treats an
unadmitted quarantine as live state.

The encrypted height-96 native-tail transfer and Windows real-machine execution
remain qualification gates. Source availability and cross-target type checking
do not establish those results.

## Production and exports

The producer uses four proving workers. Native proving and bounded nonce-search
slices run outside the consensus owner's mutex. A changed parent invalidates a
prepared block. Every produced block returns through the same native verifier,
execution-commitment comparison and durable admission path as a peer block.
A production error is exported while validation and serving remain active.

Status uses `connections`, `ready`, `sync_status`, the current committed head,
a run identifier and freshness fields. A disconnected or stale session cannot
keep readiness true. Stop requests name the exact active run; a previous run's
request cannot stop its replacement. `mining_enabled` describes configuration,
not evidence of active work or an accepted reward.

Checkpoint exchange follows each completed ordinary block round. It accepts at
most three canonical messages under a shared ten-second phase deadline and
retains budget ownership through host consumption. The host reconstructs the
checkpoint from locally verified archived state before signing. The public
projection contains the current and pending public issuance fee; it does not
export ordinary transaction fee amounts.

Pending transaction exchange follows the checkpoint phase. Each inventory has
at most 128 identities and each direction requests at most three missing
packets. Packets and fee sidecars remain inside the encrypted channel. Ingress
and decoded work retain separate shared-budget reservations through native
admission. The same ten-second phase deadline bounds I/O and lock acquisition;
it is checked before and after synchronous native verification, and immediately
before pending-pool mutation. Verification is not preemptible, so this is not
a hard CPU execution limit.

The pending pool independently verifies the transaction statement, private fee
opening, snapshot and canonical conflicts. It retains at most 128 transactions
and 65 MiB, with tighter per-peer limits. Production selects admitted work before
filling remaining positions with padding. A failed candidate does not remove
pending entries; canonical inclusion or staleness releases their reservations.
An explicit `SIWORLD_ENG2_SUBMIT_SOCKET` path enables a submission-only Unix
socket in an existing owner directory with mode 700; the socket has mode 600.
It accepts only the existing kind-3 private packet framing, at most four active
requests and a ten-second request deadline including owner contention. It has no
read, admin, signing or TCP capability. Shutdown cancels pending admission and
removes only the created socket identity. Only byte-identical pending retries
receive the same admission acknowledgement. The wallet keeps proving and keys
client-side; a pending response does not establish block inclusion.

This adapter does not supply the authenticated receipt history needed by the
browser wallet. That integration and actual positive wallet-to-resident transfer
acceptance remain separate qualifications.

## Public operation submission

`submit-operations DIRECTORY PUBLIC_BUNDLE_FILE RUN_ID PARENT NEXT_HEIGHT
--expected-genesis ID` queues one canonical public operation bundle for an
existing resident. The bundle contains version 1, the existing typed governance
and fund operations object (or null), and canonical issuance-record hex strings.
It contains no signing keys or wallet custody. `operations-result DIRECTORY
RUN_ID` reads its bounded result.

The mailbox is confined to fixed private files in the node directory and allows
one active request. Run, genesis, network, parent and next-height checks reject
stale work. Preparation, proving and persistence failures are distinct results;
`committed` requires the actual durable block and header to match. A failed
operation does not stop validation or serving. The command does not sign,
regenerate identities, or read custody material.

## Remaining qualification

Local loopback rounds and height-zero restart tests establish transport and
lifecycle behavior only. A separately enabled owner-local qualification can read
only the public genesis and first proved block from an existing rehearsal, admit
that block through the native Driver, transfer it between two encrypted residents
and check authenticated restart at height one without generating another proof.
This does not establish production deployment, a signed checkpoint at height 72
with 24 confirmations, public-operation inclusion, a usable wallet transaction
adapter, or fresh-node recovery after pruning. Those require separate
owner-operated measurements. Unknown competing forks are rejected by this
linear extension transport; it does not implement automatic discovery of
unknown competing forks or reorganization.
