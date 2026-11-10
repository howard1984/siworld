# Versioned engineering resident runtime

`siworld-eng2-node` is an explicitly selected engineering entry point. Building
it requires the owner-operated `eng2-runtime` feature. Development workflows do
not enable this feature or execute this binary. The resident checkpoint adapter
currently requires Unix; this entry point does not establish Windows support.

## Explicit state and identity

Each directory contains a canonical `genesis.bin`, an existing peer identity
bound to that genesis and an independently selected peer configuration. Commands
require `--expected-genesis ID`; a mismatched identifier fails before startup.
No command regenerates peer or checkpoint keys, migrates an older network's
state, or falls back to historical proof replay.

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
linear extension transport; it does not implement automatic snapshot selection
or reorganization.
