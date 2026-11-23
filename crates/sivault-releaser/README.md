# SIVault Releaser Policy

This library contains noncredential message metadata, permanent slot ledger
transitions, sequential client scheduling, and a native admission journal.
The calling protocol authenticates messages and evaluates credentials; this
library does not expose a releaser service.

## Metadata encoding

`message::Message` encodes a candidate local metadata transcript. It is not a
cryptographic wire protocol or an approved suite. Suite identifiers and digest
values are opaque inputs. Enrollment contains only record manifest metadata.
Reply public keys and certificates are represented by digests. No signatures,
verifiers, shares, proofs, or credential results are serialized. The reserved
`OpenProof` and `OpenResult` tags are rejected by the decoder.

All integers use big endian byte order. Identifiers and externally computed
digests are 32 bytes. The fixed header is:

| Offset | Width | Field |
| --- | --- | --- |
| 0 | 4 | `SVMN` magic |
| 4 | 2 | Suite identifier |
| 6 | 2 | Metadata format version, 1 |
| 8 | 32 | Network identifier |
| 40 | 1 | Message kind |
| 41 | 1 | Operation |
| 42 | 32 | Safe identifier |
| 74 | 8 | Generation |
| 82 | 32 | Permanent slot identifier |
| 114 | 32 | Releaser incarnation |
| 146 | 32 | Request identifier |
| 178 | 4 | Body byte length |
| 182 | variable | Typed body in declaration order |

Optional digests use a single 0 byte for absence, or 1 followed by the digest.
Share identifier lists use a u16 count followed by strictly increasing, unique
identifiers, with 1 through 64 entries. Messages are at most 4,096 bytes. Unknown
tags or versions, trailing/duplicate fields, incorrect body lengths, invalid
operation domains, and noncanonical options/lists are rejected. Cryptographic
integration must authenticate the complete canonical transcript, validate the
approved suite and deployment, and apply all required predecessor bindings.

## Ledger authority boundary

`Ledger::enrollment` creates only a pure initial snapshot. An adapter must install
the owner-authenticated slot allocation once, with its fixed allowance and ledger
identity. It must verify the authenticated inventory, reserves and total cap.
Existing slots cannot be re-enrolled or donate their unused allowance. There is
no removal/reset transition. Only explicit owner increments increase the ceiling.
Spent attempts, command counters, request bindings, fences and tombstones survive
generation and endpoint changes.

`Ledger::transition` returns a proposal and never an admission token. An adapter
may reconstruct a snapshot by replaying its exact protected event journal through
these pure transitions. Neither replay nor a deserialized local file establishes
freshness. `Releaser::new` and `Releaser::default` start quarantined. Only
`DurableAuthority::recover_exclusive` can establish the exact protected state and
exclusive authority. Owner restore commands alone cannot clear quarantine.

`DurableAuthority::commit` must check exclusive current-state ownership, compare
the complete expected ledger, and durably commit the full transition before
returning success. The calling protocol validates event authentication, time,
possession verdicts, selected record membership, command/predecessor and manifest
bindings, expected ledger-head and tombstone digests, certificates/readiness,
replacement fencing, and physical deletion evidence. Payload rotation and its
fresh-key/re-encryption requirements remain an external integration obligation.
The default adapter always fails closed. The native journal appends and
synchronizes each transition before advancing its credential-store checkpoint.
An absent checkpoint, divergent head or torn tail denies service. The journal
does not resolve an interrupted checkpoint update by truncating records.
Its marker is best-effort restore detection, not protection against a
simultaneous rollback of both stores. The macOS and Windows checkpoint adapters
are not yet integrated into the desktop application.

After that commit, `Releaser::apply` may return a non-cloneable `CredentialReady`
token containing the exact admitted attempt metadata and committed revision.
Charge and consumed-request insertion happen in that same transition before the
token exists. This token is not a credential result, approval or reusable opening
capability. A duplicate request never gets another token. Failed possession does
not charge. A crash after persistence can lose a charged attempt. Any failed or
uncertain authority operation quarantines service until exact recovery.

Preparation leaves the current generation operational. Commit activates only the
matching staged record and preserves budget/history. A removed endpoint can
instead fence its current record using an authenticated successor certificate.
Deletion first persists a tombstone; a separate durable removal confirmation is
required. Incarnation replacement preserves the entire ledger and requires the
adapter to fence the previous authority. It cannot resurrect a retired record.
Pending challenges are limited to 128. Permanent issued identities and permanent
owner-command histories each have a hard limit of 1,024 entries per slot. These
prototype limits bound all retained maps: consumed attempts are a subset of
issued identities, and retirement/incarnation records are bounded by command
history. Deadline cycling cannot reclaim issued capacity. At capacity, new
identities or new commands fail closed with `HistoryCapacity`; existing identical
admin retries still return their original receipt, and already registered live
challenges may consume their single allowed charge. No history is pruned or reset
by generation/incarnation replacement. Capacity exhaustion can deny availability
even with allowance remaining. No authenticated compaction/checkpoint mechanism
is implemented, and external rate limits are still needed to resist saturation.

## Client scheduling

Each `scheduler::Scheduler` represents one opening. It admits one in-flight
request, bound to the full target domain. Credential failure, approval, rejection
and close terminate the opening. Only timeout or unavailability permits the next
distinct permanent slot. Both retain a possibly-charged record. Late responses
cannot complete a different outstanding request. The transport integration must
authenticate and bind replies before reporting a classification to the scheduler.
These classifications are external inputs, not credential validation by this
crate. There is no approval cache or offline controlled opening.

## Local validation

```sh
cargo fmt --check
cargo clippy --offline --locked --all-targets -- -D warnings
cargo test --offline --locked
```

Tests use synthetic metadata and a test-only transactional reference store. No
real credentials, services, clocks, durable stores, or cryptographic suites are
exercised. The literal encoding vector is documented in `tests/vectors/README.md`.
