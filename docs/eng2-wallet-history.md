# Engineering v2 wallet history exports

## Scope

The implementation provides an explicit read-only accepted-store adapter, a
portable public-receipt codec, and methods on the existing descriptor-confined
public-file exporter. It does not enable browser synchronization, routes,
listeners, transaction submission, proving, or balance reporting.

A wallet must independently pin the engineering genesis identifier. The
bootstrap decoder binds the exact genesis configuration, governance bytes,
native proof profile, rules commitment and `LegacyMiner` fee mode. It rejects
the legacy engineering genesis identifier and unsupported fee modes.

## Authentication

Each receipt envelope contains the network, genesis, rules, profile and fee-mode
binding, the exact 190-byte `SWE2` header, and the existing `SWLR0001` BLAKE3
range-proof encoding. The proof authenticates selected public bytes of
`u64LE(body_length) || canonical_body` under the existing
`siworld eng2 canonical block body v1` derive-key domain. Its root must equal
the expected header's body commitment. Legacy range-proof entry points, domain,
limits and encoding remain unchanged.

The caller must authenticate that exact header in its selected chain. A matching
body commitment does not establish native proof validity, chain selection,
network connectivity or current state freshness. Header pages supply at most
128 canonical headers; consumers still verify work, difficulty and continuity.

The public records include every transaction slot, miner rewards, public fund
outputs and issuance records. Transaction and issuance proof payloads are not
retained by the decoder. Adjacent BLAKE3 chunks can contain public proof bytes.
Ordinary fee sidecars, wallet secrets, ordinary fee totals and slot
classifications are not export inputs. The unused all-zero legacy fee-output
slot is checked and is excluded from commitment-tree outputs.

## Accepted-state and resource boundaries

`Head::capture` reads the actual durable accepted store. Receipt and header-page
requests must retain that exact head pin; a changed head causes rejection and a
fresh capture. No pending pool, admitted anchor or proposed block can satisfy
this interface. Receipt membership is separate from a pending submission
acknowledgement.

Receipt envelopes are bounded to 8 MiB plus 327 bytes. Header pages are bounded
to 24,507 bytes. Construction currently reads a retained canonical body and
reserves `3 * body_bytes + 4 * MAX_RECEIPT_BYTES + 65,536` from the node's shared
memory budget before body allocations. The resulting artifact retains that
reservation while its bytes remain owned. A large source body can exceed the
available budget and is rejected without changing validation. Actual transfer
size depends on the disclosed public records and authentication chunks; no
real-network bandwidth measurement is implied by codec tests.

The existing public-file exporter can explicitly publish `wallet-genesis.bin`,
`wallet-head.json`, immutable receipt artifacts and header pages. A head
publication does not assert that every historical artifact is available.
The transport owner must enforce publication freshness and route only
independently authenticated public artifacts.

## Remaining integration

The browser WASM synchronization owner, engineering header-chain selection,
owned paths and nullifier tracking, cache persistence, spend readiness and
confirmation flow are not connected by this increment. Receipt decryption
reuses the existing wallet scanner without passing engineering headers through
legacy `LightWallet::append` or legacy state validation.

The source store currently retains full canonical bodies. Automatic permanent
receipt retention before body-proof removal is not implemented. A pruning owner
must first durably materialize and authenticate receipts for every affected
accepted block, preserve their canonical index, and retain verification from
those artifacts after the original proof body is absent. This implementation
performs no pruning or data deletion.
