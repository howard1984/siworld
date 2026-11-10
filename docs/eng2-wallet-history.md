# Engineering v2 wallet history exports

## Scope

The implementation provides an explicit read-only accepted-store adapter, a
portable public-receipt codec, and an opt-in generation publisher on the existing
descriptor-confined public-file exporter. The default configuration does not
schedule wallet exports or enable browser routes, listeners, transaction
submission, proving, or balance reporting.

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
outputs, issuance records and bounded raw signed governance action frames.
Governance frames are authenticated to the selected header; consumers must decode
and execute their authorization lineage from independently pinned genesis.
This codec does not authorize governance actions. Transaction and issuance proof
payloads are not retained by the decoder. Adjacent BLAKE3 chunks can contain
public proof bytes.
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
to 24,507 bytes. First construction reads a retained canonical body and
reserves `3 * body_bytes + 4 * MAX_RECEIPT_BYTES + 65,536` from the node's shared
memory budget before body allocations. The resulting artifact retains that
reservation while its bytes remain owned. A large source body can exceed the
available budget and is rejected without changing validation. Actual transfer
size depends on the disclosed public records and authentication chunks; no
real-network bandwidth measurement is implied by codec tests.

The generation publisher stages `wallet-genesis.bin`, every receipt in the
selected prefix, immutable header chunks and a complete manifest. It durably
replaces the bounded generation catalog before replacing `wallet-head.json`
last. A manifest covers exactly heights 1 through its advertised head; the
zero-height generation uses the pinned genesis identifier and no chunks.
The source checks its actual accepted head before committing publication.
HTTP requests cannot refresh the source publication timestamp.

`Store::materialize_permanent_receipt` explicitly materializes one accepted
height under the same shared budget. It authenticates the immutable context,
exact canonical header and body length, then durably commits the receipt and its
digest in one transaction. Repeated materialization is idempotent; conflicting
or incomplete existing pairs are preserved and rejected. Stored receipts can be
exported without the original body, with their digest, header binding and body
length checked on read. This API does not schedule background work or delete
canonical bodies, proofs or state.

## Immutable generations and retained pins

All binary integers are little endian. The 129-byte binding is network,
genesis, rules and profile identifiers (32 bytes each), followed by the
`LegacyMiner` fee-mode byte 0. Content digests use SHA-256.

`wallet-chunk-<digest>.bin` contains `SWE2WHC1`, the binding, a u64 starting
height, a u16 count and 1–128 records. Each record contains the canonical
190-byte header, its 32-byte native identity, u32 receipt length and 32-byte
receipt digest. Chunk starts are 1 modulo 128. Consecutive header parents must
match, and only the final chunk can be partial. The maximum chunk is 33,171
bytes. Complete chunks are reused as the head advances; a growing partial
chunk receives a different content identity.

`wallet-generation-<height>-<tip>.bin` contains `SWE2WGM1`, the binding, u64
height, 32-byte tip, u16 chunk count, then descriptors. A descriptor is u64
start, u16 count, u32 chunk length and 32-byte chunk digest. Coverage is exact
and contiguous. The finite export limit is 100,000 headers, 782 chunks and
36,151 manifest bytes. Manifests contain no timestamp or mutable sequence.

`wallet-generations.json` contains exactly `version` (1), the four context
identifiers, `fee_mode` (0), `sequence` and `entries`. Each entry has `height`,
`tip`, `manifest_sha256` and `expires_unix_seconds`. The one active entry has
expiry 0. Replaced heads remain pinned for 900 seconds; the catalog has at
most four entries and 4,096 bytes. An interrupted catalog-before-head write
retains the previously committed head; an orphan active generation is not a
committed head. Restart reconciles the committed generation against the local
accepted prefix before continuing incremental backfill.

A full catalog pauses new publication until an entry expires; it never evicts
an unexpired pin. Expiry removes catalog references only. Artifacts are never
deleted by this publisher. A reader must resolve an exact retained `(height,
tip)` and must not substitute the newer head. It can assemble an arbitrary
page of at most 128 headers from at most two chunks, producing the existing
`SWE2WHP1` response. A receipt must match the selected record's identity,
header, exact length and digest. Transport digests do not authenticate proof
validity, work or chain selection.

## Owner scheduling and artifact limits

The existing Unix resident enables publication only when
`SIWORLD_ENG2_WALLET_EXPORT=1`. The existing owner loop advances one receipt
per one-second checkpoint interval, borrowing its Store and shared memory
budget. There is no new worker, observer or Store. Wallet failures only pause
this export; checkpoint coordination, validation and production continue.
Existing resident status reports `wallet_export_enabled` and the optional
`wallet_export_paused` state. No engineering-v1 path is changed.

The default artifact budget is 32 GiB. An explicit `WalletPolicy` accepts a
finite bound from 128 KiB through 1 TiB. Opening inventories descriptor-confined
regular-file metadata with a 300,010-entry ceiling. New immutable bytes,
allocation rounding and per-file metadata are reserved durably before writing.
A fixed mutable-metadata reserve of at least 128 KiB (32 allocation units)
covers replacement and temporary files;
failed writes may consume conservative budget. A mutable-write failure stops
further wallet writes until reopen and inventory. Budget saturation does not
remove data, change accepted state or stop validation. A descriptor lease
permits only one publisher for an export directory.

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
