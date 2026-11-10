# Engineering-v2 wallet runtime

## Status and trust boundary

The portable `Eng2LightState`, explicit `BrowserWallet` eng2 methods and
worker-only `Eng2Session` implement a staged receive, balance and history path.
They are separate from the engineering-v1 light wallet and compact history.
The existing website build, vault selection and worker dispatcher remain
engineering-v1. Importing this module does not activate a website or service.

The client verifies complete native-header continuity, median time past,
ASERT difficulty, proof of work, cumulative work and receipt authentication
against each header's body commitment. It scans the complete receipt prefix
from the independently pinned engineering-v2 genesis. It verifies local tree
and owned membership-path consistency. It neither imports a full-node state
snapshot nor skips an unavailable prefix using a checkpoint.

`full_node_consensus_verified` and `send_supported` are both `false`.
Transaction proofs, settlement proofs, governance authorization, economics and
the execution commitment are not independently verified by this light client.
The API uses the trust label
`eng2-header-work-and-body-receipt-authenticated-full-node-consensus`.
A caller must not present it as full-node consensus validation.

## Immutable context

The configuration requires version 2, name `siworld-eng-2`, nonzero network,
genesis, rules and native-profile identifiers, fee mode 0 (`LegacyMiner`), and
an exact HTTPS or loopback API origin. These values are local pins. They are
not learned from the service. The native context authenticates the complete
genesis bytes against the pinned identifier and compiled native proof profile.
Other fee modes and legacy genesis or compact encodings are rejected.

The staged client supports at most 100,000 scanned headers. It requires
complete permanent receipt history from genesis. A missing record pauses
synchronization and preserves the previous committed balance.

## Read API

The source adapter uses the following routes:

- `GET /api/v2/wallet/genesis` returns pinned raw genesis bytes.
- `GET /api/v2/wallet/head` returns version, network, genesis, rules, profile,
  fee mode, height, tip and publication timestamp.
- `GET /api/v2/wallet/headers?height=H&tip=T&from=F&limit=L` returns a context-bound
  header page with at most 128 headers.
- `GET /api/v2/wallet/receipts/N/I?height=H&tip=T` returns the permanent receipt
  at height N and selected header identifier I under the same accepted-head pin.

Head publication must be no more than 300 seconds old or 30 seconds in the
future. This is a freshness check on a service export, not proof of current
peer connectivity. The client rechecks the head before durable adoption.
Transport admission or an unsigned head response does not establish native
proof validity. Redirects, credentials and legacy endpoint fallback are absent.

## Candidate adoption and local storage

All block work and receipt checks finish in an isolated native candidate.
Candidate append returns height, tip and `committed:false`; it does not return
candidate balances as final. Adoption requires reaching the exact pinned head
and greater cumulative work for a changed tip. The current local balance
remains available as stale data if a scan fails.

The IndexedDB namespace contains network, genesis, rules, native profile and
fee mode. No engineering-v1 database, journal, compact cache, vault store or
migration is accessed. Cache and scan metadata are encrypted inside the wallet
and saved in one database transaction before synchronous native adoption.
The cache additionally binds the derived wallet address, full native header
history, frontier, recent roots, assets, receipts and private owned paths.
Cache restoration accepts only a same-wallet authenticated local envelope;
it is not a remote state-import interface.

Local cache encryption uses `SWE2SC01` and journal encryption uses `SWE2JL01`,
with separate domain-separated keys. Plain cache bytes and decrypted note
metadata must remain in the worker and must never be sent to a service.
A cancelled scan, head race, authentication failure, foreign cache or failed
storage transaction preserves the preceding committed state.

## Remaining integration

A dedicated engineering-v2 custody/backup namespace, website dispatcher and
pinned build manifest are required before exposing this runtime in a website.
A new compatible WASM artifact and endpoint/export deployment must be qualified
separately. This source does not supply either deployment.

Sending requires exact anchored transaction witness preparation, native
proof runtime and profile dispatch, a durable payment journal, submission
admission, and receipt-confirmed inclusion. These capabilities are not enabled
by this staged receive/balance runtime. Owner custody data is not required for
source or synthetic fixture validation.
