# Engineering-v2 wallet runtime

## Status and trust boundary

The portable `Eng2LightState`, explicit `BrowserWallet` eng2 methods and
worker-only `Eng2Session` implement a staged receive, balance and history path.
`Eng2WalletSession` composes that owner with the encrypted payment journal and
the explicit engineering-v2 admission adapter; construction leaves every
website mutation gate closed.
They are separate from the engineering-v1 light wallet and compact history.
The website builder accepts an explicit read-only engineering-v2 profile and
selects this worker runtime without constructing an engineering-v1 history
owner. The default unconfigured build remains inactive. Importing this module
does not activate a website or service.

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
Public reads use at most three transport attempts, each with a separate
30-second deadline and 0.5- then 1-second backoff. Network failures, timeouts
and HTTP 429, 502, 503 or 504 are retryable. Decoding, byte bounds, context
checks and native authentication remain outside that retry boundary.
Cancellation ends the pending request and backoff. The page retries a paused
synchronization after five seconds; a failed initialization is attempted again
by either the timer or the explicit synchronization control.

Transport admission or an unsigned head response does not establish native
proof validity. Redirects, credentials and legacy endpoint fallback are absent.

## Candidate adoption and local storage

All block work and receipt checks finish in an isolated native candidate.
Candidate append returns height, tip and `committed:false`; it does not return
candidate balances as final. A direct extension saves an authenticated prefix
every eight blocks after checking its work and the fresh service head's branch.
A competing branch is adopted only after the complete selected candidate passes
validation; partial competing prefixes never replace the accepted state.
Only the exact fresh head marks synchronization ready. Saved partial prefixes
remain stale, and reopening downloads only blocks after that durable prefix.
The current local balance remains available as stale data if a scan fails.

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

## Read-only website build

`build.py --eng2-manifest CONTEXT --output DIRECTORY` requires exactly version 2,
name `siworld-eng-2`, network, genesis, rules and native-profile identifiers,
fee mode 0, the API origin and `read_only:true`. Legacy rules/manifests,
synthetic fixture mode and a separate Vault manifest are incompatible with this
profile. The output fixes `desktop_send_measured:false` and installs the
engineering-v2 custody adapter as its storage entry point. Legacy builds keep
their existing storage adapter.

Encrypted vault records, account registries and selection preferences use a
separate database bound to network, genesis, rules, profile and fee mode. The
backup format is `siworld-eng2-wallet-backup`; its public context must match the
build before unlock/import. Vault encryption and address derivation retain
their existing native network binding. This adapter does not introduce a new
vault cipher or imply that its public backup-context fields are encrypted.
There is no legacy database discovery, backup conversion or automatic migration.

The worker independently rejects payment preparation, submission, cancellation
and public address registration in this read-only profile. UI flags cannot
enable them. A new compatible WASM artifact and a packaged browser integration
must still be qualified against the independently pinned genesis and profile.
This source does not supply a deployment or claim browser acceptance.

## Offline transaction interfaces

`Eng2LightState::prepare_sip` constructs the shared native witness from the
complete body-authenticated receipt prefix and owned membership paths. The
caller pins the network and exact current engineering-v2 header snapshot.
The fee schedule and frozen proof profile remain unchanged. The canonical
transaction-anchor lifetime is 4,096 blocks, independently of local proof
storage retention. Unknown, expired, future and foreign anchors are rejected.

`prove_sip` uses the frozen native transaction prover and independently verifies
the generated proof against the retained engineering-v2 snapshot. Packet
verification checks the exact network, snapshot identity, recent-root anchor,
fee opening and proof. It does not establish global admission or inclusion.
The framing is the native envelope followed by the fixed sidecar; the private
owner socket adds its own transport prefix.

The worker-only `Eng2Payments` journal durably encrypts input reservations and
payment openings before proving, and stores the finalized exact packet before
any transport call. It records uncertainty before an explicitly injected
admission adapter runs. Timeouts and ambiguous replies never release inputs;
reopening retries the same stored packet. Only an authenticated receipt under
a committed native header marks inclusion. A removed inclusion restores the
uncertain reservation. The receipt session and payment journal share a lock.
An interrupted reserved witness can be cancelled locally; it is never silently
reconstructed after reopening.

The composed website owner returns an allowlisted display projection, subtracts
held input totals from available SIP and never exports openings, input
commitments or exact packet bytes to the page. Accepted and uncertain rows keep
their reservations. A refresh scans at most 32 pinned receipts for unresolved
payments, authenticates them against committed native headers and resumes an
in-memory cursor. A branch change resets that cursor; a removed inclusion
restores uncertainty. Account switching and lock release only the in-memory
owner and preserve encrypted records. The history distinguishes pending
admission from authenticated inclusion.

The worker mutation gate remains closed, and both
`send_supported` and `full_node_consensus_verified` remain false. Local synthetic
framing tests, generated native proof tests and browser automation evidence
must be reported separately from deployed-chain transfer acceptance.

The source-level entry qualification reports `entry_qualified:false`,
`static_thread_adapter_qualified:false` and `live_transfer_qualified:false`.
Service replies and caller flags cannot change these values. A separate
packaged UI and static-worker trial, followed by deployed-chain transfer
acceptance, is required before a send-enabled release can be qualified.

## Engineering deployment artifact binding

`networks/eng2-readonly.json` fixes the current internal engineering network and
exact API origin. `releases/eng2-readonly.json` lists the complete eight-file
static release, raw packager inputs, tool versions and native runtime source
hashes. The runtime binary is reused from the corresponding nonfixture build;
the manifest does not assert that a fresh runtime compilation is byte identical.
Deployment records bind the published source commit to the immutable output
hashes outside the served static directory. An additional file in that
directory is rejected by the static integrity verifier. Sending remains closed.
