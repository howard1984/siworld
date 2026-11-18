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
an exact primary HTTPS or loopback API origin. Optional `apis` and
`submission_apis` arrays independently pin one or two data and admission
origins. The primary API must be the first data origin; duplicate origins,
credentials, paths and discovery are rejected. These values are local pins. They are
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
With two data origins, each retry rotates the origin within the same three-
attempt budget; it preserves the complete selected-head route and prefers the
last successful source for subsequent reads. Byte, context and native-authentication
failures do not trigger failover. The builder and static packager add only the pinned data and
admission origins to the final HTTP connection policy. The release manifest
records that exact list; release verification can independently pin it, and
activation still requires the approved manifest digest. Other CSP directives
and the separate vault origin retain their existing restrictions. A production two-source
configuration still requires independent export and admission qualification.
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

## Bounded rollback contract

Every nonzero saved head is looked up under the newly selected service head,
including a refresh whose advertised head has not changed. A mismatched hash
cannot mark the accepted balance ready. A complete native candidate must still
pass receipt and greater-work validation before adoption.

`eng2-rollback.js` supplies worker-private window selection and atomic storage
contracts. It retains at most 32 linked header identities and four encrypted
native caches captured at heights divisible by eight. For an accepted height H,
the earliest retained cache boundary is
`max(0, floor((H - 24) / 8) * 8)`. This includes the cache needed for a fork at
exactly H - 24, for every remainder of H modulo eight. Restoring the cache may
require replaying up to seven unchanged blocks before the common ancestor;
these remain isolated candidate work, without publishing intermediate balances.

The additional retained cache ciphertext has a total 64 MiB ceiling. This is a
local storage budget, distinct from the native per-cache 64 MiB plaintext limit
and its 48-byte encryption envelope. The current authoritative cache remains a
separate record. The encrypted rollback index is bounded to 16 KiB plaintext.
Capacity pressure drops older rollback caches and explicitly reports unavailable
coverage. A missing or incomplete window does not authorize a partial balance or
skip receipt authentication. The current complete historical candidate path is
still available when an earlier authenticated scan is required.

The accepted metadata, authoritative cache, encrypted index, occupied cache
slots and deletion of obsolete slots use one IndexedDB transaction. Payment
records and input reservations are outside this record set. The caller must hold
the existing wallet-owner lock and complete native adoption after durability,
including cancellation arriving during the transaction. Cross-tab freshness and
saved-prefix restoration continue to use the accepted metadata/cache pair.

`Eng2Session` collects a sealed cache at each global eight-block boundary
while staging receipts, independently of its durable prefix cadence. Reopening
loads the rollback index under the owner lock before restoring the accepted
cache. Legacy wallets without an index seed locally verified header identities
and retain explicit incomplete coverage until further authenticated scanning.
A missing cache window falls back to the complete historical candidate path.

`begin_eng2_cached_candidate` opens an authenticated private envelope into an
isolated native candidate. The cache must belong to the same wallet and exact
context, match the requested height/hash, and terminate at an accepted local
prefix at most 31 blocks back. That bound covers 24 changed blocks plus at most
seven unchanged replay blocks. The accepted balance and prepared witness remain
untouched. Receipts are replayed normally and the final complete-candidate and
greater-work checks still run before durable adoption. A failed or cancelled
candidate leaves the accepted metadata/cache/archive generation in place; a
cancellation arriving during persistence finishes matching native adoption and
keeps readiness false. A native commit failure after durability requires
reopening the complete saved generation.

The source contains offline native framing/work/cache tests and synthetic
JavaScript session tests for this path. Those tests do not establish real
transaction-proof verification, a packaged browser integration, a real five-
minute automatic lock, or deployed-network reorganization acceptance.

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

After a fresh native sync, automatic replay is considered only when the pending
statement set has completed every authenticated receipt batch through the same
committed head. Each candidate statement must belong to that scanned set.
Runtime flags cannot enable replay: the immutable entry, thread-adapter and
live-transfer qualifications must all be true, the profile must explicitly allow
sending, and the wallet must remain ready at the same head. The current compiled
qualification remains closed. Locking, cancellation, account release, partial
receipt scans and synchronization errors cannot initiate replay.

A qualified replay uses the exact stored packet and statement identifier after
native proof, anchor and input checks. It constructs no replacement witness or
proof. Included and never-submitted finalized records are excluded. Pending age
must reach 30 minutes, checks are serial and limited to two per refresh, and
retry delays are persisted with exponential backoff from five minutes up to an
hour. Permission is checked again after durable uncertainty and immediately
before transport. Invalid or expired original packets retain their reservation
without transport. A timeout retains the same packet, reservation and deadline.

History displays authenticated receipt confirmation counts. Fewer than 24
confirmations are labeled pending; this is a display threshold and changes no
native reward maturity, finality or consensus rule. Reward maturity remains a
separate label. A rescan replaces the history and may reduce counts or remove
orphaned receipts. Legacy history without confirmation metadata retains its
previous display behavior.

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

`networks/eng2-readonly.json` records the internal engineering network and API
origin used by the historical read-only release.
`releases/eng2-readonly.json` is that release's historical source manifest: it
lists eight static files, raw packager inputs, tool versions and native runtime
source hashes. It is not the manifest of a newly generated package. Its runtime
binary was reused from the corresponding nonfixture build; the manifest does
not assert that a fresh runtime compilation is byte identical.

Each new package records its immutable file hashes and approved connection
origins in its own `release-manifest.json`. The generated HTTP policy retains
`Strict-Transport-Security: max-age=31536000`; changing connection origins does
not shorten that policy. Deployment records bind the published source commit
to the immutable output hashes outside the served static directory. An
additional file in that directory is rejected by the static integrity verifier.
Sending remains closed.

## Admission-source failover

The explicit admission adapter may try the second configured submission origin
after a transport failure, timeout or HTTP 429, 502, 503 or 504. It uses a private
byte-for-byte copy of the same finalized packet and statement identifier, with
one 45-second attempt per origin. It does not prepare a new transaction, sign,
prove, alter fees or clear input reservations. Context, framing, response bounds
and acknowledgement validation remain mandatory; malformed or foreign replies
do not trigger failover. The returned acknowledgement remains pending and is
not inclusion evidence. This transport capability does not open website sending
or establish that either remote endpoint is deployed.
