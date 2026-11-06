# Engineering V1 browser wallet

Status: local engineering implementation. Public hosting, independent review
and physical-phone send measurements are incomplete. Only `siworld-eng-1` can
be configured. This implementation does not connect to the legacy website
wallet derivation or its mock-chain API.

The wallet creates/restores native V1 keys, encrypts local custody, authenticates
compact public history, scans balances locally and generates new SIP transaction
proofs in WASM. Historical transaction validity trusts full-node consensus;
the browser checks header work and compact byte authentication without replaying
historical transaction, settlement or issuance proofs. See
[the light protocol and Vault design](../../docs/v1-browser-wallet.md).

Sending supports ordinary and priority fees with the native two-input limit.
An encrypted journal reserves inputs before proving and saves the finalized
packet before explicit transmission. Uncertain submissions retain reservations
and retry the same packet. Phone sending remains disabled. Token balances can
be scanned, but this UI sends SIP only. The engineering journal is limited to
16 tracked payments; capacity exhaustion fails closed rather than discarding
payment history. A public short-address directory is not implemented: short
addresses require a locally imported matching full-address contact record.
Native version-1 JSON recipient files remain compatible with miner tools.

Vault is an independent off-chain backup service, using another application
origin, random credentials and separate local storage. It never inherits wallet
keys or a wallet login. The server stores fixed 512 KiB encrypted snapshots.
Local content packages retain their individual passphrases. Recovery requires
an independent encrypted recovery file and sync passphrase. Wallet recovery
words do not recover this Vault account.

## Multiple accounts and local names

An unlocked recovery phrase can derive up to 10 locally managed account
indexes on the pinned network. **Create new wallet** selects the next unused index;
it does not generate another phrase. Account derivation copies seed entropy
only inside WASM. A newly created wallet cannot derive accounts until its
recovery challenge is complete. One management panel is expanded at a time,
with a separate private balance scanner and encrypted payment journal per account.
Accounts share a locally authenticated public-history frontier. Checked history
prefixes are encrypted every 16 blocks and on an interrupted extension, so a
new account continues the existing history work. Exact birthday frontiers are
also encrypted for reuse when switching back to an earlier account. Account
balances become current only after their own scan and journal commit together.
If the optional commitment-projection service is unavailable, the worker
authenticates the same frontier from public compact records. It erases those
historical input bytes after use and does not persist pre-birthday ciphertext
downloaded only for tree authentication. Invalid authentication fails closed.
Switching is blocked while the payment panel is open or a proof is running.
Collapsed balances show their last scanned block rather than implying that
every account is synchronized in the background. Read-only deployments keep
all sending controls disabled.

The wallet collection displays its current count and the ten-wallet limit.
At capacity the creation button is disabled, while existing expandable
management panels remain available. The local registry enforces the same
limit during creation and backup import, including concurrent tabs; invalid
or oversized imports do not overwrite existing local data.

Names are optional display metadata, limited to 48 visible Unicode code
points and rendered as text. Names and account indexes are encrypted with
the account-zero local-storage key before being written to IndexedDB. The
key derives from the recovery material and network inside WASM; it is not
stored beside the ciphertext. The storage lookup key hashes account zero's
public address. Decrypted names remain in the page/worker memory only while
unlocked. They are never included in HTTP requests, address-directory entries,
transactions, node exports, telemetry or Vault snapshots. IndexedDB is local
browser storage; it is not an online backup.

The locked-device selector identifies encrypted seed records by stable local
record IDs. It remembers the last selected record across lock and reload;
names become available only after decryption. Indexed accounts created from
the same recovery phrase share that seed record and its device password.
Renaming an account or exporting its registry interrupts pending balance
downloads before entering the serialized worker queue. Synchronization then
resumes without discarding accepted scan state or the payment journal.

A manually downloaded version-2 encrypted wallet backup includes the
encrypted account registry. The device password protects the seed backup;
the recovered seed decrypts the registry. Version-1 backups remain readable.
Restoring words on another device can derive the same indexed addresses,
but cannot discover names or unused indexes that existed only on the original
device. Retain the encrypted backup and note which indexes were used. Import
validates registry authentication and bounds before preserving a backup.
Existing local names take precedence when importing older registry entries.

The transaction list has All, Received and Sent filters, 20-row pages and
expandable details. Incoming payments and mining tranches are rebuilt by
local compact-data scanning; change outputs and zero-value notes are omitted.
Mining tranches from the same block and asset are grouped, with individual
unlock heights in the details. Reorganizations rebuild receipts from the
accepted candidate chain. Sent status, amount, fee and recipient come from
the encrypted local journal, which is currently bounded to 16 payments per
account. A phrase-only restore cannot recover outgoing details from another
browser. No additional server-side account or transaction index is introduced.

## Build and service configuration

Install the `wasm32-unknown-unknown` Rust target and
`wasm-bindgen-cli 0.2.120`. Build into a fresh directory:

```sh
python3 crates/native-wallet-web/build.py --output build/wallet-v1 \
  --network-manifest engineering-public.json \
  --rules-file engineering-network.bin \
  --chain-api https://chain.example.invalid \
  --vault-manifest vault-services.json
```

The public network manifest must contain `name: siworld-eng-1`, a native
`network` ID and `genesis_id`. The rules file must match that network and use
the original timing profile. Do not substitute a genesis hash for a network ID.
A build without pinned services cannot synchronize or send. The
`browser-fixtures` feature is restricted to disposable synthetic local tests
and must never be enabled in a deployed build.

The Vault manifest has `api`, `application` and `wallet_application` URL fields.
Wallet and Vault application origins must differ; cookies, URL parameters,
messages and DOM state do not transfer wallet identity between them. Builds remap machine-local compiler paths to stable source prefixes. Generated
configuration and runtime artifacts are not source fixtures. Host only the
appropriate application on each origin; the local reference directory contains
both entry pages for integration testing.

The optional native `wallet-light-gateway` feature connects to the existing
canonical owner through a private Unix socket when
`SIWORLD_WALLET_GATEWAY_SOCKET` is set. Its existing parent directory must be
owned by the service account and mode 700; the socket is mode 600. This feature
adds no TCP listener, wallet custody, remote scanning or proving API.
`tools/engineering-services.py` is a bounded loopback reference adapter for that
socket and for a separate Vault ciphertext database. It is not a complete
public TLS/enrollment/rate-limit deployment. Do not expose native IPC or an
existing local wallet server to the Internet.

Serve applications over HTTPS, with `X-Frame-Options: DENY`,
`Cache-Control: no-store`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer` and a CSP header containing
`frame-ancestors 'none'`. The HTML restricts scripts, workers, forms and exact
service origins. No analytics or third-party secret-page dependencies are used.
The admission endpoint can observe the fee opening and submission IP/timing;
separate Vault credentials do not guarantee anonymity against traffic analysis.

## Targeted validation

```sh
cargo test --locked --release --manifest-path crates/native-wallet-engine/Cargo.toml
cargo test --locked --release --manifest-path crates/native-wallet-core/Cargo.toml
WALLET_PARITY_OUTPUT=/tmp/wallet-native-vectors.json \
WALLET_PARITY_VAULT=/tmp/wallet-native-vault.json \
cargo test --locked --release --manifest-path crates/native-wallet-core/Cargo.toml \
  --features native-parity --test native_parity
WALLET_WEB_OUTPUT="$PWD/build/wallet-v1" \
WALLET_PARITY_OUTPUT=/tmp/wallet-native-vectors.json \
WALLET_PARITY_VAULT=/tmp/wallet-native-vault.json \
node --test crates/native-wallet-web/tests/browser-core.test.mjs \
  crates/native-wallet-web/tests/content-vault.test.mjs
python3 crates/native-wallet-web/tests/services-test.py
node --test crates/native-wallet-web/tests/storage-selection.test.mjs
```

The optional browser lifecycle regression uses Playwright and an unpacked
engineering build with supported pinned protocol parameters. It serves an
empty localhost chain, creates disposable wallets, stalls synchronization,
and verifies rename, backup, selection persistence and password retry. It
blocks external requests and never submits payments:

```sh
WALLET_WEB_OUTPUT="$PWD/build/wallet-v1" \
node crates/native-wallet-web/tests/wallet-lifecycle.browser.mjs
```

Install Playwright in the test environment, or set `WALLET_PLAYWRIGHT` to its
module entry point. `WALLET_BROWSER` optionally selects a Chromium executable.

The shared-history regression accepts a two-block fixture directory in
`WALLET_FIXTURE_DIR` with protocol parameters supported by the wallet build.
Synthetic parameters require `--browser-fixtures`; public engineering blocks
work with the standard engineering build. The test returns HTTP 400 for
projections, interrupts one account during synchronization, and checks that
another account resumes verified history without downloading it again:

```sh
WALLET_WEB_OUTPUT="$PWD/build/wallet-fixtures" \
WALLET_FIXTURE_DIR="$PWD/build/wallet-fixtures-data" \
node crates/native-wallet-web/tests/shared-history.browser.mjs
```

Set `WALLET_TEST_STAGGERED_BIRTHDAYS=1` to create accounts at different block
heights. This case verifies that returning to the interrupted earlier account
reuses its encrypted boundary; only its later blocks need a receipt scan.

Parity data uses only disposable synthetic phrases, never a real wallet.
These tests exercise application compatibility and hostile-data boundaries;
they do not replace native consensus or hardware qualification. Range-proof
verification requires independent review before mainnet use.

## Optional local proving experiments

The default WASM artifact uses one proving thread. A dedicated Worker keeps
that computation off the UI thread; it is not a parallel prover. `--wasm-simd`
enables the existing dependency SIMD implementations. `--wasm-threads` also
enables the existing backend parallel feature and pinned thread adapter; it
requires a build-std-capable Rust toolchain with `rust-src`, plus COOP
`same-origin` and COEP `require-corp` on the application and worker responses.
The browser worker initializes at most four proving threads. It rejects a
threaded build when cross-origin isolation is missing; use the separately built
standard artifact on unsupported browsers. The build does not silently enable
parallelism or change frozen proof source, parameters or verifier keys.

Use `--browser-fixtures` only for synthetic local measurements. It is rejected
with a deployment manifest. Keep fixture artifacts separate from release
artifacts. Compare actual generation plus the unchanged native verifier's local
self-check, WASM high-water allocation and sampled browser process memory on
the same device. Record compiler flags, artifact hashes and thread counts.

Payment preparation reports actual input-preparation, durable-reservation,
proof-generation/local-verification and encrypted-packet-save stages. The
prover call has no arithmetic progress callback, so the activity bar is
indeterminate until successful completion. Elapsed time updates on the UI
thread. Before a first proof, the desktop reference is labeled as a reference;
later remaining-time estimates use only the latest three successful durations
in this page session. An overrun never becomes a fake completion percentage.
Preparing a proof does not transmit it; explicit review and submission remain
separate actions.


## Read-only public file export

The disabled-by-default `wallet-light-gateway` feature can export accepted public
chain data when `SIWORLD_WALLET_PUBLIC_EXPORT` names an existing private mode-700
directory owned by the node process. The node service must run as `siworld`;
exported files inherit that owner and have mode 600. No environment setting means
no export. File export creates no socket, listener or request worker, and has no
submission or administrative capability. The existing owner-only mode-600
`SIWORLD_WALLET_GATEWAY_SOCKET` is a separate local reference interface; it is
not enabled by file export. Setting both disables the optional export and logs
a generic initialization failure without stopping the node.

The public directory contains immutable identity-addressed compact `.bin`
records and an atomically replaced `chain.json`. Records contain only public
headers, commitments, ML-KEM ciphertexts, view tags, nullifiers and tree/authentication
state required by the light client. They exclude full transaction proofs, fee
openings, peers, mempool contents and local secrets. The index contains only
version, network, genesis, height, tip and canonical block identities. No index
is published until every referenced record has been durably installed. A
reorganization replaces the canonical list while retaining previous fork records.
Export failures preserve the last complete index and never propagate into node
validation, state transitions or block admission. Generic diagnostics omit paths
and underlying error context; retries wait five seconds and runtime error logs
occur at most once per minute. No database format or consensus rule changes.

The local index is bounded to one million identities and 68,000,512 bytes.
Publication occurs at most once per five seconds; remote transfer must use pages
of at most 128 identities. Exporting one record per canonical-owner turn and
serializing the index adds bounded local I/O; this is not a production-node
performance qualification. Monitor owner-loop latency before production use.

A separate outbound uploader reads only the public export directory through a
read-only sandbox mount, using the restricted `siworld` UID to read mode-600
files. It receives no node database, wallet files, configuration or reference
IPC. It initiates authenticated HTTPS transfer to an independent archive receiver
(or an independently authorized private object-storage relay). Receiver activation
requires authenticated record validation, bound network/genesis, continuity and
an atomic complete-index switch. The wallet host serves static pages and a
read-only API over its stored copy; it never connects to a node port and runs no
node. Transaction broadcast is a separate unimplemented deployment prerequisite;
this update adds no submission channel or relay. Uploader, receiver, credentials,
production sandboxing and any service activation are outside this public patch.

`siworld-compact-inspect` accepts at most 8,388,656 bytes on standard input and
returns authenticated public identity, network, height, parent and SHA-256.
It verifies the existing compact authentication format. It does not generate
or replay transaction/settlement proofs, select a chain or replace browser
header work/continuity validation.

## Static release integrity

`tools/package-release.py` consumes an existing web build and pinned esbuild
0.25.12. It emits separate wallet and Vault distributions, immutable release
paths, script/style SHA-384 SRI, a fixed integrity value on WASM fetches, static
same-origin Workers and a complete activation manifest. The threaded adapter
uses at most four Workers and requires COOP/COEP. Packaging fails if the pinned
upstream adapter layout differs; no Blob or dynamic-import fallback is used.
Private deployment artwork must be included before final integrity generation.

Verify every distribution file with `verify_release` before activation, passing
an independently approved SHA-256 of the complete manifest as
`expected_manifest_sha256`, and mount releases read-only at runtime. Without
that external pin, manifest verification checks self-consistency only. Main-script SRI does not transitively
verify Worker responses: `new Worker()` has no native SRI parameter. Worker
integrity therefore depends on the fixed same-origin loader path, HTTPS, strict
`worker-src 'self'`, immutable paths and trusted preactivation verification.
Do not describe this as browser-enforced Worker SRI.

The generated response-header manifest requires a CSP with no inline script
or JavaScript eval, only same-origin resources and `wasm-unsafe-eval` for WASM,
plus COOP `same-origin`, COEP `require-corp`, CORP `same-origin`, frame denial
and no-referrer. A deployment must enforce these as HTTP headers on HTML,
Workers, errors and relevant API responses. The packager does not provision
TLS, DNS, a public perimeter, source agents or durable Vault storage.
