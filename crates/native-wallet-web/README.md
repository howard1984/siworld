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
```

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
