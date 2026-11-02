# Native V1 browser wallet

Status: local custody and receiving implementation; chain synchronization,
browser proving, payment submission and a public short-address directory are
not implemented. The receiving text format is proposed and is not recognized by
the current native CLI. Exported version-1 JSON recipient files retain the
existing native format and can be used by native miner configuration tools.

The reference UI creates and restores native wallets in a dedicated worker,
requires a randomized backup challenge, encrypts custody locally and exports
encrypted backups and public receiving files. It does not reuse the legacy
website mnemonic derivation, storage namespace or mock-chain gateway.

Install the `wasm32-unknown-unknown` Rust target and `wasm-bindgen-cli 0.2.120`.
Build into a fresh output directory:

```sh
python3 crates/native-wallet-web/build.py --output build/wallet-v1
```

The default UI requires a native network ID. For an engineering deployment,
`--network-manifest engineering-public.json` pins the public ID at build time.
Do not substitute a genesis block hash. Runtime files are generated locally and
are not repository artifacts. Serve the result over HTTPS or loopback, with
`X-Frame-Options: DENY`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`
and a header CSP including `frame-ancestors 'none'`. The HTML also supplies a CSP
that prohibits all network connections and form submission.

## Targeted validation

```sh
cargo test --locked --release --manifest-path crates/native-wallet-core/Cargo.toml
WALLET_PARITY_OUTPUT=/tmp/wallet-native-vectors.json \
WALLET_PARITY_VAULT=/tmp/wallet-native-vault.json \
cargo test --locked --release --manifest-path crates/native-wallet-core/Cargo.toml --features native-parity --test native_parity
WALLET_WEB_OUTPUT="$PWD/build/wallet-v1" \
WALLET_PARITY_OUTPUT=/tmp/wallet-native-vectors.json \
WALLET_PARITY_VAULT=/tmp/wallet-native-vault.json \
node --test crates/native-wallet-web/tests/browser-core.test.mjs
```

The generated parity data uses only synthetic public test phrases. It must never
be produced from a real wallet. These are identity/custody compatibility tests;
they do not generate transaction/settlement proofs or rerun hardware acceptance.
