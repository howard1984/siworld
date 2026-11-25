<picture>
  <source media="(prefers-color-scheme: dark)" srcset="brand/siworld-on-dark.png">
  <img alt="SIWORLD" src="brand/siworld-on-light.png" width="300">
</picture>

# SIWORLD

**Private by default. Post-quantum by design. Mined on everyday CPUs.**

Rust implementation of shielded multi-asset payments with native STARK proofs and RandomX proof of work.

[![CI](https://github.com/howard1984/siworld/actions/workflows/ci.yml/badge.svg)](https://github.com/howard1984/siworld/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-GPL--3.0--only-blue.svg)](LICENSE)

## Protocol features

- **Every ordinary transfer is shielded.** The ledger conceals the payment graph, transfer amounts and assets, and the receipt height of spent notes.
- **Post-quantum cryptography protects payments and authenticates protocol actions.** Recipient data uses ML-KEM-768 and signed protocol messages use ML-DSA-65.
- **Native STARKs prove private state transitions without a trusted setup.** Nodes verify each transfer against the public statement.
- **RandomX runs on general-purpose CPUs.** Miners use the same proof-of-work algorithm to extend the chain.
- **Voyager and Holder spread new issuance over time.** The two mining modes use distinct subsidy allocation and locking rules and share the Holder pool.

## Documentation

| Resource | Purpose |
| --- | --- |
| [Whitepaper](docs/whitepaper.md) | Protocol design, privacy, and security assumptions. |
| [Specs](docs/README.md#protocol-specifications) | Consensus, proof formats, wire protocols, and validation rules. |
| [Run a node](docs/guides/run-a-node.md) | Installation, verification, and synchronization. |
| [Mine](docs/guides/mine-on-linux.md) | Linux installation, reward modes, and operation. |
| [Exchange integration](docs/guides/exchange-integration.md) | Deposit finality, withdrawal submission, and reconciliation. |

For the public network ID and address formats, see the
[protocol parameters](docs/reference/parameters.md). For memory sizing, see
the Linux miner's [recommended configurations](docs/guides/mine-on-linux.md#recommended-memory).

## Build from source

The Rust toolchain is pinned in [rust-toolchain.toml](rust-toolchain.toml). Install a C and C++ toolchain and CMake for the native dependencies. From the repository root, build the native node library with the peer and wallet gateway interfaces:

```sh
cargo build --release --locked --manifest-path crates/native-node/Cargo.toml \
  --features native-p2p,wallet-light-gateway --lib
```

Use the [node guide](docs/guides/run-a-node.md) for release-specific binaries and verification steps. The [contribution guide](CONTRIBUTING.md) lists local checks.

## Repository layout

| Path | Contents |
| --- | --- |
| [`crates/native-node/`](crates/native-node/) | Node validation, chain selection, storage, and peer services. |
| [`crates/bench-multi-asset/`](crates/bench-multi-asset/) | Native transaction, issuance, and settlement proof relations. |
| [`crates/native-wallet-engine/`](crates/native-wallet-engine/) | Wallet state, payment construction, and light verification. |
| [`crates/core/src/pow.rs`](crates/core/src/pow.rs) | Work-target arithmetic shared by the node runtimes. |
| [`crates/miner-cli/`](crates/miner-cli/) | Miner commands and local operation. |
| [`docs/`](docs/README.md) | Whitepaper, specifications, guides, and reference. |
| [`scripts/`](scripts/) | Build, packaging, and validation tooling. |
| [`tools/`](tools/) | Explorer and supporting tools. |

## Security

Use the [private disclosure process](SECURITY.md) to report a vulnerability. See the [security model](docs/security/security-model.md) for the protocol's trust and privacy assumptions.

## License

Software is licensed under [GPL-3.0-only](LICENSE). See [NOTICE](NOTICE) for third-party notices and [the brand license](brand/LICENSE) for logo assets.

[siworld.io](https://siworld.io/)
