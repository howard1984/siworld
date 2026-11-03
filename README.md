# SIWORLD — post-quantum private payments (in development)

[![CI](https://github.com/siworld-labs/siworld/actions/workflows/ci.yml/badge.svg)](https://github.com/siworld-labs/siworld/actions/workflows/ci.yml)
[![License: GPL-3.0-only](https://img.shields.io/badge/license-GPL--3.0--only-blue.svg)](LICENSE)

Rust implementation and research for shielded multi-asset payments with native
STARK transaction proofs and confidential fee settlement.

**Engineering target ≥80-bit quantum security, pending independent review.**
The public native V1 test network and production network are not available. Use only
disposable test keys and valueless test assets.

## Implementation status

| Status | Scope |
| --- | --- |
| Done | Native V1 transaction, fixed-576 settlement and three-note issuance proof parameters engineering-frozen for `native-v1-economics-1`; public verifier artifacts and source-bound measurements |
| In progress | Native node/wallet/network integration, release validation and launch-time fund configuration |
| Not yet | Independent security review: pending; public test network: not available; production network: not available |

The revised transaction relation checks input unlock heights against the
canonical snapshot height. Its selected profile measured **1.463 seconds median
four-worker generation**, **17.007 ms median one-worker verification** and a
maximum **588,832-byte proof body** across the selected one/four-worker trials.
The four-worker process-tree peak was **525,234,176 bytes**. The selected
instance-specific quantum Johnson ledger is **81.692 bits**. The
[relation manifest](crates/bench-multi-asset/artifacts/v1-native-proof-profiles.json),
[measurement scope](docs/v1-multi-asset-evaluation.md) and
[reproduction procedure](docs/native-proof-profiles.md) bind these results to
fixed sources, parameters and public keys. Engineering freeze does not establish
independent review, native-network activation or whole-node resource acceptance.
See [current decisions](docs/00-decisions.md) and the
[economic specification](docs/v1-economics.md).
The default workspace node uses the **legacy recursive proof route**. The
retained seven-node N=2 engineering testnet does not run native V1.

## Native V1 design

- **One transaction shape:** two inputs and three outputs, private 32-byte
  asset identifiers in one shared privacy pool, per-asset conservation and
  SIP-only confidential fees. Standard transfers and valid zero-value padding
  use the same public format.
- **Native verification:** wallets produce one D8/W24 STARK transaction proof.
  Nodes verify on admission; miners generate one separate native settlement
  proof per block. V1 does not recursively aggregate transaction proofs.
- **Blocks:** 64–576 positions in groups of 16, with a 300-second PoW target.
  Strict ordering by proof-independent BLAKE3 statement identity and duplicate
  rejection are enforced by the native engineering runtime.
- **Lifecycle:** permanent public ledger data; transaction, settlement and
  issuance proofs plus private fee sidecars expire three days after final
  confirmation. Checkpoint bootstrap has an explicit trust boundary.
- **Privacy limits:** on-chain commitments hide fee openings. Sidecar recipients
  learn those openings; miners recognize their own padding. Uniform encodings
  are intended to reduce on-chain classification. Headers/PoW, commitments,
  ciphertexts, nullifiers, issuance and signed fund records remain public.
  Source anonymity and computational indistinguishability require separate
  analysis and acceptance.

The Plonky3 proof suite uses **KoalaBear D8, standard Poseidon2 W24 and
twelve-element (48-byte) digests**. Output encryption uses **ML-KEM-768** and
ChaCha20-Poly1305; **ML-DSA-65** authenticates public development-fund payouts
and issuance declarations. Their native wallet/node integration is a separate
launch gate. The selected transaction body cap is **640 KiB**; settlement
and issuance have separate **512-KiB** caps. The conditional complete network
budget requires **43 Mbps minimum uplink**, with **100 Mbps recommended**.

## Documentation

| Start here | Scope |
| --- | --- |
| [V1 overview](docs/v1-overview.md) | Transaction flow, implementation boundaries and trust assumptions |
| [Current decisions](docs/00-decisions.md) | Authoritative protocol requirements |
| [Architecture](docs/architecture.md) and [protocol](docs/protocol.md) | Selected native design and legacy separation |
| [Native transaction specification](docs/route-a-v1.md) | Transaction proofs and integration requirements |
| [Multi-asset format](docs/v1-multi-asset.md) and [fee settlement](docs/fee-settlement.md) | Asset conservation, issuance and confidential reward accounting |
| [Proof reproduction](docs/native-proof-profiles.md) and [measurements](docs/v1-multi-asset-evaluation.md) | Source-bound parameters, public keys, security accounting and measured limits |
| [Node/network milestones](docs/v1-node-network-plan.md) | Integration work and exit conditions |
| [Testnet acceptance](docs/prover-acceptance.md) | Independent review, state, network, resources and recovery gates |
| [Deployment and monitoring](docs/v1-deployment.md) | Roles, candidate hardware and qualification |
| [Documentation index](docs/README.md) | Storage, transport, development, legacy implementation and paused V2 research |

| Resource | Qualification profile |
| --- | --- |
| Linux qualification minimum | Ubuntu 24.04 collector, x86-64-v3 CPU/OS support, at least four available vCPUs; record each actual allocation |
| x86_64 release baseline | Fixed `x86-64-v3`, including AVX2 and CPU/OS-state admission checks; no scalar fallback |
| Validator / miner minimum RAM | 16 GB validator / 32 GB miner; at least 15 GiB / 30 GiB system-visible memory respectively; sustained integrated qualification remains separate |
| Usable SSD | 500-GB installation floor; 1 TB recommended; lifetime depends on workload |
| Uplink | Conditional 43-Mbps minimum; 100 Mbps recommended |
| macOS / Windows | Native packaging, resource and recovery qualification pending |

These are admission floors, not guarantees of sustained workload performance.
The 5-GiB proof experiment is not a miner RAM requirement. Follow
[deployment qualification](docs/v1-deployment.md) before operating a new native
network.

## Proof validation

Rust is pinned in [rust-toolchain.toml](rust-toolchain.toml). Reproduce the
native proof components with the isolated workspace:

```sh
cargo test --release --locked --manifest-path crates/bench-multi-asset/Cargo.toml --features security-report --lib
python3 scripts/check-repository.py
```

See [the proof workspace](crates/bench-multi-asset/README.md),
[validation coverage](docs/testing.md) and [contribution requirements](CONTRIBUTING.md)
for complete commands. Passing proof CI does not establish a running native V1
network or hardware acceptance.

## Legacy node builds

The existing node commands build the legacy recursive runtime, not native V1:

```sh
cargo build --release --locked -p siworld-node
python3 scripts/check-node-features.py
```

Default binaries enable Plonky3 and reject mock-proof networks. Explicit
`development` builds use forgeable mock proofs and are test tools. Follow the
[legacy node operations](docs/legacy/node-operations.md) and
[legacy RPC/recovery](docs/legacy/rpc.md) documentation for that implementation.
No deployment-qualified native V1 launch command is available before runtime
integration and acceptance are complete.

## Support

SIWORLD is supported by 22,336 USDC in donations from friends of the project, as of 28 October 2026.

## License

[GPL-3.0-only](LICENSE). Required third-party attribution, including references
to [midstate](https://github.com/ciphernom/midstate), is recorded in [NOTICE](NOTICE).
