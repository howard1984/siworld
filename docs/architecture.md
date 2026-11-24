# System Architecture

Status: selected native V1 architecture with implemented isolated proof
components. The complete native node, wallet and network path is not yet
integrated. [Legacy architecture](legacy/architecture.md) documents the
runnable recursive implementation.

## Components and implementation boundaries

| Component | Present scope | Native V1 boundary |
| --- | --- | --- |
| `crates/bench-multi-asset` | Transaction, issuance and settlement AIRs, native proof tools and codecs | Source-bound economic profiles; public-key reproduction and full CI remain release checks |
| `crates/bench-d8` | Earlier two-output native proof baseline and dependency adapter | Diagnostic baseline; does not activate the three-output profile |
| `core`, `crypto`, `state` | Shared integer monetary reference and legacy cryptographic/state primitives | Native integration explicitly binds types, network identity and economic state |
| `crates/native-node` | Isolated codec, shared transition, admission, sync/forks, wallet and audit interfaces | Atomic economic state and audit are implemented; live transport and deployment remain unqualified |
| `circuits`, `prover`, `bench-stark` | Legacy recursive proof route and pinned keys | Retained runtime and paused V2 review surface |
| `consensus`, `storage`, `node` | Legacy block production/validation, persistent full-block replay, libp2p and local RPC | Native block codec, common transition, admission, retention and transport remain milestones |
| `tools/control-panel` | Local operational interface for retained engineering nodes | It is outside consensus and is not native V1 deployment evidence |

The `native-v1-economics-1` transaction profile pins parameters,
source/dependency identities, security data and public verifier artifacts. The
[three-relation manifest](../crates/bench-multi-asset/artifacts/v1-native-proof-profiles.json)
also fixes public preprocessing identities for 576-position settlement and
three-initial-note issuance. Those shapes do not adopt broader issuance policy
or qualify other capacities. Standalone proof
success does not establish wallet, node, database or network behavior.

## Native transaction and block path

Wallets construct two-input/three-output transactions, encrypt and self-check
all outputs, and generate a native proof. Nodes must resolve the selected
snapshot from canonical local state, verify sidecars and proofs under bounded
resource admission, then atomically reserve nullifiers.

Miners assemble 64–576 positions in groups of 16. The isolated native codec and
shared transition enforce strictly ascending proof-independent BLAKE3 statement
IDs and reject equality. Proof bytes, proof lengths/randomness and fee sidecars
do not affect those IDs. A separate settlement proof binds ordered commitments
and all one/five mode-dependent SIP reward notes. The [monetary transition](v1-economics.md)
updates the Holder pool, cumulative burn and independent fund entitlements,
vesting and signed spending atomically with the block. Native production binds
an explicit Voyager/Holder preference at template creation. Deployment
qualification remains separate from the revised proof measurements.

Production, validation and historical application must use one deterministic,
integer-only, atomic transition. Compact relay references accepted transaction
identities and recovers bounded missing data; it does not authorize skipping
proof validation. Isolated issuance proves exact hidden minted supply, while
node acceptance must also verify ML-DSA-65 and atomically consume its SIP fee
payment and update the registry.

## Storage and synchronization

Native V1 permanently retains public ledger data and deletes transaction,
settlement and native issuance proofs plus fee sidecars three days after final
confirmation. Finality/deletion metadata must survive restarts and recovery.
The retained native implementation has a 24-block local reorganization bound.
The [candidate profile](protocol.md#candidate-mining-and-checkpoint-finality)
instead finalizes history covered by a valid 2-of-3 checkpoint and selects
greatest cumulative valid work above it. It is not activated by this document.
The accepted snapshot window is the newest 4,096 canonical identities.

Default bootstrap uses a release checkpoint under explicit genesis-pinned
quorum trust, followed by PoW and normal block verification. PoW cannot replace
deleted historical proof validity. See [storage and bootstrap](v1-storage-and-sync.md).
The legacy runtime retains full blocks/proofs and has a 100-block bound.

## Network, platform and observability

Hybrid X25519 + ML-KEM transport, dual identity authentication and Dandelion++
are selected designs, not completed listeners. The current legacy transport is
TCP/Noise/Yamux with direct flooding. [Network design](v1-network-design.md)
defines the native requirements and adversarial tests.

Every validator independently enforces consensus; a miner adds production.
Discovery services and private monitoring collectors have no authority over
validity or fork choice. Telemetry must expose public health and bounded
resource measures without fee openings, sender endpoints or private payment
associations. See [deployment and observability](v1-deployment.md) and
[the implementation milestones](v1-node-network-plan.md).
