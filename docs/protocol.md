# Native V1 Protocol Requirements

The [selected monetary rules](v1-economics.md) are implemented under relation
revision `native-v1-economics-1`. The revised transaction, settlement and
issuance AIRs have source-bound security and reference-host measurement
records. Public-key reproduction and complete CI remain release gates;
engineering proof qualification does not activate a network.

Status: selected native V1 requirements and isolated proof implementations.
[Current decisions](00-decisions.md) are authoritative. The complete native
block runtime and network are not activated. Existing source constants and
commands belong to the [legacy protocol](legacy/protocol.md) unless an
integration milestone explicitly adopts and tests a native rule.

## Transaction and proof format

All payment/padding transactions use two inputs and three outputs. Notes bind
a private 32-byte asset ID, owner, integer amount, unlock height and randomness.
The relation balances each asset independently; fees use SIP only. A nonzero
input requires membership. Zero-valued inputs skip membership but retain
authorization/nullifier derivation; nodes must reject duplicate nullifiers.

Depth-12 recent-root membership is checked inside the transaction AIR. Nodes
accept the newest 4,096 canonical-chain snapshot identities and reconstruct
their trusted roots. Snapshot age 4,095 passes; age 4,096 and orphaned identities
fail. The proof binds the selected snapshot context and all ciphertext bytes.
V1 does not prove ML-KEM/ChaCha20 encryption correctness; sender self-check and
recipient AEAD/commitment checks form the separate encryption boundary.

The suite is KoalaBear D8, standard Poseidon2 W24 and twelve-element digests.
The transaction profile is b7/q41 with 20-bit query/batch grinding, zero
commitment grinding, binary folding and final-polynomial log length zero.
Its engineering cap is **655,360 bytes (640 KiB)**; settlement uses the same
**655,360-byte** cap and issuance retains a separate **524,288-byte** cap. The [relation manifest](../crates/bench-multi-asset/artifacts/v1-native-proof-profiles.json)
records the economic transaction shape, exactly 576-position settlement and
exactly three-initial-note issuance with source-bound public keys. The transaction
AIR has 256 base rows, 1,392 main columns, 247 preprocessed columns and 101
public values. The selected reference trials satisfy the two-second generation
target; the largest selected proof across one- and four-worker trials is
588,832 bytes. This does not adopt an issuance note limit or qualify other capacities. See
[profile reproduction](native-proof-profiles.md) and [measurements](v1-multi-asset-evaluation.md).

**Engineering target ≥80-bit quantum security, pending independent review.**
Require classical conjectured security ≥128 bits; Johnson Fiat–Shamir query
and enforced-grinding terms ≥80 bits after quantum halving; challenge-domain
terms ≥80 bits after halving; and selected BHT commitment collision resistance
≥80 bits. Estimator outputs do not establish full-system approval.

## Block and state-transition requirements

| Requirement | Native V1 value or invariant |
| --- | --- |
| Capacity | 64–576 positions, divisible by 16 |
| Target interval | 300 seconds; PoW timing is stochastic |
| Position ordering | Strictly ascending proof-independent, domain-separated BLAKE3 statement ID; reject duplicate IDs |
| Identity inputs | Canonical network, suite, snapshot identity, public body and fee commitment; exclude proof bytes/length/randomness and sidecars |
| Nullifiers | Validate every input and reject repeated or previously spent values |
| Fees | Standard/priority anchored schedules, on-chain commitments, private validated openings, SIP-only payment |
| Settlement | Independent native proof binds ordered fee commitments, height/mode, a node-recomputed consensus reward plan and all one or five SIP miner reward notes; the shared node transition independently validates pool/burn/fund state |
| Subsidy | Nominal 87% miner / 10% independent development-fund entitlements / 3% Holder pool; fees remain entirely with the miner |
| Reward mode | Explicit Voyager or Holder selection per block template; no default or mid-template change |
| Reward locks | Initial note matures after 24 blocks; Holder adds four height-locked notes; input unlocks use the trusted selected snapshot height |
| Economic state | Pool deposits/draws, cumulative burn and independent fund vesting/spending roll back atomically |
| State application | One deterministic integer-only atomic transition for production, validation and replay |
| Reorganization | Local `MAX_REORG_DEPTH=24`; deeper recovery requires an explicit procedure |
| Network capacity | Conditional minimum 43-Mbps uplink; 100 Mbps recommended |

The isolated native block codec and shared transition enforce strict BLAKE3
ordering and duplicate-ID rejection. Maintain swapped-ID, duplicate-ID,
proof-replacement and sidecar-independence tests. This implementation does not
by itself establish deployed-network acceptance.

The native public position ledger is 2,115 bytes: the 2,027-byte three-output
body, 48-byte fee commitment and 40-byte snapshot selector. Complete envelope
framing, issuance bounds and native node admission remain integration gates.
The complete conditional [wire model](v1-network-budget.md) uses separate
proof caps and three relay copies; it is not observed whole-network throughput.

## Issuance and privacy

Assets share one privacy pool. ML-DSA-65 authenticates public fixed-supply
issuance declarations, and a native issuance proof binds hidden minted notes
to declared supply. Atomic SIP fee consumption, replay rejection, registry
updates and issuance resource policy remain node/protocol gates.

Padding uses the same public format and genuine encryption to ephemeral
ML-KEM recipients. Uniform formats and fee commitments limit specified
on-chain signals; they do not prove perfect indistinguishability. Sidecar
recipients know fee openings and producers know their own padding. Public
metrics must not reveal fee tiers, individual fees or padding classifications.

## Retention and bootstrap

All nodes permanently retain headers/PoW, output commitments/tree state,
ciphertexts, nullifiers, fee commitments, proof-free settlement declarations,
reward notes, signed fund records, issuance records and recent-root snapshots.
Transaction, settlement and native issuance proofs and private fee sidecars
expire **259,200 elapsed seconds after final confirmation**, subject to durable
finality metadata and fail-closed recovery. V1 has no archive-node role.

New nodes default to release-pinned checkpoints under explicit two-of-three
authority trust and verify subsequent PoW and blocks. This does not
independently validate deleted pre-checkpoint proof history. See
[storage and sync](v1-storage-and-sync.md), [network design](v1-network-design.md)
and [testnet acceptance](prover-acceptance.md).

## Legacy separation

The retained seven-node N=2 engineering testnet uses classical D4/W16 recursive
proofs, two-output slots and the legacy 100-block reorganization bound. Its
verifier, keys and history remain unchanged. Native V1 requires independent
genesis, directories and keys. Recursive aggregation and historical compression
are [paused V2 research](v2/README.md), not V1 acceptance criteria.
