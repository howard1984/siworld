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

## Candidate mining and checkpoint finality

Status: candidate requirements, distinct from the implementations retained in
this source revision. This specification does not activate a network or attest
to the software or parameters deployed on any node. Existing engineering and
legacy formats remain unchanged. Activation requires a source-bound release,
compatible genesis/rules, qualified clients and separate deployment acceptance.

| Parameter | Candidate requirement |
| --- | --- |
| Block work | RandomX v1.2.1 with SIWORLD-specific parameters and an independent SIWORLD salt |
| Work profile | CPU-friendly and memory-intensive; intended to reduce GPU/ASIC advantages |
| Block interval | 300 seconds as a stochastic target, not a deadline |
| ASERT half-life | 3,600 seconds (one hour) |
| Initial difficulty | Measured effective work rate in valid attempts per second multiplied by 300 seconds, with the consensus difficulty representation and rounding fixed before activation |
| Miner work threads | Available CPU cores minus two by default; explicitly configurable |
| Finality | Coverage by a valid checkpoint certificate signed by two of the three authorized checkpoint signers (2-of-3) |
| Fork choice | No reorganization at or below the accepted checkpoint; greatest cumulative valid work among compatible branches above it |

The exact RandomX parameter set, independent salt bytes, canonical input and
output encodings, test vectors and network binding must be pinned in the
activation specification. The version name alone is insufficient. CPU
friendliness does not imply equal performance, eliminate specialized hardware
or guarantee that ASIC mining will remain impossible. Initial difficulty must
use measurements of effective work under the selected profile; internal hash
rounds, proof-generation throughput and a different network's calibration are
not substitutes. Recalibration must not silently change an existing network.
The default thread rule concerns mining work, not proof-generation workers or
hardware admission floors. The minimum valid thread count on machines with two
or fewer available cores remains an implementation detail to define explicitly;
this specification does not add a command-line option to existing binaries.

A checkpoint certificate must authenticate the pinned network, covered block
and authorized signer roster. A block is final when its canonical ancestry is
covered by that accepted certificate. A fixed confirmation count or elapsed
time does not establish finality. Conflicting valid certificates require
fail-closed handling and explicit recovery; more work cannot override an
accepted final checkpoint. This model limits deep reorganizations and
associated double-spend risk under its checkpoint trust assumptions. It does
not make a 51% attack impossible or guarantee signer honesty or availability.
The existing 24-block reward maturity and longer unlock schedules are separate
spendability rules and are not changed by this candidate finality requirement.

Wallets must distinguish inclusion in an accepted block from checkpoint
finality. The candidate browser wallet verifies pinned checkpoint certificates
and the applicable authenticated proofs; it does not verify RandomX in the
browser. It must disclose its full-node validity and checkpoint trust boundary
and must not label an unsigned service response or an inclusion receipt as
finality. Missing or invalid checkpoint evidence leaves inclusion unfinalized.
This client model does not describe the existing engineering light client,
which checks its older work profile in WASM.

BLAKE3 remains in use for non-mining purposes, including addresses, short-address
derivation, commitments, identifiers and checksums wherever those formats
already specify it. Those uses are not replaced by RandomX. Transaction
anti-spam work, historical proof-system grinding and historical measurements
are separate from the candidate block-work algorithm.

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
| Reorganization | Candidate: checkpoint-covered history is final; greatest cumulative valid work above it. Retained implementation: local `MAX_REORG_DEPTH=24` |
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
