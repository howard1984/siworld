# Security and Privacy Model

The [monetary revision](v1-economics.md) adds review boundaries for trusted
snapshot-height locks, mode-dependent SIP reward notes, pool/burn conservation,
per-credit fund vesting and atomic economic rollback. The
`native-v1-economics-1` profiles bind the revised AIRs and fresh reference-host
evidence; pre-revision measurements do not qualify them. Wallet threshold backup reconstructs one
key and supplies no V1 consensus multisignature guarantee.

## Status and scope

**Engineering target ≥80-bit quantum security, pending independent review.**
The transaction, fixed-576 settlement and three-initial-note issuance relations
have a [source-bound engineering freeze](native-proof-profiles.md); they execute
in isolated proof tools. This does not adopt issuance policy or qualify other
capacity keys. Public-key reproduction and complete CI remain release checks.
The atomic native monetary transition, wallet lock primitives and subsidy/fund
spending audit are implemented; complete wallet, transport, retention and
checkpoint integration remain incomplete. There is no public native V1 testnet, production release or mainnet.
CI and estimator results do not establish independent approval.
[Dependency advisory applicability](dependency-advisories.md) distinguishes
runtime remediation from open isolated-experiment advisories.

The existing runnable node and retained seven-node N=2 engineering testnet
use the [legacy recursive classical route](legacy/security-model.md). Its keys,
history, two-output format and 100-block reorganization bound do not activate
native V1. Development mock proofs are forgeable and provide no proof security.

## Observer boundaries

| Observer | Available information |
| --- | --- |
| Chain reader | Headers/PoW, inclusion positions, nullifiers, commitments, ciphertexts, public issuance and fund records |
| Sidecar recipient | Relayed statement, arrival context and fee opening; a zero opening can identify padding to that recipient |
| Producer | Selected transactions, private fee openings and its own generated padding |
| Recipient wallet | Recovered note plaintexts and inclusion of its own payments |
| Transport peer | Its direct connection endpoints and traffic metadata |
| Privileged local process | Files and memory accessible to its OS identity, potentially including active secrets |

Uniform transaction shape and fee commitments reduce specified on-chain
signals. They do not guarantee perfect indistinguishability, payment-time
anonymity or source anonymity. Low traffic, known payments, active probing,
producer-owned padding and off-chain observations can weaken privacy. Public
metrics must not classify transactions/padding or emit individual fee openings,
endpoint identifiers or nullifier/time associations.

## Proof and encryption boundaries

The D8/W24/12 suite must pass actual-instance security accounting for every
native relation. Conjectured classical security must be ≥128 bits; selected
Johnson Fiat–Shamir, challenge-domain and BHT terms must meet the quantum
80-bit floors under their stated models. The measured 81.692-bit transaction
challenge ledger is not full-system security approval. Review transcript
binding, hiding randomness, dependency patches, application hashes and
composition independently. See [cryptography](cryptography.md) and
[collision accounting](bht-security-accounting.md).

The AIR binds ciphertext bytes but does not prove correct encryption or
decryptability. Sender self-checks, recipient AEAD/commitment validation and
protected receipt material remain wallet obligations. A malformed output may
lose that payment without violating the proof relation. ML-KEM note encryption
and ML-DSA signatures alone do not secure all protocol components.

Nullifier derivation is part of the proof relation. Global duplicate/spent
rejection is a node/state responsibility. Canonical encoding, trusted snapshot
resolution, duplicate statement-ID rejection and atomic application cannot be
replaced by a passing standalone proof.

## Network, storage and recovery

Hybrid X25519 + ML-KEM, dual-identity authentication and Dandelion++ are
selected native designs awaiting implementation and adversarial review.
Encrypted transport protects contents against recording attacks; endpoints
remain visible to peers. The existing legacy node uses Noise and direct flood
relay. Worker-handshake tests do not qualify native hybrid peer transport.

The retained implementation uses a local 24-block reorganization bound and the
newest 4,096 canonical snapshots. The [candidate model](protocol.md#candidate-mining-and-checkpoint-finality)
uses RandomX v1.2.1 with SIWORLD-specific parameters and an independent salt,
and finalizes history covered by a valid 2-of-3 checkpoint. Compatible branches
above it use greatest cumulative valid work. The CPU-friendly, memory-intensive
work profile aims to reduce GPU/ASIC advantages; it does not eliminate them.
Checkpoint trust limits deep reorganizations and double-spend risk without
making a 51% attack impossible. Conflicting valid certificates require
fail-closed recovery. This requirement does not attest to implementation or
deployment; fixed confirmations and reward maturity do not prove finality.
Three-day-after-finality proof deletion makes full proof replay from genesis
unavailable by default. Release checkpoint bootstrap explicitly trusts a
genesis-pinned two-of-three authority; PoW does not prove deleted historical
validity. Permanent public-data integrity and backups remain mandatory.

Encrypted keystores, explicit unlock and zeroized owned buffers reduce specific
exposure paths. They do not prove erasure of allocator/compiler copies, swap,
crash dumps or dependency buffers. Monitoring services must not hold spend
keys. A compromised host can expose active keys and private fee openings.

## Activation gates

Qualify the shared atomic transition and bounded decoders; complete isolated
verifier budgets, durable native wallet/recovery, actual-listener transport/source relay,
public-data durability, checkpoint authentication and real retention lifecycle.
Qualify validator and miner resources separately under maximum sustained load
and independent-host failures. Hardware profiles and modeled bandwidth are
not accepted operational guarantees. Close security-limiting findings through
independent review before public testnet launch; production requires further
explicit acceptance. See [testnet gates](prover-acceptance.md) and
[open requirements](11-risks-open-questions.md).
