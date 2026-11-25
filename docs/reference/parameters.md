# Protocol parameters

These parameters describe the public RandomX ruleset. Genesis binds the
network identifier, initial timestamp and target, proof profile, authorized
verification material, and the monetary rules. Read selectable values from
the independently pinned genesis. Role-based proof pruning, peer limits,
RPC bounds, and operator settings are described by the appropriate
specification or guide and do not change block validity.

| Scope | Parameter | Value and unit | Definition |
| --- | --- | --- | --- |
| Network | Public network identifier | `d38a665e4751c7cb6153ad56df86426303121524edca5158b8d60b4fc53b638f` (32 bytes) | [09. Addresses and wallets](../specs/09-addresses-and-wallets.md#public-network-and-address-class) |
| Network | Public genesis identifier | Pin independently from the verified release manifest and check against `genesis.bin` | [Run a node](../guides/run-a-node.md#steps) |
| Address | Public address class | `mainnet` | [09. Addresses and wallets](../specs/09-addresses-and-wallets.md#public-network-and-address-class) |
| Address | Primary full format | `sivf1…`, bound to the network ID | [09. Addresses and wallets](../specs/09-addresses-and-wallets.md#canonical-receiving-address) |
| Address | Secondary short format | `si1p…`, Bech32m, version 2 descriptor bound to the genesis ID | [09. Addresses and wallets](../specs/09-addresses-and-wallets.md#short-address-and-contact-resolution) |
| Consensus | Work algorithm | SIWORLD RandomX v1.2.1 | [05. Consensus](../specs/05-consensus.md#randomx-proof-of-work) |
| Consensus | RandomX Argon2d salt | `SIWORLD/RandomX/ArgonSalt/v1` | [05. Consensus](../specs/05-consensus.md#randomx-proof-of-work) |
| Consensus | RandomX key interval and delay | 2,048 and 64 blocks | [05. Consensus](../specs/05-consensus.md#randomx-proof-of-work) |
| Consensus | Block target interval | 300 seconds | [05. Consensus](../specs/05-consensus.md#asert-and-timestamps) |
| Consensus | ASERT half-life | 3,600 seconds | [05. Consensus](../specs/05-consensus.md#asert-and-timestamps) |
| Consensus | ASERT target range | 1 through $2^{256}-1$ | [05. Consensus](../specs/05-consensus.md#asert-and-timestamps) |
| Consensus | Median timestamp window | 11 preceding timestamps | [05. Consensus](../specs/05-consensus.md#asert-and-timestamps) |
| Finality | Checkpoint signature threshold | 2 of 3 distinct authorized ML-DSA-65 keys | [05. Consensus](../specs/05-consensus.md#checkpoints-and-finality) |
| Finality | Checkpoint authorization depth | At least 24 blocks | [05. Consensus](../specs/05-consensus.md#checkpoints-and-finality) |
| Finality | Signature and verification key widths | 3,309 and 1,952 bytes | [05. Consensus](../specs/05-consensus.md#checkpoints-and-finality) |
| State | Execution components | 11 | [01. Notes and state](../specs/01-notes-and-state.md#snapshots-and-state-commitment) |
| State | Component descriptor | 42 bytes | [01. Notes and state](../specs/01-notes-and-state.md#snapshots-and-state-commitment) |
| State | Note-tree depth | 40 | [01. Notes and state](../specs/01-notes-and-state.md#notes-and-commitments) |
| State | Recent-root tree and snapshot window | Depth 12 and 4,096 snapshots | [01. Notes and state](../specs/01-notes-and-state.md#snapshots-and-state-commitment) |
| State | Asset identifier | 32 bytes, zero reserved for SIP | [01. Notes and state](../specs/01-notes-and-state.md#assets) |
| Transfer | Inputs and outputs | 2 inputs and 3 outputs | [02. Transactions](../specs/02-transactions.md#transfer-shape) |
| Transfer | Output plaintext | 208 bytes | [02. Transactions](../specs/02-transactions.md#transfer-shape) |
| Transfer | Envelope version and public record | Version 2 and 2,027 public record bytes | [02. Transactions](../specs/02-transactions.md#canonical-envelope-and-statement-identifier) |
| Proof | KoalaBear modulus | 2,130,706,433 | [03. Proof system](../specs/03-proof-system.md#suite-and-relations) |
| Proof | Extension degree | 8 | [03. Proof system](../specs/03-proof-system.md#suite-and-relations) |
| Proof | Poseidon2 width, rate, and digest | 24, 12, and 12 field elements | [03. Proof system](../specs/03-proof-system.md#suite-and-relations) |
| Proof | Transaction FRI profile | $2^7$ blowup, 41 queries, binary folding, 20 bits of grinding at each batching and query step | [03. Proof system](../specs/03-proof-system.md#transaction-profile) |
| Proof | Transaction and settlement proof limits | 655,360 bytes each | [03. Proof system](../specs/03-proof-system.md#transaction-profile) |
| Proof | Issuance proof limit | 524,288 bytes | [02. Transactions](../specs/02-transactions.md#public-issuance) |
| Block | Header and body prefix | 190 and 85 bytes | [04. Blocks and fees](../specs/04-blocks-and-fees.md#header-and-body) |
| Block | Permitted slot count | 16 through 576 in steps of 16 | [04. Blocks and fees](../specs/04-blocks-and-fees.md#slots-and-order) |
| Block | Miner reward notes | 1 for Voyager, 5 for Holder | [06. Monetary policy](../specs/06-monetary-policy.md#allocation-and-miner-modes) |
| Block | Reward ciphertext | 1,313 bytes | [04. Blocks and fees](../specs/04-blocks-and-fees.md#header-and-body) |
| Block | Maximum fund claims and governance actions | 8 and 32 per block | [04. Blocks and fees](../specs/04-blocks-and-fees.md#header-and-body) |
| Issuance | Initial note positions | 3 | [02. Transactions](../specs/02-transactions.md#public-issuance) |
| Issuance | Metadata and record decoder ceilings | 256 bytes and 4 records per block, subject to the active genesis policy | [02. Transactions](../specs/02-transactions.md#public-issuance) |
| Money | Atoms per SIP | 100,000,000 | [06. Monetary policy](../specs/06-monetary-policy.md#sip-subsidy) |
| Money | Initial subsidy | 3,394,524,515 atoms | [06. Monetary policy](../specs/06-monetary-policy.md#sip-subsidy) |
| Money | Subsidy epoch and decay | 4,032 blocks and Q32 factor 4,268,204,354 | [06. Monetary policy](../specs/06-monetary-policy.md#sip-subsidy) |
| Money | Tail subsidy and starting height | 100,000,000 atoms at height 2,274,049 and later | [06. Monetary policy](../specs/06-monetary-policy.md#sip-subsidy) |
| Money | Base allocation | 85% miner, 12% development fund, 3% Holder pool | [06. Monetary policy](../specs/06-monetary-policy.md#allocation-and-miner-modes) |
| Money | Voyager adjustments | 5% burn and 20% additional pool credit from the miner base | [06. Monetary policy](../specs/06-monetary-policy.md#allocation-and-miner-modes) |
| Money | Holder draw and locked notes | Pre-block pool divided by 4,032, four notes at one-tenth of base each | [06. Monetary policy](../specs/06-monetary-policy.md#allocation-and-miner-modes) |
| Money | Miner maturity and Holder offsets | 24 blocks, then separate offsets of 52,560, 105,120, 157,680, and 210,240 blocks | [06. Monetary policy](../specs/06-monetary-policy.md#allocation-and-miner-modes) |
| Money | Transfer fee tiers | Subsidy divided by 10,000, priority multiplier 4 | [04. Blocks and fees](../specs/04-blocks-and-fees.md#transfer-fees-and-settlement) |
| Money | Issuance fee | 5,000,000,000 atoms (50 SIP) | [06. Monetary policy](../specs/06-monetary-policy.md#issuance-fee) |
| Fund | Member count and share total | 1–32 members and 10,000 basis points | [06. Monetary policy](../specs/06-monetary-policy.md#development-fund) |
| Fund | Direct and periodic releases | Half at 24 blocks, remainder over 48 periods of 8,766 blocks | [06. Monetary policy](../specs/06-monetary-policy.md#development-fund) |
| Fund | Destination update delay | 4,032 blocks | [06. Monetary policy](../specs/06-monetary-policy.md#development-fund) |
