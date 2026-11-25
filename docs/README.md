# SIWORLD documentation

[Whitepaper](whitepaper.md) · [Protocol specifications](#protocol-specifications) · [Guides](#guides) · [Security and reference](#security-and-reference)

The [whitepaper](whitepaper.md) explains the protocol design. The specifications
define the rules used to validate transactions, blocks, state, and network
data. Each specification identifies its applicable ruleset. Select the
ruleset using the pinned genesis for the network. The guides cover
installation, verification, and integration.

## Protocol specifications

| Specification | Scope |
| --- | --- |
| [01. Notes and state](specs/01-notes-and-state.md) | Notes, commitments, nullifiers, assets, snapshots, and the execution commitment |
| [02. Transactions](specs/02-transactions.md) | Shielded transfers, canonical statements, and fixed-supply asset issuance |
| [03. Proof system](specs/03-proof-system.md) | Native STARK relations, profile selection, and verification |
| [04. Blocks and fees](specs/04-blocks-and-fees.md) | Header and body encoding, slot order, and confidential transfer fee settlement |
| [05. Consensus](specs/05-consensus.md) | RandomX, ASERT, accumulated work, and checkpoint finality |
| [06. Monetary policy](specs/06-monetary-policy.md) | SIP issuance, Voyager and Holder, fund claims, and the issuance fee |
| [07. Storage and synchronization](specs/07-storage-and-sync.md) | Authenticated checkpoint import, proof retention, and light-wallet evidence |
| [08. Peer-to-peer network](specs/08-p2p-network.md) | Hybrid transport, peer authentication, and data exchange |
| [09. Addresses and wallets](specs/09-addresses-and-wallets.md) | Recipient formats, short-address resolution, and wallet verification |
| [10. RPC](specs/10-rpc.md) | Private wallet gateway and read-only chain export |

## Guides

| Guide | Task |
| --- | --- |
| [Run a node](guides/run-a-node.md) | Verify a release, initialize a node, and synchronize the selected chain |
| [Mine on Linux](guides/mine-on-linux.md) | Install, configure, and operate the RandomX miner |
| [Exchange integration](guides/exchange-integration.md) | Verify deposits, submit withdrawals, and reconcile state |
| [Wallet](guides/wallet.md) | Create or restore a wallet and verify payment status |

## Security and reference

| Document | Scope |
| --- | --- |
| [Security model](security/security-model.md) | Observer visibility, proof assumptions, and trust boundaries |
| [Parameters](reference/parameters.md) | Consensus values, units, and defining specifications |
| [Glossary](reference/glossary.md) | Canonical protocol terminology |
| [Security policy](../SECURITY.md) | Private vulnerability disclosure |
| [Contributing](../CONTRIBUTING.md) | Invariants, local validation, and change review |
