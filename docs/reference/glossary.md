# Glossary

Use these spellings across specifications, guides, and public interfaces.

| Term | Definition |
| --- | --- |
| Accumulated work | Sum of the individual work values for a validated header history. It orders eligible branches. |
| ASERT | The exponentially adjusted proof-of-work target rule anchored at genesis. |
| Asset identifier | Fixed 32-byte label for an asset. SIP uses the reserved all-zero identifier. |
| Atom | Integer unit of SIP. 100,000,000 atoms equal one SIP. |
| Authorization block | Block that authenticates the chain context used to verify a checkpoint certificate. |
| Body commitment | Header field that authenticates the canonical block-body bytes. |
| Checkpoint | Authenticated block reference that sets the network's reorganization boundary when accepted. |
| Checkpoint certificate | Canonical statement and two authorized ML-DSA-65 signatures. |
| Checkpoint coverage | Verified inclusion in the ancestry of an accepted checkpoint, including the checkpoint block itself. |
| Commitment | Cryptographic binding to data that may be kept private or supplied separately. |
| Development fund | Subsidy allocation credited and released independently to its configured members. |
| Execution commitment | Header commitment to the state components after applying the block. |
| Fee commitment | Randomized commitment to a private transfer fee. |
| Fee opening | Private amount and randomness used to verify a fee commitment. |
| Finality | Protocol boundary across which a node must not reorganize after accepting a checkpoint. |
| FRI | Low-degree testing protocol used in the deployed STARK profile. |
| Full receiving address | Network-bound text encoding of the public recipient data and checksum. |
| Genesis | Initial chain identity and starting parameters selected independently by the node. |
| Holder | Mining mode that locks part of the base allocation and draws from the pre-block Holder pool. |
| Holder pool | Public state that receives subsidy credits and provides mode-specific draws. |
| Issuance fee | Fixed SIP payment required by the ruleset for public fixed-supply asset creation. |
| Light wallet | Wallet that verifies applicable header, receipt, and checkpoint evidence for its own state. |
| Miner base | Residual subsidy allocated to the miner before mode adjustments and transfer fees. |
| Native STARK | Deployed transparent proof for a transaction, issuance, or settlement relation. |
| Note | Shielded unit of value with an owner, asset, amount, unlock height, and randomness. |
| Nullifier | Public spend marker allowing the node to reject repeat spends without revealing the input note. |
| Padding | Valid zero-value transaction record that occupies a slot in the canonical block layout. |
| Proof body | The proof-bearing data used to validate or relay blocks, distinct from retained public records. |
| Provisional | Included on the selected chain but beyond accepted checkpoint coverage. |
| Public receipt | Authenticated block records used to verify selected public facts and scan encrypted outputs. |
| RandomX | CPU-oriented proof-of-work algorithm used to validate header work. |
| Short receiving address | Network-bound commitment to a full address, resolved using a matching full contact. |
| SIP | Native monetary unit and asset used for transfer fees. |
| Snapshot | Canonical state selection identified by height and block ID. |
| Statement identifier | Domain-separated transaction ID computed from the canonical public statement. |
| Subsidy | SIP created at a block height and distributed by the monetary transition. |
| Transfer fee | Committed SIP amount paid to the miner and accounted for by the settlement proof. |
| Unlock height | First eligible consensus height for spending a note, subject to its trusted snapshot. |
| Voyager | Mining mode that burns part of its base allocation and credits an extra amount to the Holder pool. |
