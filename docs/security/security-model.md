# Security model

## Scope

This model covers shielded transfers, native proof verification, recipient
encryption, protocol signatures, checkpoint finality, and local wallet
custody. It distinguishes the public ledger, transport participants, and
the people who hold wallet material.

## Observer visibility

| Observer | Information available |
| --- | --- |
| Public ledger reader | Headers, proof of work, timestamps, slot counts and order, snapshot selectors, nullifiers, commitments, ciphertexts, miner modes, and public issuance, fund, and governance records |
| Relaying peer | The transaction it relays, its arrival time, and any fee opening provided |
| Block miner | Selected transactions, the fee openings it receives, and its own padding decisions |
| Recipient | Decrypted contents of its own notes, their inclusion, and their spend conditions |
| Network observer | Connection endpoints, message sizes, and timing |
| Compromised wallet host | Wallet data and keys available to its processes |

Ordinary transfers keep the sender, recipient, amount, asset, and the spent
note's receipt height out of the public record. Known payments, sparse
activity, data shared with peers, and network observations can still
correlate activity. Public issuance discloses the issuer's declaration
and fixed supply. Confidential transfer fee openings are visible to
the parties receiving them.

## Cryptography

Recipient encryption relies on ML-KEM-768 and authenticated
ChaCha20-Poly1305 encryption with appropriate keys and nonces. On-chain
protocol authentication uses ML-DSA-65. Spending relies on knowledge of the
correct note secrets proved in the transaction relation. Proofs bind public
ciphertext bytes. Wallets authenticate decryption and check that those
bytes represent the committed note.

Peer transport uses hybrid X25519 and ML-KEM-768 with Ed25519 and
ML-DSA-65 session authentication. The elliptic-curve component is a peer
transport primitive. It is separate from note-spending authorization and
recipient encryption. The post-quantum protection claims depend on the
deployed primitives, their composition, and correct key handling.

## Proof security

Native STARKs use hash commitments and FRI. They require public
preprocessing and no trusted setup. Proof security depends on the soundness
of the relation and verifier profile, transcript binding, randomness for
witness hiding, and the security of the instantiated hash and field
constructions.

The 80-bit quantum security target is a profile screening target. In the
transaction profile, the quantum-adjusted Johnson challenge estimate is
about 81.69 bits. Collision estimates measure separate terms. For the
ideal BHT model, the conservative 185-bit classical estimate for the
Poseidon2 commitment yields about 123.33 bits, and 256-bit BLAKE3 bindings
yield about 85.33 bits. These estimates are not a compositional theorem
or independent audit. Reproducibility requires the exact source, proof
parameters, verified public artifacts, and profile checks.

## Finality and synchronization

Full nodes validate header work, executed state, proofs, and the accepted
checkpoint before replacing a branch. A checkpoint certificate relies on
two authorized ML-DSA-65 signatures out of three and on chain binding.
Incompatible authenticated checkpoints indicate a fault and require
settlement to pause. A cloned snapshot or public API response is not
independent validation.

A light wallet checks the authenticated receipts needed for its own notes.
A browser light wallet uses authenticated checkpoints for RandomX finality.
The tail beyond its last accepted checkpoint remains provisional.
The cost of generic quantum nonce search affects proof-of-work competition.
It does not provide a way to construct an otherwise unauthorized spend.

## Wallet custody

Recovery material controls the wallet. Protect it offline and verify
addresses and network identity before authorizing transfers. Keep private
fee openings out of public logs. A short address is a commitment and must
be resolved against the matching full contact. Clients keep decryption
and spend authorization local.

## References

- [Whitepaper, Section 9](../whitepaper.md#9-what-each-observer-can-see)
- [Whitepaper, Section 10](../whitepaper.md#10-quantum-attacks-and-resistance)
- [Proof system](../specs/03-proof-system.md)
- [Consensus](../specs/05-consensus.md)
- [Addresses and wallets](../specs/09-addresses-and-wallets.md)
