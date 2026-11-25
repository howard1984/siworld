# SIWORLD: Post-Quantum Shielded Payments with Native STARK Transaction Proofs

SIWORLD

November 2026

## Abstract

SIWORLD is a post-quantum private payment network. The public ledger conceals **who** paid whom, **how much** they paid and in which asset, and **when** a spent note was received. Every ordinary transfer is shielded by default. SIP and issued assets share one private note pool and one transaction format.

The sender's wallet produces one native STARK proof per transfer, with no trusted setup. Post-quantum encryption protects payments, and post-quantum signatures authenticate protocol actions. Each block carries 16 to 576 transaction slots, a proof of confidential fee settlement and a commitment to the resulting state. RandomX orders the chain at a target interval of five minutes. Signed checkpoints anchor finality and synchronization.

Section 10 explains the defenses against quantum attacks and the proof system's 80-bit quantum security target.

## Three layers of privacy: who, how much, when

A transparent ledger records the payment graph. SIWORLD records the evidence that a payment is valid and keeps its parties, value and receipt history private.

| Who | How much | When |
| --- | --- | --- |
| Note owners stay private | Amounts and asset types stay inside notes | The input note's receipt block stays private |
| A nullifier prevents double spending without naming the input note | Proofs enforce balance for each asset | Proofs establish membership under a recent snapshot |
| Recipients identify their notes by local decryption | Fee commitments keep amounts off the public ledger | Statement identifiers determine slot order |
| SIP and issued assets share one note pool | One proof settles the block's fees | Padding shares the same record format |

### Who: the ledger hides the payment graph

The chain holds a note commitment. A spend publishes a nullifier derived from private note data and the spender's secret. The proof checks that derivation without naming the input note. Recipients find their outputs by decrypting them locally.

### How much: amounts, assets and fees stay private

The proof checks that each asset balances and that the fee is paid in SIP. Amounts and asset types stay inside the notes. The public transaction carries a randomized commitment to the fee. One proof settles the committed fees for the entire block.

### When: the ledger hides when a spent note arrived

The transaction anchors to a recent canonical snapshot. Its proof establishes membership beneath a root covered by that snapshot and keeps the note's receipt block private. Blocks order transactions by statement identifier and use the same record format for padding.

## 1. Motivation

Bitcoin and Ethereum showed that a public ledger can settle payments without a central clearing party. A payment system also needs to keep financial activity private and protect it across generations of computing hardware. SIWORLD addresses both problems at the protocol level.

### Transparent ledgers have lost their anonymity

Bitcoin was described as pseudonymous [1]. Meiklejohn and colleagues showed in 2013 that patterns of joint spending can cluster addresses and that known entities can be linked to some of those clusters [2]. Béres and colleagues found that address reuse, activity patterns, fee choices and transaction graph structure can link activity on Ethereum, including some mixer deposits and withdrawals [3].

A single identified payment can expose other parts of a person's transaction history. A public record preserves those links for future analysis.

### The quantum clock is accelerating cryptography

A sufficiently capable fault-tolerant quantum computer can use Shor's algorithm to recover private signing keys from exposed elliptic-curve public keys [4]. An observer can also store ciphertexts protected by elliptic-curve key exchange today and try to decrypt them when such a machine becomes available.

NIST standardized ML-KEM for key encapsulation and ML-DSA for signatures in 2024 [5, 6]. SIWORLD uses ML-KEM-768 to protect recipient outputs and ML-DSA-65 for protocol signatures. Section 10 explains how these defenses address quantum attacks and quantifies the proof security target.

### Five design choices

1. **Publish as little as possible.** A shielded transfer records commitments, nullifiers and ciphertexts. The note owners, amounts and asset types remain in private note data.
2. **Prove with hashes.** Native STARK proofs show transaction validity using hash commitments and low-degree testing, without a trusted setup.
3. **Encrypt and sign with post-quantum primitives.** Recipient outputs use ML-KEM-768 with authenticated encryption. Issuance and governance records use ML-DSA-65 signatures. Peer connections combine X25519 with ML-KEM-768.
4. **Mine with ordinary CPUs.** RandomX runs on general-purpose processors, so anyone with suitable CPU hardware can participate in mining.
5. **Spread early issuance over time.** Voyager directs part of the miner's subsidy share to the Holder pool and burns a fixed portion. Holder locks part of that share at staggered heights. These rules spread out when newly issued SIP becomes spendable.

## 2. Notes, assets and state

Value lives in notes. A note records an owner, an amount, a 32-byte asset identifier, an unlock height and fresh randomness. A Poseidon2 commitment to its fields is appended to the global note tree. Spending a note reveals its nullifier. Nodes maintain a set of spent nullifiers and reject any repeat.

**One pool, many assets.** SIP uses the reserved all-zero identifier. A fixed-supply asset begins with a public declaration signed with ML-DSA-65. The identifier is a domain-separated BLAKE3 hash of the network, the issuer's public key and a sequence number. The declaration exposes the asset and total supply. An issuance proof binds the newly created notes to that supply. Later shielded transfers use the same pool and transaction format as SIP.

**Issuance fee.** Public issuance requires a fixed SIP issuance fee, which does not go to the miner.

**Recent roots.** Nodes accept anchors from the newest 4,096 canonical snapshots. Each snapshot commits to a depth-12 tree of recent note-tree roots. A proof establishes membership through that tree.

**Encryption.** The payment output uses ML-KEM-768 and ChaCha20-Poly1305. The two change positions use ChaCha20-Poly1305 with domain-separated BLAKE3 key derivation. Each output plaintext is 208 bytes. Padding uses genuine encryption under fresh throwaway keys and the same field sizes as payment slots.

**State commitment.** Each block header commits to the resulting execution state separately from the block body. The commitment binds the note tree, nullifiers, recent roots, asset registry, monetary state and governance, among other state components. Full nodes recompute it from the executed block before accepting the new state.

## 3. Transactions

Every transfer uses two inputs, three outputs, one committed SIP fee and one native STARK proof generated by the sender's wallet. The output positions are payment, asset change and SIP change. Unused positions can carry zero value.

The proof shows that each nonzero input belongs to the spender and exists under an accepted root. It checks the nullifiers, conservation of each asset, the SIP fee commitment, and that each input has reached its unlock height at the selected snapshot. It also binds the output commitments and ciphertext bytes to the statement.

The sending wallet checks its encryption before broadcast. The receiving wallet authenticates and decrypts the output and recomputes the note commitment.

### Proof system and parameters

The native proofs use Plonky3 over KoalaBear with a degree-eight extension, Poseidon2 of width 24 and digests of twelve field elements. The transaction profile uses FRI with a blowup factor of $2^7$, 41 queries, binary folding and 20-bit grinding at each of the query and batching steps. The transaction proof frame is limited to 655,360 bytes. Wallets and verifiers derive public preprocessing from the agreed profile. Randomized commitments and polynomial masking protect witness data in the proof transcript. Section 10 gives the security accounting for these choices.

## 4. Blocks and confidential fees

A block contains 16 to 576 transaction slots, in steps of 16. The miner selects transactions and can fill slots with proved, zero-value padding. Slots are sorted in strictly increasing order by a domain-separated BLAKE3 statement identifier. This order binds the chosen statements and rejects duplicates.

### Confidential fees

Let $h$ be the selected snapshot height and $S(h)$ the subsidy in atoms. The standard fee is $b=\lfloor S(\max(1,h))/10{,}000\rfloor$ atoms. The priority fee is $4b$. At the genesis snapshot, the standard fee is 0.00339452 SIP (about 0.0034 SIP) and the priority fee is 0.01357808 SIP (about 0.0136 SIP), and both decline with the subsidy. Padding commits to zero.

The miner attaches one native settlement proof to the block. It binds the ordered transaction list and the corresponding fee commitments to the miner's reward notes. The entire transfer-fee sum is added to the miner's first reward note. The remaining subsidy allocation and unlock heights follow Section 6.

## 5. Consensus

A full node checks work, proof validity, double spends and the deterministic state transition. Among valid branches that preserve the accepted checkpoint, the branch with the greatest accumulated work wins.

### 5.1 Proof of work and difficulty

SIWORLD uses RandomX v1.2.1 with a network-specific Argon2d salt [7]. The work input binds the header and nonce. The epoch key is derived with BLAKE3 from genesis and an ancestor of that header's parent chain. Key heights are multiples of 2,048, selected with a delay of 64 blocks. A block passes the work check when the RandomX digest, read as a 256-bit integer, is strictly below its target.

ASERT sets each block's target from a genesis reference, with a 300-second target interval and a one-hour half-life. Let $T_0,t_0$ be the genesis target and timestamp and $h_p,t_p$ the parent height and timestamp. The exponential relation is

```math
T \approx T_0\,2^{[(t_p-t_0)-300 h_p]/3600}.
```

The consensus calculation uses fixed-point integer arithmetic and clamps the result to the permitted target range. Once eleven prior timestamps are available, a block must exceed their median. Before that, it must exceed its parent's timestamp.

### 5.2 Checkpoints and finality

The network periodically publishes signed checkpoints, nodes never reorganize past an accepted checkpoint, and new nodes can synchronize quickly from a checkpoint.

## 6. Monetary policy and governance

SIP is issued through block subsidies beginning at height 1. One SIP contains $10^8$ atoms. All supply and allocation arithmetic is integer.

### Issuance schedule

With $e=\lfloor(h-1)/4032\rfloor$, the subsidy at height $h$ is $r_e$.

```math
r_0 = 3{,}394{,}524{,}515,\qquad
r_{e+1} = \max\!\left(10^8,\left\lfloor r_e\frac{4{,}268{,}204{,}354}{2^{32}}\right\rfloor\right)
\quad\text{atoms}.
```

At the target interval, gross issuance is about 3.30 million SIP in the first 365 days. The decaying phase issues about 21.32 million SIP. Issuance has no hard cap. The tail begins at height 2,274,049, about year 22 at the target interval, and continues permanently at 1 SIP per block. The schedule counts issuance before any Voyager burn.

### Where each subsidy goes

Genesis sets the nominal split at 85% for the miner, 12% for the development fund and 3% for the Holder pool. For a subsidy $S$, the fund gets $\lfloor12S/100\rfloor$, the pool gets $\lfloor3S/100\rfloor$, and the miner's base is the remainder $M$. The miner's mode applies to $M$. Transfer fees are settled separately.

At the initial subsidy of 3,394,524,515 atoms, the fund gets 407,342,941 atoms, the pool gets 101,835,735 atoms, and the miner's base is 2,885,345,839 atoms.

### Miner modes: Voyager and Holder

Each block declares one mode. **Voyager** burns $\lfloor 5M/100\rfloor$ and credits $\lfloor 20M/100\rfloor$ to the Holder pool. The remainder matures after 24 blocks. **Holder** puts $\lfloor M/10\rfloor$ into each of four notes that unlock 52,560, 105,120, 157,680 and 210,240 blocks after issuance. Its remaining base and pool draw mature after 24 blocks.

Let $P$ be the pool balance before the block. A Holder block draws $\lfloor P/4032\rfloor$ before crediting the block's 3% pool allocation. A Voyager block draws nothing and credits both the 3% allocation and the Voyager contribution. The pool is public consensus state.

At that subsidy, Voyager burns 144,267,291 atoms, adds 577,069,167 atoms to the pool on top of the protocol allocation, and creates a note of 2,164,009,381 atoms that matures after 24 blocks. Holder creates four locked notes of 288,534,583 atoms each. With an illustrative opening pool balance of 4,032 SIP, Holder draws 1 SIP and adds it to the remaining 1,731,207,507 atoms. The resulting note of 1,831,207,507 atoms matures after 24 blocks. These amounts exclude transfer fees.

### Development fund

Each block credits members according to their configured shares. Of a member's credit $C$ at height $h$, $\lfloor C/2\rfloor$ is released at $h+24$. Let $L=C-\lfloor C/2\rfloor$. After $n$ complete periods, the cumulative release from $L$ is $\lfloor L\min(n,48)/48\rfloor$. Periods are 8,766 blocks starting at $h$, and the last one releases all residual atoms. A claim requires a member's ML-DSA-65 signature, an increasing counter, sufficient released balance and the active destination. Changing the destination preserves the member's ledger.

### Governance keys

The founder key can propose a change to a development fund member's payment address. The change takes effect 4,032 blocks after inclusion. The revocation key can cancel it before it takes effect.

### Conservation

Cumulative subsidy equals the sum of subsidy allocated to miner notes, the current Holder pool, cumulative burns and cumulative fund entitlements, counting pool draws only when they become miner allocations. Transfer and issuance fees and fund payouts move existing SIP. Nodes roll back the affected monetary state together when they replace a branch.

## 7. Storage and synchronization

### 7.1 Reclaiming disk space

A full node needs the proofs to verify a new block's state transition. After validation and checkpoint coverage, it can reclaim space by removing proof-bearing bodies while retaining the authenticated public records. Headers, work and public receipts remain available. The receipts retain commitments, nullifiers, encrypted outputs and the public issuance, fund and governance records.

```text
Validated block
    |-- Header + public receipt  --> retained
    `-- Proof-bearing body      --> eligible for pruning after checkpoint coverage
```

Service nodes can prune a block's proofs after 24 observed hours of checkpoint confirmation and once the block lies outside the most recent 312 blocks. Under the 96-block miner retention policy, checkpoint-covered proofs outside the most recent 96 blocks are eligible.

### 7.2 Synchronization from a checkpoint

A joining full node verifies the header chain and its work from genesis, authenticates a checkpoint and checks the imported state against the checkpoint header. It reconciles the retained public receipts with the snapshot and fully validates subsequent blocks.

### 7.3 Light-wallet verification

A light wallet checks inclusion using public receipts bound to block headers and scans ciphertexts locally for its notes. A native light wallet verifies header work. A browser light wallet uses authenticated checkpoints to establish RandomX finality. The wallet marks a payment as checkpoint-covered after verifying that the selected chain includes it and an accepted checkpoint covers it.

## 8. Network

Peer sessions use TLS 1.3 with hybrid X25519 and ML-KEM-768 key exchange. The peers authenticate the session binding with Ed25519 and ML-DSA-65 signatures. This binds the peers and the network context to the encrypted channel.

Nodes exchange transactions, headers and block data over encrypted links. Each full node validates blocks and proofs under the consensus rules.

## 9. What each observer can see

| Observer | Visible data |
| --- | --- |
| Public ledger reader | Headers, work, block times, slot counts and order, snapshot selectors, nullifiers, commitments, ciphertexts, miner modes and public issuance, fund and governance records |
| Relaying node | The transaction it receives, arrival time and any accompanying fee opening |
| Block miner | The selected transactions and fee openings, and which padding it generated |
| Recipient | Its own decrypted notes and their inclusion on the chain |
| Network peer | Its connection endpoints and traffic pattern |
| Compromised wallet host | Wallet data and keys available to its processes |

Known payments, sparse activity, fee openings and traffic patterns can help an observer correlate activity. Public issuance exposes an asset's existence and supply. Consensus binds the ciphertext bytes, and the recipient checks that they decrypt to the committed note.

In a browser wallet, the RandomX chain beyond the last authenticated checkpoint is provisional.

## 10. Quantum attacks and resistance

SIWORLD's transaction authorization, recipient encryption, on-chain protocol signatures and proofs are independent of the elliptic-curve and RSA assumptions that Shor's algorithm breaks [4, 5, 6, 8]. Under the hash, lattice and authenticated-encryption assumptions used here, a quantum attacker cannot feasibly use today's public ledger data alone to decrypt shielded payments, forge protocol signatures or authorize spends.

### Proofs and transaction authorization

To authorize a transfer, the wallet proves knowledge of the note's spending secret with a hash-based STARK [8]. The proof uses public preprocessing, hash commitments and FRI low-degree testing without a trusted setup.

### Encryption and signatures

Payments use ML-KEM-768 encapsulation and authenticated encryption [5]. An attacker who stores the encapsulation and the recipient's public key faces a lattice-based key recovery problem. Shor's discrete-logarithm algorithm does not solve that problem. Hybrid peer sessions also use ML-KEM-768 in their key exchange. Change outputs use keys derived from private wallet material.

ML-DSA-65 authenticates issuance, governance and fund claims [6]. The peer handshake also uses ML-DSA-65 alongside its elliptic-curve signature.

### RandomX under quantum search

For a target that accepts a fraction $p$ of pseudorandom work outputs, classical independent nonce trials take order $1/p$ evaluations. Grover's algorithm gives a quadratic speedup for generic unstructured search, taking order $1/\sqrt{p}$ coherent RandomX queries [9]. Each coherent query must still execute the RandomX computation and its memory accesses. This nonce-search advantage changes mining competition, while ASERT adjusts for changes in the overall block rate and spending remains protected by the same authorization rules.

### The 80-bit target

The proof system targets at least 80 bits of quantum security. For each Johnson-bound Fiat–Shamir challenge term, the analysis estimates an error exponent $b_i$ and applies quantum screening by halving it. The combined exponent is $-\log_2\sum_i m_i2^{-b_i/2}$, where $m_i$ counts repetitions. For the transaction proof, the combined estimate is about 81.69 bits, dominated by the FRI query term of about 163.38 bits before halving.

Merkle commitment collisions are counted separately. In the ideal Brassard–Høyer–Tapp model [10], the 185-bit classical birthday estimate corresponds to $2\times185/3\approx123.33$ quantum bits for the modeled Poseidon2 commitment. Ideal collision search for the 256-bit BLAKE3 application bindings gives $256/3\approx85.33$ bits.

## 11. Conclusion

Every ordinary SIWORLD transfer is private by default. Native STARKs let anyone verify that payments obey the rules, and post-quantum cryptography protects payment contents and authenticates protocol actions. RandomX lets people mine with ordinary CPUs and help build the same publicly verifiable ledger.

## References

1. Satoshi Nakamoto, *Bitcoin: A Peer-to-Peer Electronic Cash System*, 2008.
2. Sarah Meiklejohn et al., *A Fistful of Bitcoins: Characterizing Payments Among Men with No Names*, IMC 2013, DOI 10.1145/2504730.2504747.
3. Ferenc Béres et al., *Blockchain is Watching You: Profiling and Deanonymizing Ethereum Users*, arXiv:2005.14051, 2020.
4. Peter W. Shor, *Polynomial-Time Algorithms for Prime Factorization and Discrete Logarithms on a Quantum Computer*, SIAM Journal on Computing 26(5), 1997, DOI 10.1137/S0097539795293172.
5. NIST, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, FIPS 203, 2024, DOI 10.6028/NIST.FIPS.203.
6. NIST, *Module-Lattice-Based Digital Signature Standard*, FIPS 204, 2024, DOI 10.6028/NIST.FIPS.204.
7. RandomX contributors, *RandomX Design and Specification*, RandomX v1.2.1.
8. Eli Ben-Sasson et al., *Scalable, Transparent, and Post-Quantum Secure Computational Integrity*, IACR ePrint 2018/046.
9. Lov K. Grover, *A Fast Quantum Mechanical Algorithm for Database Search*, STOC 1996, arXiv:quant-ph/9605043.
10. Gilles Brassard, Peter Høyer and Alain Tapp, *Quantum Algorithm for the Collision Problem*, arXiv:quant-ph/9705002, 1997.
