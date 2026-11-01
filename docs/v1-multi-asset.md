# V1 Multi-Asset Transaction Format

**Status:** Selected V1 design with native transaction, settlement and issuance
proof parameters engineering-frozen for the revised lock and economic relations
in `crates/bench-multi-asset`. The fresh actual-AIR scan records the selected
source-bound profile; required CI and public-key reproduction remain release
checks.
The [profile artifact](../crates/bench-multi-asset/artifacts/v1-transaction-profile.json)
binds the selected parameters, measured implementation and public preprocessing
key. It is not independent cryptographic approval or network activation.
Node integration, protocol review, resource qualification and external review
remain required. The prior two-output implementation is an unchanged baseline.

## Scope and invariants

SIP and permissionlessly issued assets share one privacy pool. Every note
contains one private 32-byte asset identifier. The identifier enters both the
note commitment and the encrypted note plaintext; ordinary transfers do not
publish it. Issuance publishes the issuer key, sequence, supply and metadata,
so the corresponding identifier is computable. Privacy means that subsequent
transfers do not reveal or link that identifier, not that the identifier itself
is unknowable.

The fixed transaction shape is two inputs and three outputs. Every position
uses one ML-KEM recipient ciphertext and two symmetric sender-change
ciphertexts, including pure SIP transfers and padding. A spare output has value
zero. These roles support token receipt, token change and SIP fee change; the
third output is not a second arbitrary recipient.

The transaction AIR checks each asset balance independently. SIP alone pays
the standard or priority transaction fee; padding pays zero. All nonzero
inputs require ownership and commitment-tree membership, while zero-valued
inputs skip membership. Nullifiers still must differ. The recent-root-tree
membership check is inside the AIR and exposes only its root. The codec and
public statement bind all transaction ciphertext bytes.

## Asset identifiers and note commitments

SIP reserves the all-zero identifier. A non-SIP identifier is the full output of
BLAKE3's derive-key mode with context `siworld asset identifier v1`, absorbing
network identity, the canonical 1,952-byte ML-DSA-65 issuer public key and the
little-endian u64 issuance sequence. The registry rejects the reserved value,
a duplicate identifier or a reused issuer sequence.

The AIR represents the identifier as sixteen independently range-checked u16
limbs, without field reduction. A 256-bit digest has a generic classical
collision exponent of 128 and a BHT exponent of approximately 85.3. These
application-hash figures differ from the W24 commitment-hash calculation. A
16-byte identifier does not satisfy the selected collision targets.

The versioned note commitment absorbs five rate-12 blocks:

```text
owner[12]
amount_u16[4] || unlock_u16[4] || asset_u16[0..4]
asset_u16[4..16]
rho[12]
rseed[12]
```

The multi-asset note domain is 130. The separate versioned registry assigns
owner 129, nullifier 131, output-rho 132--134, fee 136, set binding 138,
anchor 140 and miner-rho 141. The additional output must not reuse a rho,
AEAD or KDF index from another output.

## Implemented public encoding and encryption

The isolated codec implements a canonical fixed-width three-output body.
All output plaintexts remain 208 bytes: 144 bytes of note fields, including
the 32-byte asset identifier, followed by 64 zero-padding bytes.

| Component | Bytes per transaction position |
| --- | ---: |
| Fixed three-output public body | 2,027 |
| Confidential fee commitment | 48 |
| Canonical snapshot selector | 40 |
| Permanent position record | 2,115 |

The public body contains two nullifiers, three output commitments, the
1,088-byte ML-KEM ciphertext, three 208-byte encrypted bodies, three AEAD tags,
two explicit change nonces and three view tags. These byte counts are
implemented encoding lengths, not earlier source estimates. Proof envelopes,
sidecars, block records and issuance records are additional components.

Both sender-change outputs use 256-bit ChaCha20-Poly1305 keys derived with
domain-separated BLAKE3. Output indices 1 and 2 have distinct authenticated
contexts. The recipient path performs real ML-KEM encapsulation and
ChaCha20-Poly1305 encryption. The sender helper checks decryption and the
reconstructed commitment before returning ciphertext. Recipient and change
recovery parse the private asset identifier and verify the note commitment.

The proof binds ciphertext bytes; it does not prove correct ML-KEM or AEAD
execution. Wallets must verify tags and decrypted commitments. A malformed
payment ciphertext can make that payment unreceivable without permitting an
invalid state transition. Production wallet persistence, mnemonic recovery,
payment-opening retention and broadcast integration remain separate work.
Padding ciphertexts must use actual encryption under temporary valid keys.

## Per-asset balance and fees

The implemented AIR constrains asset-equality flags against all sixteen
identifier limbs and checks every nonzero input and output. It cannot balance
an input of one asset against an output of another, or use a non-SIP amount to
pay a transaction fee. The SIP equation includes the private fee; its commitment
is public and the opening remains in the sidecar.

Integer limb arithmetic constrains signed carries and rejects overflow and
an invalid final carry. Three output amounts and the SIP fee are four
subtractands. The implementation covers positive non-SIP amounts in atomic
units, retaining the existing 10,000-atom minimum for nonzero SIP outputs.
This conditional minimum is implemented experimentally and still requires
protocol review before activation.

A normal token payment uses one token input and one SIP fee input, producing
a token receipt, token change and SIP change. Two distinct non-SIP inputs have
no SIP fee source in this fixed shape and must be rejected or split by the
wallet. Pure SIP transfers use the same fields and ciphertext roles.

## Native fixed-supply issuance

The isolated issuance path implements a separate native D8/W24 proof, without
a recursive verifier. The signed canonical declaration binds:

* network identity and declaration version;
* the canonical ML-DSA-65 issuer key and u64 sequence;
* the derived asset identifier and public declared supply;
* the asset name and precision;
* the issuance fee amount; and
* ordered initial-note commitments and ordered ciphertext digests.

The signature context is `siworld asset issuance v1`. The canonical record
starts with the domain `siworld asset issuance declaration v1` followed by a
zero byte. Variable fields have explicit lengths, integers are little-endian,
and field elements use canonical u32 encodings. Development-fund keys and
signing domains are not reused.

The issuance AIR recomputes each initial note commitment, constrains every
note's private asset identifier to the declared identifier, and proves that
the exact checked u64 sum of all hidden initial-note amounts equals the
public supply. There is no terminal carry that could hide overissuance.
Its public statement also binds the complete declaration digest and the
ordered commitment list. An external signature alone is insufficient to mint.

Native verification checks the network, version, asset-ID derivation,
resource policy, ML-DSA-65 signature, ciphertext counts and byte hashes, and
the issuance proof. Acceptance additionally requires a caller-provided
verifier for an actual SIP fee payment bound to that declaration digest.
Merely supplying the claimed fee amount does not satisfy this gate.
Permissionless issuance and public supply are the selected design. Testnet
issuance costs exactly **50 SIP (5,000,000,000 atoms)**, with the entire fee
credited to a dedicated development-fund account. This account has not been
configured, so issuance admission remains closed. A missing or invalid
destination fails closed; it cannot waive the fee, select an implicit account
or redirect any amount to the miner. The mainnet issuance fee remains
undecided.

The reference registry checks sequence, asset-ID and commitment reuse before
mutation. This is an isolated atomicity model, not the node database
transition. Node integration must verify every gate and atomically append the
issuance record, registry entry and minted notes in one storage transaction,
with the verified SIP payment's one-time consumption and dedicated fund credit,
and equivalent reorg and duplicate-acceptance handling. Configuration of the
destination and this durable transition remain implementation gates; the
isolated caller-provided payment verifier does not satisfy them. Later transfers prove
ordinary ownership, membership and private asset conservation. Additional
minting and burning are not implicitly enabled.

### Issuance record size and resource policy

For `n` initial notes and a UTF-8 asset name of `name_bytes`, the implemented
canonical declaration plus ML-DSA-65 signature occupies:

```text
5,416 + name_bytes + 80*n bytes
```

The fixed part includes the 1,952-byte public key and 3,309-byte signature.
Each note contributes a 48-byte commitment and a 32-byte ciphertext digest.
Using a full recipient ciphertext for every initial note adds 1,313 bytes per
note, giving:

```text
5,416 + name_bytes + 1,393*n bytes, before proof and framing
```

The native benchmark helper generates real ML-KEM ciphertexts and locally
decrypts them. Its public deterministic ML-DSA fixture seed is exclusively a
synthetic measurement identity and must never configure an issuer or network.
Byte-digest binding does not assert encryption correctness or finalize the
issuance wire decoder.

The caller currently supplies note-count, metadata and per-note ciphertext
limits through an explicit policy. Canonical metadata limits, issuance
record/proof limits and per-block issuance byte/CPU limits must be adopted
before network acceptance. The selected testnet fee destination must also be
configured and its atomic accounting qualified. Until those limits and actual
database overhead are fixed, the permanent-position ledger cannot establish
a finite worst-case total for every protocol record.

Issuance proofs follow the same pruning rule as transaction and settlement
proofs: retain them for three elapsed days after final confirmation, then
delete them. Retain the signed public declaration, ciphertexts, commitments,
issuance state and public settlement statements permanently. A trusted
checkpoint must bind the asset registry and issuance state.

## Native SIP reward settlement

Apply the [shared integer monetary transition](v1-economics.md) to reconstruct
subsidy, reward mode, the pre-block pool, current credit and claim, burn and
fund credits. Voyager has one reward note; Holder has an immediate note plus
four height-locked notes. The AIR recomputes every fee commitment and exact
private fee sum, adds all fees only to note zero, and binds each note amount,
owner, unlock height, distinct index/randomness and complete commitment.
All reward asset-ID limbs must equal the reserved SIP identifier inside the
AIR; a host-only check is insufficient. Validators reconstruct the canonical
context and ordered transaction/fee list rather than trust peer-supplied
subsidy, pool, mode or reward openings. Note zero matures after 24 blocks,
including fees and the Holder pool claim. Revised preprocessing and security
measurements are required before freezing this relation.

The implementation and its rejection tests are separate from the retained
network. Block application, fee-payment accounting and the consensus
transition must use the same verified relation before activation.

## Extracted native AIR dimensions

The following are extracted dimensions of the isolated implementation, not
source-level estimates. Hiding and query choices can increase the padded
height. The selected issuance profile uses `log_blowup=8`, 36 queries and
20-bit query/opening-batch grinding. These are engineering profiles, not
independently approved cryptographic parameters.

| Relation | Padded rows | Main columns | Preprocessed columns | Public values | Constraints per row | Maximum degree |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Two-input/three-output transaction | 256 | 1,392 | 247 | 101 | 2,898 | 3 |
| Settlement, 576 positions | 1,024 | 581 | 609 | 7,050 | 19,703 | 3 |
| Issuance, three initial notes | 128 | 438 | 10 | 72 | 577 | 3 |

Issuance uses five Poseidon2 rows per initial note before padding, with seven
parallel u16 range-check lanes. Its public width is `36 + 12*n` and its
preprocessed width is `7 + n`. Transfer, issuance and settlement proofs require
separate instance-specific security reports; sharing a suite does not make
their shape-dependent terms identical.

## Rejection and integration coverage

The isolated tests exercise asset mixing, non-SIP fee payment, asset-ID limb
substitution, invalid balance carries, changed transaction fields, malformed
three-output encodings and invalid reward asset limbs. Issuance tests include
missing or invalid ML-DSA signatures, wrong network/version, forged derived
IDs, hidden overissuance, note-asset substitution, missing or changed
ciphertexts, policy-bound failures, unpaid SIP fees and atomic sequence reuse
rejection. Direct-AIR tests check supply and asset constraints independently
of native witness prevalidation.

Remaining node-level tests must prove unchanged accepted state, nullifiers,
asset registry and mempool after rejection. Wallet integration must cover
issuance followed by transfer, token and SIP change, padding, mnemonic
restoration and rescanning. Verify malformed, replayed and reorged issuance
records under the eventual block transition. Isolated prover tests do not
establish these network properties.

## Parameter scan and acceptance gates

Use the pinned `p3-security` version to scan every requested blowup/grinding
combination against the actual transaction AIR. Retain at least 128 bits of
classical conjectured security and at least 80 bits after Johnson-bound quantum
halving for all Fiat--Shamir challenge terms, including FRI queries and
grinding. Challenge-domain terms and BHT collision resistance must also reach
80 bits. Assess each native proof relation separately.

The revised transaction profile uses `log_blowup=7`, 41 queries, 20-bit
query/opening-batch grinding, zero commitment grinding, binary folding and
final-polynomial log length zero. Its three EPYC 7763 four-worker generation
trials are 1.531155438, 1.429902190 and 1.462877730 seconds. Four-worker bodies
are 581,392–585,808 bytes; the maximum across the separate one-worker group
as well is 588,832 bytes. The largest charged process-tree peak is 525,234,176
bytes. One-worker verification has a 17.006900-ms median, measured inside a
fresh setup/prove/verify process rather than a verifier-only process. Its peak
therefore does not establish independent verifier memory.

The [complete eight-profile scan](v1-multi-asset-evaluation.md) records every
trial, charged peak, actual shape and security term. Selection requires every
four-worker generation trial to pass two seconds and the proof-body limit,
then minimizes the largest observed body. Quantum-halved Johnson challenge
union is 81.692218869 bits; classical conjectured union is 185 bits and selected
W24 BHT collision ledger is 123.333333333 bits.

The body cap is **655,360 bytes (640 KiB)**, 11.2983% above the largest selected
body across both worker groups, rounded up to 64 KiB. It is an admission limit,
not a theorem that every randomized valid proof fits. Independently qualify
malformed decoding, verifier resources and wallet/node integration. The earlier
`bench-d8` decoder retains its 512-KiB limit. Settlement and issuance use
separate 655,360-byte settlement and 524,288-byte issuance caps and b8/q36/g20 profiles; the fresh scan measures each
with three four-worker and three one-worker processes.

Keep the maximum at 576 positions. The economic-record complete network model
charges 36.51651984 Mbps; **43 Mbps** minimum leaves 15.077861% unused, and
deployment recommends **100 Mbps**. Relay, validation and storage budgets use
the unchanged 2,115-byte permanent position record plus bounded block/fund and
issuance records. Actual transport, complete-block processing and issuance
resource policy remain qualification gates.

The selected AIR has 1,392 main columns. Further column/opening optimization
cannot silently change its key, cap or security target. Adopt a replacement
only after new source-bound security, timing, memory and proof-size evidence.

## Compatibility and remaining work

The former two-input/two-output implementation remains an unchanged diagnostic
baseline in `crates/bench-d8`; its proof results and keys do not accept the new
relation. The separate multi-asset crate preserves those frozen source,
artifact and dependency hashes. No missing native D8 dependency API currently
prevents these isolated native proof paths.

Before activation, complete protocol-policy review, production node and wallet
integration, issuance and block resource bounds, actual-shape parameter review,
full-load network/resource qualification and independent security review. The
native replay auditor checks canonical issued supplies and the fee-bound
registry through the shared transition. Public-data backup jobs, wallet
recovery acceptance and real three-day pruning qualification remain separate
work; their requirements do not establish implementation or acceptance.

The new engineering network must use reviewed new genesis data and independent
keys. Existing seven-node engineering history remains unchanged. Retained
production history and height-activated verifier compatibility remain future
design work. This document remains a proposal until all activation gates are
reviewed and satisfied.
