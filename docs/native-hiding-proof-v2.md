# Native hiding proof format V2

## Status and scope

This inactive implementation adds independently randomized Merkle leaves to
the input and FRI commitments of the native D8/W24 proof family. It retains
polynomial masking. It does not select a network, change an existing genesis,
or establish a complete zero-knowledge security claim. Transaction, retained
settlement and asset-issuance adapters exist. The complete confidential fee
relation, network admission and browser generation remain integration gates.

## Private and public information

The intended private transaction witness includes input note amounts, note
contents, spending material, commitment blindings and the selected recent-root
membership path. Canonical nullifiers, output commitments, ciphertexts, fee
commitments and authenticated chain context remain public. Salted Merkle trees
do not hide public inputs or eliminate information already implied by them.

Retained settlement proves openings of fee commitments and reward-note
commitments; its authenticated public statement includes the reward allocation
plan and chain context. Asset issuance intentionally publishes the declaration,
issuer verification key, asset metadata, supply and issuance fee. Its individual
note witness and encryption randomness are separate private inputs. The
confidential fee relation requires a joint review of transaction, settlement,
ciphertext and public block data; these native adapters alone do not establish
that per-transaction or per-block fee totals are hidden.

## Randomness and commitments

The field is KoalaBear, with modulus `0x7f000001`; challenges use an extension
of degree eight. The input and FRI MMCSs use the width-24 Poseidon2 permutation,
a rate-12 sponge, twelve-field digests and nine independent field elements of
salt per committed matrix row. FRI extension elements are flattened into base
fields before the salted MMCS. Input and FRI cap heights are one and two.

Each private proof attempt obtains 96 bytes from the operating system. Three
disjoint 32-byte portions are derived under separate BLAKE3 domains for
polynomial masks, input salts and FRI salts. No deterministic private fallback
exists. Configuration aliases share one ownership fence; successful final
opening, callback completion or unwinding retires private authority. An
additional dependency-level fence prevents reopening private masked data.

Nine uniform field salts contain approximately 278.9 ideal bits per row. Each
private stream has a 256-bit seed. These counts are not a claim of 278.9-bit
computational security, post-quantum security or protocol zero knowledge.

Public preprocessing is deterministic and reusable, with an explicit public
route that cannot activate private commits. Its randomness is public and is
not a witness-hiding mechanism. Independent private attempts reuse public
preprocessing without reusing private mask or leaf-salt streams.

## Openings and hiding obligations

A queried leaf is transmitted with both its values and salt. Thus salts protect
unopened leaf commitments; they do not themselves conceal a queried value.
Queried values must be evaluations of adequately masked polynomials. OOD
evaluations, random-codeword openings, FRI sibling values and the final
polynomial also form part of the public transcript.

The configured PCS retains eight random codewords, interleaved random trace
rows, randomized quotient chunks and the STARK randomization polynomial. Its
conservative mask budget is `N >= 2 * (q + D * p)`, where `N` is the private mask
height, `q` the query count, `D = 8`, and `p` the number of supplied opening
points. Opening and verification check the actual disclosure count. Repeated
private openings cannot multiply this budget. Both MMCS layers must be hiding;
polynomial masking alone does not satisfy that documented requirement.

A complete review must still analyze the joint distribution conditioned on all
disclosed random openings, adaptive Fiat-Shamir challenges, exceptional
challenge events and correlations across quotient, lookup, FRI and transaction
proofs. The query/grinding score is not a replacement for an instance-specific
soundness analysis. Salt tampering rejection and distinct proof outputs are
functional evidence, not a simulator or a proof of zero knowledge.

## Format and admission

The complete frame has a 48-byte header: eight-byte `SIWZKP2` magic including
its zero terminator, little-endian version two, relation byte, zero flags,
32-byte profile identity and little-endian body length. The canonical postcard
body follows. Unknown versions, flags, identities, truncation and trailing
bytes are rejected; parsing never falls back to V1.

The expected identity binds the codec, backend parameters, relation, complete
AIR identifier, preprocessing key including its commitment, structural limits,
genesis and rules digest. These are authenticated local inputs. A header digest
is not a signature and does not authenticate peer-selected keys or programs.
Dimensions alone cannot identify an AIR. Production admission requires a
genesis registry for the exact constraint program and independently rebuilt
public statement.

Before typed decoding, a bounded parser checks all vector lengths, canonical
fields, opening counts, salt dimensions and authentication frontiers. Successful
decoding establishes structure only; independent cryptographic verification
against the canonical statement remains mandatory.

| Relation | Complete frame upper bound | Salt encoding increase | New header |
| --- | ---: | ---: | ---: |
| Transaction | 631383 bytes | 30886 bytes | 48 bytes |
| Retained settlement, capacity 576 | 563791 bytes | 29859 bytes | 48 bytes |
| Asset issuance, three notes | 319354 bytes | 25752 bytes | 48 bytes |

These are structural maxima checked against actual typed postcard containers,
including maximum authentication frontiers. The containers are deliberately
not valid cryptographic proofs. The increment compares identical geometry with
the corresponding unsalted body; it is not a measured difference between two
random proof samples. The transaction frame cap is 655360 bytes. Exactly one
complete-fee proof is permitted per block, with a separate complete-frame cap
of 5242880 bytes (5 MiB); issuance retains its 524288-byte cap. These limits and
the fee-proof count are encoded in a canonical consensus-parameter record and
included in the V2 profile identity. Actual proof sizes, setup and generation time,
independent verification time and peak memory require separate measurements.

The existing complete-fee candidate has 7668 main columns and 80 queries. Main
query values alone require `7668 * 80 * 4 = 2453760` bytes, before any salts,
paths or other sections. Existing complete frames of 3982061 through 3992477
bytes fit the separate fee cap. Those measurements are from an earlier
confidential candidate and do not qualify the V2 profile. The uni-STARK codec
still explicitly rejects the complete-fee relation: its batch schema contains
additional permutation and lookup fields and requires its own bounded decoder
and authenticated verification adapter. No AIR compression or security-parameter
reduction is required by the fee size limit.

The V2 fee receiver checks the outer declared length before reading proof bytes
or allocating a body. After reading the fixed header it checks the authenticated
identity and exact inner length before allocating at most the admitted frame
size. Truncation and excess declarations fail without invoking a verifier.
Transport read deadlines and bounded aggregate concurrency remain mandatory.

Fee verification requires a configurable operational deadline and a terminable
isolated worker. Expiry must kill and reap the worker; discarding a future or
thread result while computation continues is insufficient. A timeout, busy
worker or process failure defers local admission and must not mark a block
permanently consensus-invalid or penalize a peer for an invalid proof. Only a
completed cryptographic check against the canonical statement may establish
validity. A deadline is a resource policy, not a consensus parameter.

The local supervisor uses one shared permit with no waiting queue. Its
provisional default deadline is five seconds and can be configured by the
operator. Hashing, input staging, startup, verification, child exit and receipt
acceptance share that deadline. A fixed-size receipt binds the attempt, network,
genesis, rules, profile, verification-key set, statement, proof and captured
canonical context. Late output cannot complete admission. The permit is released
only after confirmed child reaping; an uncertain process-control result keeps
it occupied. Native process isolation is excluded from WASM builds.

The supervisor is an integration component, not a verifier. A resident must own
one shared supervisor, select a trusted child executable that spawns no children,
rebuild its statement and keys independently, enforce transport read deadlines,
and recheck canonical context before adopting state. The new complete-fee batch
adapter and genesis registry must connect these boundaries before activation.

## Review assumptions and remaining evidence

The intended hiding argument assumes unpredictable operating-system entropy,
secure stream generation and domain separation, the required hiding properties
of salted Poseidon2 commitments, appropriate Fiat-Shamir/hash assumptions,
adequate masks for the complete transcript, correct one-time ownership and no
side-channel or secret export outside the proof. This implementation does not
make constant-time or forensic memory-erasure claims. Endpoint compromise and
network traffic correlation are outside the proof-hiding claim.

Required remaining evidence includes real proofs and independently rebuilt
statements for each relation, independent public preprocessing reproduction,
complete-fee size qualification, whole-block disclosure analysis and the web
wallet's new-format generation path. An external cryptographic review must
assess the combined protocol and its assumptions. The presence of both salted
MMCSs completes a specific missing configuration obligation; it does not by
itself close these remaining obligations.
