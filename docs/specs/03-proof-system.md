# 03. Proof system

| Field | Value |
| --- | --- |
| Title | 03. Proof system |
| Status | Active |
| Version | 1.0.0 |
| Applies to | SIWORLD public RandomX ruleset |
| Last updated | 2026-11-25 |

## Abstract

Defines the proof suite, its statement binding, and the required verification boundary for transfers, issuance, and block settlement.

## Motivation

Independent verifiers need the same relations and proof profile. Proof-carried values cannot select the rules that validate them.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" are
interpreted as described in BCP 14 (RFC 2119 and RFC 8174) when, and only when,
they appear in all capitals.

### Suite and relations

The public ruleset uses Plonky3 native STARKs over KoalaBear with a degree-eight
extension and a width-24 Poseidon2 permutation. A digest contains 12 base-field
elements. Public preprocessing MUST come from the independently selected
relation and profile. Supplying a verifier key or altered verifier parameters
through a proof envelope MUST NOT change the accepted relation.

| Relation | Public binding | Required result |
| --- | --- | --- |
| Shielded transfer | Snapshot roots, public record, fee commitment | Valid ownership, spend conditions, nullifiers, and per-asset conservation |
| Fixed-supply issuance | Declaration, asset identifier, supply, and initial note commitments | Valid allocation of exactly the declared supply |
| Confidential fee settlement | Ordered fee commitments, height, declared mode, consensus reward plan, and reward records | Valid fees and exact miner output amounts |

### Transaction profile

The transaction proof uses FRI with binary folding, a blowup factor of
$2^7$, and 41 queries. The batching and query steps each enforce 20 bits of
grinding. A verifier MUST select the transaction, issuance, or settlement
profile before decoding a proof. It MUST reject invalid encodings,
trailing data, incorrect public inputs or profile binding, and proofs
exceeding the applicable limits in [parameters](../reference/parameters.md).
It MUST check each proof against the public inputs reconstructed from the
candidate block and trusted state, including the selected snapshot height
used for unlock constraints.

### Public preprocessing and hiding

Proof generation uses public preprocessing and witness hiding via randomized
commitments and polynomial masking. Independent builders SHOULD verify the
published profile artifacts against the pinned sources, generated public
verification data, and conformance tests. Provers MUST follow the deployed
proof format and use secure fresh randomness for hiding.

## Rationale

Separate relations allow transaction, issuance, and settlement checks to bind different public inputs without requiring a trusted setup or changing the transfer format.

## Security considerations

The [security model](../security/security-model.md#proof-security) describes the assumptions behind the proof security target. Implementations MUST enforce frame and verifier limits before allocating from untrusted lengths.

## References

- [Native proof implementation and profiles](../../crates/bench-multi-asset/)
- [Transactions](02-transactions.md)
- [Blocks and fees](04-blocks-and-fees.md)
- [Whitepaper, Section 10](../whitepaper.md#10-quantum-attacks-and-resistance)
- [STARK construction](https://eprint.iacr.org/2018/046)
- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119)
- [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)
