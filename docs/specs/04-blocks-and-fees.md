# 04. Blocks and fees

| Field | Value |
| --- | --- |
| Title | 04. Blocks and fees |
| Status | Active |
| Version | 1.0.0 |
| Applies to | SIWORLD public RandomX ruleset |
| Last updated | 2026-11-25 |

## Abstract

Defines block structure, canonical transaction ordering, and confidential transfer fee settlement.

## Motivation

Block validation must bind proof-bearing data and executed state independently. A miner must account for all accepted transfer fees without exposing individual fee amounts on the ledger.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" are
interpreted as described in BCP 14 (RFC 2119 and RFC 8174) when, and only when,
they appear in all capitals.

### Header and body

The fixed-width header is 190 bytes. Its version prefix is four ASCII bytes
`SWE2` followed by little-endian `u16` version 2. The ordered fields
after the prefix are:

| Field | Bytes |
| --- | ---: |
| Network identifier | 32 |
| Height | 8 |
| Parent block identifier | 32 |
| Timestamp | 8 |
| Work target | 32 |
| Execution commitment | 32 |
| Body commitment | 32 |
| Nonce | 8 |

Height, timestamp, and nonce are little-endian `u64`. Readers MUST preserve
the raw 32-byte targets and digests. A block body MUST have the matching
canonical body commitment and comply with the active genesis rules. The
body commitment uses domain-separated BLAKE3 over the little-endian
`u64` encoded body length followed by the exact body bytes.

The body begins with the ASCII bytes `SW2B` and little-endian `u16` version
1. The 85-byte prefix continues with the 32-byte network identifier,
little-endian `u64` height, 32-byte proof profile, little-endian `u16` slot
count, and five one-byte fields: mining mode, reward count, fund-claim
count, governance-action count, and issuance count. A block permits at
most eight fund claims and 32 governance actions.

The remaining records MUST appear in the following order:

1. Mode-specific miner reward records, each with a 48-byte commitment and
   1,313-byte ciphertext.
2. A reserved record of the same size. For miner fee settlement, every
   byte of this record MUST be zero. It remains bound by the body commitment
   and contributes no note commitment to state.
3. Fixed-width fund claims.
4. Governance actions, issuance records, ordered transfer envelopes, and
   the settlement proof, in that order. Each of these records is prefixed
   with its little-endian `u32` byte length.

Readers MUST reject trailing bytes and recompute the header's execution
commitment after executing the verified records.

### Slots and order

A block MUST carry a multiple of 16 transaction slots from 16 through 576.
A miner MAY fill unused slots with proved zero-value padding. Padding uses
the ordinary public record format and valid ciphertext encodings. Validators
MUST reject duplicate or non-increasing statement identifiers in the
consensus byte order. Each transfer and specialized record MUST be validated
under its selected relation before its effects are committed.

### Transfer fees and settlement

Let $h$ be the transaction's selected snapshot height and $S$ the subsidy
function. The standard fee is $b=\lfloor S(\max(1,h))/10{,}000\rfloor$ atoms.
The priority fee is $4b$. Padding commits to zero. At the genesis snapshot the
two fees are 339,452 and 1,357,808 atoms respectively.

The submitting client supplies a private fee opening over an authenticated
submission path when required by the miner. An opening MUST match its public
commitment. Openings MUST be kept outside the public block body. Each block
MUST carry one native settlement proof binding the ordered fee commitments,
block height, declared mode, and reward records to the consensus-derived
allocation. The full sum of transfer fees MUST be added to the first miner
reward note. Validators MUST enforce the mode-specific note count, amounts,
and unlock heights through the proof and the shared monetary transition.

## Rationale

The public order is independent of arrival order and of proof randomness. One block settlement proof enforces fee conservation while keeping the individual fee amounts out of the public record.

## Security considerations

A valid claim about a body hash does not establish proof validity. Validators MUST check the body and resulting state against independently authenticated header commitments. Miners and relay peers can observe fee openings delivered to them.

## References

- [Transaction identifiers](02-transactions.md#canonical-envelope-and-statement-identifier)
- [Monetary policy](06-monetary-policy.md)
- [Proof system](03-proof-system.md)
- [Native block implementation](../../crates/native-node/)
- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119)
- [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)
