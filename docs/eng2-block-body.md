# Engineering block-body encoding

Status: implemented canonical framing for a separately activated network. The
encoding is not a proof verifier or an existing-network activation. Each engine
must select its complete proof profile from immutable genesis rules. The internal
`LegacyMiner` engine uses the existing native transaction, settlement and issuance
profile. Activating the separate confidential-destination fee mode requires its
complete qualified payment-recoverability profile; it is not a prerequisite for
the explicitly different legacy mode.

## Context and local decoding policy

Every body binds its network, exact nonzero inclusion height and a 32-byte proof
profile identifier. A caller supplies the immutable expected profile, total body
byte bound and settlement-proof byte bound. There is no production default and
no profile selected by received data. An unknown profile or mismatched context
is rejected. A successful decoder does not establish proof or signature validity.

## Canonical layout

Integers use fixed little-endian encoding. The 85-byte prefix contains:

| Field | Bytes |
| --- | ---: |
| Magic `SW2B` | 4 |
| Format version, currently 1 | 2 |
| Network | 32 |
| Inclusion height | 8 |
| Proof profile | 32 |
| Transaction slot count | 2 |
| Reward mode | 1 |
| Miner reward count | 1 |
| Public fund-claim count | 1 |
| Governance-action count | 1 |
| Issuance-record count | 1 |

Reward mode zero is Voyager, with one miner reward; mode one is Holder, with five.
The following fields occur in order:

1. The fixed number of miner rewards, each with a 48-byte canonical commitment
   and 1,313-byte payment ciphertext.
2. One fixed-shape fee output slot. In the confidential-destination prototype
   it contains a fee payment, including zero-fee blocks, and cannot duplicate a
   miner reward. The sealed `LegacyMiner` engine instead requires all 1,361 bytes
   to be zero, never appends this sentinel and pays fees through miner note zero
   using the existing native settlement proof.
3. Fixed-width versioned public fund claims, ordered by distinct member index.
   Their network and inclusion height must match this body.
4. Governance actions, each prefixed by a four-byte length and strictly ordered
   by increasing action sequence. Each uses the shared governance codec.
5. Issuance records, each prefixed by a four-byte length and strictly ordered by
   declaration binding. Each uses the existing bounded issuance codec.
6. Transaction envelopes, each prefixed by a four-byte length and strictly ordered
   by canonical public statement identity. Envelope network and canonical public
   fields are checked before copying its bounded opaque proof.
7. A nonempty confidential settlement proof, prefixed by a four-byte length and
   bounded by the explicitly supplied native profile policy.

Transactions retain the fixed 64-to-576 slot bounds in groups of 16. Existing
fund-claim, governance and issuance count and per-record framing limits apply.
Unknown modes or versions, duplicate or unordered records, excessive counts,
noncanonical fields, truncation, oversized asserted lengths and trailing bytes
are rejected. Ordinary transaction envelopes contain no fee opening, aggregate
ordinary-transaction fee amount or real-slot count. This statement does not cover
the separate public fund-claim or issuance records. Existing `SWIS` issuance
encoding includes `issuance_fee_atoms` and `fee_rho`, and the body includes a public
issuance-record count; those fields retain their existing semantics.

## Header binding and resource use

The body commitment uses the standalone header's domain-separated hash over the
eight-byte body length followed by every canonical byte. The streaming writer and
commitment calculation buffer at most one variable-sized record, rather than a
second entire body. Writer failures preserve their I/O error kind. The native
engine must independently verify every transaction, issuance, settlement and
authorization, apply the ordered state transition atomically, and compare the
execution commitment with the authenticated header before adoption.
