# 01. Notes and state

| Field | Value |
| --- | --- |
| Title | 01. Notes and state |
| Status | Active |
| Version | 1.0.0 |
| Applies to | SIWORLD public RandomX ruleset |
| Last updated | 2026-11-25 |

## Abstract

Defines the shielded note pool, asset namespace, snapshot selection, and authenticated execution state.

## Motivation

A validator needs a common state against which it can check ownership, membership, and conservation while keeping note contents private.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" are
interpreted as described in BCP 14 (RFC 2119 and RFC 8174) when, and only when,
they appear in all capitals.

### Notes and commitments

A note contains an owner, an amount in atoms, a 32-byte asset identifier, an
unlock height, and randomness. Implementations MUST encode amount and height
as integers and MUST use canonical KoalaBear elements for the lanes of a
Poseidon2 digest. A digest has 12 elements encoded as little-endian 32-bit
values. A value equal to or above the field modulus MUST be rejected.

A created note MUST append its commitment to the depth-40 note tree in the
consensus execution order. A spend MUST demonstrate ownership and membership
under the selected snapshot and publish the corresponding nullifier. Every
nonzero nullifier MUST be unused in the selected state and unique within the
transition. A failed transition MUST leave the note tree and nullifier set
unchanged.

### Assets

The 32-byte zero identifier is reserved for SIP. An issued asset MUST derive
its identifier by domain-separated BLAKE3 over the network identifier, issuer
key, and issuer sequence using the canonical declaration encoding. The asset
registry MUST reject duplicate identifiers. Its public declaration defines
a fixed supply. [Transaction rules](02-transactions.md#public-issuance) define
the authorization, initial notes, and fee checks.

### Snapshots and state commitment

A snapshot is selected by height and exact block identifier. A validator MUST
resolve it against the canonical state view used for the transition and inside
the 4,096-snapshot window. Each snapshot binds a depth-12 tree of recent
note-tree roots. The input proof MUST establish membership through a root
covered by that snapshot.

A candidate header carries an execution commitment separate from its body
commitment. Validators MUST reconstruct the execution commitment from the
canonical descriptors for the resulting components. In order of component
identifier (1–11), these are chain context, note commitment tree, nullifiers,
recent roots, Holder pool, development fund, fee destination state,
governance, issuance and burn counters, locked rewards, and asset registry.

Each 42-byte descriptor contains a little-endian `u16` component identifier,
a little-endian `u64` encoded byte length, and a 32-byte component digest.
The digest is domain-separated BLAKE3 over the identifier, length, and
canonical component bytes. The aggregate uses a separate domain and binds
little-endian `u16` version 1, the network identifier, little-endian `u64`
height, the parent identifier, little-endian `u16` component count, and all
descriptors in order. Validators MUST reject a mismatch before installing
the state. If a branch is replaced, its execution components MUST roll
back together.

## Rationale

One pool supports asset conservation and uniform shielded transfers. An independently authenticated execution commitment gives block validation and checkpoint import the same post-state verification boundary.

## Security considerations

Public commitments, nullifiers, and snapshot selectors have different privacy properties. Validators MUST derive their snapshot and component descriptors from authenticated state. See the [security model](../security/security-model.md).

## References

- [Transactions](02-transactions.md)
- [Block commitments](04-blocks-and-fees.md#header-and-body)
- [Parameters](../reference/parameters.md)
- [Native node and state implementation](../../crates/native-node/)
- [Native proof relations](../../crates/bench-multi-asset/)
- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119)
- [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)
