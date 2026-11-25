# 05. Consensus

| Field | Value |
| --- | --- |
| Title | 05. Consensus |
| Status | Active |
| Version | 1.0.0 |
| Applies to | SIWORLD public RandomX ruleset |
| Last updated | 2026-11-25 |

## Abstract

Specifies RandomX proof of work, ASERT target adjustment, accumulated-work selection, and checkpoint-bounded finality.

## Motivation

Nodes must come to the same decision about candidate work and preserve an authenticated checkpoint when evaluating competing branches.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" are
interpreted as described in BCP 14 (RFC 2119 and RFC 8174) when, and only when,
they appear in all capitals.

### RandomX proof of work

Consensus uses RandomX v1.2.1 with the Argon2d salt
`SIWORLD/RandomX/ArgonSalt/v1`. For candidate height $h$, the key-block height
is $2048\lfloor\max(h-64,0)/2048\rfloor$. Heights above zero MUST resolve on the
candidate's parent ancestry. Height zero resolves to the sealed genesis
identifier. The epoch key is derived by domain-separated BLAKE3 over the
genesis identifier, little-endian key-block height, and key-block identifier.

The header seed is domain-separated BLAKE3 over the first 182 header bytes
through the body commitment. The work input binds that seed and the
little-endian nonce. The RandomX input consists of the fixed
`SIWORLD/RandomX/PoW/v1` domain and a terminating zero byte, followed by the
32-byte header seed and the eight nonce bytes. A node MUST independently
compute the branch-specific key, header seed, and work digest. The digest
interpreted as an unsigned big-endian integer MUST be strictly below the expected target.
The block identifier uses domain-separated BLAKE3 over the header seed
followed by the eight nonce bytes.

### ASERT and timestamps

The target interval is 300 seconds. The public profile uses a 3,600-second
ASERT half-life. Let $T_0,t_0$ be the genesis target and timestamp, and
$h_p,t_p$ the parent height and timestamp. The exponential relation is:

```math
T \approx T_0\,2^{((t_p-t_0)-300h_p)/3600}.
```

For the first block the target is $T_0$. For later blocks a validator MUST
compute the following with exact integer arithmetic. Division in the
exponent truncates toward zero, and the exponent shift is arithmetic.

```text
e = trunc(((parent_time - genesis_time) - 300 * parent_height) * 65536 / 3600)
s = e >> 16
f = e & 65535
factor = 65536 + ((45426 * f) >> 16) +
         ((15746 * f * f) >> 32) + ((3643 * f * f * f) >> 48)
target = (genesis_target * factor) >> 16
shift = min(abs(s), 255)
```

Shift the target left by `shift` if `s > 0`, or right otherwise. Clamp
the result to $[1,2^{256}-1]$. Decode the genesis target and encode the new
target as unsigned 32-byte big-endian integers. The declared target MUST
match this result. For example, with $T_0=2^{253}$, genesis time 1,000,
and parent height 12, elapsed times of 0, 3,600, and 7,200 seconds produce
targets of $2^{252}$, $2^{253}$, and $2^{254}$, respectively.

A timestamp MUST exceed the median of the 11 preceding timestamps once
available, or the parent's timestamp before then. Live admission applies
a separate future-time check against the local clock. Historical
validation uses the committed timestamps.

### Checkpoints and finality

A checkpoint certificate MUST contain two valid ML-DSA-65 signatures from
distinct authorized keys out of three. Both signatures MUST bind the same
canonical statement. That statement binds the network, checkpoint height and
block identifier, authorization height and block identifier, and the
authorization commitment. Authorization MUST be grounded in the authenticated
chain. The authorization block MUST descend from the checkpoint and be at
least 24 heights later. Reject mismatched networks, contradictory ancestry,
duplicate signers, and invalid signatures. A certificate for a header outside
the verified selection MUST NOT finalize that header by itself.

Nodes MUST NOT reorganize across an accepted checkpoint. Among eligible
branches that preserve it, a node selects the branch with the greatest
validated accumulated work. Each block with target $T$ contributes
$\lfloor 2^{256}/(T+1)\rfloor$. A header-only candidate MUST NOT replace executed
state. A node importing a checkpoint MUST follow
[storage and synchronization](07-storage-and-sync.md#checkpoint-synchronization).

## Rationale

An ancestry-derived epoch key gives each candidate its own reproducible work input. ASERT responds to timing changes against an immutable reference. A verified checkpoint constrains the set of eligible branches.

## Security considerations

Proof of work and checkpoint authentication establish different properties. A claimed checkpoint height or work total is insufficient without independent verification. Operators should treat incompatible authenticated checkpoint evidence as a finality fault. See the [security model](../security/security-model.md).

## References

- [RandomX design and specification, v1.2.1](https://raw.githubusercontent.com/tevador/RandomX/v1.2.1/doc/specs.md)
- [Parameters](../reference/parameters.md)
- [Block encoding](04-blocks-and-fees.md#header-and-body)
- [Work-target arithmetic](../../crates/core/src/pow.rs)
- [Checkpoint and fork-choice implementation](../../crates/native-node/)
- [FIPS 204](https://doi.org/10.6028/NIST.FIPS.204)
- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119)
- [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)
