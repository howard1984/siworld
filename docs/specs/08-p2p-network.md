# 08. Peer-to-peer network

| Field | Value |
| --- | --- |
| Title | 08. Peer-to-peer network |
| Status | Active |
| Version | 1.0.0 |
| Applies to | SIWORLD public RandomX ruleset |
| Last updated | 2026-11-25 |

## Abstract

Defines the authenticated transport and the separation of peer data acquisition from consensus admission.

## Motivation

Peers need to exchange bounded data across an authenticated connection. Transport authentication and consensus validity are independent checks.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" are
interpreted as described in BCP 14 (RFC 2119 and RFC 8174) when, and only when,
they appear in all capitals.

### Session establishment

Peers use TLS 1.3 with the hybrid X25519 and ML-KEM-768 key exchange.
A peer MUST validate its expected network, authenticated peer identity
and role before accepting protocol traffic. The session binding uses
Ed25519 and ML-DSA-65 signatures and binds the connection to its network
context. Peers MUST reject invalid signatures, mismatched session bindings,
or unrecognized peer capabilities. A descriptor supplied over the connection
MUST NOT silently replace an independently trusted peer pin.

### Data exchange

Peers exchange transactions, headers, blocks or bounded body pieces, and
checkpoint and synchronization records. A receiver MUST enforce canonical
framing, message limits and negotiated capabilities before accepting data.
A header MUST pass the ancestry, timestamp, target, and work checks.
Bodies and pieces MUST be matched to the candidate and authenticated
before the reconstructed body is used for execution. A full node MUST then
verify the proofs and state transition independently.

Transaction submission MAY carry a private fee opening for miner admission.
A receiving peer MUST follow the authenticated submission boundary and
separate that opening from the public transaction record. A transport receipt
or admission acknowledgment MUST NOT be presented as inclusion or finality.

### Roles and isolation

The selected package and peer manifest define the allowed connection roles
and independent peer pins. A client MUST use peers and genesis material from
the intended network. A node MAY serve or request published checkpoint data
without acting as a checkpoint signer.

## Rationale

Hybrid session authentication binds the peer identities and network while preserving local validation as the sole admission boundary.

## Security considerations

Encrypted channels do not hide endpoints, message timing, or data disclosed to the receiving peer. Untrusted peers may send incomplete or invalid inputs, so peer authentication MUST NOT substitute for structural and proof validation.

## References

- [Consensus](05-consensus.md)
- [Storage and synchronization](07-storage-and-sync.md)
- [Node networking implementation](../../crates/native-node/)
- [TLS 1.3, RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)
- [FIPS 203](https://doi.org/10.6028/NIST.FIPS.203)
- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119)
- [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)
