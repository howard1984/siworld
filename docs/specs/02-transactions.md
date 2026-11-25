# 02. Transactions

| Field | Value |
| --- | --- |
| Title | 02. Transactions |
| Status | Active |
| Version | 1.0.0 |
| Applies to | SIWORLD public RandomX ruleset |
| Last updated | 2026-11-25 |

## Abstract

Specifies the ordinary shielded transfer, its public identity, and the authorization of fixed-supply asset issuance.

## Motivation

Uniform transaction records allow a validator to verify transfers and prevent double spending using public proof inputs without learning the payment contents.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" are
interpreted as described in BCP 14 (RFC 2119 and RFC 8174) when, and only when,
they appear in all capitals.

### Transfer shape

A transfer MUST use two input positions and three output positions. The output
positions are payment, asset change, and SIP change, in that order. The
transaction proof MUST enforce ownership and inclusion for nonzero inputs,
derive their nullifiers, check their unlock heights at the selected snapshot,
and conserve value separately for each asset. The SIP balance MUST cover the
fee. Unused positions follow the relation's zero-value convention.

The sender MUST produce a proof over a single public record and bind the fee
commitment, commitments to the three new notes, and the encoded ciphertext
bytes. The payment output uses ML-KEM-768 and ChaCha20-Poly1305. Change
positions use ChaCha20-Poly1305 with keys derived from private wallet material
via domain-separated BLAKE3. Output plaintexts have a fixed width of 208 bytes.

### Canonical envelope and statement identifier

| Field | Encoding |
| --- | --- |
| Envelope tag, format, and proof suite | `SWTX`, little-endian `u16` version, 27-byte suite identifier |
| Network | 32 bytes |
| Snapshot | Little-endian `u64` height and 32-byte block ID |
| Public transaction record | 2,027 bytes |
| Fee commitment | 48-byte canonical digest |
| Transaction proof | Little-endian `u32` length, then exactly that many proof bytes |

A decoder MUST reject incorrect lengths, noncanonical public fields, an
unrecognized proof suite, and a different network. The proof MUST satisfy the
bound in [parameters](../reference/parameters.md). The statement identifier is
the BLAKE3 derive-key hash with context
`siworld native transaction identity v1`. Its input is the little-endian
`u16` suite length, suite bytes, little-endian `u16` format version, network,
snapshot height and block ID, public transaction record, and fee commitment in
that sequence. Proof bytes, their length, and the fee opening are excluded.

### Public issuance

An issuer MUST sign the canonical declaration with ML-DSA-65. The declaration
binds the network, issuer sequence, asset metadata, and supply. The issuance
proof MUST bind three initial note positions and enforce their total supply and
asset identifier. Validators MUST verify the declaration, proof, and fee
receipt before registering the asset and appending the initial commitments.

The fee receipt MUST identify a verified SIP output to the issuance fee
destination, uniquely bound to the declaration and unused as another issuance
receipt. It MUST match the configured fixed amount. Ordinary transfer fees
and the issuance fee have distinct settlement rules.

## Rationale

The statement identifier stays stable across proof randomness. The public issuance record makes the existence and supply of a new asset verifiable while subsequent transfers use the common shielded pool.

## Security considerations

A sender SHOULD check that its output ciphertexts decrypt to the intended note contents before submitting. A recipient MUST authenticate decryption and recompute the note commitment. Replay resistance also depends on the canonical network and snapshot checks.

## References

- [Notes and state](01-notes-and-state.md)
- [Proof system](03-proof-system.md)
- [Blocks and fees](04-blocks-and-fees.md)
- [Monetary policy](06-monetary-policy.md#issuance-fee)
- [Native wire and issuance implementation](../../crates/native-node/)
- [FIPS 203](https://doi.org/10.6028/NIST.FIPS.203)
- [FIPS 204](https://doi.org/10.6028/NIST.FIPS.204)
- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119)
- [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)
