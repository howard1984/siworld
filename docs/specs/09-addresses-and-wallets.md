# 09. Addresses and wallets

| Field | Value |
| --- | --- |
| Title | 09. Addresses and wallets |
| Status | Active |
| Version | 1.0.0 |
| Applies to | SIWORLD public RandomX ruleset |
| Last updated | 2026-11-25 |

## Abstract

Defines network-bound recipient addresses, short-address resolution, and verification of wallet observations.

## Motivation

Address encodings must carry or authenticate enough context to prevent a substitution or a payment to a different network. Wallets should derive payment status locally from authenticated records.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" are
interpreted as described in BCP 14 (RFC 2119 and RFC 8174) when, and only when,
they appear in all capitals.

### Canonical receiving address

A binary receiving address is 1,232 bytes, consisting of a 48-byte
canonical owner digest and a validated 1,184-byte ML-KEM-768 public key.
The full text format starts with `sivf1`. The encoded payload MUST contain
one version byte with value 1, the 32-byte network identifier, and the binary
receiving address. The text encoding is lowercase Base32 with alphabet
`abcdefghijklmnopqrstuvwxyz234567`, without padding. The eight-byte
checksum is appended to the payload before Base32 encoding and binds
the textual prefix, expected network, and payload.

The checksum uses BLAKE3 derive-key context
`siworld native recipient text checksum v1` and takes the first eight
digest bytes. A decoder MUST reject a different network, invalid receiving
key, noncanonical field values, or a failed checksum.

### Short address and contact resolution

A short address starts with `sivs1`. Its payload consists of version 1 and
a 32-byte commitment to the network and binary receiving address, with the
same checksum construction. The commitment uses BLAKE3 derive-key context
`siworld native recipient directory v1` over the network and binary address
in that order. The wallet MUST obtain a full address independently,
validate it, and recompute and match the commitment before sending. A short
address alone MUST NOT be interpreted as a receiving key.

### Wallet verification

A wallet MUST bind its account to its selected network and genesis. For an
incoming payment, it MUST authenticate decryption, recompute the note
commitment, and match the output against the selected history. It MUST use
the verified note unlock height and distinguish provisional inclusion from
[checkpoint coverage](07-storage-and-sync.md#light-wallet-evidence).
For a native 24-word recovery phrase, the decoded 256-bit BIP39 entropy
feeds the wallet derivation. A wallet MUST NOT replace it with the
passphrase-derived BIP39 seed.

## Rationale

A short commitment makes address sharing compact while preserving verification of the full encrypted recipient. Starting from canonical history lets the wallet discover payments without sending its secret keys to peers.

## Security considerations

Recovery words and viewing material can reveal or control wallet state. Keep them within the wallet's custody boundary. A payment accepted on a provisional branch may be removed by a permitted reorganization.

## References

- [Wallet implementation](../../crates/native-wallet-core/)
- [Wallet engine](../../crates/native-wallet-engine/)
- [Wallet guide](../guides/wallet.md)
- [Transactions](02-transactions.md)
- [BIP 39](https://bips.dev/39/)
- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119)
- [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)
