# Public fund-claim encoding

Status: implemented verification primitive for the separately activated engineering
network. This format is not enabled by the existing network transition and does
not replace entitlement accounting.

## Public-note boundary

A fund claim already discloses its member index, spend counter, SIP amount, owner,
note randomness, commitment, ciphertext and immutable member verification key.
The versioned claim additionally discloses the 32-byte ML-KEM encapsulation coins
for that single public payment. The coins permit reconstruction of that payment's
shared secret and plaintext. They are neither a wallet private key nor a wallet
view key.

This encoding must never be reused for confidential fee settlement or confidential
wallet payments: publishing encapsulation coins reveals the payment plaintext.

## Encoding and authentication

The fixed 6,861-byte encoding contains, in order:

| Field | Bytes |
| --- | ---: |
| Magic `SW2F` | 4 |
| Version, little-endian, currently 1 | 2 |
| Network identifier | 32 |
| Exact inclusion height, little-endian | 8 |
| Existing fund-spend fields before its signature | 3,474 |
| Single-payment encapsulation coins | 32 |
| ML-DSA-65 signature | 3,309 |

The signature covers every preceding byte, including the format identifier and
version, under context `siworld eng2 public fund claim v1`. The unsigned fund-spend
fields include the member, counter, amount, complete disclosed note, commitment,
ciphertext and verification key. Legacy fund-spend signatures use a different
message and context and do not authorize this format. Noncanonical lengths,
unknown versions and a zero inclusion height are rejected.

The member verification key must equal the immutable configured authority. The
note nonce must equal the canonical network/member/counter derivation, and the
note opening must match the commitment. The claim network and inclusion height
must match both the frozen governance state and the block being evaluated.

## Complete payment-destination verification

Verification uses the active full payment address from frozen governance state,
including its ML-KEM encapsulation key. It reconstructs the KEM ciphertext from
the disclosed coins, authenticates and decrypts the payment under the network's
encryption context, and compares every recovered note field and commitment with
the disclosed note. Equal owner commitments with different encapsulation keys
are not interchangeable. A valid authority signature cannot excuse an incorrect
KEM ciphertext, encrypted body, authentication tag, view tag, encapsulation coins
or network context.

Successful verification returns a non-clone authorization capability containing
the bound member, amount, counter, commitment and ciphertext. Before output
insertion, `AuthorizedFundClaim::debit` consumes this capability through the sole
fund ledger's released-entitlement and counter checks at the exact network and
height. It creates a second non-clone `DebitedFundOutput` only after the actual
debit succeeds. Replays and overdrafts cannot create that output. This operation
must target an isolated candidate ledger: the debit and output must commit
atomically with the remaining block state.

## Candidate authorization window

`WindowedFundClaim` is an inactive version-two primitive. It retains the same
public payment fields, interprets the signed height as the first permitted
inclusion height, and adds an eight-byte last permitted height immediately
after it. Both endpoints are inclusive. At least 288 heights must be permitted;
zero starts, shorter intervals and overflowing minimum endpoints are rejected.
The fixed frame is 6,869 bytes. Every field and both endpoints are signed under
`siworld eng2 public fund claim v2`. Version-one and version-two signatures and
decoders are not interchangeable.

Verification checks the actual inclusion height and its frozen governance
state. The active complete destination and immutable member authority still
apply; an interval does not preserve an obsolete destination after rotation.
The authorization capability binds the actual inclusion height, and its debit
continues to enforce available entitlement and the next unspent counter.
Rebroadcasting the same signed payload cannot debit the ledger a second time.

The existing body decoder still accepts only version-one exact-height claims.
Selecting the windowed format requires a new authenticated genesis/rules binding,
bounded body framing, producer and validator integration, signing-tool support
and reorganization acceptance. Adding this primitive does not modify the
retained engineering genesis or establish full-network qualification.
