# Native V1 browser wallet

Status: local receiving and custody implementation. Public deployment, native
chain synchronization, locally verified balances and browser payment generation
remain incomplete. Existing native CLI behavior is unchanged.

## Recovery and local custody

Recovery uses exactly 24 canonical English BIP39 words encoding the original
256-bit entropy. It does not use the BIP39 PBKDF2 seed or an optional BIP39
passphrase. Native network ID and unsigned 32-bit account index bind all existing
key-derivation domains. A phrase restored with a different context produces a
different identity; the original context must be retained with the backup.

The implementation reuses the frozen KoalaBear/Poseidon2 field hash and pinned
ML-KEM-768 implementation. Integration tests compare the portable identity to
the existing native wallet across networks, accounts and synthetic entropies.
No circuit, proof, reward, maturity or consensus parameter is modified.

New entropy comes from browser cryptographic randomness inside a dedicated
worker. Three distinct randomized word positions must be answered before
encrypted persistence or receiving-file export. Cancel, lock, page exit and
backgrounding clear recovery fields and terminate the worker. A five-minute
inactivity timeout also locks the session. Strings copied by the browser or
JavaScript engine cannot be guaranteed to have been erased; compromised scripts,
extensions, the device and recovery screenshots remain outside this boundary.

The binary vault is the existing 132-byte SWNVLT01 format: magic, 16-byte salt,
24-byte nonce, authenticated 68-byte payload and 16-byte tag. The payload is
network (32), little-endian account (4), and entropy (32). Argon2id v19 uses
65,536 KiB, three iterations and one lane. XChaCha20-Poly1305 authenticates the
native domain string and the entire header. The device password does not affect
the receiving identity. Native and portable vaults authenticate each other.

IndexedDB stores ciphertext and public recovery context in a separate native V1
namespace. Adds are atomic and never replace an existing wallet. Backup parsing
is bounded, validates an exact schema and rejects legacy formats. The browser
authenticates network/account against the decrypted payload before importing a
backup. A seed vault export is not a native payment-journal backup; native tools
must retain existing payment journals and their reservations.

## Receiving interfaces

Canonical native receiving data remains 1,232 bytes: 48 bytes of canonical owner
fields and an independently validated 1,184-byte ML-KEM-768 public key. The public
version-1 descriptor keeps exactly `version`, `network`, `account`, `address_hex`.
No recovery phrase, private key, device password or view secret is exported to
the miner.

The proposed text encodings are interfaces above consensus. They use lowercase
RFC 4648 base32 without padding. The full form has prefix `sivf1` and a payload
containing version byte 1, network ID (32), and recipient bytes (1,232). The short
form has prefix `sivs1` and payload version byte 1 plus a 32-byte directory
commitment. The short string has 71 characters; the full string has 2,042.

Both forms append an eight-byte BLAKE3 checksum before base32 encoding. Its
derive-key domain is `siworld native recipient text checksum v1`, followed by
prefix, expected network and payload. The directory commitment uses domain
`siworld native recipient directory v1`, followed by network and recipient bytes.
Parsers reject noncanonical trailing bits, mixed/uppercase text, wrong networks,
bad checksums, noncanonical owner fields and invalid encapsulation keys.

A short address cannot reconstruct an ML-KEM public key. It must resolve through
a matching full-address contact record; the recipient commitment is recomputed
locally. Unresolved or substituted entries fail explicitly. No registry is
contacted or published automatically. The current implementation imports bounded
public contact files locally; it does not provide a public address directory.
These proposed text forms must not be described as deployed miner interfaces
until the native tools have adopted the same parser. The existing public JSON
descriptor is the interoperability route in the meantime.

## Chain and payment integration boundary

Receiving-key creation does not authenticate a balance, receipt, chain tip or
payment. The UI displays an unavailable balance and disables sending. It makes
no HTTP/RPC calls, embeds its WASM locally and prohibits network connections in
CSP. There is no remote seed, password or private-key API.

A subsequent integration requires a reviewed public native chain-data service,
a client verifier pinned to native network/configuration/profile identity, local
ciphertext scanning and commitment reconstruction, inclusion witnesses and a
portable native proof worker. A transaction submitter may receive only the
already-proved public envelope and required public sidecar. It must preserve
durable local reservations before proving and retain identical packets across
ambiguous submission results. Successful HTTP delivery is not acceptance.

Candidate public interfaces are bounded, anonymous block-range retrieval and
proved-envelope submission. They must not accept wallet keys, phrases,
passwords, nullifier/time associations, fee-tier telemetry or per-block real
transaction counts. Reorganizations require local rollback and replay of wallet
state, and remote responses remain untrusted until locally verified. A private
loopback wallet server that owns host wallet files must never be exposed as this
public service. Deployment and gateway operation require separate review.
