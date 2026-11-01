# Offline Development-Fund Key Custody

Status: local Unix tool and operating procedure pending independent review.
This is a key-custody procedure, not network activation or an approval of a
specific recipient allocation. Engineering genesis uses separate disposable
test keys; it does not wait for real holder keys. A main-network registry
requires the real public submissions and exact shares before activation.
The current filesystem checks enforce Unix owner/mode/link constraints but do
not yet reject macOS extended ACL entries. Do not use the tool for production
custody on macOS until ACL inspection is implemented and tested; Linux
production use remains subject to the same independent custody review.

## Trust boundary

Main-network fund keys must be generated on a dedicated, disconnected Linux
device. macOS support is limited to engineering tests until extended ACL
rejection is implemented and tested; it does not qualify for main-network
key generation.

Each holder generates one ML-DSA-65 key on their own trusted offline device.
The private seed and expanded signing key remain on that device; the tool has
no plaintext private export. Transfer only the public submission JSON and its
fingerprint. Do not upload a custody directory, encrypted vault, passphrase,
recovery shares, private screenshot or diagnostic memory dump to the project,
an online signing service, a code repository or a support channel.

Encrypted backup media remain under the holder's offline custody. Other team
members do not generate a holder's production key. Sharing a project operator's
test key, node identity or wallet seed is not a substitute for holder custody.
The public registry fixes each key and share at genesis and provides no V1 key
replacement. Loss of all authenticated backups or their unlock secret can
permanently remove the ability to authorize that wallet's claims.

## Build and verify before disconnecting

The isolated source is [the fund-keytool crate](../crates/fund-keytool/README.md).
It has no native-node/prover dependency or runtime network connection. Build
with the pinned toolchain and committed lockfile on a separate preparation
machine, and run its full test suite. Review the exact source revision and
third-party dependency graph. Hashes verify byte identity; obtain the expected
source/binary hashes over an independently authenticated release channel.
A hash copied beside an untrusted binary does not authenticate it.

```sh
cargo test --release --locked --manifest-path crates/fund-keytool/Cargo.toml
cargo build --release --locked --manifest-path crates/fund-keytool/Cargo.toml
sha256sum crates/fund-keytool/target/release/siworld-fund-keytool
```

For an offline rebuild, prepare a Cargo vendor directory and its source
replacement configuration on the preparation machine using the committed
lockfile. Transfer the inspected source, lockfile, toolchain and vendored
dependencies to the offline device. Then use:

```sh
cargo build --release --locked --offline --manifest-path crates/fund-keytool/Cargo.toml
```

Verify the transferred files against the authenticated manifest. Build output
may depend on the toolchain and target; byte-for-byte reproducibility is a
separate qualification. The tool supports Unix protected filesystems, including
Linux and macOS, and rejects unsupported platforms. Use `shasum -a 256` when
`sha256sum` is unavailable. Never enable networking on the custody device to
fetch a missing dependency after key creation.

## Generate and submit a public key

Use a dedicated offline session without remote desktop, screen recording,
clipboard synchronization or cloud folder backup. Disable core dumps and
unencrypted swap/hibernation before handling secrets. Full-disk encryption
protects powered-off storage but does not replace the encrypted vault or a
clean operating system. A compromised process running as the same user is
outside the filesystem and memory-erasure guarantees.

Use an existing physical parent path with no symlink components. The tool
creates the final custody directory itself; it must not already exist. Do not
precreate it. All custody files require owner-only permissions. Filesystems
must support Unix ownership, advisory locks, hard links and durable file and
directory sync; a failing sync is an error rather than successful custody.

Run the binary from the verified location, using a new directory name:

```sh
umask 077
ulimit -c 0
./siworld-fund-keytool generate fund-key > public-submission.json
./siworld-fund-keytool verify fund-key > verified-public.json
./siworld-fund-keytool check-public public-submission.json
cmp public-submission.json verified-public.json
```

Creation prompts twice through hidden terminal input. Use a high-entropy
passphrase kept separately from the vault; the enforced 16-byte minimum is
not a strength measurement. Passphrases are never command arguments,
environment variables, scripts or files. Do not paste them through shared
clipboard history. Each generation draws a fresh 32-byte seed from operating
system randomness and derives an ML-DSA-65 key using pinned libcrux code.

`verify` authenticates the encrypted seed and signs/verifies a fresh random
challenge locally. Its signature and challenge are not exported. `public`
also requires the vault passphrase and authenticates the stored public record
against the regenerated key before output:

```sh
./siworld-fund-keytool public fund-key > public-submission.json
```

Send only `public-submission.json`. Check its fingerprint independently, for
example by comparing a printed fingerprint with the coordinator through a
second authenticated channel. `check-public` checks format and fingerprint;
it does not prove ownership, holder identity, authorization of an allocation
or possession of the corresponding private key.

## Public submission format

The tool emits exactly one compact JSON object, with these fields in this
order and one final LF. No names, addresses, device identifiers, shares,
private material or additional fields occur in this key submission:

| Field | Required value |
| --- | --- |
| `version` | Integer `1` |
| `algorithm` | String `ML-DSA-65` |
| `public_key_hex` | Exactly 3,904 lowercase ASCII hex characters encoding the raw 1,952-byte ML-DSA-65 verification key |
| `fingerprint` | Exactly 64 lowercase ASCII hex characters |

The fingerprint is `blake3::derive_key(context, raw_public_key)`, with exact
context `SIWORLD offline development fund ML-DSA-65 public key fingerprint v1`
and only the raw key bytes as key material. This is the custody-tool format;
it changes no existing consensus domain, signature context or genesis bytes.
Validation rejects a zero public key and any unknown or duplicate JSON fields.
It also rejects alternate ordering, uppercase hex, whitespace changes, a missing
final LF, a wrong algorithm or a mismatched fingerprint. Public files are bounded
to 8,192 bytes before parsing. A
coordinator can validate a transferred file without any private vault:

```sh
./siworld-fund-keytool check-public public-submission.json
```

## Encrypted backups and recovery exercise

Keep at least two encrypted backups on separate offline media with physical
access controls and independent failure domains. Do not hard-link or copy a
live custody folder through an untrusted online backup agent. The supported
backup command holds source custody exclusively, authenticates the original,
creates a new destination, and freshly reencrypts the same seed with new salt
and nonce. It reads the persisted result back and compares the complete public
identity before reporting success. It never overwrites an existing folder.

```sh
./siworld-fund-keytool backup fund-key /media/offline-backup/fund-key > backup-public.json
./siworld-fund-keytool verify /media/offline-backup/fund-key > recovered-public.json
cmp public-submission.json backup-public.json
cmp public-submission.json recovered-public.json
```

The source password and a confirmed backup password are entered in separate
hidden prompts. Remember which unlock secret protects each media copy; a new
backup password changes encryption only, not the public key. The test proves
local decryption and signing after reopening, not long-term media durability.
Repeat the recovery exercise on a clean offline device before discarding any
other copy, periodically thereafter, and after replacing backup media. Verify
the same public fingerprint and retain the verified public submission outside
the secret custody directory.

The custody directory contains `seed.vault`, `public.json` and the stable
`.fund-key.lock`. Never delete a live lock file, relax permissions to bypass an
error or generate a replacement key after an authentication failure. A crash
between write-once records may leave an incomplete new directory; the tool
fails closed and does not repair or overwrite it. Preserve it, check another
authenticated backup, and use a separate new destination for any recovery.
Lost passwords cannot be reset. Suspected corruption or compromise requires a
separate incident procedure; V1 has no silent key substitution mechanism.

## Shamir backup recommendation

Shamir backup does not change consensus authorization: a fund wallet still has
one ML-DSA-65 key. This tool does not implement Shamir, SLIP39, share import,
seed export, threshold signatures or a seed-to-share bridge. Do not claim that
its backups alone are 2-of-3 recovery, and do not split arbitrary files or
mnemonic strings with a homegrown polynomial script.

For threshold custody, select an independently reviewed offline SLIP39
implementation and document an exact recovery ceremony before use. One design
that avoids exporting this tool's private seed splits a separate random
256-bit backup-unlock secret 2-of-3. Its documented canonical representation
is used as the encrypted vault passphrase; recovering two shares recovers
only that unlock secret. Recovery also requires an intact encrypted vault,
the representation instructions and the verified public fingerprint. This
external workflow is not implemented or qualified by this tool, and must be
independently reviewed and tested with disposable keys before real custody.

Create, verify and reconstruct shares only on the holder's trusted offline
device with the selected implementation. Keep shares under separately named
physical custodians or locations; never submit them with public keys or use
an online share generator. The written private ceremony identifies who holds
each share, the recovery device and location, approval to recover, and how
temporary copies are handled. After recovery, close tools, erase owned secret
buffers where supported, remove temporary files, and power off the offline
device. Ordinary file deletion does not prove erasure on SSDs or remove prior
snapshots; avoid creating plaintext temporary exports in the first place.

## Review scope

Review OS entropy, libcrux seed semantics and owned signing-key erasure;
Argon2id parameters and XChaCha20-Poly1305 format/authentication; interactive
secret input and public-only output; descriptor anchoring, symlink/hard-link
rejection, ownership, permissions, exclusive locks, no-overwrite publication,
crash/durability failures and backup readback; canonical public submissions;
and the separate external threshold-custody ceremony. Main-network use remains
conditional on that review and an owner-performed recovery exercise.
