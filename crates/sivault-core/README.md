# SIVault offline standard format

`standard::Safe` provides a provisional folder-safe API for creation, explicit
file import/export, directory metadata, removal and read-only opening. Files
remain encrypted in opaque, immutable objects; decrypted contents are written
only to an explicitly selected export destination. The desktop shell owns the
session and drops its keys when locked.

```sh
cargo test --locked --offline --manifest-path crates/sivault-core/Cargo.toml
cargo clippy --locked --offline --manifest-path crates/sivault-core/Cargo.toml --all-targets -- -D warnings
```

Passwords use the [RFC 8265 OpaqueString profile](https://www.rfc-editor.org/rfc/rfc8265.html#section-4.2),
including NFC and non-ASCII space mapping, without case folding. Normalized
UTF-8 is bounded to 1-1,024 bytes. Version 1 fixes Argon2id v19 to 64 MiB,
three iterations, one lane and a 32-byte output; parameter changes require a
new format version. A random content key is wrapped with XChaCha20-Poly1305.
HKDF-SHA-256 labels separate wrap, index, commit and per-revision payload keys.

Each physical piece contains at most 1 GiB of plaintext, split into 64 KiB
chunks. RustCrypto's [STREAM BE32](https://docs.rs/aead/0.5.2/aead/stream/struct.StreamBE32.html)
implementation supplies chunk counters and final flags; each piece begins
with a fresh 19-byte random nonce prefix. The exact chunk ciphertext is the
plaintext length plus a 16-byte tag, including a full-size final chunk.
Piece associated data binds safe, entry, revision, piece index/count, total
file length and piece length. A piece stores `19 + length + 16*ceil(length/65536)`
bytes. Empty files have no pieces and their length is authenticated by the
index. This candidate is incompatible with the earlier unimplemented
single-tag-per-piece draft.

The binary index and 224-byte generation record use explicit little-endian
lengths and authenticated references. Version/flags, names, parent graphs,
duplicates, bounds, object lengths, tags and trailing bytes are checked.
Maximum index plaintext is 128 MiB, entries 100,000, directory depth 127, and
generation 2^32-1. Untrusted file opens reject links and nonregular objects;
Unix safe records use directory-relative handles with `O_NOFOLLOW`.

Independent synthetic KATs are in [vectors](vectors/README.md).
Known limitations and filesystem acceptance gaps are documented in the
[security model](../../docs/sivault-security-model.md). Existing source files
must remain stable during import. Cooperating clients use OS file locks;
this is not a boundary against a malicious local process with write access.

## Fixed-size development format

The desktop development build can create a fixed-size safe with one 1 GiB
random-filled segment and an optional decoy password. The primary slot is
chosen at random. Only its encrypted wrap carries write authority. Explicit
read-only opening and decoy opening both use a read-only segment handle and
do not publish metadata or create sidecars. Only the writable primary view
can add or replace decoy files. The development UI supports root files only.

Any claim about indistinguishability is limited to a single captured image
without additional secrets or external traces. This format does not hide
timing, OS logs, memory, or changes across multiple images. Physical
power-loss and removable-media validation remain distribution requirements.
