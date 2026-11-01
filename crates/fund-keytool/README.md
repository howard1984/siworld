# Offline Fund Key Tool

Status: local Unix custody implementation pending independent review. macOS
extended ACL rejection is not yet implemented; do not use this tool for
production custody on macOS until that check is added and tested. This tool
has an isolated Cargo workspace and no node, prover, wallet or network client
dependency. It does not activate a network, change fund shares or sign payouts.

Build and test from the repository root:

```sh
cargo build --release --locked --manifest-path crates/fund-keytool/Cargo.toml
cargo test --release --locked --manifest-path crates/fund-keytool/Cargo.toml
```

The binary is `crates/fund-keytool/target/release/siworld-fund-keytool` unless
the build uses a different target directory. Prepare vendored dependencies and
verify the source and binary on a separate build machine before offline use.
See the [custody procedure](../../docs/v1-offline-fund-keys.md) for the complete
offline workflow, backup exercises, public submission and Shamir limitations.

```text
generate DIRECTORY                 Create a new encrypted ML-DSA-65 seed
public DIRECTORY                   Authenticate and export only public JSON
check-public FILE                  Check canonical public JSON and fingerprint
verify DIRECTORY                   Local fresh-challenge sign/verify self-test
backup DIRECTORY BACKUP_DIRECTORY  Reencrypt the same key in a new directory
```

Passwords use hidden local-terminal prompts and creation requires confirmation.
There are no password arguments, environment options, stdin secret imports,
plaintext private exports, payout signing commands or listening sockets. Only
public JSON is written to successful stdout. Secrets never implement `Debug`,
`Display` or serialization.

The encrypted seed uses Argon2id v19 with 65,536 KiB, three passes and one lane,
and XChaCha20-Poly1305 with fresh 16-byte salt and 24-byte nonce. Authentication
binds the version, fixed KDF profile, salt, nonce and public-key fingerprint.
The seed is 32 OS-random bytes consumed by pinned `libcrux-ml-dsa=0.0.11`
ML-DSA-65 key generation. Its raw public key is exactly 1,952 bytes.

Custody paths reject symlinks at every component and parent traversal. A new
directory must not already exist. Its owner and mode must be the current user
and exactly `0700`; custody files require that owner, exactly `0600`, regular
file type and a single hard link. Every operation holds an exclusive advisory
lock. Complete records publish through no-overwrite same-directory hard links
after file sync, followed by link cleanup and directory sync. Any incomplete
or damaged record fails closed. The stable lock file must not be deleted.

Owned seed, passphrase, KDF memory and expanded signing-key buffers are erased
on drop. This does not establish erasure of dependency-internal or register
copies, recovery from an untrusted operating system, or protection against a
malicious process with the same user privileges. Independent cryptographic
and filesystem review remains required before main-network custody.
