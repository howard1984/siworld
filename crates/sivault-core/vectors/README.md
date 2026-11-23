# Independent synthetic vectors

All keys, salts, nonces and plaintext in `independent.json` are fixed public
test inputs and must never be used for a safe. `generate.py` invokes PyNaCl
1.6.2 (libsodium XChaCha20-Poly1305) and argon2-cffi 25.1.0 (reference Argon2 C).
HKDF uses Python's HMAC implementation. It does not invoke Rust code.

The fixture covers Argon2id at the format parameters, composed/decomposed NFC,
HKDF wrap derivation, authenticated content-key wrapping, a complete 64 KiB
chunk, a partial final chunk, and a full-size final chunk. Chunk ciphertext
SHA-256 and tags provide compact comparisons without storing large blobs.

To reproduce in an isolated Python environment with those packages installed:

```sh
python crates/sivault-core/vectors/generate.py > /tmp/sivault-independent.json
cmp /tmp/sivault-independent.json crates/sivault-core/vectors/independent.json
```

The fixture also contains a complete empty safe generated independently in
Python, including its wrapped content key, encrypted index, generation digest
and commit MAC. The Rust implementation opens it using the decomposed password.

Rust integration tests consume the fixture. This verifies primitive and
STREAM compatibility and one complete empty-folder encoding; it is not
evidence of power-loss durability.
