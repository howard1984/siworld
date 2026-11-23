# SIVault Releaser Vectors

`open-init.hex` is a literal, synthetic metadata-format-v1 encoding vector. Each
line contains one field in header/body order. It was written from the documented
byte layout independently of the encoder implementation. It contains no real
identifiers, public keys or credentials. The expected encoded length is 279 bytes.

Suite `0x1234` is an opaque test identifier, not a selected cryptographic suite.
The body has three 32-byte fields and an absent certificate digest, totaling 97
bytes. `tests/messages.rs` verifies literal bytes and canonical decoding, and
independently tests rejection of malformed and credential-message encodings.

This is an encoding fixture, not a published cryptographic known-answer vector.
No proof, wrapping, credential evaluation or cryptographic enforcement is tested.
