# Portable native V1 wallet core

Client-side wallet identity, canonical recipient validation, native mnemonic
recovery and SWNVLT01 encrypted seed custody. The field hash is compiled directly
from the frozen native multi-asset source. No proof source or parameter changes.

The `native-parity` feature enables integration tests against the existing native
wallet. It is excluded from browser builds. The web wrapper is a separate crate.

See [the browser wallet specification](../../docs/v1-browser-wallet.md).
