# Checkpoint rejection acceptance build

The standalone rejection executable is built on an approved owner-controlled Linux x86_64 machine. It is excluded from GitHub Actions. Offline compilation and synthetic harness tests do not establish real fixture acceptance.

Use the repository-pinned toolchain and locked dependencies with target `x86_64-unknown-linux-gnu`. Enable `native-p2p`, `wallet-light-gateway` and `checkpoint-rejection-acceptance`. Retain default features and the repository `x86-64-v3` policy. `scripts/local-workload.py checkpoint-rejection-build` provides a dry-run by default and requires an exact clean source commit before execution.

Record the exact source commit, tracked-source SHA-256 values, compiler, target, features, inspected ISA and executable hashes. Keep the baseline CPU guard separate from the optimized worker. A package must contain a guarded launcher, the optimized executable, build provenance and SHA256SUMS. Owner-controlled builds must identify their actual build method rather than claim an Actions run. Approval of the build-machine/source/hash plan precedes deployment.

Before use, verify package contents and source bindings and admit only the exact stopped disposable fixture according to [the acceptance procedure](checkpoint-rejection-acceptance.md). The executable must preserve the fixture and canonical state across rejected input cases. Keep actual native results separate from synthetic harness evidence and from live P2P injection. No build step starts a node, registers a fixture or changes a production service.
