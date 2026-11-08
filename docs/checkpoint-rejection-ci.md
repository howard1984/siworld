# Offline checkpoint acceptance build artifact

The `Offline checkpoint rejection acceptance` workflow validates the explicit
`checkpoint-rejection-acceptance` feature and builds one standalone Linux
acceptance executable. It does not build or publish the normal node package,
deploy a service, access signing material or run acceptance against node data.

Path-filtered branch pushes run the job. The job unconditionally skips
same-repository pull-request events and pushes to `main`; it does not query
whether a corresponding branch-push run exists or succeeded. Before reusing a
result or merging, the operator must independently observe a successful
branch-push job and its artifact for the exact source commit. Missing, failed,
cancelled or skipped jobs provide no validation. A changed source commit
requires its own successful job and artifact. Fork pull requests run with
read-only permissions and no persisted checkout credentials. Explicit workflow
dispatch is also available. Each executing job has a finite 90-minute timeout
and runs the four focused harness tests once.

The build uses Rust 1.99.1, the `x86_64-unknown-linux-gnu` target and the repository
`x86-64-v3` compilation policy. The enabled feature set is `native-p2p`,
`wallet-light-gateway` and `checkpoint-rejection-acceptance`, with default features
retained. Compilation and artifact inspection do not establish live fixture
acceptance or a historical proof audit.

The downloadable artifact contains a `tar.gz` package and an outer archive
`SHA256SUMS`. The archive preserves executable permissions and contains:

- `bin/siworld-checkpoint-rejection-acceptance`: a small shell launcher.
- `bin/checkpoint-cpu-check`: the existing native runtime CPU guard compiled for
  baseline `x86-64`; it checks complete `x86-64-v3` CPU and operating-system state
  before the launcher can execute the optimized worker.
- `libexec/siworld-checkpoint-rejection-acceptance`: the standalone optimized
  acceptance worker.
- `build-receipt.json`: exact source commit, source-file hashes, features,
  target, compiler, ISA inspection, executable hashes and CI run identity.
- `cpu-admission.json`: the build runner's baseline CPU qualification result.
- `focused-tests.json`: observed counts and duration for the four harness tests.
- `SHA256SUMS`: hashes of every other packaged file.

The launcher only delegates the supplied arguments after CPU admission. It
does not select a data directory, register a fixture or start a node. The caller
must verify the complete artifact and source/CI bindings, then admit the exact
stopped disposable fixture according to
[the acceptance procedure](checkpoint-rejection-acceptance.md). The workflow's
synthetic-chain harness evidence remains separate from that later real native
fixture execution.
