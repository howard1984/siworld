# Offline validation and local workloads

GitHub Actions is restricted to compilation, bounded offline unit tests, wallet and WASM tests, and proof-system checks. It does not perform miner hardware admission, mining, proof-of-work stress, miner packaging or execution, or real-network operations.

`ci-fetch.sh` acquires locked dependencies before validation. Generated native graphs use pinned source preparation and retain registry-pin checks. Every validation command and child runs without hosting credentials inside a Linux network namespace containing only loopback and no route. Missing isolation fails closed. Cargo runs offline during validation. Synthetic local networking remains possible for unit tests.

`ci-test.py` compiles test executables, enumerates selected cases and enforces a five-second deadline for proof-of-work rule cases, with a longer bound for proof-system tests. Tests excluded by the normal harness remain excluded. Consensus fixtures use minimum work parameters; explicit nonce searches are bounded. Production difficulty and validation rules are unchanged.

Heavy engineering and miner tasks run only on owner-controlled machines through `scripts/local-workload.py`. Select a task, exact clean source commit, a new evidence file outside the checkout and a timeout; the default is dry-run. `--execute` runs the selected existing local implementation. CI and runner contexts are rejected. Individual tools retain their own platform, resource, input and safety requirements. Build-machine and source/hash plans require approval before deployment. No script publishes a release or updates a node automatically.

Retired workflow files under `scripts/tests/fixtures/retired-workflows` are inert historical contract fixtures, not execution entries. They are never scheduled or sourced by Actions. Three byte-identical historical files are temporarily exposed at the paths embedded in immutable measurement records during validation, then removed. This permits the original hash checks without changing the measured proof sources or scheduling retired jobs. Keep their former hosted assumptions separate from current local build evidence.

Attach only inspected, sanitized text results to reviews. Keep node endpoints, keys, wallets, runtime stores and raw operational logs outside version control. A successful build does not establish live acceptance or Windows hardware compatibility.
