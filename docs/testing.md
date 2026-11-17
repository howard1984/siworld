# Validation and Regression Coverage

The [monetary relations](v1-economics.md) use revision
`native-v1-economics-1`. Fresh actual-AIR reports and 39 qualified-reference
trials cover the economic proof profiles. Reproducing their public keys and
passing complete CI remain release checks. Historical profiles and earlier
service observations do not qualify changed economic relations.

## Proof and runtime boundaries

The root workspace tests the legacy recursive runtime. Native V1 transaction,
issuance and settlement relations execute in `crates/bench-multi-asset`; its
proof/profile checks are separate from complete native node/network acceptance.
The earlier `bench-d8` two-output freeze remains an unchanged baseline. No
passed proof-only job establishes native block propagation, retained-history
pruning, checkpoint bootstrap, standalone verifier budgets or public-testnet
operation. See [testnet acceptance](prover-acceptance.md).

## Required checks

```sh
python3 scripts/check-repository.py
python3 scripts/check-node-features.py
python3 scripts/check-native-proof-profiles.py --check crates/bench-multi-asset/artifacts/v1-native-proof-profiles.json
cargo test --release --locked --manifest-path crates/bench-multi-asset/Cargo.toml --features security-report --lib
cargo fmt --all --check
cargo fmt --manifest-path crates/bench-stark/Cargo.toml --all --check
cargo check --locked -p siworld-node --bins
cargo test --locked -p siworld-node --bin siworld-node
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo test --release --locked --manifest-path crates/bench-stark/Cargo.toml \
  -p siworld-bench-plonky3 -p siworld-bench-common
```

All-features tests intentionally enable development helpers. Release artifacts use default features. The feature check excludes deterministic crypto, state and consensus test helpers from the default normal/build graph.

Tests that start the continuous miner service are ignored by default with the
reason `owner-local only: spawns miner`. Run the complete root suite, including
these tests, only on an owner-controlled machine:

```sh
cargo test --workspace --all-features --locked -- --include-ignored
```

Do not run this command on GitHub computing resources. `Miner::spawn` refuses
startup with a permission error when `GITHUB_ACTIONS=true`; the offline CI
isolation preserves that flag. The refusal test uses a child process without
changing the environment shared by concurrent tests.

Single-block fixtures remain eligible for offline CI. The consensus
`test-utils` feature and native test fixtures limit searches to 65,536 nonces
and two seconds, with at most 1,000 hash iterations per nonce. Exhausting a
bound fails the fixture. These limits do not change production block validity
or the default production search. Continuous node and miner acceptance,
propagation measurements and endurance runs remain owner-operated tests.

## Coverage

| Area | Location |
|---|---|
| Native multi-asset conservation, issuance signatures and SIP-reward settlement | `crates/bench-multi-asset/src` and its native proof tests |
| Every-input validation, nullifiers and atomic rollback (legacy runtime) | `crates/consensus/tests/counterexamples.rs` |
| Canonical encodings | `crates/consensus/tests/encoding.rs` |
| Producer/validator agreement | `producer_seed.rs`, `state_delta.rs` in consensus tests |
| Statement binding and miner notes | `container_statement.rs`, `miner_package.rs`, `crates/prover/tests` |
| Native monetary allocation, pool/burn, independent fund vesting/spending and 20-year conservation simulation | `crates/core/src/v1_economics_tests.rs`; native state/audit tests |
| Snapshot-height locks, canonical limbs and reduced-width asset matches | `multi_asset_transaction.rs` in the multi-asset proof workspace |
| Available/locked wallet tranches, private delay and small-SIP consolidation | Native wallet tests; complete durable M2 integration remains separate |
| Legacy integer issuance and fund accounting | `issuance.rs`, `payouts.rs` in consensus tests |
| Difficulty and fork choice | `pow.rs`, `fork_choice.rs`, `main_chain.rs` in consensus tests |
| Native/circuit equivalence | `crates/poseidon2`, `crates/bench-stark/common`, `crates/bench-stark/plonky3` |
| Peers, payments and RPC | `crates/node/tests/network.rs`, `payments.rs`, `rpc.rs` |
| Custody and durable recovery | `keystore.rs`, `backup.rs`, `orders.rs`, `retention.rs` in node tests |
| Fund approvals, budgets and recovery | `fund_security.rs`, `fund_payments.rs`, `fund_backup.rs` in node tests |

## Counterexamples

Preserve regressions for invalid later inputs, repeated nullifiers and authorization reuse where applicable, malformed encodings, incorrect roots/rewards and partial mutation after failure. Write the failing consensus test before implementation.

Proof changes require valid and tampered witnesses, native/circuit consistency, root-input mutations, overflow rejection and key compatibility checks. Regenerating a key does not authorize silently replacing a pinned key.

Tests establish behavior only for their configurations and fixtures. They do not establish cryptographic soundness, anonymity or production readiness. Performance claims need the [benchmark procedure](benchmarks.md).
