# Native Proof Profile Reproduction

Status: engineering-frozen native proof parameters for relation revision
`native-v1-economics-1`. Schema-two artifacts bind the revised snapshot-height
input locks and reward relations to measured sources, actual-AIR reports and
public preprocessing keys. The transaction scan contains 24 four-worker grid
trials, three selected one-worker transaction trials and 12 settlement/issuance
trials split across one/four-worker processes: 39 trials in total. Engineering
freeze is separate from release validation, cryptographic approval, native
node/network activation and integrated resource acceptance.

## Fixed relation scope

| Relation | Fixed shape | FRI profile | Proof-body admission requirement |
| --- | --- | --- | ---: |
| Transaction | Two inputs, three outputs; per-asset balance, SIP-only fees and snapshot-height input locks | Blowup 7, 41 queries | 655,360 bytes |
| Fee settlement | 576 ordered positions; SIP reward asset and one/five mode-dependent reward notes | Blowup 8, 36 queries | 655,360 bytes |
| Asset issuance | Three initial unlocked notes; fixed public supply | Blowup 8, 36 queries | 524,288 bytes |

All use KoalaBear D8, Poseidon2 W24, twelve-element digests, query and opening-
batch grinding of 20 bits, zero commitment grinding, binary folding and final
polynomial log length zero. The issuance shape does not adopt a protocol limit
of three notes: metadata, note-count and per-block issuance policy still require
explicit decisions before integration. Other settlement capacities require their
own preprocessing identities; this manifest freezes the maximum-capacity shape.

Runtime envelope policy version 1 is checked independently by
[`check-native-envelope-policy.py`](../scripts/check-native-envelope-policy.py).
The source-bound measurement profiles retain their historical 524,288-byte
settlement admission value and their original hashes. The active native wire
and bounded decoder accept settlement proof bodies up to 655,360 bytes; this
admission change does not change the measured AIR, preprocessing keys or
8/36/20 FRI configuration. Full-capacity qualification must separately measure
three fresh proofs with maximum fees and fund claims, with every observed body
at most 589,824 bytes, before claiming ten-percent headroom. The policy check
does not establish that measurement gate or resource acceptance.

The [relation manifest](../crates/bench-multi-asset/artifacts/v1-native-proof-profiles.json)
records deterministic public preprocessing keys, actual-AIR security reports,
parameters and fixed capacities. It binds the current
[transaction profile](../crates/bench-multi-asset/artifacts/v1-transaction-profile.json),
which pins native source files, dependency identities, the measured transaction
selection and repeated one/four-worker measurements for all three relations.
Each new key uses the offline `SWMP-v1` encoding:
`magic[4]`, little-endian version `u16`, relation kind `u8`, capacity `u32`, six
FRI parameter `u32` values, preprocessing width `u32`, degree bits `u32`,
commitment byte length `u32`, and the canonical dependency-encoded commitment.
Kind identifiers are transaction 1, settlement 2 and issuance 3. Capacity zero
identifies the fixed transaction shape. This encoding is an artifact identity;
it does not register a consensus envelope or permit peer-supplied keys.

The security reports pass the selected instance-specific accounting model.
External review must assess the implementation, hiding, application hashes and
protocol composition. The measured transaction shape has 256 base rows,
1,392 main columns, 247 preprocessed columns and 101 public values. Its selected
quantum Johnson ledger is 81.692 bits. The hosted process-tree measurements do
not establish standalone-verifier memory, full-block or sustained-load
qualification.

## Reproduce the public keys

Use the pinned Rust toolchain and Python 3.11 or newer. The reproduction tool
reads the selected parameters from the transaction profile at compile time.
Rebuild it after changing or restoring that profile; an executable compiled with
an earlier profile does not reproduce a later freeze. The commands below
target Linux x86_64, where the repository release baseline requires AVX2 and
operating-system AVX state support. Compile the CPU admission checker directly
with the generic x86-64 baseline, independently of Cargo target flags. It must
succeed before running any optimized executable; unsupported hardware or AVX
state support is rejected with exit status 78.
These commands prepare an isolated manifest with paths to unchanged native
sources; they do not modify the dependency checkout or generate transaction
proofs. Use a new local output directory for each reproduction:

```sh
set -eu
mkdir -p .local/native-profiles
rustc scripts/prover-launcher.rs --edition=2021 -O -D warnings \
  -C target-cpu=x86-64 -o .local/native-profiles/cpu-check
.local/native-profiles/cpu-check --check-cpu
python3 scripts/check-native-proof-profiles.py \
  --check crates/bench-multi-asset/artifacts/v1-native-proof-profiles.json
python3 scripts/check-native-proof-profiles.py \
  --prepare .local/native-profiles/application
cargo build --release --locked \
  --manifest-path .local/native-profiles/application/Cargo.toml \
  --features security-report --bin native-proof-artifacts
mkdir -p .local/native-profiles/reproduced
RAYON_NUM_THREADS=4 SIWORLD_COMPOSITION_HIDING_WORKERS=2 \
  .local/native-profiles/application/target/release/native-proof-artifacts \
  transaction .local/native-profiles/reproduced/transaction.json
RAYON_NUM_THREADS=4 SIWORLD_COMPOSITION_HIDING_WORKERS=2 \
  .local/native-profiles/application/target/release/native-proof-artifacts \
  settlement .local/native-profiles/reproduced/settlement.json
RAYON_NUM_THREADS=4 SIWORLD_COMPOSITION_HIDING_WORKERS=2 \
  .local/native-profiles/application/target/release/native-proof-artifacts \
  issuance .local/native-profiles/reproduced/issuance.json
python3 scripts/check-native-proof-profiles.py \
  --check crates/bench-multi-asset/artifacts/v1-native-proof-profiles.json \
  --reproduced .local/native-profiles/reproduced
```

Do not substitute downloaded or peer-provided keys. `--check` alone validates
the recorded manifest and source binding; `--reproduced` additionally compares
the regenerated keys and complete security reports. The transaction commitment
must also match the current frozen transaction key. Public preprocessing is
performed serially to avoid unnecessary concurrent memory pressure.

## Generate and verify synthetic proofs

The original `.github/workflows/v1-economics.yml` is an immutable input to the
historical source-bound measurement and is disabled in this repository.
`.github/workflows/v1-economic-regressions.yml` retains the economic tests,
actual-AIR screening and public-key reproduction. Its full parameter grid is
disabled by default and requires explicit manual dispatch with
`measure_wallet_grid` enabled. Routine PR validation must not start a new grid
or rewrite the frozen profile.

The isolated `native-scan` executable generates a fresh synthetic proof, verifies
it locally, and writes a technical result file. It does not export a reusable
proof package or provide a wallet/peer verification API. To exercise each fixed
profile deliberately, build the existing native crate and use separate new
output files:

```sh
set -eu
mkdir -p .local/native-profiles
rustc scripts/prover-launcher.rs --edition=2021 -O -D warnings \
  -C target-cpu=x86-64 -o .local/native-profiles/cpu-check
.local/native-profiles/cpu-check --check-cpu
cargo build --release --locked --manifest-path crates/bench-multi-asset/Cargo.toml \
  --features security-report --bin native-scan
RAYON_NUM_THREADS=4 SIWORLD_COMPOSITION_HIDING_WORKERS=2 \
  crates/bench-multi-asset/target/release/native-scan \
  transaction 7 41 20 4 .local/transaction-roundtrip.json
RAYON_NUM_THREADS=4 SIWORLD_COMPOSITION_HIDING_WORKERS=2 \
  crates/bench-multi-asset/target/release/native-scan \
  settlement 8 36 20 4 .local/settlement-roundtrip.json
RAYON_NUM_THREADS=4 SIWORLD_COMPOSITION_HIDING_WORKERS=2 \
  crates/bench-multi-asset/target/release/native-scan \
  issuance 8 36 20 4 .local/issuance-roundtrip.json
```

A successful result requires `verified: true`. The issuance diagnostic checks
ML-DSA-65 and the proof, but its SIP issuance-fee callback is a synthetic fixture;
it does not consume an actual on-chain fee payment. Production issuance must
use `IssuanceProver::verify_signed` with authenticated network/policy context and
atomic exactly-once SIP-payment consumption. Transactions require a verifier-
selected canonical snapshot and reconstructed public statement. Settlement
requires the ordered transaction/fee list and an authenticated consensus reward
plan, including mode, allocation amounts and unlock heights. The node derives
that plan from the canonical parent state, subsidy schedule and height; a
peer-supplied plan is not authoritative. Network and transaction-list identities
are also bound to the candidate block. The standalone diagnostics supply none of the durable
node state transitions, compact relay or wallet recovery required for launch.

## Ordering and integration boundary

The retained recursive node sorts legacy proof-free slot IDs and rejects any
non-strict adjacent pair, including duplicate IDs. Its old slot encoding is not
the new three-output transaction statement. The isolated native codec and transition implement strict block ordering:
compute the specified domain-separated BLAKE3
statement identity, excluding proof randomness, proof length and sidecar; sort
strictly; reject duplicate IDs and unsorted blocks before expensive proof work.
The shared producer/validator transition and node-level atomic rejection tests
must exercise this rule. Public-key reproduction does not qualify sustained
runtime, wallet or network integration.
