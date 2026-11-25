#!/usr/bin/env bash
# Dependency acquisition only: never compile or execute project binaries here.
set -euo pipefail
cd "${GITHUB_WORKSPACE:?}"
job="${1:?}"
case "$job" in
 native-economic-accounting|workspace) manifest=Cargo.toml ;;
 offline-fund-keys) manifest=crates/fund-keytool/Cargo.toml ;;
 bench-plonky3) manifest=crates/bench-stark/Cargo.toml ;;
 native-multi-asset) manifest=crates/bench-multi-asset/Cargo.toml ;;
 native-runtime) manifest=crates/native-node/Cargo.toml ;;
 wallet)
  for crate in native-wallet-core native-wallet-engine native-wallet-web; do
   cargo fetch --locked --manifest-path "crates/$crate/Cargo.toml"
  done
  exit 0 ;;
 native-transaction) manifest=crates/native-proof/Cargo.toml ;;
 *) echo 'Unknown dependency graph' >&2; exit 2 ;;
esac
cargo fetch --locked --manifest-path "$manifest"
