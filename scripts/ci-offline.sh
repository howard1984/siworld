#!/usr/bin/env bash
# Every validation command and descendant inherits a loopback-only network.
set -euo pipefail
[[ "$(uname -s)" == Linux && "$(id -u)" != 0 && "$#" == 1 ]]
for tool in sudo unshare ip setpriv; do command -v "$tool" >/dev/null; done
root="${GITHUB_WORKSPACE:?}"
real_cargo="$(command -v cargo || true)"
exec sudo -n unshare --net -- bash -c '
 set -euo pipefail
 uid="$1"; gid="$2"; task_home="$3"; task_path="$4"; root="$5"; real_cargo="$6"; script="$7"; target="$8"
 ip link set lo up
 [[ "$(ip -o link show | wc -l)" -eq 1 && -z "$(ip route show)" && -z "$(ip -6 route show default)" ]]
 target_env=(); if [[ -n "$target" ]]; then target_env+=("CARGO_TARGET_DIR=$target"); fi
 exec setpriv --reuid "$uid" --regid "$gid" --clear-groups --no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all -- \
 env -i HOME="$task_home" PATH="$root/scripts/ci-bin:$task_path" \
 CARGO_HOME="$task_home/.cargo" RUSTUP_HOME="$task_home/.rustup" \
 CARGO_NET_OFFLINE=true CARGO_TERM_COLOR=always SIWORLD_REAL_CARGO="$real_cargo" \
 "${target_env[@]}" GITHUB_WORKSPACE="$root" CI=true \
 RAYON_NUM_THREADS=4 SIWORLD_COMPOSITION_HIDING_WORKERS=2 \
 LANG=C.UTF-8 LC_ALL=C.UTF-8 python3 "$root/scripts/ci-fixtures.py" bash --noprofile --norc -eo pipefail "$script"
' offline-ci "$(id -u)" "$(id -g)" "$HOME" "$PATH" "$root" "$real_cargo" "$1" "${CARGO_TARGET_DIR:-}"
