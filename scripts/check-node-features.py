"""Reject test-only capabilities in the default node's normal build graph."""

import re
import subprocess
import sys
from pathlib import Path


FORBIDDEN = {
    "siworld-crypto": {"insecure-deterministic"},
    "siworld-state": {"test-utils"},
    "siworld-consensus": {"test-utils"},
    "siworld-node": {"development"},
    "siworld-bench-plonky3": {"experimental-fanin", "phase-profile", "security-report", "d8-geometry"},
}


def forbidden_features(graph):
    enabled = {}
    for package, features in re.findall(r"^(\S+) .* features=\[([^]]*)\]", graph, re.M):
        enabled.setdefault(package, set()).update(features.split(","))
    missing = FORBIDDEN.keys() - enabled.keys()
    if missing:
        raise ValueError(f"Build graph is missing expected packages: {sorted(missing)}")
    return sorted(
        f"{package}: {feature}"
        for package, forbidden in FORBIDDEN.items()
        for feature in enabled[package] & forbidden
    )


def main():
    repository = Path(__file__).resolve().parents[1]
    graph = subprocess.run(
        [
            "cargo", "tree", "-p", "siworld-node", "--locked",
            "--edges", "normal,build", "--prefix", "none",
            "--format", "{p} features=[{f}]",
        ],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    violations = forbidden_features(graph)
    if violations:
        print("Default node enables development capabilities:", file=sys.stderr)
        print("\n".join(violations), file=sys.stderr)
        return 1
    print("Default node normal/build dependencies exclude development features.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
