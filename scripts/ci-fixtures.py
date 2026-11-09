#!/usr/bin/env python3
"""Expose exact historical paths for frozen-source checks during one command."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    # These paths are embedded in immutable engineering measurement records.
    # They are absent from Git and cannot schedule jobs. Only source bytes are
    # inspected; no retired workflow is interpreted or executed.
    pins = {}
    for name in ('crates/bench-d8/artifacts/v1-native-freeze.json',
                 'crates/bench-multi-asset/artifacts/v1-transaction-profile.json'):
        value = json.loads((ROOT / name).read_text())
        for path, digest in value['source_sha256'].items():
            if path.startswith('.github/workflows/'):
                if path in pins and pins[path] != digest:
                    raise SystemExit('Conflicting historical source anchors')
                pins[path] = digest
    created = []
    try:
        for name, digest in pins.items():
            target = ROOT / name
            source = ROOT / 'scripts/tests/fixtures/retired-workflows' / target.name
            body = source.read_bytes()
            if hashlib.sha256(body).hexdigest() != digest:
                raise SystemExit('Historical source bytes changed')
            if target.exists() or target.is_symlink():
                raise SystemExit('Historical source path must be absent')
            with target.open('xb') as stream:
                stream.write(body)
            created.append((target, digest))
        raise SystemExit(subprocess.call(sys.argv[1:]))
    finally:
        for target, digest in created:
            if target.is_symlink() or hashlib.sha256(target.read_bytes()).hexdigest() != digest:
                raise RuntimeError('Historical check input changed; preserved for inspection')
            target.unlink()


if __name__ == '__main__':
    main()
