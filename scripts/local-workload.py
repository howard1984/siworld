#!/usr/bin/env python3
"""Explicit owner-machine entry point for workloads excluded from hosted CI."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
TASKS = {
    'runtime-package': ['python3', 'scripts/build-native-runtime.py'],
    'windows-package': ['python3', 'scripts/build-windows-miner.py'],
    'proof-package': ['python3', 'scripts/build-prover-release.py'],
    'd8-build': ['python3', 'scripts/build-d8-checkpoint.py'],
    'intra-proof-build': ['python3', 'scripts/build-composition-intra.py'],
    'transaction-qualification': ['python3', 'scripts/qualify-native-transaction.py'],
    'settlement-qualification': ['python3', 'scripts/qualify-native-settlement.py'],
    'full-load': ['python3', 'scripts/measure-settlement-full-load.py'],
    'hardware-admission': ['python3', 'scripts/minimum-hardware.py'],
    'checkpoint-rejection-build': ['cargo', 'build', '--release', '--locked', '--offline',
        '--manifest-path', 'crates/native-node/Cargo.toml', '--features',
        'native-p2p,wallet-light-gateway,checkpoint-rejection-acceptance',
        '--bin', 'siworld-checkpoint-rejection-acceptance'],
    'wallet-roundtrip': ['cargo', 'test', '--release', '--locked', '--offline',
        '--manifest-path', 'crates/native-node/Cargo.toml', '--features',
        'native-p2p,wallet-light-gateway', '--test', 'native_wallet_roundtrip', '--', '--ignored'],
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('task', choices=TASKS)
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--record', type=Path, required=True)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--timeout', type=int, default=3600)
    args, extra = parser.parse_known_args()
    if any(os.environ.get(k) for k in ('CI', 'GITHUB_ACTIONS', 'RUNNER_ENVIRONMENT', 'GITHUB_RUN_ID')):
        parser.error('Owner-machine workloads are forbidden in CI and runner environments')
    if not re.fullmatch('[0-9a-f]{40}', args.expected_commit) or not 1 <= args.timeout <= 14400:
        parser.error('Require a full commit and a bounded timeout')
    def git(*values):
        return subprocess.check_output(['git', '-c', 'protocol.allow=never', *values],
                                       cwd=ROOT, text=True).strip()
    if git('rev-parse', 'HEAD') != args.expected_commit or git('status', '--porcelain'):
        parser.error('Require an exact clean source commit')
    command = [*TASKS[args.task], *(extra[1:] if extra[:1] == ['--'] else extra)]
    if not args.execute:
        print(json.dumps({'task': args.task, 'commit': args.expected_commit, 'executed': False}))
        return
    if args.record.exists() or ROOT in args.record.resolve().parents:
        parser.error('Use a new evidence path outside the source repository')
    started = time.monotonic()
    result = subprocess.run(command, cwd=ROOT, timeout=args.timeout, check=False)
    # Raw terminal output is not copied into publishable evidence.
    value = {'schema': 1, 'task': args.task, 'source_commit': args.expected_commit,
             'exit_code': result.returncode, 'elapsed_seconds': round(time.monotonic()-started, 3),
             'entrypoint_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
             'ci': False, 'raw_output_exported': False}
    args.record.parent.mkdir(parents=True, exist_ok=True)
    with args.record.open('x') as stream:
        json.dump(value, stream, indent=2); stream.write('\n')
    raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()
