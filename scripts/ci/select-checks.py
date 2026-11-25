"""Select offline validation jobs from changed repository paths."""
import fnmatch
import os
from pathlib import Path
import re
import subprocess
import sys

COMMON = ('Cargo.toml',
 'Cargo.lock',
 'rust-toolchain.toml',
 '.cargo/**',
 '.github/workflows/**',
 'scripts/ci/**',
 'scripts/tests/test_ci*',
 'ops/ci/**')
RULES = {'native-economic-accounting': ('crates/core/**',
                                'crates/crypto/**',
                                'crates/poseidon2/**',
                                'crates/state/**',
                                'crates/circuits/**',
                                'crates/consensus/**',
                                'crates/storage/**',
                                'crates/prover/**',
                                'crates/node/**',
                                'scripts/ci/check-fund-simulation.py'),
 'offline-fund-keys': ('crates/fund-keytool/**',),
 'workspace': ('crates/core/**',
               'crates/crypto/**',
               'crates/poseidon2/**',
               'crates/state/**',
               'crates/circuits/**',
               'crates/consensus/**',
               'crates/storage/**',
               'crates/prover/**',
               'crates/node/**'),
 'bench-plonky3': ('crates/core/**',
                   'crates/crypto/**',
                   'crates/poseidon2/**',
                   'crates/state/**',
                   'crates/circuits/**',
                   'crates/consensus/**',
                   'crates/storage/**',
                   'crates/prover/**',
                   'crates/node/**',
                   'crates/bench-stark/**'),
 'native-multi-asset': ('crates/core/**',
                        'crates/crypto/**',
                        'crates/poseidon2/**',
                        'crates/state/**',
                        'crates/circuits/**',
                        'crates/consensus/**',
                        'crates/storage/**',
                        'crates/prover/**',
                        'crates/node/**',
                        'crates/bench-multi-asset/**',
                        'crates/native-proof/**',
                        'crates/bench-stark/patches/**',
                        'scripts/bench/multi-asset-profile.py',
                        'scripts/bench/**',
                        'scripts/tests/fixtures/source-provenance/**',
                        'scripts/bench/prover-launcher.rs'),
 'native-transaction': ('crates/core/**',
                        'crates/crypto/**',
                        'crates/poseidon2/**',
                        'crates/state/**',
                        'crates/circuits/**',
                        'crates/consensus/**',
                        'crates/storage/**',
                        'crates/prover/**',
                        'crates/node/**',
                        'crates/native-proof/**',
                        'crates/bench-stark/patches/**',
                        'scripts/ci/check-transaction-proof-profile.py',
                        'scripts/bench/**',
                        'scripts/tests/fixtures/source-provenance/**',
                        'scripts/bench/prover-launcher.rs',
                        'scripts/bench/check-profile-reproduction.py'),
 'native-runtime': ('crates/core/**',
                    'crates/crypto/**',
                    'crates/poseidon2/**',
                    'crates/state/**',
                    'crates/circuits/**',
                    'crates/consensus/**',
                    'crates/storage/**',
                    'crates/prover/**',
                    'crates/node/**',
                    'crates/native-*/**',
                    'crates/native-proof/**',
                    'crates/bench-multi-asset/**',
                    'crates/bench-stark/patches/**'),
 'wallet': ('crates/core/**',
            'crates/crypto/**',
            'crates/poseidon2/**',
            'crates/state/**',
            'crates/circuits/**',
            'crates/consensus/**',
            'crates/storage/**',
            'crates/prover/**',
            'crates/node/**',
            'crates/native-*/**',
            'crates/native-proof/**',
            'crates/bench-multi-asset/**',
            'crates/bench-stark/patches/**')}


def select(paths):
    paths = tuple(paths)
    global_change = any(fnmatch.fnmatchcase(path, pattern) for path in paths for pattern in COMMON)
    return {name: global_change or any(fnmatch.fnmatchcase(path, pattern)
            for path in paths for pattern in patterns) for name, patterns in RULES.items()}


def changed(base, head):
    if not all(re.fullmatch(r'[0-9a-f]{40}', value) for value in (base, head)):
        raise ValueError('Expected full commit identities')
    output = subprocess.check_output(['git', '-c', 'protocol.allow=never', 'diff',
        '--name-only', '-z', '--no-renames', base + '...' + head, '--'])
    return [os.fsdecode(value) for value in output.split(b'\0') if value]


def main():
    try:
        jobs = select(changed(*sys.argv[1:]))
    except (ValueError, TypeError, subprocess.SubprocessError):
        # Missing history or invalid metadata must run the complete validation.
        jobs = dict.fromkeys(RULES, True)
        print('Path selection unavailable; running all checks.', file=sys.stderr)
    with Path(os.environ['GITHUB_OUTPUT']).open('a') as stream:
        for name, enabled in jobs.items():
            print(name.replace('-', '_') + '=' + str(enabled).lower(), file=stream)


if __name__ == '__main__':
    main()
