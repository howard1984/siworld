#!/usr/bin/env python3
"""Run offline Rust test executables with a deadline for each selected test."""
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys


# These integration targets start a mining service or use a test driver
# with an unbounded nonce search. Compile them in hosted checks.
LOCAL_TARGETS = {
    'crates/node/tests/devnet.rs',
    'crates/node/tests/network.rs',
    'crates/node/tests/node.rs',
    'crates/node/tests/plonky3.rs',
    'crates/node/tests/proving.rs',
}
LOCAL_TESTS = {'devnet_releases_inputs_of_evicted_payments'}


def run(command, timeout):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, start_new_session=True)
    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        output, _ = process.communicate()
        print(output, end='')
        raise SystemExit('Test deadline exceeded')
    if process.returncode:
        print(output, end='')
        raise SystemExit(process.returncode)
    return output


def main():
    hosted = '--hosted' in sys.argv[1:]
    arguments = [a for a in sys.argv[1:] if a not in ('--offline', '--hosted')]
    split = arguments.index('--') if '--' in arguments else len(arguments)
    cargo_args, runtime_args = arguments[:split], arguments[split + 1:]
    if '--doc' in cargo_args:
        print(run([os.environ['SIWORLD_REAL_CARGO'], 'test', '--offline', *arguments], 300), end='')
        return
    # Cargo accepts one positional test-name filter. All selector options below
    # take a value; flags do not. Preserve libtest skip/exact/ignored semantics.
    values = {'-p', '--package', '--manifest-path', '--features', '--target', '--target-dir',
              '--bin', '--example', '--test', '--bench', '-j', '--jobs', '--profile',
              '--exclude', '--color', '--config'}
    take_value = False
    filters = []
    for argument in cargo_args:
        if take_value:
            take_value = False
        elif argument in values:
            take_value = True
        elif not argument.startswith('-'):
            filters.append(argument)
    compiled = run([os.environ['SIWORLD_REAL_CARGO'], 'test', '--offline',
                    '--no-run', '--message-format=json', *cargo_args], 3600)
    binaries = {}
    for line in compiled.splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            print(line)
            continue
        if value.get('reason') == 'compiler-message':
            print(value.get('message', {}).get('rendered', ''), end='')
        executable = value.get('executable')
        if value.get('reason') == 'compiler-artifact' and executable and value.get('profile', {}).get('test'):
            binaries[executable] = value
    if not binaries:
        raise SystemExit('No compiled test executable found')
    count = 0
    for binary, metadata in binaries.items():
        target = metadata['target']
        source = '/'.join(Path(target['src_path']).parts[-4:])
        if hosted and source in LOCAL_TARGETS:
            print(f'Local validation only: {source}', flush=True)
            continue
        listed = run([binary, *filters, *runtime_args, '--list', '--format=terse'], 30)
        names = [line[:-6] for line in listed.splitlines() if line.endswith(': test')]
        for name in names:
            if hosted and name in LOCAL_TESTS:
                continue
            # Consensus fixtures and PoW-related tests must finish in seconds.
            pow_test = (metadata.get('target', {}).get('name') == 'pow' or
                        re.search(r'(^|::|_)(pow|mining|nonce|mine|mined)(::|_|$)', name))
            deadline = 5 if pow_test else 300
            print(f'Checking {metadata.get("target", {}).get("name")}: {name} ({deadline}s)', flush=True)
            output = run([binary, name, '--exact', *[a for a in runtime_args if a != '--exact']], deadline)
            print(output, end='')
            count += 1
    if filters and not count:
        raise SystemExit('No tests match the requested selection')
    print(f'Bounded offline test selections: {count}')


if __name__ == '__main__':
    main()
