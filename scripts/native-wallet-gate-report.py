#!/usr/bin/env python3
"""Export a bounded, allowlisted outcome for the private native wallet test.

The progress record and test log remain private. Only fixed stage names, bounded
counts and an optional repository-relative Rust source location are exported.
Exception text and panic messages are never included in the report or stderr.
"""
import argparse
import json
from itertools import islice
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_HEIGHT = 26
SLOTS_PER_BLOCK = 64
MAX_ELAPSED_MS = 14_400_000
MAX_JSON_BYTES = 4096
MAX_LOG_BYTES = 1_048_576
SOURCE = 'crates/native-node/src/wallet_vault/native_roundtrip.rs'
CRATE_SOURCE = 'src/wallet_vault/native_roundtrip.rs'
STAGES = frozenset(('native-funding', 'native-payment-accepted', 'complete'))
OUTCOMES = frozenset(('success', 'failure', 'cancelled', 'skipped'))
RUN_NAME = re.compile(r'native-wallet-roundtrip-[a-f0-9]{32}')
COMMIT = re.compile(r'[a-f0-9]{40}')
PANIC_LOCATION = re.compile(
    r"^thread 'wallet_vault::native_roundtrip::"
    r"genuine_genesis_rewards_persist_pay_and_restore_with_native_proofs' "
    r'panicked at (?:' + re.escape(SOURCE) + '|' + re.escape(CRATE_SOURCE)
    + r'):([1-9][0-9]{0,5}):([1-9][0-9]{0,3}):\r?$',
    re.MULTILINE,
)


class InvalidEvidence(ValueError):
    """Evidence failed validation; its contents must not be printed."""


def require(condition):
    if not condition:
        raise InvalidEvidence('Invalid native wallet gate evidence')


def integer(value, minimum=0, maximum=MAX_ELAPSED_MS):
    require(type(value) is int and minimum <= value <= maximum)
    return value


def signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def directory(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode))
    return info


def bounded_file(path, maximum):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        require(signature(os.fstat(descriptor)) == signature(before))
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            raw = stream.read(maximum + 1)
        require(len(raw) <= maximum and signature(os.fstat(descriptor)) == signature(before))
    finally:
        os.close(descriptor)
    require(signature(path.lstat()) == signature(before))
    return raw.decode('utf-8'), before


def unique_object(pairs):
    value = {}
    for name, entry in pairs:
        require(name not in value)
        value[name] = entry
    return value


def bounded_json(path):
    raw, info = bounded_file(path, MAX_JSON_BYTES)
    value = json.loads(raw, object_pairs_hook=unique_object,
                       parse_constant=lambda _value: require(False))
    require(type(value) is dict)
    return value, info


def source_commit(value):
    require(type(value) is str and COMMIT.fullmatch(value) is not None)
    actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT,
                                     text=True, stderr=subprocess.DEVNULL, timeout=10).strip()
    require(actual == value)
    return value


def prepare(private, commit):
    """Refuse stale runs and bind collection to this source and empty run root."""
    directory(private)
    runs = private / 'runs'
    info = directory(runs)
    require(not any(runs.iterdir()))
    require(not (private / 'roundtrip.log').exists() and not (private / 'roundtrip.log').is_symlink())
    marker = {'schema': 1, 'source_commit': commit, 'started_ns': time.time_ns(),
              'run_root_device': info.st_dev, 'run_root_inode': info.st_ino}
    with (private / 'gate-start.json').open('x', encoding='utf-8') as stream:
        json.dump(marker, stream, sort_keys=True)
        stream.write('\n')


def progress(private, commit):
    """Return only typed fields from exactly one newly created owned run."""
    directory(private)
    runs = private / 'runs'
    root_info = directory(runs)
    marker, _ = bounded_json(private / 'gate-start.json')
    require(set(marker) == {'schema', 'source_commit', 'started_ns', 'run_root_device', 'run_root_inode'})
    require(type(marker['schema']) is int and marker['schema'] == 1 and marker['source_commit'] == commit)
    now = time.time_ns()
    started = integer(marker['started_ns'], 1, now)
    require(integer(marker['run_root_device'], 0, 2**64 - 1) == root_info.st_dev
            and integer(marker['run_root_inode'], 1, 2**64 - 1) == root_info.st_ino)
    entries = list(islice(runs.iterdir(), 2))
    if not entries:
        return None, 'missing-run'
    require(len(entries) == 1 and RUN_NAME.fullmatch(entries[0].name) is not None)
    run = entries[0]
    run_info = directory(run)
    require(run_info.st_dev == root_info.st_dev and started <= run_info.st_ctime_ns <= now)
    record = run / 'roundtrip-progress.json'
    if not record.exists() and not record.is_symlink():
        return None, 'no-progress'
    value, record_info = bounded_json(record)
    require(started <= record_info.st_mtime_ns <= now)
    require(set(value) == {'schema', 'stage', 'accepted_height', 'required_height', 'slots_per_block', 'elapsed_ms'})
    require(type(value['schema']) is int and value['schema'] == 1)
    stage = value['stage']
    require(type(stage) is str and stage in STAGES)
    height = integer(value['accepted_height'], 1, REQUIRED_HEIGHT)
    require(type(value['required_height']) is int and value['required_height'] == REQUIRED_HEIGHT)
    require(type(value['slots_per_block']) is int and value['slots_per_block'] == SLOTS_PER_BLOCK)
    elapsed = integer(value['elapsed_ms'], 1, MAX_ELAPSED_MS - 1)
    require((stage == 'native-funding' and height <= 25)
            or (stage != 'native-funding' and height == REQUIRED_HEIGHT))
    return {'stage': stage, 'accepted_height': height, 'elapsed_ms': elapsed}, None


def panic_location(private):
    """Discard all panic content; recognize only the exact test source path."""
    text, _ = bounded_file(private / 'roundtrip.log', MAX_LOG_BYTES)
    matches = PANIC_LOCATION.findall(text)
    require(len(matches) <= 1)
    if not matches:
        return None
    line, column = (int(value) for value in matches[0])
    return f'{SOURCE}:{line}:{column}'


def build_report(private, commit, outcome):
    require(type(commit) is str and COMMIT.fullmatch(commit) is not None)
    require(type(outcome) is str and outcome in OUTCOMES)
    report = {'schema': 1, 'source_commit': commit, 'stage': 'not-started',
              'accepted_height': 0, 'required_height': REQUIRED_HEIGHT,
              'slots_per_block': SLOTS_PER_BLOCK, 'elapsed_ms': 0,
              'genuine_native_wallet_gate_passed': False}
    category = 'test-not-started'
    try:
        values, category = progress(private, commit)
        if values is not None:
            report.update(values)
            if outcome == 'success' and values['stage'] == 'complete':
                report['genuine_native_wallet_gate_passed'] = True
            else:
                category = ('test-process-cancelled' if outcome == 'cancelled'
                            else 'test-process-failed' if outcome == 'failure'
                            else 'incomplete-progress')
        else:
            report['stage'] = 'no-progress'
    except FileNotFoundError:
        if (private / 'gate-start.json').exists() or (private / 'gate-start.json').is_symlink():
            report['stage'], category = 'invalid-progress', 'invalid-evidence'
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        report['stage'], category = 'invalid-progress', 'invalid-evidence'
    if not report['genuine_native_wallet_gate_passed']:
        report['failure_category'] = category
        # Locations are considered only for an actual failed process with a
        # validated fresh run root. Malformed evidence cannot add diagnostics.
        if outcome == 'failure' and category in {'test-process-failed', 'missing-run', 'no-progress'}:
            try:
                location = panic_location(private)
                if location is not None:
                    report['failure_category'] = 'native-test-panic'
                    report['failure_location'] = location
            except (OSError, ValueError, TypeError, RecursionError):
                pass
    return report


def save_report(output, value):
    output.parent.mkdir(parents=True, exist_ok=True)
    directory(output.parent)
    with output.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('prepare', 'report'))
    parser.add_argument('--private-root', type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--outcome', choices=sorted(OUTCOMES))
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    try:
        commit = source_commit(args.source_commit)
        if args.command == 'prepare':
            require(args.output is None and args.outcome is None)
            prepare(args.private_root, commit)
            return 0
        require(args.output is not None and args.outcome is not None)
        report = build_report(args.private_root, commit, args.outcome)
        save_report(args.output, report)
        return 0 if report['genuine_native_wallet_gate_passed'] else 1
    except (OSError, ValueError, TypeError, subprocess.SubprocessError, RecursionError):
        print('Native wallet gate evidence validation failed', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
