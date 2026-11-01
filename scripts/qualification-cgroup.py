#!/usr/bin/env python3
"""Qualification-only scope adapter; frozen collectors and profiles stay intact."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('frozen_measurement', ROOT / 'scripts/measure-multi-asset.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
CG = M.CG
BASE_SCOPE_COMMAND = CG.scope_command
CURRENT_STAGE = 'controller'
STAGES = CG.STAGES | {'cpu-profile', 'proof-report', 'scope-launch', 'result-read', 'trial-validation'}
CLASSES = {'OSError', 'PermissionError', 'FileNotFoundError', 'ValueError', 'TypeError',
           'KeyError', 'JSONDecodeError', 'CalledProcessError', 'TimeoutExpired',
           'ProcessLookupError', 'SubprocessError'}


def __getattr__(name):
    return getattr(M, name)


def failure_diagnostic(error, stage, event='native-cgroup-diagnostic-failed'):
    """Export only fixed labels and kernel basenames, never exception messages."""
    return {'event': event,
        'classification': type(error).__name__ if type(error).__name__ in CLASSES else 'SubprocessError',
        'stage': stage if stage in STAGES else 'controller',
        'os_error_number': (error.errno if isinstance(error, OSError)
            and type(error.errno) is int and 0 <= error.errno <= 4096 else None),
        'kernel_file': (Path(error.filename).name if isinstance(error, OSError)
            and error.filename and Path(error.filename).name in CG.ERROR_FILES else None),
        'acceptance': False}


def startup_diagnostic(output):
    for line in output.splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if not isinstance(value, dict) or value.get('event') not in (
                'native-cgroup-diagnostic-failed', 'multi-asset-diagnostic-failed'):
            continue
        result = {'category': 'scope-recorder-failure'}
        for name, allowed in (('stage', STAGES), ('classification', CLASSES), ('kernel_file', CG.ERROR_FILES)):
            if isinstance(value.get(name), str) and value[name] in allowed:
                result[name] = value[name]
        number = value.get('os_error_number')
        if type(number) is int and 0 <= number <= 4096:
            result['os_error_number'] = number
        return result
    return CG.startup_diagnostic(output)


def weighted_scope_command(unit, config, maximum=M.MEMORY_MAX):
    command = BASE_SCOPE_COMMAND(unit, config, maximum)
    # Accounting can work without cpu.max. The default weight requests the CPU
    # controller without changing the quota or overriding inherited limits.
    index = command.index('/usr/bin/python3')
    command[index:index] = ['-p', 'CPUWeight=100']
    return command


def scope_command(unit, config):
    command = weighted_scope_command(unit, config)
    index = command.index(str((ROOT / 'scripts/measure-native-cgroup.py').resolve()))
    command[index] = str(Path(__file__).resolve())
    return command


def record(config):
    """Instrument frozen recorder boundaries without changing its resource rules.

    Hooks exist only in this isolated recorder process and are restored on exit.
    Proof processes still run under the original unprivileged UID/GID.
    """
    global CURRENT_STAGE
    CURRENT_STAGE = 'membership'
    originals = (CG.scoped_group, CG.snapshot, M.subprocess.Popen, M.write_json, M.validate_report)
    snapshot_count = 0
    report_failure = None

    def group(*args, **kwargs):
        global CURRENT_STAGE
        result = originals[0](*args, **kwargs)
        CURRENT_STAGE = 'recorder-oom-protection'
        return result

    def snapshot(*args, **kwargs):
        nonlocal snapshot_count
        global CURRENT_STAGE
        CURRENT_STAGE = 'initial-counters' if snapshot_count == 0 else 'final-counters'
        result = originals[1](*args, **kwargs)
        snapshot_count += 1
        CURRENT_STAGE = 'cpu-profile' if snapshot_count == 1 else 'proof-report'
        return result

    def launch(*args, **kwargs):
        global CURRENT_STAGE
        CURRENT_STAGE = 'proof-launch'
        result = originals[2](*args, **kwargs)
        CURRENT_STAGE = 'proof-wait'
        return result

    def validate(*args, **kwargs):
        nonlocal report_failure
        global CURRENT_STAGE
        CURRENT_STAGE = 'proof-report'
        try:
            return originals[4](*args, **kwargs)
        except (OSError, ValueError, TypeError, KeyError) as error:
            report_failure = failure_diagnostic(error, CURRENT_STAGE)
            raise

    def write(path, value):
        global CURRENT_STAGE
        CURRENT_STAGE = 'result-write'
        if report_failure is not None:
            value['report_diagnostic'] = report_failure
        return originals[3](path, value)

    CG.scoped_group, CG.snapshot = group, snapshot
    M.subprocess.Popen, M.write_json, M.validate_report = launch, write, validate
    try:
        return M.record(config)
    finally:
        CG.scoped_group, CG.snapshot, M.subprocess.Popen, M.write_json, M.validate_report = originals


def main():
    if '--smoke-scope' in sys.argv:
        # Reuse the fixed /usr/bin/true probe, exact scope checks and OOM policy.
        CG.scope_command = weighted_scope_command
        return CG.main()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker-config', type=Path, required=True)
    args = parser.parse_args()
    try:
        return record(json.loads(args.worker_config.read_text()))
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        print(json.dumps(failure_diagnostic(error, CURRENT_STAGE,
            'multi-asset-diagnostic-failed')), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
