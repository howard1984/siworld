#!/usr/bin/env python3
"""Collect independent hosted Linux proving and verification diagnostics.

The root recorder stays in each systemd scope until kernel counters are saved.
The proof runs without root privileges and cannot migrate out of that scope.
Only an allowlisted summary is exported; proof fixtures and raw logs stay local.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
MEMORY_MAX = 5 * 1024**3
VERIFIER_MEMORY_MAX = 128 * 1024**2
VERIFIER_CPU_ALLOWANCE_NS = 250_000_000
CPU_POLL_SECONDS = 0.01
VERIFIER_KINDS = frozenset(('verify-transaction', 'verify-settlement', 'verify-block576'))
SUITE = 'KoalaBear-D8-Poseidon2-W24-digest12'
PARAMETERS = {'log_blowup': 8, 'num_queries': 36, 'query_pow_bits': 20,
              'batch_pow_bits': 20, 'commit_pow_bits': 0, 'max_log_arity': 1}
EVENTS = ('max', 'oom', 'oom_kill', 'oom_group_kill')
CURRENT_STAGE = 'controller'
STAGES = frozenset(('controller', 'membership', 'recorder-oom-protection',
    'initial-counters', 'proof-launch', 'proof-wait', 'final-counters', 'result-write'))
ERROR_FILES = frozenset(('oom_score_adj', 'memory.max', 'memory.swap.max', 'memory.oom.group',
    'memory.peak', 'memory.current', 'memory.swap.current', 'memory.events',
    'memory.events.local', 'cpu.stat', 'cpu.max', 'cgroup.procs'))


def startup_diagnostic(text):
    """Export fixed error labels, never arbitrary systemd stderr or host paths."""
    for line in text.splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get('event') == 'native-cgroup-diagnostic-failed':
            result = {'category': 'scope-recorder-failure'}
            if value.get('classification') in {'OSError', 'PermissionError', 'FileNotFoundError',
                    'ValueError', 'CalledProcessError', 'TimeoutExpired', 'ProcessLookupError',
                    'SubprocessError'}:
                result['classification'] = value['classification']
            if value.get('stage') in STAGES:
                result['stage'] = value['stage']
            number = value.get('os_error_number')
            if type(number) is int and 0 <= number <= 4096:
                result['os_error_number'] = number
            if value.get('kernel_file') in ERROR_FILES:
                result['kernel_file'] = value['kernel_file']
            return result
    patterns = (('Failed to connect to bus', 'systemd-bus-unavailable'),
        ('Unknown assignment', 'systemd-property-rejected'),
        ('Unknown property', 'systemd-property-rejected'),
        ('unrecognized option', 'systemd-option-rejected'),
        ('Failed to start transient scope unit', 'systemd-scope-startup-rejected'),
        ('a password is required', 'sudo-password-required'),
        ('Failed to find executable', 'scope-executable-missing'),
        ('Failed to execute', 'scope-executable-failed'))
    result = {'category': next((label for needle, label in patterns if needle in text),
                               'scope-no-recorder-result')}
    if result['category'] == 'systemd-property-rejected':
        match = re.search(r'Unknown (?:assignment|property):\s*[\"\']?([A-Za-z][A-Za-z0-9]+)', text)
        allowed = {'CPUAccounting', 'MemoryAccounting', 'MemoryMax', 'MemorySwapMax', 'MemoryOOMGroup'}
        if match and match[1] in allowed:
            result['property'] = match[1]
    return result


def write_json(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write('\n')


def read_numbers(path):
    return {key: int(value) for key, value in
            (line.split() for line in path.read_text().splitlines())}


def integer(value, label, positive=False):
    if type(value) is not int or value < (1 if positive else 0):
        raise ValueError('Invalid nonnegative measurement: ' + label)
    return value


def scoped_group(membership, unit, mount=Path('/sys/fs/cgroup')):
    if not re.fullmatch(r'siworld-native-[a-f0-9]{32}\.scope', unit):
        raise ValueError('Unexpected scope unit')
    rows = [line[3:] for line in membership.splitlines() if line.startswith('0::')]
    if len(rows) != 1:
        raise ValueError('Unified cgroup v2 membership required')
    relative = Path(rows[0])
    if not relative.is_absolute() or '..' in relative.parts or relative.name != unit:
        raise ValueError('Recorder is outside its exact independent systemd scope')
    group = mount / str(relative).lstrip('/')
    if group == mount:
        raise ValueError('Root cgroup cannot be measured')
    return group


def validate_events(counters):
    if not isinstance(counters, dict) or not set(EVENTS).issubset(counters):
        raise ValueError('Incomplete kernel memory event counters')
    for value in counters.values():
        if type(value) is not int or value < 0:
            raise ValueError('Invalid kernel memory event counter')


def memory_limit(kind):
    return VERIFIER_MEMORY_MAX if kind in VERIFIER_KINDS else MEMORY_MAX


def process_cpu_ns(before, after):
    """Account child user+system CPU, including startup; cpu.max is only a rate quota."""
    elapsed = ((after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime))
    if elapsed < 0:
        raise ValueError('Child CPU counters regressed')
    return round(elapsed * 1_000_000_000)


def verification_cpu_budget(kind):
    return VERIFIER_CPU_ALLOWANCE_NS * (576 if kind == 'verify-block576' else 1)


def diagnostic_timeout(kind, requested):
    if kind not in VERIFIER_KINDS:
        return requested
    return min(requested, 180 if kind == 'verify-block576' else 2)


def kill_owned_tree(process, group):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    for pid in member_pids(group):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def wait_with_cpu_budget(process, group, initial_usage_usec, timeout, budget_ns):
    """Kill the owned process tree on sampled aggregate cgroup CPU exhaustion.

    Sampling has an explicit maximum 10-ms wait interval, so final counters may
    exceed the budget. Such overshoot fails the diagnostic; it is never hidden
    or represented as a nanosecond-precision kernel CPU quota.
    """
    deadline = time.monotonic() + timeout
    samples = 0
    observed = 0
    while True:
        current = read_numbers(group / 'cpu.stat')['usage_usec']
        if current < initial_usage_usec:
            raise ValueError('Scope CPU counters regressed')
        observed = (current - initial_usage_usec) * 1000
        samples += 1
        limited = observed > budget_ns
        timed_out = time.monotonic() >= deadline
        if limited or timed_out:
            kill_owned_tree(process, group)
            return process.wait(), timed_out, limited, observed, samples
        try:
            code = process.wait(timeout=min(CPU_POLL_SECONDS, max(0.001, deadline - time.monotonic())))
            return code, False, False, observed, samples
        except subprocess.TimeoutExpired:
            continue


def snapshot(group, maximum=MEMORY_MAX):
    names = ('memory.max', 'memory.swap.max', 'memory.oom.group', 'memory.peak',
             'memory.current', 'memory.swap.current')
    data = {name: int((group / name).read_text().strip()) for name in names}
    for name in ('memory.events', 'memory.events.local', 'cpu.stat'):
        data[name] = read_numbers(group / name)
    for name in ('memory.events', 'memory.events.local'):
        validate_events(data[name])
    data['cpu.max'] = (group / 'cpu.max').read_text().strip()
    if data['memory.max'] != maximum or data['memory.swap.max'] != 0:
        raise ValueError('Systemd memory limit readback mismatch')
    # systemd 255 does not accept a transient MemoryOOMGroup assignment.
    # Require the kernel's default per-process OOM policy before any proof starts.
    if data['memory.oom.group'] != 0:
        raise ValueError('Recorder must survive a proof-only OOM')
    return data


def assess(before, after, exit_code, timed_out, remaining, maximum=MEMORY_MAX):
    validate_events(before['memory.events'])
    validate_events(after['memory.events'])
    delta = {key: after['memory.events'].get(key, 0) - before['memory.events'].get(key, 0)
             for key in set(before['memory.events']) | set(after['memory.events'])}
    if any(value < 0 for value in delta.values()):
        raise ValueError('Memory event counters regressed')
    peak = after['memory.peak']
    return {'event_deltas': delta, 'resource_control_pass': (
        exit_code == 0 and not timed_out and not remaining and 0 < peak <= maximum
        and after['memory.swap.current'] == 0
        and all(delta.get(event, 0) == 0 for event in EVENTS)),
        'acceptance': False}


def proof_metrics(kind, report):
    if report.get('suite') != SUITE:
        raise ValueError('Unexpected proof suite')
    if kind in VERIFIER_KINDS:
        calls = 576 if kind == 'verify-block576' else 1
        if (report.get('verification_only') is not True or report.get('workers') != 1
                or report.get('setup_performed') is not False or report.get('generation_calls') != 0
                or report.get('verification_calls') != calls or report.get('unique_proof_count') != 1
                or report.get('stateful_block_validation') is not False
                or report.get('statement_reconstructed') is not True
                or report.get('wire_codec') != ('SWST-v1' if kind == 'verify-settlement' else 'SWTX-v1')
                or report.get('verified') is not True):
            raise ValueError('Independent verifier performed unexpected work')
        params = report['parameters']
        if any(params.get(key) != value for key, value in PARAMETERS.items()):
            raise ValueError('Unexpected independent verifier parameters')
        public = {name: integer(report[name], name, positive=True) for name in
            ('loading_ns', 'verification_ns', 'proof_body_bytes', 'verification_calls',
             'per_proof_wall_min_ns', 'per_proof_wall_median_ns', 'per_proof_wall_max_ns')}
        public.update({'unique_proof_count': 1, 'stateful_block_validation': False,
                       'generation_calls': 0, 'setup_performed': False, 'workers': 1,
                       'statement_reconstructed': True, 'wire_codec': report['wire_codec'],
                       'workload_basis': ('576 cryptographic verifications of one repeated transaction fixture; no valid-block claim'
                           if calls == 576 else 'one independent native proof verification')})
        return public
    if kind == 'transaction':
        if (report.get('verified') is not True or report.get('workers') != 4
                or report.get('operation') != 'four_worker'
                or report.get('production_selection_allowed') is not False):
            raise ValueError('Transaction diagnostic did not generate and verify with four workers')
        params = report['parameters']
        if any(params.get(key) != value for key, value in PARAMETERS.items()):
            raise ValueError('Unexpected transaction diagnostic parameters')
        names = ('setup_ns', 'generation_ns', 'verification_ns', 'proof_body_bytes')
        return {name: integer(report[name], name, positive=True) for name in names}
    if kind != 'settlement' or (report.get('schema') != 2
            or report.get('settlement_statement') != 'confidential-miner-note-v1'
            or report.get('capacities') != [576]
            or report.get('worker_count') != 4
            or report.get('fri_profile') != 'transaction-candidate-diagnostic'):
        raise ValueError('Unexpected settlement diagnostic profile')
    records = report['records']
    if len(records) != 1 or records[0]['capacity'] != 576 or len(records[0]['trials']) != 1:
        raise ValueError('Each settlement process must contain exactly one 576-slot proof')
    trial = records[0]['trials'][0]
    return {'generation_ns': integer(trial['generation_ms'], 'generation_ms', True) * 1_000_000,
            'verification_ns': integer(trial['verification_ms'], 'verification_ms') * 1_000_000,
            'proof_body_bytes': integer(trial['proof_bytes'], 'proof_bytes', True),
            'air_shape': {key: integer(value, key, True) for key, value in records[0]['shape'].items()}}


def child_command(kind, executable, output, index, run_id, fixtures=None, fixture_manifest_sha256=None):
    if kind == 'scope-smoke':
        return ['/usr/bin/true']
    if kind in VERIFIER_KINDS:
        if fixtures is None or not re.fullmatch(r'[a-f0-9]{64}', fixture_manifest_sha256 or ''):
            raise ValueError('Independent verifier requires trusted fixtures')
        return [str(executable), '--kind', kind.removeprefix('verify-'),
                '--fixtures', str(fixtures), '--fixture-manifest-sha256', fixture_manifest_sha256,
                '--output', str(output)]
    if kind == 'transaction':
        return [str(executable), '--log-blowup', '8', '--queries', '36', '--grinding', '20',
                '--operation', 'four_worker', '--trial-index', str(index), '--run-id', run_id,
                '--machine-id', 'github-hosted-ubuntu-24.04-diagnostic', '--output', str(output)]
    if kind == 'settlement':
        return [str(executable), '--capacity', '576', '--trials', '1', '--output', str(output)]
    raise ValueError('Unknown diagnostic kind')


def scope_command(unit, config, maximum=MEMORY_MAX):
    if maximum not in (MEMORY_MAX, VERIFIER_MEMORY_MAX):
        raise ValueError('Unsupported diagnostic memory limit')
    property_value = '5G' if maximum == MEMORY_MAX else '128M'
    return ['sudo', '--non-interactive', 'systemd-run', '--scope', '--quiet', '--unit=' + unit,
            '-p', 'MemoryAccounting=yes', '-p', 'CPUAccounting=yes',
            '-p', 'MemoryMax=' + property_value, '-p', 'MemorySwapMax=0',
            '/usr/bin/python3', str(Path(__file__).resolve()),
            '--worker-config', str(config)]


def member_pids(group):
    return {int(value) for file in group.rglob('cgroup.procs')
            for value in file.read_text().split()} - {os.getpid()}


def run_in_scope(config):
    global CURRENT_STAGE
    if os.geteuid() != 0 or config['uid'] <= 0 or config['gid'] <= 0:
        raise ValueError('Root recorder and nonroot proof UID/GID required')
    CURRENT_STAGE = 'membership'
    group = scoped_group(Path('/proc/self/cgroup').read_text(), config['unit'])
    # The proof inherits score 0, not this recorder's OOM immunity. Keeping the
    # tiny recorder alive preserves final kernel counters after proof OOMs.
    CURRENT_STAGE = 'recorder-oom-protection'
    Path('/proc/self/oom_score_adj').write_text('-1000')
    CURRENT_STAGE = 'initial-counters'
    maximum = memory_limit(config['kind'])
    before = snapshot(group, maximum)
    raw = Path(config['private_output'])
    command = child_command(config['kind'], config['executable'], raw,
                            config['trial'], config['run_id'], config.get('fixtures'), config.get('fixture_manifest_sha256'))

    def unprivileged():
        Path('/proc/self/oom_score_adj').write_text('0')
        os.setgroups([])
        os.setgid(config['gid'])
        os.setuid(config['uid'])

    started = time.monotonic_ns()
    cpu_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    timed_out = False
    cpu_limited = False
    cpu_samples = 0
    with Path(config['private_log']).open('xb') as log:
        CURRENT_STAGE = 'proof-launch'
        process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
            stdout=log, stderr=log, start_new_session=True, preexec_fn=unprivileged,
            env={'PATH': '/usr/bin:/bin', 'RAYON_NUM_THREADS': '1' if config['kind'] in VERIFIER_KINDS else '4',
                 'SIWORLD_COMPOSITION_HIDING_WORKERS': '2'})
        CURRENT_STAGE = 'proof-wait'
        if config['kind'] in VERIFIER_KINDS:
            code, timed_out, cpu_limited, _, cpu_samples = wait_with_cpu_budget(
                process, group, before['cpu.stat']['usage_usec'],
                diagnostic_timeout(config['kind'], config['timeout']),
                verification_cpu_budget(config['kind']))
        else:
            try:
                code = process.wait(timeout=config['timeout'])
            except subprocess.TimeoutExpired:
                timed_out = True
                kill_owned_tree(process, group)
                code = process.wait()
    elapsed = time.monotonic_ns() - started
    child_cpu = process_cpu_ns(cpu_before, resource.getrusage(resource.RUSAGE_CHILDREN))
    remaining = member_pids(group)
    # Only this exact UUID scope is inspected. Nonroot proof processes cannot
    # migrate to another scope; terminate surviving members before collection.
    for pid in remaining:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    until = time.monotonic() + 5
    while member_pids(group) and time.monotonic() < until:
        time.sleep(0.05)
    CURRENT_STAGE = 'final-counters'
    after = snapshot(group, maximum)
    report = {'schema': 1, 'kind': config['kind'], 'trial': config['trial'],
        'scope_id': config['unit'], 'suite': SUITE, 'parameters': PARAMETERS,
        'exit_code': code, 'timed_out': timed_out, 'process_wall_ns': elapsed,
        'process_cpu_ns': child_cpu, 'process_cpu_basis': 'resource.getrusage RUSAGE_CHILDREN user+system delta',
        'memory_max_bytes': maximum, 'memory_swap_max_bytes': 0,
        'source_commit': config.get('source_commit'),
        **config.get('freeze_evidence', {'engineering_profile_frozen': False}),
        'memory': {'before': before, 'after': after},
        'remaining_proof_processes': len(remaining),
        'peak_scope': ('fresh verification process-tree lifetime including startup, public key loading and bounded decoding; recorder included'
            if config['kind'] in VERIFIER_KINDS else
            'fresh process-tree lifetime including setup, proof and verification; recorder included'),
        'timing_scope': ('verification wall time measured by the executable; child startup CPU and wall lifetime recorded separately'
            if config['kind'] in VERIFIER_KINDS else
            'proof generation measured by the executable; process lifetime recorded separately'),
        **assess(before, after, code, timed_out, remaining, maximum)}
    if config['kind'] in VERIFIER_KINDS:
        calls = 576 if config['kind'] == 'verify-block576' else 1
        report['cpu_allowance_per_proof_ns'] = VERIFIER_CPU_ALLOWANCE_NS
        report['cpu_allowance_basis'] = 'entire child CPU including startup divided by cryptographic verification calls'
        scope_cpu = (after['cpu.stat']['usage_usec'] - before['cpu.stat']['usage_usec']) * 1000
        if scope_cpu < 0:
            raise ValueError('Scope CPU counters regressed')
        budget = verification_cpu_budget(config['kind'])
        report['scope_cpu_ns'] = scope_cpu
        report['cpu_watchdog'] = {'budget_ns': budget, 'poll_interval_ns': round(CPU_POLL_SECONDS * 1_000_000_000),
            'samples': cpu_samples, 'killed_on_budget': cpu_limited,
            'observed_overshoot_ns': max(0, scope_cpu - budget),
            'scope': 'all processes in the owned cgroup including recorder and startup'}
        report['cpu_allowance_pass'] = child_cpu <= budget and scope_cpu <= budget and not cpu_limited
        report['resource_control_pass'] &= report['cpu_allowance_pass']
    try:
        report['proof'] = ({} if config['kind'] == 'scope-smoke'
            else proof_metrics(config['kind'], json.loads(raw.read_text())))
        report['proof_report_valid'] = True
    except (OSError, ValueError, TypeError, KeyError):
        report['proof_report_valid'] = False
        report['resource_control_pass'] = False
    CURRENT_STAGE = 'result-write'
    write_json(config['result'], report)
    return 0 if report['resource_control_pass'] else 1


def freeze_evidence(manifest):
    """Authenticate the engineering profile independently of diagnostic success."""
    manifest = manifest.resolve(strict=True)
    subprocess.run([sys.executable, str(ROOT / 'scripts/ci/check-transaction-proof-profile.py'),
                    '--manifest', str(manifest)], check=True, cwd=ROOT)
    data = manifest.read_bytes()
    value = json.loads(data)
    if (value.get('schema') != 1 or value.get('status') != 'engineering-frozen'
            or value.get('cryptographic_approval') is not False
            or value.get('network_activation') is not False):
        raise ValueError('Unexpected engineering freeze status')
    keys = {kind: value['profiles'][kind]['verifier_artifact_sha256']
            for kind in ('transaction', 'settlement')}
    if any(not re.fullmatch(r'[a-f0-9]{64}', digest) for digest in keys.values()):
        raise ValueError('Invalid frozen verifier identity')
    return {'engineering_profile_frozen': True, 'verifier_artifact_sha256': keys,
            'freeze_manifest_sha256': hashlib.sha256(data).hexdigest(),
            'cryptographic_approval': False, 'network_activation': False}


def validate_fixture_keys(fixtures, frozen):
    data = (fixtures / 'manifest.json').read_bytes()
    manifest = json.loads(data)
    for kind, expected in frozen['verifier_artifact_sha256'].items():
        if manifest[kind].get('vk_sha256') != expected:
            raise ValueError('Fixture key differs from frozen public verifier')
    return hashlib.sha256(data).hexdigest()


def collect(args):
    if args.output.exists():
        raise ValueError('Refusing to overwrite measurement evidence')
    args.output.mkdir(parents=True)
    spec = importlib.util.spec_from_file_location('proof_cgroup', ROOT / 'scripts/bench/measure-proof-cgroup.py')
    hardware_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hardware_module)
    hardware, evidence = hardware_module.qualify()
    write_json(args.output / 'hardware.json', {'hardware': hardware,
        'lscpu': evidence['lscpu_json'], 'lscpu_text': evidence['lscpu_text'],
        'hardware_profile': 'github-hosted-diagnostic', 'reserved_reference_machine': False})
    executables = ({'scope-smoke': Path('/usr/bin/true')} if args.smoke_scope else
        {'transaction': args.transaction.resolve(strict=True),
         'settlement': args.settlement.resolve(strict=True),
         **{kind: args.verifier.resolve(strict=True) for kind in sorted(VERIFIER_KINDS)}})
    hashes = {kind: {
        'launcher_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'worker_sha256': hashlib.sha256((path if args.smoke_scope else
            path.parent.parent / 'libexec' / path.name).read_bytes()).hexdigest()
        } for kind, path in executables.items()}
    source_commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True, cwd=ROOT).strip()
    if not re.fullmatch(r'[a-f0-9]{40}', source_commit):
        raise ValueError('Invalid source commit identity')
    frozen = ({'engineering_profile_frozen': False} if args.smoke_scope
              else freeze_evidence(args.freeze_manifest))
    fixture_sha = None if args.smoke_scope else validate_fixture_keys(args.fixtures, frozen)
    outcomes = []
    # Config, raw fixture/digest reports, absolute paths and stderr are never
    # copied to the uploaded artifact directory.
    with tempfile.TemporaryDirectory(prefix='native-cgroup-', dir=args.private_parent) as temporary:
        private = Path(temporary)
        for kind in executables:
            for trial in range(1, 2 if args.smoke_scope else 4):
                unit = 'siworld-native-' + uuid.uuid4().hex + '.scope'
                result = args.output.resolve() / f'{kind}-{trial}.json'
                config = {'unit': unit, 'uid': os.getuid(), 'gid': os.getgid(), 'kind': kind,
                    'trial': trial, 'run_id': uuid.uuid4().hex, 'timeout': args.timeout,
                    'executable': str(executables[kind]), 'result': str(result),
                    'source_commit': source_commit, 'freeze_evidence': frozen,
                    'fixture_manifest_sha256': fixture_sha if kind in VERIFIER_KINDS else None,
                    'fixtures': str(args.fixtures.resolve(strict=True)) if kind in VERIFIER_KINDS else None,
                    'private_output': str(private / f'{kind}-{trial}-raw.json'),
                    'private_log': str(private / f'{kind}-{trial}.log')}
                config_file = private / f'{kind}-{trial}-config.json'
                write_json(config_file, config)
                scope_log = private / f'{kind}-{trial}-scope.log'
                try:
                    with scope_log.open('xb') as log:
                        completed = subprocess.run(scope_command(unit, config_file, memory_limit(kind)),
                            stdin=subprocess.DEVNULL, stdout=log,
                            stderr=subprocess.STDOUT, timeout=args.timeout + 30, check=False)
                    returncode = completed.returncode
                except subprocess.TimeoutExpired:
                    returncode = 124
                finally:
                    # This invocation owns only its UUID unit. A failed startup
                    # or killed recorder must not leave a proof process running.
                    subprocess.run(['sudo', '--non-interactive', 'systemctl', 'stop', unit],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=20)
                saved = json.loads(result.read_text()) if result.exists() else None
                outcomes.append({'kind': kind, 'trial': trial,
                    **hashes[kind], 'scope_exit_code': returncode,
                    'result_present': saved is not None,
                    'startup_diagnostic': (startup_diagnostic(scope_log.read_text(errors='replace'))
                        if saved is None else None),
                    'resource_control_pass': bool(saved and saved['resource_control_pass']
                                                  and returncode == 0)})
    report = {'schema': 1, 'suite': SUITE, 'parameters': PARAMETERS,
        'trials': outcomes, 'source_commit': source_commit,
        'prover_memory_max_bytes': MEMORY_MAX, 'verifier_memory_max_bytes': VERIFIER_MEMORY_MAX,
        'verifier_cpu_allowance_per_proof_ns': VERIFIER_CPU_ALLOWANCE_NS,
        'memory_swap_max_bytes': 0,
        'resource_control_pass': all(row['resource_control_pass'] for row in outcomes),
        **frozen,
        'acceptance': False, 'hardware_profile': 'github-hosted-diagnostic',
        'resource_scope': '5-GiB proving scopes; 128-MiB verification scopes including startup; zero swap; diagnostic only'}
    report['measurement_kind'] = ('scope-smoke-only' if args.smoke_scope else 'native-proof-diagnostic')
    write_json(args.output / 'summary.json', report)
    if args.smoke_scope:
        print(json.dumps(report))
    return 0 if report['resource_control_pass'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--transaction', type=Path)
    parser.add_argument('--settlement', type=Path)
    parser.add_argument('--verifier', type=Path)
    parser.add_argument('--fixtures', type=Path)
    parser.add_argument('--freeze-manifest', type=Path,
                        default=ROOT / 'crates/native-proof/artifacts/transaction-proof-profile.json')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--private-parent', type=Path, default=Path('.local'))
    parser.add_argument('--timeout', type=int, default=600)
    parser.add_argument('--smoke-scope', action='store_true',
                        help='Check recorder and kernel files with /usr/bin/true before compiling proofs')
    parser.add_argument('--worker-config', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if args.worker_config:
            return run_in_scope(json.loads(args.worker_config.read_text()))
        if (not args.output or args.timeout <= 0
                or (not args.smoke_scope and not all((args.transaction, args.settlement, args.verifier, args.fixtures)))):
            parser.error('output and positive timeout are required; proof mode also needs proving/verifier executables and trusted fixtures')
        return collect(args)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        # Do not expose proof log contents or private host paths in CI output.
        print(json.dumps({'event': 'native-cgroup-diagnostic-failed',
                          'classification': type(error).__name__,
                          'stage': CURRENT_STAGE if CURRENT_STAGE in STAGES else 'controller',
                          'os_error_number': error.errno if isinstance(error, OSError) else None,
                          'kernel_file': (Path(error.filename).name
                              if isinstance(error, OSError) and error.filename
                              and Path(error.filename).name in ERROR_FILES else None),
                          'acceptance': False}))
        return 2


if __name__ == '__main__':
    sys.exit(main())
