#!/usr/bin/env python3
"""Qualify only the frozen native transaction profile on a fresh hosted build.

Each of six fresh scopes uses the existing root recorder, a nonroot proof
process, a 5-GiB memory boundary and no swap. Single-worker verification timing
comes from a setup/prove/verify process; its peak is not verifier-only memory.
The optional actual-host diagnostic never certifies a deployment role.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import uuid

import importlib.util

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'scripts' / name)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


M = module('measure-multi-asset.py')
F = module('check-native-proof-profiles.py')
H = module('minimum-hardware.py')
PARAMETERS = dict(log_blowup=7, num_queries=41, query_pow_bits=20,
    commit_pow_bits=0, batch_pow_bits=20, max_log_arity=1, log_final_poly_len=0)
MEASUREMENTS = ('setup_ns', 'generation_ns', 'verification_ns', 'proof_bytes',
    'public_transaction_bytes', 'permanent_position_bytes')


def bound_profile(manifest_path, reproduced, screen_path):
    manifest = json.loads(manifest_path.read_text())
    F.validate(manifest, reproduced=reproduced)
    frozen = F.transaction_profile()
    screen = json.loads(screen_path.read_text())
    chosen = M.profiles(screen, 'transaction').get((7, 20))
    if not chosen or chosen['parameters'] != PARAMETERS or frozen['parameters'] != PARAMETERS:
        raise ValueError('Frozen transaction parameters changed')
    for name in ('air_source_sha256', 'dependencies_sha256'):
        if M.digest(screen[name]) != frozen[name]:
            raise ValueError('Screened build differs from frozen source identity')
    if chosen['security'] != frozen['selected_security']:
        raise ValueError('Actual security report differs from frozen transaction report')
    relation = next(value for value in manifest['relations'] if value['kind'] == 'transaction')
    return {**chosen, 'air_source_sha256': screen['air_source_sha256'],
        'dependencies_sha256': screen['dependencies_sha256'],
        'public_verifier_key_sha256': relation['public_verifier_key']['sha256']}


def cpu_max(value):
    if not isinstance(value, str) or not re.fullmatch(r'(max|[1-9][0-9]*) [1-9][0-9]*', value):
        raise ValueError('Invalid CPU quota evidence')
    return value


def clean_trial(row, raw, config, profile):
    """Recheck recorder evidence and export only typed, allowlisted fields."""
    for name in ('kind', 'workers', 'trial', 'parameters', 'hardware_profile'):
        if row.get(name) != config[name]:
            raise ValueError('Recorder identity changed')
    if (row.get('verification_workers') != config['workers']
            or row.get('memory_max_bytes') != M.MEMORY_MAX
            or row.get('memory_swap_max_bytes') != 0
            or row.get('measurement_scope_sha256') != hashlib.sha256(config['unit'].encode()).hexdigest()):
        raise ValueError('Incomplete or failed recorder evidence')
    counters = {}
    for name in ('memory_events_before', 'memory_events_after', 'memory_events_delta'):
        M.CG.validate_events(row[name])
        counters[name] = {key: row[name][key] for key in M.CG.EVENTS}
    for name in M.CG.EVENTS:
        if counters['memory_events_after'][name] - counters['memory_events_before'][name] != counters['memory_events_delta'][name]:
            raise ValueError('Inconsistent memory event counters')
    peak = M.integer(row['memory_peak_bytes'], 'memory_peak_bytes', positive=True)
    limits = []
    for index, value in enumerate(row['visible_cpu_limits']):
        quota = value['quota_cores']
        if (value['ancestor_level'] != index or (quota is not None
                and (type(quota) not in (int, float) or not 0 < quota <= 1_000_000))):
            raise ValueError('Invalid visible CPU-limit evidence')
        maximum = value['cpu_max']
        if maximum is None:
            if quota is not None:
                raise ValueError('Unreadable CPU limit cannot have a known quota')
        else:
            maximum = cpu_max(maximum)
            numerator, period = maximum.split()
            expected = None if numerator == 'max' else int(numerator) / int(period)
            if quota != expected:
                raise ValueError('CPU quota differs from its kernel limit')
            if (config.get('qualification_profile', config['hardware_profile']) != 'diagnostic'
                    and expected is not None and expected < 4):
                raise ValueError('Visible CPU quota is below four vCPUs')
        # Inaccessible ancestors remain explicitly unknown, never unlimited.
        limits.append(dict(ancestor_level=index, cpu_max=maximum, quota_cores=quota))
    if not limits:
        raise ValueError('Missing CPU-limit evidence')
    exit_code = row.get('exit_code')
    if type(exit_code) is not int or type(row.get('timed_out')) is not bool:
        raise ValueError('Invalid recorder process outcome')
    descendants = M.integer(row['remaining_descendants_at_exit'], 'remaining_descendants_at_exit')
    resource_pass = (row.get('resource_control_pass') is True and exit_code == 0
        and row['timed_out'] is False and descendants == 0 and peak <= M.MEMORY_MAX
        and not any(counters['memory_events_delta'].values()))
    proof_pass = False
    measured = None
    try:
        measurement = M.validate_report(raw, config)
        if M.security_summary(raw['security']) != profile['security']:
            raise ValueError('Measured security differs from frozen profile')
        names = MEASUREMENTS if config['kind'] == 'transaction' else MEASUREMENTS[:4]
        measured = {name: M.integer(measurement[name], name, positive=True) for name in names}
        if any(row['measurement'].get(name) != number for name, number in measured.items()):
            raise ValueError('Recorder and actual report measurement differ')
        proof_pass = row.get('proof_report_valid') is True
    except (OSError, ValueError, TypeError, KeyError):
        measured = None
    result = {'kind': config['kind'], 'workers': config['workers'], 'trial': config['trial'],
        'parameters': config['parameters'].copy(), 'hardware_profile': config['hardware_profile'],
        'qualification_profile': config.get('qualification_profile', config['hardware_profile']),
        'measurement_scope_sha256': row['measurement_scope_sha256'],
        'resource_control_pass': resource_pass, 'proof_report_valid': proof_pass,
        'exit_code': exit_code, 'timed_out': row['timed_out'],
        'remaining_descendants_at_exit': descendants,
        'process_wall_ns': M.integer(row['process_wall_ns'], 'process_wall_ns', positive=True),
        'process_cpu_ns': M.integer(row['process_cpu_ns'], 'process_cpu_ns', positive=True),
        'memory_peak_bytes': peak, 'memory_max_bytes': M.MEMORY_MAX,
        'memory_swap_max_bytes': 0, **counters, 'cpu_max': cpu_max(row['cpu_max']),
        'visible_cpu_limits': limits, 'verification_workers': config['workers'],
        'scope_exit_code': 0, 'acceptance': False}
    if measured is not None:
        result['measurement'] = measured
    return result


def collect(args):
    if args.output.exists():
        raise ValueError('Refusing to overwrite qualification evidence')
    args.output.mkdir(parents=True)
    profile = bound_profile(args.manifest, args.reproduced, args.screen)
    qualify = H.qualify_and_record if args.hardware_profile in H.MINIMUM_MEMORY else M.qualify_and_record
    hardware = qualify(args.output, args.hardware_profile)
    if hardware is None:
        return 1
    executable, worker = args.executable.resolve(strict=True), args.worker.resolve(strict=True)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if not re.fullmatch('[a-f0-9]{40}', commit):
        raise ValueError('Invalid source commit')
    identity = {name: profile[name] for name in ('air_source_sha256', 'dependencies_sha256')}
    identity['binary_sha256'] = M.sha(worker)
    groups = {}
    with tempfile.TemporaryDirectory(prefix='fixed-native-private-', dir=args.private_parent) as temporary:
        private = Path(temporary)
        for workers in (4, 1):
            rows = []
            for index in range(1, 4):
                stem = f'transaction-w{workers}-{index}'
                config = dict(uid=os.getuid(), gid=os.getgid(),
                    unit='siworld-native-' + uuid.uuid4().hex + '.scope', kind='transaction',
                    parameters=PARAMETERS.copy(), workers=workers, trial=index, timeout=args.timeout,
                    executable=str(executable),
                    hardware_profile='diagnostic' if args.hardware_profile in H.MINIMUM_MEMORY else args.hardware_profile,
                    qualification_profile=args.hardware_profile,
                    private_output=str(private / (stem + '-raw.json')),
                    private_log=str(private / (stem + '.log')),
                    result=str(private / (stem + '-result.json')), scan_mode='economics-candidate', **identity)
                path = private / (stem + '-config.json')
                M.write_json(path, config)
                try:
                    completed = subprocess.run(M.scope_command(config['unit'], path),
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                        timeout=args.timeout + 30, check=False)
                    recorded = json.loads(Path(config['result']).read_text())
                    try:
                        raw = json.loads(Path(config['private_output']).read_text())
                    except (OSError, ValueError):
                        raw = {}
                    row = clean_trial(recorded, raw, config, profile)
                    row['scope_exit_code'] = completed.returncode
                    if completed.returncode != 0:
                        row['resource_control_pass'] = False
                except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
                    row = dict(kind='transaction', workers=workers, trial=index,
                        parameters=PARAMETERS.copy(), resource_control_pass=False,
                        proof_report_valid=False, failure='scope-report-or-profile-validation-failed', acceptance=False)
                rows.append(row)
            groups[str(workers)] = dict(trials=rows, summary=M.medians(rows))
    complete = all(group['summary'].get('complete') is True for group in groups.values())
    body_pass = complete and all(row['measurement']['proof_bytes'] <= M.ECONOMICS_PROOF_MAX
        for group in groups.values() for row in group['trials'])
    time_pass = complete and all(row['measurement']['generation_ns'] <= M.GENERATION_MAX_NS
        for row in groups['4']['trials'])
    baseline = args.hardware_profile != 'diagnostic'
    target = bool(baseline and complete and body_pass and time_pass)
    result = dict(schema=1, status='minimum-qualified' if target else
        ('minimum-target-not-met' if baseline else 'actual-host-diagnostic-only'),
        source_commit=commit, suite=M.SUITE, parameters=PARAMETERS.copy(), **identity,
        launcher_sha256=M.sha(executable), manifest_sha256=M.sha(args.manifest),
        public_verifier_key_sha256=profile['public_verifier_key_sha256'],
        reproduced_public_keys_match=True, actual_security_report=profile['security'],
        hardware_profile=args.hardware_profile, baseline_qualified=target,
        hardware=hardware, minimum_configuration_qualified=target,
        engineering_target_pass=target, all_measurements_complete=complete,
        proof_body_limit_bytes=M.ECONOMICS_PROOF_MAX, proof_body_limit_pass=bool(body_pass),
        four_worker_generation_limit_ns=M.GENERATION_MAX_NS,
        four_worker_generation_limit_pass=bool(time_pass), workers=groups,
        diagnostic_memory_max_bytes=M.MEMORY_MAX, diagnostic_swap_max_bytes=0,
        memory_boundary_is_miner_requirement=False, verification_only_process=False,
        verification_measurement='single-worker verifier timing inside setup/prove/verify; memory is not an independent verifier memory measurement',
        acceptance=False, cryptographic_approval=False, network_activation=False)
    M.write_json(args.output / 'summary.json', result)
    return 0 if complete and body_pass and (time_pass or not baseline) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--screen', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, default=ROOT / F.MANIFEST)
    parser.add_argument('--reproduced', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--private-parent', type=Path)
    parser.add_argument('--hardware-profile', choices=('minimum-validator', 'minimum-miner', 'diagnostic'),
        default='minimum-miner')
    parser.add_argument('--timeout', type=int, default=120)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 600:
        parser.error('timeout must be between 1 and 600 seconds')
    try:
        return collect(args)
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        print('Fixed-profile qualification failed: ' + type(error).__name__, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
