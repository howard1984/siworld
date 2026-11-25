#!/usr/bin/env python3
"""Screen and measure isolated multi-asset proofs in fresh Linux cgroup scopes.

The 5-GiB boundary is a diagnostic limit, not a miner hardware requirement.
A root recorder preserves kernel counters after OOM while the proof runs as the
original unprivileged user. Uploaded summaries exclude private logs and fixtures.
The one-worker process still performs setup and proving before verification;
its memory peak is not an independent verifier memory measurement.
"""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import resource
import signal
import statistics
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
MEMORY_MAX = 5368709120
PROOF_MAX = 524288
ECONOMICS_PROOF_MAX = 655_360
GENERATION_MAX_NS = 2_000_000_000
SUITE = 'KoalaBear-D8-Poseidon2-W24-digest12'
GRID = tuple((b, g) for b in range(4, 9) for g in (16, 20, 24))
FALLBACK_GRID = tuple((9, g) for g in (16, 20, 24))
WALLET_FAST_GRID = tuple((b, g) for b in range(5, 9) for g in (20, 24))
HARDWARE_PROFILES = ('diagnostic', 'epyc7763-baseline', 'epyc9v45-control')
PARAMETER_KEYS = ('log_blowup', 'num_queries', 'query_pow_bits', 'commit_pow_bits',
                  'batch_pow_bits', 'max_log_arity', 'log_final_poly_len')
SHAPE_KEYS = ('base_trace_rows', 'main_width', 'preprocessed_width', 'public_values',
              'num_constraints', 'max_constraint_degree', 'num_quotient_chunks',
              'num_batched_functions', 'log_committed_trace_length',
              'challenge_field_bits_floor', 'classical_collision_bits_floor')
SCREEN_KEYS = ('classical_conjectured_union_bits', 'classical_johnson_union_bits',
               'quantum_johnson_challenge_union_bits', 'bht_collision_bits',
               'johnson_m', 'proof_multiplicity')


def module(filename):
    spec = importlib.util.spec_from_file_location(filename.replace('-', '_'), ROOT / 'scripts' / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


CG = module('bench/measure-native-cgroup.py')


def write_json(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write('\n')


def integer(value, label, positive=False):
    if type(value) is not int or value < (1 if positive else 0):
        raise ValueError('Invalid integer: ' + label)
    return value


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def digest(value):
    if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{64}', value):
        raise ValueError('Invalid content identity')
    return value


def clean_numbers(value, keys):
    result = {}
    for key in keys:
        number = value.get(key)
        if type(number) not in (int, float) or not math.isfinite(number) or number < 0:
            raise ValueError('Invalid screened numeric term: ' + key)
        result[key] = number
    return result


def security_summary(report):
    if (report.get('p3_security_version') != '0.9.0-rc.2'
            or report.get('accounting') != 'single-proof-johnson-halving-bht-v1'
            or report.get('shape', {}).get('status') != 'actual-extracted'):
        raise ValueError('Unexpected security implementation')
    screen = report['screen']
    if type(screen.get('passes_selected_model')) is not bool:
        raise ValueError('Missing security screen outcome')
    result = {'p3_security_version': '0.9.0-rc.2',
        'accounting': 'single-proof-johnson-halving-bht-v1',
        'shape': clean_numbers(report['shape'], SHAPE_KEYS),
        'screen': {'passes_selected_model': screen['passes_selected_model'],
                   **clean_numbers(screen, SCREEN_KEYS)}}
    if screen['passes_selected_model'] and any(result['screen'][key] < minimum for key, minimum in (
            ('classical_conjectured_union_bits', 128), ('classical_johnson_union_bits', 100),
            ('quantum_johnson_challenge_union_bits', 80), ('bht_collision_bits', 80))):
        raise ValueError('Inconsistent security screen outcome')
    if result['screen']['proof_multiplicity'] != 1:
        raise ValueError('Unexpected proof composition multiplicity')
    for name in ('conjectured', 'proven_johnson', 'johnson_fri_terms', 'challenge_domain_terms'):
        source = report[name]
        terms = []
        for term in (source['terms'] if isinstance(source, dict) else source):
            label = term.get('label')
            if not isinstance(label, str) or not re.fullmatch('[a-z][a-z0-9-]*', label):
                raise ValueError('Unexpected security error label')
            bits = term['bits']
            if bits != 'positive_infinity' and (type(bits) not in (int, float) or not math.isfinite(bits)):
                raise ValueError('Invalid security error term')
            terms.append({'label': label, 'bits': bits})
        result[name] = {'terms': terms} if isinstance(source, dict) else terms
    binding = report['application_binding']
    if binding.get('algorithm') != 'BLAKE3-256' or binding.get('digest_bytes') != 32:
        raise ValueError('Unexpected external application binding')
    result['application_binding'] = {'algorithm': 'BLAKE3-256', 'digest_bytes': 32,
        **clean_numbers(binding, ('nominal_classical_collision_bits', 'nominal_bht_collision_bits')),
        'included_in_p3_security_report': False,
        'model_status': 'nominal-collision-model-requires-review'}
    return result


def profiles(screen, kind):
    if screen.get('suite') != SUITE or screen.get('cryptographic_approval') is not False or screen.get('network_activation') is not False:
        raise ValueError('Unexpected screen identity or status')
    digest(screen['air_source_sha256']); digest(screen['dependencies_sha256'])
    records = {}
    for entry in screen['reports']:
        if entry.get('kind') != kind:
            continue
        key = (entry['log_blowup'], entry['grinding'])
        if key not in GRID + FALLBACK_GRID or key in records:
            raise ValueError('Duplicate or unexpected screen coordinate')
        report = entry.get('minimum_passing_report')
        if report is None:
            records[key] = None
            continue
        summary = security_summary(report)
        if not summary['screen']['passes_selected_model']:
            raise ValueError('Minimum report did not pass')
        params = {key: integer(report['fri'][key], key) for key in PARAMETER_KEYS}
        if (params['log_blowup'], params['query_pow_bits']) != key or params['batch_pow_bits'] != key[1] or params['commit_pow_bits'] != 0 or params['max_log_arity'] != 1 or params['log_final_poly_len'] != 0:
            raise ValueError('Screen parameters differ from coordinate')
        if not 1 <= params['num_queries'] <= 128:
            raise ValueError('Unexpected query count')
        records[key] = {'parameters': params, 'security': summary}
    if not set(GRID).issubset(records):
        raise ValueError('Incomplete actual-AIR screen grid')
    return records


def child_command(config):
    params = config['parameters']
    if config['kind'] not in ('transaction', 'settlement', 'issuance') or config['workers'] not in (1, 4):
        raise ValueError('Unsupported measurement process')
    return [config['executable'], config['kind'], str(params['log_blowup']),
        str(params['num_queries']), str(params['query_pow_bits']), str(config['workers']),
        config['private_output']]


def validate_report(report, config):
    expected = {'suite': SUITE, 'kind': config['kind'], 'workers': config['workers'],
        'verified': True, 'synthetic_fixture': True,
        'cryptographic_approval': False, 'network_activation': False,
        'hiding_workers': '1' if config['workers'] == 1 else '2'}
    for key, value in expected.items():
        if report.get(key) != value:
            raise ValueError('Unexpected measurement field: ' + key)
    for key in ('air_source_sha256', 'dependencies_sha256', 'binary_sha256'):
        if digest(report.get(key)) != config[key]:
            raise ValueError('Measurement identity differs from screened build')
    if report['parameters'] != config['parameters']:
        raise ValueError('Measured parameters differ from screened parameters')
    summary = security_summary(report['security'])
    if not summary['screen']['passes_selected_model']:
        raise ValueError('Measured profile failed security screen')
    source = report['measurement']
    measurement = {name: integer(source[name], name, positive=True)
        for name in ('setup_ns', 'generation_ns', 'verification_ns', 'proof_bytes')}
    if config['kind'] == 'transaction':
        if source.get('actual_encryption_self_check') is not True:
            raise ValueError('Missing canonical transaction encryption self-check')
        measurement.update({name: integer(source[name], name, positive=True) for name in
            ('public_transaction_bytes', 'permanent_position_bytes')})
        measurement['proof_within_524288_bytes'] = measurement['proof_bytes'] <= PROOF_MAX
    if config['kind'] == 'settlement':
        if source.get('capacity') != 576 or source.get('reward_asset_constrained_si') is not True:
            raise ValueError('Unexpected settlement relation')
        measurement.update({'capacity': 576, 'reward_asset_constrained_si': True})
    if config['kind'] == 'issuance':
        if source.get('initial_notes') != 3 or source.get('actual_ml_dsa65_verification') is not True:
            raise ValueError('Unexpected issuance relation')
        measurement.update({'initial_notes': 3, 'actual_ml_dsa65_verification': True,
            **{name: integer(source[name], name, positive=True) for name in ('signed_record_bytes', 'ciphertext_bytes')}})
    return measurement


def scope_command(unit, config):
    # Keep the tested exact-scope and memory properties, but run this recorder.
    command = CG.scope_command(unit, config)
    command[command.index(str((ROOT / 'scripts/bench/measure-native-cgroup.py').resolve()))] = str(Path(__file__).resolve())
    return command


def record(config):
    if os.geteuid() != 0 or config['uid'] <= 0 or config['gid'] <= 0:
        raise ValueError('Root recorder and nonroot proof identity required')
    group = CG.scoped_group(Path('/proc/self/cgroup').read_text(), config['unit'])
    Path('/proc/self/oom_score_adj').write_text('-1000')
    before = CG.snapshot(group, MEMORY_MAX)
    command = child_command(config)
    hardware_profile = config.get('hardware_profile', 'diagnostic')
    cpu_helper = module('bench/measure-proof-cgroup.py')
    cpu_ancestry = cpu_helper.cpu_ancestry(group, Path('/sys/fs/cgroup'))
    cpu_helper.qualify_cpu_profile(cpu_ancestry, hardware_profile)

    def unprivileged():
        Path('/proc/self/oom_score_adj').write_text('0')
        os.setgroups([])
        os.setgid(config['gid'])
        os.setuid(config['uid'])

    started = time.monotonic_ns()
    cpu_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    timed_out = False
    with Path(config['private_log']).open('xb') as log:
        process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
            stdout=log, stderr=log, start_new_session=True, preexec_fn=unprivileged,
            env={'PATH': '/usr/bin:/bin', 'RAYON_NUM_THREADS': str(config['workers']),
                 'SIWORLD_COMPOSITION_HIDING_WORKERS': '1' if config['workers'] == 1 else '2'})
        try:
            code = process.wait(timeout=config['timeout'])
        except subprocess.TimeoutExpired:
            timed_out = True
            CG.kill_owned_tree(process, group)
            code = process.wait()
    elapsed = time.monotonic_ns() - started
    cpu = CG.process_cpu_ns(cpu_before, resource.getrusage(resource.RUSAGE_CHILDREN))
    remaining = CG.member_pids(group)
    for pid in remaining:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 5
    while CG.member_pids(group) and time.monotonic() < deadline:
        time.sleep(0.05)
    after = CG.snapshot(group, MEMORY_MAX)
    assessment = CG.assess(before, after, code, timed_out, remaining, MEMORY_MAX)
    outcome = {'kind': config['kind'], 'workers': config['workers'],
        'trial': config['trial'], 'parameters': config['parameters'],
        'exit_code': code, 'timed_out': timed_out,
        'process_wall_ns': elapsed, 'process_cpu_ns': cpu,
        'average_child_cores': cpu / elapsed if elapsed else 0,
        'memory_max_bytes': MEMORY_MAX, 'memory_swap_max_bytes': 0,
        'memory_peak_bytes': after['memory.peak'],
        'memory_events_before': before['memory.events'], 'memory_events_after': after['memory.events'],
        'memory_events_delta': assessment['event_deltas'], 'cpu_max': after['cpu.max'],
        'hardware_profile': hardware_profile,
        'visible_cpu_limits': clean_cpu_limits(cpu_ancestry),
        'resource_control_pass': assessment['resource_control_pass'],
        'remaining_descendants_at_exit': len(remaining),
        'verification_workers': config['workers'],
        'memory_scope': 'whole fresh setup/prove/verify process tree plus recorder',
        'verification_only_process': False, 'cryptographic_approval': False,
        'network_activation': False, 'acceptance': False}
    if config.get('scan_mode') == 'economics-candidate':
        outcome['measurement_scope_sha256'] = hashlib.sha256(config['unit'].encode('ascii')).hexdigest()
    try:
        outcome['measurement'] = validate_report(json.loads(Path(config['private_output']).read_text()), config)
        outcome['proof_report_valid'] = True
    except (OSError, ValueError, TypeError, KeyError):
        outcome['proof_report_valid'] = False
        outcome['resource_control_pass'] = False
    write_json(config['result'], outcome)
    # A rejected profile remains valid diagnostic evidence, never acceptance.
    return 0


def choose(trials):
    eligible = [trial for trial in trials if trial.get('resource_control_pass') is True
        and trial.get('proof_report_valid') is True and trial.get('workers') == 4
        and trial.get('measurement', {}).get('proof_bytes', PROOF_MAX + 1) <= PROOF_MAX
        and trial['measurement']['generation_ns'] <= GENERATION_MAX_NS]
    return min(eligible, key=lambda t: (t['measurement']['proof_bytes'],
        t['measurement']['generation_ns'], t['parameters']['log_blowup'],
        t['parameters']['query_pow_bits'])) if eligible else None


def diagnostic_choice(trials):
    """Keep an actual measured fallback even when time or size targets fail."""
    valid = [trial for trial in trials if trial.get('resource_control_pass') is True
        and trial.get('proof_report_valid') is True and trial.get('workers') == 4]
    return min(valid, key=lambda t: (t['measurement']['proof_bytes'] > PROOF_MAX,
        t['measurement']['proof_bytes'], t['measurement']['generation_ns'])) if valid else None


def medians(rows):
    if len(rows) != 3 or any(not row.get('resource_control_pass') or not row.get('proof_report_valid') for row in rows):
        return {'complete': False, 'trial_count': len(rows)}
    return {'complete': True, 'trial_count': 3,
        'generation_median_ns': statistics.median(row['measurement']['generation_ns'] for row in rows),
        'generation_min_ns': min(row['measurement']['generation_ns'] for row in rows),
        'generation_max_ns': max(row['measurement']['generation_ns'] for row in rows),
        'verification_median_ns': statistics.median(row['measurement']['verification_ns'] for row in rows),
        'process_wall_median_ns': statistics.median(row['process_wall_ns'] for row in rows),
        'memory_peak_median_bytes': statistics.median(row['memory_peak_bytes'] for row in rows),
        'memory_peak_max_bytes': max(row['memory_peak_bytes'] for row in rows),
        'proof_bytes_min': min(row['measurement']['proof_bytes'] for row in rows),
        'proof_bytes_max': max(row['measurement']['proof_bytes'] for row in rows),
        'acceptance': False}


def clean_cpu_limits(ancestry):
    """Retain visible rate limits without exporting host cgroup paths."""
    return [{'ancestor_level': index, 'cpu_max': row.get('cpu.max'),
        'quota_cores': row.get('cpu_limit', {}).get('quota_cores')
            if row.get('cpu_limit') else None}
        for index, row in enumerate(ancestry)]


def current_cpu_ancestry(helper):
    mount = Path('/sys/fs/cgroup')
    memberships = [line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines()
                   if line.startswith('0::')]
    if len(memberships) != 1:
        raise ValueError('Unified cgroup v2 membership required')
    relative = Path(memberships[0])
    if not relative.is_absolute() or '..' in relative.parts:
        raise ValueError('Invalid current cgroup membership')
    return helper.cpu_ancestry(mount / str(relative).lstrip('/'), mount)


def qualify_and_record(output, profile):
    """Keep a sanitized failure artifact when a hosted runner is not the baseline."""
    helper = module('bench/measure-proof-cgroup.py')
    record = {'required_hardware_profile': profile, 'profile_qualified': False,
        'reserved_reference_machine': False, 'acceptance': False}
    try:
        hardware, evidence = helper.qualify()
        record.update(hardware=hardware, lscpu=evidence['lscpu_json'],
                      lscpu_text=evidence['lscpu_text'])
        record['qualification'] = helper.qualify_hardware_profile(hardware, profile)
        ancestry = current_cpu_ancestry(helper)
        record['visible_cpu_limits'] = clean_cpu_limits(ancestry)
        helper.qualify_cpu_profile(ancestry, profile)
        record['profile_qualified'] = True
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        record['failure'] = 'required-cpu-os-topology-or-cgroup-profile-unavailable'
        record['classification'] = type(error).__name__
        write_json(output / 'hardware-qualification.json', record)
        print('Hardware qualification failed: requires Ubuntu 24.04 x86_64, AVX2, '
              'and the requested CPU/topology profile with no visible CPU quota below four cores.',
              file=sys.stderr)
        return None
    write_json(output / 'hardware-qualification.json', record)
    return record


def choose_wallet_fast(profile_results):
    """Require all three four-worker trials to meet time; proof size is unrestricted."""
    eligible = [row for row in profile_results if row['summary'].get('complete') is True
        and row['summary']['generation_max_ns'] <= GENERATION_MAX_NS
        and len(row['trials']) == 3 and all(trial.get('workers') == 4 for trial in row['trials'])]
    return min(eligible, key=lambda row: (row['summary']['proof_bytes_max'],
        row['summary']['generation_median_ns'], row['parameters']['log_blowup'],
        row['parameters']['query_pow_bits'])) if eligible else None


def choose_economics_candidate(profile_results):
    """Apply the revised body limit to every valid four-worker trial."""
    eligible = []
    for row in profile_results:
        trials = row['trials']
        summary = medians(trials)
        if (summary.get('complete') is True
                and all(trial.get('workers') == 4 for trial in trials)
                and summary['generation_max_ns'] <= GENERATION_MAX_NS
                and summary['proof_bytes_max'] <= ECONOMICS_PROOF_MAX):
            eligible.append((row, summary))
    return min(eligible, key=lambda entry: (entry[1]['proof_bytes_max'],
        entry[1]['generation_median_ns'], entry[0]['parameters']['log_blowup'],
        entry[0]['parameters']['query_pow_bits']))[0] if eligible else None


def economics_candidate_measurements(grids, trial):
    """Measure pending revised relations without changing the prior wallet scan."""
    profile_results = []
    for coordinate in WALLET_FAST_GRID:
        profile = grids['transaction'][coordinate]
        if profile is None:
            profile_results.append({'coordinate': {'log_blowup': coordinate[0],
                'grinding': coordinate[1]}, 'parameters': None, 'security': None,
                'trials': [], 'summary': {'complete': False, 'trial_count': 0},
                'reason': 'no-security-passing-profile'})
            continue
        rows = [trial('transaction', profile, 4, index) for index in range(1, 4)]
        profile_results.append({'coordinate': {'log_blowup': coordinate[0],
            'grinding': coordinate[1]}, 'parameters': profile['parameters'],
            'security': profile['security'], 'trials': rows, 'summary': medians(rows)})
    selected = choose_economics_candidate(profile_results)
    repeats = {}
    if selected is None:
        repeats['transaction'] = {'measured': False, 'reason': 'no-qualifying-profile'}
    else:
        rows = [trial('transaction', selected, 1, index) for index in range(1, 4)]
        repeats['transaction'] = {'measured': True, 'parameters': selected['parameters'],
            'security': selected['security'], 'workers': {
                '4': {'trials': selected['trials'], 'summary': selected['summary'],
                      'source': 'selected-grid-trials'},
                '1': {'trials': rows, 'summary': medians(rows)}}}
    for kind in ('settlement', 'issuance'):
        profile = grids[kind][(8, 20)]
        if profile is None:
            repeats[kind] = {'measured': False, 'reason': 'no-security-passing-profile'}
            continue
        groups = {}
        for workers in (4, 1):
            rows = [trial(kind, profile, workers, index) for index in range(1, 4)]
            groups[str(workers)] = {'trials': rows, 'summary': medians(rows)}
        repeats[kind] = {'measured': True, 'parameters': profile['parameters'],
            'security': profile['security'], 'workers': groups}
    return {'profile_results': profile_results, 'candidate_selected': selected is not None,
        'candidate_parameters': selected['parameters'] if selected else None,
        'candidate_security': selected['security'] if selected else None,
        'candidate_summary': selected['summary'] if selected else None,
        'candidate_rejected': selected is None, 'three_trial_target_met': selected is not None,
        'measurement_grid_complete': all(row['summary'].get('complete') for row in profile_results),
        'selected_transaction_single_worker_complete': selected is not None
            and repeats['transaction']['workers']['1']['summary'].get('complete') is True,
        'related_relation_measurements_complete': all(repeats[kind]['measured']
            and all(group['summary'].get('complete') is True
                    for group in repeats[kind]['workers'].values())
            for kind in ('settlement', 'issuance')),
        'repeated_measurements': repeats}


def collect(args):
    if args.output.exists():
        raise ValueError('Refusing to overwrite diagnostic evidence')
    args.output.mkdir(parents=True)
    screen = json.loads(args.screen.read_text())
    grids = {kind: profiles(screen, kind) for kind in ('transaction', 'settlement', 'issuance')}
    scan_mode = getattr(args, 'scan_mode', 'legacy')
    hardware_profile = getattr(args, 'hardware_profile', 'diagnostic')
    if scan_mode == 'wallet-fast' and hardware_profile != 'epyc7763-baseline':
        raise ValueError('Wallet-fast scan requires the EPYC 7763 baseline profile')
    if scan_mode == 'economics-candidate' and hardware_profile not in (
            'epyc7763-baseline', 'epyc9v45-control'):
        raise ValueError('Economic-relation scan requires the EPYC 7763 baseline or explicit EPYC 9V45 control profile')
    hardware_record = qualify_and_record(args.output, hardware_profile)
    if hardware_record is None:
        return 1
    executable = args.executable.resolve(strict=True)
    worker = args.worker.resolve(strict=True)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if not re.fullmatch('[a-f0-9]{40}', commit):
        raise ValueError('Invalid source commit')
    identity = {'air_source_sha256': screen['air_source_sha256'],
        'dependencies_sha256': screen['dependencies_sha256'], 'binary_sha256': sha(worker)}
    outcomes = []
    scopes_valid = True
    with tempfile.TemporaryDirectory(prefix='multi-asset-private-', dir=args.private_parent) as temporary:
        private = Path(temporary)

        def trial(kind, profile, workers, index):
            nonlocal scopes_valid
            unit = 'siworld-native-' + uuid.uuid4().hex + '.scope'
            stem = f'{kind}-b{profile["parameters"]["log_blowup"]}-g{profile["parameters"]["query_pow_bits"]}-w{workers}-{len(outcomes)}'
            config = {'uid': os.getuid(), 'gid': os.getgid(), 'unit': unit,
                'kind': kind, 'parameters': profile['parameters'], 'workers': workers,
                'trial': index, 'timeout': args.timeout, 'executable': str(executable),
                'hardware_profile': hardware_profile,
                'private_output': str(private / (stem + '-raw.json')),
                'private_log': str(private / (stem + '.log')),
                'result': str(private / (stem + '-result.json')), **identity}
            if scan_mode == 'economics-candidate':
                config['scan_mode'] = scan_mode
            config_path = private / (stem + '-config.json')
            write_json(config_path, config)
            completed = subprocess.run(scope_command(unit, config_path),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                timeout=args.timeout + 30, check=False)
            result_path = Path(config['result'])
            if result_path.is_file():
                result = json.loads(result_path.read_text())
            else:
                scopes_valid = False
                result = {'kind': kind, 'workers': workers, 'trial': index,
                    'parameters': profile['parameters'], 'resource_control_pass': False,
                    'proof_report_valid': False,
                    'failure': CG.startup_diagnostic(completed.stdout), 'acceptance': False}
            result['scope_exit_code'] = completed.returncode
            if completed.returncode != 0:
                result['resource_control_pass'] = False
                scopes_valid = False
            outcomes.append(result)
            return result

        if scan_mode == 'wallet-fast':
            profile_results = []
            for coordinate in WALLET_FAST_GRID:
                profile = grids['transaction'][coordinate]
                if profile is None:
                    profile_results.append({'coordinate': {'log_blowup': coordinate[0],
                        'grinding': coordinate[1]}, 'parameters': None, 'security': None,
                        'trials': [], 'summary': {'complete': False, 'trial_count': 0},
                        'reason': 'no-security-passing-profile'})
                    continue
                rows = [trial('transaction', profile, 4, index) for index in range(1, 4)]
                profile_results.append({'coordinate': {'log_blowup': coordinate[0],
                    'grinding': coordinate[1]}, 'parameters': profile['parameters'],
                    'security': profile['security'], 'trials': rows, 'summary': medians(rows)})
            selected = choose_wallet_fast(profile_results)
            summary = {'schema': 2, 'suite': SUITE, 'source_commit': commit,
                'diagnostic_binary': 'native-scan', 'local_guard_alias': 'v1-transaction-scan',
                'launcher_sha256': sha(executable), **identity,
                'hardware': hardware_record, 'hardware_profile': hardware_profile,
                'memory_max_bytes': MEMORY_MAX, 'memory_swap_max_bytes': 0,
                'memory_boundary_is_miner_requirement': False,
                'scan_mode': scan_mode, 'trial_count_per_profile': 3,
                'rayon_workers': 4, 'hiding_workers': 2,
                'selection_scope': 'all three four-worker generation trials at or below two seconds; smallest maximum measured proof body',
                'legacy_524288_byte_cap_applied': False,
                'generation_limit_ns': GENERATION_MAX_NS,
                'profile_results': profile_results, 'candidate_selected': selected is not None,
                'candidate_parameters': selected['parameters'] if selected else None,
                'three_trial_target_met': selected is not None,
                'candidate_rejected': selected is None,
                'candidate_security': selected['security'] if selected else None,
                'candidate_summary': selected['summary'] if selected else None,
                'measurement_grid_complete': all(row['summary'].get('complete') for row in profile_results),
                'scope_startup_complete': scopes_valid,
                'proof_size_scope': 'observed serialized proof bodies; no deterministic maximum-length claim',
                'verification_measurement': 'four-worker process verifier timing; not a single-worker verification benchmark',
                'cryptographic_approval': False, 'network_activation': False, 'acceptance': False}
            write_json(args.output / 'summary.json', summary)
            return 0 if scopes_valid and summary['measurement_grid_complete'] else 1

        if scan_mode == 'economics-candidate':
            measured = economics_candidate_measurements(grids, trial)
            complete = (scopes_valid and measured['measurement_grid_complete']
                and measured['selected_transaction_single_worker_complete']
                and measured['related_relation_measurements_complete'])
            baseline_eligible = hardware_profile == 'epyc7763-baseline'
            summary = {'schema': 3,
                'status': 'candidate-pending-review' if baseline_eligible else 'control-diagnostic-only',
                'baseline_eligible': baseline_eligible,
                'suite': SUITE, 'source_commit': commit,
                'diagnostic_binary': 'native-scan', 'local_guard_alias': 'v1-transaction-scan',
                'launcher_sha256': sha(executable), **identity,
                'hardware': hardware_record, 'hardware_profile': hardware_profile,
                'memory_max_bytes': MEMORY_MAX, 'memory_swap_max_bytes': 0,
                'memory_boundary_is_miner_requirement': False,
                'scan_mode': scan_mode, 'trial_count_per_profile': 3,
                'grid_rayon_workers': 4, 'grid_hiding_workers': 2,
                'single_worker_hiding_workers': 1,
                'selection_scope': 'all three four-worker generation trials at or below two seconds and 655360 bytes; smallest maximum measured proof body',
                'proof_body_limit_bytes': ECONOMICS_PROOF_MAX,
                'generation_limit_ns': GENERATION_MAX_NS,
                'legacy_524288_byte_cap_applied': False,
                'related_relation_coordinate': {'log_blowup': 8, 'grinding': 20},
                **measured, 'scope_startup_complete': scopes_valid,
                'all_measurements_complete': complete,
                'proof_size_scope': 'observed serialized proof bodies; no deterministic maximum-length claim',
                'memory_scope': 'whole fresh setup/prove/verify process tree plus recorder',
                'verification_only_process': False,
                'verification_measurement': 'single-worker verifier timing inside a one-worker setup/prove/verify process; memory includes all three phases; not an independent verifier memory measurement',
                'cryptographic_approval': False, 'network_activation': False, 'acceptance': False}
            write_json(args.output / 'summary.json', summary)
            return 0 if complete else 1

        coordinates = GRID if args.grid_mode == 'full' else tuple((8, g) for g in (16, 20, 24))
        grid = []
        for coordinate in coordinates:
            profile = grids['transaction'][coordinate]
            if profile is not None:
                grid.append(trial('transaction', profile, 4, 1))
        selected = choose(grid)
        fallback_attempted = selected is None
        fallback_trials = []
        if selected is None:
            for coordinate in FALLBACK_GRID:
                profile = grids['transaction'].get(coordinate)
                if profile is not None:
                    fallback_trials.append(trial('transaction', profile, 4, 1))
            selected = choose(fallback_trials)
        diagnostic = selected or diagnostic_choice(grid + fallback_trials)
        repeats = {}
        for kind in ('transaction', 'settlement', 'issuance'):
            profile = ({'parameters': diagnostic['parameters']} if diagnostic else None) if kind == 'transaction' else grids[kind][(8, 20)]
            if profile is None:
                repeats[kind] = {'measured': False, 'reason': 'no-qualifying-profile'}
                continue
            groups = {}
            for workers in (4, 1):
                rows = [trial(kind, profile, workers, index) for index in range(1, 4)]
                groups[str(workers)] = {'trials': rows, 'summary': medians(rows)}
            repeats[kind] = {'measured': True, 'parameters': profile['parameters'], 'workers': groups}
        repeated_ok = False
        if selected is not None:
            repeated = repeats['transaction']['workers']['4']['summary']
            repeated_ok = (repeated.get('complete') is True
                and repeated['generation_median_ns'] <= GENERATION_MAX_NS
                and repeated['proof_bytes_max'] <= PROOF_MAX)
        diagnostic_reason = ('no-valid-measurement' if diagnostic is None else
            'proof-cap-exceeded' if diagnostic['measurement']['proof_bytes'] > PROOF_MAX else
            'generation-budget-exceeded' if diagnostic['measurement']['generation_ns'] > GENERATION_MAX_NS else
            'repeated-targets-not-met' if not repeated_ok else 'targets-met-in-diagnostic-trials')
        summary = {'schema': 1, 'suite': SUITE, 'source_commit': commit,
            'diagnostic_binary': 'native-scan', 'local_guard_alias': 'v1-transaction-scan',
            'launcher_sha256': sha(executable), **identity,
            'hardware': hardware_record, 'memory_max_bytes': MEMORY_MAX, 'memory_swap_max_bytes': 0,
            'memory_boundary_is_miner_requirement': False,
            'grid_mode': args.grid_mode, 'complete_transaction_grid': args.grid_mode == 'full',
            'selection_scope': 'one four-worker screening trial per passing grid coordinate',
            'screened_profiles': {kind: [dict(coordinate={'log_blowup': key[0], 'grinding': key[1]}, **value)
                if value is not None else {'coordinate': {'log_blowup': key[0], 'grinding': key[1]}, 'passes': False}
                for key, value in values.items()] for kind, values in grids.items()},
            'grid_trials': grid, 'fallback_larger_blowup_attempted': fallback_attempted,
            'fallback_grid_trials': fallback_trials, 'candidate_selected': selected is not None,
            'candidate_parameters': selected['parameters'] if selected else None,
            'candidate_rejected': not repeated_ok, 'three_trial_target_met': repeated_ok,
            'diagnostic_transaction_parameters': diagnostic['parameters'] if diagnostic else None,
            'diagnostic_transaction_reason': diagnostic_reason,
            'repeated_measurements': repeats, 'scope_startup_complete': scopes_valid,
            'verification_measurement': 'one-worker verifier timing inside a one-worker setup/prove/verify process; memory includes all three phases',
            'cryptographic_approval': False, 'network_activation': False, 'acceptance': False}
        write_json(args.output / 'summary.json', summary)
    return 0 if scopes_valid else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker-config', type=Path)
    parser.add_argument('--executable', type=Path)
    parser.add_argument('--worker', type=Path)
    parser.add_argument('--screen', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--private-parent', type=Path)
    parser.add_argument('--scan-mode', choices=('legacy', 'wallet-fast', 'economics-candidate'), default='legacy')
    parser.add_argument('--hardware-profile', choices=HARDWARE_PROFILES, default='diagnostic')
    parser.add_argument('--qualify-only', action='store_true')
    parser.add_argument('--grid-mode', choices=('full', 'b8-only'), default='full')
    parser.add_argument('--timeout', type=int, default=600)
    args = parser.parse_args()
    if args.worker_config:
        return record(json.loads(args.worker_config.read_text()))
    if args.qualify_only:
        if not args.output:
            parser.error('output is required for qualification')
        args.output.mkdir(parents=True, exist_ok=False)
        return 0 if qualify_and_record(args.output, args.hardware_profile) else 1
    if not all((args.executable, args.worker, args.screen, args.output)) or args.timeout < 1:
        parser.error('executable, worker, screen, output and positive timeout are required')
    return collect(args)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        # Never echo private paths or child stderr into an uploaded result.
        print(json.dumps({'event': 'multi-asset-diagnostic-failed', 'classification': type(error).__name__}), file=sys.stderr)
        raise SystemExit(1)
