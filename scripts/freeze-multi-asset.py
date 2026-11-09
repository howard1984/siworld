#!/usr/bin/env python3
"""Create or check a source-bound multi-asset engineering profile.

Only allowlisted technical measurements are published. This profile records an
engineering choice; it does not assert cryptographic approval or activation.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SUITE = 'KoalaBear-D8-Poseidon2-W24-digest12'
DEPENDENCY_REVISION = 'd3d15b2b5d1325fb38ebc8979c1cae04b761e71f'
GENERATION_MAX_NS = 2_000_000_000
MEMORY_MAX = 5_368_709_120
ECONOMICS_PROOF_MAX = 655_360
GRID = tuple((b, g) for b in range(5, 9) for g in (20, 24))
RELATION_SOURCES = tuple('crates/bench-multi-asset/src/' + name + '.rs' for name in (
    'multi_asset', 'multi_asset_air', 'multi_asset_trace', 'multi_asset_transaction',
    'codec', 'encryption', 'settlement', 'issuance', 'issuance_air', 'security'))
FIXED_SOURCES = frozenset((
    '.cargo/config.toml', 'rust-toolchain.toml',
    'crates/bench-multi-asset/Cargo.toml', 'crates/bench-multi-asset/Cargo.lock',
    'crates/bench-d8/Cargo.toml', 'crates/bench-d8/Cargo.lock',
    'scripts/freeze-multi-asset.py', 'scripts/measure-multi-asset.py',
    'scripts/measure-native-cgroup.py', 'scripts/measure-proof-cgroup.py',
    'scripts/prover-launcher.rs', 'scripts/check-prover-isa.py',
    'scripts/build-composition-intra.py', '.github/workflows/multi-asset-native.yml'))
OFFLINE_TOOLS = frozenset(('scripts/freeze-multi-asset.py',
    'crates/bench-multi-asset/src/bin/profile-artifacts.rs'))
ECONOMICS_FIXED_SOURCES = frozenset(('scripts/v1-economics-candidate.py',
    'scripts/native-proof-artifacts.rs', '.github/workflows/v1-economics.yml'))

TOP_KEYS = frozenset('''schema status suite cryptographic_approval network_activation
    dependency_revision measured_source_commit air_source_sha256 dependencies_sha256
    measurement_binary_sha256 measurement_launcher_sha256 source_sha256 measured_source_sha256 reference_execution
    generation_limit_ns selection_rule parameters selected_security public_verifier_key
    max_leaf_proof_bytes max_settlement_proof_bytes max_issuance_proof_bytes proof_cap_policy
    proof_size_scope measurement_memory_scope diagnostic_memory_max_bytes
    memory_boundary_is_miner_requirement public_transaction_bytes permanent_position_bytes profiles'''.split())
PROFILE_KEYS = frozenset('''coordinate parameters security generation_ns generation_median_ns
    generation_max_ns proof_bytes proof_bytes_min proof_bytes_max cgroup_peak_bytes
    cgroup_peak_max_bytes memory_events_delta'''.split())


def module(filename):
    spec = importlib.util.spec_from_file_location(filename.replace('-', '_'), ROOT / 'scripts' / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


MEASUREMENT = module('measure-multi-asset.py')
HARDWARE = module('measure-proof-cgroup.py')
RELOCATIONS = module('frozen-source-relocations.py')


def digest(value):
    if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{64}', value):
        raise ValueError('Invalid SHA-256 content identity')
    return value


def positive(value):
    if type(value) is not int or value <= 0:
        raise ValueError('Positive integer measurement required')
    return value


def source_bytes(root, name):
    path = root / name
    if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError('Frozen source escapes repository root')
    return path.read_bytes()


def source_paths(root, revision=1):
    paths = set(FIXED_SOURCES)
    if revision == 2:
        paths.update(ECONOMICS_FIXED_SOURCES)
    for crate in ('bench-d8', 'bench-multi-asset'):
        paths.update(str(path.relative_to(root)) for path in (root / 'crates' / crate / 'src').rglob('*.rs')
                     if 'experiments' not in path.relative_to(root / 'crates' / crate / 'src').parts)
    return sorted(paths)


def source_hashes(root, revision=1):
    return {name: hashlib.sha256(source_bytes(root, name)).hexdigest() for name in source_paths(root, revision)}


def measured_path(name, revision=1):
    if name in FIXED_SOURCES or (revision == 2 and name in ECONOMICS_FIXED_SOURCES):
        return True
    for crate in ('bench-d8', 'bench-multi-asset'):
        prefix = 'crates/' + crate + '/src/'
        if name.startswith(prefix) and name.endswith('.rs'):
            return 'experiments' not in Path(name[len(prefix):]).parts
    return False


def measured_source_hashes(root, commit, revision=1):
    """Compare the runtime/build boundary with immutable measured Git blobs."""
    try:
        listed = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', commit],
            cwd=root, stderr=subprocess.DEVNULL).decode().splitlines()
        recorded = {name: path for name, path in RELOCATIONS.canonical_sources(listed).items()
                    if measured_path(name, revision)}
        measured = set(recorded)
        current = set(source_paths(root, revision))
        # Only these offline tools may be added after the measurement commit.
        allowed_new = OFFLINE_TOOLS - measured
        if not measured or current - allowed_new != measured:
            raise ValueError('Runtime/build source set differs from measured commit')
        result = {}
        for name in sorted(measured):
            data = subprocess.check_output(['git', 'show', commit + ':' + recorded[name]],
                cwd=root, stderr=subprocess.DEVNULL)
            expected = hashlib.sha256(data).hexdigest()
            if not RELOCATIONS.matches(root, name, source_bytes(root, name), expected):
                raise ValueError('Runtime/build source differs from measured commit')
            result[name] = expected
        return result
    except (subprocess.SubprocessError, UnicodeError) as error:
        raise ValueError('Measured commit source blobs are unavailable') from error


def validate_measured_sources(value, root, revision=1):
    measured = value.get('measured_source_sha256')
    if not isinstance(measured, dict):
        raise ValueError('Missing measured runtime/build source boundary')
    current = set(source_paths(root, revision))
    if set(measured) != current - (OFFLINE_TOOLS - set(measured)):
        raise ValueError('Measured runtime/build source boundary changed')
    for name, expected in measured.items():
        if not RELOCATIONS.matches(root, name, source_bytes(root, name), digest(expected)):
            raise ValueError('Runtime/build source differs from frozen measurement')


def relation_hash(root):
    parts = []
    for name in RELATION_SOURCES:
        data = source_bytes(root, name)
        parts.extend((len(data).to_bytes(8, 'little'), data))
    return hashlib.sha256(b''.join(parts)).hexdigest()


def proof_cap(maximum):
    with_margin = (positive(maximum) * 110 + 99) // 100
    return ((with_margin + 65535) // 65536) * 65536


def check_parameters(value, coordinate):
    if not isinstance(value, dict) or set(value) != set(MEASUREMENT.PARAMETER_KEYS):
        raise ValueError('Incomplete FRI profile')
    if any(type(number) is not int for number in value.values()):
        raise ValueError('FRI parameters must be integers')
    b, g = coordinate
    if (value['log_blowup'] != b or value['query_pow_bits'] != g or value['batch_pow_bits'] != g
            or value['commit_pow_bits'] != 0 or value['max_log_arity'] != 1
            or value['log_final_poly_len'] != 0 or not 1 <= value['num_queries'] <= 128):
        raise ValueError('Unexpected FRI profile')
    return dict(value)


def checked_security(value):
    # The sanitized collector form intentionally omits the already-checked shape status.
    expanded = {**value, 'shape': {'status': 'actual-extracted', **value.get('shape', {})}}
    result = MEASUREMENT.security_summary(expanded)
    if not result['screen']['passes_selected_model']:
        raise ValueError('Actual AIR security screen did not pass')
    return result


def clean_profile(entry):
    coordinate = entry['coordinate']
    pair = (coordinate['log_blowup'], coordinate['grinding'])
    if pair not in GRID:
        raise ValueError('Unexpected scan coordinate')
    parameters = check_parameters(entry['parameters'], pair)
    security = checked_security(entry['security'])
    trials = entry['trials']
    if len(trials) != 3 or {row.get('trial') for row in trials} != {1, 2, 3}:
        raise ValueError('Exactly three distinct trials per profile required')
    times, sizes, peaks = [], [], []
    for row in sorted(trials, key=lambda trial: trial['trial']):
        if (row.get('kind') != 'transaction' or row.get('workers') != 4
                or row.get('verification_workers') != 4 or row.get('parameters') != parameters
                or row.get('hardware_profile') != 'epyc7763-baseline'
                or row.get('resource_control_pass') is not True or row.get('proof_report_valid') is not True
                or row.get('scope_exit_code') != 0 or row.get('exit_code') != 0
                or row.get('timed_out') is not False or row.get('remaining_descendants_at_exit') != 0
                or row.get('memory_max_bytes') != MEMORY_MAX or row.get('memory_swap_max_bytes') != 0
                or row.get('cryptographic_approval') is not False or row.get('network_activation') is not False
                or row.get('acceptance') is not False):
            raise ValueError('Invalid or incomplete transaction measurement')
        events = row.get('memory_events_delta')
        if (not isinstance(events, dict) or not {'max', 'oom', 'oom_kill', 'oom_group_kill'}.issubset(events)
                or any(type(number) is not int or number != 0 for number in events.values())):
            raise ValueError('Kernel memory events must remain zero')
        for counter in ('memory_events_before', 'memory_events_after'):
            value = row.get(counter)
            if (not isinstance(value, dict) or set(value) != set(events)
                    or any(type(number) is not int or number < 0 for number in value.values())):
                raise ValueError('Incomplete kernel event counters')
        if row['memory_events_before'] != row['memory_events_after']:
            raise ValueError('Kernel event counter evidence is inconsistent')
        limits = row.get('visible_cpu_limits')
        if not isinstance(limits, list) or not limits:
            raise ValueError('Missing inherited CPU limit evidence')
        for limit in limits:
            actual = HARDWARE.parse_cpu_max(limit['cpu_max']) if limit.get('cpu_max') else None
            if actual and actual['quota_cores'] is not None and actual['quota_cores'] < 4:
                raise ValueError('CPU quota below four cores')
            if limit.get('quota_cores') != (actual['quota_cores'] if actual else None):
                raise ValueError('Inconsistent CPU quota evidence')
        data = row['measurement']
        if data.get('public_transaction_bytes') != 2027 or data.get('permanent_position_bytes') != 2115:
            raise ValueError('Unexpected multi-asset public encoding')
        times.append(positive(data['generation_ns']))
        sizes.append(positive(data['proof_bytes']))
        peak = positive(row['memory_peak_bytes'])
        if peak > MEMORY_MAX:
            raise ValueError('Measurement exceeded diagnostic memory boundary')
        peaks.append(peak)
    return {'coordinate': {'log_blowup': pair[0], 'grinding': pair[1]},
        'parameters': parameters, 'security': security, 'generation_ns': times,
        'generation_median_ns': sorted(times)[1], 'generation_max_ns': max(times),
        'proof_bytes': sizes, 'proof_bytes_min': min(sizes), 'proof_bytes_max': max(sizes),
        'cgroup_peak_bytes': peaks, 'cgroup_peak_max_bytes': max(peaks),
        'memory_events_delta': {'max': 0, 'oom': 0, 'oom_kill': 0, 'oom_group_kill': 0}}


def selection(profiles):
    passing = [row for row in profiles if row['generation_max_ns'] <= GENERATION_MAX_NS]
    if not passing:
        raise ValueError('No profile meets all three two-second generation trials')
    return min(passing, key=lambda row: (row['proof_bytes_max'], row['generation_median_ns'],
        row['parameters']['log_blowup'], row['parameters']['query_pow_bits']))


def verifier_key(value, parameters, security):
    if (value.get('schema') != 1 or value.get('suite') != SUITE or value.get('kind') != 'transaction'
            or value.get('parameters') != parameters):
        raise ValueError('Public verifier profile differs from selected transaction parameters')
    report = value['security']
    if report.get('fri') != parameters or checked_security(report) != security:
        raise ValueError('Public verifier security report differs from selected actual AIR')
    key = value['public_verifier_key']
    if key.get('encoding') != 'SWMV-v1' or not isinstance(key.get('hex'), str):
        raise ValueError('Unexpected public verifier encoding')
    if not re.fullmatch('[a-f0-9]{86,8278}', key['hex']) or len(key['hex']) % 2:
        raise ValueError('Invalid public verifier bytes')
    raw = bytes.fromhex(key['hex'])
    if raw[:7] != b'SWMV\x01\x00\x01' or hashlib.sha256(raw).hexdigest() != digest(key['sha256']):
        raise ValueError('Public verifier header or content hash mismatch')
    fields = [int.from_bytes(raw[offset:offset+4], 'little') for offset in range(7, 43, 4)]
    expected = [parameters[name] for name in ('log_blowup', 'num_queries', 'query_pow_bits',
                'commit_pow_bits', 'batch_pow_bits', 'max_log_arity')]
    width, degree, length = fields[6:]
    if fields[:6] != expected or length != len(raw) - 43 or length <= 0:
        raise ValueError('Public verifier parameter or commitment length mismatch')
    if (key.get('width') != width or key.get('degree_bits') != degree
            or width != security['shape']['preprocessed_width'] or not 0 <= degree <= 32
            or 1 << degree != 2 * security['shape']['base_trace_rows']):
        raise ValueError('Public verifier shape differs from selected AIR')
    return {'encoding': 'SWMV-v1', 'hex': key['hex'], 'sha256': key['sha256'],
        'width': width, 'degree_bits': degree}


def create_wallet_fast(summary, public_verifier, root=ROOT):
    if (summary.get('schema') != 2 or summary.get('suite') != SUITE
            or summary.get('scan_mode') != 'wallet-fast' or summary.get('hardware_profile') != 'epyc7763-baseline'
            or summary.get('rayon_workers') != 4 or summary.get('hiding_workers') != 2
            or summary.get('trial_count_per_profile') != 3 or summary.get('measurement_grid_complete') is not True
            or summary.get('scope_startup_complete') is not True
            or summary.get('candidate_selected') is not True or summary.get('candidate_rejected') is not False
            or summary.get('three_trial_target_met') is not True
            or summary.get('legacy_524288_byte_cap_applied') is not False
            or summary.get('cryptographic_approval') is not False or summary.get('network_activation') is not False
            or summary.get('acceptance') is not False):
        raise ValueError('Complete qualified wallet-fast diagnostics required')
    if summary.get('memory_max_bytes') != MEMORY_MAX or summary.get('memory_swap_max_bytes') != 0:
        raise ValueError('Unexpected diagnostic memory boundary')
    hardware = summary['hardware']
    if hardware.get('required_hardware_profile') != 'epyc7763-baseline' or hardware.get('profile_qualified') is not True:
        raise ValueError('Baseline hardware was not qualified')
    HARDWARE.qualify_hardware_profile(hardware['hardware'], 'epyc7763-baseline')
    model = 'AMD EPYC 7763'
    if not isinstance(summary.get('source_commit'), str) or not re.fullmatch('[a-f0-9]{40}', summary['source_commit']):
        raise ValueError('Invalid measured source commit')
    measured_sources = measured_source_hashes(root, summary['source_commit'])
    air_hash = digest(summary['air_source_sha256'])
    dependency_hash = digest(summary['dependencies_sha256'])
    if air_hash != relation_hash(root) or dependency_hash != hashlib.sha256(source_bytes(root, 'crates/bench-multi-asset/Cargo.lock')).hexdigest():
        raise ValueError('Measurement relation or dependency differs from current source')
    profiles = [clean_profile(row) for row in summary['profile_results']]
    coordinates = [(row['coordinate']['log_blowup'], row['coordinate']['grinding']) for row in profiles]
    if len(coordinates) != 8 or set(coordinates) != set(GRID):
        raise ValueError('Exactly eight unique measured profiles required')
    profiles.sort(key=lambda row: (row['coordinate']['log_blowup'], row['coordinate']['grinding']))
    selected = selection(profiles)
    if summary['candidate_parameters'] != selected['parameters'] or checked_security(summary['candidate_security']) != selected['security']:
        raise ValueError('Collector candidate differs from independently recomputed choice')
    if summary['candidate_summary'].get('proof_bytes_max') != selected['proof_bytes_max']:
        raise ValueError('Collector candidate proof range is inconsistent')
    result = {'schema': 1, 'status': 'engineering-frozen', 'suite': SUITE,
        'cryptographic_approval': False, 'network_activation': False,
        'dependency_revision': DEPENDENCY_REVISION,
        'measured_source_commit': summary['source_commit'], 'air_source_sha256': air_hash,
        'dependencies_sha256': dependency_hash,
        'measurement_binary_sha256': digest(summary['binary_sha256']),
        'measurement_launcher_sha256': digest(summary['launcher_sha256']),
        'source_sha256': source_hashes(root), 'measured_source_sha256': measured_sources,
        'reference_execution': {'cpu_model': model, 'os': 'Ubuntu 24.04',
            'architecture': 'x86_64', 'exposed_cores': 2, 'exposed_vcpus': 4,
            'rayon_workers': 4, 'hiding_workers': 2, 'required_isa': 'x86-64-v3'},
        'generation_limit_ns': GENERATION_MAX_NS,
        'selection_rule': 'all-three-trials-within-limit-then-smallest-maximum-observed-proof',
        'parameters': selected['parameters'], 'selected_security': selected['security'],
        'public_verifier_key': verifier_key(public_verifier, selected['parameters'], selected['security']),
        'max_leaf_proof_bytes': proof_cap(selected['proof_bytes_max']),
        'max_settlement_proof_bytes': 524288, 'max_issuance_proof_bytes': 524288,
        'proof_cap_policy': 'at-least-ten-percent-above-observed-maximum-rounded-up-to-65536-bytes',
        'proof_size_scope': 'observed synthetic proof bodies; admission cap is not a mathematical size bound',
        'measurement_memory_scope': 'whole setup-prove-verify process tree including recorder',
        'diagnostic_memory_max_bytes': MEMORY_MAX,
        'memory_boundary_is_miner_requirement': False,
        'public_transaction_bytes': 2027, 'permanent_position_bytes': 2115,
        'profiles': profiles}
    return result


def validate_wallet_fast(value, root=ROOT):
    if set(value) != TOP_KEYS:
        raise ValueError('Unexpected public engineering profile fields')
    if (value.get('schema') != 1 or value.get('status') != 'engineering-frozen' or value.get('suite') != SUITE
            or value.get('cryptographic_approval') is not False or value.get('network_activation') is not False
            or value.get('dependency_revision') != DEPENDENCY_REVISION):
        raise ValueError('Invalid multi-asset engineering profile identity')
    validate_measured_sources(value, root)
    if not RELOCATIONS.mapping_matches(root, value.get('source_sha256'), source_paths(root), source_bytes):
        raise ValueError('Frozen implementation or source boundary changed')
    if value.get('air_source_sha256') != relation_hash(root):
        raise ValueError('Frozen AIR relation identity changed')
    if not RELOCATIONS.matches(root, 'crates/bench-multi-asset/Cargo.lock', source_bytes(root, 'crates/bench-multi-asset/Cargo.lock'), value.get('dependencies_sha256')):
        raise ValueError('Frozen dependency lock changed')
    profiles = value['profiles']
    if len(profiles) != 8 or {(row['coordinate']['log_blowup'], row['coordinate']['grinding']) for row in profiles} != set(GRID):
        raise ValueError('Frozen profile grid is incomplete')
    for row in profiles:
        if set(row) != PROFILE_KEYS or set(row['coordinate']) != {'log_blowup', 'grinding'}:
            raise ValueError('Unexpected public measurement fields')
        check_parameters(row['parameters'], (row['coordinate']['log_blowup'], row['coordinate']['grinding']))
        if checked_security(row['security']) != row['security']:
            raise ValueError('Unexpected security fields')
        for field in ('generation_ns', 'proof_bytes', 'cgroup_peak_bytes'):
            if len(row[field]) != 3 or any(type(number) is not int or number <= 0 for number in row[field]):
                raise ValueError('Invalid frozen three-trial measurements')
        expected = {'generation_median_ns': sorted(row['generation_ns'])[1],
            'generation_max_ns': max(row['generation_ns']), 'proof_bytes_min': min(row['proof_bytes']),
            'proof_bytes_max': max(row['proof_bytes']), 'cgroup_peak_max_bytes': max(row['cgroup_peak_bytes'])}
        if any(row.get(key) != expected_value for key, expected_value in expected.items()):
            raise ValueError('Frozen measurement summary is inconsistent')
        if row['cgroup_peak_max_bytes'] > MEMORY_MAX or row['memory_events_delta'] != {'max': 0, 'oom': 0, 'oom_kill': 0, 'oom_group_kill': 0}:
            raise ValueError('Frozen kernel memory evidence is inconsistent')
    selected = selection(profiles)
    if value.get('parameters') != selected['parameters'] or value.get('selected_security') != selected['security']:
        raise ValueError('Frozen selected profile is inconsistent')
    if (value.get('max_leaf_proof_bytes') != proof_cap(selected['proof_bytes_max'])
            or value.get('max_settlement_proof_bytes') != 524288 or value.get('max_issuance_proof_bytes') != 524288):
        raise ValueError('Frozen proof admission cap is inconsistent')
    digest(value['measurement_binary_sha256']); digest(value['measurement_launcher_sha256'])
    if not isinstance(value.get('measured_source_commit'), str) or not re.fullmatch('[a-f0-9]{40}', value['measured_source_commit']):
        raise ValueError('Invalid measured source commit')
    expected_reference = {'cpu_model': 'AMD EPYC 7763', 'os': 'Ubuntu 24.04',
        'architecture': 'x86_64', 'exposed_cores': 2, 'exposed_vcpus': 4,
        'rayon_workers': 4, 'hiding_workers': 2, 'required_isa': 'x86-64-v3'}
    if value.get('reference_execution') != expected_reference:
        raise ValueError('Unexpected reference execution profile')
    for name, expected in {'generation_limit_ns': GENERATION_MAX_NS,
        'diagnostic_memory_max_bytes': MEMORY_MAX, 'memory_boundary_is_miner_requirement': False,
        'public_transaction_bytes': 2027, 'permanent_position_bytes': 2115,
        'selection_rule': 'all-three-trials-within-limit-then-smallest-maximum-observed-proof',
        'proof_cap_policy': 'at-least-ten-percent-above-observed-maximum-rounded-up-to-65536-bytes',
        'proof_size_scope': 'observed synthetic proof bodies; admission cap is not a mathematical size bound',
        'measurement_memory_scope': 'whole setup-prove-verify process tree including recorder'}.items():
        if value.get(name) != expected:
            raise ValueError('Frozen measurement policy differs')
    full_security = {**value['selected_security'], 'fri': value['parameters']}
    public = {'schema': 1, 'suite': SUITE, 'kind': 'transaction', 'parameters': value['parameters'],
        'security': full_security, 'public_verifier_key': value['public_verifier_key']}
    if verifier_key(public, value['parameters'], value['selected_security']) != value['public_verifier_key']:
        raise ValueError('Unexpected public verifier fields')
    return value


ECONOMICS_TOP_KEYS = TOP_KEYS | frozenset(('relation_revision', 'measurement_schema',
    'proof_body_limit_bytes', 'selected_transaction_proof_bytes_max', 'repeated_measurements',
    'verification_measurement', 'verification_only_process', 'hardware_qualification', 'acceptance'))
ECONOMICS_PROFILE_KEYS = PROFILE_KEYS | frozenset(('kernel_trials',))
ECONOMICS_VERIFICATION = ('single-worker verifier timing inside a one-worker setup/prove/verify process; '
    'memory includes all three phases; not an independent verifier memory measurement')
ECONOMICS_HARDWARE_KEYS = ('cpu_model', 'os', 'architecture', 'avx2', 'logical_cpus',
    'online_logical_cpus', 'exposed_physical_cores', 'affinity_cpus', 'virtualization_detection')
ECONOMICS_REQUIRED_MEMORY_EVENTS = frozenset(('low', 'high', 'max', 'oom',
    'oom_kill', 'oom_group_kill'))
ECONOMICS_OPTIONAL_MEMORY_EVENTS = frozenset(('sock_throttled',))


def economic_trial(row, kind, workers, parameters):
    """Retain bounded kernel evidence without private process or cgroup paths."""
    expected = {'kind': kind, 'workers': workers, 'verification_workers': workers,
        'parameters': parameters, 'hardware_profile': 'epyc7763-baseline',
        'resource_control_pass': True, 'proof_report_valid': True, 'scope_exit_code': 0,
        'exit_code': 0, 'timed_out': False, 'remaining_descendants_at_exit': 0,
        'memory_max_bytes': MEMORY_MAX, 'memory_swap_max_bytes': 0,
        'memory_scope': 'whole fresh setup/prove/verify process tree plus recorder',
        'verification_only_process': False, 'cryptographic_approval': False,
        'network_activation': False, 'acceptance': False}
    if any(type(row.get(key)) is not type(value) or row.get(key) != value
           for key, value in expected.items()):
        raise ValueError('Invalid economic relation process or kernel outcome')
    trial_id = row.get('trial')
    if type(trial_id) is not int or trial_id not in (1, 2, 3):
        raise ValueError('Invalid distinct trial index')
    events = row.get('memory_events_delta')
    if (not isinstance(events, dict)
            or not ECONOMICS_REQUIRED_MEMORY_EVENTS.issubset(events)
            or not set(events).issubset(
                ECONOMICS_REQUIRED_MEMORY_EVENTS | ECONOMICS_OPTIONAL_MEMORY_EVENTS)
            or any(type(number) is not int or number != 0 for number in events.values())):
        raise ValueError('Kernel memory events must remain zero')
    for field in ('memory_events_before', 'memory_events_after'):
        if row.get(field) != events or any(type(number) is not int for number in row[field].values()):
            raise ValueError('Fresh scope counters must be consistent and zero')
    peak = positive(row['memory_peak_bytes'])
    if peak > MEMORY_MAX:
        raise ValueError('Measurement exceeded diagnostic memory boundary')
    limits = row.get('visible_cpu_limits')
    if not isinstance(limits, list) or not limits or not row.get('cpu_max'):
        raise ValueError('Missing inherited CPU limit evidence')
    cleaned_limits = []
    for index, limit in enumerate(limits):
        if type(limit.get('ancestor_level')) is not int or limit['ancestor_level'] != index:
            raise ValueError('Invalid inherited CPU limit order')
        actual = HARDWARE.parse_cpu_max(limit['cpu_max']) if limit.get('cpu_max') else None
        quota = actual['quota_cores'] if actual else None
        if quota is not None and quota < 4:
            raise ValueError('CPU quota below four cores')
        if limit.get('quota_cores') != quota:
            raise ValueError('Inconsistent CPU quota evidence')
        cleaned_limits.append({'ancestor_level': index, 'cpu_max': limit.get('cpu_max'), 'quota_cores': quota})
    if row['cpu_max'] != cleaned_limits[0]['cpu_max']:
        raise ValueError('Scope CPU limit differs from inherited evidence')
    data = row['measurement']
    measured = {name: positive(data[name]) for name in
        ('setup_ns', 'generation_ns', 'verification_ns', 'proof_bytes')}
    if kind == 'transaction':
        if data.get('public_transaction_bytes') != 2027 or data.get('permanent_position_bytes') != 2115:
            raise ValueError('Unexpected economic transaction public encoding')
        measured.update(public_transaction_bytes=2027, permanent_position_bytes=2115,
            proof_within_524288_bytes=measured['proof_bytes'] <= 524288)
    elif kind == 'settlement':
        if data.get('capacity') != 576 or data.get('reward_asset_constrained_si') is not True:
            raise ValueError('Unexpected economic settlement statement')
        measured.update(capacity=576, reward_asset_constrained_si=True)
    elif kind == 'issuance':
        if data.get('initial_notes') != 3 or data.get('actual_ml_dsa65_verification') is not True:
            raise ValueError('Unexpected economic issuance statement')
        measured.update(initial_notes=3, actual_ml_dsa65_verification=True,
            signed_record_bytes=positive(data['signed_record_bytes']),
            ciphertext_bytes=positive(data['ciphertext_bytes']))
    else:
        raise ValueError('Unknown economic relation')
    return {**expected, 'trial': trial_id,
        'measurement_scope_sha256': digest(row.get('measurement_scope_sha256')),
        'process_wall_ns': positive(row['process_wall_ns']),
        'process_cpu_ns': positive(row['process_cpu_ns']), 'memory_peak_bytes': peak,
        'memory_events_delta': dict(events), 'memory_events_before': dict(events),
        'memory_events_after': dict(events), 'cpu_max': row['cpu_max'],
        'visible_cpu_limits': cleaned_limits, 'measurement': measured}


def economic_trials(rows, kind, workers, parameters):
    if not isinstance(rows, list) or len(rows) != 3:
        raise ValueError('Exactly three economic relation trials required')
    result = [economic_trial(row, kind, workers, parameters) for row in rows]
    if {row['trial'] for row in result} != {1, 2, 3}:
        raise ValueError('Replayed economic relation trial index')
    return sorted(result, key=lambda row: row['trial'])


def economic_profile(entry):
    result = clean_profile(entry)
    rows = economic_trials(entry['trials'], 'transaction', 4, result['parameters'])
    if entry.get('summary') != MEASUREMENT.medians(rows):
        raise ValueError('Collector grid summary differs from kernel trials')
    return {**result, 'kernel_trials': rows}


def economic_selection(profiles):
    passing = [row for row in profiles if row['generation_max_ns'] <= GENERATION_MAX_NS
        and row['proof_bytes_max'] <= ECONOMICS_PROOF_MAX]
    if not passing:
        raise ValueError('No economic profile meets time and proof-length limits')
    return min(passing, key=lambda row: (row['proof_bytes_max'], row['generation_median_ns'],
        row['parameters']['log_blowup'], row['parameters']['query_pow_bits']))


def economic_summary(summary, require_admission_margin=True):
    """Recompute the complete remote selection before exporting or freezing it."""
    expected = {'schema': 3, 'status': 'candidate-pending-review', 'suite': SUITE,
        'scan_mode': 'economics-candidate', 'hardware_profile': 'epyc7763-baseline',
        'grid_rayon_workers': 4, 'grid_hiding_workers': 2, 'single_worker_hiding_workers': 1,
        'trial_count_per_profile': 3, 'measurement_grid_complete': True,
        'scope_startup_complete': True, 'selected_transaction_single_worker_complete': True,
        'related_relation_measurements_complete': True, 'all_measurements_complete': True,
        'candidate_selected': True, 'candidate_rejected': False, 'three_trial_target_met': True,
        'legacy_524288_byte_cap_applied': False, 'proof_body_limit_bytes': ECONOMICS_PROOF_MAX,
        'generation_limit_ns': GENERATION_MAX_NS, 'memory_max_bytes': MEMORY_MAX,
        'memory_swap_max_bytes': 0, 'verification_only_process': False,
        'cryptographic_approval': False, 'network_activation': False, 'acceptance': False}
    if any(type(summary.get(key)) is not type(value) or summary.get(key) != value
           for key, value in expected.items()):
        raise ValueError('Complete qualified economic-candidate diagnostics required')
    hardware = summary['hardware']
    if (hardware.get('required_hardware_profile') != 'epyc7763-baseline'
            or hardware.get('profile_qualified') is not True):
        raise ValueError('Baseline hardware was not qualified')
    HARDWARE.qualify_hardware_profile(hardware['hardware'], 'epyc7763-baseline')
    detection = hardware['hardware']['virtualization_detection']
    if not isinstance(detection.get('result'), str) or not re.fullmatch('[a-z][a-z0-9_-]{0,31}', detection['result']):
        raise ValueError('Unexpected virtual-machine classification')
    clean_hardware = {'required_hardware_profile': 'epyc7763-baseline', 'profile_qualified': True,
        'hardware': {key: hardware['hardware'][key] for key in ECONOMICS_HARDWARE_KEYS}}
    clean_hardware['hardware']['cpu_model'] = 'AMD EPYC 7763'
    clean_hardware['hardware']['virtualization_detection'] = {'exit_code': 0, 'result': detection['result']}
    profiles = [economic_profile(row) for row in summary['profile_results']]
    coordinates = [(row['coordinate']['log_blowup'], row['coordinate']['grinding']) for row in profiles]
    if len(coordinates) != 8 or set(coordinates) != set(GRID):
        raise ValueError('Exactly eight unique economic profiles required')
    profiles.sort(key=lambda row: (row['coordinate']['log_blowup'], row['coordinate']['grinding']))
    selected = economic_selection(profiles)
    if (summary['candidate_parameters'] != selected['parameters']
            or checked_security(summary['candidate_security']) != selected['security']
            or summary.get('candidate_summary') != MEASUREMENT.medians(selected['kernel_trials'])):
        raise ValueError('Collector choice differs from independently recomputed economic choice')
    identities = [row['measurement_scope_sha256'] for entry in profiles for row in entry['kernel_trials']]
    repeats = {}
    for kind in ('transaction', 'settlement', 'issuance'):
        entry = summary['repeated_measurements'][kind]
        p = selected['parameters'] if kind == 'transaction' else check_parameters(entry['parameters'], (8, 20))
        if (entry.get('measured') is not True or entry.get('parameters') != p
                or set(entry.get('workers', {})) != {'4', '1'}):
            raise ValueError('Incomplete selected or related relation measurements')
        security = checked_security(entry['security'])
        if kind == 'transaction' and security != selected['security']:
            raise ValueError('Selected single-worker security differs from grid')
        groups = {}
        for workers in (4, 1):
            group = entry['workers'][str(workers)]
            rows = economic_trials(group['trials'], kind, workers, p)
            computed = MEASUREMENT.medians(rows)
            if group.get('summary') != computed:
                raise ValueError('Related relation summary differs from kernel trials')
            if kind == 'transaction' and workers == 4:
                if group.get('source') != 'selected-grid-trials' or rows != selected['kernel_trials']:
                    raise ValueError('Selected four-worker measurements were substituted')
            else:
                identities.extend(row['measurement_scope_sha256'] for row in rows)
            if computed['proof_bytes_max'] > (ECONOMICS_PROOF_MAX if kind == 'transaction' else 524288):
                raise ValueError('Measured proof exceeds the relation admission limit')
            groups[str(workers)] = {'trials': rows, 'summary': computed}
            if kind == 'transaction' and workers == 4:
                groups[str(workers)]['source'] = 'selected-grid-trials'
        repeats[kind] = {'measured': True, 'parameters': p, 'security': security, 'workers': groups}
    if len(identities) != 39 or len(set(identities)) != len(identities):
        raise ValueError('Replayed economic measurement scope identity')
    maximum = max(group['summary']['proof_bytes_max']
        for group in repeats['transaction']['workers'].values())
    cap = proof_cap(maximum)
    if require_admission_margin and cap > ECONOMICS_PROOF_MAX:
        raise ValueError('Ten-percent transaction admission margin exceeds 655360 bytes')
    return {'profiles': profiles, 'selected': selected, 'repeated_measurements': repeats,
        'selected_transaction_proof_bytes_max': maximum, 'max_leaf_proof_bytes': cap,
        'hardware_qualification': clean_hardware}


def create_economics(summary, public_verifier, root=ROOT):
    measured = economic_summary(summary)
    commit = summary.get('source_commit')
    if not isinstance(commit, str) or not re.fullmatch('[a-f0-9]{40}', commit):
        raise ValueError('Invalid measured source commit')
    blobs = measured_source_hashes(root, commit, revision=2)
    air_hash, dependency_hash = digest(summary['air_source_sha256']), digest(summary['dependencies_sha256'])
    if (air_hash != relation_hash(root)
            or dependency_hash != hashlib.sha256(source_bytes(root, 'crates/bench-multi-asset/Cargo.lock')).hexdigest()):
        raise ValueError('Measurement relation or dependency differs from current source')
    selected = measured['selected']
    return {'schema': 2, 'status': 'engineering-frozen', 'suite': SUITE,
        'relation_revision': 'native-v1-economics-1', 'measurement_schema': 3,
        'cryptographic_approval': False, 'network_activation': False, 'acceptance': False,
        'dependency_revision': DEPENDENCY_REVISION, 'measured_source_commit': commit,
        'air_source_sha256': air_hash, 'dependencies_sha256': dependency_hash,
        'measurement_binary_sha256': digest(summary['binary_sha256']),
        'measurement_launcher_sha256': digest(summary['launcher_sha256']),
        'source_sha256': source_hashes(root, revision=2), 'measured_source_sha256': blobs,
        'reference_execution': {'cpu_model': 'AMD EPYC 7763', 'os': 'Ubuntu 24.04',
            'architecture': 'x86_64', 'exposed_cores': 2, 'exposed_vcpus': 4,
            'rayon_workers': 4, 'hiding_workers': 2, 'required_isa': 'x86-64-v3'},
        'hardware_qualification': measured['hardware_qualification'],
        'generation_limit_ns': GENERATION_MAX_NS, 'proof_body_limit_bytes': ECONOMICS_PROOF_MAX,
        'selection_rule': 'all-three-trials-within-time-and-size-limits-then-smallest-maximum-observed-proof',
        'parameters': selected['parameters'], 'selected_security': selected['security'],
        'public_verifier_key': verifier_key(public_verifier, selected['parameters'], selected['security']),
        'max_leaf_proof_bytes': measured['max_leaf_proof_bytes'],
        'selected_transaction_proof_bytes_max': measured['selected_transaction_proof_bytes_max'],
        'max_settlement_proof_bytes': 524288, 'max_issuance_proof_bytes': 524288,
        'proof_cap_policy': 'at-least-ten-percent-above-observed-maximum-rounded-up-to-65536-bytes',
        'proof_size_scope': 'observed synthetic proof bodies; admission cap is not a mathematical size bound',
        'measurement_memory_scope': 'whole setup-prove-verify process tree including recorder',
        'diagnostic_memory_max_bytes': MEMORY_MAX, 'memory_boundary_is_miner_requirement': False,
        'verification_measurement': ECONOMICS_VERIFICATION, 'verification_only_process': False,
        'public_transaction_bytes': 2027, 'permanent_position_bytes': 2115,
        'profiles': measured['profiles'], 'repeated_measurements': measured['repeated_measurements']}


def validate_economics(value, root=ROOT):
    if set(value) != ECONOMICS_TOP_KEYS:
        raise ValueError('Unexpected public economic engineering profile fields')
    expected = {'schema': 2, 'status': 'engineering-frozen', 'suite': SUITE,
        'relation_revision': 'native-v1-economics-1', 'measurement_schema': 3,
        'cryptographic_approval': False, 'network_activation': False, 'acceptance': False,
        'dependency_revision': DEPENDENCY_REVISION, 'generation_limit_ns': GENERATION_MAX_NS,
        'proof_body_limit_bytes': ECONOMICS_PROOF_MAX, 'diagnostic_memory_max_bytes': MEMORY_MAX,
        'memory_boundary_is_miner_requirement': False, 'verification_only_process': False,
        'verification_measurement': ECONOMICS_VERIFICATION,
        'public_transaction_bytes': 2027, 'permanent_position_bytes': 2115,
        'max_settlement_proof_bytes': 524288, 'max_issuance_proof_bytes': 524288,
        'selection_rule': 'all-three-trials-within-time-and-size-limits-then-smallest-maximum-observed-proof',
        'proof_cap_policy': 'at-least-ten-percent-above-observed-maximum-rounded-up-to-65536-bytes',
        'proof_size_scope': 'observed synthetic proof bodies; admission cap is not a mathematical size bound',
        'measurement_memory_scope': 'whole setup-prove-verify process tree including recorder',
        'reference_execution': {'cpu_model': 'AMD EPYC 7763', 'os': 'Ubuntu 24.04',
            'architecture': 'x86_64', 'exposed_cores': 2, 'exposed_vcpus': 4,
            'rayon_workers': 4, 'hiding_workers': 2, 'required_isa': 'x86-64-v3'}}
    if any(type(value.get(key)) is not type(wanted) or value.get(key) != wanted
           for key, wanted in expected.items()):
        raise ValueError('Invalid economic engineering profile identity or policy')
    validate_measured_sources(value, root, revision=2)
    if not RELOCATIONS.mapping_matches(root, value['source_sha256'], source_paths(root, revision=2), source_bytes):
        raise ValueError('Frozen economic source boundary changed')
    if (value['air_source_sha256'] != relation_hash(root)
            or not RELOCATIONS.matches(root, 'crates/bench-multi-asset/Cargo.lock', source_bytes(root, 'crates/bench-multi-asset/Cargo.lock'), value['dependencies_sha256'])):
        raise ValueError('Frozen economic relation or dependency changed')
    commit = value.get('measured_source_commit')
    if not isinstance(commit, str) or not re.fullmatch('[a-f0-9]{40}', commit):
        raise ValueError('Invalid measured source commit')
    profile_results = []
    for row in value['profiles']:
        if set(row) != ECONOMICS_PROFILE_KEYS:
            raise ValueError('Unexpected public economic profile fields')
        entry = {name: row[name] for name in ('coordinate', 'parameters', 'security')}
        entry.update(trials=row['kernel_trials'], summary=MEASUREMENT.medians(row['kernel_trials']))
        if economic_profile(entry) != row:
            raise ValueError('Public economic profile differs from its kernel trials')
        profile_results.append(entry)
    matches = [row for row in profile_results if row['parameters'] == value['parameters']]
    if len(matches) != 1:
        raise ValueError('Selected economic profile is absent')
    summary = {'schema': 3, 'status': 'candidate-pending-review', 'suite': SUITE,
        'scan_mode': 'economics-candidate', 'hardware_profile': 'epyc7763-baseline',
        'grid_rayon_workers': 4, 'grid_hiding_workers': 2, 'single_worker_hiding_workers': 1,
        'trial_count_per_profile': 3, 'measurement_grid_complete': True,
        'scope_startup_complete': True, 'selected_transaction_single_worker_complete': True,
        'related_relation_measurements_complete': True, 'all_measurements_complete': True,
        'candidate_selected': True, 'candidate_rejected': False, 'three_trial_target_met': True,
        'legacy_524288_byte_cap_applied': False, 'proof_body_limit_bytes': ECONOMICS_PROOF_MAX,
        'generation_limit_ns': GENERATION_MAX_NS, 'memory_max_bytes': MEMORY_MAX,
        'memory_swap_max_bytes': 0, 'verification_only_process': False,
        'cryptographic_approval': False, 'network_activation': False, 'acceptance': False,
        'hardware': value['hardware_qualification'], 'profile_results': profile_results,
        'candidate_parameters': value['parameters'], 'candidate_security': value['selected_security'],
        'candidate_summary': matches[0]['summary'], 'repeated_measurements': value['repeated_measurements']}
    measured = economic_summary(summary)
    if checked_security(value['selected_security']) != value['selected_security']:
        raise ValueError('Unexpected selected economic security fields')
    for name in ('max_leaf_proof_bytes', 'selected_transaction_proof_bytes_max',
                 'profiles', 'repeated_measurements', 'hardware_qualification'):
        if value[name] != measured[name]:
            raise ValueError('Frozen economic selection, cap or measurement evidence changed')
    full_security = {**value['selected_security'], 'fri': value['parameters']}
    public = {'schema': 1, 'suite': SUITE, 'kind': 'transaction', 'parameters': value['parameters'],
        'security': full_security, 'public_verifier_key': value['public_verifier_key']}
    if verifier_key(public, value['parameters'], value['selected_security']) != value['public_verifier_key']:
        raise ValueError('Unexpected economic public verifier fields')
    digest(value['measurement_binary_sha256']); digest(value['measurement_launcher_sha256'])
    return value


def create(summary, public_verifier, root=ROOT):
    if summary.get('schema') == 3:
        return create_economics(summary, public_verifier, root)
    return create_wallet_fast(summary, public_verifier, root)


def validate(value, root=ROOT):
    if value.get('schema') == 2:
        return validate_economics(value, root)
    return validate_wallet_fast(value, root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--create', type=Path, metavar='SUMMARY')
    mode.add_argument('--check', type=Path, metavar='PROFILE')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verifier-key', type=Path)
    args = parser.parse_args()
    if args.create:
        if not args.output or not args.verifier_key:
            parser.error('output and verifier-key are required for create')
        result = create(json.loads(args.create.read_text()), json.loads(args.verifier_key.read_text()))
        validate(result)
        with args.output.open('x') as stream:
            json.dump(result, stream, indent=2, allow_nan=False)
            stream.write('\n')
        print('Created a source-bound multi-asset engineering profile.')
    else:
        if args.output:
            parser.error('output is only valid with create')
        frozen = validate(json.loads(args.check.read_text()))
        if args.verifier_key:
            reproduced = verifier_key(json.loads(args.verifier_key.read_text()),
                frozen['parameters'], frozen['selected_security'])
            if reproduced != frozen['public_verifier_key']:
                raise ValueError('Reproduced public verifier key differs from frozen artifact')
        print('Multi-asset profile, source identities and measured parameter choice validated.')


if __name__ == '__main__':
    main()
