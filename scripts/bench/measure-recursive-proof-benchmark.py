#!/usr/bin/env python3
"""Run three frozen D8 merge trials and assess a provisional N=16 projection.

The worker protocol is deliberately separate from D4 controls. A missing D8
worker, actual leaf/merge shape, security term or memory-model component is an
incomplete checkpoint, never a zero cost or a successful smoke measurement.
All raw output remains in the explicitly selected private output directory.
"""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
EXPERIMENTAL_MEMORY_MAX = 10737418240
RESOURCE_LIMITS = {'memory_max': EXPERIMENTAL_MEMORY_MAX, 'memory_swap_max': 0,
                   'production_memory_budget_status': 'undecided'}
SUITE = 'KoalaBear-D8-Poseidon2-W24-digest12'
LAYERS = ('leaf', 'merge8', 'root')
MEASURED_PHASES = ('startup', 'ready_resident', 'leaf16', 'merge8', 'verification', 'handoffs', 'teardown')
PROJECTED_PHASES = ('leaf16', 'merge1', 'merge2', 'root', 'handoffs')
SECURITY_TERMS = ('ood', 'deep', 'ali', 'fri_fold', 'merkle_collision', 'commitment_collision')
FILE_ROLES = ('launcher', 'worker', 'build_receipt', 'cargo_config', 'configuration',
              'actual_shapes', 'security_report', 'leaf_artifact', 'leaf_verifying_key',
              'merge8_artifact', 'merge8_verifying_key', 'root_model', 'dependency_lock',
              'source_archive', 'recursion_patch', 'leaf_input_fixture', 'merge_input_proofs')
INITIAL_ROLES = ('launcher', 'worker', 'build_receipt', 'cargo_config', 'configuration',
                 'root_model', 'dependency_lock', 'source_archive', 'recursion_patch', 'leaf_input_fixture')
FULL_ROOT_ROLES = ('root_artifact', 'root_verifying_key')
FULL_PHASES = ('startup', 'ready_resident', 'leaf16', 'merge1', 'merge2', 'root', 'verification', 'teardown')
LIMITS = {'conjectured': 128, 'johnson': 100, 'quantum_challenges': 100, 'bht_collision': 100}


class CheckpointFailure(ValueError):
    """A measured failure requires progression to pause."""


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def number(value, name, minimum=0):
    if type(value) not in (int, float) or not math.isfinite(value) or value < minimum:
        raise ValueError('Missing, nonfinite or invalid ' + name)
    return value


def integer(value, name, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError('Missing or invalid integer ' + name)
    return value


def bundle_file(base, relative):
    if (not isinstance(relative, str) or not relative or Path(relative).is_absolute()
            or '..' in Path(relative).parts):
        raise ValueError('Frozen files must have relative bundle paths')
    target = (base / relative).resolve(strict=True)
    if base.resolve() not in target.parents or not target.is_file():
        raise ValueError('Frozen file escaped its bundle')
    return target


def evidence_term(term, name):
    if not isinstance(term, dict):
        raise ValueError('Missing ' + name)
    value = integer(term.get('value'), name)
    if (term.get('kind') not in ('measured', 'estimated')
            or not isinstance(term.get('evidence'), str)
            or term['evidence'].partition('#')[0] not in FILE_ROLES):
        raise ValueError('A frozen evidence source and measured/estimated kind are required for ' + name)
    return value


def validate_resource_limits(value):
    if (not isinstance(value, dict) or value != RESOURCE_LIMITS
            or type(value.get('memory_max')) is not int
            or type(value.get('memory_swap_max')) is not int):
        raise ValueError('The checkpoint requires a frozen 10-GiB experimental limit, zero swap and an undecided production memory budget')
    return dict(value)


def validate_header(manifest):
    if manifest.get('schema') != 1 or manifest.get('suite') != SUITE:
        raise ValueError('Checkpoint requires the D8/W24/12-element suite schema')
    if manifest.get('poseidon2_parameters') != 'Plonky3-standard':
        raise ValueError('Checkpoint requires standard Plonky3 W24 parameters')
    validate_resource_limits(manifest.get('resource_limits'))
    for key in ('source_revision', 'recursion_revision'):
        if not re.fullmatch('[0-9a-f]{40}', manifest.get(key, '')):
            raise ValueError('A frozen revision is required: ' + key)
    expected = {'slots': 16, 'jobs': 1, 'native_workers': 2, 'rayon_threads': 2, 'hiding_workers': 2}
    if manifest.get('execution') != expected:
        raise ValueError('Checkpoint requires N=16, one proof job and two native workers')
    if manifest.get('checkpoint_mode') not in ('merge8-early', 'n16-full'):
        raise ValueError('An explicit checkpoint_mode is required')
    for layer in LAYERS:
        parameters = manifest.get('parameters', {}).get(layer, {})
        if parameters.get('batch_grinding') != 16:
            raise ValueError('The frozen final configuration requires 16 batch grinding bits: ' + layer)
        for key in ('log_blowup', 'queries', 'max_log_arity'):
            integer(parameters.get(key), layer + '.' + key, 1)
        for key in ('commit_grinding', 'query_grinding', 'final_poly_log'):
            integer(parameters.get(key), layer + '.' + key)


def validate_metadata(manifest, shapes, security):
    validate_header(manifest)
    for layer in LAYERS:
        actual = shapes.get('layers', {}).get(layer, {})
        if (layer != 'root' or manifest['checkpoint_mode'] == 'n16-full') and actual.get('status') != 'actual-extracted':
            raise ValueError('An actual extracted shape is required: ' + layer)
        if layer == 'root' and (actual.get('status') not in ('actual-extracted', 'shape-estimate')
                or (actual['status'] == 'shape-estimate' and not actual.get('estimate_basis'))):
            raise ValueError('Root shape requires measured geometry or an explicit estimate basis')
        if not actual.get('tables'):
            raise ValueError('Missing table geometry: ' + layer)
        for table in actual['tables']:
            height = integer(table.get('height'), layer + '.table.height', 1)
            if height & (height - 1):
                raise ValueError('Table height must be a power of two')
            integer(table.get('main_columns'), layer + '.main_columns', 1)
            integer(table.get('preprocessed_columns'), layer + '.preprocessed_columns')
        for key in ('constraints', 'max_degree', 'quotient_chunks', 'batched_openings'):
            integer(actual.get(key), layer + '.' + key, 1)
        if not isinstance(actual.get('lookup_dimensions'), list):
            raise ValueError('Missing lookup dimensions: ' + layer)
        for dimension in actual['lookup_dimensions']:
            integer(dimension, layer + '.lookup_dimension')
    if shapes.get('suite') != SUITE or security.get('suite') != SUITE:
        raise ValueError('Shape/security suite mismatch')
    if security.get('p3_security') != '0.9.0-rc.2':
        raise ValueError('Pinned p3-security version is required')
    if security.get('composition', {}).get('proof_count') != 19:
        raise ValueError('Security accounting must include the 19-proof composition')
    reports = [(name, security.get('layers', {}).get(name, {})) for name in LAYERS]
    reports.append(('composition', security.get('composition', {})))
    for label, report in reports:
        for name, minimum in LIMITS.items():
            number(report.get('bounds', {}).get(name), label + '.' + name, minimum)
        if not report.get('weakest_term'):
            raise ValueError('The weakest security term must be reported: ' + label)
        for name in SECURITY_TERMS:
            row = report.get('error_terms', {}).get(name, {})
            number(row.get('classical_bits'), label + '.' + name + '.classical_bits')
            number(row.get('quantum_bits'), label + '.' + name + '.quantum_bits', 100)


def frozen_manifest(path, expected_sha):
    path = path.resolve(strict=True)
    if not re.fullmatch('[0-9a-f]{64}', expected_sha) or digest(path) != expected_sha:
        raise ValueError('Frozen manifest checksum mismatch')
    manifest = json.loads(path.read_text())
    validate_header(manifest)
    return path, manifest


def frozen_files(path, manifest, roles):
    files = {}
    for role in roles:
        entry = manifest.get('files', {}).get(role, {})
        file = bundle_file(path.parent, entry.get('path'))
        if digest(file) != entry.get('sha256'):
            raise ValueError('Frozen file checksum mismatch: ' + role)
        files[role] = file
    return files


def validate_configuration(manifest, files):
    limits = validate_resource_limits(manifest.get('resource_limits'))
    root_model = json.loads(files['root_model'].read_text())
    if root_model.get('projection') != manifest.get('projection'):
        raise ValueError('Frozen root model differs from the manifest projection')
    configuration = json.loads(files['configuration'].read_text())
    if (configuration.get('parameters') != manifest['parameters']
            or configuration.get('resource_limits') != limits
            or configuration.get('suite') != SUITE
            or configuration.get('source_revision') != manifest['source_revision']
            or configuration.get('recursion_revision') != manifest['recursion_revision']):
        raise ValueError('Frozen configuration does not match the checkpoint parameters')
    validate_resource_limits(configuration.get('resource_limits'))
    receipt = json.loads(files['build_receipt'].read_text())
    worker = files['worker']
    if (files['launcher'].parent.name != 'bin'
            or worker != files['launcher'].parent.parent / 'libexec' / files['launcher'].name):
        raise ValueError('A separately installed CPU-check launcher and v3 worker are required')
    entries = [row for row in receipt.get('workers', []) if row.get('name') == worker.name]
    if (receipt.get('worker_isa') != 'x86-64-v3' or receipt.get('bootstrap_isa') != 'x86-64'
            or receipt.get('bootstrap_sha256') != digest(files['launcher'])
            or receipt.get('repository_config_sha256') != digest(files['cargo_config'])
            or len(entries) != 1 or entries[0].get('worker_sha256') != digest(worker)
            or entries[0].get('isa_inspection', {}).get('binary_sha256') != digest(worker)
            or entries[0].get('isa_inspection', {}).get('required_isa') != 'x86-64-v3'
            or entries[0].get('isa_inspection', {}).get('avx2_packed_multiply_instructions', 0) < 1):
        raise ValueError('Frozen CPU guard, optimized worker or AVX2 receipt mismatch')
    build = receipt.get('worker_build_receipt') or {}
    if (build.get('binary_sha256') != digest(worker)
            or build.get('effective_rustflags') != '-C target-cpu=x86-64-v3'
            or build.get('cargo_working_directory') != 'repository-root'
            or build.get('repository_config_sha256') != digest(files['cargo_config'])):
        raise ValueError('Controlled v3 worker build provenance is missing')


def load_bootstrap(path, expected_sha):
    path, manifest = frozen_manifest(path, expected_sha)
    if manifest.get('stage') != 'bootstrap':
        raise ValueError('The initial manifest must explicitly be a bootstrap freeze')
    files = frozen_files(path, manifest, INITIAL_ROLES)
    validate_configuration(manifest, files)
    return manifest, files


def load_frozen(path, expected_sha):
    path, manifest = frozen_manifest(path, expected_sha)
    roles = FILE_ROLES + (FULL_ROOT_ROLES if manifest['checkpoint_mode'] == 'n16-full' else ())
    files = frozen_files(path, manifest, roles)
    shapes = json.loads(files['actual_shapes'].read_text())
    security = json.loads(files['security_report'].read_text())
    validate_metadata(manifest, shapes, security)
    for role in ('configuration', 'actual_shapes'):
        if security.get(role + '_sha256') != digest(files[role]):
            raise ValueError('Security report is not bound to the frozen ' + role)
    validate_configuration(manifest, files)
    return manifest, files


def check_setup_freeze(bootstrap, final):
    for name in ('suite', 'checkpoint_mode', 'source_revision', 'recursion_revision',
                 'execution', 'parameters', 'projection', 'resource_limits'):
        if bootstrap.get(name) != final.get(name):
            raise ValueError('Prepared setup changed a pre-frozen field: ' + name)
    for role in INITIAL_ROLES:
        if bootstrap['files'].get(role) != final['files'].get(role):
            raise ValueError('Prepared setup replaced a pre-frozen artifact: ' + role)


def attribute_phases(phases, measurement):
    result = {}
    started = measurement['monotonic_started_ns']
    finished = started + measurement.get('elapsed_ns', 2**63)
    previous_end = started
    for phase in phases:
        name, first, last = phase['phase'], phase['start_ns'], phase['end_ns']
        if (name in result or type(first) is not int or type(last) is not int
                or first < previous_end or not first < last <= finished):
            raise ValueError('Duplicate, overlapping or out-of-lifetime phase interval')
        samples = [sample['memory_current'] for sample in measurement['samples']
                   if first <= started + sample['elapsed_ns'] <= last]
        boundaries = [integer(phase[key], name + '.' + key)
                      for key in ('memory_start', 'memory_end') if key in phase]
        values = samples + boundaries
        result[name] = {'wall_ns': last - first, 'sample_count': len(values),
            'interval_sample_count': len(samples), 'boundary_sample_count': len(boundaries),
            'sampled_memory_peak': max(values) if values else None,
            'memory_evidence_kind': 'sampled-lower-bound',
            'kernel_lifetime_peak_upper_reference': measurement['memory_peak'],
            'scope': 'Owned cgroup process tree; sampling is not exact component attribution'}
        previous_end = last
    return result


def validate_canonical_root_output(row, root_phase, timed_end):
    output = row.get('canonical_root_output', {})
    if output.get('encoding') != 'plonky3-canonical-artifact':
        raise ValueError('A canonical root artifact must complete inside the root phase')
    completed = integer(output.get('completed_ns'), 'canonical_root_output.completed_ns')
    size = integer(output.get('bytes'), 'canonical_root_output.bytes', 1)
    if not root_phase['start_ns'] <= completed <= root_phase['end_ns'] <= timed_end:
        raise ValueError('Canonical root output completed outside the proof timing boundary')
    if row.get('retained_serialized_bytes', {}).get('root') != size:
        raise ValueError('The retained root buffer must be the complete canonical artifact')
    return output


def attribute_handoff_gaps(proof_phases, first, last, measurement):
    gaps, values, boundaries = [], [], []
    cursor, previous_memory = first, None
    for phase in proof_phases:
        if cursor < phase['start_ns']:
            gaps.append({'start_ns': cursor, 'end_ns': phase['start_ns']})
            if previous_memory is not None:
                boundaries.append(previous_memory)
            boundaries.append(integer(phase.get('memory_start'), 'handoff.memory_start'))
        cursor = phase['end_ns']
        previous_memory = integer(phase.get('memory_end'), 'handoff.memory_end')
    if cursor < last:
        gaps.append({'start_ns': cursor, 'end_ns': last})
        boundaries.append(previous_memory)
    for sample in measurement['samples']:
        at = measurement['monotonic_started_ns'] + sample['elapsed_ns']
        if any(gap['start_ns'] <= at <= gap['end_ns'] for gap in gaps):
            values.append(integer(sample['memory_current'], 'handoff.memory_current'))
    observed = values + boundaries
    return {'wall_ns': sum(gap['end_ns'] - gap['start_ns'] for gap in gaps),
        'sample_count': len(observed), 'interval_sample_count': len(values),
        'boundary_sample_count': len(boundaries),
        'sampled_memory_peak': max(observed) if observed else None,
        'memory_evidence_kind': 'sampled-lower-bound',
        'kernel_lifetime_peak_upper_reference': measurement['memory_peak'],
        'scope': 'Owned cgroup charge during gaps between proof phases; not component attribution',
        'gaps': gaps}


def read_trial(directory, manifest, frozen_sha, worker_row=None, setup_phases=None, teardown=None):
    limits = validate_resource_limits(manifest.get('resource_limits'))
    measurement = json.loads((directory / 'measurement.json').read_text())
    if not measurement.get('resource_control_pass'):
        raise CheckpointFailure('A failed resource-control trial blocks the checkpoint; no retry')
    if worker_row is None:
        records = []
        for line in (directory / 'stdout.jsonl').read_text().splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if row.get('event') == 'd8_checkpoint_trial':
                records.append(row)
        if len(records) != 1:
            raise ValueError('Missing or duplicate D8 checkpoint worker result')
        row = records[0]
    else:
        row = worker_row
    if row.get('verified') is False:
        raise CheckpointFailure('The D8 merge proof did not verify')
    if (row.get('manifest_sha256') != frozen_sha or row.get('suite') != SUITE
            or row.get('verified') is not True or row.get('fresh_hiding_randomness') is not True
            or row.get('parameters') != manifest['parameters']
            or row.get('execution') != manifest['execution']
            or row.get('leaf_proofs_at_merge_start') != 16
            or set(row.get('batch_grinding_verified_paths', [])) != {'native', 'recursive', 'prepared'}):
        raise ValueError('The D8 worker result does not establish the frozen configuration')
    runtime = row.get('runtime', {})
    if (runtime.get('packing_width') != 8 or runtime.get('compiled_avx2') is not True
            or runtime.get('compiled_avx512f') is not False
            or runtime.get('global_rayon_threads') != 2
            or runtime.get('rayon_num_threads') != '2'
            or runtime.get('composition_hiding_workers') != '2'):
        raise ValueError('Worker runtime differs from the fixed two-worker v3 configuration')
    qualification = measurement.get('hardware_qualification', {})
    if (qualification.get('profile') != 'epyc7763-baseline'
            or qualification.get('profile_qualified') is not True
            or measurement.get('memory_max') != limits['memory_max']
            or measurement.get('memory_swap_max') != limits['memory_swap_max']):
        raise ValueError('A qualified EPYC 7763 baseline under the frozen 10-GiB experimental/no-swap limit is required')
    if measurement.get('worker_environment') != {
            'RAYON_NUM_THREADS': '2', 'SIWORLD_COMPOSITION_HIDING_WORKERS': '2'}:
        raise ValueError('Supervisor worker environment differs from the frozen configuration')
    all_phases = [*(setup_phases or []), *row.get('phases', []), *([teardown] if teardown else [])]
    for phase in all_phases:
        for key in ('memory_start', 'memory_end'):
            integer(phase.get(key), phase.get('phase', 'unknown') + '.' + key)
    phases = attribute_phases(all_phases, measurement)
    required = FULL_PHASES if manifest['checkpoint_mode'] == 'n16-full' else MEASURED_PHASES
    if set(phases) != set(required):
        raise ValueError('Every startup, resident, leaf, merge, verification, handoff and teardown phase is required')
    extra = {}
    if manifest['checkpoint_mode'] == 'n16-full':
        first = integer(row.get('timed_start_ns'), 'timed_start_ns')
        last = integer(row.get('timed_end_ns'), 'timed_end_ns')
        indexed = {phase['phase']: phase for phase in all_phases}
        if not (indexed['ready_resident']['end_ns'] <= first <= indexed['leaf16']['start_ns']
                and indexed['root']['end_ns'] <= last <= indexed['verification']['start_ns']):
            raise ValueError('Full proof timing must cover every proof phase and exclude verification')
        canonical_output = validate_canonical_root_output(row, indexed['root'], last)
        proof_phases = ('leaf16', 'merge1', 'merge2', 'root')
        overhead = last - first - sum(phases[name]['wall_ns'] for name in proof_phases)
        if overhead < 0:
            raise ValueError('Proof timing phases exceed the full interval')
        handoff_memory = attribute_handoff_gaps([indexed[name] for name in proof_phases],
            first, last, measurement)
        if handoff_memory['wall_ns'] != overhead:
            raise ValueError('Handoff gaps do not reconcile with timed overhead')
        retained = row.get('retained_serialized_bytes', {})
        for name in ('leaves', 'merge1', 'merge2', 'root'):
            integer(retained.get(name), 'retained_serialized_bytes.' + name)
        values = [sample['memory_current'] for sample in measurement['samples']
                  if first <= measurement['monotonic_started_ns'] + sample['elapsed_ns'] <= last]
        boundary_peaks = [phases[name]['sampled_memory_peak'] for name in proof_phases]
        extra = {'trial': row.get('trial'), 'timed_total_ns': last - first,
            'canonical_root_output': canonical_output,
            'handoff_overhead_ns': overhead, 'handoff_memory': handoff_memory,
            'retained_serialized_bytes': retained,
            'sampled_trial_memory_peak': max([*values, *boundary_peaks]),
            'memory_peak_scope': 'Shared kernel lifetime peak; a conservative per-trial upper reference'}
    return {**extra, 'resource_control_pass': True, 'verified': True, 'phases': phases,
        'resource_limits': limits,
        'memory_peak': measurement['memory_peak'], 'swap_peak': measurement['swap_peak'],
        'memory_events_delta': measurement['memory_events_delta'],
        'cpu_summary': measurement.get('cpu_summary'), 'hardware_qualification': qualification,
        'acceptance': False}


def decide(total_ns, memory):
    if total_ns > 180_000_000_000 or memory > EXPERIMENTAL_MEMORY_MAX:
        return 'pause'
    return 'continue' if total_ns <= 135_000_000_000 else 'continue-optimize'


def project_full(trials, resource_limits):
    limits = validate_resource_limits(resource_limits)
    if len(trials) != 3 or [trial.get('trial') for trial in trials] != [1, 2, 3]:
        raise ValueError('Exactly three ordered warm trials in the same process are required')
    for trial in trials:
        if trial.get('resource_limits') != limits:
            raise ValueError('Trial resource limits differ from the frozen experiment')
        if not trial.get('resource_control_pass') or trial.get('swap_peak') != 0:
            raise CheckpointFailure('A failed full trial blocks progression')
        for name in FULL_PHASES:
            phase = trial.get('phases', {}).get(name, {})
            integer(phase.get('wall_ns'), name + '.wall_ns', 1)
            integer(phase.get('sample_count'), name + '.sample_count', 1)
            integer(phase.get('sampled_memory_peak'), name + '.sampled_memory_peak', 1)
    peaks = {trial['memory_peak'] for trial in trials}
    if len(peaks) != 1:
        raise ValueError('Persistent trials must share one kernel lifetime memory peak')
    total = statistics.median(trial['timed_total_ns'] for trial in trials)
    peak = next(iter(peaks))
    phases = {name: {'wall_ns': statistics.median(trial['phases'][name]['wall_ns'] for trial in trials),
        'wall_ns_max': max(trial['phases'][name]['wall_ns'] for trial in trials),
        'sampled_memory_peak_median': statistics.median(trial['phases'][name]['sampled_memory_peak'] for trial in trials),
        'sampled_memory_peak_max': max(trial['phases'][name]['sampled_memory_peak'] for trial in trials)}
        for name in FULL_PHASES}
    handoffs = [trial['handoff_memory'] for trial in trials]
    observed_handoffs = [phase['sampled_memory_peak'] for phase in handoffs
        if phase['sampled_memory_peak'] is not None]
    phases['handoffs'] = {'wall_ns': statistics.median(phase['wall_ns'] for phase in handoffs),
        'wall_ns_max': max(phase['wall_ns'] for phase in handoffs),
        'sampled_memory_peak_median': statistics.median(observed_handoffs) if observed_handoffs else None,
        'sampled_memory_peak_max': max(observed_handoffs) if observed_handoffs else None,
        'memory_evidence_kind': 'sampled-lower-bound',
        'observed_trials': len(observed_handoffs)}
    return {'schema': 1, 'purpose': 'D8 N=16 full proof engineering checkpoint',
        'resource_limits': limits,
        'acceptance': False, 'trials': 3, 'projected_total_ns': total,
        'time_evidence_kind': 'measured complete last-package-to-root interval',
        'timed_total_ns_max': max(trial['timed_total_ns'] for trial in trials),
        'projected_memory_peak': peak, 'memory_evidence_kind': 'kernel lifetime peak including resident setup and all three trials',
        'trial_sampled_memory_peak_median': statistics.median(trial['sampled_trial_memory_peak'] for trial in trials),
        'trial_sampled_memory_peak_max': max(trial['sampled_trial_memory_peak'] for trial in trials),
        'phase_medians': phases, 'handoff_overhead_median_ns': statistics.median(
            trial['handoff_overhead_ns'] for trial in trials),
        'decision': decide(total, peak), 'time_margin_ns': 180_000_000_000 - total,
        'memory_margin_bytes': limits['memory_max'] - peak,
        'limitations': ['Stage and per-trial sampled peaks are lower bounds, not reset kernel peaks.',
            'The shared lifetime kernel peak bounds startup, all prepared layers and all warm trials.',
            'Serialized retained proof bytes do not include allocator or object overhead.',
            'The 10-GiB limit is experimental; the production memory budget is undecided.',
            'This is a feasibility checkpoint, not independent security approval or network acceptance.']}


def project(manifest, trials):
    limits = validate_resource_limits(manifest.get('resource_limits'))
    if manifest.get('checkpoint_mode') == 'n16-full':
        return project_full(trials, limits)
    if len(trials) != 3:
        raise ValueError('Exactly three trials on one live baseline machine are required')
    for trial in trials:
        if trial.get('resource_limits') != limits:
            raise ValueError('Trial resource limits differ from the frozen experiment')
        if not trial.get('resource_control_pass') or trial.get('swap_peak') != 0:
            raise CheckpointFailure('A failed trial blocks progression; no outlier removal or automatic retry')
        for name in MEASURED_PHASES:
            phase = trial.get('phases', {}).get(name, {})
            integer(phase.get('wall_ns'), name + '.wall_ns', 1)
            integer(phase.get('sample_count'), name + '.sample_count', 1)
            integer(phase.get('sampled_memory_peak'), name + '.sampled_memory_peak', 1)
    model = manifest.get('projection', {})
    memory = model.get('memory', {})
    resident = evidence_term(memory.get('resident_all'), 'resident_all')
    startup = evidence_term(memory.get('startup_peak'), 'startup_peak')
    resident_components = memory.get('resident_components', {})
    resident_sum = sum(evidence_term(resident_components.get(name), 'resident.' + name)
                       for name in (*LAYERS, 'fixed_service'))
    if resident_sum != resident or startup < resident:
        raise ValueError('Resident components must reconcile with the full baseline and startup peak')
    breakdown = {}
    for name in PROJECTED_PHASES:
        phase = memory.get('phases', {}).get(name, {})
        workspace = evidence_term(phase.get('workspace'), name + '.workspace')
        retained = evidence_term(phase.get('retained'), name + '.retained')
        if (phase['workspace'].get('includes_resident') is not False
                or phase['retained'].get('includes_resident') is not False):
            raise ValueError('Workspace/retained terms must exclude the resident baseline: ' + name)
        breakdown[name] = {'resident_all': memory['resident_all'], 'workspace': phase['workspace'],
            'retained': phase['retained'], 'simultaneous_peak_estimate': resident + workspace + retained}
    medians = {name: {'wall_ns': statistics.median(t['phases'][name]['wall_ns'] for t in trials),
        'wall_ns_max': max(t['phases'][name]['wall_ns'] for t in trials),
        'sampled_memory_peak_median': statistics.median(t['phases'][name]['sampled_memory_peak'] for t in trials),
        'sampled_memory_peak_max': max(t['phases'][name]['sampled_memory_peak'] for t in trials)}
        for name in MEASURED_PHASES}
    overhead = evidence_term(model.get('overhead_ns'), 'timed overhead_ns')
    if overhead < medians['handoffs']['wall_ns']:
        raise ValueError('Projected overhead cannot omit observed handoff cost')
    for measured, projected in (('leaf16', 'leaf16'), ('merge8', 'merge1')):
        if medians[measured]['sampled_memory_peak_max'] > breakdown[projected]['simultaneous_peak_estimate']:
            raise ValueError('Memory model underestimates an observed stage: ' + measured)
    if medians['startup']['sampled_memory_peak_max'] > startup:
        raise ValueError('Startup model underestimates observed preparation memory')
    root = model.get('root_time', {})
    if root.get('kind') == 'merge8-proxy' and root.get('evidence'):
        root_ns = medians['merge8']['wall_ns']
    elif root.get('kind') == 'measured':
        root_ns = evidence_term(root, 'root_time')
    else:
        raise ValueError('Root timing requires measured evidence or an explicit merge8 proxy')
    total = medians['leaf16']['wall_ns'] + 2 * medians['merge8']['wall_ns'] + root_ns + overhead
    modeled_peak = max(startup, *(phase['simultaneous_peak_estimate'] for phase in breakdown.values()))
    observed_max = max(t['memory_peak'] for t in trials)
    projected_peak = max(modeled_peak, observed_max)
    return {'schema': 1, 'purpose': 'provisional D8 N=16 engineering feasibility checkpoint',
        'resource_limits': limits,
        'acceptance': False, 'trials': 3, 'projected_total_ns': total,
        'projected_memory_peak': projected_peak, 'modeled_memory_peak': modeled_peak,
        'observed_memory_peak_median': statistics.median(t['memory_peak'] for t in trials),
        'observed_memory_peak_max': observed_max, 'phase_medians': medians,
        'projected_phase_memory': breakdown, 'resident_components': resident_components,
        'startup_peak_model': memory['startup_peak'],
        'root_time': {**root, 'value_ns': root_ns}, 'overhead_ns': model['overhead_ns'],
        'decision': decide(total, projected_peak), 'time_margin_ns': 180_000_000_000 - total,
        'memory_margin_bytes': limits['memory_max'] - projected_peak,
        'limitations': ['Root proxies and shape-based memory estimates are not upper bounds.',
            'Sampled stage peaks are lower bounds; the kernel reports the complete lifetime peak.',
            'The 10-GiB limit is experimental; the production memory budget is undecided.',
            'A complete checkpoint requires actual N=16 proofs and all-stage measurements; it does not establish production acceptance.']}


def read_worker_rows(directory):
    rows = []
    for line in (directory / 'stdout.jsonl').read_text().splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if value.get('event') in ('d8_checkpoint_trial', 'd8_checkpoint_complete'):
            rows.append(value)
    return rows


FAILURE_PHASES = set((*FULL_PHASES, *MEASURED_PHASES, 'prepare_leaf', 'bootstrap_leaf',
                      'prepare_merge8', 'bootstrap_merge8', 'prepare_root', 'bootstrap_root'))


def failure_evidence(directory):
    """Allowlist scalar failure evidence; never return worker error strings."""
    measurement = {}
    path = directory / 'measurement.json'
    if path.is_file():
        try:
            measurement = json.loads(path.read_text())
        except (ValueError, OSError):
            pass
    events = measurement.get('memory_events_delta')
    if events is None and 'memory_events_before' in measurement and 'memory_events_after' in measurement:
        before, after = measurement['memory_events_before'], measurement['memory_events_after']
        events = {name: after[name] - value for name, value in before.items() if name in after}
    event_keys = ('low', 'high', 'max', 'oom', 'oom_kill', 'oom_group_kill')
    events = {name: value for name, value in (events or {}).items()
              if name in event_keys and type(value) is int and value >= 0} if events is not None else None
    result = {'classification': 'worker-error', 'last_phase': None,
        'memory_peak': measurement.get('memory_peak'), 'swap_peak': measurement.get('swap_peak'),
        'zero_swap_observed': measurement.get('swap_peak') == 0 if 'swap_peak' in measurement else None,
        'memory_events_delta': events, 'memory_max': measurement.get('memory_max'),
        'memory_swap_max': measurement.get('memory_swap_max'),
        'exit_code': measurement.get('exit_code'), 'timed_out': measurement.get('timed_out'),
        'resource_control_pass': measurement.get('resource_control_pass'),
        'completed_phase_summaries': []}
    starts, completed, error_text = {}, [], ''
    output = directory / 'stdout.jsonl'
    if output.is_file():
        for line in output.read_text().splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if not isinstance(row, dict):
                continue
            if row.get('event') == 'd8_phase_start' and row.get('phase') in FAILURE_PHASES:
                result['last_phase'] = row['phase']
                starts[row['phase']] = row
            elif row.get('event') == 'd8_phase_end':
                phase = row.get('measurement', {})
                if phase.get('phase') in FAILURE_PHASES:
                    result['last_phase'] = phase['phase']
                    completed.append(phase)
                    starts.pop(phase['phase'], None)
            elif row.get('event') == 'd8_checkpoint_failure':
                error_text = row.get('error', '') if isinstance(row.get('error'), str) else ''
    for phase in completed:
        try:
            values = attribute_phases([phase], measurement)[phase['phase']]
            result['completed_phase_summaries'].append({'phase': phase['phase'], **values})
        except (KeyError, TypeError, ValueError):
            result['phase_evidence_incomplete'] = True
    if starts and measurement.get('monotonic_started_ns') is not None and measurement.get('elapsed_ns'):
        label = result['last_phase']
        start = starts.get(label)
        if start:
            interrupted = {'phase': label, 'start_ns': start.get('start_ns'),
                'end_ns': measurement['monotonic_started_ns'] + measurement['elapsed_ns'],
                'memory_start': start.get('memory_start')}
            try:
                values = attribute_phases([interrupted], measurement)[label]
                result['interrupted_phase_summary'] = {'phase': label, 'completed': False, **values}
            except (KeyError, TypeError, ValueError):
                result['phase_evidence_incomplete'] = True
    if events and any(events.get(name, 0) for name in ('oom', 'oom_kill', 'oom_group_kill')):
        result['classification'] = 'cgroup-oom'
    elif events and events.get('max', 0):
        result['classification'] = 'cgroup-memory-limit'
    elif measurement.get('timed_out'):
        result['classification'] = 'process-timeout'
    elif 'actual D8 shape fails ' in error_text:
        result['classification'] = 'actual-security-screen-rejected'
        bound = re.search(r'actual D8 shape fails (conjectured|johnson|quantum_challenges|bht_collision): ([0-9.eE+-]+)', error_text)
        if bound:
            try:
                value = float(bound[2])
                if math.isfinite(value):
                    result['rejected_security_bound'] = {'name': bound[1], 'bits': value}
            except ValueError:
                pass
    elif not measurement:
        result['classification'] = 'collection-incomplete'
    return result


def supervisor_command(args, files, directory, control, resource_limits):
    limits = validate_resource_limits(resource_limits)
    return ['sudo', '--preserve-env=RAYON_NUM_THREADS,SIWORLD_COMPOSITION_HIDING_WORKERS,GITHUB_ACTIONS',
        sys.executable, str(ROOT / 'scripts/bench/measure-proof-cgroup.py'),
        '--output', str(directory), '--uid', str(os.getuid()), '--gid', str(os.getgid()),
        '--timeout', str(args.timeout), '--hardware-profile', 'epyc7763-baseline',
        '--memory-max', str(limits['memory_max']), '--',
        str(files['launcher']), '--checkpoint-bootstrap', str(args.manifest.resolve()),
        '--checkpoint-bootstrap-sha256', args.sha256, '--checkpoint-control-dir', str(control.resolve())]


def run(args):
    if os.geteuid() == 0:
        raise ValueError('Run checkpoint orchestration as the unprivileged runner user')
    bootstrap, files = load_bootstrap(args.manifest, args.sha256)
    for name in ('RAYON_NUM_THREADS', 'SIWORLD_COMPOSITION_HIDING_WORKERS'):
        if os.environ.get(name) != '2':
            raise ValueError('Set ' + name + '=2 explicitly')
    cpu_check = json.loads(subprocess.check_output([str(files['launcher']), '--check-cpu'], text=True))
    if (cpu_check.get('required_baseline') != 'x86-64-v3' or cpu_check.get('supported') is not True
            or cpu_check.get('scalar_fallback') is not False):
        raise ValueError('Independent CPU guard did not establish v3 support')
    spec = importlib.util.spec_from_file_location('checkpoint_cgroup', ROOT / 'scripts/bench/measure-proof-cgroup.py')
    measurement = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(measurement)
    hardware, _ = measurement.qualify()
    qualification = measurement.qualify_hardware_profile(hardware, 'epyc7763-baseline')
    boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    args.output.mkdir(parents=True, exist_ok=False)
    control = args.output / 'control'
    control.mkdir()
    directory = args.output / 'process-tree'
    receipt = {'schema': 1, 'complete': False, 'acceptance': False,
        'resource_limits': dict(bootstrap['resource_limits']),
        'bootstrap_manifest_sha256': args.sha256, 'hardware_qualification': qualification,
        'same_live_machine_boot_id': boot_id, 'observations': []}
    report = args.output / 'checkpoint.json'
    command = supervisor_command(args, files, directory, control, bootstrap['resource_limits'])
    process = None
    try:
        with (args.output / 'supervisor.log').open('x') as log:
            process = subprocess.Popen(command, stdout=log, stderr=log)
            ready_path = control / 'setup-ready.json'
            started = time.monotonic()
            while not ready_path.is_file():
                if process.poll() is not None:
                    raise CheckpointFailure('Resident D8 setup failed before the freeze barrier')
                if time.monotonic() - started > args.timeout:
                    raise CheckpointFailure('Resident setup timed out; the owning cgroup supervisor must finish cleanup')
                time.sleep(0.05)
            ready = json.loads(ready_path.read_text())
            final_path = Path(ready['manifest_path']).resolve(strict=True)
            if args.manifest.resolve().parent not in final_path.parents:
                raise ValueError('Prepared manifest escaped the pre-frozen bundle')
            final, _ = load_frozen(final_path, ready['manifest_sha256'])
            check_setup_freeze(bootstrap, final)
            if ready.get('resident_setup_complete') is not True:
                raise ValueError('Worker did not establish complete resident setup before the freeze')
            expected_layers = set(LAYERS if final['checkpoint_mode'] == 'n16-full' else ('leaf', 'merge8'))
            if set(ready.get('prepared_layers', [])) != expected_layers:
                raise ValueError('Prepared resident layer inventory does not match the checkpoint mode')
            grant = {'manifest_sha256': ready['manifest_sha256'], 'allowed_trials': 3,
                     'granted_monotonic_ns': time.monotonic_ns()}
            temporary = control / 'grant.tmp'
            temporary.write_text(json.dumps(grant) + '\n')
            temporary.replace(control / 'grant.json')
            receipt['manifest_sha256'] = ready['manifest_sha256']
            receipt['setup_phases'] = ready.get('setup_phases', [])
            receipt['grant'] = grant
            report.write_text(json.dumps(receipt, indent=2) + '\n')
            process.wait(timeout=args.timeout + 15)
        if Path('/proc/sys/kernel/random/boot_id').read_text().strip() != boot_id:
            raise ValueError('The live machine boot epoch changed during the checkpoint')
        if process.returncode != 0:
            if (directory / 'measurement.json').is_file():
                failed = json.loads((directory / 'measurement.json').read_text())
                receipt['failed_observation'] = {key: failed.get(key) for key in
                    ('memory_peak', 'swap_peak', 'memory_events_delta', 'exit_code',
                     'timed_out', 'resource_control_pass')}
            raise CheckpointFailure('Resource-controlled process failed; preserve evidence and stop without retry')
        rows = read_worker_rows(directory)
        trials = [row for row in rows if row['event'] == 'd8_checkpoint_trial']
        completed = [row for row in rows if row['event'] == 'd8_checkpoint_complete']
        if len(completed) != 1 or completed[0].get('manifest_sha256') != ready['manifest_sha256']:
            raise ValueError('Missing or mismatched completion marker')
        if len(trials) != 3 or [row.get('trial') for row in trials] != [1, 2, 3]:
            raise ValueError('Exactly three ordered warm trials are required')
        first_start = min(phase['start_ns'] for phase in trials[0].get('phases', []))
        if first_start < grant['granted_monotonic_ns']:
            raise ValueError('A measured proof began before the verified freeze grant')
        teardown = completed[0].get('teardown_phase')
        for row in trials:
            receipt['observations'].append(read_trial(directory, final, ready['manifest_sha256'],
                row, ready.get('setup_phases', []), teardown))
        load_frozen(final_path, ready['manifest_sha256'])
        receipt.update(project(final, receipt['observations']))
        receipt['complete'] = True
        return receipt
    except BaseException as error:
        receipt.update(decision='pause' if isinstance(error, CheckpointFailure) else 'incomplete',
                       error=type(error).__name__ + ': ' + str(error))
        raise
    finally:
        # Never kill the delegated cgroup supervisor or unrelated processes.
        # On a pre-grant validation failure, explicitly cancel the cooperative
        # worker and let the supervisor enforce its own timeout and cleanup.
        if process is not None and process.poll() is None:
            (control / 'cancel.json').write_text(json.dumps({'cancel': True}) + '\n')
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                receipt['runner_cleanup_pending'] = True
        if receipt.get('complete') is not True:
            receipt['failure'] = failure_evidence(directory)
            if receipt['failure']['classification'] in ('cgroup-oom', 'cgroup-memory-limit', 'process-timeout'):
                receipt['decision'] = 'pause'
        report.write_text(json.dumps(receipt, indent=2) + '\n')


def public_summary(report):
    keys = ('schema', 'purpose', 'complete', 'acceptance', 'trials', 'decision',
        'resource_limits',
        'projected_total_ns', 'projected_memory_peak', 'observed_memory_peak_median',
        'observed_memory_peak_max', 'phase_medians', 'time_margin_ns', 'memory_margin_bytes',
        'trial_sampled_memory_peak_median', 'trial_sampled_memory_peak_max',
        'time_evidence_kind', 'memory_evidence_kind', 'handoff_overhead_median_ns', 'timed_total_ns_max')
    result = {key: report[key] for key in keys if key in report}
    trial_keys = ('trial', 'timed_total_ns', 'handoff_overhead_ns', 'retained_serialized_bytes',
                  'canonical_root_output', 'handoff_memory',
                  'sampled_trial_memory_peak', 'memory_peak', 'memory_peak_scope',
                  'swap_peak', 'verified')
    if report.get('failure'):
        failure_keys = ('classification', 'last_phase', 'memory_peak', 'swap_peak',
            'zero_swap_observed', 'memory_events_delta', 'memory_max', 'memory_swap_max',
            'exit_code', 'timed_out', 'resource_control_pass', 'phase_evidence_incomplete',
            'rejected_security_bound')
        result['failure'] = {key: report['failure'][key] for key in failure_keys if key in report['failure']}
        phase_keys = ('phase', 'completed', 'wall_ns', 'sample_count', 'interval_sample_count',
            'boundary_sample_count', 'sampled_memory_peak', 'memory_evidence_kind',
            'kernel_lifetime_peak_upper_reference')
        result['failure']['completed_phase_summaries'] = [{key: phase[key] for key in phase_keys if key in phase}
            for phase in report['failure'].get('completed_phase_summaries', [])]
        if report['failure'].get('interrupted_phase_summary'):
            phase = report['failure']['interrupted_phase_summary']
            result['failure']['interrupted_phase_summary'] = {key: phase[key] for key in phase_keys if key in phase}
    if report.get('complete') is True:
        result['trial_observations'] = []
        for trial in report.get('observations', []):
            row = {key: trial[key] for key in trial_keys if key in trial}
            row['phases'] = {name: {key: phase[key] for key in ('wall_ns', 'sample_count',
                'sampled_memory_peak', 'memory_evidence_kind', 'kernel_lifetime_peak_upper_reference')
                if key in phase} for name, phase in trial.get('phases', {}).items()}
            result['trial_observations'].append(row)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--validate-only', action='store_true')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--timeout', type=int, default=3600)
    args = parser.parse_args()
    if args.timeout <= 0 or (not args.validate_only and args.output is None):
        parser.error('A positive timeout and an output directory for measured runs are required')
    try:
        if args.validate_only:
            load_bootstrap(args.manifest, args.sha256)
            print(json.dumps({'complete': False, 'acceptance': False, 'manifest_validated': True,
                              'resource_limits': dict(RESOURCE_LIMITS)}))
            return
        report = run(args)
        print(json.dumps(public_summary(report), indent=2))
        raise SystemExit(0 if report['decision'] != 'pause' else 1)
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(json.dumps({'complete': False, 'acceptance': False,
                          'resource_limits': dict(RESOURCE_LIMITS),
                          'decision': 'pause' if isinstance(error, CheckpointFailure) else 'incomplete',
                          'error': type(error).__name__ + ': ' + str(error)}), file=sys.stderr)
        raise SystemExit(1 if isinstance(error, CheckpointFailure) else 2)


if __name__ == '__main__':
    main()
