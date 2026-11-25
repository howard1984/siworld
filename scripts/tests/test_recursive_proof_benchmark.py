import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('d8_checkpoint', Path(__file__).parents[1] / 'bench/measure-recursive-proof-benchmark.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def term(value):
    return {'value': value, 'kind': 'estimated', 'evidence': 'root_model#reviewed-memory-model',
            'includes_resident': False}


def manifest():
    memory = {'resident_all': term(100), 'startup_peak': term(500),
              'resident_components': {name: term(25) for name in (*MODULE.LAYERS, 'fixed_service')},
              'phases': {name: {'workspace': term(200), 'retained': term(100)}
                         for name in MODULE.PROJECTED_PHASES}}
    return {'schema': 1, 'checkpoint_mode': 'merge8-early', 'suite': MODULE.SUITE,
            'resource_limits': dict(MODULE.RESOURCE_LIMITS), 'poseidon2_parameters': 'Plonky3-standard',
            'source_revision': 'a' * 40, 'recursion_revision': 'b' * 40,
            'execution': {'slots': 16, 'jobs': 1, 'native_workers': 2,
                          'rayon_threads': 2, 'hiding_workers': 2},
            'parameters': {name: {'log_blowup': 3, 'queries': 160,
                'commit_grinding': 16, 'query_grinding': 16, 'batch_grinding': 16,
                'max_log_arity': 1, 'final_poly_log': 0}
                for name in MODULE.LAYERS},
            'projection': {'memory': memory, 'root_time': {'kind': 'merge8-proxy',
                'evidence': 'root_model#root-shape-and-time-proxy'},
                'overhead_ns': term(1_000_000_000)}}


def shape(status):
    return {'status': status, 'tables': [{'height': 1024, 'main_columns': 100,
        'preprocessed_columns': 0}], 'constraints': 1000, 'max_degree': 7,
        'quotient_chunks': 8, 'lookup_dimensions': [8, 12], 'batched_openings': 100,
        'estimate_basis': 'Frozen root model with all resident allocations'}


def shapes():
    return {'suite': MODULE.SUITE, 'layers': {
        'leaf': shape('actual-extracted'), 'merge8': shape('actual-extracted'),
        'root': shape('shape-estimate')}}


def security():
    row = {'bounds': {'conjectured': 130, 'johnson': 110,
        'quantum_challenges': 101, 'bht_collision': 123},
        'error_terms': {name: {'classical_bits': 202, 'quantum_bits': 101}
                        for name in MODULE.SECURITY_TERMS}, 'weakest_term': 'fri_fold'}
    return {'p3_security': '0.9.0-rc.2', 'suite': MODULE.SUITE,
            'layers': {name: copy.deepcopy(row) for name in MODULE.LAYERS},
            'composition': {**copy.deepcopy(row), 'proof_count': 19}}


def trial(merge_ns=30_000_000_000, peak=500):
    return {'resource_control_pass': True, 'memory_peak': peak,
        'resource_limits': dict(MODULE.RESOURCE_LIMITS),
        'swap_peak': 0, 'phases': {name: {'wall_ns': 10_000_000_000 if name == 'leaf16'
            else merge_ns if name == 'merge8' else 1_000_000_000,
            'sampled_memory_peak': 300, 'sample_count': 2}
            for name in MODULE.MEASURED_PHASES}}


class CheckpointTests(unittest.TestCase):
    def test_valid_metadata_allows_explicit_root_estimate(self):
        MODULE.validate_metadata(manifest(), shapes(), security())

    def test_header_requires_exact_experimental_resource_limits(self):
        for limits in (None, {},
                {**MODULE.RESOURCE_LIMITS, 'memory_max': 5368709120},
                {**MODULE.RESOURCE_LIMITS, 'memory_max': 21474836480},
                {**MODULE.RESOURCE_LIMITS, 'memory_swap_max': 1},
                {**MODULE.RESOURCE_LIMITS, 'memory_swap_max': False},
                {**MODULE.RESOURCE_LIMITS, 'production_memory_budget_status': 'approved'},
                {**MODULE.RESOURCE_LIMITS, 'production_memory_budget': 10737418240}):
            with self.subTest(limits=limits):
                value = manifest()
                value['resource_limits'] = limits
                with self.assertRaisesRegex(ValueError, 'experimental limit'):
                    MODULE.validate_header(value)

    def test_d4_substitute_rejected(self):
        value = manifest()
        value['suite'] = 'D4-W16'
        with self.assertRaisesRegex(ValueError, 'suite'):
            MODULE.validate_metadata(value, shapes(), security())

    def test_zero_batch_grinding_rejected(self):
        value = manifest()
        value['parameters']['merge8']['batch_grinding'] = 0
        with self.assertRaisesRegex(ValueError, 'batch'):
            MODULE.validate_metadata(value, shapes(), security())

    def test_estimated_merge_shape_rejected(self):
        value = shapes()
        value['layers']['merge8']['status'] = 'shape-estimate'
        with self.assertRaisesRegex(ValueError, 'actual'):
            MODULE.validate_metadata(manifest(), value, security())

    def test_composition_cannot_omit_union(self):
        value = security()
        value['composition']['proof_count'] = 1
        with self.assertRaisesRegex(ValueError, '19'):
            MODULE.validate_metadata(manifest(), shapes(), value)

    def test_individual_security_term_failure_rejected(self):
        value = security()
        value['layers']['merge8']['error_terms']['fri_fold']['quantum_bits'] = 99
        with self.assertRaisesRegex(ValueError, 'fri_fold'):
            MODULE.validate_metadata(manifest(), shapes(), value)

    def test_unknown_root_residency_is_incomplete(self):
        value = manifest()
        value['projection']['memory']['phases']['root']['workspace']['value'] = None
        with self.assertRaisesRegex(ValueError, 'workspace'):
            MODULE.project(value, [trial(), trial(), trial()])

    def test_missing_handoff_is_incomplete(self):
        value = manifest()
        del value['projection']['memory']['phases']['handoffs']['retained']
        with self.assertRaises(ValueError):
            MODULE.project(value, [trial(), trial(), trial()])

    def test_median_projection_does_not_sum_independent_memory_peaks(self):
        value = MODULE.project(manifest(), [trial(30_000_000_000),
            trial(31_000_000_000), trial(29_000_000_000)])
        self.assertEqual(value['projected_total_ns'], 101_000_000_000)
        self.assertEqual(value['projected_memory_peak'], 500)
        self.assertEqual(value['decision'], 'continue')
        self.assertFalse(value['acceptance'])

    def test_exact_thresholds(self):
        self.assertEqual(MODULE.decide(135_000_000_000, MODULE.EXPERIMENTAL_MEMORY_MAX), 'continue')
        self.assertEqual(MODULE.decide(135_000_000_001, MODULE.EXPERIMENTAL_MEMORY_MAX), 'continue-optimize')
        self.assertEqual(MODULE.decide(180_000_000_000, MODULE.EXPERIMENTAL_MEMORY_MAX), 'continue-optimize')
        self.assertEqual(MODULE.decide(180_000_000_001, MODULE.EXPERIMENTAL_MEMORY_MAX), 'pause')
        self.assertEqual(MODULE.decide(1, MODULE.EXPERIMENTAL_MEMORY_MAX + 1), 'pause')
        self.assertEqual(MODULE.decide(1, 5368709120 + 1), 'continue')

    def test_projection_margins_use_experimental_ceiling_without_production_acceptance(self):
        result = MODULE.project(manifest(), [trial(peak=8 * 1024**3) for _ in range(3)])
        self.assertEqual(result['decision'], 'continue')
        self.assertEqual(result['memory_margin_bytes'], 2 * 1024**3)
        self.assertEqual(result['resource_limits'], MODULE.RESOURCE_LIMITS)
        self.assertEqual(result['resource_limits']['production_memory_budget_status'], 'undecided')
        self.assertFalse(result['acceptance'])

    def test_projection_rejects_mixed_resource_limits(self):
        rows = [trial(), trial(), trial()]
        rows[1]['resource_limits']['memory_max'] = 5368709120
        with self.assertRaisesRegex(ValueError, 'resource limits'):
            MODULE.project(manifest(), rows)

    def test_observed_maximum_cannot_hide_behind_median(self):
        value = MODULE.project(manifest(), [trial(), trial(), trial(peak=MODULE.EXPERIMENTAL_MEMORY_MAX + 1)])
        self.assertEqual(value['decision'], 'pause')

    def test_failed_trial_cannot_be_discarded(self):
        value = trial()
        value['resource_control_pass'] = False
        with self.assertRaisesRegex(ValueError, 'failed'):
            MODULE.project(manifest(), [trial(), value, trial()])

    def test_missing_phase_samples_are_incomplete(self):
        value = trial()
        value['phases']['merge8']['sample_count'] = 0
        with self.assertRaisesRegex(ValueError, 'sample'):
            MODULE.project(manifest(), [trial(), trial(), value])

    def test_requires_exactly_three_trials(self):
        with self.assertRaisesRegex(ValueError, 'three'):
            MODULE.project(manifest(), [trial(), trial()])

    def test_bundle_paths_cannot_escape_or_follow_external_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            (base / 'file').write_text('data')
            self.assertEqual(MODULE.bundle_file(base, 'file'), (base / 'file').resolve())
            for path in ('../file', '/etc/passwd'):
                with self.assertRaises(ValueError):
                    MODULE.bundle_file(base, path)
            (base / 'link').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError):
                MODULE.bundle_file(base, 'link')

    def test_phase_attribution_is_sampled_not_exact(self):
        phases = [{'phase': 'merge8', 'start_ns': 110, 'end_ns': 210}]
        measurement = {'monotonic_started_ns': 100, 'memory_peak': 900,
            'samples': [{'elapsed_ns': 20, 'memory_current': 300},
                        {'elapsed_ns': 100, 'memory_current': 500}]}
        value = MODULE.attribute_phases(phases, measurement)['merge8']
        self.assertEqual(value['sampled_memory_peak'], 500)
        self.assertEqual(value['kernel_lifetime_peak_upper_reference'], 900)
        self.assertEqual(value['memory_evidence_kind'], 'sampled-lower-bound')

    def test_phase_outside_lifetime_rejected(self):
        measurement = {'monotonic_started_ns': 100, 'elapsed_ns': 50,
                       'memory_peak': 100, 'samples': []}
        with self.assertRaisesRegex(ValueError, 'interval'):
            MODULE.attribute_phases([{'phase': 'merge8', 'start_ns': 90, 'end_ns': 110}], measurement)

    def test_missing_security_bound_is_not_a_pass(self):
        value = security()
        del value['composition']['bounds']['bht_collision']
        with self.assertRaisesRegex(ValueError, 'bht_collision'):
            MODULE.validate_metadata(manifest(), shapes(), value)


    def test_resident_memory_cannot_be_double_counted(self):
        value = manifest()
        value['projection']['memory']['phases']['root']['workspace']['includes_resident'] = True
        with self.assertRaisesRegex(ValueError, 'exclude'):
            MODULE.project(value, [trial(), trial(), trial()])

    def test_resident_component_inventory_is_required(self):
        value = manifest()
        del value['projection']['memory']['resident_components']['root']
        with self.assertRaisesRegex(ValueError, 'resident.root'):
            MODULE.project(value, [trial(), trial(), trial()])

    def test_nonfinite_security_is_rejected(self):
        value = security()
        value['layers']['leaf']['bounds']['conjectured'] = float('nan')
        with self.assertRaisesRegex(ValueError, 'conjectured'):
            MODULE.validate_metadata(manifest(), shapes(), value)

    def test_external_unfrozen_evidence_reference_is_rejected(self):
        value = manifest()
        value['projection']['memory']['startup_peak']['evidence'] = 'unfrozen-report#startup'
        with self.assertRaisesRegex(ValueError, 'evidence'):
            MODULE.project(value, [trial(), trial(), trial()])

    def test_handoff_overhead_cannot_be_omitted(self):
        value = manifest()
        value['projection']['overhead_ns']['value'] = 0
        with self.assertRaisesRegex(ValueError, 'handoff'):
            MODULE.project(value, [trial(), trial(), trial()])

    def test_short_phase_uses_boundary_readings_without_sleep(self):
        measurement = {'monotonic_started_ns': 100, 'elapsed_ns': 100,
            'memory_peak': 900, 'samples': []}
        phases = [{'phase': 'handoffs', 'start_ns': 110, 'end_ns': 111,
                   'memory_start': 400, 'memory_end': 500}]
        value = MODULE.attribute_phases(phases, measurement)['handoffs']
        self.assertEqual(value['sample_count'], 2)
        self.assertEqual(value['interval_sample_count'], 0)
        self.assertEqual(value['boundary_sample_count'], 2)
        self.assertEqual(value['sampled_memory_peak'], 500)

    def test_overlapping_phase_intervals_rejected(self):
        measurement = {'monotonic_started_ns': 100, 'elapsed_ns': 100,
            'memory_peak': 900, 'samples': []}
        phases = [{'phase': 'leaf16', 'start_ns': 110, 'end_ns': 140},
                  {'phase': 'merge8', 'start_ns': 130, 'end_ns': 180}]
        with self.assertRaisesRegex(ValueError, 'interval'):
            MODULE.attribute_phases(phases, measurement)

    def test_failed_merge_is_a_pause(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'measurement.json').write_text(json.dumps({'resource_control_pass': True}))
            (directory / 'stdout.jsonl').write_text(json.dumps({
                'event': 'd8_checkpoint_trial', 'verified': False}) + '\n')
            with self.assertRaises(MODULE.CheckpointFailure):
                MODULE.read_trial(directory, manifest(), 'a' * 64)

    def test_no_worker_result_is_incomplete(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'measurement.json').write_text(json.dumps({'resource_control_pass': True}))
            (directory / 'stdout.jsonl').write_text('')
            with self.assertRaisesRegex(ValueError, 'worker result'):
                MODULE.read_trial(directory, manifest(), 'a' * 64)

    def test_report_summary_excludes_private_raw_observations(self):
        value = MODULE.project(manifest(), [trial(), trial(), trial()])
        value.update(same_live_machine_boot_id='private', observations=[{'private': True}])
        summary = MODULE.public_summary(value)
        self.assertNotIn('observations', summary)
        self.assertNotIn('same_live_machine_boot_id', summary)
        self.assertIn('phase_medians', summary)
        self.assertEqual(summary['resource_limits'], MODULE.RESOURCE_LIMITS)

    def test_summary_does_not_relabel_historical_resource_limits(self):
        historical = {**MODULE.RESOURCE_LIMITS, 'memory_max': 5368709120}
        summary = MODULE.public_summary({'complete': False, 'acceptance': False,
            'resource_limits': historical})
        self.assertEqual(summary['resource_limits'], historical)
        self.assertEqual(summary['resource_limits']['memory_max'], 5368709120)


    def full_trials(self):
        rows = []
        for index in range(1, 4):
            phases = {name: {'wall_ns': 10_000_000_000,
                'sampled_memory_peak': 300, 'sample_count': 2}
                for name in MODULE.FULL_PHASES}
            rows.append({'trial': index, 'resource_control_pass': True,
                'resource_limits': dict(MODULE.RESOURCE_LIMITS),
                'swap_peak': 0, 'memory_peak': 500, 'phases': phases,
                'timed_total_ns': 101_000_000_000 + index,
                'handoff_overhead_ns': 1_000_000_000,
                'handoff_memory': {'wall_ns': 1_000_000_000, 'sampled_memory_peak': 250},
                'sampled_trial_memory_peak': 300 + index})
        return rows

    def test_full_proof_can_use_actual_memory_without_allocator_estimates(self):
        value = manifest()
        value['checkpoint_mode'] = 'n16-full'
        result = MODULE.project(value, self.full_trials())
        self.assertEqual(result['projected_total_ns'], 101_000_000_002)
        self.assertEqual(result['projected_memory_peak'], 500)
        self.assertEqual(result['trial_sampled_memory_peak_median'], 302)
        self.assertIn('kernel lifetime', result['memory_evidence_kind'])
        self.assertFalse(result['acceptance'])
        self.assertEqual(result['memory_margin_bytes'], MODULE.EXPERIMENTAL_MEMORY_MAX - 500)
        self.assertEqual(result['resource_limits'], MODULE.RESOURCE_LIMITS)

    def test_full_projection_rejects_old_or_mixed_resource_limits(self):
        rows = self.full_trials()
        rows[0]['resource_limits']['memory_max'] = 5368709120
        with self.assertRaisesRegex(ValueError, 'resource limits'):
            MODULE.project_full(rows, MODULE.RESOURCE_LIMITS)

    def test_full_trials_cannot_mix_independent_process_lifetime_peaks(self):
        rows = self.full_trials()
        rows[2]['memory_peak'] = 501
        with self.assertRaisesRegex(ValueError, 'share one'):
            MODULE.project_full(rows, MODULE.RESOURCE_LIMITS)

    def test_full_trials_must_be_ordered_without_retry(self):
        rows = self.full_trials()
        rows[2]['trial'] = 2
        with self.assertRaisesRegex(ValueError, 'ordered'):
            MODULE.project_full(rows, MODULE.RESOURCE_LIMITS)

    def test_complete_root_shape_cannot_be_an_estimate(self):
        value = manifest()
        value['checkpoint_mode'] = 'n16-full'
        with self.assertRaisesRegex(ValueError, 'actual'):
            MODULE.validate_metadata(value, shapes(), security())

    def test_setup_cannot_change_pre_frozen_parameters(self):
        before = manifest()
        before['files'] = {role: {'path': role, 'sha256': 'a' * 64} for role in MODULE.INITIAL_ROLES}
        after = copy.deepcopy(before)
        after['parameters']['root']['queries'] += 1
        with self.assertRaisesRegex(ValueError, 'parameters'):
            MODULE.check_setup_freeze(before, after)

    def test_setup_cannot_change_pre_frozen_resource_limits(self):
        before = manifest()
        before['files'] = {role: {'path': role, 'sha256': 'a' * 64} for role in MODULE.INITIAL_ROLES}
        after = copy.deepcopy(before)
        after['resource_limits']['memory_max'] = 5368709120
        with self.assertRaisesRegex(ValueError, 'resource_limits'):
            MODULE.check_setup_freeze(before, after)

    def test_supervisor_receives_frozen_experimental_memory_limit(self):
        from types import SimpleNamespace
        args = SimpleNamespace(timeout=3600, manifest=Path('/synthetic/bootstrap.json'), sha256='a' * 64)
        command = MODULE.supervisor_command(args, {'launcher': Path('/synthetic/bin/recursive-proof-benchmark')},
            Path('/synthetic/process-tree'), Path('/synthetic/control'), MODULE.RESOURCE_LIMITS)
        option = command.index('--memory-max')
        self.assertLess(option, command.index('--'))
        self.assertEqual(command[option + 1], '10737418240')
        self.assertEqual(command[command.index('--timeout') + 1], '3600')
        self.assertEqual(command[command.index('--hardware-profile') + 1], 'epyc7763-baseline')
        self.assertNotIn('5368709120', command)
        with self.assertRaisesRegex(ValueError, 'experimental limit'):
            MODULE.supervisor_command(args, {}, Path('/synthetic/tree'), Path('/synthetic/control'),
                {**MODULE.RESOURCE_LIMITS, 'memory_max': 5368709120})

    def test_setup_cannot_replace_pre_frozen_binary(self):
        before = manifest()
        before['files'] = {role: {'path': role, 'sha256': 'a' * 64} for role in MODULE.INITIAL_ROLES}
        after = copy.deepcopy(before)
        after['files']['worker']['sha256'] = 'b' * 64
        with self.assertRaisesRegex(ValueError, 'worker'):
            MODULE.check_setup_freeze(before, after)

    def test_full_trial_reconstructs_boundary_and_excludes_verification(self):
        value = manifest()
        value['checkpoint_mode'] = 'n16-full'
        setup = [{'phase': 'startup', 'start_ns': 110, 'end_ns': 200, 'memory_start': 10, 'memory_end': 200},
                 {'phase': 'ready_resident', 'start_ns': 210, 'end_ns': 300, 'memory_start': 200, 'memory_end': 200}]
        phases = [{'phase': name, 'start_ns': 400 + index * 200,
                   'end_ns': 500 + index * 200, 'memory_start': 200, 'memory_end': 300}
                  for index, name in enumerate(('leaf16', 'merge1', 'merge2', 'root', 'verification'))]
        teardown = {'phase': 'teardown', 'start_ns': 2000, 'end_ns': 2100, 'memory_start': 200, 'memory_end': 10}
        row = {'event': 'd8_checkpoint_trial', 'trial': 1, 'suite': MODULE.SUITE,
            'manifest_sha256': 'a' * 64, 'verified': True, 'fresh_hiding_randomness': True,
            'parameters': value['parameters'], 'execution': value['execution'],
            'leaf_proofs_at_merge_start': 16,
            'batch_grinding_verified_paths': ['native', 'recursive', 'prepared'],
            'runtime': {'packing_width': 8, 'compiled_avx2': True, 'compiled_avx512f': False,
                'global_rayon_threads': 2, 'rayon_num_threads': '2', 'composition_hiding_workers': '2'},
            'timed_start_ns': 400, 'timed_end_ns': 1100,
            'canonical_root_output': {'encoding': 'plonky3-canonical-artifact',
                'completed_ns': 1090, 'bytes': 100},
            'retained_serialized_bytes': {name: 100 for name in ('leaves', 'merge1', 'merge2', 'root')},
            'phases': phases}
        measurement = {'resource_control_pass': True,
            'hardware_qualification': {'profile': 'epyc7763-baseline', 'profile_qualified': True},
            'memory_max': MODULE.EXPERIMENTAL_MEMORY_MAX, 'memory_swap_max': 0,
            'worker_environment': {'RAYON_NUM_THREADS': '2', 'SIWORLD_COMPOSITION_HIDING_WORKERS': '2'},
            'monotonic_started_ns': 100, 'elapsed_ns': 3000, 'samples': [],
            'memory_peak': 500, 'swap_peak': 0, 'memory_events_delta': {}}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'measurement.json').write_text(json.dumps(measurement))
            result = MODULE.read_trial(directory, value, 'a' * 64, row, setup, teardown)
            measurement['memory_max'] = 5368709120
            (directory / 'measurement.json').write_text(json.dumps(measurement))
            with self.assertRaisesRegex(ValueError, '10-GiB experimental'):
                MODULE.read_trial(directory, value, 'a' * 64, row, setup, teardown)
        self.assertEqual(result['timed_total_ns'], 700)
        self.assertEqual(result['handoff_overhead_ns'], 300)
        self.assertEqual(result['sampled_trial_memory_peak'], 300)
        self.assertEqual(result['phases']['verification']['wall_ns'], 100)
        self.assertEqual(result['handoff_memory']['wall_ns'], 300)
        self.assertEqual(result['handoff_memory']['sampled_memory_peak'], 300)
        self.assertEqual(result['resource_limits'], MODULE.RESOURCE_LIMITS)


    def test_handoff_memory_attributes_only_gaps_and_boundary_charges(self):
        phases = [{'phase': name, 'start_ns': first, 'end_ns': first + 100,
                   'memory_start': 200, 'memory_end': 300}
                  for name, first in zip(('leaf16', 'merge1', 'merge2', 'root'), (400, 600, 800, 1000))]
        measurement = {'monotonic_started_ns': 100, 'memory_peak': 1000,
            'samples': [{'elapsed_ns': 450, 'memory_current': 700},
                        {'elapsed_ns': 550, 'memory_current': 900},
                        {'elapsed_ns': 650, 'memory_current': 800},
                        {'elapsed_ns': 1050, 'memory_current': 1000}]}
        result = MODULE.attribute_handoff_gaps(phases, 400, 1100, measurement)
        self.assertEqual(result['wall_ns'], 300)
        self.assertEqual(result['sampled_memory_peak'], 800)
        self.assertEqual(result['interval_sample_count'], 2)
        self.assertEqual(result['boundary_sample_count'], 6)
        self.assertEqual(result['memory_evidence_kind'], 'sampled-lower-bound')
        self.assertEqual(result['kernel_lifetime_peak_upper_reference'], 1000)
        self.assertEqual(result['gaps'], [{'start_ns': start, 'end_ns': start + 100}
                                         for start in (500, 700, 900)])

    def test_zero_handoff_interval_has_unknown_memory_not_zero(self):
        phases = [{'phase': 'root', 'start_ns': 400, 'end_ns': 500,
                   'memory_start': 200, 'memory_end': 300}]
        result = MODULE.attribute_handoff_gaps(phases, 400, 500,
            {'monotonic_started_ns': 100, 'memory_peak': 500, 'samples': []})
        self.assertEqual(result['wall_ns'], 0)
        self.assertIsNone(result['sampled_memory_peak'])
        self.assertEqual(result['sample_count'], 0)

    def test_canonical_root_output_must_be_complete_and_retained_before_timing_end(self):
        phase = {'start_ns': 1000, 'end_ns': 1100}
        row = {'canonical_root_output': {'encoding': 'plonky3-canonical-artifact',
                   'completed_ns': 1090, 'bytes': 100},
               'retained_serialized_bytes': {'root': 100}}
        self.assertEqual(MODULE.validate_canonical_root_output(row, phase, 1110)['bytes'], 100)
        for field, value in (('encoding', 'postcard'), ('completed_ns', 1101),
                             ('completed_ns', 999), ('bytes', 0), ('bytes', 99)):
            with self.subTest(field=field, value=value):
                invalid = copy.deepcopy(row)
                invalid['canonical_root_output'][field] = value
                with self.assertRaises(ValueError):
                    MODULE.validate_canonical_root_output(invalid, phase, 1110)
        with self.assertRaisesRegex(ValueError, 'timing boundary'):
            MODULE.validate_canonical_root_output(row, phase, 1099)
        with self.assertRaisesRegex(ValueError, 'canonical root artifact'):
            MODULE.validate_canonical_root_output({}, phase, 1110)


    def test_bootstrap_package_receipt_matches_current_isa_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = manifest()
            value['stage'] = 'bootstrap'
            value['checkpoint_mode'] = 'n16-full'
            value['files'] = {}
            for role in MODULE.INITIAL_ROLES:
                relative = ('release/bin/recursive-proof-benchmark' if role == 'launcher' else
                            'release/libexec/recursive-proof-benchmark' if role == 'worker' else role + '.json')
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('Synthetic nonexecutable fixture for manifest-validation tests')
                value['files'][role] = {'path': relative, 'sha256': MODULE.digest(path)}
            def save(role, data):
                path = root / value['files'][role]['path']
                path.write_text(json.dumps(data))
                value['files'][role]['sha256'] = MODULE.digest(path)
            save('configuration', {key: value[key] for key in
                ('suite', 'source_revision', 'recursion_revision', 'parameters', 'resource_limits')})
            save('root_model', {'projection': value['projection']})
            worker_sha = value['files']['worker']['sha256']
            config_sha = value['files']['cargo_config']['sha256']
            save('build_receipt', {'worker_isa': 'x86-64-v3', 'bootstrap_isa': 'x86-64',
                'bootstrap_sha256': value['files']['launcher']['sha256'],
                'repository_config_sha256': config_sha,
                'workers': [{'name': 'recursive-proof-benchmark', 'worker_sha256': worker_sha,
                    'isa_inspection': {'required_isa': 'x86-64-v3',
                        'binary_sha256': worker_sha, 'avx2_packed_multiply_instructions': 1}}],
                'worker_build_receipt': {'binary_sha256': worker_sha,
                    'effective_rustflags': '-C target-cpu=x86-64-v3',
                    'cargo_working_directory': 'repository-root',
                    'repository_config_sha256': config_sha}})
            path = root / 'bootstrap.json'
            path.write_text(json.dumps(value))
            loaded, _ = MODULE.load_bootstrap(path, MODULE.digest(path))
            self.assertEqual(loaded['stage'], 'bootstrap')
            self.assertEqual(loaded['parameters'], value['parameters'])
            self.assertEqual(loaded['resource_limits'], MODULE.RESOURCE_LIMITS)
            configuration = {key: value[key] for key in
                ('suite', 'source_revision', 'recursion_revision', 'parameters', 'resource_limits')}
            for limits in (None, {**MODULE.RESOURCE_LIMITS, 'memory_max': 5368709120},
                    {**MODULE.RESOURCE_LIMITS, 'production_memory_budget_status': 'approved'}):
                with self.subTest(limits=limits):
                    save('configuration', {**configuration, 'resource_limits': limits})
                    path.write_text(json.dumps(value))
                    with self.assertRaisesRegex(ValueError, 'Frozen configuration'):
                        MODULE.load_bootstrap(path, MODULE.digest(path))


    def test_startup_oom_summary_preserves_memory_and_phase_evidence_without_values(self):
        measurement = {'monotonic_started_ns': 1000, 'elapsed_ns': 1000,
            'memory_peak': MODULE.EXPERIMENTAL_MEMORY_MAX, 'swap_peak': 0, 'memory_max': MODULE.EXPERIMENTAL_MEMORY_MAX,
            'memory_swap_max': 0, 'resource_control_pass': False, 'exit_code': -9,
            'timed_out': False, 'memory_events_delta': {'max': 4, 'oom': 1, 'oom_kill': 1},
            'samples': [{'elapsed_ns': 150, 'memory_current': 200},
                        {'elapsed_ns': 500, 'memory_current': 400}]}
        rows = [{'event': 'd8_phase_start', 'phase': 'prepare_leaf', 'start_ns': 1100, 'memory_start': 100},
                {'event': 'd8_phase_end', 'measurement': {'phase': 'prepare_leaf', 'start_ns': 1100,
                    'end_ns': 1200, 'memory_start': 100, 'memory_end': 150}},
                {'event': 'd8_phase_start', 'phase': 'prepare_merge8', 'start_ns': 1300, 'memory_start': 150},
                {'event': 'd8_checkpoint_failure', 'error': 'secret-proof-value /private-build/private-owner/file'}]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'measurement.json').write_text(json.dumps(measurement))
            (directory / 'stdout.jsonl').write_text('\n'.join(json.dumps(row) for row in rows))
            evidence = MODULE.failure_evidence(directory)
        summary = MODULE.public_summary({'complete': False, 'decision': 'pause', 'failure': evidence,
            'resource_limits': dict(MODULE.RESOURCE_LIMITS)})
        self.assertEqual(summary['failure']['classification'], 'cgroup-oom')
        self.assertEqual(summary['failure']['last_phase'], 'prepare_merge8')
        self.assertEqual(summary['failure']['memory_peak'], MODULE.EXPERIMENTAL_MEMORY_MAX)
        self.assertEqual(summary['resource_limits'], MODULE.RESOURCE_LIMITS)
        self.assertEqual(summary['resource_limits']['production_memory_budget_status'], 'undecided')
        self.assertTrue(summary['failure']['zero_swap_observed'])
        self.assertEqual(summary['failure']['completed_phase_summaries'][0]['sampled_memory_peak'], 200)
        self.assertEqual(summary['failure']['interrupted_phase_summary']['sampled_memory_peak'], 400)
        self.assertFalse(summary['failure']['interrupted_phase_summary']['completed'])
        self.assertNotIn('secret-proof-value', json.dumps(summary))
        self.assertNotIn('private-owner', json.dumps(summary))

    def test_missing_failure_resource_readings_are_unknown_not_zero(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = MODULE.failure_evidence(Path(temporary))
        self.assertEqual(result['classification'], 'collection-incomplete')
        self.assertIsNone(result['memory_peak'])
        self.assertIsNone(result['zero_swap_observed'])
        self.assertIsNone(result['memory_events_delta'])


class BuilderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('d8_builder', Path(__file__).parents[1] / 'bench/build-recursive-proof-benchmark.py')
        cls.builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.builder)

    def test_application_dependencies_require_the_direct_fork_pin(self):
        text = '[workspace.dependencies]\n' + '\n'.join(
            name + ' = { git = "' + self.builder.URL + '", rev = "' + self.builder.PIN
            + '", default-features = false, features = ["parallel"] }'
            for name in self.builder.DEPENDENCIES)
        self.builder.validate_application_dependencies(text)
        with self.assertRaisesRegex(ValueError, 'exact pinned'):
            self.builder.validate_application_dependencies(text.replace(self.builder.PIN, 'a' * 40))
        with self.assertRaisesRegex(ValueError, 'exact pinned'):
            self.builder.validate_application_dependencies(text.replace(self.builder.URL, self.builder.UPSTREAM_URL))

    def test_registry_pin_comparison_retains_versions_and_checksums(self):
        lock = ('[[package]]\nname = "one"\nversion = "1"\nsource = "registry+url"\nchecksum = "abc"\n'
                '[[package]]\nname = "two"\nversion = "2"\nsource = "git+url#pin"\n')
        self.assertEqual(self.builder.registry_pins(lock), {('one', '1', 'abc')})

    def test_builder_freezes_experimental_limits_in_manifest_configuration_and_receipt(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination, workspace, upstream = (root / name for name in ('output', 'application', 'upstream'))
            for path in (destination, workspace, upstream, root / '.cargo'):
                path.mkdir(parents=True)
            (workspace / 'Cargo.lock').write_text('Synthetic dependency lock fixture')
            (upstream / 'source.rs').write_text('// Synthetic nonexecutable source fixture\n')
            (root / '.cargo/config.toml').write_text('Synthetic build configuration fixture')
            dependency_patch = root / 'recursion.patch'
            dependency_patch.write_text('Synthetic dependency patch fixture')
            launcher = destination / 'release/bin/recursive-proof-benchmark'
            worker = destination / 'release/libexec/recursive-proof-benchmark'
            for path in (launcher, worker):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('Synthetic nonexecutable release fixture')
            worker_sha = MODULE.digest(worker)
            config_sha = MODULE.digest(root / '.cargo/config.toml')
            build_receipt = {'worker_isa': 'x86-64-v3', 'bootstrap_isa': 'x86-64',
                'bootstrap_sha256': MODULE.digest(launcher), 'repository_config_sha256': config_sha,
                'workers': [{'name': 'recursive-proof-benchmark', 'worker_sha256': worker_sha,
                    'isa_inspection': {'required_isa': 'x86-64-v3', 'binary_sha256': worker_sha,
                        'avx2_packed_multiply_instructions': 1}}],
                'worker_build_receipt': {'binary_sha256': worker_sha,
                    'effective_rustflags': '-C target-cpu=x86-64-v3',
                    'cargo_working_directory': 'repository-root', 'repository_config_sha256': config_sha}}
            (destination / 'release/build-receipt.json').write_text(json.dumps(build_receipt))
            with patch.object(self.builder, 'ROOT', root), patch.object(self.builder, 'PATCH', dependency_patch), \
                    patch.object(self.builder, 'load_script', return_value=MODULE):
                path = self.builder.write_bootstrap(destination, workspace, upstream,
                    {'binary_sha256': worker_sha}, 'a' * 40)
            value = json.loads(path.read_text())
            configuration = json.loads((path.parent / value['files']['configuration']['path']).read_text())
            receipt = json.loads((destination / 'bootstrap-receipt.json').read_text())
            for record in (value, configuration, receipt):
                self.assertEqual(record['resource_limits'], MODULE.RESOURCE_LIMITS)
                self.assertEqual(record['resource_limits']['production_memory_budget_status'], 'undecided')
            loaded, _ = MODULE.load_bootstrap(path, MODULE.digest(path))
            self.assertEqual(loaded['resource_limits']['memory_max'], 10737418240)
            self.assertFalse(receipt['acceptance'])

    def test_required_correctness_filter_cannot_succeed_with_zero_tests(self):
        from unittest.mock import patch
        import subprocess
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / 'test.log'
            with patch.object(self.builder.subprocess, 'run', return_value=subprocess.CompletedProcess(
                    [], 0, stdout='running 0 tests\ntest result: ok. 0 passed')):
                with self.assertRaisesRegex(ValueError, 'zero tests'):
                    self.builder.run_logged(['cargo', 'test'], log, nonempty_tests=True)


    def test_build_diagnostics_expose_codes_names_and_relative_source_only(self):
        output = ('error[E0308]: private-proof-value at /private-build/private-owner/project\n'
            '  --> /private-build/private-owner/project/src/lib.rs:17:9\n'
            'test suite::binding_check ... FAILED\n'
            'proof = private-proof-value\n')
        result = self.builder.sanitized_diagnostics(output, 'app-test-1', 101)
        self.assertEqual(result['compiler_error_codes'], ['E0308'])
        self.assertEqual(result['failed_tests'], ['suite::binding_check'])
        self.assertEqual(result['source_locations'], [{'source': 'src/lib.rs', 'line': 17, 'column': 9}])
        self.assertNotIn('private-owner', json.dumps(result))
        self.assertNotIn('private-proof-value', json.dumps(result))

    def test_panic_diagnostics_keep_only_safe_source_and_last_fixed_phase(self):
        output = ('D8_TEST_PHASE merge_setup\n'
            "thread 'private-worker' panicked at /private-build/private-owner/project/src/agg/eight.rs:29:13:\n"
            'private-proof-value and /private-build/private-owner/witness\n'
            'D8_TEST_PHASE merge_proof\n')
        result = self.builder.sanitized_diagnostics(output, 'app-test-8', 101)
        self.assertEqual(result['source_locations'], [
            {'source': 'src/agg/eight.rs', 'line': 29, 'column': 13}])
        self.assertEqual(result['last_test_phase'], 'merge_proof')
        for private in ('private-owner', 'private-worker', 'private-proof-value', 'witness'):
            self.assertNotIn(private, json.dumps(result))

    def test_untrusted_phase_lines_do_not_replace_last_fixed_phase(self):
        output = ('D8_TEST_PHASE merge_setup\n'
            'D8_TEST_PHASE private proof payload\n'
            'D8_TEST_PHASE /private-build/private-owner/witness\n'
            ' D8_TEST_PHASE private_payload\n'
            'D8_TEST_PHASE private_payload \n'
            'D8_TEST_PHASE private-payload\n'
            'D8_TEST_PHASE private_payload\n'
            'D8_TEST_PHASE ' + 'x' * 81 + '\n')
        result = self.builder.sanitized_diagnostics(output, 'app-test-8', 101)
        self.assertEqual(result['last_test_phase'], 'merge_setup')
        for private in ('private proof payload', 'private-owner', 'private_payload', 'private-payload'):
            self.assertNotIn(private, json.dumps(result))

    def test_invalid_only_phase_and_unsafe_panic_paths_are_omitted(self):
        output = ('D8_TEST_PHASE /private-build/private-owner/witness\n'
            "thread 'worker' panicked at /private-build/private-owner/tests/binding.rs:7:3:\n"
            "thread 'worker' panicked at /private-build/private-owner/src/../witness.rs:8:4:\n")
        result = self.builder.sanitized_diagnostics(output, 'app-test-8', 101)
        self.assertIsNone(result['last_test_phase'])
        self.assertEqual(result['source_locations'], [])
        self.assertNotIn('private-owner', json.dumps(result))

    def test_error_categories_never_return_error_payloads(self):
        output = 'called unwrap: Prove("private-proof-value") WitnessConflict { private_payload }'
        result = self.builder.sanitized_diagnostics(output, 'app-test-8', 101)
        self.assertEqual(result['validation_error_categories'], ['Prove', 'WitnessConflict'])
        self.assertNotIn('private-proof-value', json.dumps(result))
        self.assertNotIn('private_payload', json.dumps(result))

    def test_passing_gate_summary_excludes_test_payloads(self):
        from unittest.mock import patch
        import subprocess
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / 'batch-pow.log'
            output = ('running 1 test\ntest suite::batch_pow_binding ... ok\n'
                'private-proof-value at /private-owner/project\n')
            stream = io.StringIO()
            with patch.object(self.builder.subprocess, 'run', return_value=subprocess.CompletedProcess(
                    [], 0, stdout=output)), contextlib.redirect_stdout(stream):
                self.builder.run_logged(['cargo', 'test'], log, nonempty_tests=True)
            result = json.loads(stream.getvalue())
            self.assertEqual(result['event'], 'd8_build_tests_passed')
            self.assertEqual(result['selected_tests'], 1)
            self.assertEqual(result['passed_tests'], ['suite::batch_pow_binding'])
            self.assertNotIn('private-proof-value', stream.getvalue())
            self.assertNotIn('private-owner', stream.getvalue())

    def test_batch_grinding_gate_cannot_select_fewer_than_seven_cases(self):
        from unittest.mock import patch
        import subprocess
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / 'batch-pow.log'
            with patch.object(self.builder.subprocess, 'run', return_value=subprocess.CompletedProcess(
                    [], 0, stdout='running 6 tests\ntest result: ok. 6 passed')):
                with contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(ValueError, 'omitted required'):
                        self.builder.run_logged(['cargo', 'test'], log, nonempty_tests=True, minimum_tests=7)


if __name__ == '__main__':
    unittest.main()
