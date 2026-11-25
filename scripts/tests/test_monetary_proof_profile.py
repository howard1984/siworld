"""Rejections for the source-bound economic proof-profile revision."""
import copy
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import tempfile
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('economic_freeze', ROOT / 'scripts/bench/multi-asset-profile.py')
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
SPEC = importlib.util.spec_from_file_location('old_freeze_fixtures', ROOT / 'scripts/tests/test_multi_asset_profile.py')
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


def completed_summary():
    value = FIXTURE.summary()
    value.update(schema=3, status='candidate-pending-review', scan_mode='economics-candidate',
        grid_rayon_workers=4, grid_hiding_workers=2, single_worker_hiding_workers=1,
        proof_body_limit_bytes=655360, generation_limit_ns=F.GENERATION_MAX_NS,
        selected_transaction_single_worker_complete=True, related_relation_measurements_complete=True,
        all_measurements_complete=True, verification_only_process=False,
        source_commit='a' * 40)
    value.pop('rayon_workers'); value.pop('hiding_workers')
    for entry in value['profile_results']:
        p = entry['parameters']
        for row in entry['trials']:
            prepare_trial(row, 'transaction', 4, p)
        entry['summary'] = F.MEASUREMENT.medians(entry['trials'])
    selected = min(value['profile_results'], key=lambda row: (row['summary']['proof_bytes_max'],
        row['summary']['generation_median_ns'], row['parameters']['log_blowup'],
        row['parameters']['query_pow_bits']))
    value['candidate_parameters'] = selected['parameters']
    value['candidate_security'] = selected['security']
    value['candidate_summary'] = selected['summary']
    repeated = {}
    for kind in ('transaction', 'settlement', 'issuance'):
        p = selected['parameters'] if kind == 'transaction' else FIXTURE.FIXTURE.params(b=8, g=20)
        groups = {}
        for workers in (4, 1):
            rows = copy.deepcopy(selected['trials'])
            if kind != 'transaction' or workers != 4:
                for row in rows:
                    prepare_trial(row, kind, workers, p)
            groups[str(workers)] = {'trials': rows, 'summary': F.MEASUREMENT.medians(rows)}
            if kind == 'transaction' and workers == 4:
                groups[str(workers)]['source'] = 'selected-grid-trials'
        repeated[kind] = {'measured': True, 'parameters': p,
            'security': selected['security'], 'workers': groups}
    value['repeated_measurements'] = repeated
    return value


def prepare_trial(row, kind, workers, parameters):
    row.update(kind=kind, workers=workers, verification_workers=workers, parameters=parameters,
        process_wall_ns=3_000_000_000 + row['trial'], process_cpu_ns=4_000_000_000,
        cpu_max='max 100000', memory_scope='whole fresh setup/prove/verify process tree plus recorder',
        verification_only_process=False)
    identity = json.dumps([kind, workers, parameters, row['trial']], sort_keys=True)
    row['measurement_scope_sha256'] = hashlib.sha256(identity.encode()).hexdigest()
    row['measurement'] = {'setup_ns': 1000, 'generation_ns': 1_500_000_000 + row['trial'],
        'verification_ns': 100_000 + row['trial'],
        'proof_bytes': 550000 + parameters['log_blowup'] * 100 + parameters['query_pow_bits'] + row['trial']
            if kind == 'transaction' else 300000 + row['trial']}
    if kind == 'transaction':
        row['measurement'].update(public_transaction_bytes=2027, permanent_position_bytes=2115,
            proof_within_524288_bytes=False)
    elif kind == 'settlement':
        row['measurement'].update(capacity=576, reward_asset_constrained_si=True)
    else:
        row['measurement'].update(initial_notes=3, actual_ml_dsa65_verification=True,
            signed_record_bytes=4000, ciphertext_bytes=3000)


@contextmanager
def immutable_sources():
    snapshot = {name: F.source_bytes(ROOT, name) for name in F.source_paths(ROOT, revision=2)}
    def git_blob(command, **_):
        if command == ['git', 'ls-tree', '-r', '--name-only', 'a' * 40]:
            return ('\n'.join(snapshot) + '\n').encode()
        if command[:2] == ['git', 'show'] and command[2].startswith('a' * 40 + ':'):
            return snapshot[command[2][41:]]
        raise AssertionError('Only immutable measured Git blob reads are allowed')
    with mock.patch.object(F.subprocess, 'check_output', side_effect=git_blob):
        yield snapshot


class EconomicsFreezeTests(unittest.TestCase):
    def freeze(self, value=None, key=None):
        value = completed_summary() if value is None else value
        with immutable_sources():
            return F.create(value, FIXTURE.public_key(value) if key is None else key)

    def test_public_revision_records_all_relations_without_private_fields(self):
        source = completed_summary()
        source['private_path'] = '/private/owner'
        source['profile_results'][0]['trials'][0]['private_path'] = '/private/owner'
        value = self.freeze(source)
        self.assertEqual(value['schema'], 2)
        self.assertEqual(value['relation_revision'], 'native-v1-economics-1')
        self.assertEqual(value['max_leaf_proof_bytes'], 655360)
        self.assertEqual(value['max_settlement_proof_bytes'], 524288)
        self.assertEqual(value['max_issuance_proof_bytes'], 524288)
        self.assertNotIn('/private/owner', json.dumps(value))
        self.assertEqual(len(value['profiles']), 8)
        self.assertEqual(len(value['repeated_measurements']['transaction']['workers']['1']['trials']), 3)
        self.assertFalse(value['verification_only_process'])
        self.assertFalse(value['network_activation'])
        with mock.patch.object(F.subprocess, 'check_output', side_effect=AssertionError('check cannot need Git')):
            self.assertEqual(F.validate(value), value)

    def test_every_remote_completeness_flag_and_hardware_profile_are_required(self):
        flags = ('measurement_grid_complete', 'scope_startup_complete', 'candidate_selected',
            'three_trial_target_met', 'selected_transaction_single_worker_complete',
            'related_relation_measurements_complete', 'all_measurements_complete')
        changes = [lambda s, name=name: s.update({name: False}) for name in flags]
        changes += [lambda s: s.update(status='engineering-frozen'),
            lambda s: s['hardware']['hardware'].update(cpu_model='AMD EPYC 9V45'),
            lambda s: s.update(hardware_profile='diagnostic'),
            lambda s: s.update(grid_rayon_workers=1),
            lambda s: s.update(proof_body_limit_bytes=655361)]
        for index, change in enumerate(changes):
            source = completed_summary(); change(source)
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.freeze(source)

    def test_replayed_scope_measurements_and_selected_grid_substitution_are_rejected(self):
        for change in ('grid', 'single-worker', 'relation', 'selected-four'):
            source = completed_summary()
            original = source['profile_results'][0]['trials'][0]
            if change == 'grid':
                source['profile_results'][1]['trials'][0]['measurement_scope_sha256'] = original['measurement_scope_sha256']
            elif change == 'single-worker':
                source['repeated_measurements']['transaction']['workers']['1']['trials'][0]['measurement_scope_sha256'] = original['measurement_scope_sha256']
            elif change == 'relation':
                source['repeated_measurements']['settlement']['workers']['1']['trials'][0]['measurement_scope_sha256'] = original['measurement_scope_sha256']
            else:
                source['repeated_measurements']['transaction']['workers']['4']['trials'][0]['measurement']['proof_bytes'] += 1
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.freeze(source)

    def test_kernel_failures_duplicate_trials_and_worker_mismatches_are_rejected(self):
        changes = (
            lambda r: r[0]['memory_events_delta'].update(oom_kill=1),
            lambda r: r[0]['memory_events_after'].update(high=1),
            lambda r: r[0]['memory_events_delta'].update({'/private/owner': 0}),
            lambda r: r[0].update(memory_peak_bytes=F.MEMORY_MAX + 1),
            lambda r: r[0].update(scope_exit_code=1),
            lambda r: r[0].update(workers=4),
            lambda r: r[0].update(trial=2),
            lambda r: r[0].update(measurement_scope_sha256='not-a-hash'),
            lambda r: r[0].update(visible_cpu_limits=[]),
            lambda r: r[0]['visible_cpu_limits'][0].update(cpu_max='300000 100000', quota_cores=3),
        )
        for index, change in enumerate(changes):
            source = completed_summary()
            change(source['repeated_measurements']['transaction']['workers']['1']['trials'])
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.freeze(source)

    def test_known_optional_socket_counter_is_preserved_when_zero_and_consistent(self):
        source = completed_summary()
        rows = [row for entry in source['profile_results'] for row in entry['trials']]
        rows += [row for entry in source['repeated_measurements'].values()
                 for group in entry['workers'].values() for row in group['trials']]
        for row in rows:
            for field in ('memory_events_before', 'memory_events_after', 'memory_events_delta'):
                row[field]['sock_throttled'] = 0
        value = self.freeze(source)
        for entry in value['profiles']:
            for row in entry['kernel_trials']:
                self.assertEqual(row['memory_events_delta']['sock_throttled'], 0)
                self.assertEqual(row['memory_events_before'], row['memory_events_delta'])
                self.assertEqual(row['memory_events_after'], row['memory_events_delta'])
        self.assertEqual(F.validate(value), value)

    def test_socket_counter_must_be_zero_and_match_all_three_snapshots(self):
        source = completed_summary()
        original = source['repeated_measurements']['transaction']['workers']['1']['trials'][0]
        fields = ('memory_events_before', 'memory_events_after', 'memory_events_delta')
        for field in fields:
            original[field]['sock_throttled'] = 0
        self.assertEqual(
            F.economic_trial(original, 'transaction', 1, original['parameters'])
                ['memory_events_delta']['sock_throttled'], 0)
        for field in fields:
            for value in (1, -1, False):
                row = copy.deepcopy(original)
                row[field]['sock_throttled'] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    F.economic_trial(row, 'transaction', 1, row['parameters'])
            row = copy.deepcopy(original)
            row[field].pop('sock_throttled')
            with self.subTest(missing=field), self.assertRaises(ValueError):
                F.economic_trial(row, 'transaction', 1, row['parameters'])
        row = copy.deepcopy(original)
        for field in fields:
            row[field]['unknown_kernel_counter'] = 0
        with self.assertRaises(ValueError):
            F.economic_trial(row, 'transaction', 1, row['parameters'])

    def test_all_six_standard_memory_counters_remain_mandatory(self):
        source = completed_summary()
        original = source['repeated_measurements']['transaction']['workers']['1']['trials'][0]
        for key in ('low', 'high', 'max', 'oom', 'oom_kill', 'oom_group_kill'):
            row = copy.deepcopy(original)
            for field in ('memory_events_before', 'memory_events_after', 'memory_events_delta'):
                row[field].pop(key)
                row[field]['sock_throttled'] = 0
            with self.subTest(missing=key), self.assertRaises(ValueError):
                F.economic_trial(row, 'transaction', 1, row['parameters'])

    def test_margin_is_based_on_all_selected_worker_counts_and_cannot_exceed_limit(self):
        source = completed_summary()
        row = source['repeated_measurements']['transaction']['workers']['1']['trials'][0]
        row['measurement']['proof_bytes'] = 595781
        source['repeated_measurements']['transaction']['workers']['1']['summary'] = F.MEASUREMENT.medians(
            source['repeated_measurements']['transaction']['workers']['1']['trials'])
        value = self.freeze(source)
        self.assertEqual(value['selected_transaction_proof_bytes_max'], 595781)
        self.assertEqual(value['max_leaf_proof_bytes'], 655360)
        row['measurement']['proof_bytes'] = 595782
        source['repeated_measurements']['transaction']['workers']['1']['summary'] = F.MEASUREMENT.medians(
            source['repeated_measurements']['transaction']['workers']['1']['trials'])
        with self.assertRaises(ValueError):
            self.freeze(source)

    def test_related_proof_caps_are_checked_without_inventing_a_new_margin(self):
        for kind in ('settlement', 'issuance'):
            source = completed_summary()
            row = source['repeated_measurements'][kind]['workers']['1']['trials'][0]
            row['measurement']['proof_bytes'] = 524289
            source['repeated_measurements'][kind]['workers']['1']['summary'] = F.MEASUREMENT.medians(
                source['repeated_measurements'][kind]['workers']['1']['trials'])
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.freeze(source)

    def test_key_parameters_commitment_shape_and_security_must_match_selection(self):
        for change in ('parameters', 'hash', 'shape', 'security'):
            source = completed_summary(); key = FIXTURE.public_key(source)
            if change == 'parameters':
                key['parameters'] = copy.deepcopy(key['parameters']); key['parameters']['num_queries'] += 1
            elif change == 'hash':
                key['public_verifier_key']['sha256'] = '0' * 64
            elif change == 'shape':
                key['public_verifier_key']['width'] += 1
            else:
                key['security'] = copy.deepcopy(key['security'])
                key['security']['screen']['quantum_johnson_challenge_union_bits'] = 79
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.freeze(source, key)

    def test_measured_blob_changes_and_current_source_changes_are_rejected(self):
        source = completed_summary()
        read = F.source_bytes
        def changed(root, name):
            return read(root, name) + (b'changed' if name == 'crates/bench-d8/src/lib.rs' else b'')
        with immutable_sources(), mock.patch.object(F, 'source_bytes', side_effect=changed), self.assertRaises(ValueError):
            F.create(source, FIXTURE.public_key(source))
        value = self.freeze(source)
        with mock.patch.object(F, 'source_bytes', side_effect=changed), self.assertRaises(ValueError):
            F.validate(value)
        value = self.freeze(source); value['measured_source_sha256'].pop('scripts/measure-multi-asset.py')
        with self.assertRaises(ValueError):
            F.validate(value)

    def test_selected_native_keys_use_actual_measured_coordinate_and_reproduce_twice(self):
        spec = importlib.util.spec_from_file_location('candidate_keys', ROOT / 'scripts/bench/prepare-monetary-proof-profile.py')
        helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
        source = completed_summary()
        screen = FIXTURE.FIXTURE.screen()
        for name in ('air_source_sha256', 'dependencies_sha256'):
            screen[name] = source[name]
        commands = []
        def generate(command, **_):
            commands.append(command)
            _, mode, kind, b, q, g, output = command
            self.assertEqual(mode, '--candidate')
            parameters = FIXTURE.FIXTURE.params(b=int(b), q=int(q), g=int(g))
            report = next(entry['minimum_passing_report'] for entry in screen['reports']
                if (entry['kind'], entry['log_blowup'], entry['grinding']) == (kind, int(b), int(g)))
            Path(output).write_text(json.dumps({'status': 'candidate-pending-review', 'acceptance': False,
                'parameters': parameters, 'security': report,
                'public_verifier_key': {'hex': '00', 'sha256': hashlib.sha256(bytes(1)).hexdigest()}}))
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            summary_path = base / 'summary.json'; summary_path.write_text(json.dumps(source))
            screen_path = base / 'screen.json'; screen_path.write_text(json.dumps(screen))
            with mock.patch.object(helper, 'freeze_module', return_value=F), \
                 mock.patch.object(helper.subprocess, 'run', side_effect=generate), \
                 mock.patch.object(helper.subprocess, 'check_output', return_value='a' * 40):
                helper.keys(base / 'binary', screen_path, base / 'keys', summary_path)
            manifest = json.loads((base / 'keys/candidate-manifest.json').read_text())
            self.assertTrue(manifest['selected_by_actual_measurement'])
            self.assertEqual(manifest['relations'][0]['parameters'], source['candidate_parameters'])
            self.assertNotEqual(source['candidate_parameters']['log_blowup'], 7)
            self.assertEqual(len(commands), 6)
            self.assertEqual(commands[0][2:6], commands[1][2:6])
            self.assertFalse(manifest['acceptance'])
            self.assertFalse(manifest['cryptographic_approval'])
            self.assertFalse(manifest['network_activation'])
            self.assertEqual(manifest['measurement_summary_sha256'], hashlib.sha256(summary_path.read_bytes()).hexdigest())
            self.assertTrue(all(not name.endswith('.json') for name in manifest['sources_sha256']))

    def test_public_measurement_cap_key_or_source_mutation_is_rejected(self):
        original = self.freeze()
        changes = (
            lambda v: v.update(max_leaf_proof_bytes=589824),
            lambda v: v.update(selected_transaction_proof_bytes_max=1),
            lambda v: v['profiles'][0]['kernel_trials'][0].update(process_cpu_ns=0),
            lambda v: v['repeated_measurements']['issuance']['workers']['1']['summary'].update(verification_median_ns=1),
            lambda v: v['source_sha256'].pop('scripts/measure-multi-asset.py'),
            lambda v: v['public_verifier_key'].update(width=2),
            lambda v: v['selected_security'].update(private_path='/private/owner'),
            lambda v: v.update(acceptance=True),
        )
        for index, change in enumerate(changes):
            value = copy.deepcopy(original); change(value)
            with self.subTest(index=index), self.assertRaises(ValueError):
                F.validate(value)


if __name__ == '__main__':
    unittest.main()
