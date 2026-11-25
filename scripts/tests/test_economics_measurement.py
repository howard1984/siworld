"""Resource and selection rejections for pending economic-relation scans."""
import importlib.util
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('economics_measurement', ROOT / 'scripts/bench/measure-multi-asset.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def params(b=8, g=20):
    return {'log_blowup': b, 'num_queries': 36, 'query_pow_bits': g,
        'commit_pow_bits': 0, 'batch_pow_bits': g, 'max_log_arity': 1,
        'log_final_poly_len': 0}


def trial(size=600000, elapsed=1_900_000_000, workers=4):
    return {'resource_control_pass': True, 'proof_report_valid': True,
        'workers': workers, 'parameters': params(),
        'process_wall_ns': elapsed + 100, 'process_cpu_ns': elapsed * workers,
        'average_child_cores': workers, 'memory_peak_bytes': 1_234_567_890,
        'memory_max_bytes': M.MEMORY_MAX, 'memory_swap_max_bytes': 0,
        'memory_events_before': {'max': 0, 'oom': 0, 'oom_kill': 0},
        'memory_events_after': {'max': 0, 'oom': 0, 'oom_kill': 0},
        'memory_events_delta': {'max': 0, 'oom': 0, 'oom_kill': 0},
        'cpu_max': 'max 100000', 'verification_workers': workers,
        'visible_cpu_limits': [{'ancestor_level': 0, 'cpu_max': 'max 100000',
            'quota_cores': None}],
        'measurement': {'generation_ns': elapsed, 'verification_ns': 1000,
            'proof_bytes': size}, 'acceptance': False}


def profile(size=600000, times=(1_900_000_000,) * 3, workers=4):
    rows = [trial(size, value, workers) for value in times]
    return {'parameters': params(), 'trials': rows, 'summary': M.medians(rows)}


def grid():
    return {kind: {coordinate: {'parameters': params(*coordinate),
        'security': {'synthetic_test_screen': True}} for coordinate in M.WALLET_FAST_GRID}
        for kind in ('transaction', 'settlement', 'issuance')}


class EconomicsMeasurementTests(unittest.TestCase):
    def test_selection_requires_every_trial_within_both_inclusive_limits(self):
        boundary = profile(size=655360, times=(2_000_000_000,) * 3)
        slow_tail = profile(size=1, times=(1, 1, 2_000_000_001))
        large_tail = profile(size=1)
        large_tail['trials'][2]['measurement']['proof_bytes'] = 655361
        large_tail['summary'] = M.medians(large_tail['trials'])
        self.assertIs(M.choose_economics_candidate([slow_tail, large_tail, boundary]), boundary)
        self.assertIsNone(M.choose_economics_candidate([slow_tail, large_tail]))
        smaller = profile(size=600000)
        self.assertIs(M.choose_economics_candidate([boundary, smaller]), smaller)

    def test_selection_rechecks_resource_outcomes_workers_and_trial_count(self):
        for change in ('resource', 'proof', 'workers', 'count'):
            value = profile(size=1)
            if change == 'resource':
                value['trials'][0]['resource_control_pass'] = False
            elif change == 'proof':
                value['trials'][0]['proof_report_valid'] = False
            elif change == 'workers':
                value['trials'][0]['workers'] = 1
            else:
                value['trials'].pop()
            with self.subTest(change=change):
                self.assertIsNone(M.choose_economics_candidate([value]))

    def collect(self, base, grids=None, alter=None, hardware=True,
                hardware_profile='epyc7763-baseline'):
        screen_path = base / 'screen.json'
        screen_path.write_text(json.dumps({'air_source_sha256': 'a' * 64,
            'dependencies_sha256': 'b' * 64}))
        executable = base / 'launcher'; executable.write_bytes(b'launcher')
        worker = base / 'worker'; worker.write_bytes(b'worker')
        args = SimpleNamespace(output=base / 'output', screen=screen_path,
            executable=executable, worker=worker, private_parent=base,
            grid_mode='full', scan_mode='economics-candidate',
            hardware_profile=hardware_profile, timeout=5)
        configs = []
        def run_scope(command, **_):
            cfg = json.loads(Path(command[command.index('--worker-config') + 1]).read_text())
            configs.append(cfg)
            coordinate = (cfg['parameters']['log_blowup'], cfg['parameters']['query_pow_bits'])
            size = 600000 if coordinate == (6, 20) else 620000
            value = {**trial(size=size, workers=cfg['workers']), 'kind': cfg['kind'],
                'trial': cfg['trial'], 'parameters': cfg['parameters'],
                'hardware_profile': cfg['hardware_profile'],
                'measurement_scope_sha256': hashlib.sha256(cfg['unit'].encode()).hexdigest()}
            if cfg['kind'] == 'transaction' and cfg['workers'] == 4:
                if coordinate == (5, 20):
                    value['measurement']['proof_bytes'] = 500000
                    if cfg['trial'] == 3:
                        value['measurement']['generation_ns'] = 2_000_000_001
                elif coordinate == (5, 24):
                    value['measurement']['proof_bytes'] = 655361
            if alter:
                alter(cfg, value)
            Path(cfg['result']).write_text(json.dumps(value))
            return SimpleNamespace(returncode=0, stdout='')
        available = grid() if grids is None else grids
        qualification = {'profile_qualified': True, 'hardware': {'cpu_model': 'synthetic test fixture'}}
        with mock.patch.object(M, 'profiles', side_effect=lambda _screen, kind: available[kind]), \
             mock.patch.object(M, 'qualify_and_record', return_value=qualification if hardware else None) as qualify, \
             mock.patch.object(M.subprocess, 'check_output', return_value='a' * 40), \
             mock.patch.object(M.subprocess, 'run', side_effect=run_scope):
            code = M.collect(args)
        qualify.assert_called_once_with(args.output, hardware_profile)
        saved = json.loads((args.output / 'summary.json').read_text()) if hardware else None
        return code, saved, configs

    def test_full_grid_and_single_worker_checks_preserve_kernel_resource_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            code, saved, configs = self.collect(Path(directory))
        self.assertEqual(code, 0)
        self.assertEqual(len(configs), 39)
        self.assertTrue(all(row['scan_mode'] == 'economics-candidate' for row in configs))
        self.assertEqual(len({row['unit'] for row in configs}), 39)
        tx_four = [row for row in configs if row['kind'] == 'transaction' and row['workers'] == 4]
        self.assertEqual(len(tx_four), 24)
        self.assertEqual({(row['parameters']['log_blowup'], row['parameters']['query_pow_bits'])
            for row in tx_four}, set(M.WALLET_FAST_GRID))
        self.assertEqual(saved['candidate_parameters'], params(6, 20))
        tx_one = [row for row in configs if row['kind'] == 'transaction' and row['workers'] == 1]
        self.assertEqual(len(tx_one), 3)
        self.assertTrue(all(row['parameters'] == params(6, 20) for row in tx_one))
        for kind in ('settlement', 'issuance'):
            for workers in (4, 1):
                rows = [row for row in configs if (row['kind'], row['workers']) == (kind, workers)]
                self.assertEqual(len(rows), 3)
                self.assertTrue(all(row['parameters'] == params(8, 20) for row in rows))
        saved_trial = saved['repeated_measurements']['transaction']['workers']['1']['trials'][0]
        self.assertEqual(saved_trial['memory_peak_bytes'], 1_234_567_890)
        self.assertEqual(saved_trial['memory_events_delta']['oom_kill'], 0)
        self.assertEqual(saved_trial['cpu_max'], 'max 100000')
        self.assertEqual(saved_trial['verification_workers'], 1)
        self.assertEqual(len(saved_trial['measurement_scope_sha256']), 64)
        self.assertNotIn('siworld-native-', json.dumps(saved))
        self.assertEqual(saved['proof_body_limit_bytes'], 655360)
        self.assertEqual(saved['status'], 'candidate-pending-review')
        self.assertTrue(saved['measurement_grid_complete'])
        self.assertTrue(saved['related_relation_measurements_complete'])
        self.assertTrue(saved['selected_transaction_single_worker_complete'])
        self.assertFalse(saved['verification_only_process'])
        self.assertIn('not an independent verifier memory measurement', saved['verification_measurement'])
        self.assertFalse(saved['acceptance'])
        self.assertFalse(saved['cryptographic_approval'])
        self.assertFalse(saved['network_activation'])

    def test_single_worker_resource_failure_remains_visible_and_fails_completion(self):
        def fail(cfg, value):
            if cfg['kind'] == 'transaction' and cfg['workers'] == 1 and cfg['trial'] == 2:
                value['resource_control_pass'] = False
                value['memory_events_after']['oom_kill'] = 1
                value['memory_events_delta']['oom_kill'] = 1
        with tempfile.TemporaryDirectory() as directory:
            code, saved, _ = self.collect(Path(directory), alter=fail)
        self.assertEqual(code, 1)
        self.assertTrue(saved['candidate_selected'])
        self.assertFalse(saved['selected_transaction_single_worker_complete'])
        rows = saved['repeated_measurements']['transaction']['workers']['1']['trials']
        self.assertEqual(rows[1]['memory_events_delta']['oom_kill'], 1)
        self.assertFalse(rows[1]['resource_control_pass'])
        self.assertFalse(saved['acceptance'])

    def test_explicit_control_runs_the_same_grid_and_repeats_without_baseline_eligibility(self):
        with tempfile.TemporaryDirectory() as baseline_dir, tempfile.TemporaryDirectory() as control_dir:
            baseline_code, baseline, baseline_configs = self.collect(Path(baseline_dir))
            code, saved, configs = self.collect(Path(control_dir), hardware_profile='epyc9v45-control')
        self.assertEqual((baseline_code, code), (0, 0))
        self.assertEqual(len(configs), 39)
        projection = lambda rows: [(r['kind'], r['workers'], r['trial'], r['parameters']) for r in rows]
        self.assertEqual(projection(configs), projection(baseline_configs))
        self.assertEqual(saved['candidate_parameters'], baseline['candidate_parameters'])
        self.assertEqual(saved['status'], 'control-diagnostic-only')
        self.assertEqual(saved['hardware_profile'], 'epyc9v45-control')
        self.assertFalse(saved['baseline_eligible'])
        self.assertTrue(baseline['baseline_eligible'])
        self.assertEqual({row['hardware_profile'] for row in configs}, {'epyc9v45-control'})
        rows = [row for result in saved['profile_results'] for row in result['trials']]
        rows += [row for kind, relation in saved['repeated_measurements'].items()
                 for workers, group in relation['workers'].items()
                 if (kind, workers) != ('transaction', '4') for row in group['trials']]
        self.assertEqual(len(rows), 39)
        self.assertEqual(len({row['measurement_scope_sha256'] for row in rows}), 39)
        self.assertEqual({row['hardware_profile'] for row in rows}, {'epyc9v45-control'})
        self.assertTrue(saved['all_measurements_complete'])
        self.assertFalse(saved['acceptance'])
        self.assertFalse(saved['cryptographic_approval'])
        self.assertFalse(saved['network_activation'])

    def test_control_qualification_failure_prevents_all_proof_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            code, saved, configs = self.collect(Path(directory), hardware=False,
                hardware_profile='epyc9v45-control')
        self.assertEqual(code, 1)
        self.assertIsNone(saved)
        self.assertEqual(configs, [])

    def test_missing_security_passing_related_profile_is_not_silently_skipped(self):
        available = grid(); available['settlement'][(8, 20)] = None
        with tempfile.TemporaryDirectory() as directory:
            code, saved, configs = self.collect(Path(directory), grids=available)
        self.assertEqual(code, 1)
        self.assertFalse(saved['related_relation_measurements_complete'])
        self.assertEqual(saved['repeated_measurements']['settlement']['reason'], 'no-security-passing-profile')
        self.assertFalse(any(row['kind'] == 'settlement' for row in configs))

    def test_no_qualifying_transaction_reports_failure_without_fabricated_repeats(self):
        def slow(cfg, value):
            if cfg['kind'] == 'transaction':
                value['measurement']['generation_ns'] = 2_000_000_001
        with tempfile.TemporaryDirectory() as directory:
            code, saved, configs = self.collect(Path(directory), alter=slow)
        self.assertEqual(code, 1)
        self.assertFalse(saved['candidate_selected'])
        self.assertFalse(saved['selected_transaction_single_worker_complete'])
        self.assertFalse(saved['repeated_measurements']['transaction']['measured'])
        self.assertFalse(any(row['kind'] == 'transaction' and row['workers'] == 1 for row in configs))
        self.assertTrue(saved['related_relation_measurements_complete'])

    def test_baseline_qualification_failure_prevents_all_proof_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            code, saved, configs = self.collect(Path(directory), hardware=False)
        self.assertEqual(code, 1)
        self.assertIsNone(saved)
        self.assertEqual(configs, [])

    def test_diagnostic_hardware_profile_cannot_substantiate_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            path = base / 'screen.json'; path.write_text('{}')
            args = SimpleNamespace(output=base / 'output', screen=path,
                scan_mode='economics-candidate', hardware_profile='diagnostic')
            with mock.patch.object(M, 'profiles', return_value={}), \
                 mock.patch.object(M, 'qualify_and_record') as qualify:
                with self.assertRaises(ValueError):
                    M.collect(args)
            qualify.assert_not_called()


if __name__ == '__main__':
    unittest.main()
