import copy
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('multi_asset_measurement', ROOT / 'scripts/bench/measure-multi-asset.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def security():
    return {'p3_security_version': '0.9.0-rc.2',
        'accounting': 'single-proof-johnson-halving-bht-v1',
        'shape': {'status': 'actual-extracted', **{key: 1 for key in M.SHAPE_KEYS}},
        'screen': {'passes_selected_model': True,
            **{key: 200 for key in M.SCREEN_KEYS}, 'proof_multiplicity': 1},
        'conjectured': {'terms': [{'label': 'deep-ali', 'bits': 200}]},
        'proven_johnson': {'terms': [{'label': 'low-degree-test', 'bits': 164}]},
        'johnson_fri_terms': [{'label': 'fri-query', 'bits': 164}],
        'challenge_domain_terms': [{'label': 'ood-deep-ali-domain', 'bits': 200}],
        'application_binding': {'algorithm': 'BLAKE3-256', 'digest_bytes': 32,
            'nominal_classical_collision_bits': 128, 'nominal_bht_collision_bits': 256 / 3}}


def params(b=8, q=36, g=20):
    return {'log_blowup': b, 'num_queries': q, 'query_pow_bits': g,
        'commit_pow_bits': 0, 'batch_pow_bits': g, 'max_log_arity': 1, 'log_final_poly_len': 0}


def screen():
    entries = []
    for kind in ('transaction', 'settlement', 'issuance'):
        for b, g in M.GRID + M.FALLBACK_GRID:
            report = security()
            report['fri'] = params(b=b, g=g)
            entries.append({'kind': kind, 'log_blowup': b, 'grinding': g,
                'minimum_passing_report': report})
    return {'suite': M.SUITE, 'cryptographic_approval': False, 'network_activation': False,
        'air_source_sha256': 'a' * 64, 'dependencies_sha256': 'b' * 64, 'reports': entries}


def config():
    return {'kind': 'transaction', 'workers': 4, 'parameters': params(),
        'air_source_sha256': 'a' * 64, 'dependencies_sha256': 'b' * 64,
        'binary_sha256': 'c' * 64}


def report():
    c = config()
    return {**c, 'suite': M.SUITE, 'verified': True, 'synthetic_fixture': True,
        'cryptographic_approval': False, 'network_activation': False,
        'hiding_workers': '2', 'security': security(),
        'measurement': {'setup_ns': 1, 'generation_ns': 2, 'verification_ns': 3,
            'proof_bytes': 500000, 'public_transaction_bytes': 2027,
            'permanent_position_bytes': 2115, 'actual_encryption_self_check': True}}


def trial(size=500000, elapsed=1_900_000_000, workers=4):
    return {'resource_control_pass': True, 'proof_report_valid': True, 'workers': workers,
        'parameters': params(), 'process_wall_ns': elapsed + 100,
        'memory_peak_bytes': 1_000_000_000,
        'measurement': {'generation_ns': elapsed, 'verification_ns': 1000,
                        'proof_bytes': size}}


class MultiAssetMeasurementTests(unittest.TestCase):
    def test_profile_grid_rejects_missing_duplicate_and_unscreened_coordinates(self):
        self.assertEqual(len(M.profiles(screen(), 'transaction')), 18)
        for change in ('missing', 'duplicate', 'wrong-ledger', 'projected', 'mismatched-grinding'):
            value = screen()
            if change == 'missing':
                value['reports'].pop(0)
            elif change == 'duplicate':
                value['reports'].append(copy.deepcopy(value['reports'][0]))
            elif change == 'wrong-ledger':
                value['reports'][0]['minimum_passing_report']['accounting'] = 'conjecture-only'
            elif change == 'projected':
                value['reports'][0]['minimum_passing_report']['shape']['status'] = 'projected'
            else:
                value['reports'][0]['minimum_passing_report']['fri']['batch_pow_bits'] = 0
            with self.subTest(change=change), self.assertRaises(ValueError):
                M.profiles(value, 'transaction')

    def test_security_summary_cannot_export_unknown_fields_or_accept_a_false_score(self):
        value = security()
        value['private_path'] = '/private/owner'
        value['shape']['private_identity'] = '/private/owner'
        cleaned = M.security_summary(value)
        self.assertNotIn('/private', json.dumps(cleaned))
        value['screen']['quantum_johnson_challenge_union_bits'] = 79.9
        with self.assertRaises(ValueError):
            M.security_summary(value)
        value = security()
        value['proven_johnson']['terms'][0]['label'] = '/private/owner'
        with self.assertRaises(ValueError):
            M.security_summary(value)

    def test_worker_identity_threads_parameters_and_encryption_are_checked(self):
        value = report()
        value['measurement']['private_nullifier'] = 'excluded'
        self.assertNotIn('private_nullifier', M.validate_report(value, config()))
        changes = [('verified', False), ('workers', 1), ('hiding_workers', '1'),
                   ('binary_sha256', 'd' * 64), ('air_source_sha256', 'd' * 64),
                   ('dependencies_sha256', 'd' * 64), ('cryptographic_approval', True)]
        for key, wrong in changes:
            value = report(); value[key] = wrong
            with self.subTest(key=key), self.assertRaises(ValueError):
                M.validate_report(value, config())
        for key, wrong in [('actual_encryption_self_check', False), ('generation_ns', -1)]:
            value = report(); value['measurement'][key] = wrong
            with self.subTest(key=key), self.assertRaises(ValueError):
                M.validate_report(value, config())
        value = report(); value['parameters']['num_queries'] += 1
        with self.assertRaises(ValueError):
            M.validate_report(value, config())

    def test_settlement_capacity_and_sip_reward_cannot_be_substituted(self):
        cfg = config(); cfg['kind'] = 'settlement'
        value = report(); value['kind'] = 'settlement'
        value['measurement'].update({'capacity': 576, 'reward_asset_constrained_si': True})
        self.assertEqual(M.validate_report(value, cfg)['capacity'], 576)
        for key, wrong in [('capacity', 544), ('reward_asset_constrained_si', False)]:
            changed = copy.deepcopy(value); changed['measurement'][key] = wrong
            with self.subTest(key=key), self.assertRaises(ValueError):
                M.validate_report(changed, cfg)

    def test_selection_preserves_cap_time_and_actual_resource_outcome(self):
        rejected = [trial(size=524289), trial(elapsed=2_000_000_001), trial(workers=1)]
        failed = trial(size=1); failed['resource_control_pass'] = False; rejected.append(failed)
        failed = trial(size=1); failed['proof_report_valid'] = False; rejected.append(failed)
        self.assertIsNone(M.choose(rejected))
        boundary = trial(size=524288, elapsed=2_000_000_000)
        small = trial(size=490000)
        self.assertIs(M.choose(rejected + [boundary, small]), small)
        self.assertIs(M.choose(rejected + [boundary]), boundary)

    def test_diagnostic_selection_retains_rejected_measured_profiles(self):
        slow_fit = trial(size=514000, elapsed=4_000_000_000)
        fast_large = trial(size=558000, elapsed=1_000_000_000)
        self.assertIsNone(M.choose([slow_fit, fast_large]))
        self.assertIs(M.diagnostic_choice([slow_fit, fast_large]), slow_fit)
        smaller_large = trial(size=550000)
        self.assertIs(M.diagnostic_choice([fast_large, smaller_large]), smaller_large)
        failed = trial(); failed['resource_control_pass'] = False
        self.assertIsNone(M.diagnostic_choice([failed]))

    def test_rejected_slow_cap_fitting_profile_still_receives_three_repeats(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            screen_path = base / 'screen.json'; screen_path.write_text(json.dumps(screen()))
            executable = base / 'launcher'; executable.write_bytes(b'launcher')
            worker = base / 'worker'; worker.write_bytes(b'worker')
            args = SimpleNamespace(output=base / 'output', screen=screen_path,
                executable=executable, worker=worker, private_parent=base,
                grid_mode='full', timeout=5)
            helper = mock.Mock()
            helper.qualify.return_value = ({'cpu_model': 'synthetic'},
                {'lscpu_json': {}, 'lscpu_text': 'synthetic'})
            def run_scope(command, **_):
                cfg = json.loads(Path(command[command.index('--worker-config') + 1]).read_text())
                size = 514000 if cfg['parameters']['log_blowup'] == 9 else 558000
                value = {**trial(size=size, elapsed=4_000_000_000, workers=cfg['workers']),
                    'kind': cfg['kind'], 'trial': cfg['trial'], 'parameters': cfg['parameters']}
                Path(cfg['result']).write_text(json.dumps(value))
                return SimpleNamespace(returncode=0, stdout='')
            with mock.patch.object(M, 'qualify_and_record', return_value={'profile_qualified': True}), \
                 mock.patch.object(M.subprocess, 'check_output', return_value='a' * 40), \
                 mock.patch.object(M.subprocess, 'run', side_effect=run_scope):
                self.assertEqual(M.collect(args), 0)
            saved = json.loads((args.output / 'summary.json').read_text())
            self.assertFalse(saved['candidate_selected'])
            self.assertTrue(saved['candidate_rejected'])
            self.assertFalse(saved['three_trial_target_met'])
            self.assertEqual(saved['diagnostic_transaction_parameters']['log_blowup'], 9)
            self.assertEqual(saved['diagnostic_transaction_reason'], 'generation-budget-exceeded')
            repeated = saved['repeated_measurements']['transaction']['workers']
            for workers in ('4', '1'):
                self.assertEqual(len(repeated[workers]['trials']), 3)
                self.assertTrue(repeated[workers]['summary']['complete'])

    def test_repeated_measurements_require_three_valid_trials_and_report_maximum_peak(self):
        rows = [trial(elapsed=v) for v in (200, 100, 300)]
        rows[0]['memory_peak_bytes'] = 3_000_000_000
        self.assertEqual(M.medians(rows)['generation_median_ns'], 200)
        self.assertEqual(M.medians(rows)['memory_peak_max_bytes'], 3_000_000_000)
        self.assertFalse(M.medians(rows)['acceptance'])
        self.assertFalse(M.medians(rows[:2])['complete'])
        rows[0]['resource_control_pass'] = False
        self.assertFalse(M.medians(rows)['complete'])

    def test_wallet_fast_selection_ignores_old_cap_and_requires_every_trial_under_time(self):
        def profile(size, times, b=5, g=20):
            rows = [trial(size=size, elapsed=value) for value in times]
            return {'parameters': params(b=b, g=g), 'trials': rows, 'summary': M.medians(rows)}
        passing = profile(900000, (1_000_000_000, 1_100_000_000, 2_000_000_000))
        median_only = profile(600000, (1_000_000_000, 1_100_000_000, 2_000_000_001))
        slower_small = profile(800000, (1_900_000_000,) * 3, b=6)
        self.assertIs(M.choose_wallet_fast([passing, median_only]), passing)
        self.assertIs(M.choose_wallet_fast([passing, median_only, slower_small]), slower_small)
        self.assertIsNone(M.choose_wallet_fast([median_only]))
        incomplete = profile(1, (100,) * 3)
        incomplete['trials'][0]['resource_control_pass'] = False
        incomplete['summary'] = M.medians(incomplete['trials'])
        self.assertIsNone(M.choose_wallet_fast([incomplete]))
        single_worker = profile(1, (100,) * 3)
        single_worker['trials'][0]['workers'] = 1
        self.assertIsNone(M.choose_wallet_fast([single_worker]))

    def test_wallet_fast_measures_exact_eight_profiles_three_times_with_no_size_filter(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            screen_path = base / 'screen.json'; screen_path.write_text(json.dumps(screen()))
            executable = base / 'launcher'; executable.write_bytes(b'launcher')
            worker = base / 'worker'; worker.write_bytes(b'worker')
            args = SimpleNamespace(output=base / 'output', screen=screen_path,
                executable=executable, worker=worker, private_parent=base,
                grid_mode='full', scan_mode='wallet-fast',
                hardware_profile='epyc7763-baseline', timeout=5)
            configs = []
            def run_scope(command, **_):
                cfg = json.loads(Path(command[command.index('--worker-config') + 1]).read_text())
                configs.append(cfg)
                value = {**trial(size=700000 + cfg['parameters']['log_blowup'],
                    elapsed=1_500_000_000, workers=cfg['workers']), 'kind': cfg['kind'],
                    'trial': cfg['trial'], 'parameters': cfg['parameters']}
                Path(cfg['result']).write_text(json.dumps(value))
                return SimpleNamespace(returncode=0, stdout='')
            with mock.patch.object(M, 'qualify_and_record', return_value={'profile_qualified': True}), \
                 mock.patch.object(M.subprocess, 'check_output', return_value='a' * 40), \
                 mock.patch.object(M.subprocess, 'run', side_effect=run_scope):
                self.assertEqual(M.collect(args), 0)
            saved = json.loads((args.output / 'summary.json').read_text())
            self.assertEqual(len(configs), 24)
            self.assertEqual({(row['parameters']['log_blowup'], row['parameters']['query_pow_bits'])
                for row in configs}, set(M.WALLET_FAST_GRID))
            self.assertEqual({row['workers'] for row in configs}, {4})
            self.assertEqual({row['kind'] for row in configs}, {'transaction'})
            self.assertEqual({row['hardware_profile'] for row in configs}, {'epyc7763-baseline'})
            self.assertTrue(saved['candidate_selected'])
            self.assertFalse(saved['legacy_524288_byte_cap_applied'])
            self.assertEqual(saved['candidate_parameters']['log_blowup'], 5)
            self.assertEqual(saved['candidate_summary']['proof_bytes_max'], 700005)
            self.assertEqual(len(saved['profile_results']), 8)
            self.assertTrue(all(row['summary']['trial_count'] == 3 for row in saved['profile_results']))
            self.assertFalse(saved['acceptance'])

    def test_baseline_hardware_or_quota_failure_retains_sanitized_evidence(self):
        for failure in ('hardware', 'quota'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                helper = mock.Mock()
                helper.qualify.return_value = ({'cpu_model': 'AMD EPYC 7763'},
                    {'lscpu_json': {'lscpu': []}, 'lscpu_text': 'synthetic'})
                if failure == 'hardware':
                    helper.qualify_hardware_profile.side_effect = ValueError('/private/owner')
                else:
                    helper.qualify_hardware_profile.return_value = {'profile_qualified': True}
                    helper.qualify_cpu_profile.side_effect = ValueError('/private/owner')
                with mock.patch.object(M, 'module', return_value=helper), \
                     mock.patch.object(M, 'current_cpu_ancestry', return_value=[]):
                    self.assertIsNone(M.qualify_and_record(Path(directory), 'epyc7763-baseline'))
                saved = json.loads((Path(directory) / 'hardware-qualification.json').read_text())
                self.assertFalse(saved['profile_qualified'])
                self.assertEqual(saved['failure'], 'required-cpu-os-topology-or-cgroup-profile-unavailable')
                self.assertNotIn('/private/owner', json.dumps(saved))

    def test_fresh_scope_keeps_exact_memory_boundary_and_calls_new_recorder(self):
        command = M.scope_command('siworld-native-' + 'a' * 32 + '.scope', Path('/synthetic/config'))
        self.assertIn('--scope', command)
        self.assertIn('MemoryMax=5G', command)
        self.assertIn('MemorySwapMax=0', command)
        self.assertIn(str(ROOT / 'scripts/bench/measure-multi-asset.py'), command)
        self.assertNotIn(str(ROOT / 'scripts/bench/measure-native-cgroup.py'), command)
        child = M.child_command({**config(), 'executable': '/synthetic/worker', 'private_output': '/synthetic/raw'})
        self.assertEqual(child[1:6], ['transaction', '8', '36', '20', '4'])

    def test_oom_evidence_survives_absent_child_result_without_acceptance(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            membership = base / 'membership'
            membership.write_text('0::/system.slice/siworld-native-' + 'a' * 32 + '.scope')
            before = {'memory.events': {'max': 0, 'oom': 0, 'oom_kill': 0, 'oom_group_kill': 0},
                'memory.peak': 100, 'memory.swap.current': 0, 'cpu.max': 'max 100000'}
            after = copy.deepcopy(before); after['memory.peak'] = M.MEMORY_MAX
            after['memory.events']['oom_kill'] = 1
            cfg = {**config(), 'uid': 1001, 'gid': 1001,
                'unit': 'siworld-native-' + 'a' * 32 + '.scope', 'trial': 1, 'timeout': 5,
                'executable': '/synthetic/worker', 'private_output': str(base / 'absent.json'),
                'private_log': str(base / 'worker.log'), 'result': str(base / 'result.json')}
            process = mock.Mock(pid=100); process.wait.return_value = -9
            def mapped(path):
                if str(path) == '/proc/self/cgroup':
                    return membership
                if str(path) == '/proc/self/oom_score_adj':
                    return base / 'score'
                return Path(path)
            with mock.patch.object(M.os, 'geteuid', return_value=0), \
                 mock.patch.object(M, 'Path', side_effect=mapped), \
                 mock.patch.object(M.CG, 'scoped_group', return_value=base / 'scope'), \
                 mock.patch.object(M, 'module') as helper, \
                 mock.patch.object(M.CG, 'snapshot', side_effect=[before, after]), \
                 mock.patch.object(M.CG, 'member_pids', return_value=set()), \
                 mock.patch.object(M.subprocess, 'Popen', return_value=process):
                helper.return_value.cpu_ancestry.return_value = []
                self.assertEqual(M.record(cfg), 0)
            result = json.loads((base / 'result.json').read_text())
            self.assertEqual(result['memory_events_delta']['oom_kill'], 1)
            self.assertEqual(result['memory_peak_bytes'], M.MEMORY_MAX)
            self.assertEqual(result['exit_code'], -9)
            self.assertFalse(result['resource_control_pass'])
            self.assertFalse(result['proof_report_valid'])
            self.assertFalse(result['acceptance'])
            self.assertFalse(result['verification_only_process'])
            self.assertEqual((base / 'score').read_text(), '-1000')


if __name__ == '__main__':
    unittest.main()
