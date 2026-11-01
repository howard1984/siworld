"""Fixed-profile qualification contracts without building or proving locally."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('fixed_qualification', ROOT / 'scripts/qualify-native-transaction.py')
Q = importlib.util.module_from_spec(SPEC)
if SPEC.loader and SPEC.origin and Path(SPEC.origin).is_file():
    SPEC.loader.exec_module(Q)


def parameters():
    return dict(log_blowup=7, num_queries=41, query_pow_bits=20,
        commit_pow_bits=0, batch_pow_bits=20, max_log_arity=1, log_final_poly_len=0)


class FixedQualificationTests(unittest.TestCase):
    def failed_trial(self, mode):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            config = dict(kind='transaction', workers=4, trial=1, parameters=parameters(),
                timeout=5, unit='siworld-native-' + 'a' * 32 + '.scope',
                result=str(base / 'result.json'), private_output=str(base / 'raw.json'))
            diagnostic = json.dumps(dict(event='multi-asset-diagnostic-failed',
                classification='FileNotFoundError', stage='initial-counters',
                os_error_number=2, kernel_file='cpu.max', private_data='secret'))
            def run(command, **kwargs):
                if '--worker-config' not in command:
                    return SimpleNamespace(returncode=0)
                if mode == 'timeout':
                    raise Q.subprocess.TimeoutExpired(command, 35, output='private timeout output')
                if mode == 'malformed':
                    Path(config['result']).write_text('private malformed report')
                return SimpleNamespace(returncode=1, stdout=diagnostic + '\nprivate stderr')
            with mock.patch.object(Q.subprocess, 'run', side_effect=run) as invoked:
                row = Q.collect_trial(config, base / 'config.json', {})
            return row, invoked.call_args_list

    def test_missing_result_retains_recorder_stage_without_private_output(self):
        row, calls = self.failed_trial('missing')
        self.assertFalse(row['resource_control_pass'])
        self.assertEqual(row['scope_exit_code'], 1)
        self.assertEqual(row['collector_diagnostic']['stage'], 'result-read')
        self.assertEqual(row['startup_diagnostic']['kernel_file'], 'cpu.max')
        self.assertEqual(row['startup_diagnostic']['stage'], 'initial-counters')
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[-1].args[0][-1], 'siworld-native-' + 'a' * 32 + '.scope')
        for private in ('secret', 'private stderr', '/private', 'malformed report'):
            self.assertNotIn(private, json.dumps(row))

    def test_scope_timeout_preserves_class_and_cleans_only_owned_scope(self):
        row, calls = self.failed_trial('timeout')
        self.assertEqual(row['collector_diagnostic']['classification'], 'TimeoutExpired')
        self.assertEqual(row['collector_diagnostic']['stage'], 'scope-launch')
        self.assertNotIn('scope_exit_code', row)
        self.assertEqual(len(calls), 2)
        self.assertNotIn('private timeout', json.dumps(row))

    def test_malformed_result_is_distinct_from_missing_result(self):
        row, _ = self.failed_trial('malformed')
        self.assertEqual(row['collector_diagnostic']['classification'], 'JSONDecodeError')
        self.assertEqual(row['collector_diagnostic']['stage'], 'result-read')

    def test_minimum_workflow_probes_scope_before_build(self):
        workflow = (ROOT / '.github/workflows/native-fixed-qualification.yml').read_text()
        self.assertIn('--smoke-scope', workflow)
        self.assertLess(workflow.index('--smoke-scope'), workflow.index('Install the repository toolchain'))

    def test_cpu_controller_requested_without_a_new_quota_or_memory_budget(self):
        command = Q.M.scope_command('siworld-native-' + 'a' * 32 + '.scope', Path('/synthetic/config.json'))
        for prop in ('CPUWeight=100', 'CPUAccounting=yes', 'MemoryMax=5G', 'MemorySwapMax=0'):
            self.assertIn(prop, command)
        self.assertFalse(any('CPUQuota' in arg for arg in command))
        self.assertIn(str(Path(Q.M.__file__).resolve()), command)

    def test_two_core_four_thread_7r13_meets_the_miner_preflight(self):
        hardware = dict(os='Ubuntu 24.04', architecture='x86_64', cpu_model='AMD EPYC 7R13 Processor',
            exposed_physical_cores=2, logical_cpus=4, online_logical_cpus=4, affinity_cpus=4,
            memory_total_bytes=32_908_029_952,
            x86_64_v3_features={name: True for name in Q.H.X86_64_V3_FLAGS})
        self.assertTrue(Q.H.qualify_hardware_profile(hardware, 'minimum-miner')['profile_qualified'])
        Q.H.qualify_cpu_profile([{'cpu_limit': {'quota_cores': 4}}], 'minimum-miner')
        with self.assertRaises(ValueError):
            Q.H.qualify_cpu_profile([{'cpu_limit': {'quota_cores': 2}}], 'minimum-miner')

    def test_adapter_preserves_missing_cpu_file_stage_and_restores_hooks(self):
        adapter = Q.M
        config = dict(uid=1000, gid=1000, unit='siworld-native-' + 'a' * 32 + '.scope')
        missing = FileNotFoundError(2, 'private exception', '/private/owner/cpu.max')
        with mock.patch.object(adapter.M.os, 'geteuid', return_value=0), \
             mock.patch.object(adapter.CG, 'scoped_group', return_value=Path('/synthetic/group')) as group, \
             mock.patch.object(adapter.CG, 'snapshot', side_effect=missing) as snapshot, \
             mock.patch.object(Path, 'read_text', return_value='0::/synthetic/group'), \
             mock.patch.object(Path, 'write_text'):
            with self.assertRaises(FileNotFoundError) as caught:
                adapter.record(config)
            self.assertIs(adapter.CG.scoped_group, group)
            self.assertIs(adapter.CG.snapshot, snapshot)
        report = adapter.failure_diagnostic(caught.exception, adapter.CURRENT_STAGE)
        self.assertEqual(adapter.startup_diagnostic(json.dumps(report)), {
            'category': 'scope-recorder-failure', 'classification': 'FileNotFoundError',
            'stage': 'initial-counters', 'os_error_number': 2, 'kernel_file': 'cpu.max'})
        self.assertNotIn('private', json.dumps(report))

    def test_malformed_diagnostic_values_and_unknown_fields_are_not_exported(self):
        report = dict(event='multi-asset-diagnostic-failed', classification={'private': 'value'},
            stage=['private'], kernel_file='/private/cpu.max', os_error_number=True, token='secret')
        self.assertEqual(Q.M.startup_diagnostic(json.dumps(report)), {'category': 'scope-recorder-failure'})

    def run_collect(self, base, alter=None, hardware=True, profile='minimum-miner'):
        for name in ('launcher', 'worker', 'screen.json', 'manifest.json'):
            (base / name).write_text('{}')
        args = SimpleNamespace(output=base / 'results', executable=base / 'launcher',
            worker=base / 'worker', screen=base / 'screen.json', manifest=base / 'manifest.json',
            reproduced=base / 'keys', private_parent=base, hardware_profile=profile, timeout=5)
        bound = {'parameters': parameters(), 'security': {'screen': {'passes_selected_model': True}},
            'air_source_sha256': 'a' * 64, 'dependencies_sha256': 'b' * 64,
            'public_verifier_key_sha256': 'c' * 64}
        configs = []

        def scope(command, **_):
            if '--worker-config' not in command:
                return SimpleNamespace(returncode=0)
            config = json.loads(Path(command[command.index('--worker-config') + 1]).read_text())
            configs.append(config)
            counters = {name: 0 for name in Q.M.CG.EVENTS}
            row = dict(kind='transaction', workers=config['workers'], trial=config['trial'],
                parameters=parameters(), resource_control_pass=True, proof_report_valid=True,
                exit_code=0, timed_out=False, process_wall_ns=1_900_000_100,
                process_cpu_ns=1_900_000_000 * config['workers'], average_child_cores=1,
                memory_peak_bytes=600_000_000, memory_max_bytes=Q.M.MEMORY_MAX,
                memory_swap_max_bytes=0, memory_events_before=counters.copy(),
                memory_events_after=counters.copy(), memory_events_delta=counters.copy(),
                remaining_descendants_at_exit=0, cpu_max='max 100000',
                verification_workers=config['workers'], hardware_profile=config['hardware_profile'],
                measurement_scope_sha256=hashlib.sha256(config['unit'].encode()).hexdigest(),
                visible_cpu_limits=[dict(ancestor_level=0, cpu_max='max 100000', quota_cores=None)],
                measurement=dict(setup_ns=10, generation_ns=1_900_000_000,
                    verification_ns=17_000_000, proof_bytes=600_000,
                    public_transaction_bytes=2709, permanent_position_bytes=2741))
            raw = {'security': bound['security'], 'measurement': row['measurement']}
            if alter:
                alter(config, row, raw)
            if raw is not None:
                Path(config['private_output']).write_text(json.dumps(raw))
            Path(config['result']).write_text(json.dumps(row))
            return SimpleNamespace(returncode=0, stdout='private transport output')

        hardware_record = dict(profile_qualified=True, hardware=dict(cpu_model='Synthetic CPU',
            exposed_physical_cores=8, logical_cpus=8, memory_total_bytes=32 * 1024**3)) if hardware else None
        with mock.patch.object(Q, 'bound_profile', return_value=bound), \
             mock.patch.object(Q.M, 'qualify_and_record', return_value={'profile_qualified': True} if hardware else None), \
             mock.patch.object(Q.H, 'qualify_and_record', return_value=hardware_record), \
             mock.patch.object(Q.M, 'validate_report', side_effect=lambda raw, config: raw['measurement']), \
             mock.patch.object(Q.M, 'security_summary', side_effect=lambda value: value), \
             mock.patch.object(Q.subprocess, 'check_output', return_value='d' * 40), \
             mock.patch.object(Q.subprocess, 'run', side_effect=scope):
            code = Q.collect(args)
        saved = json.loads((args.output / 'summary.json').read_text()) if hardware else None
        return code, saved, configs

    def test_exact_frozen_six_fresh_scopes_and_reused_resource_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            code, value, configs = self.run_collect(Path(directory))
        self.assertEqual(code, 0)
        self.assertEqual([(x['workers'], x['trial']) for x in configs],
            [(4, 1), (4, 2), (4, 3), (1, 1), (1, 2), (1, 3)])
        self.assertEqual(len({x['unit'] for x in configs}), 6)
        self.assertTrue(all(x['kind'] == 'transaction' and x['parameters'] == parameters() for x in configs))
        command = Q.M.scope_command('siworld-native-' + 'a' * 32 + '.scope', Path('/tmp/config'))
        self.assertIn('MemoryMax=5G', command)
        self.assertIn('MemorySwapMax=0', command)
        self.assertIn(str(ROOT / 'scripts/qualification-cgroup.py'), command)
        self.assertTrue(value['baseline_qualified'])
        self.assertTrue(value['engineering_target_pass'])
        self.assertTrue(value['minimum_configuration_qualified'])
        self.assertEqual(value['hardware']['hardware']['memory_total_bytes'], 32 * 1024**3)
        self.assertTrue(all(x['qualification_profile'] == 'minimum-miner' for x in configs))
        self.assertTrue(all(x['hardware_profile'] == 'diagnostic' for x in configs))
        self.assertFalse(value['verification_only_process'])
        self.assertFalse(value['acceptance'])

    def test_every_trial_must_meet_size_and_four_worker_time(self):
        for field, number in [('generation_ns', 2_000_000_001), ('proof_bytes', 655361)]:
            def alter(config, row, raw):
                if config['workers'] == 4 and config['trial'] == 3:
                    row['measurement'][field] = number
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                code, value, _ = self.run_collect(Path(directory), alter=alter)
                self.assertEqual(code, 1)
                self.assertFalse(value['engineering_target_pass'])

    def test_one_worker_proof_size_is_also_bounded(self):
        def alter(config, row, raw):
            if config['workers'] == 1:
                row['measurement']['proof_bytes'] = 655361
        with tempfile.TemporaryDirectory() as directory:
            code, value, _ = self.run_collect(Path(directory), alter=alter)
        self.assertEqual(code, 1)
        self.assertFalse(value['engineering_target_pass'])

    def test_exact_time_and_size_limits_pass_and_extra_time_is_not_allowed(self):
        def boundary(config, row, raw):
            row['measurement'].update(generation_ns=2_000_000_000 if config['workers'] == 4
                                     else 3_000_000_000, proof_bytes=655360)
        with tempfile.TemporaryDirectory() as directory:
            code, value, _ = self.run_collect(Path(directory), alter=boundary)
        self.assertEqual(code, 0)
        self.assertTrue(value['engineering_target_pass'])
        self.assertEqual(value['four_worker_generation_limit_ns'], 2_000_000_000)

    def test_legacy_recorder_diagnostic_profile_cannot_bypass_minimum_cpu_quota(self):
        def reduced(config, row, raw):
            self.assertEqual(config['hardware_profile'], 'diagnostic')
            row['visible_cpu_limits'][0].update(cpu_max='300000 100000', quota_cores=3)
        with tempfile.TemporaryDirectory() as directory:
            code, value, _ = self.run_collect(Path(directory), alter=reduced)
        self.assertEqual(code, 1)
        self.assertFalse(value['engineering_target_pass'])

    def test_whole_process_memory_peak_cannot_exceed_the_unchanged_budget(self):
        def excessive(config, row, raw):
            row['memory_peak_bytes'] = Q.M.MEMORY_MAX + 1
        with tempfile.TemporaryDirectory() as directory:
            code, value, _ = self.run_collect(Path(directory), alter=excessive)
        self.assertEqual(code, 1)
        self.assertFalse(value['engineering_target_pass'])

    def test_missing_proof_report_preserves_available_kernel_counters(self):
        def alter(config, row, raw):
            raw.clear()
            row['resource_control_pass'] = False
            row['memory_events_after']['oom_kill'] = 1
            row['memory_events_delta']['oom_kill'] = 1
        with tempfile.TemporaryDirectory() as directory:
            code, value, _ = self.run_collect(Path(directory), alter=alter)
        self.assertEqual(code, 1)
        self.assertEqual(value['workers']['4']['trials'][0]['memory_events_delta']['oom_kill'], 1)

    def test_security_change_and_kernel_failure_cannot_pass(self):
        for failure in ('security', 'event', 'descendant', 'missing_counter', 'invalid_report'):
            def alter(config, row, raw):
                if failure == 'security':
                    raw['security'] = {'changed': True}
                elif failure == 'event':
                    row['memory_events_after']['oom_kill'] = 1
                    row['memory_events_delta']['oom_kill'] = 1
                elif failure == 'descendant':
                    row['remaining_descendants_at_exit'] = 1
                elif failure == 'missing_counter':
                    del row['memory_events_delta']['max']
                else:
                    row['proof_report_valid'] = False
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                code, value, _ = self.run_collect(Path(directory), alter=alter)
                self.assertEqual(code, 1)
                self.assertFalse(value['all_measurements_complete'])
                if failure == 'event':
                    self.assertEqual(value['workers']['4']['trials'][0]['memory_events_delta']['oom_kill'], 1)

    def test_unavailable_baseline_runs_no_proofs_and_diagnostic_never_certifies_it(self):
        with tempfile.TemporaryDirectory() as directory:
            code, value, configs = self.run_collect(Path(directory), hardware=False)
        self.assertEqual((code, value, configs), (1, None, []))
        with tempfile.TemporaryDirectory() as directory:
            code, value, configs = self.run_collect(Path(directory), profile='diagnostic')
        self.assertEqual(code, 0)
        self.assertEqual(len(configs), 6)
        self.assertFalse(value['baseline_qualified'])
        self.assertFalse(value['engineering_target_pass'])
        self.assertEqual(value['status'], 'actual-host-diagnostic-only')

    def test_private_and_unknown_fields_are_never_exported(self):
        def alter(config, row, raw):
            row['raw_log'] = '/private/credential'
            row['measurement']['wallet'] = '/private/credential'
            raw['private_address'] = '/private/credential'
        with tempfile.TemporaryDirectory() as directory:
            code, value, _ = self.run_collect(Path(directory), alter=alter)
        self.assertEqual(code, 0)
        self.assertNotIn('/private/credential', json.dumps(value))
        self.assertNotIn('siworld-native-', json.dumps(value))

    def test_inaccessible_cpu_ancestor_remains_unknown_and_contradictory_quotas_fail(self):
        def unknown(config, row, raw):
            row['visible_cpu_limits'].append(dict(ancestor_level=1, cpu_max=None, quota_cores=None))
        with tempfile.TemporaryDirectory() as directory:
            code, value, _ = self.run_collect(Path(directory), alter=unknown)
        self.assertEqual(code, 0)
        self.assertIsNone(value['workers']['4']['trials'][0]['visible_cpu_limits'][1]['cpu_max'])
        self.assertIsNone(value['workers']['4']['trials'][0]['visible_cpu_limits'][1]['quota_cores'])
        for cpu, quota in ((None, 4), ('max 100000', 4), ('400000 100000', None),
                           ('400000 100000', 3), ('400000 100000', True), ('300000 100000', 3)):
            def inconsistent(config, row, raw):
                row['visible_cpu_limits'].append(dict(ancestor_level=1, cpu_max=cpu, quota_cores=quota))
            with self.subTest(cpu=cpu, quota=quota), tempfile.TemporaryDirectory() as directory:
                code, value, _ = self.run_collect(Path(directory), alter=inconsistent)
                self.assertEqual(code, 1)
                self.assertFalse(value['all_measurements_complete'])

    def test_all_genuine_frozen_trials_pass_with_actual_security_and_unknown_ancestor(self):
        frozen = json.loads((ROOT / Q.F.TRANSACTION).read_text())
        manifest = json.loads((ROOT / Q.F.MANIFEST).read_text())
        import copy
        for workers in ('4', '1'):
            for original in frozen['repeated_measurements']['transaction']['workers'][workers]['trials']:
                row = copy.deepcopy(original)
                config = dict(unit='siworld-native-' + 'e' * 32 + '.scope', kind='transaction',
                    workers=int(workers), trial=row['trial'], parameters=parameters(),
                    hardware_profile='epyc7763-baseline', binary_sha256=frozen['measurement_binary_sha256'],
                    air_source_sha256=frozen['air_source_sha256'], dependencies_sha256=frozen['dependencies_sha256'])
                row['measurement_scope_sha256'] = hashlib.sha256(config['unit'].encode()).hexdigest()
                raw = dict(suite=Q.M.SUITE, kind='transaction', workers=int(workers),
                    hiding_workers='1' if workers == '1' else '2', verified=True,
                    synthetic_fixture=True, cryptographic_approval=False, network_activation=False,
                    binary_sha256=config['binary_sha256'], air_source_sha256=config['air_source_sha256'],
                    dependencies_sha256=config['dependencies_sha256'], parameters=parameters(),
                    security=manifest['relations'][0]['security'],
                    measurement={**row['measurement'], 'actual_encryption_self_check': True})
                actual = Q.clean_trial(row, raw, config, {'security': frozen['selected_security']})
                self.assertTrue(actual['proof_report_valid'])
                self.assertTrue(actual['resource_control_pass'])
                self.assertEqual(actual['measurement']['generation_ns'], original['measurement']['generation_ns'])
                self.assertIsNone(actual['visible_cpu_limits'][2]['cpu_max'])

    def test_bound_profile_rejects_changed_sources_parameters_or_reproduced_keys(self):
        manifest = json.loads((ROOT / Q.F.MANIFEST).read_text())
        source = json.loads((ROOT / Q.F.TRANSACTION).read_text())
        entry = manifest['relations'][0]
        screen = {'air_source_sha256': source['air_source_sha256'],
            'dependencies_sha256': source['dependencies_sha256']}
        chosen = {'parameters': parameters(), 'security': source['selected_security']}
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); path = base / 'manifest.json'; path.write_text(json.dumps(manifest))
            screen_path = base / 'screen.json'; screen_path.write_text(json.dumps(screen))
            with mock.patch.object(Q.F, 'validate') as validate, \
                 mock.patch.object(Q.F, 'transaction_profile', return_value=source), \
                 mock.patch.object(Q.M, 'profiles', return_value={(7, 20): chosen}):
                result = Q.bound_profile(path, base / 'keys', screen_path)
                self.assertEqual(result['parameters'], parameters())
                validate.assert_called_once()
                self.assertEqual(validate.call_args.kwargs['reproduced'], base / 'keys')
                for field in ('num_queries', 'batch_pow_bits'):
                    chosen['parameters'][field] += 1
                    with self.assertRaises(ValueError):
                        Q.bound_profile(path, base / 'keys', screen_path)
                    chosen['parameters'][field] -= 1
                screen['air_source_sha256'] = '0' * 64
                screen_path.write_text(json.dumps(screen))
                with self.assertRaises(ValueError):
                    Q.bound_profile(path, base / 'keys', screen_path)
            with mock.patch.object(Q.F, 'validate', side_effect=ValueError('changed key')):
                with self.assertRaises(ValueError):
                    Q.bound_profile(path, base / 'keys', screen_path)
        self.assertEqual(entry['parameters'], parameters())


if __name__ == '__main__':
    unittest.main()
