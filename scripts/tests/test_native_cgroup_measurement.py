"""Protect scope attribution, failure evidence and public artifact boundaries."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('native_cgroup',
    Path(__file__).parents[1] / 'bench/measure-native-cgroup.py')
CG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CG)


class NativeCgroupTests(unittest.TestCase):
    UNIT = 'siworld-native-' + 'a' * 32 + '.scope'

    def counters(self):
        return {'memory.events': {'max': 0, 'oom': 0, 'oom_kill': 0, 'oom_group_kill': 0},
                'memory.peak': 1000, 'memory.swap.current': 0}

    def test_exact_scope_membership_is_required(self):
        mount = Path('/synthetic/cgroup')
        self.assertEqual(CG.scoped_group('0::/system.slice/' + self.UNIT, self.UNIT, mount),
                         mount / 'system.slice' / self.UNIT)
        for membership in ('0::/', '0::/other.scope', '0::/../' + self.UNIT,
                           '1:memory:/system.slice/' + self.UNIT,
                           '0::relative/' + self.UNIT,
                           '0::/system.slice/' + self.UNIT + '\n0::/system.slice/' + self.UNIT):
            with self.subTest(membership=membership), self.assertRaises(ValueError):
                CG.scoped_group(membership, self.UNIT, mount)

    def test_scope_properties_keep_recorder_alive_and_apply_exact_limits(self):
        command = CG.scope_command(self.UNIT, Path('/synthetic/config.json'))
        self.assertIn('--scope', command)
        self.assertIn('--unit=' + self.UNIT, command)
        for prop in ('MemoryMax=5G', 'MemorySwapMax=0', 'MemoryAccounting=yes', 'CPUAccounting=yes'):
            self.assertIn(prop, command)
        self.assertNotIn('--user', command)
        self.assertNotIn('MemoryOOMGroup=no', command)
        with self.assertRaises(ValueError):
            CG.scoped_group('0::/unrelated.scope', 'unrelated.scope')

    def test_smoke_scope_cannot_execute_an_arbitrary_worker(self):
        self.assertEqual(CG.child_command('scope-smoke', Path('/untrusted/worker'),
            Path('/ignored/output'), 1, 'unused'), ['/usr/bin/true'])

    def test_startup_errors_are_fixed_labels_without_host_paths(self):
        text = 'Failed to connect to bus: /private/owner/sensitive'
        self.assertEqual(CG.startup_diagnostic(text)['category'], 'systemd-bus-unavailable')
        rejected = CG.startup_diagnostic('Unknown assignment: MemoryOOMGroup=no')
        self.assertEqual(rejected, {'category': 'systemd-property-rejected', 'property': 'MemoryOOMGroup'})
        self.assertNotIn('property', CG.startup_diagnostic('Unknown assignment: private-owner-setting'))
        text = json.dumps({'event': 'native-cgroup-diagnostic-failed',
            'classification': 'FileNotFoundError', 'stage': 'initial-counters',
            'os_error_number': 2, 'kernel_file': 'cpu.max', 'private_path': '/private/owner'})
        result = CG.startup_diagnostic(text)
        self.assertEqual(result['kernel_file'], 'cpu.max')
        self.assertEqual(result['stage'], 'initial-counters')
        self.assertNotIn('private_path', result)
        injected = json.dumps({'event': 'native-cgroup-diagnostic-failed',
            'classification': '/private/owner', 'stage': '/private/owner',
            'kernel_file': '/private/owner', 'os_error_number': '/private/owner'})
        self.assertNotIn('/private/owner', str(CG.startup_diagnostic(injected)))

    def test_failed_proof_is_never_reported_as_resource_acceptance(self):
        before, after = self.counters(), self.counters()
        success = CG.assess(before, after, 0, False, set())
        self.assertTrue(success['resource_control_pass'])
        self.assertFalse(success['acceptance'])
        self.assertNotIn('production_parameters_frozen', success)
        for event in CG.EVENTS:
            changed = copy.deepcopy(after)
            changed['memory.events'][event] = 1
            with self.subTest(event=event):
                self.assertFalse(CG.assess(before, changed, 0, False, set())['resource_control_pass'])
        for code, timeout, remaining in ((137, False, set()), (0, True, set()), (0, False, {42})):
            self.assertFalse(CG.assess(before, after, code, timeout, remaining)['resource_control_pass'])
        after['memory.peak'] = CG.MEMORY_MAX + 1
        self.assertFalse(CG.assess(before, after, 0, False, set())['resource_control_pass'])
        after['memory.events']['max'] = -1
        with self.assertRaises(ValueError):
            CG.assess(before, after, 0, False, set())

    def test_missing_or_invalid_kernel_events_fail_closed(self):
        for stage in ('before', 'after'):
            for event in CG.EVENTS:
                before, after = self.counters(), self.counters()
                del (before if stage == 'before' else after)['memory.events'][event]
                with self.subTest(stage=stage, event=event), self.assertRaises(ValueError):
                    CG.assess(before, after, 0, False, set())
        for wrong in (-1, True, '0'):
            before, after = self.counters(), self.counters()
            after['memory.events']['oom'] = wrong
            with self.subTest(value=wrong), self.assertRaises(ValueError):
                CG.assess(before, after, 0, False, set())

    def test_kernel_readback_cannot_silently_drop_limit_or_oom_protection(self):
        with tempfile.TemporaryDirectory() as temporary:
            group = Path(temporary)
            files = {'memory.max': str(CG.MEMORY_MAX), 'memory.swap.max': '0',
                     'memory.oom.group': '0', 'memory.peak': '1000', 'memory.current': '500',
                     'memory.swap.current': '0', 'memory.events': 'max 0\noom 0\noom_kill 0\noom_group_kill 0\n',
                     'memory.events.local': 'max 0\noom 0\noom_kill 0\noom_group_kill 0\n', 'cpu.stat': 'usage_usec 1\n',
                     'cpu.max': 'max 100000'}
            for name, value in files.items():
                (group / name).write_text(value)
            self.assertEqual(CG.snapshot(group)['memory.peak'], 1000)
            for name, wrong in (('memory.max', '1000'), ('memory.swap.max', '1'), ('memory.oom.group', '1')):
                (group / name).write_text(wrong)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    CG.snapshot(group)
                (group / name).write_text(files[name])

    def test_each_settlement_process_proves_exactly_once(self):
        command = CG.child_command('settlement', Path('fee-settlement-bench'), Path('raw.json'), 1, 'r')
        self.assertEqual(command[command.index('--capacity') + 1], '576')
        self.assertEqual(command[command.index('--trials') + 1], '1')
        trial = {'generation_ms': 20, 'verification_ms': 2, 'proof_bytes': 1000,
                 'private_commitment': 'excluded'}
        report = {'schema': 2, 'settlement_statement': 'confidential-miner-note-v1',
            'suite': CG.SUITE, 'capacities': [576], 'worker_count': 4,
            'fri_profile': 'transaction-candidate-diagnostic',
            'records': [{'capacity': 576, 'trials': [trial],
                         'shape': {'air_rows': 16}, 'input_digests': ['excluded']}]}
        public = CG.proof_metrics('settlement', report)
        self.assertEqual(public['generation_ns'], 20_000_000)
        self.assertNotIn('input_digests', public)
        self.assertNotIn('private_commitment', str(public))
        for key, value in (('schema', 1), ('settlement_statement', 'public-miner-amount')):
            with self.subTest(key=key), self.assertRaises(ValueError):
                CG.proof_metrics('settlement', {**report, key: value})
        report['records'][0]['trials'].append(trial)
        with self.assertRaises(ValueError):
            CG.proof_metrics('settlement', report)

    def test_oom_counters_are_saved_before_scope_recorder_exits(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            group = base / 'cgroup'
            group.mkdir()
            before = self.counters()
            after = self.counters()
            after['memory.events']['oom_kill'] = 1
            config = {'uid': 1001, 'gid': 1001, 'unit': self.UNIT,
                'private_output': str(base / 'raw.json'), 'private_log': str(base / 'raw.log'),
                'executable': '/synthetic/transaction', 'trial': 1, 'run_id': 'test',
                'timeout': 5, 'kind': 'transaction', 'result': str(base / 'result.json')}
            process = mock.Mock()
            process.wait.return_value = -9
            process.pid = 100
            def redirected(path):
                if str(path) in ('/proc/self/cgroup', '/proc/self/oom_score_adj'):
                    return base / Path(path).name
                return Path(path)
            (base / 'cgroup').mkdir(exist_ok=True)
            # Membership is read before the group resolver; provide a harmless
            # fixture instead of relying on the unit-test host's kernel.
            membership = base / 'membership'
            membership.write_text('0::/system.slice/' + self.UNIT)
            def mapped(path):
                if str(path) == '/proc/self/cgroup':
                    return membership
                return redirected(path)
            with mock.patch.object(CG.os, 'geteuid', return_value=0), \
                 mock.patch.object(CG, 'Path', side_effect=mapped), \
                 mock.patch.object(CG, 'scoped_group', return_value=group), \
                 mock.patch.object(CG, 'snapshot', side_effect=[before, after]), \
                 mock.patch.object(CG, 'member_pids', return_value=set()), \
                 mock.patch.object(CG.subprocess, 'Popen', return_value=process):
                self.assertEqual(CG.run_in_scope(config), 1)
            saved = json.loads((base / 'result.json').read_text())
            self.assertEqual(saved['memory']['after']['memory.events']['oom_kill'], 1)
            self.assertEqual(saved['event_deltas']['oom_kill'], 1)
            self.assertEqual(saved['exit_code'], -9)
            self.assertFalse(saved['resource_control_pass'])
            self.assertFalse(saved['proof_report_valid'])
            self.assertEqual((base / 'oom_score_adj').read_text(), '-1000')

    def test_verification_scopes_have_distinct_startup_inclusive_memory_budget(self):
        command = CG.scope_command(self.UNIT, Path('/synthetic/config.json'), CG.VERIFIER_MEMORY_MAX)
        self.assertIn('MemoryMax=128M', command)
        self.assertNotIn('MemoryMax=5G', command)
        self.assertIn('MemorySwapMax=0', command)
        for kind in CG.VERIFIER_KINDS:
            self.assertEqual(CG.memory_limit(kind), 134217728)
            command = CG.child_command(kind, Path('/guard/native-verifier-bench'),
                Path('/private/result'), 1, 'unused', Path('/private/fixtures'), 'a' * 64)
            self.assertIn('--fixtures', command)
            self.assertNotIn('--prepare-fixtures', command)
        with self.assertRaises(ValueError):
            CG.scope_command(self.UNIT, Path('/synthetic/config.json'), 256 * 1024**2)
        before, after = self.counters(), self.counters()
        after['memory.peak'] = CG.VERIFIER_MEMORY_MAX + 1
        self.assertFalse(CG.assess(before, after, 0, False, set(),
                                  CG.VERIFIER_MEMORY_MAX)['resource_control_pass'])

    def test_engineering_freeze_requires_checker_success_and_disclaims_approval(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest = Path(temporary) / 'profile.json'
            manifest.write_text(json.dumps({'schema': 1, 'status': 'engineering-frozen',
                'cryptographic_approval': False, 'network_activation': False,
                'profiles': {kind: {'verifier_artifact_sha256': 'a' * 64}
                             for kind in ('transaction', 'settlement')}}))
            with mock.patch.object(CG.subprocess, 'run') as check:
                evidence = CG.freeze_evidence(manifest)
                self.assertTrue(evidence['engineering_profile_frozen'])
                self.assertFalse(evidence['cryptographic_approval'])
                self.assertFalse(evidence['network_activation'])
                self.assertEqual(len(evidence['freeze_manifest_sha256']), 64)
                self.assertTrue(check.call_args.kwargs['check'])
            manifest.write_text(json.dumps({'schema': 1, 'status': 'engineering-frozen',
                'cryptographic_approval': True, 'network_activation': False}))
            with mock.patch.object(CG.subprocess, 'run'), self.assertRaises(ValueError):
                CG.freeze_evidence(manifest)

    def test_fixtures_use_the_frozen_public_verifier_not_a_self_selected_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            frozen = {'verifier_artifact_sha256': {'transaction': 'a' * 64, 'settlement': 'b' * 64}}
            manifest = {kind: {'vk_sha256': digest} for kind, digest in frozen['verifier_artifact_sha256'].items()}
            (directory / 'manifest.json').write_text(json.dumps(manifest))
            self.assertEqual(len(CG.validate_fixture_keys(directory, frozen)), 64)
            manifest['transaction']['vk_sha256'] = 'c' * 64
            (directory / 'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                CG.validate_fixture_keys(directory, frozen)

    def test_actual_child_cpu_is_user_plus_system_and_not_cpu_quota(self):
        before = mock.Mock(ru_utime=1.0, ru_stime=2.0)
        after = mock.Mock(ru_utime=1.125, ru_stime=2.03125)
        self.assertEqual(CG.process_cpu_ns(before, after), 156250000)
        with self.assertRaises(ValueError):
            CG.process_cpu_ns(after, before)

    def test_cpu_watchdog_terminates_only_the_owned_tree_and_reports_sampled_overshoot(self):
        process = mock.Mock(pid=123)
        process.wait.side_effect = [CG.subprocess.TimeoutExpired('worker', 0.01), -9]
        with mock.patch.object(CG, 'read_numbers', side_effect=[{'usage_usec': 1000},
                {'usage_usec': 251001}]), \
             mock.patch.object(CG.time, 'monotonic', return_value=0), \
             mock.patch.object(CG, 'kill_owned_tree') as kill:
            result = CG.wait_with_cpu_budget(process, Path('/owned/scope'), 1000, 2, 250000000)
        self.assertEqual(result, (-9, False, True, 250001000, 2))
        kill.assert_called_once_with(process, Path('/owned/scope'))
        self.assertLessEqual(process.wait.call_args_list[0].kwargs['timeout'], 0.01)
        self.assertEqual(CG.verification_cpu_budget('verify-block576'), 144000000000)
        self.assertEqual(CG.diagnostic_timeout('verify-transaction', 600), 2)
        self.assertEqual(CG.diagnostic_timeout('verify-block576', 600), 180)
        self.assertEqual(CG.diagnostic_timeout('transaction', 600), 600)

    def test_cpu_watchdog_fails_closed_if_accounting_regresses(self):
        with mock.patch.object(CG, 'read_numbers', return_value={'usage_usec': 999}), \
             mock.patch.object(CG.time, 'monotonic', return_value=0), self.assertRaises(ValueError):
            CG.wait_with_cpu_budget(mock.Mock(), Path('/owned/scope'), 1000, 2, 250000000)

    def test_verifier_reports_reject_setup_generation_wrong_threads_and_valid_block_claim(self):
        report = {'suite': CG.SUITE, 'verification_only': True, 'workers': 1,
            'setup_performed': False, 'generation_calls': 0, 'verified': True,
            'verification_calls': 576, 'unique_proof_count': 1,
            'statement_reconstructed': True, 'wire_codec': 'SWTX-v1',
            'stateful_block_validation': False, 'parameters': dict(CG.PARAMETERS),
            'loading_ns': 1, 'verification_ns': 100, 'proof_body_bytes': 10,
            'per_proof_wall_min_ns': 1, 'per_proof_wall_median_ns': 2,
            'per_proof_wall_max_ns': 3, 'private_path': '/private/owner'}
        public = CG.proof_metrics('verify-block576', report)
        self.assertEqual(public['verification_calls'], 576)
        self.assertFalse(public['stateful_block_validation'])
        self.assertNotIn('private_path', public)
        for key, value in (('setup_performed', True), ('generation_calls', 1),
                ('workers', 4), ('verification_calls', 1), ('unique_proof_count', 576),
                ('stateful_block_validation', True), ('statement_reconstructed', False),
                ('wire_codec', 'raw-postcard'), ('verified', False)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                CG.proof_metrics('verify-block576', {**report, key: value})
        with self.assertRaises(ValueError):
            CG.proof_metrics('verify-transaction', report)

    def test_cpu_kill_evidence_survives_missing_worker_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            group = base / 'scope'
            group.mkdir()
            membership = base / 'membership'
            membership.write_text('0::/system.slice/' + self.UNIT)
            before, after = self.counters(), self.counters()
            before['cpu.stat'] = {'usage_usec': 1000}
            after['cpu.stat'] = {'usage_usec': 261000}
            config = {'uid': 1001, 'gid': 1001, 'unit': self.UNIT, 'kind': 'verify-transaction',
                'private_output': str(base / 'absent.json'), 'private_log': str(base / 'worker.log'),
                'executable': '/synthetic/verifier', 'trial': 1, 'run_id': 'test', 'timeout': 600,
                'fixtures': str(base / 'fixtures'), 'fixture_manifest_sha256': 'a' * 64,
                'result': str(base / 'result.json')}
            def mapped(path):
                if str(path) == '/proc/self/cgroup':
                    return membership
                if str(path) == '/proc/self/oom_score_adj':
                    return base / 'score'
                return Path(path)
            process = mock.Mock(pid=100)
            with mock.patch.object(CG.os, 'geteuid', return_value=0), \
                 mock.patch.object(CG, 'Path', side_effect=mapped), \
                 mock.patch.object(CG, 'scoped_group', return_value=group), \
                 mock.patch.object(CG, 'snapshot', side_effect=[before, after]), \
                 mock.patch.object(CG, 'member_pids', return_value=set()), \
                 mock.patch.object(CG.subprocess, 'Popen', return_value=process), \
                 mock.patch.object(CG, 'wait_with_cpu_budget', return_value=(-9, False, True, 260000000, 2)):
                self.assertEqual(CG.run_in_scope(config), 1)
            saved = json.loads((base / 'result.json').read_text())
            self.assertTrue(saved['cpu_watchdog']['killed_on_budget'])
            self.assertEqual(saved['cpu_watchdog']['observed_overshoot_ns'], 10000000)
            self.assertFalse(saved['proof_report_valid'])
            self.assertFalse(saved['resource_control_pass'])
            self.assertEqual(saved['memory_max_bytes'], 134217728)

    def test_unverified_or_wrong_parameter_transaction_is_rejected(self):
        report = {'suite': CG.SUITE, 'verified': True, 'workers': 4,
            'operation': 'four_worker', 'production_selection_allowed': False,
            'parameters': dict(CG.PARAMETERS), 'setup_ns': 1, 'generation_ns': 2,
            'verification_ns': 3, 'proof_body_bytes': 4, 'private_source_path': 'excluded'}
        self.assertNotIn('private_source_path', CG.proof_metrics('transaction', report))
        for key, value in (('verified', False), ('workers', 1),
                           ('production_selection_allowed', True), ('generation_ns', -1)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                CG.proof_metrics('transaction', {**report, key: value})
        report['parameters']['num_queries'] = 1
        with self.assertRaises(ValueError):
            CG.proof_metrics('transaction', report)


if __name__ == '__main__':
    unittest.main()
