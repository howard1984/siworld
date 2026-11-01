"""Check isolated full-load measurement provenance and failure handling."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('full_load', ROOT / 'scripts/measure-settlement-full-load.py')
FULL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FULL)


class NativeFullLoadTests(unittest.TestCase):
    UNIT = 'siworld-native-' + 'a' * 32 + '.scope'

    def report(self):
        return dict(schema=1, suite=FULL.CG.SUITE, statement='native-v1-confidential-miner-note',
                    capacity=576, parameters=dict(FULL.PARAMETERS), workers=4, verified=True,
                    fee_tier='priority', active_fee_slots=576, reward_note_count=5,
                    fund_claims_measured=False, max_fund_claims=8, setup_ns=1,
                    private_source_path='/private/excluded',
                    trials=[dict(proof_body_bytes=FULL.LIMIT, generation_ns=2,
                                 verification_ns=3, private_commitment='excluded')])

    def counters(self):
        return {'memory.events': {name: 0 for name in FULL.CG.EVENTS},
                'memory.peak': 1000, 'memory.swap.current': 0}

    def record(self, base, report, exit_code=0, after=None, launch_error=None, timeout=False):
        raw = base / 'raw.json'
        if report is not None:
            raw.write_text(json.dumps(report))
        membership = base / 'membership'
        membership.write_text('0::/system.slice/' + self.UNIT)
        config = dict(trial=1, unit=self.UNIT, source_commit='a' * 40,
                      binary_sha256='b' * 64, uid=1001, gid=1001,
                      binary='/synthetic/proof', raw=str(raw), log=str(base / 'worker.log'),
                      result=str(base / 'result.json'))
        process = mock.Mock(pid=100)
        process.wait.return_value = exit_code
        if timeout:
            process.wait.side_effect = [FULL.subprocess.TimeoutExpired('synthetic-proof', 1800), -9]
        process.poll.return_value = exit_code

        def mapped(path):
            if str(path) == '/proc/self/cgroup':
                return membership
            if str(path) == '/proc/self/oom_score_adj':
                return base / 'oom-score'
            return Path(path)

        with mock.patch.object(FULL.os, 'geteuid', return_value=0), \
             mock.patch.object(FULL, 'Path', side_effect=mapped), \
             mock.patch.object(FULL.CG, 'scoped_group', return_value=base / 'scope'), \
             mock.patch.object(FULL.CG, 'snapshot', side_effect=[self.counters(), after or self.counters()]), \
             mock.patch.object(FULL.CG, 'kill_owned_tree') as kill, \
             mock.patch.object(FULL, 'drain', return_value=set()), \
             mock.patch.object(FULL.subprocess, 'Popen', return_value=process, side_effect=launch_error) as popen:
            code = FULL.record(config)
            if timeout:
                kill.assert_called_once_with(process, base / 'scope')
        result = json.loads((base / 'result.json').read_text())
        return code, result, popen

    def test_metric_allowlist_excludes_private_data_and_requires_exact_profile(self):
        public = FULL.metrics(self.report())
        self.assertEqual(set(public), {'proof_body_bytes', 'generation_ns', 'verification_ns', 'setup_ns'})
        self.assertNotIn('excluded', json.dumps(public))
        mutations = [lambda r: r.update(verified=False), lambda r: r.update(workers=1),
                     lambda r: r.update(workers=4.0), lambda r: r.update(schema=True),
                     lambda r: r.update(capacity=512), lambda r: r.update(reward_note_count=1),
                     lambda r: r.update(fee_tier='standard'), lambda r: r.update(active_fee_slots=575),
                     lambda r: r.update(fund_claims_measured=True), lambda r: r.update(max_fund_claims=32),
                     lambda r: r['parameters'].update(log_blowup=7),
                     lambda r: r['parameters'].update(commit_pow_bits=False),
                     lambda r: r['trials'].append(dict(r['trials'][0])),
                     lambda r: r['trials'][0].update(generation_ns=-1),
                     lambda r: r['trials'][0].update(proof_body_bytes=True)]
        for mutation in mutations:
            value = self.report()
            mutation(value)
            with self.subTest(index=mutations.index(mutation)), self.assertRaises(ValueError):
                FULL.metrics(value)

    def test_independent_recorder_enforces_margin_and_keeps_kernel_evidence(self):
        for size, passes in ((FULL.LIMIT, True), (FULL.LIMIT + 1, False)):
            with self.subTest(size=size), tempfile.TemporaryDirectory() as temporary:
                report = self.report()
                report['trials'][0]['proof_body_bytes'] = size
                code, saved, popen = self.record(Path(temporary), report)
                self.assertEqual(code, 0 if passes else 1)
                self.assertEqual(saved['complete'], passes)
                self.assertEqual(saved['proof_body_limit_pass'], passes)
                self.assertEqual(saved['memory_peak_bytes'], 1000)
                self.assertFalse(saved['acceptance'])
                args = popen.call_args.args[0]
                self.assertEqual(args[args.index('--trials') + 1], '1')
                self.assertEqual(popen.call_args.kwargs['env']['RAYON_NUM_THREADS'], '4')
                self.assertNotIn('/private', json.dumps(saved))

    def test_oom_without_worker_report_preserves_peak_and_event_counters(self):
        after = self.counters()
        after['memory.events']['oom_kill'] = 1
        with tempfile.TemporaryDirectory() as temporary:
            code, saved, _ = self.record(Path(temporary), None, exit_code=-9, after=after)
        self.assertEqual(code, 1)
        self.assertEqual(saved['memory_after']['memory.events']['oom_kill'], 1)
        self.assertEqual(saved['event_deltas']['oom_kill'], 1)
        self.assertEqual(saved['exit_code'], -9)
        self.assertFalse(saved['complete'])
        self.assertFalse(saved['proof_report_valid'])

    def test_launch_error_is_not_published_and_final_counters_still_survive(self):
        with tempfile.TemporaryDirectory() as temporary:
            code, saved, _ = self.record(Path(temporary), None,
                launch_error=FileNotFoundError('/private/host/secret-path'))
        self.assertEqual(code, 1)
        self.assertEqual(saved['error_class'], 'FileNotFoundError')
        self.assertIn('memory_before', saved)
        self.assertIn('memory_after', saved)
        self.assertNotIn('secret-path', json.dumps(saved))
        self.assertFalse(saved['complete'])

    def test_timeout_kills_only_the_owned_tree_and_saves_failure_counters(self):
        with tempfile.TemporaryDirectory() as temporary:
            code, saved, _ = self.record(Path(temporary), None, exit_code=-9, timeout=True)
        self.assertEqual(code, 1)
        self.assertTrue(saved['timed_out'])
        self.assertEqual(saved['exit_code'], -9)
        self.assertIn('memory_after', saved)
        self.assertFalse(saved['resource_control_pass'])
        self.assertFalse(saved['complete'])

    def test_manifest_preserves_original_sources_dependencies_and_lockfile(self):
        application = ROOT / 'crates/bench-multi-asset'
        originals = {name: (application / name).read_bytes() for name in ('Cargo.toml', 'Cargo.lock')}
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'application'
            manifest = FULL.prepare(output)
            text = manifest.read_text()
            self.assertIn('[package]\nautobins = false\n', text)
            self.assertIn('[lib]\npath = ' + json.dumps(str(application / 'src/lib.rs')), text)
            self.assertEqual(text.count('[[bin]]'), 1)
            self.assertIn('name = "settlement-full-load"\npath = '
                          + json.dumps(str(ROOT / 'scripts/settlement-full-load.rs')), text)
            self.assertIn('path = ' + json.dumps(str(ROOT / 'crates/bench-d8')), text)
            self.assertEqual((output / 'Cargo.lock').read_bytes(), originals['Cargo.lock'])
            with self.assertRaises(FileExistsError):
                FULL.prepare(output)
        for name, original in originals.items():
            self.assertEqual((application / name).read_bytes(), original)
        self.assertFalse((application / 'src/bin/settlement-full-load.rs').exists())

    def test_scope_names_and_properties_are_owned_and_independent(self):
        command = FULL.command(self.UNIT, Path('/synthetic/config.json'))
        for value in ('--scope', '--unit=' + self.UNIT, 'MemoryMax=5G', 'MemorySwapMax=0',
                      'MemoryAccounting=yes', 'CPUAccounting=yes'):
            self.assertIn(value, command)
        self.assertNotIn('--user', command)
        self.assertNotIn('MemoryOOMGroup=no', command)
        with self.assertRaises(ValueError):
            FULL.command('unrelated-node.scope', Path('/synthetic/config.json'))

    def test_ancestor_quota_and_affinity_are_both_required_for_four_vcpu_baseline(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            membership = base / 'membership'
            membership.write_text('0::/jobs/test.scope')
            mount = base / 'cgroups'
            group = mount / 'jobs/test.scope'
            group.mkdir(parents=True)
            (mount / 'cpu.max').write_text('max 100000')
            (group.parent / 'cpu.max').write_text('400000 100000')
            (group / 'cpu.max').write_text('max 100000')
            with mock.patch.object(FULL.os, 'sched_getaffinity', return_value={0, 1, 2, 3}, create=True):
                self.assertTrue(FULL.cpu_capacity(membership, mount)['four_vcpu_capacity_visible'])
                (group.parent / 'cpu.max').write_text('200000 100000')
                capacity = FULL.cpu_capacity(membership, mount)
                self.assertFalse(capacity['four_vcpu_capacity_visible'])
                self.assertEqual(capacity['minimum_visible_quota_millicpus'], 2000)
            with mock.patch.object(FULL.os, 'sched_getaffinity', return_value={0, 1}, create=True):
                self.assertFalse(FULL.cpu_capacity(membership, mount)['four_vcpu_capacity_visible'])
            self.assertNotIn(temporary, json.dumps(capacity))
            membership.write_text('0::/../escape')
            with self.assertRaises(ValueError):
                FULL.cpu_capacity(membership, mount)

    def test_real_hierarchy_root_may_omit_cpu_max_but_nonroot_must_expose_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            membership = base / 'membership'
            membership.write_text('0::/jobs/test.scope')
            mount = base / 'cgroups'
            group = mount / 'jobs/test.scope'
            group.mkdir(parents=True)
            (group.parent / 'cpu.max').write_text('400000 100000')
            (group / 'cpu.max').write_text('max 100000')
            with mock.patch.object(FULL.os, 'sched_getaffinity', return_value={0, 1, 2, 3}, create=True):
                self.assertTrue(FULL.cpu_capacity(membership, mount)['four_vcpu_capacity_visible'])
                (group.parent / 'cpu.max').unlink()
                with self.assertRaises(FileNotFoundError):
                    FULL.cpu_capacity(membership, mount)
                membership.write_text('0::/')
                self.assertTrue(FULL.cpu_capacity(membership, mount)['four_vcpu_capacity_visible'])

    def test_collection_uses_three_fresh_scopes_and_publishes_only_allowlisted_results(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            (base / 'private').mkdir()
            (base / 'public').mkdir()
            binary = base / 'target/release/settlement-full-load'
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b'synthetic test executable identity')
            cpuinfo = base / 'cpuinfo'
            cpuinfo.write_text('model name\t: AMD EPYC 7763 64-Core Processor\n')
            commands = []
            recorder_results = set()
            original_write = FULL.write

            def parent_write(path, value):
                if Path(path) in recorder_results:
                    raise PermissionError('The recorder result is owned by root')
                original_write(path, value)

            def mapped(path):
                return cpuinfo if str(path) == '/proc/cpuinfo' else Path(path)

            def run(command, **kwargs):
                commands.append(command)
                config = json.loads(Path(command[-1]).read_text())
                original_write(config['result'], dict(complete=True, proof_report_valid=True,
                    measurement=FULL.metrics(self.report()), memory_peak_bytes=1000))
                recorder_results.add(Path(config['result']))
                return mock.Mock(returncode=0, stdout='/private/host/excluded log')

            with mock.patch.object(FULL, 'BASE', base), \
                 mock.patch.object(FULL, 'Path', side_effect=mapped), \
                 mock.patch.dict(FULL.os.environ, {'CARGO_TARGET_DIR': str(base / 'target')}), \
                 mock.patch.object(FULL, 'cpu_capacity', return_value=dict(four_vcpu_capacity_visible=True)), \
                 mock.patch.object(FULL, 'write', side_effect=parent_write), \
                 mock.patch.object(FULL.subprocess, 'check_output', return_value='a' * 40), \
                 mock.patch.object(FULL.subprocess, 'run', side_effect=run):
                self.assertEqual(FULL.collect(), 0)
            self.assertEqual(len(commands), 3)
            self.assertTrue(all(path.parent == base / 'private' for path in recorder_results))
            self.assertEqual(len(list((base / 'public').glob('trial-*.json'))), 3)
            self.assertEqual(len({command[command.index('--quiet') + 1] for command in commands}), 3)
            summary = json.loads((base / 'public/summary.json').read_text())
            self.assertTrue(summary['epyc7763_baseline_complete'])
            self.assertEqual(summary['max_proof_body_bytes'], FULL.LIMIT)
            self.assertFalse(summary['fund_claims_measured'])
            self.assertEqual(summary['max_fund_claims'], 8)
            self.assertFalse(summary['acceptance'])
            for path in (base / 'public').glob('*.json'):
                self.assertNotIn('/private/host', path.read_text())
                self.assertNotIn(temporary, path.read_text())

    def test_workflow_keeps_failure_artifacts_and_uses_only_isolated_locked_application(self):
        text = (ROOT / '.github/workflows/native-v1-full-load.yml').read_text()
        self.assertIn('runs-on: ubuntu-24.04', text)
        self.assertIn('RAYON_NUM_THREADS: 4', text)
        self.assertIn('persist-credentials: false', text)
        self.assertIn('--locked --manifest-path .local/native-v1-full-load/application/Cargo.toml', text)
        self.assertNotIn('--manifest-path crates/bench-multi-asset/Cargo.toml', text)
        self.assertGreaterEqual(text.count('if: ${{ always() }}'), 2)
        self.assertIn('path: .local/native-v1-full-load/public/*.json', text)
        self.assertNotIn('path: .local/native-v1-full-load/private', text)
        self.assertIn('signed-claim-envelope:', text)
        self.assertIn('--test max_fund_claim_envelope maximum_opaque_proof_envelope_with_eight_signed_claims_preserves_native_budgets -- --ignored --exact', text)
        self.assertIn('path: .local/native-v1-full-load/public/claim-*.json', text)


if __name__ == '__main__':
    unittest.main()
