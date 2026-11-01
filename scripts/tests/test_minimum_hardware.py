"""Minimum deployment resources and unchanged native proof admission limits."""
import copy
import importlib.util
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'scripts' / name)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


H = load('minimum-hardware.py')


class MinimumHardwareTests(unittest.TestCase):
    def hardware(self, memory=32 * 1024**3):
        return dict(os='Ubuntu 24.04', architecture='x86_64', cpu_model='Example x86 CPU',
            logical_cpus=8, online_logical_cpus=8, affinity_cpus=8,
            exposed_physical_cores=8, memory_total_bytes=memory,
            x86_64_v3_features={name: True for name in H.X86_64_V3_FLAGS},
            virtualization_detection=dict(result='none', exit_code=1))

    def test_model_topology_and_virtualization_are_measurement_metadata(self):
        for model in ('AMD EPYC 7763', 'AMD EPYC 9V74', 'Intel Xeon', 'Example CPU'):
            for profile in ('minimum-validator', 'minimum-miner'):
                hardware = self.hardware()
                hardware['cpu_model'] = model
                self.assertTrue(H.qualify_hardware_profile(hardware, profile)['profile_qualified'])

    def test_each_role_has_an_exact_memory_floor(self):
        for role, gib in (('validator', 16), ('miner', 32)):
            profile = 'minimum-' + role
            for delta, accepted in ((-1, False), (0, True), (1, True)):
                with self.subTest(role=role, delta=delta):
                    value = self.hardware(gib * 1024**3 + delta)
                    if accepted:
                        self.assertTrue(H.qualify_hardware_profile(value, profile)['profile_qualified'])
                    else:
                        with self.assertRaises(ValueError):
                            H.qualify_hardware_profile(value, profile)

    def test_missing_features_and_reduced_cpu_capacity_fail(self):
        for name in H.X86_64_V3_FLAGS:
            value = self.hardware()
            value['x86_64_v3_features'][name] = False
            with self.subTest(feature=name), self.assertRaises(ValueError):
                H.qualify_hardware_profile(value, 'minimum-miner')
        for field in ('logical_cpus', 'online_logical_cpus', 'affinity_cpus'):
            for invalid in (3, 0, True, None):
                value = self.hardware()
                value[field] = invalid
                with self.subTest(field=field, value=invalid), self.assertRaises(ValueError):
                    H.qualify_hardware_profile(value, 'minimum-validator')

    def test_linux_flag_aliases_and_every_cpu_are_checked(self):
        flags = {aliases[0] for aliases in H.X86_64_V3_FLAGS.values()}
        self.assertTrue(all(H.v3_features([flags, flags]).values()))
        self.assertFalse(H.v3_features([flags, flags - {'fma'}])['fma'])
        self.assertFalse(all(H.v3_features([]).values()))

    def test_deployment_memory_limits_do_not_relabel_small_allocations(self):
        for profile, gib in (('minimum-validator', 16), ('minimum-miner', 32)):
            for limit in (str(gib * 1024**3), 'max'):
                H.qualify_memory_profile([{'memory.max': limit}], profile)
            with self.assertRaises(ValueError):
                H.qualify_memory_profile([{'memory.max': str(gib * 1024**3 - 1)}], profile)
            with self.assertRaises(ValueError):
                H.qualify_cpu_profile([{'cpu_limit': H.parse_cpu_max('399999 100000')}], profile)

    def test_required_memory_and_feature_evidence_cannot_be_missing_or_malformed(self):
        for field, invalid in (('memory_total_bytes', None), ('memory_total_bytes', True),
                               ('x86_64_v3_features', {}), ('cpu_model', None),
                               ('exposed_physical_cores', None), ('exposed_physical_cores', True)):
            value = self.hardware()
            value[field] = invalid
            with self.subTest(field=field), self.assertRaises(ValueError):
                H.qualify_hardware_profile(value, 'minimum-validator')

    def test_preflight_records_actual_allocation_and_retains_failed_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            limit = base / 'memory.max'
            limit.write_text('max')
            flags = 'flags : ' + ' '.join(aliases[0] for aliases in H.X86_64_V3_FLAGS.values())
            read_text = Path.read_text

            def read(path, *args, **kwargs):
                if str(path) == '/proc/cpuinfo':
                    return flags + '\n\n' + flags
                if str(path) == '/proc/meminfo':
                    return 'MemTotal:       33554432 kB\n'
                return read_text(path, *args, **kwargs)

            evidence = dict(lscpu_json={'lscpu': []}, lscpu_text='Synthetic CPU metadata')
            ancestry = [dict(path=str(base), **{'cpu.max': 'max 100000'},
                             cpu_limit=H.parse_cpu_max('max 100000'))]
            output = base / 'out'
            output.mkdir()
            failed_output = base / 'failed'
            failed_output.mkdir()
            with mock.patch.object(H.H, 'qualify', side_effect=lambda: (self.hardware(), evidence)), \
                 mock.patch.object(H.M, 'current_cpu_ancestry', return_value=ancestry), \
                 mock.patch.object(Path, 'read_text', read):
                record = H.qualify_and_record(output, 'minimum-miner')
                self.assertTrue(record['profile_qualified'])
                self.assertEqual(record['hardware']['memory_total_bytes'], 32 * 1024**3)
                self.assertEqual(record['hardware']['cpu_model'], 'Example x86 CPU')
                self.assertEqual(record['hardware']['exposed_physical_cores'], 8)
                self.assertNotIn(str(base), json.dumps(record))
                limit.write_text(str(16 * 1024**3))
                self.assertIsNone(H.qualify_and_record(failed_output, 'minimum-miner'))
            failed = json.loads((failed_output / 'hardware-qualification.json').read_text())
            self.assertFalse(failed['profile_qualified'])
            self.assertEqual(failed['visible_memory_limits'][0]['memory_max_bytes'], 16 * 1024**3)


class SettlementAdmissionTests(unittest.TestCase):
    def test_byte_and_memory_boundaries_keep_the_ninety_percent_ceiling(self):
        q = load('qualify-native-settlement.py')
        valid = dict(resource_control_pass=True, proof_report_valid=True,
            memory_peak_bytes=5 * 1024**3, measurement={'proof_bytes': 589824})
        self.assertTrue(q.admission([copy.deepcopy(valid) for _ in range(3)]))
        for field, value in (('proof_bytes', 589825), ('proof_bytes', 655361),
                             ('memory_peak_bytes', 5 * 1024**3 + 1)):
            rows = [copy.deepcopy(valid) for _ in range(3)]
            if field == 'proof_bytes':
                rows[2]['measurement'][field] = value
            else:
                rows[2][field] = value
            with self.subTest(field=field, value=value):
                self.assertFalse(q.admission(rows))
        self.assertFalse(q.admission([valid, valid]))

    def test_failed_or_incomplete_scopes_never_pass(self):
        q = load('qualify-native-settlement.py')
        valid = dict(resource_control_pass=True, proof_report_valid=True,
            memory_peak_bytes=1000, measurement={'proof_bytes': 500000})
        for field in ('resource_control_pass', 'proof_report_valid'):
            rows = [copy.deepcopy(valid) for _ in range(3)]
            rows[1][field] = False
            self.assertFalse(q.admission(rows))

    def test_frozen_settlement_source_parameters_and_security_are_bound(self):
        q = load('qualify-native-settlement.py')
        manifest = json.loads((ROOT / q.F.MANIFEST).read_text())
        frozen = q.F.transaction_profile()
        relation = next(row for row in manifest['relations'] if row['kind'] == 'settlement')
        selected = dict(parameters=q.PARAMETERS.copy(), security=q.M.security_summary(relation['security']))
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            screen = base / 'screen.json'
            screen.write_text(json.dumps({name: frozen[name] for name in
                                          ('air_source_sha256', 'dependencies_sha256')}))
            args = SimpleNamespace(manifest=ROOT / q.F.MANIFEST, reproduced=base, screen=screen)
            with mock.patch.object(q.F, 'validate'), \
                 mock.patch.object(q.M, 'profiles', return_value={(8, 20): selected}):
                self.assertEqual(q.bound_profile(args)['parameters'], q.PARAMETERS)
                selected['parameters']['num_queries'] += 1
                with self.assertRaises(ValueError):
                    q.bound_profile(args)
                selected['parameters']['num_queries'] -= 1
                selected['security'] = {'changed': True}
                with self.assertRaises(ValueError):
                    q.bound_profile(args)

    def test_three_fresh_scopes_keep_frozen_parameters_metadata_and_private_boundary(self):
        q = load('qualify-native-settlement.py')
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for name in ('launcher', 'worker', 'screen', 'manifest'):
                (base / name).write_text('{}')
            args = SimpleNamespace(output=base / 'out', executable=base / 'launcher',
                worker=base / 'worker', screen=base / 'screen', manifest=base / 'manifest',
                reproduced=base, private_parent=base, hardware_profile='minimum-miner', timeout=5)
            profile = dict(parameters=q.PARAMETERS, security={'screen': {'passes_selected_model': True}},
                air_source_sha256='a' * 64, dependencies_sha256='b' * 64,
                public_verifier_key_sha256='c' * 64)
            hardware = dict(profile_qualified=True, hardware=dict(cpu_model='Synthetic CPU',
                exposed_physical_cores=8, logical_cpus=8, memory_total_bytes=32 * 1024**3))
            configs = []

            def scope(command, **_):
                config = json.loads(Path(command[command.index('--worker-config') + 1]).read_text())
                configs.append(config)
                counters = {name: 0 for name in q.M.CG.EVENTS}
                measurement = dict(setup_ns=10, generation_ns=5_500_000_000,
                                   verification_ns=20_000_000, proof_bytes=589824)
                row = dict(kind='settlement', workers=4, trial=config['trial'], parameters=q.PARAMETERS,
                    resource_control_pass=True, proof_report_valid=True, exit_code=0, timed_out=False,
                    process_wall_ns=6_000_000_000, process_cpu_ns=20_000_000_000,
                    memory_peak_bytes=3_200_000_000, memory_max_bytes=q.M.MEMORY_MAX,
                    memory_swap_max_bytes=0, memory_events_before=counters.copy(),
                    memory_events_after=counters.copy(), memory_events_delta=counters.copy(),
                    remaining_descendants_at_exit=0, cpu_max='max 100000', verification_workers=4,
                    hardware_profile='diagnostic', measurement=measurement,
                    measurement_scope_sha256=hashlib.sha256(config['unit'].encode()).hexdigest(),
                    visible_cpu_limits=[dict(ancestor_level=0, cpu_max='max 100000', quota_cores=None)],
                    private_field='PRIVATE-MATERIAL')
                Path(config['private_output']).write_text(json.dumps(dict(
                    security=profile['security'], measurement=measurement)))
                Path(config['result']).write_text(json.dumps(row))
                return SimpleNamespace(returncode=0)

            with mock.patch.object(q.Q.H, 'qualify_and_record', return_value=hardware), \
                 mock.patch.object(q, 'bound_profile', return_value=profile), \
                 mock.patch.object(q.subprocess, 'check_output', return_value='d' * 40), \
                 mock.patch.object(q.subprocess, 'run', side_effect=scope), \
                 mock.patch.object(q.M, 'validate_report', side_effect=lambda raw, config: raw['measurement']), \
                 mock.patch.object(q.M, 'security_summary', side_effect=lambda raw: raw):
                self.assertEqual(q.collect(args), 0)
            result = json.loads((args.output / 'summary.json').read_text())
            self.assertEqual(len({row['unit'] for row in configs}), 3)
            self.assertTrue(all(row['parameters'] == q.PARAMETERS for row in configs))
            self.assertTrue(result['engineering_target_pass'])
            self.assertEqual(result['measurement_ceiling_bytes'], 589824)
            self.assertEqual(result['hardware'], hardware)
            self.assertIsNone(result['generation_limit_ns'])
            self.assertNotIn('PRIVATE-MATERIAL', json.dumps(result))


class QualificationWorkflowTests(unittest.TestCase):
    def test_both_roles_are_checked_and_cpu_os_guard_precedes_optimized_builds(self):
        workflow = (ROOT / '.github/workflows/native-fixed-qualification.yml').read_text()
        self.assertIn('role: [validator, miner]', workflow)
        self.assertIn('HARDWARE_PROFILE: minimum-${{ matrix.role }}', workflow)
        self.assertNotIn('epyc7763', workflow)
        self.assertLess(workflow.index('python3 scripts/minimum-hardware.py'),
                        workflow.index('cargo clippy'))
        self.assertLess(workflow.index('/tmp/native-fixed-cpu-check --check-cpu'),
                        workflow.index('cargo clippy'))
        self.assertIn('python3 scripts/qualify-native-settlement.py', workflow)


if __name__ == '__main__':
    unittest.main()
