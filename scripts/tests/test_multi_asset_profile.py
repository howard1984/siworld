import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('multi_asset_freeze', ROOT / 'scripts/bench/multi-asset-profile.py')
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
SPEC = importlib.util.spec_from_file_location('multi_asset_fixtures', ROOT / 'scripts/tests/test_multi_asset_measurement.py')
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


def summary():
    profiles = []
    for b, g in F.GRID:
        parameters = FIXTURE.params(b=b, g=g)
        rows = []
        for index in (1, 2, 3):
            events = {'low': 0, 'high': 0, 'max': 0, 'oom': 0, 'oom_kill': 0, 'oom_group_kill': 0}
            rows.append({'kind': 'transaction', 'workers': 4, 'verification_workers': 4,
                'parameters': parameters, 'trial': index, 'hardware_profile': 'epyc7763-baseline',
                'resource_control_pass': True, 'proof_report_valid': True, 'scope_exit_code': 0,
                'exit_code': 0, 'timed_out': False, 'remaining_descendants_at_exit': 0,
                'memory_max_bytes': F.MEMORY_MAX, 'memory_swap_max_bytes': 0,
                'memory_peak_bytes': 1_000_000_000 + index,
                'memory_events_delta': events.copy(), 'memory_events_before': events.copy(),
                'memory_events_after': events.copy(),
                'visible_cpu_limits': [{'ancestor_level': 0, 'cpu_max': 'max 100000', 'quota_cores': None}],
                'cryptographic_approval': False, 'network_activation': False, 'acceptance': False,
                'measurement': {'public_transaction_bytes': 2027, 'permanent_position_bytes': 2115,
                    'generation_ns': 1_500_000_000 + index, 'proof_bytes': 700000 + b * 100 + g + index}})
        profiles.append({'coordinate': {'log_blowup': b, 'grinding': g}, 'parameters': parameters,
            'security': F.MEASUREMENT.security_summary(FIXTURE.security()), 'trials': rows})
    selected = F.selection([F.clean_profile(row) for row in profiles])
    return {'schema': 2, 'suite': F.SUITE, 'scan_mode': 'wallet-fast', 'hardware_profile': 'epyc7763-baseline',
        'rayon_workers': 4, 'hiding_workers': 2, 'trial_count_per_profile': 3,
        'measurement_grid_complete': True, 'scope_startup_complete': True,
        'candidate_selected': True, 'candidate_rejected': False, 'three_trial_target_met': True,
        'legacy_524288_byte_cap_applied': False, 'cryptographic_approval': False,
        'network_activation': False, 'acceptance': False, 'memory_max_bytes': F.MEMORY_MAX,
        'memory_swap_max_bytes': 0, 'hardware': {'required_hardware_profile': 'epyc7763-baseline',
            'profile_qualified': True, 'hardware': {'cpu_model': 'AMD EPYC 7763 64-Core Processor',
                'os': 'Ubuntu 24.04', 'architecture': 'x86_64', 'avx2': True, 'logical_cpus': 4,
                'online_logical_cpus': 4, 'exposed_physical_cores': 2, 'affinity_cpus': 4,
                'virtualization_detection': {'exit_code': 0, 'result': 'kvm'}}},
        'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(), 'air_source_sha256': F.relation_hash(ROOT),
        'dependencies_sha256': hashlib.sha256((ROOT / 'crates/bench-multi-asset/Cargo.lock').read_bytes()).hexdigest(),
        'binary_sha256': 'b' * 64, 'launcher_sha256': 'c' * 64, 'profile_results': profiles,
        'candidate_parameters': selected['parameters'], 'candidate_security': selected['security'],
        'candidate_summary': {'proof_bytes_max': selected['proof_bytes_max']}}


def public_key(value):
    parameters = value['candidate_parameters']
    security = {**value['candidate_security'], 'fri': parameters}
    words = [parameters[name] for name in ('log_blowup', 'num_queries', 'query_pow_bits',
             'commit_pow_bits', 'batch_pow_bits', 'max_log_arity')] + [1, 1, 32]
    raw = b'SWMV\x01\x00\x01' + b''.join(word.to_bytes(4, 'little') for word in words) + bytes(32)
    return {'schema': 1, 'suite': F.SUITE, 'kind': 'transaction', 'parameters': parameters,
        'security': security, 'public_verifier_key': {'encoding': 'SWMV-v1', 'hex': raw.hex(),
            'sha256': hashlib.sha256(raw).hexdigest(), 'width': 1, 'degree_bits': 1}}


class MultiAssetFreezeTests(unittest.TestCase):
    def test_create_sanitizes_private_inputs_and_binds_sources(self):
        value = summary()
        value['private_log'] = '/private/owner'
        value['hardware']['lscpu_text'] = '/private/owner'
        value['profile_results'][0]['private_log'] = '/private/owner'
        result = F.create(value, public_key(value))
        F.validate(result)
        self.assertNotIn('/private/owner', json.dumps(result))
        self.assertNotIn('lscpu_text', json.dumps(result))
        self.assertEqual(result['parameters']['log_blowup'], 5)
        self.assertEqual(result['max_leaf_proof_bytes'], 786432)
        self.assertEqual(result['max_settlement_proof_bytes'], 524288)
        self.assertEqual(result['max_issuance_proof_bytes'], 524288)
        self.assertEqual(len(result['profiles']), 8)
        self.assertEqual(len(result['profiles'][0]['generation_ns']), 3)
        self.assertFalse(result['network_activation'])

    def test_cap_uses_ceiling_and_64kib_rounding(self):
        self.assertEqual(F.proof_cap(655360), 720896)
        self.assertEqual(F.proof_cap(655361), 786432)
        self.assertEqual(F.proof_cap(1), 65536)
        with self.assertRaises(ValueError):
            F.proof_cap(True)

    def test_incomplete_wrong_hardware_events_and_unscreened_inputs_are_rejected(self):
        changes = (
            lambda s: s.update(measurement_grid_complete=False),
            lambda s: s.update(cryptographic_approval=True),
            lambda s: s['hardware']['hardware'].update(cpu_model='AMD EPYC 9V45'),
            lambda s: s['hardware']['hardware'].update(logical_cpus=2),
            lambda s: s.update(air_source_sha256='d' * 64),
            lambda s: s.update(dependencies_sha256='d' * 64),
            lambda s: s['profile_results'].pop(),
            lambda s: s['profile_results'][0]['trials'].pop(),
            lambda s: s['profile_results'][0]['trials'][0]['memory_events_delta'].update(oom=1),
            lambda s: s['profile_results'][0]['trials'][0]['memory_events_after'].update(high=1),
            lambda s: s['profile_results'][0]['trials'][0].update(visible_cpu_limits=[]),
            lambda s: s['profile_results'][0]['trials'][0]['visible_cpu_limits'][0].update(cpu_max='300000 100000', quota_cores=3),
            lambda s: s['profile_results'][0]['security']['screen'].update(quantum_johnson_challenge_union_bits=79.9),
        )
        for index, change in enumerate(changes):
            value = summary(); key = public_key(value); change(value)
            with self.subTest(index=index), self.assertRaises(ValueError):
                F.create(value, key)

    def test_candidate_selection_cannot_use_median_only_or_changed_candidate(self):
        value = summary()
        value['profile_results'][0]['trials'][2]['measurement']['generation_ns'] = 2_000_000_001
        with self.assertRaises(ValueError):
            F.create(value, public_key(value))
        value = summary(); value['candidate_parameters'] = FIXTURE.params(b=8)
        with self.assertRaises(ValueError):
            F.create(value, public_key(value))

    def test_runtime_source_changes_after_measurement_are_rejected(self):
        value = summary(); key = public_key(value)
        real_read = F.source_bytes
        def changed(root, name):
            original = real_read(root, name)
            return original + b'\n// changed after measurement\n' if name == 'crates/bench-d8/src/lib.rs' else original
        with mock.patch.object(F, 'source_bytes', side_effect=changed), self.assertRaises(ValueError):
            F.create(value, key)
        original = F.create(value, key)
        with mock.patch.object(F.subprocess, 'check_output', side_effect=AssertionError('check must not need Git')):
            F.validate(original)
        with mock.patch.object(F, 'source_bytes', side_effect=changed), self.assertRaises(ValueError):
            F.validate(original)
        real_paths = F.source_paths(ROOT)
        with mock.patch.object(F, 'source_paths', return_value=real_paths + ['crates/bench-multi-asset/src/new_runtime.rs']), self.assertRaises(ValueError):
            F.create(value, key)

    def test_public_verifier_header_parameters_shape_and_security_are_bound(self):
        value = summary()
        for name in ('hash', 'parameters', 'header', 'shape', 'security'):
            key = public_key(value)
            if name == 'hash':
                key['public_verifier_key']['sha256'] = '0' * 64
            elif name == 'parameters':
                key['parameters'] = FIXTURE.params(b=8)
            elif name == 'header':
                raw = bytes.fromhex(key['public_verifier_key']['hex'])
                raw = b'BAD!' + raw[4:]
                key['public_verifier_key'].update(hex=raw.hex(), sha256=hashlib.sha256(raw).hexdigest())
            elif name == 'shape':
                key['public_verifier_key']['degree_bits'] = 2
            else:
                key['security'] = copy.deepcopy(key['security'])
                key['security']['screen']['quantum_johnson_challenge_union_bits'] = 79
            with self.subTest(name=name), self.assertRaises(ValueError):
                F.create(value, key)

    def test_frozen_source_measurement_cap_and_key_mutations_are_rejected(self):
        source = summary(); original = F.create(source, public_key(source))
        changes = (
            lambda v: v['source_sha256'].pop(next(iter(v['source_sha256']))),
            lambda v: v.update(max_leaf_proof_bytes=524288),
            lambda v: v['profiles'][0].update(generation_median_ns=1),
            lambda v: v['profiles'][0]['memory_events_delta'].update(oom=1),
            lambda v: v['public_verifier_key'].update(width=2),
            lambda v: v.update(network_activation=True),
            lambda v: v.update(private_log='/private/owner'),
            lambda v: v['profiles'][0].update(private_log='/private/owner'),
        )
        for index, change in enumerate(changes):
            value = copy.deepcopy(original); change(value)
            with self.subTest(index=index), self.assertRaises(ValueError):
                F.validate(value)

    def test_cli_refuses_overwrite_and_check_accepts_created_profile(self):
        source = summary()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            summary_path = base / 'summary.json'; summary_path.write_text(json.dumps(source))
            key_path = base / 'key.json'; key_path.write_text(json.dumps(public_key(source)))
            output = base / 'profile.json'
            command = ['python3', str(ROOT / 'scripts/bench/multi-asset-profile.py'), '--create', str(summary_path),
                       '--verifier-key', str(key_path), '--output', str(output)]
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            original = output.read_bytes()
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual(output.read_bytes(), original)
            checked = subprocess.run(['python3', str(ROOT / 'scripts/bench/multi-asset-profile.py'), '--check', str(output), '--verifier-key', str(key_path)], capture_output=True)
            self.assertEqual(checked.returncode, 0, checked.stderr.decode())
            key = json.loads(key_path.read_text()); key['public_verifier_key']['width'] = 2
            key_path.write_text(json.dumps(key))
            changed = subprocess.run(['python3', str(ROOT / 'scripts/bench/multi-asset-profile.py'), '--check',
                str(output), '--verifier-key', str(key_path)], capture_output=True)
            self.assertNotEqual(changed.returncode, 0)


if __name__ == '__main__':
    unittest.main()
