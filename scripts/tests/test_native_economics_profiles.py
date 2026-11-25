"""Synthetic rejection fixtures for the revised source-bound native manifest."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('revised_native_profiles', ROOT / 'scripts/ci/check-native-proof-profiles.py')
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
SPEC = importlib.util.spec_from_file_location('native_measurement_fixtures', ROOT / 'scripts/tests/test_multi_asset_measurement.py')
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)
SHAPES = ((256, 1392, 247), (1024, 581, 609), (128, 438, 10))
PUBLIC_VALUES = (101, 7050, 72)


def key(kind, parameters, payload=b'\x07' * 32, shape=None):
    index = P.KINDS.index(kind)
    rows, _, width = SHAPES[index] if shape is None else shape
    words = [parameters[name] for name in ('log_blowup', 'num_queries', 'query_pow_bits',
        'commit_pow_bits', 'batch_pow_bits', 'max_log_arity')] + [width, rows.bit_length(), len(payload)]
    raw = b'SWMP\x01\x00' + bytes([index + 1]) + P.CAPACITIES[index].to_bytes(4, 'little')
    raw += b''.join(word.to_bytes(4, 'little') for word in words) + payload
    return {'encoding': 'SWMP-v1', 'hex': raw.hex(), 'sha256': hashlib.sha256(raw).hexdigest(),
        'width': width, 'degree_bits': rows.bit_length()}


def summary():
    return {'complete': True, 'trial_count': 3, 'generation_median_ns': 1_000_000_000,
        'generation_min_ns': 900_000_000, 'generation_max_ns': 1_100_000_000,
        'verification_median_ns': 100_000, 'process_wall_median_ns': 2_000_000_000,
        'memory_peak_median_bytes': 100_000_000, 'memory_peak_max_bytes': 110_000_000,
        'proof_bytes_min': 300_000, 'proof_bytes_max': 310_000, 'acceptance': False}


def synthetic_profile():
    profile = {'schema': 2, 'status': 'engineering-frozen', 'relation_revision': 'native-v1-economics-1',
        'acceptance': False, 'parameters': FIXTURE.params(b=6, q=53, g=24),
        'verification_measurement': 'single-worker verifier timing inside measured setup/prove/verify',
        'verification_only_process': False, 'repeated_measurements': {}}
    reports = {}
    for index, kind in enumerate(P.KINDS):
        parameters = profile['parameters'] if kind == 'transaction' else FIXTURE.params(b=8, q=36)
        report = FIXTURE.security()
        rows, main, pre = SHAPES[index]
        report['shape'].update(base_trace_rows=rows, main_width=main, preprocessed_width=pre,
            public_values=PUBLIC_VALUES[index])
        report['fri'] = parameters
        reports[kind] = report
        profile['repeated_measurements'][kind] = {'measured': True, 'parameters': parameters,
            'security': FIXTURE.M.security_summary(report),
            'workers': {'1': {'summary': summary()}, '4': {'summary': summary()}}}
    profile['selected_security'] = profile['repeated_measurements']['transaction']['security']
    native = key('transaction', profile['parameters'])
    raw = bytes.fromhex(native['hex'])
    raw = b'SWMV\x01\x00\x01' + raw[11:]
    profile['public_verifier_key'] = {**native, 'encoding': 'SWMV-v1', 'hex': raw.hex(),
        'sha256': hashlib.sha256(raw).hexdigest()}
    return profile, reports


class EconomicNativeProfileTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.profile, self.reports = synthetic_profile()
        path = self.root / P.TRANSACTION
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(self.profile))
        for name in P.TOOLS:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('synthetic tool source: ' + name)
        self.validated = mock.Mock(side_effect=lambda value, root: value)
        self.freeze = SimpleNamespace(SUITE=FIXTURE.M.SUITE, MEASUREMENT=FIXTURE.M,
            validate=self.validated)
        self.patch = mock.patch.object(P, 'freeze_module', return_value=self.freeze)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.reproduced = self.root / 'reproduced'
        self.reproduced.mkdir()
        for index, kind in enumerate(P.KINDS):
            value = {'kind': kind, 'capacity': P.CAPACITIES[index],
                'parameters': self.profile['repeated_measurements'][kind]['parameters'],
                'security': self.reports[kind], 'cryptographic_approval': False, 'network_activation': False,
                'status': 'candidate-pending-review', 'acceptance': False}
            value['public_verifier_key'] = key(kind, value['parameters'])
            (self.reproduced / (kind + '.json')).write_text(json.dumps(value))

    def create(self):
        return P.create(self.reproduced, self.root)

    def test_revised_manifest_binds_selected_parameters_and_fresh_performance(self):
        value = self.create()
        self.assertEqual(P.validate(value, self.root, self.reproduced), value)
        self.assertEqual(value['schema'], 2)
        self.assertEqual(value['relation_revision'], 'native-v1-economics-1')
        self.assertEqual(value['relations'][0]['parameters']['log_blowup'], 6)
        self.assertEqual(value['relations'][0]['parameters']['query_pow_bits'], 24)
        for index, relation in enumerate(value['relations']):
            shape = relation['security']['shape']
            self.assertEqual((shape['base_trace_rows'], shape['main_width'],
                shape['preprocessed_width']), SHAPES[index])
            self.assertEqual(shape['public_values'], PUBLIC_VALUES[index])
        self.assertEqual(value['relations'][0]['performance']['1']['trial_count'], 3)
        for relation in value['relations']:
            self.assertNotIn('status', relation)
            self.assertNotIn('acceptance', relation)
            self.assertNotIn('acceptance', relation['performance']['1'])
        self.assertFalse(value['verification_only_process'])
        self.assertGreater(self.validated.call_count, 0)
        self.assertNotIn('crates/native-node/src/proofs.rs', value['tool_source_sha256'])

    def test_revised_source_profile_revision_shape_capacity_and_key_mutations_fail(self):
        original = self.create()
        changes = [
            lambda p: p.update(relation_revision='native-v1-economics-2'),
            lambda p: p.update(transaction_profile_sha256='0' * 64),
            lambda p: p.update(verification_only_process=True),
            lambda p: p['tool_source_sha256'].update({P.PROVENANCE.canonical_path(P.TOOLS[0]): '0' * 64}),
            lambda p: p['relations'][1].update(capacity=575),
            lambda p: p['relations'][0]['parameters'].update(log_blowup=7),
            lambda p: p['relations'][0]['security']['shape'].update(main_width=1420),
            lambda p: p['relations'][0]['security']['shape'].update(main_width=1488),
            lambda p: p['relations'][0]['security']['shape'].update(main_width=1440),
            lambda p: p['relations'][0]['security']['shape'].update(main_width=1424),
            lambda p: p['relations'][0]['security']['shape'].update(preprocessed_width=243),
            lambda p: p['relations'][1]['security']['shape'].update(main_width=580),
            lambda p: p['relations'][0]['security']['shape'].update(public_values=100),
            lambda p: p['relations'][1]['security']['shape'].update(public_values=7049),
            lambda p: p['relations'][2]['security']['shape'].update(public_values=71),
            lambda p: p['relations'][2]['public_verifier_key'].update(sha256='0' * 64),
            lambda p: p['relations'][0]['public_verifier_key'].update(width=True),
            lambda p: p['relations'][2]['performance']['1'].update(trial_count=2),
            lambda p: p['relations'][0]['performance']['4'].update(generation_max_ns=1),
            lambda p: p['relations'][0].update(acceptance=False),
        ]
        for index, change in enumerate(changes):
            value = copy.deepcopy(original)
            change(value)
            with self.subTest(index=index), self.assertRaises((ValueError, KeyError)):
                P.validate(value, self.root)
        (self.root / P.TOOLS[1]).write_text('mutated source')
        with self.assertRaises(ValueError):
            P.validate(original, self.root)

    def test_changed_profile_content_and_missing_reproduced_key_fail(self):
        original = self.create()
        self.profile['verification_measurement'] += ' changed'
        (self.root / P.TRANSACTION).write_text(json.dumps(self.profile))
        with self.assertRaises(ValueError):
            P.validate(original, self.root)
        (self.root / P.TRANSACTION).write_text(json.dumps(synthetic_profile()[0]))
        (self.reproduced / 'issuance.json').unlink()
        with self.assertRaises(FileNotFoundError):
            self.create()

    def test_historical_schema_retains_original_parameters_and_shapes(self):
        profile = copy.deepcopy(self.profile)
        profile['schema'] = 1
        profile['parameters'] = P.parameters('transaction')
        for index, kind in enumerate(P.KINDS):
            parameters = P.parameters(kind)
            report = copy.deepcopy(self.reports[kind])
            rows, main, pre = P.SHAPES[index]
            report['shape'].update(base_trace_rows=rows, main_width=main, preprocessed_width=pre)
            report['fri'] = parameters
            value = {'kind': kind, 'capacity': P.CAPACITIES[index], 'parameters': parameters,
                'security': report, 'cryptographic_approval': False, 'network_activation': False,
                'public_verifier_key': key(kind, parameters, shape=P.SHAPES[index])}
            (self.reproduced / (kind + '.json')).write_text(json.dumps(value))
            if kind == 'transaction':
                profile['selected_security'] = FIXTURE.M.security_summary(report)
        (self.root / P.TRANSACTION).write_text(json.dumps(profile))
        value = self.create()
        self.assertEqual(value['schema'], 1)
        self.assertEqual(P.validate(value, self.root, self.reproduced), value)
        self.assertEqual(value['relations'][1]['public_verifier_key']['width'], 587)
        self.assertNotIn('performance', value['relations'][0])
        changed = copy.deepcopy(value)
        changed['relations'][1]['security']['shape']['main_width'] = 581
        with self.assertRaises(ValueError):
            P.validate(changed, self.root)

    def test_candidate_flags_and_reproduced_content_must_match(self):
        original = self.create()
        path = self.reproduced / 'settlement.json'
        for changes in ({'acceptance': True}, {'status': 'engineering-frozen'}, {'private_log': 'excluded'}):
            value = json.loads(path.read_text())
            value.update(changes)
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                self.create()
            value = {'kind': 'settlement', 'capacity': 576,
                'parameters': self.profile['repeated_measurements']['settlement']['parameters'],
                'security': self.reports['settlement'], 'cryptographic_approval': False,
                'network_activation': False, 'status': 'candidate-pending-review', 'acceptance': False,
                'public_verifier_key': key('settlement', self.profile['repeated_measurements']['settlement']['parameters'])}
            path.write_text(json.dumps(value))
        value = json.loads(path.read_text())
        value['public_verifier_key'] = key('settlement', value['parameters'], b'\x08' * 32)
        path.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            P.validate(original, self.root, self.reproduced)


if __name__ == '__main__':
    unittest.main()
