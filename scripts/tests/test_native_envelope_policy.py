"""Reject admission changes or measured-profile rebinding without proof work."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('native_envelope_policy',
    ROOT / 'scripts/check-native-envelope-policy.py')
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


class NativeEnvelopePolicyTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        for name in (P.MANIFEST, P.WIRE, P.CODEC, P.PROOFS, P.ISSUANCE,
                     'crates/bench-multi-asset/artifacts/v1-transaction-profile.json'):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / name).read_bytes())
        return root

    def test_runtime_limits_are_independent_of_immutable_measured_profiles(self):
        value = P.validate()
        self.assertEqual(value['policy_version'], 1)
        self.assertEqual(value['proof_body_limits_bytes']['settlement'], 655_360)
        self.assertEqual(value['required_settlement_three_trial_maximum_bytes'], 589_824)
        self.assertFalse(value['resource_acceptance'])
        self.assertFalse(value['network_activation'])

    def test_profile_rebinding_and_runtime_manifest_substitution_fail(self):
        for name in (P.MANIFEST,
                     'crates/bench-multi-asset/artifacts/v1-transaction-profile.json', P.PROOFS):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = self.fixture(directory)
                path = root / name
                if name == P.PROOFS:
                    path.write_text(path.read_text().replace(P.MANIFEST_SHA256, '0' * 64))
                else:
                    path.write_bytes(path.read_bytes() + b'\n')
                with self.assertRaises(ValueError):
                    P.validate(root)

    def test_wire_decoder_and_issuance_limits_cannot_diverge(self):
        for name, before, after in ((P.WIRE, 'MAX_SETTLEMENT_PROOF: usize = 655_360',
                                    'MAX_SETTLEMENT_PROOF: usize = 524_288'),
                                   (P.CODEC, 'MAX_SETTLEMENT_PROOF_BODY_LEN: usize = 655_360',
                                    'MAX_SETTLEMENT_PROOF_BODY_LEN: usize = 655_361'),
                                   (P.WIRE, 'MAX_SLOTS: usize = 576', 'MAX_SLOTS: usize = 128'),
                                   (P.ISSUANCE, 'MAX_PROOF_BYTES: usize = 524_288',
                                    'MAX_PROOF_BYTES: usize = 655_360')):
            with self.subTest(source=name, change=before), tempfile.TemporaryDirectory() as directory:
                root = self.fixture(directory)
                path = root / name
                self.assertIn(before, path.read_text())
                path.write_text(path.read_text().replace(before, after))
                with self.assertRaises(ValueError):
                    P.validate(root)

    def test_production_fri_selection_and_public_key_header_remain_fixed(self):
        for before, after in (('Self::Transaction => (7, 41)', 'Self::Transaction => (8, 36)'),
                              ('Self::Settlement => (8, 36)', 'Self::Settlement => (7, 41)'),
                              ('batch_pow_bits: 20,', 'batch_pow_bits: 0,'),
                              ('TransactionProver::new(Relation::Transaction.params())',
                               'TransactionProver::new(FriParams::fast())'),
                              ('SettlementProver::new(SETTLEMENT_CAPACITY, Relation::Settlement.params())',
                               'SettlementProver::new(128, Relation::Settlement.params())'),
                              ('53574d50010001000000000700000029',
                               '53574d50010001000000000800000029')):
            with self.subTest(change=before), tempfile.TemporaryDirectory() as directory:
                root = self.fixture(directory)
                path = root / P.PROOFS
                self.assertIn(before, path.read_text())
                path.write_text(path.read_text().replace(before, after))
                with self.assertRaises(ValueError):
                    P.validate(root)

    def test_constant_reader_rejects_dynamic_duplicate_or_executable_values(self):
        for source in ('const LIMIT: usize = selected_limit();',
                       'const LIMIT: usize = 1; const LIMIT: usize = 2;',
                       'const LIMIT: usize = __import__("os").system("false");'):
            with self.subTest(source=source), self.assertRaises(ValueError):
                P.constant(source, 'LIMIT')


if __name__ == '__main__':
    unittest.main()
