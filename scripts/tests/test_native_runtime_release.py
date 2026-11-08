"""Native runtime releases bind the guarded worker to inspected build evidence."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


NATIVE = module('native_runtime_release', 'build-native-runtime.py')
RELEASE = module('native_runtime_release_helpers', 'build-prover-release.py')
ELF = b'\x7fELF\x02\x01' + bytes(12) + b'\x3e\x00' + b'synthetic-worker'
GUARD = b'synthetic-baseline-cpu-guard'


def worker_at(directory, name='siworld-native-node', data=ELF, mode=0o755):
    worker = Path(directory) / name
    worker.write_bytes(data)
    worker.chmod(mode)
    return worker


def receipt_for(worker):
    return {
        'binary_sha256': RELEASE.digest(worker),
        'effective_rustflags': ' '.join(RELEASE.V3_FLAGS),
        'cargo_working_directory': 'repository-root',
        'repository_config_sha256': RELEASE.digest(ROOT / '.cargo/config.toml'),
    }


def inspection_for(worker):
    return {
        'required_isa': 'x86-64-v3',
        'avx2_packed_multiply_instructions': 1,
        'binary_sha256': RELEASE.digest(worker),
        'instruction_examples': ['100: vpmuludq ymm0,ymm1,ymm2'],
    }


def compile_guard(command, **kwargs):
    if command[0] != 'rustc' or kwargs != {'cwd': ROOT, 'check': True}:
        raise AssertionError('Unexpected release compiler invocation')
    Path(command[command.index('-o') + 1]).write_bytes(GUARD)


class NativeRuntimeReleaseTests(unittest.TestCase):
    def test_restart_qualification_worker_is_guarded_and_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            worker = worker_at(directory)
            qualifier = worker_at(directory, name='siworld-restart-qualify', data=ELF + b'qualify')
            receipt = {**receipt_for(worker), 'restart_qualify_sha256': RELEASE.digest(qualifier)}
            output = Path(directory) / 'release'
            with patch.object(RELEASE, 'inspect_proof', return_value=inspection_for(worker)), \
                 patch.object(NATIVE.subprocess, 'run', side_effect=compile_guard):
                NATIVE.package(worker, output, receipt, RELEASE)
            self.assertEqual((output / 'bin/siworld-restart-qualify').read_bytes(), GUARD)
            self.assertEqual((output / 'libexec/siworld-restart-qualify').read_bytes(), qualifier.read_bytes())
            saved = json.loads((output / 'build-receipt.json').read_text())
            self.assertEqual(saved['worker_build_receipt']['restart_qualify_sha256'],
                             RELEASE.digest(output / 'libexec/siworld-restart-qualify'))

    def test_changed_restart_qualification_worker_prevents_release(self):
        with tempfile.TemporaryDirectory() as directory:
            worker = worker_at(directory)
            worker_at(directory, name='siworld-restart-qualify')
            receipt = {**receipt_for(worker), 'restart_qualify_sha256': '0' * 64}
            output = Path(directory) / 'release'
            with patch.object(RELEASE, 'inspect_proof', return_value=inspection_for(worker)), \
                 patch.object(NATIVE.subprocess, 'run', side_effect=compile_guard), \
                 self.assertRaisesRegex(ValueError, 'qualification worker digest mismatch'):
                NATIVE.package(worker, output, receipt, RELEASE)
            self.assertFalse(output.exists())

    def test_checkpoint_key_worker_is_guarded_and_bound_to_its_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            worker = worker_at(directory)
            key_worker = worker_at(directory, name='siworld-checkpoint-key', data=ELF + b'key')
            receipt = {**receipt_for(worker), 'checkpoint_key_sha256': RELEASE.digest(key_worker)}
            output = Path(directory) / 'release'
            with patch.object(RELEASE, 'inspect_proof', return_value=inspection_for(worker)), \
                 patch.object(NATIVE.subprocess, 'run', side_effect=compile_guard):
                NATIVE.package(worker, output, receipt, RELEASE)
            self.assertEqual((output / 'bin/siworld-checkpoint-key').read_bytes(), GUARD)
            self.assertEqual((output / 'libexec/siworld-checkpoint-key').read_bytes(), key_worker.read_bytes())
            saved = json.loads((output / 'build-receipt.json').read_text())
            self.assertEqual(saved['worker_build_receipt']['checkpoint_key_sha256'],
                             RELEASE.digest(output / 'libexec/siworld-checkpoint-key'))

    def test_unbound_checkpoint_key_worker_never_creates_a_release(self):
        with tempfile.TemporaryDirectory() as directory:
            worker = worker_at(directory)
            worker_at(directory, name='siworld-checkpoint-key')
            receipt = {**receipt_for(worker), 'checkpoint_key_sha256': '0' * 64}
            output = Path(directory) / 'release'
            with patch.object(RELEASE, 'inspect_proof', return_value=inspection_for(worker)), \
                 patch.object(NATIVE.subprocess, 'run', side_effect=compile_guard), \
                 self.assertRaisesRegex(ValueError, 'key worker digest mismatch'):
                NATIVE.package(worker, output, receipt, RELEASE)
            self.assertFalse(output.exists())

    def test_rejects_malformed_wrong_architecture_and_wrong_worker(self):
        cases = [
            ('wrong-name', 'composition-bench', ELF, 0o755),
            ('not-executable', 'siworld-native-node', ELF, 0o644),
            ('not-elf', 'siworld-native-node', b'not an executable', 0o755),
            ('truncated', 'siworld-native-node', ELF[:19], 0o755),
            ('elf32', 'siworld-native-node', ELF[:4] + b'\x01' + ELF[5:], 0o755),
            ('big-endian', 'siworld-native-node', ELF[:5] + b'\x02' + ELF[6:], 0o755),
            ('aarch64', 'siworld-native-node', ELF[:18] + b'\xb7\x00' + ELF[20:], 0o755),
        ]
        for case, name, data, mode in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                worker = worker_at(directory, name=name, data=data, mode=mode)
                output = Path(directory) / 'release'
                with patch.object(RELEASE, 'inspect_proof') as inspect, \
                     patch.object(NATIVE.subprocess, 'run') as compile_launcher, \
                     self.assertRaises(ValueError):
                    NATIVE.package(worker, output, receipt_for(worker), RELEASE)
                inspect.assert_not_called()
                compile_launcher.assert_not_called()
                self.assertFalse(output.exists())

    def test_missing_worker_is_rejected_before_inspection(self):
        with tempfile.TemporaryDirectory() as directory:
            worker = Path(directory) / 'siworld-native-node'
            output = Path(directory) / 'release'
            with patch.object(RELEASE, 'inspect_proof') as inspect, \
                 patch.object(NATIVE.subprocess, 'run') as compile_launcher, \
                 self.assertRaises(ValueError):
                NATIVE.package(worker, output, {}, RELEASE)
            inspect.assert_not_called()
            compile_launcher.assert_not_called()
            self.assertFalse(output.exists())

    def test_incomplete_or_wrong_build_receipt_is_rejected_before_inspection(self):
        with tempfile.TemporaryDirectory() as directory:
            worker = worker_at(directory)
            original = receipt_for(worker)
            output = Path(directory) / 'release'
            for key in original:
                for missing in [True, False]:
                    changed = original.copy()
                    if missing:
                        del changed[key]
                    else:
                        changed[key] = 'unrelated'
                    with self.subTest(key=key, missing=missing), \
                         patch.object(RELEASE, 'inspect_proof') as inspect, \
                         patch.object(NATIVE.subprocess, 'run') as compile_launcher, \
                         self.assertRaisesRegex(ValueError, 'receipt mismatch'):
                        NATIVE.package(worker, output, changed, RELEASE)
                    inspect.assert_not_called()
                    compile_launcher.assert_not_called()
                    self.assertFalse(output.exists())

    def test_scalar_inspection_failure_never_creates_a_release_or_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            worker = worker_at(directory)
            output = Path(directory) / 'release'
            with patch.object(RELEASE, 'inspect_proof', side_effect=ValueError('no AVX2 packed arithmetic')), \
                 patch.object(NATIVE.subprocess, 'run') as compile_launcher, \
                 self.assertRaisesRegex(ValueError, 'no AVX2'):
                NATIVE.package(worker, output, receipt_for(worker), RELEASE)
            compile_launcher.assert_not_called()
            self.assertFalse(output.exists())
            self.assertFalse(list(Path(directory).glob('.native-package-*')))

    def test_mocked_guard_and_worker_hashes_match_the_published_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            worker = worker_at(directory)
            receipt = receipt_for(worker)
            inspection = inspection_for(worker)
            output = Path(directory) / 'release'
            with patch.object(RELEASE, 'inspect_proof', return_value=inspection) as inspect, \
                 patch.object(NATIVE.subprocess, 'run', side_effect=compile_guard) as compile_launcher:
                NATIVE.package(worker, output, receipt, RELEASE)
            inspect.assert_called_once_with(worker)
            compile_launcher.assert_called_once()
            command = compile_launcher.call_args.args[0]
            self.assertEqual(command[1], str(ROOT / 'scripts/native-runtime-launcher.rs'))
            self.assertIn('target-cpu=x86-64', command)
            self.assertNotIn('target-cpu=native', command)
            installed = output / 'libexec/siworld-native-node'
            guard = output / 'bin/siworld-native-node'
            self.assertEqual(guard.read_bytes(), GUARD)
            self.assertEqual(installed.read_bytes(), ELF)
            saved = json.loads((output / 'build-receipt.json').read_text())
            self.assertEqual(saved['worker'], 'siworld-native-node')
            self.assertEqual(saved['worker_isa'], 'x86-64-v3')
            self.assertEqual(saved['bootstrap_isa'], 'x86-64')
            self.assertEqual(saved['bootstrap_sha256'], RELEASE.digest(guard))
            self.assertEqual(saved['worker_build_receipt'], receipt)
            self.assertEqual(saved['isa_inspection'], inspection)
            self.assertEqual(saved['worker_build_receipt']['binary_sha256'], RELEASE.digest(installed))
            self.assertEqual(saved['isa_inspection']['binary_sha256'], RELEASE.digest(installed))
            self.assertFalse(list(Path(directory).glob('.native-package-*')))

    def test_worker_replacement_during_inspection_cannot_rebind_the_build_receipt(self):
        for report_replacement_hash in [False, True]:
            with self.subTest(report_replacement_hash=report_replacement_hash), \
                 tempfile.TemporaryDirectory() as directory:
                worker = worker_at(directory)
                receipt = receipt_for(worker)
                original_inspection = inspection_for(worker)
                output = Path(directory) / 'release'

                def inspect_and_replace(path):
                    replacement = path.with_name('replacement')
                    replacement.write_bytes(ELF + b'replacement')
                    replacement.chmod(0o755)
                    replacement.replace(path)
                    return inspection_for(path) if report_replacement_hash else original_inspection

                with patch.object(RELEASE, 'inspect_proof', side_effect=inspect_and_replace), \
                     patch.object(NATIVE.subprocess, 'run', side_effect=compile_guard), \
                     self.assertRaisesRegex(ValueError, 'changed during packaging'):
                    NATIVE.package(worker, output, receipt, RELEASE)
                self.assertFalse(output.exists())
                self.assertFalse(list(Path(directory).glob('.native-package-*')))


if __name__ == '__main__':
    unittest.main()
