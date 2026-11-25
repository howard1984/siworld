"""Fail closed on uncontrolled builds, scalar artifacts and unsupported hosts."""
import copy
import hashlib
import importlib.util
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


BUILD = module('release_build', 'bench/build-prover-release.py')
ISA = module('release_isa', 'bench/check-prover-isa.py')


class ReleaseBuildTests(unittest.TestCase):
    def test_rejects_flag_and_compiler_profile_overrides(self):
        BUILD.validate_environment({'RUSTFLAGS': '', 'CARGO_TARGET_DIR': 'target'})
        for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC',
                    'CARGO_BUILD_RUSTFLAGS', 'CARGO_BUILD_TARGET', 'RUSTC_BOOTSTRAP',
                    'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS', 'CARGO_PROFILE_RELEASE_LTO'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                BUILD.validate_environment({key: 'override'})

    def test_repository_baseline_is_fixed_v3(self):
        config = {'target': {'cfg(target_arch = "x86_64")': {'rustflags': BUILD.V3_FLAGS}}}
        BUILD.validate_config(config)
        for flags in (['-C', 'target-cpu=native'], ['-C', 'target-feature=+avx2'], []):
            changed = copy.deepcopy(config)
            changed['target']['cfg(target_arch = "x86_64")']['rustflags'] = flags
            with self.subTest(flags=flags), self.assertRaises(ValueError):
                BUILD.validate_config(changed)

    def test_unsupported_adapter_cannot_produce_unusable_package(self):
        for system, machine in (('Darwin', 'arm64'), ('Linux', 'aarch64'), ('Windows', 'AMD64')):
            with patch.object(BUILD.platform, 'system', return_value=system), \
                 patch.object(BUILD.platform, 'machine', return_value=machine), self.assertRaises(ValueError):
                BUILD.validate_platform()

    def test_worker_receipt_binds_binary_flags_and_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            worker = Path(directory) / 'composition-bench'
            worker.write_bytes(b'controlled fixture')
            receipt = {'binary_sha256': hashlib.sha256(worker.read_bytes()).hexdigest(),
                       'effective_rustflags': '-C target-cpu=x86-64-v3',
                       'cargo_working_directory': 'repository-root',
                       'repository_config_sha256': 'config'}
            BUILD.validate_receipt(worker, receipt, 'config')
            for key in receipt:
                changed = {**receipt, key: 'wrong'}
                with self.subTest(key=key), self.assertRaises(ValueError):
                    BUILD.validate_receipt(worker, changed, 'config')

    def test_scalar_worker_rejected_before_creating_package(self):
        with tempfile.TemporaryDirectory() as directory:
            worker = Path(directory) / 'composition-bench'
            worker.write_bytes(b'\x7fELF\x02\x01' + bytes(12) + b'\x3e\x00' + bytes(8))
            worker.chmod(0o755)
            output = Path(directory) / 'release'
            with patch.object(BUILD, 'validate_platform'), \
                 patch.object(BUILD, 'inspect_proof', side_effect=ValueError('no AVX2')), \
                 self.assertRaisesRegex(ValueError, 'no AVX2'):
                BUILD.package([worker], output)
            self.assertFalse(output.exists())

    def test_worker_replacement_after_inspection_cannot_be_packaged(self):
        with tempfile.TemporaryDirectory() as directory:
            worker = Path(directory) / 'composition-bench'
            worker.write_bytes(b'\x7fELF\x02\x01' + bytes(12) + b'\x3e\x00' + bytes(8))
            worker.chmod(0o755)
            output = Path(directory) / 'release'
            original_hash = BUILD.digest(worker)
            def inspect_then_replace(path):
                path.write_bytes(path.read_bytes() + b'replaced')
                return {'binary_sha256': original_hash}
            def compile_launcher(command, **_kwargs):
                Path(command[-1]).write_bytes(b'baseline bootstrap')
            with patch.object(BUILD, 'validate_platform'), \
                 patch.object(BUILD, 'inspect_proof', side_effect=inspect_then_replace), \
                 patch.object(BUILD.subprocess, 'run', side_effect=compile_launcher), \
                 self.assertRaisesRegex(ValueError, 'changed during packaging'):
                BUILD.package([worker], output)
            self.assertFalse(output.exists())

    def test_native_d8_workers_require_inspected_avx2_packages(self):
        launcher = (ROOT / "scripts/bench/prover-launcher.rs").read_text()
        for name in ("v1-transaction-scan", "fee-settlement-bench"):
            with self.subTest(name=name):
                self.assertIn(name, BUILD.PROOF_WORKERS)
                self.assertIn('"' + name + '"', launcher)
                with tempfile.TemporaryDirectory() as directory:
                    worker = Path(directory) / name
                    worker.write_bytes(b"\x7fELF\x02\x01" + bytes(12) + b"\x3e\x00" + bytes(8))
                    worker.chmod(0o755)
                    with patch.object(BUILD, "validate_platform"), \
                         patch.object(BUILD, "inspect_proof", side_effect=ValueError("no AVX2")), \
                         self.assertRaisesRegex(ValueError, "no AVX2"):
                        BUILD.package([worker], Path(directory) / "release")

    def test_rejects_wrong_architecture_and_non_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            worker = Path(directory) / 'composition-bench'
            worker.write_bytes(b'not an ELF')
            worker.chmod(0o755)
            with self.assertRaisesRegex(ValueError, 'ELF'):
                BUILD.validate_worker(worker)
            worker.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'executable'):
                BUILD.validate_worker(worker)


class IsaInspectionTests(unittest.TestCase):
    def test_only_256_bit_integer_multiply_qualifies(self):
        for line in ('123: vpmuludq ymm1,ymm2,ymm3', 'abc: vpmuldq ymm0,ymm1,YMMWORD PTR [rax]'):
            self.assertIsNotNone(ISA.PATTERN.search(line))
        for line in ('vpmuludq xmm1,xmm2,xmm3', 'vpmuludq zmm0,zmm1,zmm2',
                     'mul rax', 'vmovaps ymm0,ymm1', 'notavpmuludq ymm0,ymm1,ymm2'):
            self.assertIsNone(ISA.PATTERN.search(line))

    def test_scalar_disassembly_fails(self):
        class Process:
            stdout = iter(['100: mul rax\n'])
            class Error:
                @staticmethod
                def read():
                    return ''
            stderr = Error()
            @staticmethod
            def wait():
                return 0
        with patch.object(ISA.subprocess, 'Popen', return_value=Process()), \
             self.assertRaisesRegex(ValueError, 'no AVX2'):
            ISA.inspect(Path('scalar'))


if __name__ == '__main__':
    unittest.main()
