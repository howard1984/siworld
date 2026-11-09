"""Regression checks for release provenance and static-runtime PE admission."""
import importlib.util
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
from windows_miner_pe import audit, imports  # noqa: E402

SPEC = importlib.util.spec_from_file_location('build_windows_miner', SCRIPTS / 'build-windows-miner.py')
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def executable(ordinary='kernel32.dll', delayed=None):
    data = bytearray(0x800)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', data, 0x84, 0x8664, 1, 0, 0, 0, 240, 2)
    optional = 0x98
    struct.pack_into('<H', data, optional, 0x20b)
    struct.pack_into('<Q', data, optional + 24, 0x140000000)
    struct.pack_into('<I', data, optional + 60, 0x200)
    struct.pack_into('<I', data, optional + 108, 16)
    struct.pack_into('<II', data, optional + 112 + 8, 0x1000, 40)
    section = optional + 240
    struct.pack_into('<IIII', data, section + 8, 0x600, 0x1000, 0x600, 0x200)
    struct.pack_into('<IIIII', data, 0x200, 0x1200, 0, 0, 0x1100, 0x1200)
    name = ordinary.encode('ascii') + b'\0'
    data[0x300:0x300 + len(name)] = name
    if delayed:
        struct.pack_into('<II', data, optional + 112 + 13 * 8, 0x1040, 64)
        struct.pack_into('<IIIIIIII', data, 0x240, 1, 0x1140, 0, 0x1200, 0, 0, 0, 0)
        name = delayed.encode('ascii') + b'\0'
        data[0x340:0x340 + len(name)] = name
    return data


class PeTests(unittest.TestCase):
    def audit_data(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'miner.exe'
            path.write_bytes(data)
            return audit(path)

    def test_system_and_delay_imports(self):
        result = self.audit_data(executable('KERNEL32.dll', 'bcrypt.dll'))
        self.assertEqual(result['imports'], ['kernel32.dll'])
        self.assertEqual(result['delay_imports'], ['bcrypt.dll'])
        self.assertFalse(result['dynamic_crt'])

    def test_rejects_dynamic_crt_and_non_system_dlls(self):
        for name in ['vcruntime140.dll', 'msvcp140.dll', 'ucrtbase.dll',
                     'api-ms-win-crt-runtime-l1-1-0.dll', 'libcrypto.dll', 'python3.dll']:
            for delayed in [False, True]:
                with self.subTest(name=name, delayed=delayed):
                    data = executable('kernel32.dll', name) if delayed else executable(name)
                    with self.assertRaisesRegex(ValueError, 'DLL dependency'):
                        self.audit_data(data)

    def test_accepts_windows_core_api_set(self):
        self.audit_data(executable('api-ms-win-core-synch-l1-2-0.dll'))
        self.audit_data(executable('bcryptprimitives.dll'))

    def test_rejects_truncated_and_wrong_machine(self):
        for size in [0, 0x40, 0x90, 0x210, 0x799]:
            with self.subTest(size=size), self.assertRaises(ValueError):
                imports(executable()[:size])
        data = executable()
        struct.pack_into('<H', data, 0x84, 0x14c)
        with self.assertRaises(ValueError):
            imports(data)

    def test_rejects_unmapped_names_and_unterminated_directory(self):
        data = executable()
        struct.pack_into('<I', data, 0x200 + 12, 0x9000)
        with self.assertRaisesRegex(ValueError, 'RVA'):
            imports(data)
        data = executable()
        struct.pack_into('<II', data, 0x98 + 112 + 8, 0x1000, 20)
        with self.assertRaisesRegex(ValueError, 'Unterminated'):
            imports(data)


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.environment = {}

    def test_local_build_provenance(self):
        for host, method in [('darwin', 'cargo-xwin-msvc'), ('win32', 'native-msvc')]:
            with patch.object(builder.sys, 'platform', host):
                result = builder.local_context({})
                self.assertEqual(result['method'], method)
                self.assertFalse(result['ci'])

    def test_rejects_hosted_execution(self):
        for key in ('CI', 'GITHUB_ACTIONS', 'GITHUB_RUN_ID', 'RUNNER_ENVIRONMENT'):
            with patch.object(builder.sys, 'platform', 'darwin'), self.assertRaises(ValueError):
                builder.local_context({key: 'true'})

    def test_rejects_toolchain_overrides(self):
        for key in ('CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER'):
            with patch.object(builder.sys, 'platform', 'darwin'), self.assertRaises(ValueError):
                builder.local_context({key: 'unreviewed'})

    def test_rejects_dirty_or_mismatched_checkout(self):
        answers = [str(builder.ROOT) + '\n', 'a' * 40 + '\n', b' M Cargo.lock\n']
        with patch.object(builder.subprocess, 'check_output', side_effect=answers), self.assertRaisesRegex(ValueError, 'unmodified'):
            builder.source_revision('a' * 40)
        with patch.object(builder.subprocess, 'check_output', side_effect=answers[:2]), self.assertRaisesRegex(ValueError, 'differs'):
            builder.source_revision('b' * 40)
        with patch.object(builder.subprocess, 'check_output', return_value=str(builder.ROOT.parent)), self.assertRaisesRegex(ValueError, 'own Git'):
            builder.source_revision('a' * 40)

    def test_archive_checksums_bind_provenance_to_exact_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'docs').mkdir()
            for name in ['LICENSE', 'NOTICE', 'docs/windows-native-miner.md']:
                (root / name).write_text('Technical test fixture\n', encoding='utf-8')

            builds = []

            def fake_build(manifest, target, flags, extra=None):
                builds.append((manifest, flags, extra))
                destination = target / builder.TARGET / 'release'
                destination.mkdir(parents=True)
                name = 'siworld-miner-worker.exe' if 'miner-cli/' in manifest else 'siworld-miner.exe'
                (destination / name).write_bytes(executable())

            def output(command, **kwargs):
                if command[:2] == ['rustc', '-vV']:
                    return f'rustc test\nhost: {builder.TARGET}\n'
                if command[:2] == ['git', 'ls-files']:
                    return b'LICENSE\0NOTICE\0docs/windows-native-miner.md\0'
                if command[:2] == ['cargo', 'tree']:
                    return 'siworld-miner-cli v0.1.0\n'
                raise AssertionError(command)

            with patch.object(builder, 'ROOT', root), patch.object(builder.sys, 'platform', 'win32'), \
                    patch.dict(builder.os.environ, self.environment, clear=True), \
                    patch.object(builder, 'source_revision', return_value='a' * 40), \
                    patch.object(builder, 'build', side_effect=fake_build), \
                    patch.object(builder.subprocess, 'check_output', side_effect=output), \
                    patch.object(builder.subprocess, 'run') as run:
                archive = builder.package(root / 'output', 'a' * 40)
            record = json.loads((archive.parent / 'provenance.json').read_text())
            self.assertEqual(record['archive']['sha256'], hashlib.sha256(archive.read_bytes()).hexdigest())
            self.assertEqual(record['source_revision'], 'a' * 40)
            with zipfile.ZipFile(archive) as package:
                prefix = 'siworld-miner-windows-x86_64/'
                info = package.read(prefix + 'build-info.json')
                self.assertEqual(record['build_info_sha256'], hashlib.sha256(info).hexdigest())
                self.assertEqual(json.loads(info)['build'], record['build'])
                for line in package.read(prefix + 'SHA256SUMS').decode().splitlines():
                    checksum, name = line.split('  ', 1)
                    self.assertEqual(checksum, hashlib.sha256(package.read(prefix + name)).hexdigest())
            for line in (archive.parent / 'SHA256SUMS').read_text().splitlines():
                checksum, name = line.split('  ', 1)
                self.assertEqual(checksum, hashlib.sha256((archive.parent / name).read_bytes()).hexdigest())
            self.assertEqual(len(builds), 2)
            self.assertTrue(all('target-feature=+crt-static' in build[1] for build in builds))
            self.assertEqual(builds[1][2]['SIWORLD_WORKER_SHA256'], hashlib.sha256(executable()).hexdigest())
            run.assert_called_once()


if __name__ == '__main__':
    unittest.main()
