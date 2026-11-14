"""Check static release integrity and isolation using an existing built core."""
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('packaging', Path(__file__).resolve().parents[1] / 'tools/package-release.py')
packaging = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packaging)


def runtime_asset_names(manifest):
    app, threaded = manifest.get('application'), manifest.get('threaded')
    if app not in ('wallet', 'vault') or type(threaded) is not bool:
        raise ValueError('Invalid release runtime mode.')
    expected = {'wallet_bg.wasm', 'wallet.css'} | (
        {'wallet.mjs', 'wallet-startup.mjs', 'wallet-worker.mjs'} if app == 'wallet'
        else {'vault.mjs', 'content-worker.mjs', 'cloud-worker.mjs'})
    if threaded:
        expected.add('rayon-worker.mjs')
    names = [Path(name).name for name in manifest['assets']]
    if set(names) != expected or len(names) != len(expected):
        raise ValueError('Release assets differ from the declared runtime mode.')
    return sorted(expected)


def wasm_export_names(data):
    if data[:8] != b'\0asm\x01\0\0\0':
        raise ValueError('Invalid WebAssembly header.')
    at = 8

    def unsigned(end):
        nonlocal at
        value = 0
        for shift in range(0, 35, 7):
            if at >= end:
                raise ValueError('Truncated WebAssembly integer.')
            byte = data[at]
            at += 1
            if shift == 28 and byte > 15:
                raise ValueError('WebAssembly integer exceeds u32.')
            value |= (byte & 127) << shift
            if byte < 128:
                return value
        raise ValueError('Invalid WebAssembly integer.')

    exports = set()
    while at < len(data):
        section = unsigned(len(data))
        size = unsigned(len(data))
        end = at + size
        if end > len(data):
            raise ValueError('Truncated WebAssembly section.')
        if section == 7:
            for _ in range(unsigned(end)):
                size = unsigned(end)
                if at + size >= end:
                    raise ValueError('Truncated WebAssembly export.')
                exports.add(data[at:at + size].decode('utf-8'))
                at += size + 1  # Skip the export kind before its index.
                unsigned(end)
            if at != end:
                raise ValueError('Trailing WebAssembly export bytes.')
        at = end
    return exports


class RuntimeAssetTests(unittest.TestCase):
    def test_complete_standard_and_threaded_asset_sets(self):
        for app, entries in [('wallet', ['wallet.mjs', 'wallet-startup.mjs', 'wallet-worker.mjs']),
                             ('vault', ['vault.mjs', 'content-worker.mjs', 'cloud-worker.mjs'])]:
            for threaded in [False, True]:
                names = entries + ['wallet_bg.wasm', 'wallet.css'] + (['rayon-worker.mjs'] if threaded else [])
                manifest = dict(application=app, threaded=threaded, assets={name: 'unused-digest' for name in names})
                with self.subTest(app=app, threaded=threaded):
                    self.assertEqual(runtime_asset_names(manifest), sorted(names))
                    manifest['threaded'] = not threaded
                    with self.assertRaisesRegex(ValueError, 'declared runtime mode'):
                        runtime_asset_names(manifest)

    def test_missing_extra_and_ambiguous_assets_are_rejected(self):
        names = ['wallet.mjs', 'wallet-startup.mjs', 'wallet-worker.mjs', 'wallet_bg.wasm', 'wallet.css']
        for added, removed in [(['workerHelpers.no-bundler.js'], []), ([], ['wallet-worker.mjs']),
                               (['other/wallet.mjs'], [])]:
            manifest = dict(application='wallet', threaded=False,
                            assets={name: 'unused-digest' for name in names + added if name not in removed})
            with self.subTest(added=added, removed=removed), self.assertRaisesRegex(ValueError, 'declared runtime mode'):
                runtime_asset_names(manifest)
        for value in [None, 0, 1, 'false']:
            with self.subTest(threaded=value), self.assertRaisesRegex(ValueError, 'runtime mode'):
                runtime_asset_names(dict(application='wallet', threaded=value, assets={}))

    def test_wasm_exports_are_inspected_without_instantiating_the_core(self):
        # A public synthetic module exports the same empty function under two names.
        names = ['ordinary', 'initThreadPool']
        entries = b''.join(bytes([len(name)]) + name.encode() + b'\0\0' for name in names)
        section = bytes([len(names)]) + entries
        data = (b'\0asm\x01\0\0\0\x01\x04\x01\x60\0\0\x03\x02\x01\0'
                + bytes([7, len(section)]) + section + b'\x0a\x04\x01\x02\0\x0b')
        self.assertEqual(wasm_export_names(data), set(names))
        for invalid in [b'invalid', data[:11], data[:8] + b'\x07\x80\x80\x80\x80\x10']:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                wasm_export_names(invalid)


class ReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='wallet-release-tests-')
        cls.root = Path(cls.directory.name)
        cls.output = cls.root / 'built'
        packaging.package(Path(os.environ['WALLET_WEB_OUTPUT']), cls.output, Path(os.environ['WALLET_ESBUILD']))

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def mutated(self, suffix):
        root = self.root / suffix
        shutil.copytree(self.output / 'wallet', root)
        return root

    def test_both_origins_are_independent_and_hashes_match(self):
        for app, other in [('wallet', 'vault'), ('vault', 'wallet')]:
            root = self.output / app
            manifest = packaging.verify_release(root)
            runtime_asset_names(manifest)
            self.assertFalse((root / (other + '.html')).exists())
            html = (root / (app + '.html')).read_text()
            self.assertEqual(html.count('integrity="sha384-'), 3 if app == 'wallet' else 2)
            self.assertNotIn('http-equiv="Content-Security-Policy"', html)
            self.assertIn('releases/' + manifest['release'], html)

    def test_wallet_startup_is_visible_before_application_execution(self):
        root = self.output / 'wallet'
        html = (root / 'wallet.html').read_text()
        self.assertRegex(html, r'<dialog id="wallet-startup"[^>]* open>')
        self.assertLess(html.index('id="wallet-startup"'), html.index('id="create"'))
        self.assertLess(html.index('/assets/wallet-startup.mjs'), html.index('/assets/wallet.mjs'))
        startup = next(root.rglob('wallet-startup.mjs')).read_text()
        self.assertNotRegex(startup, r'\b(?:import|export)\b')
        self.assertNotIn('wallet-startup', (self.output / 'vault/vault.html').read_text())

    def test_javascript_and_wasm_corruption_are_rejected(self):
        manifest = packaging.verify_release(self.output / 'wallet')
        for suffix in runtime_asset_names(manifest):
            root = self.mutated(suffix)
            artifact = next(root.rglob(suffix))
            artifact.write_bytes(artifact.read_bytes() + b'altered')
            with self.assertRaisesRegex(ValueError, 'integrity mismatch'):
                packaging.verify_release(root)

    def test_runtime_connection_origins_are_frozen_and_independently_checked(self):
        wallet = self.output / 'wallet'
        pinned = packaging.wallet_connection_origins(Path(os.environ['WALLET_WEB_OUTPUT']))
        manifest = packaging.verify_release(wallet, expected_connect_origins=pinned)
        self.assertEqual(manifest['connect_origins'], pinned)
        headers = json.loads((wallet / 'response-headers.json').read_text())
        self.assertEqual(headers, packaging.response_headers(pinned))
        self.assertEqual(headers['Strict-Transport-Security'], 'max-age=31536000')
        self.assertEqual(packaging.verify_release(self.output / 'vault')['connect_origins'], [])
        with self.assertRaisesRegex(ValueError, 'Approved connection origins differ'):
            packaging.verify_release(wallet, expected_connect_origins=['https://unapproved.example.test'])
        altered = self.mutated('extra-connection-origin')
        headers['Content-Security-Policy'] = headers['Content-Security-Policy'].replace(
            "connect-src 'self'", "connect-src 'self' https://unapproved.example.test")
        (altered / 'response-headers.json').write_text(json.dumps(headers))
        with self.assertRaisesRegex(ValueError, 'Response policy differs'):
            packaging.verify_release(altered)
        downgraded = self.mutated('hsts-downgrade')
        policy = json.loads((downgraded / 'response-headers.json').read_text())
        policy['Strict-Transport-Security'] = 'max-age=86400'
        (downgraded / 'response-headers.json').write_text(json.dumps(policy))
        with self.assertRaisesRegex(ValueError, 'Response policy differs'):
            packaging.verify_release(downgraded)

    def test_runtime_policy_comes_from_a_fixed_engineering_module(self):
        source = self.root / 'runtime-config-only'
        (source / 'sdk').mkdir(parents=True)
        config = dict(version=2, name='siworld-eng-2', network='1'*64, genesis='2'*64,
                      rules='3'*64, profile='4'*64, fee_mode=0, read_only=True,
                      api='https://primary.example.test',
                      apis=['https://primary.example.test', 'https://secondary.example.test'],
                      submission_apis=['https://secondary.example.test', 'https://primary.example.test'])
        module = source / 'sdk/network.js'
        module.write_text('export const ENGINEERING = ' + json.dumps(config) + ';\n')
        self.assertEqual(packaging.wallet_connection_origins(source), config['apis'])
        for changes in ({'fee_mode': False}, {'apis': []}, {'submission_apis': ['https://bad.example.test/path']},
                        {'api': 'https://other.example.test'}, {'read_only': False}):
            module.write_text('export const ENGINEERING = ' + json.dumps({**config, **changes}) + ';\n')
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                packaging.wallet_connection_origins(source)
        module.write_text('export const ENGINEERING = discoverSources();\n')
        with self.assertRaisesRegex(ValueError, 'runtime configuration differs'):
            packaging.wallet_connection_origins(source)

    def test_connection_policy_rejects_discovery_wildcards_and_credentials(self):
        for values in (['*'], ['https:'], ['https://*.example.test'], ['https://a.example.test/path'],
                       ['https://user:password@a.example.test'], ['http://a.example.test'],
                       ['https://a.example.test', 'https://a.example.test'], ['https://a.example.test:443'],
                       ['https://a.example.test#fragment'], ['https://a.example.test?query'], 'https://a.example.test'):
            with self.subTest(values=values), self.assertRaises(ValueError):
                packaging.connection_origins(values)
        self.assertEqual(packaging.connection_origins(['http://127.0.0.1:8890', 'https://a.example.test']),
                         ['http://127.0.0.1:8890', 'https://a.example.test'])

    def test_unexpected_files_symlinks_and_html_changes_are_rejected(self):
        for index, mutation in enumerate(['extra', 'link', 'html']):
            root = self.mutated('unexpected-' + str(index))
            if mutation == 'extra':
                (root / 'unexpected.js').write_text('')
            elif mutation == 'link':
                (root / 'link').symlink_to(root / 'wallet.html')
            else:
                (root / 'wallet.html').write_text('altered')
            with self.assertRaises(ValueError):
                packaging.verify_release(root)

    def test_path_escape_and_policy_weakening_are_rejected(self):
        root = self.mutated('path-escape')
        p = root / 'release-manifest.json'
        manifest = json.loads(p.read_text())
        manifest['assets']['../escape'] = 'sha384-invalid'
        p.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'artifact path'):
            packaging.verify_release(root)
        root = self.mutated('policy')
        p = root / 'response-headers.json'
        headers = json.loads(p.read_text())
        headers['Content-Security-Policy'] += "; worker-src blob:"
        p.write_text(json.dumps(headers))
        with self.assertRaisesRegex(ValueError, 'policy differs'):
            packaging.verify_release(root)

    def test_worker_graph_is_static_and_wasm_fetch_has_integrity(self):
        for app in ['wallet', 'vault']:
            for p in (self.output / app).rglob('*.mjs'):
                text = p.read_text()
                self.assertFalse(any(value in text for value in ['/Users/', '/private/', 'wallet-release-']), 'Local build path leaked.')
                self.assertNotRegex(text, r'\bimport\s*\(')
                if p.name.endswith('worker.mjs'):
                    self.assertNotIn('createObjectURL', text)
                    self.assertNotIn('new Blob(', text)
                    self.assertIn('integrity: "sha384-', text)
            manifest = packaging.verify_release(self.output / app)
            runtime_asset_names(manifest)
            core = Path(os.environ['WALLET_WEB_OUTPUT']) / 'sdk/core'
            exports = wasm_export_names((core / 'wallet_bg.wasm').read_bytes())
            workers = list((self.output / app).rglob('rayon-worker.mjs'))
            helpers = list((core / 'snippets').glob('wasm-bindgen-rayon-*/src/workerHelpers.no-bundler.js'))
            if manifest['threaded']:
                self.assertEqual(len(workers), 1)
                self.assertEqual(len(helpers), 1)
                self.assertIn('initThreadPool', exports)
                self.assertIn('wbg_rayon_start_worker', exports)
                worker = workers[0].read_text()
                self.assertIn('Copyright 2022 Google Inc.', worker)
                self.assertIn('module_or_path: data.module, memory: data.memory', worker)
            else:
                self.assertEqual(workers, [])
                self.assertEqual(helpers, [])
                self.assertFalse(any(name in {'initThreadPool', '__wasm_init_tls', '__wbindgen_thread_destroy'}
                                     or name.startswith('wbg_rayon_') for name in exports))
                self.assertNotRegex((core / 'wallet.js').read_text(),
                                    r'\bexport\s+(?:async\s+)?function\s+(?:initThreadPool|wbg_rayon_)')

    def test_activation_requires_an_independently_pinned_manifest_digest(self):
        import hashlib
        root = self.mutated('trusted-manifest')
        p = root / 'release-manifest.json'
        expected = hashlib.sha256(p.read_bytes()).hexdigest()
        packaging.verify_release(root, expected)
        manifest = json.loads(p.read_text())
        manifest['html_integrity'] = packaging.integrity(b'changed HTML')
        (root / 'wallet.html').write_bytes(b'changed HTML')
        p.write_text(json.dumps(manifest))
        # Self-consistency cannot establish authorization of replacement bytes.
        packaging.verify_release(root)
        with self.assertRaisesRegex(ValueError, 'Approved manifest digest differs'):
            packaging.verify_release(root, expected)

    def test_pinned_input_and_fresh_output_are_enforced(self):
        with self.assertRaisesRegex(ValueError, 'Pinned input layout differs'):
            packaging.replace_once('different input', 'expected', 'replacement')
        with self.assertRaisesRegex(ValueError, 'fresh directory'):
            packaging.package(Path(os.environ['WALLET_WEB_OUTPUT']), self.output, Path(os.environ['WALLET_ESBUILD']))


if __name__ == '__main__':
    unittest.main()
