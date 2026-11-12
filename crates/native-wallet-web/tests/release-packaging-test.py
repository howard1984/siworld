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
        for suffix in ['wallet.mjs', 'wallet-startup.mjs', 'wallet-worker.mjs', 'rayon-worker.mjs', 'wallet_bg.wasm', 'wallet.css']:
            root = self.mutated(suffix)
            artifact = next(root.rglob(suffix))
            artifact.write_bytes(artifact.read_bytes() + b'altered')
            with self.assertRaisesRegex(ValueError, 'integrity mismatch'):
                packaging.verify_release(root)

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
            worker = next((self.output / app).rglob('rayon-worker.mjs')).read_text()
            self.assertIn('Copyright 2022 Google Inc.', worker)
            self.assertIn('module_or_path: data.module, memory: data.memory', worker)

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
