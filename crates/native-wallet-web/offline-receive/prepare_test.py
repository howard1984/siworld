"""Synthetic preparation/server isolation tests; no key generation or real WASM."""
import copy
import http.client
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import HTTPServer

spec = importlib.util.spec_from_file_location('offline_receive', Path(__file__).with_name('prepare.py'))
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class ReceiveBuildTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.core = self.root / 'core'
        self.core.mkdir()
        synthetic = {'wallet.js': b'export default function init() {}\n', 'wallet_bg.wasm': b'\0asm-synthetic-test-only'}
        qualified = copy.deepcopy(tool.CORE)
        for name, data in synthetic.items():
            (self.core / name).write_bytes(data)
            qualified['files'][name] = tool.digest(data)
        self.patch = patch.object(tool, 'CORE', qualified)
        self.patch.start()
        self.input = self.root / 'context.json'
        self.context = {'version': 1, 'name': 'siworld-eng-2', 'network': 'a1' * 32, 'genesis': None, 'network_parameter_fixed': True,
                        'recipient_wallet': {'receive_only': True, 'online_api': None, 'address_directory': False, 'separate_storage_namespace_required': True, 'custody_input_allowed': False}}
        self.input.write_text(json.dumps(self.context))
        self.output = self.root / 'site'
        self.port = 8879

    def tearDown(self):
        self.patch.stop()
        self.temp.cleanup()

    def prepare(self):
        return tool.prepare(self.input, tool.digest(self.input.read_bytes()), self.core, self.output, self.port, 'a' * 40)

    def test_fresh_hashed_output_and_no_overwrite(self):
        manifest = self.prepare()
        self.assertEqual(set(manifest['files']), tool.SERVED)
        self.assertEqual(manifest['context_sha256'], tool.digest(self.input.read_bytes()))
        self.assertEqual(manifest['qualified_core'], tool.CORE)
        self.assertEqual(len(manifest['source_sha256']), 64)
        self.assertEqual(tool.load_build(self.output)[1], manifest)
        with self.assertRaises(FileExistsError):
            self.prepare()
        self.assertFalse((self.output / 'network.js').exists())
        self.assertFalse((self.output / 'storage.js').exists())

    def test_wrong_context_or_core_fails_before_output(self):
        for change in [{'name': 'siworld-eng-1'}, {'network': '0' * 64}, {'genesis': 'c3' * 32}, {'network_parameter_fixed': False}, {'recipient_wallet': {}}]:
            self.input.write_text(json.dumps({**self.context, **change}))
            with self.assertRaises(ValueError):
                self.prepare()
            self.assertFalse(self.output.exists())
        self.input.write_text(json.dumps(self.context))
        with self.assertRaises(ValueError):
            tool.prepare(self.input, '0' * 64, self.core, self.output, self.port, 'a' * 40)
        (self.core / 'wallet.js').write_text('changed core')
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_changed_prepared_asset_or_symlink_is_rejected(self):
        self.prepare()
        target = self.output / 'app.mjs'
        target.write_text('changed')
        with self.assertRaises(ValueError):
            tool.load_build(self.output)
        target.unlink()
        target.symlink_to(self.core / 'wallet.js')
        with self.assertRaises((ValueError, OSError)):
            tool.load_build(self.output)

    def test_http_whitelist_origin_methods_and_integrity(self):
        # Port zero is used by this disposable synthetic HTTP fixture only.
        manifest = self.prepare()
        server = HTTPServer(('127.0.0.1', 0), tool.handler(self.output, manifest))
        self.port = server.server_port
        manifest['origin'] = tool.pinned_origin(self.port)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def request(path='/', method='GET', headers=None):
            connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
            connection.request(method, path, headers=headers or {})
            response = connection.getresponse()
            result = response.status, dict(response.getheaders()), response.read()
            connection.close()
            return result
        try:
            code, headers, body = request()
            self.assertEqual(code, 200)
            self.assertIn(b'Create a new receive account', body)
            self.assertEqual(headers['Cache-Control'], 'no-store')
            self.assertIn("connect-src 'self'", headers['Content-Security-Policy'])
            self.assertIn("form-action 'none'", headers['Content-Security-Policy'])
            self.assertEqual(headers['Cross-Origin-Resource-Policy'], 'same-origin')
            for name in tool.SERVED:
                self.assertEqual(request('/' + name)[0], 200)
            self.assertEqual(request('/core/wallet_bg.wasm')[1]['Content-Type'], 'application/wasm')
            self.assertEqual(request('/', 'HEAD')[2], b'')
            for path in ['/api/v1/head', '/build-manifest.json', '/core/', '/../context.json', '/%2e%2e/context.json', '/app.mjs?query', '/app.mjs#fragment', 'http://invalid.example/app.mjs']:
                self.assertIn(request(path)[0], (403, 404))
            for headers in [{'Host': 'localhost:' + str(self.port)}, {'Origin': 'https://invalid.example'}, {'Sec-Fetch-Site': 'cross-site'}, {'Service-Worker': 'script'}, {'Content-Length': '1'}]:
                self.assertEqual(request(headers=headers)[0], 403)
            for method in ['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'TRACE', 'CONNECT']:
                self.assertEqual(request('/', method)[0], 405)
            (self.output / 'app.mjs').write_text('changed')
            self.assertEqual(request('/app.mjs')[0], 409)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
