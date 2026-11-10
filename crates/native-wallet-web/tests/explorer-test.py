"""Public projection schema, file boundary and existing-origin routing tests."""
import copy
import http.client
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest

spec = importlib.util.spec_from_file_location('services', Path(__file__).parents[1] / 'tools/engineering-services.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def fixture():
    return {
        'version': 1, 'network': '11' * 32, 'genesis': '22' * 32,
        'height': 0, 'tip': '22' * 32, 'published_unix_seconds': 1700000000,
        'blocks': [], 'checkpoint': None,
        'economics': {'issued_atoms': '0', 'burned_atoms': '0', 'holder_pool_atoms': '0',
                      'locked_reward_atoms': '0', 'circulating_estimate_atoms': None,
                      'unlock_schedule': [], 'unlock_schedule_complete': True, 'funds': []},
        'governance': {'current_signers': None, 'fee_address': None, 'fund_addresses': None, 'changes': None},
    }


class ExplorerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.value = fixture()
        self.index = {key: self.value[key] for key in ('network', 'genesis', 'height', 'tip')}
        self.index['ids'] = []
        self.write()

    def tearDown(self):
        self.directory.cleanup()

    def write(self):
        (self.root / 'chain.json').write_text(json.dumps(self.index))
        (self.root / 'explorer.json').write_text(json.dumps(self.value))

    def test_only_allowlisted_primitive_fields_can_leave_adapter(self):
        self.assertEqual(m.read_explorer(self.root), self.value)
        for path, private in [
            ((), {'fees': '1'}), (('economics',), {'address_count': 2}),
            (('economics', 'issued_atoms'), {'wallet': 'private'}),
            (('governance', 'changes'), [{'fee_amount': '1'}]),
        ]:
            candidate = copy.deepcopy(self.value)
            target = candidate
            for key in path[:-1]:
                target = target[key]
            if path:
                target[path[-1]] = private
            else:
                target.update(private)
            with self.subTest(path=path), self.assertRaises(ValueError):
                m.explorer_projection(candidate, self.index)

    def test_identity_malformed_amounts_and_unbounded_samples_are_rejected(self):
        complete = copy.deepcopy(self.value)
        complete['economics']['funds'] = [
            {'index': index, 'entitled_atoms': '2', 'released_atoms': '1', 'spent_atoms': '0'}
            for index in range(32)]
        self.assertEqual(len(m.explorer_projection(complete, self.index)['economics']['funds']), 32)
        complete['economics']['funds'].append(
            {'index': 32, 'entitled_atoms': '2', 'released_atoms': '1', 'spent_atoms': '0'})
        with self.assertRaises(ValueError):
            m.explorer_projection(complete, self.index)
        for key, bad in [('network', '33' * 32), ('height', True), ('published_unix_seconds', {}), ('blocks', [{}] * 102)]:
            candidate = copy.deepcopy(self.value)
            candidate[key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                m.explorer_projection(candidate, self.index)
        for bad in ['-1', '01', str(1 << 128), 0, {'fee': '1'}]:
            candidate = copy.deepcopy(self.value)
            candidate['economics']['issued_atoms'] = bad
            with self.subTest(amount=bad), self.assertRaises(ValueError):
                m.explorer_projection(candidate, self.index)

    def test_projection_cannot_follow_links_or_read_oversized_file(self):
        source = self.root / 'explorer.json'
        other = self.root / 'other.json'
        source.rename(other)
        source.symlink_to(other)
        with self.assertRaises(OSError): m.read_explorer(self.root)
        source.unlink()
        os.link(other, source)
        with self.assertRaises(ValueError): m.read_explorer(self.root)
        source.unlink()
        source.write_bytes(b' ' * 131073)
        with self.assertRaises(ValueError): m.read_explorer(self.root)

    def test_existing_origin_is_required_and_route_is_get_only(self):
        server = m.Server(('127.0.0.1', 0), m.Handler)
        server.role, server.origin, server.data = 'chain', 'https://explorer.invalid', self.root
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for method, path, origin, status in [
                ('GET', '/v1/explorer', None, 403),
                ('GET', '/v1/explorer', 'https://other.invalid', 403),
                ('GET', '/v1/explorer', server.origin, 200),
                ('POST', '/v1/explorer', server.origin, 400),
                ('GET', '/v1/explorer?extra=1', server.origin, 400),
            ]:
                connection = http.client.HTTPConnection(*server.server_address, timeout=5)
                connection.request(method, path, headers={'Origin': origin} if origin else {})
                response = connection.getresponse()
                body = response.read()
                self.assertEqual(response.status, status, (method, path, origin))
                if status == 200:
                    self.assertEqual(json.loads(body), self.value)
                    self.assertEqual(response.getheader('Cache-Control'), 'no-store')
                connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
