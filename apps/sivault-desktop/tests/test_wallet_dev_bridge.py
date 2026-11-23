import http.client
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import unittest


spec = importlib.util.spec_from_file_location(
    "wallet_dev_bridge", Path(__file__).resolve().parents[1] / "wallet-dev-bridge.py"
)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class BridgeTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.path = self.root / "submit.sock"
        self.server = bridge.Bridge(0, self.root, self.path)
        self.addCleanup(self.server.server_close)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(self.server.shutdown)

    def request(self, method, route, body=None, headers=None):
        client = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        try:
            client.request(method, bridge.PREFIX + route, body=body, headers=headers or {})
            response = client.getresponse()
            return response.status, response.read()
        finally:
            client.close()

    def test_serves_only_named_public_artifacts_to_native_clients(self):
        (self.root / "wallet-head.json").write_bytes(b'{"height":2}')
        self.assertEqual(self.request("GET", "head"), (200, b'{"height":2}'))
        for route in ("../wallet-head.json", "head?extra=1", "wallet-export.lock", "chunks/zz"):
            self.assertEqual(self.request("GET", route)[0], 404)
        for headers in ({"Origin": "null"}, {"Sec-Fetch-Site": "same-site"}, {"Host": "bad.test"}):
            self.assertEqual(self.request("GET", "head", headers=headers)[0], 403)
        (self.root / "wallet-head.json").write_bytes(b" " * 2049)
        self.assertEqual(self.request("GET", "head")[0], 503)

    def test_forwards_packet_without_claiming_confirmation(self):
        packet = bytes(range(80))
        pending = b'{"status":"pending","statement_id":"' + b"1" * 64 + b'"}'
        headers = {"Content-Type": bridge.OCTETS}
        self.assertEqual(self.request("POST", "submit", packet, headers)[0], 503)
        self.assertEqual(self.request("POST", "submit", packet[:78], headers)[0], 413)
        with socket.socket(socket.AF_UNIX) as resident:
            resident.bind(str(self.path))
            resident.listen()
            resident.settimeout(5)
            frames = []

            def answer():
                for status, payload in ((0, pending), (1, b"rejected")):
                    conn, _ = resident.accept()
                    with conn, conn.makefile("rb") as source:
                        frames.append(source.read(5 + len(packet)))
                        conn.sendall(struct.pack("<BI", status, len(payload)) + payload)

            thread = threading.Thread(target=answer, daemon=True)
            thread.start()
            self.assertEqual(
                self.request("POST", "submit", packet, headers),
                (202, b'{"status": "pending", "statement_id": "' + b"1" * 64 + b'"}'),
            )
            self.assertEqual(self.request("POST", "submit", packet, headers)[0], 422)
            thread.join(5)
        self.assertEqual(frames, [struct.pack("<BI", 3, len(packet)) + packet] * 2)

    @unittest.skipUnless(os.environ.get("SIVAULT_DIRECTORY_HELPER"), "Rust helper not provided")
    def test_bulk_directory_uses_shared_codec_and_rejects_stale_pages(self):
        helper = bridge.RecipientDirectory(
            Path(os.environ["SIVAULT_DIRECTORY_HELPER"]), "01" * 32
        )
        self.addCleanup(helper.close)
        self.server.recipient_directory = helper
        address = b"tsi1pwl6pnufr5kwq4a25yr4yneu2vk6qzt45sdy2urmqyvx75p69mtcq640vmd"
        descriptor = bytes([2, 1]) + bytes([1]) * 32 + bytes([2]) + bytes(1231)
        headers = {"Content-Type": bridge.OCTETS}
        status, body = self.request("GET", "directory")
        self.assertEqual(status, 200)
        empty = json.loads(body)
        self.assertEqual(empty["count"], 0)
        self.assertEqual(self.request("POST", "directory", address + descriptor, headers)[0], 200)
        self.assertEqual(self.request("POST", "directory", address + descriptor, headers)[0], 429)
        for snapshot, expected in ((empty, 409), (json.loads(self.request("GET", "directory")[1]), 200)):
            status, body = self.request(
                "GET",
                f"directory/page?id={snapshot['id']}&count={snapshot['count']}&offset=0&limit=1",
            )
            self.assertEqual(status, expected)
        self.assertEqual(json.loads(body), {"next": None, "entries": [[address.decode(), descriptor.hex()]]})
        self.assertEqual(self.request("GET", "directory/" + address.decode())[0], 404)


if __name__ == "__main__":
    unittest.main()
