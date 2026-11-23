#!/usr/bin/env python3
"""Expose an isolated ENG2 resident's public wallet artifacts on IPv4 loopback."""

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import re
import socket
import struct
import subprocess
import time
from urllib.parse import parse_qs


PREFIX = "/api/v2/wallet/"
HASH = r"[0-9a-f]{64}"
HEIGHT = r"(?:0|[1-9][0-9]{0,4}|100000)"
MAX_PACKET = 2184 + 655360 + 78
SHORT_ADDRESS_BYTES = 63
DESCRIPTOR_BYTES = 1266
OCTETS = "application/octet-stream"
DIRECTORY = PREFIX + "directory"
PAGE = DIRECTORY + "/page"


class RecipientDirectory:
    def __init__(self, helper, genesis):
        self.process = subprocess.Popen(
            [str(helper.resolve(strict=True)), genesis],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )

    def request(self, payload):
        frame = json.dumps(payload, separators=(",", ":")).encode("ascii") + b"\n"
        if len(frame) > 3000:
            raise ValueError("Directory request exceeds frame")
        self.process.stdin.write(frame)
        self.process.stdin.flush()
        reply = self.process.stdout.readline(180_001)
        if not reply.endswith(b"\n") or len(reply) > 180_000:
            raise ValueError("Invalid directory reply")
        return json.loads(reply)

    def close(self):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self.process.stdout.close()


def artifact(route):
    if route == "head":
        return "wallet-head.json", 2048, "application/json"
    if route == "genesis":
        return "wallet-genesis.bin", 4 * 1024 * 1024, OCTETS
    for pattern, name, limit in (
        (rf"generations/({HEIGHT})/({HASH})", "wallet-generation-{}-{}.bin", 40_000),
        (rf"chunks/({HASH})", "wallet-chunk-{}.bin", 34_000),
        (rf"receipts/({HEIGHT})/({HASH})", "wallet-{}-{}.bin", 32 * 1024 * 1024),
    ):
        match = re.fullmatch(pattern, route)
        if match:
            return name.format(*match.groups()), limit, OCTETS
    return None


def submit(socket_path, packet):
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(10)
        conn.connect(str(socket_path))
        conn.sendall(struct.pack("<BI", 3, len(packet)) + packet)
        with conn.makefile("rb") as reply:
            status, length = struct.unpack("<BI", reply.read(5))
            if status == 1:
                return None
            if status != 0 or not 1 <= length <= 256:
                raise ValueError("Invalid resident response")
            data = reply.read(length)
            if len(data) != length:
                raise ValueError("Truncated resident response")
    payload = json.loads(data)
    if (
        not isinstance(payload, dict)
        or set(payload) != {"status", "statement_id"}
        or payload["status"] != "pending"
        or not isinstance(payload["statement_id"], str)
        or not re.fullmatch(HASH, payload["statement_id"])
    ):
        raise ValueError("Invalid resident submission status")
    return payload


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        self.request.settimeout(5)
        super().setup()

    def log_message(self, *_args):
        pass

    def response(self, status, body=b"", media="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", media)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def allowed(self):
        return (
            self.headers.get_all("Host") == [f"127.0.0.1:{self.server.server_port}"]
            and "Origin" not in self.headers
            and "Sec-Fetch-Site" not in self.headers
        )

    def do_GET(self):
        if not self.allowed():
            return self.response(403)
        if self.path == DIRECTORY:
            return self.directory({"op": "snapshot"})
        if self.path.startswith(PAGE + "?"):
            try:
                fields = parse_qs(self.path[len(PAGE) + 1:], strict_parsing=True, max_num_fields=4)
                if set(fields) != {"id", "count", "offset", "limit"}:
                    raise ValueError("Unexpected page fields")
                if any(len(values) != 1 for values in fields.values()):
                    raise ValueError("Repeated page field")
                if not re.fullmatch(HASH, fields["id"][0]):
                    raise ValueError("Invalid snapshot ID")
                request = {"op": "page", "id": fields["id"][0]}
                for key in ("count", "offset", "limit"):
                    value = fields[key][0]
                    if not re.fullmatch(r"0|[1-9][0-9]{0,4}", value):
                        raise ValueError("Invalid page bound")
                    request[key] = int(value)
            except ValueError:
                return self.response(400)
            return self.directory(request)
        selected = artifact(self.path.removeprefix(PREFIX)) if self.path.startswith(PREFIX) else None
        if selected is None:
            return self.response(404)
        name, limit, media = selected
        try:
            with (self.server.export / name).open("rb") as source:
                body = source.read(limit + 1)
        except FileNotFoundError:
            return self.response(404)
        except OSError:
            return self.response(503)
        if not 1 <= len(body) <= limit:
            return self.response(503)
        self.response(200, body, media)

    def do_POST(self):
        if not self.allowed():
            return self.response(403)
        publish = self.path == DIRECTORY
        if not publish and self.path != PREFIX + "submit":
            return self.response(404)
        if self.headers.get_all("Content-Type") != [OCTETS] or "Transfer-Encoding" in self.headers:
            return self.response(415)
        sizes = self.headers.get_all("Content-Length", [])
        if len(sizes) != 1 or not re.fullmatch(r"[1-9][0-9]{0,5}", sizes[0]):
            return self.response(400)
        size = int(sizes[0])
        if not (
            size == SHORT_ADDRESS_BYTES + DESCRIPTOR_BYTES
            if publish else 78 < size <= MAX_PACKET
        ):
            return self.response(413)
        try:
            body = self.rfile.read(size)
        except TimeoutError:
            return self.response(408)
        if len(body) != size:
            return self.response(400)
        if publish:
            address, descriptor = body[:SHORT_ADDRESS_BYTES], body[SHORT_ADDRESS_BYTES:]
            try:
                address = address.decode("ascii")
            except UnicodeDecodeError:
                return self.response(400)
            return self.directory(
                {"op": "publish", "address": address, "descriptor": descriptor.hex()}
            )
        try:
            result = submit(self.server.submit_socket, body)
        except (OSError, ValueError, struct.error):
            return self.response(503)
        if result is None:
            return self.response(422, b'{"status":"rejected"}')
        self.response(202, json.dumps(result).encode("ascii"))

    def directory(self, request):
        if self.server.recipient_directory is None:
            return self.response(503)
        if request["op"] == "publish":
            now = time.monotonic()
            if now < self.server.next_publish:
                return self.response(429)
            self.server.next_publish = now + 0.25
        try:
            result = self.server.recipient_directory.request(request)
        except (OSError, ValueError):
            return self.response(503)
        status = 200
        if "error" in result:
            status = 409 if request["op"] == "page" else 422
        self.response(status, json.dumps(result, separators=(",", ":")).encode("ascii"))


class Bridge(HTTPServer):
    def __init__(self, port, export, submit_socket, recipient_directory=None):
        self.export = export.resolve(strict=True)
        self.submit_socket = submit_socket
        self.recipient_directory = recipient_directory
        self.next_publish = 0
        super().__init__(("127.0.0.1", port), Handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--export", required=True, type=Path)
    parser.add_argument("--submit-socket", required=True, type=Path)
    parser.add_argument("--directory-helper", required=True, type=Path)
    parser.add_argument("--genesis", required=True)
    args = parser.parse_args()
    if not re.fullmatch(HASH, args.genesis):
        parser.error("Expected lowercase genesis hash")
    with (args.export / "wallet-head.json").open("rb") as source:
        head_bytes = source.read(2049)
    if len(head_bytes) > 2048:
        parser.error("Wallet export head exceeds its size limit")
    head = json.loads(head_bytes)
    if not isinstance(head, dict) or head.get("genesis") != args.genesis:
        parser.error("Wallet export does not match the isolated genesis pin")
    directory = RecipientDirectory(args.directory_helper, args.genesis)
    try:
        with Bridge(args.port, args.export, args.submit_socket, directory) as server:
            server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        directory.close()


if __name__ == "__main__":
    main()
