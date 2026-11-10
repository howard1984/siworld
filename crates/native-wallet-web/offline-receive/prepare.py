#!/usr/bin/env python3
"""Prepare or serve a separately pinned, offline receive-only browser tool."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

# Qualified nonfixture CI core. This tool does not rebuild or accept arbitrary WASM.
CORE = {
    'source_commit': '8dc55105f759d329f76dff9faa4f822dc068bf45',
    'ci_run': 42141242204,
    'artifact_id': 13469362663,
    'archive_sha256': 'ba8c55c15aa1bb8b2e4e058e455c6f40e0dc811dcd6ad977f4d8a557762dd224',
    'files': {
        'wallet.js': '49d34e81798bc654d65f0cf3bdb72e4a91be68b9e5ce3fb5e3fa517ab9548dc7',
        'wallet_bg.wasm': '763b63a88f46b907383cf664601feb7a685e7e2e204c5b6956888e9cb01be27d',
    },
}
ASSETS = ('app.mjs', 'context.mjs', 'index.html', 'protocol.mjs', 'session.mjs', 'style.css', 'worker.mjs')
SERVED = set(ASSETS) | {'core/wallet.js', 'core/wallet_bg.wasm'}
SOURCE = Path(__file__).resolve().parent
HEX = re.compile(r'[0-9a-f]{64}')
CSP = "; ".join([
    "default-src 'none'", "script-src 'self' 'wasm-unsafe-eval'", "style-src 'self'",
    "worker-src 'self'", "connect-src 'self'", "img-src 'none'", "object-src 'none'",
    "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'",
])


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_regular(path, maximum=8_000_000):
    """Read one bounded regular file without following its final symlink."""
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
            raise ValueError('A bounded regular file with one link is required.')
        with os.fdopen(descriptor, 'rb', closefd=False) as handle:
            data = handle.read(maximum + 1)
        after = os.fstat(descriptor)
        if len(data) > maximum or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError('The input changed while being read.')
        return data
    finally:
        os.close(descriptor)


def pinned_origin(port):
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError('Use a dedicated unprivileged loopback port.')
    return 'http://127.0.0.1:' + str(port)


def internal_context(raw, expected, origin):
    if not HEX.fullmatch(expected) or digest(raw) != expected:
        raise ValueError('The exact internal context SHA-256 differs.')
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError('The internal context must be an object.')
    recipient = value.get('recipient_wallet', {})
    if not isinstance(recipient, dict):
        raise ValueError('The receive-only context must be an object.')
    network = value.get('network')
    if value.get('version') != 1 or value.get('name') != 'siworld-eng-2' or not isinstance(network, str) or not HEX.fullmatch(network) or network == '0' * 64 or value.get('genesis', False) is not None or value.get('network_parameter_fixed') is not True or recipient.get('receive_only') is not True or recipient.get('online_api', False) is not None or recipient.get('address_directory') is not False or recipient.get('separate_storage_namespace_required') is not True or recipient.get('custody_input_allowed') is not False:
        raise ValueError('An explicit pinned internal receive-only context is required.')
    return {'name': 'siworld-eng-2', 'network': network, 'genesis': None,
            'account': 0, 'birth_height': 0, 'receive_only': True,
            'origin': origin, 'context_sha256': expected}


def write_new(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def prepare(context_file, context_sha256, core_dir, output, port, implementation_commit):
    if not re.fullmatch(r'[0-9a-f]{40}', implementation_commit):
        raise ValueError('Record the reviewed implementation commit.')
    origin = pinned_origin(port)
    pin = internal_context(read_regular(context_file, 16_384), context_sha256, origin)
    files = {name: read_regular(SOURCE / name) for name in ASSETS}
    source_files = {name: digest(data) for name, data in files.items()}
    source_files['prepare.py'] = digest(read_regular(SOURCE / 'prepare.py'))
    for name, expected in CORE['files'].items():
        data = read_regular(Path(core_dir) / name)
        if digest(data) != expected:
            raise ValueError('Use the exact qualified nonfixture CI core.')
        files['core/' + name] = data
    if b'initThreadPool' in files['core/wallet.js']:
        raise ValueError('The receive tool requires the standard nonthreaded core.')
    files['context.mjs'] = ('export const CONTEXT = ' + json.dumps(pin, sort_keys=True, separators=(',', ':')) + ';\n').encode()
    # mkdir fails closed on existing output, including symlinks. Never overwrite a wallet directory.
    output = Path(output)
    output.mkdir(mode=0o700)
    (output / 'core').mkdir(mode=0o700)
    for name, data in files.items():
        write_new(output / name, data)
    manifest = {
        'version': 1, 'kind': 'siworld-eng2-offline-receive-build',
        'implementation_commit': implementation_commit,
        'context_sha256': context_sha256, 'origin': origin,
        'source_sha256': digest(json.dumps(source_files, sort_keys=True, separators=(',', ':')).encode()),
        'source_files': source_files, 'qualified_core': CORE,
        'files': {name: {'sha256': digest(data), 'bytes': len(data)} for name, data in files.items()},
    }
    write_new(output / 'build-manifest.json', (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode())
    return manifest


def load_build(directory):
    directory = Path(directory).absolute()
    if directory.resolve() != directory or not directory.is_dir():
        raise ValueError('Use the original build directory without symlink aliases.')
    manifest = json.loads(read_regular(directory / 'build-manifest.json', 32_768))
    if manifest.get('version') != 1 or manifest.get('kind') != 'siworld-eng2-offline-receive-build' or manifest.get('qualified_core') != CORE or set(manifest.get('files', {})) != SERVED:
        raise ValueError('Invalid offline receive build manifest.')
    origin = manifest.get('origin', '')
    url = urlsplit(origin)
    if url.scheme != 'http' or url.hostname != '127.0.0.1' or not url.port or origin != pinned_origin(url.port):
        raise ValueError('A pinned explicit loopback origin is required.')
    for name, record in manifest['files'].items():
        data = read_regular(directory / name)
        if record != {'sha256': digest(data), 'bytes': len(data)}:
            raise ValueError('Prepared receive assets changed.')
    for name, expected in CORE['files'].items():
        if manifest['files']['core/' + name]['sha256'] != expected:
            raise ValueError('Prepared core differs from the qualified nonfixture core.')
    generated = read_regular(directory / 'context.mjs').decode()
    prefix, suffix = 'export const CONTEXT = ', ';\n'
    if not generated.startswith(prefix) or not generated.endswith(suffix):
        raise ValueError('Invalid generated context module.')
    context = json.loads(generated[len(prefix):-len(suffix)])
    if context.get('origin') != origin or context.get('context_sha256') != manifest.get('context_sha256'):
        raise ValueError('Prepared context differs from its manifest.')
    return directory, manifest


def handler(directory, manifest):
    class ReceiveHandler(BaseHTTPRequestHandler):
        server_version = 'LocalReceive'
        sys_version = ''
        timeout = 10

        def log_message(self, *_args):
            pass  # Request paths, headers, file names and bodies are never logged.

        def end_headers(self):
            for key, value in {
                'Cache-Control': 'no-store', 'Content-Security-Policy': CSP,
                'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
                'Referrer-Policy': 'no-referrer', 'Cross-Origin-Resource-Policy': 'same-origin',
                'Cross-Origin-Opener-Policy': 'same-origin',
                'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
            }.items():
                self.send_header(key, value)
            super().end_headers()

        def send_error(self, code, message=None, explain=None):
            self.send_response(code)
            self.send_header('Content-Length', '0')
            self.send_header('Connection', 'close')
            self.end_headers()
            self.close_connection = True

        def refuse(self):
            self.send_error(405)

        do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_CONNECT = do_TRACE = refuse

        def do_HEAD(self):
            self.get_file(head=True)

        def do_GET(self):
            self.get_file(head=False)

        def get_file(self, head):
            authority = urlsplit(manifest['origin']).netloc
            if self.headers.get_all('Host') != [authority] or self.headers.get('Origin', manifest['origin']) != manifest['origin'] or self.headers.get('Sec-Fetch-Site', 'none') not in ('none', 'same-origin') or self.headers.get('Service-Worker') or self.headers.get('Content-Length', '0') != '0' or self.headers.get('Transfer-Encoding'):
                return self.send_error(403)
            name = 'index.html' if self.path == '/' else self.path[1:]
            if self.path != '/' and self.path != '/' + name or name not in SERVED:
                return self.send_error(404)
            try:
                data = read_regular(directory / name)
                if manifest['files'][name] != {'sha256': digest(data), 'bytes': len(data)}:
                    return self.send_error(409)
            except (ValueError, OSError):
                return self.send_error(409)
            content_type = {'html': 'text/html; charset=utf-8', 'mjs': 'text/javascript; charset=utf-8', 'js': 'text/javascript; charset=utf-8', 'css': 'text/css; charset=utf-8', 'wasm': 'application/wasm'}[name.rsplit('.', 1)[1]]
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            if not head:
                self.wfile.write(data)

    return ReceiveHandler


def serve(directory):
    directory, manifest = load_build(directory)
    port = urlsplit(manifest['origin']).port
    # Binding fails if another process owns the dedicated origin; there is no fallback origin.
    with HTTPServer(('127.0.0.1', port), handler(directory, manifest)) as server:
        print('Offline receive tool: ' + manifest['origin'] + '/', flush=True)
        print('Keep this terminal open. Stop with Ctrl+C after saving and reopening the encrypted backup.', flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest='action', required=True)
    build = actions.add_parser('prepare')
    build.add_argument('--context-file', type=Path, required=True)
    build.add_argument('--context-sha256', required=True)
    build.add_argument('--core', type=Path, required=True)
    build.add_argument('--output', type=Path, required=True)
    build.add_argument('--port', type=int, required=True)
    build.add_argument('--implementation-commit', required=True)
    run = actions.add_parser('serve')
    run.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == 'prepare':
            result = prepare(args.context_file, args.context_sha256, args.core, args.output, args.port, args.implementation_commit)
            print(json.dumps({'origin': result['origin'], 'source_sha256': result['source_sha256'], 'core_wasm_sha256': CORE['files']['wallet_bg.wasm']}))
        else:
            serve(args.directory)
    except (ValueError, OSError, json.JSONDecodeError):
        raise SystemExit('Offline receive preparation or server validation failed. Existing files were preserved.') from None


if __name__ == '__main__':
    main()
