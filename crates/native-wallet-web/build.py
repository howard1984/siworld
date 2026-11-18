"""Build the locked portable wallet into an isolated static directory."""
import argparse
import json
import os
import re
import shlex
from pathlib import Path
import shutil
import subprocess
from urllib.parse import urlsplit


def engineering_v2_manifest(data):
    required = {'version', 'name', 'network', 'genesis', 'rules', 'profile', 'fee_mode', 'api', 'read_only'}
    optional = {'apis', 'submission_apis'}
    identifiers = ('network', 'genesis', 'rules', 'profile')
    if (not isinstance(data, dict) or not required <= set(data) or set(data) - required - optional or type(data['version']) is not int or data['version'] != 2
            or data['name'] != 'siworld-eng-2' or type(data['fee_mode']) is not int or data['fee_mode'] != 0
            or data['read_only'] is not True or any(not isinstance(data[key], str)
                or not re.fullmatch('[0-9a-f]{64}', data[key]) or set(data[key]) == {'0'} for key in identifiers)):
        raise ValueError('Pin the exact read-only engineering-v2 network, genesis, rules, native profile and LegacyMiner mode.')
    def origin(value):
        if not isinstance(value, str):
            raise ValueError('An exact engineering-v2 API origin is required.')
        endpoint = urlsplit(value)
        endpoint.port  # Reject invalid or out-of-range ports before invoking tools.
        if (not endpoint.hostname or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment
                or endpoint.path not in ('', '/') or not (endpoint.scheme == 'https' or endpoint.scheme == 'http'
                    and endpoint.hostname in ('localhost', '127.0.0.1', '::1'))
                or not re.fullmatch(r'[A-Za-z0-9.:[\]\-]+', endpoint.netloc)):
            raise ValueError('Use an exact pinned HTTPS or loopback engineering-v2 API origin.')
        host = endpoint.hostname.lower()
        if ':' in host:
            host = '[' + host + ']'
        port = endpoint.port
        suffix = ':' + str(port) if port is not None and port != (443 if endpoint.scheme == 'https' else 80) else ''
        return endpoint.scheme + '://' + host + suffix

    api = origin(data['api'])
    def origins(values):
        if not isinstance(values, list) or not 1 <= len(values) <= 2:
            raise ValueError('Pin one or two independent engineering-v2 API origins.')
        result = [origin(value) for value in values]
        if len(set(result)) != len(result):
            raise ValueError('Engineering-v2 API origins must be unique.')
        return result

    apis = origins(data.get('apis', [api]))
    submission_apis = origins(data.get('submission_apis', apis))
    if apis[0] != api:
        raise ValueError('The primary engineering-v2 API origin must match the first data source.')
    return {**data, 'api': api, 'apis': apis, 'submission_apis': submission_apis,
            'account': 0, 'desktop_send_measured': False}



def engineering_v2_html(text):
    """Label the engineering-v2 page without changing the shared V1 template."""
    replacements = {
        'siworld-eng-1': 'siworld-eng-2', 'SIWORLD-ENG-1': 'SIWORLD-ENG-2',
        'native V1': 'engineering-v2', 'Native V1': 'Engineering-v2',
        'NATIVE V1': 'ENGINEERING-V2', 'V1 ACCOUNT': 'ENGINEERING-V2 ACCOUNT',
        'Your V1 receiving address.': 'Your engineering-v2 receiving address.',
        'Recipient short or full V1 address': 'Recipient full engineering-v2 address',
        'Authenticated compact sync': 'Authenticated receipt sync',
        'Unlock to scan public compact records locally.': 'Unlock to scan authenticated receipts locally.',
        'Paste either address directly into the miner setup. Full addresses work without a directory; enable the short address once to make it resolvable.': 'Use the full receiving address. Short-address publication is unavailable in this build.',
        'Enable the short address before using it. This publishes only its matching public full address; no recovery words, private keys or viewing keys leave this device.': 'Use the full receiving address. Short-address publication is unavailable in this build.',
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--network-manifest', type=Path)
    parser.add_argument('--eng2-manifest', type=Path, help='Explicit read-only engineering-v2 context; incompatible with legacy manifests and fixtures.')
    parser.add_argument('--wasm-bindgen', default='wasm-bindgen')
    parser.add_argument('--rules-file', type=Path)
    parser.add_argument('--chain-api')
    parser.add_argument('--vault-manifest', type=Path)
    parser.add_argument('--wasm-simd', action='store_true')
    parser.add_argument('--wasm-threads', action='store_true', help='Experimental; requires a build-std capable Rust toolchain and isolated HTTPS headers.')
    parser.add_argument('--target-dir', type=Path)
    parser.add_argument('--browser-fixtures', action='store_true', help='Synthetic local measurements only; incompatible with a deployment manifest.')
    args = parser.parse_args()
    crate = Path(__file__).resolve().parent
    output = args.output.resolve()
    if output.exists():
        raise SystemExit('Output must be a fresh directory; existing files are preserved.')
    manifest = None
    if args.eng2_manifest and (args.network_manifest or args.browser_fixtures or args.rules_file or args.chain_api or args.vault_manifest):
        raise SystemExit('Engineering-v2 builds cannot use legacy rules, manifests, endpoints or synthetic fixture mode.')
    if args.browser_fixtures and args.network_manifest:
        raise SystemExit('Synthetic fixture builds cannot use a deployment manifest.')
    if args.eng2_manifest:
        manifest = engineering_v2_manifest(json.loads(args.eng2_manifest.read_text()))
    if args.network_manifest:
        data = json.loads(args.network_manifest.read_text())
        network = data.get('network')
        if not isinstance(network, str) or len(network) != 64 or any(c not in '0123456789abcdef' for c in network) or set(network) == {'0'}:
            raise SystemExit('Manifest must contain a nonzero native network ID.')
        genesis=data.get('genesis_id')
        if data.get('name')!='siworld-eng-1' or not isinstance(genesis,str) or len(genesis)!=64 or any(c not in '0123456789abcdef' for c in genesis) or not args.rules_file or not args.chain_api:
            raise SystemExit('Pin siworld-eng-1, genesis_id, the public rules file and an exact chain API origin.')
        from urllib.parse import urlsplit
        endpoint=urlsplit(args.chain_api)
        if not endpoint.hostname or not re.fullmatch(r'[A-Za-z0-9.:[\]\-]+',endpoint.netloc) or endpoint.username or endpoint.password or endpoint.path not in ('','/') or endpoint.query or endpoint.fragment or not (endpoint.scheme=='https' or endpoint.scheme=='http' and endpoint.hostname=='localhost'):
            raise SystemExit('Use an exact HTTPS chain origin or loopback origin for local validation.')
        rules=args.rules_file.read_bytes()
        if rules[:8]==b'SWNDv4\0\0':
            rules=rules[8:]
        if len(rules)<34 or rules[:32].hex()!=network or rules[33]!=0:
            raise SystemExit('Public rules must bind the engineering network without fixture timings.')
        manifest = {'name':'siworld-eng-1','network':network,'genesis':genesis,'rules_hex':rules.hex(),'api':args.chain_api.rstrip('/'),'account':0,'desktop_send_measured':True}
    version = subprocess.check_output([args.wasm_bindgen, '--version'], text=True).strip()
    if version != 'wasm-bindgen 0.2.120':
        raise SystemExit('Use wasm-bindgen-cli 0.2.120.')
    environment = os.environ.copy()
    encoded = environment.get('CARGO_ENCODED_RUSTFLAGS')
    flags = [value for value in encoded.split('\x1f') if value] if encoded is not None else shlex.split(environment.get('RUSTFLAGS', ''))
    flags.extend(['--remap-path-prefix=' + str(Path.home()) + '=/build',
                  '--remap-path-prefix=' + str(crate.parents[1]) + '=/src/siworld'])
    features = []
    if args.wasm_simd:
        features.append('+simd128')
    if args.wasm_threads:
        features.extend(['+atomics', '+bulk-memory', '+mutable-globals'])
    if features:
        flags.extend(['-C', 'target-feature=' + ','.join(features)])
    environment['CARGO_ENCODED_RUSTFLAGS'] = '\x1f'.join(flags)
    target = (args.target_dir or crate / 'target').resolve()
    command = ['cargo', 'rustc' if args.wasm_threads else 'build', '--lib', '--locked', '--release', '--target', 'wasm32-unknown-unknown', '--target-dir', str(target), '--manifest-path', str(crate / 'Cargo.toml')]
    cargo_features = []
    if args.browser_fixtures:
        cargo_features.append('browser-fixtures')
    if args.wasm_threads:
        cargo_features.append('wasm-parallel')
        command.extend(['-Z', 'build-std=std,panic_abort'])
    if cargo_features:
        command.extend(['--features', ','.join(cargo_features)])
    if args.wasm_threads:
        command.extend(['--', '-C', 'link-arg=--shared-memory', '-C', 'link-arg=--import-memory', '-C', 'link-arg=--max-memory=2147483648',
                        '-C', 'link-arg=--export=__heap_base', '-C', 'link-arg=--export=__data_end',
                        '-C', 'link-arg=--export=__wasm_init_tls', '-C', 'link-arg=--export=__tls_size',
                        '-C', 'link-arg=--export=__tls_align', '-C', 'link-arg=--export=__tls_base'])
    subprocess.run(command, check=True, env=environment)
    shutil.copytree(crate / 'web', output)
    core = output / 'sdk/core'
    subprocess.run([args.wasm_bindgen, '--target', 'web', '--out-dir', str(core), '--out-name', 'wallet', str(target / 'wasm32-unknown-unknown/release/siworld_native_wallet_web.wasm')], check=True)
    binary = (core / 'wallet_bg.wasm').read_bytes()
    if manifest:
        (output / 'sdk/network.js').write_text('export const ENGINEERING = ' + json.dumps(manifest) + ';\n')
        if manifest['name'] == 'siworld-eng-2':
            shutil.copyfile(crate / 'web/sdk/eng2-custody.js', output / 'sdk/storage.js')
            page = output / 'wallet.html'
            page.write_text(engineering_v2_html(page.read_text()))
    if manifest:
        sources = list(dict.fromkeys(manifest.get('apis', [manifest['api']]) + manifest.get('submission_apis', [])))
        html=(output/'wallet.html').read_text().replace("connect-src 'self';", "connect-src 'self' " + ' '.join(sources) + ";")
        (output/'wallet.html').write_text(html)
    if args.vault_manifest:
        vault=json.loads(args.vault_manifest.read_text())
        from urllib.parse import urlsplit
        if set(vault)!= {'api','application','wallet_application'}:
            raise SystemExit('Vault configuration requires separate API, application and wallet application URLs.')
        urls=[urlsplit(vault[k]) for k in ['api','application','wallet_application']]
        for url in urls:
            if not url.hostname or not re.fullmatch(r'[A-Za-z0-9.:[\]\-]+',url.netloc) or url.username or url.password or url.query or not (url.scheme=='https' or url.scheme=='http' and url.hostname=='localhost'):
                raise SystemExit('Use pinned HTTPS or local validation URLs without credentials or query values.')
        if (urls[1].scheme,urls[1].netloc)==(urls[2].scheme,urls[2].netloc):
            raise SystemExit('Wallet and Vault application origins must differ.')
        (output/'sdk/vault-network.js').write_text('export const VAULT = '+json.dumps(vault)+';\n')
        html=(output/'vault.html').read_text().replace("connect-src 'self';", "connect-src 'self' " + vault['api'].rstrip('/') + ";")
        (output/'vault.html').write_text(html)
    if args.wasm_threads:
        # The pinned no-bundler thread adapter spawns its same-origin worker from a blob.
        for name in ['wallet.html', 'vault.html']:
            page = output / name
            page.write_text(page.read_text().replace("worker-src 'self';", "worker-src 'self' blob:;"))
    print(json.dumps({'wasm_bytes': len(binary), 'network_configured': manifest is not None, 'wasm_simd': args.wasm_simd, 'wasm_threads': args.wasm_threads}))


if __name__ == '__main__':
    main()
