"""Build the locked portable V1 wallet into a separate static directory."""
import argparse
import base64
import json
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--network-manifest', type=Path)
    parser.add_argument('--wasm-bindgen', default='wasm-bindgen')
    args = parser.parse_args()
    crate = Path(__file__).resolve().parent
    output = args.output.resolve()
    if output.exists():
        raise SystemExit('Output must be a fresh directory; existing files are preserved.')
    manifest = None
    if args.network_manifest:
        data = json.loads(args.network_manifest.read_text())
        network = data.get('network')
        if not isinstance(network, str) or len(network) != 64 or any(c not in '0123456789abcdef' for c in network) or set(network) == {'0'}:
            raise SystemExit('Manifest must contain a nonzero native network ID.')
        manifest = {'name': 'siworld-eng-1', 'network': network, 'account': 0}
    version = subprocess.check_output([args.wasm_bindgen, '--version'], text=True).strip()
    if version != 'wasm-bindgen 0.2.120':
        raise SystemExit('Use wasm-bindgen-cli 0.2.120.')
    subprocess.run(['cargo', 'build', '--locked', '--release', '--target', 'wasm32-unknown-unknown', '--target-dir', str(crate / 'target'), '--manifest-path', str(crate / 'Cargo.toml')], check=True)
    shutil.copytree(crate / 'web', output)
    core = output / 'sdk/core'
    subprocess.run([args.wasm_bindgen, '--target', 'web', '--out-dir', str(core), '--out-name', 'wallet', str(crate / 'target/wasm32-unknown-unknown/release/siworld_native_wallet_web.wasm')], check=True)
    binary = (core / 'wallet_bg.wasm').read_bytes()
    (core / 'bytes.js').write_text("// Generated from the locked native wallet WASM build.\nexport const wasmBytes = Uint8Array.from(atob('" + base64.b64encode(binary).decode('ascii') + "'), c => c.charCodeAt(0));\n")
    if manifest:
        (output / 'sdk/network.js').write_text('export const ENGINEERING = ' + json.dumps(manifest) + ';\n')
    print(json.dumps({'wasm_bytes': len(binary), 'network_configured': manifest is not None}))


if __name__ == '__main__':
    main()
