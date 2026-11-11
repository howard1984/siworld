"""Package a built wallet into isolated static origins with integrity metadata."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

CSP = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; script-src-attr 'none'; style-src 'self'; style-src-attr 'none'; connect-src 'self'; worker-src 'self'; img-src 'self'; font-src 'self'; media-src 'self'; manifest-src 'none'; frame-src 'none'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"
HEADERS = {
    'Content-Security-Policy': CSP,
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Embedder-Policy': 'require-corp',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Origin-Agent-Cluster': '?1',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), display-capture=()',
    'Strict-Transport-Security': 'max-age=86400',
}


def integrity(data):
    return 'sha384-' + base64.b64encode(hashlib.sha384(data).digest()).decode()


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Pinned input layout differs; no permissive packaging fallback.')
    return text.replace(old, new, 1)


def verify_release(root, expected_manifest_sha256=None):
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Release root must be a regular directory.')
    entries = list(root.rglob('*'))
    if any(p.is_symlink() or not (p.is_dir() or p.is_file()) for p in entries):
        raise ValueError('Unexpected artifact or symbolic link.')
    sizes = [p.stat().st_size for p in entries if p.is_file()]
    if any(n > 64 * 1024 * 1024 for n in sizes) or sum(sizes) > 256 * 1024 * 1024:
        raise ValueError('Release byte limit.')
    manifest_path = root / 'release-manifest.json'
    if manifest_path.stat().st_size > 65536:
        raise ValueError('Manifest byte limit.')
    raw_manifest = manifest_path.read_bytes()
    if expected_manifest_sha256 is not None:
        if not re.fullmatch('[0-9a-f]{64}', expected_manifest_sha256) or hashlib.sha256(raw_manifest).hexdigest() != expected_manifest_sha256:
            raise ValueError('Approved manifest digest differs.')
    manifest = json.loads(raw_manifest)
    app, release = manifest['application'], manifest['release']
    if app not in ('wallet', 'vault') or not re.fullmatch('[0-9a-f]{64}', release):
        raise ValueError('Invalid release identity.')
    prefix = f'releases/{release}/assets/'
    digests = {}
    for name, expected in manifest['assets'].items():
        if not name.startswith(prefix) or not re.fullmatch('[A-Za-z0-9_.-]+', name[len(prefix):]):
            raise ValueError('Invalid artifact path.')
        if integrity((root / name).read_bytes()) != expected:
            raise ValueError('Artifact integrity mismatch.')
        digests[name[len(prefix):]] = expected
    computed = hashlib.sha256(json.dumps(digests, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if computed != release or integrity((root / (app + '.html')).read_bytes()) != manifest['html_integrity']:
        raise ValueError('Release or HTML integrity mismatch.')
    if json.loads((root / 'response-headers.json').read_text()) != HEADERS:
        raise ValueError('Response policy differs.')
    expected_files = set(manifest['assets']) | {app + '.html', 'release-manifest.json', 'response-headers.json'}
    actual_files = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
    if actual_files != expected_files or any(p.is_symlink() for p in root.rglob('*')):
        raise ValueError('Unexpected artifact or symbolic link.')
    return manifest


STATIC_HELPER = '''
let workers = [];
export async function startWorkers(module, memory, builder) {
  const count = builder.numThreads();
  if (!Number.isInteger(count) || count < 1 || count > 4) throw new Error('Invalid proof thread count.');
  workers = [];
  try {
    await Promise.all(Array.from({length: count}, () => new Promise((resolve, reject) => {
      const worker = new Worker(new URL('./rayon-worker.mjs', import.meta.url), {type: 'module'});
      workers.push(worker);
      const timer = setTimeout(() => reject(new Error('Proof thread startup timed out.')), 15000);
      worker.addEventListener('error', () => { clearTimeout(timer); reject(new Error('Proof thread startup failed.')); }, {once: true});
      worker.addEventListener('message', ({data}) => {
        if (data?.type === 'wasm_bindgen_worker_ready') { clearTimeout(timer); resolve(); }
      });
      worker.postMessage({type: 'wasm_bindgen_worker_init', module, memory, receiver: builder.receiver()});
    })));
    builder.build();
  } catch (error) {
    workers.forEach(worker => worker.terminate());
    workers = [];
    throw error;
  }
}
'''

STATIC_RAYON = '''
import init, {wbg_rayon_start_worker} from './sdk/core/wallet.js';
self.addEventListener('message', async ({data}) => {
  if (data?.type !== 'wasm_bindgen_worker_init' || !(data.module instanceof WebAssembly.Module)
      || !(data.memory instanceof WebAssembly.Memory) || !(data.memory.buffer instanceof SharedArrayBuffer))
    throw new Error('Invalid proof thread initialization.');
  await init({module_or_path: data.module, memory: data.memory});
  self.postMessage({type: 'wasm_bindgen_worker_ready'});
  wbg_rayon_start_worker(data.receiver);
}, {once: true});
'''


def stage_input(source, stage):
    shutil.copytree(source, stage)
    core = stage / 'sdk/core/wallet.js'
    wasm = stage / 'sdk/core/wallet_bg.wasm'
    expected = integrity(wasm.read_bytes())
    js = core.read_text()
    js = replace_once(js, 'module_or_path = fetch(module_or_path);',
                      "module_or_path = fetch(module_or_path, {integrity: '" + expected +
                      "', mode: 'same-origin', credentials: 'omit', redirect: 'error'});")
    core.write_text(js)
    helpers = list((stage / 'sdk/core/snippets').glob('wasm-bindgen-rayon-*/src/workerHelpers.no-bundler.js')) if (stage / 'sdk/core/snippets').exists() else []
    if len(helpers) > 1:
        raise ValueError('Ambiguous thread adapter.')
    threaded = bool(helpers)
    if threaded:
        helper = helpers[0]
        old = helper.read_text()
        if 'const pkg = await import(data.mainJS);' not in old or 'URL.createObjectURL(scriptBlob)' not in old:
            raise ValueError('Pinned thread adapter differs.')
        # Preserve the third-party copyright and license notice.
        notice = old[:old.index('*/') + 2]
        helper.write_text(notice.replace('/*', '/*!', 1) + '\n' + STATIC_HELPER)
        (stage / 'rayon-entry.js').write_text(STATIC_RAYON)
    for name in ['worker.js', 'content-worker.js', 'cloud-worker.js']:
        p = stage / 'sdk' / name
        p.write_text(replace_once(p.read_text(), "new URL('./core/wallet_bg.wasm',import.meta.url)",
                                  "new URL('./wallet_bg.wasm',import.meta.url)"))
    changes = {
        'native-wallet.js': ("../sdk/worker.js", './wallet-worker.mjs'),
        'native-vault.js': ("../sdk/content-worker.js", './content-worker.mjs'),
        'cloud-vault.js': ("../sdk/cloud-worker.js", './cloud-worker.mjs'),
    }
    for name, (old, new) in changes.items():
        p = stage / 'assets' / name
        p.write_text(replace_once(p.read_text(), old, new))
    return threaded


def package(source, destination, esbuild):
    if destination.exists():
        raise ValueError('Output must be a fresh directory.')
    version = subprocess.check_output([str(esbuild), '--version'], text=True).strip()
    if version != '0.25.12':
        raise ValueError('Use the pinned esbuild version 0.25.12.')
    with tempfile.TemporaryDirectory(prefix='wallet-release-') as temporary:
        temporary = Path(temporary)
        stage = temporary / 'stage'
        threaded = stage_input(source, stage)
        prepared = temporary / 'release'
        for app, entry, workers in [
            ('wallet', 'assets/native-wallet.js', {'wallet-worker': 'sdk/worker.js'}),
            ('vault', 'assets/vault-application.js', {'content-worker': 'sdk/content-worker.js', 'cloud-worker': 'sdk/cloud-worker.js'}),
        ]:
            app_root = prepared / app
            assets = app_root / 'assets'
            assets.mkdir(parents=True)
            entries = {app: entry, **workers}
            if threaded:
                entries['rayon-worker'] = 'rayon-entry.js'
            meta = temporary / (app + '-meta.json')
            command = [str(esbuild)] + [name + '=' + path for name, path in entries.items()]
            command += ['--bundle', '--platform=browser', '--format=esm', '--target=es2022', '--charset=utf8',
                        '--legal-comments=inline', '--out-extension:.js=.mjs', '--outdir=' + str(assets), '--metafile=' + str(meta)]
            subprocess.run(command, cwd=stage, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            metadata = json.loads(meta.read_text())
            if any(output['imports'] for output in metadata['outputs'].values()):
                raise ValueError('Unbundled JavaScript imports remain.')
            for p in assets.glob('*.mjs'):
                text = p.read_text()
                if re.search(r'\bimport\s*\(', text):
                    raise ValueError('Dynamic imports remain.')
                if p.name.endswith('worker.mjs') and ('createObjectURL' in text or 'new Blob(' in text):
                    raise ValueError('Blob execution remains in a Worker bundle.')
            shutil.copyfile(source / 'sdk/core/wallet_bg.wasm', assets / 'wallet_bg.wasm')
            shutil.copyfile(source / 'assets/native-wallet.css', assets / 'wallet.css')
            digests = {p.name: integrity(p.read_bytes()) for p in sorted(assets.iterdir())}
            release = hashlib.sha256(json.dumps(digests, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            release_root = app_root / 'releases' / release
            release_root.mkdir(parents=True)
            assets.rename(release_root / 'assets')
            html = (source / (app + '.html')).read_text()
            html, count = re.subn(r'<meta http-equiv="Content-Security-Policy"[^>]+>', '', html)
            if count != 1:
                raise ValueError('Missing pinned HTML policy marker.')
            html = replace_once(html, '<link rel="stylesheet" href="assets/native-wallet.css">',
                                '<link rel="stylesheet" href="/releases/' + release + '/assets/wallet.css" integrity="' + digests['wallet.css'] + '" crossorigin="anonymous">')
            original = 'native-wallet.js' if app == 'wallet' else 'vault-application.js'
            html = replace_once(html, '<script type="module" src="assets/' + original + '"></script>',
                                '<script type="module" src="/releases/' + release + '/assets/' + app + '.mjs" integrity="' + digests[app + '.mjs'] + '" crossorigin="anonymous"></script>')
            (app_root / (app + '.html')).write_text(html)
            manifest = {'version': 1, 'application': app, 'release': release, 'threaded': threaded,
                        'assets': {f'releases/{release}/assets/{name}': digest for name, digest in digests.items()},
                        'html_integrity': integrity(html.encode()),
                        'worker_integrity_boundary': 'Static same-origin HTTPS workers; manifest validation is not browser Worker SRI.'}
            (app_root / 'release-manifest.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
            (app_root / 'response-headers.json').write_text(json.dumps(HEADERS, sort_keys=True, indent=2) + '\n')
            verify_release(app_root)
        shutil.copytree(prepared, destination)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--esbuild', type=Path, required=True)
    args = parser.parse_args()
    package(args.input.resolve(), args.output.resolve(), args.esbuild.resolve())
