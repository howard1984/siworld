// Synthetic localhost data for visual and interaction checks. No node or wallet access.
import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {dirname, extname, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const types = {'.html': 'text/html', '.mjs': 'text/javascript', '.css': 'text/css'};
export const fixtureNetworks = [
  {name: 'siworld-eng-1', network: '11'.repeat(32), genesis: '22'.repeat(32), api: '/chain/eng1'},
  {name: 'siworld-eng-2', network: '33'.repeat(32), genesis: '44'.repeat(32), api: '/chain/eng2'},
];
const hash = height => height.toString(16).padStart(64, '0');
export function fixtureSnapshot(config = fixtureNetworks[0], scenario = 'full') {
  const now = Math.floor(Date.now() / 1000);
  const empty = scenario === 'empty' || config.name === 'siworld-eng-2';
  const blocks = empty || scenario === 'partial' ? [] : Array.from({length: 101}, (_, i) => {
    const height = 1134 + i;
    return {height, hash: hash(height), parent_hash: hash(height - 1), timestamp: now - (100 - i) * 300 - (i % 7) * 15,
      target: '0000' + 'ff'.repeat(30), slots_including_padding: 576, reward_mode: i % 4 ? 'holder' : 'voyager', work: '65536'};
  });
  return {version: 1, network: config.network, genesis: config.genesis, height: empty ? 0 : 1234,
    tip: empty ? config.genesis : hash(1234), published_unix_seconds: now, blocks,
    economics: {issued_atoms: '56412345678900', burned_atoms: '1234560000', holder_pool_atoms: '2020100000000',
      locked_reward_atoms: '1440123000000', circulating_estimate_atoms: null,
      unlock_schedule: empty ? [] : [{height: 1400, atoms: '120000000000'}, {height: 1500, atoms: '121000000000'}],
      unlock_schedule_complete: true, funds: empty ? [] : [{index: 0, entitled_atoms: '12000000000000', released_atoms: '1000000000000', spent_atoms: '100000000000'}]},
    checkpoint: empty ? null : {height: 1152, hash: hash(1152), issued_unix_seconds: now - 21600, roster: '55'.repeat(32), signer_indices: [0, 1]},
    governance: {current_signers: null, fee_address: null, fund_addresses: null, changes: null}};
}

export async function fixtureServer() {
  let scenario = 'full';
  const requests = [];
  const server = http.createServer(async (request, response) => {
    requests.push({method: request.method, path: request.url});
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    if (request.method !== 'GET') { response.writeHead(405); return response.end(); }
    const path = new URL(request.url, 'http://localhost').pathname;
    if (path === '/assets/siworld-horizontal-on-dark.svg' && process.env.EXPLORER_SITE_ASSETS) {
      try { response.setHeader('Content-Type', 'image/svg+xml');return response.end(await readFile(resolve(process.env.EXPLORER_SITE_ASSETS, 'siworld-horizontal-on-dark.svg'))); }
      catch { response.writeHead(404);return response.end(); }
    }
    if (path === '/explorer-config.json') {
      response.setHeader('Content-Type', 'application/json');
      return response.end(JSON.stringify({version: 1, active: 'siworld-eng-1', networks: fixtureNetworks}));
    }
    const config = fixtureNetworks.find(item => path === item.api + '/v1/explorer');
    if (config) {
      if (scenario === 'delayed') await new Promise(done => setTimeout(done, 2000));
      if (scenario === 'error') { response.writeHead(503); return response.end(); }
      response.setHeader('Content-Type', 'application/json');
      const data = fixtureSnapshot(config, scenario);
      if (scenario === 'identity-error') data.genesis = '99'.repeat(32);
      return response.end(JSON.stringify(data));
    }
    try {
      const relative = path === '/' ? 'index.html' : path.slice(1);
      if (!['index.html', 'explorer.mjs', 'chain-client.mjs', 'projection.mjs', 'explorer.css'].includes(relative)) throw new Error();
      response.setHeader('Content-Type', types[extname(relative)]);
      response.end(await readFile(resolve(root, relative)));
    } catch { response.writeHead(404); response.end(); }
  });
  await new Promise(done => server.listen(0, '127.0.0.1', done));
  return {origin: 'http://127.0.0.1:' + server.address().port, requests,
    setScenario(value) { if (!['full', 'empty', 'partial', 'error', 'identity-error', 'delayed'].includes(value)) throw new Error('Unknown fixture scenario.'); scenario = value; },
    close: () => new Promise(done => server.close(done))};
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const fixture = await fixtureServer();
  process.stdout.write('Synthetic explorer fixture: ' + fixture.origin + '\n');
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', value => {
    try { fixture.setScenario(value.trim()); process.stdout.write('Scenario: ' + value.trim() + '\n'); }
    catch { process.stdout.write('Use full, empty, partial, error, identity-error or delayed.\n'); }
  });
  process.on('SIGINT', async () => { await fixture.close(); process.exit(0); });
}
