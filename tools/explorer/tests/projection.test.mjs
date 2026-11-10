import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizeProjection, intervalStatistics, difficulty, formatSIP, publicReceipts} from '../projection.mjs';
import {PublicChainClient, boundedJSON, networkConfiguration} from '../chain-client.mjs';

const config = {name: 'siworld-eng-1', network: '11'.repeat(32), genesis: '22'.repeat(32), api: '/chain'};
const origin = 'https://explorer.invalid';
function fixture() {
  const blocks = [1, 2, 3].map(height => ({height, hash: height.toString(16).padStart(64, '0'),
    parent_hash: height === 1 ? config.genesis : (height - 1).toString(16).padStart(64, '0'),
    timestamp: 1_700_000_000 + height * 300, target: 'ff'.repeat(32), slots_including_padding: 576,
    reward_mode: height % 2 ? 'holder' : 'voyager', work: '1'}));
  return {version: 1, network: config.network, genesis: config.genesis, height: 3, tip: blocks.at(-1).hash,
    published_unix_seconds: 1_700_001_000, blocks,
    economics: {issued_atoms: '1000000000', burned_atoms: '0', holder_pool_atoms: '30000000', locked_reward_atoms: '0',
      unlock_schedule: [], unlock_schedule_complete: true, funds: [], circulating_estimate_atoms: null},
    checkpoint: null, governance: {current_signers: null, fee_address: null, fund_addresses: null, changes: null}};
}
function response(value) { return new Response(JSON.stringify(value), {headers: {'content-type': 'application/json'}}); }

test('public projection is network/genesis bound and refuses unsupported fields', () => {
  const value = normalizeProjection(fixture(), config);
  assert.equal(value.blocks.length, 3);
  for (const change of [x => x.network = '33'.repeat(32), x => x.genesis = '33'.repeat(32),
    x => x.fees = '1', x => x.blocks[0].real_transaction_count = 1,
    x => x.economics.address_count = 1, x => x.governance.fee_amount = '1']) {
    const bad = fixture(); change(bad); assert.throws(() => normalizeProjection(bad, config));
  }
});

test('unlinked blocks, false head, malformed amounts and false fund balances are rejected', () => {
  for (const change of [x => x.blocks[1].parent_hash = '44'.repeat(32), x => x.tip = '55'.repeat(32),
    x => x.blocks[0].slots_including_padding = 0, x => x.blocks[0].work = '999', x => x.economics.issued_atoms = '1e10',
    x => x.economics.issued_atoms = (1n << 128n).toString(),
    x => x.economics.unlock_schedule = [{height: 2, atoms: '1'}],
    x => x.economics.funds = [{index: 0, entitled_atoms: '1', released_atoms: '2', spent_atoms: '0'}]]) {
    const bad = fixture(); change(bad); assert.throws(() => normalizeProjection(bad, config));
  }
});

test('interval and work estimates use the same complete timestamp span', () => {
  const blocks = fixture().blocks;
  const measured = intervalStatistics(blocks);
  assert.equal(measured.count, 2); assert.equal(measured.mean, 300);
  assert.equal(measured.estimatedWorkRate, .003);
  assert.equal(difficulty('ff'.repeat(32)), 1);
  assert.equal(intervalStatistics([]), null);
  blocks[1].timestamp = blocks[0].timestamp;
  assert.equal(intervalStatistics(blocks), null);
});

test('SIP formatting does not round integer atoms through floating point', () => {
  assert.equal(formatSIP('1'), '0.00000001');
  assert.equal(formatSIP('100000000'), '1.00000000');
  assert.equal(formatSIP('9007199254740993'), '90,071,992.54740993');
  assert.equal(formatSIP(null), 'Unknown');
});

test('public receipt import rejects wallet fields, duplicate hashes and foreign networks', () => {
  const file = {version: 1, network: config.network, genesis: config.genesis,
    blocks: [{height: 1, hash: '01'.repeat(32), reward_mode: 'holder'}]};
  assert.equal(publicReceipts(file, config).length, 1);
  assert.throws(() => publicReceipts({...file, viewing_key: 'synthetic-disallowed-field'}, config));
  assert.throws(() => publicReceipts({...file, blocks: [...file.blocks, ...file.blocks]}, config));
  assert.throws(() => publicReceipts({...file, genesis: '99'.repeat(32)}, config));
});

test('client sends read-only anonymous requests and validates pinned chain pages', async () => {
  const calls = [];
  const client = new PublicChainClient(config, {origin, request: async (url, options) => {
    calls.push({url, options});
    if (url.includes('/v1/head')) return response({network: config.network, genesis: config.genesis, height: 1, tip: '01'.repeat(32)});
    return response({ids: ['01'.repeat(32)]});
  }});
  const head = await client.head();
  assert.equal((await client.page(head, 1))[0].height, 1);
  for (const {url, options} of calls) {
    assert.equal(new URL(url).origin, origin); assert.equal(options.method, 'GET');
    assert.equal(options.credentials, 'omit'); assert.equal(options.redirect, 'error');
    assert.equal(options.referrerPolicy, 'no-referrer'); assert.equal(options.body, undefined);
  }
  assert.throws(() => networkConfiguration({...config, api: 'https://elsewhere.invalid'}, origin));
  assert.throws(() => networkConfiguration({...config, api: 'http://explorer.invalid'}, origin));
  for (const api of [undefined, '', 0]) assert.throws(() => networkConfiguration({...config, api}, origin));
});

test('body limits apply without a trusted Content-Length', async () => {
  await assert.rejects(boundedJSON(response({large: 'a'.repeat(1000)}), 50), /limit/);
  await assert.rejects(boundedJSON(new Response('{}', {headers: {'content-type': 'text/html'}}), 50), /Unexpected/);
});
