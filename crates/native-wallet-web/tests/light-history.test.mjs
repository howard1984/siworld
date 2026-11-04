import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {resolve, sep} from 'node:path';
import {pathToFileURL} from 'node:url';
const root = pathToFileURL(resolve(process.env.WALLET_WEB_OUTPUT) + sep);
const fixture = pathToFileURL(resolve(process.env.WALLET_FIXTURE_DIR) + sep);
const {initSync, BrowserWallet} = await import(new URL('sdk/core/wallet.js', root));
initSync({module: readFileSync(new URL('sdk/core/wallet_bg.wasm', root))});
// Public synthetic chain and mnemonic; this build must never be deployed.
const config = JSON.parse(readFileSync(new URL('fixture.json', fixture)));
const bytes = readFileSync(new URL('block-64.bin', fixture));
test('private history scans real fixture receipts and isolates derived accounts', () => {
  const wallet = BrowserWallet.restore(config.network, 0, config.words);
  const other = wallet.derive_account(1);
  try {
    for (const active of [wallet, other]) {
      active.enable_light(config.rules_hex, config.genesis);
      active.begin_candidate();
      const state = JSON.parse(active.append_compact(bytes));
      assert.ok(Number.isSafeInteger(state.block_timestamp));
      active.commit_candidate(String(state.height), state.tip);
    }
    const history = JSON.parse(wallet.light_history());
    assert.ok(history.length > 0);
    assert.ok(history.every(row => row.amount_atoms !== '0' && Number.isSafeInteger(row.height)));
    assert.ok(history.some(row => row.kind === 'mining'));
    for (const row of history) assert.deepEqual(Object.keys(row).sort(), ['amount_atoms', 'asset', 'block_id', 'height', 'id', 'kind', 'spent', 'unlock_height']);
    assert.deepEqual(JSON.parse(other.light_history()), []);
    const before = wallet.light_history();
    wallet.begin_extension(); assert.throws(() => wallet.append_compact(bytes), /continuity/); wallet.abort_candidate();
    assert.equal(wallet.light_history(), before);
  } finally {wallet.free(); other.free();}
});

const {LightSession} = await import(new URL('sdk/light-session.js', root));
function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return {promise, resolve};
}
function waitingResponse(signal) {
  return new Promise((resolve, reject) => {
    if (signal.aborted) return reject(signal.reason);
    signal.addEventListener('abort', () => reject(signal.reason), {once: true});
  });
}
async function interruptedSync(stage, accepted = false) {
  const originalFetch = globalThis.fetch;
  const navigatorDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
  const started = deferred();
  let requestSignal, persisted = 0;
  const wallet = BrowserWallet.restore(config.network, 0, config.words);
  const session = new LightSession(wallet, config);
  wallet.enable_light(config.rules_hex, config.genesis);
  if (accepted) {
    wallet.begin_candidate();
    const state = JSON.parse(wallet.append_compact(bytes));
    wallet.commit_candidate(String(state.height), state.tip);
  }
  const journal = {version: 1, network: config.network, tip: accepted ? config.rows[0].block_id : config.genesis,
    height: accepted ? 1 : 0, payments: []};
  const previousHistory = wallet.light_history();
  Object.assign(session, {base: 'https://wallet.invalid/api', key: 'synthetic-session', journal});
  session.fresh = async () => {};
  session.persist = async () => { persisted++; };
  Object.defineProperty(globalThis, 'navigator', {configurable: true, value: {locks: {
    request(name, options, action) { options.signal.throwIfAborted(); return action(); }
  }}});
  globalThis.fetch = async (url, options) => {
    if (stage === 'chain' && url.endsWith('/head')) return Response.json({network: config.network,
      genesis: config.genesis, height: 1, tip: config.rows[0].block_id});
    assert.ok(url.endsWith('/head') || url.includes('/chain?'));
    requestSignal = options.signal; started.resolve();
    return waitingResponse(requestSignal);
  };
  try {
    const syncing = session.sync();
    const rejected = assert.rejects(syncing, error => error.name === 'AbortError');
    await started.promise;
    session.cancelSync();
    await rejected;
    assert.equal(requestSignal.aborted, true);
    assert.equal(session.syncing, false);
    assert.equal(session.ready, false);
    assert.equal(session.syncController, null);
    assert.equal(session.journal, journal);
    assert.equal(persisted, 0);
    assert.equal(JSON.parse(wallet.light_balance()).height, journal.height);
    assert.equal(wallet.light_history(), previousHistory);
    // The aborted candidate must not prevent the accepted chain from syncing again.
    globalThis.fetch = async () => Response.json({network: config.network,
      genesis: config.genesis, height: journal.height, tip: journal.tip});
    const resumed = await session.sync();
    assert.equal(resumed.height, journal.height); assert.equal(resumed.ready, true);
    session.cancelSync(); assert.equal(session.ready, true);
  } finally {
    wallet.free(); globalThis.fetch = originalFetch;
    if (navigatorDescriptor) Object.defineProperty(globalThis, 'navigator', navigatorDescriptor);
    else delete globalThis.navigator;
  }
}
test('wallet changes abort a stalled head request without changing accepted state', async () => {
  await interruptedSync('head');
});
test('wallet changes discard a candidate waiting for the chain index and allow retry', async () => {
  await interruptedSync('chain');
});
test('interrupting a later synchronization preserves accepted reward receipts', async () => {
  await interruptedSync('head', true);
});
