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
