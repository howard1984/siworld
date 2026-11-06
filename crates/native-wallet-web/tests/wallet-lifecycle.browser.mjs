// Run only against disposable browser storage and a localhost API. No payments.
import assert from 'node:assert/strict';
import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {resolve, sep, extname} from 'node:path';
import {pathToFileURL} from 'node:url';

if (!process.env.WALLET_WEB_OUTPUT) throw new Error('Set WALLET_WEB_OUTPUT to an unpacked engineering wallet build.');
const root = resolve(process.env.WALLET_WEB_OUTPUT);
const {ENGINEERING: pinned} = await import(pathToFileURL(resolve(root, 'sdk/network.js')));
assert.equal(pinned.name, 'siworld-eng-1');
assert.ok(pinned.network && pinned.genesis && pinned.rules_hex, 'Use supported pinned protocol parameters.');
const {chromium} = await import(process.env.WALLET_PLAYWRIGHT || 'playwright');
let hold = false, held = false, release = () => {}, gate = Promise.resolve();
function stall() { hold = true; held = false; gate = new Promise(done => { release = done; }); }
const requests = [], errors = [];
let origin;
const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, origin);
  requests.push({method: request.method, path: url.pathname});
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  response.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  if (request.method !== 'GET') { response.writeHead(405); return response.end(); }
  if (url.pathname === '/api/v1/head') {
    if (hold) { held = true; await gate; }
    response.setHeader('Content-Type', 'application/json');
    return response.end(JSON.stringify({network:pinned.network, genesis:pinned.genesis, height:0, tip:pinned.genesis}));
  }
  if (url.pathname === '/sdk/network.js') {
    response.setHeader('Content-Type', 'text/javascript');
    return response.end('export const ENGINEERING = ' + JSON.stringify({...pinned, api:origin + '/api', read_only:true, address_directory:false}) + ';');
  }
  try {
    const file = resolve(root, '.' + (url.pathname === '/' ? '/wallet.html' : url.pathname));
    assert.ok(file.startsWith(root + sep));
    response.setHeader('Content-Type', ({'.html':'text/html', '.js':'text/javascript', '.css':'text/css', '.wasm':'application/wasm'})[extname(file)] || 'application/octet-stream');
    response.end(await readFile(file));
  } catch { response.writeHead(404); response.end(); }
});
await new Promise(done => server.listen(0, 'localhost', done));
origin = 'http://localhost:' + server.address().port;
const browser = await chromium.launch({headless:true, ...(process.env.WALLET_BROWSER ? {executablePath:process.env.WALLET_BROWSER} : {})});
try {
  const context = await browser.newContext();
  context.setDefaultTimeout(15000);
  // Force the newer record to sort last, reproducing the original selection bug.
  await context.addInitScript(() => {
    let count = 0;
    crypto.randomUUID = () => [++count === 1 ? '11111111' : 'eeeeeeee', '1111', '4111', '8111', '111111111111'].join('-');
  });
  await context.route('**/*', route => new URL(route.request().url()).origin === origin ? route.continue() : route.abort());
  const page = await context.newPage();
  page.on('pageerror', error => errors.push(error.message));
  const ready = () => page.waitForFunction(() => !document.querySelector('#create').disabled);
  const open = () => page.waitForSelector('#wallet-collection:not([hidden])');
  const waitScan = () => page.waitForFunction(() => document.querySelector('#chain-status').textContent.includes('height 0'));
  async function create(password) {
    await page.click('#create'); await page.click('#next');
    await page.waitForFunction(() => document.querySelectorAll('#words li').length === 24);
    const words = await page.locator('#words li').allTextContents();
    await page.click('#next'); await page.waitForSelector('#answers input');
    await page.evaluate(() => new Promise(done => requestAnimationFrame(() => requestAnimationFrame(done))));
    for (const id of await page.locator('#answers input').evaluateAll(nodes => nodes.map(node => node.id))) {
      await page.fill('#' + id, words[Number(id.split('-')[1]) - 1]);
    }
    words.fill('');
    await page.fill('#password', password); await page.fill('#confirm', password); await page.click('#next');
    await open(); await waitScan();
  }
  async function lock() { await page.click('#lock'); await ready(); }
  async function unlock(password) { await page.click('#open-unlock'); await page.fill('#password', password); await page.click('#next'); }
  await page.goto(origin); await ready();
  const first = 'synthetic first device passphrase';
  const second = '  synthetic second device passphrase \u5bc6\u7801 \u{1f511}  ';
  const firstId = '11111111-1111-4111-8111-111111111111', secondId = 'eeeeeeee-1111-4111-8111-111111111111';
  await create(first); await lock(); await create(second); await lock();
  assert.equal(await page.inputValue('#saved-wallet'), secondId, 'New wallets must remain selected.');
  await page.reload(); await ready();
  assert.equal(await page.inputValue('#saved-wallet'), secondId, 'Selection must survive a reload.');
  await unlock('synthetic incorrect device passphrase');
  await page.waitForFunction(() => document.querySelector('#flow-error').textContent.includes('Incorrect device password'));
  assert.equal(await page.locator('#saved-wallet option').count(), 2);
  await page.fill('#password', second); await page.click('#next'); await open(); await waitScan();
  const address = await page.inputValue('#full-address');
  await page.click('#add-wallet');
  await page.waitForFunction(() => document.querySelector('#account-index').textContent.startsWith('Account 1 '));
  await waitScan();
  const derived = await page.inputValue('#full-address'); assert.notEqual(derived, address);
  stall(); await page.click('#sync-now');
  for (let i = 0; i < 100 && !held; i++) await new Promise(done => setTimeout(done, 20));
  assert.ok(held, 'A real synchronization request must be pending.');
  await page.click('[aria-label="Edit name for account 1"]');
  await page.fill('#wallet-name', 'Synthetic renamed wallet');
  const started = performance.now(); await page.click('#wallet-name-save');
  await page.waitForFunction(() => !document.querySelector('#wallet-name-dialog').open, null, {timeout:2500});
  const renameMs = Math.round(performance.now() - started);
  assert.equal(await page.locator('#account-title').textContent(), 'Synthetic renamed wallet');
  hold = false; release();
  await page.click('[aria-label="Edit name for account 1"]'); await page.fill('#wallet-name', 'a'.repeat(49)); await page.click('#wallet-name-save');
  await page.waitForFunction(() => document.querySelector('#wallet-name-error').textContent.includes('48 visible'));
  assert.equal(await page.locator('#wallet-name-save').isEnabled(), true);
  await page.click('#wallet-name-cancel');
  // Backup requests must also remain usable during a slow balance request.
  await waitScan(); stall(); await page.click('#sync-now');
  for (let i = 0; i < 100 && !held; i++) await new Promise(done => setTimeout(done, 20));
  assert.ok(held);
  const download = page.waitForEvent('download'); await page.click('#export-backup');
  const saved = await download;
  const backupPath = await saved.path();
  const backup = JSON.parse(await readFile(backupPath, 'utf8'));
  hold = false; release();
  assert.equal(backup.version, 2); assert.ok(backup.accounts_hex);
  assert.ok(!JSON.stringify(backup).includes('Synthetic renamed wallet'));
  await waitScan();
  // A sync queued behind a registry lock must be skipped when a rename arrives,
  // even though no network AbortController existed when it was queued.
  await page.evaluate(async address => {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(address)));
    const key = 'wallet-accounts:' + [...digest].map(byte => byte.toString(16).padStart(2, '0')).join('');
    window.testRegistryKey = key;
    let started;
    const acquired = new Promise(resolve => { started = resolve; });
    window.registryHold = navigator.locks.request(key, () => new Promise(resolve => { window.releaseRegistry = resolve; started(); }));
    await acquired;
  }, address);
  const queuedDownload = page.waitForEvent('download'); await page.click('#export-backup');
  await page.waitForFunction(async () => (await navigator.locks.query()).pending.some(lock => lock.name === window.testRegistryKey));
  stall(); await page.click('#sync-now');
  await page.click('[aria-label="Edit name for account 1"]');
  await page.fill('#wallet-name', 'Synthetic renamed wallet'); await page.click('#wallet-name-save');
  await page.evaluate(async () => { window.releaseRegistry(); await window.registryHold; delete window.registryHold; delete window.releaseRegistry; delete window.testRegistryKey; });
  await queuedDownload;
  await page.waitForFunction(() => !document.querySelector('#wallet-name-dialog').open, null, {timeout:2500});
  hold = false; release();
  await lock(); await page.reload(); await ready();
  assert.equal(await page.inputValue('#saved-wallet'), secondId);
  await page.selectOption('#saved-wallet', firstId); await page.reload(); await ready();
  assert.equal(await page.inputValue('#saved-wallet'), firstId, 'Manual selection must survive a reload.');
  await page.click('#open-unlock');
  // The modal authenticates the record shown when it opened.
  await page.locator('#saved-wallet').evaluate((select, id) => { select.value = id; }, secondId);
  await page.fill('#password', first); await page.click('#next'); await open();
  assert.equal(await page.locator('#wallet-count').textContent(), '1 / 10');
  await lock(); await page.selectOption('#saved-wallet', secondId); await unlock(second); await open();
  assert.equal(await page.locator('#wallet-count').textContent(), '2 / 10');
  await page.click('#wallet-list > details:nth-child(2) > summary');
  await page.waitForFunction(() => document.querySelector('#account-index').textContent.startsWith('Account 1 '));
  assert.equal(await page.locator('#account-title').textContent(), 'Synthetic renamed wallet');
  assert.equal(await page.inputValue('#full-address'), derived);
  assert.equal(await page.locator('#send-open').isDisabled(), true);
  const other = await browser.newContext();
  other.setDefaultTimeout(15000);
  await other.route('**/*', route => new URL(route.request().url()).origin === origin ? route.continue() : route.abort());
  const restored = await other.newPage();
  restored.on('pageerror', error => errors.push(error.message));
  await restored.goto(origin);
  await restored.waitForFunction(() => !document.querySelector('#import-backup').disabled);
  await restored.setInputFiles('#backup-file', backupPath);
  await restored.waitForSelector('#password:visible');
  await restored.fill('#password', second); await restored.click('#next');
  await restored.waitForSelector('#wallet-collection:not([hidden])');
  assert.equal(await restored.locator('#wallet-count').textContent(), '2 / 10');
  await restored.click('#wallet-list > details:nth-child(2) > summary');
  await restored.waitForFunction(() => document.querySelector('#account-index').textContent.startsWith('Account 1 '));
  assert.equal(await restored.locator('#account-title').textContent(), 'Synthetic renamed wallet');
  assert.equal(await restored.inputValue('#full-address'), derived);
  await other.close();
  assert.deepEqual(errors, []); assert.ok(requests.every(request => request.method === 'GET'));
  console.log(JSON.stringify({result:'passed', new_wallet_selection:true, reload_selection:true, manual_selection:true,
    wrong_password_rejected:true, retry_correct_password:true, exact_unicode_and_whitespace_password:true,
    unlock_record_captured:true, rename_during_stalled_sync:true, rename_ms:renameMs,
    invalid_name_recovery:true, backup_during_stalled_sync:true, queued_sync_interrupted:true,
    encrypted_backup:true, backup_restored_in_fresh_context:true,
    derived_account_name_and_address_persist:true,
    javascript_errors:0, non_get_requests:0, payments_sent:0}));
} finally {
  release(); await browser.close(); server.closeAllConnections(); await new Promise(done => server.close(done));
}
