import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { resolve, sep } from 'node:path';
if (!process.env.WALLET_WEB_OUTPUT) throw new Error('Set WALLET_WEB_OUTPUT to the built wallet directory.');
const root = pathToFileURL(resolve(process.env.WALLET_WEB_OUTPUT) + sep);
const { initSync, seal_content, open_content, BrowserWallet } = await import(new URL('sdk/core/wallet.js', root));
const { contentBackup, contentBytes, parseContentBackup, contentId, DB_NAME } = await import(new URL('sdk/content-storage.js', root));
initSync({ module: readFileSync(new URL('sdk/core/wallet_bg.wasm', root)) });
const network = '03'.repeat(32), password = 'synthetic-content-password';
const seal = (secret = 'Disposable test content') => seal_content(network, 7, '1700000000000', 0, 'Synthetic title', secret, password);

test('actual WASM seals fixed-width randomized packages with encrypted metadata', () => {
  const a = seal(), b = seal();
  assert.equal(a.length, 4160); assert.notDeepEqual(a, b);
  assert.equal(Buffer.from(a).includes(Buffer.from('Synthetic title')), false);
  const data = JSON.parse(open_content(network, 7, a, password));
  assert.deepEqual(data, { title: 'Synthetic title', secret: 'Disposable test content', kind: 0, created_at: '1700000000000' });
});
test('actual WASM rejects wrong passphrases, context and ciphertext tampering', () => {
  const bytes = seal();
  assert.throws(() => open_content(network, 7, bytes, 'incorrect-password'), /passphrase|damaged/);
  assert.throws(() => open_content('04'.repeat(32), 7, bytes, password), /different network/);
  assert.throws(() => open_content(network, 8, bytes, password), /different network/);
  for (const at of [0, 8, 24, 48, 4159]) {
    const changed = bytes.slice(); changed[at] ^= 1;
    assert.throws(() => open_content(network, 7, changed, password));
  }
});
test('encrypted content backups restore independently of wallet seed backups', async () => {
  const bytes = seal(), backup = contentBackup(network, 7, bytes);
  const text = JSON.stringify(backup), restored = parseContentBackup(text);
  assert.doesNotMatch(text, /Synthetic title|Disposable test content|synthetic-content-password/);
  assert.equal(JSON.parse(open_content(restored.network, restored.account, contentBytes(restored), password)).secret, 'Disposable test content');
  assert.equal(await contentId(backup), await contentId(restored));
  assert.notEqual(DB_NAME, 'siworld-native-v1');
  assert.throws(() => parseContentBackup(JSON.stringify({ ...backup, secret: 'plaintext' })), /Invalid/);
  // Public synthetic test mnemonic; never use this phrase for real funds.
  const words = [...Array(23).fill('abandon'), 'art'].join(' '), wallet = BrowserWallet.restore(network, 7, words);
  try { assert.throws(() => open_content(network, 7, wallet.seal(password, ''), password), /Invalid/); }
  finally { wallet.free(); }
  assert.throws(() => BrowserWallet.unlock(network, bytes, password), /Invalid/);
});
test('backup validation rejects legacy, oversized and malformed files before decryption', () => {
  const backup = contentBackup(network, 7, seal());
  for (const update of [{ network: '0'.repeat(64) }, { account: -1 }, { account: 1.5 }, { account: 2 ** 32 },
      { envelope_hex: backup.envelope_hex.slice(2) }, { envelope_hex: backup.envelope_hex.toUpperCase() }, { version: 2 }]) {
    assert.throws(() => parseContentBackup(JSON.stringify({ ...backup, ...update })), /Invalid/);
  }
  assert.throws(() => parseContentBackup('x'.repeat(10001)), /too large/);
  assert.throws(() => parseContentBackup('{'), /Invalid/);
  assert.throws(() => parseContentBackup(JSON.stringify({ format: 'siworld-vault-local', version: 1 })), /Invalid/);
});
test('payload limits apply to UTF-8 bytes and invalid EVM keys are rejected', () => {
  assert.throws(() => seal('x'.repeat(2049)), /size/);
  assert.throws(() => seal('\u00e9'.repeat(1025)), /size/);
  assert.equal(JSON.parse(open_content(network, 7, seal('x'.repeat(2048)), password)).secret.length, 2048);
  assert.throws(() => seal_content(network, 7, '1700000000000', 2, 'Synthetic key', '0'.repeat(64), password));
  assert.throws(() => seal_content(network, 7, '1700000000000', 0, 'Synthetic title', 'text', 'short'), /passphrase/);
});
test('Wallet and Vault preserve independent origins and explicit backup separation', () => {
  const html = readFileSync(new URL('wallet.html', root), 'utf8');
  assert.match(html, /data-view="wallet"/); assert.match(html, /data-view="vault"/);
  assert.match(html, /wallet recovery words do not recover Vault/);
  assert.match(html, /Chain storage and network fees are not connected/);
  assert.match(html, /connect-src 'self'/);
  for (const path of ['assets/native-vault.js', 'sdk/content-storage.js', 'sdk/content-worker.js']) {
    const source = readFileSync(new URL(path, root), 'utf8');
    assert.doesNotMatch(source, /console\.|fetch\(|XMLHttpRequest|sendBeacon|WebSocket|localStorage|\.innerHTML\s*=/);
  }
});
