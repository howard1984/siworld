import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { resolve, sep } from 'node:path';
const site = process.env.WALLET_WEB_OUTPUT;
if (!site) throw new Error('Set WALLET_WEB_OUTPUT to the built wallet directory.');
const root = pathToFileURL(resolve(site) + sep);
const { initSync, BrowserWallet, inspect_address } = await import(new URL('sdk/core/wallet.js',root));
const { parseBackup, backup, bytes } = await import(new URL('sdk/storage.js',root));
initSync({ module: readFileSync(new URL('sdk/core/wallet_bg.wasm',root)) });
const network = '01'.repeat(32);
// Public synthetic test mnemonic; never use this phrase for real funds.
const words = [...Array(23).fill('abandon'), 'art'].join(' ');
const password = 'synthetic-browser-password';

test('native mnemonic restores without the legacy PBKDF2 derivation', () => {
  const wallet = BrowserWallet.restore(network, 42, words);
  try {
    const info = JSON.parse(wallet.public_info());
    assert.equal(info.descriptor.address_hex.length, 2464);
    assert.equal(info.descriptor.network, network); assert.equal(info.descriptor.account, 42);
    assert.equal(info.balance_status, 'unavailable'); assert.equal(info.send_available, false);
  } finally { wallet.free(); }
});
test('new wallets require distinct randomized backup answers before use', () => {
  const wallet = BrowserWallet.create(network, 0);
  try {
    const phrase = wallet.recovery_words().split(' '), positions = [...wallet.backup_positions()];
    assert.equal(phrase.length, 24); assert.equal(new Set(positions).size, 3);
    assert.throws(() => wallet.public_info(), /Confirm/);
    assert.throws(() => wallet.seal(password, 'wrong wrong wrong'), /Backup answers/);
    assert.throws(() => wallet.public_info(), /Confirm/);
    const encrypted = wallet.seal(password, positions.map(p => phrase[p-1]).join(' '));
    assert.equal(encrypted.length, 132); assert.throws(() => wallet.recovery_words(), /only during/);
    const reopened = BrowserWallet.unlock(network, encrypted, password);
    try { assert.deepEqual(JSON.parse(reopened.public_info()), JSON.parse(wallet.public_info())); } finally { reopened.free(); }
  } finally { wallet.free(); }
});
test('portable encrypted backup preserves network, account and address', () => {
  const wallet = BrowserWallet.restore(network, 42, words);
  try {
    const record = backup(network, 42, wallet.seal(password, ''));
    const parsed = parseBackup(JSON.stringify(record));
    const reopened = BrowserWallet.unlock(parsed.network, bytes(parsed), password);
    try { assert.deepEqual(JSON.parse(reopened.public_info()), JSON.parse(wallet.public_info())); } finally { reopened.free(); }
    assert.throws(() => BrowserWallet.unlock('02'.repeat(32), bytes(parsed), password), /different network/);
    assert.throws(() => BrowserWallet.unlock(network, bytes(parsed), 'incorrect'), /Incorrect device password/);
  } finally { wallet.free(); }
});
test('full addresses and verified short contacts share one parser', () => {
  const wallet = BrowserWallet.restore(network, 0, words);
  try {
    const info = JSON.parse(wallet.public_info());
    const full = JSON.parse(inspect_address(info.full_address, network, ''));
    assert.equal(full.address_hex, info.descriptor.address_hex);
    assert.equal(JSON.parse(inspect_address(info.short_address, network, info.full_address)).address_hex, full.address_hex);
    assert.throws(() => inspect_address(info.short_address, network, ''), /unresolved/);
    assert.throws(() => inspect_address(info.full_address, '02'.repeat(32), ''), /mismatch/);
    assert.throws(() => inspect_address('tsi1legacy', network, ''), /Legacy/);
  } finally { wallet.free(); }
});
test('backup decoder rejects secrets, oversized input and legacy formats', () => {
  assert.throws(() => parseBackup('x'.repeat(2049)), /too large/);
  assert.throws(() => parseBackup(JSON.stringify({ format: 'siworld-wallet-v0', seed: words })), /Invalid native/);
  const fake = {format:'siworld-native-wallet-backup',version:1,network,account:0,vault_hex:'53574e564c543031'+'00'.repeat(124)};
  assert.doesNotThrow(() => parseBackup(JSON.stringify(fake)));
  assert.throws(() => parseBackup(JSON.stringify({...fake,words})), /Invalid native/);
  assert.throws(() => parseBackup(JSON.stringify({...fake,account:-1})), /Invalid native/);
});
test('UI delegates bounded network operations to its worker without secret-bearing logging', () => {
  const html = readFileSync(new URL('wallet.html',root),'utf8');
  assert.match(html, /connect-src 'self'/); assert.match(html, /form-action 'none'/);
  for (const path of ['assets/native-wallet.js','sdk/worker.js','sdk/storage.js']) {
    const source = readFileSync(new URL(path,root),'utf8');
    assert.doesNotMatch(source, /console\.|fetch\(|XMLHttpRequest|sendBeacon|WebSocket|localStorage/);
    assert.doesNotMatch(source, /\.innerHTML\s*=/);
  }
});
test('WASM matches all twelve original native identity vectors', () => {
  const vectors=JSON.parse(readFileSync(process.env.WALLET_PARITY_OUTPUT,'utf8'));
  assert.equal(vectors.length,12);
  for (const vector of vectors) {
    const wallet=BrowserWallet.restore(vector.network,vector.account,vector.words);
    try { assert.equal(JSON.parse(wallet.public_info()).descriptor.address_hex,vector.address_hex); }
    finally { wallet.free(); }
  }
});
test('browser WASM decrypts an original native wallet vault', () => {
  const vector=JSON.parse(readFileSync(process.env.WALLET_PARITY_VAULT,'utf8'));
  const wallet=BrowserWallet.unlock(vector.network,Uint8Array.from(vector.vault_hex.match(/../g),b=>parseInt(b,16)),'synthetic-native-password');
  try { assert.equal(JSON.parse(wallet.public_info()).descriptor.address_hex,vector.address_hex); }
  finally { wallet.free(); }
});
