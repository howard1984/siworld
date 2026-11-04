import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {resolve, sep} from 'node:path';
const root = pathToFileURL(resolve(process.env.WALLET_WEB_OUTPUT) + sep);
const {initSync, BrowserWallet} = await import(new URL('sdk/core/wallet.js', root));
const {WalletAccounts, accountIndex, walletName} = await import(new URL('sdk/wallet-accounts.js', root));
const {transactionRows} = await import(new URL('assets/wallet-history.js', root));
const {parseBackup, backup, bytes} = await import(new URL('sdk/storage.js', root));
initSync({module: readFileSync(new URL('sdk/core/wallet_bg.wasm', root))});
// Public synthetic mnemonic and device password; never use for real funds.
const words = [...Array(23).fill('abandon'), 'art'].join(' ');
const password = 'synthetic-multiple-accounts-password';
const network = '01'.repeat(32);
const sip = '0'.repeat(64);
const locks = new Map();
Object.defineProperty(globalThis, 'navigator', {configurable: true, value: {locks: {request(name, action) {
  const result = (locks.get(name) || Promise.resolve()).then(action);
  locks.set(name, result.catch(() => {})); return result;
}}}});
function memory() {
  const values = new Map();
  const storage = async (store, key, value) => {
    assert.equal(store, 'private');
    if (value !== undefined) values.set(key, new Uint8Array(value));
    return values.has(key) ? new Uint8Array(values.get(key)) : undefined;
  };
  return {values, storage};
}
test('one phrase adds distinct accounts and encrypts local names', async () => {
  const data = memory(), wallet = BrowserWallet.restore(network, 0, words), book = new WalletAccounts(wallet, data.storage);
  const previousFetch = globalThis.fetch;
  globalThis.fetch = () => { throw new Error('Account metadata must not use a network.'); };
  try {
    assert.equal((await book.initialize()).length, 1);
    const second = await book.add(); assert.equal(second.account, 1);
    const third = await book.add(); assert.equal(third.account, 2);
    assert.equal(new Set(third.accounts.map(row => row.info.full_address)).size, 3);
    const renamed = await book.rename(1, 'Miner one'); assert.equal(renamed.accounts[1].name, 'Miner one');
    for (const value of data.values.values()) assert.ok(!new TextDecoder().decode(value).includes('Miner one'));
    const derived = book.derive(1), restored = BrowserWallet.restore(network, 1, words);
    try { assert.equal(derived.public_info(), restored.public_info()); }
    finally {derived.free(); restored.free();}
    assert.throws(() => book.derive(5), /Select/);
  } finally {book.free(); wallet.free(); globalThis.fetch = previousFetch;}
});
test('an encrypted backup restores all indexes and names on another device', async () => {
  const a = memory(), b = memory(), wallet = BrowserWallet.restore(network, 0, words);
  const book = new WalletAccounts(wallet, a.storage); let reopened, imported;
  try {
    await book.initialize(); await book.add(); await book.rename(1, 'Miner two');
    const record = {...backup(network, 0, wallet.seal(password, '')), version: 2, accounts_hex: await book.backup()};
    const parsed = parseBackup(JSON.stringify(record));
    reopened = BrowserWallet.unlock(network, bytes(parsed), password);
    imported = new WalletAccounts(reopened, b.storage);
    const rows = await imported.initialize(parsed.accounts_hex);
    assert.deepEqual(rows.map(row => [row.account, row.name]), [[0, 'Wallet 1'], [1, 'Miner two']]);
    assert.equal(rows[1].info.full_address, book.list()[1].info.full_address);
  } finally {imported?.free(); reopened?.free(); book.free(); wallet.free();}
});
test('restoring another account in the same phrase finds the local registry', async () => {
  const data = memory(), a = BrowserWallet.restore(network, 0, words), b = BrowserWallet.restore(network, 1, words);
  const first = new WalletAccounts(a, data.storage), second = new WalletAccounts(b, data.storage);
  try {
    await first.initialize(); await first.add(); await first.rename(1, 'Mining account');
    const rows = await second.initialize();
    assert.equal(first.key, second.key); assert.equal(rows[1].name, 'Mining account');
    await Promise.all([first.add(), second.add()]);
    const saved = await first.read(); assert.deepEqual(saved.accounts.map(row => row.account), [0, 1, 2, 3]);
  } finally {first.free(); second.free(); a.free(); b.free();}
});
test('damaged and foreign account registries fail without overwriting storage', async () => {
  const data = memory(), a = BrowserWallet.restore(network, 0, words), b = BrowserWallet.restore('02'.repeat(32), 0, words);
  const first = new WalletAccounts(a, data.storage), second = new WalletAccounts(b, data.storage);
  try {
    await first.initialize(); const exported = await first.backup();
    await assert.rejects(second.initialize(exported), /authentication/);
    const prior = data.values.get(first.key); prior[prior.length - 1] ^= 1;
    const damaged = new Uint8Array(prior);
    await assert.rejects(first.add(), /authentication/);
    assert.deepEqual(data.values.get(first.key), damaged);
  } finally {first.free(); second.free(); a.free(); b.free();}
});
test('account names and indexes have bounded unambiguous input', () => {
  for (const value of [-1, 1.5, 0x100000000, NaN, '1']) assert.throws(() => accountIndex(value), /index/);
  for (const value of ['', ' '.repeat(10), 'a'.repeat(49), 'bad\nname', 'bad\u202ename']) assert.throws(() => walletName(value), /characters/);
  assert.equal(walletName('  Miner one  '), 'Miner one');
  assert.equal(walletName('<img src=x>'), '<img src=x>');
});
test('ten wallets can be created and the eleventh preserves the encrypted registry', async () => {
  const data = memory(), wallet = BrowserWallet.restore(network, 0, words), book = new WalletAccounts(wallet, data.storage);
  try {
    await book.initialize();
    for (let account = 1; account < 10; account++) {
      const result = await book.add(); assert.equal(result.account, account);
    }
    assert.equal(book.list().length, 10);
    assert.equal(new Set(book.list().map(row => row.info.full_address)).size, 10);
    let prior = new Uint8Array(data.values.get(book.key));
    await assert.rejects(book.add(), /10 wallets/); assert.deepEqual(data.values.get(book.key), prior);
    assert.equal(book.list().length, 10);
    const reopened = new WalletAccounts(wallet, data.storage);
    try { assert.equal((await reopened.initialize()).length, 10); }
    finally { reopened.free(); }
    await book.write({...book.value, accounts: [{account: 0xffffffff, name: 'Last account'}]});
    prior = new Uint8Array(data.values.get(book.key));
    await assert.rejects(book.add(), /index/); assert.deepEqual(data.values.get(book.key), prior);
  } finally {book.free(); wallet.free();}
});
test('concurrent creation cannot exceed ten wallets', async () => {
  const data = memory(), wallet = BrowserWallet.restore(network, 0, words);
  const first = new WalletAccounts(wallet, data.storage), second = new WalletAccounts(wallet, data.storage);
  try {
    await first.initialize(); for (let i = 1; i < 9; i++) await first.add(); await second.initialize();
    const results = await Promise.allSettled([first.add(), second.add()]);
    assert.equal(results.filter(row => row.status === 'fulfilled').length, 1);
    assert.equal(results.filter(row => row.status === 'rejected' && /10 wallets/.test(row.reason.message)).length, 1);
    assert.deepEqual((await first.read()).accounts.map(row => row.account), Array.from({length: 10}, (_, i) => i));
  } finally {first.free(); second.free(); wallet.free();}
});
test('oversized backup registries fail before overwriting local wallets', async () => {
  const data = memory(), wallet = BrowserWallet.restore(network, 0, words), book = new WalletAccounts(wallet, data.storage);
  try {
    await book.initialize(); await book.rename(0, 'Existing wallet');
    const prior = new Uint8Array(data.values.get(book.key));
    const plain = new TextEncoder().encode(JSON.stringify({...book.value,
      accounts: Array.from({length: 11}, (_, account) => ({account, name: `Wallet ${account + 1}`}))}));
    const bytes = book.anchor.protect_local(plain); plain.fill(0);
    const imported = [...bytes].map(value => value.toString(16).padStart(2, '0')).join('');
    const importing = new WalletAccounts(wallet, data.storage);
    try { await assert.rejects(importing.initialize(imported), /Invalid encrypted wallet list/); }
    finally { importing.free(); }
    assert.deepEqual(data.values.get(book.key), prior); assert.equal(book.list()[0].name, 'Existing wallet');
  } finally {book.free(); wallet.free();}
});
test('merging valid backups cannot exceed ten wallets or overwrite existing names', async () => {
  const data = memory(), otherData = memory(), wallet = BrowserWallet.restore(network, 0, words);
  const current = new WalletAccounts(wallet, data.storage), incoming = new WalletAccounts(wallet, otherData.storage);
  let importer;
  try {
    await current.initialize(); await current.rename(0, 'Keep this name');
    for (let i = 1; i < 10; i++) await current.add();
    await incoming.initialize();
    await incoming.write({...incoming.value, accounts: [...incoming.value.accounts, {account: 10, name: 'Other device'}]});
    const prior = new Uint8Array(data.values.get(current.key));
    importer = new WalletAccounts(wallet, data.storage);
    await assert.rejects(importer.initialize(await incoming.backup()), /Invalid encrypted wallet list/);
    assert.deepEqual(data.values.get(current.key), prior);
    assert.equal((await current.read()).accounts[0].name, 'Keep this name');
  } finally {importer?.free(); current.free(); incoming.free(); wallet.free();}
});
test('history groups reward tranches and keeps each payment and status distinct', () => {
  const note = {id: 'a'.repeat(96), block_id: 'b'.repeat(64), height: 5, timestamp: 500, asset: sip, amount_atoms: '100', unlock_height: 24, spent: false, kind: 'mining'};
  const rows = transactionRows({height: 30, received_records: [note, {...note, id: 'c'.repeat(96), unlock_height: 100}, {...note, id: 'd'.repeat(96), kind: 'received'}],
    payments: [{id: 'synthetic-pending', phase: 'unknown', amount_atoms: '10', fee_atoms: '1', created_at: 600}, {id: 'synthetic-confirmed', phase: 'confirmed', amount_atoms: '11', fee_atoms: '1', confirmed_height: 4, confirmed_timestamp: 400}]});
  assert.equal(rows.length, 4); assert.equal(rows[0].status, 'Status uncertain');
  const reward = rows.find(row => row.title === 'Mining reward');
  assert.equal(reward.amount_atoms, '200'); assert.equal(reward.notes.length, 2); assert.equal(reward.status, 'Locked');
  assert.equal(rows.filter(row => row.direction === 'sent').length, 2);
  assert.equal(rows.find(row => row.title === 'Payment received').amount_atoms, '100');
});

test('history distinguishes coinbase maturity from scheduled Holder locks', () => {
  const note = {id: 'a'.repeat(96), block_id: 'b'.repeat(64), height: 1, timestamp: 500, asset: sip,
    amount_atoms: '100', unlock_height: 25, spent: false, kind: 'mining', awaiting_maturity: true};
  let rows = transactionRows({height: 24, received_records: [note]});
  assert.equal(rows[0].status, 'Awaiting maturity');
  rows = transactionRows({height: 25, received_records: [{...note, awaiting_maturity: false}]});
  assert.equal(rows[0].status, 'Confirmed');
  for (const records of [
    [note, {...note, id: 'c'.repeat(96), unlock_height: 100, awaiting_maturity: false}],
    [{...note, id: 'c'.repeat(96), unlock_height: 100, awaiting_maturity: false}, note],
  ]) assert.equal(transactionRows({height: 24, received_records: records})[0].status, 'Locked');
  assert.equal(transactionRows({height: 24, received_records: [{...note, spent: true}]})[0].status, 'Confirmed');
});
