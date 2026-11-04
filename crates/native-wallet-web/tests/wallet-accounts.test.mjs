import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {resolve, sep} from 'node:path';
const root = pathToFileURL(resolve(process.env.WALLET_WEB_OUTPUT) + sep);
const {initSync, BrowserWallet} = await import(new URL('sdk/core/wallet.js', root));
const {WalletAccounts, accountIndex, walletName, walletBirthday, captureBirthday} = await import(new URL('sdk/wallet-accounts.js', root));
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
    await book.write({...book.value, highest_account:0xffffffff, accounts: [{account: 0xffffffff, name: 'Last account', birth_height:0, created_on:null}]});
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
    await incoming.write({...incoming.value, highest_account:10, accounts: [...incoming.value.accounts, {account: 10, name: 'Other device', birth_height:0, created_on:null}]});
    const prior = new Uint8Array(data.values.get(current.key));
    importer = new WalletAccounts(wallet, data.storage);
    await assert.rejects(importer.initialize(await incoming.backup()), /Invalid encrypted wallet list/);
    assert.deepEqual(data.values.get(current.key), prior);
    assert.equal((await current.read()).accounts[0].name, 'Keep this name');
  } finally {importer?.free(); current.free(); incoming.free(); wallet.free();}
});

test('birthdays and highest account index survive an encrypted backup without plaintext metadata', async () => {
  const firstData=memory(), restoredData=memory(), wallet=BrowserWallet.restore(network,0,words);
  const book=new WalletAccounts(wallet,firstData.storage), restored=new WalletAccounts(wallet,restoredData.storage);
  try {
    await book.initialize('',{birth_height:100,created_on:'2000-01-02'});
    await book.add({birth_height:150,created_on:'2000-01-03'});
    const rows=await restored.initialize(await book.backup());
    assert.deepEqual(rows.map(row=>[row.account,row.birth_height,row.created_on]),[[0,100,'2000-01-02'],[1,150,'2000-01-03']]);
    assert.equal(restored.value.highest_account,1);
    for(const value of firstData.values.values())for(const text of ['birth_height','2000-01-02','highest_account'])assert.ok(!new TextDecoder().decode(value).includes(text));
  }finally{book.free();restored.free();wallet.free();}
});
test('new wallet birthday queries only pinned public head metadata', async () => {
  const config={name:'siworld-eng-1',network,genesis:'03'.repeat(32),api:'https://wallet.invalid/api'};
  const queries=[];
  const result=await captureBirthday(config,network,{date:'2000-01-02',json:async(url,options)=>{
    queries.push(url);assert.equal(options.limit,20000);assert.ok(options.signal instanceof AbortSignal);
    return {network,genesis:config.genesis,tip:'04'.repeat(32),height:123};
  }});
  assert.deepEqual(queries,['https://wallet.invalid/api/v1/head']);
  assert.deepEqual(result,{birth_height:123,created_on:'2000-01-02'});
});
test('unavailable or mismatched birthday metadata falls back to genesis', async () => {
  const config={name:'siworld-eng-1',network,genesis:'03'.repeat(32),api:'https://wallet.invalid/api'};
  const head={network,genesis:config.genesis,tip:'04'.repeat(32),height:123};
  for(const row of [{...head,network:'02'.repeat(32)},{...head,genesis:'05'.repeat(32)},{...head,height:1000001},{...head,height:-1},{...head,tip:'bad'}]){
    assert.deepEqual(await captureBirthday(config,network,{date:'2000-01-02',json:async()=>row}),{birth_height:0,created_on:'2000-01-02'});
  }
  assert.equal((await captureBirthday(config,network,{json:async()=>{throw new Error('Synthetic offline state');}})).birth_height,0);
  let queried=false;
  assert.equal((await captureBirthday({...config,api:'https://user:password@wallet.invalid/api'},network,{json:async()=>{queried=true;}})).birth_height,0);
  assert.equal(queried,false);
});
test('legacy lists migrate with unknown birthdays instead of skipping historical receipts', async () => {
  const data=memory(), wallet=BrowserWallet.restore(network,0,words), book=new WalletAccounts(wallet,data.storage);
  try {
    await book.initialize();
    const legacy={version:1,type:'wallet-accounts',network,accounts:[{account:0,name:'Existing wallet'},{account:3,name:'Existing miner'}]};
    data.values.set(book.key,book.anchor.protect_local(new TextEncoder().encode(JSON.stringify(legacy))));
    const rows=await book.initialize('',{birth_height:200,created_on:'2000-01-02'});
    assert.deepEqual(rows.map(row=>[row.birth_height,row.created_on]),[[0,null],[0,null]]);
    assert.equal(book.value.version,2);assert.equal(book.value.highest_account,3);
    assert.equal((await book.add()).account,4);
  }finally{book.free();wallet.free();}
});
test('backup merge keeps the earliest scan boundary and local name', async () => {
  const data=memory(), importedData=memory(), wallet=BrowserWallet.restore(network,0,words);
  const current=new WalletAccounts(wallet,data.storage), incoming=new WalletAccounts(wallet,importedData.storage);
  try {
    await current.initialize('',{birth_height:200,created_on:'2000-02-02'});await current.rename(0,'Keep local name');
    await incoming.initialize('',{birth_height:100,created_on:'2000-01-02'});
    const rows=await current.initialize(await incoming.backup());
    assert.equal(rows[0].name,'Keep local name');assert.equal(rows[0].birth_height,100);assert.equal(rows[0].created_on,'2000-01-02');
    await current.write({...current.value,highest_account:7});
    assert.equal((await current.add({birth_height:250,created_on:'2000-02-03'})).account,8);
    assert.equal(current.value.highest_account,8);
  }finally{current.free();incoming.free();wallet.free();}
});
test('invalid birthday and highest-index metadata preserve the encrypted registry', async () => {
  const data=memory(),wallet=BrowserWallet.restore(network,0,words),book=new WalletAccounts(wallet,data.storage);
  try {
    await book.initialize();const prior=new Uint8Array(data.values.get(book.key));
    for(const birth_height of [-1,1.5,1000001,NaN,'1'])assert.throws(()=>walletBirthday({birth_height,created_on:null}),/birthday/);
    for(const created_on of ['2000-02-30','2000-13-01','00-01-01','2000-01-01T00:00:00Z',17])assert.throws(()=>walletBirthday({birth_height:1,created_on}),/birthday/);
    assert.throws(()=>walletBirthday({birth_height:1,created_on:null,extra:0}),/birthday/);
    await assert.rejects(book.write({...book.value,highest_account:-1}),/index/);
    assert.throws(()=>book.add({birth_height:-1,created_on:null}),/birthday/);
    assert.deepEqual(data.values.get(book.key),prior);
  }finally{book.free();wallet.free();}
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
