import {test} from 'node:test';
import {readFileSync} from 'node:fs';
import assert from 'node:assert/strict';
import {context, backup, parseBackup, vaultBytes, FORMAT, MAX_BACKUP} from './protocol.mjs';
import {ReceiveSession} from './session.mjs';
const pin = {name:'siworld-eng-2',network:'a1'.repeat(32),genesis:null,account:0,birth_height:0,receive_only:true,origin:'http://127.0.0.1:8879',context_sha256:'b2'.repeat(32)};
const cipher = () => Uint8Array.from(Buffer.from('53574e564c543031' + '00'.repeat(124),'hex'));
function fakeCore() {
  const counts = {created:0,freed:0,unlocked:0};
  const wallet = () => ({recovery_words:() => Array(24).fill('synthetic').join(' '),backup_positions:() => [1,8,24],
    seal:(_password, answers) => { if (answers !== 'synthetic synthetic synthetic') throw Error('Backup answers do not match.'); return cipher(); },
    public_info:() => JSON.stringify({network:pin.network,account:0,balance_status:'unavailable',send_available:false,full_address:'synthetic-public-address'}),
    free:() => counts.freed++});
  return {counts, BrowserWallet:{create:(network,account) => { assert.equal(network,pin.network);assert.equal(account,0);counts.created++;return wallet(); },
    unlock:(network,bytes,password) => { assert.equal(network,pin.network);assert.equal(bytes.length,132);if(password!=='synthetic-test-password')throw Error('Wrong password.');counts.unlocked++;return wallet(); }},
    inspect_address:(address,network,resolved) => { assert.equal(resolved,'');return JSON.stringify({network,full_address:address}); }};
}
test('network, origin, genesis and receive-only boundary are pinned', () => {
  assert.equal(context(pin,pin.origin).network,pin.network);
  for (const update of [{name:'siworld-eng-1'},{network:'0'.repeat(64)},{network:'A1'.repeat(32)},{genesis:'c3'.repeat(32)},{account:1},{birth_height:1},{receive_only:false},{api:'https://invalid.example'},{origin:'http://localhost:8879'},{origin:'https://127.0.0.1:8879'},{origin:'http://127.0.0.1'},{origin:pin.origin+'/'}]) {
    assert.throws(() => context({...pin,...update},pin.origin));
  }
  assert.throws(() => context(pin,'http://127.0.0.1:8768'));
  assert.throws(() => context(null,pin.origin));
});
test('backup framing excludes older formats, foreign networks and secret-bearing extra fields', () => {
  const text=backup(pin,cipher()), value=parseBackup(text,pin);
  assert.equal(value.format,FORMAT);assert.equal(vaultBytes(value).length,132);
  for(const update of [{format:'siworld-native-wallet-backup'},{network:'c3'.repeat(32)},{account:1},{birth_height:1},{version:2},{words:'synthetic'},{vault_hex:value.vault_hex+'00'},{vault_hex:'00'.repeat(132)}]) {
    assert.throws(() => parseBackup(JSON.stringify({...value,...update}),pin));
  }
  assert.throws(() => parseBackup('x'.repeat(MAX_BACKUP+1),pin));
  assert.throws(() => parseBackup('[]',pin));
});
test('fake creation requires a challenge and releases material after sealing', () => {
  const core=fakeCore(), session=new ReceiveSession(core,pin,pin.origin);
  assert.throws(() => session.handle('create',['foreign-network']));
  const challenge=session.handle('create');assert.equal(challenge.words.split(' ').length,24);
  assert.throws(() => session.handle('seal',['synthetic-test-password','wrong wrong wrong']));
  assert.equal(core.counts.freed,0);
  const sealed=session.handle('seal',['synthetic-test-password','synthetic synthetic synthetic']);
  assert.equal(core.counts.freed,1);assert.equal(session.wallet,null);
  assert.equal(sealed.info.full_address,'synthetic-public-address');
  assert.throws(() => session.handle('seal',['synthetic-test-password','synthetic synthetic synthetic']));
  assert.equal(session.handle('unlock',[sealed.backup,'synthetic-test-password']).full_address,sealed.info.full_address);
  assert.equal(core.counts.unlocked,1);assert.equal(core.counts.freed,2);
  assert.throws(() => session.handle('unlock',[sealed.backup,'wrong']));
  for(const action of ['restore','send','balance','sync','publish','derive_account'])assert.throws(() => session.handle(action,[]));
});
test('invalid native public results fail closed and free successful ciphertext sessions', () => {
  const core=fakeCore(), original=core.BrowserWallet.create;
  core.BrowserWallet.create=(...args) => {const wallet=original(...args);wallet.public_info=()=>JSON.stringify({network:'c3'.repeat(32),account:0});return wallet;};
  const session=new ReceiveSession(core,pin,pin.origin);session.handle('create');
  assert.throws(() => session.handle('seal',['synthetic-test-password','synthetic synthetic synthetic']));
  assert.equal(core.counts.freed,1);assert.equal(session.wallet,null);
});
test('lock frees pending fake creation and invalid challenges are not displayed', () => {
  const core=fakeCore(), session=new ReceiveSession(core,pin,pin.origin);
  session.handle('create');session.handle('lock');assert.equal(core.counts.freed,1);
  const original=core.BrowserWallet.create;
  core.BrowserWallet.create=(...args)=>{const wallet=original(...args);wallet.backup_positions=()=>[1,1,2];return wallet;};
  assert.throws(()=>session.handle('create'));assert.equal(session.wallet,null);assert.equal(core.counts.freed,2);
});

test('runtime source graph contains no online or persistence client', () => {
  const expected = {'app.mjs':['./context.mjs','./protocol.mjs'],
    'worker.mjs':['./core/wallet.js','./context.mjs','./session.mjs','./protocol.mjs'],
    'session.mjs':['./protocol.mjs'], 'protocol.mjs':[], 'context.mjs':[]};
  for (const [name, dependencies] of Object.entries(expected)) {
    const source=readFileSync(new URL(name,import.meta.url),'utf8');
    assert.deepEqual([...source.matchAll(/from ['"]([^'"]+)['"]/g)].map(value=>value[1]),dependencies);
    assert.doesNotMatch(source,/console\.|localStorage|indexedDB|sessionStorage|XMLHttpRequest|sendBeacon|WebSocket|fetch\(|innerHTML\s*=/);
  }
  const source=readFileSync(new URL('app.mjs',import.meta.url),'utf8');
  assert.match(source,/navigator\.clipboard\.writeText\(\$\('address'\)\.value\)/);
  assert.doesNotMatch(source,/writeText\((?:words|password|answers)/);
});
