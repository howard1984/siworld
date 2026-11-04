import {test} from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {CommitmentSession} from '../web/sdk/commitment-session.js';

Object.defineProperty(globalThis, 'crypto', {value: webcrypto, configurable: true});
Object.defineProperty(globalThis, 'navigator', {value: {locks: {request: async (_key, options, run) => {
  options.signal?.throwIfAborted(); return run();
}}}, configurable: true});
const id = height => height.toString(16).padStart(64, '0');
const config = {name:'siworld-eng-1', network:id(99), genesis:id(0), rules_hex:'synthetic', api:'https://history.invalid/api'};
const anchor = {public_info: () => JSON.stringify({network:config.network, account:0, full_address:'synthetic account-zero address'})};
const encoder = new TextEncoder(), decoder = new TextDecoder();
class Tree {
  constructor(height = 0) { this.height = height; }
  static create() { return new Tree(); }
  static restore(_rules, _genesis, _anchor, bytes) {
    const text = decoder.decode(bytes);
    if (!text.startsWith('sealed:')) throw new Error('Authentication failed.');
    return new Tree(Number(text.slice(7)));
  }
  fork() { return new Tree(this.height); }
  summary() { return JSON.stringify({height:this.height, tip:id(this.height), output_count:3*this.height}); }
  append(bytes) {
    if (bytes[0] !== this.height + 1) throw new Error('Historical work or continuity failed.');
    this.height++;
    return JSON.stringify({...JSON.parse(this.summary()), authentication_ciphertext_bytes:2});
  }
  check_head(height, tip, previous) {
    if (String(this.height) !== height || id(this.height) !== tip || this.height < previous.height) throw new Error('Insufficient work.');
  }
  sealed_cache() { return encoder.encode('sealed:' + this.height); }
  free() {}
}
function fixture() {
  const saved = new Map(), records = [], requested = [], writes = [];
  let failAt = 0;
  const io = {
    storage: async (store, key, value) => {
      assert.equal(store, 'private');
      if (value !== undefined) {
        assert.match(decoder.decode(value), /^sealed:[0-9]+$/);
        writes.push(value.slice()); saved.set(key, value.slice());
      }
      return saved.get(key);
    },
    json: async url => {
      requested.push(url);
      const p = new URL(url).searchParams;
      const from = Number(p.get('from')), end = Number(BigInt('0x' + p.get('tip')));
      return {ids:Array.from({length:Math.min(Number(p.get('limit')), end-from+1)}, (_, i) => id(from+i))};
    },
    binary: async url => {
      requested.push(url); assert.match(url, /\/v1\/commitments\/[0-9a-f]{64}$/);
      const height = Number('0x' + url.split('/').at(-1));
      const bytes = Uint8Array.of(height === failAt ? 255 : height, 17, 18, 19);
      records.push(bytes); return {bytes};
    },
  };
  return {io, saved, records, requested, writes, fail:height => { failAt = height; }};
}
const head = height => ({network:config.network, genesis:config.genesis, height, tip:id(height)});

test('historical authentication downloads only projections and erases every raw record', async () => {
  const f = fixture(), session = new CommitmentSession(anchor, config, Tree, f.io);
  await session.initialize();
  const result = await session.sync(head(3));
  assert.equal(result.downloaded_bytes, 12); assert.equal(result.authentication_ciphertext_bytes, 6);
  assert.equal(result.height, 3); assert.equal(f.writes.length, 1);
  assert.ok(f.records.every(bytes => bytes.every(value => value === 0)));
  assert.ok(f.requested.every(url => !url.includes('/compact/')));
  const restored = new CommitmentSession(anchor, config, Tree, f.io);
  assert.equal((await restored.initialize()).height, 3);
  const before = f.requested.length;
  assert.equal((await restored.sync(head(3))).downloaded_bytes, 0);
  assert.equal(f.requested.length, before);
  assert.equal((await restored.sync(head(4))).downloaded_bytes, 4);
});

test('invalid work preserves the accepted encrypted frontier and erases rejected bytes', async () => {
  const f = fixture(), session = new CommitmentSession(anchor, config, Tree, f.io);
  await session.initialize(); await session.sync(head(1));
  const old = [...f.saved.values()][0].slice(); f.fail(3);
  await assert.rejects(session.sync(head(3)), /continuity/);
  assert.deepEqual([...f.saved.values()][0], old);
  assert.ok(f.records.every(bytes => bytes.every(value => value === 0)));
  assert.equal(JSON.parse(session.tree.summary()).height, 1);
});

test('cancellation leaves no partial candidate persisted', async () => {
  const f = fixture(), session = new CommitmentSession(anchor, config, Tree, f.io);
  const controller = new AbortController();
  await session.initialize();
  await assert.rejects(session.sync(head(3), controller.signal, () => controller.abort()), {name:'AbortError'});
  assert.equal(f.writes.length, 0);
  assert.ok(f.records.every(bytes => bytes.every(value => value === 0)));
});

test('cache authentication and account-zero binding fail closed', async () => {
  const f = fixture(), session = new CommitmentSession(anchor, config, Tree, f.io);
  await session.initialize(); f.saved.set(session.key, encoder.encode('untrusted server snapshot'));
  await assert.rejects(new CommitmentSession(anchor, config, Tree, f.io).initialize(), /Authentication/);
  const other = {public_info:() => JSON.stringify({network:config.network, account:1})};
  await assert.rejects(new CommitmentSession(other, config, Tree, f.io).initialize(), /account-zero/);
});

test('birthday view reuses an authenticated tree without repeating projection downloads', async () => {
  const f=fixture(),session=new CommitmentSession(anchor,config,Tree,f.io);
  await session.initialize();
  let view=await session.atHeight(head(4),3);
  assert.equal(view.height,3);assert.equal(view.downloaded_bytes,12);view.release();
  const before=f.records.length;
  view=await session.atHeight(head(4),3);
  assert.equal(view.downloaded_bytes,0);assert.equal(view.authentication_ciphertext_bytes,0);
  assert.equal(f.records.length,before);assert.equal(view.tree,session.tree);view.release();
});
test('older birthday reconstruction preserves the later encrypted frontier', async () => {
  const f=fixture(),session=new CommitmentSession(anchor,config,Tree,f.io);
  await session.initialize();await session.sync(head(4));
  const saved=[...f.saved.values()][0].slice(),writes=f.writes.length;
  const view=await session.atHeight(head(4),2);
  assert.equal(view.height,2);assert.equal(view.downloaded_bytes,8);assert.notEqual(view.tree,session.tree);
  assert.equal(JSON.parse(session.tree.summary()).height,4);assert.equal(f.writes.length,writes);
  assert.deepEqual([...f.saved.values()][0],saved);view.release();
  assert.ok(f.records.every(bytes=>bytes.every(value=>value===0)));
});
test('malformed birthday indexes fail before downloading history or replacing a frontier', async () => {
  const f=fixture(),session=new CommitmentSession(anchor,config,Tree,{...f.io,json:async()=>({ids:['bad']})});
  await session.initialize();
  await assert.rejects(session.atHeight(head(4),2),/Missing historical/);
  await assert.rejects(session.atHeight(head(4),5),/Invalid historical/);
  assert.equal(f.records.length,0);assert.equal(f.writes.length,0);
});
