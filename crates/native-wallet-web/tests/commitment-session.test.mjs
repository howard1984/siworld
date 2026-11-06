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
  append_compact(bytes) { return this.append(bytes); }
  check_head(height, tip, previous) {
    if (previous.freed) throw new Error('Previous frontier was freed.');
    if (String(this.height) !== height || id(this.height) !== tip || this.height < previous.height) throw new Error('Insufficient work.');
  }
  sealed_cache() { return encoder.encode('sealed:' + this.height); }
  free() { this.freed=true; }
}
function fixture() {
  const saved = new Map(), records = [], requested = [], writes = [];
  let failAt = 0;
  const io = {
    storage: async (store, key, value) => {
      if (store === 'compact') { assert.equal(value,undefined); return undefined; }
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

test('cancellation retains a verified shared prefix without declaring readiness', async () => {
  const f = fixture(), session = new CommitmentSession(anchor, config, Tree, f.io);
  const controller = new AbortController();
  await session.initialize();
  await assert.rejects(session.sync(head(3), controller.signal, () => controller.abort()), {name:'AbortError'});
  assert.equal(JSON.parse(session.tree.summary()).height, 1);
  const restored = new CommitmentSession(anchor, config, Tree, f.io);
  assert.equal((await restored.initialize()).height, 1);
  const before = f.records.length;
  await restored.sync(head(3));
  assert.equal(f.records.length - before, 2);
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
  assert.equal(f.records.length,before);assert.equal(view.tree.summary(),session.tree.summary());view.release();
});
test('older birthday reconstruction preserves the later encrypted frontier', async () => {
  const f=fixture(),session=new CommitmentSession(anchor,config,Tree,f.io);
  await session.initialize();await session.sync(head(4));
  const saved=[...f.saved.values()][0].slice(),writes=f.writes.length;
  const view=await session.atHeight(head(4),2);
  assert.equal(view.height,2);assert.equal(view.downloaded_bytes,8);assert.notEqual(view.tree,session.tree);
  assert.equal(JSON.parse(session.tree.summary()).height,4);assert.equal(f.writes.length,writes+1);
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

test('an earlier birthday reuses its encrypted boundary after another account advances history', async () => {
  const f=fixture(), session=new CommitmentSession(anchor,config,Tree,f.io);
  await session.initialize();
  (await session.atHeight(head(5),2)).release();
  (await session.atHeight(head(5),4)).release();
  const restored=new CommitmentSession(anchor,config,Tree,f.io);
  await restored.initialize();
  const before=f.records.length;
  const view=await restored.atHeight(head(5),2);
  assert.equal(view.height,2);assert.equal(view.downloaded_bytes,0);
  assert.equal(f.records.length,before);view.release();
  assert.equal(JSON.parse(restored.tree.summary()).height,4);
});

test('an unavailable projection falls back once to authenticated compact input and erases it', async () => {
  const f=fixture(), calls=[], raw=[];
  const binary=async url=>{
    calls.push(url);
    if(url.includes('/commitments/'))throw Object.assign(new Error('Unavailable.'),{status:400});
    assert.match(url,/\/compact\//);
    const bytes=Uint8Array.of(Number('0x'+url.split('/').at(-1)),17,18,19);
    raw.push(bytes);return {bytes};
  };
  const session=new CommitmentSession(anchor,config,Tree,{...f.io,binary});
  await session.initialize();const view=await session.atHeight(head(3),3);
  assert.equal(view.height,3);assert.equal(view.downloaded_bytes,12);view.release();
  assert.equal(calls.filter(url=>url.includes('/commitments/')).length,1);
  assert.equal(calls.filter(url=>url.includes('/compact/')).length,3);
  assert.ok(raw.every(bytes=>bytes.every(value=>value===0)));
});

test('projection authentication errors fail closed without compact fallback', async () => {
  const f=fixture();f.fail(1);
  const session=new CommitmentSession(anchor,config,Tree,f.io);
  await session.initialize();
  await assert.rejects(session.sync(head(2)),/continuity/);
  assert.ok(f.requested.every(url=>!url.includes('/compact/')));
  assert.equal(f.writes.length,0);
});

test('a cancelled birthday remains reusable after a later account catches up', async () => {
  const f=fixture(), session=new CommitmentSession(anchor,config,Tree,f.io), controller=new AbortController();
  await session.initialize();
  await assert.rejects(session.atHeight(head(4),2,controller.signal,()=>controller.abort()),{name:'AbortError'});
  // Cancellation happened at the first block, before the original boundary.
  assert.equal(JSON.parse(session.tree.summary()).height,1);
  let view=await session.atHeight(head(4),4);view.release();
  const before=f.records.length;
  view=await session.atHeight(head(4),2);view.release();
  assert.equal(f.records.length,before);
});

test('registered birthdays survive an interrupted scan and a new worker session', async () => {
  const f=fixture(), first=new CommitmentSession(anchor,config,Tree,f.io), controller=new AbortController();
  await first.initialize();
  await assert.rejects(first.atHeight(head(4),2,controller.signal,()=>controller.abort()),{name:'AbortError'});
  first.free();
  const later=new CommitmentSession(anchor,config,Tree,{...f.io,birthdays:[2,4]});
  await later.initialize();(await later.atHeight(head(4),4)).release();
  const restored=new CommitmentSession(anchor,config,Tree,f.io);
  await restored.initialize();const before=f.records.length;
  const view=await restored.atHeight(head(4),2);
  assert.equal(view.height,2);assert.equal(view.downloaded_bytes,0);view.release();
  assert.equal(f.records.length,before);
  assert.equal(JSON.parse(restored.tree.summary()).height,4);
});

test('retained birthday snapshots fail closed when their historical prefix is invalid', async () => {
  const f=fixture(),session=new CommitmentSession(anchor,config,Tree,{...f.io,birthdays:[2,4]});
  await session.initialize();f.fail(2);
  await assert.rejects(session.atHeight(head(4),4),/continuity/);
  assert.equal(f.writes.length,0);
  assert.equal(JSON.parse(session.tree.summary()).height,0);
  assert.ok(f.records.every(bytes=>bytes.every(value=>value===0)));
});

test('historical boundary registration rejects invalid heights and deduplicates accounts', () => {
  const f=fixture();
  for(const birthdays of [[-1],[1.5],[1000001],['2'],[null],false]) {
    assert.throws(()=>new CommitmentSession(anchor,config,Tree,{...f.io,birthdays}),/boundar/);
  }
  const session=new CommitmentSession(anchor,config,Tree,{...f.io,birthdays:[0,2,2]});
  session.rememberBirthdays([2,4]);
  assert.deepEqual([...session.birthdays],[2,4]);
});

test('birthday snapshots use the current frontier after periodic checkpoints replace it', async () => {
  const f=fixture(),session=new CommitmentSession(anchor,config,Tree,{...f.io,birthdays:[18,20]});
  await session.initialize();(await session.atHeight(head(20),20)).release();
  const before=f.records.length,view=await session.atHeight(head(20),18);
  assert.equal(view.height,18);assert.equal(view.downloaded_bytes,0);view.release();
  assert.equal(f.records.length,before);
  assert.equal(JSON.parse(session.tree.summary()).height,20);
});

test('long shared history persists checked prefixes before the requested head', async () => {
  const f=fixture(),session=new CommitmentSession(anchor,config,Tree,f.io);
  await session.initialize();
  await session.sync(head(20),undefined,row=>{
    if(row.height===16) assert.equal(decoder.decode(f.saved.get(session.key)),'sealed:16');
  });
  assert.equal(decoder.decode(f.saved.get(session.key)),'sealed:20');
});
