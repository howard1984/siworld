import {test} from 'node:test';
import assert from 'node:assert/strict';
import {emptyEng2Rollback,advanceEng2Rollback,selectEng2Rollback,rewindEng2Rollback,persistEng2Rollback,loadEng2Rollback,ENG2_ROLLBACK_CACHE_BYTES} from '../web/sdk/eng2-rollback.js';
import {eng2Storage} from '../web/sdk/eng2-storage.js';

const pin={version:2,name:'siworld-eng-2',network:'1'.repeat(64),genesis:'2'.repeat(64),rules:'3'.repeat(64),profile:'4'.repeat(64),fee_mode:0,api:'http://127.0.0.1:8890'};
const encode=value=>new TextEncoder().encode(JSON.stringify(value));
const decode=bytes=>JSON.parse(new TextDecoder().decode(bytes));
const id=(height,fork=Infinity)=>height===0?pin.genesis:(height+(height>fork?100000:4)).toString(16).padStart(64,'0');
const header=(height,fork=Infinity)=>({height,id:id(height,fork),parent:height===0?null:id(height-1,fork)});
// Synthetic envelope framing only; no cryptographic authentication is claimed.
const seal=(magic,plain)=>{const bytes=new Uint8Array(plain.length+48);bytes.set(new TextEncoder().encode(magic));bytes.set(plain,32);return bytes;};
const protect=plain=>seal('SWE2JL01',plain),open=bytes=>bytes.slice(32,-16);
const cache=(height,fork=Infinity)=>seal('SWE2SC01',encode({height,tip:id(height,fork)}));
const scan=(height,fork=Infinity)=>protect(encode({height,tip:id(height,fork)}));
function grown(height,budget=ENG2_ROLLBACK_CACHE_BYTES){
  let window=advanceEng2Rollback(emptyEng2Rollback(pin),[],cache(0),{budget});
  for(let h=1;h<=height;h++)window=advanceEng2Rollback(window,[header(h)],h%8===0?cache(h):null,{budget});
  return window;
}
function remote(height,oldHeight,fork=Infinity){
  const from=Math.max(1,oldHeight-24),to=Math.min(oldHeight,height);
  return {height,tip:id(height,fork),headers:Array.from({length:Math.max(0,to-from+1)},(_,i)=>header(from+i,fork))};
}
function memory(){
  const data=new Map();let abort=false,writes=0;
  const storage={read:async key=>data.get(key)?.slice(),atomic:async(entries,removed)=>{
    writes++;const next=new Map(data);for(const [key,bytes] of entries)next.set(key,bytes.slice());for(const key of removed)next.delete(key);
    if(abort)throw new Error('Synthetic atomic transaction abort.');data.clear();for(const [key,bytes] of next)data.set(key,bytes);
  }};
  return {storage,data,setAbort:value=>{abort=value;},writes:()=>writes};
}
const snapshot=data=>Array.from(data,([key,bytes])=>[key,[...bytes]]);

test('every stride boundary retains the cache needed for an exact 24-block fork',()=>{
  for(let offset=0;offset<8;offset++)for(const base of [24,64]){
    const height=base+offset,window=grown(height),fork=height-24,boundary=base-24;
    const plan=selectEng2Rollback(window,remote(height+3,height,fork));
    assert.equal(window.headers.length,Math.min(height+1,32));assert.equal(window.checkpoints.length,4);
    assert.equal(plan.status,'rollback');assert.equal(plan.depth,24);assert.equal(plan.fork_height,fork);
    assert.equal(plan.cache_height,boundary);assert.equal(plan.replay_from,boundary+1);assert.equal(fork-plan.cache_height,offset);
    assert.deepEqual(decode(open(plan.cache)),{height:boundary,tip:id(boundary)});
    assert.equal(window.height,height);assert.equal(window.tip,id(height));
  }
});
test('all depths 1 through 24 select a preceding private cache; deeper forks are unavailable',()=>{
  const window=grown(71);
  for(let depth=1;depth<=24;depth++){
    const fork=71-depth,plan=selectEng2Rollback(window,remote(74,71,fork));
    assert.equal(plan.status,'rollback');assert.equal(plan.depth,depth);assert.ok(plan.cache_height<=fork);assert.ok(fork-plan.cache_height<8);
  }
  assert.deepEqual(selectEng2Rollback(window,remote(74,71,46)),{status:'unavailable',reason:'outside-window'});
  assert.deepEqual(selectEng2Rollback(window,remote(74,71)),{status:'extension',height:71,tip:id(71)});
});
test('capacity pressure bounds ciphertext bytes and reports missing coverage without changing the old window',()=>{
  const original=grown(40),bytes=original.checkpoints.reduce((sum,point)=>sum+point.bytes.length,0);
  const limited=advanceEng2Rollback(original,[header(41)],null,{budget:0});
  assert.ok(bytes>0);assert.equal(limited.checkpoints.length,0);assert.equal(limited.capacity_limited,true);
  assert.equal(selectEng2Rollback(limited,remote(43,41,40)).reason,'missing-private-cache');
  assert.equal(original.height,40);assert.equal(original.checkpoints.length,4);
  assert.throws(()=>advanceEng2Rollback(original,[],null,{budget:ENG2_ROLLBACK_CACHE_BYTES+1}));
});
test('rewinding a staged window discards orphan caches while retaining the accepted window',()=>{
  const original=grown(40),plan=selectEng2Rollback(original,remote(43,40,25));
  let candidate=rewindEng2Rollback(original,plan);
  assert.equal(candidate.height,25);assert.ok(candidate.checkpoints.every(point=>point.height<=25));
  for(let height=26;height<=43;height++)candidate=advanceEng2Rollback(candidate,[header(height,25)],height%8===0?cache(height,25):null);
  assert.equal(candidate.height,43);assert.equal(candidate.tip,id(43,25));
  assert.deepEqual(candidate.checkpoints.map(point=>point.height),[16,24,32,40]);
  assert.deepEqual(decode(open(candidate.checkpoints[2].bytes)),{height:32,tip:id(32,25)});
  assert.equal(original.tip,id(40));assert.equal(original.checkpoints.at(-1).tip,id(40));
  assert.throws(()=>rewindEng2Rollback(original,{...plan,fork_tip:id(99)}));
});
test('malformed, disconnected or incomplete remote prefixes cannot select a rollback cache',()=>{
  const window=grown(40),valid=remote(43,40,25);
  const missing=structuredClone(valid);missing.headers.shift();
  const disconnected=structuredClone(valid);disconnected.headers[1].parent=id(99);
  const wrongOrder=structuredClone(valid);wrongOrder.headers.reverse();
  for(const value of [missing,disconnected,wrongOrder])assert.throws(()=>selectEng2Rollback(window,value));
  const regressed=remote(39,40);regressed.tip=id(99);assert.throws(()=>selectEng2Rollback(window,regressed));
  assert.throws(()=>advanceEng2Rollback(window,[{...header(41),parent:id(99)}]));
  assert.throws(()=>advanceEng2Rollback(window,[header(41)],cache(41)));
});
test('a complete recent window and accepted pair survive reopen in one encrypted record set',async()=>{
  const f=memory(),window=grown(40);
  await assert.rejects(persistEng2Rollback(f.storage,'scan',new Uint8Array(),'cache',cache(40),window,protect));
  await persistEng2Rollback(f.storage,'scan',scan(40),'cache',cache(40),window,protect);
  assert.equal(f.data.size,7);assert.equal(f.writes(),1);
  const loaded=await loadEng2Rollback(f.storage,'scan','cache',pin,{height:40,tip:id(40)},open);
  assert.equal(loaded.height,40);assert.equal(loaded.checkpoints.length,4);
  assert.equal(selectEng2Rollback(loaded,remote(43,40,16)).depth,24);
});
test('an aborted atomic replacement preserves active cache, index, rollback slots and unrelated reservations',async()=>{
  const f=memory(),old=grown(40);f.data.set('payment-input-reservation',protect(encode({held:true})));
  await persistEng2Rollback(f.storage,'scan',scan(40),'cache',cache(40),old,protect);
  const before=snapshot(f.data),next=advanceEng2Rollback(old,[header(41)]);
  f.setAbort(true);await assert.rejects(persistEng2Rollback(f.storage,'scan',scan(41),'cache',cache(41),next,protect),/transaction abort/);
  assert.deepEqual(snapshot(f.data),before);
  const reopened=await loadEng2Rollback(f.storage,'scan','cache',pin,{height:40,tip:id(40)},open);
  assert.equal(reopened.height,40);assert.deepEqual(decode(open(f.data.get('payment-input-reservation'))),{held:true});
});
test('successful replacement deletes orphan slots without touching payment or input records',async()=>{
  const f=memory(),old=grown(40);f.data.set('payment-input-reservation',new Uint8Array([9]));
  await persistEng2Rollback(f.storage,'scan',scan(40),'cache',cache(40),old,protect);
  const next=rewindEng2Rollback(old,selectEng2Rollback(old,remote(43,40,25)));
  await persistEng2Rollback(f.storage,'scan',scan(25),'cache',cache(25),next,protect);
  assert.equal(f.data.has('rollback:scan:2'),false);assert.equal(f.data.has('rollback:scan:3'),false);
  assert.deepEqual([...f.data.get('payment-input-reservation')],[9]);
  const loaded=await loadEng2Rollback(f.storage,'scan','cache',pin,{height:25,tip:id(25)},open);
  assert.deepEqual(loaded.checkpoints.map(point=>point.height),[16,24]);
});
test('foreign context, stale generation, missing slots and hostile declared sizes fail before adoption',async()=>{
  for(const mode of ['foreign','stale','missing','size']){
    const f=memory(),window=grown(40);await persistEng2Rollback(f.storage,'scan',scan(40),'cache',cache(40),window,protect);
    const metadata=decode(open(f.data.get('rollback:scan')));
    if(mode==='foreign')metadata.profile='9'.repeat(64);
    if(mode==='stale')metadata.height=39;
    if(mode==='missing')f.data.delete('rollback:scan:0');
    if(mode==='size')metadata.checkpoints[0].size=ENG2_ROLLBACK_CACHE_BYTES+1;
    f.data.set('rollback:scan',protect(encode(metadata)));const before=snapshot(f.data);
    await assert.rejects(loadEng2Rollback(f.storage,'scan','cache',pin,{height:40,tip:id(40)},open));
    assert.deepEqual(snapshot(f.data),before);
  }
});
test('an existing wallet without a rollback index remains explicitly unqualified for cached rewind',async()=>{
  const f=memory();f.data.set('scan',scan(40));f.data.set('cache',cache(40));
  const before=snapshot(f.data);
  assert.equal(await loadEng2Rollback(f.storage,'scan','cache',pin,{height:40,tip:id(40)},open),null);
  assert.deepEqual(snapshot(f.data),before);
});
test('the storage adapter stages all records and deletions in one transaction and propagates aborts',async()=>{
  const original=globalThis.indexedDB,data=new Map([['obsolete',new Uint8Array([3])],['reservation',new Uint8Array([8])]]);
  let abort=false,transactions=0,closed=0;
  globalThis.indexedDB={open(){const request={};queueMicrotask(()=>{request.result={close(){closed++;},transaction(store,mode){
    assert.equal(store,'private');assert.equal(mode,'readwrite');transactions++;const staged=new Map(data);let scheduled=false;
    const finish=()=>{if(scheduled)return;scheduled=true;queueMicrotask(()=>{if(abort){tx.onabort();return;}data.clear();for(const [key,value] of staged)data.set(key,value);tx.oncomplete();});};
    const tx={objectStore:()=>({put(value,key){staged.set(key,value.slice());finish();},delete(key){staged.delete(key);finish();}}),abort(){queueMicrotask(()=>tx.onabort());}};return tx;
  }};request.onsuccess();});return request;}};
  try{
    const storage=eng2Storage(pin);await storage.atomic([['scan',scan(40)],['cache',cache(40)]],['obsolete']);
    assert.equal(data.has('obsolete'),false);assert.equal(data.has('reservation'),true);assert.equal(transactions,1);
    await storage.pair('journal',new Uint8Array([1]),'journal',new Uint8Array([2]));
    assert.deepEqual([...data.get('journal')],[2]);assert.equal(transactions,2);
    const before=snapshot(data);abort=true;
    await assert.rejects(storage.atomic([['scan',scan(41)],['cache',cache(41)]],['reservation']),/not durably saved/);
    assert.deepEqual(snapshot(data),before);assert.equal(transactions,3);assert.equal(closed,3);
    await assert.rejects(storage.atomic([['scan',scan(1)],['scan',scan(2)]]),/keys differ/);assert.equal(transactions,3);
  }finally{globalThis.indexedDB=original;}
});
