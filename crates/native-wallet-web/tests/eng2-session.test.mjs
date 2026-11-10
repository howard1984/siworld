import {test} from 'node:test';
import assert from 'node:assert/strict';
import {Eng2Session} from '../web/sdk/eng2-session.js';
import {eng2Context,eng2Namespace,eng2Head} from '../web/sdk/eng2-context.js';
import {eng2Storage} from '../web/sdk/eng2-storage.js';
const enc = value => new TextEncoder().encode(JSON.stringify(value));
const dec = bytes => JSON.parse(new TextDecoder().decode(bytes));
const pin = {version:2,name:'siworld-eng-2',network:'1'.repeat(64),genesis:'2'.repeat(64),rules:'3'.repeat(64),profile:'4'.repeat(64),fee_mode:0,api:'http://127.0.0.1:8890'};
const id = height => height === 0 ? pin.genesis : (height+4).toString(16).padStart(64,'0');
const state = (height=0) => ({version:2,network:pin.network,genesis:pin.genesis,rules:pin.rules,profile:pin.profile,fee_mode:0,height,tip:id(height),send_supported:false,full_node_consensus_verified:false,rows:[]});
const head = (height=1) => {const {send_supported,full_node_consensus_verified,rows,...value}=state(height);return {...value,published_unix_seconds:1000};};
function fixture() {
  const data = new Map(), requests = [], receipts = [];
  let fail = false, current = state(), candidate = null, headCalls = 0, changed = false, corrupt = false, hook = null, commits = 0, heads = null, mismatch = false, writeHook = null;
  const wallet = {
    public_info: () => JSON.stringify({network:pin.network,full_address:'synthetic-public-address'}),
    enable_eng2: () => JSON.stringify(current=state()),
    eng2_balance: () => JSON.stringify(current),eng2_history: () => '[]',
    protect_eng2_local: bytes => bytes.slice(),open_eng2_local: bytes => bytes.slice(),
    eng2_cache: pending => enc(pending ? candidate : current),
    restore_eng2_cache: (_g,_p,bytes) => JSON.stringify(current=dec(bytes)),
    begin_eng2_candidate: extension => {candidate=extension?structuredClone(current):state();},
    eng2_header_page: bytes => JSON.stringify(dec(bytes)),
    append_eng2_receipt: (header,bytes) => {const value=dec(bytes);if(corrupt)throw new Error('Synthetic native receipt authentication rejected.');assert.equal(header.length,190);candidate=state(value.height);return JSON.stringify({height:candidate.height,tip:candidate.tip,committed:false});},
    check_eng2_candidate: (height,tip) => {assert.equal(candidate.height,Number(height));assert.equal(candidate.tip,tip);},
    commit_eng2_candidate: () => {commits++;current=candidate;candidate=null;return JSON.stringify(current);},
    abort_eng2_candidate: () => {candidate=null;}
  };
  const storage = {read:async key=>data.get(key)?.slice(),pair:async (a,av,b,bv)=>{writeHook?.();if(fail)throw new Error('Synthetic durable write failed.');data.set(a,av.slice());data.set(b,bv.slice());}};
  const io = {storage,now:()=>1000,hash:async ()=>'opaque-wallet-hash',locks:{request:async (_key,options,fn)=>(typeof options==='function'?options:fn)()},
    json:async url=>{requests.push(url);headCalls++;const value=heads?.[Math.min(headCalls-1,heads.length-1)];return typeof value==='object'?value:head(value??(changed&&headCalls>1?2:1));},
    binary:async url=>{
      requests.push(url);const value=new URL(url);
      if(value.pathname.endsWith('/genesis'))return {bytes:new Uint8Array([1,2,3])};
      const height=Number(value.searchParams.get('height'));assert.equal(value.searchParams.get('tip'),id(height));
      if(value.pathname.endsWith('/headers')){
        const from=Number(value.searchParams.get('from')),limit=Number(value.searchParams.get('limit'));
        return {bytes:enc({height,tip:id(height),from,headers:Array.from({length:Math.min(limit,height-from+1)},(_,offset)=>{const h=from+offset;return {height:h,id:mismatch&&height>h?id(9):id(h),parent:id(h-1),bytes_hex:'00'.repeat(190)};})})};
      }
      if(value.pathname.includes('/receipts/')){const receiptHeight=Number(value.pathname.split('/').at(-2));assert.ok(value.pathname.endsWith('/'+id(receiptHeight)));hook?.(receiptHeight);const bytes=enc({height:receiptHeight});receipts.push(bytes);return {bytes};}
      throw new Error('Unexpected synthetic route.');
    }};
  const session = new Eng2Session(wallet,pin,io);
  return {session,wallet,storage,data,requests,receipts,setFail:()=>{fail=true;},setChanged:()=>{changed=true;},setCorrupt:()=>{corrupt=true;},setHook:value=>{hook=value;},setHeads:value=>{heads=value;headCalls=0;},setMismatch:()=>{mismatch=true;},setWriteHook:value=>{writeHook=value;},commits:()=>commits,current:()=>current};
}
test('pins separate network/genesis/rules/profile and reject legacy or unsealed contexts', () => {
  assert.equal(eng2Context(pin).api,pin.api);
  for (const key of ['network','genesis','rules','profile']) {
    assert.notEqual(eng2Namespace(pin),eng2Namespace({...pin,[key]:'9'.repeat(64)}));
    assert.throws(()=>eng2Context({...pin,[key]:null}));
  }
  for(const changes of [{name:'siworld-eng-1'},{fee_mode:1},{api:'https://example.test/path'},{api:'http://example.test'},{api:'https://user:pass@example.test/'}])assert.throws(()=>eng2Context({...pin,...changes}));
  for(const changes of [{profile:'9'.repeat(64)},{height:100001},{published_unix_seconds:699},{published_unix_seconds:1031},{height:0,tip:id(1)}])assert.throws(()=>eng2Head({...head(),...changes},pin,1000));
});
test('scans to a fresh pinned head, saves atomically and returns only committed balances', async () => {
  const f=fixture();const initial=await f.session.initialize();assert.equal(initial.ready,false);assert.equal(initial.height,0);
  const progress=[];const result=await f.session.sync(value=>{progress.push(value);assert.equal(f.current().height,0);});
  assert.equal(result.height,1);assert.equal(result.ready,true);assert.equal(result.committed,true);assert.equal(result.send_supported,false);assert.equal(f.commits(),1);
  assert.equal(progress.length,1);assert.equal(progress[0].height,1);assert.ok(f.receipts.every(bytes=>bytes.every(byte=>byte===0)));
  assert.equal(f.data.size,2);assert.ok(f.requests.every(url=>!url.includes('/v1/')));
  assert.ok(f.requests.some(url=>url.includes('/api/v2/wallet/receipts/1/')));
  assert.throws(()=>f.session.prepare(),/unavailable/);assert.throws(()=>f.session.submit(),/unavailable/);
  const before=f.requests.length;await f.session.sync();assert.equal(f.requests.length,before+1);assert.equal(f.commits(),1);
});
test('native authentication errors and durable-write failures preserve accepted state', async () => {
  for(const change of ['setCorrupt','setFail']){
    const f=fixture();await f.session.initialize();const before=Array.from(f.data,([key,value])=>[key,[...value]]);f[change]();
    await assert.rejects(f.session.sync());assert.equal(f.current().height,0);assert.equal(f.session.summary().ready,false);assert.equal(f.commits(),0);
    assert.deepEqual(Array.from(f.data,([key,value])=>[key,[...value]]),before);
  }
});

test('a moving head preserves a verified prefix and resumes without downloading it again', async () => {
  const f=fixture();await f.session.initialize();f.setHeads([1,2,2,2]);
  const pending=await f.session.sync();
  assert.equal(pending.height,1);assert.equal(pending.ready,false);assert.equal(pending.stale,true);assert.equal(pending.catchup_pending,true);assert.equal(pending.target_height,2);assert.equal(pending.target_tip,id(2));assert.equal(f.commits(),1);
  assert.equal(dec(f.data.get(f.session.key)).height,1);assert.equal(dec(f.data.get(f.session.cacheKey)).height,1);
  const resumed=await f.session.sync();assert.equal(resumed.height,2);assert.equal(resumed.ready,true);assert.equal(resumed.catchup_pending,false);assert.equal(f.commits(),2);
  assert.deepEqual(f.requests.filter(url=>url.includes('/receipts/')).map(url=>Number(new URL(url).pathname.split('/').at(-2))),[1,2]);
  const boundary=f.requests.find(url=>url.includes('/headers?')&&new URL(url).searchParams.get('height')==='2'&&new URL(url).searchParams.get('from')==='1');
  assert.equal(new URL(boundary).searchParams.get('limit'),'1');
});
test('continually advancing heads retain bounded completed generations without claiming readiness', async () => {
  const f=fixture();await f.session.initialize();f.setHeads([1,2,2,3]);
  for(const height of [1,2]) {const result=await f.session.sync();assert.equal(result.height,height);assert.equal(result.ready,false);assert.equal(result.catchup_pending,true);}
  assert.equal(f.commits(),2);assert.equal(f.receipts.length,2);
});
test('same-height forks, regressed heads, mismatched prefixes and foreign heads preserve accepted state', async () => {
  for(const value of [{...head(1),tip:id(9)},head(0),head(2),{...head(2),network:'9'.repeat(64)},{...head(2),published_unix_seconds:699}]){
    const f=fixture();await f.session.initialize();f.setHeads([1,value]);if(value.height===2&&value.network===pin.network&&value.published_unix_seconds===1000)f.setMismatch();
    const before=Array.from(f.data,([key,bytes])=>[key,[...bytes]]);
    await assert.rejects(f.session.sync());assert.equal(f.current().height,0);assert.equal(f.commits(),0);assert.equal(f.session.summary().ready,false);
    assert.deepEqual(Array.from(f.data,([key,bytes])=>[key,[...bytes]]),before);
  }
});
test('failure on a later extension preserves the completed prefix for reopen', async () => {
  const f=fixture();await f.session.initialize();f.setHeads([1,2,2,2]);await f.session.sync();f.setCorrupt();
  await assert.rejects(f.session.sync());assert.equal(f.current().height,1);assert.equal(f.commits(),1);assert.equal(f.session.invalidated,false);
  const reopened=new Eng2Session(f.wallet,pin,{storage:f.storage,now:()=>1000,hash:async ()=>'opaque-wallet-hash',locks:{request:async (_key,fn)=>fn()},binary:async () => ({bytes:new Uint8Array([1,2,3])})});
  assert.equal((await reopened.initialize()).height,1);assert.equal(reopened.summary().ready,false);
});
test('cancellation during durable adoption finishes matching native state but remains stale', async () => {
  const f=fixture();await f.session.initialize();f.setWriteHook(()=>f.session.cancelSync());
  const result=await f.session.sync();assert.equal(result.height,1);assert.equal(result.ready,false);assert.equal(result.stale,true);assert.equal(f.commits(),1);
  assert.equal(dec(f.data.get(f.session.key)).height,1);assert.equal(dec(f.data.get(f.session.cacheKey)).height,1);
});
test('cancellation and cross-tab metadata changes prevent candidate adoption', async () => {
  const f=fixture();await f.session.initialize();f.setHook(()=>f.session.cancelSync());await assert.rejects(f.session.sync());assert.equal(f.current().height,0);assert.equal(f.commits(),0);
  const g=fixture();await g.session.initialize();g.data.set(g.session.key,enc({...g.session.metadata,height:1,tip:id(1)}));await assert.rejects(g.session.sync(),/Another tab/);assert.equal(g.commits(),0);
});
test('same-context local cache can reopen; foreign profile metadata cannot', async () => {
  const f=fixture();await f.session.initialize();await f.session.sync();
  const reopened=new Eng2Session(f.wallet,pin,{storage:f.storage,now:()=>1000,hash:async ()=>'opaque-wallet-hash',locks:{request:async (_key,fn)=>fn()},binary:async () => ({bytes:new Uint8Array([1,2,3])})});
  assert.equal((await reopened.initialize()).height,1);assert.equal(reopened.summary().ready,false);
  f.data.set(reopened.key,enc({...reopened.metadata,profile:'8'.repeat(64)}));
  const foreign=new Eng2Session(f.wallet,pin,{storage:f.storage,hash:async ()=>'opaque-wallet-hash',locks:{request:async (_key,fn)=>fn()},binary:async () => ({bytes:new Uint8Array([1,2,3])})});
  await assert.rejects(foreign.initialize(),/context differs/);
});
test('storage uses a dedicated exact-context database and one two-record transaction', async () => {
  const original=globalThis.indexedDB,names=[],puts=[];let closed=0;
  globalThis.indexedDB={open(name){names.push(name);const request={};queueMicrotask(()=>{request.result={close(){closed++;},transaction(store,mode){assert.equal(store,'private');assert.equal(mode,'readwrite');const tx={objectStore:()=>({put(value,key){puts.push([key,[...value]]);if(puts.length===2)queueMicrotask(()=>tx.oncomplete());}})};return tx;}};request.onsuccess();});return request;}};
  try{const storage=eng2Storage(pin);await storage.pair('a',new Uint8Array([1]),'b',new Uint8Array([2]));assert.deepEqual(names,[eng2Namespace(pin)]);assert.deepEqual(puts,[['a',[1]],['b',[2]]]);assert.equal(closed,1);await assert.rejects(storage.pair('a',{},'b',new Uint8Array()),/encrypted/);assert.equal(names.length,1);}finally{globalThis.indexedDB=original;}
});
