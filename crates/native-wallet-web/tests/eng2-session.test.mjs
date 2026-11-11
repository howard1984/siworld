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
  const reopened=new Eng2Session(f.wallet,pin,{storage:f.storage,now:()=>1000,hash:async ()=>'opaque-wallet-hash',locks:{request:async (_key,options,fn)=>(typeof options==='function'?options:fn)()},binary:async () => ({bytes:new Uint8Array([1,2,3])})});
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
  const reopened=new Eng2Session(f.wallet,pin,{storage:f.storage,now:()=>1000,hash:async ()=>'opaque-wallet-hash',locks:{request:async (_key,options,fn)=>(typeof options==='function'?options:fn)()},binary:async () => ({bytes:new Uint8Array([1,2,3])})});
  assert.equal((await reopened.initialize()).height,1);assert.equal(reopened.summary().ready,false);
  f.data.set(reopened.key,enc({...reopened.metadata,profile:'8'.repeat(64)}));
  const foreign=new Eng2Session(f.wallet,pin,{storage:f.storage,hash:async ()=>'opaque-wallet-hash',locks:{request:async (_key,options,fn)=>(typeof options==='function'?options:fn)()},binary:async () => ({bytes:new Uint8Array([1,2,3])})});
  await assert.rejects(foreign.initialize(),/context differs/);
});
test('storage uses a dedicated exact-context database and one two-record transaction', async () => {
  const original=globalThis.indexedDB,names=[],puts=[];let closed=0;
  globalThis.indexedDB={open(name){names.push(name);const request={};queueMicrotask(()=>{request.result={close(){closed++;},transaction(store,mode){assert.equal(store,'private');assert.equal(mode,'readwrite');const tx={objectStore:()=>({put(value,key){puts.push([key,[...value]]);if(puts.length===2)queueMicrotask(()=>tx.oncomplete());}})};return tx;}};request.onsuccess();});return request;}};
  try{const storage=eng2Storage(pin);await storage.pair('a',new Uint8Array([1]),'b',new Uint8Array([2]));assert.deepEqual(names,[eng2Namespace(pin)]);assert.deepEqual(puts,[['a',[1]],['b',[2]]]);assert.equal(closed,1);await assert.rejects(storage.pair('a',{},'b',new Uint8Array()),/encrypted/);assert.equal(names.length,1);}finally{globalThis.indexedDB=original;}
});

test('genesis transport retry succeeds but exhausted initialization remains a real failure',async()=>{
  const f=fixture(),binary=f.session.binary;let calls=0;
  f.session.binary=async(...args)=>{if(++calls===1)throw new DOMException('Synthetic timeout.','TimeoutError');return binary(...args);};
  assert.equal((await f.session.initialize()).height,0);assert.equal(calls,2);assert.equal(f.session.controller,null);
  const g=fixture(),failure=Object.assign(new Error('Synthetic unavailable.'),{status:503});let attempts=0;
  g.session.binary=async()=>{attempts++;throw failure;};
  await assert.rejects(g.session.initialize(),error=>error===failure);assert.equal(attempts,3);
  assert.equal(g.session.metadata,null);assert.equal(g.session.controller,null);assert.equal(g.data.size,0);
});
test('a later receipt retries the same GET without redownloading the verified candidate prefix',async()=>{
  const f=fixture();await f.session.initialize();f.setHeads([2,2]);const binary=f.session.binary,calls=[];let interrupted=false;
  f.session.binary=async(url,options)=>{
    if(url.includes('/receipts/')){const height=Number(new URL(url).pathname.split('/').at(-2));calls.push(height);if(height===2&&!interrupted){interrupted=true;throw Object.assign(new Error('Synthetic rate limit.'),{status:429});}}
    return binary(url,options);
  };
  const result=await f.session.sync();assert.equal(result.height,2);assert.equal(result.ready,true);assert.equal(f.commits(),1);
  assert.deepEqual(calls,[1,2,2]);assert.ok(f.receipts.every(bytes=>bytes.every(byte=>byte===0)));
});
test('default public head transport retries while injected JSON decoding is not retried',async()=>{
  const f=fixture();await f.session.initialize();let calls=0;
  const binary=f.session.binary;
  f.session.binary=async(url,options)=>{if(url.endsWith('/head')){if(++calls===1)throw Object.assign(new Error('Synthetic gateway failure.'),{status:502});return {bytes:enc(head())};}return binary(url,options);};
  // Default construction installs a closure over this.binary; retain the same
  // synthetic wallet/storage while omitting the optional JSON test adapter.
  const original=f.session;
  const session=new Eng2Session(f.wallet,pin,{storage:f.storage,now:()=>1000,hash:async()=>'opaque-wallet-hash',locks:original.locks,binary:original.binary});
  await session.initialize();assert.equal((await session.sync()).height,1);assert.equal(calls,3);
  const g=fixture();await g.session.initialize();let jsonCalls=0;const failure=new TypeError('Synthetic JSON adapter decoding failure.');
  g.session.json=async()=>{jsonCalls++;throw failure;};
  await assert.rejects(g.session.sync(),error=>error===failure);assert.equal(jsonCalls,1);assert.equal(g.commits(),0);
});
test('native receipt authentication errors are not retried and the caller still wipes received bytes',async()=>{
  const f=fixture();await f.session.initialize();f.setCorrupt();
  await assert.rejects(f.session.sync(),/Synthetic native receipt authentication rejected/);
  assert.equal(f.requests.filter(url=>url.includes('/receipts/')).length,1);assert.equal(f.receipts.length,1);
  assert.ok(f.receipts[0].every(byte=>byte===0));assert.equal(f.commits(),0);
});
test('wallet cancellation aborts an initializing genesis GET without enabling native state or retrying',async()=>{
  const f=fixture();let attempts=0,enables=0;f.wallet.enable_eng2=()=>{enables++;throw new Error('Native state must not be enabled.');};
  f.session.binary=async(_url,{signal})=>{attempts++;return new Promise((_,reject)=>signal.addEventListener('abort',()=>reject(signal.reason),{once:true}));};
  const pending=f.session.initialize();await new Promise(resolve=>setImmediate(resolve));f.session.cancelSync();
  await assert.rejects(pending,error=>error.name==='AbortError');assert.equal(attempts,1);assert.equal(enables,0);assert.equal(f.session.controller,null);assert.equal(f.data.size,0);
});

function reopen(f) {
  return new Eng2Session(f.wallet,pin,{storage:f.storage,now:()=>1000,hash:f.session.hash,locks:f.session.locks,binary:f.session.binary,json:f.session.json});
}
test('eight-block extension commits remain stale until the exact fresh head is reached',async()=>{
  const f=fixture();await f.session.initialize();f.setHeads([17]);const commit=f.wallet.commit_eng2_candidate,ends=[],begins=[];
  const begin=f.wallet.begin_eng2_candidate;f.wallet.begin_eng2_candidate=extension=>{begins.push(extension);return begin(extension);};
  f.wallet.commit_eng2_candidate=(height,tip)=>{ends.push(Number(height));return commit(height,tip);};
  const result=await f.session.sync(progress=>{if(progress.height===9){assert.equal(f.current().height,8);assert.equal(f.session.metadata.height,8);assert.equal(f.session.summary().stale,true);}});
  assert.deepEqual(ends,[8,16,17]);assert.deepEqual(begins,[true,true,true]);assert.equal(result.ready,true);assert.equal(result.height,17);
  assert.equal(dec(f.data.get(f.session.key)).height,17);assert.ok(f.receipts.every(bytes=>bytes.every(byte=>byte===0)));
});
test('a failed later receipt reopens from the last complete eight-block prefix',async()=>{
  for(const [failedHeight,prefix] of [[10,8],[17,16]]){
    const f=fixture();await f.session.initialize();f.setHeads([17]);f.setHook(height=>{if(height===failedHeight)throw new Error('Synthetic terminal receipt failure.');});
    await assert.rejects(f.session.sync(),/Synthetic terminal receipt failure/);
    assert.equal(f.current().height,prefix);assert.equal(f.session.metadata.height,prefix);assert.equal(f.session.invalidated,false);assert.equal(f.session.ready,false);
    assert.equal(dec(f.data.get(f.session.key)).height,prefix);assert.equal(dec(f.data.get(f.session.cacheKey)).height,prefix);
    f.setHook(null);const before=f.requests.length,next=reopen(f);assert.equal((await next.initialize()).height,prefix);
    assert.equal((await next.sync()).height,17);
    const downloaded=f.requests.slice(before).filter(url=>url.includes('/receipts/')).map(url=>Number(new URL(url).pathname.split('/').at(-2)));
    assert.deepEqual(downloaded,Array.from({length:17-prefix},(_,index)=>prefix+index+1));
  }
});
test('cancellation before an eight-block adoption preserves the prior pair',async()=>{
  const f=fixture();await f.session.initialize();f.setHeads([17]);
  await assert.rejects(f.session.sync(progress=>{if(progress.height===8)f.session.cancelSync();}),error=>error.name==='AbortError');
  assert.equal(f.current().height,0);assert.equal(f.commits(),0);assert.equal(dec(f.data.get(f.session.key)).height,0);
  assert.ok(f.receipts.every(bytes=>bytes.every(byte=>byte===0)));assert.equal(f.session.invalidated,false);
});
test('cancellation during partial durable adoption finishes native commit and stops stale',async()=>{
  const f=fixture();await f.session.initialize();f.setHeads([17]);f.setWriteHook(()=>f.session.cancelSync());
  const result=await f.session.sync();assert.equal(result.height,8);assert.equal(result.ready,false);assert.equal(result.catchup_pending,true);
  assert.equal(f.current().height,8);assert.equal(f.session.metadata.height,8);assert.equal(f.commits(),1);assert.equal(f.session.invalidated,false);
  assert.equal(dec(f.data.get(f.session.key)).height,8);assert.equal(dec(f.data.get(f.session.cacheKey)).height,8);
  f.setWriteHook(null);const next=reopen(f);assert.equal((await next.initialize()).height,8);assert.equal((await next.sync()).height,17);
});
test('cancellation after a prefix commit cannot append to its consumed candidate',async()=>{
  const f=fixture();await f.session.initialize();f.setHeads([17]);const commit=f.wallet.commit_eng2_candidate,begin=f.wallet.begin_eng2_candidate;let begins=0;
  f.wallet.begin_eng2_candidate=extension=>{begins++;return begin(extension);};
  f.wallet.commit_eng2_candidate=(height,tip)=>{const value=commit(height,tip);f.session.cancelSync();return value;};
  assert.equal((await f.session.sync()).height,8);assert.equal(begins,1);assert.equal(f.session.invalidated,false);assert.equal(f.session.ready,false);
});
test('second-batch storage failure preserves the first matched cache without invalidating it',async()=>{
  const f=fixture();await f.session.initialize();f.setHeads([17]);const pair=f.storage.pair;let writes=0;
  f.storage.pair=async(...args)=>{if(++writes===2)throw new Error('Synthetic atomic storage abort.');return pair(...args);};
  await assert.rejects(f.session.sync(),/Synthetic atomic storage abort/);
  assert.equal(f.current().height,8);assert.equal(f.session.metadata.height,8);assert.equal(f.session.invalidated,false);
  assert.equal(dec(f.data.get(f.session.key)).height,8);assert.equal(dec(f.data.get(f.session.cacheKey)).height,8);
  f.storage.pair=pair;const next=reopen(f);assert.equal((await next.initialize()).height,8);
});
test('a native commit failure after storage marks uncertainty and reopen restores the durable pair',async()=>{
  const f=fixture();await f.session.initialize();f.setHeads([17]);const commit=f.wallet.commit_eng2_candidate;
  f.wallet.commit_eng2_candidate=(height,tip)=>{if(Number(height)===16)throw new Error('Synthetic native commit failure.');return commit(height,tip);};
  await assert.rejects(f.session.sync(),/Engineering-v2 state was saved/);
  assert.equal(f.current().height,8);assert.equal(f.session.metadata.height,8);assert.equal(f.session.invalidated,true);
  assert.equal(dec(f.data.get(f.session.key)).height,16);assert.equal(dec(f.data.get(f.session.cacheKey)).height,16);
  const next=reopen(f);assert.equal((await next.initialize()).height,16);assert.equal(next.invalidated,false);
});
test('a later native receipt failure wipes bytes and retains the completed prefix',async()=>{
  const f=fixture();await f.session.initialize();f.setHeads([17]);const append=f.wallet.append_eng2_receipt;
  f.wallet.append_eng2_receipt=(header,bytes)=>{if(dec(bytes).height===10)throw new Error('Synthetic later native authentication failure.');return append(header,bytes);};
  await assert.rejects(f.session.sync(),/Synthetic later native authentication failure/);
  assert.equal(f.current().height,8);assert.equal(f.session.invalidated,false);assert.equal(f.receipts.length,10);
  assert.ok(f.receipts.every(bytes=>bytes.every(byte=>byte===0)));
});
test('fresh reorganization candidates never commit partial eight-block prefixes',async()=>{
  for(const fail of [false,true]){
    const f=fixture();await f.session.initialize();f.setHeads([9]);await f.session.sync();
    const binary=f.session.binary,commit=f.wallet.commit_eng2_candidate,begin=f.wallet.begin_eng2_candidate,ends=[],begins=[];
    f.session.binary=async(url,options)=>{const result=await binary(url,options);const parsed=new URL(url);if(parsed.pathname.endsWith('/headers')&&Number(parsed.searchParams.get('from'))===10){const value=dec(result.bytes);value.headers[0].parent=id(99);result.bytes=enc(value);}return result;};
    f.wallet.commit_eng2_candidate=(height,tip)=>{ends.push(Number(height));return commit(height,tip);};
    f.wallet.begin_eng2_candidate=extension=>{begins.push(extension);return begin(extension);};
    f.setHeads([17]);if(fail)f.setHook(height=>{if(height===10)throw new Error('Synthetic fork authentication failure.');});
    if(fail){await assert.rejects(f.session.sync(),/Synthetic fork authentication failure/);assert.deepEqual(ends,[]);assert.equal(f.current().height,9);assert.equal(dec(f.data.get(f.session.key)).height,9);}
    else{assert.equal((await f.session.sync()).height,17);assert.deepEqual(ends,[17]);}
    assert.deepEqual(begins,[false]);
  }
});
test('a changed branch at a later prefix boundary cannot replace the preceding saved prefix',async()=>{
  const f=fixture();await f.session.initialize();f.setHeads([17,17,{...head(17),tip:id(99)}]);
  await assert.rejects(f.session.sync(),/incompatible branch/);assert.equal(f.current().height,8);assert.equal(f.session.invalidated,false);assert.equal(dec(f.data.get(f.session.key)).height,8);
});
test('an advancing head preserves completed batches but does not claim complete synchronization',async()=>{
  const f=fixture();await f.session.initialize();f.setHeads([17,18,18,18,18,18]);
  const result=await f.session.sync();assert.equal(result.height,17);assert.equal(result.ready,false);assert.equal(result.catchup_pending,true);assert.equal(result.target_height,18);
  assert.equal(f.commits(),3);assert.equal((await f.session.sync()).height,18);assert.equal(f.session.ready,true);
});


test('cancelling initialization during wallet hashing prevents genesis and storage work',async()=>{
  const f=fixture();let finishHash,enables=0;
  f.session.hash=()=>new Promise(resolve=>{finishHash=resolve;});
  f.wallet.enable_eng2=()=>{enables++;throw new Error('Cancelled initialization must not enable native state.');};
  const pending=f.session.initialize();f.session.cancelSync();finishHash('opaque-wallet-hash');
  await assert.rejects(pending,error=>error.name==='AbortError');
  assert.equal(f.requests.length,0);assert.equal(enables,0);assert.equal(f.data.size,0);assert.equal(f.session.metadata,null);assert.equal(f.session.controller,null);
});
test('cancelling initialization queued behind another owner aborts the lock request',async()=>{
  const f=fixture();let entered,callbackCalls=0,reads=0;
  const queued=new Promise(resolve=>{entered=resolve;});
  f.storage.read=async()=>{reads++;};
  f.session.locks={request:(_key,options,callback)=>{
    entered(options.signal);assert.ok(options.signal instanceof AbortSignal);
    return new Promise((resolve,reject)=>{
      options.signal.addEventListener('abort',()=>reject(options.signal.reason),{once:true});
      // No callback runs while the synthetic other owner retains its lock.
      if(options.signal.aborted)reject(options.signal.reason);
    });
  }};
  const pending=f.session.initialize();
  const rejected=assert.rejects(pending,error=>error.name==='AbortError');
  const signal=await queued;f.session.cancelSync();await rejected;
  assert.equal(signal.aborted,true);assert.equal(callbackCalls,0);assert.equal(reads,0);assert.equal(f.data.size,0);assert.equal(f.session.metadata,null);assert.equal(f.session.controller,null);
});
test('cancelling either initialization read preserves the existing matched cache',async()=>{
  for(const stopAt of [1,2]){
    const f=fixture();await f.session.initialize();await f.session.sync();
    const before=Array.from(f.data,([key,value])=>[key,[...value]]),next=reopen(f),read=f.storage.read;
    let reads=0,finish,entered,restores=0;
    const waiting=new Promise(resolve=>{entered=resolve;});
    f.storage.read=async key=>{if(++reads===stopAt){entered();await new Promise(resolve=>{finish=resolve;});}return read(key);};
    next.storage=f.storage;f.wallet.restore_eng2_cache=()=>{restores++;throw new Error('Cancelled initialization must not restore native cache.');};
    const pending=next.initialize();await waiting;next.cancelSync();finish();
    await assert.rejects(pending,error=>error.name==='AbortError');
    assert.equal(reads,stopAt);assert.equal(restores,0);assert.equal(next.metadata,null);assert.equal(next.controller,null);
    assert.deepEqual(Array.from(f.data,([key,value])=>[key,[...value]]),before);
  }
});
test('cancellation during the initial atomic save retains the matched native and durable state',async()=>{
  const f=fixture();f.setWriteHook(()=>f.session.cancelSync());
  const result=await f.session.initialize();
  assert.equal(result.ready,false);assert.equal(result.stale,true);assert.equal(result.height,0);assert.equal(f.session.metadata.height,0);assert.equal(f.session.invalidated,false);assert.equal(f.session.controller,null);
  assert.equal(dec(f.data.get(f.session.key)).height,0);assert.equal(dec(f.data.get(f.session.cacheKey)).height,0);assert.equal(f.current().height,0);
});
