import {test} from 'node:test';
import assert from 'node:assert/strict';
import {Eng2Session} from '../web/sdk/eng2-session.js';
import {loadEng2Rollback} from '../web/sdk/eng2-rollback.js';

const pin={version:2,name:'siworld-eng-2',network:'1'.repeat(64),genesis:'2'.repeat(64),rules:'3'.repeat(64),profile:'4'.repeat(64),fee_mode:0,api:'http://127.0.0.1:8890'};
const encode=value=>new TextEncoder().encode(JSON.stringify(value));
const decode=bytes=>JSON.parse(new TextDecoder().decode(bytes));
const seal=(magic,plain)=>{const bytes=new Uint8Array(plain.length+48);bytes.set(new TextEncoder().encode(magic));bytes.set(plain,32);return bytes;};
const open=bytes=>bytes.slice(32,-16);
const id=(height,fork=Infinity)=>height===0?pin.genesis:(height+(height>fork?100000:4)).toString(16).padStart(64,'0');
const header=(height,fork=Infinity)=>({height,id:id(height,fork),parent:height===0?null:id(height-1,fork),bytes_hex:Array.from(encode({height,id:id(height,fork),parent:height===0?null:id(height-1,fork)}),byte=>byte.toString(16).padStart(2,'0')).join('')});
const initial=()=>({height:0,tip:pin.genesis,headers:[header(0)],notes:[]});
function fixture(){
  const data=new Map(),requests=[],events=[],receiptBytes=[];
  let accepted=initial(),candidate=null,height=0,fork=Infinity,writeHook=null,receiptHook=null,readHook=null,failWrite=false,failCommit=false,held=false;
  const balance=()=>({...pin,height:accepted.height,tip:accepted.tip,send_supported:false,full_node_consensus_verified:false,rows:[{asset:'0'.repeat(64),available_atoms:accepted.notes.reduce((sum,row)=>sum+BigInt(row.value),0n).toString()}]});
  // Synthetic adapter boundaries. No signatures, real header work or native
  // transaction proofs are checked by these JavaScript fixtures.
  const wallet={
    public_info:()=>JSON.stringify({network:pin.network,full_address:'synthetic-rollback-address'}),
    enable_eng2:()=>{accepted=initial();candidate=null;return JSON.stringify(balance());},
    eng2_balance:()=>JSON.stringify(balance()),eng2_history:()=>JSON.stringify(accepted.notes),
    protect_eng2_local:plain=>seal('SWE2JL01',plain),open_eng2_local:open,
    eng2_cache:pending=>seal('SWE2SC01',encode(pending?candidate:accepted)),
    eng2_recent_headers:()=>JSON.stringify(accepted.headers.slice(-32)),
    restore_eng2_cache:(_genesis,_id,bytes)=>{accepted=decode(open(bytes));return JSON.stringify(balance());},
    begin_eng2_candidate:extension=>{events.push({kind:'begin',extension});candidate=extension?structuredClone(accepted):initial();},
    begin_eng2_cached_candidate:(_genesis,_id,bytes,value,tip)=>{
      const restored=decode(open(bytes));assert.equal(restored.height,Number(value));assert.equal(restored.tip,tip);
      assert.equal(accepted.headers[restored.height].id,tip);assert.ok(accepted.height-restored.height<=31);
      events.push({kind:'cached',height:restored.height});candidate=restored;
      return JSON.stringify({height:restored.height,tip,committed:false});
    },
    eng2_header_page:bytes=>new TextDecoder().decode(bytes),
    append_eng2_receipt:(raw,bytes)=>{
      const row=decode(raw),receipt=decode(bytes);assert.equal(row.parent,candidate.tip);assert.equal(row.height,candidate.height+1);assert.equal(receipt.id,row.id);
      candidate={height:row.height,tip:row.id,headers:[...candidate.headers,row],notes:[...candidate.notes,{height:row.height,value:receipt.value,block_id:row.id}]};
      return JSON.stringify({height:row.height,tip:row.id,committed:false});
    },
    check_eng2_candidate:(value,tip)=>{assert.equal(candidate.height,Number(value));assert.equal(candidate.tip,tip);assert.ok(candidate.tip===accepted.tip||candidate.height>accepted.height,'greater synthetic work required');},
    commit_eng2_candidate:(value,tip)=>{wallet.check_eng2_candidate(value,tip);if(failCommit)throw new Error('Synthetic commit failure.');events.push({kind:'commit',height:candidate.height});accepted=candidate;candidate=null;},
    abort_eng2_candidate:()=>{candidate=null;}
  };
  const storage={read:async key=>{await readHook?.(key);return data.get(key)?.slice();},atomic:async(entries,removed=[])=>{
    const next=new Map(data);for(const [key,value] of entries)next.set(key,value.slice());for(const key of removed)next.delete(key);
    await writeHook?.();if(failWrite)throw new Error('Synthetic storage abort.');data.clear();for(const [key,value] of next)data.set(key,value);
  }};
  const locks={request:async(_key,options,callback)=>{const fn=typeof options==='function'?options:callback;options?.signal?.throwIfAborted();assert.equal(held,false);held=true;try{return await fn();}finally{held=false;}}};
  const io={storage,locks,hash:async()=>'rollback-address-hash',now:()=>1000,
    json:async()=>{const {name,api,...context}=pin;return {...context,height,tip:id(height,fork),published_unix_seconds:1000};},
    binary:async(url,{signal})=>{
      signal.throwIfAborted();requests.push(url);const parsed=new URL(url);
      if(parsed.pathname.endsWith('/genesis'))return {bytes:new Uint8Array([1])};
      assert.equal(parsed.searchParams.get('height'),String(height));assert.equal(parsed.searchParams.get('tip'),id(height,fork));
      if(parsed.pathname.endsWith('/headers')){const from=Number(parsed.searchParams.get('from')),limit=Number(parsed.searchParams.get('limit'));return {bytes:encode({height,tip:id(height,fork),from,headers:Array.from({length:Math.min(limit,height-from+1)},(_,offset)=>header(from+offset,fork))})};}
      const at=Number(parsed.pathname.split('/').at(-2));await receiptHook?.(at);const bytes=encode({id:id(at,fork),value:at>fork?'2':'1'});receiptBytes.push(bytes);return {bytes};
    }};
  const session=new Eng2Session(wallet,pin,io);
  return {session,wallet,storage,data,requests,events,receiptBytes,current:()=>accepted,reopen:()=>new Eng2Session(wallet,pin,io),head:(value,branch=Infinity)=>{height=value;fork=branch;},writeHook:value=>{writeHook=value;},receiptHook:value=>{receiptHook=value;},readHook:value=>{readHook=value;},failWrite:value=>{failWrite=value;},failCommit:value=>{failCommit=value;}};
}
const snapshot=data=>Array.from(data,([key,value])=>[key,[...value]]);
async function at(f,height){await f.session.initialize();f.head(height);await f.session.sync();}
const downloads=urls=>urls.filter(url=>url.includes('/receipts/')).map(url=>Number(new URL(url).pathname.split('/').at(-2)));

test('the connected session replays an exact 24-block fork from the sparse cache and adopts once',async()=>{
  const f=fixture();await at(f,71);f.data.set('payment-input-reservation',new Uint8Array([9]));const before=f.requests.length,event=f.events.length;
  f.head(74,47);const progress=[];
  const result=await f.session.sync(value=>{progress.push(value);assert.equal(f.current().height,71);assert.equal(f.session.metadata.height,71);});
  assert.equal(result.height,74);assert.equal(result.ready,true);assert.equal(result.rows[0].available_atoms,'101');
  assert.deepEqual(f.events.slice(event),[{kind:'cached',height:40},{kind:'commit',height:74}]);
  assert.deepEqual(downloads(f.requests.slice(before)),Array.from({length:34},(_,i)=>41+i));
  assert.equal(progress[0].phase,'eng2-rollback');assert.equal(progress[0].depth,24);assert.equal(progress[0].fork_height,47);
  assert.deepEqual([...f.data.get('payment-input-reservation')],[9]);assert.ok(f.receiptBytes.every(bytes=>bytes.every(byte=>byte===0)));
  const next=f.reopen();assert.equal((await next.initialize()).height,74);assert.equal((await next.sync()).height,74);assert.equal(next.rollback.height,74);
});
test('global eight-block caches are collected across arbitrary final sync heights',async()=>{
  const f=fixture();await f.session.initialize();
  for(const height of [3,7,11,19,30,37,51,63,71]){f.head(height);await f.session.sync();}
  assert.deepEqual(f.session.rollback.checkpoints.map(point=>point.height),[40,48,56,64]);
  f.head(74,47);await f.session.sync();assert.ok(f.events.some(event=>event.kind==='cached'&&event.height===40));
});
test('a failed reorganization save retains the accepted pair, archive and reservations for retry',async()=>{
  const f=fixture();await at(f,40);f.data.set('payment-input-reservation',new Uint8Array([7]));const before=snapshot(f.data);
  f.head(43,25);f.failWrite(true);await assert.rejects(f.session.sync(),/storage abort/);
  assert.equal(f.current().height,40);assert.equal(f.session.metadata.height,40);assert.equal(f.session.invalidated,false);assert.equal(f.session.ready,false);assert.deepEqual(snapshot(f.data),before);
  f.failWrite(false);const next=f.reopen();assert.equal((await next.initialize()).height,40);assert.equal((await next.sync()).height,43);assert.deepEqual([...f.data.get('payment-input-reservation')],[7]);
});
test('cancellation before and during reorganization durability respects the existing adoption boundary',async()=>{
  for(const duringStorage of [false,true]){
    const f=fixture();await at(f,40);f.head(43,25);const before=snapshot(f.data);
    if(duringStorage)f.writeHook(()=>f.session.cancelSync());
    if(duringStorage){const result=await f.session.sync();assert.equal(result.height,43);assert.equal(result.ready,false);assert.equal(f.current().height,43);}
    else{await assert.rejects(f.session.sync(value=>{if(value.phase==='eng2-rollback')f.session.cancelSync();}),error=>error.name==='AbortError');assert.equal(f.current().height,40);assert.deepEqual(snapshot(f.data),before);}
    f.writeHook(null);const next=f.reopen();assert.equal((await next.initialize()).height,duringStorage?43:40);assert.equal((await next.sync()).height,43);
  }
});
test('cancelling an archive read on reopen preserves records before native restoration',async()=>{
  const f=fixture();await at(f,40);const before=snapshot(f.data),next=f.reopen();
  f.readHook(key=>{if(key.startsWith('rollback:'))next.cancelSync();});
  await assert.rejects(next.initialize(),error=>error.name==='AbortError');assert.equal(next.metadata,null);assert.deepEqual(snapshot(f.data),before);
  f.readHook(null);const reopened=f.reopen();assert.equal((await reopened.initialize()).height,40);
});
test('a missing legacy archive reports earlier rescan until authenticated window coverage exists',async()=>{
  const f=fixture();await at(f,40);for(const key of [...f.data.keys()])if(key.startsWith('rollback:'))f.data.delete(key);
  const next=f.reopen();await next.initialize();f.head(43,25);const progress=[],before=f.requests.length;
  await next.sync(value=>progress.push(value));assert.equal(progress[0].phase,'eng2-rescan');assert.equal(progress[0].reason,'missing-private-cache');
  assert.equal(downloads(f.requests.slice(before))[0],1);assert.equal(f.current().height,43);assert.equal(next.rollback.height,43);
});
test('a commit failure after durable rollback requires reopening the matched saved generation',async()=>{
  const f=fixture();await at(f,40);f.head(43,25);f.failCommit(true);
  await assert.rejects(f.session.sync(),/state was saved/);assert.equal(f.current().height,40);assert.equal(f.session.metadata.height,40);assert.equal(f.session.invalidated,true);
  f.failCommit(false);const next=f.reopen();assert.equal((await next.initialize()).height,43);assert.equal(next.rollback.height,43);assert.equal(next.invalidated,false);
  const archived=await loadEng2Rollback(f.storage,next.key,next.cacheKey,pin,next.metadata,open);assert.equal(archived.height,43);
});
