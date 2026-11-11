import {test} from 'node:test';
import assert from 'node:assert/strict';
import {Eng2WalletSession} from '../web/sdk/eng2-wallet-session.js';
import {eng2EntryAcceptance,assertWalletOperation} from '../web/sdk/runtime-profile.js';
import {transactionRows} from '../web/assets/wallet-history.js';

const pin={version:2,name:'siworld-eng-2',network:'1'.repeat(64),genesis:'2'.repeat(64),rules:'3'.repeat(64),profile:'4'.repeat(64),fee_mode:0,api:'http://127.0.0.1:8890',read_only:true};
const id='5'.repeat(64),input='7'.repeat(96),SIP='0'.repeat(64);
const encode=value=>new TextEncoder().encode(JSON.stringify(value));
const decode=value=>JSON.parse(new TextDecoder().decode(value));
const block=height=>height.toString(16).padStart(64,'0');
const ABSENT='eng2 payment statement absent from authenticated receipt';
function fixture(){
  const data=new Map(),requests=[],events=[];
  let height=9,includeAt=null,authenticated=true,badHeader=false,receiptError=null,canonical=true;
  let admitted=false,storedPacket=null,clock=0,paused=false;
  const protection=bytes=>new Uint8Array([192,...bytes.map(x=>x^165)]),opening=bytes=>bytes.slice(1).map(x=>x^165);
  const wallet={
    public_info:()=>JSON.stringify({network:pin.network,full_address:'public-synthetic-address'}),
    protect_eng2_local:protection,open_eng2_local:opening,
    eng2_balance:()=>JSON.stringify({...pin,height,tip:block(height)}),
    prepare_eng2_sip:(_network,anchor,tip,recipient,_resolved,amount)=>{
      events.push('prepare');return JSON.stringify({...pin,statement_id:id,phase:'reserved',anchor_height:Number(anchor),anchor_tip:tip,inputs:[input],input_atoms:'5000',amount_atoms:amount,fee_atoms:'100',payment_opening:'private-opening',private_extension:'must-not-reach-page'});
    },
    prove_eng2_sip:()=>{events.push('prove');assert.equal(decode(opening(data.get('payments:opaque:'+id))).phase,'reserved');return new Uint8Array([1,2,3]);},
    check_eng2_payment:()=>JSON.stringify({statement_id:id,proof_verified:true,anchor_height:9,anchor_tip:block(9)}),
    cancel_eng2_prepared:()=>{},
    eng2_payment_inclusion_valid:(value,hash)=>canonical&&hash===block(Number(value))&&Number(value)<=height,
    eng2_header_page:bytes=>new TextDecoder().decode(bytes),
    eng2_payment_receipt:(value,_bytes,statement)=>{
      if(receiptError)throw new Error(receiptError);
      if(!authenticated)throw new Error('Synthetic unauthenticated receipt.');
      if(Number(value)!==includeAt)throw new Error(ABSENT);
      return JSON.stringify({statement_id:statement,height:Number(value),block_id:block(Number(value)),receipt_authenticated:true,full_node_consensus_verified:false});
    },
  };
  const storage={read:async key=>data.get(key)?.slice(),pair:async(a,av,b,bv)=>{data.set(a,av.slice());data.set(b,bv.slice());}};
  let held=false;
  const locks={request:async(_key,fn)=>{assert.equal(held,false,'locks must not be nested');held=true;try{return await fn();}finally{held=false;}}};
  const session={wallet,config:pin,lockKey:'same-owner',metadata:null,ready:false,syncing:false,invalidated:false,base:pin.api+'/api/v2/wallet',
    initialize:async()=>{session.metadata={height,tip:block(height)};},
    summary:()=>({...pin,height,tip:block(height),ready:session.ready,stale:!session.ready,send_supported:false,full_node_consensus_verified:false,rows:[{asset:SIP,available_atoms:'10000',locked_atoms:'200'}],payments:[]}),
    fresh:async()=>{},sync:async()=>{session.metadata={height,tip:block(height)};session.ready=true;return session.summary();},
    cancelSync:()=>{session.ready=false;paused=true;},
    binary:async(url,options)=>{
      requests.push(url);assert.ok(options.signal);const parsed=new URL(url);
      assert.equal(parsed.searchParams.get('height'),String(height));assert.equal(parsed.searchParams.get('tip'),block(height));
      if(parsed.pathname.endsWith('/headers')){
        const from=Number(parsed.searchParams.get('from')),limit=Number(parsed.searchParams.get('limit'));
        assert.ok(limit<=32);return {bytes:encode({height,tip:block(height),from,headers:Array.from({length:limit},(_,i)=>({height:from+i,id:badHeader?'a'.repeat(64):block(from+i)}))})};
      }
      if(paused)options.signal.throwIfAborted();
      return {bytes:encode({synthetic:true})};
    },
  };
  const io={session,storage,locks,hash:async()=>'opaque',now:()=>123,clock:()=>clock+=5,
    admit:async(packet,context)=>{admitted=true;storedPacket=[...packet];assert.equal(decode(opening(data.get('payments:opaque:'+id))).phase,'uncertain');return {...pin,status:'accepted',statement_id:context.statement_id};}};
  const owner=new Eng2WalletSession(wallet,pin,io);
  return {owner,wallet,session,io,data,requests,events,opening,setHeight:value=>{height=value;},setIncluded:value=>{includeAt=value;},setBadReceipt:()=>{authenticated=false;},setBadHeader:()=>{badHeader=true;},setError:value=>{receiptError=value;},setReorg:()=>{canonical=false;},admitted:()=>admitted,storedPacket:()=>storedPacket};
}
async function prepared(f){await f.owner.initialize();await f.owner.sync();return f.owner.prepare('synthetic-recipient','','1000',false);}
async function accepted(f){await prepared(f);return f.owner.submit(id);}

test('actual composed entry projects only display metadata and subtracts held input totals',async()=>{
  const f=fixture(),progress=[];await f.owner.initialize();await f.owner.sync();
  const result=await f.owner.prepare('synthetic-recipient','','1000',false,value=>progress.push(value));
  assert.equal(result.prepared_id,id);assert.equal(result.proving_ms,5);assert.equal(result.payments[0].id,id);
  assert.equal(result.payments[0].recipient,'synthetic-recipient');assert.equal(result.payments[0].created_at,123);
  assert.equal(result.rows[0].available_atoms,'5000');assert.equal(result.rows[0].mature_atoms,'10000');assert.equal(result.rows[0].reserved_atoms,'5000');
  assert.deepEqual(progress,['preparing','proving','saving']);assert.deepEqual(f.events,['prepare','prove']);
  const publicResult=JSON.stringify(result);
  for(const name of ['private-opening','private_extension','must-not-reach-page','payment_opening','packet_hex','inputs'])assert.ok(!publicResult.includes('"'+name+'"'));
  assert.equal(result.send_supported,false);assert.equal(result.full_node_consensus_verified,false);
  assert.deepEqual(result.entry_acceptance,eng2EntryAcceptance());
  for(const action of ['prepare','submit','cancel-payment','register-address'])assert.throws(()=>assertWalletOperation(action,pin));
});
test('pending acknowledgement stays pending until native authenticated inclusion and survives owner release',async()=>{
  const f=fixture(),pending=await accepted(f);assert.equal(f.admitted(),true);assert.deepEqual(f.storedPacket(),[1,2,3]);
  assert.equal(pending.payments[0].phase,'accepted');assert.equal(pending.rows[0].reserved_atoms,'5000');
  const saved=[...f.data.entries()].map(([key,bytes])=>[key,[...bytes]]);
  f.owner.release();assert.deepEqual([...f.data.entries()].map(([key,bytes])=>[key,[...bytes]]),saved);
  await assert.rejects(f.owner.summary(),/Reopen/);
  const reopened=new Eng2WalletSession(f.wallet,pin,f.io);await reopened.initialize();f.setHeight(10);f.setIncluded(10);
  const result=await reopened.sync();assert.equal(result.payments[0].phase,'included');assert.equal(result.payments[0].confirmed_height,10);
  assert.equal(result.reserved_count,0);assert.equal(result.rows[0].reserved_atoms,'0');assert.equal(result.send_supported,false);
});
test('receipt reconciliation is pinned, bounded to 32 per refresh and resumes its cursor',async()=>{
  const f=fixture();await accepted(f);f.setHeight(80);
  await f.owner.sync();assert.equal(f.requests.filter(url=>url.includes('/receipts/')).length,32);
  assert.equal(f.owner.cursor.next,42);
  await f.owner.sync();assert.equal(f.requests.filter(url=>url.includes('/receipts/')).length,64);assert.equal(f.owner.cursor.next,74);
  await f.owner.sync();assert.equal(f.requests.filter(url=>url.includes('/receipts/')).length,71);assert.equal(f.owner.cursor.next,81);
  await f.owner.sync();assert.equal(f.requests.filter(url=>url.includes('/receipts/')).length,71);
  assert.equal((await f.owner.summary()).payments[0].phase,'accepted');
});
test('only exact authenticated absence is ignored; invalid receipts or branches fail closed',async()=>{
  for(const error of ['Synthetic unauthenticated receipt.',ABSENT+' extra']){
    const f=fixture();await accepted(f);f.setHeight(10);f.setError(error);
    await assert.rejects(f.owner.sync(),new RegExp(error.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
    assert.equal((await f.owner.summary()).payments[0].phase,'accepted');assert.equal(f.owner.cursor.next,10);
  }
  const f=fixture();await accepted(f);f.setHeight(10);f.setBadHeader();await assert.rejects(f.owner.sync(),/branch differs/);
  assert.equal(f.requests.filter(url=>url.includes('/receipts/')).length,0);
});
test('reorganization restores uncertainty and reservations without creating a replacement packet',async()=>{
  const f=fixture();await accepted(f);f.setHeight(10);f.setIncluded(10);await f.owner.sync();
  assert.equal((await f.owner.summary()).payments[0].phase,'included');f.setReorg();
  await assert.rejects(f.owner.sync(),/branch differs/);
  const result=await f.owner.summary();assert.equal(result.payments[0].phase,'uncertain');assert.equal(result.reserved_count,1);assert.equal(result.rows[0].reserved_atoms,'5000');
  await assert.rejects(f.owner.cancel(id),/cannot release/);
  assert.deepEqual(f.storedPacket(),[1,2,3]);
});
test('history distinguishes pending admission, authenticated inclusion and cancelled payments',()=>{
  const result={height:20,received_records:[],payments:['reserved','finalized','uncertain','accepted','included','cancelled'].map((phase,i)=>({id:String(i),phase,amount_atoms:'1000',fee_atoms:'100',created_at:123,confirmed_height:phase==='included'?10:null}))};
  const rows=transactionRows(result),byPhase=Object.fromEntries(rows.map(row=>[row.phase,row]));
  assert.equal(byPhase.accepted.status,'Pending');assert.equal(byPhase.uncertain.status,'Status uncertain');
  assert.equal(byPhase.included.status,'Included in authenticated receipt');assert.equal(byPhase.cancelled.status,'Cancelled');
  assert.equal(byPhase.accepted.height,null);assert.equal(byPhase.included.height,10);
});

test('wallet-change cancellation aborts receipt adoption and preserves the encrypted pending packet',async()=>{
  const f=fixture();await accepted(f);f.setHeight(10);f.setIncluded(10);
  const original=f.session.binary;let receiptBytes;
  f.session.binary=async(url,options)=>{
    const result=await original(url,options);
    if(url.includes('/receipts/')){receiptBytes=result.bytes;f.owner.cancelSync();}
    return result;
  };
  await assert.rejects(f.owner.sync(),error=>error.name==='AbortError');
  assert.equal(receiptBytes.every(value=>value===0),true);
  const result=await f.owner.summary();assert.equal(result.ready,false);assert.equal(result.payments[0].phase,'accepted');
  assert.equal(result.rows[0].reserved_atoms,'5000');
  const saved=decode(f.opening(f.data.get('payments:opaque:'+id)));assert.equal(saved.packet_hex,'010203');
});
