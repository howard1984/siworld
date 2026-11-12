import {test} from 'node:test';
import assert from 'node:assert/strict';
import {Eng2Payments} from '../web/sdk/eng2-payments.js';
const pin={version:2,name:'siworld-eng-2',network:'1'.repeat(64),genesis:'2'.repeat(64),rules:'3'.repeat(64),profile:'4'.repeat(64),fee_mode:0,api:'http://127.0.0.1:8890'};
const id='5'.repeat(64),tip='6'.repeat(64),input='7'.repeat(96),enc=value=>new TextEncoder().encode(JSON.stringify(value)),dec=bytes=>JSON.parse(new TextDecoder().decode(bytes));
const packet=new Uint8Array([1,2,3,4]);
function fixture(admission) {
  const data=new Map(),events=[],packets=[];
  let fail=false,proofFail=false,anchorExpired=false,canonical=true,signatureBad=false,prepared=false,nextId=id,nextInput=input;
  const protect=bytes=>new Uint8Array([192,...bytes.map(value=>value^165)]),open=bytes=>bytes.slice(1).map(value=>value^165);
  const wallet={
    public_info:()=>JSON.stringify({network:pin.network,full_address:'synthetic-only-public-address'}),
    eng2_balance:()=>JSON.stringify({...pin,height:9,tip,send_supported:false}),
    protect_eng2_local:protect,open_eng2_local:open,
    prepare_eng2_sip:(network,height,head,recipient,resolved,amount,priority,reserved)=>{
      events.push('prepare');assert.equal(network,pin.network);assert.equal(height,'9');assert.equal(head,tip);
      if(JSON.parse(reserved).includes(nextInput))throw new Error('Synthetic reserved input unavailable.');
      prepared=true;return JSON.stringify({...pin,phase:'reserved',statement_id:nextId,inputs:[nextInput],anchor_height:9,anchor_tip:tip,expires_at_height:4105,amount_atoms:amount,fee_atoms:'100',input_atoms:'5000',payment_opening:'ab'.repeat(32)});
    },
    prove_eng2_sip:()=>{events.push('prove');assert.equal(prepared,true);assert.equal(dec(open(data.get('payments:opaque:'+nextId))).phase,'reserved');if(proofFail)throw new Error('Synthetic proving failure.');const bytes=packet.slice();packets.push(bytes);return bytes;},
    check_eng2_payment:(network,bytes)=>{events.push('verify');if(network!==pin.network||anchorExpired)throw new Error('Synthetic wrong network or expired anchor.');assert.deepEqual([...bytes],[...packet]);return JSON.stringify({statement_id:nextId,proof_verified:!signatureBad,anchor_height:9,anchor_tip:tip});},
    cancel_eng2_prepared:()=>{events.push('clear');prepared=false;},
    eng2_payment_receipt:(height,bytes,statement)=>{if(signatureBad)throw new Error('Synthetic unauthenticated receipt.');return JSON.stringify({statement_id:statement,height:Number(height),block_id:tip,receipt_authenticated:true,full_node_consensus_verified:false});},
    eng2_payment_inclusion_valid:()=>canonical,
  };
  const storage={read:async key=>data.get(key)?.slice(),pair:async(a,av,b,bv)=>{events.push('persist');if(fail)throw new Error('Synthetic atomic write failed.');data.set(a,av.slice());data.set(b,bv.slice());}};
  const session={wallet,config:pin,metadata:{height:9,tip},ready:true,syncing:false,invalidated:false,lockKey:'same-session-lock',fresh:async()=>{}};
  const locks={request:async(key,fn)=>{assert.equal(key,'same-session-lock');return fn();}};
  const io={storage,hash:async()=>'opaque',locks};
  if(admission)io.admit=async(bytes,context)=>{events.push('admit');assert.equal(dec(open(data.get('payments:opaque:'+id))).phase,'uncertain');return admission(bytes,context);};
  const payments=new Eng2Payments(session,io);
  return {payments,session,wallet,data,events,packets,io,open,setFail:()=>{fail=true;},setProofFail:()=>{proofFail=true;},setExpired:()=>{anchorExpired=true;},setReorg:()=>{canonical=false;},setBad:()=>{signatureBad=true;},setNextId:value=>{nextId=value;},setInput:value=>{nextInput=value;}};
}
const prepare=async f=>{await f.payments.initialize();return f.payments.prepare({recipient:'synthetic-recipient',amount:'1000'});};
const finalized=async f=>{await prepare(f);return f.payments.prove(id);};
test('offline journal durably reserves before proving and finalizes the exact native packet',async()=>{
  const f=fixture();await prepare(f);assert.equal(f.payments.summary().reserved_count,1);
  const result=await f.payments.prove(id);assert.equal(result.phase,'finalized');assert.equal(result.send_supported,false);
  assert.ok(f.events.indexOf('persist')<f.events.indexOf('prove'));assert.ok(f.packets.every(bytes=>bytes.every(value=>value===0)));
  assert.ok([...f.data.values()].every(bytes=>bytes[0]===192));
  const row=dec(f.open(f.data.get('payments:opaque:'+id)));assert.equal(row.packet_hex,'01020304');assert.equal(row.payment_opening,'ab'.repeat(32));
  assert.ok(!JSON.stringify(f.payments.summary()).includes('payment_opening'));
  await assert.rejects(f.payments.submit(id),/unavailable/);assert.equal(row.phase,'finalized');
});
test('write or proving failures never call admission and preserve input reservations',async()=>{
  const f=fixture();await prepare(f);f.setProofFail();await assert.rejects(f.payments.prove(id),/proving failure/);assert.equal(f.payments.summary().reserved_count,1);assert.equal(f.payments.summary().payments[0].phase,'reserved');
  const g=fixture();await g.payments.initialize();g.setFail();await assert.rejects(g.payments.prepare({recipient:'a',amount:'1'}),/write failed/);assert.equal(g.payments.summary().reserved_count,0);assert.ok(g.events.includes('clear'));assert.ok(!g.events.includes('prove'));
  const h=fixture();await prepare(h);h.setFail();await assert.rejects(h.payments.prove(id),/write failed/);assert.equal(h.payments.summary().payments[0].phase,'reserved');assert.ok(h.packets.every(bytes=>bytes.every(value=>value===0)));
});
test('ambiguous admission preserves inputs and retries the byte-identical durable packet after reopen',async()=>{
  let attempts=0;const seen=[];
  const f=fixture(async(bytes,context)=>{seen.push([...bytes]);if(attempts++===0)throw new Error('Synthetic transport timeout.');return {...pin,statement_id:context.statement_id,status:'accepted'};});
  await finalized(f);await assert.rejects(f.payments.submit(id),/timeout/);
  assert.equal(f.payments.summary().payments[0].phase,'uncertain');assert.equal(f.payments.summary().reserved_count,1);
  await assert.rejects(f.payments.cancel(id),/cannot release/);
  const reopened=new Eng2Payments(f.session,f.io);await reopened.initialize();const result=await reopened.submit(id);
  assert.equal(result.phase,'accepted');assert.equal(result.included,false);assert.deepEqual(seen,[[1,2,3,4],[1,2,3,4]]);
  assert.ok(f.events.indexOf('persist')<f.events.indexOf('admit'));
});
test('wrong-context acceptance remains uncertain and never becomes an inclusion',async()=>{
  const f=fixture(async(_bytes,context)=>({...pin,network:'9'.repeat(64),statement_id:context.statement_id,status:'accepted'}));
  await finalized(f);await assert.rejects(f.payments.submit(id),/uncertain/);assert.equal(f.payments.summary().payments[0].phase,'uncertain');assert.equal(f.payments.summary().reserved_count,1);
});
test('expired anchors and failed native verification stop before the transport',async()=>{
  for(const mutate of ['setExpired','setBad']){
    const f=fixture(async()=>{throw new Error('Transport must not run.');});await finalized(f);f[mutate]();await assert.rejects(f.payments.submit(id));assert.ok(!f.events.includes('admit'));assert.equal(f.payments.summary().payments[0].phase,'finalized');
  }
});
test('a failed uncertain-state durable write prevents all transport',async()=>{
  const f=fixture(async()=>{throw new Error('Transport must not run.');});await finalized(f);f.setFail();await assert.rejects(f.payments.submit(id),/write failed/);assert.ok(!f.events.includes('admit'));assert.equal(f.payments.summary().payments[0].phase,'finalized');
});
test('receipt authentication confirms inclusion and a reorganization reinstates uncertainty and reservations',async()=>{
  const f=fixture();await finalized(f);await f.payments.confirm(id,10,new Uint8Array([1]));assert.equal(f.payments.summary().payments[0].phase,'included');assert.equal(f.payments.summary().reserved_count,0);
  f.setReorg();await f.payments.reconcile();assert.equal(f.payments.summary().payments[0].phase,'uncertain');assert.equal(f.payments.summary().reserved_count,1);await assert.rejects(f.payments.cancel(id),/cannot release/);
  const g=fixture();await finalized(g);g.setBad();await assert.rejects(g.payments.confirm(id,10,new Uint8Array([1])),/unauthenticated/);assert.equal(g.payments.summary().payments[0].phase,'finalized');
});
test('reopened reserved payments may be cancelled but are never silently recreated',async()=>{
  const f=fixture();await prepare(f);const reopened=new Eng2Payments(f.session,f.io);await reopened.initialize();await reopened.cancel(id);assert.equal(reopened.summary().reserved_count,0);assert.equal(reopened.summary().payments[0].phase,'cancelled');
});
test('stale sessions, duplicate active reservations and another tab prevent a new payment',async()=>{
  const f=fixture();await prepare(f);await assert.rejects(f.payments.prepare({recipient:'a',amount:'1'}),/existing reserved/);
  await f.payments.cancel(id);f.session.ready=false;await assert.rejects(f.payments.prepare({recipient:'a',amount:'1'}),/synchronization/);
  const g=fixture();await prepare(g);const other=new Eng2Payments(g.session,g.io);await other.initialize();await other.cancel(id);await assert.rejects(g.payments.prove(id),/Another tab/);
});
test('wrong-context and inconsistent encrypted journals refuse to open',async()=>{
  const f=fixture();await prepare(f);const original=dec(f.open(f.data.get('payments:opaque')));f.data.set('payments:opaque',f.wallet.protect_eng2_local(enc({...original,network:'9'.repeat(64)})));
  await assert.rejects(new Eng2Payments(f.session,f.io).initialize(),/context differs/);
  const g=fixture();await prepare(g);const row=dec(g.open(g.data.get('payments:opaque:'+id)));g.data.set('payments:opaque:'+id,g.wallet.protect_eng2_local(enc({...row,inputs:['a'.repeat(96)]})));await assert.rejects(g.payments.cancel(id),/disagree/);
});

test('cancelling an older finalized packet preserves another payment prepared witness',async()=>{
  const f=fixture();await finalized(f);const second='9'.repeat(64);f.setNextId(second);f.setInput('a'.repeat(96));await f.payments.prepare({recipient:'a',amount:'1'});
  await f.payments.cancel(id);const proved=await f.payments.prove(second);assert.equal(proved.phase,'finalized');assert.equal(proved.statement_id,second);
});
