import {test} from 'node:test';
import assert from 'node:assert/strict';
import {eng2Admission} from '../web/sdk/eng2-admission.js';
const pin={version:2,name:'siworld-eng-2',network:'1'.repeat(64),genesis:'2'.repeat(64),rules:'3'.repeat(64),profile:'4'.repeat(64),fee_mode:0,api:'http://127.0.0.1:8890'};
const statement='5'.repeat(64),expected={...pin,type:'eng2-admission',statement_id:statement};
const {name,api,...context}=pin;
const ack={...context,status:'pending',statement_id:statement,included:false};
function packet(){const raw=new Uint8Array(2184+1+78);raw.set(new TextEncoder().encode('SWTX'));raw.set(new Uint8Array(32).fill(17),33);new DataView(raw.buffer).setUint32(2180,1,true);raw.set(new TextEncoder().encode('SWFS'),raw.length-78);return raw;}
const response=(value=ack,options={})=>new Response(JSON.stringify(value),{status:200,headers:{'Content-Type':'application/json'},...options});
test('explicit eng2 adapter binds context and maps native pending admission without inclusion',async()=>{
  let calls=0;const admit=eng2Admission(pin,{fetch:async(url,request)=>{calls++;assert.equal(url,pin.api+'/api/v2/wallet/transactions');assert.equal(request.method,'POST');assert.equal(request.credentials,'omit');assert.equal(request.redirect,'error');assert.equal(request.cache,'no-store');assert.deepEqual(JSON.parse(request.headers['X-SIWORLD-Context']),context);assert.equal(request.headers['X-SIWORLD-Statement'],statement);assert.deepEqual([...request.body],[...packet()]);return response();}});
  assert.equal(calls,0);const result=await admit(packet(),expected);assert.equal(calls,1);assert.equal(result.status,'accepted');assert.equal(result.included,false);assert.equal(result.statement_id,statement);
});
test('foreign context, wrong network and malformed envelope framing fail before transport',async()=>{
  const admit=eng2Admission(pin,{fetch:async()=>{throw new Error('Transport must not run.');}});
  await assert.rejects(admit(packet(),{...expected,genesis:'9'.repeat(64)}),/context/);
  for(const mutation of [value=>{value[33]^=1;},value=>{value[2180]=2;},value=>{value[value.length-78]^=1;},value=>{value[0]=0;}]){const raw=packet();mutation(raw);await assert.rejects(admit(raw,expected),/packet/);}
  await assert.rejects(admit(new Uint8Array(700000),expected),/bounds/);
});
test('wrong-context, wrong-statement, extra-field and inclusion acknowledgements are refused',async()=>{
  for(const value of [{...ack,network:'9'.repeat(64)},{...ack,statement_id:'9'.repeat(64)},{...ack,included:true},{...ack,status:'queued'},{...ack,extra:true}]){
    await assert.rejects(eng2Admission(pin,{fetch:async()=>response(value)})(packet(),expected),/acknowledgement/);
  }
});
test('unavailable, non-JSON and oversized responses remain uncertain',async()=>{
  for(const value of [response(ack,{status:503}),response(ack,{headers:{'Content-Type':'text/html'}}),response(ack,{headers:{'Content-Type':'application/json','Content-Length':'5000'}}),response({...ack,padding:'x'.repeat(5000)})]){
    await assert.rejects(eng2Admission(pin,{fetch:async()=>value})(packet(),expected));
  }
});
