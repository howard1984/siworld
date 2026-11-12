import {test} from 'node:test';
import assert from 'node:assert/strict';
import {publicGet,publicJSON} from '../web/sdk/public-fetch.js';

const url='https://example.test/api/v2/wallet/head';
const transportError=name=>new DOMException('Synthetic transport failure.',name);
const statusError=status=>Object.assign(new Error('Synthetic HTTP failure.'),{status});
function fixture() {
  const signals=[],delays=[];
  return {signals,delays,io:{timeout:milliseconds=>{assert.equal(milliseconds,30000);const controller=new AbortController();signals.push(controller);return controller.signal;},wait:async milliseconds=>{delays.push(milliseconds);}}};
}

test('transient GET failures have three total attempts with new deadlines and bounded backoff',async()=>{
  for(const failure of [transportError('TimeoutError'),new TypeError('Synthetic network failure.'),...([429,502,503,504].map(statusError))]){
    const f=fixture(),seen=[];
    const request=async(target,options)=>{assert.equal(target,url);assert.equal(options.method,'GET');assert.equal(options.limit,123);seen.push(options.signal);throw failure;};
    await assert.rejects(publicGet(request,url,{limit:123},f.io),error=>error===failure);
    assert.equal(seen.length,3);assert.equal(new Set(seen).size,3);assert.equal(f.signals.length,3);assert.deepEqual(f.delays,[500,1000]);
  }
});
test('successful retry preserves the returned object and caller-owned buffer',async()=>{
  const f=fixture(),bytes=new Uint8Array([1,2,3]),result={bytes};let calls=0;
  assert.equal(await publicGet(async()=>{if(++calls===1)throw statusError(503);return result;},url,{},f.io),result);
  assert.equal(calls,2);assert.deepEqual([...bytes],[1,2,3]);assert.deepEqual(f.delays,[500]);
  bytes.fill(0);assert.deepEqual([...result.bytes],[0,0,0]);
});
test('JSON and UTF-8 decoding occur outside the transport retry boundary',async()=>{
  for(const bytes of [new TextEncoder().encode('{invalid'),new Uint8Array([255])]){
    const f=fixture();let calls=0;
    await assert.rejects(publicJSON(async()=>{calls++;return {bytes};},url,{},f.io),/Malformed engineering service response/);
    assert.equal(calls,1);assert.deepEqual(f.delays,[]);
  }
  const f=fixture();let calls=0;
  assert.deepEqual(await publicJSON(async()=>{if(++calls===1)throw statusError(502);return {bytes:new TextEncoder().encode('{"height":1}')};},url,{},f.io),{height:1});
  assert.equal(calls,2);assert.deepEqual(f.delays,[500]);
});
test('non-GET and GET bodies are rejected without calling the transport',async()=>{
  let calls=0;const request=async()=>{calls++;};
  for(const options of [{method:'POST'},{method:'PUT'},{method:'DELETE'},{method:'HEAD'},{body:new Uint8Array([1])}])await assert.rejects(publicGet(request,url,options),/Only an idempotent public GET/);
  assert.equal(calls,0);
});
test('permanent HTTP, byte-bound, JSON, context and authentication errors are not retried',async()=>{
  for(const failure of [statusError(400),statusError(401),statusError(403),statusError(404),statusError(500),new Error('Response exceeds its byte limit.'),new SyntaxError('Synthetic malformed JSON.'),new Error('Malformed engineering service response.'),new Error('Engineering-v2 head differs from its pinned context, height bound or freshness policy.'),new Error('Synthetic native receipt authentication rejected.')]){
    const f=fixture();let calls=0;
    await assert.rejects(publicGet(async()=>{calls++;throw failure;},url,{},f.io),error=>error===failure);
    assert.equal(calls,1);assert.deepEqual(f.delays,[]);
  }
});
test('a deadline does not turn a nontransport parsing or byte-bound error into a retry',async()=>{
  for(const failure of [new SyntaxError('Synthetic JSON failure.'),new Error('Response exceeds its byte limit.')]){
    const f=fixture();let calls=0;
    await assert.rejects(publicGet(async()=>{calls++;f.signals.at(-1).abort(transportError('TimeoutError'));throw failure;},url,{},f.io),error=>error===failure);
    assert.equal(calls,1);assert.deepEqual(f.delays,[]);
  }
});
test('external cancellation before and during a transport attempt is never retried',async()=>{
  const outer=new AbortController(),reason=transportError('AbortError');outer.abort(reason);let calls=0;
  await assert.rejects(publicGet(async()=>{calls++;},url,{signal:outer.signal}),error=>error===reason);assert.equal(calls,0);
  const active=new AbortController(),f=fixture();
  await assert.rejects(publicGet(async(_url,{signal})=>{calls++;const waiting=new Promise((_,reject)=>signal.addEventListener('abort',()=>reject(signal.reason),{once:true}));active.abort(reason);return waiting;},url,{signal:active.signal},f.io),error=>error===reason);
  assert.equal(calls,1);assert.deepEqual(f.delays,[]);
});
test('external cancellation during backoff stops before the next attempt',async()=>{
  const outer=new AbortController(),reason=transportError('AbortError');let calls=0;
  const pending=publicGet(async()=>{calls++;throw statusError(429);},url,{signal:outer.signal});
  await new Promise(resolve=>setImmediate(resolve));outer.abort(reason);
  await assert.rejects(pending,error=>error===reason);assert.equal(calls,1);
});
test('per-attempt timeout renews without aborting the external owner signal',async()=>{
  const outer=new AbortController(),f=fixture();let calls=0;
  const result=await publicGet(async(_url,{signal})=>{
    if(++calls===1){const waiting=new Promise((_,reject)=>signal.addEventListener('abort',()=>reject(signal.reason),{once:true}));f.signals[0].abort(transportError('TimeoutError'));return waiting;}
    assert.equal(signal.aborted,false);return 'success';
  },url,{signal:outer.signal},f.io);
  assert.equal(result,'success');assert.equal(calls,2);assert.equal(outer.signal.aborted,false);assert.deepEqual(f.delays,[500]);
});
