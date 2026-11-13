import {test} from 'node:test';
import assert from 'node:assert/strict';
import {eng2Context,eng2Namespace} from '../web/sdk/eng2-context.js';
import {eng2PublicGet} from '../web/sdk/eng2-sources.js';

const primary='https://primary.example.test',backup='https://backup.example.test';
const pin={version:2,name:'siworld-eng-2',network:'1'.repeat(64),genesis:'2'.repeat(64),rules:'3'.repeat(64),profile:'4'.repeat(64),fee_mode:0,api:primary,apis:[primary,backup],submission_apis:[backup,primary]};
const route='/api/v2/wallet/receipts/61/'+ '5'.repeat(64)+'?height=191&tip='+'6'.repeat(64);
const fast={wait:async()=>{},timeout:()=>new AbortController().signal};
const failure=status=>Object.assign(new Error('Synthetic service unavailable.'),{status});

test('data and submission sources are independently pinned without changing private namespaces',()=>{
  const value=eng2Context(pin);
  assert.deepEqual(value.apis,[primary,backup]);assert.deepEqual(value.submission_apis,[backup,primary]);
  assert.ok(Object.isFrozen(value.apis));assert.ok(Object.isFrozen(value.submission_apis));
  assert.equal(eng2Namespace(pin),eng2Namespace({...pin,apis:[primary],submission_apis:[primary]}));
  for(const changes of [{apis:[]},{apis:[backup,primary]},{apis:[primary,primary+'/']},{apis:[primary,primary+':443']},{apis:[primary,backup,'https://third.example.test']},{apis:[primary,'http://remote.example.test']},{submission_apis:[]},{submission_apis:[backup+'/?unsafe=true']},{submission_apis:'https://backup.example.test'}])assert.throws(()=>eng2Context({...pin,...changes}));
});
test('a transport failure switches origin with the exact selected-head route and retains that source',async()=>{
  const calls=[],bytes=new Uint8Array([1,2,3]);
  const get=eng2PublicGet(async(url,options)=>{calls.push(url);assert.equal(options.method,'GET');assert.equal(options.limit,8);if(url.startsWith(primary))throw failure(503);return {bytes};},pin,fast);
  assert.equal((await get(primary+route,{limit:8})).bytes,bytes);
  await get(primary+'/api/v2/wallet/head',{limit:8});
  assert.deepEqual(calls,[primary+route,backup+route,backup+'/api/v2/wallet/head']);
});
test('two unavailable sources have three total attempts rather than three attempts per source',async()=>{
  const calls=[];const get=eng2PublicGet(async url=>{calls.push(url);throw new TypeError('Synthetic transport failure.');},pin,fast);
  await assert.rejects(get(primary+route));assert.deepEqual(calls,[primary+route,backup+route,primary+route]);
});
test('byte bounds, permission errors and malformed successful bodies do not become source failover',async()=>{
  for(const error of [failure(403),failure(404),new Error('Response exceeds its byte limit.'),new SyntaxError('Synthetic decode failure.')]){
    const calls=[];const get=eng2PublicGet(async url=>{calls.push(url);throw error;},pin,fast);
    await assert.rejects(get(primary+route),value=>value===error);assert.deepEqual(calls,[primary+route]);
  }
  let calls=0;const get=eng2PublicGet(async()=>{calls++;return {bytes:new Uint8Array([255])};},pin,fast);
  const result=await get(primary+route);assert.deepEqual([...result.bytes],[255]);assert.equal(calls,1);
});
test('external cancellation prevents fallback and routes cannot escape the configured source',async()=>{
  const controller=new AbortController();let calls=0;
  const get=eng2PublicGet(async(_url,{signal})=>{calls++;const result=new Promise((_,reject)=>signal.addEventListener('abort',()=>reject(signal.reason),{once:true}));controller.abort();return result;},pin,fast);
  await assert.rejects(get(primary+route,{signal:controller.signal}),value=>value.name==='AbortError');assert.equal(calls,1);
  for(const url of [backup+route,primary+'/other',primary+route+'#fragment'])await assert.rejects(get(url),/outside its pinned source/);
  assert.equal(calls,1);
});
