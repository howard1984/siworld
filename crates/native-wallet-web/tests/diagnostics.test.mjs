import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {runInNewContext} from 'node:vm';
import {failureContext,failureDiagnostic,workerFailure,failureFromReply} from '../web/sdk/diagnostics.js';
import {publicGet,publicJSON} from '../web/sdk/public-fetch.js';
import {fetchLimited} from '../web/sdk/online-storage.js';
const secret='private-fixture-value-not-for-diagnostics';

test('a frozen nested transport rejection crosses the worker boundary with only categorical causes',()=>{
  const timeout=new DOMException(secret,'TimeoutError');
  const failure=Object.freeze(Object.assign(new Error(secret,{cause:timeout}),{status:503}));
  assert.equal(failureContext(failure,'public-source',{source:2,attempt:3}),failure);
  failureContext(failure,'receipt-fetch');
  const reply=structuredClone(workerFailure(7,'sync',failureContext(failure,'dispatch')));
  const restored=failureFromReply(reply),diagnostic=restored.diagnostic;
  assert.deepEqual(diagnostic.chain.map(row=>row.kind),['Error','TimeoutError']);
  assert.equal(diagnostic.chain[0].http_status,503);
  assert.ok(diagnostic.chain[0].contexts.some(row=>row.stage==='public-source'&&row.source===2&&row.attempt===3));
  assert.ok(diagnostic.chain[0].contexts.some(row=>row.stage==='receipt-fetch'));
  assert.ok(!JSON.stringify(diagnostic).includes(secret));
  assert.ok(!JSON.stringify(diagnostic).includes('message'));
  assert.notEqual(restored,failure);
});

test('primitive native errors, cycles and throwing accessors remain bounded and redact their values',()=>{
  const primitive=failureContext(secret,'receipt-apply');
  assert.deepEqual(failureDiagnostic(primitive,'sync').chain.map(row=>row.kind),['Error','String']);
  const cycle=new Error(secret);cycle.cause=cycle;
  assert.equal(failureDiagnostic(cycle,'sync').truncated,true);
  let nested=new Error(secret);
  for(let i=0;i<20;i++)nested=new Error(secret,{cause:nested});
  assert.equal(failureDiagnostic(nested,'sync').chain.length,6);
  assert.equal(failureDiagnostic(nested,'sync').truncated,true);
  const hostile={get name(){throw new Error(secret);},get status(){throw new Error(secret);},get cause(){throw new Error(secret);},get message(){throw new Error(secret);}};
  const reply=workerFailure(8,secret,hostile);
  assert.equal(reply.diagnostic.action,'unknown');assert.equal(reply.diagnostic.chain[0].kind,'Unknown');
  assert.ok(!JSON.stringify(reply).includes(secret));
});

test('the page rejects oversized or expanded diagnostic schemas instead of copying arbitrary worker fields',()=>{
  const valid=workerFailure(1,'sync',failureContext(new Error(secret),'receipt-fetch'));
  for(const mutate of [value=>{value.url=secret;},value=>{value.chain[0].message=secret;},value=>{value.chain[0].contexts[0].stage=secret;},value=>{value.chain=Array(7).fill(value.chain[0]);},value=>{value.chain[0].contexts=Array(9).fill({stage:'dispatch'});},value=>{value.chain[0].http_status='503';}]){
    const reply=structuredClone(valid);mutate(reply.diagnostic);
    assert.equal(failureFromReply(reply).diagnostic,undefined);
  }
});

test('the actual page RPC rejection retains the redacted worker cause metadata',async()=>{
  const source=await readFile(new URL('../web/assets/native-wallet.js',import.meta.url),'utf8');
  const start=source.indexOf('function startWorker()'),end=source.indexOf('function clearSecrets()',start);
  assert.ok(start>0&&end>start);
  const failure=Object.assign(new Error(secret,{cause:new DOMException(secret,'TimeoutError')}),{status:504});
  failureContext(failure,'receipt-fetch');
  class Worker {
    postMessage({id,action}){queueMicrotask(()=>this.onmessage({data:structuredClone(workerFailure(id,action,failure))}));}
  }
  const context={Worker,URL,Promise,Map,ENGINEERING:{name:'siworld-eng-2'},failureFromReply};
  runInNewContext('let worker,sequence=0,epoch=0,ready=false,storageHealthy=false,info=null;const pending=new Map();'+source.slice(start,end).replaceAll('import.meta.url',JSON.stringify('https://wallet.example.test/assets/wallet.mjs'))+'startWorker();globalThis.invoke=call;',context);
  await assert.rejects(context.invoke('sync'),error=>error.diagnostic.chain[0].http_status===504&&error.diagnostic.chain[1].kind==='TimeoutError'&&error.diagnostic.chain[0].contexts.some(row=>row.stage==='receipt-fetch'));
});

test('JSON decoding keeps its real cause and does not enter the transport retry loop',async()=>{
  for(const bytes of [new TextEncoder().encode('{invalid'),new Uint8Array([255])]){
    let calls=0;
    await assert.rejects(publicJSON(async()=>{calls++;return {bytes};},'https://service.example.test/api/v2/wallet/head'),error=>{
      const diagnostic=failureDiagnostic(error,'sync');
      return diagnostic.chain[0].contexts.some(row=>row.stage==='json-decode')&&['SyntaxError','TypeError'].includes(diagnostic.chain[1].kind);
    });
    assert.equal(calls,1);
  }
});

test('a failed body-reader cancellation cannot replace the primary timeout or its retry policy',async()=>{
  const originalFetch=globalThis.fetch,timeout=new DOMException(secret,'TimeoutError');let requests=0,cancellations=0;
  globalThis.fetch=async()=>{requests++;return {ok:true,headers:{get:()=>null},body:{getReader:()=>({read:async()=>{throw timeout;},cancel:async()=>{cancellations++;throw new TypeError(secret);}})}};};
  try{
    await assert.rejects(publicGet(fetchLimited,'https://service.example.test/api/v2/wallet/head',{}, {timeout:()=>new AbortController().signal,wait:async()=>{}}),error=>error===timeout);
    const diagnostic=failureDiagnostic(timeout,'sync');
    assert.equal(requests,3);assert.equal(cancellations,3);
    assert.ok(diagnostic.chain[0].contexts.some(row=>row.stage==='response-cancel'&&row.related_kind==='TypeError'));
    assert.ok(!JSON.stringify(diagnostic).includes(secret));
  }finally{globalThis.fetch=originalFetch;}
});
