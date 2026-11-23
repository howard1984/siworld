import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
const source=await readFile(new URL('../web/assets/native-wallet.js',import.meta.url),'utf8');
const start=source.indexOf('function startOnline()'),end=source.indexOf("$('#send-open').onclick",start);
assert.ok(start>0&&end>start);
function fixture(respond){
 const nodes=new Map(),scheduled=new Map(),requests=[],shown=[];let sequence=0;
 const context=vm.createContext({ENGINEERING:{name:'siworld-eng-2'},$:id=>{if(!nodes.has(id))nodes.set(id,{});return nodes.get(id);},call:async(action,...args)=>{requests.push(action);return respond(action,...args);},showBalance:(value,stale)=>shown.push({value,stale}),setTimeout:fn=>{const id=++sequence;scheduled.set(id,fn);return id;},clearTimeout:id=>scheduled.delete(id)});
 vm.runInContext('let epoch=0,onlineReady=false,onlineBusy=false,info={},pollTimer;'+source.slice(start,end)+";globalThis.control={startOnline,refreshOnline,state:()=>({epoch,onlineReady,onlineBusy,unlocked:!!info}),lock:()=>{++epoch;info=null;onlineReady=onlineBusy=false;},busy:()=>{onlineBusy=true;}};",context);
 return {control:context.control,nodes,scheduled,requests,shown};
}
test('initialization failure can be retried by the actual Sync now handler',async()=>{
 let initialization=0;const f=fixture(async action=>{if(action==='online-init'&&++initialization===1)throw new Error('Synthetic initialization timeout.');return {height:3};});
 await f.control.startOnline();assert.equal(f.control.state().onlineReady,false);assert.deepEqual(f.requests,['online-init']);assert.equal(f.scheduled.size,1);
 await f.nodes.get('#sync-now').onclick();assert.deepEqual(f.requests,['online-init','online-init','sync']);assert.equal(f.control.state().onlineReady,true);assert.equal(f.control.state().onlineBusy,false);assert.equal(f.scheduled.size,1);
});
test('scheduled retry reinitializes before synchronizing and clears the previous retry',async()=>{
 let attempt=0;const f=fixture(async action=>{if(action==='online-init'&&++attempt===1)throw new Error('Synthetic initialization failure.');return {height:4};});
 await f.control.startOnline();await [...f.scheduled.values()][0]();assert.deepEqual(f.requests,['online-init','online-init','sync']);assert.equal(f.scheduled.size,1);assert.equal(f.shown.at(-1).value.height,4);
});
test('sync failures keep the initialized owner and automatically retry synchronization',async()=>{
 let attempt=0;const f=fixture(async action=>{if(action==='sync'&&++attempt===1)throw new Error('Synthetic receipt timeout.');return {height:8};});
 await f.control.startOnline();assert.equal(f.control.state().onlineReady,true);assert.equal(f.nodes.get('#send-open').disabled,true);
 await [...f.scheduled.values()][0]();assert.deepEqual(f.requests,['online-init','sync','sync']);assert.equal(f.shown.at(-1).value.height,8);
});
test('concurrent clicks share one active initialization and locking rejects late results',async()=>{
 let finish;const f=fixture(()=>new Promise(resolve=>{finish=resolve;}));
 const pending=f.control.startOnline();await f.nodes.get('#sync-now').onclick();assert.deepEqual(f.requests,['online-init']);f.control.lock();finish({height:9});await pending;
 assert.equal(f.shown.length,0);assert.equal(f.scheduled.size,0);assert.equal(f.control.state().unlocked,false);assert.equal(f.control.state().onlineReady,false);
});
