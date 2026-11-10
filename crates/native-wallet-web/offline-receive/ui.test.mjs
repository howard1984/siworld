// Simulated DOM/worker tests. No browser wallet or real cryptography is started.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {SourceTextModule, createContext} from 'node:vm';
import {backup} from './protocol.mjs';
const pin={name:'siworld-eng-2',network:'a1'.repeat(32),genesis:null,account:0,birth_height:0,receive_only:true,origin:'http://127.0.0.1:8879',context_sha256:'b2'.repeat(32)};
const encrypted=backup(pin,Uint8Array.from(Buffer.from('53574e564c543031'+'00'.repeat(124),'hex')));
const sealResult={backup:encrypted,info:{full_address:'synthetic-public-address'}};
const event={preventDefault(){}};
function deferred(){let resolve;const promise=new Promise(done=>{resolve=done;});return {promise,resolve};}
class Element {
 constructor(tag='div',id=''){this.tag=tag;this.id=id;this.value='';this.textContent='';this.disabled=false;this.hidden=false;this.children=[];this.files=[];}
 replaceChildren(...children){this.children=children;}
 append(child){this.children.push(child);}
 querySelectorAll(tag){return this.children.flatMap(child=>[...(child.tag===tag?[child]:[]),...child.querySelectorAll(tag)]);}
 click(){if(!this.disabled)return this.onclick?.();}
 focus(){}
}
async function fixture(){
 const nodes=new Map();
 const buttonIds=['create','open','lock','written','save','verify','copy'];
 const inputIds=['password','repeat','unlock-password','file'];
 for(const id of ['status','words','answers','recovery','seal','download','unlock','receiving','address','network',...buttonIds,...inputIds])nodes.set(id,new Element(buttonIds.includes(id)?'button':inputIds.includes(id)?'input':'div',id));
 for(const id of ['create','open','lock'])nodes.get(id).disabled=true;
 for(const id of ['recovery','seal','download','unlock','receiving'])nodes.get(id).hidden=true;
 const workers=[],listeners=new Map(), timers=new Map();let nextTimer=0;
 class FakeWorker {
  constructor(){this.requests=[];this.terminated=false;workers.push(this);}
  postMessage(request){this.requests.push(structuredClone(request));}
  terminate(){this.terminated=true;}
  ready(){this.onmessage({data:{ready:true}});}
  respond(result){const request=this.requests.at(-1);this.onmessage({data:{id:request.id,result:structuredClone(result)}});}
 }
 const document={getElementById:id=>nodes.get(id),createElement:tag=>new Element(tag),addEventListener(){},
  querySelectorAll:()=>[...nodes.values()].filter(node=>['button','input'].includes(node.tag)).concat(nodes.get('answers').querySelectorAll('input'))};
 const window={Worker:FakeWorker,WebAssembly:{},addEventListener:(name,fn)=>listeners.set(name,fn)};window.top=window;
 const sandbox=createContext({document,window,Worker:FakeWorker,WebAssembly:{},crypto:{getRandomValues(){throw Error('No key generation in UI fixture.');}},
  navigator:{serviceWorker:{controller:null},clipboard:{writeText:async()=>{}}},location:{origin:pin.origin},isSecureContext:true,
  TextEncoder,URL,Blob,Set,Map,Error,Promise,setTimeout:(fn)=>{const id=++nextTimer;timers.set(id,fn);return id;},clearTimeout:id=>timers.delete(id)});
 const modules=new Map();
 async function module(name){
  if(modules.has(name))return modules.get(name);
  const text=name==='context.mjs'?'export const CONTEXT = '+JSON.stringify(pin)+';':readFileSync(new URL(name,import.meta.url),'utf8');
  const loaded=new SourceTextModule(text,{context:sandbox,identifier:pin.origin+'/'+name,initializeImportMeta:meta=>{meta.url=pin.origin+'/'+name;}});
  modules.set(name,loaded);await loaded.link(spec=>module(spec.replace('./','')));return loaded;
 }
 const loaded=await module('app.mjs');await loaded.evaluate();workers[0].ready();
 return {nodes,workers,listeners,timers,get:id=>nodes.get(id),current:()=>workers.at(-1)};
}
const tick=()=>new Promise(done=>setImmediate(done));
async function created(f){const task=f.get('create').click();f.current().respond({words:Array(24).fill('synthetic').join(' '),positions:[1,8,24]});await task;}
async function sealed(f){await created(f);f.get('written').click();for(const input of f.get('answers').querySelectorAll('input'))input.value='synthetic';f.get('password').value=f.get('repeat').value='synthetic-test-password';const task=f.get('seal').onsubmit(event);f.current().respond(sealResult);await task;}
function assertCleared(f){assert.equal(f.get('words').children.length,0);assert.equal(f.get('address').value,'');for(const id of ['recovery','seal','download','unlock','receiving'])assert.equal(f.get(id).hidden,true);}
test('clear during delayed creation ignores the old worker and allows a fresh session',async()=>{
 const f=await fixture(),old=f.current();const task=f.get('create').click();
 assert.equal(f.get('create').disabled,true);assert.equal(f.get('lock').disabled,false);
 f.get('lock').click();old.respond({words:Array(24).fill('synthetic').join(' '),positions:[1,8,24]});await task;
 assert.equal(old.terminated,true);assertCleared(f);f.current().ready();await created(f);assert.equal(f.get('words').children.length,24);
});
test('clear during delayed sealing prevents backup or address resurrection and clears challenge fields immediately',async()=>{
 const f=await fixture();await created(f);f.get('written').click();assert.equal(f.get('words').children.length,0);
 const inputs=f.get('answers').querySelectorAll('input');for(const input of inputs)input.value='synthetic';
 f.get('password').value=f.get('repeat').value='synthetic-test-password';const old=f.current(),task=f.get('seal').onsubmit(event);
 assert.equal(f.get('password').value,'');assert.equal(f.get('repeat').value,'');assert.ok(inputs.every(input=>input.value===''));
 f.get('lock').click();old.respond(sealResult);await task;assertCleared(f);
});
test('clear or page exit during delayed file reading cannot import the old backup',async()=>{
 for(const pageExit of [false,true]){
  const f=await fixture(),read=deferred();f.get('file').files=[{size:encrypted.length,text:()=>read.promise}];
  const task=f.get('file').onchange();await tick();
  if(pageExit)f.listeners.get('pagehide')();else f.get('lock').click();
  read.resolve(encrypted);await task;assertCleared(f);
  assert.equal(f.current().requests.length,0);
 }
});
test('exact original backup is required; full public address appears only after reopen',async()=>{
 const f=await fixture();await sealed(f);assert.equal(f.get('address').value,'');assert.equal(f.get('receiving').hidden,true);
 f.get('file').files=[{size:encrypted.length,text:async()=>JSON.stringify(JSON.parse(encrypted))}];await f.get('file').onchange();
 assert.equal(f.get('unlock').hidden,true);assert.match(f.get('status').textContent,/exact encrypted file/);
 f.get('file').files=[{size:encrypted.length,text:async()=>encrypted}];await f.get('file').onchange();
 f.get('unlock-password').value='synthetic-test-password';const task=f.get('unlock').onsubmit(event);
 assert.equal(f.get('unlock-password').value,'');f.current().respond({full_address:'synthetic-public-address'});await task;
 assert.equal(f.get('address').value,'synthetic-public-address');assert.equal(f.get('receiving').hidden,false);
 assert.ok(f.current().requests.every(request=>['create','seal','unlock'].includes(request.action)));
});
test('clear during delayed unlock and late worker errors cannot repopulate or overwrite the new session',async()=>{
 const f=await fixture();await sealed(f);f.get('file').files=[{size:encrypted.length,text:async()=>encrypted}];await f.get('file').onchange();
 f.get('unlock-password').value='synthetic-test-password';const old=f.current(),task=f.get('unlock').onsubmit(event);
 f.get('lock').click();f.current().ready();const prior=f.get('status').textContent;
 old.respond({full_address:'synthetic-public-address'});old.onerror();await task;assertCleared(f);assert.equal(f.get('status').textContent,prior);
});
