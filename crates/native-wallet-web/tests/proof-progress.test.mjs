import test from 'node:test';
import assert from 'node:assert/strict';
import { ProofProgress } from '../web/sdk/proof-progress.js';
function setup() {
 let now=0,callback,stopped=0;
 const element=()=>({hidden:false,textContent:'',attributes:new Map(),setAttribute(k,v){this.attributes.set(k,v);},removeAttribute(k){this.attributes.delete(k);delete this[k];}});
 const elements={root:element(),bar:element(),label:element(),detail:element()};
 const progress=new ProofProgress(elements,{now:()=>now,every:fn=>(callback=fn,1),stop:()=>stopped++});
 return {progress,elements,advance(ms){now+=ms;callback?.();},get stopped(){return stopped;}};
}
test('A first proof stays indeterminate and never invents a completion percentage',()=>{
 const {progress,elements,advance}=setup();progress.start();progress.stage('proving');advance(90000);
 assert.equal(elements.bar.value,undefined);assert.match(elements.label.textContent,/post-quantum/);
 assert.match(elements.detail.textContent,/90 s elapsed/);assert.match(elements.detail.textContent,/may take longer/);
 assert.equal(elements.root.attributes.get('aria-busy'),'true');
});
test('Only a successful completed proof becomes complete; a session estimate can overrun',()=>{
 const {progress,elements,advance}=setup();progress.start();progress.stage('proving');progress.finish(22000);
 assert.equal(elements.bar.value,1);assert.match(elements.label.textContent,/locally verified/);
 progress.start();progress.stage('proving');advance(10000);assert.match(elements.detail.textContent,/About 12 s remaining/);
 advance(20000);assert.match(elements.detail.textContent,/Taking longer/);assert.equal(elements.bar.value,undefined);
});
test('Failure, wallet lock and unknown phase events cannot display successful completion',()=>{
 const {progress,elements,advance}=setup();progress.start();progress.stage('proving');progress.stage('untrusted-event');
 assert.match(elements.label.textContent,/post-quantum/);progress.fail();assert.equal(elements.bar.hidden,true);
 assert.match(elements.label.textContent,/stopped/);assert.equal(elements.root.attributes.get('aria-busy'),'false');
 const text=elements.detail.textContent;advance(5000);assert.equal(elements.detail.textContent,text);
 progress.reset();assert.equal(elements.root.hidden,true);progress.finish(1);assert.equal(elements.bar.value,undefined);
});
