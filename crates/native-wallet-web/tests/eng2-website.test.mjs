import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {failureContext,workerFailure} from '../web/sdk/diagnostics.js';
import {runInNewContext} from 'node:vm';
import {createEng2Custody} from '../web/sdk/eng2-custody-storage.js';
import {eng2ReadOnlyProfile,sessionConfiguration,assertWalletOperation} from '../web/sdk/runtime-profile.js';
const pin={version:2,name:'siworld-eng-2',network:'1'.repeat(64),genesis:'2'.repeat(64),rules:'3'.repeat(64),profile:'4'.repeat(64),fee_mode:0,api:'http://127.0.0.1:8890',read_only:true};
// Structural public fixture only; no cryptographic key or real vault is created.
const vault=Uint8Array.from(('53574e564c543031'+'00'.repeat(124)).match(/../g),value=>parseInt(value,16));

test('engineering-v2 custody binds every immutable pin and preserves encrypted bytes',()=>{
 const storage=createEng2Custody(pin),record=storage.backup(pin.network,7,vault);
 assert.equal(record.format,'siworld-eng2-wallet-backup');assert.deepEqual(storage.bytes(record),vault);
 assert.equal(storage.parseBackup(JSON.stringify({...record,version:2,accounts_hex:'0011'})).accounts_hex,'0011');
 for(const key of ['network','genesis','rules','profile']){
  const other=createEng2Custody({...pin,[key]:'9'.repeat(64)});
  assert.notEqual(other.DB_NAME,storage.DB_NAME);
  assert.throws(()=>other.parseBackup(JSON.stringify(record)),/context/);
 }
 assert.throws(()=>storage.parseBackup(JSON.stringify({...record,format:'siworld-native-wallet-backup'})),/context/);
 assert.throws(()=>storage.parseBackup(JSON.stringify({...record,context:{...record.context,api:'http://localhost'}})),/context/);
 assert.throws(()=>storage.parseBackup(JSON.stringify({...record,account:-1})),/context/);
});
test('saved engineering-v2 records unlock without accepting backup metadata',()=>{
 const storage=createEng2Custody(pin),record=storage.backup(pin.network,7,vault);
 const stored={id:'12345678-1234-4123-8123-123456789abc',...record};
 assert.deepEqual(storage.bytes(stored),vault);
 assert.deepEqual(storage.bytes(record),vault);
 assert.throws(()=>storage.parseBackup(JSON.stringify(stored)),/context/);
 for(const id of ['',undefined,7,'invalid-record-identity'])assert.throws(()=>storage.bytes({...stored,id}),/identity/);
 assert.throws(()=>storage.bytes({...stored,unexpected:true}),/context/);
 assert.throws(()=>storage.bytes({...stored,context:{...record.context,genesis:'9'.repeat(64)}}),/context/);
});
test('eng2 registry and selection only open the exact custody database',async()=>{
 const original=globalThis.indexedDB,names=[],operations=[];
 globalThis.indexedDB={open(name){names.push(name);const request={};queueMicrotask(()=>{
  request.result={close(){},transaction(store,mode){operations.push([store,mode]);const tx={objectStore:()=>({get(){const result={};queueMicrotask(()=>{result.result='opaque';result.onsuccess();tx.oncomplete();});return result;},put(value){const result={};queueMicrotask(()=>{result.result=value;result.onsuccess();tx.oncomplete();});return result;}})};return tx;}};request.onsuccess();});return request;}};
 try{
  const storage=createEng2Custody(pin);
  assert.equal(await storage.selectedWallet(),'opaque');
  assert.equal(await storage.registry('private','registry'),'opaque');
  await storage.registry('private','registry',new Uint8Array([1,2]));
  assert.ok(names.every(name=>name===storage.DB_NAME));
  assert.deepEqual(operations,[['selection','readonly'],['private','readonly'],['private','readwrite']]);
  await assert.rejects(storage.registry('compact','x'),/encrypted/);
  await assert.rejects(storage.registry('private','x','plaintext'),/encrypted/);
 }finally{globalThis.indexedDB=original;}
});
test('eng2 worker dispatch cannot select V1 endpoints or enable mutation through flags',()=>{
 assert.equal(sessionConfiguration(pin,pin).read_only,true);
 for(const changes of [{name:'siworld-eng-1'},{genesis:'9'.repeat(64)},{api:'http://127.0.0.1:8891'},{apis:[pin.api,'https://foreign.example.test']},{submission_apis:['https://foreign.example.test']},{read_only:false},{desktop_send_measured:true}])assert.throws(()=>sessionConfiguration({...pin,...changes},pin));
 for(const action of ['prepare','submit','cancel-payment','register-address'])assert.throws(()=>assertWalletOperation(action,pin),/unavailable/);
 for(const action of ['sync','online-init','inspect','accounts-add'])assert.doesNotThrow(()=>assertWalletOperation(action,pin));
 assert.throws(()=>eng2ReadOnlyProfile({...pin,fee_mode:1}));
 assert.doesNotThrow(()=>assertWalletOperation('submit',{name:'siworld-eng-1'}));
});
test('website worker uses the eng2 owner and isolated registry without constructing V1 history',async()=>{
 const messages=[],calls=[];let injectedFailure=null;
 const info={network:pin.network,account:0,full_address:'synthetic-public-fixture'};
 const wallet={public_info:()=>JSON.stringify(info),free(){}};
 class Accounts {
  constructor(root,storage){assert.equal(root,wallet);assert.equal(typeof storage,'function');calls.push('isolated-registry');this.value={accounts:[{account:0,birth_height:0}]};}
  async initialize(){return [];}
  derive(){return wallet;}
  free(){}
 }
 class Session {
  constructor(active,context){assert.equal(active,wallet);assert.equal(context.genesis,pin.genesis);calls.push('eng2-session');}
  async initialize(){return {height:0,send_supported:false};}
  async sync(){if(injectedFailure)throw injectedFailure;return {height:1,send_supported:false};}
  async summary(){return {height:1,send_supported:false,journal:true};}
  cancelSync(){calls.push('cancel-sync');}
  release(){calls.push('release-owner');}
 }
 const forbidden=class {constructor(){throw new Error('Legacy session or history must not be constructed.');}};
 const self={postMessage:value=>messages.push(value)};
 const source=(await readFile(new URL('../web/sdk/worker.js',import.meta.url),'utf8')).replace(/^import .*;\n/gm,'').replaceAll('import.meta.url',JSON.stringify('http://127.0.0.1:8890/sdk/worker.js'));
 await runInNewContext('(async()=>{'+source+'})()',{
  self,init:async()=>{},core:{BrowserWallet:{unlock:()=>wallet},inspect_address:()=>{}},
  ENGINEERING:pin,Eng2WalletSession:Session,LightSession:forbidden,CommitmentSession:forbidden,
  WalletAccounts:Accounts,AddressDirectory:class {},createEng2Custody,eng2ReadOnlyProfile,sessionConfiguration,assertWalletOperation,
  failureContext,workerFailure,accountIndex:()=>{},captureBirthday:()=>{},URL,location:new URL('http://127.0.0.1:8890'),
 });
 assert.equal(messages.shift().ready,true);
 let id=0;
 async function request(action,args=[]){const next=++id;self.onmessage({data:{id:next,action,args,account:0}});for(let i=0;i<20;i++){await new Promise(resolve=>setImmediate(resolve));const message=messages.find(value=>value.id===next);if(message)return message;}throw new Error('Synthetic worker did not respond.');}
 assert.equal((await request('unlock')).result.network,pin.network);
 assert.deepEqual((await request('accounts-init')).result,[]);
 assert.equal((await request('online-init',[pin])).result.send_supported,false);
 assert.equal((await request('sync')).result.height,1);
 injectedFailure=Object.freeze(Object.assign(new Error('Synthetic private failure.',{cause:new DOMException('Synthetic private cause.','TimeoutError')}),{status:503}));
 const rejected=await request('sync');
 assert.equal(rejected.diagnostic.action,'sync');assert.equal(rejected.diagnostic.chain[0].http_status,503);
 assert.equal(rejected.diagnostic.chain[1].kind,'TimeoutError');assert.equal(rejected.diagnostic.chain[0].contexts.at(-1).stage,'dispatch');
 assert.ok(!JSON.stringify(rejected.diagnostic).includes('Synthetic private'));injectedFailure=null;
 assert.match((await request('prepare')).error,/unavailable/);
 assert.match((await request('submit')).error,/unavailable/);
 assert.equal((await request('journal')).result.journal,true);
 assert.equal((await request('account-select',[0])).result.account,0);
 assert.deepEqual(calls,['isolated-registry','eng2-session','cancel-sync','release-owner']);
 await request('online-init',[pin]);
 assert.equal((await request('lock')).result,true);
 assert.deepEqual(calls.slice(-3),['eng2-session','cancel-sync','release-owner']);
});
