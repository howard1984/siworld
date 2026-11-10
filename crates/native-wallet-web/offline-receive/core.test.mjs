// Uses public synthetic recovery words only. Never invoke the real creation API.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {backup,parseBackup} from './protocol.mjs';
import {ReceiveSession} from './session.mjs';
if(!process.env.RECEIVE_CORE)throw Error('Set RECEIVE_CORE to the exact qualified standard CI core.');
const root=resolve(process.env.RECEIVE_CORE);
const wasm=readFileSync(resolve(root,'wallet_bg.wasm'));
const glue=readFileSync(resolve(root,'wallet.js'));
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
assert.equal(sha(wasm),'763b63a88f46b907383cf664601feb7a685e7e2e204c5b6956888e9cb01be27d');
assert.equal(sha(glue),'49d34e81798bc654d65f0cf3bdb72e4a91be68b9e5ce3fb5e3fa517ab9548dc7');
const core=await import(pathToFileURL(resolve(root,'wallet.js')));
assert.equal(core.initThreadPool,undefined);
core.initSync({module:wasm});
const pin={name:'siworld-eng-2',network:'a1'.repeat(32),genesis:null,account:0,birth_height:0,receive_only:true,origin:'http://127.0.0.1:8879',context_sha256:'b2'.repeat(32)};
// Fixed public BIP39 test vector; this phrase must never receive real funds.
const words=[...Array(23).fill('abandon'),'art'].join(' ');
const password='synthetic-receive-test-password';
const session=new ReceiveSession({BrowserWallet:{create:()=>{throw Error('Real creation is forbidden in this test.');},unlock:core.BrowserWallet.unlock},inspect_address:core.inspect_address},pin,pin.origin);
let text, info;
test('qualified real WASM seals and reopens the fixed public synthetic vector',()=>{
 const wallet=core.BrowserWallet.restore(pin.network,0,words);
 try {
  info=JSON.parse(wallet.public_info());assert.equal(info.account,0);assert.equal(info.network,pin.network);
  const encrypted=wallet.seal(password,'');
  try{text=backup(pin,encrypted);}finally{encrypted.fill(0);}
  const opened=session.handle('unlock',[text,password]);
  assert.equal(opened.full_address,info.full_address);
  assert.equal(JSON.parse(core.inspect_address(opened.full_address,pin.network,'')).full_address,info.full_address);
 }finally{wallet.free();}
});
test('qualified real WASM rejects incorrect password and authenticated metadata substitution',()=>{
 assert.throws(()=>session.handle('unlock',[text,'incorrect-password']),/password|authentication/i);
 const value=parseBackup(text,pin);
 assert.throws(()=>session.handle('unlock',[JSON.stringify({...value,network:'c3'.repeat(32)}),password]),/pinned|original/i);
 const foreign=core.BrowserWallet.restore('c3'.repeat(32),0,words);
 try {
  const encrypted=foreign.seal(password,'');
  try{assert.throws(()=>session.handle('unlock',[backup(pin,encrypted),password]),/network/i);}
  finally{encrypted.fill(0);}
 }finally{foreign.free();}
 const account=core.BrowserWallet.restore(pin.network,1,words);
 try {
  const encrypted=account.seal(password,'');
  try{assert.throws(()=>session.handle('unlock',[backup(pin,encrypted),password]),/account|context/i);}
  finally{encrypted.fill(0);}
 }finally{account.free();}
 assert.throws(()=>core.inspect_address(info.full_address,'c3'.repeat(32),''),/mismatch/i);
});
