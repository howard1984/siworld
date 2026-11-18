import {eng2Namespace, sameEng2Context} from './eng2-context.js';
import {eng2ReadOnlyProfile} from './runtime-profile.js';

// This store never opens, imports or migrates an engineering-v1 database.
export function createEng2Custody(configuration) {
  const pin = eng2ReadOnlyProfile(configuration);
  const FORMAT = 'siworld-eng2-wallet-backup', MAX_BACKUP = 72*1024;
  const DB_NAME = eng2Namespace(pin) + '-custody';
  const context = Object.freeze(Object.fromEntries(['version','network','genesis','rules','profile','fee_mode'].map(key=>[key,pin[key]])));
  function parseBackup(text) {
    if (typeof text !== 'string' || new TextEncoder().encode(text).length > MAX_BACKUP) throw new Error('Encrypted backup is too large.');
    let value;
    try { value=JSON.parse(text); } catch { throw new Error('Invalid engineering-v2 encrypted backup.'); }
    const keys=['format','version','network','account','vault_hex','context'];
    if (value?.version===2) keys.push('accounts_hex');
    if (!value || Object.keys(value).sort().join()!==keys.sort().join() || value.format!==FORMAT || ![1,2].includes(value.version) ||
        value.network!==pin.network || !Number.isInteger(value.account) || value.account<0 || value.account>0xffffffff ||
        !value.context || Object.keys(value.context).sort().join()!==Object.keys(context).sort().join() || !sameEng2Context(value.context,pin) ||
        typeof value.vault_hex!=='string' || !/^53574e564c543031[0-9a-f]{248}$/.test(value.vault_hex) ||
        value.version===2 && (typeof value.accounts_hex!=='string' || value.accounts_hex.length>65664 || !/^(?:[0-9a-f]{2})+$/.test(value.accounts_hex))) throw new Error('Engineering-v2 backup differs from this build context. No conversion or migration was performed.');
    return value;
  }
  const bytes = record => {
    if (!record || typeof record !== 'object' || Array.isArray(record)) throw new Error('Invalid encrypted engineering-v2 wallet record.');
    if (Object.hasOwn(record,'id') && (typeof record.id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(record.id))) throw new Error('Invalid local engineering-v2 wallet identity.');
    const {id,...value}=record;
    return Uint8Array.from(parseBackup(JSON.stringify(value)).vault_hex.match(/../g),pair=>parseInt(pair,16));
  };
  const backup = (network,account,value) => parseBackup(JSON.stringify({format:FORMAT,version:1,network,account,context,vault_hex:[...value].map(n=>n.toString(16).padStart(2,'0')).join('')}));
  function database() {
    return new Promise((resolve,reject)=>{
      const request=indexedDB.open(DB_NAME,1);
      request.onupgradeneeded=()=>{request.result.createObjectStore('wallets',{keyPath:'id'});request.result.createObjectStore('private');request.result.createObjectStore('selection');};
      request.onsuccess=()=>resolve(request.result);
      request.onerror=request.onblocked=()=>reject(new Error('Engineering-v2 encrypted storage is unavailable. Existing data was preserved.'));
    });
  }
  async function transact(store,mode,operation) {
    const db=await database();
    try { return await new Promise((resolve,reject)=>{
      const tx=db.transaction(store,mode);let request,result;
      tx.oncomplete=()=>resolve(result);
      tx.onabort=tx.onerror=()=>reject(new Error('Engineering-v2 encrypted storage failed. Existing data was preserved.'));
      try {request=operation(tx.objectStore(store));request.onsuccess=()=>{result=request.result;};} catch {tx.abort();}
    }); } finally {db.close();}
  }
  async function records() {
    const values=await transact('wallets','readonly',store=>store.getAll());
    if (!Array.isArray(values)||values.length>100) throw new Error('Invalid encrypted engineering-v2 wallet collection.');
    return values.map(value=>({id:value.id,...parseBackup(JSON.stringify(value.backup))}));
  }
  async function save(value) {
    const valid=parseBackup(JSON.stringify(value));
    return navigator.locks.request(DB_NAME+':wallets',async()=>{
      if ((await records()).length>=100) throw new Error('At most 100 encrypted wallets may be stored in this browser.');
      const id=crypto.randomUUID();await transact('wallets','readwrite',store=>store.add({id,backup:valid}));return id;
    });
  }
  async function selectedWallet(id) {
    try {return await transact('selection',id===undefined?'readonly':'readwrite',store=>id===undefined?store.get('wallet'):store.put(id,'wallet'))||id||'';}
    catch {return id||'';}
  }
  async function registry(store,key,value) {
    if (store!=='private' || value!==undefined && !(value instanceof Uint8Array)) throw new Error('Only encrypted engineering-v2 registry bytes may be persisted.');
    return transact('private',value===undefined?'readonly':'readwrite',target=>value===undefined?target.get(key):target.put(value,key));
  }
  return Object.freeze({FORMAT,MAX_BACKUP,DB_NAME,parseBackup,backup,bytes,records,save,selectedWallet,registry,
    savedWalletLabel:record=>`Encrypted wallet ${record.id} · account ${record.account}`});
}
