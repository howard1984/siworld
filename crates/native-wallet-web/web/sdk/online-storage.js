// Private values are encrypted by WASM before entering this store.
const NAME = 'siworld-engineering-light-v1';
function database() { return new Promise((resolve,reject)=>{const r=indexedDB.open(NAME,1);r.onupgradeneeded=()=>{r.result.createObjectStore('private');r.result.createObjectStore('compact');};r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(new Error('Light wallet storage is unavailable.'));}); }
export async function stored(store,key,value) {
  const db=await database();
  try {return await new Promise((resolve,reject)=>{const tx=db.transaction(store,value===undefined?'readonly':'readwrite');const r=value===undefined?tx.objectStore(store).get(key):tx.objectStore(store).put(value,key);let result;r.onsuccess=()=>{result=r.result;};tx.oncomplete=()=>resolve(result);tx.onabort=tx.onerror=()=>reject(new Error('Durable wallet storage failed; sending is paused.'));});}finally{db.close();}
}
// Scan state and its payment journal must advance in the same durable transaction.
export async function storePrivatePair(firstKey, first, secondKey, second) {
  const db=await database();
  try {await new Promise((resolve,reject)=>{
    const tx=db.transaction('private','readwrite'), store=tx.objectStore('private');
    tx.oncomplete=resolve;
    tx.onabort=tx.onerror=()=>reject(new Error('Durable scan state failed; the previous wallet was preserved.'));
    try{store.put(first,firstKey); store.put(second,secondKey);}
    catch{tx.abort();reject(new Error('Durable scan state failed; the previous wallet was preserved.'));}
  });}finally{db.close();}
}
export const hex=bytes=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
export const unhex=text=>{if(typeof text!=='string'||text.length%2||!/^[0-9a-f]*$/.test(text))throw new Error('Invalid binary encoding.');return Uint8Array.from(text.match(/../g)||[],p=>parseInt(p,16));};
export const hash=async bytes=>hex(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)));
export async function fetchLimited(url,{limit=8388656,method='GET',body,headers={},signal}={}) {
  const response=await fetch(url,{method,body,headers,signal,credentials:'omit',referrerPolicy:'no-referrer',redirect:'error',cache:'no-store'});
  if(!response.ok)throw Object.assign(new Error(`Engineering service returned HTTP ${response.status}.`),{status:response.status});
  const declared=Number(response.headers.get('content-length'));if(declared>limit)throw new Error('Response exceeds its byte limit.');
  const reader=response.body.getReader();const parts=[];let size=0;
  try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>limit)throw new Error('Response exceeds its byte limit.');parts.push(value);}}catch(error){await reader.cancel();throw error;}
  const bytes=new Uint8Array(size);let at=0;for(const part of parts){bytes.set(part,at);at+=part.length;}return {bytes,headers:response.headers};
}
export async function readJSON(url,options={}) {const {bytes}=await fetchLimited(url,{...options,limit:options.limit||100000});try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{throw new Error('Malformed engineering service response.');}}
