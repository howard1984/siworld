import {eng2Namespace} from './eng2-context.js';
// Private cache and scan metadata are one transaction in a dedicated exact-
// context database. No legacy vault, journal, compact store or migration is read.
export function eng2Storage(context) {
  const name = eng2Namespace(context);
  async function database() {
    return new Promise((resolve,reject) => {
      const request = indexedDB.open(name,1);
      request.onupgradeneeded = () => request.result.createObjectStore('private');
      request.onsuccess = () => resolve(request.result);
      request.onerror = request.onblocked = () => reject(new Error('Engineering-v2 private storage is unavailable. Existing data was preserved.'));
    });
  }
  return Object.freeze({name,
    async read(key) {
      const db = await database();
      try { return await new Promise((resolve,reject) => {
        const tx = db.transaction('private','readonly'), request = tx.objectStore('private').get(key);
        let result;
        request.onsuccess = () => { result = request.result; };
        tx.oncomplete = () => resolve(result);
        tx.onabort = tx.onerror = () => reject(new Error('Engineering-v2 private storage could not be read.'));
      }); } finally { db.close(); }
    },
    async pair(firstKey,first,secondKey,second) {
      if(!(first instanceof Uint8Array)||!(second instanceof Uint8Array))throw new Error('Only encrypted engineering-v2 state may be persisted.');
      return this.atomic(firstKey===secondKey?[[secondKey,second]]:[[firstKey,first],[secondKey,second]]);
    },
    async atomic(entries,removed=[]) {
      if(!Array.isArray(entries)||!entries.length||entries.length>8||!Array.isArray(removed)||removed.length>4||entries.some(entry=>!Array.isArray(entry)||entry.length!==2||!(entry[1] instanceof Uint8Array)))throw new Error('Only encrypted engineering-v2 state may be persisted.');
      const keys=[...entries.map(([key])=>key),...removed];
      if(keys.some((key,i)=>typeof key!=='string'||!key||key.length>2048||keys.indexOf(key)!==i))throw new Error('Engineering-v2 atomic storage keys differ.');
      const db = await database();
      try { await new Promise((resolve,reject) => {
        const tx = db.transaction('private','readwrite'), store = tx.objectStore('private');
        tx.oncomplete = resolve;
        tx.onabort = tx.onerror = () => reject(new Error('Engineering-v2 state was not durably saved. Previous data was preserved.'));
        try { for(const [key,value] of entries)store.put(value,key);for(const key of removed)store.delete(key); } catch { tx.abort(); }
      }); } finally { db.close(); }
    }
  });
}
