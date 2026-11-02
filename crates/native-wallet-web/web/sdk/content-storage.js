export const FORMAT = 'siworld-native-content-vault';
export const DB_NAME = 'siworld-native-v1-content';
export const MAX_BACKUP = 10000;
const fields = ['account', 'envelope_hex', 'format', 'network', 'version'];

export function parseContentBackup(text) {
  if (typeof text !== 'string' || new TextEncoder().encode(text).length > MAX_BACKUP) throw new Error('Content backup is too large.');
  let data;
  try { data = JSON.parse(text); } catch { throw new Error('Invalid encrypted content backup.'); }
  if (!data || Object.keys(data).sort().join() !== fields.join() || data.format !== FORMAT || data.version !== 1 ||
      typeof data.network !== 'string' || !/^[0-9a-f]{64}$/.test(data.network) || /^0+$/.test(data.network) ||
      !Number.isInteger(data.account) || data.account < 0 || data.account > 0xffffffff ||
      typeof data.envelope_hex !== 'string' || !/^53574e434e543031[0-9a-f]{8304}$/.test(data.envelope_hex)) {
    throw new Error('Invalid V1 content backup. Wallet seed backups and legacy Vault files are separate.');
  }
  return { format: data.format, version: data.version, network: data.network, account: data.account, envelope_hex: data.envelope_hex };
}
export function contentBackup(network, account, bytes) {
  return parseContentBackup(JSON.stringify({ format: FORMAT, version: 1, network, account,
    envelope_hex: [...bytes].map(b => b.toString(16).padStart(2, '0')).join('') }));
}
export function contentBytes(data) {
  const valid = parseContentBackup(JSON.stringify(data));
  return Uint8Array.from(valid.envelope_hex.match(/../g), pair => parseInt(pair, 16));
}
export async function contentId(data) {
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', contentBytes(data)));
  return [...hash].map(b => b.toString(16).padStart(2, '0')).join('');
}
function database() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore('packages', { keyPath: 'id' });
    request.onerror = () => reject(new Error('Encrypted content storage is unavailable.'));
    request.onsuccess = () => resolve(request.result);
  });
}
async function transact(mode, operation) {
  const db = await database();
  try { return await new Promise((resolve, reject) => {
    const tx = db.transaction('packages', mode), request = operation(tx.objectStore('packages'));
    let result;
    request.onsuccess = () => { result = request.result; };
    tx.oncomplete = () => resolve(result);
    tx.onabort = tx.onerror = () => reject(new Error('Content storage failed. Existing packages were preserved.'));
  }); } finally { db.close(); }
}
export async function contentRecords() {
  const values = await transact('readonly', store => store.getAll());
  if (values.length > 100) throw new Error('Too many local content packages.');
  const ids = new Set();
  for (const value of values) {
    value.backup = parseContentBackup(JSON.stringify(value.backup));
    if (await contentId(value.backup) !== value.id || ids.has(value.id)) throw new Error('A local content record failed validation. Existing data was preserved.');
    ids.add(value.id);
  }
  return values;
}
export async function saveContent(data) {
  const valid = parseContentBackup(JSON.stringify(data)), id = await contentId(valid);
  return navigator.locks.request('siworld-native-v1-content-storage', async () => {
    const records = await contentRecords(), found = records.find(record => record.id === id);
    if (found) {
      if (JSON.stringify(found.backup) !== JSON.stringify(valid)) throw new Error('A different package uses this identifier. Existing content was preserved.');
      return id;
    }
    if (records.length >= 100) throw new Error('At most 100 encrypted content packages may be stored.');
    await transact('readwrite', store => store.add({ id, backup: valid }));
    return id;
  });
}
