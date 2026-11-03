export const FORMAT = 'siworld-native-wallet-backup';
export const MAX_BACKUP = 70 * 1024;
export const DB_NAME = 'siworld-native-v1';
export function parseBackup(text) {
  if (typeof text !== 'string' || new TextEncoder().encode(text).length > MAX_BACKUP) throw new Error('Encrypted backup is too large.');
  let data;
  try { data = JSON.parse(text); } catch { throw new Error('Invalid encrypted backup.'); }
  const keys = ['account', 'format', 'network', 'vault_hex', 'version'];
  const multiple = data?.version === 2;
  if (multiple) keys.push('accounts_hex');
  keys.sort();
  if (!data || typeof data !== 'object' || Object.keys(data).sort().join() !== keys.join() || data.format !== FORMAT ||
      (!multiple && data.version !== 1) || !/^[0-9a-f]{64}$/.test(data.network) || /^0+$/.test(data.network) ||
      !Number.isInteger(data.account) || data.account < 0 || data.account > 0xffffffff ||
      (multiple && (typeof data.accounts_hex !== 'string' || data.accounts_hex.length > 65664 || !/^(?:[0-9a-f]{2})+$/.test(data.accounts_hex))) ||
      typeof data.vault_hex !== 'string' || !/^53574e564c543031[0-9a-f]{248}$/.test(data.vault_hex)) {
    throw new Error('Invalid native V1 encrypted backup. Legacy website backups are incompatible.');
  }
  return data;
}
export function backup(network, account, bytes) {
  const vault_hex = [...bytes].map(n => n.toString(16).padStart(2, '0')).join('');
  return parseBackup(JSON.stringify({ format: FORMAT, version: 1, network, account, vault_hex }));
}
export function bytes(record) { return Uint8Array.from(record.vault_hex.match(/../g), pair => parseInt(pair, 16)); }
function database() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore('wallets', { keyPath: 'id' });
    request.onerror = () => reject(new Error('Encrypted browser storage is unavailable.'));
    request.onsuccess = () => resolve(request.result);
  });
}
async function transact(mode, operation) {
  const db = await database();
  try { return await new Promise((resolve, reject) => {
    const tx = db.transaction('wallets', mode);
    const request = operation(tx.objectStore('wallets'));
    let result;
    request.onsuccess = () => { result = request.result; };
    tx.oncomplete = () => resolve(result);
    tx.onabort = tx.onerror = () => reject(new Error('Encrypted wallet storage failed. Existing wallets were preserved.'));
  }); } finally { db.close(); }
}
export async function records() {
  const result = await transact('readonly', store => store.getAll());
  if (result.length > 100) throw new Error('Too many local wallet records.');
  return result.map(record => ({ id: record.id, ...parseBackup(JSON.stringify(record.backup)) }));
}
export async function save(record) {
  const valid = parseBackup(JSON.stringify(record));
  return navigator.locks.request('siworld-native-v1-storage', async () => {
    if ((await records()).length >= 100) throw new Error('At most 100 encrypted wallets may be stored in this browser.');
    const id = crypto.randomUUID();
    await transact('readwrite', store => store.add({ id, backup: valid }));
    return id;
  });
}
