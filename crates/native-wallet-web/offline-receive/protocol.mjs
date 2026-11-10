// Receive-only backup framing. No storage or chain service is used.
export const FORMAT = 'siworld-eng2-offline-receive-backup';
export const MAX_BACKUP = 4096;
const hex = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value) && !/^0+$/.test(value);
export function context(value, origin) {
  if (!value || Object.keys(value).sort().join() !== 'account,birth_height,context_sha256,genesis,name,network,origin,receive_only' ||
      value.name !== 'siworld-eng-2' || !hex(value.network) || !hex(value.context_sha256) || value.genesis !== null ||
      value.account !== 0 || value.birth_height !== 0 || value.receive_only !== true) throw new Error('Pinned internal receive-only context is required.');
  const url = new URL(value.origin);
  if (url.origin !== value.origin || url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port ||
      url.username || url.password || origin !== value.origin) throw new Error('Open the dedicated pinned loopback origin.');
  return Object.freeze({...value});
}
export function parseBackup(text, pin) {
  if (typeof text !== 'string' || new TextEncoder().encode(text).length > MAX_BACKUP) throw new Error('Receive backup exceeds its size limit.');
  let value;
  try { value = JSON.parse(text); } catch { throw new Error('Invalid encrypted receive backup.'); }
  if (!value || Object.keys(value).sort().join() !== 'account,birth_height,format,network,vault_hex,version' ||
      value.format !== FORMAT || value.version !== 1 || value.network !== pin.network || value.account !== 0 ||
      value.birth_height !== 0 || typeof value.vault_hex !== 'string' || !/^53574e564c543031[0-9a-f]{248}$/.test(value.vault_hex)) {
    throw new Error('Use the original encrypted backup for this pinned internal network and account. Old backups are not converted.');
  }
  return value;
}
export function backup(pin, bytes) {
  const value = {format:FORMAT, version:1, network:pin.network, account:0, birth_height:0,
    vault_hex:[...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('')};
  const text = JSON.stringify(value) + '\n';
  parseBackup(text, pin);
  return text;
}
export function vaultBytes(value) {
  return Uint8Array.from(value.vault_hex.match(/../g), byte => parseInt(byte, 16));
}
