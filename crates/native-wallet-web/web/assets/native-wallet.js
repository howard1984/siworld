import { initVault } from './native-vault.js';
import { backup, bytes, parseBackup, records, save, MAX_BACKUP } from '../sdk/storage.js';
import { ENGINEERING } from '../sdk/network.js';

const $ = selector => document.querySelector(selector);
const flow = $('#flow');
let worker, sequence = 0, epoch = 0, ready = false, busy = false, storageHealthy = false;
let mode = '', stage = '', context, positions, info, encrypted, savedRecords = [], imported;
let timer;
const pending = new Map(), contacts = new Map();
function message(text, error = false) { $('#status').textContent = text; $('#status').classList.toggle('error', error); }
function capability(value) { for (const id of ['create', 'restore', 'import-backup', 'check', 'import-contact']) $(`#${id}`).disabled = !value; }
function startWorker() {
  worker = new Worker(new URL('../sdk/worker.js', import.meta.url), { type: 'module' });
  worker.onmessage = ({ data }) => {
    if (data.ready) { ready = true; capability(storageHealthy); if (storageHealthy) message('Native V1 ready. Keys are processed locally; no chain connection is configured.'); return; }
    const request = pending.get(data.id);
    if (!request) return;
    pending.delete(data.id);
    data.error ? request.reject(new Error(data.error)) : request.resolve(data.result);
  };
  worker.onerror = () => { for (const request of pending.values()) request.reject(new Error('The local wallet core stopped. Lock and reopen the page.')); pending.clear(); capability(false); message('The local wallet core could not load. No wallet data was sent.', true); };
}
function call(action, ...args) {
  return new Promise((resolve, reject) => { const id = ++sequence; pending.set(id, { resolve, reject }); worker.postMessage({ id, action, args }); });
}
function clearSecrets() {
  for (const input of flow.querySelectorAll('input[type=password], #restore-words, #answers input')) input.value = '';
  $('#words').replaceChildren(); $('#answers').replaceChildren(); positions = null;
}
function lock(text = 'Wallet locked. Recovery fields and the local worker session were cleared.', restart = true) {
  ++epoch; clearTimeout(timer); worker?.terminate(); ready = false; capability(false);
  for (const request of pending.values()) request.reject(new Error('Wallet session was closed.'));
  pending.clear(); clearSecrets(); flow.close();
  info = encrypted = imported = context = null; busy = false; stage = mode = '';
  $('#next').disabled = false;
  $('#recipient').value = ''; $('#address-result').textContent = ''; contacts.clear();
  $('#setup').hidden = false; $('#receiving').hidden = true; $('#full-address').value = ''; $('#short-address').textContent = '';
  $('#account-index').textContent = 'No wallet unlocked'; $('#account-state').textContent = 'LOCKED';
  $('#lock').disabled = $('#copy-address').disabled = true;
  if (restart) startWorker(); message(text);
}
function activity() { if (info || flow.open) { clearTimeout(timer); timer = setTimeout(() => lock('Wallet locked after five minutes of inactivity.'), 300000); } }
function showStage(next) {
  stage = next; $('#flow-error').textContent = '';
  for (const id of ['context-fields', 'restore-fields', 'words-view', 'challenge-fields', 'password-fields']) $(`#${id}`).hidden = true;
  $('#confirm-field').hidden = false;
  const display = (id, visible) => { $(`#${id}`).hidden = !visible; };
  if (next === 'context') {
    $('#flow-title').textContent = mode === 'create' ? 'Create your V1 wallet.' : 'Restore your V1 wallet.';
    $('#flow-description').textContent = mode === 'create' ? 'New keys are generated only on this device. Engineering assets have no monetary value.' : 'Use the original native V1 network, account and 24 recovery words. An older website wallet uses a different derivation.';
    display('context-fields', true); display('restore-fields', mode === 'restore');
    $('#next').textContent = mode === 'create' ? 'Generate recovery words ↗' : 'Continue ↗';
  } else if (next === 'words') {
    $('#flow-title').textContent = 'Keep your way back.';
    $('#flow-description').textContent = `Write down the 24 words privately. Network: ${context.network} · Account: ${context.account}.`;
    display('words-view', true); $('#next').textContent = 'I wrote down my backup ↗';
  } else if (next === 'seal') {
    $('#flow-title').textContent = mode === 'create' ? 'Verify and protect.' : 'Protect this device.';
    $('#flow-description').textContent = 'Only an encrypted wallet file is saved in this browser. Keep your recovery words and original network/account separately.';
    display('challenge-fields', mode === 'create'); display('password-fields', true); $('#next').textContent = 'Save encrypted wallet ↗';
    $('#password').autocomplete = 'new-password';
  } else if (next === 'unlock') {
    $('#flow-title').textContent = 'Unlock your V1 wallet.';
    $('#flow-description').textContent = 'Your password decrypts the selected wallet only on this device.';
    display('password-fields', true); $('#confirm-field').hidden = true; $('#password').autocomplete = 'current-password';
    $('#next').textContent = imported ? 'Unlock and import ↗' : 'Unlock wallet ↗';
  }
  for (const input of flow.querySelectorAll('input,textarea')) input.required = !input.closest('[hidden]');
  activity(); requestAnimationFrame(() => flow.querySelector('div:not([hidden]) input, div:not([hidden]) textarea')?.focus());
}
function begin(nextMode) {
  if (!ready || busy) return;
  clearSecrets(); mode = nextMode; ++epoch; imported = null;
  $('#network').value = ENGINEERING.network; $('#account').value = '0';
  $('#lock').disabled = false; showStage('context'); flow.showModal();
}
async function reloadSaved() {
  savedRecords = await records(); $('#saved').hidden = !savedRecords.length;
  $('#saved-wallet').replaceChildren(...savedRecords.map((record, index) => {
    const option = document.createElement('option'); option.value = record.id;
    option.textContent = `Wallet ${index + 1} · account ${record.account} · network ${record.network.slice(0, 10)}…`; return option;
  }));
}
function render(publicInfo, record) {
  info = publicInfo; encrypted = record;
  $('#setup').hidden = true; $('#receiving').hidden = false;
  $('#full-address').value = info.full_address; $('#short-address').textContent = info.short_address;
  $('#account-state').textContent = 'UNLOCKED'; $('#account-index').textContent = `Account ${info.account} · ${info.network.slice(0, 12)}…`;
  $('#lock').disabled = $('#copy-address').disabled = false;
  message('Wallet unlocked locally. Receiving keys are ready; balance verification and sending are not connected.'); activity();
}
$('#create').addEventListener('click', () => begin('create'));
$('#restore').addEventListener('click', () => begin('restore'));
$('#lock').addEventListener('click', () => lock());
$('#cancel').addEventListener('click', () => lock('Setup cancelled. No pending recovery words were kept.'));
flow.addEventListener('cancel', event => { event.preventDefault(); lock('Setup cancelled.'); });
$('#flow-form').addEventListener('submit', async event => {
  event.preventDefault(); if (busy) return;
  busy = true; const token = epoch; $('#next').disabled = true; $('#flow-error').textContent = '';
  try {
    if (stage === 'context') {
      context = { network: $('#network').value.trim(), account: Number($('#account').value) };
      if (!/^[0-9a-f]{64}$/.test(context.network) || /^0+$/.test(context.network) || !Number.isInteger(context.account) || context.account < 0 || context.account > 0xffffffff) throw new Error('Enter a nonzero native network ID and an unsigned 32-bit account index.');
      if (mode === 'create') {
        const result = await call('create', context.network, context.account); if (token !== epoch) return;
        positions = result.positions;
        $('#words').replaceChildren(...result.words.split(' ').map(word => { const item = document.createElement('li'); item.textContent = word; return item; }));
        result.words = ''; showStage('words');
      } else {
        let words = $('#restore-words').value; $('#restore-words').value = '';
        const result = call('restore', context.network, context.account, words); words = ''; await result;
        if (token === epoch) showStage('seal');
      }
    } else if (stage === 'words') {
      $('#words').replaceChildren();
      for (const position of positions) {
        const label = document.createElement('label'); label.htmlFor = `answer-${position}`; label.textContent = `Recovery word ${position}`;
        const input = document.createElement('input'); input.id = label.htmlFor; input.autocomplete = 'off'; input.spellcheck = false; input.maxLength = 16; input.required = true;
        $('#answers').append(label, input);
      }
      showStage('seal');
    } else if (stage === 'seal') {
      let password = $('#password').value;
      if (password !== $('#confirm').value) throw new Error('Device passwords do not match.');
      if (new TextEncoder().encode(password).length < 12) throw new Error('Use a device password of at least 12 UTF-8 bytes.');
      let answers = [...document.querySelectorAll('#answers input')].map(input => input.value).join(' ');
      for (const input of flow.querySelectorAll('input[type=password]')) input.value = '';
      const resultPromise = call('seal', password, answers); password = answers = '';
      const result = await resultPromise; if (token !== epoch) return;
      const record = backup(context.network, context.account, result.bytes); result.bytes.fill(0);
      await save(record); if (token !== epoch) return;
      clearSecrets(); flow.close(); render(result.info, record); await reloadSaved();
    } else if (stage === 'unlock') {
      const record = imported || savedRecords.find(r => r.id === $('#saved-wallet').value);
      if (!record) throw new Error('Select an encrypted wallet first.');
      let password = $('#password').value; $('#password').value = '';
      const resultPromise = call('unlock', record.network, bytes(record), password); password = '';
      const result = await resultPromise; if (token !== epoch) return;
      if (result.network !== record.network || result.account !== record.account) { await call('lock'); throw new Error('Backup recovery context does not match its authenticated wallet.'); }
      if (imported) await save(imported); if (token !== epoch) return;
      clearSecrets(); flow.close(); render(result, record); imported = null; await reloadSaved();
    }
  } catch (error) { if (token === epoch) $('#flow-error').textContent = error.message; }
  finally { if (token === epoch) { busy = false; $('#next').disabled = false; } }
});
$('#open-unlock').addEventListener('click', () => {
  clearSecrets(); ++epoch; imported = null; $('#lock').disabled = false; showStage('unlock'); flow.showModal();
});
$('#import-backup').addEventListener('click', () => $('#backup-file').click());
$('#backup-file').addEventListener('change', async event => {
  try {
    const file = event.target.files[0]; if (!file) return; if (file.size > MAX_BACKUP) throw new Error('Encrypted backup is too large.');
    imported = parseBackup(await file.text()); clearSecrets(); ++epoch; $('#lock').disabled = false; showStage('unlock'); flow.showModal();
  } catch (error) { message(error.message, true); } finally { event.target.value = ''; }
});
function download(name, value, type = 'application/json') {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2) + '\n'], { type }));
  const link = document.createElement('a'); link.href = url; link.download = name; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
$('#export-backup').addEventListener('click', () => { if (encrypted) download('siworld-native-v1-encrypted.json', parseBackup(JSON.stringify({format:encrypted.format,version:encrypted.version,network:encrypted.network,account:encrypted.account,vault_hex:encrypted.vault_hex}))); });
$('#export-recipient').addEventListener('click', () => { if (info) download('siworld-native-v1-recipient.json', info.descriptor); });
$('#export-contact').addEventListener('click', () => { if (info) download('siworld-native-v1-contact.address', { format: 'siworld-native-v1-contact', version: 1, network: info.network, full_address: info.full_address, short_address: info.short_address }); });
$('#copy-address').addEventListener('click', async () => {
  if (!info) return;
  try { await navigator.clipboard.writeText(info.full_address); message('Full V1 address copied. This is public receiving data.'); }
  catch { $('#full-address').focus(); $('#full-address').select(); message('Copy the selected public address manually.'); }
});
$('#import-contact').addEventListener('click', () => $('#contact-file').click());
$('#contact-file').addEventListener('change', async event => {
  try {
    const file = event.target.files[0]; if (!file) return; if (file.size > 6000) throw new Error('Contact record is too large.');
    const data = JSON.parse(await file.text());
    if (!data || Object.keys(data).sort().join() !== ['format','full_address','network','short_address','version'].join() || data.format !== 'siworld-native-v1-contact' || data.version !== 1) throw new Error('Invalid V1 contact record.');
    const expected = info?.network || ENGINEERING.network;
    if (data.network !== expected || typeof data.full_address !== 'string' || data.full_address.length > 2200 || typeof data.short_address !== 'string' || data.short_address.length > 100) throw new Error('Contact record network or address is invalid.');
    const result = await call('inspect', data.short_address, expected, data.full_address);
    contacts.set(result.short_address, result.full_address); $('#recipient').value = result.short_address; $('#address-result').textContent = 'Contact imported and verified against its short address.';
  } catch { $('#address-result').textContent = 'Contact import failed. Use a matching native V1 contact record.'; }
  finally { event.target.value = ''; }
});
$('#check-address').addEventListener('submit', async event => {
  event.preventDefault(); const text = $('#recipient').value.trim();
  try { const result = await call('inspect', text, info?.network || ENGINEERING.network, contacts.get(text) || ''); $('#address-result').textContent = `Valid native V1 receiving address · ${result.short_address}`; }
  catch (error) { $('#address-result').textContent = error.message; }
});
for (const event of ['pointerdown', 'keydown']) document.addEventListener(event, activity, { passive: true });
document.addEventListener('visibilitychange', () => { if (document.hidden && (info || flow.open)) lock('Wallet locked when the page left the foreground.'); });
window.addEventListener('pagehide', () => lock('Wallet locked when leaving this page.', false));
window.addEventListener('pageshow', event => { if (event.persisted && storageHealthy) startWorker(); });
if (!isSecureContext || window.top !== window || !crypto?.getRandomValues || !navigator.locks || !window.indexedDB || !window.Worker || !window.WebAssembly) {
  capability(false); message('Open this wallet directly on HTTPS or localhost in a browser with WebAssembly, Web Crypto and Web Locks.', true);
} else {
  startWorker(); reloadSaved().then(() => { storageHealthy = true; capability(ready); }).catch(() => { storageHealthy = false; capability(false); message('Encrypted storage could not be read. Existing data was preserved; saving is paused.', true); });
}

initVault(() => info);
