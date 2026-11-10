import {CONTEXT} from './context.mjs';
import {context, parseBackup, MAX_BACKUP} from './protocol.mjs';
const $ = id => document.getElementById(id);
let worker, ready = false, serial = 0, busy = false, timer, epoch = 0;
let stage = 'idle', positions = [], generated = null, imported = null;
const pending = new Map(), urls = new Set();
function status(text, error = false) { $('status').textContent = text; $('status').className = error ? 'error' : ''; }
function controls() {
  for (const node of document.querySelectorAll('button,input')) if (node.id !== 'lock') node.disabled = !ready || busy;
  for (const id of ['create', 'open']) $(id).disabled = !ready || busy || !['idle', 'verified'].includes(stage);
  $('lock').disabled = !worker || (!busy && stage === 'idle');
}
function current(token) { if (token !== epoch) throw new Error('Receive session cleared.'); }
function clearFields() {
  for (const id of ['password', 'repeat', 'unlock-password', 'address', 'file']) $(id).value = '';
  for (const node of $('answers').querySelectorAll('input')) node.value = '';
  $('words').replaceChildren(); $('answers').replaceChildren(); positions.fill(0); positions = [];
  for (const id of ['recovery', 'seal', 'download', 'unlock', 'receiving']) $(id).hidden = true;
}
function call(token, action, ...args) {
  current(token);
  if (!ready) return Promise.reject(new Error('Wait for the local core.'));
  return new Promise((resolve, reject) => {
    const id = ++serial; pending.set(id, {resolve, reject});
    try { worker.postMessage({id, action, args}); }
    catch (error) { pending.delete(id); reject(error); }
    finally { args.fill(null); }
  });
}
function start() {
  const token = epoch;
  const instance = new Worker(new URL('./worker.mjs', import.meta.url), {type:'module', name:'siworld-eng2-offline-receive'});
  worker = instance;
  instance.onmessage = ({data}) => {
    if (token !== epoch || worker !== instance) { if (data?.result?.words) data.result.words = ''; return; }
    if (data.ready) { ready = true; controls(); status('Ready for local receive backup. No chain service is connected.'); return; }
    const request = pending.get(data.id); if (!request) return; pending.delete(data.id);
    data.error ? request.reject(new Error(data.error)) : request.resolve(data.result);
  };
  instance.onerror = () => {
    if (token !== epoch || worker !== instance) return;
    clear(false); status('The local core stopped. Existing downloaded backups were preserved.', true);
  };
}
function clear(restart = true) {
  epoch++; ready = false; worker?.terminate(); worker = null; clearTimeout(timer);
  for (const request of pending.values()) request.reject(new Error('Receive session cleared.'));
  pending.clear(); busy = false; stage = 'idle'; generated = imported = null; clearFields();
  for (const url of urls) URL.revokeObjectURL(url); urls.clear(); controls();
  if (restart) { start(); status('Session cleared. Reopen your downloaded encrypted backup when needed.'); }
}
function activity() { clearTimeout(timer); if (!$('lock').disabled) timer = setTimeout(() => clear(), 300000); }
async function attempt(action) {
  if (busy || !ready) return;
  const token = epoch; busy = true; controls(); activity();
  try { await action(token); }
  catch (error) { if (token === epoch) status(error.message || 'Local receive operation failed.', true); }
  finally { if (token === epoch) { busy = false; controls(); activity(); } }
}
$('create').onclick = () => attempt(async token => {
  if (!['idle', 'verified'].includes(stage)) return;
  const result = await call(token, 'create'); current(token);
  clearFields(); generated = imported = null;
  const phrase = result.words.split(' '); result.words = '';
  try { $('words').replaceChildren(...phrase.map(word => { const item = document.createElement('li'); item.textContent = word; return item; })); }
  finally { phrase.fill(''); }
  positions = result.positions; stage = 'recovery'; $('recovery').hidden = false;
  status('Recovery words are displayed only for this new local account.');
});
$('written').onclick = () => {
  if (busy || stage !== 'recovery') return;
  $('words').replaceChildren(); $('recovery').hidden = true;
  $('answers').replaceChildren(...positions.map(position => { const label = document.createElement('label'); label.textContent = `Recovery word ${position}`; const input = document.createElement('input'); input.type = 'password'; input.autocomplete = 'off'; input.required = true; input.maxLength = 16; label.append(input); return label; }));
  stage = 'challenge'; $('seal').hidden = false; activity();
};
$('seal').onsubmit = event => { event.preventDefault(); return attempt(async token => {
  let password = $('password').value, repeated = $('repeat').value;
  let answers = [...$('answers').querySelectorAll('input')].map(input => input.value.trim()).join(' ');
  $('password').value = $('repeat').value = '';
  for (const input of $('answers').querySelectorAll('input')) input.value = '';
  if (password !== repeated) { password = repeated = answers = ''; throw new Error('The backup passwords do not match.'); }
  const task = call(token, 'seal', password, answers); password = repeated = answers = '';
  const result = await task; current(token);
  generated = {backup:result.backup, address:result.info.full_address};
  clearFields(); stage = 'download'; $('download').hidden = false;
  status('Encrypted locally. Save and reopen the original backup to verify it.');
}); };
$('save').onclick = () => {
  if (busy || !generated || stage !== 'download') return;
  const url = URL.createObjectURL(new Blob([generated.backup], {type:'application/json'})); urls.add(url);
  const link = document.createElement('a'); link.href = url; link.download = 'siworld-eng2-account-0-encrypted.json'; link.click();
  setTimeout(() => { URL.revokeObjectURL(url); urls.delete(url); }, 1000); activity();
};
$('open').onclick = () => { if (!busy && ready && ['idle', 'verified'].includes(stage)) { $('file').value = ''; $('file').click(); } };
$('verify').onclick = () => { if (!busy && ready && generated && stage === 'download') { $('file').value = ''; $('file').click(); } };
$('file').onchange = () => attempt(async token => {
  const file = $('file').files?.[0]; $('file').value = ''; if (!file) return;
  if (file.size > MAX_BACKUP) throw new Error('Receive backup exceeds its size limit.');
  let text = await file.text();
  if (token !== epoch) { text = ''; return; }
  parseBackup(text, CONTEXT);
  if (generated && text !== generated.backup) { text = ''; throw new Error('Select the exact encrypted file downloaded in this session.'); }
  imported = text; text = ''; stage = 'imported'; $('unlock').hidden = false; $('unlock-password').focus();
});
$('unlock').onsubmit = event => { event.preventDefault(); return attempt(async token => {
  let password = $('unlock-password').value; $('unlock-password').value = '';
  const task = call(token, 'unlock', imported, password); password = '';
  const info = await task; current(token);
  if (generated && info.full_address !== generated.address) throw new Error('Recovered public address differs from the created account.');
  clearFields(); $('address').value = info.full_address; $('receiving').hidden = false;
  stage = 'verified'; generated = imported = null;
  status('Encrypted backup reopened and its pinned account address verified locally.');
}); };
$('copy').onclick = () => attempt(async token => {
  if (stage !== 'verified' || !$('address').value) throw new Error('Verify the encrypted backup first.');
  await navigator.clipboard.writeText($('address').value); current(token); status('Full public receive address copied.');
});
$('lock').onclick = () => clear();
for (const event of ['pointerdown', 'keydown']) document.addEventListener(event, activity);
window.addEventListener('pagehide', () => clear(false));
try {
  context(CONTEXT, location.origin);
  if (!isSecureContext || window.top !== window || !crypto?.getRandomValues || !window.Worker || !window.WebAssembly || navigator.serviceWorker?.controller) throw new Error('Use the dedicated loopback page without a controlling service worker.');
  $('network').textContent = CONTEXT.name + ' · ' + CONTEXT.network;
  start();
} catch (error) { status(error.message, true); }
