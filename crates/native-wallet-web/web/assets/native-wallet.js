import { WalletList } from './wallet-list.js';
import { WalletHistory } from './wallet-history.js';
import { MAX_ACCOUNTS } from '../sdk/wallet-accounts.js';
import { VAULT } from '../sdk/vault-network.js';
import { backup, bytes, parseBackup, records, save, MAX_BACKUP } from '../sdk/storage.js';
import { ENGINEERING } from '../sdk/network.js';
import { ProofProgress } from '../sdk/proof-progress.js';

const $ = selector => document.querySelector(selector);
const flow = $('#flow');
let worker, sequence = 0, epoch = 0, ready = false, busy = false, storageHealthy = false;
let mode = '', stage = '', context, positions, info, encrypted, savedRecords = [], imported;
let timer, pollTimer, onlineBusy=false, onlineReady=false, preparedId=null;
const pending = new Map(), contacts = new Map();
const proofProgress = new ProofProgress({root: $('#send-progress'), label: $('#send-progress-label'), detail: $('#send-progress-detail'), bar: $('#send-progress-bar')});
const history = new WalletHistory($('#wallet-history'));
const walletList = new WalletList({collection: $('#wallet-collection'), list: $('#wallet-list'), workspace: $('#wallet-workspace'), select: chooseAccount, rename: editWalletName});
let namingAccount = null;
function walletCreation(status = '') {
  const count = walletList.rows.size, full = count >= MAX_ACCOUNTS;
  $('#wallet-count').textContent = `${count} / ${MAX_ACCOUNTS}`;
  $('#add-wallet').disabled = !info || busy || full;
  $('#add-wallet').textContent = busy ? 'Please wait…' : 'Create new wallet ＋';
  $('#add-wallet').setAttribute('aria-busy', String(busy));
  $('#wallet-creation-status').textContent = status || (full
    ? `Wallet limit reached (${MAX_ACCOUNTS} of ${MAX_ACCOUNTS}). You can still manage all existing wallets.`
    : 'Create another wallet with the same recovery phrase. No new recovery phrase is needed.');
}
const paymentControls = () => { for (const id of ['send-recipient', 'send-amount', 'send-priority', 'send-prepare']) $(`#${id}`).disabled = proofProgress.active; };
function message(text, error = false) { $('#status').textContent = text; $('#status').classList.toggle('error', error); }
function capability(value) { value=value&&ENGINEERING.name==='siworld-eng-1'&&/^[0-9a-f]{64}$/.test(ENGINEERING.network); for (const id of ['create', 'restore', 'import-backup']) $(`#${id}`).disabled = !value; }
function startWorker() {
  worker = new Worker(new URL('../sdk/worker.js', import.meta.url), { type: 'module' });
  worker.onmessage = ({ data }) => {
    if (data.ready) { ready = true; capability(storageHealthy); if (storageHealthy) message('Native V1 core ready. Only the pinned engineering network can connect.'); return; }
    const request = pending.get(data.id);
    if (!request) return;
    if (data.progress) { request.onProgress?.(data.progress); return; }
    pending.delete(data.id);
    data.error ? request.reject(new Error(data.error)) : request.resolve(data.result);
  };
  worker.onerror = () => { for (const request of pending.values()) request.reject(new Error('The local wallet core stopped. Lock and reopen the page.')); pending.clear(); capability(false); message('The local wallet core stopped. Preserve pending payments and reopen the encrypted wallet.', true); };
}
function call(action, ...args) {
  return new Promise((resolve, reject) => { const id = ++sequence; pending.set(id, { resolve, reject, onProgress: action === 'prepare' ? stage => proofProgress.stage(stage) : null }); worker.postMessage({ id, action, args, account: info?.account }); });
}
function clearSecrets() {
  for (const input of flow.querySelectorAll('input[type=password], #restore-words, #answers input')) input.value = '';
  $('#words').replaceChildren(); $('#answers').replaceChildren(); positions = null;
  $('#password-strength').textContent = '';
}
function lock(text = 'Wallet locked. Recovery fields and the local worker session were cleared.', restart = true) {
  walletList.reset(); history.reset(); history.root.hidden = true; $('#add-wallet').disabled = true;
  $('#wallet-count').textContent = `0 / ${MAX_ACCOUNTS}`; $('#wallet-creation-status').textContent = '';
  $('#wallet-name-dialog').close(); $('#wallet-name').value = ''; $('#wallet-name-save').disabled = false; namingAccount = null;
  proofProgress.reset(); paymentControls();
  ++epoch; clearTimeout(timer); clearTimeout(pollTimer); onlineReady=false; onlineBusy=false; preparedId=null; worker?.terminate(); ready = false; capability(false);
  for (const request of pending.values()) request.reject(new Error('Wallet session was closed.'));
  pending.clear(); clearSecrets(); flow.close();
  info = encrypted = imported = context = null; busy = false; stage = mode = '';
  $('#next').disabled = false; $('#send-open').disabled=true; $('#send-flow').close(); $('#balance-value').textContent='—'; $('#chain-status').textContent='Wallet locked.';
  contacts.clear();
  $('#locked-notes').hidden=true;$('#locked-note-list').replaceChildren();$('#balance-detail').textContent='Unlock to scan public compact records locally.';$('#asset-balances').replaceChildren();$('#payment-list').replaceChildren();$('#send-recipient').value='';$('#send-amount').value='';$('#send-review').textContent='';$('#send-error').textContent='';
  $('#setup').hidden = false; $('#receiving').hidden = true; $('#full-address').value = ''; $('#short-address').textContent = '';
  $('#account-title').textContent = 'V1 ACCOUNT'; $('#send-source').textContent = '';
  $('#account-index').textContent = 'No wallet unlocked'; $('#account-state').textContent = 'LOCKED';
  $('#lock').disabled = $('#copy-address').disabled = $('#copy-short-address').disabled = true;
  $('#short-address-status').textContent = ''; $('#copy-short-address').textContent = 'Enable short address ↙';
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
    $('#flow-description').textContent = 'Recovery words are the only way to restore this wallet. Confirm your backup before continuing. Engineering assets have no monetary value. The device password only encrypts local storage.';
    display('challenge-fields', mode === 'create'); display('password-fields', true); $('#next').textContent = 'Save encrypted wallet ↗';
    $('#password').autocomplete = 'new-password';
  } else if (next === 'unlock') {
    $('#flow-title').textContent = 'Unlock your V1 wallet.';
    $('#flow-description').textContent = 'Your password decrypts the selected wallet only on this device.';
    display('password-fields', true); $('#confirm-field').hidden = true; $('#password').autocomplete = 'current-password';
    $('#next').textContent = imported ? 'Unlock and import ↗' : 'Unlock wallet ↗';
  }
  $('#password-strength').hidden = next !== 'seal';
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
async function render(publicInfo, record, selected = false) {
  const token = epoch;
  if (!selected) {
    const accounts = await call('accounts-init', record.accounts_hex || '');
    if (token !== epoch) return;
    walletList.load(accounts, publicInfo.account);
  } else walletList.activate(publicInfo.account);
  info = publicInfo; encrypted = record;
  history.reset(); history.root.hidden = false;
  $('#balance-value').textContent = '—'; $('#balance-detail').textContent = 'Synchronizing this account locally.';
  $('#chain-status').textContent = 'Synchronizing this account locally.';
  $('#locked-notes').hidden = true; $('#locked-note-list').replaceChildren();
  $('#asset-balances').replaceChildren(); $('#payment-list').replaceChildren();
  $('#send-open').disabled = true; $('#send-flow').close(); preparedId = null; proofProgress.reset(); paymentControls();
  $('#send-recipient').value = ''; $('#send-amount').value = ''; $('#send-review').textContent = ''; $('#send-error').textContent = '';
  $('#send-source').textContent = `From ${walletList.name(info.account)} · account ${info.account} · ${info.short_address}`;
  $('#account-title').textContent = walletList.name(info.account);
  walletCreation();
  $('#setup').hidden = true; $('#receiving').hidden = false;
  $('#full-address').value = info.full_address; $('#short-address').textContent = info.short_address;
  $('#account-state').textContent = 'UNLOCKED'; $('#account-index').textContent = `Account ${info.account} · ${info.network.slice(0, 12)}…`;
  $('#lock').disabled = $('#copy-address').disabled = false;
  $('#copy-short-address').disabled = ENGINEERING.address_directory !== true;
  $('#copy-short-address').textContent = 'Enable short address ↙';
  $('#short-address-status').textContent = 'Enable the short address to publish only its matching public full address. No recovery words, private keys or viewing keys are sent.';
  $('#send-open').textContent = ENGINEERING.read_only === true ? 'Read-only · Send unavailable' : 'Send ↗';
  message('Wallet unlocked locally. Starting compact engineering synchronization.'); activity(); startOnline();
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
      const assessment = await call('password-check', password);
      if (token !== epoch) return;
      if (!assessment.valid) throw new Error(assessment.label);
      let answers = [...document.querySelectorAll('#answers input')].map(input => input.value).join(' ');
      for (const input of flow.querySelectorAll('input[type=password]')) input.value = '';
      const resultPromise = call('seal', password, answers); password = answers = '';
      const result = await resultPromise; if (token !== epoch) return;
      const record = backup(context.network, context.account, result.bytes); result.bytes.fill(0);
      await save(record); if (token !== epoch) return;
      clearSecrets(); flow.close(); await render(result.info, record); await reloadSaved();
    } else if (stage === 'unlock') {
      const record = imported || savedRecords.find(r => r.id === $('#saved-wallet').value);
      if (!record) throw new Error('Select an encrypted wallet first.');
      let password = $('#password').value; $('#password').value = '';
      const resultPromise = call('unlock', record.network, bytes(record), password); password = '';
      const result = await resultPromise; if (token !== epoch) return;
      if (result.network !== record.network || result.account !== record.account) { await call('lock'); throw new Error('Backup recovery context does not match its authenticated wallet.'); }
      clearSecrets(); await render(result, record); if (token !== epoch) return;
      if (imported) await save(imported); if (token !== epoch) return;
      flow.close(); imported = null; await reloadSaved();
    }
  } catch (error) { if (token === epoch) $('#flow-error').textContent = error.message; }
  finally { if (token === epoch) { busy = false; $('#next').disabled = false; walletCreation(); } }
});
let passwordRevision = 0;
$('#password').addEventListener('input', async () => {
  if (stage !== 'seal' || !ready) return;
  const revision = ++passwordRevision, token = epoch;
  try {
    const assessment = await call('password-check', $('#password').value);
    if (token === epoch && revision === passwordRevision && stage === 'seal') $('#password-strength').textContent = assessment.label;
  } catch { /* Sealing still enforces the same policy inside WASM. */ }
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
$('#export-backup').addEventListener('click', async () => {
  if (!encrypted || busy) return;
  const token = epoch, record = encrypted;
  try {
    const accounts_hex = await call('accounts-backup');
    if (token !== epoch) return;
    download('siworld-native-v1-encrypted.json', parseBackup(JSON.stringify({format:record.format,version:2,network:record.network,account:record.account,vault_hex:record.vault_hex,accounts_hex})));
  } catch (error) { if (token === epoch) message(error.message, true); }
});
$('#copy-address').addEventListener('click', async () => {
  if (!info) return;
  try { await navigator.clipboard.writeText(info.full_address); message('Full V1 address copied. This is public receiving data.'); }
  catch { $('#full-address').focus(); $('#full-address').select(); message('Copy the selected public address manually.'); }
});
$('#copy-short-address').addEventListener('click', async () => {
  if(!info||!ready)return; const token=epoch; const expected=info.short_address;
  $('#copy-short-address').disabled=true;
  try {
    const result=contacts.get(expected)===info.full_address?info:await call('register-address'); if(token!==epoch)return;
    if(result.short_address!==expected)throw new Error('Address registration mismatch.');
    contacts.set(result.short_address,result.full_address);
    $('#short-address-status').textContent='Short address enabled and locally verified. Paste this address directly into the miner setup.';
    $('#copy-short-address').textContent='Copy short address ↙';
    try {await navigator.clipboard.writeText(result.short_address); message('Short address copied.');}
    catch {message('Short address enabled. Copy it from the receiving panel.');}
  } catch(error){if(token===epoch)$('#short-address-status').textContent=error.message;}
  finally {if(token===epoch)$('#copy-short-address').disabled=false;}
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

if(VAULT.application){const link=document.querySelector('[data-view="vault"]');link.href=VAULT.application;link.rel='noreferrer noopener';}else document.querySelector('[data-view="vault"]').addEventListener('click',event=>{event.preventDefault();message('The independent Vault origin is not configured in this build.',true);});
function atoms(text){const n=BigInt(text||'0');return `${n/100000000n}.${(n%100000000n).toString().padStart(8,'0')}`;}
function desktopSend(){return ENGINEERING.read_only!==true&&ENGINEERING.desktop_send_measured===true&&!navigator.userAgentData?.mobile&&!/Android|iPhone|iPad|iPod/i.test(navigator.userAgent)&&navigator.maxTouchPoints===0;}
function showBalance(result,stale=false){
 walletList.balance(info.account,result); history.set(result);
 const tranches=result.locked_tranches||[];$('#locked-notes').hidden=tranches.length===0;$('#locked-note-list').replaceChildren(...tranches.map(tranche=>{const p=document.createElement('p');const estimated=tranche.estimated_timestamp===null||tranche.estimated_timestamp===undefined?null:new Date(tranche.estimated_timestamp*1000);p.textContent=`${atoms(tranche.amount_atoms)} ${tranche.asset==='0'.repeat(64)?'SIP':'asset '+tranche.asset.slice(0,12)+'…'} · unlock height ${tranche.unlock_height} · ${estimated&&!Number.isNaN(estimated.valueOf())?'estimated '+estimated.toLocaleDateString():'date unavailable'}`;return p;}));
 const sip=result.rows.find(row=>row.asset==='0'.repeat(64));$('#balance-value').textContent=atoms(sip?.available_atoms);
 $('#balance-detail').textContent=`Mature ${atoms(sip?.mature_atoms)} SIP · locked ${atoms(sip?.locked_atoms)} SIP · reserved ${atoms(sip?.reserved_atoms)} SIP (${result.reserved_count||0} inputs) · ${result.payments?.filter(p=>p.phase==='pending'||p.phase==='unknown').length||0} pending or uncertain payments`;
 $('#chain-status').textContent=`${stale?'Stale · ':''}siworld-eng-1 · height ${result.height} · ${result.tip.slice(0,16)}… · transactions trust full-node consensus`;
 $('#send-open').disabled=stale||!result.ready||!desktopSend();
 $('#asset-balances').replaceChildren(...result.rows.filter(r=>r.asset!=='0'.repeat(64)).map(row=>{const p=document.createElement('p');p.textContent=`Asset ${row.asset.slice(0,12)}… · available ${row.available_atoms} atoms · locked ${row.locked_atoms} atoms`;return p;}));
 $('#payment-list').replaceChildren(...(result.payments||[]).map(payment=>{const row=document.createElement('p');row.textContent=`${atoms(payment.amount_atoms)} SIP · ${payment.phase} `;if(['finalized','pending','unknown'].includes(payment.phase)){const button=document.createElement('button');button.type='button';button.textContent=payment.phase==='finalized'?'Review and submit':'Retry same packet';button.disabled=stale||!result.ready||!desktopSend();button.onclick=()=>{if(proofProgress.active)return;proofProgress.reset();preparedId=payment.id;$('#send-disclosure').checked=false;$('#send-review').textContent=`${atoms(payment.amount_atoms)} SIP · fee ${atoms(payment.fee_atoms)} SIP · recipient ${payment.recipient}`;$('#send-ready').hidden=false;$('#send-prepare').hidden=true;$('#send-transmit').hidden=false;$('#send-flow').showModal();};row.append(button);}if(['prepared','finalized'].includes(payment.phase)){const cancel=document.createElement('button');cancel.type='button';cancel.textContent='Cancel unsent payment';cancel.onclick=async()=>{try{showBalance(await call('cancel-payment',payment.id));}catch(error){message(error.message,true);}};row.append(cancel);}return row;}));
}
async function startOnline(){const token=epoch;onlineReady=false;try{const result=await call('online-init',ENGINEERING);if(token!==epoch)return;showBalance(result,true);onlineReady=true;await refreshOnline();}catch(error){if(token===epoch)$('#chain-status').textContent=error.message;}}
async function refreshOnline(){clearTimeout(pollTimer);if(!onlineReady||onlineBusy||!info)return;onlineBusy=true;const token=epoch;try{const result=await call('sync');if(token===epoch)showBalance(result);}catch(error){if(token===epoch){$('#chain-status').textContent=`Synchronization paused: ${error.message} Previous balance is stale.`;$('#send-open').disabled=true;}}finally{if(token===epoch){onlineBusy=false;if(info)pollTimer=setTimeout(refreshOnline,5000);}}}
$('#sync-now').onclick=refreshOnline;
$('#send-open').onclick=()=>{if(proofProgress.active){$('#send-flow').showModal();return;}proofProgress.reset();$('#send-disclosure').checked=false;$('#send-recipient').value='';$('#send-prepare').hidden=false;$('#send-ready').hidden=true;$('#send-transmit').hidden=true;$('#send-error').textContent='';$('#send-flow').showModal();};
$('#send-close').onclick=()=>$('#send-flow').close();
$('#send-form').onsubmit=async event=>{event.preventDefault();if(onlineBusy)return;onlineBusy=true;clearTimeout(pollTimer);const token=epoch;$('#send-error').textContent='';try{if(!desktopSend())throw new Error('Phone sending remains disabled pending physical-device measurements.');const amount=$('#send-amount').value;if(!/^(0|[1-9][0-9]{0,10})(\.[0-9]{1,8})?$/.test(amount))throw new Error('Enter a positive SIP amount with at most eight decimals.');const [whole,fraction='']=amount.split('.');const value=BigInt(whole)*100000000n+BigInt(fraction.padEnd(8,'0'));if(value<=0n)throw new Error('Amount must be positive.');const address=$('#send-recipient').value.trim();const checked=await call('inspect',address,info.network,contacts.get(address)||'');if(token!==epoch)return;contacts.set(checked.short_address,checked.full_address);proofProgress.start();paymentControls();const result=await call('prepare',address,contacts.get(address)||'',value.toString(),$('#send-priority').checked);if(token!==epoch)return;proofProgress.finish(result.proving_ms);preparedId=result.prepared_id;showBalance(result);const review=result.payments.find(p=>p.id===preparedId);$('#send-review').textContent=`${atoms(review.amount_atoms)} SIP · fee ${atoms(review.fee_atoms)} SIP · recipient ${review.recipient}`;$('#send-error').textContent=`Proof generated and locally verified in ${(result.proving_ms/1000).toFixed(2)} seconds. Nothing has been transmitted.`;$('#send-ready').hidden=false;$('#send-prepare').hidden=true;$('#send-transmit').hidden=false;}catch(error){if(token===epoch){proofProgress.fail();$('#send-error').textContent=error.message;}}finally{if(token===epoch){onlineBusy=false;paymentControls();pollTimer=setTimeout(refreshOnline,5000);}}};
$('#send-transmit').onclick=async()=>{if(!desktopSend()){$('#send-error').textContent='Phone sending remains disabled pending physical-device measurements.';return;}if(onlineBusy||!preparedId||!$('#send-disclosure').checked)return;onlineBusy=true;const token=epoch;try{const result=await call('submit',preparedId);if(token!==epoch)return;showBalance(result);$('#send-error').textContent='Admission acknowledged pending. Inclusion is confirmed only by a later authenticated compact block.';$('#send-transmit').hidden=true;}catch(error){if(token===epoch)$('#send-error').textContent=`Submission is uncertain: ${error.message} Retry the same stored packet; do not create a replacement payment.`;}finally{if(token===epoch){onlineBusy=false;pollTimer=setTimeout(refreshOnline,5000);}}};


async function chooseAccount(account) {
  if (!info || busy || proofProgress.active || $('#send-flow').open) { message('Close the payment panel and finish the current operation before switching wallets.', true); return; }
  if (info.account === account) { walletList.activate(account); return; }
  busy = true; const token = ++epoch; clearTimeout(pollTimer); onlineReady = false;
  walletCreation('Opening the selected wallet. Its balance will synchronize separately.'); $('#send-open').disabled = true;
  message('Opening the selected wallet. Pausing the previous balance synchronization.');
  try {
    const selected = await call('account-select', account);
    if (token !== epoch) return;
    onlineBusy = false;
    await render(selected, encrypted, true);
  } catch (error) { if (token === epoch) lock(error.message); }
  finally { if (token === epoch) { busy = false; walletCreation(); } }
}
$('#add-wallet').onclick = async () => {
  if (!info || busy || proofProgress.active || $('#send-flow').open) return;
  busy = true; const token = epoch; let failure = '';
  walletCreation('Creating a wallet locally. Pausing the current balance synchronization.');
  message('Creating a wallet with the same recovery phrase. No new recovery phrase is needed.');
  try {
    const result = await call('accounts-add');
    if (token !== epoch) return;
    walletList.load(result.accounts, info.account); busy = false;
    await chooseAccount(result.account);
    if (token < epoch && info?.account === result.account) message('Wallet added using the same recovery phrase. Save a new encrypted backup to preserve account indexes and local names.');
  } catch (error) { if (token === epoch) { failure = `Wallet creation failed: ${error.message}`; message(failure, true); } }
  finally { if (token === epoch) { busy = false; walletCreation(failure); } }
};
function editWalletName(row) {
  if (!info || busy || proofProgress.active) return;
  namingAccount = row.account; $('#wallet-name').value = row.name; $('#wallet-name-error').textContent = '';
  $('#wallet-name-dialog').showModal(); $('#wallet-name').focus();
}
function closeName() { $('#wallet-name-dialog').close(); $('#wallet-name').value = ''; namingAccount = null; }
$('#wallet-name-cancel').onclick = closeName;
$('#wallet-name-dialog').addEventListener('cancel', event => { event.preventDefault(); closeName(); });
$('#wallet-name-form').onsubmit = async event => {
  event.preventDefault(); if (!info || namingAccount === null || busy) return;
  const token = epoch; busy = true; $('#wallet-name-save').disabled = true;
  try {
    const result = await call('accounts-rename', namingAccount, $('#wallet-name').value);
    if (token !== epoch) return;
    walletList.load(result.accounts, info.account); $('#account-title').textContent = walletList.name(info.account);
    $('#send-source').textContent = `From ${walletList.name(info.account)} · account ${info.account} · ${info.short_address}`;
    closeName(); message('Wallet name saved only in encrypted storage on this device.');
  } catch (error) { if (token === epoch) $('#wallet-name-error').textContent = error.message; }
  finally { if (token === epoch) { busy = false; $('#wallet-name-save').disabled = false; } }
};
