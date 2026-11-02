import { ENGINEERING } from '../sdk/network.js';
import { MAX_BACKUP, parseContentBackup, contentBackup, contentBytes, contentRecords, saveContent } from '../sdk/content-storage.js';

export function initVault(walletInfo) {
  const $ = selector => document.querySelector(selector), dialog = $('#vault-flow');
  let worker, ready = false, healthy = false, sequence = 0, epoch = 0, busy = false;
  let mode = '', selected = null, packages = [], idleTimer, revealTimer, unsaved = false;
  const requests = new Map();
  const status = (text, error = false) => { $('#vault-status').textContent = text; $('#vault-status').classList.toggle('error', error); };
  function capability() { $('#vault-create').disabled = $('#vault-import').disabled = !ready || !healthy; }
  function startWorker() {
    worker = new Worker(new URL('../sdk/content-worker.js', import.meta.url), { type: 'module' });
    worker.onmessage = ({ data }) => {
      if (data.ready) { ready = true; capability(); return; }
      const request = requests.get(data.id); if (!request) return;
      requests.delete(data.id); data.error ? request.reject(new Error(data.error)) : request.resolve(data.result);
    };
    worker.onerror = () => {
      ready = false; capability();
      for (const request of requests.values()) request.reject(new Error('The local content core stopped. Close and reopen this view.'));
      requests.clear(); status('The local content core could not load. Existing encrypted packages were preserved.', true);
    };
  }
  function call(action, args) {
    return new Promise((resolve, reject) => {
      const id = ++sequence; requests.set(id, { resolve, reject }); worker.postMessage({ id, action, args }); args.fill(null);
    });
  }
  function clear() {
    for (const input of dialog.querySelectorAll('input,textarea')) input.value = '';
    selected = null; mode = ''; busy = unsaved = false;
    $('#vault-next').disabled = false; $('#vault-error').textContent = '';
  }
  function close(restart = true) {
    ++epoch; clearTimeout(idleTimer); clearTimeout(revealTimer);
    worker?.terminate(); ready = false;
    for (const request of requests.values()) request.reject(new Error('Content session closed.'));
    requests.clear(); clear(); dialog.close();
    $('#lock').disabled = !walletInfo() && !$('#flow')?.open;
    if (healthy && restart) startWorker(); capability();
  }
  function activity() {
    if (!dialog.open || mode === 'reveal') return;
    clearTimeout(idleTimer); idleTimer = setTimeout(close, 300000);
  }
  function stage(next) {
    mode = next;
    const creating = next === 'create', revealed = next === 'reveal', sealed = next === 'sealed';
    for (const id of ['vault-context', 'vault-fields']) $(`#${id}`).hidden = !creating;
    $('#vault-password-fields').hidden = revealed || sealed;
    $('#vault-confirm-field').hidden = !creating;
    $('#vault-reveal').hidden = !revealed;
    $('#vault-download').hidden = !sealed;
    $('[data-vault-illustration="saved"]').hidden = !sealed || unsaved;
    $('#vault-flow-title').textContent = creating ? 'Create a package.' : revealed ? 'Your private content.' : sealed ? 'Your encrypted package.' : 'Open a package.';
    $('#vault-description').textContent = creating ? 'Use an independent passphrase. The title and content are encrypted locally. Wallet recovery words cannot restore this package.' : revealed ? 'Only this temporary view contains decrypted content. Nothing is sent to the network.' : sealed ? 'Only ciphertext was retained. Download an encrypted backup and keep the passphrase separately.' : 'Enter this package’s independent passphrase. Importing a backup authenticates its network and account before saving.';
    $('#vault-next').textContent = creating ? 'Encrypt and save ↗' : revealed || sealed ? 'Close and clear' : 'Unlock package ↗';
    $('#vault-password').autocomplete = creating ? 'new-password' : 'current-password';
    for (const input of dialog.querySelectorAll('input,textarea,select')) input.required = !input.readOnly && !input.closest('[hidden]');
    activity();
  }
  function begin(next, record = null) {
    if (!ready || !healthy || busy) return;
    ++epoch; clear(); selected = record; stage(next);
    if (next === 'create') { const info = walletInfo(); $('#vault-network').value = info?.network || ENGINEERING.network; $('#vault-account').value = String(info?.account || 0); }
    $('#lock').disabled = false; dialog.showModal();
    (next === 'create' ? ($('#vault-network').value ? $('#vault-title') : $('#vault-network')) : $('#vault-password')).focus();
  }
  function download(record) {
    const valid = parseContentBackup(JSON.stringify(record));
    const url = URL.createObjectURL(new Blob([JSON.stringify(valid, null, 2) + '\n'], { type: 'application/json' }));
    const link = document.createElement('a'); link.href = url; link.download = 'siworld-v1-encrypted-content.json'; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  async function render() {
    packages = await contentRecords(); $('#vault-count').textContent = String(packages.length); $('#vault-empty').hidden = packages.length !== 0;
    $('#vault-list').replaceChildren(...packages.map((record, index) => {
      const row = document.createElement('article'); row.className = 'vault-entry';
      const heading = document.createElement('h3'); heading.textContent = `Encrypted package ${index + 1}`;
      const note = document.createElement('p'); note.textContent = `Account ${record.backup.account} · network ${record.backup.network.slice(0, 10)}… · content locked`;
      const actions = document.createElement('div'); actions.className = 'actions';
      const open = document.createElement('button'); open.type = 'button'; open.textContent = 'Open package ↗'; open.addEventListener('click', () => begin('open', record.backup));
      const backup = document.createElement('button'); backup.type = 'button'; backup.textContent = 'Encrypted backup ↓'; backup.addEventListener('click', () => download(record.backup));
      actions.append(open, backup); row.append(heading, note, actions); return row;
    }));
  }
  $('#vault-create').addEventListener('click', () => begin('create'));
  $('#vault-import').addEventListener('click', () => $('#vault-backup-file').click());
  $('#vault-backup-file').addEventListener('change', async event => {
    try { const file = event.target.files[0]; if (!file) return;
      if (file.size > MAX_BACKUP) throw new Error('Content backup is too large.');
      begin('import', parseContentBackup(await file.text()));
    } catch (error) { status(error.message, true); } finally { event.target.value = ''; }
  });
  $('#vault-cancel').addEventListener('click', close);
  $('#lock').addEventListener('click', close);
  dialog.addEventListener('cancel', event => { event.preventDefault(); close(); });
  $('#vault-download').addEventListener('click', () => { if (selected) { download(selected); if (unsaved) $('#vault-error').textContent = 'Backup download requested. Keep the file before closing this unsaved package.'; } });
  $('#vault-form').addEventListener('submit', async event => {
    event.preventDefault(); if (busy) return;
    if (mode === 'reveal' || mode === 'sealed') { close(); return; }
    busy = true; const token = epoch; $('#vault-next').disabled = true; $('#vault-error').textContent = '';
    try {
      if (mode === 'create') {
        const network = $('#vault-network').value.trim(), account = Number($('#vault-account').value);
        if (!/^[0-9a-f]{64}$/.test(network) || /^0+$/.test(network) || !Number.isInteger(account) || account < 0 || account > 0xffffffff) throw new Error('Enter a nonzero native network ID and unsigned account index.');
        if ($('#vault-password').value !== $('#vault-confirm').value) throw new Error('Vault passphrases do not match.');
        const args = [network, account, String(Date.now()), Number($('#vault-kind').value), $('#vault-title').value.trim(), $('#vault-secret').value, $('#vault-password').value];
        for (const id of ['vault-password', 'vault-confirm']) $(`#${id}`).value = '';
        const bytes = await call('seal', args); if (token !== epoch) return;
        selected = contentBackup(network, account, bytes); bytes.fill(0);
        $('#vault-title').value = $('#vault-secret').value = '';
        try { await saveContent(selected); if (token !== epoch) return; await render(); status('Package encrypted and saved on this device. Download its separate encrypted backup.'); }
        catch { unsaved = true; }
        if (token !== epoch) return;
        stage('sealed');
        if (!unsaved) document.dispatchEvent(new Event('vault-content-saved'));
        if (unsaved) $('#vault-error').textContent = 'Browser storage failed. Download the encrypted backup before closing. Closing discards this unsaved package; existing data was preserved.';
      } else {
        const args = [selected.network, selected.account, contentBytes(selected), $('#vault-password').value];
        $('#vault-password').value = '';
        const result = await call('open', args); if (token !== epoch) return;
        if (mode === 'import') { await saveContent(selected); if (token !== epoch) return; await render(); status('Content backup authenticated and restored. Existing packages were preserved.'); }
        if (token !== epoch) return;
        stage('reveal'); $('#vault-open-title').value = result.title; $('#vault-open-secret').value = result.secret;
        result.title = result.secret = ''; clearTimeout(idleTimer); revealTimer = setTimeout(close, 60000);
      }
    } catch (error) { if (token === epoch) $('#vault-error').textContent = error.message; }
    finally { if (token === epoch) { busy = false; $('#vault-next').disabled = false; } }
  });
  function view() {
    const vault = location.hash === '#vault';
    if($('#wallet-view')) $('#wallet-view').hidden = vault; $('#vault-view').hidden = !vault;
    for (const link of document.querySelectorAll('[data-view]')) {
      if ((link.dataset.view === 'vault') === vault) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current');
    }
    document.dispatchEvent(new CustomEvent('vault-view-change', { detail: { active: vault } }));
  }
  window.addEventListener('hashchange', view); view();
  document.addEventListener('vault-collection-changed',()=>render().catch(()=>status('Imported collection could not be read.',true)));
  for (const event of ['keydown', 'pointerdown']) dialog.addEventListener(event, activity, { passive: true });
  document.addEventListener('visibilitychange', () => { if (document.hidden && dialog.open) close(); });
  window.addEventListener('pagehide', () => close(false));
  window.addEventListener('pageshow', event => { if (event.persisted && healthy) startWorker(); });
  if (!isSecureContext || window.top !== window || !crypto?.getRandomValues || !navigator.locks || !window.indexedDB || !window.Worker || !window.WebAssembly) {
    status('Open Vault directly on HTTPS or localhost with WebAssembly, Web Crypto and Web Locks.', true);
  } else {
    startWorker(); render().then(() => { healthy = true; capability(); status('Content packages are encrypted locally. Chain storage is not connected.'); })
      .catch(() => { healthy = false; capability(); status('Content storage could not be read. Existing data was preserved; saving is paused.', true); });
  }
}
