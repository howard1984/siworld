import init, * as core from './core/wallet.js';
import { LightSession, AddressDirectory } from './light-session.js';
import { ENGINEERING } from './network.js';
import { WalletAccounts, accountIndex, captureBirthday } from './wallet-accounts.js';
import { CommitmentSession } from './commitment-session.js';
await init({module_or_path:new URL('./core/wallet_bg.wasm',import.meta.url)});
if (core.initThreadPool) {
  if (!self.crossOriginIsolated || typeof SharedArrayBuffer === 'undefined') throw new Error('Threaded proving requires cross-origin isolated page headers. Use the standard build otherwise.');
  await core.initThreadPool(Math.max(1, Math.min(4, navigator.hardwareConcurrency || 1)));
}
const { BrowserWallet, inspect_address } = core;
const directory = new AddressDirectory(ENGINEERING,inspect_address);
self.postMessage({ ready: true });
let wallet = null, active = null, accounts = null, online = null, history = null, creationBirthday = null, queue = Promise.resolve(), syncRevision = 0;
const release = () => { history?.free(); active?.free(); accounts?.free(); wallet?.free(); active = accounts = wallet = online = history = creationBirthday = null; };
const scoped = new Set(['register-address', 'online-init', 'sync', 'prepare', 'submit', 'cancel-payment', 'journal']);
function selectAccount(account) {
  accountIndex(account);
  const next = accounts.derive(account);
  active?.free(); active = next; online = null;
  return JSON.parse(active.public_info());
}
self.onmessage = ({ data }) => {
  // Interrupt network waits before queuing a wallet change. WASM operations
  // remain serialized until the abandoned candidate has been discarded.
  if (['accounts-add', 'account-select', 'accounts-rename', 'accounts-backup'].includes(data.action)) { ++syncRevision; online?.cancelSync(); }
  const revision = syncRevision;
  queue=queue.then(()=>handle(data, revision));
};
async function handle(data, revision) {
  const { id, action, args = [] } = data;
  try {
    let result;
    if (action === 'sync' && revision !== syncRevision) throw new Error('Balance synchronization paused for a wallet change.');
    if (scoped.has(action) && (!active || data.account !== JSON.parse(active.public_info()).account)) throw new Error('The selected wallet changed. Reopen its payment panel.');
    switch (action) {
      case 'password-check': result = JSON.parse(core.device_password_status(...args)); break;
      case 'create': release(); wallet = BrowserWallet.create(...args); creationBirthday = await captureBirthday(ENGINEERING,args[0]); result = { words: wallet.recovery_words(), positions: [...wallet.backup_positions()], birthday:creationBirthday }; break;
      case 'restore': release(); wallet = BrowserWallet.restore(...args); result = true; break;
      case 'unlock': release(); wallet = BrowserWallet.unlock(...args); result = JSON.parse(wallet.public_info()); break;
      case 'seal': if (!wallet) throw new Error('Wallet is locked.'); result = { bytes: wallet.seal(...args), info: JSON.parse(wallet.public_info()) }; break;
      case 'accounts-init':
        if (!wallet) throw new Error('Wallet is locked.');
        active?.free(); active = null; history?.free(); history = null; accounts?.free(); online = null;
        accounts = new WalletAccounts(wallet);
        result = await accounts.initialize(args[0], creationBirthday || undefined);
        history = new CommitmentSession(accounts.anchor, ENGINEERING, core.BrowserCommitmentTree);
        creationBirthday = null;
        selectAccount(JSON.parse(wallet.public_info()).account);
        break;
      case 'accounts-add': if (!accounts) throw new Error('Wallet is locked.'); result = await accounts.add(await captureBirthday(ENGINEERING,accounts.network)); break;
      case 'accounts-rename': if (!accounts) throw new Error('Wallet is locked.'); result = await accounts.rename(...args); break;
      case 'accounts-backup': if (!accounts) throw new Error('Wallet is locked.'); result = await accounts.backup(); break;
      case 'account-select': if (!accounts) throw new Error('Wallet is locked.'); result = selectAccount(args[0]); break;
      case 'inspect': result = await directory.resolve(...args); break;
      case 'register-address': if(!wallet)throw new Error('Wallet is locked.'); result=await directory.publish(JSON.parse(active.public_info()).full_address); break;
      case 'online-init': if(!wallet)throw new Error('Wallet is locked.'); online=new LightSession(active,args[0],{history,birthday:accounts.value.accounts.find(row=>row.account===data.account)}); result=await online.initialize(progress=>self.postMessage({id,progress})); break;
      case 'sync': result=await online.sync(progress=>self.postMessage({id,progress})); break;
      case 'prepare': result=await online.prepare(...args,stage=>self.postMessage({id,progress:stage})); break;
      case 'submit': result=await online.submit(...args); break;
      case 'cancel-payment': result=await online.cancel(...args); break;
      case 'journal': result=online.summary(); break;
      case 'lock': release(); result = true; break;
      default: throw new Error('Unsupported wallet operation.');
    }
    self.postMessage({ id, result });
  } catch (error) {
    self.postMessage({ id, error: typeof error === 'string' ? error : error.message || 'Wallet operation failed. Preserve pending payments and retry only their stored packets.' });
  } finally { args.fill(null); }
};
