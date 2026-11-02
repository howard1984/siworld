import init, * as core from './core/wallet.js';
import { LightSession, AddressDirectory } from './light-session.js';
import { ENGINEERING } from './network.js';
await init({module_or_path:new URL('./core/wallet_bg.wasm',import.meta.url)});
if (core.initThreadPool) {
  if (!self.crossOriginIsolated || typeof SharedArrayBuffer === 'undefined') throw new Error('Threaded proving requires cross-origin isolated page headers. Use the standard build otherwise.');
  await core.initThreadPool(Math.max(1, Math.min(4, navigator.hardwareConcurrency || 1)));
}
const { BrowserWallet, inspect_address } = core;
const directory = new AddressDirectory(ENGINEERING,inspect_address);
self.postMessage({ ready: true });
let wallet = null, online = null, queue = Promise.resolve();
const release = () => { wallet?.free(); wallet = null; online = null; };
self.onmessage = ({ data }) => { queue=queue.then(()=>handle(data)); };
async function handle(data) {
  const { id, action, args = [] } = data;
  try {
    let result;
    switch (action) {
      case 'create': release(); wallet = BrowserWallet.create(...args); result = { words: wallet.recovery_words(), positions: [...wallet.backup_positions()] }; break;
      case 'restore': release(); wallet = BrowserWallet.restore(...args); result = true; break;
      case 'unlock': release(); wallet = BrowserWallet.unlock(...args); result = JSON.parse(wallet.public_info()); break;
      case 'seal': if (!wallet) throw new Error('Wallet is locked.'); result = { bytes: wallet.seal(...args), info: JSON.parse(wallet.public_info()) }; break;
      case 'inspect': result = await directory.resolve(...args); break;
      case 'register-address': if(!wallet)throw new Error('Wallet is locked.'); result=await directory.publish(JSON.parse(wallet.public_info()).full_address); break;
      case 'online-init': if(!wallet)throw new Error('Wallet is locked.'); online=new LightSession(wallet,args[0]); result=await online.initialize(); break;
      case 'sync': result=await online.sync(); break;
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
