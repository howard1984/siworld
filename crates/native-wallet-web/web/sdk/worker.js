import { initSync, BrowserWallet, inspect_address } from './core/wallet.js';
import { wasmBytes } from './core/bytes.js';
initSync({ module: wasmBytes });
self.postMessage({ ready: true });
let wallet = null;
const release = () => { wallet?.free(); wallet = null; };
self.onmessage = ({ data }) => {
  const { id, action, args = [] } = data;
  try {
    let result;
    switch (action) {
      case 'create': release(); wallet = BrowserWallet.create(...args); result = { words: wallet.recovery_words(), positions: [...wallet.backup_positions()] }; break;
      case 'restore': release(); wallet = BrowserWallet.restore(...args); result = true; break;
      case 'unlock': release(); wallet = BrowserWallet.unlock(...args); result = JSON.parse(wallet.public_info()); break;
      case 'seal': if (!wallet) throw new Error('Wallet is locked.'); result = { bytes: wallet.seal(...args), info: JSON.parse(wallet.public_info()) }; break;
      case 'inspect': result = JSON.parse(inspect_address(...args)); break;
      case 'lock': release(); result = true; break;
      default: throw new Error('Unsupported wallet operation.');
    }
    self.postMessage({ id, result });
  } catch (error) {
    self.postMessage({ id, error: typeof error === 'string' ? error : 'Wallet operation failed. No network request was made.' });
  } finally { args.fill(null); }
};
