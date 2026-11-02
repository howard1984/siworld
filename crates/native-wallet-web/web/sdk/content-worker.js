import { initSync, seal_content, open_content } from './core/wallet.js';
import { wasmBytes } from './core/bytes.js';
initSync({ module: wasmBytes });
self.postMessage({ ready: true });
self.onmessage = ({ data }) => {
  const { id, action, args = [] } = data;
  try {
    let result;
    if (action === 'seal') result = seal_content(...args);
    else if (action === 'open') result = JSON.parse(open_content(...args));
    else throw new Error('Unsupported content operation.');
    self.postMessage({ id, result });
  } catch (error) {
    self.postMessage({ id, error: typeof error === 'string' ? error : 'Content operation failed. Nothing was sent.' });
  } finally { args.fill(null); }
};
