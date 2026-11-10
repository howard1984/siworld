import init, * as core from './core/wallet.js';
import {CONTEXT} from './context.mjs';
import {ReceiveSession} from './session.mjs';
import {context} from './protocol.mjs';
context(CONTEXT, self.location.origin);
if (core.initThreadPool) throw new Error('Use the verified standard nonthreaded receive core.');
await init({module_or_path:new URL('./core/wallet_bg.wasm', import.meta.url)});
const session = new ReceiveSession(core, CONTEXT, self.location.origin);
self.onmessage = ({data}) => {
  const {id, action, args = []} = data || {};
  if (!Number.isSafeInteger(id) || id < 1) return;
  try { self.postMessage({id, result:session.handle(action, args)}); }
  catch (error) { self.postMessage({id, error:typeof error === 'string' ? error : error.message || 'Receive operation failed.'}); }
  finally { if (Array.isArray(args)) args.fill(null); }
};
self.postMessage({ready:true});
