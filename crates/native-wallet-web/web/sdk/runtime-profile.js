import {eng2Context, sameEng2Context} from './eng2-context.js';

export function eng2ReadOnlyProfile(value) {
  const context = eng2Context(value);
  if (value.read_only !== true || value.desktop_send_measured === true) throw new Error('Engineering-v2 website sending is not qualified. Use the explicit read-only profile.');
  return Object.freeze({...context, read_only:true, desktop_send_measured:false, account:0});
}
export function sessionConfiguration(requested, pinned) {
  if (pinned.name !== 'siworld-eng-2') {
    if (requested?.name !== pinned.name || requested?.network !== pinned.network) throw new Error('Wallet session differs from the build configuration.');
    return requested;
  }
  const context = eng2ReadOnlyProfile(pinned), request = eng2ReadOnlyProfile(requested);
  if (!sameEng2Context(request,context) || request.api !== context.api) throw new Error('Engineering-v2 session differs from the immutable build configuration.');
  return context;
}
export function assertWalletOperation(action, pinned) {
  if (pinned.name === 'siworld-eng-2' && ['prepare','submit','cancel-payment','register-address'].includes(action)) throw new Error('Engineering-v2 sending and address publication remain unavailable in this read-only build.');
}

// Source integration is separate from packaged-entry and live-chain acceptance.
// Runtime configuration and service responses cannot upgrade these capabilities.
export function eng2EntryAcceptance() {
  return Object.freeze({entry_qualified:false,static_thread_adapter_qualified:false,live_transfer_qualified:false});
}
