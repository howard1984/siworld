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
  if (!sameEng2Context(request,context) || request.api !== context.api || JSON.stringify(request.apis) !== JSON.stringify(context.apis) || JSON.stringify(request.submission_apis) !== JSON.stringify(context.submission_apis)) throw new Error('Engineering-v2 session differs from the immutable build configuration.');
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

// Automatic replay is a send operation. Runtime flags cannot replace compiled
// entry, adapter and live-transfer qualification, even for an existing packet.
export function eng2RebroadcastAllowed(configuration) {
  const acceptance=eng2EntryAcceptance();
  return configuration?.name==='siworld-eng-2' && configuration.read_only===false && configuration.desktop_send_measured===true
    && acceptance.entry_qualified===true && acceptance.static_thread_adapter_qualified===true && acceptance.live_transfer_qualified===true;
}
