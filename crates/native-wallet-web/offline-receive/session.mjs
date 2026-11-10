// Worker-owned custody; only recovery display, ciphertext and public data leave.
import {context, backup, parseBackup, vaultBytes} from './protocol.mjs';
export class ReceiveSession {
  constructor(core, config, origin) { this.core = core; this.pin = context(config, origin); this.wallet = null; }
  lock() { this.wallet?.free(); this.wallet = null; }
  info(wallet) {
    const value = JSON.parse(wallet.public_info());
    if (value.network !== this.pin.network || value.account !== 0 || value.balance_status !== 'unavailable' || value.send_available !== false) throw new Error('Authenticated receive account differs from the pinned context.');
    const checked = JSON.parse(this.core.inspect_address(value.full_address, this.pin.network, ''));
    if (checked.network !== this.pin.network || checked.full_address !== value.full_address) throw new Error('Public address failed the native network check.');
    return {network:value.network, account:0, full_address:value.full_address};
  }
  handle(action, args = []) {
    if (!Array.isArray(args)) throw new Error('Invalid receive operation.');
    switch (action) {
      case 'create': {
        if (args.length) throw new Error('The receive network and account cannot be overridden.');
        this.lock(); this.wallet = this.core.BrowserWallet.create(this.pin.network, 0);
        try {
          const words = this.wallet.recovery_words(), positions = [...this.wallet.backup_positions()];
          if (typeof words !== 'string' || words.split(' ').length !== 24 || positions.length !== 3 ||
              new Set(positions).size !== 3 || positions.some(p => !Number.isInteger(p) || p < 1 || p > 24)) throw new Error('Invalid native backup challenge.');
          return {words, positions};
        } catch (error) { this.lock(); throw error; }
      }
      case 'seal': {
        if (args.length !== 2 || args.some(value => typeof value !== 'string') || !this.wallet) throw new Error('An active recovery challenge is required.');
        const encrypted = this.wallet.seal(args[0], args[1]);
        try {
          const info = this.info(this.wallet);
          const text = backup(this.pin, encrypted);
          return {backup:text, info};
        } finally { encrypted.fill(0); this.lock(); }
      }
      case 'unlock': {
        if (args.length !== 2 || args.some(value => typeof value !== 'string')) throw new Error('Encrypted backup and its password are required.');
        this.lock();
        const bytes = vaultBytes(parseBackup(args[0], this.pin));
        let opened;
        try { opened = this.core.BrowserWallet.unlock(this.pin.network, bytes, args[1]); return this.info(opened); }
        finally { bytes.fill(0); opened?.free(); }
      }
      case 'lock': if (args.length) throw new Error('Invalid lock request.'); this.lock(); return true;
      default: throw new Error('This tool only creates and verifies encrypted receive backups.');
    }
  }
}
