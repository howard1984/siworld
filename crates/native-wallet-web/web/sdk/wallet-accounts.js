import {stored, hash} from './online-storage.js';

export const MAX_ACCOUNTS = 10;
const MAX_REGISTRY = 32768;
const encode = value => new TextEncoder().encode(JSON.stringify(value));
export function accountIndex(value) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) throw new Error('Invalid account index.');
  return value;
}
export function walletName(value) {
  if (typeof value !== 'string') throw new Error('Enter a wallet name.');
  const name = value.trim();
  if (!name || [...name].length > 48 || /[\p{Cc}\p{Cf}]/u.test(name)) throw new Error('Use 1 to 48 visible characters for the wallet name.');
  return name;
}

// This registry never crosses a network boundary. The account-zero identity is
// an internal encryption anchor, independent of which account was restored.
export class WalletAccounts {
  constructor(root, storage = stored) {
    this.root = root;
    this.storage = storage;
    this.anchor = null;
    this.value = null;
    this.key = null;
  }
  validate(value) {
    if (!value || Object.keys(value).sort().join() !== 'accounts,network,type,version' || value.version !== 1 ||
        value.type !== 'wallet-accounts' || value.network !== this.network || !Array.isArray(value.accounts) ||
        !value.accounts.length || value.accounts.length > MAX_ACCOUNTS) throw new Error('Invalid encrypted wallet list. Existing data was preserved.');
    const seen = new Set();
    for (const row of value.accounts) {
      if (!row || Object.keys(row).sort().join() !== 'account,name' || seen.has(accountIndex(row.account)) || walletName(row.name) !== row.name) throw new Error('Invalid wallet entry. Existing data was preserved.');
      seen.add(row.account);
    }
    return value;
  }
  decrypt(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length > MAX_REGISTRY + 64) throw new Error('Encrypted wallet list exceeds limit.');
    const plain = this.anchor.open_local(bytes);
    try {
      if (plain.length > MAX_REGISTRY) throw new Error('Wallet list exceeds limit.');
      return this.validate(JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(plain)));
    } finally { plain.fill(0); }
  }
  async read() {
    const bytes = await this.storage('private', this.key);
    return bytes ? this.decrypt(bytes) : null;
  }
  async write(value) {
    this.validate(value);
    const plain = encode(value);
    try {
      if (plain.length > MAX_REGISTRY) throw new Error('Wallet list exceeds limit.');
      await this.storage('private', this.key, this.anchor.protect_local(plain));
    } finally { plain.fill(0); }
    this.value = value;
  }
  async initialize(imported = '') {
    const info = JSON.parse(this.root.public_info());
    this.network = info.network;
    this.anchor = this.root.derive_account(0);
    this.key = 'wallet-accounts:' + await hash(new TextEncoder().encode(JSON.parse(this.anchor.public_info()).full_address));
    return navigator.locks.request(this.key, async () => {
      const existing = await this.read();
      let incoming = null;
      if (imported) {
        if (typeof imported !== 'string' || imported.length > (MAX_REGISTRY + 64) * 2 || !/^(?:[0-9a-f]{2})+$/.test(imported)) throw new Error('Invalid encrypted wallet list backup.');
        incoming = this.decrypt(Uint8Array.from(imported.match(/../g), pair => parseInt(pair, 16)));
      }
      const entries = new Map((incoming?.accounts || []).map(row => [row.account, row]));
      for (const row of existing?.accounts || []) entries.set(row.account, row);
      if (!entries.has(info.account)) entries.set(info.account, {account: info.account, name: `Wallet ${entries.size + 1}`});
      await this.write({version: 1, type: 'wallet-accounts', network: this.network,
        accounts: [...entries.values()].sort((a, b) => a.account - b.account)});
      return this.list();
    });
  }
  list() {
    return this.value.accounts.map(row => {
      const wallet = this.root.derive_account(row.account);
      try { return {...row, info: JSON.parse(wallet.public_info())}; }
      finally { wallet.free(); }
    });
  }
  derive(account) {
    accountIndex(account);
    if (!this.value?.accounts.some(row => row.account === account)) throw new Error('Select a wallet from this recovery phrase.');
    return this.root.derive_account(account);
  }
  async update(change) {
    return navigator.locks.request(this.key, async () => {
      const current = await this.read();
      if (!current) throw new Error('Wallet list is missing. Lock and reopen the wallet.');
      const value = structuredClone(current);
      const result = change(value);
      await this.write(value);
      return {accounts: this.list(), account: result};
    });
  }
  add() {
    return this.update(value => {
      if (value.accounts.length >= MAX_ACCOUNTS) throw new Error(`At most ${MAX_ACCOUNTS} wallets can be managed with this recovery phrase on this device.`);
      const account = Math.max(...value.accounts.map(row => row.account)) + 1;
      accountIndex(account);
      value.accounts.push({account, name: `Wallet ${value.accounts.length + 1}`});
      return account;
    });
  }
  rename(account, name) {
    accountIndex(account); name = walletName(name);
    return this.update(value => {
      const row = value.accounts.find(entry => entry.account === account);
      if (!row) throw new Error('Unknown wallet account.');
      row.name = name;
      return account;
    });
  }
  async backup() {
    return navigator.locks.request(this.key, async () => {
      const bytes = await this.storage('private', this.key);
      if (!bytes) throw new Error('Wallet list is missing.');
      this.decrypt(bytes);
      return [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('');
    });
  }
  free() { this.anchor?.free(); this.anchor = this.root = this.value = this.key = null; }
}
