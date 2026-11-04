import {stored, hash, readJSON} from './online-storage.js';

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
export function walletBirthday(value) {
  if (!value || Object.keys(value).sort().join() !== 'birth_height,created_on' ||
      !Number.isSafeInteger(value.birth_height) || value.birth_height < 0 || value.birth_height > 1000000 ||
      value.created_on !== null && (typeof value.created_on !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value.created_on) ||
        !Number.isFinite(Date.parse(value.created_on + 'T00:00:00Z')) || new Date(value.created_on + 'T00:00:00Z').toISOString().slice(0,10) !== value.created_on)) throw new Error('Invalid wallet birthday.');
  return {...value};
}
const unknownBirthday = () => ({birth_height: 0, created_on: null});
export async function captureBirthday(config, network, io = {}) {
  const fallback = walletBirthday({birth_height:0, created_on:io.date || new Date().toISOString().slice(0,10)});
  try {
    if (network !== config.network || config.name !== 'siworld-eng-1') throw new Error('Unpinned birthday context.');
    const origin = new URL(config.api);
    if (origin.username || origin.password || origin.search || origin.hash ||
        !(origin.protocol === 'https:' || origin.protocol === 'http:' && origin.hostname === 'localhost')) throw new Error('Pinned birthday service required.');
    const head = await (io.json || readJSON)(origin.href.replace(/\/$/,'') + '/v1/head', {signal:AbortSignal.timeout(3000), limit:20000});
    if (head.network !== network || head.genesis !== config.genesis || !/^[0-9a-f]{64}$/.test(head.tip) ||
        !Number.isSafeInteger(head.height) || head.height < 0 || head.height > 1000000) throw new Error('Invalid birthday head.');
    return {...fallback, birth_height:head.height};
  } catch { return fallback; }
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
    const legacy = value?.version === 1;
    if (!value || Object.keys(value).sort().join() !== (legacy ? 'accounts,network,type,version' : 'accounts,highest_account,network,type,version') || ![1,2].includes(value.version) ||
        value.type !== 'wallet-accounts' || value.network !== this.network || !Array.isArray(value.accounts) ||
        !value.accounts.length || value.accounts.length > MAX_ACCOUNTS) throw new Error('Invalid encrypted wallet list. Existing data was preserved.');
    const seen = new Set();
    for (const row of value.accounts) {
      if (!row || Object.keys(row).sort().join() !== (legacy ? 'account,name' : 'account,birth_height,created_on,name') || seen.has(accountIndex(row.account)) || walletName(row.name) !== row.name) throw new Error('Invalid wallet entry. Existing data was preserved.');
      if (!legacy) walletBirthday({birth_height:row.birth_height, created_on:row.created_on});
      seen.add(row.account);
    }
    const highest = Math.max(...seen);
    if (!legacy && accountIndex(value.highest_account) < highest) throw new Error('Highest wallet index is inconsistent.');
    return legacy ? {...value, version:2, highest_account:highest,
      accounts:value.accounts.map(row => ({...row, ...unknownBirthday()}))} : value;
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
    value = this.validate(value);
    const plain = encode(value);
    try {
      if (plain.length > MAX_REGISTRY) throw new Error('Wallet list exceeds limit.');
      await this.storage('private', this.key, this.anchor.protect_local(plain));
    } finally { plain.fill(0); }
    this.value = value;
  }
  async initialize(imported = '', birthday = unknownBirthday()) {
    birthday = walletBirthday(birthday);
    const info = JSON.parse(this.root.public_info());
    this.network = info.network;
    this.anchor?.free();
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
      for (const row of existing?.accounts || []) {
        const other = entries.get(row.account);
        // Preserve local names and the earliest scan boundary from either backup.
        entries.set(row.account, other ? {...row, birth_height:Math.min(row.birth_height, other.birth_height),
          created_on:row.created_on && other.created_on ? [row.created_on,other.created_on].sort()[0] : row.created_on || other.created_on} : row);
      }
      if (!entries.has(info.account)) entries.set(info.account, {account: info.account, name: `Wallet ${entries.size + 1}`, ...birthday});
      await this.write({version: 2, type: 'wallet-accounts', network: this.network,
        highest_account:Math.max(info.account, existing?.highest_account || 0, incoming?.highest_account || 0, ...entries.keys()),
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
  add(birthday = unknownBirthday()) {
    birthday = walletBirthday(birthday);
    return this.update(value => {
      if (value.accounts.length >= MAX_ACCOUNTS) throw new Error(`At most ${MAX_ACCOUNTS} wallets can be managed with this recovery phrase on this device.`);
      const account = value.highest_account + 1;
      accountIndex(account);
      value.accounts.push({account, name: `Wallet ${value.accounts.length + 1}`, ...birthday});
      value.highest_account = account;
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
