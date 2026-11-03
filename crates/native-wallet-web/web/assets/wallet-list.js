const amount = value => { const n = BigInt(value || '0'); return `${n / 100000000n}.${(n % 100000000n).toString().padStart(8, '0')}`; };

// One expanded management panel and one proving session prevent ambiguous
// payment sources. Collapsed summaries retain explicitly stale scan results.
export class WalletList {
  constructor({collection, list, workspace, select, rename}) {
    Object.assign(this, {collection, list, workspace, select, rename});
    this.home = document.createComment('wallet workspace');
    workspace.before(this.home);
    this.rows = new Map();
    this.summaries = new Map();
    this.selected = null;
  }
  load(accounts, selected) {
    this.home.after(this.workspace);
    this.rows.clear(); this.list.replaceChildren();
    for (const row of accounts) {
      const detail = document.createElement('details'); detail.className = 'wallet-entry';
      const summary = document.createElement('summary');
      const title = document.createElement('strong'); title.textContent = row.name;
      const address = document.createElement('span'); address.className = 'wallet-address-hint';
      address.textContent = `Account ${row.account} · ${row.info.short_address.slice(0, 14)}…${row.info.short_address.slice(-8)}`;
      const balance = document.createElement('span'); balance.className = 'wallet-summary-balance';
      const body = document.createElement('div'); body.className = 'wallet-entry-body';
      const actions = document.createElement('div'); actions.className = 'wallet-entry-actions';
      const edit = document.createElement('button'); edit.type = 'button'; edit.textContent = 'Edit name';
      edit.setAttribute('aria-label', `Edit name for account ${row.account}`);
      edit.onclick = () => this.rename(row);
      actions.append(edit); body.append(actions); summary.append(title, address, balance); detail.append(summary, body);
      summary.onclick = event => {
        event.preventDefault();
        if (this.selected === row.account) { detail.open = !detail.open; return; }
        this.select(row.account);
      };
      this.rows.set(row.account, {...row, detail, body, balance}); this.list.append(detail);
      this.paint(row.account);
    }
    this.collection.hidden = false; this.activate(selected);
  }
  activate(account) {
    const selected = this.rows.get(account);
    if (!selected) throw new Error('Selected wallet is unavailable.');
    for (const [index, row] of this.rows) row.detail.open = index === account;
    selected.body.append(this.workspace); this.selected = account;
  }
  name(account) { return this.rows.get(account)?.name || `Account ${account}`; }
  paint(account) {
    const row = this.rows.get(account); if (!row) return;
    const state = this.summaries.get(account), sip = state?.rows.find(item => item.asset === '0'.repeat(64));
    row.balance.textContent = state ? `${amount(sip?.available_atoms)} SIP available · last scanned at block ${state.height}` : 'Balance not scanned';
  }
  balance(account, result) { this.summaries.set(account, result); this.paint(account); }
  reset() {
    this.home.after(this.workspace); this.collection.hidden = true; this.list.replaceChildren();
    this.rows.clear(); this.summaries.clear(); this.selected = null;
  }
}
