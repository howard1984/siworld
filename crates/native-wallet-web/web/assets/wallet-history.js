const sip = '0'.repeat(64);
const count=value=>Number.isSafeInteger(value)&&value>=0?value:null;
export const checkpointSettlementText = 'Payments are final once covered by a checkpoint, under the stated signer assumptions. Before that, a payment can still be reversed.';
const phases = {prepared: 'Proof incomplete', finalized: 'Ready to send', pending: 'Pending', unknown: 'Status uncertain', confirmed: 'Confirmed', reserved: 'Proof incomplete', uncertain: 'Status uncertain', accepted: 'Pending', included: 'Included in authenticated receipt', cancelled: 'Cancelled'};
export function transactionRows(result) {
  const grouped = new Map(), settlement = result.checkpoint_finality === true;
  const provisional = result.finality_suspended === true ? 'Included · Finality suspended' : 'Included · Awaiting final confirmation';
  for (const note of result.received_records || []) {
    const id = note.kind === 'mining' ? `reward:${note.block_id}:${note.asset}` : `receipt:${note.id}`;
    let row = grouped.get(id);
    if (!row) {
      row = {id, direction: 'received', title: note.kind === 'mining' ? 'Mining reward' : note.kind === 'allocation' ? 'Allocation received' : 'Payment received',
        asset: note.asset, amount_atoms: '0', height: note.height, timestamp: note.timestamp,
        status: 'Confirmed', confirmations:count(note.confirmations), notes: [], block_id: note.block_id,
        checkpoint_covered:settlement && note.checkpoint_covered===true, checkpoint_finality:settlement};
      grouped.set(id, row);
    }
    row.checkpoint_covered &&= note.checkpoint_covered===true;
    const confirmations=count(note.confirmations);
    if(confirmations!==null)row.confirmations=row.confirmations===null?confirmations:Math.min(row.confirmations,confirmations);
    row.amount_atoms = (BigInt(row.amount_atoms) + BigInt(note.amount_atoms)).toString();
    row.notes.push(note);
    if (!note.spent && note.unlock_height > result.height) {
      if (!note.awaiting_maturity) row.status = 'Locked';
      else if (row.status !== 'Locked') row.status = 'Awaiting maturity';
    }
  }
  const rows = [...grouped.values()].map(row=>({...row,status:settlement
    ? (row.checkpoint_covered?'Checkpoint covered (final)':provisional)+(row.status==='Confirmed'?'':` · ${row.status}`)
    : row.confirmations!==null&&row.confirmations<24
      ? 'Pending confirmation'+(row.status==='Confirmed'?'':` · ${row.status}`):row.status}));
  for (const payment of result.payments || []) rows.push({
    ...payment, id: `payment:${payment.id}`, direction: 'sent', title: 'Payment sent', asset: sip,
    timestamp: payment.confirmed_timestamp ?? payment.created_at ?? null,
    height: payment.confirmed_height ?? null, confirmations:count(payment.confirmations),
    checkpoint_finality:settlement, checkpoint_covered:settlement && payment.phase==='included' && payment.checkpoint_covered===true,
    status:settlement
      ? payment.phase==='included'
        ? payment.checkpoint_covered===true?'Checkpoint covered (final)':provisional
        : ['accepted','pending','uncertain','unknown'].includes(payment.phase)?'Unconfirmed':phases[payment.phase] || 'Status unavailable'
      : payment.phase==='included'&&count(payment.confirmations)!==null&&payment.confirmations<24?'Pending confirmation':phases[payment.phase] || 'Status unavailable',
    notes: [],
  });
  return rows.sort((a, b) => (b.height === null) - (a.height === null) || (b.height ?? 0) - (a.height ?? 0) || (b.timestamp ?? 0) - (a.timestamp ?? 0) || a.id.localeCompare(b.id));
}
function formatted(atoms, asset) {
  if (asset !== sip) return `${atoms} atoms · asset ${asset.slice(0, 12)}…`;
  const n = BigInt(atoms); return `${n / 100000000n}.${(n % 100000000n).toString().padStart(8, '0')} SIP`;
}
function date(value) {
  if (!Number.isSafeInteger(value) || value < 0 || !Number.isFinite(new Date(value * 1000).valueOf())) return 'Time unavailable';
  return new Intl.DateTimeFormat(undefined, {dateStyle: 'medium', timeStyle: 'short'}).format(new Date(value * 1000));
}
export class WalletHistory {
  constructor(root) {
    this.root = root; root.hidden = true; this.filter = 'all'; this.page = 0; this.rows = [];
    root.querySelectorAll('[data-history-filter]').forEach(button => {
      button.onclick = () => { this.filter = button.dataset.historyFilter; this.page = 0; this.paint(); };
    });
    root.querySelector('[data-history-previous]').onclick = () => { this.page--; this.paint(); };
    root.querySelector('[data-history-next]').onclick = () => { this.page++; this.paint(); };
  }
  set(result) {
    this.rows = transactionRows(result);
    this.checkpointFinality = result.checkpoint_finality === true;
    this.finalitySuspended = this.checkpointFinality && result.finality_suspended === true;
    this.paint();
  }
  reset() { this.rows = []; this.checkpointFinality = false; this.finalitySuspended = false; this.filter = 'all'; this.page = 0; this.paint(); }
  paint() {
    const rows = this.rows.filter(row => this.filter === 'all' || row.direction === this.filter);
    const pages = Math.max(1, Math.ceil(rows.length / 20)); this.page = Math.max(0, Math.min(pages - 1, this.page));
    for (const button of this.root.querySelectorAll('[data-history-filter]')) button.setAttribute('aria-pressed', String(button.dataset.historyFilter === this.filter));
    const list = this.root.querySelector('[data-history-list]'); list.replaceChildren();
    if (this.checkpointFinality) {
      const notice = document.createElement('p'); notice.className = 'help'; notice.setAttribute('role','status');
      notice.textContent = this.finalitySuspended
        ? 'Finality suspended. Previously verified payments remain recorded; wait for verified signer recovery before treating new payments as final.'
        : checkpointSettlementText;
      list.append(notice);
    }
    if (!rows.length) { const empty = document.createElement('p'); empty.className = 'help'; empty.textContent = 'No transactions in this view. Synchronize this wallet to update its history.'; list.append(empty); }
    for (const row of rows.slice(this.page * 20, (this.page + 1) * 20)) {
      const detail = document.createElement('details'); detail.className = 'transaction-entry';
      const summary = document.createElement('summary');
      for (const [text, css] of [[row.title, 'transaction-title'], [(row.direction === 'sent' ? '−' : '+') + formatted(row.amount_atoms, row.asset), 'transaction-amount'], [row.confirmations===null?row.status:`${row.status} · ${row.confirmations} confirmation${row.confirmations===1?'':'s'}`, 'transaction-status'], [date(row.timestamp), 'transaction-date']]) {
        const span = document.createElement('span'); span.className = css; span.textContent = text; summary.append(span);
      }
      const fields = [row.height === null ? 'Not included in an accepted block' : `Block ${row.height}`];
      if (row.confirmations!==null) {
        fields.push(`Confirmations: ${row.confirmations}`);
      }
      if (row.checkpoint_finality && !row.checkpoint_covered) fields.push('For high-value payments, wait for checkpoint coverage before treating the payment as settled.');
      else if (!row.checkpoint_finality && row.confirmations!==null) fields.push('Wait for at least 24 confirmations for high-value payments.');
      if (row.recipient) fields.push(`Recipient: ${row.recipient}`);
      if (row.fee_atoms !== undefined) fields.push(`Fee: ${formatted(row.fee_atoms, sip)}`);
      if (row.statement_id) fields.push(`Statement: ${row.statement_id}`);
      if (row.block_id) fields.push(`Block ID: ${row.block_id}`);
      if (row.direction === 'received') fields.push('Sender identity is private.');
      for (const note of row.notes) fields.push(`${formatted(note.amount_atoms, note.asset)} · unlock height ${note.unlock_height}${note.spent ? ' · spent' : ''} · receipt ${note.id}`);
      for (const text of fields) { const p = document.createElement('p'); p.textContent = text; detail.append(p); }
      detail.prepend(summary); list.append(detail);
    }
    this.root.querySelector('[data-history-previous]').disabled = this.page === 0;
    this.root.querySelector('[data-history-next]').disabled = this.page + 1 >= pages;
    this.root.querySelector('[data-history-page]').textContent = `Page ${this.page + 1} of ${pages}`;
  }
}
