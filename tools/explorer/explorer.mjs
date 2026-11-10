import {PublicChainClient, boundedJSON, networkConfiguration} from './chain-client.mjs';
import {difficulty, formatSIP, intervalStatistics, publicReceipts} from './projection.mjs';

const $ = id => document.getElementById(id);
let configurations = [], client, snapshot = null, receipts = [], generation = 0, controller;
const text = (id, value) => { $(id).textContent = value ?? 'Unknown'; };
const count = value => value == null ? 'Unknown' : value.toLocaleString('en-US');
const number = value => value == null || !Number.isFinite(value) ? 'Unknown' : value.toLocaleString('en-US', {maximumFractionDigits: 3});
const timestamp = value => value == null ? 'Unknown' : new Date(value * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC');
const seconds = value => value == null ? 'Unknown' : number(value) + ' s';
const mode = value => value === 'holder' ? 'Holder' : 'Voyager';

function node(tag, value, className) {
  const item = document.createElement(tag);
  if (value != null) item.textContent = value;
  if (className) item.className = className;
  return item;
}
function hashButton(hash) {
  const button = node('button', hash.slice(0, 12) + '…' + hash.slice(-8), 'hash-button');
  button.title = hash;
  button.setAttribute('aria-label', 'Copy block hash ' + hash);
  button.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(hash); button.textContent = 'Copied'; }
    catch { button.textContent = hash; }
  });
  return button;
}
function table(id, rows, columns, empty) {
  const body = $(id); body.replaceChildren();
  if (!rows.length) {
    const cell = node('td', empty, 'empty-cell'); cell.colSpan = columns;
    const row = node('tr'); row.append(cell); body.append(row); return;
  }
  for (const cells of rows) {
    const row = node('tr');
    for (const value of cells) { const cell = node('td'); cell.append(value instanceof Node ? value : document.createTextNode(String(value))); row.append(cell); }
    body.append(row);
  }
}

function renderMine() {
  text('mine-count', receipts.length ? count(receipts.length) : '—');
  const holders = receipts.filter(row => row.reward_mode === 'holder').length;
  text('holder-share', receipts.length ? number(100 * holders / receipts.length) + '%' : '—');
  text('voyager-share', receipts.length ? number(100 * (receipts.length - holders) / receipts.length) + '%' : '—');
  const current = new Map((snapshot?.blocks ?? []).map(block => [block.height, block]));
  table('mine-blocks', [...receipts].sort((a, b) => b.height - a.height).slice(0, 100).map(row => {
    const block = current.get(row.height);
    const matched = block?.hash === row.hash && block?.reward_mode === row.reward_mode;
    return [count(row.height), hashButton(row.hash), mode(row.reward_mode), matched ? 'Matches sampled chain' : block ? 'Differs from sampled chain' : 'Not in current sample'];
  }), 4, 'No public receipts loaded.');
  $('clear-receipts').disabled = !receipts.length;
}

function render(value) {
  snapshot = value;
  const blocks = value?.blocks ?? [], latest = blocks.at(-1), stats = intervalStatistics(blocks);
  text('chain-height', count(value?.height));
  text('tip-hash', value ? value.tip.slice(0, 16) + '…' + value.tip.slice(-8) : '—');
  text('latest-time', latest ? timestamp(latest.timestamp) : 'Unknown');
  const age = latest ? Math.max(0, Math.floor(Date.now() / 1000) - latest.timestamp) : null;
  text('latest-age', age === null ? 'Unknown' : age < 60 ? age + ' s ago' : age < 3600 ? Math.floor(age / 60) + ' min ago' : number(age / 3600) + ' h ago');
  text('difficulty', number(difficulty(latest?.target)));
  text('hashrate', stats ? number(stats.estimatedWorkRate) : 'Unknown');
  text('interval-count', stats ? stats.count + ' intervals · accepted block timestamps' : 'No interval sample');
  text('interval-mean', seconds(stats?.mean)); text('interval-median', seconds(stats?.median));
  text('interval-p95', seconds(stats?.p95));
  text('interval-range', stats ? number(stats.minimum) + '–' + number(stats.maximum) + ' s' : 'Unknown');
  const chart = $('interval-chart'); chart.replaceChildren(); chart.classList.toggle('empty', !stats);
  if (stats) {
    chart.setAttribute('aria-label', stats.count + ' block intervals, mean ' + seconds(stats.mean) + ', range ' + seconds(stats.minimum) + ' to ' + seconds(stats.maximum));
    for (const interval of stats.intervals) {
      const bar = node('i'); bar.style.height = Math.max(2, interval / stats.maximum * 100) + '%';
      bar.title = seconds(interval); chart.append(bar);
    }
  } else { chart.setAttribute('aria-label', 'Block intervals unavailable'); chart.append(node('span', 'Interval measurements are unavailable.')); }
  table('blocks', [...blocks].reverse().slice(0, 20).map(block => [count(block.height), hashButton(block.hash), timestamp(block.timestamp), number(difficulty(block.target)), count(block.slots_including_padding), node('span', mode(block.reward_mode), 'mode ' + block.reward_mode)]), 6, 'Block data is unavailable.');
  const economics = value?.economics;
  for (const [id, key] of [['issued', 'issued_atoms'], ['burned', 'burned_atoms'], ['holder-pool', 'holder_pool_atoms'], ['locked', 'locked_reward_atoms'], ['circulating', 'circulating_estimate_atoms']]) text(id, formatSIP(economics?.[key]));
  table('unlocks', (economics?.unlock_schedule ?? []).map(row => [count(row.height), formatSIP(row.atoms)]), 2, economics ? 'No scheduled subsidy unlocks.' : 'Unknown');
  text('unlock-note', economics?.unlock_schedule_complete === false ? 'The next 64 scheduled heights. Additional future unlocks are outside this sample.' : 'Public subsidy reward schedule.');
  table('funds', (economics?.funds ?? []).map(row => ['Member ' + (row.index + 1), formatSIP(row.entitled_atoms), formatSIP(row.released_atoms), formatSIP(row.spent_atoms)]), 4, 'Fund measurements are unavailable.');
  const checkpoint = value?.checkpoint;
  text('checkpoint-height', count(checkpoint?.height)); text('checkpoint-hash', checkpoint?.hash);
  text('checkpoint-time', checkpoint ? timestamp(checkpoint.issued_unix_seconds) : 'Unknown');
  text('checkpoint-roster', checkpoint?.roster);
  text('checkpoint-votes', checkpoint ? checkpoint.signer_indices.map(index => 'Slot ' + (index + 1)).join(', ') : 'Unknown');
  for (const id of ['current-signers', 'pending-signers', 'fee-address', 'fund-addresses']) text(id, 'Unknown');
  const issuance = value?.governance?.issuance_fee;
  text('current-issuance-fee', issuance ? formatSIP(issuance.current_atoms) + ' SIP' : 'Unknown');
  text('issuance-fee-bounds', issuance ? formatSIP(issuance.minimum_atoms) + '–' + formatSIP(issuance.maximum_atoms) + ' SIP' : 'Unknown');
  text('pending-issuance-fee', !issuance ? 'Unknown' : issuance.pending ? formatSIP(issuance.pending.amount_atoms) + ' SIP' : 'None');
  text('pending-issuance-height', !issuance ? 'Unknown' : issuance.pending ?
    'Included #' + count(issuance.pending.included_height) + ' · effective #' + count(issuance.pending.effective_height) +
      ' · proposal ' + issuance.pending.proposal_sequence : 'No pending change');
  table('changes', [], 5, 'Configuration-change records are unavailable on this network.');
  text('snapshot-time', value ? 'Snapshot ' + timestamp(value.published_unix_seconds) : 'Snapshot time unknown');
  renderMine();
}

async function refresh() {
  if (!client) return;
  controller?.abort(); controller = new AbortController();
  const current = ++generation;
  $('refresh').disabled = true;
  text('status', 'Loading public node snapshot…');
  try {
    const value = await client.snapshot(controller.signal);
    if (current !== generation) return;
    render(value);
    text('status', 'Public node snapshot loaded');
    text('notice', 'Node-reported chain data. Network work rate is estimated from at most 100 block intervals. Missing fields remain Unknown.');
  } catch (error) {
    if (current !== generation) return;
    render(null);
    text('status', 'Data unavailable');
    text('notice', error.message === 'The public explorer returned a different network.' ? error.message : 'The public snapshot is unavailable or failed validation. Refresh to try again.');
  } finally { if (current === generation) $('refresh').disabled = false; }
}

function selectNetwork(index) {
  controller?.abort(); generation++;
  receipts = []; snapshot = null; render(null);
  text('receipt-status', 'No receipts loaded. A public receipt export is required.');
  $('receipts').value = '';
  client = new PublicChainClient(configurations[index]);
  refresh();
}

$('refresh').addEventListener('click', refresh);
$('network').addEventListener('change', event => selectNetwork(Number(event.target.value)));
for (const button of document.querySelectorAll('[data-panel]')) {
  button.addEventListener('click', () => {
    for (const item of document.querySelectorAll('[data-panel]')) item.removeAttribute('aria-current');
    button.setAttribute('aria-current', 'page');
    for (const panel of document.querySelectorAll('.panel')) panel.hidden = panel.id !== button.dataset.panel;
  });
}
$('receipts').addEventListener('change', async event => {
  const file = event.target.files[0], current = generation;
  if (!file || !client) return;
  try {
    if (file.size > 2_000_000) throw new Error('The public receipt file exceeds its limit.');
    const value = JSON.parse(await file.text());
    if (current !== generation) return;
    receipts = publicReceipts(value, client.configuration); renderMine();
    text('receipt-status', receipts.length + ' public receipts loaded in this tab. Mode shares describe this imported file; older blocks are not checked against the current sample.');
  } catch { receipts = []; renderMine(); text('receipt-status', 'The public receipt file was rejected. Select a matching public export; wallet files and keys are not accepted.'); }
  finally { event.target.value = ''; }
});
$('clear-receipts').addEventListener('click', () => { receipts = []; renderMine(); text('receipt-status', 'Public receipts cleared from this tab.'); });

async function initialize() {
  try {
    const response = await fetch('./explorer-config.json', {credentials: 'omit', redirect: 'error', cache: 'no-store', referrerPolicy: 'no-referrer', signal: AbortSignal.timeout(10_000)});
    const value = await boundedJSON(response, 16384);
    if (value.version !== 1 || !Array.isArray(value.networks) || !value.networks.length || value.networks.length > 2) throw new Error();
    configurations = value.networks.map(config => networkConfiguration(config, location.origin));
    if (new Set(configurations.map(config => config.name)).size !== configurations.length || new Set(configurations.map(config => config.network + config.genesis)).size !== configurations.length) throw new Error();
    const active = configurations.findIndex(config => config.name === value.active);
    if (active < 0) throw new Error();
    $('network').replaceChildren(...configurations.map((config, index) => { const option = node('option', config.name); option.value = String(index); return option; }));
    $('network').value = String(active); $('network').disabled = false;
    selectNetwork(active);
  } catch { render(null); text('status', 'Network configuration unavailable'); text('notice', 'A matching network configuration is required before chain data can be displayed.'); }
}
initialize();
