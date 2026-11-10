const HASH = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]{0,38})$/;
const MODES = ['holder', 'voyager'];
function requireValue(test, message = 'The public explorer response is invalid.') {
  if (!test) throw new Error(message);
}
function keys(value, expected) {
  requireValue(value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).sort().join(',') === expected.split(' ').sort().join(','));
}
function integer(value, maximum = 1_000_000) {
  requireValue(Number.isSafeInteger(value) && value >= 0 && value <= maximum);
  return value;
}
function hash(value) { requireValue(typeof value === 'string' && HASH.test(value)); return value; }
function atoms(value) {
  if (value === null) return null;
  requireValue(typeof value === 'string' && DECIMAL.test(value) && BigInt(value) < 1n << 128n);
  return value;
}

function issuanceFee(value, head) {
  keys(value, 'current_atoms minimum_atoms maximum_atoms pending');
  for (const key of ['current_atoms', 'minimum_atoms', 'maximum_atoms']) {
    atoms(value[key]); requireValue(value[key] !== null);
  }
  requireValue(value.minimum_atoms === '100000000' && value.maximum_atoms === '1000000000000');
  const within = amount => BigInt(amount) >= 100_000_000n && BigInt(amount) <= 1_000_000_000_000n;
  requireValue(within(value.current_atoms));
  let pending = null;
  if (value.pending !== null) {
    const row = value.pending;
    keys(row, 'amount_atoms proposal_sequence included_height effective_height');
    atoms(row.amount_atoms); atoms(row.proposal_sequence);
    requireValue(row.amount_atoms !== null && within(row.amount_atoms) && row.proposal_sequence !== null &&
      BigInt(row.proposal_sequence) > 0n && BigInt(row.proposal_sequence) <= (1n << 64n) - 1n);
    integer(row.included_height); integer(row.effective_height, Number.MAX_SAFE_INTEGER);
    requireValue(row.included_height > 0 && row.included_height <= head && head < row.effective_height &&
      row.effective_height === row.included_height + 4032);
    pending = Object.freeze({...row});
  }
  return Object.freeze({...value, pending});
}

export function normalizeProjection(value, config) {
  keys(value, 'version network genesis height tip published_unix_seconds blocks economics checkpoint governance');
  requireValue([1, 2].includes(value.version) && value.network === config.network && value.genesis === config.genesis,
    'The public explorer returned a different network.');
  integer(value.height); hash(value.tip); integer(value.published_unix_seconds, Number.MAX_SAFE_INTEGER);
  requireValue(value.height !== 0 || value.tip === config.genesis);
  requireValue(Array.isArray(value.blocks) && value.blocks.length <= 101);
  const blocks = value.blocks.map((block, index) => {
    keys(block, 'height hash parent_hash timestamp target slots_including_padding reward_mode work');
    integer(block.height); hash(block.hash); hash(block.parent_hash); hash(block.target);
    integer(block.timestamp, Number.MAX_SAFE_INTEGER);
    requireValue(block.height > 0 && block.height <= value.height && BigInt('0x' + block.target) > 0n);
    requireValue(Number.isInteger(block.slots_including_padding) && block.slots_including_padding >= 64 &&
      block.slots_including_padding <= 576 && block.slots_including_padding % 16 === 0 && MODES.includes(block.reward_mode));
    requireValue(typeof block.work === 'string' && /^[1-9][0-9]{0,77}$/.test(block.work));
    requireValue(BigInt(block.work) === (1n << 256n) / (BigInt('0x' + block.target) + 1n));
    if (index) {
      const previous = value.blocks[index - 1];
      requireValue(previous.height + 1 === block.height && previous.hash === block.parent_hash);
    }
    return Object.freeze({...block});
  });
  requireValue(!blocks.length || blocks.at(-1).height === value.height && blocks.at(-1).hash === value.tip);
  const economic = value.economics;
  keys(economic, 'issued_atoms burned_atoms holder_pool_atoms locked_reward_atoms unlock_schedule unlock_schedule_complete funds circulating_estimate_atoms');
  for (const name of ['issued_atoms', 'burned_atoms', 'holder_pool_atoms', 'locked_reward_atoms', 'circulating_estimate_atoms']) atoms(economic[name]);
  requireValue(Array.isArray(economic.unlock_schedule) && economic.unlock_schedule.length <= 64 &&
    typeof economic.unlock_schedule_complete === 'boolean' && Array.isArray(economic.funds) && economic.funds.length <= 32);
  const schedule = economic.unlock_schedule.map((row, index) => {
    keys(row, 'height atoms'); integer(row.height, Number.MAX_SAFE_INTEGER); atoms(row.atoms);
    requireValue(row.height > value.height && (index === 0 || row.height > economic.unlock_schedule[index - 1].height));
    return Object.freeze({...row});
  });
  const funds = economic.funds.map((fund, index) => {
    keys(fund, 'index entitled_atoms released_atoms spent_atoms');
    requireValue(fund.index === index);
    atoms(fund.entitled_atoms); atoms(fund.released_atoms); atoms(fund.spent_atoms);
    if (fund.entitled_atoms !== null && fund.released_atoms !== null && fund.spent_atoms !== null) {
      requireValue(BigInt(fund.spent_atoms) <= BigInt(fund.released_atoms) && BigInt(fund.released_atoms) <= BigInt(fund.entitled_atoms));
    }
    return Object.freeze({...fund});
  });
  let checkpoint = null;
  if (value.checkpoint !== null) {
    const item = value.checkpoint;
    keys(item, 'height hash issued_unix_seconds roster signer_indices');
    integer(item.height); hash(item.hash); hash(item.roster); integer(item.issued_unix_seconds, Number.MAX_SAFE_INTEGER);
    requireValue(item.height > 0 && item.height <= value.height && Array.isArray(item.signer_indices) && item.signer_indices.length >= 2 && item.signer_indices.length <= 3 &&
      item.signer_indices.every(n => Number.isInteger(n) && n >= 0 && n < 3) && new Set(item.signer_indices).size === item.signer_indices.length);
    checkpoint = Object.freeze({...item, signer_indices: Object.freeze([...item.signer_indices])});
  }
  const names = 'current_signers fee_address fund_addresses changes';
  keys(value.governance, value.version === 1 ? names : names + ' issuance_fee');
  requireValue(names.split(' ').every(key => value.governance[key] === null));
  const governance = {...value.governance};
  if (value.version === 2) governance.issuance_fee = issuanceFee(governance.issuance_fee, value.height);
  return Object.freeze({...value, blocks: Object.freeze(blocks), checkpoint,
    economics: Object.freeze({...economic, unlock_schedule: Object.freeze(schedule), funds: Object.freeze(funds)}),
    governance: Object.freeze(governance)});
}

export function intervalStatistics(blocks) {
  if (blocks.length < 2) return null;
  const intervals = blocks.slice(1).map((block, index) => block.timestamp - blocks[index].timestamp);
  if (intervals.some(seconds => seconds <= 0)) return null;
  const sorted = [...intervals].sort((a, b) => a - b);
  const total = intervals.reduce((sum, seconds) => sum + seconds, 0);
  const work = blocks.slice(1).reduce((sum, block) => sum + BigInt(block.work), 0n);
  return {count: intervals.length, intervals, minimum: sorted[0], maximum: sorted.at(-1),
    median: sorted.length % 2 ? sorted[(sorted.length - 1) / 2] : (sorted[sorted.length / 2 - 1] + sorted[sorted.length / 2]) / 2,
    mean: total / intervals.length, p95: sorted[Math.ceil(sorted.length * .95) - 1],
    estimatedWorkRate: Number(work * 1000n / BigInt(total)) / 1000};
}

export function difficulty(target) {
  if (!target) return null;
  hash(target);
  return Number(((1n << 256n) * 1_000_000n) / (BigInt('0x' + target) + 1n)) / 1_000_000;
}

export function formatSIP(value) {
  if (value === null || value === undefined) return 'Unknown';
  atoms(value);
  const n = BigInt(value), whole = n / 100_000_000n, fraction = (n % 100_000_000n).toString().padStart(8, '0');
  return whole.toLocaleString('en-US') + '.' + fraction;
}

export function publicReceipts(value, config) {
  keys(value, 'version network genesis blocks');
  requireValue(value.version === 1 && value.network === config.network && value.genesis === config.genesis,
    'The public receipt file belongs to a different network.');
  requireValue(Array.isArray(value.blocks) && value.blocks.length <= 20_000, 'The public receipt file exceeds its limit.');
  const seen = new Set();
  return Object.freeze(value.blocks.map(row => {
    keys(row, 'height hash reward_mode'); integer(row.height); hash(row.hash);
    requireValue(row.height > 0 && MODES.includes(row.reward_mode) && !seen.has(row.hash));
    seen.add(row.hash);
    return Object.freeze({...row});
  }));
}
