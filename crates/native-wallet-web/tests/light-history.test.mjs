import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {resolve, sep} from 'node:path';
import {pathToFileURL} from 'node:url';
const root = pathToFileURL(resolve(process.env.WALLET_WEB_OUTPUT) + sep);
const fixture = pathToFileURL(resolve(process.env.WALLET_FIXTURE_DIR) + sep);
const {initSync, BrowserWallet, BrowserCommitmentTree} = await import(new URL('sdk/core/wallet.js', root));
initSync({module: readFileSync(new URL('sdk/core/wallet_bg.wasm', root))});
// Public synthetic chain and mnemonic; this build must never be deployed.
const config = JSON.parse(readFileSync(new URL('fixture.json', fixture)));
const bytes = readFileSync(new URL('block-64.bin', fixture));
test('private history scans real fixture receipts and isolates derived accounts', () => {
  const wallet = BrowserWallet.restore(config.network, 0, config.words);
  const other = wallet.derive_account(1);
  try {
    for (const active of [wallet, other]) {
      active.enable_light(config.rules_hex, config.genesis);
      active.begin_candidate();
      const state = JSON.parse(active.append_compact(bytes));
      assert.ok(Number.isSafeInteger(state.block_timestamp));
      active.commit_candidate(String(state.height), state.tip);
    }
    const history = JSON.parse(wallet.light_history());
    assert.ok(history.length > 0);
    assert.ok(history.every(row => row.amount_atoms !== '0' && Number.isSafeInteger(row.height)));
    assert.ok(history.some(row => row.kind === 'mining'));
    assert.ok(history.every(row => typeof row.awaiting_maturity === 'boolean'));
    for (const row of history) assert.deepEqual(Object.keys(row).sort(), ['amount_atoms', 'asset', 'awaiting_maturity', 'block_id', 'height', 'id', 'kind', 'spent', 'unlock_height']);
    assert.deepEqual(JSON.parse(other.light_history()), []);
    const before = wallet.light_history();
    wallet.begin_extension(); assert.throws(() => wallet.append_compact(bytes), /continuity/); wallet.abort_candidate();
    assert.equal(wallet.light_history(), before);
  } finally {wallet.free(); other.free();}
});

const {LightSession} = await import(new URL('sdk/light-session.js', root));
const {CommitmentSession} = await import(new URL('sdk/commitment-session.js', root));
function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return {promise, resolve};
}
function waitingResponse(signal) {
  return new Promise((resolve, reject) => {
    if (signal.aborted) return reject(signal.reason);
    signal.addEventListener('abort', () => reject(signal.reason), {once: true});
  });
}
async function interruptedSync(stage, accepted = false) {
  const originalFetch = globalThis.fetch;
  const navigatorDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
  const started = deferred();
  let requestSignal, persisted = 0;
  const progress = [];
  const wallet = BrowserWallet.restore(config.network, 0, config.words);
  const session = new LightSession(wallet, config);
  wallet.enable_light(config.rules_hex, config.genesis);
  if (accepted) {
    wallet.begin_candidate();
    const state = JSON.parse(wallet.append_compact(bytes));
    wallet.commit_candidate(String(state.height), state.tip);
  }
  const journal = {version: 1, network: config.network, tip: accepted ? config.rows[0].block_id : config.genesis,
    height: accepted ? 1 : 0, payments: []};
  const previousHistory = wallet.light_history();
  Object.assign(session, {base: 'https://wallet.invalid/api', key: 'synthetic-session', journal});
  session.fresh = async () => {};
  session.persist = async () => { persisted++; };
  Object.defineProperty(globalThis, 'navigator', {configurable: true, value: {locks: {
    request(name, options, action) { options.signal.throwIfAborted(); return action(); }
  }}});
  globalThis.fetch = async (url, options) => {
    if (stage === 'chain' && url.endsWith('/head')) return Response.json({network: config.network,
      genesis: config.genesis, height: 1, tip: config.rows[0].block_id});
    assert.ok(url.endsWith('/head') || url.includes('/chain?'));
    requestSignal = options.signal; started.resolve();
    return waitingResponse(requestSignal);
  };
  try {
    const syncing = session.sync(update => progress.push(update));
    const rejected = assert.rejects(syncing, error => error.name === 'AbortError');
    await started.promise;
    session.cancelSync();
    await rejected;
    assert.equal(requestSignal.aborted, true);
    assert.equal(session.syncing, false);
    assert.equal(session.ready, false);
    assert.equal(session.syncController, null);
    assert.equal(session.journal, journal);
    assert.equal(persisted, 0);
    assert.equal(progress.length, stage === 'chain' ? 1 : 0);
    if (progress.length) assert.deepEqual(progress[0], {kind: 'synchronization', phase: 'scan',
      height: 0, target_height: 1, eta_seconds: null});
    assert.equal(JSON.parse(wallet.light_balance()).height, journal.height);
    assert.equal(wallet.light_history(), previousHistory);
    // The aborted candidate must not prevent the accepted chain from syncing again.
    globalThis.fetch = async () => Response.json({network: config.network,
      genesis: config.genesis, height: journal.height, tip: journal.tip});
    const resumed = await session.sync();
    assert.equal(resumed.height, journal.height); assert.equal(resumed.ready, true);
    session.cancelSync(); assert.equal(session.ready, true);
  } finally {
    wallet.free(); globalThis.fetch = originalFetch;
    if (navigatorDescriptor) Object.defineProperty(globalThis, 'navigator', navigatorDescriptor);
    else delete globalThis.navigator;
  }
}
test('wallet changes abort a stalled head request without changing accepted state', async () => {
  await interruptedSync('head');
});
test('wallet changes discard a candidate waiting for the chain index and allow retry', async () => {
  await interruptedSync('chain');
});
test('interrupting a later synchronization preserves accepted reward receipts', async () => {
  await interruptedSync('head', true);
});

test('authenticated scan progress keeps sending paused until candidate persistence', async () => {
  const savedFetch = globalThis.fetch, savedDB = globalThis.indexedDB;
  const savedNavigator = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
  const values = new Map(), progress = [];
  const database = {close() {}, transaction() {
    const tx = {objectStore() {return {
      get(key) {return operation(values.get(key));},
      put(value, key) {values.set(key, value); return operation(key);},
    };}};
    function operation(value) {
      const request = {};
      queueMicrotask(() => {request.result = value; request.onsuccess(); tx.oncomplete();});
      return request;
    }
    return tx;
  }};
  globalThis.indexedDB = {open() {
    const request = {}; queueMicrotask(() => {request.result = database; request.onsuccess();});
    return request;
  }};
  Object.defineProperty(globalThis, 'navigator', {configurable: true, value: {locks: {
    request(_name, options, action) {options.signal.throwIfAborted(); return action();}
  }}});
  const wallet = BrowserWallet.restore(config.network, 0, config.words);
  wallet.enable_light(config.rules_hex, config.genesis);
  const session = new LightSession(wallet, config);
  Object.assign(session, {base: 'https://wallet.invalid/api', key: 'synthetic-progress',
    journal: {version: 1, network: config.network, tip: config.genesis, height: 0, payments: []}});
  session.fresh = async () => {};
  session.persistScan = async next => {
    assert.equal(session.ready, false);
    assert.equal(JSON.parse(wallet.light_balance()).height, 0);
    session.journal = next;
  };
  globalThis.fetch = async url => {
    if (url.endsWith('/head')) return Response.json({network: config.network, genesis: config.genesis,
      height: 1, tip: config.rows[0].block_id});
    if (url.includes('/chain?')) return Response.json({ids: [config.rows[0].block_id]});
    assert.ok(url.endsWith('/compact/' + config.rows[0].block_id));
    return new Response(bytes);
  };
  try {
    const result = await session.sync(update => {assert.equal(session.ready, false); progress.push(update);});
    assert.equal(result.ready, true); assert.equal(result.height, 1);
    assert.deepEqual(progress.map(update => [update.height, update.target_height]), [[0, 1], [1, 1]]);
    assert.ok(progress.every(update => update.eta_seconds === null));
    assert.ok(progress.every(update => Object.keys(update).sort().join() === 'eta_seconds,height,kind,phase,target_height'));
  } finally {
    wallet.free(); globalThis.fetch = savedFetch; globalThis.indexedDB = savedDB;
    if (savedNavigator) Object.defineProperty(globalThis, 'navigator', savedNavigator);
    else delete globalThis.navigator;
  }
});

test('sealed scan cache restores private receipts and rejects another account or damaged bytes', () => {
  const wallet = BrowserWallet.restore(config.network, 0, config.words);
  const reopened = BrowserWallet.restore(config.network, 0, config.words);
  const foreign = wallet.derive_account(1);
  try {
    wallet.enable_light(config.rules_hex, config.genesis); wallet.begin_candidate();
    const state = JSON.parse(wallet.append_compact(bytes));
    const pending = wallet.light_cache(true);
    assert.equal(new TextDecoder().decode(pending.slice(0, 8)), 'SWNSCN01');
    assert.throws(() => wallet.open_local(pending), /Invalid local encrypted/);
    wallet.commit_candidate(String(state.height), state.tip);
    assert.throws(() => foreign.restore_light_cache(config.rules_hex, config.genesis, pending), /authentication/);
    const corrupt = new Uint8Array(pending); corrupt[corrupt.length - 1] ^= 1;
    assert.throws(() => reopened.restore_light_cache(config.rules_hex, config.genesis, corrupt), /authentication/);
    reopened.restore_light_cache(config.rules_hex, config.genesis, pending);
    assert.equal(reopened.light_balance(), wallet.light_balance());
    assert.equal(reopened.light_history(), wallet.light_history());
    assert.throws(() => reopened.restore_light_cache(config.rules_hex, config.genesis, pending), /fresh confirmed/);
  } finally {wallet.free(); reopened.free(); foreign.free();}
});

test('scan state and journal persist atomically and reopen without public downloads', async () => {
  const savedFetch = globalThis.fetch, savedNavigator = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
  const values = new Map(), publicValues = new Map(); let failWrite = true, downloaded = 0;
  const io = {
    storage: async (store, key, value) => {
      const target = store === 'private' ? values : publicValues;
      if (value !== undefined) target.set(key, structuredClone(value));
      return target.has(key) ? structuredClone(target.get(key)) : undefined;
    },
    batch: async (a, av, b, bv) => {
      if (failWrite) throw new Error('Synthetic atomic storage failure.');
      values.set(a, new Uint8Array(av)); values.set(b, new Uint8Array(bv));
    },
  };
  Object.defineProperty(globalThis, 'navigator', {configurable: true, value: {locks: {
    request(_name, options, action) {return (action || options)();}
  }}});
  const pinned = {...config, name:'siworld-eng-1', api:'https://wallet.invalid/api'};
  const wallet = BrowserWallet.restore(config.network, 0, config.words);
  const reopened = BrowserWallet.restore(config.network, 0, config.words);
  const session = new LightSession(wallet, pinned, io);
  try {
    await session.initialize();
    globalThis.fetch = async url => {
      if (url.endsWith('/head')) return Response.json({network:config.network, genesis:config.genesis, height:1, tip:config.rows[0].block_id});
      if (url.includes('/chain?')) return Response.json({ids:[config.rows[0].block_id]});
      assert.ok(url.endsWith('/compact/'+config.rows[0].block_id)); downloaded++; return new Response(bytes);
    };
    await assert.rejects(session.sync(), /atomic storage failure/);
    assert.equal(values.size, 0); assert.equal(session.ready, false);
    assert.equal(JSON.parse(wallet.light_balance()).height, 0); assert.equal(session.journal.height, 0);
    failWrite = false; await session.sync();
    assert.equal(session.journal.version, 2); assert.equal(values.size, 2);
    const before = session.summary(), fetched = downloaded;
    globalThis.fetch = () => {throw new Error('Reopening a private scan cache must not download history.');};
    const opened = new LightSession(reopened, pinned, io), progress = [];
    const after = await opened.initialize(row => progress.push(row));
    assert.equal(after.height, before.height); assert.deepEqual(after.rows, before.rows);
    assert.deepEqual(after.received_records, before.received_records);
    assert.equal(after.ready, false); assert.equal(downloaded, fetched);
    assert.deepEqual(progress, [{kind:'synchronization',phase:'cache',height:1,target_height:1,eta_seconds:0}]);
  } finally {
    wallet.free(); reopened.free(); globalThis.fetch = savedFetch;
    if (savedNavigator) Object.defineProperty(globalThis, 'navigator', savedNavigator); else delete globalThis.navigator;
  }
});

test('birthday sync authenticates the prefix, scans later notes and reuses the tree for another account', async () => {
  const savedFetch=globalThis.fetch,savedNavigator=Object.getOwnPropertyDescriptor(globalThis,'navigator');
  const privateValues=new Map(),publicValues=new Map(),requests=[];
  const io={storage:async(store,key,value)=>{
    const values=store==='private'?privateValues:publicValues;
    if(value!==undefined)values.set(key,structuredClone(value));
    return values.has(key)?structuredClone(values.get(key)):undefined;
  },batch:async(a,av,b,bv)=>{privateValues.set(a,new Uint8Array(av));privateValues.set(b,new Uint8Array(bv));}};
  Object.defineProperty(globalThis,'navigator',{configurable:true,value:{locks:{request:(_key,options,action)=>(action||options)()}}});
  const pinned={...config,name:'siworld-eng-1',api:'https://wallet.invalid/api'};
  const wallet=BrowserWallet.restore(config.network,0,config.words),anchor=wallet.derive_account(0),other=wallet.derive_account(1);
  const history=new CommitmentSession(anchor,pinned,BrowserCommitmentTree,io);
  const first=config.rows[0].block_id,next=config.rows[0].next_block_id;
  const nextBytes=readFileSync(new URL('next-64.bin',fixture)),prefix=readFileSync(new URL('commitments-64.bin',fixture));
  globalThis.fetch=async url=>{
    requests.push(url);
    if(url.endsWith('/head'))return Response.json({network:config.network,genesis:config.genesis,height:2,tip:next});
    if(url.includes('/chain?')){const from=Number(new URL(url).searchParams.get('from'));return Response.json({ids:[from===1?first:next]});}
    if(url.endsWith('/commitments/'+first))return new Response(prefix);
    assert.ok(url.endsWith('/compact/'+next),'Pre-birthday compact ciphertext must never be requested.');
    return new Response(nextBytes);
  };
  try {
    const session=new LightSession(wallet,pinned,{...io,history,birthday:{birth_height:1}}),progress=[];
    await session.initialize();const result=await session.sync(row=>progress.push(row));
    assert.equal(result.height,2);assert.equal(result.ready,true);assert.equal(result.received_records.length,1);
    assert.equal(result.received_records[0].height,2);
    assert.equal(result.downloaded_bytes,prefix.length+nextBytes.length);assert.ok(result.authentication_ciphertext_bytes>0);
    assert.ok(progress.some(row=>row.phase==='history'));
    const downloads=requests.filter(url=>url.includes('/compact/')||url.includes('/commitments/')).length;
    const second=new LightSession(other,pinned,{...io,history,birthday:{birth_height:1}});
    await second.initialize();const otherResult=await second.sync();
    assert.equal(otherResult.height,2);assert.deepEqual(otherResult.received_records,[]);
    assert.equal(otherResult.downloaded_bytes,0);
    assert.equal(requests.filter(url=>url.includes('/compact/')||url.includes('/commitments/')).length,downloads);
  }finally{
    history.free();other.free();anchor.free();wallet.free();globalThis.fetch=savedFetch;
    if(savedNavigator)Object.defineProperty(globalThis,'navigator',savedNavigator);else delete globalThis.navigator;
  }
});
