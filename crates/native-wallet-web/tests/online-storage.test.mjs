import {test} from 'node:test';
import assert from 'node:assert/strict';
import {COMPACT_REORG_BLOCKS, pruneCompact} from '../web/sdk/online-storage.js';

function databaseFixture(rows, failure = false) {
  const original = globalThis.indexedDB, stores = [];
  let opens = 0, closed = 0;
  globalThis.indexedDB = {open() {
    opens++;
    const request = {};
    queueMicrotask(() => {
      request.result = {close() {closed++;}, transaction(store, mode) {
        stores.push([store, mode]);
        const tx = {}, entries = [...rows];
        tx.objectStore = name => {
          assert.equal(name, 'compact');
          return {openCursor() {
            const cursorRequest = {};
            let at = 0;
            const next = () => queueMicrotask(() => {
              if (failure) {tx.onerror(); return;}
              const entry = entries[at++];
              cursorRequest.result = entry ? {value:entry[1], delete:() => rows.delete(entry[0]), continue:next} : null;
              cursorRequest.onsuccess();
              if (!entry) tx.oncomplete();
            });
            next(); return cursorRequest;
          }};
        };
        return tx;
      }};
      request.onsuccess();
    });
    return request;
  }};
  return {stores, opens:() => opens, closed:() => closed, restore:() => {globalThis.indexedDB = original;}};
}

test('public retention keeps the full recent window including recent forks', async () => {
  assert.equal(COMPACT_REORG_BLOCKS, 128);
  const rows = new Map(Array.from({length:130}, (_, i) => ['block-'+(i+1), {height:i+1}]));
  rows.set('old-fork', {height:2}); rows.set('recent-fork', {height:3});
  const f = databaseFixture(rows);
  try {
    assert.equal(await pruneCompact(130), 3);
    assert.equal(rows.size, 129); assert.ok(rows.has('block-3')); assert.ok(rows.has('block-130'));
    assert.ok(rows.has('recent-fork')); assert.ok(!rows.has('old-fork'));
    assert.deepEqual(f.stores, [['compact','readwrite']]); assert.equal(f.closed(), 1);
  } finally {f.restore();}
});

test('invalid boundaries never open storage and short chains need no cleanup', async () => {
  const f = databaseFixture(new Map());
  try {
    for (const value of [-1, 1.5, NaN, '130', 1000001]) await assert.rejects(pruneCompact(value), /boundary/);
    assert.equal(await pruneCompact(128), 0); assert.equal(f.opens(), 0);
  } finally {f.restore();}
});

test('public cleanup failure closes the database and reports preservation of private data', async () => {
  const rows = new Map([['old',{height:1}]]), f = databaseFixture(rows, true);
  try {
    await assert.rejects(pruneCompact(130), /Private wallet data was preserved/);
    assert.equal(rows.size, 1); assert.equal(f.closed(), 1);
    assert.deepEqual(f.stores, [['compact','readwrite']]);
  } finally {f.restore();}
});
