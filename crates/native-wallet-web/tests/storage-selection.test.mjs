import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
const source = await readFile(new URL('../web/sdk/storage.js', import.meta.url));
const {selectedWallet, savedWalletLabel} = await import('data:text/javascript;base64,' + source.toString('base64'));

test('optional selection storage cannot prevent encrypted wallet access', async () => {
  Object.defineProperty(globalThis, 'indexedDB', {configurable: true, get() {
    throw new Error('Synthetic browser storage restriction.');
  }});
  try {
    assert.equal(await selectedWallet(), '');
    assert.equal(await selectedWallet('local-record'), 'local-record');
  } finally { delete globalThis.indexedDB; }
});

test('record labels remain stable when the storage order changes', () => {
  const a = {id: '11111111-1111-4111-8111-111111111111', account: 0};
  const b = {id: 'eeeeeeee-1111-4111-8111-111111111111', account: 0};
  assert.notEqual(savedWalletLabel(a), savedWalletLabel(b));
  assert.deepEqual([b, a].map(savedWalletLabel).reverse(), [a, b].map(savedWalletLabel));
  assert.equal(savedWalletLabel(a), savedWalletLabel({...a, name: 'Private wallet name'}));
});
