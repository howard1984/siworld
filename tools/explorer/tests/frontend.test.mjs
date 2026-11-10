// Execute the real page module against synthetic responses and a minimal DOM.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {fixtureNetworks, fixtureSnapshot} from './fixture-server.mjs';

class Element {
  constructor() { this.children = []; this.textContent = ''; this.listeners = new Map(); this.classList = {toggle() {}}; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  setAttribute() {}
  removeAttribute() {}
  addEventListener(name, callback) { this.listeners.set(name, callback); }
}
test('page shows actual v2 issuance values, clears to v1 Unknown and rejects leaked fields', async () => {
  const html = await readFile(new URL('../index.html', import.meta.url), 'utf8');
  const elements = new Map([...html.matchAll(/id="([^"]+)"/g)].map(match => [match[1], new Element()]));
  const config = fixtureNetworks[1];
  let value = fixtureSnapshot(config); value.version = 2; value.height = 3; value.tip = '77'.repeat(32);
  value.governance.issuance_fee = {current_atoms: '5000000000', minimum_atoms: '100000000', maximum_atoms: '1000000000000',
    pending: {amount_atoms: '7500000000', proposal_sequence: '9007199254740993', included_height: 1, effective_height: 4033}};
  const previous = new Map(['document', 'Node', 'location', 'fetch'].map(key => [key, Object.getOwnPropertyDescriptor(globalThis, key)]));
  Object.assign(globalThis, {document: {getElementById: id => elements.get(id), querySelectorAll: () => [],
    createElement: () => new Element(), createTextNode: text => text}, Node: Element, location: {origin: 'https://explorer.invalid'},
    fetch: async url => new Response(JSON.stringify(url === './explorer-config.json' ? {version: 1, active: config.name, networks: [config]} : value),
      {headers: {'Content-Type': 'application/json'}})});
  try {
    await import('../explorer.mjs?issuance-frontend-test');
    for (let i = 0; i < 100 && elements.get('status').textContent !== 'Public node snapshot loaded'; i++) await new Promise(done => setImmediate(done));
    assert.equal(elements.get('status').textContent, 'Public node snapshot loaded');
    assert.equal(elements.get('current-issuance-fee').textContent, '50.00000000 SIP');
    assert.equal(elements.get('pending-issuance-fee').textContent, '75.00000000 SIP');
    assert.equal(elements.get('issuance-fee-bounds').textContent, '1.00000000–10,000.00000000 SIP');
    assert.equal(elements.get('pending-issuance-height').textContent, 'Included #1 · effective #4,033 · proposal 9007199254740993');
    value.governance.issuance_fee.pending = null;
    await elements.get('refresh').listeners.get('click')();
    assert.equal(elements.get('pending-issuance-fee').textContent, 'None');
    value = fixtureSnapshot(config);
    await elements.get('refresh').listeners.get('click')();
    assert.equal(elements.get('current-issuance-fee').textContent, 'Unknown');
    assert.equal(elements.get('pending-issuance-fee').textContent, 'Unknown');
    value.governance.normal_fee_atoms = '1';
    await elements.get('refresh').listeners.get('click')();
    assert.equal(elements.get('status').textContent, 'Data unavailable');
    assert.equal(elements.get('current-issuance-fee').textContent, 'Unknown');
  } finally {
    for (const [key, descriptor] of previous) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor); else delete globalThis[key];
    }
  }
});
