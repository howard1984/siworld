import type { Entry, SafeBridge, SafeInfo } from './bridge';

type DemoSafe = { info: SafeInfo; entries: Entry[] };
const sampleText = 'SIVault synthetic demo file. No private data or encryption is involved.\n';

// This in-memory fixture never reads local files or handles passwords or keys.
export function createDemoBridge(): SafeBridge {
  const safes = new Map<string, DemoSafe>();
  let active: DemoSafe | undefined;
  let importCount = 0;
  function current(sessionId: string, writable = false): DemoSafe {
    if (!active || active.info.sessionId !== sessionId) throw new Error('This safe is locked.');
    if (writable && active.info.readOnly) throw new Error('This safe is open read-only.');
    return active;
  }
  function open(safe: DemoSafe, readOnly: boolean): SafeInfo {
    active = safe;
    safe.info = { ...safe.info, sessionId: crypto.randomUUID(), readOnly };
    return { ...safe.info };
  }
  return {
    async create(name) {
      const id = crypto.randomUUID();
      const safe: DemoSafe = { info: { id, name, sessionId: '', readOnly: false }, entries: [] };
      safes.set(id, safe);
      return open(safe, false);
    },
    async open(readOnly) {
      const id = crypto.randomUUID();
      const safe: DemoSafe = {
        info: { id, name: 'Personal archive', sessionId: '', readOnly },
        entries: [
          { id: 'documents', parent: null, name: 'Documents', is_dir: true, size: 0 },
          { id: 'photos', parent: null, name: 'Photographs', is_dir: true, size: 0 },
          { id: 'sample-notes', parent: null, name: 'Archive notes.txt', is_dir: false, size: sampleText.length },
          { id: 'sample-record', parent: 'documents', name: 'Sample record.txt', is_dir: false, size: sampleText.length },
          { id: 'sample-index', parent: 'photos', name: 'Photo index.txt', is_dir: false, size: sampleText.length },
        ],
      };
      safes.set(id, safe);
      return open(safe, readOnly);
    },
    async unlock(id, readOnly) {
      const safe = safes.get(id);
      if (!safe) throw new Error('The synthetic safe is no longer available.');
      return open(safe, readOnly);
    },
    async list(sessionId, parent) {
      return current(sessionId).entries.filter((entry) => entry.parent === parent).map((entry) => ({ ...entry }));
    },
    async importFiles(sessionId, parent) {
      const safe = current(sessionId, true);
      importCount += 1;
      safe.entries.push({ id: crypto.randomUUID(), parent, name: `Sample import ${importCount}.txt`, is_dir: false, size: sampleText.length });
      return 1;
    },
    async exportFile(sessionId, entryId) {
      const entry = current(sessionId).entries.find((entry) => entry.id === entryId);
      if (!entry || entry.is_dir) throw new Error('Select a file to export.');
      const url = URL.createObjectURL(new Blob([sampleText], { type: 'text/plain' }));
      const link = document.createElement('a');
      link.href = url;
      link.download = entry.name;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      return true;
    },
    async createDirectory(sessionId, name, parent) {
      const safe = current(sessionId, true);
      if (safe.entries.some((entry) => entry.parent === parent && entry.name === name)) throw new Error('An item with that name already exists.');
      const entry: Entry = { id: crypto.randomUUID(), parent, name, is_dir: true, size: 0 };
      safe.entries.push(entry);
      return { ...entry };
    },
    async lock(sessionId) {
      const safe = current(sessionId);
      safe.info.sessionId = '';
      active = undefined;
    },
  };
}
