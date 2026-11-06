import {stored, hash, fetchLimited, readJSON} from './online-storage.js';

const identity = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const requestSignal = signal => signal
  ? AbortSignal.any([signal, AbortSignal.timeout(30000)]) : AbortSignal.timeout(30000);

// Run inside the wallet worker. Only the sealed frontier is persisted. Raw
// authentication records, including incidental ciphertext bytes, are erased.
export class CommitmentSession {
  constructor(anchor, config, Tree, io = {}) {
    this.anchor = anchor; this.config = config; this.Tree = Tree;
    this.storage = io.storage || stored;
    this.json = io.json || readJSON;
    this.binary = io.binary || fetchLimited;
    this.tree = null; this.projections = true;
  }
  async initialize() {
    const c = this.config, info = JSON.parse(this.anchor.public_info());
    if (c.name !== 'siworld-eng-1' || !identity(c.genesis) || !c.rules_hex ||
        info.network !== c.network || info.account !== 0) throw new Error('Pinned account-zero history context required.');
    const origin = new URL(c.api);
    if (origin.username || origin.password || origin.search || origin.hash ||
        !(origin.protocol === 'https:' || origin.protocol === 'http:' && origin.hostname === 'localhost')) throw new Error('Pinned HTTPS history service required.');
    this.base = origin.href.replace(/\/$/, '');
    this.key = 'commitment-tree:' + await hash(new TextEncoder().encode(info.full_address));
    const encrypted = await this.storage('private', this.key);
    this.tree = encrypted ? this.Tree.restore(c.rules_hex, c.genesis, this.anchor, encrypted)
      : this.Tree.create(c.rules_hex, c.genesis);
    return JSON.parse(this.tree.summary());
  }
  async atHeight(head, height, signal, onProgress = () => {}) {
    if (!Number.isSafeInteger(height) || height < 0 || height > head.height || head.network !== this.config.network ||
        head.genesis !== this.config.genesis || !identity(head.tip)) throw new Error('Invalid historical scan boundary.');
    let tip = height === 0 ? this.config.genesis : head.tip;
    if (height > 0 && height < head.height) {
      const page = await this.json(`${this.base}/v1/chain?tip=${head.tip}&from=${height}&limit=1`, {signal:requestSignal(signal), limit:20000});
      if (!Array.isArray(page.ids) || page.ids.length !== 1 || !identity(page.ids[0])) throw new Error('Missing historical scan boundary.');
      tip = page.ids[0];
    }
    return this.sync({...head, height, tip}, signal, onProgress, true);
  }
  async sync(head, signal, onProgress = () => {}, view = false) {
    const c = this.config;
    if (!this.tree || head.network !== c.network || head.genesis !== c.genesis ||
        !identity(head.tip) || !Number.isSafeInteger(head.height) || head.height < 0 || head.height > 1000000) throw new Error('History head differs from the pinned network.');
    return navigator.locks.request(this.key, {signal}, async () => {
      // Reopen the authenticated frontier under the cross-tab lock.
      const encrypted = await this.storage('private', this.key);
      if (encrypted) {
        const current = this.Tree.restore(c.rules_hex, c.genesis, this.anchor, encrypted);
        this.tree.free(); this.tree = current;
      }
      const accepted = JSON.parse(this.tree.summary());
      // Each locally managed birthday keeps an encrypted, exact boundary. A
      // later account must not force an earlier account to rebuild its prefix.
      const boundary = view ? 'commitment-boundary:' + await hash(new TextEncoder().encode(`${this.key}:${head.height}`)) : null;
      if (boundary) {
        const saved = await this.storage('private', boundary);
        if (saved) {
          const tree = this.Tree.restore(c.rules_hex, c.genesis, this.anchor, saved);
          const state = JSON.parse(tree.summary());
          if (state.height === head.height && state.tip === head.tip) return {...state, downloaded_bytes:0,
            authentication_ciphertext_bytes:0, tree, release:() => tree.free()};
          tree.free();
        }
      }
      let extension = accepted.height === 0;
      if (accepted.tip === head.tip && accepted.height === head.height) {
        if (boundary) await this.storage('private', boundary, this.tree.sealed_cache(this.anchor));
        return {...accepted, downloaded_bytes: 0, authentication_ciphertext_bytes: 0,
          ...(view ? {tree:this.tree, release:() => {}} : {})};
      }
      if (accepted.height && head.height > accepted.height) {
        const page = await this.json(`${this.base}/v1/chain?tip=${head.tip}&from=${accepted.height}&limit=1`, {signal:requestSignal(signal), limit:20000});
        extension = Array.isArray(page.ids) && page.ids.length === 1 && page.ids[0] === accepted.tip;
      }
      const trial = extension ? this.tree.fork() : this.Tree.create(c.rules_hex, c.genesis);
      // An older birthday or another prefix is a temporary view. Never replace
      // a later accepted local frontier with this historical reconstruction.
      const transient = view && !extension;
      const baseline = transient ? this.Tree.create(c.rules_hex, c.genesis) : this.tree;
      let previous = extension ? accepted.height : 0, downloaded = 0, incidental = 0;
      let currentTip = extension ? accepted.tip : c.genesis;
      const checkpoint = async () => {
        if (transient || !extension || previous === JSON.parse(this.tree.summary()).height) return;
        trial.check_head(String(previous), currentTip, this.tree);
        if (boundary && previous === head.height) await this.storage('private', boundary, trial.sealed_cache(this.anchor));
        await this.storage('private', this.key, trial.sealed_cache(this.anchor));
        this.tree.free(); this.tree = trial.fork();
      };
      try {
        while (previous < head.height) {
          signal?.throwIfAborted();
          const page = await this.json(`${this.base}/v1/chain?tip=${head.tip}&from=${previous + 1}&limit=128`, {signal:requestSignal(signal), limit:20000});
          if (!Array.isArray(page.ids) || !page.ids.length || page.ids.length > 128 || page.ids.length > head.height - previous) throw new Error('Incomplete historical commitment index.');
          for (const id of page.ids) {
            signal?.throwIfAborted();
            if (!identity(id)) throw new Error('Invalid historical block identity.');
            let bytes, compact = !this.projections;
            if (!compact) {
              try { ({bytes} = await this.binary(`${this.base}/v1/commitments/${id}`, {signal:requestSignal(signal)})); }
              catch (error) {
                signal?.throwIfAborted();
                if (![400,404,405,501,503].includes(error.status)) throw error;
                this.projections = false; compact = true;
              }
            }
            if (compact) {
              // Reuse public data already downloaded by another account. Do not
              // persist pre-birthday ciphertext fetched only for authentication.
              const cached = await this.storage('compact', id);
              if (cached?.bytes) bytes = new Uint8Array(cached.bytes);
              else { ({bytes} = await this.binary(`${this.base}/v1/compact/${id}`, {signal:requestSignal(signal)})); downloaded += bytes.length; }
            } else downloaded += bytes.length;
            try {
              signal?.throwIfAborted();
              const state = JSON.parse(compact ? trial.append_compact(bytes) : trial.append(bytes));
              if (state.tip !== id || state.height !== previous + 1) throw new Error('Historical record identity or height differs.');
              incidental += state.authentication_ciphertext_bytes;
              previous = state.height; currentTip = state.tip;
              if (previous % 16 === 0) await checkpoint();
              onProgress({height: previous, target_height: head.height, downloaded_bytes: downloaded,
                authentication_ciphertext_bytes: incidental});
            } finally { bytes.fill(0); }
          }
        }
        signal?.throwIfAborted();
        trial.check_head(String(head.height), head.tip, transient ? baseline : this.tree);
        if (boundary) await this.storage('private', boundary, trial.sealed_cache(this.anchor));
        if (transient) return {...JSON.parse(trial.summary()), downloaded_bytes:downloaded,
          authentication_ciphertext_bytes:incidental, tree:trial, release:() => trial.free()};
        // Once persistence begins, finish the in-memory replacement as well.
        await this.storage('private', this.key, trial.sealed_cache(this.anchor));
        this.tree.free(); this.tree = trial;
        return {...JSON.parse(trial.summary()), downloaded_bytes: downloaded,
          authentication_ciphertext_bytes: incidental, ...(view ? {tree:this.tree, release:() => {}} : {})};
      } catch (error) {
        // Cancellation may preserve only a checked extension. It never advances
        // an account balance, its payment journal, or the sending-ready flag.
        try { if (signal?.aborted && error === signal.reason) await checkpoint(); }
        finally { trial.free(); }
        throw error;
      }
      finally { if (transient) baseline.free(); }
    });
  }
  free() { this.tree?.free(); this.tree = this.anchor = null; }
}
