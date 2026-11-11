import {eng2Context,eng2Namespace,eng2Head,sameEng2Context} from './eng2-context.js';
import {eng2Storage} from './eng2-storage.js';
import {fetchLimited,hash,unhex} from './online-storage.js';
import {publicGet,publicJSON} from './public-fetch.js';
const encode = value => new TextEncoder().encode(JSON.stringify(value));
const metadataKeys = 'fee_mode,genesis,height,network,profile,rules,tip,type,version';
const headQuery = head => new URLSearchParams({height:String(head.height),tip:head.tip});
const exactHeight = value => Number.isSafeInteger(value) && value >= 0 && value <= 100000;
const PREFIX_BLOCKS = 8;

// Worker-only, staged receive/balance/history client. Sending remains unavailable
// until anchored witness/proof and admission/inclusion contracts are qualified.
export class Eng2Session {
  constructor(wallet,configuration,io={}) {
    this.wallet = wallet; this.config = eng2Context(configuration);
    this.storage = io.storage || eng2Storage(this.config);
    this.binary = io.binary || fetchLimited;
    this.json = io.json || ((url,options) => publicJSON(this.binary,url,options));
    this.hash = io.hash || hash; this.now = io.now || (() => Date.now()/1000);
    this.locks = io.locks || navigator.locks;
    this.ready = false; this.syncing = false; this.invalidated = false;
    this.metadata = null; this.controller = null;
    this.base = this.config.api + '/api/v2/wallet';
    this.namespace = eng2Namespace(this.config);
  }
  checkBalance(value) {
    if (!sameEng2Context(value,this.config) || !exactHeight(value.height) || typeof value.tip !== 'string' || !/^[0-9a-f]{64}$/.test(value.tip) || value.send_supported !== false || value.full_node_consensus_verified !== false) throw new Error('Engineering-v2 native wallet capability or context differs.');
    return value;
  }
  checkMetadata(value) {
    if (!value || Object.keys(value).sort().join() !== metadataKeys || value.type !== 'eng2-wallet-scan' || !sameEng2Context(value,this.config) || !exactHeight(value.height) || typeof value.tip !== 'string' || !/^[0-9a-f]{64}$/.test(value.tip) || value.height === 0 && value.tip !== this.config.genesis) throw new Error('Engineering-v2 encrypted scan context differs. Preserve the original local data.');
    return value;
  }
  metadataFor(height,tip) {
    const {network,genesis,rules,profile,fee_mode} = this.config;
    return this.checkMetadata({version:2,type:'eng2-wallet-scan',network,genesis,rules,profile,fee_mode,height,tip});
  }
  decrypt(bytes) {
    const plain = this.wallet.open_eng2_local(bytes);
    try { return this.checkMetadata(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plain))); }
    finally { plain.fill(0); }
  }
  async persist(next,candidate) {
    const plain = encode(next);
    try { await this.storage.pair(this.key,this.wallet.protect_eng2_local(plain),this.cacheKey,this.wallet.eng2_cache(candidate)); }
    finally { plain.fill(0); }
  }
  async initialize(onProgress=()=>{}) {
    const info = JSON.parse(this.wallet.public_info());
    if (info.network !== this.config.network) throw new Error('Wallet belongs to another network. No conversion was performed.');
    const controller = new AbortController(); this.controller = controller;
    try {
      this.key = 'scan:' + await this.hash(new TextEncoder().encode(info.full_address));
      controller.signal.throwIfAborted();
      this.cacheKey = 'cache:' + this.key; this.lockKey = this.namespace + ':' + this.key;
      const {bytes} = await publicGet(this.binary,this.base+'/genesis',{limit:262144,signal:controller.signal});
      controller.signal.throwIfAborted();
      this.genesis = bytes;
      const initial = this.checkBalance(JSON.parse(this.wallet.enable_eng2(bytes,this.config.genesis)));
      return await this.locks.request(this.lockKey,{signal:controller.signal},async () => {
        controller.signal.throwIfAborted();
        const saved = await this.storage.read(this.key);
        controller.signal.throwIfAborted();
        const cache = await this.storage.read(this.cacheKey);
        controller.signal.throwIfAborted();
        if (!!saved !== !!cache) throw new Error('Engineering-v2 cache and scan metadata are incomplete. Preserve both local records.');
        if (saved) {
          const metadata = this.decrypt(saved);
          const restored = this.checkBalance(JSON.parse(this.wallet.restore_eng2_cache(bytes,this.config.genesis,cache)));
          if (restored.height !== metadata.height || restored.tip !== metadata.tip) throw new Error('Engineering-v2 private cache and metadata disagree.');
          this.metadata = metadata;
          onProgress({kind:'synchronization',phase:'cache',height:metadata.height,target_height:metadata.height,eta_seconds:0});
        } else {
          const metadata = this.metadataFor(initial.height,initial.tip);
          await this.persist(metadata,false); this.metadata = metadata;
        }
        return this.summary();
      });
    } finally { if (this.controller === controller) this.controller = null; }
  }
  summary() {
    const value = this.checkBalance(JSON.parse(this.wallet.eng2_balance()));
    return {...value,ready:this.ready,stale:!this.ready,committed:true,send_supported:false,received_records:JSON.parse(this.wallet.eng2_history()),payments:[],reserved_count:0};
  }
  async fresh() {
    const bytes = await this.storage.read(this.key);
    if (!bytes || JSON.stringify(this.decrypt(bytes)) !== JSON.stringify(this.metadata)) throw new Error('Another tab changed this engineering-v2 wallet. Lock and reopen it.');
  }
  cancelSync() { this.ready = false; this.controller?.abort(); }
  async sync(onProgress=()=>{}) {
    if (!this.metadata || this.invalidated || this.syncing) throw new Error('Reopen or finish the current engineering-v2 synchronization first.');
    this.ready = false; this.syncing = true;
    const controller = new AbortController(); this.controller = controller;
    let persisted = false;
    try { return await this.locks.request(this.lockKey,{signal:controller.signal},async () => {
      await this.fresh();
      const head = eng2Head(await this.json(this.base+'/head',{limit:20000,signal:controller.signal}),this.config,this.now());
      controller.signal.throwIfAborted();
      if (head.height === this.metadata.height && head.tip === this.metadata.tip) { this.ready = true; return this.summary(); }
      let extension = false, firstPage = null;
      const page = async (from,target=head,limit=Math.min(128,target.height-from+1)) => {
        const query = headQuery(target); query.set('from',String(from)); query.set('limit',String(limit));
        const {bytes} = await publicGet(this.binary,this.base+'/headers?'+query,{limit:65536,signal:controller.signal});
        const value = JSON.parse(this.wallet.eng2_header_page(bytes,String(target.height),target.tip));
        if (value.height !== target.height || value.tip !== target.tip || value.from !== from || !Array.isArray(value.headers) || !value.headers.length || value.headers.length > limit) throw new Error('Engineering-v2 header page does not reach the requested context.');
        return value;
      };
      if (head.height > this.metadata.height) {
        firstPage = await page(this.metadata.height+1);
        extension = firstPage.headers[0].parent === this.metadata.tip;
      }
      this.wallet.begin_eng2_candidate(extension);
      const scanStartHeight = extension ? this.metadata.height : 0;
      let height = scanStartHeight, downloaded = 0, observedHead = head;
      const start = performance.now();
      const adopt = async (height,tip) => {
        controller.signal.throwIfAborted();
        this.wallet.check_eng2_candidate(String(height),tip);
        const current = eng2Head(await this.json(this.base+'/head',{limit:20000,signal:controller.signal}),this.config,this.now());
        if (current.height < observedHead.height || current.height === observedHead.height && current.tip !== observedHead.tip) throw new Error('Engineering-v2 head changed to an incompatible branch. Previous balance was preserved.');
        if (current.height !== head.height || current.tip !== head.tip) {
          if (current.height <= head.height) throw new Error('Engineering-v2 head changed to an incompatible branch. Previous balance was preserved.');
          const boundary = await page(height,current,1);
          if (boundary.headers[0].height !== height || boundary.headers[0].id !== tip) throw new Error('Engineering-v2 head no longer extends the verified prefix. Previous balance was preserved.');
        }
        controller.signal.throwIfAborted();
        const metadata = this.metadataFor(height,tip);
        await this.persist(metadata,true); persisted = true;
        // Finish a durable adoption before observing a cancellation that arrived
        // during storage. Later failures may discard only the next candidate.
        this.wallet.commit_eng2_candidate(String(height),tip);
        this.metadata = metadata; persisted = false; observedHead = current;
        this.ready = height === current.height && tip === current.tip && !controller.signal.aborted;
        return current;
      };
      while (height < head.height) {
        const current = firstPage?.from === height+1 ? firstPage : await page(height+1); firstPage = null;
        for (const header of current.headers) {
          controller.signal.throwIfAborted();
          if (header.height !== height+1 || typeof header.id !== 'string' || !/^[0-9a-f]{64}$/.test(header.id)) throw new Error('Engineering-v2 receipt header order differs.');
          const query = headQuery(head);
          const {bytes} = await publicGet(this.binary,`${this.base}/receipts/${header.height}/${header.id}?${query}`,{limit:8*1024*1024+32768,signal:controller.signal});
          downloaded += bytes.length;
          let applied;
          try { controller.signal.throwIfAborted(); applied = JSON.parse(this.wallet.append_eng2_receipt(unhex(header.bytes_hex),bytes)); }
          finally { bytes.fill(0); }
          if (applied.committed !== false || applied.height !== header.height || applied.tip !== header.id) throw new Error('Engineering-v2 candidate application returned a different header.');
          height = applied.height;
          onProgress({kind:'synchronization',phase:'eng2-receipts',height,target_height:head.height,downloaded_bytes:downloaded,eta_seconds:height ? Math.ceil((performance.now()-start)/1000*(head.height-height)/Math.max(1,height-scanStartHeight)) : null});
          if (extension && height < head.height && height-this.metadata.height >= PREFIX_BLOCKS) {
            const current = await adopt(height,header.id);
            if (controller.signal.aborted) return {...this.summary(),downloaded_bytes:downloaded,catchup_pending:true,target_height:current.height,target_tip:current.tip};
            this.wallet.begin_eng2_candidate(true);
          }
        }
      }
      const current = await adopt(head.height,head.tip);
      const advanced = current.height !== head.height || current.tip !== head.tip;
      // Preserve completed native verification across a moving head. The next
      // owner refresh extends this durable prefix; the new head is still stale.
      return {...this.summary(),downloaded_bytes:downloaded,catchup_pending:advanced,target_height:current.height,target_tip:current.tip};
    }); } catch (error) {
      this.ready = false; this.wallet.abort_eng2_candidate();
      if (persisted) { this.invalidated = true; throw new Error('Engineering-v2 state was saved. Lock and reopen before continuing.'); }
      throw error;
    } finally { this.syncing = false; if (this.controller === controller) this.controller = null; }
  }
  prepare() { throw new Error('Engineering-v2 sending is unavailable until anchored transaction proving is qualified.'); }
  submit() { throw new Error('Engineering-v2 transaction submission is unavailable in this receive/balance profile.'); }
  cancel() { throw new Error('This engineering-v2 profile has no prepared or submitted payments.'); }
}
