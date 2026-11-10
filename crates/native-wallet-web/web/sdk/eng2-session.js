import {eng2Context,eng2Namespace,eng2Head,sameEng2Context} from './eng2-context.js';
import {eng2Storage} from './eng2-storage.js';
import {fetchLimited,readJSON,hash,unhex} from './online-storage.js';
const encode = value => new TextEncoder().encode(JSON.stringify(value));
const metadataKeys = 'fee_mode,genesis,height,network,profile,rules,tip,type,version';
const headQuery = head => new URLSearchParams({height:String(head.height),tip:head.tip});
const exactHeight = value => Number.isSafeInteger(value) && value >= 0 && value <= 100000;

// Worker-only, staged receive/balance/history client. Sending remains unavailable
// until anchored witness/proof and admission/inclusion contracts are qualified.
export class Eng2Session {
  constructor(wallet,configuration,io={}) {
    this.wallet = wallet; this.config = eng2Context(configuration);
    this.storage = io.storage || eng2Storage(this.config);
    this.binary = io.binary || fetchLimited; this.json = io.json || readJSON;
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
    this.key = 'scan:' + await this.hash(new TextEncoder().encode(info.full_address));
    this.cacheKey = 'cache:' + this.key; this.lockKey = this.namespace + ':' + this.key;
    const {bytes} = await this.binary(this.base+'/genesis',{limit:262144,signal:AbortSignal.timeout(30000)});
    this.genesis = bytes;
    const initial = this.checkBalance(JSON.parse(this.wallet.enable_eng2(bytes,this.config.genesis)));
    return this.locks.request(this.lockKey,async () => {
      const saved = await this.storage.read(this.key), cache = await this.storage.read(this.cacheKey);
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
    const signal = () => AbortSignal.any([controller.signal,AbortSignal.timeout(30000)]);
    let persisted = false;
    try { return await this.locks.request(this.lockKey,{signal:controller.signal},async () => {
      await this.fresh();
      const head = eng2Head(await this.json(this.base+'/head',{limit:20000,signal:signal()}),this.config,this.now());
      controller.signal.throwIfAborted();
      if (head.height === this.metadata.height && head.tip === this.metadata.tip) { this.ready = true; return this.summary(); }
      let extension = false, firstPage = null;
      const page = async from => {
        const query = headQuery(head); query.set('from',String(from)); query.set('limit',String(Math.min(128,head.height-from+1)));
        const {bytes} = await this.binary(this.base+'/headers?'+query,{limit:65536,signal:signal()});
        const value = JSON.parse(this.wallet.eng2_header_page(bytes,String(head.height),head.tip));
        if (value.height !== head.height || value.tip !== head.tip || value.from !== from || !Array.isArray(value.headers) || !value.headers.length || value.headers.length > Math.min(128,head.height-from+1)) throw new Error('Engineering-v2 header page does not reach the requested context.');
        return value;
      };
      if (head.height > this.metadata.height) {
        firstPage = await page(this.metadata.height+1);
        extension = firstPage.headers[0].parent === this.metadata.tip;
      }
      this.wallet.begin_eng2_candidate(extension);
      let height = extension ? this.metadata.height : 0, downloaded = 0;
      const start = performance.now();
      while (height < head.height) {
        const current = firstPage?.from === height+1 ? firstPage : await page(height+1); firstPage = null;
        for (const header of current.headers) {
          controller.signal.throwIfAborted();
          if (header.height !== height+1 || typeof header.id !== 'string' || !/^[0-9a-f]{64}$/.test(header.id)) throw new Error('Engineering-v2 receipt header order differs.');
          const query = headQuery(head);
          const {bytes} = await this.binary(`${this.base}/receipts/${header.height}/${header.id}?${query}`,{limit:8*1024*1024+32768,signal:signal()});
          downloaded += bytes.length;
          let applied;
          try { controller.signal.throwIfAborted(); applied = JSON.parse(this.wallet.append_eng2_receipt(unhex(header.bytes_hex),bytes)); }
          finally { bytes.fill(0); }
          if (applied.committed !== false || applied.height !== header.height || applied.tip !== header.id) throw new Error('Engineering-v2 candidate application returned a different header.');
          height = applied.height;
          onProgress({kind:'synchronization',phase:'eng2-receipts',height,target_height:head.height,downloaded_bytes:downloaded,eta_seconds:height ? Math.ceil((performance.now()-start)/1000*(head.height-height)/Math.max(1,height-(extension?this.metadata.height:0))) : null});
        }
      }
      this.wallet.check_eng2_candidate(String(head.height),head.tip);
      const current = eng2Head(await this.json(this.base+'/head',{limit:20000,signal:signal()}),this.config,this.now());
      if (current.height !== head.height || current.tip !== head.tip) throw new Error('Engineering-v2 head changed during scanning. Previous balance was preserved.');
      controller.signal.throwIfAborted();
      const metadata = this.metadataFor(head.height,head.tip);
      await this.persist(metadata,true); persisted = true;
      // Once durable adoption begins, finish the synchronous native commit even
      // if a wallet-selection cancellation arrives during the storage write.
      this.wallet.commit_eng2_candidate(String(head.height),head.tip);
      this.metadata = metadata; this.ready = true;
      return {...this.summary(),downloaded_bytes:downloaded};
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
