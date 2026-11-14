import {eng2Context,eng2Namespace,eng2Head,sameEng2Context} from './eng2-context.js';
import {eng2Storage} from './eng2-storage.js';
import {emptyEng2Rollback,seedEng2Rollback,advanceEng2Rollback,selectEng2Rollback,candidateEng2Rollback,persistEng2Rollback,loadEng2Rollback} from './eng2-rollback.js';
import {fetchLimited,hash,unhex} from './online-storage.js';
import {eng2PublicGet} from './eng2-sources.js';
import {failureContext} from './diagnostics.js';
const encode = value => new TextEncoder().encode(JSON.stringify(value));
const metadataKeys = 'fee_mode,genesis,height,network,profile,rules,tip,type,version';
const headQuery = head => new URLSearchParams({height:String(head.height),tip:head.tip});
const exactHeight = value => Number.isSafeInteger(value) && value >= 0 && value <= 100000;
const PREFIX_BLOCKS = 8;

// A display status never changes native reward maturity or proves finality.
export function eng2Confirmations(height,head) {
  if (!exactHeight(height) || height === 0 || !exactHeight(head)) throw new Error('Engineering-v2 confirmation height rejected.');
  const confirmations = height <= head ? head-height+1 : 0;
  return {confirmations,confirmation_status:confirmations < 24 ? 'pending' : 'confirmed'};
}

// Worker-only, staged receive/balance/history client. Sending remains unavailable
// until anchored witness/proof and admission/inclusion contracts are qualified.
export class Eng2Session {
  constructor(wallet,configuration,io={}) {
    this.wallet = wallet; this.config = eng2Context(configuration);
    this.storage = io.storage || eng2Storage(this.config);
    this.binary = io.binary || fetchLimited;
    this.get = eng2PublicGet((...args)=>this.binary(...args),this.config,io.publicIO);
    this.json = io.json || (async(url,options) => {
      const {bytes}=await this.get(url,options);
      try {return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}
      catch (cause) {throw failureContext(new Error('Malformed engineering service response.',{cause}),'json-decode');}
      finally {bytes.fill(0);}
    });
    this.hash = io.hash || hash; this.now = io.now || (() => Date.now()/1000);
    this.locks = io.locks || navigator.locks;
    this.ready = false; this.syncing = false; this.invalidated = false;
    this.metadata = null; this.rollback = null; this.controller = null;
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
  async persist(next,candidate,window) {
    const plain = encode(next);
    try { await persistEng2Rollback(this.storage,this.key,this.wallet.protect_eng2_local(plain),this.cacheKey,this.wallet.eng2_cache(candidate),window,bytes=>this.wallet.protect_eng2_local(bytes)); }
    finally { plain.fill(0); }
  }
  async initialize(onProgress=()=>{}) {
    let stage='initialize-info';
    const controller = new AbortController(); this.controller = controller;
    try {
      const info = JSON.parse(this.wallet.public_info());
      if (info.network !== this.config.network) throw new Error('Wallet belongs to another network. No conversion was performed.');
      this.key = 'scan:' + await this.hash(new TextEncoder().encode(info.full_address));
      controller.signal.throwIfAborted();
      this.cacheKey = 'cache:' + this.key; this.lockKey = this.namespace + ':' + this.key;
      stage='genesis-fetch';
      const {bytes} = await this.get(this.base+'/genesis',{limit:262144,signal:controller.signal});
      controller.signal.throwIfAborted();
      this.genesis = bytes;
      stage='genesis-enable';
      const initial = this.checkBalance(JSON.parse(this.wallet.enable_eng2(bytes,this.config.genesis)));
      stage='initialize-lock';
      return await this.locks.request(this.lockKey,{signal:controller.signal},async () => {
        controller.signal.throwIfAborted();
        stage='cache-read';
        const saved = await this.storage.read(this.key);
        controller.signal.throwIfAborted();
        const cache = await this.storage.read(this.cacheKey);
        controller.signal.throwIfAborted();
        if (!!saved !== !!cache) throw new Error('Engineering-v2 cache and scan metadata are incomplete. Preserve both local records.');
        if (saved) {
          stage='cache-restore';
          const metadata = this.decrypt(saved);
          const archived = await loadEng2Rollback(this.storage,this.key,this.cacheKey,this.config,metadata,value=>this.wallet.open_eng2_local(value),controller.signal);
          controller.signal.throwIfAborted();
          const restored = this.checkBalance(JSON.parse(this.wallet.restore_eng2_cache(bytes,this.config.genesis,cache)));
          if (restored.height !== metadata.height || restored.tip !== metadata.tip) throw new Error('Engineering-v2 private cache and metadata disagree.');
          this.metadata = metadata;
          this.rollback = archived || seedEng2Rollback(this.config,metadata,JSON.parse(this.wallet.eng2_recent_headers()),metadata.height%PREFIX_BLOCKS===0?cache:null);
          onProgress({kind:'synchronization',phase:'cache',height:metadata.height,target_height:metadata.height,eta_seconds:0});
        } else {
          stage='cache-initialize';
          const metadata = this.metadataFor(initial.height,initial.tip);
          const window = advanceEng2Rollback(emptyEng2Rollback(this.config),[],this.wallet.eng2_cache(false));
          await this.persist(metadata,false,window); this.metadata = metadata; this.rollback = window;
        }
        stage='summary';return this.summary();
      });
    } catch(error) {throw failureContext(error,stage);}
    finally { if (this.controller === controller) this.controller = null; }
  }
  summary() {
    const value = this.checkBalance(JSON.parse(this.wallet.eng2_balance()));
    return {...value,ready:this.ready,stale:!this.ready,committed:true,send_supported:false,received_records:JSON.parse(this.wallet.eng2_history()).map(row=>({...row,...eng2Confirmations(row.height,value.height)})),payments:[],reserved_count:0};
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
    let persisted = false,stage='sync-lock';
    try { return await this.locks.request(this.lockKey,{signal:controller.signal},async () => {
      stage='cache-fresh';await this.fresh();
      stage='head-fetch';const reply=await this.json(this.base+'/head',{limit:20000,signal:controller.signal});
      stage='head-validate';const head = eng2Head(reply,this.config,this.now());
      controller.signal.throwIfAborted();
      let extension = false, firstPage = null;
      const page = async (from,target=head,limit=Math.min(128,target.height-from+1)) => {
        const query = headQuery(target); query.set('from',String(from)); query.set('limit',String(limit));
        stage='headers-fetch';
        const {bytes} = await this.get(this.base+'/headers?'+query,{limit:65536,signal:controller.signal});
        stage='headers-decode';
        const value = JSON.parse(this.wallet.eng2_header_page(bytes,String(target.height),target.tip));
        stage='headers-validate';
        if (value.height !== target.height || value.tip !== target.tip || value.from !== from || !Array.isArray(value.headers) || !value.headers.length || value.headers.length > limit) throw new Error('Engineering-v2 header page does not reach the requested context.');
        return value;
      };
      // Recheck the accepted block under the selected head on every refresh,
      // including an unchanged-height head. A service tip alone is no prefix
      // witness; a mismatch keeps the balance stale until a candidate completes.
      let savedHeadMatches = this.metadata.height === 0;
      if (this.metadata.height > 0 && head.height >= this.metadata.height) {
        const saved = await page(this.metadata.height,head,1);
        if (saved.headers.length !== 1 || saved.headers[0].height !== this.metadata.height) throw new Error('Engineering-v2 saved header position differs.');
        savedHeadMatches = saved.headers[0].id === this.metadata.tip;
        if (head.height === this.metadata.height && head.tip === this.metadata.tip && !savedHeadMatches) throw new Error('Engineering-v2 saved header hash differs from the advertised tip. Previous balance was preserved.');
      }
      controller.signal.throwIfAborted();
      if (head.height === this.metadata.height && head.tip === this.metadata.tip && savedHeadMatches) { this.ready = true; return this.summary(); }
      if (head.height > this.metadata.height) {
        firstPage = await page(this.metadata.height+1);
        extension = savedHeadMatches && firstPage.headers[0].parent === this.metadata.tip;
      }
      let window=this.rollback,scanStartHeight=extension?this.metadata.height:0,cached=false;
      if(!extension && window){
        const from=Math.max(1,this.metadata.height-24),to=Math.min(this.metadata.height,head.height);
        const remote=to>=from?(await page(from,head,to-from+1)).headers:[];
        const plan=selectEng2Rollback(window,{height:head.height,tip:head.tip,headers:remote});
        if(plan.status==='rollback'){
          controller.signal.throwIfAborted();
          stage='candidate-restore';let restored;
          try{restored=JSON.parse(this.wallet.begin_eng2_cached_candidate(this.genesis,this.config.genesis,plan.cache,String(plan.cache_height),plan.cache_tip));}
          finally{plan.cache.fill(0);}
          if(restored.committed!==false||restored.height!==plan.cache_height||restored.tip!==plan.cache_tip)throw new Error('Engineering-v2 cached candidate returned a different prefix.');
          window=candidateEng2Rollback(window,plan);scanStartHeight=plan.cache_height;cached=true;
          onProgress({kind:'synchronization',phase:'eng2-rollback',height:plan.cache_height,fork_height:plan.fork_height,depth:plan.depth,target_height:head.height});
        }else{
          onProgress({kind:'synchronization',phase:'eng2-rescan',height:0,target_height:head.height,reason:plan.reason||'prefix-unavailable'});
        }
      }
      if(!cached){
        stage='candidate-start';this.wallet.begin_eng2_candidate(extension);
        if(!extension)window=advanceEng2Rollback(emptyEng2Rollback(this.config),[],this.wallet.eng2_cache(true));
      }
      let height = scanStartHeight, downloaded = 0, observedHead = head;
      const start = performance.now();
      const adopt = async (height,tip) => {
        controller.signal.throwIfAborted();
        stage='candidate-check';this.wallet.check_eng2_candidate(String(height),tip);
        stage='head-recheck';
        const current = eng2Head(await this.json(this.base+'/head',{limit:20000,signal:controller.signal}),this.config,this.now());
        if (current.height < observedHead.height || current.height === observedHead.height && current.tip !== observedHead.tip) throw new Error('Engineering-v2 head changed to an incompatible branch. Previous balance was preserved.');
        if (current.height !== head.height || current.tip !== head.tip) {
          if (current.height <= head.height) throw new Error('Engineering-v2 head changed to an incompatible branch. Previous balance was preserved.');
          const boundary = await page(height,current,1);
          if (boundary.headers[0].height !== height || boundary.headers[0].id !== tip) throw new Error('Engineering-v2 head no longer extends the verified prefix. Previous balance was preserved.');
        }
        controller.signal.throwIfAborted();
        const metadata = this.metadataFor(height,tip);
        stage='cache-save';await this.persist(metadata,true,window); persisted = true;
        // Finish a durable adoption before observing a cancellation that arrived
        // during storage. Later failures may discard only the next candidate.
        stage='candidate-commit';this.wallet.commit_eng2_candidate(String(height),tip);
        this.metadata = metadata; this.rollback = window; persisted = false; observedHead = current;
        this.ready = height === current.height && tip === current.tip && !controller.signal.aborted;
        return current;
      };
      while (height < head.height) {
        const current = firstPage?.from === height+1 ? firstPage : await page(height+1); firstPage = null;
        for (const header of current.headers) {
          controller.signal.throwIfAborted();
          stage='headers-validate';
          if (header.height !== height+1 || typeof header.id !== 'string' || !/^[0-9a-f]{64}$/.test(header.id)) throw new Error('Engineering-v2 receipt header order differs.');
          const query = headQuery(head);
          stage='receipt-fetch';
          const {bytes} = await this.get(`${this.base}/receipts/${header.height}/${header.id}?${query}`,{limit:8*1024*1024+32768,signal:controller.signal});
          downloaded += bytes.length;
          let applied;
          try { controller.signal.throwIfAborted();stage='receipt-header';const encoded=unhex(header.bytes_hex);stage='receipt-apply';const result=this.wallet.append_eng2_receipt(encoded,bytes);stage='receipt-decode';applied=JSON.parse(result); }
          finally { bytes.fill(0); }
          stage='receipt-check';
          if (applied.committed !== false || applied.height !== header.height || applied.tip !== header.id) throw new Error('Engineering-v2 candidate application returned a different header.');
          height = applied.height;
          stage='rollback-cache';window=advanceEng2Rollback(window,[header],height%PREFIX_BLOCKS===0?this.wallet.eng2_cache(true):null);
          stage='progress';onProgress({kind:'synchronization',phase:'eng2-receipts',height,target_height:head.height,downloaded_bytes:downloaded,eta_seconds:height ? Math.ceil((performance.now()-start)/1000*(head.height-height)/Math.max(1,height-scanStartHeight)) : null});
          if (extension && height < head.height && height-this.metadata.height >= PREFIX_BLOCKS) {
            const current = await adopt(height,header.id);
            if (controller.signal.aborted) return {...this.summary(),downloaded_bytes:downloaded,catchup_pending:true,target_height:current.height,target_tip:current.tip};
            stage='candidate-start';this.wallet.begin_eng2_candidate(true);
          }
        }
      }
      const current = await adopt(head.height,head.tip);
      const advanced = current.height !== head.height || current.tip !== head.tip;
      // Preserve completed native verification across a moving head. The next
      // owner refresh extends this durable prefix; the new head is still stale.
      return {...this.summary(),downloaded_bytes:downloaded,catchup_pending:advanced,target_height:current.height,target_tip:current.tip};
    }); } catch (error) {
      this.ready = false;const failure=failureContext(error,stage);
      try {this.wallet.abort_eng2_candidate();}catch(related){failureContext(failure,'candidate-abort',{related});}
      if (persisted) { this.invalidated = true; throw failureContext(new Error('Engineering-v2 state was saved. Lock and reopen before continuing.',{cause:failure}),'reopen-required'); }
      throw failure;
    } finally { this.syncing = false; if (this.controller === controller) this.controller = null; }
  }
  prepare() { throw new Error('Engineering-v2 sending is unavailable until anchored transaction proving is qualified.'); }
  submit() { throw new Error('Engineering-v2 transaction submission is unavailable in this receive/balance profile.'); }
  cancel() { throw new Error('This engineering-v2 profile has no prepared or submitted payments.'); }
}
