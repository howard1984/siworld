import {stored,hash,fetchLimited,readJSON} from './online-storage.js';
const encode=value=>new TextEncoder().encode(JSON.stringify(value));
const idPattern=/^[0-9a-f]{64}$/;
function scanProgress(phase, start, from, height, target) {
  const completed=height-from, elapsed=performance.now()-start;
  return {kind:'synchronization', phase, height, target_height:target,
    eta_seconds:completed>=2?Math.ceil(Math.max(0,target-height)*elapsed/completed/1000):null};
}
// Public address publication is explicit and independent of chain synchronization.
// No wallet object, recovery material or account identifier enters this adapter.
export class AddressDirectory {
  constructor(config, inspect, request=readJSON) { this.config=config;this.inspect=inspect;this.request=request; }
  endpoint() {
    if(this.config.name!=='siworld-eng-1'||!idPattern.test(this.config.network)||this.config.address_directory!==true)throw new Error('Short-address directory is unavailable. Use the full address.');
    const base=new URL(this.config.api);
    if(base.origin!==globalThis.location.origin||base.username||base.password||base.search||base.hash||base.protocol!=='https:'&&!(base.protocol==='http:'&&base.hostname==='localhost'))throw new Error('Address directory must use the pinned same-origin engineering service.');
    return base.href.replace(/\/$/,'')+'/v1/addresses';
  }
  async resolve(text,network,resolved='') {
    if(network!==this.config.network)throw new Error('Receiving address network differs.');
    if(typeof text!=='string'||text.length>2200)throw new Error('Invalid receiving address length.');
    if(!text.startsWith('sivs1')||resolved)return JSON.parse(this.inspect(text,network,resolved));
    if(!/^sivs1[a-z2-7]{66}$/.test(text))throw new Error('Invalid short receiving address.');
    let record;
    try {record=await this.request(this.endpoint()+'/'+text,{limit:4096,credentials:'omit',redirect:'error',referrerPolicy:'no-referrer',cache:'no-store',signal:AbortSignal.timeout(10000)});}
    catch {throw new Error('Short address is not registered or its directory is unavailable. Use the full address.');}
    if(!record||Object.keys(record).sort().join()!=='full_address,network,short_address,version'||record.version!==1||record.network!==network||record.short_address!==text||typeof record.full_address!=='string'||record.full_address.length!==2042)throw new Error('Address directory response rejected.');
    // The local codec authenticates the full address against the short commitment.
    return JSON.parse(this.inspect(text,network,record.full_address));
  }
  async publish(full) {
    const info=JSON.parse(this.inspect(full,this.config.network,''));
    if(info.full_address!==full)throw new Error('Publish a full receiving address only.');
    const record=await this.request(this.endpoint(),{method:'POST',body:JSON.stringify({full_address:full}),headers:{'Content-Type':'application/json'},limit:4096,credentials:'omit',redirect:'error',referrerPolicy:'no-referrer',cache:'no-store',signal:AbortSignal.timeout(10000)});
    if(!record||Object.keys(record).sort().join()!=='full_address,network,short_address,version'||record.version!==1||record.network!==this.config.network||record.short_address!==info.short_address||record.full_address!==full)throw new Error('Address registration response rejected.');
    return this.resolve(info.short_address,this.config.network,record.full_address);
  }
}
export class LightSession {
  constructor(wallet,config) {this.wallet=wallet;this.config=config;this.ready=false;this.syncing=false;this.journal=null;this.key=null;this.times=new Map();}
  async initialize(onProgress=()=>{}) {
    const c=this.config,info=JSON.parse(this.wallet.public_info());
    if(c.name!=='siworld-eng-1'||!c.rules_hex||!idPattern.test(c.genesis)||info.network!==c.network)throw new Error('This build has no pinned siworld-eng-1 light service.');
    const origin=new URL(c.api);if(origin.username||origin.password||origin.search||origin.hash||!(origin.protocol==='https:'||(origin.protocol==='http:'&&origin.hostname==='localhost')))throw new Error('Use the pinned HTTPS engineering service.');
    this.base=origin.href.replace(/\/$/,'');this.key=await hash(new TextEncoder().encode(info.full_address));
    this.wallet.enable_light(c.rules_hex,c.genesis);
    const saved=await stored('private',this.key);
    this.journal=saved?JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(this.wallet.open_local(saved))):{version:1,network:c.network,tip:c.genesis,height:0,payments:[]};
    const j=this.journal;
    if(j.version!==1||j.network!==c.network||!idPattern.test(j.tip)||!Number.isSafeInteger(j.height)||j.height<0||!Array.isArray(j.payments)||j.payments.length>16)throw new Error('Invalid local journal; sending remains paused.');
    if(j.height)await this.replaySaved(onProgress);
    return this.summary();
  }
  async fresh() {const raw=await stored('private',this.key);if(raw){const current=JSON.parse(new TextDecoder().decode(this.wallet.open_local(raw)));if(JSON.stringify(current)!==JSON.stringify(this.journal))throw new Error('Another tab changed this wallet. Lock and reopen before continuing.');}}
  async persist(next=this.journal) {await stored('private',this.key,this.wallet.protect_local(encode(next)));this.journal=next;}
  summary() {
    const balance=JSON.parse(this.wallet.light_balance());
    const pending=this.journal.payments.filter(p=>p.phase!=='confirmed');
    const reserved=pending.reduce((n,p)=>n+BigInt(p.input_atoms||'0'),0n);
    balance.rows=balance.rows.map(row=>{const amount=row.asset==='0'.repeat(64)?reserved:0n;const mature=BigInt(row.available_atoms);return {...row,mature_atoms:row.available_atoms,reserved_atoms:amount.toString(),available_atoms:(mature>amount?mature-amount:0n).toString()};});
    return {...balance,received_records:JSON.parse(this.wallet.light_history()).map(note=>({...note,timestamp:this.times.get(note.block_id)??null})),ready:this.ready,payments:this.journal.payments.map(p=>({id:p.id,phase:p.phase,amount_atoms:p.amount_atoms,fee_atoms:p.fee_atoms,recipient:p.recipient,statement_id:p.statement_id,created_at:p.created_at??null,confirmed_height:p.confirmed_height??null,confirmed_timestamp:p.confirmed_timestamp??null})),reserved_count:pending.reduce((n,p)=>n+p.inputs.length,0)};
  }
  async replaySaved(onProgress=()=>{}) {
    const start=performance.now();
    onProgress(scanProgress('cache',start,0,0,this.journal.height));
    const chain=[];let tip=this.journal.tip;
    for(let height=this.journal.height;height>0;height--){const c=await stored('compact',tip);if(!c||c.height!==height||!idPattern.test(c.parent))throw new Error('Compact cache is incomplete. Restore public history before sending.');chain.push({id:tip,height:c.height,parent:c.parent});tip=c.parent;}
    if(tip!==this.config.genesis)throw new Error('Compact cache has a different genesis.');
    this.wallet.begin_candidate();
    try{for(const c of chain.reverse()){const record=await stored('compact',c.id);if(!record)throw new Error('Compact cache was removed during replay.');const state=JSON.parse(this.wallet.append_compact(record.bytes));if(state.tip!==c.id)throw new Error('Compact cache identity mismatch.');if(state.owned_receipts)this.times.set(c.id,state.block_timestamp);onProgress(scanProgress('cache',start,0,state.height,this.journal.height));}this.wallet.commit_candidate(String(this.journal.height),this.journal.tip);}catch(error){this.wallet.abort_candidate();throw error;}
  }
  cancelSync() { this.syncController?.abort(new DOMException('Balance synchronization paused for a wallet change.', 'AbortError')); }
  async sync(onProgress=()=>{}) {
    if(this.syncing)throw new Error('A compact synchronization is already running.');this.syncing=true;this.ready=false;
    const controller = this.syncController = new AbortController();
    const signal = timeout => AbortSignal.any([controller.signal, AbortSignal.timeout(timeout)]);
    try {return await navigator.locks.request(`siworld-light-${this.key}`,{signal:controller.signal},async()=>{
      await this.fresh();
      controller.signal.throwIfAborted();
      const head=await readJSON(`${this.base}/v1/head`,{signal:signal(15000)});
      if(head.network!==this.config.network||head.genesis!==this.config.genesis||!idPattern.test(head.tip)||!Number.isSafeInteger(head.height)||head.height<0||head.height>1000000)throw new Error('Engineering head does not match the pinned network.');
      if(head.tip===this.journal.tip&&head.height===this.journal.height){this.ready=true;return this.summary();}
      let extension=false;
      if(this.journal.height>0&&head.height>this.journal.height){const page=await readJSON(`${this.base}/v1/chain?tip=${head.tip}&from=${this.journal.height}&limit=1`,{signal:signal(15000)});extension=Array.isArray(page.ids)&&page.ids.length===1&&page.ids[0]===this.journal.tip;}
      if(extension)this.wallet.begin_extension();else this.wallet.begin_candidate();
      let parent=extension?this.journal.tip:this.config.genesis;let previous=extension?this.journal.height:0;let downloaded=0;
      const start=performance.now(), fromHeight=previous;
      onProgress(scanProgress('scan',start,fromHeight,previous,head.height));
      const needed=new Set(this.journal.payments.map(p=>p.statement_id));const included=new Map();
      for(let from=previous+1;from<=head.height;) {
        const page=await readJSON(`${this.base}/v1/chain?tip=${head.tip}&from=${from}&limit=128`,{signal:signal(15000)});
        if(!Array.isArray(page.ids)||page.ids.length===0||page.ids.length>128||page.ids.length>head.height-from+1)throw new Error('Incomplete compact chain index.');
        for(const id of page.ids){if(!idPattern.test(id))throw new Error('Invalid compact chain identity.');let cached=await stored('compact',id);let bytes=cached?.bytes;
          if(!bytes){const data=await fetchLimited(`${this.base}/v1/compact/${id}`,{signal:signal(30000)});bytes=data.bytes;downloaded+=bytes.length;}
          controller.signal.throwIfAborted();
          const state=JSON.parse(this.wallet.append_compact(bytes));
          if(state.tip!==id||state.height!==previous+1)throw new Error('Compact block identity or height differs.');
          for(const statement of state.observed_statements||[])if(needed.has(statement))included.set(statement,{height:state.height,timestamp:state.block_timestamp});
          if(state.owned_receipts)this.times.set(id,state.block_timestamp);
          if(!cached)await stored('compact',id,{id,parent,height:state.height,bytes});parent=id;previous=state.height;
          onProgress(scanProgress('scan',start,fromHeight,previous,head.height));
        }from+=page.ids.length;
      }
      controller.signal.throwIfAborted();
      this.wallet.check_candidate(String(head.height),head.tip);
      const payments=this.journal.payments.map(p=>{const found=included.get(p.statement_id);const orphaned=p.phase==='confirmed'&&!extension&&!found;return {...p,phase:found?'confirmed':orphaned?(p.ever_submitted?'unknown':'finalized'):p.phase,confirmed_height:found?.height??(orphaned?null:p.confirmed_height??null),confirmed_timestamp:found?.timestamp??(orphaned?null:p.confirmed_timestamp??null)};});
      // Persist before replacing the accepted in-memory state. Cancellation
      // after this point must finish both steps so disk and memory agree.
      await this.persist({...this.journal,height:head.height,tip:head.tip,payments});
      this.wallet.commit_candidate(String(head.height),head.tip);this.ready=true;return {...this.summary(),downloaded_bytes:downloaded};
    });}catch(error){this.wallet.abort_candidate();throw error;}finally{this.syncing=false;this.syncController=null;}
  }
  async prepare(recipient,resolved,amount,priority,onProgress=()=>{}) {
    if(!this.ready||this.syncing)throw new Error('Finish current compact synchronization before sending.');
    return navigator.locks.request(`siworld-light-${this.key}`,async()=>{
      const persisted=await stored('private',this.key);if(persisted){const j=JSON.parse(new TextDecoder().decode(this.wallet.open_local(persisted)));if(JSON.stringify(j)!==JSON.stringify(this.journal))throw new Error('Another tab changed this wallet. Lock and reopen before sending.');}
      if(this.journal.payments.length>=16)throw new Error('The bounded payment journal is full. Export and resolve pending payments.');
      const reserved=this.journal.payments.filter(p=>p.phase!=='confirmed').flatMap(p=>p.inputs);
      onProgress('preparing');
      const prepared=JSON.parse(this.wallet.prepare_sip(recipient,resolved,amount,priority,JSON.stringify(reserved)));
      const payment={...prepared,id:crypto.randomUUID(),recipient,ever_submitted:false,created_at:Math.floor(Date.now()/1000)};
      onProgress('reserving');
      try{await this.persist({...this.journal,payments:[...this.journal.payments,payment]});}catch(error){this.wallet.cancel_prepared();throw error;}
      // Proving never begins until input reservations and private opening are durably encrypted.
      onProgress('proving');
      const start=performance.now();const packet=this.wallet.prove_sip();const proving_ms=performance.now()-start;
      onProgress('saving');
      await stored('private',`${this.key}:${payment.id}`,this.wallet.protect_local(packet));packet.fill(0);
      await this.persist({...this.journal,payments:this.journal.payments.map(p=>p.id===payment.id?{...p,phase:'finalized'}:p)});
      this.wallet.cancel_prepared();return {...this.summary(),prepared_id:payment.id,proving_ms};
    });
  }
  async submit(id) {
    if(!this.ready)throw new Error('Synchronize before submitting a finalized payment.');
    return navigator.locks.request(`siworld-light-${this.key}`,async()=>{
      await this.fresh();
      const payment=this.journal.payments.find(p=>p.id===id);
      if(!payment||!['finalized','unknown','pending'].includes(payment.phase))throw new Error('Select a finalized or unknown payment.');
      const encrypted=await stored('private',`${this.key}:${id}`);if(!encrypted)throw new Error('Finalized packet is missing. Do not create a replacement payment.');
      const packet=this.wallet.open_local(encrypted);
      // Mark uncertain before the first byte can leave this worker. Retries use exactly this packet.
      await this.persist({...this.journal,payments:this.journal.payments.map(p=>p.id===id?{...p,phase:'unknown',ever_submitted:true}:p)});
      try {
        const ack=await readJSON(`${this.base}/v1/transactions`,{method:'POST',body:packet,headers:{'Content-Type':'application/octet-stream'},signal:AbortSignal.timeout(30000)});
        if(ack.status!=='pending'||ack.statement_id!==payment.statement_id)throw new Error('Admission acknowledgment is uncertain. Retry only the same finalized packet.');
        await this.persist({...this.journal,payments:this.journal.payments.map(p=>p.id===id?{...p,phase:'pending'}:p)});
      }finally{packet.fill(0);}return this.summary();
    });
  }
  async cancel(id) {return navigator.locks.request(`siworld-light-${this.key}`,async()=>{
    await this.fresh();
    const p=this.journal.payments.find(p=>p.id===id);
    if(!p||p.ever_submitted||!['prepared','finalized'].includes(p.phase))throw new Error('An uncertain or submitted payment cannot release inputs.');
    await this.persist({...this.journal,payments:this.journal.payments.filter(p=>p.id!==id)});this.wallet.cancel_prepared();return this.summary();
  });}
}
