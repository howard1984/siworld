import {stored,hash,fetchLimited,readJSON} from './online-storage.js';
const encode=value=>new TextEncoder().encode(JSON.stringify(value));
const idPattern=/^[0-9a-f]{64}$/;
export class LightSession {
  constructor(wallet,config) {this.wallet=wallet;this.config=config;this.ready=false;this.syncing=false;this.journal=null;this.key=null;}
  async initialize() {
    const c=this.config,info=JSON.parse(this.wallet.public_info());
    if(c.name!=='siworld-eng-1'||!c.rules_hex||!idPattern.test(c.genesis)||info.network!==c.network)throw new Error('This build has no pinned siworld-eng-1 light service.');
    const origin=new URL(c.api);if(origin.username||origin.password||origin.search||origin.hash||!(origin.protocol==='https:'||(origin.protocol==='http:'&&origin.hostname==='localhost')))throw new Error('Use the pinned HTTPS engineering service.');
    this.base=origin.href.replace(/\/$/,'');this.key=await hash(new TextEncoder().encode(info.full_address));
    this.wallet.enable_light(c.rules_hex,c.genesis);
    const saved=await stored('private',this.key);
    this.journal=saved?JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(this.wallet.open_local(saved))):{version:1,network:c.network,tip:c.genesis,height:0,payments:[]};
    const j=this.journal;
    if(j.version!==1||j.network!==c.network||!idPattern.test(j.tip)||!Number.isSafeInteger(j.height)||j.height<0||!Array.isArray(j.payments)||j.payments.length>16)throw new Error('Invalid local journal; sending remains paused.');
    if(j.height)await this.replaySaved();
    return this.summary();
  }
  async fresh() {const raw=await stored('private',this.key);if(raw){const current=JSON.parse(new TextDecoder().decode(this.wallet.open_local(raw)));if(JSON.stringify(current)!==JSON.stringify(this.journal))throw new Error('Another tab changed this wallet. Lock and reopen before continuing.');}}
  async persist(next=this.journal) {await stored('private',this.key,this.wallet.protect_local(encode(next)));this.journal=next;}
  summary() {
    const balance=JSON.parse(this.wallet.light_balance());
    const pending=this.journal.payments.filter(p=>p.phase!=='confirmed');
    const reserved=pending.reduce((n,p)=>n+BigInt(p.input_atoms||'0'),0n);
    balance.rows=balance.rows.map(row=>{const amount=row.asset==='0'.repeat(64)?reserved:0n;const mature=BigInt(row.available_atoms);return {...row,mature_atoms:row.available_atoms,reserved_atoms:amount.toString(),available_atoms:(mature>amount?mature-amount:0n).toString()};});
    return {...balance,ready:this.ready,payments:this.journal.payments.map(p=>({id:p.id,phase:p.phase,amount_atoms:p.amount_atoms,fee_atoms:p.fee_atoms,recipient:p.recipient})),reserved_count:pending.reduce((n,p)=>n+p.inputs.length,0)};
  }
  async replaySaved() {
    const chain=[];let tip=this.journal.tip;
    for(let height=this.journal.height;height>0;height--){const c=await stored('compact',tip);if(!c||c.height!==height||!idPattern.test(c.parent))throw new Error('Compact cache is incomplete. Restore public history before sending.');chain.push({id:tip,height:c.height,parent:c.parent});tip=c.parent;}
    if(tip!==this.config.genesis)throw new Error('Compact cache has a different genesis.');
    this.wallet.begin_candidate();
    try{for(const c of chain.reverse()){const record=await stored('compact',c.id);if(!record)throw new Error('Compact cache was removed during replay.');const state=JSON.parse(this.wallet.append_compact(record.bytes));if(state.tip!==c.id)throw new Error('Compact cache identity mismatch.');}this.wallet.commit_candidate(String(this.journal.height),this.journal.tip);}catch(error){this.wallet.abort_candidate();throw error;}
  }
  async sync() {
    if(this.syncing)throw new Error('A compact synchronization is already running.');this.syncing=true;this.ready=false;
    try {return await navigator.locks.request(`siworld-light-${this.key}`,async()=>{
      await this.fresh();
      const head=await readJSON(`${this.base}/v1/head`,{signal:AbortSignal.timeout(15000)});
      if(head.network!==this.config.network||head.genesis!==this.config.genesis||!idPattern.test(head.tip)||!Number.isSafeInteger(head.height)||head.height<0||head.height>1000000)throw new Error('Engineering head does not match the pinned network.');
      if(head.tip===this.journal.tip&&head.height===this.journal.height){this.ready=true;return this.summary();}
      let extension=false;
      if(this.journal.height>0&&head.height>this.journal.height){const page=await readJSON(`${this.base}/v1/chain?tip=${head.tip}&from=${this.journal.height}&limit=1`,{signal:AbortSignal.timeout(15000)});extension=Array.isArray(page.ids)&&page.ids.length===1&&page.ids[0]===this.journal.tip;}
      if(extension)this.wallet.begin_extension();else this.wallet.begin_candidate();
      let parent=extension?this.journal.tip:this.config.genesis;let previous=extension?this.journal.height:0;let downloaded=0;
      const needed=new Set(this.journal.payments.map(p=>p.statement_id));const included=new Set();
      for(let from=previous+1;from<=head.height;) {
        const page=await readJSON(`${this.base}/v1/chain?tip=${head.tip}&from=${from}&limit=128`,{signal:AbortSignal.timeout(15000)});
        if(!Array.isArray(page.ids)||page.ids.length===0||page.ids.length>128||page.ids.length>head.height-from+1)throw new Error('Incomplete compact chain index.');
        for(const id of page.ids){if(!idPattern.test(id))throw new Error('Invalid compact chain identity.');let cached=await stored('compact',id);let bytes=cached?.bytes;
          if(!bytes){const data=await fetchLimited(`${this.base}/v1/compact/${id}`,{signal:AbortSignal.timeout(30000)});bytes=data.bytes;downloaded+=bytes.length;}
          const state=JSON.parse(this.wallet.append_compact(bytes));
          if(state.tip!==id||state.height!==previous+1)throw new Error('Compact block identity or height differs.');
          for(const statement of state.observed_statements||[])if(needed.has(statement))included.add(statement);
          if(!cached)await stored('compact',id,{id,parent,height:state.height,bytes});parent=id;previous=state.height;
        }from+=page.ids.length;
      }
      this.wallet.check_candidate(String(head.height),head.tip);
      const payments=this.journal.payments.map(p=>({...p,phase:included.has(p.statement_id)?'confirmed':p.phase==='confirmed'&&!extension?(p.ever_submitted?'unknown':'finalized'):p.phase}));
      // Persist before replacing the accepted in-memory state. An interrupted candidate is discarded.
      await this.persist({...this.journal,height:head.height,tip:head.tip,payments});
      this.wallet.commit_candidate(String(head.height),head.tip);this.ready=true;return {...this.summary(),downloaded_bytes:downloaded};
    });}catch(error){this.wallet.abort_candidate();throw error;}finally{this.syncing=false;}
  }
  async prepare(recipient,resolved,amount,priority,onProgress=()=>{}) {
    if(!this.ready||this.syncing)throw new Error('Finish current compact synchronization before sending.');
    return navigator.locks.request(`siworld-light-${this.key}`,async()=>{
      const persisted=await stored('private',this.key);if(persisted){const j=JSON.parse(new TextDecoder().decode(this.wallet.open_local(persisted)));if(JSON.stringify(j)!==JSON.stringify(this.journal))throw new Error('Another tab changed this wallet. Lock and reopen before sending.');}
      if(this.journal.payments.length>=16)throw new Error('The bounded payment journal is full. Export and resolve pending payments.');
      const reserved=this.journal.payments.filter(p=>p.phase!=='confirmed').flatMap(p=>p.inputs);
      onProgress('preparing');
      const prepared=JSON.parse(this.wallet.prepare_sip(recipient,resolved,amount,priority,JSON.stringify(reserved)));
      const payment={...prepared,id:crypto.randomUUID(),recipient,ever_submitted:false};
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
