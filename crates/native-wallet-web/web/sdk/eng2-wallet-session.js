import {Eng2Session} from './eng2-session.js';
import {Eng2Payments} from './eng2-payments.js';
import {eng2Admission} from './eng2-admission.js';
import {publicGet} from './public-fetch.js';
import {eng2EntryAcceptance,eng2RebroadcastAllowed} from './runtime-profile.js';

const SIP='0'.repeat(64), MAX_RECEIPTS=32;
const digest=value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);

// The actual worker owner composes receive and payment contracts. Its entry
// qualification remains closed independently of the underlying proof methods.
export class Eng2WalletSession {
  constructor(wallet,configuration,io={}) {
    this.session=io.session||new Eng2Session(wallet,configuration,io);
    this.wallet=wallet;this.config=this.session.config;
    this.payments=io.payments||new Eng2Payments(this.session,{...io,admit:io.admit||eng2Admission(this.config,io)});
    this.clock=io.clock||(()=>performance.now());this.cursor=null;this.controller=null;this.released=false;
    this.rebroadcastProfile=Object.freeze({...configuration});this.refreshing=false;this.epoch=0;
  }
  assertOwner() {if(this.released)throw new Error('Reopen the engineering-v2 wallet owner.');}
  async initialize(progress=()=>{}) {
    this.assertOwner();await this.session.initialize(progress);await this.payments.initialize();return this.summary();
  }
  async summary(extra={}) {
    this.assertOwner();
    const journal=await this.payments.displaySummary(),value=this.session.summary();
    const rows=value.rows.map(row=>{
      if(row.asset!==SIP)return row;
      const mature=BigInt(row.available_atoms),reserved=BigInt(journal.reserved_atoms);
      return {...row,mature_atoms:mature.toString(),reserved_atoms:reserved.toString(),available_atoms:(mature>reserved?mature-reserved:0n).toString()};
    });
    return {...value,...journal,...extra,rows,send_supported:false,full_node_consensus_verified:false,entry_acceptance:eng2EntryAcceptance()};
  }
  cancelSync() {this.epoch++;this.session.cancelSync();this.controller?.abort();}
  release() {this.cancelSync();this.payments.release();this.cursor=null;this.released=true;}
  async sync(progress=()=>{}) {
    this.assertOwner();if(this.refreshing)throw new Error('Finish the current engineering-v2 wallet refresh first.');
    this.refreshing=true;const epoch=this.epoch;
    try {
      const result=await this.session.sync(progress);
      if(this.session.ready){
        const reconciled=await this.reconcilePayments(progress);
        const allowed=statement=>!this.released&&this.epoch===epoch&&this.session.ready&&!this.session.syncing&&!this.session.invalidated
          &&reconciled.complete&&this.session.metadata.height===reconciled.head.height&&this.session.metadata.tip===reconciled.head.tip
          &&(statement===undefined||reconciled.statements.includes(statement))&&eng2RebroadcastAllowed(this.rebroadcastProfile);
        if(allowed())await this.payments.rebroadcastPending(allowed);
      }
      return await this.summary({downloaded_bytes:result.downloaded_bytes,catchup_pending:result.catchup_pending,target_height:result.target_height,target_tip:result.target_tip});
    }catch(error){this.session.ready=false;throw error;}
    finally{this.refreshing=false;}
  }
  async prepare(recipient,resolved,amount,priority,progress=()=>{}) {
    this.assertOwner();progress('preparing');
    const prepared=await this.payments.prepare({recipient,resolved,amount,priority});
    progress('proving');const start=this.clock();await this.payments.prove(prepared.statement_id);
    const proving_ms=this.clock()-start;progress('saving');
    return this.summary({prepared_id:prepared.statement_id,proving_ms});
  }
  async submit(id) {this.assertOwner();await this.payments.submit(id);return this.summary();}
  async cancel(id) {this.assertOwner();await this.payments.cancel(id);return this.summary();}
  async reconcilePayments(progress=()=>{}) {
    const pending=await this.payments.pendingScan(),head={...this.session.metadata};
    if(!pending.length){this.cursor=null;return {complete:true,head,statements:[]};}
    const statements=pending.map(row=>row.statement_id),key=[...statements].sort().join();
    const first=Math.min(...pending.map(row=>row.from));
    if(!this.cursor||this.cursor.key!==key||this.cursor.height>head.height||this.cursor.height>0&&!this.wallet.eng2_payment_inclusion_valid(String(this.cursor.height),this.cursor.id))this.cursor={key,next:first,height:0,id:null};
    if(this.cursor.next>head.height)return {complete:true,head,statements};
    const controller=new AbortController();this.controller=controller;
    const get=(url,options)=>this.session.get?this.session.get(url,options):publicGet(this.session.binary,url,options);
    try {
      const from=this.cursor.next,limit=Math.min(MAX_RECEIPTS,head.height-from+1);
      const query=new URLSearchParams({height:String(head.height),tip:head.tip,from:String(from),limit:String(limit)});
      const response=await get(this.session.base+'/headers?'+query,{limit:65536,signal:controller.signal});
      let page;
      try {page=JSON.parse(this.wallet.eng2_header_page(response.bytes,String(head.height),head.tip));}
      finally {response.bytes.fill(0);}
      if(page.height!==head.height||page.tip!==head.tip||page.from!==from||!Array.isArray(page.headers)||page.headers.length!==limit)throw new Error('Engineering-v2 payment header page differs from the committed context.');
      for(let i=0;i<page.headers.length;i++){
        controller.signal.throwIfAborted();
        const header=page.headers[i];
        if(header.height!==from+i||!digest(header.id)||!this.wallet.eng2_payment_inclusion_valid(String(header.height),header.id))throw new Error('Engineering-v2 payment receipt branch differs from the committed headers.');
        const pin=new URLSearchParams({height:String(head.height),tip:head.tip});
        const {bytes}=await get(`${this.session.base}/receipts/${header.height}/${header.id}?${pin}`,{limit:8*1024*1024+32768,signal:controller.signal});
        try {controller.signal.throwIfAborted();await this.payments.observeReceipt(header.height,header.id,bytes);}
        finally {bytes.fill(0);}
        this.cursor={key,next:header.height+1,height:header.height,id:header.id};
        progress({kind:'synchronization',phase:'eng2-payment-receipts',height:header.height,target_height:head.height});
      }
      return {complete:this.cursor.next>head.height,head,statements};
    } finally {if(this.controller===controller)this.controller=null;}
  }
}
