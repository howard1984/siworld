import {eng2Context,eng2Namespace,sameEng2Context} from './eng2-context.js';
import {eng2Storage} from './eng2-storage.js';
import {hash,unhex} from './online-storage.js';

const encode = value => new TextEncoder().encode(JSON.stringify(value));
const hex = bytes => Array.from(bytes,value=>value.toString(16).padStart(2,'0')).join('');
const digest = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const commitment = value => typeof value === 'string' && /^[0-9a-f]{96}$/.test(value);
const phases = new Set(['reserved','finalized','uncertain','accepted','included','cancelled']);
const holdsInputs = phase => !['included','cancelled'].includes(phase);
const atoms = value => typeof value === 'string' && /^(0|[1-9][0-9]{0,38})$/.test(value);
const ABSENT = 'eng2 payment statement absent from authenticated receipt';
const MAX_ROWS = 64, MAX_BYTES = 1_900_000, MAX_PACKET_BYTES = 658000;

// Worker-only transfer/journal contract. Construction does not enable sending.
// The website mutation gate and release qualification remain independent.
// Admission is available only through an explicitly injected adapter.
export class Eng2Payments {
  constructor(session,io={}) {
    this.session=session;this.wallet=session.wallet;this.config=eng2Context(session.config);
    this.storage=io.storage||eng2Storage(this.config);this.hash=io.hash||hash;
    this.locks=io.locks||navigator.locks;this.admit=io.admit||null;
    this.index=null;this.invalidated=false;this.now=io.now||(()=>Math.floor(Date.now()/1000));
  }
  context(type) {
    const {network,genesis,rules,profile,fee_mode}=this.config;
    return {version:2,type,network,genesis,rules,profile,fee_mode};
  }
  check(value,type) {
    if (!value||value.type!==type||!sameEng2Context(value,this.config)) throw new Error('Engineering-v2 payment journal context differs. Preserve the original encrypted data.');
    return value;
  }
  protect(value) {
    const plain=encode(value);
    try { if(plain.length>MAX_BYTES)throw new Error('Engineering-v2 payment journal byte bound exceeded.');return this.wallet.protect_eng2_local(plain); }
    finally {plain.fill(0);}
  }
  open(bytes,type) {
    const plain=this.wallet.open_eng2_local(bytes);
    try {if(plain.length>MAX_BYTES)throw new Error('Engineering-v2 payment journal byte bound exceeded.');return this.check(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plain)),type);}
    finally {plain.fill(0);}
  }
  validateIndex(index) {
    this.check(index,'eng2-payment-index');
    if(!Number.isSafeInteger(index.revision)||index.revision<0||!Array.isArray(index.rows)||index.rows.length>MAX_ROWS)throw new Error('Engineering-v2 payment index bound rejected.');
    const ids=new Set();
    for(const row of index.rows){
      if(!row||!digest(row.statement_id)||ids.has(row.statement_id)||!phases.has(row.phase)||!Array.isArray(row.inputs)||row.inputs.length<1||row.inputs.length>2||!row.inputs.every(commitment)||new Set(row.inputs).size!==row.inputs.length)throw new Error('Engineering-v2 payment reservation rejected.');
      ids.add(row.statement_id);
    }
    return index;
  }
  async initialize() {
    if(!this.session.metadata)throw new Error('Initialize the engineering-v2 receipt session first.');
    const info=JSON.parse(this.wallet.public_info());
    if(info.network!==this.config.network)throw new Error('Engineering-v2 payment wallet network differs.');
    this.key='payments:'+await this.hash(new TextEncoder().encode(info.full_address));
    // Share the receipt-session lock to exclude sync, proving and other tabs.
    this.lockKey=this.session.lockKey||eng2Namespace(this.config)+':'+this.key;
    return this.locks.request(this.lockKey,async()=>{
      const saved=await this.storage.read(this.key);
      this.index=saved?this.validateIndex(this.open(saved,'eng2-payment-index')):{...this.context('eng2-payment-index'),revision:0,rows:[]};
      if(!saved){const bytes=this.protect(this.index);await this.storage.pair(this.key,bytes,this.key,bytes);}
      return this.summary();
    });
  }
  summary() {
    if(!this.index)throw new Error('Initialize the engineering-v2 payment journal first.');
    return {send_supported:false,payments:this.index.rows.map(({statement_id,phase})=>({statement_id,phase})),reserved_count:this.index.rows.filter(row=>holdsInputs(row.phase)).reduce((sum,row)=>sum+row.inputs.length,0)};
  }
  async displaySummary() {
    return this.locks.request(this.lockKey,async()=>{
      await this.fresh();
      let reserved=0n;
      const payments=[];
      for(const entry of this.index.rows){
        const row=await this.load(entry.statement_id);
        if(!atoms(row.amount_atoms)||!atoms(row.fee_atoms)||!atoms(row.input_atoms))throw new Error('Engineering-v2 payment amounts are incomplete. Preserve the encrypted journal.');
        if(holdsInputs(row.phase))reserved+=BigInt(row.input_atoms);
        // Only this display projection may cross the worker boundary. Openings,
        // input commitments, packet bytes and private row extensions stay here.
        payments.push({id:row.statement_id,statement_id:row.statement_id,phase:row.phase,
          amount_atoms:row.amount_atoms,fee_atoms:row.fee_atoms,
          recipient:typeof row.recipient==='string'?row.recipient:'Recipient unavailable',
          created_at:Number.isSafeInteger(row.created_at)&&row.created_at>=0?row.created_at:null,
          confirmed_height:row.phase==='included'?row.inclusion?.height??null:null});
      }
      return {send_supported:false,payments,reserved_atoms:reserved.toString(),reserved_count:this.summary().reserved_count};
    });
  }
  async pendingScan() {
    return this.locks.request(this.lockKey,async()=>{
      await this.fresh();this.ready();await this.reconcileIncluded();
      const pending=[];
      for(const entry of this.index.rows.filter(row=>['uncertain','accepted'].includes(row.phase))){
        const row=await this.load(entry.statement_id);
        if(!Number.isSafeInteger(row.anchor_height)||row.anchor_height<0||row.anchor_height>this.session.metadata.height)throw new Error('Engineering-v2 payment anchor differs from the committed head.');
        pending.push({statement_id:row.statement_id,from:row.anchor_height+1});
      }
      return pending;
    });
  }
  async observeReceipt(height,blockId,receipt) {
    return this.locks.request(this.lockKey,async()=>{
      await this.fresh();this.ready();
      if(!Number.isSafeInteger(height)||height<1||height>this.session.metadata.height||!digest(blockId)||!this.wallet.eng2_payment_inclusion_valid(String(height),blockId))throw new Error('Engineering-v2 payment receipt header is not committed.');
      for(const entry of this.index.rows.filter(row=>['uncertain','accepted'].includes(row.phase))){
        const row=await this.load(entry.statement_id);
        let inclusion;
        try {inclusion=JSON.parse(this.wallet.eng2_payment_receipt(String(height),receipt,row.statement_id));}
        catch(error){if((typeof error==='string'?error:error.message)===ABSENT)continue;throw error;}
        if(inclusion.statement_id!==row.statement_id||inclusion.height!==height||inclusion.block_id!==blockId||inclusion.receipt_authenticated!==true||inclusion.full_node_consensus_verified!==false)throw new Error('Engineering-v2 payment inclusion differs.');
        await this.save({...row,phase:'included',inclusion});
      }
      return this.summary();
    });
  }
  release() {
    // Account changes drop the in-memory owner only. Durable reservations and
    // exact uncertain packets must survive lock, tab close and cold reopen.
    this.invalidated=true;this.index=null;this.admit=null;
  }
  async fresh() {
    if(!this.index||this.invalidated)throw new Error('Reopen the engineering-v2 payment journal before continuing.');
    const bytes=await this.storage.read(this.key);
    if(!bytes||JSON.stringify(this.validateIndex(this.open(bytes,'eng2-payment-index')))!==JSON.stringify(this.index))throw new Error('Another tab changed the engineering-v2 payment journal. Lock and reopen it.');
    await this.session.fresh();
  }
  ready() {
    if(!this.session.ready||this.session.syncing||this.session.invalidated)throw new Error('Finish synchronization to a fresh engineering-v2 head first.');
    const balance=JSON.parse(this.wallet.eng2_balance());
    if(!sameEng2Context(balance,this.config)||balance.height!==this.session.metadata.height||balance.tip!==this.session.metadata.tip)throw new Error('Engineering-v2 verified receipt head differs.');
  }
  async load(id) {
    if(!digest(id))throw new Error('Invalid engineering-v2 payment statement.');
    const entry=this.index.rows.find(row=>row.statement_id===id),bytes=await this.storage.read(this.key+':'+id);
    if(!entry||!bytes)throw new Error('Engineering-v2 payment record is incomplete. Preserve the encrypted journal.');
    const row=this.open(bytes,'eng2-payment');
    if(row.statement_id!==id||row.phase!==entry.phase||JSON.stringify(row.inputs)!==JSON.stringify(entry.inputs))throw new Error('Engineering-v2 payment record and reservations disagree.');
    return row;
  }
  async save(row) {
    const next={...this.index,revision:this.index.revision+1,rows:this.index.rows.filter(value=>value.statement_id!==row.statement_id)};
    next.rows.push({statement_id:row.statement_id,phase:row.phase,inputs:row.inputs});
    this.validateIndex(next);
    await this.storage.pair(this.key,this.protect(next),this.key+':'+row.statement_id,this.protect(row));
    this.index=next;
  }
  async prepare({recipient,resolved='',amount,priority=false}) {
    return this.locks.request(this.lockKey,async()=>{
      await this.fresh();this.ready();await this.reconcileIncluded();
      if(this.index.rows.length>=MAX_ROWS||this.index.rows.some(row=>row.phase==='reserved'))throw new Error('Finish or cancel the existing reserved payment before preparing another.');
      const inputs=this.index.rows.filter(row=>holdsInputs(row.phase)).flatMap(row=>row.inputs);
      const head=this.session.metadata;
      const row=JSON.parse(this.wallet.prepare_eng2_sip(this.config.network,String(head.height),head.tip,recipient,resolved,String(amount),priority,JSON.stringify(inputs)));
      if(!sameEng2Context(row,this.config)||!digest(row.statement_id)||row.phase!=='reserved'||row.anchor_height!==head.height||row.anchor_tip!==head.tip) {
        this.wallet.cancel_eng2_prepared();throw new Error('Engineering-v2 native preparation context differs.');
      }
      if(this.index.rows.some(value=>value.statement_id===row.statement_id)){this.wallet.cancel_eng2_prepared();throw new Error('Engineering-v2 payment statement already exists.');}
      try {await this.save({...row,type:'eng2-payment',recipient,created_at:this.now()});}
      catch(error){this.wallet.cancel_eng2_prepared();throw error;}
      return {statement_id:row.statement_id,phase:'reserved',amount_atoms:row.amount_atoms,fee_atoms:row.fee_atoms,send_supported:false};
    });
  }
  async prove(id) {
    return this.locks.request(this.lockKey,async()=>{
      await this.fresh();this.ready();const row=await this.load(id);
      if(row.phase!=='reserved')throw new Error('Only a durably reserved engineering-v2 payment can be proved.');
      let packet;
      try {
        packet=this.wallet.prove_eng2_sip();
        if(!(packet instanceof Uint8Array)||packet.length>MAX_PACKET_BYTES)throw new Error('Engineering-v2 native payment packet bound rejected.');
        const checked=JSON.parse(this.wallet.check_eng2_payment(this.config.network,packet));
        if(checked.statement_id!==id||checked.proof_verified!==true||checked.anchor_height!==row.anchor_height||checked.anchor_tip!==row.anchor_tip)throw new Error('Engineering-v2 native proof identity differs.');
        await this.save({...row,phase:'finalized',packet_hex:hex(packet)});
        this.wallet.cancel_eng2_prepared();return {statement_id:id,phase:'finalized',packet_bytes:packet.length,send_supported:false};
      } finally {packet?.fill(0);}
    });
  }
  async submit(id) {
    if(typeof this.admit!=='function')throw new Error('Engineering-v2 admission is unavailable. Website sending remains closed.');
    return this.locks.request(this.lockKey,async()=>{
      await this.fresh();this.ready();const row=await this.load(id);
      if(!['finalized','uncertain','accepted'].includes(row.phase)||typeof row.packet_hex!=='string'||row.packet_hex.length>MAX_PACKET_BYTES*2)throw new Error('Engineering-v2 finalized packet is unavailable.');
      const packet=unhex(row.packet_hex);
      try {
        const checked=JSON.parse(this.wallet.check_eng2_payment(this.config.network,packet));
        if(checked.statement_id!==id||checked.proof_verified!==true)throw new Error('Engineering-v2 finalized packet identity differs.');
        // Persist uncertainty before transport. A timeout never frees inputs.
        const uncertain={...row,phase:'uncertain'};await this.save(uncertain);
        const receipt=await this.admit(packet,{...this.context('eng2-admission'),statement_id:id});
        if(!receipt||!sameEng2Context(receipt,this.config)||receipt.statement_id!==id||receipt.status!=='accepted')throw new Error('Engineering-v2 admission is uncertain. Keep the same packet and reserved inputs.');
        await this.save({...uncertain,phase:'accepted'});
        return {statement_id:id,phase:'accepted',included:false,send_supported:false};
      } finally {packet.fill(0);}
    });
  }
  async cancel(id) {
    return this.locks.request(this.lockKey,async()=>{
      await this.fresh();const row=await this.load(id);
      if(!['reserved','finalized'].includes(row.phase))throw new Error('A possibly submitted engineering-v2 payment cannot release its inputs.');
      await this.save({...row,phase:'cancelled',packet_hex:undefined,payment_opening:undefined});
      if(row.phase==='reserved')this.wallet.cancel_eng2_prepared();return this.summary();
    });
  }
  async confirm(id,height,receipt) {
    return this.locks.request(this.lockKey,async()=>{
      await this.fresh();this.ready();const row=await this.load(id);
      if(!['finalized','uncertain','accepted','included'].includes(row.phase))throw new Error('Engineering-v2 payment is not finalized.');
      const inclusion=JSON.parse(this.wallet.eng2_payment_receipt(String(height),receipt,id));
      if(inclusion.statement_id!==id||inclusion.height!==height||!digest(inclusion.block_id)||inclusion.receipt_authenticated!==true)throw new Error('Engineering-v2 payment inclusion differs.');
      await this.save({...row,phase:'included',inclusion});return this.summary();
    });
  }
  async reconcileIncluded() {
    for(const entry of this.index.rows.filter(row=>row.phase==='included')){
      const row=await this.load(entry.statement_id);
      if(!row.inclusion||!this.wallet.eng2_payment_inclusion_valid(String(row.inclusion.height),row.inclusion.block_id))await this.save({...row,phase:'uncertain',inclusion:undefined});
    }
  }
  async reconcile() {
    return this.locks.request(this.lockKey,async()=>{await this.fresh();this.ready();await this.reconcileIncluded();return this.summary();});
  }
}
