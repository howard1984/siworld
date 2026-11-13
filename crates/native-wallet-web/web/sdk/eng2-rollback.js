import {eng2Context,sameEng2Context} from './eng2-context.js';

export const ENG2_ROLLBACK_DEPTH = 24;
export const ENG2_ROLLBACK_CACHE_BYTES = 64*1024*1024;
const STRIDE=8, HEADERS=32, SLOTS=4, INDEX_BYTES=16384, ENVELOPE=48;
const hex=value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
const height=value=>Number.isSafeInteger(value)&&value>=0&&value<=100000;
const encode=value=>new TextEncoder().encode(JSON.stringify(value));
const binding=config=>Object.fromEntries(['version','network','genesis','rules','profile','fee_mode'].map(key=>[key,config[key]]));
const sealed=(bytes,magic,limit)=>bytes instanceof Uint8Array&&bytes.length>=ENVELOPE&&bytes.length<=limit+ENVELOPE&&magic.split('').every((char,i)=>bytes[i]===char.charCodeAt(0));
const fail=()=>{throw new Error('Engineering-v2 rollback records differ. Preserve the accepted scan and private cache.');};
function header(value,config) {
  if(!value||!height(value.height)||!hex(value.id)||!(value.height===0?value.id===config.genesis&&value.parent===null:hex(value.parent)))fail();
  return {height:value.height,id:value.id,parent:value.parent};
}
function chain(rows,config) {
  if(!Array.isArray(rows)||!rows.length||rows.length>128)fail();
  const result=rows.map(row=>header(row,config));
  if(result[0].height===1&&result[0].parent!==config.genesis)fail();
  for(let i=1;i<result.length;i++)if(result[i].height!==result[i-1].height+1||result[i].parent!==result[i-1].id)fail();
  return result;
}
function validate(window) {
  if(!window||!sameEng2Context(window,window.context)||window.type!=='eng2-wallet-rollback'||window.schema!==1||!height(window.height)||!hex(window.tip)||typeof window.capacity_limited!=='boolean')fail();
  const config=eng2Context(window.context),rows=chain(window.headers,config);
  if(rows.length>HEADERS||rows.at(-1).height!==window.height||rows.at(-1).id!==window.tip||!Array.isArray(window.checkpoints)||window.checkpoints.length>SLOTS)fail();
  let bytes=0,prior=-1;
  for(const point of window.checkpoints){
    if(!height(point.height)||point.height%STRIDE!==0||point.height<=prior||!hex(point.tip)||!sealed(point.bytes,'SWE2SC01',ENG2_ROLLBACK_CACHE_BYTES)||!rows.some(row=>row.height===point.height&&row.id===point.tip))fail();
    bytes+=point.bytes.length;prior=point.height;
  }
  if(bytes>ENG2_ROLLBACK_CACHE_BYTES)fail();
  return config;
}

// Worker-private bookkeeping only. Headers must come from a completed native
// scan. Opaque cache ciphertext is opened and checked again by the native
// candidate adapter before use; this module does not validate proof or work.
export function emptyEng2Rollback(configuration) {
  const context=eng2Context(configuration);
  return {...binding(context),type:'eng2-wallet-rollback',schema:1,context,height:0,tip:context.genesis,
    headers:[{height:0,id:context.genesis,parent:null}],checkpoints:[],capacity_limited:false};
}
export function seedEng2Rollback(configuration,accepted,headers,cache=null) {
  const window={...emptyEng2Rollback(configuration),height:accepted.height,tip:accepted.tip,headers};
  validate(window);
  return advanceEng2Rollback(window,[],cache);
}
export function candidateEng2Rollback(window,plan) {
  const prefix=rewindEng2Rollback(window,plan);
  const next={...prefix,height:plan.cache_height,tip:plan.cache_tip,
    headers:prefix.headers.filter(row=>row.height<=plan.cache_height),
    checkpoints:prefix.checkpoints.filter(point=>point.height<=plan.cache_height)};
  validate(next);return next;
}
export function advanceEng2Rollback(window,rows,cache=null,{budget=ENG2_ROLLBACK_CACHE_BYTES}={}) {
  const config=validate(window);
  if(!Number.isSafeInteger(budget)||budget<0||budget>ENG2_ROLLBACK_CACHE_BYTES)fail();
  const added=rows.length?chain(rows,config):[],last=added.at(-1)||window.headers.at(-1);
  if(added.length&&(added[0].height!==window.height+1||added[0].parent!==window.tip))fail();
  if(cache!==null&&(!sealed(cache,'SWE2SC01',ENG2_ROLLBACK_CACHE_BYTES)||last.height%STRIDE!==0))fail();
  let checkpoints=window.checkpoints.filter(point=>point.height>=Math.max(0,Math.floor((last.height-ENG2_ROLLBACK_DEPTH)/STRIDE)*STRIDE));
  if(cache!==null)checkpoints=[...checkpoints.filter(point=>point.height!==last.height),{height:last.height,tip:last.id,bytes:cache.slice()}];
  let capacity_limited=window.capacity_limited;
  while(checkpoints.reduce((sum,point)=>sum+point.bytes.length,0)>budget){checkpoints=checkpoints.slice(1);capacity_limited=true;}
  const next={...window,height:last.height,tip:last.id,headers:[...window.headers,...added].slice(-HEADERS),checkpoints,capacity_limited};
  validate(next);return next;
}

// Remote header pages are branch-selection hints. Even a matching prefix never
// authorizes adoption: replay all receipts to the selected head, then require
// native context, work and complete-candidate checks before atomic persistence.
export function selectEng2Rollback(window,remote) {
  const config=validate(window);
  if(!remote||!height(remote.height)||!hex(remote.tip)||remote.height===0&&remote.tip!==config.genesis)fail();
  const from=Math.max(1,window.height-ENG2_ROLLBACK_DEPTH),to=Math.min(window.height,remote.height);
  const rows=to>=from?chain(remote.headers,config):[];
  if(rows.length!==Math.max(0,to-from+1)||rows.length&&rows[0].height!==from||rows.length&&rows.at(-1).height!==to||to===remote.height&&rows.length&&rows.at(-1).id!==remote.tip)fail();
  if(!rows.length&&remote.headers?.length)fail();
  const local=new Map(window.headers.map(row=>[row.height,row.id]));
  let ancestor=from===1?{height:0,id:config.genesis}:null;
  for(const row of rows)if(local.get(row.height)===row.id)ancestor=row;
  if(!ancestor||window.height-ancestor.height>ENG2_ROLLBACK_DEPTH)return {status:'unavailable',reason:'outside-window'};
  if(ancestor.height===window.height)return {status:'extension',height:window.height,tip:window.tip};
  const point=window.checkpoints.findLast(point=>point.height<=ancestor.height);
  if(!point)return {status:'unavailable',reason:'missing-private-cache',fork_height:ancestor.height,fork_tip:ancestor.id};
  return {status:'rollback',fork_height:ancestor.height,fork_tip:ancestor.id,depth:window.height-ancestor.height,
    cache_height:point.height,cache_tip:point.tip,cache:point.bytes.slice(),replay_from:point.height+1};
}
export function rewindEng2Rollback(window,plan) {
  validate(window);
  if(plan?.status!=='rollback'||!height(plan.fork_height)||window.height-plan.fork_height<1||window.height-plan.fork_height>ENG2_ROLLBACK_DEPTH||!window.headers.some(row=>row.height===plan.fork_height&&row.id===plan.fork_tip)||!window.checkpoints.some(point=>point.height===plan.cache_height&&point.tip===plan.cache_tip&&point.height<=plan.fork_height))fail();
  const next={...window,height:plan.fork_height,tip:plan.fork_tip,headers:window.headers.filter(row=>row.height<=plan.fork_height),checkpoints:window.checkpoints.filter(point=>point.height<=plan.fork_height)};
  validate(next);return next;
}
function keys(scanKey,cacheKey) {
  if(typeof scanKey!=='string'||!scanKey||scanKey.length>512||typeof cacheKey!=='string'||!cacheKey||cacheKey.length>512||scanKey===cacheKey)fail();
  const index='rollback:'+scanKey,slots=Array.from({length:SLOTS},(_,i)=>index+':'+i);
  if([scanKey,cacheKey,index,...slots].some((key,i,all)=>all.indexOf(key)!==i))fail();
  return {index,slots};
}
export async function persistEng2Rollback(storage,scanKey,scan,cacheKey,cache,window,protect) {
  validate(window);const record=keys(scanKey,cacheKey);
  if(!sealed(scan,'SWE2JL01',2_000_000)||!sealed(cache,'SWE2SC01',ENG2_ROLLBACK_CACHE_BYTES))fail();
  const {context,checkpoints,...metadata}=window;
  const plain=encode({...metadata,checkpoints:checkpoints.map(({height,tip,bytes},slot)=>({height,tip,size:bytes.length,slot}))});
  if(plain.length>INDEX_BYTES)fail();
  let encrypted;
  try{encrypted=protect(plain);}finally{plain.fill(0);}
  if(!sealed(encrypted,'SWE2JL01',INDEX_BYTES))fail();
  // The accepted pair, encrypted index, occupied slots and deleted stale slots
  // become durable in one transaction. Callers retain the owner lock and must
  // finish native adoption after durability, even if cancellation arrived.
  await storage.atomic([[scanKey,scan],[cacheKey,cache],[record.index,encrypted],...checkpoints.map((point,i)=>[record.slots[i],point.bytes])],record.slots.slice(checkpoints.length));
}
export async function loadEng2Rollback(storage,scanKey,cacheKey,configuration,accepted,open,signal) {
  signal?.throwIfAborted();
  const config=eng2Context(configuration),record=keys(scanKey,cacheKey),encrypted=await storage.read(record.index);
  signal?.throwIfAborted();
  if(!encrypted)return null;
  if(!sealed(encrypted,'SWE2JL01',INDEX_BYTES))fail();
  let metadata;const plain=open(encrypted);
  try{if(!(plain instanceof Uint8Array)||plain.length>INDEX_BYTES)fail();metadata=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plain));}finally{plain.fill(0);}
  if(!sameEng2Context(metadata,config)||metadata.height!==accepted.height||metadata.tip!==accepted.tip||!Array.isArray(metadata.checkpoints)||metadata.checkpoints.length>SLOTS)fail();
  const checkpoints=[];let bytes=0;
  for(const [i,point] of metadata.checkpoints.entries()){
    if(point.slot!==i||!Number.isSafeInteger(point.size)||point.size<ENVELOPE||point.size>ENG2_ROLLBACK_CACHE_BYTES||bytes+point.size>ENG2_ROLLBACK_CACHE_BYTES)fail();
    signal?.throwIfAborted();
    const value=await storage.read(record.slots[i]);
    signal?.throwIfAborted();
    if(!sealed(value,'SWE2SC01',ENG2_ROLLBACK_CACHE_BYTES)||value.length!==point.size)fail();
    bytes+=point.size;checkpoints.push({height:point.height,tip:point.tip,bytes:value});
  }
  const window={...metadata,context:config,checkpoints};validate(window);return window;
}
