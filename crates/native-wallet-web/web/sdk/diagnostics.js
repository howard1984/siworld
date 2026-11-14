// Worker diagnostics contain fixed categories only. Never copy messages, stacks,
// URLs, arguments, wallet identities or receipt/transaction contents into them.
const contexts = new WeakMap();
const stages = new Set(['unknown','dispatch','sync-lock','initialize-info','initialize-lock','genesis-fetch','genesis-enable','cache-read','cache-restore','cache-initialize','cache-fresh','head-fetch','head-validate','headers-fetch','headers-decode','headers-validate','candidate-start','candidate-restore','candidate-check','head-recheck','cache-save','candidate-commit','receipt-fetch','receipt-header','receipt-apply','receipt-decode','receipt-check','rollback-cache','progress','summary','candidate-abort','reopen-required','public-source','public-request','json-decode','response-read','response-cancel']);
const kinds = new Set(['Error','TypeError','RangeError','ReferenceError','SyntaxError','EvalError','URIError','AggregateError','CompileError','LinkError','RuntimeError','AbortError','TimeoutError','DataError','OperationError','QuotaExceededError','InvalidStateError','UnknownError','String','Number','Boolean','Null','Undefined','Unknown']);
const actions = new Set(['online-init','sync']);
const MAX_CHAIN=6,MAX_CONTEXTS=8;
const object = value => value !== null && (typeof value === 'object' || typeof value === 'function');
const get = (value,key) => {try{return value?.[key];}catch{return undefined;}};
const kind = value => {
  if (value === null) return 'Null';
  if (typeof value === 'string') return 'String';
  if (typeof value === 'number') return 'Number';
  if (typeof value === 'boolean') return 'Boolean';
  if (value === undefined) return 'Undefined';
  const name=get(value,'name');return kinds.has(name)?name:'Unknown';
};
const status = value => Number.isInteger(value) && value >= 100 && value <= 599 ? value : null;

export function failureContext(error,stage,detail={}) {
  // Preserve Error identity so transport retry and cancellation policies do not
  // change. Primitive WASM rejections retain their original value as the cause.
  const failure=object(error)?error:new Error(typeof error==='string'?error:'Wallet operation failed.',{cause:error});
  const context={stage:stages.has(stage)?stage:'unknown'};
  if([1,2].includes(detail.source))context.source=detail.source;
  if(Number.isInteger(detail.attempt)&&detail.attempt>=1&&detail.attempt<=3)context.attempt=detail.attempt;
  if(typeof detail.timed_out==='boolean')context.timed_out=detail.timed_out;
  if(Object.hasOwn(detail,'related'))context.related_kind=kind(detail.related);
  contexts.set(failure,[...(contexts.get(failure)||[]),Object.freeze(context)].slice(-MAX_CONTEXTS));
  return failure;
}

export function failureDiagnostic(error,action) {
  const chain=[],seen=new Set();let current=error,truncated=false;
  for(let i=0;i<MAX_CHAIN;i++){
    if(seen.has(current)){truncated=true;break;}
    seen.add(current);
    chain.push({kind:kind(current),http_status:status(get(current,'status')),contexts:[...(object(current)?contexts.get(current)||[]:[])]});
    const cause=get(current,'cause');
    if(cause===undefined)break;
    current=cause;if(i===MAX_CHAIN-1)truncated=true;
  }
  return {version:1,action:actions.has(action)?action:'unknown',chain,truncated};
}

function validatedDiagnostic(value) {
  if(!value||Object.keys(value).sort().join()!=='action,chain,truncated,version'||value.version!==1||!['unknown',...actions].includes(value.action)||typeof value.truncated!=='boolean'||!Array.isArray(value.chain)||value.chain.length<1||value.chain.length>MAX_CHAIN)return null;
  const chain=[];
  for(const row of value.chain){
    if(!row||Object.keys(row).sort().join()!=='contexts,http_status,kind'||!kinds.has(row.kind)||row.http_status!==null&&status(row.http_status)===null||!Array.isArray(row.contexts)||row.contexts.length>MAX_CONTEXTS)return null;
    const clean=[];
    for(const item of row.contexts){
      if(!item||!Object.keys(item).every(key=>['stage','source','attempt','timed_out','related_kind'].includes(key))||!stages.has(item.stage)||item.source!==undefined&&![1,2].includes(item.source)||item.attempt!==undefined&&(!Number.isInteger(item.attempt)||item.attempt<1||item.attempt>3)||item.timed_out!==undefined&&typeof item.timed_out!=='boolean'||item.related_kind!==undefined&&!kinds.has(item.related_kind))return null;
      clean.push({...item});
    }
    chain.push({kind:row.kind,http_status:row.http_status,contexts:clean});
  }
  return {version:1,action:value.action,chain,truncated:value.truncated};
}

export function workerFailure(id,action,error) {
  const message=typeof error==='string'?error:get(error,'message');
  return {id,error:typeof message==='string'&&message?message:'Wallet operation failed. Preserve pending payments and retry only their stored packets.',diagnostic:failureDiagnostic(error,action)};
}

export function failureFromReply(reply) {
  const error=new Error(typeof reply.error==='string'?reply.error:'Wallet operation failed.');
  const diagnostic=validatedDiagnostic(reply.diagnostic);
  if(diagnostic)Object.defineProperty(error,'diagnostic',{value:diagnostic});
  return error;
}
