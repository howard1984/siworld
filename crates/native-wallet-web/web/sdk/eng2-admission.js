import {eng2Context,sameEng2Context} from './eng2-context.js';

const id = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const hex = bytes => Array.from(bytes,value=>value.toString(16).padStart(2,'0')).join('');
const PREFIX=2184, SIDECAR=78, MAX_PACKET=PREFIX+655360+SIDECAR;

// Explicit engineering-v2 bridge; importing this module does not enable sending.
// The independently pinned endpoint must acknowledge actual native admission.
// An acknowledgement is pending, never proof of canonical block inclusion.
export function eng2Admission(configuration,io={}) {
  const context=eng2Context(configuration),request=io.fetch||globalThis.fetch;
  return async(packet,expected)=>{
    if(!sameEng2Context(expected,context)||expected.type!=='eng2-admission'||!id(expected.statement_id))throw new Error('Engineering-v2 admission context differs.');
    if(!(packet instanceof Uint8Array)||packet.length<PREFIX+1+SIDECAR||packet.length>MAX_PACKET||String.fromCharCode(...packet.subarray(0,4))!=='SWTX'||hex(packet.subarray(33,65))!==context.network)throw new Error('Engineering-v2 admission packet context or bounds differ.');
    const length=new DataView(packet.buffer,packet.byteOffset,packet.byteLength).getUint32(PREFIX-4,true);
    if(length!==packet.length-PREFIX-SIDECAR||String.fromCharCode(...packet.subarray(packet.length-SIDECAR,packet.length-SIDECAR+4))!=='SWFS')throw new Error('Engineering-v2 admission packet framing differs.');
    const {network,genesis,rules,profile,fee_mode}=context;
    const pin={version:2,network,genesis,rules,profile,fee_mode};
    const response=await request(context.api+'/api/v2/wallet/transactions',{
      method:'POST',headers:{'Content-Type':'application/octet-stream','X-SIWORLD-Context':JSON.stringify(pin),'X-SIWORLD-Statement':expected.statement_id},
      body:packet,credentials:'omit',redirect:'error',cache:'no-store',referrerPolicy:'no-referrer',signal:AbortSignal.timeout(45000),
    });
    if(!response.ok||response.status!==200||!/^application\/json(?:;|$)/i.test(response.headers.get('Content-Type')||''))throw new Error('Engineering-v2 native admission is uncertain. Retry only the original finalized packet.');
    const maximum=4096,lengthHeader=response.headers.get('Content-Length');
    if(lengthHeader!==null&&(!/^[0-9]+$/.test(lengthHeader)||Number(lengthHeader)>maximum))throw new Error('Engineering-v2 admission reply bound rejected.');
    const reader=response.body.getReader(),chunks=[];let count=0;
    try {while(true){const {value,done}=await reader.read();if(done)break;count+=value.length;if(count>maximum)throw new Error('Engineering-v2 admission reply bound rejected.');chunks.push(value);}}
    catch(error){await reader.cancel().catch(()=>{});throw error;}
    finally {reader.releaseLock();}
    const bytes=new Uint8Array(count);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
    let result;
    try {result=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}
    finally {bytes.fill(0);}
    if(!sameEng2Context(result,context)||result.status!=='pending'||result.statement_id!==expected.statement_id||result.included!==false||Object.keys(result).sort().join()!=='fee_mode,genesis,included,network,profile,rules,statement_id,status,version')throw new Error('Engineering-v2 native acknowledgement differs. Keep the original packet and reserved inputs.');
    return {...pin,statement_id:result.statement_id,status:'accepted',included:false};
  };
}
