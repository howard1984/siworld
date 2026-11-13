import {eng2Context} from './eng2-context.js';
import {publicGet} from './public-fetch.js';
import {failureContext} from './diagnostics.js';

// Only transport failures rotate independently pinned origins. Successful bytes
// retain the caller's native authentication, byte bounds and selected-head pin.
export function eng2PublicGet(request,configuration,io={}) {
  const context=eng2Context(configuration);let preferred=0;
  return async(url,options={})=>{
    const target=new URL(url);
    if(target.origin!==context.api||target.username||target.password||target.hash||!target.pathname.startsWith('/api/v2/wallet/'))throw new Error('Engineering-v2 public route is outside its pinned source.');
    const start=preferred;let attempt=0;
    return publicGet(async(_url,settings)=>{
      const index=(start+attempt++)%context.apis.length;
      try {
        const result=await request(context.apis[index]+target.pathname+target.search,settings);
        preferred=index;return result;
      } catch(error) {throw failureContext(error,'public-source',{source:index+1,attempt});}
    },url,options,io);
  };
}
