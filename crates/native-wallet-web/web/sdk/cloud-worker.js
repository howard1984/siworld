import init,{BrowserVault} from './core/wallet.js';
import {CloudSession} from './cloud-session.js';
import {hash} from './online-storage.js';
import {stored} from './online-storage.js';
import {VAULT} from './vault-network.js';
await init({module_or_path:new URL('./core/wallet_bg.wasm',import.meta.url)});
let account=null,session=null,backupVerified=false,queue=Promise.resolve();
self.postMessage({ready:true});
self.onmessage=({data})=>{queue=queue.then(()=>handle(data));};
async function pin(recovery){const info=session.info();await stored('private',`vault:${info.locator}`,{revision:info.revision,digest:info.digest,recovery});}
async function resumePin(){const info=session.info();const local=await stored('private',`vault:${info.locator}`);if(local)account.accept(local.revision,local.digest);}
function close(){account?.free();account=session=null;backupVerified=false;}
async function handle({id,action,args=[]}) {
 try {let result;
  switch(action){
   case 'create':close();account=BrowserVault.create();session=new CloudSession(account,VAULT.api);result={info:session.info(),recovery:account.recovery(args[0])};break;
   case 'restore':close();account=BrowserVault.restore(...args);session=new CloudSession(account,VAULT.api);backupVerified=true;await resumePin();result={info:session.info()};break;
   case 'verify-backup': {const reopened=BrowserVault.restore(...args);try{if(reopened.public_info()!==account.public_info())throw new Error('Select the new independent Vault recovery file.');backupVerified=true;await pin(args[0]);result=true;}finally{reopened.free();}break;}
   case 'enroll':if(!backupVerified)throw new Error('Reopen your exported recovery file before enrolling.');result=await session.enroll();break;
   case 'upload':if(!backupVerified)throw new Error('Verify the independent recovery file first.');result=await session.upload(...args);await pin(result.recovery);break;
   case 'download':result=await session.download(...args);await pin(result.recovery);break;
   case 'open-offline':{const [bytes,password,metadata]=args;const digest=await hash(bytes);if(digest!==metadata.digest)throw new Error('Offline snapshot digest differs.');const packages=JSON.parse(account.open_snapshot(bytes,password,metadata.revision,metadata.previous,metadata.signature));account.accept(metadata.revision,digest);result={packages,info:session.info(),recovery:account.recovery(password),snapshot:bytes,meta:metadata};await pin(result.recovery);break;}
   case 'lock':close();result=true;break;
   default:throw new Error('Unsupported independent Vault operation.');
  }
  self.postMessage({id,result});
 }catch(error){self.postMessage({id,error:typeof error==='string'?error:error.message||'Vault operation failed. Existing copies were preserved.'});}
 finally{args.fill(null);}
}
