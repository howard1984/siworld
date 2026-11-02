import {fetchLimited,readJSON,hex,unhex,hash} from './online-storage.js';
const ZERO='00'.repeat(32);
export class CloudSession {
  constructor(account,api) {this.account=account;const u=new URL(api);if(u.username||u.password||u.search||u.hash||u.pathname!=='/'||!(u.protocol==='https:'||(u.protocol==='http:'&&u.hostname==='localhost')))throw new Error('Use the pinned independent Vault service origin.');this.api=u.origin;}
  info(){return JSON.parse(this.account.public_info());}
  async auth(method,body,info=this.info()) {
    const {challenge}=await readJSON(`${this.api}/v1/vault/challenge`,{method:'POST',body:JSON.stringify({locator:info.locator,method}),headers:{'Content-Type':'application/json'},signal:AbortSignal.timeout(15000)});
    const signature=this.account.sign_request(this.api,method,challenge,info.revision,body,info.digest);
    return {'X-Vault-Challenge':challenge,'X-Vault-Signature':signature,'X-Vault-Revision':info.revision,'X-Vault-Previous':info.digest,'Content-Type':'application/octet-stream'};
  }
  async enroll(){const info=this.info();const body=unhex(info.public_key);return readJSON(`${this.api}/v1/vault/accounts/${info.locator}`,{method:'POST',body,headers:await this.auth('POST',body),signal:AbortSignal.timeout(15000)});}
  async upload(packages,password){
    const info=this.info();const body=this.account.snapshot(JSON.stringify(packages),password);
    if(body.length!==524288)throw new Error('Vault snapshot must be exactly 512 KiB.');
    const digest=await hash(body);const revision=(BigInt(info.revision)+1n).toString();
    const headers=await this.auth('PUT',body,info);headers['X-Vault-Record']=this.account.sign_revision(revision,body,info.digest);
    const ack=await readJSON(`${this.api}/v1/vault/snapshot/${info.locator}`,{method:'PUT',body,headers,signal:AbortSignal.timeout(30000)});
    if(ack.status!=='stored'||ack.revision!==revision||ack.digest!==digest)throw new Error('Vault acknowledgment is uncertain. Download and reconcile before retrying.');
    this.account.accept(revision,digest);return {info:this.info(),recovery:this.account.recovery(password),snapshot:body,meta:{revision,previous:info.digest,digest,signature:headers['X-Vault-Record']}};
  }
  async download(password){
    const info=this.info(),headers=await this.auth('GET',new Uint8Array());
    const result=await fetchLimited(`${this.api}/v1/vault/snapshot/${info.locator}`,{headers,limit:524288,signal:AbortSignal.timeout(30000)});
    const revision=result.headers.get('X-Vault-Revision'),previous=result.headers.get('X-Vault-Previous'),signature=result.headers.get('X-Vault-Record');
    const digest=await hash(result.bytes);if(digest!==result.headers.get('X-Vault-Digest'))throw new Error('Vault ciphertext digest mismatch.');
    const packages=JSON.parse(this.account.open_snapshot(result.bytes,password,revision,previous,signature));
    this.account.accept(revision,digest);return {packages,info:this.info(),recovery:this.account.recovery(password),snapshot:result.bytes,meta:{revision,previous,digest,signature}};
  }
}
