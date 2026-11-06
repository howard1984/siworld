// Disposable local browser storage and synthetic chain data only. No payments.
import assert from 'node:assert/strict';
import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {resolve, sep, extname} from 'node:path';
const root=resolve(process.env.WALLET_WEB_OUTPUT), fixtures=resolve(process.env.WALLET_FIXTURE_DIR);
const config=JSON.parse(await readFile(resolve(fixtures,'fixture.json')));
const ids=[config.rows[0].block_id,config.rows[0].next_block_id];
const blocks=await Promise.all(['block-64.bin','next-64.bin'].map(name=>readFile(resolve(fixtures,name))));
const {chromium}=await import(process.env.WALLET_PLAYWRIGHT||'playwright');
const errors=[],downloads=[0,0];let origin,held=false,stall=true,projections=0;
let notifyBlocked;
const blocked=new Promise(done=>{notifyBlocked=done;});
const server=http.createServer(async(request,response)=>{
  response.setHeader('Cross-Origin-Opener-Policy','same-origin');
  response.setHeader('Cross-Origin-Embedder-Policy','require-corp');
  response.setHeader('Cache-Control','no-store');
  if(request.method!=='GET'){errors.push('Non-GET request.');response.writeHead(405);return response.end();}
  const url=new URL(request.url,origin);
  if(url.pathname==='/')return response.end('<!doctype html><title>Local shared history regression</title>');
  if(url.pathname==='/sdk/network.js'){
    response.setHeader('Content-Type','text/javascript');
    return response.end('export const ENGINEERING = '+JSON.stringify({...config,name:'siworld-eng-1',api:origin+'/api',read_only:true})+';');
  }
  if(url.pathname==='/api/v1/head')return response.end(JSON.stringify({network:config.network,genesis:config.genesis,height:2,tip:ids[1]}));
  if(url.pathname==='/api/v1/chain'){
    const tip=url.searchParams.get('tip'),from=Number(url.searchParams.get('from')),limit=Number(url.searchParams.get('limit'));
    assert.ok(ids.includes(tip));assert.ok(from>=1&&limit>=1&&limit<=128);
    return response.end(JSON.stringify({ids:ids.slice(from-1,Math.min(ids.indexOf(tip)+1,from-1+limit))}));
  }
  if(url.pathname.startsWith('/api/v1/commitments/')){projections++;response.writeHead(400);return response.end('{"error":"Public data unavailable."}');}
  if(url.pathname.startsWith('/api/v1/compact/')){
    const at=ids.indexOf(url.pathname.split('/').at(-1));assert.ok(at>=0);
    if(at===1&&stall){held=true;notifyBlocked();await new Promise(done=>response.once('close',done));return;}
    downloads[at]++;return response.end(blocks[at]);
  }
  try{
    const file=resolve(root,'.'+url.pathname);assert.ok(file.startsWith(root+sep));
    response.setHeader('Content-Type',({'.js':'text/javascript','.wasm':'application/wasm'})[extname(file)]||'application/octet-stream');
    response.end(await readFile(file));
  }catch{response.writeHead(404);response.end();}
});
await new Promise(done=>server.listen(0,'localhost',done));origin='http://localhost:'+server.address().port;
const browser=await chromium.launch({headless:true,...(process.env.WALLET_BROWSER?{executablePath:process.env.WALLET_BROWSER}:{})});
try{
  const context=await browser.newContext();context.setDefaultTimeout(30000);
  await context.route('**/*',route=>new URL(route.request().url()).origin===origin?route.continue():route.abort());
  const page=await context.newPage();page.on('pageerror',error=>errors.push(error.message));await page.goto(origin);
  await page.evaluate(async()=>{
    const {ENGINEERING}=await import('/sdk/network.js');window.config=ENGINEERING;
    const worker=new Worker('/sdk/worker.js',{type:'module'}),pending=new Map();let sequence=0,ready;
    const started=new Promise(done=>{ready=done;});window.progress=[];
    worker.onmessage=({data})=>{
      if(data.ready)return ready();
      if(data.progress){window.progress.push(data.progress);return;}
      const entry=pending.get(data.id);pending.delete(data.id);
      data.error?entry.reject(new Error(data.error)):entry.resolve(data.result);
    };
    window.rpc=(action,args=[],account=0)=>new Promise((resolve,reject)=>{
      const id=++sequence;pending.set(id,{resolve,reject});worker.postMessage({id,action,args,account});
    });
    await started;
    const created=await rpc('create',[ENGINEERING.network,0]);
    const words=created.words.split(' '),answers=created.positions.map(position=>words[position-1]).join(' ');
    const sealed=await rpc('seal',['synthetic shared history passphrase',answers]);
    words.fill('');created.words='';sealed.bytes.fill(0);
    await rpc('accounts-init');await rpc('online-init',[ENGINEERING]);
    window.firstScan=rpc('sync').then(()=>({completed:true}),error=>({error:error.message}));
  });
  await page.waitForFunction(()=>window.progress.some(row=>row.phase==='history'&&row.height===1));
  await blocked;
  assert.ok(held,'The first account must be interrupted during the next network request.');
  stall=false;
  const result=await page.evaluate(async()=>{
    const added=await rpc('accounts-add');
    const interrupted=await firstScan;
    await rpc('account-select',[added.account]);await rpc('online-init',[config],added.account);
    const second=await rpc('sync',[],added.account);
    await rpc('account-select',[0],added.account);await rpc('online-init',[config]);
    const first=await rpc('sync');
    return {interrupted:!!interrupted.error,second:{ready:second.ready,height:second.height,receipts:second.received_records.length},
      first:{ready:first.ready,height:first.height,receipts:first.received_records.length}};
  });
  assert.equal(result.interrupted,true);
  for(const account of [result.first,result.second])assert.deepEqual(account,{ready:true,height:2,receipts:0});
  assert.deepEqual(downloads,[1,1],'Verified history must be downloaded once across both accounts.');
  assert.equal(projections,1,'Probe the unavailable projection service once per shared session.');
  assert.deepEqual(errors,[]);
  console.log(JSON.stringify({result:'passed',cancelled_prefix_reused:true,both_accounts_ready:true,
    compact_downloads:downloads,projection_probes:projections,javascript_errors:0,transactions_sent:0}));
  await context.close();
}finally{await browser.close();server.closeAllConnections();await new Promise(done=>server.close(done));}
