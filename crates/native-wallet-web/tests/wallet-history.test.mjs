import {test} from 'node:test';
import assert from 'node:assert/strict';
import {transactionRows,WalletHistory} from '../web/assets/wallet-history.js';
const sip='0'.repeat(64);
const note=(overrides={})=>({id:'synthetic-note',kind:'payment',block_id:'5'.repeat(64),asset:sip,amount_atoms:'100000000',height:10,unlock_height:0,spent:false,timestamp:1,...overrides});

test('receipt confirmation status changes at the display boundary and falls back after a head rollback',()=>{
  const value=confirmations=>transactionRows({height:40,received_records:[note({confirmations})]})[0];
  assert.equal(value(1).status,'Pending confirmation');assert.equal(value(23).status,'Pending confirmation');assert.equal(value(24).status,'Confirmed');
  assert.equal(value(24).confirmations,24);assert.equal(value(2).status,'Pending confirmation');assert.equal(value(2).confirmations,2);
  assert.equal(transactionRows({height:40,received_records:[]}).length,0);
});
test('mining reward grouping keeps confirmations distinct from spend maturity',()=>{
  const rows=transactionRows({height:10,received_records:[
    note({id:'a',kind:'mining',confirmations:1,unlock_height:34,awaiting_maturity:true}),
    note({id:'b',kind:'mining',confirmations:1,amount_atoms:'200000000',unlock_height:34,awaiting_maturity:true})
  ]});
  assert.equal(rows.length,1);assert.equal(rows[0].amount_atoms,'300000000');assert.equal(rows[0].confirmations,1);assert.equal(rows[0].status,'Pending confirmation · Awaiting maturity');
  assert.equal(transactionRows({height:34,received_records:[note({kind:'mining',confirmations:25,unlock_height:34,awaiting_maturity:true})]})[0].status,'Confirmed');
});
test('legacy history without confirmation metadata keeps existing maturity and payment status',()=>{
  assert.equal(transactionRows({height:10,received_records:[note({unlock_height:20})]})[0].status,'Locked');
  const result={height:10,payments:[{id:'x',phase:'included',confirmed_height:10,amount_atoms:'1'}]};
  assert.equal(transactionRows(result)[0].status,'Included in authenticated receipt');assert.equal(transactionRows(result)[0].confirmations,null);
  for(const confirmations of [-1,NaN,1.5,'1'])assert.equal(transactionRows({height:10,received_records:[note({confirmations})]})[0].confirmations,null);
});
test('included outgoing payments display low confirmations while pending admission remains pending',()=>{
  const rows=transactionRows({height:11,payments:[{id:'a',phase:'included',confirmed_height:10,confirmations:2,amount_atoms:'1'},{id:'b',phase:'accepted',confirmations:0,amount_atoms:'1'}]});
  assert.equal(rows.find(row=>row.id==='payment:a').status,'Pending confirmation');assert.equal(rows.find(row=>row.id==='payment:b').status,'Pending');
});
test('history rendering shows confirmation counts in summary and detail and removes an orphan on refresh',()=>{
  class Element{
    constructor(tag='div'){this.tag=tag;this.children=[];this.textContent='';this.dataset={};}
    append(...nodes){this.children.push(...nodes);}prepend(node){this.children.unshift(node);}replaceChildren(...nodes){this.children=nodes;}setAttribute(){}
  }
  const original=globalThis.document;globalThis.document={createElement:tag=>new Element(tag)};
  const list=new Element(),previous=new Element('button'),next=new Element('button'),page=new Element(),root=new Element();
  const filters=['all','received','sent'].map(value=>{const button=new Element('button');button.dataset.historyFilter=value;return button;});
  root.querySelectorAll=()=>filters;root.querySelector=selector=>({'[data-history-list]':list,'[data-history-previous]':previous,'[data-history-next]':next,'[data-history-page]':page})[selector];
  try{
    const history=new WalletHistory(root);history.set({height:10,received_records:[note({confirmations:1})]});
    const detail=list.children[0],summary=detail.children[0];
    assert.equal(summary.children.find(node=>node.className==='transaction-status').textContent,'Pending confirmation · 1 confirmation');
    assert.ok(detail.children.some(node=>node.textContent==='Confirmations: 1'));assert.equal(previous.disabled,true);assert.equal(next.disabled,true);
    history.set({height:11,received_records:[]});assert.equal(list.children.length,1);assert.equal(list.children[0].tag,'p');assert.match(list.children[0].textContent,/No transactions/);
  }finally{globalThis.document=original;}
});
