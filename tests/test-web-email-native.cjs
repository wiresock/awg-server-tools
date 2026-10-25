const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const tick = () => new Promise(resolve => setImmediate(resolve));
const ok = value => ({ok:true,json:async()=>value});
const saved = {revision:1,source:'panel',enabled:true,operational:true,storage_ready:true,host:'smtp.example.test',port:587,tls:'starttls',authenticate:true,username:'mailer',credentials_present:true,from:'vpn@example.test',reply_to:null,public_base:'https://download.example.test',link_enabled:true,ttl_seconds:86400};
const contacts=[{id:'a',peer_id:7,managed_name:'Alice <phone>',email:'alice@example.test',binding_version:2,retired_at:null},{id:'b',peer_id:8,managed_name:'Bob',email:null,binding_version:1,retired_at:null}];
function page(kind,responder,storage=new Map(),search="",clock={now:Date.now()}) {
  const ids=new Map(),requests=[],all=[],timers=new Map();let timerId=0;
  const document={activeElement:null};
  function element(id='') {const e={id,value:'',textContent:'',checked:false,disabled:false,hidden:false,open:false,dataset:{},children:[],listeners:{},
    append(...children){this.children.push(...children);},replaceChildren(...children){this.children=children;},
    setAttribute(k,v){this[k]=v;},removeAttribute(k){delete this[k];},
    addEventListener(k,fn){(this.listeners[k] ||= []).push(fn);},
    async fire(k,extra={}){for(const fn of this.listeners[k]||[]) await fn({target:this,preventDefault(){},...extra});},
    focus(){document.activeElement=this;},showModal(){this.open=true;},close(){this.open=false;this.fire('close');},
    reportValidity(){return this.valid!==false;},checkValidity(){return this.valid!==false;}
  };all.push(e);return e;}
  const get=id=>{if(!ids.has(id)) ids.set(id,element(id));return ids.get(id);};
  const selects=[7,8].map(id=>{const e=element();e.dataset.emailSelect=String(id);e.dataset.peerName=id===7?'Alice':'Bob';e.dataset.peerKey='key-'+id;e.closest=()=>({remove(){e.removed=true;}});return e;});
  const sends=(kind==='peers-no-actions'?[]:[7,8]).map(id=>{const e=element();e.dataset.emailSend=String(id);return e;});
  const edits=(kind==='peers-no-actions'?[]:[7,8]).map(id=>{const e=element();e.dataset.emailEdit=String(id);return e;});
  const readiness=[7,8].map(id=>{const e=element();e.dataset.emailReadiness=String(id);return e;});
  const formats=['conf','qr','vpn-uri'].map(format=>{const e=element();e.dataset.emailFormat=format;e.checked=format==='conf';return e;});
  get('email-base').value='/private';get('email-csrf').value='csrf';get('email-mode').value='direct';get('email-ttl').value='86400';
  get('smtp-password-action').value='keep';get('smtp-password').value='';get('email-test-recipient').value='admin@example.test';
  document.getElementById=id=>id===(kind==='settings'?'peer-email-tools':'email-settings-form')?null:get(id);
  document.createElement=element;
  document.querySelectorAll=selector=>selector.includes('email-select')?selects:selector.includes('email-send')?sends:selector.includes('email-edit')?edits:selector.includes('email-readiness')?readiness:selector.includes('email-format')?(selector.includes(':checked')?formats.filter(e=>e.checked):formats):[];
  const window={listeners:{},addEventListener(k,fn){(this.listeners[k] ||= []).push(fn);}};
  const context=vm.createContext({document,window,Set,Map,Date:class extends Date {constructor(...args){super(...(args.length?args:[clock.now]));}static now(){return clock.now;}},URLSearchParams,AbortController,setTimeout:(fn,ms)=>{timers.set(++timerId,{fn,ms});return timerId;},clearTimeout:id=>timers.delete(id),location:{search,pathname:'/private/'},
    sessionStorage:{getItem:k=>storage.get(k)||null,setItem:(k,v)=>storage.set(k,v),removeItem:k=>storage.delete(k)},
    confirm:()=>true,crypto:{getRandomValues:a=>{a.fill(13);return a;}},Uint8Array,btoa:s=>Buffer.from(s,'binary').toString('base64'),
    fetch:async(url,options)=>{const request={url,options,body:options.body?JSON.parse(options.body):null};requests.push(request);return responder(request);}});
  for(const file of ['email_common.js',kind==='settings'?'email_settings.js':'peer_email.js']) {
    const p=path.join(__dirname,'../amneziawg-web/src/web',file);
    if(fs.existsSync(p)) vm.runInContext(fs.readFileSync(p,'utf8'),context);
  }
  return {get,selects,sends,edits,readiness,formats,requests,storage,document,window,all,timers};
}
const responder=(overrides={})=>async r=>{
  const key=r.url.split('/').pop();if(overrides[key])return overrides[key](r);
  if(key==='settings')return ok(saved);if(key==='contacts')return ok(contacts);if(key==='jobs')return ok([]);
  if(key==='send')return ok(['job']);
  if(key==='preview')return ok({id:'preview-one',settings_revision:1,mode:'direct',formats:['conf'],ttl_seconds:86400,items:[{client_id:'a',name:contacts[0].managed_name,recipient:contacts[0].email}],skipped:[{client_id:'b',reason:'email_missing'}]});
  return ok({});
};
const text=e=>[e.textContent,...e.children.map(text)].join(' ');

test('accepted bulk send clears eligible selections but keeps skipped peers and header consistent',async()=>{
  const p=page('peers',responder({send:()=>ok(['job-a'])}));await tick();
  for(const c of p.selects){c.checked=true;await c.fire('change');}
  await p.get('email-bulk-send').fire('click');await p.get('email-confirm').fire('click');
  assert.equal(p.selects[0].checked,false);assert.equal(p.selects[1].checked,true);
  assert.equal(p.get('email-select-all').checked,false);assert.equal(p.get('email-select-all').indeterminate,true);
  assert.equal(p.get('email-selection-count').textContent,'1 selected');assert.match(p.get('email-peer-status').textContent,/skipped.*kept/i);
});
test('completed bulk send clears counts and disables empty-selection actions',async()=>{
  const p=page('peers',responder({send:()=>ok(['job-a'])}));await tick();
  p.selects[0].checked=true;await p.selects[0].fire('change');await p.get('email-bulk-send').fire('click');await p.get('email-confirm').fire('click');
  assert.equal(p.get('email-selection-count').textContent,'0 selected');assert.equal(p.get('email-bulk-send').disabled,true);assert.equal(p.get('peer-bulk-delete').disabled,true);
  assert.equal(p.get('email-select-all').checked,false);assert.equal(p.get('email-select-all').indeterminate,false);
});
test('rejected and interrupted bulk submissions keep all selections',async()=>{
  for(const fail of [()=>({ok:false,json:async()=>({error:'changed'})}),()=>Promise.reject(new Error('offline'))]) {
    const p=page('peers',responder({send:fail}));await tick();p.selects[0].checked=true;await p.selects[0].fire('change');
    await p.get('email-bulk-send').fire('click');await p.get('email-confirm').fire('click');assert.equal(p.selects[0].checked,true);
  }
});
test('late bulk response clears original selection but not a new or reselected peer',async()=>{
  for(const reselect of [false,true]) {
    let release;const p=page('peers',responder({send:()=>new Promise(r=>release=r)}));await tick();
    p.selects[0].checked=true;await p.selects[0].fire('change');await p.get('email-bulk-send').fire('click');const work=p.get('email-confirm').fire('click');await tick();await p.get('email-cancel').fire('click');
    if(reselect){p.selects[0].checked=false;await p.selects[0].fire('change');p.selects[0].checked=true;await p.selects[0].fire('change');}
    p.selects[1].checked=true;await p.selects[1].fire('change');release(ok(['job-a']));await work;
    assert.equal(p.selects[0].checked,reselect);assert.equal(p.selects[1].checked,true);
  }
});
test('recovered bulk confirmation after reload clears only its unchanged original selection',async()=>{
  const p=page('peers',responder({send:()=>Promise.reject(new Error('offline'))}));await tick();
  p.selects[0].checked=true;await p.selects[0].fire('change');await p.get('email-bulk-send').fire('click');await p.get('email-confirm').fire('click');
  const next=page('peers',responder({send:()=>ok(['job-a'])}),p.storage);await tick();next.selects[1].checked=true;await next.selects[1].fire('change');
  await next.get('email-pending-check').fire('click');await next.get('email-confirm').fire('click');
  assert.equal(next.selects[0].checked,false);assert.equal(next.selects[1].checked,true);
});
test('single peer email success does not clear a separately selected bulk peer',async()=>{
  const p=page('peers',responder({send:()=>ok(['job-a'])}));await tick();p.selects[0].checked=true;await p.selects[0].fire('change');
  await p.sends[0].fire('click');await p.get('email-confirm').fire('click');assert.equal(p.selects[0].checked,true);
});
test('explicit separate bulk review after uncertainty clears its newly confirmed selection',async()=>{
  let attempts=0;const p=page('peers',responder({send:()=>++attempts===1?Promise.reject(new Error('offline')):ok(['job-new'])}));await tick();
  p.selects[0].checked=true;await p.selects[0].fire('change');await p.get('email-bulk-send').fire('click');await p.get('email-confirm').fire('click');
  await p.get('email-new-review').fire('click');await p.get('email-confirm').fire('click');
  assert.equal(p.get('email-selection-count').textContent,'0 selected');assert.equal(p.get('email-bulk-send').disabled,true);
});
test('a response after navigation cannot overwrite the new page selection or recovery intent',async()=>{
  let release;const p=page('peers',responder({send:()=>new Promise(r=>release=r)}));await tick();
  p.selects[0].checked=true;await p.selects[0].fire('change');await p.get('email-bulk-send').fire('click');const work=p.get('email-confirm').fire('click');await tick();
  for(const fn of p.window.listeners.pagehide)fn({});
  const next=page('peers',responder(),p.storage);await tick();next.selects[1].checked=true;await next.selects[1].fire('change');
  release(ok(['job-a']));await work;assert.deepEqual(JSON.parse(p.storage.get('awg-email-selected:/private')),['7','8']);
  assert.equal(p.storage.get('awg-email-pending:/private'),'preview-one');
  await next.get('email-pending-check').fire('click');await next.get('email-confirm').fire('click');assert.equal(next.selects[0].checked,false);assert.equal(next.selects[1].checked,true);
});
const activity=(id,state,accepted_at=null,extra={})=>({id,client_id:'a',request_id:'request',actor:'admin',recipient:id+'@example.test',mode:'direct',link_ttl_seconds:86400,formats:'["conf"]',binding_version:2,state,attempts:1,next_attempt_at:1700000060,created_at:1699999000,accepted_at,error_code:null,invalidated_at:null,invalidation_code:null,...extra});
test('Clear history hides only observed terminal results and preserves unresolved request recovery',async()=>{
  let rows=['accepted','failed','unknown','cancelled','queued','sending'].map(s=>activity(s,s,s==='accepted'?1700000000:null));
  const storage=new Map([['awg-email-pending:/private','uncertain-request']]);
  const p=page('peers',responder({jobs:()=>ok(rows)}),storage,'',{now:1700000010000});await tick();
  assert.equal(p.get('email-activity-clear').disabled,false);await p.get('email-activity-clear').fire('click');
  for(const s of ['accepted','failed','unknown','cancelled'])assert.doesNotMatch(text(p.get('email-activity')),new RegExp(s+'@example.test'));
  for(const s of ['queued','sending'])assert.match(text(p.get('email-activity')),new RegExp(s+'@example.test'));
  assert.equal(storage.get('awg-email-pending:/private'),'uncertain-request');assert.equal(p.get('email-pending-check').hidden,false);
  assert.equal(p.get('email-activity-clear').disabled,true);await p.get('email-refresh').fire('click');
  assert.doesNotMatch(text(p.get('email-activity')),/failed@example.test/);
  rows=[...rows,activity('new-result','failed')];await p.get('email-refresh').fire('click');assert.match(text(p.get('email-activity')),/new-result@example.test/);
  const restored=page('peers',responder({jobs:()=>ok(rows)}),storage,'',{now:1700000010000});await tick();
  assert.doesNotMatch(text(restored.get('email-activity')),/unknown@example.test/);assert.match(text(restored.get('email-activity')),/new-result@example.test/);
  assert.equal(restored.requests.filter(r=>r.body).length,0);assert.ok([...storage.values()].every(v=>!v.includes('@example.test')));
});
test('cleared results reappear on retry, changed resolution or revocation, never hiding active work',async()=>{
  let rows=[activity('retry','failed'),activity('resolve','unknown'),activity('revoke','accepted',1700000000)];
  const p=page('peers',responder({jobs:()=>ok(rows)}),new Map(),'',{now:1700000010000});await tick();await p.get('email-activity-clear').fire('click');
  assert.match(text(p.get('email-activity')),/No visible/);
  rows=[activity('retry','queued'),activity('resolve','accepted',1700000009),activity('revoke','accepted',1700000000,{invalidated_at:1700000009,invalidation_code:'changed'})];
  await p.get('email-refresh').fire('click');for(const id of ['retry','resolve','revoke'])assert.match(text(p.get('email-activity')),new RegExp(id+'@example.test'));
  rows=[activity('retry','failed',null,{attempts:2})];await p.get('email-refresh').fire('click');assert.match(text(p.get('email-activity')),/retry@example.test/);
  await p.get('email-activity-clear').fire('click');await p.get('email-activity-show').fire('click');assert.match(text(p.get('email-activity')),/retry@example.test/);
});
test('Back Forward restores newer selections, pending recovery and cleared history without writes',async()=>{
  const rows=[activity('old','failed')],respond=responder({jobs:()=>ok(rows)});
  const p=page('peers',respond);await tick();p.selects[0].checked=true;await p.selects[0].fire('change');
  for(const fn of p.window.listeners.pagehide)fn({});
  const newer=page('peers',respond,p.storage);await tick();await newer.get('email-clear-selection').fire('click');newer.selects[1].checked=true;await newer.selects[1].fire('change');await newer.get('email-activity-clear').fire('click');
  p.storage.set('awg-email-pending:/private','newer-request');
  for(const fn of p.window.listeners.pageshow)fn({persisted:true});await tick();
  assert.equal(p.selects[0].checked,false);assert.equal(p.selects[1].checked,true);assert.equal(p.get('email-pending-check').hidden,false);
  assert.equal(p.storage.get('awg-email-pending:/private'),'newer-request');assert.doesNotMatch(text(p.get('email-activity')),/old@example.test/);
  assert.equal(p.requests.filter(r=>r.body).length,0);
});
test('old send response after BFCache return cannot clear a newer pending request',async()=>{
  let release;const p=page('peers',responder({send:()=>new Promise(r=>release=r)}));await tick();p.selects[0].checked=true;await p.selects[0].fire('change');await p.get('email-bulk-send').fire('click');const work=p.get('email-confirm').fire('click');await tick();
  for(const fn of p.window.listeners.pagehide)fn({});
  p.storage.set('awg-email-pending:/private','newer-request');
  for(const fn of p.window.listeners.pageshow)fn({persisted:true});await tick();release(ok(['job-a']));await work;
  assert.equal(p.storage.get('awg-email-pending:/private'),'newer-request');assert.equal(p.selects[0].checked,true);
});
test('activity uses server acceptance time and expires only successful rows at ten minutes',async()=>{
  const clock={now:1700000599000};const rows=[activity('success','accepted',1700000000),activity('unknown','unknown'),activity('failed','failed'),activity('queued','queued'),activity('legacy','accepted'),activity('revoked','accepted',1700000000,{invalidated_at:1700000010})];
  const p=page('peers',responder({jobs:()=>ok(rows)}),new Map(),'',clock);await tick();
  assert.match(text(p.get('email-activity')),/success@example.test/);
  const time=p.all.find(e=>e.id==='time' && e.dateTime==='2023-11-14T22:13:20.000Z');assert.ok(time);assert.ok(time.textContent);
  clock.now+=1000;const timer=[...p.timers.values()].find(t=>t.ms===1000);assert.ok(timer);await timer.fn();await tick();
  assert.doesNotMatch(text(p.get('email-activity')),/success@example.test/);
  for(const id of ['unknown','failed','queued','legacy','revoked'])assert.match(text(p.get('email-activity')),new RegExp(id+'@example.test'));
  const next=page('peers',responder({jobs:()=>ok(rows)}),p.storage,'',clock);await tick();assert.doesNotMatch(text(next.get('email-activity')),/success@example.test/);
  assert.equal(p.requests.filter(r=>r.body).length,0);
});
test('successful activity can be dismissed and shown without hiding uncertain rows or deleting history',async()=>{
  const clock={now:1700000010000};const rows=[activity('success','accepted',1700000000),activity('unknown','unknown')];
  const p=page('peers',responder({jobs:()=>ok(rows)}),new Map(),'',clock);await tick();
  const dismiss=p.all.find(e=>e.id==='button' && /Dismiss/.test(e.textContent));assert.ok(dismiss);await dismiss.fire('click');
  assert.doesNotMatch(text(p.get('email-activity')),/success@example.test/);assert.match(text(p.get('email-activity')),/unknown@example.test/);
  await p.get('email-activity-show').fire('click');assert.match(text(p.get('email-activity')),/success@example.test/);
  const next=page('peers',responder({jobs:()=>ok(rows)}),p.storage,'',clock);await tick();assert.doesNotMatch(text(next.get('email-activity')),/success@example.test/);
  assert.equal(p.requests.filter(r=>r.body).length,0);
});
test('activity never truncates a pending or unknown item behind twelve successes',async()=>{
  const rows=[...Array.from({length:12},(_,i)=>activity('ok'+i,'accepted',1700000000)),activity('older-pending','sending'),activity('older-unknown','unknown')];
  const p=page('peers',responder({jobs:()=>ok(rows)}),new Map(),'',{now:1700000010000});await tick();
  assert.match(text(p.get('email-activity')),/older-pending@example.test/);assert.match(text(p.get('email-activity')),/older-unknown@example.test/);
});
test('older activity response cannot replace newer status and pagehide stops polling',async()=>{
  let release,calls=0;const p=page('peers',responder({jobs:()=>++calls===1?new Promise(r=>release=r):ok([activity('latest','unknown')])}));await tick();
  await p.get('email-refresh').fire('click');release(ok([activity('stale','accepted',1700000000)]));await tick();
  assert.match(text(p.get('email-activity')),/latest@example.test/);assert.doesNotMatch(text(p.get('email-activity')),/stale@example.test/);
  for(const fn of p.window.listeners.pagehide)fn({});assert.equal(p.timers.size,0);
});
test('an uncertain result with a retained timestamp never claims SMTP acceptance or expires',async()=>{
  const p=page('peers',responder({jobs:()=>ok([activity('uncertain','unknown',1700000000)])}),new Map(),'',{now:1700000600000});await tick();
  assert.match(text(p.get('email-activity')),/uncertain@example.test/);assert.doesNotMatch(text(p.get('email-activity')),/SMTP accepted:/);
});

test('native settings load a redacted profile and Save never invokes Test',async()=>{
  const p=page('settings',responder());await tick();
  assert.equal(p.get('smtp-host').value,'smtp.example.test');assert.equal(p.get('smtp-password').value,'');
  assert.match(p.get('email-credential-state').textContent,/stored/i);
  await p.get('email-settings-form').fire('submit');
  const writes=p.requests.filter(r=>r.body);assert.equal(writes.length,1);assert.ok(writes[0].url.endsWith('/settings'));
  assert.equal(writes[0].body.password_action,'keep');assert.ok(!('password' in writes[0].body));assert.equal(writes[0].body.revision,1);
  assert.equal(writes[0].options.headers['X-CSRF-Token'],'csrf');
});
test('replacement password is write only and cleared after submission',async()=>{
  const p=page('settings',responder());await tick();
  p.get('smtp-password-action').value='replace';await p.get('smtp-password-action').fire('change');p.get('smtp-password').value='dummy-secret';
  await p.get('email-settings-form').fire('submit');assert.equal(p.requests.find(r=>r.body).body.password,'dummy-secret');
  assert.equal(p.get('smtp-password').value,'');assert.equal(p.storage.size,0);
});
test('duplicate Save is suppressed and uncertain Save requires reload',async()=>{
  let reject;const p=page('settings',responder({settings:r=>r.body?new Promise((_,j)=>reject=j):ok(saved)}));await tick();
  const first=p.get('email-settings-form').fire('submit');await p.get('email-settings-form').fire('submit');
  assert.equal(p.requests.filter(r=>r.body).length,1);reject(new Error('offline'));await first;
  await p.get('email-settings-form').fire('submit');assert.equal(p.requests.filter(r=>r.body).length,1);
  assert.match(p.get('email-settings-status').textContent,/reload/i);
});
test('test mail requires confirmation and interrupted responses recover by GET without resubmission',async()=>{
  const reply={state:'accepted',recipient:'admin@example.test',settings_revision:1,settings_changed:false};
  const normal=responder({test:()=>Promise.reject(new Error('offline'))});
  const p=page('settings',r=>r.url.includes('/settings/test/')?ok(reply):normal(r));await tick();
  await p.get('email-test-open').fire('click');assert.equal(p.requests.filter(r=>r.body).length,0);
  assert.equal(p.get('email-test-dialog').open,true);await p.get('email-test-confirm').fire('click');
  await p.get('email-test-confirm').fire('click');const sends=p.requests.filter(r=>r.body);
  assert.equal(sends.length,1);assert.ok(p.requests.some(r=>r.url.endsWith('/test/'+sends[0].body.request_id)&&!r.body));
  assert.match(p.get('email-test-status').textContent,/sent.*accepted by SMTP/i);
  assert.doesNotMatch(p.get('email-test-status').textContent,/unconfirmed|unverified|inbox/i);
});
test('unavailable private storage prevents Save but transient testing does not persist credentials',async()=>{
  const p=page('settings',responder({settings:()=>ok({...saved,storage_ready:false})}));await tick();
  assert.equal(p.get('email-save').disabled,true);assert.match(p.get('email-storage-notice').textContent,/private|permission/i);
  await p.get('email-settings-form').fire('input');await p.get('email-test-open').fire('click');
  assert.equal(p.get('email-test-dialog').open,true);assert.equal(p.requests.filter(r=>r.body).length,0);
});
test('main peer selection persists across navigation and restores only existing peer ids',async()=>{
  const p=page('peers',responder());await tick();p.selects[0].checked=true;await p.selects[0].fire('change');
  assert.match(p.get('email-selection-count').textContent,/1 selected/);
  const second=page('peers',responder(),p.storage);await tick();assert.equal(second.selects[0].checked,true);
  assert.ok([...p.storage.values()].every(v=>!v.includes('alice@example.test')));
});
test('row Actions and Bulk use server recipient preview with readable skipped explanations',async()=>{
  const p=page('peers',responder());await tick();await p.sends[0].fire('click');await tick();
  assert.equal(p.get('email-send-dialog').open,true);assert.match(text(p.get('email-recipients')),/Alice <phone>.*alice@example.test/);
  assert.match(text(p.get('email-skipped')),/Bob.*email address/i);assert.match(p.get('email-confirm').textContent,/1 recipient/);
  assert.equal(p.requests.find(r=>r.url.endsWith('/preview')).body.clients[0],'a');
});
test('changing options discards an in-flight stale preview and Cancel preserves selection',async()=>{
  let release;const p=page('peers',responder({preview:()=>new Promise(r=>release=r)}));await tick();
  p.selects[0].checked=true;await p.selects[0].fire('change');const first=p.get('email-bulk-send').fire('click');await tick();
  p.formats[1].checked=true;await p.formats[1].fire('change');release(ok({id:'stale',items:[{name:'stale',recipient:'old@example.test'}],skipped:[]}));await first;
  assert.equal(p.get('email-confirm').disabled,true);assert.ok(!text(p.get('email-recipients')).includes('old@example.test'));
  await p.get('email-cancel').fire('click');assert.equal(p.selects[0].checked,true);assert.equal(p.get('email-send-dialog').open,false);
});
test('not configured and missing email lead to settings/edit actions without sending',async()=>{
  const p=page('peers',responder({settings:()=>ok({...saved,enabled:false,operational:false})}));await tick();await p.sends[1].fire('click');
  assert.equal(p.get('email-setup').hidden,false);assert.equal(p.requests.filter(r=>r.body).length,0);
  assert.match(p.readiness[1].textContent,/email/i);
});
test('send retries keep the same preview id and duplicate clicks do not enqueue twice',async()=>{
  let reject;let calls=0;const p=page('peers',responder({send:()=>++calls===1?new Promise((_,j)=>reject=j):ok(['job'])}));await tick();await p.sends[0].fire('click');
  const first=p.get('email-confirm').fire('click');await p.get('email-confirm').fire('click');assert.equal(calls,1);
  reject(new Error('offline'));await first;await p.get('email-confirm').fire('click');
  const writes=p.requests.filter(r=>r.url.endsWith('/send'));assert.equal(writes.length,2);assert.equal(writes[0].body.request_id,writes[1].body.request_id);
  assert.match(p.get('email-peer-status').textContent,/queued/i);
});
test('editing missing email uses contact version and Cancel never saves',async()=>{
  const p=page('peers',responder());await tick();await p.edits[1].fire('click');p.get('email-edit-address').value='bob@example.test';
  await p.get('email-edit-cancel').fire('click');assert.equal(p.requests.filter(r=>r.body).length,0);
  await p.edits[1].fire('click');p.get('email-edit-address').value='bob@example.test';await p.get('email-edit-form').fire('submit');
  const write=p.requests.find(r=>r.url.endsWith('/contact'));assert.equal(write.body.client_id,'b');assert.equal(write.body.version,1);
});
test('closing an uncertain send and selecting another peer keeps the original confirmed request',async()=>{
  const p=page('peers',responder({send:()=>Promise.reject(new Error('offline'))}));await tick();await p.sends[0].fire('click');await p.get('email-confirm').fire('click');
  await p.get('email-cancel').fire('click');await p.sends[1].fire('click');await p.get('email-confirm').fire('click');
  const previews=p.requests.filter(r=>r.url.endsWith('/preview'));assert.equal(previews.length,1);
  const sends=p.requests.filter(r=>r.url.endsWith('/send'));assert.equal(sends.length,2);assert.equal(sends[0].body.request_id,sends[1].body.request_id);
});
test('reload preserves only an unresolved send id and requires explicit check before a new preview',async()=>{
  const p=page('peers',responder({send:()=>Promise.reject(new Error('offline'))}));await tick();await p.sends[0].fire('click');await p.get('email-confirm').fire('click');
  const restored=page('peers',responder(),p.storage);await tick();
  assert.equal(restored.get('email-pending-check').hidden,false);
  assert.equal(restored.requests.filter(r=>r.body).length,0);
  await restored.get('email-pending-check').fire('click');await restored.get('email-confirm').fire('click');
  assert.equal(restored.requests.find(r=>r.url.endsWith('/send')).body.request_id,'preview-one');
  assert.ok([...p.storage.values()].every(v=>!v.includes('alice@example.test')));
});
test('reload recovers a test email using a read-only status request and never stores the recipient',async()=>{
  const p=page('settings',responder({test:()=>Promise.reject(new Error('offline'))}));await tick();await p.get('email-test-open').fire('click');await p.get('email-test-confirm').fire('click');
  const prior=p.requests.find(r=>r.body);assert.ok(prior);
  const restored=page('settings',r=>r.url.includes('/settings/test/')?ok({id:prior.body.request_id,recipient:'admin@example.test',state:'accepted',settings_revision:1}):responder()(r),p.storage);await tick();
  assert.ok(restored.requests.some(r=>r.url.endsWith('/settings/test/'+prior.body.request_id)));
  assert.equal(restored.requests.filter(r=>r.body).length,0);assert.match(restored.get('email-test-recovery').textContent,/accepted/i);
  assert.ok([...p.storage.values()].every(v=>!v.includes('admin@example.test')));
  assert.equal(restored.get('email-test-open').disabled,true);
});
test('unbound selected peers are named as skipped beside eligible recipients',async()=>{
  const p=page('peers',responder({contacts:()=>ok([contacts[0]])}));await tick();
  for(const c of p.selects){c.checked=true;await c.fire('change');}
  await p.get('email-bulk-send').fire('click');assert.match(text(p.get('email-skipped')),/Bob.*current contact binding/i);
  assert.match(text(p.get('email-recipients')),/alice@example.test/);
});
test('profile inputs are locked during Save so a delayed response cannot discard later user edits',async()=>{
  let resolve;const p=page('settings',responder({settings:r=>r.body?new Promise(r=>resolve=r):ok(saved)}));await tick();
  const pending=p.get('email-settings-form').fire('submit');
  assert.equal(p.get('email-save').disabled,true);assert.equal(p.get('email-reload').disabled,true);
  for(const id of ['smtp-host','smtp-port','smtp-tls','smtp-enabled','smtp-authenticate','smtp-username','smtp-password-action','smtp-from','smtp-reply-to','smtp-public-base','smtp-ttl'])assert.equal(p.get(id).disabled,true,id);
  resolve(ok({...saved,revision:2}));await pending;assert.equal(p.get('smtp-host').disabled,false);
  assert.equal(p.get('email-save').disabled,false);assert.equal(p.get('email-reload').disabled,false);
});
test('single-row setup navigation restores that recipient review without changing bulk selection',async()=>{
  const p=page('peers',responder({settings:()=>ok({...saved,enabled:false,operational:false})}));await tick();await p.sends[0].fire('click');await p.get('email-setup-link').fire('click');
  const restored=page('peers',responder(),p.storage);await tick();await tick();
  const request=restored.requests.find(r=>r.url.endsWith('/preview'));assert.ok(request);assert.deepEqual(request.body.clients,['a']);
  assert.equal(restored.selects[0].checked,false);assert.equal(restored.get('email-send-dialog').open,true);
});
test('safe SMTP failure categories give useful guidance without returning raw relay replies',async()=>{
  for(const [code,phrase] of [['permanent_rejection',/authentication|sender|policy/i],['transient_rejection',/later/i]]) {
    const p=page('settings',responder({test:()=>ok({state:'failed',error_code:code,recipient:'admin@example.test',settings_revision:1})}));await tick();await p.get('email-test-open').fire('click');await p.get('email-test-confirm').fire('click');
    assert.match(p.get('email-test-status').textContent,phrase);
  }
});


test('bulk delete is disabled for empty selection and Cancel is the safe default',async()=>{
  const p=page('peers',responder());await tick();assert.equal(p.get('peer-bulk-delete').disabled,true);
  p.selects[0].checked=true;await p.selects[0].fire('change');await p.get('peer-bulk-delete').fire('click');
  assert.equal(p.get('peer-delete-dialog').open,true);assert.match(text(p.get('peer-delete-list')),/Alice/);
  assert.equal(p.document.activeElement,p.get('peer-delete-cancel'));assert.equal(p.get('peer-delete-confirm').disabled,true);
  await p.get('peer-delete-confirm').fire('click');assert.equal(p.requests.filter(r=>r.url.endsWith('/remove')).length,0);
  await p.get('peer-delete-cancel').fire('click');assert.equal(p.get('peer-delete-dialog').open,false);assert.equal(p.selects[0].checked,true);
});
test('bulk delete reports partial results and keeps only failed selections with identity guard',async()=>{
  const p=page('peers',async r=>r.url.endsWith('/remove')?{ok:r.url.includes('/7/'),status:r.url.includes('/7/')?200:500,json:async()=>({ok:true})}:responder()(r));await tick();
  for(const c of p.selects){c.checked=true;await c.fire('change');}await p.get('peer-bulk-delete').fire('click');
  p.get('peer-delete-ack').checked=true;await p.get('peer-delete-ack').fire('change');await p.get('peer-delete-confirm').fire('click');
  assert.equal(p.selects[0].removed,true);assert.equal(p.selects[1].checked,true);assert.equal(p.get('email-selection-count').textContent,'1 selected');
  assert.match(text(p.get('peer-delete-list')),/Alice.*Deleted/);assert.match(text(p.get('peer-delete-list')),/Bob.*failed/i);
  const req=p.requests.filter(r=>r.url.endsWith('/remove'));assert.equal(req.length,2);assert.equal(req[0].url,'/private/api/admin/users/7/remove');assert.equal(req[0].body.expected_public_key_sha256,'key-7');assert.equal(req[0].options.headers['X-CSRF-Token'],'csrf');
});
test('bulk delete suppresses repeated confirmation and never automatically retries unknown results',async()=>{
  let reject;const p=page('peers',async r=>r.url.endsWith('/remove')?new Promise((_,j)=>reject=j):responder()(r));await tick();
  p.selects[0].checked=true;await p.selects[0].fire('change');await p.get('peer-bulk-delete').fire('click');p.get('peer-delete-ack').checked=true;await p.get('peer-delete-ack').fire('change');
  const first=p.get('peer-delete-confirm').fire('click');await tick();await p.get('peer-delete-confirm').fire('click');assert.equal(p.requests.filter(r=>r.url.endsWith('/remove')).length,1);
  reject(new Error('connection lost'));await first;assert.equal(p.selects[0].checked,true);assert.match(text(p.get('peer-delete-list')),/unknown/i);
  await p.get('peer-delete-confirm').fire('click');assert.equal(p.requests.filter(r=>r.url.endsWith('/remove')).length,1);
});
test('stale removed selection clears safely while changed identity stays selected',async()=>{
  const p=page('peers',async r=>r.url.endsWith('/remove')?{ok:false,status:r.url.includes('/7/')?404:409,json:async()=>({error:'peer_changed'})}:responder()(r));await tick();
  for(const c of p.selects){c.checked=true;await c.fire('change');}await p.get('peer-bulk-delete').fire('click');p.get('peer-delete-ack').checked=true;await p.get('peer-delete-ack').fire('change');await p.get('peer-delete-confirm').fire('click');
  assert.equal(p.selects[0].removed,true);assert.equal(p.selects[1].checked,true);assert.match(text(p.get('peer-delete-list')),/already.*removed|no longer present/i);assert.match(text(p.get('peer-delete-list')),/changed|busy/i);
});
test('navigation stops undispatched bulk deletes and never starts deletion itself',async()=>{
  let resolve;const p=page('peers',async r=>r.url.endsWith('/remove')?new Promise(done=>resolve=done):responder()(r));await tick();
  for(const c of p.selects){c.checked=true;await c.fire('change');}await p.get('peer-bulk-delete').fire('click');p.get('peer-delete-ack').checked=true;await p.get('peer-delete-ack').fire('change');const work=p.get('peer-delete-confirm').fire('click');await tick();
  for(const fn of p.window.listeners.pagehide)fn({});resolve(ok({ok:true}));await work;
  assert.equal(p.requests.filter(r=>r.url.endsWith('/remove')).length,1);assert.equal(p.selects[1].checked,true);assert.match(text(p.get('peer-delete-list')),/not attempted/i);
});

test('bulk deletion stops undispatched clients on explicit Stop without claiming current rollback',async()=>{
  let resolve;const p=page('peers',async r=>r.url.endsWith('/remove')?new Promise(done=>resolve=done):responder()(r));await tick();
  for(const c of p.selects){c.checked=true;await c.fire('change');}await p.get('peer-bulk-delete').fire('click');p.get('peer-delete-ack').checked=true;const work=p.get('peer-delete-confirm').fire('click');await tick();
  assert.equal(p.get('peer-delete-cancel').disabled,false);assert.match(p.get('peer-delete-cancel').textContent,/stop/i);
  await p.get('peer-delete-cancel').fire('click');assert.match(p.get('peer-delete-status').textContent,/current.*may.*complete/i);
  resolve(ok({ok:true}));await work;assert.equal(p.requests.filter(r=>r.url.endsWith('/remove')).length,1);assert.equal(p.selects[1].checked,true);
});
test('bulk deletion timeout is unknown, releases controls and never dispatches the remainder',async()=>{
  const p=page('peers',async r=>r.url.endsWith('/remove')?new Promise(()=>{}):responder()(r));await tick();
  for(const c of p.selects){c.checked=true;await c.fire('change');}await p.get('peer-bulk-delete').fire('click');p.get('peer-delete-ack').checked=true;const work=p.get('peer-delete-confirm').fire('click');await tick();
  const timer=[...p.timers.values()].find(t=>t.ms===30000);assert.ok(timer);timer.fn();await work;
  assert.equal(p.get('peer-delete-cancel').disabled,false);assert.match(text(p.get('peer-delete-list')),/unknown/i);assert.equal(p.requests.filter(r=>r.url.endsWith('/remove')).length,1);
  assert.ok(p.requests.find(r=>r.url.endsWith('/remove')).options.signal.aborted);assert.equal(p.get('email-selection-count').textContent,'2 selected');
});

test('peer readiness preserves readable UTF-8 punctuation after UI edits',async()=>{
  const p=page('peers',responder());await tick();
  assert.equal(p.get('email-readiness').textContent,'Email enabled \u00b7 open a peer or select peers to send');
  assert.equal(p.readiness[0].textContent,'alice@example.test');
});

test('peer detail entry opens only recipient review and retains bulk selection on Cancel',async()=>{
  const storage=new Map([['awg-email-selected:/private','["8"]']]);
  const p=page('peers-no-actions',responder(),storage,'?send_peer=7');await tick();await tick();
  const preview=p.requests.find(r=>r.url.endsWith('/preview'));assert.deepEqual(preview.body.clients,['a']);
  assert.equal(p.get('email-peer-context').hidden,false);assert.equal(p.get('email-peer-return').href,'/private/peers/7');
  assert.equal(p.requests.filter(r=>r.url.endsWith('/send')).length,0);await p.get('email-cancel').fire('click');
  assert.equal(p.get('email-send-dialog').open,false);assert.equal(p.selects[1].checked,true);
  assert.equal(p.document.activeElement,p.selects[0],'Cancel returns focus to the reviewed peer without selecting it');
  assert.equal(p.selects[0].checked,false);
});
test('peer detail missing email and unbound states expose scoped recovery links without sending',async()=>{
  const p=page('peers',responder({preview:()=>ok({id:'empty',items:[],skipped:[{client_id:'b',reason:'email_missing'}]})}),new Map(),'?send_peer=8');await tick();await tick();
  assert.equal(p.get('email-peer-edit').hidden,false);assert.equal(p.get('email-peer-edit').href,'/private/peers/8#peer-email');assert.equal(p.get('email-confirm').disabled,true);
  const unbound=page('peers',responder({contacts:()=>ok([])}),new Map(),'?send_peer=7');await tick();await tick();
  assert.equal(unbound.get('email-peer-recovery').hidden,false);assert.equal(unbound.requests.filter(r=>r.url.endsWith('/send')).length,0);
});
test('repeated opening during preview keeps the first peer confirmation usable',async()=>{
  let resolve;const p=page('peers',responder({preview:()=>new Promise(r=>resolve=r)}));await tick();
  const first=p.sends[0].fire('click');await tick();await p.sends[0].fire('click');
  resolve(ok({id:'preview-one',items:[{client_id:'a',name:'Alice',recipient:'alice@example.test'}],skipped:[]}));await first;
  assert.equal(p.requests.filter(r=>r.url.endsWith('/preview')).length,1);assert.equal(p.get('email-confirm').disabled,false);
  assert.equal(p.requests.filter(r=>r.url.endsWith('/send')).length,0);
});
test('peer detail SMTP setup preserves its context and ineligible preview cannot send',async()=>{
  const p=page('peers',responder({settings:()=>ok({...saved,operational:false})}),new Map(),'?send_peer=7');await tick();await tick();
  assert.equal(p.get('email-setup').hidden,false);assert.equal(p.get('email-peer-return').href,'/private/peers/7');await p.get('email-setup-link').fire('click');
  const restored=page('peers',responder({preview:()=>ok({id:'disabled',items:[],skipped:[{client_id:'a',reason:'ineligible'}]})}),p.storage);await tick();await tick();
  assert.deepEqual(restored.requests.find(r=>r.url.endsWith('/preview')).body.clients,['a']);assert.equal(restored.get('email-confirm').disabled,true);assert.match(text(restored.get('email-skipped')),/disabled|expired/i);
});


test('Check SMTP uses current draft and suppresses repeated clicks without submitting mail',async()=>{
 let release;const p=page('settings',responder({check:()=>new Promise(r=>release=r)}));await tick();
 assert.equal(p.requests.filter(r=>r.body).length,0);
 const first=p.get('email-smtp-check').fire('click');await tick();
 await p.get('email-smtp-check').fire('click');
 assert.equal(p.requests.filter(r=>r.body).length,1);
 assert.equal(p.requests.find(r=>r.body).body.draft.host,'smtp.example.test');
 assert.equal(p.requests.find(r=>r.body).body.draft.password_action,'keep');
 assert.equal(p.get('email-smtp-check').disabled,true);
 release(ok({settings_revision:1,settings_changed:false,outcome:'connected',security:'starttls',authenticated:true}));await first;
 assert.match(p.get('email-smtp-result').textContent,/No message was sent/);
 assert.doesNotMatch(p.get('email-smtp-result').textContent,/unconfirmed|unverified|inbox/i);
 await p.get('email-settings-form').fire('input');
 assert.equal(p.get('email-smtp-check').disabled,false);
});

test('disabled saved profile can test an unsaved replacement without Save or browser persistence',async()=>{
 const p=page('settings',responder({settings:()=>ok({...saved,enabled:false,operational:false}),check:()=>ok({outcome:'connected',settings_revision:1,settings_changed:false,security:'starttls',authenticated:true})}));await tick();
 p.get('smtp-host').value='draft.example.test';p.get('smtp-password-action').value='replace';await p.get('smtp-password-action').fire('change');p.get('smtp-password').value='draft-secret';await p.get('email-settings-form').fire('input');
 assert.equal(p.get('email-smtp-check').disabled,false);await p.get('email-smtp-check').fire('click');
 const writes=p.requests.filter(r=>r.body);assert.equal(writes.length,1);assert.ok(writes[0].url.endsWith('/check'));
 assert.equal(writes[0].body.draft.host,'draft.example.test');assert.equal(writes[0].body.draft.password,'draft-secret');assert.equal(writes[0].body.draft.enabled,false);
 assert.equal(p.get('smtp-enabled').checked,false);assert.equal(p.get('smtp-host').value,'draft.example.test');assert.equal(p.get('smtp-password').value,'draft-secret');
 assert.equal(p.storage.size,0);assert.doesNotMatch(p.get('email-smtp-result').textContent,/draft-secret/);
});

test('draft test email confirmation is invalidated by edits and Cancel has no write effect',async()=>{
 const p=page('settings',responder({settings:()=>ok({...saved,enabled:false,operational:false}),test:()=>ok({state:'accepted',recipient:'admin@example.test',settings_revision:1})}));await tick();
 p.get('smtp-password-action').value='clear';p.get('smtp-host').value='first.example.test';await p.get('email-settings-form').fire('input');await p.get('email-test-open').fire('click');
 assert.equal(p.get('email-test-dialog').open,true);await p.get('email-test-cancel').fire('click');assert.equal(p.requests.filter(r=>r.body).length,0);
 await p.get('email-test-open').fire('click');p.get('smtp-host').value='second.example.test';await p.get('email-settings-form').fire('input');await p.get('email-test-confirm').fire('click');assert.equal(p.requests.filter(r=>r.body).length,0);
 await p.get('email-test-cancel').fire('click');await p.get('email-test-open').fire('click');await p.get('email-test-confirm').fire('click');
 const writes=p.requests.filter(r=>r.body);assert.equal(writes.length,1);assert.equal(writes[0].body.draft.host,'second.example.test');assert.equal(writes[0].body.draft.password_action,'clear');
 assert.ok(!('password' in writes[0].body.draft));assert.ok([...p.storage.values()].every(v=>!v.includes('example.test')));
});

test('plaintext draft testing requires acknowledgment and never silently clears retained password',async()=>{
 const p=page('settings',responder({check:()=>ok({outcome:'connected',settings_revision:1,security:'none',authenticated:false})}));await tick();
 p.get('smtp-tls').value='none';await p.get('email-settings-form').fire('change');await p.get('email-smtp-check').fire('click');assert.equal(p.requests.filter(r=>r.body).length,0);
 p.get('smtp-allow-plaintext').checked=true;await p.get('email-smtp-check').fire('click');assert.equal(p.requests.filter(r=>r.body).length,0);assert.equal(p.get('smtp-password-action').value,'keep');
 p.get('smtp-password-action').value='clear';p.get('smtp-authenticate').checked=false;p.get('smtp-username').value='';await p.get('email-smtp-check').fire('click');assert.equal(p.requests.find(r=>r.body).body.draft.password_action,'clear');
});
test('plaintext Save requires explicit acknowledgment and never clears a password implicitly',async()=>{
 const p=page('settings',responder());await tick();p.get('smtp-tls').value='none';await p.get('email-settings-form').fire('change');
 await p.get('email-settings-form').fire('submit');assert.equal(p.requests.filter(r=>r.body).length,0);
 p.get('smtp-allow-plaintext').checked=true;await p.get('email-settings-form').fire('submit');
 const body=p.requests.find(r=>r.body).body;assert.equal(body.allow_plaintext,true);assert.equal(body.password_action,'keep');
});

test('SMTP check truthfully labels stale results and failures and never checks on reload',async()=>{
 let release;const p=page('settings',responder({check:()=>new Promise(r=>release=r)}));await tick();
 const first=p.get('email-smtp-check').fire('click');await tick();
 await p.get('email-settings-form').fire('input');
 release(ok({settings_revision:1,settings_changed:true,outcome:'tls_failed'}));await first;
 assert.match(p.get('email-smtp-result').textContent,/certificate validation failed/);
 assert.match(p.get('email-smtp-result').textContent,/does not validate the new settings/);
 const again=page('settings',responder(),p.storage);await tick();assert.equal(again.requests.filter(r=>r.body).length,0);
});

test('completed SMTP results are invalidated by subsequent edits and reload',async()=>{
 const p=page('settings',responder({check:()=>ok({settings_revision:1,settings_changed:false,outcome:'connected',security:'starttls',authenticated:true})}));await tick();
 await p.get('email-smtp-check').fire('click');assert.match(p.get('email-smtp-result').textContent,/passed/);
 await p.get('email-settings-form').fire('input');assert.doesNotMatch(p.get('email-smtp-result').textContent,/passed/);assert.match(p.get('email-smtp-result').textContent,/again/i);
 await p.get('email-reload').fire('click');await p.get('email-smtp-check').fire('click');assert.match(p.get('email-smtp-result').textContent,/passed/);
 await p.get('email-reload').fire('click');assert.doesNotMatch(p.get('email-smtp-result').textContent,/passed/);
 assert.equal(p.requests.filter(r=>r.body).length,2);
});

test('SMTP result tones distinguish pending, successful and definite failed checks with words',async()=>{
 let release;const p=page('settings',responder({check:()=>new Promise(r=>release=r)}));await tick();
 const first=p.get('email-smtp-check').fire('click');await tick();
 assert.equal(p.get('email-smtp-result').dataset.result,'pending');assert.match(p.get('email-smtp-result').textContent,/Checking/);
 release(ok({settings_revision:1,settings_changed:false,outcome:'connected',security:'starttls',authenticated:true}));await first;
 assert.equal(p.get('email-smtp-result').dataset.result,'success');assert.match(p.get('email-smtp-result').textContent,/passed/);
 for(const outcome of ['tls_failed','authentication_rejected','timeout','unavailable']) {
  const failed=page('settings',responder({check:()=>ok({settings_revision:1,settings_changed:false,outcome})}));await tick();await failed.get('email-smtp-check').fire('click');
  assert.equal(failed.get('email-smtp-result').dataset.result,'failure',outcome);assert.match(failed.get('email-smtp-result').textContent,/failed|rejected|timed out|could not complete/i);
 }
});

test('SMTP success color is cleared by edits, reload and late stale success',async()=>{
 const p=page('settings',responder({check:()=>ok({settings_revision:1,settings_changed:false,outcome:'connected',security:'starttls',authenticated:true})}));await tick();
 await p.get('email-smtp-check').fire('click');await p.get('email-settings-form').fire('input');assert.equal(p.get('email-smtp-result').dataset.result,'stale');
 await p.get('email-smtp-check').fire('click');await p.get('email-reload').fire('click');assert.equal(p.get('email-smtp-result').dataset.result,'stale');
 let release;const late=page('settings',responder({check:()=>new Promise(r=>release=r)}));await tick();const pending=late.get('email-smtp-check').fire('click');await tick();await late.get('email-settings-form').fire('input');
 release(ok({settings_revision:1,settings_changed:true,outcome:'connected',security:'starttls',authenticated:true}));await pending;
 assert.equal(late.get('email-smtp-result').dataset.result,'stale');assert.match(late.get('email-smtp-result').textContent,/does not validate the new settings/);
});

test('lost or unrecognized SMTP check results remain visibly uncertain rather than failed or successful',async()=>{
 for(const check of [()=>Promise.reject(new Error('offline')),()=>({ok:false,json:async()=>({error:'smtp_check_unknown'})}),()=>ok({settings_revision:1,settings_changed:false,outcome:'unexpected'})]) {
  const p=page('settings',responder({check}));await tick();await p.get('email-smtp-check').fire('click');
  assert.equal(p.get('email-smtp-result').dataset.result,'unknown');assert.match(p.get('email-smtp-result').textContent,/unknown|unavailable/i);assert.doesNotMatch(p.get('email-smtp-result').textContent,/passed/);
  assert.equal(p.get('email-smtp-check').disabled,false);assert.equal(p.requests.filter(r=>r.body).length,1);
 }
});

test('unclassified SMTP failure includes security without inventing a failed stage',async()=>{
 const p=page('settings',responder({check:()=>ok({settings_revision:1,settings_changed:false,outcome:'unavailable'})}));await tick();await p.get('email-smtp-check').fire('click');
 assert.match(p.get('email-smtp-result').textContent,/connection, security or authentication/i);
 assert.doesNotMatch(p.get('email-smtp-result').textContent,/authentication completed|connection check passed/i);
});

test('draft Keep cannot test another server or identity without explicit replacement or clear',async()=>{
 for(const [id,value] of [['smtp-host','other.example.test'],['smtp-port','465'],['smtp-tls','implicit'],['smtp-username','other-user']]){
  const p=page('settings',responder());await tick();p.get(id).value=value;await p.get('email-settings-form').fire('input');
  await p.get('email-smtp-check').fire('click');await p.get('email-test-open').fire('click');
  assert.equal(p.requests.filter(r=>r.body).length,0,id);assert.equal(p.get('email-test-dialog').open,false);
  assert.match(p.get('email-settings-status').textContent,/replace.*clear/i);
  assert.equal(p.get('smtp-password-action').value,'keep');assert.equal(p.get('smtp-password').value,'');
 }
});

test('unknown test result never becomes sent and repeated confirmation only reads its status',async()=>{
 const result={state:'unknown',recipient:'admin@example.test',settings_revision:1,error_code:'acceptance_unknown'};
 const normal=responder({test:()=>ok(result)});const p=page('settings',r=>r.url.includes('/settings/test/')?ok(result):normal(r));await tick();
 await p.get('email-test-open').fire('click');await p.get('email-test-confirm').fire('click');await p.get('email-test-confirm').fire('click');await p.get('email-test-check').fire('click');
 assert.equal(p.requests.filter(r=>r.body).length,1);assert.match(p.get('email-test-status').textContent,/unknown/i);
 assert.doesNotMatch(p.get('email-test-status').textContent,/sent - accepted/i);assert.equal(p.get('email-test-open').disabled,true);
});

test('definite draft rejection permits a corrected explicit test without uncertain-send recovery',async()=>{
 let calls=0;const p=page('settings',responder({test:()=>++calls===1?{ok:false,json:async()=>({error:'draft_password_scope_changed'})}:ok({state:'accepted',recipient:'admin@example.test',settings_revision:1})}));await tick();
 await p.get('email-test-open').fire('click');await p.get('email-test-confirm').fire('click');
 assert.equal(p.get('email-test-open').disabled,false);assert.equal(p.storage.size,0);assert.match(p.get('email-test-status').textContent,/no message was submitted/i);
 assert.doesNotMatch(p.get('email-test-status').textContent,/may already|unknown/i);
 await p.get('email-test-cancel').fire('click');p.get('smtp-password-action').value='replace';await p.get('smtp-password-action').fire('change');p.get('smtp-password').value='replacement';
 await p.get('email-test-open').fire('click');await p.get('email-test-confirm').fire('click');
 assert.equal(calls,2);assert.match(p.get('email-test-status').textContent,/sent.*accepted/i);
});
