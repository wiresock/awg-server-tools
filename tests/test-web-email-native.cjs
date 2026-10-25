const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const tick = () => new Promise(resolve => setImmediate(resolve));
const ok = value => ({ok:true,json:async()=>value});
const saved = {revision:1,source:'panel',enabled:true,operational:true,storage_ready:true,host:'smtp.example.test',port:587,tls:'starttls',authenticate:true,username:'mailer',credentials_present:true,from:'vpn@example.test',reply_to:null,public_base:'https://download.example.test',link_enabled:true,ttl_seconds:86400};
const contacts=[{id:'a',peer_id:7,managed_name:'Alice <phone>',email:'alice@example.test',binding_version:2,retired_at:null},{id:'b',peer_id:8,managed_name:'Bob',email:null,binding_version:1,retired_at:null}];
function page(kind,responder,storage=new Map(),search="") {
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
  const sends=[7,8].map(id=>{const e=element();e.dataset.emailSend=String(id);return e;});
  const edits=[7,8].map(id=>{const e=element();e.dataset.emailEdit=String(id);return e;});
  const readiness=[7,8].map(id=>{const e=element();e.dataset.emailReadiness=String(id);return e;});
  const formats=['conf','qr','vpn-uri'].map(format=>{const e=element();e.dataset.emailFormat=format;e.checked=format==='conf';return e;});
  get('email-base').value='/private';get('email-csrf').value='csrf';get('email-mode').value='direct';get('email-ttl').value='86400';
  get('smtp-password-action').value='keep';get('smtp-password').value='';get('email-test-recipient').value='admin@example.test';
  document.getElementById=id=>id===(kind==='settings'?'peer-email-tools':'email-settings-form')?null:get(id);
  document.createElement=element;
  document.querySelectorAll=selector=>selector.includes('email-select')?selects:selector.includes('email-send')?sends:selector.includes('email-edit')?edits:selector.includes('email-readiness')?readiness:selector.includes('email-format')?(selector.includes(':checked')?formats.filter(e=>e.checked):formats):[];
  const window={listeners:{},addEventListener(k,fn){(this.listeners[k] ||= []).push(fn);}};
  const context=vm.createContext({document,window,Set,Map,URLSearchParams,AbortController,setTimeout:(fn,ms)=>{timers.set(++timerId,{fn,ms});return timerId;},clearTimeout:id=>timers.delete(id),location:{search,pathname:'/private/'},
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
  if(key==='preview')return ok({id:'preview-one',settings_revision:1,mode:'direct',formats:['conf'],ttl_seconds:86400,items:[{client_id:'a',name:contacts[0].managed_name,recipient:contacts[0].email}],skipped:[{client_id:'b',reason:'email_missing'}]});
  return ok({});
};
const text=e=>[e.textContent,...e.children.map(text)].join(' ');

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
test('test mail requires separate confirmation and reuses request identity on uncertain response',async()=>{
  let calls=0;const p=page('settings',responder({test:r=>{calls++;return calls===1?Promise.reject(new Error('offline')):ok({state:'accepted',settings_revision:1,settings_changed:false});}}));await tick();
  await p.get('email-test-open').fire('click');assert.equal(p.requests.filter(r=>r.body).length,0);
  assert.equal(p.get('email-test-dialog').open,true);await p.get('email-test-confirm').fire('click');
  await p.get('email-test-confirm').fire('click');const sends=p.requests.filter(r=>r.body);
  assert.equal(sends.length,2);assert.equal(sends[0].body.request_id,sends[1].body.request_id);
  assert.match(p.get('email-test-status').textContent,/accepted.*delivery.*unconfirmed/i);
});
test('unsaved settings and unavailable private storage have actionable states',async()=>{
  const p=page('settings',responder({settings:()=>ok({...saved,storage_ready:false})}));await tick();
  assert.equal(p.get('email-save').disabled,true);assert.match(p.get('email-storage-notice').textContent,/private|permission/i);
  await p.get('email-settings-form').fire('input');await p.get('email-test-open').fire('click');
  assert.equal(p.get('email-test-dialog').open,false);
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
  assert.equal(p.timers.size,1);const timer=[...p.timers.values()][0];assert.equal(timer.ms,30000);timer.fn();await work;
  assert.equal(p.get('peer-delete-cancel').disabled,false);assert.match(text(p.get('peer-delete-list')),/unknown/i);assert.equal(p.requests.filter(r=>r.url.endsWith('/remove')).length,1);
  assert.ok(p.requests.find(r=>r.url.endsWith('/remove')).options.signal.aborted);assert.equal(p.get('email-selection-count').textContent,'2 selected');
});

test('peer readiness preserves readable UTF-8 punctuation after UI edits',async()=>{
  const p=page('peers',responder());await tick();
  assert.equal(p.get('email-readiness').textContent,'Email enabled \u00b7 choose Actions or select peers to send');
  assert.equal(p.readiness[0].textContent,'alice@example.test \u00b7 checked again before sending');
});

test('peer detail entry opens only recipient review and retains bulk selection on Cancel',async()=>{
  const storage=new Map([['awg-email-selected:/private','["8"]']]);
  const p=page('peers',responder(),storage,'?send_peer=7');await tick();await tick();
  const preview=p.requests.find(r=>r.url.endsWith('/preview'));assert.deepEqual(preview.body.clients,['a']);
  assert.equal(p.get('email-peer-context').hidden,false);assert.equal(p.get('email-peer-return').href,'/private/peers/7');
  assert.equal(p.requests.filter(r=>r.url.endsWith('/send')).length,0);await p.get('email-cancel').fire('click');
  assert.equal(p.get('email-send-dialog').open,false);assert.equal(p.selects[1].checked,true);
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


test('Check SMTP is explicit, saved-only and suppresses repeated clicks without submitting mail',async()=>{
 let release;const p=page('settings',responder({check:()=>new Promise(r=>release=r)}));await tick();
 assert.equal(p.requests.filter(r=>r.body).length,0);
 const first=p.get('email-smtp-check').fire('click');await tick();
 await p.get('email-smtp-check').fire('click');
 assert.equal(p.requests.filter(r=>r.body).length,1);
 assert.deepEqual(JSON.parse(JSON.stringify(p.requests.find(r=>r.body).body)),{revision:1});
 assert.equal(p.get('email-smtp-check').disabled,true);
 release(ok({settings_revision:1,settings_changed:false,outcome:'connected',security:'starttls',authenticated:true}));await first;
 assert.match(p.get('email-smtp-result').textContent,/No message was sent/);
 assert.match(p.get('email-smtp-result').textContent,/does not prove/i);
 await p.get('email-settings-form').fire('input');
 assert.equal(p.get('email-smtp-check').disabled,true);
 await p.get('email-smtp-check').fire('click');assert.equal(p.requests.filter(r=>r.body).length,1);
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

test('unclassified SMTP failure includes security without inventing a failed stage',async()=>{
 const p=page('settings',responder({check:()=>ok({settings_revision:1,settings_changed:false,outcome:'unavailable'})}));await tick();await p.get('email-smtp-check').fire('click');
 assert.match(p.get('email-smtp-result').textContent,/connection, security or authentication/i);
 assert.doesNotMatch(p.get('email-smtp-result').textContent,/authentication completed|connection check passed/i);
});
