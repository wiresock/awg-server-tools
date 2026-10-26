const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function element(id = '') {
  return {id, value: '', textContent: '', hidden: true, disabled: false, checked: false, dataset: {}, children: [], listeners: {},
    addEventListener(name, fn) { (this.listeners[name] ||= []).push(fn); },
    async fire(name) { for (const fn of this.listeners[name] || []) await fn({target: this}); },
    append(...items) { this.children.push(...items); }, replaceChildren(...items) { this.children = items; },
    setAttribute(name, value) { this[name] = value; }, click() {}, removeAttribute(name) { delete this[name]; }
  };
}
function page(kind, responder, confirmResult = () => true) {
  const elements = new Map(); const get = id => { if (!elements.has(id)) elements.set(id, element(id)); return elements.get(id); };
  const formats = ['conf', 'qr', 'vpn-uri'].map(format => { const e = element(); e.dataset.format = format; e.checked = format === 'conf'; return e; });
  const linkOption = element(); const requests = []; const revoked = []; const replacements = []; const confirmations = [];
  get('admin-base').value = '/private'; get('admin-csrf').value = 'admin-csrf'; get('bootstrap').value = 'bootstrap'; get('mode').value = 'direct';
  const document = {getElementById: get, createElement: element,
    querySelector: () => linkOption,
    querySelectorAll: selector => selector.endsWith(':checked') ? formats.filter(f => f.checked) : formats};
  class BrowserURL extends URL { static createObjectURL() { return 'blob:fixture'; } static revokeObjectURL(value) { revoked.push(value); } }
  const context = vm.createContext({document, URL: BrowserURL, URLSearchParams, Set, location: {hash: '#test-token', pathname: '/share/delivery/', href: 'https://download.example.test/share/delivery/#test-token', search: ''},
    history: {replaceState(...args) { replacements.push(args); }}, confirm: message => { confirmations.push(message); return confirmResult(message); }, setTimeout: fn => fn(),
    fetch: async (url, options) => { const request = {url: String(url), options, body: options.body ? JSON.parse(options.body) : null}; requests.push(request); return responder(request); }});
  vm.runInContext(fs.readFileSync(path.join(__dirname, `../amneziawg-web/src/web/delivery${kind === 'admin' ? '_admin' : ''}.js`), 'utf8'), context);
  return {get, formats, requests, revoked, replacements, confirmations, context};
}
const ok = value => ({ok: true, json: async () => value, blob: async () => ({})});
const tick = () => new Promise(resolve => setImmediate(resolve));

test('public landing clears fragment without fetching; explicit redeem is sent once even on repeated action', async () => {
  let resolve; const p = page('public', () => new Promise(r => { resolve = r; }));
  assert.equal(p.requests.length, 0); assert.equal(p.replacements[0][2], '/share/delivery/');
  const first = p.get('retrieve').fire('click'); const repeat = p.get('retrieve').fire('click');
  assert.equal(p.requests.length, 1); assert.deepEqual(p.requests[0].body, {token: 'test-token'});
  resolve(ok({csrf: 'session-csrf'})); await Promise.all([first, repeat]);
  assert.equal(p.get('exports').hidden, false); assert.equal(p.requests[0].options.cache, 'no-store');
});
test('interrupted redemption requires reissue and never silently replays the token', async () => {
  const p = page('public', async () => { throw new Error('connection lost'); });
  await p.get('retrieve').fire('click'); await p.get('retrieve').fire('click');
  assert.equal(p.requests.length, 1); assert.match(p.get('status').textContent, /new link/i);
});
test('one session exports conf then QR and clears the old QR if a later retrieval fails', async () => {
  let count = 0; const p = page('public', async () => ++count === 1 ? ok({csrf: 'session-csrf'}) : count === 4 ? {ok: false} : ok({}));
  await p.get('retrieve').fire('click'); await p.formats[0].fire('click'); await p.formats[1].fire('click');
  assert.equal(p.get('qr').hidden, false); assert.equal(p.requests[2].options.headers['X-Delivery-CSRF'], 'session-csrf');
  await p.formats[1].fire('click'); assert.equal(p.get('qr').hidden, true); assert.ok(p.revoked.includes('blob:fixture'));
});

const contact = {id: 'client', peer_id: 7, managed_name: '<phone>', last_public_key: 'public-key', email: 'person@example.test', binding_version: 2, retired_at: null};
function adminResponder(overrides = {}) {
  return async request => {
    const route = request.url.split('/').pop(); if (overrides[route]) return overrides[route](request);
    if (route === 'settings') return ok({enabled: true, operational: true, link_enabled: true});
    if (route === 'contacts') return ok([contact]); if (route === 'jobs') return ok([]);
    if (route === 'preview') return ok({id: 'preview-one', mode: 'direct', formats: ['conf'], items: [{name: '<phone>', recipient: contact.email, version: 2}]});
    return ok(['job']);
  };
}
function selectContact(p) { const check = p.get('contacts').children[0].children[0].children[0]; check.checked = true; return check.fire('change'); }

test('correcting an invalid email clears the previous error after saving', async () => {
  let saves = 0;
  const p = page('admin', adminResponder({contact: () => ++saves === 1 ? {ok:false, json:async () => ({error:'invalid_email'})} : ok({})}));
  await tick();
  const cell = p.get('contacts').children[0].children[2];
  cell.children[0].value = 'bad@@example.test';
  await cell.children.find(e => e.textContent === 'Save email').fire('click');
  assert.equal(p.get('status').textContent, 'invalid_email');
  cell.children[0].value = 'corrected@example.test';
  await cell.children.find(e => e.textContent === 'Save email').fire('click');
  assert.equal(p.get('status').textContent, '');
  assert.equal(saves, 2);
});

test('preview identifies skipped clients by visible name with an ID fallback', async () => {
  const p = page('admin', adminResponder({preview: () => ok({id:'preview', mode:'direct', formats:['conf'], items:[], skipped:[{client_id:contact.id,reason:'ineligible'},{client_id:'unknown-client',reason:'unbound'}]})}));
  await tick(); await selectContact(p); await p.get('preview').fire('click');
  assert.match(p.get('preview-result').textContent, /Skipped <phone>: ineligible/);
  assert.match(p.get('preview-result').textContent, /Skipped unknown-client: unbound/);
});

test('rebind confirmation identifies both clients, frozen recipient, keys and verified target address', async () => {
  const old = {...contact, id: 'retained', peer_id: null};
  const target = {...contact, id: 'target', managed_name: 'new phone', last_public_key: 'new-key', email: null};
  const p = page('admin', adminResponder({contacts: () => ok([old,target]), 'rebind-preview': () => ok({old,target,target_addresses:['10.0.0.3/32','fd42::3/128'], old_addresses:null})}));
  await tick();
  const cell = p.get('contacts').children[0].children[3];
  const selector = cell.children.find(e => e.id === 'select'); selector.value = target.id;
  await cell.children.find(e => e.textContent === 'Review rebind').fire('click');
  const message = p.confirmations[0];
  for (const expected of ['retained','target','person@example.test','public-key','new-key','10.0.0.3/32','fd42::3/128','unavailable']) assert.ok(message.includes(expected), 'confirmation must show ' + expected);
  const sent = p.requests.find(r => r.url.endsWith('/rebind'));
  assert.equal(sent.body.client_id,'retained'); assert.equal(sent.body.target_id,'target');
});

test('cancelling rebind reloads versions so the next review can succeed', async () => {
  const old = {...contact, id:'retained', peer_id:null};
  let version = 1;
  const target = () => ({...contact, id:'target', email:null, binding_version:version});
  const p = page('admin', adminResponder({contacts:() => ok([old,target()]), 'rebind-preview':request => {
    if (request.body.target_version !== version) return {ok:false,json:async () => ({error:'changed'})};
    version++;
    return ok({old,target:target(),target_addresses:['10.0.0.3/32']});
  }}), () => false);
  await tick();
  for (let attempt=0; attempt<2; attempt++) {
    const cell = p.get('contacts').children[0].children[3];
    cell.children.find(e => e.id === 'select').value='target';
    await cell.children.find(e => e.textContent === 'Review rebind').fire('click');
  }
  assert.equal(p.confirmations.length,2);
  assert.equal(p.get('status').textContent,'');
  assert.equal(p.requests.filter(r => r.url.endsWith('/rebind')).length,0);
});
test('admin sends only after preview and explicit confirmation; interrupted confirmation retries same request ID', async () => {
  let sends = 0; const p = page('admin', adminResponder({send: async () => { if (++sends === 1) throw new Error('connection lost'); return ok(['job']); }}));
  await tick(); await selectContact(p); await p.get('preview').fire('click');
  assert.equal(p.requests.filter(r => r.url.endsWith('/send')).length, 0);
  assert.match(p.get('preview-result').textContent, /person@example.test/);
  await p.get('confirm').fire('click'); await p.get('confirm').fire('click');
  const sent = p.requests.filter(r => r.url.endsWith('/send')); assert.equal(sent.length, 2);
  assert.deepEqual(sent[0].body, sent[1].body); assert.equal(sent[0].body.request_id, 'preview-one');
});
test('changing selection while preview is pending cannot expose a stale confirmation', async () => {
  let resolve; const p = page('admin', adminResponder({preview: () => new Promise(r => { resolve = r; })}));
  await tick(); await selectContact(p); const pending = p.get('preview').fire('click');
  const check = p.get('contacts').children[0].children[0].children[0]; check.checked = false; await check.fire('change');
  resolve(ok({id: 'stale', mode: 'direct', formats: ['conf'], items: []})); await pending;
  assert.equal(p.get('confirm').hidden, true); await p.get('confirm').fire('click'); assert.equal(p.requests.filter(r => r.url.endsWith('/send')).length, 0);
});
test('changing mode or formats invalidates displayed confirmation', async () => {
  const p = page('admin', adminResponder()); await tick(); await selectContact(p); await p.get('preview').fire('click');
  p.get('mode').value = 'link'; await p.get('mode').fire('change'); assert.equal(p.get('confirm').hidden, true);
  await p.get('preview').fire('click'); await p.formats[1].fire('change'); assert.equal(p.get('confirm').hidden, true);
});
test('repeated confirmation while send is pending makes only one request', async () => {
  let resolve; const p = page('admin', adminResponder({send: () => new Promise(r => { resolve = r; })}));
  await tick(); await selectContact(p); await p.get('preview').fire('click');
  const first = p.get('confirm').fire('click'); const repeat = p.get('confirm').fire('click');
  assert.equal(p.requests.filter(r => r.url.endsWith('/send')).length, 1);
  resolve(ok(['job'])); await Promise.all([first, repeat]);
});
test('public repeated or overlapping exports use one request at a time', async () => {
  let resolve; let count = 0;
  const p = page('public', () => ++count === 1 ? ok({csrf: 'session'}) : new Promise(r => { resolve = r; }));
  await p.get('retrieve').fire('click'); const first = p.formats[0].fire('click');
  const repeat = p.formats[0].fire('click'); const overlap = p.formats[1].fire('click');
  assert.equal(p.requests.length, 2); resolve(ok({})); await Promise.all([first, repeat, overlap]);
});
