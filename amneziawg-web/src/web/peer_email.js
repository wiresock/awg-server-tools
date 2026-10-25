(() => {
  'use strict';
  const {$,base,api,node,errorText,statusText,dialog,close,wireDialog}=window.AwgEmail;
  if(!$('peer-email-tools'))return;
  const checks=[...document.querySelectorAll('[data-email-select]')], formats=[...document.querySelectorAll('[data-email-format]')];
  const deleted=new Set();let deleting=false,deleteDone=false,deleteInterrupted=false,deleteItems=[];
  const liveChecks=()=>checks.filter(c=>!deleted.has(c.dataset.emailSelect));
  const selected=new Set(),storageKey='awg-email-selected:'+base;
  const intentKey='awg-email-intent:'+base;
  const pendingKey='awg-email-pending:'+base;let pendingId=null,pendingPreview=null;
  try {const id=sessionStorage.getItem(pendingKey);if(id && id.length<=128)pendingId=id;}catch(_){}
  let contacts=[],settings=null,preview=null,sendIds=[],generation=0,sending=false,previewBusy=false,loading=0,editing=null,editBusy=false;
  const report=text=>{$('email-peer-status').textContent=text;};
  function rememberPending(id) {
    pendingId=id;$('email-pending-check').hidden=!id;
    try {id?sessionStorage.setItem(pendingKey,id):sessionStorage.removeItem(pendingKey);}catch(_){}
  }
  try {const stored=JSON.parse(sessionStorage.getItem(storageKey)||'[]');for(const id of stored)if(checks.some(c=>c.dataset.emailSelect===String(id)))selected.add(String(id));}catch(_){}
  function selection() {
    for(const c of checks){c.checked=selected.has(c.dataset.emailSelect);c.disabled=deleting || deleted.has(c.dataset.emailSelect);}
    $('email-selection-count').textContent=selected.size+' selected';$('email-bulk-send').disabled=selected.size===0 || deleting;$('peer-bulk-delete').disabled=selected.size===0 || deleting;
    $('email-select-all').disabled=deleting;$('email-clear-selection').disabled=deleting;
    $('email-select-all').checked=liveChecks().length>0 && selected.size===liveChecks().length;
    try {sessionStorage.setItem(storageKey,JSON.stringify([...selected]));}catch(_){}
  }
  function invalidate() {generation++;preview=null;$('email-confirm').disabled=true;$('email-recipients').replaceChildren();$('email-skipped').replaceChildren();}
  const contactFor=id=>contacts.find(c=>String(c.peer_id)===String(id) && c.retired_at===null);
  function ready() {
    for(const e of document.querySelectorAll('[data-email-readiness]')) {
      const c=contactFor(e.dataset.emailReadiness);
      e.textContent=!c?'No current contact binding':!c.email?'Add email address':c.email+' · checked again before sending';
    }
    $('email-readiness').textContent=settings?.operational?'Email enabled · open a peer or select peers to send':'Email is not ready. Open Settings to configure it.';
  }
  async function jobs() {
    const rows=await api('jobs');const list=$('email-activity');list.replaceChildren();
    if(!rows.length){list.append(node('p','No email submissions yet.'));return;}
    for(const j of rows.slice(0,12)){const p=node('p');const c=contacts.find(c=>c.id===j.client_id);p.append(node('strong',c?.managed_name || 'Client'),node('span',' · '+j.recipient+' — '+statusText(j)));list.append(p);}
  }
  async function load() {
    const current=++loading;
    try {
      const [s,c]=await Promise.all([api('settings'),api('contacts')]);if(current!==loading)return;
      settings=s;contacts=c;ready();selection();await jobs();
    } catch(e){report(errorText(e));}
  }
  for(const c of checks)c.addEventListener('change',()=>{
    if(deleting)return;
    if(c.checked && selected.size>=50){c.checked=false;report('Select at most 50 peers.');return;}
    c.checked?selected.add(c.dataset.emailSelect):selected.delete(c.dataset.emailSelect);selection();
  });
  $('email-select-all').addEventListener('change',()=>{if(deleting)return;selected.clear();if($('email-select-all').checked)for(const c of liveChecks().slice(0,50))selected.add(c.dataset.emailSelect);selection();});
  $('email-clear-selection').addEventListener('click',()=>{if(deleting)return;selected.clear();selection();});
  wireDialog('peer-delete-dialog');
  $('peer-bulk-delete').addEventListener('click',()=>{
    if(deleting || !selected.size)return;
    deleteItems=liveChecks().filter(c=>selected.has(c.dataset.emailSelect)).map(c=>({id:c.dataset.emailSelect,key:c.dataset.peerKey,name:contactFor(c.dataset.emailSelect)?.managed_name || c.dataset.peerName || 'Selected peer',check:c}));
    if(!deleteItems.length)return;
    deleteDone=false;deleteInterrupted=false;$('peer-delete-ack').checked=false;$('peer-delete-ack').disabled=false;
    $('peer-delete-confirm').disabled=true;$('peer-delete-cancel').disabled=false;$('peer-delete-cancel').textContent='Cancel';
    $('peer-delete-title').textContent='Delete '+deleteItems.length+' selected peer'+(deleteItems.length===1?'':'s')+'?';
    $('peer-delete-status').textContent='Nothing will be deleted until you acknowledge and confirm.';
    $('peer-delete-list').replaceChildren(...deleteItems.map(i=>node('p',i.name)));
    dialog('peer-delete-dialog',$('peer-bulk-delete'));$('peer-delete-cancel').focus();
  });
  $('peer-delete-ack').addEventListener('change',()=>{$('peer-delete-confirm').disabled=deleting || deleteDone || !$('peer-delete-ack').checked;});
  function stopDelete() {deleteInterrupted=true;$('peer-delete-status').textContent='Stopping remaining requests. The current removal may still complete; wait for its result or the 30-second timeout.';}
  $('peer-delete-cancel').addEventListener('click',()=>{if(deleting)stopDelete();else close('peer-delete-dialog');});
  $('peer-delete-dialog').addEventListener('cancel',event=>{if(deleting){event.preventDefault();stopDelete();}});
  $('peer-delete-confirm').addEventListener('click',async()=>{
    if(deleting || deleteDone || !deleteItems.length || !$('peer-delete-ack').checked)return;
    deleting=true;$('peer-delete-confirm').disabled=true;$('peer-delete-ack').disabled=true;$('peer-delete-cancel').disabled=false;$('peer-delete-cancel').textContent='Stop remaining';selection();
    $('peer-delete-list').replaceChildren();let completed=0,failed=0;
    for(const item of deleteItems) {
      if(deleteInterrupted){$('peer-delete-list').append(node('p',item.name+' — Not attempted after stop or navigation.'));failed++;continue;}
      $('peer-delete-status').textContent='Removing '+item.name+'…';let result,removed=false;
      if(!item.key){result='Identity unavailable. Reload and review before retrying.';}
      else {const controller=new AbortController();let timer;
      try {
        const request=(async()=>{const response=await fetch(base+'/api/admin/users/'+encodeURIComponent(item.id)+'/remove',{method:'POST',credentials:'same-origin',cache:'no-store',signal:controller.signal,headers:{'Content-Type':'application/json','X-CSRF-Token':$('email-csrf').value},body:JSON.stringify({expected_public_key_sha256:item.key})});
          if(response.ok && (await response.json()).ok!==true)throw new Error();return response;})();
        const response=await Promise.race([request,new Promise((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(new Error('timeout'));},30000);})]);
        if(response.status===404){removed=true;result='No longer present in the current peer list.';}
        else if(response.ok){removed=true;result='Deleted.';}
        else result=response.status===409?'Changed or busy. Reload and review before retrying.':response.status===400?'Cannot remove this peer through managed client deletion. Open Peer details.':response.status===401 || response.status===403?'Session or authorization changed. Sign in and review again.':'Removal failed; it may be partially complete. Reload and review before retrying.';
      }catch(_){deleteInterrupted=true;result='Outcome unknown. Reload and check this peer before retrying; no automatic retry.';}finally{clearTimeout(timer);}}
      if(removed){completed++;selected.delete(item.id);deleted.add(item.id);item.check.closest('tr')?.remove();}else failed++;
      $('peer-delete-list').append(node('p',item.name+' — '+result));selection();
    }
    deleting=false;deleteDone=true;selection();$('peer-delete-cancel').disabled=false;$('peer-delete-cancel').textContent='Close';
    $('peer-delete-status').textContent=completed+' removed or already absent; '+failed+' need review. Failed selections were kept.';
    report($('peer-delete-status').textContent);$('peer-delete-cancel').focus();
    try{await jobs();}catch(_){}
  });
  wireDialog('email-send-dialog');wireDialog('email-edit-dialog');
  $('email-send-dialog').addEventListener('close',()=>{invalidate();previewBusy=false;});
  $('email-cancel').addEventListener('click',()=>close('email-send-dialog'));
  function listRecipients(result) {
    const recipients=$('email-recipients'),skipped=$('email-skipped');recipients.replaceChildren();skipped.replaceChildren();
    for(const i of result.items){const p=node('p');p.append(node('strong',i.name),node('span',' → '+i.recipient));recipients.append(p);}
    for(const i of result.skipped||[]){const c=contacts.find(c=>c.id===i.client_id);skipped.append(node('p',(c?.managed_name || 'Selected peer')+' — '+errorText(i.reason)));}
    for(const id of sendIds.filter(id=>!contactFor(id))) {
      const name=checks.find(c=>c.dataset.emailSelect===id)?.dataset.peerName || 'Selected peer';
      skipped.append(node('p',name+' — No current contact binding. Review contact recovery in Settings.'));
    }
    if(!result.items.length)recipients.append(node('p','No eligible recipients. Add an email address or review the skipped peers.'));
  }
  async function refreshPreview() {
    if(sending || pendingId || previewBusy || !settings?.operational)return;
    invalidate();const current=generation;previewBusy=true;$('email-review').disabled=true;$('email-send-status').textContent='Checking current configurations and recipients…';
    try {
      const clients=sendIds.map(contactFor).filter(Boolean).map(c=>c.id);
      if(!clients.length){listRecipients({items:[],skipped:[]});$('email-send-status').textContent='No current contact bindings. Edit email or review contact recovery in Settings.';return;}
      const result=await api('preview',{clients,mode:$('email-mode').value,formats:formats.filter(e=>e.checked).map(e=>e.dataset.emailFormat),ttl_seconds:Number($('email-ttl').value)});
      if(current!==generation || !$('email-send-dialog').open)return;
      preview=result;listRecipients(result);$('email-confirm').disabled=!result.items.length;
      $('email-confirm').textContent='Queue email to '+result.items.length+' recipient'+(result.items.length===1?'':'s');
      $('email-send-status').textContent='Check each recipient. Nothing is sent until you confirm.';
    }catch(e){if(current===generation)$('email-send-status').textContent=errorText(e);}
    finally {previewBusy=false;$('email-review').disabled=sending;}
  }
  async function openSend(ids,trigger) {
    if(sending || deleting || previewBusy)return;sendIds=[...ids];invalidate();
    const single=sendIds.length===1 && checks.some(c=>c.dataset.emailSelect===sendIds[0]);
    $('email-peer-context').hidden=!single || !!pendingId;
    $('email-peer-edit').hidden=true;$('email-peer-recovery').hidden=true;
    if(single && !pendingId) {
      const c=contactFor(sendIds[0]);
      $('email-peer-return').href=base+'/peers/'+encodeURIComponent(sendIds[0]);
      $('email-peer-edit').href=base+'/peers/'+encodeURIComponent(sendIds[0])+'#peer-email';
      $('email-peer-edit').hidden=!c || !!c.email;
      $('email-peer-recovery').hidden=!!c;
    }
    $('email-new-review').hidden=!pendingId;
    if(pendingId) {
      $('email-setup').hidden=true;$('email-options').hidden=true;
      if(pendingPreview)listRecipients(pendingPreview);
      $('email-send-status').textContent='An earlier confirmed request needs checking. This uses its original recipients and request identity; it may finish queuing that same request.';
      $('email-confirm').textContent='Check previous request';$('email-confirm').disabled=false;
      $('email-cancel').textContent='Close';dialog('email-send-dialog',trigger);return;
    }
    $('email-cancel').textContent='Cancel';
    $('email-setup').hidden=!!settings?.operational;$('email-options').hidden=!settings?.operational;
    $('email-send-status').textContent='';$('email-confirm').textContent='Queue emails';
    $('email-link-option').disabled=!settings?.link_enabled;
    if(!settings?.link_enabled)$('email-mode').value='direct';
    $('email-ttl').value=String(settings?.ttl_seconds || 86400);$('email-ttl-label').hidden=$('email-mode').value!=='link';
    dialog('email-send-dialog',trigger);
    if(settings?.operational)await refreshPreview();
  }
  for(const b of document.querySelectorAll('[data-email-send]'))b.addEventListener('click',()=>openSend([b.dataset.emailSend],b));
  $('email-bulk-send').addEventListener('click',()=>{if(selected.size)return openSend(selected,$('email-bulk-send'));});
  $('email-setup-link').addEventListener('click',()=>{try{sessionStorage.setItem(intentKey,JSON.stringify(sendIds));}catch(_){}});
  const changed=()=>{if(pendingId)return;invalidate();$('email-ttl-label').hidden=$('email-mode').value!=='link';$('email-send-status').textContent='Options changed. Review recipients again before sending.';};
  $('email-mode').addEventListener('change',changed);$('email-ttl').addEventListener('input',changed);for(const f of formats)f.addEventListener('change',changed);
  $('email-review').addEventListener('click',refreshPreview);
  $('email-confirm').addEventListener('click',async()=>{
    if((!preview && !pendingId) || sending)return;
    const id=pendingId || preview.id;if(!pendingId)pendingPreview=preview;
    rememberPending(id);sending=true;$('email-options').hidden=true;$('email-confirm').disabled=true;$('email-review').disabled=true;$('email-cancel').textContent='Close';
    $('email-send-status').textContent='Queuing the confirmed recipients…';
    try {await api('send',{preview_id:id,request_id:id});rememberPending(null);pendingPreview=null;report('Queued. Refresh activity to check progress.');close('email-send-dialog');try{await jobs();}catch(_){report('Request confirmed. Refresh activity when the connection is restored.');}}
    catch(e){$('email-send-status').textContent=errorText(e)+' Check this same request before starting another.';$('email-new-review').hidden=false;$('email-confirm').textContent='Check previous request';}
    finally {sending=false;$('email-confirm').disabled=!pendingId && !preview;$('email-review').disabled=!!pendingId;}
  });
  $('email-pending-check').addEventListener('click',()=>openSend([],$('email-pending-check')));
  $('email-new-review').addEventListener('click',async()=>{
    if(sending || !confirm('The previous request may already have queued or sent mail. Starting a new review may produce duplicates. Check recent activity first. Start a separate review?'))return;
    rememberPending(null);pendingPreview=null;await openSend(sendIds,$('email-pending-check'));
  });
  for(const b of document.querySelectorAll('[data-email-edit]'))b.addEventListener('click',()=>{
    editing=contactFor(b.dataset.emailEdit);if(!editing){report('No current contact binding. Open Settings → Contact recovery.');return;}
    $('email-edit-title').textContent='Email for '+editing.managed_name;$('email-edit-address').value=editing.email || '';$('email-edit-status').textContent='';dialog('email-edit-dialog',b);
  });
  $('email-edit-cancel').addEventListener('click',()=>close('email-edit-dialog'));
  $('email-edit-form').addEventListener('submit',async event=>{
    event.preventDefault();if(!editing || editBusy || !$('email-edit-form').reportValidity())return;
    editBusy=true;$('email-edit-save').disabled=true;
    try {await api('contact',{client_id:editing.id,version:editing.binding_version,email:$('email-edit-address').value.trim() || null});close('email-edit-dialog');report('Email saved. No message was sent. Previous queued sends and links were revoked.');await load();}
    catch(e){$('email-edit-status').textContent=errorText(e);}
    finally {editBusy=false;$('email-edit-save').disabled=false;}
  });
  $('email-refresh').addEventListener('click',async()=>{try{await jobs();}catch(e){report(errorText(e));}});
  window.addEventListener('pagehide',()=>{deleteInterrupted=true;invalidate();close('email-send-dialog');});
  window.addEventListener('pageshow',event=>{if(event.persisted){invalidate();load();}});
  rememberPending(pendingId);selection();load().then(()=>{
    let intended=[];try{const stored=JSON.parse(sessionStorage.getItem(intentKey)||'[]');if(Array.isArray(stored))intended=stored.filter(id=>checks.some(c=>c.dataset.emailSelect===id)).slice(0,50);sessionStorage.removeItem(intentKey);}catch(_){}
    const id=new URLSearchParams(location.search).get('send_peer');
    const peerCheck=checks.find(c=>c.dataset.emailSelect===id);
    if(id && peerCheck)openSend([id],peerCheck);else if(intended.length)openSend(intended);
  });
})();
