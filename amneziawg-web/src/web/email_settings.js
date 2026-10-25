(() => {
  'use strict';
  const {$,base,api,errorText,statusText,dialog,close,wireDialog}=window.AwgEmail;
  const form=$('email-settings-form');if(!form)return;
  let settings, dirty=false, saving=false, uncertain=false, testing=false, smtpChecking=false, attempt=null;
  const testKey='awg-email-test:'+base;let pendingTest=null,lastTest=null,checking=false;
  try {const id=sessionStorage.getItem(testKey);if(id && id.length<=128)pendingTest=id;}catch(_){}
  function rememberTest(id) {pendingTest=id;try{id?sessionStorage.setItem(testKey,id):sessionStorage.removeItem(testKey);}catch(_){}controls();}
  const fields={host:'smtp-host',port:'smtp-port',tls:'smtp-tls',username:'smtp-username',from:'smtp-from',reply_to:'smtp-reply-to',public_base:'smtp-public-base',ttl_seconds:'smtp-ttl'};
  const status=text=>{$('email-settings-status').textContent=text;};
  function controls() {
    for(const id of [...Object.values(fields),'smtp-enabled','smtp-authenticate','smtp-password-action','smtp-allow-plaintext'])$(id).disabled=saving;
    $('email-save').disabled=!settings || saving || uncertain || !settings.storage_ready;
    $('email-reload').disabled=saving || testing;
    $('email-test-open').disabled=!settings?.operational || dirty || saving || testing || uncertain || smtpChecking || !!pendingTest;
    $('email-smtp-check').disabled=!settings?.operational || dirty || saving || testing || smtpChecking || uncertain;
    $('smtp-plaintext-warning').hidden=$('smtp-tls').value!=='none';
    $('email-smtp-hint').textContent=dirty?'Save or reload edited settings before checking SMTP.':'Checks saved settings only: connection, selected transport security and authentication when configured. No message is sent.';
    $('email-test-check').hidden=!pendingTest;$('email-test-check').disabled=checking;
    $('email-test-dismiss').hidden=!pendingTest;$('email-test-dismiss').disabled=testing || checking || lastTest?.state==='sending';
    $('smtp-password').disabled=saving || $('smtp-password-action').value!=='replace';
    $('smtp-password').required=$('smtp-password-action').value==='replace';
    $('email-test-confirm').disabled=testing || smtpChecking;
  }
  function invalidateSmtpResult() {
    const node=$('email-smtp-result');
    if(node.textContent && !smtpChecking)node.textContent='Settings were edited or reloaded. Run Check SMTP again explicitly for the saved profile.';
  }
  function fill(s) {
    invalidateSmtpResult();
    settings=s;for(const [key,id] of Object.entries(fields))$(id).value=s[key] ?? '';
    $('smtp-enabled').checked=s.enabled;$('smtp-authenticate').checked=s.authenticate;
    $('smtp-password').value='';$('smtp-password-action').value='keep';dirty=false;uncertain=false;$('smtp-allow-plaintext').checked=false;
    $('email-credential-state').textContent=s.credentials_present?'A password is stored. It is never returned to this form.':'No password is stored.';
    $('email-source').textContent=s.source==='environment'?'Source: server environment. Your first Save creates a complete panel override.':'Source: saved panel settings. Environment values are not merged into this profile.';
    $('email-storage-notice').textContent=s.storage_ready?'':'Saving requires a private database and sidecar files. Ask the operator to check ownership and permissions.';
    $('email-storage-notice').hidden=s.storage_ready;
    $('email-connection-state').textContent=s.operational?'Enabled · ready for an explicit SMTP test':'Email is disabled or unavailable. Save a valid enabled profile to send.';
    controls();
  }
  async function load() {
    status('Loading saved settings…');
    try {fill(await api('settings'));status('Saved settings loaded. Saving never sends a message.');if(pendingTest)await recoverTest();}
    catch(e){status(errorText(e));controls();}
  }
  async function recoverTest() {
    if(!pendingTest || checking)return;checking=true;controls();
    try {
      lastTest=await api('settings/test/'+encodeURIComponent(pendingTest));
      $('email-test-recovery').textContent=lastTest?'Test to '+lastTest.recipient+' — '+statusText(lastTest):'No recorded result yet. The request may still be completing. Check again before starting another test.';
    }catch(e){$('email-test-recovery').textContent=errorText(e)+' No new test was sent.';}
    finally {checking=false;controls();}
  }
  $('email-test-check').addEventListener('click',recoverTest);
  $('email-test-dismiss').addEventListener('click',()=>{
    if(testing || checking || lastTest?.state==='sending')return;
    if((!lastTest || lastTest.state==='unknown') && !confirm('The earlier test may already have been sent. A new test could duplicate it. Finish reviewing this attempt?'))return;
    rememberTest(null);attempt=null;lastTest=null;$('email-test-recovery').textContent='Previous attempt reviewed. A new test always requires a separate confirmation.';
  });
  form.addEventListener('input',()=>{dirty=true;invalidateSmtpResult();controls();});
  form.addEventListener('change',()=>{dirty=true;invalidateSmtpResult();controls();});
  $('smtp-password-action').addEventListener('change',()=>{$('smtp-password').value='';dirty=true;invalidateSmtpResult();controls();});
  form.addEventListener('submit',async event=>{
    event.preventDefault();if(saving || uncertain || !settings?.storage_ready || !form.reportValidity())return;
    if($('smtp-tls').value==='none' && !$('smtp-allow-plaintext').checked){status('Read the plaintext warning and explicitly acknowledge it before saving.');return;}
    const body={allow_plaintext:$('smtp-tls').value==='none' && $('smtp-allow-plaintext').checked,revision:settings.revision,enabled:$('smtp-enabled').checked,authenticate:$('smtp-authenticate').checked,password_action:$('smtp-password-action').value};
    for(const [key,id] of Object.entries(fields))body[key]=$(id).value;
    body.port=Number(body.port);body.ttl_seconds=Number(body.ttl_seconds);
    body.reply_to=body.reply_to.trim() || null;body.public_base=body.public_base.trim() || null;
    if(body.password_action==='replace')body.password=$('smtp-password').value;
    saving=true;controls();status('Saving settings…');
    // The submitted secret is never cached in browser storage or retained in a
    // prefilled field, including when the response is lost.
    $('smtp-password').value='';
    try {fill(await api('settings',body));status('Settings saved. Old queued sends and download links were revoked. No email was sent.');}
    catch(e){uncertain=['connection_unknown','settings_result_unknown','settings_changed'].includes(e.code);status(errorText(e)+(uncertain?' Reload saved settings before saving again.':''));}
    finally {delete body.password;saving=false;controls();}
  });
  $('email-smtp-check').addEventListener('click',async()=>{
    if(!settings?.operational || dirty || saving || testing || smtpChecking || uncertain)return;
    const revision=settings.revision;smtpChecking=true;controls();
    const resultNode=$('email-smtp-result');resultNode.textContent='Checking saved SMTP settings. No message is being sent.';
    try {
      const result=await api('settings/check',{revision});
      const details={connected:'Connection check passed.',tls_failed:'TLS negotiation or certificate validation failed.',authentication_rejected:'SMTP rejected authentication (535).',timeout:'Connection check timed out.',unavailable:'Connection, security or authentication check could not complete. Verify the saved host, port, security mode and credentials.'};
      resultNode.textContent='Saved revision '+result.settings_revision+': '+(details[result.outcome] || details.unavailable);
      if(result.outcome==='connected')resultNode.textContent+=' '+(result.security==='none'?'Plaintext connection; no TLS or authentication.':'Encrypted connection; '+(result.authenticated?'configured authentication completed.':'authentication was not configured.'));
      resultNode.textContent+=' No message was sent. This does not prove permission to send or inbox delivery.';
      if(result.settings_changed || settings.revision!==revision || dirty)resultNode.textContent+=' Settings have changed or contain unsaved edits; this result does not validate the new settings.';
    }catch(e){resultNode.textContent=errorText(e)+' No message was sent. Check again explicitly when ready.';}
    finally {smtpChecking=false;controls();}
  });
  $('email-reload').addEventListener('click',()=>{if(!saving && !testing)return load();});
  wireDialog('email-test-dialog');
  $('email-test-cancel').addEventListener('click',()=>close('email-test-dialog'));
  $('email-test-open').addEventListener('click',()=>{
    if(!settings?.operational || dirty || saving || testing || uncertain || pendingTest)return;
    if(!$('email-test-recipient').reportValidity())return;
    const recipient=$('email-test-recipient').value.trim();if(!recipient)return;
    // Keep the attempt when reopening after an interrupted response. Changing
    // the recipient or saved revision starts a visibly separate confirmation.
    if(!attempt || attempt.recipient!==recipient || attempt.revision!==settings.revision) {
      const bytes=crypto.getRandomValues(new Uint8Array(32));
      attempt={revision:settings.revision,recipient,request_id:btoa(String.fromCharCode(...bytes)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')};
    }
    $('email-test-recipient-confirm').textContent='Send one test email to '+attempt.recipient+' using the saved SMTP profile?';
    $('email-test-status').textContent='No VPN keys or client configurations will be included.';
    $('email-test-confirm').textContent='Send / check this test';dialog('email-test-dialog',$('email-test-open'));
  });
  $('email-test-confirm').addEventListener('click',async()=>{
    if(testing || smtpChecking || !attempt)return;rememberTest(attempt.request_id);testing=true;controls();$('email-test-status').textContent='Submitting test email…';
    try {
      const result=await api('settings/test',attempt);lastTest=result;$('email-test-status').textContent=statusText(result);$('email-test-recovery').textContent='Test to '+result.recipient+' — '+statusText(result);
      if(result.state!=='sending') {attempt=null;$('email-test-confirm').textContent='Test finished';}
    } catch(e){$('email-test-status').textContent=errorText(e)+' Use this same button to check the existing attempt.';}
    finally {testing=false;controls();if(!attempt)$('email-test-confirm').disabled=true;}
  });
  window.addEventListener('pagehide',()=>{$('smtp-password').value='';});
  window.addEventListener('pageshow',event=>{if(event.persisted){$('smtp-password').value='';load();}});
  controls();load();
})();
