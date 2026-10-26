(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const base = $('email-base').value, csrf = $('email-csrf').value;
  const messages = {
    authentication_required:'Sign in again to manage email.', csrf_required:'Your session changed. Reload this page.',
    invalid_email:'Enter one valid email address.', invalid_settings:'Check the SMTP form values.',
    invalid_smtp_host:'Enter a hostname only, without a URL or path.', invalid_smtp_port:'Port must be between 1 and 65535.',
    invalid_smtp_tls:'Choose STARTTLS or TLS.', tls_required:'Choose STARTTLS, TLS or explicit plaintext mode.', smtp_credentials_required:'Authentication needs a username and password.', invalid_smtp_username:'Check the SMTP username.',
    invalid_password_action:'Choose Keep, Replace or Clear explicitly.', email_storage_restart_required:'Email is paused: its database storage was not private at startup. Ask the operator to check ownership, paths and permissions, then restart the panel. Reloading this page does not resume email.',email_requires_auth:'Email requires panel authentication. Ask the operator to enable it and restart the panel.',draft_password_scope_changed:'The stored password is bound to its saved SMTP server, port, security and login. Choose Replace or Clear before saving or testing changed connection settings.', invalid_public_base:'Use a public HTTPS base URL without credentials, query or fragment.',
    invalid_ttl:'Choose a lifetime between 5 minutes and 7 days.', settings_changed:'Settings changed. Reload the saved profile and review again.',
    settings_result_unknown:'Save result is uncertain. Reload the saved profile before making another change.',
    settings_storage_not_private:'Private database storage is required. Ask the server operator to check ownership and permissions; this panel does not change them.',
    storage_unavailable:'Storage is unavailable. Retry after the server is healthy.', delivery_recovery_required:'Email is paused after a storage error. Reload or ask the server operator to recover it.',
    delivery_unavailable:'Email service is unavailable on this panel.', delivery_disabled:'Email is not enabled. Open Settings first.',
    public_route_conflict:'The admin address overlaps /delivery. Ask the operator to choose a separate admin path.',
    link_unavailable:'Configure a public HTTPS download address in Settings, or use direct attachments.',
    email_missing:'No email address. Choose Edit email before sending.', ineligible:'Peer is disabled, expired, archived or unavailable.',
    unbound:'The client key changed. Review the contact binding in Settings.', ownership_unverified:'The current configuration could not be verified.',
    changed:'The peer or recipient changed. Review a fresh preview.', preview_expired:'The preview expired. Review recipients again.',
    no_eligible_clients:'No selected peer is ready to receive a configuration.', selection_limit:'Select 1–50 peers and at least one format.',
    send_limit:'The sending limit has been reached. Try again later.', preview_limit:'Too many active previews. Try again in a few minutes.',
    admission_timeout:'The server is busy. Retry this operation.', test_busy:'Another SMTP check or test email is in progress. Wait for it to finish.',
    smtp_check_limit:'The SMTP check limit is 5 per hour. Try again later.', smtp_check_unknown:'The connection check result is unavailable.', plaintext_ack_required:'Read and acknowledge the plaintext warning before testing or saving.', plaintext_auth_forbidden:'Plaintext mode forbids authentication, username and stored password. Disable authentication, empty the username and explicitly clear the password.',
    test_limit:'The test limit is 5 messages per hour. Try again later.', test_result_unknown:'Test result is uncertain. Check this same attempt; do not start another message.',
    connection_unknown:'The response was interrupted. The operation may have completed.', invalid_request_id:'This attempt no longer matches the request. Review its status before starting another.'
  };
  const errorText = e => messages[e.code || e] || 'The operation could not be completed. Reload and review the current state.';
  const api = async (path, body) => {
    let response, value;
    try {
      response = await fetch(base + '/api/admin/delivery/' + path, {method:body ? 'POST':'GET',credentials:'same-origin',cache:'no-store',
        headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},...(body ? {body:JSON.stringify(body)}:{})});
      value = await response.json();
    } catch (_) { const e = new Error('Request outcome unavailable'); e.code='connection_unknown'; throw e; }
    if (!response.ok) {const e=new Error('Request failed');e.code=value.error || 'request_failed';throw e;}
    return value;
  };
  const node = (tag,text) => {const e=document.createElement(tag);if(text!==undefined)e.textContent=text;return e;};
  const statusText = j => ({queued:'Queued for SMTP',sending:'Submitting to SMTP',accepted:'Sent - accepted by SMTP',
    failed:'SMTP submission failed',unknown:'Acceptance unknown — review before sending again',cancelled:'Cancelled before sending'}[j.state] || 'Status unavailable') +
    (j.state==='failed' ? (j.error_code==='transient_rejection'?' · relay temporarily rejected the message; try again later':j.error_code==='permanent_rejection'?' · check authentication, sender address and relay policy':' · check SMTP settings and server availability'):'') +
    (j.invalidated_at != null ? ' · configuration/link revoked or changed':'') + (j.settings_changed ? ' · settings changed during this attempt':'');
  function dialog(id, trigger) {
    const d=$(id); d.returnFocus=trigger || document.activeElement;
    if(!d.open)d.showModal();
  }
  function close(id) {const d=$(id);if(d.open)d.close();}
  function wireDialog(id) {const d=$(id);d.addEventListener('close',()=>d.returnFocus?.focus());}
  window.AwgEmail = {$,base,api,node,errorText,statusText,dialog,close,wireDialog};
  if($('email-settings-form') && $('system-versions')) {
    fetch(base+'/api/system/versions',{credentials:'same-origin',cache:'no-store'})
      .then(r=>{if(!r.ok)throw new Error();return r.json();})
      .then(v=>{$('system-versions').textContent=typeof v.summary==='string'?v.summary:'System versions unavailable';})
      .catch(()=>{$('system-versions').textContent='System versions unavailable';});
  }
})();
