(() => {
  'use strict';
  const base = document.getElementById('admin-base').value;
  const csrf = document.getElementById('admin-csrf').value;
  const status = document.getElementById('status');
  const selected = new Set(); let preview; let contacts = [];
  let generation = 0; let previewBusy = false; let sending = false; let operational = false; let loading = 0;
  const invalidate = () => { generation++; preview = null; document.getElementById('confirm').hidden = true; document.getElementById('preview-result').textContent = ''; };
  const api = async (path, body) => {
    const response = await fetch(base + '/api/admin/delivery/' + path, {
      method: body ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store',
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf},
      ...(body ? {body: JSON.stringify(body)} : {})
    });
    const value = await response.json(); if (!response.ok) throw new Error(value.error || 'Request failed'); return value;
  };
  const report = action => async () => { status.textContent = ''; try { await action(); } catch (e) { status.textContent = e.message; } };
  const button = (label, action) => { const b = document.createElement('button'); b.type = 'button'; b.textContent = label; b.addEventListener('click', report(async () => { if (b.disabled) return; b.disabled = true; invalidate(); try { await action(); } finally { b.disabled = false; } })); return b; };
  const reload = async () => {
    const load = ++loading; invalidate(); selected.clear();
    const [settings, rows, jobs] = await Promise.all([api('settings'), api('contacts'), api('jobs')]);
    if (load !== loading) return;
    operational = settings.enabled && settings.operational !== false;
    document.getElementById('settings').textContent = operational ? 'Email sending enabled.' : 'Email is not ready. Configure it in Settings.';
    document.getElementById('preview').disabled = !operational;
    document.querySelector('#mode option[value="link"]').disabled = !settings.link_enabled;
    contacts = rows; const table = document.getElementById('contacts'); table.replaceChildren();
    for (const c of contacts) {
      const row = document.createElement('tr');
      const cells = Array.from({length: 4}, () => { const td = document.createElement('td'); row.append(td); return td; });
      const check = document.createElement('input'); check.type = 'checkbox'; check.disabled = !c.email || !c.peer_id || c.retired_at !== null;
      check.addEventListener('change', () => { if (check.checked && selected.size >= 50) { check.checked = false; status.textContent = 'Select at most 50 clients.'; return; } check.checked ? selected.add(c.id) : selected.delete(c.id); invalidate(); }); cells[0].append(check);
      if (!check.disabled && String(c.peer_id) === new URLSearchParams(location.search).get('peer')) { check.checked = true; selected.add(c.id); }
      cells[1].textContent = c.managed_name + (c.retired_at !== null ? ' (retired)' : !c.peer_id ? ' (unbound)' : '') + '\nKey: ' + c.last_public_key;
      const email = document.createElement('input'); email.type = 'email'; email.value = c.email || ''; email.setAttribute('aria-label', 'Email for ' + c.managed_name); cells[2].append(email);
      cells[2].append(button('Save email', async () => { await api('contact', {client_id: c.id, version: c.binding_version, email: email.value || null}); await reload(); }));
      cells[3].append(button('Revoke', async () => { await api('revoke', {client_id: c.id}); await reload(); }));
      cells[3].append(button('Forget contact', async () => { if (!confirm('Clear this email and retire this contact?')) return; await api('contact-delete', {client_id: c.id, version: c.binding_version}); await reload(); }));
      if (!c.peer_id && c.retired_at === null) {
        const target = document.createElement('select');
        for (const candidate of contacts.filter(t => t.peer_id && !t.email && t.retired_at === null)) { const o = document.createElement('option'); o.value = candidate.id; o.textContent = candidate.managed_name + ' / ' + candidate.last_public_key; target.append(o); }
        cells[3].append(target, button('Review rebind', async () => {
          const chosen = contacts.find(t => t.id === target.value); if (!chosen) throw new Error('Choose a verified current peer.');
          const p = await api('rebind-preview', {client_id: c.id, version: c.binding_version, target_id: chosen.id, target_version: chosen.binding_version});
          if (!confirm('Transfer saved email: ' + (p.old.email || '(none)') + '\nFrom client: ' + p.old.managed_name + ' / ID ' + p.old.id + ' / interface ' + p.old.interface + '\nOld key: ' + p.old.last_public_key + '\nHistorical address: unavailable (not retained)' + '\nTo client: ' + p.target.managed_name + ' / ID ' + p.target.id + ' / interface ' + p.target.interface + '\nNew key: ' + p.target.last_public_key + '\nVerified current addresses: ' + p.target_addresses.join(', ') + '\nTransfer contact metadata only; no email will be sent.')) { await reload(); return; }
          await api('rebind', {client_id: p.old.id, version: p.old.binding_version, target_id: p.target.id, target_version: p.target.binding_version}); await reload();
        }));
      }
      table.append(row);
    }
    document.getElementById('jobs').textContent = jobs.map(j => j.recipient + ': ' + (j.state === 'accepted' ? 'sent - accepted by SMTP' : j.state) + (j.invalidated_at ? ' — stale/revoked: ' + j.invalidation_code : '') + ' / attempts ' + j.attempts + ' / ' + (j.error_code || '')).join('\n');
  };
  document.getElementById('preview').addEventListener('click', report(async () => {
    if (previewBusy || sending || !operational) return;
    invalidate(); const revision = generation; previewBusy = true; document.getElementById('preview').disabled = true;
    const formats = [...document.querySelectorAll('[data-format]:checked')].map(e => e.dataset.format);
    try {
    const result = await api('preview', {clients: [...selected], mode: document.getElementById('mode').value, formats});
    if (generation !== revision) return; preview = result;
    document.getElementById('preview-result').textContent = 'Mode: ' + preview.mode + '\nFormats: ' + preview.formats.join(', ') + '\n' + preview.items.map(i => i.name + ' → ' + i.recipient + ' (version ' + i.version + ')').join('\n');
    document.getElementById('preview-result').textContent += '\n' + (preview.skipped || []).map(i => 'Skipped ' + (contacts.find(c => c.id === i.client_id)?.managed_name || i.client_id) + ': ' + i.reason).join('\n');
    document.getElementById('confirm').hidden = preview.items.length === 0;
    } finally { previewBusy = false; document.getElementById('preview').disabled = !operational; }
  }));
  document.getElementById('confirm').addEventListener('click', report(async () => {
    if (!preview || sending) return; const p = preview; sending = true; document.getElementById('confirm').disabled = true;
    try { await api('send', {preview_id: p.id, request_id: p.id}); status.textContent = 'Queued for SMTP. Check submission status.'; await reload(); }
    finally { sending = false; document.getElementById('confirm').disabled = false; }
  }));
  document.getElementById('mode').addEventListener('change', invalidate);
  document.querySelectorAll('[data-format]').forEach(input => input.addEventListener('change', invalidate));
  document.getElementById('refresh').addEventListener('click', report(reload));
  report(reload)();
})();
