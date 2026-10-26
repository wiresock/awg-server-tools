(() => {
  'use strict';
  let token = location.hash.slice(1);
  history.replaceState(null, '', location.pathname);
  let csrf = document.getElementById('bootstrap').value;
  let qrUrl;
  let exporting = false;
  const status = document.getElementById('status');
  const retrieve = document.getElementById('retrieve');
  const post = (path, body) => fetch(new URL(path, location.href), {
    method: 'POST', credentials: 'same-origin', cache: 'no-store',
    headers: {'Content-Type': 'application/json', 'X-Delivery-CSRF': csrf},
    body: JSON.stringify(body)
  });
  retrieve.addEventListener('click', async () => {
    if (retrieve.disabled) return;
    retrieve.disabled = true;
    try {
      const response = await post('redeem', {token});
      token = '';
      if (!response.ok) throw new Error();
      const session = await response.json();
      csrf = session.csrf;
      document.getElementById('exports').hidden = false;
      status.textContent = 'Ready. Download or view your configuration.';
    } catch (_) { token = ''; status.textContent = 'Configuration unavailable. Ask the administrator to issue a new link.'; }
  });
  document.querySelectorAll('[data-format]').forEach(button => {
    button.addEventListener('click', async () => {
      if (button.disabled || exporting) return;
      exporting = true;
      button.disabled = true;
      // Do not leave an old secret visible while refreshing or after failure.
      if (qrUrl) { URL.revokeObjectURL(qrUrl); qrUrl = undefined; }
      document.getElementById('qr').hidden = true;
      document.getElementById('qr').removeAttribute('src');
      try {
        const format = button.dataset.format;
        const response = await post('export', {format});
        if (!response.ok) throw new Error();
        const url = URL.createObjectURL(await response.blob());
        if (format === 'qr') {
          if (qrUrl) URL.revokeObjectURL(qrUrl);
          qrUrl = url;
          const qr = document.getElementById('qr'); qr.src = url; qr.hidden = false;
        } else {
          const a = document.createElement('a'); a.href = url;
          a.download = format === 'conf' ? 'client.conf' : 'vpn-uri.txt';
          a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
        }
        status.textContent = 'Configuration exported. Other formats remain available within this session.';
      } catch (_) { status.textContent = 'Configuration unavailable. The session may have expired or been revoked.'; }
      finally { button.disabled = false; exporting = false; }
    });
  });
})();
