const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(
    path.join(__dirname, '../amneziawg-web/src/web/state_export.html'),
    'utf8',
);
const script = source.match(/<script>([\s\S]*?)<\/script>/)[1];

function render(location, payload) {
    const elements = new Map();
    function element(id) {
        if (!elements.has(id)) elements.set(id, { hidden: true, textContent: '' });
        return elements.get(id);
    }
    vm.runInNewContext(script, {
        AWG_WEB_BASE: '',
        location,
        document: { getElementById: element },
        fetch: async () => ({ ok: true, json: async () => payload }),
    });
    return new Promise((resolve) => setImmediate(() => resolve(elements)));
}

test('the export form posts the passphrase and does not fetch it', () => {
    assert.match(source, /method="POST"/);
    assert.match(source, /action="\{\{base\}\}\/admin\/state\/export"/);
    assert.match(source, /name="current_password"/);
    assert.match(source, /name="passphrase"/);
    assert.match(source, /name="passphrase_confirm"/);
    assert.doesNotMatch(script, /passphrase/);
    assert.match(script, /\/api\/admin\/state-export/);
});

test('plain HTTP on a public address warns before download', async () => {
    const elements = await render(
        { protocol: 'http:', hostname: '203.0.113.5' },
        { last_export: null, stale: true, stale_days: 7, ip_literal: 0, warning: null },
    );
    assert.match(elements.get('state-export-transport').textContent, /plain HTTP/);
    assert.equal(elements.get('state-export-transport').hidden, false);
});

for (const location of [
    { protocol: 'https:', hostname: '203.0.113.5' },
    { protocol: 'http:', hostname: '127.0.0.1' },
    { protocol: 'http:', hostname: 'localhost' },
    { protocol: 'http:', hostname: '[::1]' },
]) {
    test(`no transport warning for ${location.protocol}//${location.hostname}`, async () => {
        const elements = await render(location, {
            last_export: '2026-11-08 12:00 UTC',
            stale: false,
            stale_days: 7,
            ip_literal: 0,
            warning: null,
        });
        assert.equal(elements.get('state-export-transport').hidden, true);
    });
}

test('a stale export and a literal-IP count are shown', async () => {
    const elements = await render(
        { protocol: 'https:', hostname: 'vpn.example' },
        {
            last_export: '2026-10-01 00:00 UTC',
            stale: true,
            stale_days: 7,
            ip_literal: 2,
            warning: '2 profiles use an IP in Endpoint; they will need a new profile after a ban',
        },
    );
    assert.match(elements.get('state-export-status').textContent, /2026-10-01/);
    assert.match(elements.get('state-export-stale').textContent, /older than 7 days/);
    assert.equal(elements.get('state-export-stale').hidden, false);
    assert.match(elements.get('state-export-endpoints').textContent, /2 profiles use an IP in Endpoint/);
});

test('a missing endpoint count is a warning, not a block', async () => {
    const elements = await render(
        { protocol: 'https:', hostname: 'vpn.example' },
        { last_export: null, stale: true, stale_days: 7, ip_literal: null, warning: null },
    );
    assert.match(elements.get('state-export-status').textContent, /never/);
    assert.match(elements.get('state-export-stale').textContent, /No encrypted archive/);
    assert.match(elements.get('state-export-endpoints').textContent, /Endpoint check unavailable/);
});
