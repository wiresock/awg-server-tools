const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('path');
const vm = require('node:vm');

const source = fs.readFileSync(
    path.join(__dirname, '../amneziawg-web/src/web/state_export.html'),
    'utf8',
);
const script = source.match(/<script>([\s\S]*?)<\/script>/)[1];

function render(location, payload) {
    const elements = new Map();
    const calls = [];
    function element(id) {
        if (!elements.has(id)) {
            elements.set(id, {
                hidden: true,
                textContent: '',
                open: false,
                disabled: false,
                listeners: {},
                addEventListener(type, fn) { this.listeners[type] = fn; },
            });
        }
        return elements.get(id);
    }
    const status = payload.status || payload;
    const endpoints = payload.endpoints || {
        hostname: null,
        ip_literal: null,
        warning: null,
    };
    vm.runInNewContext(script, {
        AWG_WEB_BASE: '',
        location,
        document: { getElementById: element },
        fetch: async (url) => {
            calls.push(String(url));
            const body = String(url).indexOf('/endpoints') !== -1 ? endpoints : status;
            return { ok: true, json: async () => body };
        },
    });
    return new Promise((resolve) => setImmediate(() => resolve({ elements, calls })));
}

async function openPanel(rendered) {
    const panel = rendered.elements.get('state-export-panel');
    panel.open = true;
    panel.listeners.toggle();
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));
    return rendered;
}

test('the export form posts the passphrase and does not fetch it', () => {
    assert.match(source, /method="POST"/);
    assert.match(source, /action="\{\{base\}\}\/admin\/state\/export"/);
    assert.match(source, /name="current_password"/);
    assert.match(source, /name="passphrase"/);
    assert.match(source, /name="passphrase_confirm"/);
    assert.doesNotMatch(script, /passphrase/);
    assert.match(script, /\/api\/admin\/state-export'/);
    assert.match(script, /\/api\/admin\/state-export\/endpoints/);
    assert.match(script, /addEventListener\('toggle'/);
});

test('plain HTTP on a public address warns before download', async () => {
    const { elements } = await render(
        { protocol: 'http:', hostname: '203.0.113.5' },
        { status: { last_export: null, stale: true, stale_days: 7, export_block: null } },
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
        const { elements } = await render(location, {
            status: {
                last_export: '2026-11-08 12:00 UTC',
                stale: false,
                stale_days: 7,
                export_block: null,
            },
        });
        assert.equal(elements.get('state-export-transport').hidden, true);
    });
}

test('a stale export is shown without counting endpoints', async () => {
    const rendered = await render(
        { protocol: 'https:', hostname: 'vpn.example' },
        {
            status: {
                last_export: '2026-10-01 00:00 UTC',
                stale: true,
                stale_days: 7,
                export_block: null,
            },
            endpoints: {
                hostname: 1,
                ip_literal: 2,
                warning: '2 profiles use an IP in Endpoint; they will need a new profile after a ban',
            },
        },
    );
    assert.match(rendered.elements.get('state-export-status').textContent, /2026-10-01/);
    assert.match(rendered.elements.get('state-export-stale').textContent, /older than 7 days/);
    assert.equal(rendered.elements.get('state-export-stale').hidden, false);
    assert.equal(rendered.elements.get('state-export-endpoints').hidden, true);
    assert.deepEqual(rendered.calls, ['/api/admin/state-export']);
    await openPanel(rendered);
    assert.match(rendered.elements.get('state-export-endpoints').textContent, /2 profiles use an IP in Endpoint/);
    assert.ok(rendered.calls.some((url) => url.endsWith('/api/admin/state-export/endpoints')));
});

test('a missing endpoint count is a warning, not a block', async () => {
    const rendered = await render(
        { protocol: 'https:', hostname: 'vpn.example' },
        {
            status: { last_export: null, stale: true, stale_days: 7, export_block: null },
            endpoints: { hostname: null, ip_literal: null, warning: null },
        },
    );
    assert.match(rendered.elements.get('state-export-status').textContent, /never/);
    assert.match(rendered.elements.get('state-export-stale').textContent, /No encrypted archive/);
    await openPanel(rendered);
    assert.match(rendered.elements.get('state-export-endpoints').textContent, /Endpoint check unavailable/);
});

test('a missing export tool disables the download', async () => {
    const { elements } = await render(
        { protocol: 'https:', hostname: 'vpn.example' },
        {
            status: {
                last_export: null,
                stale: true,
                stale_days: 7,
                export_block: 'export-state requires age; rerun the panel upgrade',
            },
        },
    );
    assert.match(elements.get('state-export-status').textContent, /rerun the panel upgrade/);
    assert.equal(elements.get('state-export-submit').disabled, true);
});
