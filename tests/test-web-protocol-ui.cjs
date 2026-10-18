const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../amneziawg-web/src/web/mod.rs'), 'utf8');
const template = source.slice(source.indexOf('fn render_protocol_controls('));
const script = template.match(/<script>([\s\S]*?)<\/script>/)[1]
    .replace(/\{\{/g, '{').replace(/\}\}/g, '}');
for (const [version, hideUpgrade, hideDowngrade] of [
    ['1.0', true, true], ['2.0', false, true], ['3.0', false, false], ['3.1', true, false],
]) {
    test(`protocol actions are appropriate for AWG ${version}`, async () => {
        const elements = new Map();
        vm.runInNewContext(script, {
            document: { getElementById(id) {
                if (!elements.has(id)) elements.set(id, { hidden: false, textContent: '' });
                return elements.get(id);
            } },
            fetch: async () => ({ ok: true, json: async () => ({ version }) }),
        });
        await new Promise(setImmediate);
        assert.equal(elements.get('protocol-enable-awg31').hidden, hideUpgrade);
        assert.equal(elements.get('protocol-disable-awg3').hidden, hideDowngrade);
        assert.match(elements.get('protocol-current').textContent, new RegExp(version));
    });
}
