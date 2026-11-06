#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Vadim Smirnov (doing business as WireSock)
# SPDX-License-Identifier: MIT
"""Untrusted archive tests; no root, VPN, package manager or network required."""
from contextlib import closing
from datetime import datetime, timezone
import base64
import copy
import hashlib
import gzip
import io
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import termios
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'amneziawg-install.sh'
SOURCE = SCRIPT.read_text()
CODE = SOURCE.split("<<'AWG_STATE_PY'\n", 1)[1].split('\nAWG_STATE_PY', 1)[0]
KEYS = ' '.join(re.search(r'^' + name + r'="([^"]+)"', SOURCE, re.M)[1]
                for name in ('AWG_PARAMS_KEYS', 'AWG_PARAMS_BORINGTUN_KEYS'))
KEY = base64.b64encode(b'A' * 32).decode()
PUB = base64.b64encode(b'B' * 32).decode()
PEER = base64.b64encode(b'C' * 32).decode()


def state_fixture():
    state = {name: '' for name in KEYS.split()}
    state.update(SERVER_PUB_IP='vpn.example.test', SERVER_PUB_NIC='eth0', SERVER_AWG_NIC='awg0',
                 SERVER_AWG_IPV4='10.66.66.1', SERVER_AWG_IPV6='fd42:42:42::1',
                 SERVER_PORT='51820', SERVER_PRIV_KEY=KEY, SERVER_PUB_KEY=PUB,
                 CLIENT_DNS_1='1.1.1.1', ALLOWED_IPS='0.0.0.0/0,::/0',
                 ENABLE_IPV6='n', AWG_BACKEND='kernel', AWG_PROTOCOL_VERSION='2',
                 AWG_BORINGTUN_IMITATE_PROTOCOL='none')
    for suffix, value in zip(('JC', 'JMIN', 'JMAX', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4'),
                             ('4', '40', '70', '15', '16', '17', '18', '1', '2', '3', '4')):
        state['SERVER_AWG_' + suffix] = value
    text = ''.join(f"{name}='{value}'\n" for name, value in state.items())
    conf = f'[Interface]\nAddress = 10.66.66.1/24\nPrivateKey = {KEY}\nListenPort = 51820\n'
    for suffix, field in (('JC', 'Jc'), ('JMIN', 'Jmin'), ('JMAX', 'Jmax'),
                          *((f, f) for f in ('S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4'))):
        conf += f'{field} = {state["SERVER_AWG_" + suffix]}\n'
    conf += 'PostUp = touch /this-must-never-execute\n'
    conf += f'\n### Client phone\n[Peer]\nPublicKey = {PEER}\nPresharedKey = {PUB}\nAllowedIPs = 10.66.66.2/32\n'
    client = f'[Interface]\nPrivateKey = {PEER}\nAddress = 10.66.66.2/32\n[Peer]\nPublicKey = {PUB}\nEndpoint = vpn.example.test:51820\nAllowedIPs = 0.0.0.0/0\n'
    return {'vpn/params': text.encode(), 'vpn/server.conf': conf.encode(),
            'clients/awg0-client-phone.conf': client.encode()}


def manifest(files):
    return dict(schema_version=1, exported_at=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), backend='kernel', protocol='2', interface='awg0',
                files={k: hashlib.sha256(v).hexdigest() for k, v in files.items()})


def make_tar(path, files, meta=None, extra=None):
    all_files = dict(files)
    all_files['manifest.json'] = json.dumps(meta or manifest(files)).encode()
    with tarfile.open(path, 'w:gz') as archive:
        for name, data in all_files.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
        if extra is not None:
            entry = tarfile.TarInfo(extra[0])
            entry.type = extra[1]
            entry.linkname = extra[2]
            archive.addfile(entry)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='awg-state-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.helper = self.root / 'helper.py'
        self.helper.write_text(CODE)
        self.files = state_fixture()
        self.tar = self.root / 'state.tar.gz'
        make_tar(self.tar, self.files)

    def run_helper(self, mode, path=None, *args, ok=True):
        result = subprocess.run(['python3', str(self.helper), KEYS, mode, str(path or self.tar),
                                 *map(str, args)], capture_output=True)
        if ok:
            self.assertEqual(result.returncode, 0, result.stderr.decode())
        else:
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(KEY.encode(), result.stderr)
        return result

    def add_policy(self, rows):
        database = self.root / 'fixture-policy.sqlite'
        with closing(sqlite3.connect(database)) as db, db:
            db.execute('CREATE TABLE peers(public_key TEXT, disabled INTEGER, archived INTEGER, removal_pending INTEGER, expires_at TEXT, display_name TEXT)')
            db.executemany('INSERT INTO peers VALUES(?,?,?,?,?,?)', rows)
        self.files['web/database.sqlite'] = database.read_bytes()
        make_tar(self.tar, self.files)

    def test_manifest_timestamp_required_validated_and_future_clock_rejected(self):
        for value in (None, 42, '2026-13-01T00:00:00Z', '2026-01-01T00:00:00',
                      '2026-01-01T00:00:00+00:00', '2999-01-01T00:00:00Z'):
            with self.subTest(value=value):
                meta = manifest(self.files)
                if value is None:
                    del meta['exported_at']
                else:
                    meta['exported_at'] = value
                make_tar(self.tar, self.files, meta)
                destination = self.root / 'must-not-extract'
                result = self.run_helper('unpack', self.tar, destination, ok=False)
                self.assertFalse(destination.exists())
                if value == '2999-01-01T00:00:00Z':
                    self.assertIn(b'future relative to this host', result.stderr)
                else:
                    self.assertIn(b'exported_at', result.stderr)

    def test_old_archive_warning_and_inspect_timestamp(self):
        meta = manifest(self.files)
        meta['exported_at'] = '2000-01-01T00:00:00Z'
        make_tar(self.tar, self.files, meta)
        result = self.run_helper('inspect')
        report = json.loads(result.stdout)['peer_plan']
        self.assertEqual(report['exported_at'], meta['exported_at'])
        self.assertGreater(report['archive_age_seconds'], 7 * 86400)
        self.assertIn(b'WARNING: Archive is older than 7 days', result.stderr)
        self.assertTrue(report['warnings'])
        self.assertEqual(report['counts'], {'migrate': 1, 'drop': 0})

    def test_inspect_peer_decisions_include_names_expiry_and_counts(self):
        past = base64.b64encode(b'D' * 32).decode()
        for label, public, address in (('tablet', past, 3),):
            self.files['vpn/server.conf'] += (f'\n### Client {label}\n[Peer]\nPublicKey = {public}\n'
                                              f'AllowedIPs = 10.66.66.{address}/32\n').encode()
        # An absent peer uses its DB display name; foreign control sequences are
        # not emitted as terminal escapes or extra log lines.
        pending = base64.b64encode(b'E' * 32).decode()
        self.add_policy([(PEER, 0, 0, 0, '2999-01-01T00:00:00Z', None),
                         (past, 0, 0, 0, '2000-01-01T01:00:00+01:00', None),
                         (pending, 0, 0, 1, None, 'removing\n\x1b[31m')])
        result = self.run_helper('inspect')
        view = json.loads(result.stdout)
        report = view['peer_plan']
        self.assertEqual(report['exported_at'], view['exported_at'])
        self.assertEqual(report['counts'], {'migrate': 1, 'drop': 2})
        peers = {peer['name']: peer for peer in report['peers']}
        self.assertEqual(peers['phone']['decision'], 'migrate')
        self.assertEqual(peers['phone']['reason'], 'future_expiry')
        self.assertEqual(peers['phone']['expires_at'], '2999-01-01T00:00:00Z')
        self.assertEqual(peers['tablet']['decision'], 'drop')
        self.assertEqual(peers['tablet']['reason'], 'expired')
        self.assertEqual(peers['tablet']['expires_at'], '2000-01-01T00:00:00Z')
        self.assertEqual(peers['removing[31m']['reason'], 'removal_pending')
        for secret in (KEY, PUB, PEER):
            self.assertNotIn(secret.encode(), result.stdout + result.stderr)
        self.assertNotIn(b'\x1b', result.stdout)
        destination = self.root / 'dest'
        self.run_helper('unpack', self.tar, destination)
        prepared = json.loads(self.run_helper('prepare', destination).stdout)
        self.assertEqual(prepared['counts'], report['counts'])
        self.assertIn(PEER, (destination / 'peers.conf').read_text())
        self.assertNotIn(past, (destination / 'peers.conf').read_text())

    def test_expiry_passing_between_import_and_activation_is_dropped(self):
        clock = self.root / 'clock'
        clock.write_text('2001-01-01T00:00:10Z')
        shim = """
class TestDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return cls.fromisoformat(Path(CLOCK_PATH).read_text().replace('Z', '+00:00')).astimezone(tz)
datetime = TestDatetime
""".replace('CLOCK_PATH', repr(str(clock)))
        self.helper.write_text(CODE.replace('try:\n    main()', shim + '\ntry:\n    main()'))
        self.add_policy([(PEER, 0, 0, 0, '2001-01-01T00:00:20Z', None)])
        meta = manifest(self.files)
        meta['exported_at'] = '2001-01-01T00:00:00Z'
        make_tar(self.tar, self.files, meta)
        destination = self.root / 'dest'
        self.run_helper('unpack', self.tar, destination)
        imported = json.loads(self.run_helper('prepare', destination).stdout)
        self.assertEqual(imported['counts'], {'migrate': 1, 'drop': 0})
        self.assertTrue(any('ongoing expiry enforcement' in warning for warning in imported['warnings']))
        local = self.root / 'current.conf'
        local.write_bytes((destination / 'interface.conf').read_bytes() + (destination / 'peers.conf').read_bytes())
        self.assertIn(PEER, local.read_text())
        # No real sleep and no production time override. Equality is expired.
        clock.write_text('2001-01-01T00:00:20Z')
        candidate = self.root / 'activate.conf'
        activated = json.loads(self.run_helper('reconcile', local, destination, candidate).stdout)
        self.assertEqual(activated['counts'], {'migrate': 0, 'drop': 1})
        self.assertEqual(activated['exported_at'], imported['exported_at'])
        self.assertEqual(activated['peers'][0]['reason'], 'expired')
        self.assertEqual(activated['peers'][0]['name'], 'phone')
        self.assertEqual(activated['peers'][0]['expires_at'], '2001-01-01T00:00:20Z')
        self.assertNotIn(PEER, candidate.read_text())

    def test_roundtrip_exact_files(self):
        stage = self.root / 'stage'
        for name, data in self.files.items():
            path = stage / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.run_helper('pack', stage, self.tar, 'awg-fixture')
        self.run_helper('verify')
        dest = self.root / 'dest'
        self.run_helper('unpack', self.tar, dest)
        for name, data in self.files.items():
            self.assertEqual((dest / name).read_bytes(), data)
            self.assertEqual((dest / name).stat().st_mode & 0o777, 0o600)
        view = self.run_helper('inspect').stdout
        self.assertNotIn(KEY.encode(), view)
        self.assertEqual(json.loads(view)['schema_version'], 1)
        stamp = json.loads(view)['exported_at']
        self.assertRegex(stamp, r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')
        self.assertLessEqual(datetime.fromisoformat(stamp.replace('Z', '+00:00')), datetime.now(timezone.utc))

    def test_params_literal_allowlist(self):
        path = self.root / 'params'
        path.write_bytes(self.files['vpn/params'])
        output = self.run_helper('params', path).stdout.split(b'\0')
        self.assertIn(KEY.encode(), output)
        for payload in (b"EVIL='true'\n", b"SERVER_PORT='$(touch /tmp/evil)'\n",
                        b'SERVER_PORT=51820;false\n', b"SERVER_PORT='51820'\n",
                        b"SERVER_PORT=$((10+2))\n", b'SERVER_PORT="`id`"\n'):
            with self.subTest(payload=payload):
                path.write_bytes(self.files['vpn/params'] + payload)
                self.run_helper('params', path, ok=False)
        # Injection replacing rather than duplicating an allowed assignment.
        path.write_bytes(self.files['vpn/params'].replace(b"SERVER_PORT='51820'", b"SERVER_PORT='$(id)'"))
        self.run_helper('params', path, ok=False)

    def test_unsafe_members_rejected_before_any_write(self):
        for name in ('/etc/passwd', '../outside', 'vpn/../params', './vpn/params',
                     'vpn//params', 'clients/../outside', 'unlisted-file'):
            with self.subTest(name=name):
                files = dict(self.files, **{name: b'payload'})
                make_tar(self.tar, files)
                dest = self.root / 'not-created'
                self.run_helper('unpack', self.tar, dest, ok=False)
                self.assertFalse(dest.exists())
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.DIRTYPE):
            make_tar(self.tar, self.files, extra=('clients/link.conf', kind, '/etc/shadow'))
            self.run_helper('verify', ok=False)

    def test_duplicate_member(self):
        make_tar(self.tar, self.files, extra=('vpn/params', tarfile.REGTYPE, ''))
        self.run_helper('verify', ok=False)

    def test_checksum_inventory_schema_protocol_backend(self):
        base = manifest(self.files)
        bad = copy.deepcopy(base)
        bad['files']['vpn/params'] = '0' * 64
        variants = [bad]
        for field, value in (('schema_version', 2), ('schema_version', True),
                             ('backend', 'boringtun'), ('protocol', '3.1'), ('interface', 'awg1')):
            bad = copy.deepcopy(base)
            bad[field] = value
            variants.append(bad)
        bad = copy.deepcopy(base)
        del bad['files']['vpn/params']
        variants.append(bad)
        for bad in variants:
            make_tar(self.tar, self.files, bad)
            self.run_helper('verify', ok=False)

    def test_config_key_mismatch_unknown_fields_and_saveconfig(self):
        for old, new in ((KEY, PUB), ('Jc = 4', 'Jc = 5'),
                         ('Jc = 4', 'Unknown = 4'), ('Jc = 4', 'SaveConfig = true')):
            files = dict(self.files)
            files['vpn/server.conf'] = files['vpn/server.conf'].replace(old.encode(), new.encode())
            make_tar(self.tar, files)
            self.run_helper('verify', ok=False)

    def test_client_hooks_rejected_without_rewriting_profiles(self):
        files = dict(self.files)
        name = 'clients/awg0-client-phone.conf'
        files[name] = files[name].replace(b'[Interface]\n', b'[Interface]\nPreUp = touch /bad\n')
        make_tar(self.tar, files)
        self.run_helper('verify', ok=False)

    def test_prepare_strips_hooks_preserves_keys_and_psks(self):
        dest = self.root / 'dest'
        self.run_helper('unpack', self.tar, dest)
        self.run_helper('prepare', dest)
        interface = (dest / 'interface.conf').read_text()
        peers = (dest / 'peers.conf').read_text()
        self.assertNotIn('PostUp', interface)
        self.assertNotIn('touch', interface)
        self.assertIn(KEY, interface)
        self.assertNotIn('[Peer]', interface)
        self.assertNotIn('### Client', interface)
        self.assertIn(PEER, peers)
        self.assertIn(PUB, peers)
        self.assertEqual((dest / 'clients/awg0-client-phone.conf').read_bytes(),
                         self.files['clients/awg0-client-phone.conf'])

    def test_disabled_archived_expired_and_invalid_expiry_removed(self):
        for disabled, archived, expiry, removed in ((1, 0, None, True), (0, 1, None, True),
                (0, 0, '2000-01-01T00:00:00Z', True), (0, 0, 'invalid', True),
                (0, 0, '2999-01-01T00:00:00Z', False), (0, 0, None, False)):
            with self.subTest(disabled=disabled, archived=archived, expiry=expiry):
                dest = self.root / f'dest-{disabled}-{archived}-{expiry}'
                self.run_helper('unpack', self.tar, dest)
                (dest / 'web').mkdir()
                with closing(sqlite3.connect(dest / 'web/database.sqlite')) as db, db:
                    db.execute('CREATE TABLE peers(public_key TEXT, disabled INTEGER, archived INTEGER, expires_at TEXT, removal_pending INTEGER NOT NULL DEFAULT 0)')
                    db.execute('INSERT INTO peers(public_key,disabled,archived,expires_at) VALUES(?,?,?,?)', (PEER, disabled, archived, expiry))
                self.run_helper('prepare', dest)
                self.assertEqual(PEER not in (dest / 'peers.conf').read_text(), removed)

    def test_reconciliation_preserves_next_peer_name_marker(self):
        other = base64.b64encode(b'D' * 32).decode()
        self.files['vpn/server.conf'] += (f'\n### Client tablet\n[Peer]\nPublicKey = {other}\n'
                                         'AllowedIPs = 10.66.66.3/32\n').encode()
        make_tar(self.tar, self.files)
        dest = self.root / 'dest'
        self.run_helper('unpack', self.tar, dest)
        (dest / 'web').mkdir()
        with closing(sqlite3.connect(dest / 'web/database.sqlite')) as db, db:
            db.execute('CREATE TABLE peers(public_key TEXT, disabled INTEGER, archived INTEGER, expires_at TEXT, removal_pending INTEGER NOT NULL DEFAULT 0)')
            db.execute('INSERT INTO peers(public_key,disabled,archived,expires_at) VALUES(?,1,0,NULL)', (PEER,))
        self.run_helper('prepare', dest)
        clean = (dest / 'interface.conf').read_text() + (dest / 'peers.conf').read_text()
        self.assertNotIn('### Client phone', clean)
        self.assertIn('### Client tablet', clean)
        self.assertIn(other, clean)
        self.assertNotIn(PEER, clean)

    def test_failed_manual_removal_is_not_restored(self):
        dest = self.root / 'dest'
        self.run_helper('unpack', self.tar, dest)
        (dest / 'web').mkdir()
        with closing(sqlite3.connect(dest / 'web/database.sqlite')) as db, db:
            db.execute('CREATE TABLE peers(public_key TEXT, disabled INTEGER, archived INTEGER, expires_at TEXT, removal_pending INTEGER)')
            db.execute('INSERT INTO peers VALUES(?,0,0,NULL,1)', (PEER,))
        self.run_helper('prepare', dest)
        self.assertNotIn(PEER, (dest / 'peers.conf').read_text())

    def test_policy_schema_missing_columns_fails_closed_with_clear_error(self):
        required = ('public_key', 'disabled', 'archived', 'removal_pending', 'expires_at')
        for missing in required:
            with self.subTest(missing=missing):
                dest = self.root / missing
                self.run_helper('unpack', self.tar, dest)
                (dest / 'web').mkdir()
                columns = [f'{name} TEXT' for name in required if name != missing]
                with closing(sqlite3.connect(dest / 'web/database.sqlite')) as db, db:
                    db.execute('CREATE TABLE peers(' + ','.join(columns) + ')')
                result = self.run_helper('prepare', dest, ok=False)
                self.assertIn(b'policy schema missing required columns: ' + missing.encode(), result.stderr)
                self.assertFalse((dest / 'interface.conf').exists())
                self.assertFalse((dest / 'peers.conf').exists())

    def test_panel_snapshot_database_cli_env_and_default_precedence(self):
        # Actual unit/env option parsing, with only PID 1 and SQLite CLI transport
        # mocked. Each source DB has a distinct marker, verified in the snapshot.
        for name, env, cli, expected in (
                ('both', 'env.db', '--database-url cli.db', 'cli.db'),
                ('cli', '', '--database-url=cli.db', 'cli.db'),
                ('env', 'env.db', '', 'env.db'),
                ('default', '', '', 'awg-web.db'),
                ('invalid-cli', 'env.db', '--database-url', None)):
            with self.subTest(name=name):
                root = self.root / name
                root.mkdir()
                for file in ('env.db', 'cli.db', 'awg-web.db'):
                    with closing(sqlite3.connect(root / file)) as db, db:
                        db.execute('CREATE TABLE marker(value TEXT)')
                        db.execute('INSERT INTO marker VALUES(?)', (file,))
                (root / 'env.conf').write_text(f'AWG_WEB_DB={env}\n' if env else '')
                (root / 'panel.service').write_text(
                    f'[Service]\nWorkingDirectory={root}\nEnvironmentFile={root}/env.conf\n'
                    f'ExecStart=/usr/local/bin/amneziawg-web {cli}\n')
                shell = r'''
set -euo pipefail
source "$1"
ROOT="$2"
WEB_PANEL_SYSTEMD_UNIT="$ROOT/panel.service"
WEB_PANEL_ENV_FILE="$ROOT/env.conf"
readWebPanelEffectiveProperty() { return 1; }
sqlite3() {
    printf '%s' "$2" >"$ROOT/chosen"
    python3 - "$2" "$ROOT/stage/web/database.sqlite" <<'SQLITE'
import sqlite3, sys
with sqlite3.connect(sys.argv[1]) as source, sqlite3.connect(sys.argv[2]) as dest:
    source.backup(dest)
SQLITE
}
awgStateSnapshotPanel "$ROOT/stage"
'''
                result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(root)], capture_output=True)
                if expected is None:
                    self.assertEqual(result.returncode, 2, result.stderr.decode())
                    self.assertFalse((root / 'chosen').exists())
                    self.assertFalse((root / 'stage').exists())
                    continue
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual((root / 'chosen').read_text(), str(root / expected))
                with closing(sqlite3.connect(root / 'stage/web/database.sqlite')) as db, db:
                    self.assertEqual(db.execute('SELECT value FROM marker').fetchone()[0], expected)

    def test_panel_snapshot_cli_resolver_error_never_falls_back_to_env(self):
        (self.root / 'env.db').write_bytes(b'exists')
        shell = r'''
source "$1"
ROOT="$2"
isWebPanelInstalled() { return 0; }
readWebPanelExecStartSetting() { [[ "$1" == --database-url ]] || exit 95; return 2; }
readWebPanelSetting() { printf 'must-not-read-env\n' >>"$ROOT/env-read"; printf '%s/env.db\n' "$ROOT"; }
awgStateSnapshotPanel "$ROOT/stage"
'''
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)], capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.root / 'env-read').exists())
        self.assertFalse((self.root / 'stage').exists())

    def test_shell_read_params_no_source_and_new_nic_install_hook(self):
        params = self.root / 'params'
        params.write_bytes(self.files['vpn/params'])
        stage = self.root / 'stage'
        self.run_helper('unpack', self.tar, stage)
        self.run_helper('prepare', stage)
        target = self.root / 'target'
        shell = r'''
set -euo pipefail
source "$1"
awgStateReadParams "$2" "$3/records"
SERVER_PUB_NIC=ens99
AMNEZIAWG_DIR="$3/target"
AWG_SYSCTL_FILE="$3/sysctl/awg.conf"
_AWG_STATE_IMPORT_DIR="$3/stage"
writeFirewallRules() { printf 'PostUp = echo new-uplink-%s\n' "$SERVER_PUB_NIC"; }
awg() { [[ "$1" == pubkey ]] || return 1; printf '%s\n' "$SERVER_PUB_KEY"; }
writeAwgServerInstallState
'''
        result = subprocess.run(['bash', '-c', shell, 'state-test', str(SCRIPT), str(params), str(self.root)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        conf = (target / 'awg0.conf').read_text()
        self.assertIn(KEY, conf)
        self.assertIn(PEER, conf)
        self.assertIn('new-uplink-ens99', conf)
        self.assertIn("SERVER_PUB_NIC='ens99'", (target / 'params').read_text())
        self.assertEqual((target / 'clients/awg0-client-phone.conf').read_bytes(),
                         self.files['clients/awg0-client-phone.conf'])

    def test_export_orchestration_and_existing_destination(self):
        source = self.root / 'source'
        source.mkdir()
        (source / 'params').write_bytes(self.files['vpn/params'])
        (source / 'awg0.conf').write_bytes(self.files['vpn/server.conf'])
        (source / 'clients').mkdir()
        (source / 'clients/awg0-client-phone.conf').write_bytes(self.files['clients/awg0-client-phone.conf'])
        (self.root / 'work').mkdir()
        shell = r'''
set -uo pipefail
source "$1"
ROOT="$2"
AMNEZIAWG_DIR="$ROOT/source"
AWG_STATE_PROXY_CONFIG="$ROOT/not-installed-proxy"
acquireClientLifecycleLock() { return 0; }
awgStateTrustedPath() { return 0; }
isWebPanelInstalled() { return 1; }
collectAwgClientConfigCandidates() { local -n OUTPUT="$1"; OUTPUT=("$ROOT/source/clients/awg0-client-phone.conf"); }
awg() { [[ "$1" == --version ]] && printf 'fixture-tools\n'; }
# Only transport orchestration is mocked here. Encryption itself has a separate
# real-age controlling-TTY test below; this is NOT an encryption assertion.
age() { [[ "$1" == --passphrase && "$2" == --output ]] || return 1; cp -- "$4" "$3"; }
awgStateExport "$ROOT/export-test.tar.gz" "$ROOT/work" || exit 10
[[ "$(stat -c %a "$ROOT/export-test.tar.gz")" == 600 ]] || exit 11
awgStateExport "$ROOT/export-test.tar.gz" "$ROOT/work"
[[ $? -ne 0 ]] || exit 12
'''
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)], capture_output=True)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        self.assertNotIn(KEY.encode(), result.stdout + result.stderr)
        self.run_helper('verify', self.root / 'export-test.tar.gz')

    def test_truncated_gzip_and_oversized_tar_member(self):
        self.tar.write_bytes(self.tar.read_bytes()[:30])
        self.run_helper('verify', ok=False)
        member = tarfile.TarInfo('web/database.sqlite')
        member.size = 1024 * 1024 * 1024
        # Header-only hostile fixture: reject size before attempting to read it.
        with gzip.open(self.tar, 'wb') as output:
            output.write(member.tobuf())
            output.write(b'\0' * 1024)
        self.run_helper('verify', ok=False)

    def test_import_plan_quarantine_idempotency_and_rollback(self):
        """Drive CLI orchestration, using host-command mocks confined to a temp root."""
        past = base64.b64encode(b'D' * 32).decode()
        self.files['vpn/server.conf'] += (f'\n### Client expired\n[Peer]\nPublicKey = {past}\n'
                                          'AllowedIPs = 10.66.66.3/32\n').encode()
        self.add_policy([(PEER, 0, 0, 0, '2999-01-01T00:00:00Z', None),
                         (past, 0, 0, 0, '2000-01-01T00:00:00Z', None)])
        shell = r'''
set -uo pipefail
source "$1"
ROOT="$2"
AMNEZIAWG_DIR="$ROOT/target"
AWG_STATE_JOURNAL_DIR="$ROOT/journals"
AWG_SYSTEMD_UNIT_DIR="$ROOT/units"
AWG_SYSCTL_FILE="$ROOT/sysctl/awg.conf"
AWG_MODULES_LOAD_FILE="$ROOT/modules/amneziawg.conf"
AWG_BT_MODPROBE_OVERRIDE="$ROOT/modprobe/awg.conf"
SERVER_PUB_NIC=ens99
mkdir -p "$ROOT/sysctl" "$ROOT/units" "$ROOT/modules" "$ROOT/modprobe"
printf 'original sysctl\n' >"$AWG_SYSCTL_FILE"
isRoot() { return 0; }
checkOS() { OS=debian; ID=debian; }
awgStateDependencies() { return 0; }
awgStateTrustedPath() { return 0; } # Tests run below /tmp, not a privileged path.
acquireClientLifecycleLock() { return 0; }
releaseClientLifecycleLock() { return 0; }
age() { [[ "$1" == --decrypt && "$2" == --output ]] || return 1; cp -- "$4" "$3"; }
ip() {
    [[ "$*" == 'link show dev ens99' ]] && return 0
    [[ "$*" == 'link show dev awg0' ]] && return 1
    return 1
}
ss() { return 0; }
systemctl() {
    printf '%s\n' "$*" >>"$ROOT/systemctl.log"
    case "$1" in is-active|is-enabled) return 1 ;; esac
    return 0
}
ensureAwgBackendReady() { [[ "$1" == 0 ]]; }
validateStagedAwgConfigs() { printf 'validated\n' >>"$ROOT/validated"; }
writeFirewallRules() { printf 'PostUp = echo uplink-%s\n' "$SERVER_PUB_NIC"; }
awg() { [[ "$1" == pubkey ]] || return 1; printf '%s\n' "$SERVER_PUB_KEY"; }
installAmneziaWG() {
    printf 'install\n' >>"$ROOT/install.log"
    writeAwgServerInstallState
    [[ "${FAIL_INSTALL:-0}" == 0 ]] || return 42
    mkdir -p "$AWG_SYSTEMD_UNIT_DIR/awg-quick@awg0.service.d"
    printf 'regenerated unit\n' >"$AWG_SYSTEMD_UNIT_DIR/awg-quick@awg0.service.d/override.conf"
}
awgStateCommand --import-state "$ROOT/state.tar.gz" --dry-run >"$ROOT/dry-run.out" || exit 10
[[ ! -e "$AMNEZIAWG_DIR" && ! -e "$AWG_STATE_JOURNAL_DIR" && ! -e "$ROOT/install.log" ]] || exit 11
[[ "$(<"$AWG_SYSCTL_FILE")" == 'original sysctl' ]] || exit 12
mkdir -m 755 "$AMNEZIAWG_DIR"
FAIL_INSTALL=1
awgStateCommand --import-state "$ROOT/state.tar.gz"
[[ $? -ne 0 ]] || exit 13
[[ -d "$AMNEZIAWG_DIR" && ! -e "$AMNEZIAWG_DIR/params" && "$(stat -c %a "$AMNEZIAWG_DIR")" == 700 && ! -e "$AWG_SYSTEMD_UNIT_DIR/awg-quick@awg0.service.d" ]] || exit 14
[[ "$(<"$AWG_SYSCTL_FILE")" == 'original sysctl' ]] || exit 15
FAIL_INSTALL=0
awgStateCommand --import-state "$ROOT/state.tar.gz" || exit 16
[[ -f "$AMNEZIAWG_DIR/params" && -f "$AMNEZIAWG_DIR/awg0.conf" ]] || exit 17
[[ "$(grep -c '^install$' "$ROOT/install.log")" == 2 ]] || exit 18
awgStateCommand --import-state "$ROOT/state.tar.gz" || exit 19
[[ "$(grep -c '^install$' "$ROOT/install.log")" == 2 ]] || exit 20
! grep -Eq '^(start|enable|restart) ' "$ROOT/systemctl.log" || exit 21
printf '\n# local change\n' >>"$AMNEZIAWG_DIR/awg0.conf"
awgStateCommand --import-state "$ROOT/state.tar.gz"
[[ $? -ne 0 ]] || exit 22
'''
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)], capture_output=True)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        self.assertNotIn(KEY.encode(), result.stdout + result.stderr)
        self.assertIn('rollback', ''.join(p.read_text() for p in (self.root / 'journals').glob('*/steps')))
        plan, _ = json.JSONDecoder().raw_decode((self.root / 'dry-run.out').read_text())
        self.assertEqual(plan['counts'], {'migrate': 1, 'drop': 1})
        self.assertRegex(plan['exported_at'], r'Z$')
        decisions = {peer['name']: peer for peer in plan['peers']}
        self.assertEqual(decisions['phone']['decision'], 'migrate')
        self.assertEqual(decisions['expired']['decision'], 'drop')
        self.assertEqual(decisions['expired']['expires_at'], '2000-01-01T00:00:00Z')
        self.assertIn(PEER, (self.root / 'target/awg0.conf').read_text())
        self.assertNotIn(past, (self.root / 'target/awg0.conf').read_text())

    def test_activation_and_rerun_reconcile_legacy_receipts_without_resurrection(self):
        """A pre-fix receipt may still authorize expiring/removal-pending peers.

        Test both a deadline already crossed during quarantine and one still in
        the future. Future-expiry peers must migrate; expired ones must not start.
        """
        pending = base64.b64encode(b'D' * 32).decode()
        permanent = base64.b64encode(b'E' * 32).decode()
        removed = base64.b64encode(b'F' * 32).decode()
        for name, mode, expiry in (
                ('activation-expired', '--activate-state', '2000-01-01T00:00:00Z'),
                ('activation-future', '--activate-state', '2999-01-01T00:00:00Z'),
                ('activation-crossed', '--activate-state', '2001-01-01T00:00:20Z'),
                ('reimport-future', '--import-state', '2999-01-01T00:00:00Z'),
                ('dry-run', '--dry-run', '2999-01-01T00:00:00Z'),
                ('bad-schema', '--activate-state', '2999-01-01T00:00:00Z')):
            with self.subTest(name=name):
                root = self.root / name
                root.mkdir()
                files = dict(self.files)
                for label, public, address in (('pending', pending, 3), ('permanent', permanent, 4),
                                                ('removed', removed, 5)):
                    files['vpn/server.conf'] += (f'\n### Client {label}\n[Peer]\nPublicKey = {public}\n'
                                                f'AllowedIPs = 10.66.66.{address}/32\n').encode()
                db_path = root / 'policy.sqlite'
                with closing(sqlite3.connect(db_path)) as db, db:
                    if name == 'bad-schema':
                        db.execute('CREATE TABLE peers(public_key TEXT, disabled INTEGER, archived INTEGER, expires_at TEXT)')
                    else:
                        db.execute('CREATE TABLE peers(public_key TEXT, disabled INTEGER, archived INTEGER, expires_at TEXT, removal_pending INTEGER)')
                        db.executemany('INSERT INTO peers VALUES(?,0,0,?,?)',
                                       [(PEER, expiry, 0), (pending, None, 1), (permanent, None, 0), (removed, None, 0)])
                files['web/database.sqlite'] = db_path.read_bytes()
                meta = manifest(files)
                if name == 'activation-crossed':
                    meta['exported_at'] = '2001-01-01T00:00:00Z'
                    clock = root / 'clock'
                    clock.write_text('2001-01-01T00:00:10Z')
                    # Inject a deterministic clock into TEST source only. There
                    # is intentionally no production clock/environment override.
                    shim = """
class TestDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return cls.fromisoformat(Path(CLOCK_PATH).read_text().replace('Z', '+00:00')).astimezone(tz)
datetime = TestDatetime
""".replace('CLOCK_PATH', repr(str(clock)))
                    (root / 'helper.py').write_text(CODE.replace('try:\n    main()', shim + '\ntry:\n    main()'))
                make_tar(root / 'state.tar.gz', files, meta)
                (root / 'original-params').write_bytes(files['vpn/params'])
                # This local, receipt-verified config models the old importer,
                # with generated hooks, and one peer already removed locally.
                local_conf = files['vpn/server.conf'].split(b'\n### Client removed')[0]
                local_conf = local_conf.replace(b'PostUp = touch /this-must-never-execute',
                                                b'PostUp = echo local-generated-hook')
                (root / 'local.conf').write_bytes(local_conf)
                shell = r'''
set -uo pipefail
source "$1"
ROOT="$2"
MODE="$3"
if [[ -f "$ROOT/clock" ]]; then
    awgStateArchive() { python3 "$ROOT/helper.py" "${AWG_PARAMS_KEYS} ${AWG_PARAMS_BORINGTUN_KEYS}" "$@"; }
fi
AMNEZIAWG_DIR="$ROOT/target"
AWG_STATE_JOURNAL_DIR="$ROOT/journals"
AWG_SYSCTL_FILE="$ROOT/sysctl.conf"
mkdir -p "$AMNEZIAWG_DIR/clients"
awgStateReadParams "$ROOT/original-params" "$ROOT/records" || exit 10
SERVER_PUB_NIC=ens99
SERVER_AWG_CONF="$AMNEZIAWG_DIR/awg0.conf"
serializeParams "$AMNEZIAWG_DIR/params" || exit 11
cp "$ROOT/local.conf" "$SERVER_AWG_CONF"
printf 'net.ipv4.ip_forward = 1\n' >"$AWG_SYSCTL_FILE"
awgStateArchive unpack "$ROOT/state.tar.gz" "$ROOT/reference" || exit 12
ID="$(sha256sum "$ROOT/reference/manifest.json")"; ID="${ID%% *}"
JOURNAL="$AWG_STATE_JOURNAL_DIR/$ID"
mkdir -p "$JOURNAL"
printf '%s\n' ens99 >"$JOURNAL/nic"
awgStateWriteReceipt "$JOURNAL" "$ROOT/receipt" || exit 13
isRoot() { return 0; }
checkOS() { OS=debian; ID=debian; }
awgStateDependencies() { return 0; }
awgStateTrustedPath() { return 0; }
acquireClientLifecycleLock() { return 0; }
releaseClientLifecycleLock() { return 0; }
age() { cp -- "$4" "$3"; }
installAmneziaWG() { echo 'must not reinstall' >&2; return 99; }
ensureAwgBackendReady() { [[ "$1" == 0 ]]; }
validateStagedAwgConfigs() {
    printf 'validate\n' >>"$ROOT/events"
    # Expiry passes AFTER the initial activation check, during validation.
    [[ ! -f "$ROOT/clock" ]] || printf '2001-01-01T00:00:30Z' >"$ROOT/clock"
}
sysctl() { printf 'sysctl\n' >>"$ROOT/events"; }
systemctl() {
    case "$1" in
        is-active|is-enabled) return 1 ;;
        start) cp "$SERVER_AWG_CONF" "$ROOT/at-start.conf"; printf 'start\n' >>"$ROOT/events" ;;
        *) echo 'unexpected systemctl command' >&2; return 90 ;;
    esac
}
if [[ "$MODE" == --dry-run ]]; then
    awgStateCommand --import-state "$ROOT/state.tar.gz" --dry-run
else
    awgStateCommand "$MODE" "$ROOT/state.tar.gz"
fi
STATUS=$?
[[ $STATUS -eq 0 ]] || exit "$STATUS"
sha256sum -c --status "$JOURNAL/receipt" || exit 14
'''
                result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(root), mode], capture_output=True)
                if name == 'bad-schema':
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(b'policy schema missing required columns: removal_pending', result.stderr)
                    self.assertFalse((root / 'events').exists())
                    self.assertEqual((root / 'target/awg0.conf').read_bytes(), local_conf)
                    continue
                self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
                self.assertNotIn(KEY.encode(), result.stdout + result.stderr)
                if mode == '--dry-run':
                    self.assertEqual((root / 'target/awg0.conf').read_bytes(), local_conf)
                    self.assertFalse((root / 'events').exists())
                    continue
                clean = (root / 'target/awg0.conf').read_text()
                self.assertEqual(PEER in clean, expiry.startswith('2999'))
                self.assertNotIn(pending, clean)
                self.assertNotIn(removed, clean)  # Never rebuild peers from the snapshot.
                self.assertIn(permanent, clean)
                self.assertIn('PostUp = echo local-generated-hook', clean)
                self.assertIn('future-expiry peers migrate', result.stdout.decode())
                if name == 'activation-crossed':
                    self.assertIn(b'"reason": "future_expiry"', result.stdout)
                    self.assertIn(b'"reason": "expired"', result.stdout)
                    self.assertIn(b'"name": "phone"', result.stdout)
                    self.assertIn(b'"expires_at": "2001-01-01T00:00:20Z"', result.stdout)
                if mode == '--activate-state':
                    self.assertEqual((root / 'at-start.conf').read_text(), clean)
                    self.assertEqual((root / 'events').read_text(), 'validate\nsysctl\nstart\n')
                else:
                    self.assertFalse((root / 'events').exists())
                self.assertIn('reconciled', next((root / 'journals').glob('*/steps')).read_text())

    def test_invalid_arguments_never_enter_interactive_install(self):
        for args in (['--export-state'], ['--inspect-state', 'x', '--dry-run'],
                     ['--import-state', 'x', '--unknown'], ['--import-state', '--dry-run'],
                     ['--activate-state'], ['--activate-state', 'x', '--dry-run']):
            result = subprocess.run(['bash', str(SCRIPT), *args], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'Usage:', result.stderr)

    @unittest.skipUnless(shutil.which('age'), 'age not installed')
    def test_age_passphrase_roundtrip_and_wrong_passphrase(self):
        """Real age and controlling TTY; the secret is never in argv or env."""
        def run_age(args, responses):
            pid, fd = pty.fork()
            if pid == 0:
                settings = termios.tcgetattr(0)
                settings[3] &= ~termios.ECHO
                termios.tcsetattr(0, termios.TCSANOW, settings)
                os.execvp('age', ['age', *args])
            output = b''
            deadline = time.monotonic() + 25
            index = 0
            try:
                while time.monotonic() < deadline:
                    ready, _, _ = select.select([fd], [], [], 0.2)
                    if ready:
                        try:
                            data = os.read(fd, 4096)
                        except OSError:
                            break
                        if not data:
                            break
                        output += data
                        if b':' in data and index < len(responses):
                            os.write(fd, responses[index].encode() + b'\n')
                            index += 1
                    ended, status = os.waitpid(pid, os.WNOHANG)
                    if ended:
                        return os.waitstatus_to_exitcode(status), output
                ended, status = os.waitpid(pid, os.WNOHANG)
                if ended:
                    return os.waitstatus_to_exitcode(status), output
                os.kill(pid, 9)
                os.waitpid(pid, 0)
                self.fail('age TTY interaction timed out')
            finally:
                os.close(fd)
        encrypted = self.root / 'backup.awgx'
        secret = 'a-test-only-long-passphrase'
        rc, log = run_age(['--passphrase', '--output', str(encrypted), str(self.tar)], [secret, secret])
        self.assertEqual(rc, 0, log)
        self.assertNotIn(secret.encode(), log)
        decrypted = self.root / 'decrypted.tar.gz'
        rc, log = run_age(['--decrypt', '--output', str(decrypted), str(encrypted)], [secret])
        self.assertEqual(rc, 0, log)
        self.run_helper('verify', decrypted)
        wrong = self.root / 'wrong.tar.gz'
        rc, log = run_age(['--decrypt', '--output', str(wrong), str(encrypted)], ['a-wrong-passphrase'])
        self.assertNotEqual(rc, 0, log)
        self.assertFalse(wrong.exists() and wrong.stat().st_size)


if __name__ == '__main__':
    unittest.main(verbosity=2)
