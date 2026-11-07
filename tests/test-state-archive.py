#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Vadim Smirnov (doing business as WireSock)
# SPDX-License-Identifier: MIT
"""Untrusted archive tests; no root, VPN, package manager or network required."""
from contextlib import closing
from datetime import datetime, timedelta, timezone
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
INSTALLER_LOCK_FN = re.compile(r'^readonly INSTALLER_LIFECYCLE_LOCK_DIR=.*?^}\n', re.M | re.S)


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
            db.execute('INSERT INTO peers(public_key,disabled,archived,expires_at) VALUES(?,0,0,NULL)', (other,))
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
age() { [[ "$1" == --passphrase && "$2" == --output && $# -eq 3 ]] || return 1; [[ ! -e "$ROOT/work/state.tar.gz" ]] || return 91; python3 -c 'import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())' >"$3"; }
awgStateExport "$ROOT/export-test.tar.gz" "$ROOT/work" || exit 10
[[ "$(stat -c %a "$ROOT/export-test.tar.gz")" == 600 ]] || exit 11
awgStateExport "$ROOT/export-test.tar.gz" "$ROOT/work"
[[ $? -ne 0 ]] || exit 12
[[ ! -e "$ROOT/work/state.tar.gz" ]] || exit 13
# A failing producer followed by a successful consumer must still fail.
awgStateArchive() {
    if [[ "$1" == pack ]]; then printf 'partial-plaintext'; return 23; fi
    python3 "$ROOT/helper.py" "${AWG_PARAMS_KEYS} ${AWG_PARAMS_BORINGTUN_KEYS}" "$@"
}
awgStateExport "$ROOT/producer-failure" "$ROOT/work"
[[ $? -ne 0 && ! -e "$ROOT/producer-failure" && ! -e "$ROOT/work/encrypted" ]] || exit 14
# A failing consumer must remove even an already-created partial ciphertext.
awgStateArchive() {
    if [[ "$1" == pack ]]; then printf 'partial-plaintext'; return 0; fi
    python3 "$ROOT/helper.py" "${AWG_PARAMS_KEYS} ${AWG_PARAMS_BORINGTUN_KEYS}" "$@"
}
age() { printf partial >"$3"; return 24; }
awgStateExport "$ROOT/consumer-failure" "$ROOT/work"
[[ $? -ne 0 && ! -e "$ROOT/consumer-failure" && ! -e "$ROOT/work/encrypted" ]] || exit 15
'''
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)], capture_output=True)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        self.assertNotIn(KEY.encode(), result.stdout + result.stderr)
        self.run_helper('verify', self.root / 'export-test.tar.gz')

    def test_panel_membership_is_authoritative_only_when_database_exists(self):
        destination = self.root / 'no-panel'
        self.run_helper('unpack', self.tar, destination)
        self.assertEqual(json.loads(self.run_helper('prepare', destination).stdout)['counts']['migrate'], 1)
        self.add_policy([])
        report = json.loads(self.run_helper('inspect').stdout)['peer_plan']
        self.assertEqual(report['counts'], {'migrate': 0, 'drop': 1})
        self.assertEqual(report['peers'][0]['reason'], 'not_in_panel')
        self.assertEqual(report['peers'][0]['name'], 'phone')
        destination = self.root / 'panel'
        self.run_helper('unpack', self.tar, destination)
        plan = json.loads(self.run_helper('prepare', destination).stdout)
        self.assertEqual(plan['peers'][0]['reason'], 'not_in_panel')
        self.assertNotIn(PEER, (destination / 'peers.conf').read_text())

    def test_real_clock_expiry_passes_between_import_and_activation_policy(self):
        # Exercise the unmodified production datetime.now comparison. This is a
        # short-lived isolated fixture, not a mocked clock or a live VPN test.
        deadline = (datetime.now(timezone.utc) + timedelta(seconds=5)).replace(microsecond=0)
        expiry = deadline.strftime('%Y-%m-%dT%H:%M:%SZ')
        self.add_policy([(PEER, 0, 0, 0, expiry, None)])
        destination = self.root / 'real-clock'
        self.run_helper('unpack', self.tar, destination)
        imported = json.loads(self.run_helper('prepare', destination).stdout)
        self.assertEqual(imported['peers'][0]['decision'], 'migrate')
        local = self.root / 'current.conf'
        local.write_bytes((destination / 'interface.conf').read_bytes() + (destination / 'peers.conf').read_bytes())
        remaining = (deadline - datetime.now(timezone.utc)).total_seconds()
        if remaining > 0:
            time.sleep(remaining + 0.02)
        candidate = self.root / 'at-activation.conf'
        activated = json.loads(self.run_helper('reconcile', local, destination, candidate).stdout)
        self.assertEqual(activated['peers'][0]['reason'], 'expired')
        self.assertEqual(activated['peers'][0]['expires_at'], expiry)
        self.assertNotIn(PEER, candidate.read_text())

    def test_journal_purge_refusal_force_finalized_tombstone_and_symlinks(self):
        shell = r'''
set -euo pipefail
source "$1"
ROOT="$2"
AWG_STATE_JOURNAL_DIR="$ROOT/journals"
DIGEST="$(printf 'a%.0s' {1..64})"
JOURNAL="$AWG_STATE_JOURNAL_DIR/$DIGEST"
isRoot() { return 0; }
awgStateTrustedPath() { return 0; }
acquireClientLifecycleLock() { return 0; }
releaseClientLifecycleLock() { return 0; }
mkdir -p "$JOURNAL/recovery" "$JOURNAL/before" "$ROOT/outside"
printf secret >"$JOURNAL/recovery/secret"
printf outside >"$ROOT/outside/sentinel"
if awgStatePurgeJournal "$DIGEST"; then exit 10; fi
[[ -f "$JOURNAL/recovery/secret" ]]
if awgStatePurgeJournal ../outside --force; then exit 11; fi
awgStatePurgeJournal "$DIGEST" --force
[[ ! -e "$JOURNAL" && -f "$ROOT/outside/sentinel" ]]
mkdir -p "$JOURNAL/before"
printf 'awg0\n' >"$JOURNAL/finalized"
printf secret >"$JOURNAL/receipt"
ln -s "$ROOT/outside" "$JOURNAL/recovery"
printf unrecognized >"$JOURNAL/unexpected"
if awgStatePurgeJournal "$DIGEST" --force; then exit 12; fi
[[ -f "$JOURNAL/receipt" ]]
rm "$JOURNAL/unexpected"
awgStatePurgeJournal "$DIGEST"
[[ -f "$ROOT/outside/sentinel" && ! -e "$JOURNAL/recovery" && ! -e "$JOURNAL/receipt" && ! -e "$JOURNAL/before" ]]
awgStateIsFinalized "$JOURNAL" awg0
awgStatePurgeJournal "$DIGEST" # idempotent, retaining only non-secret tombstone
rm "$JOURNAL/finalized"
ln -s "$ROOT/outside/sentinel" "$JOURNAL/finalized"
if awgStatePurgeJournal "$DIGEST"; then exit 13; fi
[[ -f "$ROOT/outside/sentinel" ]]
'''
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)], capture_output=True)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        self.assertNotIn(b'secret', result.stdout.replace(b'non-secret', b''))

    def test_reset_real_lifecycle_lock_contention_preconditions_deletion_and_release(self):
        # Use the production directory-inode flock, not an acquisition mock.
        # Only host paths/discovery are redirected to this isolated fixture.
        shell = r'''
set -euo pipefail
source "$1"
ROOT="$2"
AMNEZIAWG_DIR="$ROOT/target"
AWG_STATE_JOURNAL_DIR="$ROOT/journals"
DIGEST="$(printf 'c%.0s' {1..64})"
JOURNAL="$AWG_STATE_JOURNAL_DIR/$DIGEST"
mkdir -p "$JOURNAL/recovery"
printf 'awg0\n' >"$JOURNAL/finalized"
printf sensitive >"$JOURNAL/recovery/snapshot"
isRoot() { return 0; }
isWebPanelInstalled() { return 1; }
INSTALLER_LIFECYCLE_LOCK_DIR="$ROOT/lifecycle"
assert_locked() {
    if flock -xn "$ROOT/lifecycle" -c true; then echo 'ERROR: lifecycle lock not held' >&2; return 97; fi
}
awgStateTrustedPath() { assert_locked; }
systemctl() {
    assert_locked
    case "$2" in
        --property=ActiveState) printf 'inactive\n' ;;
        --property=UnitFileState) printf 'disabled\n' ;;
        *) return 96 ;;
    esac
}
rm() { assert_locked; printf 'rm\n' >>"$ROOT/deletions"; command rm "$@"; }
rmdir() { assert_locked; printf 'rmdir\n' >>"$ROOT/deletions"; command rmdir "$@"; }
acquireClientLifecycleLock
if awgStatePurgeJournal "$DIGEST" --reset-finalized; then exit 10; fi
[[ -f "$JOURNAL/finalized" && -f "$JOURNAL/recovery/snapshot" && ! -e "$ROOT/deletions" ]]
assert_locked # The failed contender must not release the original holder.
releaseClientLifecycleLock
awgStatePurgeJournal "$DIGEST" --reset-finalized
[[ ! -e "$JOURNAL" ]]
[[ "$(command -p cat "$ROOT/deletions")" == *rmdir* ]]
flock -xn "$ROOT/lifecycle" -c true # Released after successful deletion.
mkdir -p "$JOURNAL" "$AMNEZIAWG_DIR"
printf 'awg0\n' >"$JOURNAL/finalized"
printf retained >"$AMNEZIAWG_DIR/params"
if awgStatePurgeJournal "$DIGEST" --reset-finalized; then exit 11; fi
[[ -f "$JOURNAL/finalized" ]]
flock -xn "$ROOT/lifecycle" -c true # Released after a precondition failure too.
'''
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)], capture_output=True)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        self.assertIn(b'another client or protocol management operation', result.stderr)
        self.assertNotIn(b'lifecycle lock not held', result.stderr)

    def test_reset_reports_all_blocking_config_paths_without_printing_contents(self):
        target = self.root / 'target'
        target.mkdir()
        for name in ('awg0.conf', 'old note.conf', 'bad\nname.conf', 'escape\x1b[31m.conf', 'bidi\u202ename.conf'):
            (target / name).write_text(KEY)
        (target / 'dangling.conf').symlink_to(self.root / 'absent')
        shell = r'''
set -euo pipefail
export LC_ALL=C.UTF-8 # Reproduce bidi passthrough in the caller's UTF-8 locale.
source "$1"
ROOT="$2"
AMNEZIAWG_DIR="$ROOT/target"
AWG_STATE_JOURNAL_DIR="$ROOT/journals"
DIGEST="$(printf 'd%.0s' {1..64})"
JOURNAL="$AWG_STATE_JOURNAL_DIR/$DIGEST"
mkdir -p "$JOURNAL"
printf 'awg0\n' >"$JOURNAL/finalized"
isRoot() { return 0; }
awgStateTrustedPath() { return 0; }
acquireClientLifecycleLock() { return 0; }
releaseClientLifecycleLock() { return 0; }
systemctl() { echo 'unexpected service query' >&2; return 99; }
if awgStatePurgeJournal "$DIGEST" --reset-finalized; then exit 10; fi
[[ -f "$JOURNAL/finalized" && -f "$AMNEZIAWG_DIR/awg0.conf" ]]
'''
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)], capture_output=True)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        for name in (b'awg0.conf', b'old\\ note.conf', b'bad\\nname.conf', b'dangling.conf'):
            self.assertIn(name, result.stderr)
        self.assertNotIn(b'bad\nname.conf', result.stderr)
        self.assertNotIn(b'\x1b', result.stderr)
        self.assertNotIn('\u202e'.encode(), result.stderr)
        self.assertIn(b'bidi\\342\\200\\256name.conf', result.stderr)
        self.assertNotIn(KEY.encode(), result.stdout + result.stderr)
        self.assertNotIn(b'unexpected service query', result.stderr)

    def test_stable_lock_preserves_native_panel_database_serialization(self):
        shell = r"""
set -euo pipefail
source "$1"
ROOT="$2"
AMNEZIAWG_DIR="$ROOT/target"
INSTALLER_LIFECYCLE_LOCK_DIR="$ROOT/lifecycle"
WEB_PANEL_SYSTEMD_UNIT="$ROOT/web.service"
WEB_PANEL_ENV_FILE="$ROOT/absent.env"
systemctl() { return 1; }
mkdir -p "$ROOT/panel-state"
printf '[Service]\nEnvironment=AWG_WEB_DB=%s/panel-state/panel.db\n' "$ROOT" >"$WEB_PANEL_SYSTEMD_UNIT"
[[ "$(resolveClientLifecycleLockDir)" == "$ROOT/panel-state" ]]
acquireClientLifecycleLock
if flock -xn "$INSTALLER_LIFECYCLE_LOCK_DIR" -c true; then exit 10; fi
if flock -xn "$ROOT/panel-state" -c true; then exit 11; fi
if (acquireClientLifecycleLock); then exit 12; fi
releaseClientLifecycleLock
# Native Rust uses flock on this same read-only database-directory inode.
exec {native_fd}< "$ROOT/panel-state"
flock -xn "$native_fd"
if acquireClientLifecycleLock; then exit 13; fi
flock -xn "$INSTALLER_LIFECYCLE_LOCK_DIR" -c true # Partial acquisition released.
[[ ! -e "$AMNEZIAWG_DIR" ]]
exec {native_fd}>&-
acquireClientLifecycleLock
releaseClientLifecycleLock
before="$(stat -c '%d:%i' "$INSTALLER_LIFECYCLE_LOCK_DIR")"
rm "$WEB_PANEL_SYSTEMD_UNIT"
[[ "$(resolveClientLifecycleLockDir)" == "$INSTALLER_LIFECYCLE_LOCK_DIR" ]]
acquireClientLifecycleLock
releaseClientLifecycleLock
[[ "$(stat -c '%d:%i' "$INSTALLER_LIFECYCLE_LOCK_DIR")" == "$before" && ! -e "$AMNEZIAWG_DIR" ]]
"""
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)], capture_output=True)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        self.assertIn(b'another client or protocol management operation', result.stderr)

    def test_fresh_install_and_reset_share_real_lock_and_recheck_state(self):
        shell = r"""
set -euo pipefail
source "$1"
ROOT="$2"
AMNEZIAWG_DIR="$ROOT/target"
INSTALLER_LIFECYCLE_LOCK_DIR="$ROOT/lifecycle"
AWG_STATE_JOURNAL_DIR="$ROOT/journals"
DIGEST="$(printf 'e%.0s' {1..64})"
JOURNAL="$AWG_STATE_JOURNAL_DIR/$DIGEST"
mkdir -p "$JOURNAL"
printf 'awg0\n' >"$JOURNAL/finalized"
isRoot() { return 0; }
isWebPanelInstalled() { return 1; }
awgStateTrustedPath() { return 0; }
systemctl() { echo 'unexpected service query' >&2; return 99; }
installAmneziaWG() {
    if flock -xn "$INSTALLER_LIFECYCLE_LOCK_DIR" -c true; then return 90; fi
    # Simulate reset arriving while an ordinary fresh install owns the lock.
    if awgStatePurgeJournal "$DIGEST" --reset-finalized; then return 91; fi
    [[ -f "$JOURNAL/finalized" && ! -e "$AMNEZIAWG_DIR" ]] || return 92
    printf 'install\n' >>"$ROOT/installed"
    mkdir -p "$AMNEZIAWG_DIR"
    printf 'new installation\n' >"$AMNEZIAWG_DIR/params"
}
acquireClientLifecycleLock
if runLockedFreshInstall; then exit 10; fi
[[ ! -e "$ROOT/installed" && ! -e "$AMNEZIAWG_DIR" ]]
releaseClientLifecycleLock
runLockedFreshInstall
[[ "$(<"$ROOT/installed")" == install && -f "$AMNEZIAWG_DIR/params" ]]
if runLockedFreshInstall; then exit 11; fi # Recheck params under the lock.
[[ "$(<"$ROOT/installed")" == install ]]
flock -xn "$INSTALLER_LIFECYCLE_LOCK_DIR" -c true
rm "$AMNEZIAWG_DIR/params"
ln -s "$ROOT/absent" "$AMNEZIAWG_DIR/params"
if runLockedFreshInstall; then exit 12; fi
flock -xn "$INSTALLER_LIFECYCLE_LOCK_DIR" -c true
[[ -L "$AMNEZIAWG_DIR/params" && -f "$JOURNAL/finalized" ]]
rm "$AMNEZIAWG_DIR/params"
printf 'hand-made interface\n' >"$AMNEZIAWG_DIR/old.conf"
installAmneziaWG() {
    if flock -xn "$INSTALLER_LIFECYCLE_LOCK_DIR" -c true; then return 93; fi
    [[ "$(<"$AMNEZIAWG_DIR/old.conf")" == 'hand-made interface' ]] || return 94
    printf 'new installation\n' >"$AMNEZIAWG_DIR/params"
}
runLockedFreshInstall # Existing unrelated configs are not a new restriction.
[[ "$(<"$AMNEZIAWG_DIR/old.conf")" == 'hand-made interface' ]]
"""
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)], capture_output=True)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        self.assertIn(b'another client or protocol management operation', result.stderr)
        self.assertIn(b'installation state changed', result.stderr)
        self.assertNotIn(b'unexpected service query', result.stderr)
        self.assertIn('runLockedFreshInstall\n\tfi\nfi\n', SCRIPT.read_text())

    def test_staging_prefers_private_ram_backed_directory_with_safe_fallback(self):
        shell = r'''
set -euo pipefail
source "$1"
WORK="$(awgStateWorkDir)"
trap 'rm -rf -- "$WORK"' EXIT
[[ -d "$WORK" && "$(stat -c %a "$WORK")" == 700 ]]
if [[ -d /dev/shm && "$(stat -f -c %T /dev/shm)" == tmpfs ]]; then [[ "$WORK" == /dev/shm/awg-state.* ]]; fi
rm -rf -- "$WORK"
stat() { return 1; }
WORK="$(awgStateWorkDir)"
[[ "$WORK" == /tmp/awg-state.* && -d "$WORK" ]]
'''
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b'WARNING: RAM-backed staging unavailable', result.stderr)

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
INSTALLER_LIFECYCLE_LOCK_DIR="$ROOT/lifecycle"
isWebPanelInstalled() { return 1; }
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
SERVER_PUB_IP=203.0.113.7 awgStateCommand --import-state "$ROOT/state.tar.gz" --dry-run >"$ROOT/dry-run.out" || exit 10
[[ ! -e "$AMNEZIAWG_DIR" && ! -e "$AWG_STATE_JOURNAL_DIR" && ! -e "$ROOT/install.log" ]] || exit 11
[[ "$(<"$AWG_SYSCTL_FILE")" == 'original sysctl' ]] || exit 12
FAIL_INSTALL=1
awgStateCommand --import-state "$ROOT/state.tar.gz"
[[ $? -ne 0 && ! -e "$AMNEZIAWG_DIR" && -d "$INSTALLER_LIFECYCLE_LOCK_DIR" ]] || exit 41
[[ "$(grep -c '^install$' "$ROOT/install.log")" == 1 ]] || exit 42
mkdir -m 755 "$AMNEZIAWG_DIR"
FAIL_INSTALL=1
awgStateCommand --import-state "$ROOT/state.tar.gz"
[[ $? -ne 0 ]] || exit 13
[[ -d "$AMNEZIAWG_DIR" && ! -e "$AMNEZIAWG_DIR/params" && "$(stat -c %a "$AMNEZIAWG_DIR")" == 700 && ! -e "$AWG_SYSTEMD_UNIT_DIR/awg-quick@awg0.service.d" ]] || exit 14
[[ "$(<"$AWG_SYSCTL_FILE")" == 'original sysctl' ]] || exit 15
FAIL_INSTALL=0
rmdir "$AMNEZIAWG_DIR" || exit 43 # Truly fresh successful import with the retained lock inode.
SERVER_PUB_IP=new-vpn.example.test awgStateCommand --import-state "$ROOT/state.tar.gz" || exit 16
grep -qx "SERVER_PUB_IP='new-vpn.example.test'" "$AMNEZIAWG_DIR/params" || exit 44
[[ -f "$AMNEZIAWG_DIR/params" && -f "$AMNEZIAWG_DIR/awg0.conf" ]] || exit 17
[[ "$(grep -c '^install$' "$ROOT/install.log")" == 3 ]] || exit 18
awgStateCommand --import-state "$ROOT/state.tar.gz" || exit 19
[[ "$(grep -c '^install$' "$ROOT/install.log")" == 3 ]] || exit 20
! grep -Eq '^(start|enable|restart) ' "$ROOT/systemctl.log" || exit 21
printf '\n# local change\n' >>"$AMNEZIAWG_DIR/awg0.conf"
awgStateCommand --import-state "$ROOT/state.tar.gz"
[[ $? -ne 0 ]] || exit 22
'''
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)], capture_output=True)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        self.assertNotIn(KEY.encode(), result.stdout + result.stderr)
        self.assertIn('rollback', ''.join(p.read_text() for p in (self.root / 'journals').glob('*/steps')))
        self.assertIn(b'SERVER_PUB_IP is an IP literal', result.stderr)
        # The encrypted archive is the recovery copy: no plaintext keys or panel DB in journals.
        journal_files = [p for p in (self.root / 'journals').rglob('*') if p.is_file()]
        self.assertTrue(journal_files)
        self.assertFalse(list((self.root / 'journals').glob('*/recovery')))
        for path in journal_files:
            data = path.read_bytes()
            self.assertNotIn(KEY.encode(), data, path)
            self.assertNotIn(PEER.encode(), data, path)
            self.assertNotIn(b'SQLite format 3', data, path)
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
                ('finalize', '--activate-state', '2999-01-01T00:00:00Z'),
                ('recover-after-uninstall', '--activate-state', '2999-01-01T00:00:00Z'),
                ('enable-failure', '--activate-state', '2999-01-01T00:00:00Z'),
                ('activation-crossed', '--activate-state', '2001-01-01T00:00:20Z'),
                ('activation-real-clock', '--activate-state', ''),
                ('reimport-future', '--import-state', '2999-01-01T00:00:00Z'),
                ('dry-run', '--dry-run', '2999-01-01T00:00:00Z'),
                ('bad-schema', '--activate-state', '2999-01-01T00:00:00Z')):
            with self.subTest(name=name):
                root = self.root / name
                root.mkdir()
                if name == 'recover-after-uninstall':
                    (root / 'test-recovery').touch()
                if name == 'enable-failure':
                    (root / 'fail-enable').touch()
                if name == 'activation-real-clock':
                    expiry = (datetime.now(timezone.utc) + timedelta(seconds=5)).strftime('%Y-%m-%dT%H:%M:%SZ')
                    (root / 'real-deadline').write_text(expiry)
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
OPTION="${4:-}"
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
INSTALLER_LIFECYCLE_LOCK_DIR="$ROOT/lifecycle"
isWebPanelInstalled() { return 1; }
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
        is-active) [[ -e "$ROOT/active" ]] ;;
        is-enabled) [[ -e "$ROOT/enabled" ]] ;;
        start) touch "$ROOT/active"; cp "$SERVER_AWG_CONF" "$ROOT/at-start.conf"; printf 'start\n' >>"$ROOT/events" ;;
        enable) printf 'enable\n' >>"$ROOT/events"; [[ ! -e "$ROOT/fail-enable" ]] || return 17; touch "$ROOT/enabled" ;;
        disable) printf 'disable\n' >>"$ROOT/events"; rm -f "$ROOT/enabled" ;;
        stop) printf 'stop\n' >>"$ROOT/events"; rm -f "$ROOT/active" ;;
        *) echo 'unexpected systemctl command' >&2; return 90 ;;
    esac
}
if [[ -f "$ROOT/real-deadline" ]]; then
    awgStateArchive prepare "$ROOT/reference" || exit 23
    python3 - "$ROOT/real-deadline" <<'WAIT_REAL_CLOCK'
from datetime import datetime, timezone
from pathlib import Path
import sys, time
deadline = datetime.fromisoformat(Path(sys.argv[1]).read_text().replace('Z', '+00:00'))
remaining = (deadline - datetime.now(timezone.utc)).total_seconds()
if remaining > 0:
    time.sleep(remaining + 0.02)
WAIT_REAL_CLOCK
fi
if [[ "$MODE" == --dry-run ]]; then
    awgStateCommand --import-state "$ROOT/state.tar.gz" --dry-run
else
    awgStateCommand "$MODE" "$ROOT/state.tar.gz" ${OPTION:+"$OPTION"}
fi
STATUS=$?
[[ $STATUS -eq 0 ]] || exit "$STATUS"
sha256sum -c --status "$JOURNAL/receipt" || exit 14
if [[ "$OPTION" == --enable-at-boot ]]; then
    [[ -f "$ROOT/enabled" && -f "$JOURNAL/finalized" ]] || exit 15
    # Simulated reboot: an enabled service starts using local state, no archive.
    systemctl stop "awg-quick@awg0"
    systemctl start "awg-quick@awg0"
    printf '\n# operator edit after finalization\n' >>"$SERVER_AWG_CONF"
    cp "$SERVER_AWG_CONF" "$ROOT/finalized.conf"
    awgStateCommand --import-state "$ROOT/state.tar.gz" || exit 16
    awgStateCommand --activate-state "$ROOT/state.tar.gz" --enable-at-boot || exit 17
    cmp "$SERVER_AWG_CONF" "$ROOT/finalized.conf" || exit 18
    cp "$AMNEZIAWG_DIR/params" "$ROOT/original-public-cache"
    python3 - "$AMNEZIAWG_DIR/params" <<'STALE_PUBLIC_CACHE'
from pathlib import Path
import base64, re, sys
path = Path(sys.argv[1])
path.write_text(re.sub(r"(?m)^SERVER_PUB_KEY=.*$", "SERVER_PUB_KEY='" + base64.b64encode(b'Z' * 32).decode() + "'", path.read_text()))
STALE_PUBLIC_CACHE
    awgStateCommand --import-state "$ROOT/state.tar.gz" || exit 39
    cmp "$SERVER_AWG_CONF" "$ROOT/finalized.conf" || exit 40
    cp "$ROOT/original-public-cache" "$AMNEZIAWG_DIR/params"
    cp "$JOURNAL/steps" "$ROOT/finalized-steps"
    awgStatePurgeJournal "${JOURNAL##*/}" || exit 19
    [[ ! -e "$JOURNAL/receipt" && -f "$JOURNAL/finalized" ]] || exit 20
    awgStateCommand --activate-state "$ROOT/state.tar.gz" --enable-at-boot || exit 21
    cmp "$SERVER_AWG_CONF" "$ROOT/finalized.conf" || exit 22
    if [[ -f "$ROOT/test-recovery" ]]; then
        # Reset cannot silently undo finalization on an existing installation.
        if awgStatePurgeJournal "${JOURNAL##*/}" --reset-finalized; then exit 24; fi
        cp "$AMNEZIAWG_DIR/params" "$ROOT/saved-params"
        cp "$SERVER_AWG_CONF" "$ROOT/saved-server"
        python3 - "$AMNEZIAWG_DIR/params" <<'OTHER_IDENTITY'
from pathlib import Path
import base64, re, sys
path = Path(sys.argv[1])
text = path.read_text()
path.write_text(re.sub(r"(?m)^SERVER_PRIV_KEY=.*$", "SERVER_PRIV_KEY='" + base64.b64encode(b'Z' * 32).decode() + "'", text))
OTHER_IDENTITY
        if awgStateCommand --import-state "$ROOT/state.tar.gz"; then exit 37; fi
        cp "$ROOT/saved-params" "$AMNEZIAWG_DIR/params"
        rm "$AMNEZIAWG_DIR/params"
        if awgStateCommand --import-state "$ROOT/state.tar.gz"; then exit 25; fi
        if awgStatePurgeJournal "${JOURNAL##*/}" --reset-finalized; then exit 38; fi
        cp "$ROOT/saved-params" "$AMNEZIAWG_DIR/params"
        rm "$SERVER_AWG_CONF"
        if awgStateCommand --import-state "$ROOT/state.tar.gz"; then exit 26; fi
        cp "$ROOT/saved-server" "$SERVER_AWG_CONF"
        # Simulate uninstall: service stopped/disabled and local files removed;
        # retain the finalized tombstone exactly as the real uninstaller does.
        before_uninstall_lock_inode="$(stat -c '%d:%i' "$INSTALLER_LIFECYCLE_LOCK_DIR")"
        systemctl stop awg-quick@awg0
        systemctl disable awg-quick@awg0
        rm -rf -- "$AMNEZIAWG_DIR"
        if awgStateCommand --import-state "$ROOT/state.tar.gz"; then exit 27; fi
        [[ -f "$JOURNAL/finalized" ]] || exit 28
        systemctl() {
            case "$1" in
                show)
                    [[ ! -e "$ROOT/unreadable-service" ]] || return 1
                    case "$2" in
                        --property=ActiveState) [[ ! -e "$ROOT/active" ]] && printf 'inactive\n' || printf 'active\n' ;;
                        --property=UnitFileState) [[ ! -e "$ROOT/enabled" ]] && printf 'disabled\n' || printf 'enabled\n' ;;
                    esac ;;
                is-active|is-enabled) return 1 ;;
                daemon-reload) return 0 ;;
                *) return 90 ;;
            esac
        }
        touch "$ROOT/unreadable-service"
        if awgStatePurgeJournal "${JOURNAL##*/}" --reset-finalized; then exit 29; fi
        rm "$ROOT/unreadable-service"
        touch "$ROOT/active"
        if awgStatePurgeJournal "${JOURNAL##*/}" --reset-finalized; then exit 30; fi
        rm "$ROOT/active"
        touch "$ROOT/enabled"
        if awgStatePurgeJournal "${JOURNAL##*/}" --reset-finalized; then exit 31; fi
        rm "$ROOT/enabled"
        awgStatePurgeJournal "${JOURNAL##*/}" --reset-finalized || exit 32
        [[ ! -e "$JOURNAL" && ! -e "$AMNEZIAWG_DIR" && "$(stat -c '%d:%i' "$INSTALLER_LIFECYCLE_LOCK_DIR")" == "$before_uninstall_lock_inode" ]] || exit 33
        AWG_SYSTEMD_UNIT_DIR="$ROOT/units"
        AWG_MODULES_LOAD_FILE="$ROOT/modules/awg.conf"
        AWG_BT_MODPROBE_OVERRIDE="$ROOT/modprobe/awg.conf"
        mkdir -p "$AWG_SYSTEMD_UNIT_DIR" "$ROOT/modules" "$ROOT/modprobe"
        ip() { [[ "$*" == 'link show dev ens99' ]]; }
        ss() { return 0; }
        awg() { [[ "$1" == pubkey ]] && printf '%s\n' "$SERVER_PUB_KEY"; }
        writeFirewallRules() { printf 'PostUp = echo regenerated-uplink-%s\n' "$SERVER_PUB_NIC"; }
        installAmneziaWG() { writeAwgServerInstallState; }
        awgStateCommand --import-state "$ROOT/state.tar.gz" || exit 34
        [[ -f "$AMNEZIAWG_DIR/params" && -f "$SERVER_AWG_CONF" && -f "$JOURNAL/receipt" && ! -e "$JOURNAL/finalized" ]] || exit 35
        sha256sum -c --status "$JOURNAL/receipt" || exit 36
    fi
fi
'''
                result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(root), mode, '--enable-at-boot' if name in ('finalize', 'enable-failure', 'recover-after-uninstall') else ''], capture_output=True)
                if name == 'enable-failure':
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse((root / 'enabled').exists())
                    self.assertFalse((root / 'active').exists())
                    self.assertFalse(list((root / 'journals').glob('*/finalized')))
                    self.assertEqual((root / 'events').read_text(), 'validate\nsysctl\nstart\nenable\ndisable\nstop\n')
                    continue
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
                if name == 'recover-after-uninstall':
                    self.assertIn(b'finalized migration local params/server config are missing', result.stderr)
                    self.assertIn(b'--reset-state-journal', result.stderr)
                    self.assertIn(b'different server identity', result.stderr)
                    self.assertIn(b're-evaluated against the current host clock', result.stderr)
                    self.assertIn(b'Fresh import may proceed', result.stdout)
                    clean = (root / 'target/awg0.conf').read_text()
                    self.assertIn(PEER, clean)
                    self.assertIn(permanent, clean)
                    self.assertIn(removed, clean)  # Only explicit reset permits full snapshot replay.
                    self.assertNotIn(pending, clean)
                    self.assertFalse(list((root / 'journals').glob('*/finalized')))
                    continue
                clean = (root / 'target/awg0.conf').read_text()
                self.assertEqual(PEER in clean, expiry.startswith('2999'))
                self.assertNotIn(pending, clean)
                self.assertNotIn(removed, clean)  # Never rebuild peers from the snapshot.
                self.assertIn(permanent, clean)
                self.assertIn('PostUp = echo local-generated-hook', clean)
                self.assertIn('future-expiry peers migrate', result.stdout.decode())
                if name in ('activation-crossed', 'activation-real-clock'):
                    self.assertIn(b'"reason": "future_expiry"', result.stdout)
                    self.assertIn(b'"reason": "expired"', result.stdout)
                    self.assertIn(b'"name": "phone"', result.stdout)
                    self.assertIn(('"expires_at": "' + expiry + '"').encode(), result.stdout)
                if name == 'finalize':
                    self.assertTrue((root / 'enabled').exists())
                    self.assertEqual(next((root / 'journals').glob('*/finalized')).read_text(), 'awg0\n')
                    self.assertIn('finalized', (root / 'finalized-steps').read_text())
                    self.assertIn(b'already finalized; archived policy is not replayed', result.stdout)
                    self.assertIn(b'--purge-state-journal', result.stdout)
                    self.assertIn(b'WARNING: cached SERVER_PUB_KEY', result.stderr)
                    self.assertEqual((root / 'events').read_text(), 'validate\nsysctl\nstart\nenable\nstop\nstart\n')
                elif mode == '--activate-state':
                    self.assertEqual((root / 'at-start.conf').read_text(), clean)
                    self.assertEqual((root / 'events').read_text(), 'validate\nsysctl\nstart\n')
                else:
                    self.assertFalse((root / 'events').exists())
                self.assertIn('reconciled', (root / 'finalized-steps').read_text() if name == 'finalize' else next((root / 'journals').glob('*/steps')).read_text())

    def test_finalized_identity_checks_params_interface_and_config_without_replaying_policy(self):
        expected = self.root / 'expected-params'
        local = self.root / 'local-params'
        conf = self.root / 'local.conf'
        expected.write_bytes(self.files['vpn/params'])
        local.write_bytes(self.files['vpn/params'])
        conf.write_bytes(self.files['vpn/server.conf'])
        self.run_helper('local-identity', expected, local, conf)
        # Identity-only guard deliberately permits ordinary post-finalization edits.
        local.write_bytes(self.files['vpn/params'].replace(b"SERVER_PORT='51820'", b"SERVER_PORT='51821'"))
        conf.write_bytes(self.files['vpn/server.conf'].replace(b'ListenPort = 51820', b'ListenPort = 51821'))
        self.run_helper('local-identity', expected, local, conf)
        conf.write_bytes(self.files['vpn/server.conf'].replace(b'[Interface]', b'[Interface] # local formatting').replace(
            b'PrivateKey = ' + KEY.encode(), b'PrivateKey = ' + KEY.encode() + b' # same identity'))
        self.run_helper('local-identity', expected, local, conf)
        other = base64.b64encode(b'Z' * 32).decode().encode()
        valid_conf = conf.read_bytes()
        for cached in (other, b'stale-cache', None):
            data = self.files['vpn/params']
            if cached is None:
                data = b'\n'.join(line for line in data.split(b'\n') if not line.startswith(b'SERVER_PUB_KEY='))
            else:
                data = data.replace(b"SERVER_PUB_KEY='" + PUB.encode() + b"'", b"SERVER_PUB_KEY='" + cached + b"'")
            local.write_bytes(data)
            result = self.run_helper('local-identity', expected, local, conf)
            self.assertIn(b'WARNING: cached SERVER_PUB_KEY', result.stderr)
            self.assertNotIn(other, result.stderr)
            self.assertNotIn(KEY.encode(), result.stderr)
            if cached is None or cached == b'stale-cache':
                self.run_helper('params', local, ok=False)  # Import/export parsing remains strict.
            # Non-authoritative metadata never masks either private-key mismatch.
            local.write_bytes(data.replace(b"SERVER_PRIV_KEY='" + KEY.encode() + b"'",
                                          b"SERVER_PRIV_KEY='" + other + b"'"))
            result = self.run_helper('local-identity', expected, local, conf, ok=False)
            self.assertIn(b'different server identity', result.stderr)
            self.assertNotIn(b'WARNING: cached SERVER_PUB_KEY', result.stderr)
            local.write_bytes(data)
            conf.write_bytes(valid_conf.replace(KEY.encode(), other))
            result = self.run_helper('local-identity', expected, local, conf, ok=False)
            self.assertIn(b'different server identity', result.stderr)
            self.assertNotIn(b'WARNING: cached SERVER_PUB_KEY', result.stderr)
            conf.write_bytes(valid_conf)
        for field, old, new in ((b'SERVER_PRIV_KEY', KEY.encode(), other),
                                 (b'SERVER_AWG_NIC', b'awg0', b'awg1')):
            with self.subTest(field=field):
                local.write_bytes(self.files['vpn/params'].replace(field + b"='" + old + b"'", field + b"='" + new + b"'"))
                result = self.run_helper('local-identity', expected, local, conf, ok=False)
                self.assertIn(b'different server identity', result.stderr)
                self.assertNotIn(other, result.stderr)
        local.write_bytes(self.files['vpn/params'])
        for data in (self.files['vpn/server.conf'].replace(KEY.encode(), other),
                     self.files['vpn/server.conf'] + b'\n[Interface]\n',
                     self.files['vpn/server.conf'].replace(b'PrivateKey = ' + KEY.encode(), b'# PrivateKey removed')):
            conf.write_bytes(data)
            self.assertIn(b'different server identity', self.run_helper('local-identity', expected, local, conf, ok=False).stderr)
        conf.unlink()
        self.assertIn(b'finalized local', self.run_helper('local-identity', expected, local, conf, ok=False).stderr)

    def test_invalid_arguments_never_enter_interactive_install(self):
        for args in (['--export-state'], ['--inspect-state', 'x', '--dry-run'],
                     ['--import-state', 'x', '--unknown'], ['--import-state', '--dry-run'],
                     ['--activate-state'], ['--activate-state', 'x', '--dry-run'],
                     ['--import-state', 'x', '--enable-at-boot'], ['--purge-state-journal'],
                     ['--purge-state-journal', '../x', '--force'], ['--purge-state-journal', 'a'*64, '--unknown'],
                     ['--reset-state-journal', 'a'*64], ['--reset-state-journal', '../x', '--confirm-policy-replay'],
                     ['--reset-state-journal', 'a'*64, '--force']):
            result = subprocess.run(['bash', str(SCRIPT), *args], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'Usage:', result.stderr)

    @unittest.skipUnless(shutil.which('age'), 'age not installed')
    def test_age_passphrase_roundtrip_and_wrong_passphrase(self):
        """Real age and controlling TTY; the secret is never in argv or env."""
        def run_age(args, responses, program='age'):
            pid, fd = pty.fork()
            if pid == 0:
                settings = termios.tcgetattr(0)
                settings[3] &= ~termios.ECHO
                termios.tcsetattr(0, termios.TCSANOW, settings)
                os.execvp(program, [program, *args])
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
        source = self.root / 'source'
        for name, data in self.files.items():
            if name.startswith('vpn/'):
                path = source / ('awg0.conf' if name.endswith('server.conf') else 'params')
            else:
                path = source / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_bytes(data)
        (self.root / 'work').mkdir(mode=0o700)
        # Run the actual export pipeline with real age and a controlling TTY.
        # Only host discovery/locking is mocked, never packing or encryption.
        shell = r'''
set -euo pipefail
umask 077
source "$1"
ROOT="$2"
AMNEZIAWG_DIR="$ROOT/source"
AWG_STATE_PROXY_CONFIG="$ROOT/no-proxy"
acquireClientLifecycleLock() { return 0; }
awgStateTrustedPath() { return 0; }
isWebPanelInstalled() { return 1; }
collectAwgClientConfigCandidates() { local -n OUTPUT="$1"; OUTPUT=("$ROOT/source/clients/awg0-client-phone.conf"); }
awg() { [[ "$1" == --version ]] && printf 'fixture-tools\n'; }
awgStateExport "$ROOT/backup.awgx" "$ROOT/work"
[[ ! -e "$ROOT/work/state.tar.gz" ]]
'''
        rc, log = run_age(['-c', shell, 'test', str(SCRIPT), str(self.root)], [secret, secret], program='bash')
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


    def test_state_helper_runs_isolated_from_cwd_modules(self):
        # Root runs the embedded verifier from an arbitrary cwd: a planted
        # tarfile.py/json.py there must never be imported (python3 -I).
        planted = self.root / 'cwd'
        planted.mkdir()
        marker = self.root / 'planted-ran'
        for name in ('tarfile', 'json', 'hashlib'):
            (planted / f'{name}.py').write_text(f'open({str(marker)!r}, "w").write("pwned")\n')
        shell = r'''
set -euo pipefail
source "$1"
cd "$3"
awgStateArchive verify "$2"
'''
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.tar), str(planted)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertFalse(marker.exists())
        # Every python3 heredoc in the installer runs isolated.
        self.assertEqual(re.findall(r'python3 -(?!I )[^c]', SOURCE), [])

    def test_lifecycle_lock_falls_back_to_panel_lock_in_read_only_view(self):
        shell = r'''
set -uo pipefail
source "$1"
ROOT="$2"
mkdir -p "$ROOT/ro" "$ROOT/panel-state"
chmod 555 "$ROOT/ro" # Like /var/lib under the panel's ProtectSystem=strict.
INSTALLER_LIFECYCLE_LOCK_DIR="$ROOT/ro/amneziawg-install/lifecycle"
WEB_PANEL_ENV_FILE="$ROOT/absent.env"
WEB_PANEL_SYSTEMD_UNIT="$ROOT/web.service"
systemctl() { return 1; }
printf '[Service]\nEnvironment=AWG_WEB_DB=%s/panel-state/panel.db\n' "$ROOT" >"$WEB_PANEL_SYSTEMD_UNIT"
acquireClientLifecycleLock || exit 10
[[ -z "$CLIENT_LIFECYCLE_LOCK_FD" && -n "$CLIENT_PANEL_LIFECYCLE_LOCK_FD" ]] || exit 11
if flock -xn "$ROOT/panel-state" -c true; then exit 12; fi # Panel lock is held.
if (acquireClientLifecycleLock); then exit 13; fi
releaseClientLifecycleLock
flock -xn "$ROOT/panel-state" -c true || exit 14
[[ ! -e "$INSTALLER_LIFECYCLE_LOCK_DIR" ]] || exit 15
# Without a panel there is no shared lock to fall back to: fail closed.
rm "$WEB_PANEL_SYSTEMD_UNIT"
if acquireClientLifecycleLock; then exit 16; fi
# Once panel install/upgrade created it, the read-only directory is used.
chmod 755 "$ROOT/ro"; mkdir -p -m 700 "$INSTALLER_LIFECYCLE_LOCK_DIR"; chmod 555 "$ROOT/ro"
acquireClientLifecycleLock || exit 17
[[ -n "$CLIENT_LIFECYCLE_LOCK_FD" ]] || exit 18
releaseClientLifecycleLock
chmod 755 "$ROOT/ro"
'''
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)], capture_output=True)
        subprocess.run(['chmod', '-R', 'u+w', str(self.root)])
        if os.geteuid() == 0:
            self.skipTest('root bypasses the read-only directory permission')
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        # Non-TTY callers (the panel helper) get one short, greppable line.
        self.assertIn(b'NOTICE: lifecycle-lock-fallback=panel', result.stderr)
        self.assertNotIn(b'WARNING: cannot create', result.stderr)
        install_copy = INSTALLER_LOCK_FN.search((ROOT / 'amneziawg-web/scripts/amneziawg-web-install.sh').read_text())
        upgrade_copy = INSTALLER_LOCK_FN.search((ROOT / 'amneziawg-web/scripts/amneziawg-web-upgrade.sh').read_text())
        self.assertIsNotNone(install_copy)
        self.assertEqual(install_copy[0], upgrade_copy[0])
        self.assertIn('INSTALLER_LIFECYCLE_LOCK_DIR="/var/lib/amneziawg-install/lifecycle"', SOURCE)
        for script in ('amneziawg-web-install.sh', 'amneziawg-web-upgrade.sh'):
            text = (ROOT / 'amneziawg-web/scripts' / script).read_text()
            self.assertIn('INSTALLER_LIFECYCLE_LOCK_DIR="/var/lib/amneziawg-install/lifecycle"', text)
            self.assertIn('\n    ensure_installer_lifecycle_lock_dir\n', text)

    def test_export_releases_lock_before_prompt_checks_schema_and_skips_conflicts(self):
        source = self.root / 'source'
        (source / 'clients').mkdir(parents=True)
        (source / 'params').write_bytes(self.files['vpn/params'])
        (source / 'awg0.conf').write_bytes(self.files['vpn/server.conf'])
        (source / 'clients/awg0-client-phone.conf').write_bytes(self.files['clients/awg0-client-phone.conf'])
        (self.root / 'home').mkdir()
        (self.root / 'home/awg0-client-phone.conf').write_text('user-edited conflicting copy\n')
        bad = self.root / 'bad.sqlite'
        with closing(sqlite3.connect(bad)) as db, db:
            db.execute('CREATE TABLE peers(public_key TEXT)')
        (self.root / 'work').mkdir()
        shell = r'''
set -uo pipefail
source "$1"
ROOT="$2"
AMNEZIAWG_DIR="$ROOT/source"
AWG_STATE_PROXY_CONFIG="$ROOT/not-installed-proxy"
acquireClientLifecycleLock() { CLIENT_LIFECYCLE_LOCK_FD=held; }
releaseClientLifecycleLock() { CLIENT_LIFECYCLE_LOCK_FD=""; }
awgStateTrustedPath() { return 0; }
awgStateSnapshotPanel() { [[ -z "${BAD_DB:-}" ]] || { mkdir -p "$1/web" && cp "$BAD_DB" "$1/web/database.sqlite"; }; }
collectAwgClientConfigCandidates() { local -n OUTPUT="$1"; OUTPUT=("$ROOT/source/clients/awg0-client-phone.conf" "$ROOT/home/awg0-client-phone.conf"); }
awg() { printf 'fixture-tools\n'; }
age() { [[ -z "$CLIENT_LIFECYCLE_LOCK_FD" ]] || return 77; touch "$ROOT/age-ran"; cat >"$3"; }
BAD_DB="$ROOT/bad.sqlite" awgStateExport "$ROOT/bad-export" "$ROOT/work/a"
[[ $? -ne 0 && ! -e "$ROOT/age-ran" && ! -e "$ROOT/bad-export" ]] || exit 10
awgStateExport "$ROOT/good-export" "$ROOT/work/b" || exit 11
[[ -e "$ROOT/age-ran" ]] || exit 12
'''
        (self.root / 'work/a').mkdir()
        (self.root / 'work/b').mkdir()
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)], capture_output=True)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        self.assertIn(b'missing required columns', result.stderr)
        self.assertIn(b'skipped a conflicting same-name client config copy', result.stderr)
        with tarfile.open(self.root / 'good-export') as archive:
            data = archive.extractfile('clients/awg0-client-phone.conf').read()
            meta = json.load(archive.extractfile('manifest.json'))
        self.assertEqual(data, self.files['clients/awg0-client-phone.conf'])
        self.assertRegex(meta['versions']['installer_sha256'], r'^[0-9a-f]{64}$')

    def test_installer_sha256_unknown_when_not_run_from_a_regular_file(self):
        shell = r'source <(cat "$1"); awgStateInstallerSha256'
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT)], capture_output=True)
        self.assertEqual(result.stdout.strip(), b'unknown', result.stderr.decode())
        result = subprocess.run(['bash', '-c', 'source "$1"; awgStateInstallerSha256', 'test', str(SCRIPT)], capture_output=True)
        self.assertEqual(result.stdout.strip().decode(), hashlib.sha256(SCRIPT.read_bytes()).hexdigest())

    def test_identity_tombstone_blocks_not_newer_archives_until_reset(self):
        stage = self.root / 'stage'
        self.run_helper('unpack', self.tar, stage)
        shell = r'''
set -uo pipefail
source "$1"
ROOT="$2"; STAGE="$3"
AWG_STATE_JOURNAL_DIR="$ROOT/journals"
mkdir -p "$AWG_STATE_JOURNAL_DIR" "$ROOT/work"
awgStateTrustedPath() { return 0; }
DIGEST="$(printf 'b%.0s' {1..64})"
awgStateCheckIdentityTombstone "$STAGE" || exit 10 # Nothing finalized yet.
awgStateRecordIdentityTombstone "$STAGE" "$DIGEST" "$ROOT/work" || exit 11
[[ "$(stat -c %a "$AWG_STATE_JOURNAL_DIR/identities")" == 700 ]] || exit 12
if awgStateCheckIdentityTombstone "$STAGE"; then exit 13; fi # Same export time.
cp "$STAGE/manifest.json" "$ROOT/manifest.orig"
python3 - "$STAGE/manifest.json" <<'PY'
import json, sys
p = sys.argv[1]; m = json.load(open(p)); m['exported_at'] = '2000-01-01T00:00:00Z'; json.dump(m, open(p, 'w'))
PY
if awgStateCheckIdentityTombstone "$STAGE"; then exit 14; fi # Older archive.
cp "$ROOT/manifest.orig" "$STAGE/manifest.json"
printf '2000-01-01T00:00:00Z %s\n' "$DIGEST" >"$(echo "$AWG_STATE_JOURNAL_DIR"/identities/*)"
awgStateCheckIdentityTombstone "$STAGE" || exit 15 # Newer archive migrates.
awgStateDropIdentityTombstones "$(printf 'c%.0s' {1..64})" || exit 16
[[ -n "$(ls "$AWG_STATE_JOURNAL_DIR/identities")" ]] || exit 17
awgStateDropIdentityTombstones "$DIGEST" || exit 18
[[ -z "$(ls "$AWG_STATE_JOURNAL_DIR/identities")" ]] || exit 19
'''
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root), str(stage)], capture_output=True)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        self.assertIn(b'--reset-state-journal ' + b'b' * 64, result.stderr)

    def test_identity_tombstone_write_failure_is_retried_and_verifier_failure_fails(self):
        stage = self.root / 'stage'
        self.run_helper('unpack', self.tar, stage)
        shell = r'''
set -uo pipefail
source "$1"
ROOT="$2"; STAGE="$3"
AWG_STATE_JOURNAL_DIR="$ROOT/journals"
mkdir -p "$AWG_STATE_JOURNAL_DIR" "$ROOT/work"
awgStateTrustedPath() { return 0; }
D1="$(printf 'd%.0s' {1..64})"; D2="$(printf 'e%.0s' {1..64})"
: >"$AWG_STATE_JOURNAL_DIR/identities" # Blocks mkdir: write fails.
if awgStateRecordIdentityTombstone "$STAGE" "$D1" "$ROOT/work"; then exit 10; fi
awgStateWarnIdentityTombstone
rm "$AWG_STATE_JOURNAL_DIR/identities"
awgStateRecordIdentityTombstone "$STAGE" "$D1" "$ROOT/work" || exit 11 # Retry succeeds.
awgStateRecordIdentityTombstone "$STAGE" "$D2" "$ROOT/work" || exit 12 # Not newer: kept.
grep -q " $D1\$" "$AWG_STATE_JOURNAL_DIR"/identities/* || exit 13
# A verifier that prints plausible output but fails must not be trusted.
awgStateArchive() { printf '%s 2026-01-01T00:00:00Z\n' "$D1"; return 1; }
if awgStateCheckIdentityTombstone "$STAGE"; then exit 14; fi
if awgStateRecordIdentityTombstone "$STAGE" "$D2" "$ROOT/work"; then exit 15; fi
'''
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root), str(stage)], capture_output=True)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        self.assertIn(b'older archives of this server are NOT blocked', result.stderr)
        self.assertIn(b'rerun --activate-state', result.stderr)
        # The finalized rerun path retries the write (outside --dry-run).
        branch = SOURCE.split("Retry a server-identity tombstone write", 1)[1][:300]
        self.assertIn('awgStateRecordIdentityTombstone', branch)

    def test_import_entry_points_skip_fresh_mtu_admission_for_both_backends(self):
        shell = r"""
source "$1"
ensureSupportedInstallDistro() { return 0; }
selectFreshInstallBackend() { return 0; }
selectFreshInstallImitation() { return 0; }
freshOuterMtuBudget() { printf 1400; }
installQuestions() { return 0; }
checkBoringtunHostSupport() { return 0; }
# First host mutation after admission on both backends: stop there.
enable_apt_ipv4() { echo REACHED-INSTALL >&2; exit 42; }
apt-get() { echo REACHED-INSTALL >&2; exit 42; }
OS=debian CLIENT_MTU=1380 SERVER_AWG_S4=20
for backend in kernel boringtun; do
    AWG_BACKEND=$backend _AWG_STATE_IMPORT_DIR=/staged; (installAmneziaWG); echo "$backend import rc=$?"
    AWG_BACKEND=$backend _AWG_STATE_IMPORT_DIR=; (installAmneziaWG); echo "$backend fresh rc=$?"
done
"""
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT)], capture_output=True)
        out = result.stdout.decode()
        for backend in ('kernel', 'boringtun'):
            self.assertIn(f'{backend} import rc=42', out, result.stderr.decode())
            self.assertIn(f'{backend} fresh rc=1', out, result.stderr.decode())
        self.assertEqual(result.stderr.count(b'exceeds 1300'), 2)  # Fresh installs still refuse.

    def test_post_start_journal_append_failure_does_not_strand_running_vpn(self):
        journal = self.root / 'journal'
        (self.root / 'stage').mkdir()
        shell = r"""
set -uo pipefail
source "$1"
ROOT="$2"
AMNEZIAWG_DIR="$ROOT/vpn"; SERVER_AWG_NIC=awg0; AWG_STATE_JOURNAL_DIR="$ROOT/journals"
mkdir -p "$AMNEZIAWG_DIR" "$ROOT/work" "$ROOT/journal"; printf x >"$AMNEZIAWG_DIR/awg0.conf"
SERVER_AWG_CONF="$AMNEZIAWG_DIR/awg0.conf"; printf ens3 >"$ROOT/journal/nic"
acquireClientLifecycleLock() { return 0; }
awgStateTrustedPath() { return 0; }
sha256sum() { return 0; }
awgStateArchive() { [[ "$1" == identity ]] && return 1; cp -- "$2" "$4"; }
ensureAwgBackendReady() { return 0; }
validateStagedAwgConfigs() { return 0; }
sysctl() { return 0; }
awgStateWriteReceipt() { return 0; }
systemctl() {
    printf '%s\n' "$1" >>"$ROOT/systemctl.log"
    case "$1" in
        is-active|is-enabled) return 1 ;;
        start) touch "$ROOT/running"; rm -f "$ROOT/journal/steps"; ln -s /dev/full "$ROOT/journal/steps" ;;
        stop) rm -f "$ROOT/running" ;;
        enable) [[ "${FAIL_ENABLE:-0}" == 0 ]] || return 1; touch "$ROOT/enabled" ;;
        disable) rm -f "$ROOT/enabled" ;;
    esac
}
# ENOSPC on the audit log right after start: finalization still completes.
awgStateReconcileImport "$ROOT/stage" "$ROOT/journal" "$ROOT/work" --activate-state --enable-at-boot ens3 || exit 10
[[ -e "$ROOT/running" && -e "$ROOT/enabled" && "$(<"$ROOT/journal/finalized")" == awg0 ]] || exit 11
# A real post-start failure (enable) stops and disables; nothing is finalized.
rm -f "$ROOT/journal/finalized" "$ROOT/running" "$ROOT/enabled"
if FAIL_ENABLE=1 awgStateReconcileImport "$ROOT/stage" "$ROOT/journal" "$ROOT/work" --activate-state --enable-at-boot ens3; then exit 12; fi
[[ ! -e "$ROOT/running" && ! -e "$ROOT/enabled" && ! -e "$ROOT/journal/finalized" ]] || exit 13
"""
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)], capture_output=True)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        self.assertIn(b"could not append 'activated'", result.stderr)

    def test_retry_rollback_uses_fresh_before_image_including_absence(self):
        shell = r"""
set -uo pipefail
source "$1"
ROOT="$2"
AMNEZIAWG_DIR="$ROOT/vpn"; AWG_SYSTEMD_UNIT_DIR="$ROOT/units"; SERVER_AWG_NIC=awg0
AWG_SYSCTL_FILE="$ROOT/sysctl"; AWG_MODULES_LOAD_FILE="$ROOT/modules"; AWG_BT_MODPROBE_OVERRIDE="$ROOT/modprobe"
mkdir -p "$ROOT/journal" "$AWG_SYSTEMD_UNIT_DIR"
printf 'original\n' >"$AWG_SYSCTL_FILE"; printf 'mods\n' >"$AWG_MODULES_LOAD_FILE"
systemctl() { return 0; }
installAmneziaWG() { mkdir -p "$AMNEZIAWG_DIR"; printf 'attempt\n' | tee "$AWG_SYSCTL_FILE" "$AWG_MODULES_LOAD_FILE" "$AWG_BT_MODPROBE_OVERRIDE" >/dev/null; return 1; }
if awgStateImportTransaction "$ROOT/stage" "$ROOT/journal"; then exit 10; fi
[[ "$(<"$AWG_SYSCTL_FILE")" == original && ! -e "$AWG_BT_MODPROBE_OVERRIDE" ]] || exit 11
rm "$AWG_SYSCTL_FILE"                 # Operator change between attempts.
printf 'new-baseline\n' >"$AWG_BT_MODPROBE_OVERRIDE"
if awgStateImportTransaction "$ROOT/stage" "$ROOT/journal"; then exit 12; fi
[[ ! -e "$AWG_SYSCTL_FILE" ]] || exit 13 # Absence preserved, not resurrected.
[[ "$(<"$AWG_MODULES_LOAD_FILE")" == mods && "$(<"$AWG_BT_MODPROBE_OVERRIDE")" == new-baseline ]] || exit 14
[[ ! -e "$ROOT/journal/before.new" && ! -e "$ROOT/journal/before.old" ]] || exit 15
"""
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)], capture_output=True)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())

    def test_gzip_missing_trailer_or_bad_crc_fails_closed(self):
        original = self.tar.read_bytes()
        for name, data in (('missing-trailer', original[:-8]),
                           ('bad-crc', original[:-8] + b'\0\0\0\0' + original[-4:]),
                           ('bad-length', original[:-4] + b'\xff\xff\xff\x7f'),
                           ('trailing-garbage', original + b'garbage')):
            with self.subTest(name=name):
                self.tar.write_bytes(data)
                self.run_helper('verify', ok=False)
                self.run_helper('inspect', ok=False)
                destination = self.root / ('unpacked-' + name)
                self.run_helper('unpack', self.tar, destination, ok=False)
                self.assertFalse(destination.exists())
        self.tar.write_bytes(original)
        self.run_helper('verify')

    def test_rollback_survives_audit_log_failure_under_errexit(self):
        shell = r"""
set -uo pipefail
source "$1"
ROOT="$2"
AMNEZIAWG_DIR="$ROOT/vpn"; AWG_SYSTEMD_UNIT_DIR="$ROOT/units"; SERVER_AWG_NIC=awg0
AWG_SYSCTL_FILE="$ROOT/sysctl"; AWG_MODULES_LOAD_FILE="$ROOT/modules"; AWG_BT_MODPROBE_OVERRIDE="$ROOT/modprobe"
mkdir -p "$ROOT/journal" "$AWG_SYSTEMD_UNIT_DIR"
printf original >"$AWG_SYSCTL_FILE"
systemctl() { return 0; }
installAmneziaWG() {
    mkdir -p "$AMNEZIAWG_DIR"; printf PRIVATE-KEY >"$AMNEZIAWG_DIR/awg0.conf"
    printf mutated >"$AWG_SYSCTL_FILE"
    rm -f "$ROOT/journal/steps"; ln -s /dev/full "$ROOT/journal/steps" # ENOSPC
    return 1
}
# Plain command, not under if/!: production errexit stays active inside.
awgStateImportTransaction "$ROOT/stage" "$ROOT/journal"
rc=$?
[[ $rc -ne 0 && ! -e "$AMNEZIAWG_DIR" && "$(<"$AWG_SYSCTL_FILE")" == original ]] || exit 10
"""
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)], capture_output=True)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        self.assertIn(b"could not append 'rollback'", result.stderr)

    def activation_harness(self):
        return r"""
set -uo pipefail
source "$1"
ROOT="$2"
AMNEZIAWG_DIR="$ROOT/vpn"; SERVER_AWG_NIC=awg0; SERVER_AWG_CONF="$AMNEZIAWG_DIR/awg0.conf"
mkdir -p "$AMNEZIAWG_DIR" "$ROOT/work" "$ROOT/journal" "$ROOT/stage"
printf x >"$SERVER_AWG_CONF"; printf ens3 >"$ROOT/journal/nic"
acquireClientLifecycleLock() { return 0; }; awgStateTrustedPath() { return 0; }; sha256sum() { return 0; }
awgStateArchive() { [[ "$1" == identity ]] && return 1; cp -- "$2" "$4"; }
ensureAwgBackendReady() { return 0; }; validateStagedAwgConfigs() { return 0; }; sysctl() { return 0; }
awgStateWriteReceipt() { return 0; }
systemctl() {
    case "$1" in
        is-active|is-enabled) return 1 ;;
        start) touch "$ROOT/running"; [[ "$SIG_AT" != start ]] || kill -s "$SIG" "$BASHPID" ;;
        enable) touch "$ROOT/enabled"; [[ "$SIG_AT" != enable ]] || kill -s "$SIG" "$BASHPID" ;;
        stop) rm -f "$ROOT/running" ;;
        disable) rm -f "$ROOT/enabled" ;;
    esac
}
replaceFileExactly() {
    [[ "$SIG_AT" != marker || "$2" != */finalized ]] || kill -s "$SIG" "$BASHPID"
    cp -p -- "$1" "$2"
}
"""

    def test_signal_during_activation_stops_and_disables_unfinalized_vpn(self):
        for sig, code in (('TERM', 143), ('INT', 130), ('HUP', 129)):
            for point in ('start', 'enable', 'marker'):
                with self.subTest(sig=sig, point=point):
                    root = self.root / f'{sig}-{point}'
                    root.mkdir()
                    shell = self.activation_harness() + r"""
SIG="$3"; SIG_AT="$4"
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP # As awgStateCommand.
( awgStateReconcileImport "$ROOT/stage" "$ROOT/journal" "$ROOT/work" --activate-state --enable-at-boot ens3 )
echo "rc=$? running=$([[ -e $ROOT/running ]] && echo y || echo n) enabled=$([[ -e $ROOT/enabled ]] && echo y || echo n) finalized=$([[ -e $ROOT/journal/finalized ]] && echo y || echo n)"
"""
                    result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(root), sig, point],
                                            capture_output=True)
                    out = result.stdout.decode()
                    if point == 'marker':
                        # Interrupted while publishing: either finalized (terminal) or fully undone.
                        self.assertTrue(f'rc={code} running=n enabled=n finalized=n' in out or
                                        'running=y enabled=y finalized=y' in out, out + result.stderr.decode())
                    else:
                        self.assertIn(f'rc={code} running=n enabled=n finalized=n', out, result.stderr.decode())
        # Uninterrupted activation still finalizes and keeps the unit running.
        root = self.root / 'clean'
        root.mkdir()
        shell = self.activation_harness() + r"""
SIG=TERM SIG_AT=none
awgStateReconcileImport "$ROOT/stage" "$ROOT/journal" "$ROOT/work" --activate-state --enable-at-boot ens3 || exit 10
[[ -e $ROOT/running && -e $ROOT/enabled && -e $ROOT/journal/finalized ]] || exit 11
"""
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(root)], capture_output=True)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())

    def test_receipt_failure_restores_config_and_retry_recovers(self):
        shell = r"""
set -uo pipefail
source "$1"
ROOT="$2"
AMNEZIAWG_DIR="$ROOT/vpn"; SERVER_AWG_NIC=awg0; SERVER_AWG_CONF="$AMNEZIAWG_DIR/awg0.conf"
mkdir -p "$AMNEZIAWG_DIR" "$ROOT/journal" "$ROOT/w1" "$ROOT/w2"
printf original >"$SERVER_AWG_CONF"; printf params >"$AMNEZIAWG_DIR/params"; printf ens3 >"$ROOT/journal/nic"
sha256sum "$AMNEZIAWG_DIR/params" "$SERVER_AWG_CONF" >"$ROOT/journal/receipt"
acquireClientLifecycleLock() { return 0; }; awgStateTrustedPath() { return 0; }
awgStateArchive() { printf filtered >"$4"; } # Peer-removing reconciliation.
systemctl() { return 1; }
realWriteReceipt="$(declare -f awgStateWriteReceipt)"
awgStateWriteReceipt() { return 1; } # One-shot publication failure.
if awgStateReconcileImport "$ROOT/stage" "$ROOT/journal" "$ROOT/w1" --import-state '' ens3; then exit 10; fi
[[ "$(<"$SERVER_AWG_CONF")" == original ]] || exit 11
sha256sum -c --status "$ROOT/journal/receipt" || exit 12
eval "$realWriteReceipt"
awgStateReconcileImport "$ROOT/stage" "$ROOT/journal" "$ROOT/w2" --import-state '' ens3 || exit 13
[[ "$(<"$SERVER_AWG_CONF")" == filtered ]] && sha256sum -c --status "$ROOT/journal/receipt" || exit 14
"""
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)], capture_output=True)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())

    APT_TX = r"""
set -uo pipefail
source "$1"
ROOT="$2"; HOW="$3"
AMNEZIAWG_DIR="$ROOT/vpn"; AWG_SYSTEMD_UNIT_DIR="$ROOT/units"; SERVER_AWG_NIC=awg0
AWG_SYSCTL_FILE="$ROOT/sysctl"; AWG_MODULES_LOAD_FILE="$ROOT/modules"; AWG_BT_MODPROBE_OVERRIDE="$ROOT/modprobe"
APT_FORCE_IPV4_CONF="$ROOT/force-ipv4"; GAI_CONF="$ROOT/gai.conf"
mkdir -p "$ROOT/journal" "$AWG_SYSTEMD_UNIT_DIR"
printf original >"$AWG_SYSCTL_FILE"
mkdir() { [[ "$*" == '-p /etc/apt/apt.conf.d' ]] && return 0; command mkdir "$@"; }
systemctl() { return 0; }
installAmneziaWG() { mkdir -p "$AMNEZIAWG_DIR"; printf PRIVATE-KEY >"$AMNEZIAWG_DIR/awg0.conf"; printf mutated >"$AWG_SYSCTL_FILE"; }
ensureAwgBackendReady() { enable_apt_ipv4; case "$HOW" in exit) exit 7 ;; *) kill -s "$HOW" "$BASHPID" ;; esac; }
awgStateImportTransaction "$ROOT/stage" "$ROOT/journal"
echo "rc=$? config=$([[ -e "$AMNEZIAWG_DIR/awg0.conf" ]] && echo yes || echo no) sysctl=$(<"$AWG_SYSCTL_FILE") ipv4=$([[ -e "$APT_FORCE_IPV4_CONF" ]] && echo yes || echo no)"
"""

    def test_nested_apt_traps_never_bypass_import_rollback(self):
        for how, code in (('exit', 7), ('HUP', 129), ('TERM', 143), ('INT', 130)):
            with self.subTest(how=how):
                root = self.root / how
                root.mkdir()
                result = subprocess.run(['bash', '-c', self.APT_TX, 'test', str(SCRIPT), str(root), how], capture_output=True)
                self.assertIn(f'rc={code} config=no sysctl=original ipv4=no', result.stdout.decode(), result.stderr.decode())
                self.assertIn('rollback', (root / 'journal/steps').read_text())

    def test_apt_ipv4_exit_trap_chains_to_previous_handler(self):
        shell = r"""
source "$1"
APT_FORCE_IPV4_CONF="$2/force-ipv4"; GAI_CONF="$2/gai.conf"
mkdir() { [[ "$*" == '-p /etc/apt/apt.conf.d' ]] && return 0; command mkdir "$@"; }
( trap 'echo "previous-exit-handler status=$?"' EXIT; enable_apt_ipv4; exit 7 ); echo "rc=$?"
( trap 'echo previous-hup; exit 129' HUP; enable_apt_ipv4; kill -HUP "$BASHPID"; echo not-reached ); echo "rc=$?"
"""
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)], capture_output=True)
        out = result.stdout.decode()
        self.assertIn('previous-exit-handler status=7\nrc=7', out, result.stderr.decode())
        self.assertIn('previous-hup', out)
        self.assertIn('rc=129', out)
        self.assertNotIn('not-reached', out)
        self.assertFalse((self.root / 'force-ipv4').exists())

    def test_signal_between_config_and_receipt_keeps_them_consistent(self):
        for mode in ('--import-state', '--activate-state'):
            with self.subTest(mode=mode):
                root = self.root / mode.strip('-')
                root.mkdir()
                shell = r"""
set -uo pipefail
source "$1"
ROOT="$2"; MODE="$3"
AMNEZIAWG_DIR="$ROOT/vpn"; SERVER_AWG_NIC=awg0; SERVER_AWG_CONF="$AMNEZIAWG_DIR/awg0.conf"
mkdir -p "$AMNEZIAWG_DIR" "$ROOT/journal" "$ROOT/w1" "$ROOT/w2"
printf original >"$SERVER_AWG_CONF"; printf params >"$AMNEZIAWG_DIR/params"; printf ens3 >"$ROOT/journal/nic"
sha256sum "$AMNEZIAWG_DIR/params" "$SERVER_AWG_CONF" >"$ROOT/journal/receipt"
acquireClientLifecycleLock() { return 0; }; awgStateTrustedPath() { return 0; }
awgStateArchive() { printf filtered >"$4"; }
systemctl() { case "$1" in is-active|is-enabled) return 1 ;; start) touch "$ROOT/running" ;; stop) rm -f "$ROOT/running" ;; esac; return 0; }
ensureAwgBackendReady() { return 0; }; validateStagedAwgConfigs() { return 0; }; sysctl() { return 0; }
eval "$(declare -f replaceFileExactly | sed 's/^replaceFileExactly/realReplaceFileExactly/')"
replaceFileExactly() {
    realReplaceFileExactly "$@" || return
    [[ "$2" != "$SERVER_AWG_CONF" || "${SIGNAL_ONCE:-0}" != 1 ]] || kill -TERM "$BASHPID" # Real signal.
}
( trap 'exit 143' TERM; SIGNAL_ONCE=1; awgStateReconcileImport "$ROOT/stage" "$ROOT/journal" "$ROOT/w1" "$MODE" '' ens3 )
echo "interrupted rc=$? running=$([[ -e $ROOT/running ]] && echo y || echo n)"
sha256sum -c --status "$ROOT/journal/receipt" && echo receipt-ok
awgStateReconcileImport "$ROOT/stage" "$ROOT/journal" "$ROOT/w2" "$MODE" '' ens3; echo "retry rc=$?"
"""
                result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(root), mode], capture_output=True)
                out = result.stdout.decode()
                self.assertIn('interrupted rc=143 running=n', out, result.stderr.decode())
                self.assertIn('receipt-ok', out)
                self.assertIn('retry rc=0', out, result.stderr.decode())

    def test_reset_on_unfinalized_journal_points_to_forced_purge(self):
        shell = r'''
source "$1"
AWG_STATE_JOURNAL_DIR="$2/journals"
DIGEST="$(printf 'a%.0s' {1..64})"
mkdir -p "$AWG_STATE_JOURNAL_DIR/$DIGEST/before"
isRoot() { return 0; }
awgStateTrustedPath() { return 0; }
acquireClientLifecycleLock() { return 0; }
releaseClientLifecycleLock() { return 0; }
if awgStatePurgeJournal "$DIGEST" --reset-finalized; then exit 10; fi
[[ -d "$AWG_STATE_JOURNAL_DIR/$DIGEST/before" ]]
'''
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)], capture_output=True)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        self.assertIn(b'--purge-state-journal ' + b'a' * 64 + b' --force', result.stderr)

    def test_mtu_budget_warning_for_restored_server_mtu(self):
        conf = self.root / 'server.conf'
        conf.write_text('[Interface]\nMTU = 1420\nPrivateKey = x\n[Peer]\nMTU = 9000\n')
        shell = r'''
source "$1"
freshOuterMtuBudget() { printf 1400; }
SERVER_AWG_S4=18 CLIENT_MTU="" awgStateWarnMtuBudget "$2"
'''
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(conf)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b'restored server MTU 1420 exceeds', result.stderr)

    def test_fractional_expiry_and_small_clock_skew(self):
        # Python 3.9/3.10 fromisoformat accepts only 3 or 6 fractional digits.
        self.add_policy([(PEER, 0, 0, 0, '2999-01-01T00:00:00.5Z', None)])
        report = json.loads(self.run_helper('inspect').stdout)['peer_plan']
        self.assertEqual(report['peers'][0]['decision'], 'migrate')
        self.assertEqual(report['peers'][0]['expires_at'], '2999-01-01T00:00:00.500000Z')
        (self.root / 'fixture-policy.sqlite').unlink()
        self.add_policy([(PEER, 0, 0, 0, '2999-01-01T00:00:00.123456789+00:00', None)])
        report = json.loads(self.run_helper('inspect').stdout)['peer_plan']
        self.assertEqual(report['peers'][0]['decision'], 'migrate')
        meta = manifest(self.files)
        meta['exported_at'] = (datetime.now(timezone.utc) + timedelta(seconds=60)).strftime('%Y-%m-%dT%H:%M:%SZ')
        make_tar(self.tar, self.files, meta)
        self.run_helper('inspect')  # Within the tolerated skew.
        meta['exported_at'] = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        make_tar(self.tar, self.files, meta)
        self.assertIn(b'future relative to this host', self.run_helper('inspect', ok=False).stderr)

if __name__ == '__main__':
    unittest.main(verbosity=2)
