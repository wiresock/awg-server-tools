#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Vadim Smirnov (doing business as WireSock)
# SPDX-License-Identifier: MIT
"""Untrusted archive tests; no root, VPN, package manager or network required."""
from contextlib import closing
from datetime import datetime, timedelta, timezone
import base64
import copy
import errno
import hashlib
import gzip
import io
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import shutil
import sqlite3
import stat
import subprocess
import tarfile
import tempfile
import termios
import threading
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
        for field, value in (('schema_version', 3), ('schema_version', True),
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
        refused = self.run_helper('verify', ok=False)
        self.assertIn(b'client/peer hooks unsupported', refused.stderr)
        self.assertNotIn(b'touch', refused.stderr)
        self.assertNotIn(b'invalid or unsupported', refused.stderr)

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
eval "$(declare -f awgStateArchive | sed '1s/awgStateArchive/_real_awgStateArchive/')"
awgStateArchive() {
    if [[ "$1" == panel-snapshot ]]; then
        printf '%s' "$2" >"$ROOT/chosen"
    fi
    _real_awgStateArchive "$@"
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
        self.assertFalse((self.root / 'sysctl/awg.conf').exists(), 'quarantine published boot forwarding')
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

    def test_reset_retries_identity_failure_and_empty_journal_can_be_reused(self):
        stage = self.root / 'stage'
        self.run_helper('unpack', self.tar, stage)
        shell = r'''
set -euo pipefail
source "$1"
ROOT="$2"; STAGE="$3"; ARCHIVE="$4"
AMNEZIAWG_DIR="$ROOT/target"
AWG_STATE_JOURNAL_DIR="$ROOT/journals"
INSTALLER_LIFECYCLE_LOCK_DIR="$ROOT/lifecycle"
DIGEST="$(sha256sum "$STAGE/manifest.json")"; DIGEST="${DIGEST%% *}"
JOURNAL="$AWG_STATE_JOURNAL_DIR/$DIGEST"
mkdir -p "$JOURNAL/recovery" "$ROOT/work"
printf 'awg0\n' >"$JOURNAL/finalized"
printf synthetic >"$JOURNAL/recovery/snapshot"
printf 'temporary receipt\n' >"$JOURNAL/receipt"
isRoot() { return 0; }
isWebPanelInstalled() { return 1; }
awgStateTrustedPath() { [[ "$1" == "$ROOT/"* ]]; }
TEST_UNIT_STATE=disabled
systemctl() {
    case "$2" in
        --property=ActiveState) printf 'inactive\n' ;;
        --property=UnitFileState) printf '%s\n' "$TEST_UNIT_STATE" ;;
        *) return 96 ;;
    esac
}
awgStateRecordIdentityTombstone "$STAGE" "$DIGEST" "$ROOT/work"
IDENTITY=("$AWG_STATE_JOURNAL_DIR"/identities/*)
[[ ${#IDENTITY[@]} == 1 && -f "${IDENTITY[0]}" ]]
FAIL_IDENTITY=1; FAIL_FINALIZED=0; FAIL_RMDIR=0
rm() {
    local arg
    for arg in "$@"; do
        if [[ "$arg" == "${IDENTITY[0]}" && "$FAIL_IDENTITY" == 1 ]]; then return 71; fi
        if [[ "$arg" == "$JOURNAL/finalized" && "$FAIL_FINALIZED" == 1 ]]; then return 72; fi
    done
    command rm "$@"
}
rmdir() {
    if [[ "$*" == "-- $JOURNAL" && "$FAIL_RMDIR" == 1 ]]; then return 73; fi
    command rmdir "$@"
}

if awgStatePurgeJournal "$DIGEST" --reset-finalized; then exit 10; fi
if ! awgStateIsFinalized "$JOURNAL" awg0; then
    echo 'identity removal failure lost the finalized retry marker' >&2
    exit 11
fi
[[ -f "${IDENTITY[0]}" && ! -e "$JOURNAL/recovery" && ! -e "$JOURNAL/receipt" ]]
if awgStateCheckIdentityTombstone "$STAGE"; then exit 12; fi

# Preconditions are checked again even though the recovery files were pruned.
FAIL_IDENTITY=0; TEST_UNIT_STATE=enabled
if awgStatePurgeJournal "$DIGEST" --reset-finalized; then exit 13; fi
awgStateIsFinalized "$JOURNAL" awg0
[[ -f "${IDENTITY[0]}" ]]

TEST_UNIT_STATE=disabled; FAIL_FINALIZED=1
if awgStatePurgeJournal "$DIGEST" --reset-finalized 2>"$ROOT/finalized-unlink.err"; then exit 14; fi
awgStateIsFinalized "$JOURNAL" awg0
[[ ! -e "${IDENTITY[0]}" ]]

# A cleanup failure after unlinking the final marker leaves an empty,
# reusable directory, not an uncompleted reset.
FAIL_FINALIZED=0; FAIL_RMDIR=1
awgStatePurgeJournal "$DIGEST" --reset-finalized
[[ -d "$JOURNAL" && -z "$(ls -A -- "$JOURNAL")" ]]
checkOS() { OS=debian; }
awgStateDependencies() { return 0; }
awgStateWorkDir() { mktemp -d "$ROOT/export-work.XXXXXXXX"; }
age() { [[ "$1" == --decrypt && "$2" == --output && "$4" == "$ARCHIVE" ]] && cp -- "$4" "$3"; }
awgStateImportPreflight() { [[ "$1" == eth0 && ! -e "$AMNEZIAWG_DIR" ]]; }
EXPECTED_JOURNAL="$JOURNAL"
awgStateImportTransaction() {
    [[ "$2" == "$EXPECTED_JOURNAL" && -z "$(ls -A -- "$2")" ]] || return 74
    printf 'new import reached same journal\n' >"$ROOT/imported"
}
SERVER_PUB_NIC=eth0 awgStateCommand --import-state "$ARCHIVE"
[[ -f "$ROOT/imported" ]]
'''
        result = subprocess.run(
            ['bash', '-c', shell, 'test', str(SCRIPT), str(self.root), str(stage), str(self.tar)],
            capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        self.assertIn(b'--reset-state-journal ' + hashlib.sha256(
            (stage / 'manifest.json').read_bytes()).hexdigest().encode(), result.stderr)
        self.assertIn(b'disable the VPN before journal reset', result.stderr)
        unlink_error = (self.root / 'finalized-unlink.err').read_bytes()
        self.assertIn(b'server-identity cleanup completed', unlink_error)
        self.assertIn(b'finalized marker could not be removed', unlink_error)
        self.assertIn(b'rerun the same reset', unlink_error)
        self.assertIn(b'Finalized journal reset', result.stdout)
        self.assertIn(b'Imported in quarantine', result.stdout)

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

    def test_staging_prefers_private_ram_backed_directory_and_refuses_disk(self):
        shell = r'''
set -euo pipefail
source "$1"
WORK="$(awgStateWorkDir)"
trap 'rm -rf -- "$WORK"' EXIT
[[ -d "$WORK" && "$(stat -c %a "$WORK")" == 700 ]]
if [[ -d /dev/shm && "$(stat -f -c %T /dev/shm)" == tmpfs ]]; then [[ "$WORK" == /dev/shm/awg-state.* ]]; fi
rm -rf -- "$WORK"
stat() { printf 'ext2/ext3\n'; }
mktemp() { echo "mktemp-called $*" >&2; return 1; }
if WORK="$(awgStateWorkDir)"; then exit 10; fi
[[ -z "$WORK" ]]
'''
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b'refusing to stage decrypted state on disk', result.stderr)
        self.assertNotIn(b'mktemp-called', result.stderr)

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
# A rollback-incomplete marker blocks rerun, dry-run and activation too.
J=("$AWG_STATE_JOURNAL_DIR"/*); touch "${J[0]}/rollback-incomplete"
: >"$ROOT/systemctl.log"
if awgStateCommand --import-state "$ROOT/state.tar.gz" --dry-run 2>>"$ROOT/blocked.err"; then exit 23; fi
if awgStateCommand --import-state "$ROOT/state.tar.gz" 2>>"$ROOT/blocked.err"; then exit 23; fi
if awgStateCommand --activate-state "$ROOT/state.tar.gz" 2>>"$ROOT/blocked.err"; then exit 23; fi
if awgStateCommand --activate-state "$ROOT/state.tar.gz" --enable-at-boot 2>>"$ROOT/blocked.err"; then exit 23; fi
[[ "$(grep -c 'previous import rollback was INCOMPLETE' "$ROOT/blocked.err")" == 4 ]] || exit 24
! grep -Eq '^(start|enable) ' "$ROOT/systemctl.log" || exit 25
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
awgStateRestorePanel() { return 0; } # Panel restore has its own tests.
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
sysctl() {
    case "$1" in
        -n) echo 0 ;;
        -p)
            [[ "$2" == */forwarding.live.before ]] && printf 'sysctl-restore\n' >>"$ROOT/events" ||
                printf 'sysctl\n' >>"$ROOT/events" ;;
    esac
}
systemctl() {
    case "$1" in
        is-active) [[ -e "$ROOT/active" ]] ;;
        is-enabled) [[ -e "$ROOT/enabled" ]] ;;
        show)
            if [[ "$2" == --property=ActiveState ]]; then
                [[ ! -e "$ROOT/active" ]] && echo inactive || echo active
            else
                [[ ! -e "$ROOT/enabled" ]] && echo disabled || echo enabled
            fi ;;
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
                    self.assertEqual((root / 'events').read_text(), 'validate\nsysctl\nstart\nenable\ndisable\nstop\nsysctl-restore\n')
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

    def test_endpoint_summary_counts_without_printing_keys_and_releases_the_lock(self):
        phone = self.root / 'phone.conf'
        laptop = self.root / 'laptop.conf'
        secret = b'SECRETKEYMATERIAL='
        phone.write_bytes(
            b'[Interface]\nPrivateKey = ' + secret + b'\nAddress = 10.66.66.2/32\n\n'
            b'[Peer]\nPublicKey = SERVERPUB=\nEndpoint = 203.0.113.10:51820\n'
            b'AllowedIPs = 0.0.0.0/0\n')
        laptop.write_bytes(
            b'[Interface]\nPrivateKey = ' + secret + b'\nAddress = 10.66.66.3/32\n\n'
            b'[Peer]\nPublicKey = SERVERPUB=\nEndpoint = vpn.example.com:51820\n'
            b'AllowedIPs = 0.0.0.0/0\n')
        shell = r'''
set -euo pipefail
source "$1"
ROOT="$2"
AMNEZIAWG_DIR="$ROOT"
isRoot() { :; }
checkOS() { OS=debian; }
awgStateDependencies() { :; }
awgStateWorkDir() { mkdir -p "$ROOT/work"; printf '%s\n' "$ROOT/work"; }
acquireClientLifecycleLock() { echo locked >> "$ROOT/order"; }
releaseClientLifecycleLock() { echo release >> "$ROOT/order"; RELEASED=1; }
awgStateTrustedPath() { :; }
awgStateReadParams() { SERVER_AWG_NIC=awg0; }
collectAwgClientConfigCandidates() {
    local -n OUTPUT="$1"
    OUTPUT=("$ROOT/phone.conf" "$ROOT/laptop.conf")
}
printf() { echo "print-after-${RELEASED:-0}" >> "$ROOT/order"; builtin printf "$@"; }
: > "$ROOT/awg0.conf"
awgStateEndpointSummary > "$ROOT/counts"
'''
        result = subprocess.run(
            ['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)],
            capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        counts = (self.root / 'counts').read_text()
        self.assertEqual(counts, '1\n1\n')
        self.assertNotIn(secret, counts.encode())
        self.assertNotIn(b'PrivateKey', counts.encode())
        self.assertNotIn(b'203.0.113.10', counts.encode())
        order = (self.root / 'order').read_text().splitlines()
        self.assertIn('print-after-1', order)
        self.assertLess(order.index('release'), order.index('print-after-1'))
        self.assertFalse((self.root / 'work').exists())
        laptop.write_bytes(b'[Peer]\nEndpoint = vpn.example.com:service\n')
        incomplete = subprocess.run(
            ['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)],
            capture_output=True)
        self.assertNotEqual(incomplete.returncode, 0)
        self.assertEqual((self.root / 'counts').read_bytes(), b'')
        self.assertIn(b'incomplete client endpoint count', incomplete.stderr)

    def test_invalid_arguments_never_enter_interactive_install(self):
        for args in (['--export-state'], ['--export-state', '-'],
                     ['--export-state', '-', '--passphrase-fd'],
                     ['--export-state', '-', '--passphrase-fd', 'nope'],
                     ['--export-state', 'archive.awgx', '--passphrase-fd', '3'],
                     ['--endpoint-summary', 'extra'],
                     ['--inspect-state', 'x', '--dry-run'],
                     ['--import-state', 'x', '--unknown'], ['--import-state', '--dry-run'],
                     ['--activate-state'], ['--activate-state', 'x', '--dry-run'],
                     ['--import-state', 'x', '--enable-at-boot'], ['--purge-state-journal'],
                     ['--purge-state-journal', '../x', '--force'], ['--purge-state-journal', 'a'*64, '--unknown'],
                     ['--reset-state-journal', 'a'*64], ['--reset-state-journal', '../x', '--confirm-policy-replay'],
                     ['--reset-state-journal', 'a'*64, '--force'],
                     ['--audit-endpoints', 'extra'], ['--set-endpoint-host'],
                     ['--set-endpoint-host', '--dry-run'],
                     ['--set-endpoint-host', 'vpn.example.test', '--apply'],
                     ['--set-endpoint-host', 'vpn.example.test', '--dry-run', 'extra']):
            result = subprocess.run(['bash', str(SCRIPT), *args], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'Usage:', result.stderr)

    @unittest.skipUnless(shutil.which('age'), 'age not installed')
    def test_age_passphrase_roundtrip_and_wrong_passphrase(self):
        """Real age and controlling TTY; the secret is never in argv or env."""
        def run_age(args, responses, program='age'):
            # age 1.1.1 reads the passphrase from /dev/tty and has no
            # non-interactive switch. Answer the prompt word only: the
            # exporter prints a NOTE line that contains a colon before age
            # starts, and a rejected passphrase prints "age: error:" plus
            # "incorrect passphrase" on that same terminal. Count occurrences
            # so two prompts in one read both get a response, and so the
            # error text cannot consume one. A hangup on the pty master can
            # arrive while age is still exiting; that is not a timeout.
            pid, fd = pty.fork()
            if pid == 0:
                try:
                    settings = termios.tcgetattr(0)
                    settings[3] &= ~termios.ECHO
                    termios.tcsetattr(0, termios.TCSANOW, settings)
                except termios.error:
                    os._exit(1)
                os.execvp(program, [program, *args])
            output = b''
            deadline = time.monotonic() + 25
            sent = 0
            hangup = False
            try:
                while time.monotonic() < deadline:
                    if not hangup:
                        try:
                            ready, _, _ = select.select([fd], [], [], 0.2)
                        except (OSError, ValueError):
                            hangup = True
                            ready = []
                        if ready:
                            try:
                                data = os.read(fd, 4096)
                            except OSError:
                                data = b''
                            if not data:
                                hangup = True
                            else:
                                output += data
                                while sent < len(responses) and output.lower().count(b'passphrase') > sent:
                                    try:
                                        os.write(fd, responses[sent].encode() + b'\n')
                                    except OSError:
                                        hangup = True
                                        break
                                    sent += 1
                    ended, status = os.waitpid(pid, os.WNOHANG)
                    if ended:
                        return os.waitstatus_to_exitcode(status), output
                    if hangup:
                        time.sleep(0.05)
                ended, status = os.waitpid(pid, os.WNOHANG)
                if ended:
                    return os.waitstatus_to_exitcode(status), output
                os.kill(pid, 9)
                os.waitpid(pid, 0)
                shown = output[-800:]
                for item in responses:
                    shown = shown.replace(item.encode(), b'<redacted>')
                self.fail('age TTY interaction timed out: %r' % shown)
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
AWG_SYSCTL_FILE="$ROOT/forwarding.conf"
AMNEZIAWG_DIR="$ROOT/vpn"; SERVER_AWG_NIC=awg0; AWG_STATE_JOURNAL_DIR="$ROOT/journals"
mkdir -p "$AMNEZIAWG_DIR" "$ROOT/work" "$ROOT/journal"; printf x >"$AMNEZIAWG_DIR/awg0.conf"
SERVER_AWG_CONF="$AMNEZIAWG_DIR/awg0.conf"; printf ens3 >"$ROOT/journal/nic"
acquireClientLifecycleLock() { return 0; }
awgStateTrustedPath() { return 0; }
sha256sum() { return 0; }
awgStateArchive() { [[ "$1" == identity ]] && return 1; cp -- "$2" "$4"; }
ensureAwgBackendReady() { return 0; }
validateStagedAwgConfigs() { return 0; }
sysctl() { [[ "$1" != -n ]] || echo 0; }
awgStateWriteReceipt() { return 0; }
systemctl() {
    printf '%s\n' "$1" >>"$ROOT/systemctl.log"
    case "$1" in
        is-active|is-enabled) return 1 ;;
        show) [[ "$2" == --property=ActiveState ]] && echo inactive || echo disabled ;;
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
AWG_SYSCTL_FILE="$ROOT/forwarding.conf"
AMNEZIAWG_DIR="$ROOT/vpn"; SERVER_AWG_NIC=awg0; SERVER_AWG_CONF="$AMNEZIAWG_DIR/awg0.conf"
mkdir -p "$AMNEZIAWG_DIR" "$ROOT/work" "$ROOT/journal" "$ROOT/stage"
printf x >"$SERVER_AWG_CONF"; printf ens3 >"$ROOT/journal/nic"
acquireClientLifecycleLock() { return 0; }; awgStateTrustedPath() { return 0; }; sha256sum() { return 0; }
awgStateArchive() { [[ "$1" == identity ]] && return 1; cp -- "$2" "$4"; }
ensureAwgBackendReady() { return 0; }; validateStagedAwgConfigs() { return 0; }; sysctl() { [[ "$1" != -n ]] || echo 0; }
awgStateWriteReceipt() { return 0; }
systemctl() {
    case "$1" in
        is-active|is-enabled) return 1 ;;
        show)
            if [[ "$2" == --property=ActiveState ]]; then
                [[ ! -e "$ROOT/running" ]] && echo inactive || echo active
            else
                [[ ! -e "$ROOT/enabled" ]] && echo disabled || echo enabled
            fi ;;
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
ensureAwgBackendReady() { return 0; }; validateStagedAwgConfigs() { return 0; }; sysctl() { [[ "$1" != -n ]] || echo 0; }
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

    def test_wal_mode_panel_db_snapshot_exports_and_imports_without_sidecars(self):
        live = self.root / 'live'
        live.mkdir()
        db_path = live / 'awg-web.db'
        writer = sqlite3.connect(db_path)
        self.addCleanup(writer.close)
        writer.execute('PRAGMA journal_mode=WAL')
        writer.execute('PRAGMA user_version=7')
        writer.execute('CREATE TABLE _sqlx_migrations(version BIGINT PRIMARY KEY, description TEXT NOT NULL)')
        writer.execute('INSERT INTO _sqlx_migrations VALUES(10, "events_on_delete")')
        writer.execute('CREATE TABLE peers(id INTEGER PRIMARY KEY AUTOINCREMENT, public_key TEXT NOT NULL UNIQUE, disabled INTEGER, archived INTEGER, removal_pending INTEGER, expires_at TEXT, display_name TEXT)')
        writer.execute('CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT, peer_id INTEGER REFERENCES peers(id), action TEXT NOT NULL)')
        writer.execute('CREATE TABLE snapshots(id INTEGER PRIMARY KEY AUTOINCREMENT, public_key TEXT NOT NULL, captured_at TEXT NOT NULL, rx_bytes INTEGER NOT NULL, tx_bytes INTEGER NOT NULL)')
        writer.execute('CREATE INDEX idx_snapshots_pk_captured_id ON snapshots(public_key, captured_at, id)')
        writer.execute('INSERT INTO peers(id, public_key, disabled, archived, removal_pending, expires_at, display_name) VALUES(5,?,?,?,?,?,?)', (PEER, 1, 0, 0, None, 'phone'))
        writer.execute('INSERT INTO events(peer_id, action) VALUES(5, "peer.disabled")')
        writer.executemany(
            'INSERT INTO snapshots(public_key, captured_at, rx_bytes, tx_bytes) VALUES(?,?,?,?)',
            [(PEER, f'2026-11-19T20:00:{i:02d}Z', i * 100, i * 200) for i in range(50)],
        )
        writer.commit()  # Writer kept open: live WAL/SHM exist, like a running panel.
        self.assertTrue((live / 'awg-web.db-wal').exists())
        source = self.root / 'source'
        (source / 'clients').mkdir(parents=True)
        (source / 'params').write_bytes(self.files['vpn/params'])
        (source / 'awg0.conf').write_bytes(self.files['vpn/server.conf'])
        (source / 'clients/awg0-client-phone.conf').write_bytes(self.files['clients/awg0-client-phone.conf'])
        (self.root / 'work').mkdir()
        shell = r"""
set -uo pipefail
source "$1"
ROOT="$2"
AMNEZIAWG_DIR="$ROOT/source"
AWG_STATE_PROXY_CONFIG="$ROOT/not-installed-proxy"
acquireClientLifecycleLock() { CLIENT_LIFECYCLE_LOCK_FD=held; }
releaseClientLifecycleLock() { CLIENT_LIFECYCLE_LOCK_FD=""; }
awgStateTrustedPath() { return 0; }
isWebPanelInstalled() { return 0; }
readWebPanelExecStartSetting() { printf '%s\n' "$ROOT/live/awg-web.db"; }
resolveWebPanelEnvFile() { printf '\n'; }
collectAwgClientConfigCandidates() { local -n OUTPUT="$1"; OUTPUT=("$ROOT/source/clients/awg0-client-phone.conf"); }
awg() { printf 'fixture-tools\n'; }
age() { cat >"$3"; }
awgStateExport "$ROOT/export.tar.gz" "$ROOT/work"
"""
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)], capture_output=True)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        with tarfile.open(self.root / 'export.tar.gz') as archive:
            names = archive.getnames()
            data = archive.extractfile('web/database.sqlite').read()
        self.assertIn('web/database.sqlite', names)
        self.assertFalse([n for n in names if n.endswith(('-wal', '-shm', '-journal'))], names)
        self.assertEqual(data[18:20], b'\x01\x01')  # Rollback-journal (DELETE) mode header.
        exported_db = self.root / 'exported-check.sqlite'
        exported_db.write_bytes(data)
        with closing(sqlite3.connect(exported_db.as_uri() + '?mode=ro&immutable=1', uri=True)) as db:
            self.assertEqual(db.execute('PRAGMA integrity_check').fetchone(), ('ok',))
            self.assertEqual(db.execute('PRAGMA user_version').fetchone(), (7,))
            self.assertEqual(db.execute('SELECT id, public_key, disabled, display_name FROM peers').fetchall(), [(5, PEER, 1, 'phone')])
            self.assertEqual(db.execute('SELECT peer_id, action FROM events').fetchall(), [(5, 'peer.disabled')])
            self.assertEqual(db.execute('SELECT version FROM _sqlx_migrations').fetchall(), [(10,)])
            # Historical telemetry rows in snapshots are omitted, while table schema, index, and sequence remain intact.
            self.assertEqual(db.execute('SELECT COUNT(*) FROM snapshots').fetchone(), (0,))
            self.assertEqual(db.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_snapshots_pk_captured_id'").fetchone(), ('idx_snapshots_pk_captured_id',))
            seqs = dict(db.execute('SELECT name, seq FROM sqlite_sequence').fetchall())
            self.assertEqual(seqs.get('peers'), 5)
            self.assertEqual(seqs.get('snapshots'), 50)
        # Import side: an archive whose DB still carries a WAL header (older
        # exports) is read immutably and never grows sidecars next to it.
        wal_db = self.root / 'wal-origin.sqlite'
        with closing(sqlite3.connect(wal_db)) as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE peers(public_key TEXT, disabled INTEGER, archived INTEGER, removal_pending INTEGER, expires_at TEXT, display_name TEXT)')
            db.execute('INSERT INTO peers VALUES(?,?,?,?,?,?)', (PEER, 1, 0, 0, None, 'phone'))
            db.commit()
        self.assertEqual(wal_db.read_bytes()[18:20], b'\x02\x02')
        self.files['web/database.sqlite'] = wal_db.read_bytes()
        make_tar(self.tar, self.files)
        destination = self.root / 'unpacked'
        self.run_helper('unpack', self.tar, destination)
        report = json.loads(self.run_helper('inspect').stdout)['peer_plan']
        self.assertEqual(report['peers'][0]['decision'], 'drop')
        self.run_helper('prepare', destination, self.root / 'prepared.conf')
        leftovers = [p.name for p in destination.rglob('*') if p.name.endswith(('-wal', '-shm', '-journal'))]
        self.assertEqual(leftovers, [])

    def test_panel_snapshot_full_migrations_concurrency_and_security(self):
        migrations_dir = SCRIPT.parent / 'amneziawg-web' / 'migrations'
        migration_files = sorted(migrations_dir.glob('*.sql'))
        self.assertGreaterEqual(len(migration_files), 15)

        src = self.root / 'full-panel.db'
        other_peer = base64.b64encode(b'D' * 32).decode()
        checksum = bytes(range(48))
        digest = b'\xab' * 32
        token_hash = b'\xcd' * 32
        with closing(sqlite3.connect(src)) as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('PRAGMA application_id=1096238935')
            db.execute(
                'CREATE TABLE _sqlx_migrations(version BIGINT PRIMARY KEY, description TEXT NOT NULL, '
                'installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, success BOOLEAN NOT NULL, '
                'checksum BLOB NOT NULL, execution_time BIGINT NOT NULL)'
            )
            for mf in migration_files:
                db.executescript(mf.read_text(encoding='utf-8'))
                ver = int(mf.name.split('_', 1)[0])
                db.execute(
                    'INSERT INTO _sqlx_migrations(version, description, success, checksum, execution_time) '
                    'VALUES(?, ?, 1, ?, 1)',
                    (ver, mf.stem, checksum),
                )
            db.execute('CREATE VIEW active_peer_keys AS SELECT public_key FROM peers WHERE disabled = 0')
            db.execute('INSERT INTO peers(id, public_key, display_name) VALUES(10, ?, "alice")', (PEER,))
            db.execute('INSERT INTO peers(id, public_key, display_name) VALUES(25, ?, "temp")', (other_peer,))
            db.execute('DELETE FROM peers WHERE id = 25')  # High-water mark stays 25 in sqlite_sequence.
            db.execute(
                'INSERT INTO delivery_clients(id, peer_id, interface, managed_name, last_public_key, email, '
                'binding_version, export_digest) VALUES("c1", 10, "awg0", "alice", ?, "a@example.test", 1, ?)',
                (PEER, digest),
            )
            db.execute(
                'INSERT INTO email_jobs(id, client_id, request_id, actor, recipient, mode, formats, '
                'binding_version, export_digest, state, attempts, next_attempt_at, created_at) '
                'VALUES("j1", "c1", "r1", "admin", "a@example.test", "link", "conf", 1, ?, "queued", 0, 100, 100)',
                (digest,),
            )
            db.execute(
                'INSERT INTO delivery_grants(id, job_id, token_hash, binding_version, export_digest, expires_at) '
                'VALUES("g1", "j1", ?, 1, ?, 9999999999)',
                (token_hash, digest),
            )
            db.executemany(
                'INSERT INTO snapshots(public_key, captured_at, rx_bytes, tx_bytes) VALUES(?,?,?,?)',
                [(PEER, f'2026-11-19T21:00:{i:02d}Z', i, i * 2) for i in range(12)],
            )
            db.commit()

        # Hold an active uncommitted WAL write transaction while taking panel-snapshot.
        writer = sqlite3.connect(src, isolation_level=None)
        self.addCleanup(writer.close)
        writer.execute('BEGIN IMMEDIATE')
        writer.execute('INSERT INTO peers(id, public_key, display_name) VALUES(30, ?, "uncommitted")', (other_peer,))

        dst = self.root / 'full-snapshot.sqlite'
        # Also exercise a relative source path to verify abspath URI conversion.
        rel_src = os.path.relpath(src, self.root)
        result = subprocess.run(
            ['bash', '-c', 'set -euo pipefail; cd "$2"; source "$1"; awgStateArchive panel-snapshot "$3" "$4"',
             'test', str(SCRIPT), str(self.root), rel_src, str(dst)],
            capture_output=True,
        )
        writer.execute('ROLLBACK')
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        self.assertEqual(dst.stat().st_mode & 0o777, 0o600)
        self.assertEqual(dst.read_bytes()[18:20], b'\x01\x01')
        for suffix in ('-wal', '-shm', '-journal'):
            self.assertFalse(Path(str(dst) + suffix).exists())

        with closing(sqlite3.connect(dst.as_uri() + '?mode=ro&immutable=1', uri=True)) as db:
            self.assertEqual(db.execute('PRAGMA integrity_check').fetchone(), ('ok',))
            self.assertEqual(db.execute('PRAGMA application_id').fetchone(), (1096238935,))
            # Committed peer preserved, uncommitted WAL row excluded.
            self.assertEqual(db.execute('SELECT id, public_key, display_name FROM peers').fetchall(), [(10, PEER, 'alice')])
            # Snapshots omitted while schema and indexes remain.
            self.assertEqual(db.execute('SELECT COUNT(*) FROM snapshots').fetchone(), (0,))
            self.assertIsNotNone(db.execute("SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_snapshots_pk_captured_id'").fetchone())
            self.assertIsNotNone(db.execute("SELECT 1 FROM sqlite_master WHERE type='index' AND name='email_jobs_visible_activity'").fetchone())
            self.assertEqual(db.execute('SELECT public_key FROM active_peer_keys').fetchall(), [(PEER,)])
            # Triggers exist and did not fire during copy.
            triggers = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall()}
            self.assertTrue({'delivery_peer_invalidated', 'delivery_peer_deleted', 'delivery_contact_invalidated'}.issubset(triggers))
            self.assertEqual(db.execute('SELECT binding_version, typeof(export_digest), export_digest FROM delivery_clients').fetchall(), [(1, 'blob', digest)])
            self.assertEqual(db.execute('SELECT state, invalidation_code FROM email_jobs').fetchall(), [('queued', None)])
            self.assertEqual(db.execute('SELECT revoked_at, typeof(token_hash), token_hash FROM delivery_grants').fetchall(), [(None, 'blob', token_hash)])
            self.assertEqual(db.execute('SELECT typeof(checksum), checksum FROM _sqlx_migrations WHERE version = 1').fetchall(), [('blob', checksum)])
            # sqlite_sequence preserves high-water marks even after deleting max-id peer and omitting snapshots.
            seqs = dict(db.execute('SELECT name, seq FROM sqlite_sequence').fetchall())
            self.assertEqual(seqs.get('peers'), 25)
            self.assertEqual(seqs.get('snapshots'), 12)

        # Fail-closed & cleanup checks.
        existing = self.root / 'existing.sqlite'
        existing.write_bytes(b'keep-me')
        res = self.run_helper('panel-snapshot', src, existing, ok=False)
        self.assertEqual(existing.read_bytes(), b'keep-me')
        self.assertNotIn(b'Traceback', res.stderr)

        link_dst = self.root / 'link-dst.sqlite'
        link_dst.symlink_to(self.root / 'nowhere.sqlite')
        self.run_helper('panel-snapshot', src, link_dst, ok=False)

        link_src = self.root / 'link-src.db'
        link_src.symlink_to(src)
        out_from_link = self.root / 'from-link.sqlite'
        self.run_helper('panel-snapshot', link_src, out_from_link, ok=False)
        self.assertFalse(out_from_link.exists())

        corrupt = self.root / 'corrupt.db'
        corrupt.write_bytes(b'not-a-sqlite-database')
        out_corrupt = self.root / 'out-corrupt.sqlite'
        self.run_helper('panel-snapshot', corrupt, out_corrupt, ok=False)
        for suffix in ('', '-wal', '-shm', '-journal'):
            self.assertFalse(Path(str(out_corrupt) + suffix).exists())

        vtab = self.root / 'vtab.db'
        with closing(sqlite3.connect(vtab)) as db:
            db.execute('CREATE VIRTUAL TABLE evil USING fts5(content)')
            db.commit()
        out_vtab = self.root / 'out-vtab.sqlite'
        self.run_helper('panel-snapshot', vtab, out_vtab, ok=False)
        for suffix in ('', '-wal', '-shm', '-journal'):
            self.assertFalse(Path(str(out_vtab) + suffix).exists())

        # Missing destination arg fails cleanly without an uncaught IndexError traceback.
        missing_arg = self.run_helper('panel-snapshot', src, ok=False)
        self.assertNotIn(b'Traceback', missing_arg.stderr)

    def test_config_replace_failure_in_deferred_window_restores_previous(self):
        for case in ('landed-then-failed', 'io-error', 'interrupted'):
            with self.subTest(case=case):
                root = self.root / case
                root.mkdir()
                shell = r"""
set -uo pipefail
source "$1"
ROOT="$2"; CASE="$3"
AMNEZIAWG_DIR="$ROOT/vpn"; SERVER_AWG_NIC=awg0; SERVER_AWG_CONF="$AMNEZIAWG_DIR/awg0.conf"
mkdir -p "$AMNEZIAWG_DIR" "$ROOT/journal" "$ROOT/w1"
printf original >"$SERVER_AWG_CONF"; printf params >"$AMNEZIAWG_DIR/params"; printf ens3 >"$ROOT/journal/nic"
sha256sum "$AMNEZIAWG_DIR/params" "$SERVER_AWG_CONF" >"$ROOT/journal/receipt"
acquireClientLifecycleLock() { return 0; }; awgStateTrustedPath() { return 0; }
awgStateArchive() { printf filtered >"$4"; }
systemctl() { return 1; }
eval "$(declare -f replaceFileExactly | sed 's/^replaceFileExactly/realReplaceFileExactly/')"
replaceFileExactly() {
    if [[ "$1" == */reconciled.conf ]]; then
        case "$CASE" in
            landed-then-failed) realReplaceFileExactly "$@"; return 1 ;;
            io-error) return 1 ;;
            interrupted) kill -TERM "$BASHPID"; return 1 ;;
        esac
    fi
    realReplaceFileExactly "$@"
}
( trap 'exit 143' TERM; awgStateReconcileImport "$ROOT/stage" "$ROOT/journal" "$ROOT/w1" --import-state '' ens3 )
echo "rc=$? conf=$(<"$SERVER_AWG_CONF")"
sha256sum -c --status "$ROOT/journal/receipt" && echo receipt-ok
"""
                result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(root), case], capture_output=True)
                out, err = result.stdout.decode(), result.stderr.decode()
                self.assertIn('conf=original', out, err)
                self.assertIn('receipt-ok', out, err)
                if case == 'interrupted':
                    self.assertIn('rc=143', out, err)
                    self.assertIn('interrupted while updating', err)
                    self.assertNotIn('free space', err)
                else:
                    self.assertIn('rc=1', out, err)
                    self.assertIn('previous config was kept', err)

    def test_server_pub_ip_override_rejects_host_port(self):
        shell = r"""
source "$1"
for value in vpn.example.test 203.0.113.7 2001:db8::1 '[2001:db8::1]' ::ffff:192.0.2.1 \
             vpn.example.test:51820 203.0.113.7:51820 '[2001:db8::1]:51820' 2001:db8::1%eth0 \
             ':::' 'a b' -bad bad- '[vpn.example.test]' '' \
             :: '[::]' ::0 0:0:0:0:0:0:0:0 ::ffff:0.0.0.0 0.0.0.0 '[2001:db8::1' '2001:db8::1]' '[[2001:db8::1]]' \
             256.1.1.1 1.2.3 1.2.3.4.5 01.2.3.4 1.2.3.4. 10.0.0.255 0.1.2.3 \
             a..b .a.b a.b. a.-b.c a-.b.c "$(printf 'a%.0s' {1..64}).test" "$(printf 'a%.0s' {1..63}).test" xn--d1acufc.example 1.2.3.4a \
             127.0.0.1 127.255.255.254 ::1 '[::1]' ::ffff:127.0.0.1 224.0.0.1 239.255.255.255 ff02::1 ff0e::1 ::ffff:224.0.0.1 \
             223.255.255.255 240.0.0.1 126.0.0.1 128.0.0.1 fe80::1 fd00::1 ::ffff:203.0.113.7 ::2; do
    awgStateNormalizePubHost "$value" >/dev/null; echo "rc <$value> $?"
    if out="$(awgStateNormalizePubHost "$value")"; then echo "ok <$value> -> <$out>"; else echo "bad <$value>"; fi
done
"""
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT)], capture_output=True)
        out = result.stdout.decode()
        for line in ('ok <vpn.example.test> -> <vpn.example.test>', 'ok <203.0.113.7> -> <203.0.113.7>',
                     'ok <2001:db8::1> -> <2001:db8::1>', 'ok <[2001:db8::1]> -> <2001:db8::1>',
                     'ok <::ffff:192.0.2.1> -> <::ffff:192.0.2.1>',
                     'bad <vpn.example.test:51820>', 'bad <203.0.113.7:51820>', 'bad <[2001:db8::1]:51820>',
                     'bad <2001:db8::1%eth0>', 'bad <:::>', 'bad <a b>', 'bad <-bad>', 'bad <bad->',
                     'bad <[vpn.example.test]>', 'bad <>',
                     'bad <::>', 'bad <[::]>', 'bad <::0>', 'bad <0:0:0:0:0:0:0:0>', 'bad <::ffff:0.0.0.0>', 'bad <0.0.0.0>',
                     'bad <[2001:db8::1>', 'bad <2001:db8::1]>', 'bad <[[2001:db8::1]]>',
                     'bad <256.1.1.1>', 'bad <1.2.3>', 'bad <1.2.3.4.5>', 'bad <01.2.3.4>', 'bad <1.2.3.4.>',
                     'ok <10.0.0.255> -> <10.0.0.255>', 'ok <0.1.2.3> -> <0.1.2.3>',
                     'bad <a..b>', 'bad <.a.b>', 'bad <a.b.>', 'bad <a.-b.c>', 'bad <a-.b.c>',
                     'bad <' + 'a' * 64 + '.test>', 'ok <' + 'a' * 63 + '.test> -> <' + 'a' * 63 + '.test>',
                     'ok <xn--d1acufc.example> -> <xn--d1acufc.example>', 'ok <1.2.3.4a> -> <1.2.3.4a>',
                     'ok <223.255.255.255> -> <223.255.255.255>', 'ok <240.0.0.1> -> <240.0.0.1>',
                     'ok <126.0.0.1> -> <126.0.0.1>', 'ok <128.0.0.1> -> <128.0.0.1>', 'ok <fe80::1> -> <fe80::1>',
                     'ok <fd00::1> -> <fd00::1>', 'ok <::ffff:203.0.113.7> -> <::ffff:203.0.113.7>', 'ok <::2> -> <::2>',
                     'bad <127.0.0.1>', 'bad <127.255.255.254>', 'bad <::1>', 'bad <[::1]>', 'bad <::ffff:127.0.0.1>',
                     'bad <224.0.0.1>', 'bad <239.255.255.255>', 'bad <ff02::1>', 'bad <ff0e::1>', 'bad <::ffff:224.0.0.1>',
                     'rc <127.0.0.1> 2', 'rc <::1> 2', 'rc <[::1]> 2', 'rc <::ffff:127.0.0.1> 2', 'rc <224.0.0.1> 2',
                     'rc <ff02::1> 2', 'rc <::ffff:224.0.0.1> 2', 'rc <::> 1', 'rc <0.0.0.0> 1', 'rc <vpn.example.test:51820> 1'):
            self.assertIn(line + '\n', out, result.stderr.decode())

    def test_apt_ipv4_in_subshell_never_runs_inherited_parent_traps(self):
        shell = r"""
source "$1"
APT_FORCE_IPV4_CONF="$2/force-ipv4"; GAI_CONF="$2/gai.conf"
mkdir() { [[ "$*" == '-p /etc/apt/apt.conf.d' ]] && return 0; command mkdir "$@"; }
trap 'echo "parent-exit pid=$BASHPID"' EXIT
trap 'echo parent-hup' HUP
( enable_apt_ipv4; exit 7 ); echo "rc=$?"
( enable_apt_ipv4; disable_apt_ipv4; echo "restored=[$(trap -p EXIT)]"; exit 3 ); echo "rc=$?"
( enable_apt_ipv4; kill -TERM "$BASHPID"; echo not-reached ); echo "rc=$?"
echo "main=[$(trap -p EXIT)]"
"""
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)], capture_output=True)
        out = result.stdout.decode()
        self.assertIn('rc=7\n', out, result.stderr.decode())
        self.assertIn('restored=[]\nrc=3\n', out)
        self.assertIn('rc=143\n', out)
        self.assertNotIn('not-reached', out)
        self.assertNotIn('parent-hup', out)
        self.assertEqual(sum(l.startswith('parent-exit pid=') for l in out.splitlines()), 1, out)  # Only the real parent shell's EXIT.
        self.assertTrue(out.rstrip().rsplit('\n', 1)[1].startswith('parent-exit pid='), out)
        self.assertFalse((self.root / 'force-ipv4').exists())

    def test_incomplete_rollback_marker_write_failure_warns_without_claiming_block(self):
        shell = r"""
set -uo pipefail
source "$1"
ROOT="$2"
AMNEZIAWG_DIR="$ROOT/vpn"; AWG_SYSTEMD_UNIT_DIR="$ROOT/units"; SERVER_AWG_NIC=awg0
AWG_SYSCTL_FILE="$ROOT/sysctl"; AWG_MODULES_LOAD_FILE="$ROOT/modules"; AWG_BT_MODPROBE_OVERRIDE="$ROOT/modprobe"
mkdir -p "$ROOT/journal" "$AWG_SYSTEMD_UNIT_DIR"
printf original >"$AWG_SYSCTL_FILE"
systemctl() { return 0; }
installAmneziaWG() { printf mutated >"$AWG_SYSCTL_FILE"; mkdir "$ROOT/journal/rollback-incomplete"; return 1; } # Marker path unwritable.
cp() { [[ "$*" == *"/before/"* ]] && return 1; command cp "$@"; }
if awgStateImportTransaction "$ROOT/stage" "$ROOT/journal"; then exit 10; fi
"""
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)], capture_output=True)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        self.assertIn(b'import rollback was INCOMPLETE', result.stderr)
        self.assertIn(b'later attempts are NOT blocked automatically', result.stderr)
        self.assertNotIn(b'are refused until then', result.stderr)

    def test_incomplete_rollback_blocks_new_before_image_until_forced_purge(self):
        shell = r"""
set -uo pipefail
source "$1"
ROOT="$2"
AMNEZIAWG_DIR="$ROOT/vpn"; AWG_SYSTEMD_UNIT_DIR="$ROOT/units"; SERVER_AWG_NIC=awg0
AWG_SYSCTL_FILE="$ROOT/sysctl"; AWG_MODULES_LOAD_FILE="$ROOT/modules"; AWG_BT_MODPROBE_OVERRIDE="$ROOT/modprobe"
mkdir -p "$ROOT/journal" "$AWG_SYSTEMD_UNIT_DIR"
printf original >"$AWG_SYSCTL_FILE"
systemctl() { return 0; }
installAmneziaWG() { printf mutated >"$AWG_SYSCTL_FILE"; return 1; }
cp() { [[ "${FAIL_RESTORE:-0}" == 1 && "$*" == *"/before/"* ]] && return 1; command cp "$@"; }
FAIL_RESTORE=1
if awgStateImportTransaction "$ROOT/stage" "$ROOT/journal"; then exit 10; fi
[[ -e "$ROOT/journal/rollback-incomplete" ]] || exit 11
FAIL_RESTORE=0
printf operator-fixed >"$AWG_SYSCTL_FILE"
installAmneziaWG() { touch "$ROOT/install-ran"; return 1; }
if awgStateImportTransaction "$ROOT/stage" "$ROOT/journal"; then exit 12; fi
[[ ! -e "$ROOT/install-ran" && "$(<"$ROOT/journal/before/0")" == original ]] || exit 13
"""
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)], capture_output=True)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        self.assertIn(b'import rollback was INCOMPLETE', result.stderr)
        self.assertIn(b'refusing (including --dry-run and --activate-state)', result.stderr)
        self.assertIn(b'New import/activation attempts for this archive are refused', result.stderr)
        self.assertIn(b'--purge-state-journal journal --force', result.stderr)

    def panel_stage(self, root, schema=15, env=None):
        stage = root / 'stage'
        (stage / 'web').mkdir(parents=True)
        with closing(sqlite3.connect(stage / 'web/database.sqlite')) as db, db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE _sqlx_migrations(version INTEGER PRIMARY KEY, success INTEGER)')
            db.executemany('INSERT INTO _sqlx_migrations VALUES(?,1)', [(v,) for v in range(1, schema + 1)])
            db.execute('CREATE TABLE peers(public_key TEXT, disabled INTEGER, archived INTEGER, removal_pending INTEGER, expires_at TEXT)')
            db.execute('INSERT INTO peers VALUES(?,0,0,0,?)', (PEER, '2999-01-01T00:00:00Z'))
            db.execute('CREATE TABLE email_jobs(id TEXT, state TEXT, invalidated_at INTEGER, invalidation_code TEXT, error_code TEXT)')
            db.executemany('INSERT INTO email_jobs VALUES(?,?,NULL,NULL,NULL)', [('a', 'queued'), ('b', 'sending'), ('c', 'accepted')])
        (stage / 'web/env.conf').write_text(env if env is not None else
            'AUTH_ENABLED=true\nAUTH_USERNAME=admin\nAUTH_PASSWORD_HASH=$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA\n'
            'AWG_WEB_LISTEN=127.0.0.1:8080\nAWG_WEB_DB=%s/data/awg-web.db\nAWG_CONFIG_DIR=/home/old/clients\n' % root)
        migrations = root / 'checkout/amneziawg-web/migrations'
        migrations.mkdir(parents=True)
        for version in range(1, 16):
            (migrations / ('%04d_m.sql' % version)).write_text('-- fixture\n')
        installer = root / 'checkout/amneziawg-web/scripts/amneziawg-web-install.sh'
        installer.parent.mkdir(parents=True)
        installer.write_text('#!/bin/bash\nprintf "%s\\n" "$@" >>"$PANEL_ROOT/installer.args"\n'
                             'echo run >>"$PANEL_ROOT/installer.runs"\n[[ -z "${FAIL_INSTALLER:-}" ]] || exit 1\n'
                             'while (($#)); do [[ "$1" == --password-hash-file ]] && { stat -c %a "$2" >"$PANEL_ROOT/hash.mode"; cat "$2" >"$PANEL_ROOT/hash.seen"; }; shift; done\n'
                             'mkdir -p "$PANEL_ROOT/data"; touch "$PANEL_ROOT/unit"\n[[ -z "${FAIL_AFTER_UNIT:-}" ]]\n')
        return stage

    PANEL_HARNESS = r"""
set -uo pipefail
source "$1"
ROOT="$2"; export PANEL_ROOT="$ROOT"
awgStateLockCompanionInstallers() { AWG_COMPANION_INSTALL_LOCK_FD=0; }
AMNEZIAWG_DIR="$ROOT/vpn"; mkdir -p "$ROOT/journal" "$ROOT/work"
WEB_PANEL_ENV_FILE="$ROOT/etc/env.conf"; WEB_PANEL_SYSTEMD_UNIT="$ROOT/unit"
awgStatePanelInstaller() { printf '%s\n' "$ROOT/checkout/amneziawg-web/scripts/amneziawg-web-install.sh"; }
install() { local a=(); while (($#)); do case "$1" in -o|-g) shift 2 ;; *) a+=("$1"); shift ;; esac; done; command install "${a[@]}"; }
systemctl() {
    case "$1 ${2:-}" in
        'show --property=FragmentPath') printf '%s' "${SYSTEMD_FRAGMENT:-}"; return 0 ;;
        'show --property=ActiveState') printf '%s' "${SYSTEMD_ACTIVE:-inactive}"; return 0 ;;
    esac
    printf '%s\n' "$*" >>"$ROOT/systemctl.log"
    [[ "$1 ${FAIL_START:-}" != 'start 1' && "$1 ${FAIL_STOP:-}" != 'stop 1' ]]
}
awgStatePanelHealthy() { [[ -z "${UNHEALTHY:-}" ]]; }
AWG_STATE_PANEL_DEFAULT_DB="$ROOT/data/awg-web.db"
"""

    def run_panel(self, root, body, **env):
        result = subprocess.run(['bash', '-c', self.PANEL_HARNESS + body, 'test', str(SCRIPT), str(root)],
                                capture_output=True, env=dict(os.environ, **env))
        return result

    def test_panel_restore_installs_db_env_starts_and_is_idempotent(self):
        root = self.root / 'ok'
        root.mkdir()
        self.panel_stage(root)
        result = self.run_panel(root, r"""
awgStateRestorePanel "$ROOT/stage" "$ROOT/journal" "$ROOT/work" || exit 10
awgStateRestorePanel "$ROOT/stage" "$ROOT/journal" "$ROOT/work" || exit 11
""")
        out = (result.stdout + result.stderr).decode()
        self.assertEqual(result.returncode, 0, out)
        self.assertIn('Panel restored and healthy', out)
        self.assertIn('Panel already restored', out)
        self.assertEqual((root / 'installer.runs').read_text(), 'run\n')
        args = (root / 'installer.args').read_text().splitlines()
        for flag in ('--non-interactive', '--no-start', '--no-enable', '--password-hash-file', '--data-dir', '--env-file', '--config-dir'):
            self.assertIn(flag, args)
        # m2: the Argon2 hash never appears on the installer command line.
        self.assertNotIn('--password-hash', args)
        self.assertFalse(any('$argon2' in arg for arg in args))
        self.assertEqual((root / 'hash.seen').read_text(), '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA\n')
        self.assertEqual((root / 'hash.mode').read_text(), '600\n')
        self.assertEqual(args[args.index('--data-dir') + 1], str(root / 'data'))
        self.assertEqual(args[args.index('--config-dir') + 1], str(root / 'vpn/clients'))
        env = (root / 'etc/env.conf').read_text()
        self.assertIn('AWG_CONFIG_DIR=%s/vpn/clients\n' % root, env)
        self.assertNotIn('/home/old', env)
        self.assertEqual(oct((root / 'etc/env.conf').stat().st_mode & 0o777), '0o600')
        db_path = root / 'data/awg-web.db'
        self.assertEqual(oct(db_path.stat().st_mode & 0o777), '0o600')
        self.assertEqual(db_path.read_bytes()[18:20], b'\x01\x01')
        with closing(sqlite3.connect(db_path)) as db:
            states = dict(db.execute('SELECT id, state FROM email_jobs'))
        self.assertEqual(states, {'a': 'cancelled', 'b': 'unknown', 'c': 'accepted'})
        log = (root / 'systemctl.log').read_text()
        self.assertIn('start amneziawg-web', log)
        self.assertIn('enable amneziawg-web', log)
        self.assertTrue((root / 'journal/panel-restored').exists())
        self.assertFalse((root / 'journal/panel-installing').exists())
        self.assertIn('panel-restored', (root / 'journal/steps').read_text())

    def test_panel_restore_failure_is_retryable_and_never_enables(self):
        root = self.root / 'retry'
        root.mkdir()
        self.panel_stage(root)
        result = self.run_panel(root, r"""
if UNHEALTHY=1 awgStateRestorePanel "$ROOT/stage" "$ROOT/journal" "$ROOT/work"; then exit 10; fi
[[ -e "$ROOT/journal/panel-installing" && ! -e "$ROOT/journal/panel-restored" ]] || exit 11
[[ "$(<"$ROOT/journal/panel-approved-dir")" == "$ROOT/data" ]] || exit 16
grep -q '^stop amneziawg-web' "$ROOT/systemctl.log" || exit 12
! grep -q '^enable' "$ROOT/systemctl.log" || exit 13
# The env/unit now exist, but the journal marker identifies our own attempt.
awgStateRestorePanel "$ROOT/stage" "$ROOT/journal" "$ROOT/work" || exit 14
[[ -e "$ROOT/journal/panel-restored" ]] || exit 15
""")
        out = (result.stdout + result.stderr).decode()
        self.assertEqual(result.returncode, 0, out)
        self.assertIn('finalized VPN is unaffected', out)
        self.assertIn('did not become healthy', out)
        self.assertEqual((root / 'installer.runs').read_text(), 'run\n')

    def test_panel_completion_write_failure_preserves_later_database_changes(self):
        root = self.root / 'panel-marker'
        root.mkdir()
        self.panel_stage(root)
        result = self.run_panel(root, r"""
mkdir -p "$ROOT/journal/panel-restored"
if awgStateRestorePanel "$ROOT/stage" "$ROOT/journal" "$ROOT/work"; then exit 10; fi
[[ -f "$ROOT/journal/panel-installing" && -f "$ROOT/journal/panel-data-installed" ]] || exit 11
python3 -c 'import sqlite3, sys; db = sqlite3.connect(sys.argv[1]); db.execute("CREATE TABLE later (x)"); db.commit()' "$ROOT/data/awg-web.db"
rmdir "$ROOT/journal/panel-restored"
awgStateRestorePanel "$ROOT/stage" "$ROOT/journal" "$ROOT/work" || exit 12
python3 -c 'import sqlite3, sys; db = sqlite3.connect(sys.argv[1]); db.execute("SELECT x FROM later")' "$ROOT/data/awg-web.db"
""")
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        self.assertEqual((root / 'installer.runs').read_text(), 'run\n')

    def test_existing_panel_dir_stays_refused_after_installing_marker(self):
        # m1: panel-installing is written before prepare. A refused existing
        # directory must stay refused on the rerun the error message asks for.
        # A recorded approval for a different directory must not unlock it.
        if not os.path.isdir('/var/lib/dpkg'):
            self.skipTest('needs the existing directory /var/lib/dpkg')
        root = self.root / 'panel-dpkg-retry'
        root.mkdir()
        self.panel_stage(root, env='AUTH_PASSWORD_HASH=$argon2id$v=19$x\nAWG_WEB_DB=/var/lib/dpkg/awg-web.db\n')
        result = self.run_panel(root, r"""
if awgStateRestorePanel "$ROOT/stage" "$ROOT/journal" "$ROOT/work"; then exit 10; fi
[[ -e "$ROOT/journal/panel-installing" && ! -e "$ROOT/journal/panel-approved-dir" ]] || exit 11
[[ ! -e "$ROOT/installer.runs" ]] || exit 12
printf '%s\n' /var/lib/amneziawg-web >"$ROOT/journal/panel-approved-dir"
if awgStateRestorePanel "$ROOT/stage" "$ROOT/journal" "$ROOT/work"; then exit 13; fi
[[ ! -e "$ROOT/installer.runs" ]] || exit 14
""")
        out = (result.stdout + result.stderr).decode()
        self.assertEqual(result.returncode, 0, out)
        self.assertEqual(out.count('already exists'), 2, out)
        self.assertNotIn('installer.runs', out)

    def test_symlink_panel_path_record_is_refused(self):
        root = self.root / 'panel-approved-link'
        root.mkdir()
        self.panel_stage(root)
        result = self.run_panel(root, r"""
ln -s "$ROOT/data" "$ROOT/journal/panel-approved-dir"
if awgStateRestorePanel "$ROOT/stage" "$ROOT/journal" "$ROOT/work"; then exit 10; fi
[[ ! -e "$ROOT/installer.runs" ]] || exit 11
""")
        out = (result.stdout + result.stderr).decode()
        self.assertEqual(result.returncode, 0, out)
        self.assertIn('unsafe panel path record', out)

    def test_panel_retry_refuses_independent_install_after_prepare_failed(self):
        root = self.root / 'panel-independent'
        root.mkdir()
        self.panel_stage(root, schema=16)
        result = self.run_panel(root, r"""
if awgStateRestorePanel "$ROOT/stage" "$ROOT/journal" "$ROOT/work"; then exit 10; fi
mkdir -p "$ROOT/etc" "$ROOT/data"
printf standalone >"$WEB_PANEL_ENV_FILE"
printf standalone >"$WEB_PANEL_SYSTEMD_UNIT"
printf standalone >"$AWG_STATE_PANEL_DEFAULT_DB"
touch "$ROOT/checkout/amneziawg-web/migrations/0016_m.sql"
: >"$ROOT/systemctl.log"
if awgStateRestorePanel "$ROOT/stage" "$ROOT/journal" "$ROOT/work"; then exit 11; fi
[[ ! -s "$ROOT/systemctl.log" && ! -e "$ROOT/installer.runs" ]] || exit 12
for file in "$WEB_PANEL_ENV_FILE" "$WEB_PANEL_SYSTEMD_UNIT" "$AWG_STATE_PANEL_DEFAULT_DB"; do
    [[ "$(<"$file")" == standalone ]] || exit 13
done
""")
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())

    def test_panel_refuses_active_unit_with_missing_fragment_on_disk(self):
        root = self.root / 'panel-active-missing-fragment'
        root.mkdir()
        self.panel_stage(root)
        result = self.run_panel(root, r"""
if awgStateRestorePanel "$ROOT/stage" "$ROOT/journal" "$ROOT/work"; then exit 10; fi
[[ ! -e "$ROOT/installer.runs" && ! -e "$ROOT/systemctl.log" ]] || exit 11
""", SYSTEMD_FRAGMENT=str(root / 'unit'), SYSTEMD_ACTIVE='active')
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        self.assertIn(b'cannot establish ownership of the effective panel unit', result.stderr)

    def test_panel_restore_refusals(self):
        cases = {
            'existing-panel': ('mkdir -p "$ROOT/etc"; touch "$WEB_PANEL_ENV_FILE"', {}, 'a panel is already installed'),
            'newer-schema': ('', {'schema': 16}, 'newer than this panel source'),
            'no-hash': ('', {'env': 'AUTH_ENABLED=false\n'}, 'Argon2 AUTH_PASSWORD_HASH is required'),
            'no-installer': ('awgStatePanelInstaller() { return 1; }', {}, 'was not found next to this script'),
            'installer-fails': ('export FAIL_INSTALLER=1', {}, '--non-interactive failed'),
        }
        for name, (setup, kwargs, message) in cases.items():
            with self.subTest(name=name):
                root = self.root / name
                root.mkdir()
                self.panel_stage(root, **kwargs)
                result = self.run_panel(root, setup + r"""
if awgStateRestorePanel "$ROOT/stage" "$ROOT/journal" "$ROOT/work"; then exit 10; fi
[[ ! -e "$ROOT/journal/panel-restored" ]] || exit 11
! grep -q '^enable' "$ROOT/systemctl.log" 2>/dev/null || exit 12
""")
                out = (result.stdout + result.stderr).decode()
                self.assertEqual(result.returncode, 0, out)
                self.assertIn(message, out)
                self.assertFalse((root / 'data/awg-web.db').exists())

    def test_panel_plan_in_dry_run_and_inspect(self):
        root = self.root / 'plan'
        root.mkdir()
        stage = self.panel_stage(root)
        result = self.run_panel(root, 'awgStatePanelPlan "$ROOT/stage"')
        out = result.stdout.decode()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn('"archive_schema": 15', out)
        self.assertIn('"panel_schema": 15', out)
        self.assertIn('"queued_mail_to_cancel": 1', out)
        self.assertIn('build from source via', out)
        self.files['web/database.sqlite'] = (stage / 'web/database.sqlite').read_bytes()
        self.files['web/env.conf'] = (stage / 'web/env.conf').read_bytes()
        make_tar(self.tar, self.files)
        plan = json.loads(self.run_helper('inspect', self.tar, self.root / 'inspect-dir',
                                          root / 'checkout/amneziawg-web/migrations').stdout)['panel_plan']
        self.assertEqual(plan['archive_schema'], 15)
        self.assertTrue(plan['password_hash_present'])
        self.assertFalse(plan['schema_newer_than_panel'])
        self.assertNotIn('argon2', json.dumps(plan))

    def test_panel_health_probe_uses_listen_and_base_path(self):
        import http.server, threading
        hits = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                self.send_response(200 if self.path == '/p/api/health' else 404)
                self.end_headers()
            def log_message(self, *args):
                pass
        server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        env = self.root / 'env.conf'
        env.write_text('AWG_WEB_LISTEN=0.0.0.0:%d\nAWG_WEB_BASE_PATH="/p/"\n' % server.server_port)
        result = subprocess.run(['bash', '-c', 'source "$1"; awgStatePanelHealthy "$2"', 'test', str(SCRIPT), str(env)],
                                capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn('/p/api/health', hits)

    def test_finalized_activation_panel_failure_keeps_vpn_running(self):
        root = self.root / 'act'
        root.mkdir()
        shell = self.activation_harness() + r"""
SIG=TERM SIG_AT=none
awgStateRestorePanel() { echo "panel-called lock=${CLIENT_LIFECYCLE_LOCK_FD:-none}"; return 1; }
awgStateReconcileImport "$ROOT/stage" "$ROOT/journal" "$ROOT/work" --activate-state --enable-at-boot ens3
echo "rc=$? running=$([[ -e $ROOT/running ]] && echo y) enabled=$([[ -e $ROOT/enabled ]] && echo y) finalized=$([[ -e $ROOT/journal/finalized ]] && echo y)"
"""
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(root)], capture_output=True)
        out = result.stdout.decode()
        self.assertIn('panel-called lock=none', out, result.stderr.decode())
        self.assertIn('rc=1 running=y enabled=y finalized=y', out, result.stderr.decode())

    PROXY_TOML = ('# generated\nlisten = "0.0.0.0:51820"\nbackend = "127.0.0.1:51821"\nimitate_protocol = "dns"\n'
                  'quic_handshake_enabled = false\ndns_forward_enabled = true\ndns_upstream = "1.1.1.1:53"\n'
                  'session_ttl_secs = 300\nmax_sessions = 777\nstatus_file = "/var/lib/amneziawg-proxy/sessions.json"\n'
                  'rate_limit_per_sec = 5\nawg_config = "/etc/amnezia/amneziawg/awg0.conf"\n')

    def proxy_stage(self, root, toml=None, listen_port=51821, meta=None):
        stage = root / 'stage'
        (stage / 'vpn').mkdir(parents=True, exist_ok=True)
        (stage / 'proxy').mkdir(parents=True, exist_ok=True)
        # Realistic default topology: params keep SERVER_PORT (the proxy's public
        # port), the proxy installer moved AWG's ListenPort to the backend.
        files = state_fixture()
        (stage / 'vpn/params').write_bytes(files['vpn/params'])
        (stage / 'vpn/server.conf').write_bytes(files['vpn/server.conf'].replace(b'ListenPort = 51820', b'ListenPort = %d' % listen_port))
        if meta is not None:
            (root / 'defaults.sh').write_text('AWG_STATE_PROXY_CONFIG=%s\nAWG_STATE_PROXY_DEFAULT_DATA=%s\nAWG_STATE_PROXY_DEFAULT_INSTALL=%s\n'
                                              % (meta['config_path'], meta['data_dir'], meta['install_dir']))
        (stage / 'proxy/proxy.toml').write_text(toml if toml is not None else self.PROXY_TOML)
        if meta is not None:
            (stage / 'proxy/install.json').write_text(json.dumps(meta))
        installer = root / 'checkout/amneziawg-proxy/scripts/amneziawg-proxy-install.sh'
        installer.parent.mkdir(parents=True)
        installer.write_text('#!/bin/bash\nprintf "%s\\n" "$@" >>"$PROXY_ROOT/installer.args"\necho run >>"$PROXY_ROOT/installer.runs"\n'
                             '[[ -z "${FAIL_INSTALLER:-}" ]] || exit 1\n'
                             'while (($#)); do [[ "$1" == --config-file ]] && { mkdir -p "${2%/*}"; echo generated >"$2"; }; shift; done\n'
                             'touch "$PROXY_ROOT/unit"\n[[ -z "${FAIL_AFTER_UNIT:-}" ]]\n')
        return stage

    PROXY_HARNESS = r"""
set -uo pipefail
source "$1"
ROOT="$2"; export PROXY_ROOT="$ROOT"
awgStateLockCompanionInstallers() { AWG_COMPANION_INSTALL_LOCK_FD=0; }
AMNEZIAWG_DIR="$ROOT/vpn"; SERVER_AWG_NIC=awg0; SERVER_AWG_CONF="$AMNEZIAWG_DIR/awg0.conf"
mkdir -p "$ROOT/journal" "$ROOT/work" "$AMNEZIAWG_DIR"
cp "$ROOT/stage/vpn/server.conf" "$SERVER_AWG_CONF"
awgStateTrustedPath() { return 0; }
awg() { [[ "$*" == 'show awg0 listen-port' ]] && printf '%s\n' "${MOCK_LIVE_PORT:-51821}"; }
AWG_STATE_PROXY_UNIT="$ROOT/unit"
awgStateProxyInstaller() { printf '%s\n' "$ROOT/checkout/amneziawg-proxy/scripts/amneziawg-proxy-install.sh"; }
install() { local a=(); while (($#)); do case "$1" in -o|-g) shift 2 ;; *) a+=("$1"); shift ;; esac; done; command install "${a[@]}"; }
systemctl() {
    case "$1 ${2:-}" in
        'show --property=FragmentPath') printf '%s' "${SYSTEMD_FRAGMENT:-}"; return 0 ;;
        'show --property=ActiveState') printf '%s' "${SYSTEMD_ACTIVE:-inactive}"; return 0 ;;
    esac
    printf '%s\n' "$*" >>"$ROOT/systemctl.log"
    [[ "$1 ${FAIL_START:-}" != 'start 1' && "$1 ${FAIL_STOP:-}" != 'stop 1' ]]
}
awgStateProxyHealthy() { [[ -z "${UNHEALTHY:-}" ]]; }
[[ ! -f "$ROOT/defaults.sh" ]] || source "$ROOT/defaults.sh"
"""

    def run_proxy(self, root, body, **env):
        return subprocess.run(['bash', '-c', self.PROXY_HARNESS + body, 'test', str(SCRIPT), str(root)],
                              capture_output=True, env=dict(os.environ, **env))

    def test_proxy_restore_uses_installer_flags_archived_config_and_is_idempotent(self):
        root = self.root / 'proxy-ok'
        root.mkdir()
        meta = dict(config_path=str(root / 'custom/proxy.toml'), data_dir=str(root / 'pdata'), install_dir=str(root / 'bin'))
        self.proxy_stage(root, meta=meta)
        result = self.run_proxy(root, r"""
awgStateRestoreProxy "$ROOT/stage" "$ROOT/journal" "$ROOT/work" || exit 10
awgStateRestoreProxy "$ROOT/stage" "$ROOT/journal" "$ROOT/work" || exit 11
""")
        out = (result.stdout + result.stderr).decode()
        self.assertEqual(result.returncode, 0, out)
        self.assertIn('Proxy already restored', out)
        self.assertEqual((root / 'installer.runs').read_text(), 'run\n')
        args = (root / 'installer.args').read_text().splitlines()
        def value(flag):
            return args[args.index(flag) + 1]
        self.assertIn('--require-existing-awg-port', args)
        self.assertEqual((value('--listen-host'), value('--listen-port'), value('--backend-host'), value('--backend-port')),
                         ('0.0.0.0', '51820', '127.0.0.1', '51821'))
        self.assertEqual(value('--protocol'), 'dns')
        self.assertEqual(value('--dns-upstream'), '1.1.1.1:53')
        self.assertEqual(value('--config-file'), meta['config_path'])
        self.assertEqual(value('--data-dir'), meta['data_dir'])
        self.assertEqual(value('--install-dir'), meta['install_dir'])
        self.assertEqual(value('--awg-dir'), str(root / 'vpn'))
        for flag in ('--non-interactive', '--no-start', '--no-enable', '--dns-forward'):
            self.assertIn(flag, args)
        self.assertNotIn('--quic-handshake', args)
        config = (root / 'custom/proxy.toml').read_text()
        self.assertIn('max_sessions = 777', config)  # Archived file, not the generated one.
        self.assertIn('awg_config = "%s/vpn/awg0.conf"' % root, config)
        self.assertEqual(oct((root / 'custom/proxy.toml').stat().st_mode & 0o777), '0o600')
        log = (root / 'systemctl.log').read_text()
        self.assertLess(log.index('start amneziawg-proxy'), log.index('enable amneziawg-proxy'))
        self.assertTrue((root / 'journal/proxy-restored').exists())
        self.assertFalse((root / 'journal/proxy-installing').exists())
        self.assertIn('proxy-restored', (root / 'journal/steps').read_text())

    def test_proxy_restore_leaves_companions_unmodified_when_live_port_differs(self):
        root = self.root / 'proxy-local-port'
        root.mkdir()
        meta = dict(config_path=str(root / 'proxy/proxy.toml'), data_dir=str(root / 'pdata'),
                    install_dir=str(root / 'bin'))
        self.proxy_stage(root, meta=meta)
        result = self.run_proxy(root, r"""
if awgStateRestoreProxy "$ROOT/stage" "$ROOT/journal" "$ROOT/work"; then exit 10; fi
[[ ! -e "$ROOT/installer.runs" && ! -e "$ROOT/systemctl.log" ]]
""", MOCK_LIVE_PORT='51831')
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        self.assertIn(b'current VPN listen port does not match', result.stderr)

    def test_proxy_restore_failure_is_retryable(self):
        root = self.root / 'proxy-retry'
        root.mkdir()
        self.proxy_stage(root, meta=dict(config_path=str(root / 'p/proxy.toml'), data_dir=str(root / 'd'), install_dir=str(root / 'b')))
        result = self.run_proxy(root, r"""
if UNHEALTHY=1 awgStateRestoreProxy "$ROOT/stage" "$ROOT/journal" "$ROOT/work"; then exit 10; fi
[[ -e "$ROOT/journal/proxy-installing" && ! -e "$ROOT/journal/proxy-restored" ]] || exit 11
[[ -f "$ROOT/journal/proxy-approved-dirs" && ! -L "$ROOT/journal/proxy-approved-dirs" ]] || exit 15
! grep -q '^enable' "$ROOT/systemctl.log" || exit 12
awgStateRestoreProxy "$ROOT/stage" "$ROOT/journal" "$ROOT/work" || exit 13
[[ -e "$ROOT/journal/proxy-restored" ]] || exit 14
""")
        out = (result.stdout + result.stderr).decode()
        self.assertEqual(result.returncode, 0, out)
        self.assertIn('did not stay active/listen', out)
        self.assertIn('VPN and the panel are unaffected', out)

    def test_proxy_retry_refuses_independent_install_after_install_failed(self):
        root = self.root / 'proxy-independent'
        root.mkdir()
        self.proxy_stage(root, meta=dict(config_path=str(root / 'p/proxy.toml'), data_dir=str(root / 'd'), install_dir=str(root / 'b')))
        result = self.run_proxy(root, r"""
if FAIL_INSTALLER=1 awgStateRestoreProxy "$ROOT/stage" "$ROOT/journal" "$ROOT/work"; then exit 10; fi
mkdir -p "${AWG_STATE_PROXY_CONFIG%/*}"
printf standalone >"$AWG_STATE_PROXY_CONFIG"
printf standalone >"$AWG_STATE_PROXY_UNIT"
: >"$ROOT/systemctl.log"
if awgStateRestoreProxy "$ROOT/stage" "$ROOT/journal" "$ROOT/work"; then exit 11; fi
[[ ! -s "$ROOT/systemctl.log" && "$(<"$AWG_STATE_PROXY_CONFIG")" == standalone ]] || exit 12
[[ "$(<"$AWG_STATE_PROXY_UNIT")" == standalone ]] || exit 13
""")
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())

    def test_companion_installer_lock_is_shared_and_inherited(self):
        lock_dir = str(self.root / 'installer-lock')
        stub = """stat() { # Only substitute the ownership check for this unprivileged fixture.
    printf '0:700'
}
die() { echo "$*" >&2; exit 1; }
"""
        installer_root = SCRIPT.parent
        main_script = SCRIPT.read_text()
        main_lock = re.search(r'^function awgStateLockCompanionInstallers\(\) \{.*?^}', main_script,
                              re.MULTILINE | re.DOTALL).group().replace('/run/awg-companion-install', lock_dir)
        children = []
        for companion in ('web', 'proxy'):
            installer = installer_root / f'amneziawg-{companion}/scripts/amneziawg-{companion}-install.sh'
            lock = re.search(r'^lock_companion_installers\(\) \{.*?^}', installer.read_text(),
                             re.MULTILINE | re.DOTALL).group().replace('/run/awg-companion-install', lock_dir)
            child = self.root / f'{companion}-lock.sh'
            child.write_text(stub + lock + '\nlock_companion_installers\n')
            children.append(str(child))
        shell = stub + main_lock + r"""
awgStateLockCompanionInstallers || exit 10
for child; do
    AWG_COMPANION_INSTALL_LOCK_FD="$AWG_COMPANION_INSTALL_LOCK_FD" bash "$child" || exit 11
    if env -u AWG_COMPANION_INSTALL_LOCK_FD bash "$child"; then exit 12; fi
done
"""
        result = subprocess.run(['bash', '-c', shell, 'test', *children], capture_output=True)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        self.assertEqual(result.stderr.count(b'Another panel/proxy installer or migration is running'), 2)

    def test_owned_partial_companions_retry_only_after_successful_stop(self):
        cases = (
            ('Panel', self.panel_stage, self.run_panel),
            ('Proxy', self.proxy_stage, self.run_proxy),
        )
        for kind, stage, run in cases:
            with self.subTest(kind=kind):
                root = self.root / kind.lower()
                root.mkdir()
                if kind == 'Proxy':
                    stage(root, meta=dict(config_path=str(root / 'p/proxy.toml'),
                                          data_dir=str(root / 'd'), install_dir=str(root / 'b')))
                else:
                    stage(root)
                body = r"""
if FAIL_AFTER_UNIT=1 awgStateRestoreKIND "$ROOT/stage" "$ROOT/journal" "$ROOT/work"; then exit 10; fi
if FAIL_STOP=1 awgStateRestoreKIND "$ROOT/stage" "$ROOT/journal" "$ROOT/work"; then exit 11; fi
[[ "$(wc -l <"$ROOT/installer.runs")" == 1 ]] || exit 12
awgStateRestoreKIND "$ROOT/stage" "$ROOT/journal" "$ROOT/work" || exit 13
[[ "$(wc -l <"$ROOT/installer.runs")" == 2 ]] || exit 14
""".replace('KIND', kind)
                result = run(root, body)
                self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())

    def test_proxy_restore_refusals(self):
        cases = {
            'existing-proxy': ('touch "$ROOT/unit"', {}, 'already installed'),
            'backend-mismatch': ('', {'listen_port': 51820}, 'is not the proxy backend port'),
            'unsupported-toml': ('', {'toml': '[table]\nlisten = "0.0.0.0:1"\n'}, 'unsupported proxy.toml line'),
            'no-installer': ('awgStateProxyInstaller() { return 1; }', {}, 'was not found next to this script'),
            'installer-fails': ('export FAIL_INSTALLER=1', {}, '--non-interactive failed'),
        }
        for name, (setup, kwargs, message) in cases.items():
            with self.subTest(name=name):
                root = self.root / ('proxy-' + name)
                root.mkdir()
                self.proxy_stage(root, meta=dict(config_path=str(root / 'p/proxy.toml'), data_dir=str(root / 'd'),
                                                 install_dir=str(root / 'b')), **kwargs)
                result = self.run_proxy(root, setup + r"""
if awgStateRestoreProxy "$ROOT/stage" "$ROOT/journal" "$ROOT/work"; then exit 10; fi
[[ ! -e "$ROOT/journal/proxy-restored" ]] || exit 11
! grep -q '^enable' "$ROOT/systemctl.log" 2>/dev/null || exit 12
""")
                out = (result.stdout + result.stderr).decode()
                self.assertEqual(result.returncode, 0, out)
                self.assertIn(message, out)

    def test_companion_failure_isolation(self):
        result = subprocess.run(['bash', '-c', r"""
source "$1"
awgStateRestorePanel() { echo panel; return 1; }
awgStateRestoreProxy() { echo proxy; return 0; }
awgStateRestoreCompanions a "$2" c; echo "rc=$?"
""", 'test', str(SCRIPT), str(self.root)], capture_output=True)
        self.assertEqual(result.stdout.decode(), 'panel\nproxy\nrc=1\n')

    def test_proxy_install_paths_from_unit(self):
        unit = self.root / 'proxy.service'
        shell = r"""
source "$1"
AWG_STATE_PROXY_UNIT="$2"
awgStateProxyInstallPaths
"""
        unit.write_text('[Service]\nExecStart="/opt/p/bin/amneziawg-proxy" /srv/p/proxy.toml\nWorkingDirectory=/srv/p/data\n')
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(unit)], capture_output=True)
        self.assertEqual(result.stdout.decode(), '/srv/p/proxy.toml\n/srv/p/data\n/opt/p/bin\n', result.stderr.decode())
        unit.write_text('[Service]\nExecStart=/usr/bin/env amneziawg-proxy --config x\n')
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(unit)], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'refusing to guess', result.stderr)
        unit.unlink()
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(unit)], capture_output=True)
        self.assertEqual(result.stdout.decode(), '/etc/amneziawg-proxy/proxy.toml\n/var/lib/amneziawg-proxy\n/usr/local/bin\n')

    def test_export_includes_custom_proxy_and_schema_2(self):
        source = self.root / 'source'
        (source / 'clients').mkdir(parents=True)
        (source / 'params').write_bytes(self.files['vpn/params'])
        (source / 'awg0.conf').write_bytes(self.files['vpn/server.conf'])
        (self.root / 'srv').mkdir()
        (self.root / 'srv/proxy.toml').write_text(self.PROXY_TOML)
        (self.root / 'proxy.service').write_text('[Service]\nExecStart=/opt/bin/amneziawg-proxy %s/srv/proxy.toml\n'
                                                 'WorkingDirectory=/srv/pdata\n' % self.root)
        (self.root / 'work').mkdir()
        shell = r"""
set -uo pipefail
source "$1"
ROOT="$2"
AMNEZIAWG_DIR="$ROOT/source"; AWG_STATE_PROXY_UNIT="$ROOT/proxy.service"
acquireClientLifecycleLock() { CLIENT_LIFECYCLE_LOCK_FD=held; }
releaseClientLifecycleLock() { CLIENT_LIFECYCLE_LOCK_FD=""; }
awgStateTrustedPath() { return 0; }
isWebPanelInstalled() { return 1; }
collectAwgClientConfigCandidates() { local -n OUTPUT="$1"; OUTPUT=(); }
awg() { printf 'fixture-tools\n'; }
age() { cat >"$3"; }
awgStateExport "$ROOT/export.tar.gz" "$ROOT/work"
"""
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)], capture_output=True)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        with tarfile.open(self.root / 'export.tar.gz') as archive:
            meta = json.load(archive.extractfile('manifest.json'))
            install = json.load(archive.extractfile('proxy/install.json'))
            toml = archive.extractfile('proxy/proxy.toml').read().decode()
        self.assertEqual(meta['schema_version'], 2)
        self.assertIn('proxy/install.json', meta['files'])
        self.assertEqual(install, dict(config_path=str(self.root / 'srv/proxy.toml'), data_dir='/srv/pdata', install_dir='/opt/bin'))
        self.assertEqual(toml, self.PROXY_TOML)
        # Imports both schemas; schema 1 may not carry install.json.
        self.run_helper('verify', self.root / 'export.tar.gz')
        plan = json.loads(self.run_helper('inspect', self.root / 'export.tar.gz').stdout)['proxy_plan']
        self.assertEqual(plan['install_paths']['install_dir'], '/opt/bin')
        self.assertFalse(plan['awg_matches_backend'])  # Fixture AWG listens on 51820.
        self.files['proxy/install.json'] = json.dumps(install).encode()
        make_tar(self.tar, self.files)
        self.assertNotEqual(self.run_helper('verify', ok=False).returncode, 0)
        meta1 = manifest(self.files)
        meta1['schema_version'] = 2
        make_tar(self.tar, self.files, meta1)
        self.run_helper('verify')

    EXPORT_SHELL = r"""
set -uo pipefail
source "$1"
ROOT="$2"
AMNEZIAWG_DIR="$ROOT/source"; AWG_STATE_PROXY_UNIT="$ROOT/proxy.service"; AWG_STATE_PROXY_CONFIG="$ROOT/etc-proxy/proxy.toml"
acquireClientLifecycleLock() { CLIENT_LIFECYCLE_LOCK_FD=held; }
releaseClientLifecycleLock() { CLIENT_LIFECYCLE_LOCK_FD=""; }
awgStateTrustedPath() { return 0; }
isWebPanelInstalled() { return 1; }
collectAwgClientConfigCandidates() { local -n OUTPUT="$1"; OUTPUT=(); }
awg() { printf 'fixture-tools\n'; }
age() { cat >"$3"; }
rm -rf "$ROOT/work"; mkdir "$ROOT/work"
awgStateExport "$ROOT/export.tar.gz" "$ROOT/work"
"""

    def installer_proxy_toml(self, path, awg_conf):
        # The real proxy installer's write_proxy_config with its defaults
        # (listen = detected AWG port 51820, backend 127.0.0.1:51821).
        installer = ROOT / 'amneziawg-proxy/scripts/amneziawg-proxy-install.sh'
        shell = r"""
set -eo pipefail
eval "$(sed -n '/^readonly DEFAULT_/p' "$1")"
eval "$(sed -n '/^write_proxy_config() {/,/^}/p' "$1")"
step() { :; }; info() { :; }; warn() { :; }; chown() { :; }; _has_toml_unsafe_chars() { return 1; }
CONFIG_FILE="$2" AWG_CONF_FILE="$3" FORCE=false NON_INTERACTIVE=true SERVICE_NAME=amneziawg-proxy
LISTEN_HOST="$DEFAULT_LISTEN_HOST" LISTEN_PORT=51820 BACKEND_HOST="$DEFAULT_BACKEND_HOST" BACKEND_PORT="$DEFAULT_BACKEND_PORT"
PROTOCOL="$DEFAULT_PROTOCOL" SESSION_TTL="$DEFAULT_SESSION_TTL" RATE_LIMIT="$DEFAULT_RATE_LIMIT"
PROBE_REPLY_BYTES="$DEFAULT_PROBE_REPLY_BYTES" DNS_FORWARD_ENABLED=false QUIC_HANDSHAKE_ENABLED=false
write_proxy_config
"""
        path.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(['bash', '-c', shell, 'gen', str(installer), str(path), awg_conf], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        text = path.read_text()
        self.assertIn('listen = "0.0.0.0:51820"', text)
        self.assertIn('backend = "127.0.0.1:51821"', text)
        return text

    def export_source(self, listen_port, proxy=True):
        source = self.root / 'source'
        (source / 'clients').mkdir(parents=True, exist_ok=True)
        (source / 'params').write_bytes(self.files['vpn/params'])  # SERVER_PORT=51820, never edited by the proxy installer
        (source / 'awg0.conf').write_bytes(self.files['vpn/server.conf'].replace(b'ListenPort = 51820', b'ListenPort = %d' % listen_port))
        if proxy:
            self.installer_proxy_toml(self.root / 'etc-proxy/proxy.toml', str(source / 'awg0.conf'))
        return subprocess.run(['bash', '-c', self.EXPORT_SHELL, 'test', str(SCRIPT), str(self.root)], capture_output=True)

    def test_export_import_default_proxy_topology(self):
        # M1: proxy installer default topology. Full export path, then verify,
        # inspect, prepare and proxy-prepare from the produced archive.
        result = self.export_source(51821)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        archive = self.root / 'export.tar.gz'
        self.run_helper('verify', archive)
        inspect = self.run_helper('inspect', archive)
        plan = json.loads(inspect.stdout)['proxy_plan']
        self.assertEqual((plan['topology'], plan['awg_matches_backend'], plan['server_port'], plan['awg_listen_port']),
                         ('proxy', True, 51820, 51821))
        self.assertIsNone(plan['refusal'])
        self.assertIn(b'clients cannot reach the VPN', inspect.stderr)
        self.assertEqual(json.loads(inspect.stdout)['schema_version'], 2)
        stage = self.root / 'stage'
        self.run_helper('unpack', archive, stage)
        self.run_helper('prepare', stage)
        self.assertIn('ListenPort = 51821', (stage / 'interface.conf').read_text())
        self.assertEqual(self.run_helper('awg-port', stage).stdout, b'51821\n')
        out = self.root / 'proxy-out'
        fields = self.run_helper('proxy-prepare', stage, out, '/etc/amnezia/amneziawg/awg0.conf', '',
                                 self.root / 'etc-proxy/proxy.toml', '/var/lib/amneziawg-proxy', '/usr/local/bin').stdout.split(b'\0')
        self.assertEqual(fields[3], b'51820')
        self.assertEqual(fields[fields.index(b'--listen-port') + 1], b'51820')
        self.assertEqual(fields[fields.index(b'--backend-port') + 1], b'51821')
        # Reconcile on the finalized host keeps the backend ListenPort.
        local = self.root / 'local.conf'
        local.write_bytes((stage / 'vpn/server.conf').read_bytes())
        self.run_helper('reconcile', local, stage, self.root / 'clean.conf')

    def test_export_topology_errors_are_explicit(self):
        # ListenPort moved but no proxy config explains it (e.g. proxy removed).
        result = self.export_source(51821, proxy=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'differs from SERVER_PORT (51820) in params and no amneziawg-proxy', result.stderr)
        # Proxy present, but neither direct nor proxy topology.
        result = self.export_source(51999)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'match neither a direct setup nor the amneziawg-proxy topology', result.stderr)
        # A crafted archive is rejected the same way at verify.
        files = dict(self.files)
        files['vpn/server.conf'] = files['vpn/server.conf'].replace(b'ListenPort = 51820', b'ListenPort = 51821')
        make_tar(self.tar, files)
        self.assertIn(b'no amneziawg-proxy config explains it', self.run_helper('verify', ok=False).stderr)

    def test_non_subset_proxy_toml_does_not_block_vpn_export(self):
        # Valid TOML the proxy accepts, and an unknown key it ignores, must not
        # fail VPN export/import. The proxy step still refuses and names the key.
        cases = {
            'single-quotes': ("listen = '0.0.0.0:51820'\nbackend = '127.0.0.1:51821'\n", 'listen'),
            'underscore': ('listen = "0.0.0.0:51820"\nbackend = "127.0.0.1:51821"\nmax_sessions = 10_000\n', 'max_sessions'),
            'unknown-key': ('listen = "0.0.0.0:51820"\nbackend = "127.0.0.1:51821"\nlog_level = "info"\n', 'log_level'),
        }
        for name, (toml, key) in cases.items():
            with self.subTest(name=name):
                stage = self.root / name
                (stage / 'vpn').mkdir(parents=True)
                (stage / 'proxy').mkdir()
                (stage / 'vpn/params').write_bytes(self.files['vpn/params'])
                (stage / 'vpn/server.conf').write_bytes(
                    self.files['vpn/server.conf'].replace(b'ListenPort = 51820', b'ListenPort = 51821'))
                (stage / 'proxy/proxy.toml').write_text(toml)
                self.run_helper('export-check', stage)
                packed = self.root / (name + '.tar.gz')
                self.run_helper('pack', stage, packed, 'awg-fixture')
                self.run_helper('verify', packed)
                dest = self.root / (name + '-unpacked')
                self.run_helper('unpack', packed, dest)
                self.run_helper('prepare', dest)
                self.assertIn('ListenPort = 51821', (dest / 'interface.conf').read_text())
                # Inspect and proxy-plan warn and still emit the plan. Restore refuses.
                inspected = self.run_helper('inspect', packed)
                view = json.loads(inspected.stdout)
                self.assertIn('peer_plan', view)
                self.assertEqual(view['proxy_plan']['present'], True)
                self.assertIn(key, view['proxy_plan']['error'])
                self.assertEqual(view['proxy_plan']['refusal'], 'proxy restore would be refused')
                self.assertIn(b'WARNING: amneziawg-proxy: ', inspected.stderr)
                self.assertIn(key.encode(), inspected.stderr)
                self.assertIn(b'proxy restore would be refused', inspected.stderr)
                self.assertNotIn(b'ERROR:', inspected.stderr)
                planned = self.run_helper('proxy-plan', dest)
                plan = json.loads(planned.stdout)
                self.assertIn(key, plan['error'])
                self.assertNotIn(b'ERROR:', planned.stderr)
                refused_prepare = self.run_helper('proxy-prepare', dest, self.root / (name + '-out'),
                                                  '/etc/amnezia/amneziawg/awg0.conf', '', ok=False)
                self.assertIn(key.encode(), refused_prepare.stderr)
                self.assertNotIn(b'invalid or unsupported', refused_prepare.stderr)
                # The same file in the direct topology exports too.
                (stage / 'vpn/server.conf').write_bytes(self.files['vpn/server.conf'])
                self.run_helper('export-check', stage)
                root = self.root / (name + '-restore')
                root.mkdir()
                self.proxy_stage(root, toml=toml, meta=dict(config_path=str(root / 'p/proxy.toml'),
                                                            data_dir=str(root / 'd'), install_dir=str(root / 'b')))
                result = self.run_proxy(root, r"""
if awgStateRestoreProxy "$ROOT/stage" "$ROOT/journal" "$ROOT/work"; then exit 10; fi
[[ ! -e "$ROOT/installer.runs" ]] || exit 11
""")
                out = (result.stdout + result.stderr).decode()
                self.assertEqual(result.returncode, 0, out)
                self.assertIn(key, out)
                self.assertNotIn('invalid or unsupported', out)
        # Unreadable listen/backend: direct export still proceeds; a moved
        # ListenPort fails with the explicit topology error, not a generic one.
        stage = self.root / 'unreadable'
        (stage / 'vpn').mkdir(parents=True)
        (stage / 'proxy').mkdir()
        (stage / 'vpn/params').write_bytes(self.files['vpn/params'])
        (stage / 'vpn/server.conf').write_bytes(self.files['vpn/server.conf'])
        (stage / 'proxy/proxy.toml').write_text('not toml\n')
        self.run_helper('export-check', stage)
        (stage / 'vpn/server.conf').write_bytes(
            self.files['vpn/server.conf'].replace(b'ListenPort = 51820', b'ListenPort = 51821'))
        refused = self.run_helper('export-check', stage, ok=False)
        self.assertIn(b'no amneziawg-proxy config explains it', refused.stderr)
        self.assertNotIn(b'invalid or unsupported', refused.stderr)

    def test_unusable_proxy_address_is_a_named_warning_on_inspect(self):
        # A subset-valid proxy.toml with an unusable listen/backend must not
        # hide the VPN plan behind the generic archive error.
        cases = {
            'backend': ('listen = "0.0.0.0:51820"\nbackend = "localhost:51821"\n', b'key backend'),
            'listen': ('listen = "0.0.0.0:99999"\nbackend = "127.0.0.1:51821"\n', b'key listen'),
        }
        for name, (toml, needle) in cases.items():
            with self.subTest(name=name):
                files = dict(self.files)
                files['proxy/proxy.toml'] = toml.encode()
                packed = self.root / (name + '-addr.tar.gz')
                make_tar(packed, files)
                inspected = self.run_helper('inspect', packed)
                view = json.loads(inspected.stdout)
                self.assertIn('peer_plan', view)
                self.assertIn(needle, view['proxy_plan']['error'].encode())
                self.assertEqual(view['proxy_plan']['refusal'], 'proxy restore would be refused')
                self.assertIn(b'WARNING: amneziawg-proxy: ', inspected.stderr)
                self.assertIn(needle, inspected.stderr)
                self.assertNotIn(b'invalid or unsupported', inspected.stderr)
                stage = self.root / (name + '-addr-stage')
                self.run_helper('unpack', packed, stage)
                refused = self.run_helper('proxy-prepare', stage, self.root / (name + '-out'),
                                          '/etc/amnezia/amneziawg/awg0.conf', '', ok=False)
                self.assertIn(needle, refused.stderr)
                self.assertNotIn(b'invalid or unsupported', refused.stderr)

    def test_listen_addr_is_refused_with_an_explicit_message(self):
        # amneziawg-tools awg setconf rejects ListenAddr. Carrying it would
        # make the restored interface fail to start.
        stage = self.root / 'listen-addr'
        (stage / 'vpn').mkdir(parents=True)
        (stage / 'vpn/params').write_bytes(self.files['vpn/params'])
        conf = self.files['vpn/server.conf'].replace(
            b'ListenPort = 51820\n', b'ListenPort = 51820\nListenAddr = 127.0.0.1\n')
        (stage / 'vpn/server.conf').write_bytes(conf)
        refused = self.run_helper('export-check', stage, ok=False)
        self.assertIn(b'ListenAddr is not accepted by amneziawg-tools', refused.stderr)
        self.assertNotIn(b'invalid or unsupported', refused.stderr)
        files = dict(self.files)
        files['vpn/server.conf'] = conf
        make_tar(self.tar, files)
        verified = self.run_helper('verify', ok=False)
        self.assertIn(b'ListenAddr is not accepted by amneziawg-tools', verified.stderr)
        self.assertNotIn(b'invalid or unsupported', verified.stderr)

    def test_endpoint_audit_counts_literal_ip_profiles(self):
        files = dict(self.files)
        files['clients/awg0-client-literal.conf'] = (
            '[Interface]\nPrivateKey = %s\nAddress = 10.66.66.3/32\n'
            '# Endpoint = 198.51.100.9:51820\n'
            '[Peer]\nPublicKey = %s\nEndpoint = 203.0.113.7:51820\nAllowedIPs = 0.0.0.0/0\n' % (KEY, PUB)
        ).encode()
        files['clients/awg0-client-v6.conf'] = (
            '[Interface]\nPrivateKey = %s\nAddress = 10.66.66.4/32\n'
            '[Peer]\nPublicKey = %s\nEndpoint = [2001:db8::5]:51820\nAllowedIPs = 0.0.0.0/0\n' % (KEY, PUB)
        ).encode()
        # glibc inet_aton accepts these without DNS. They are literals, not names.
        inet_aton_hosts = (
            ('hex', '0x7f.1'),
            ('short', '123'),
            ('triple', '1.2.3'),
            ('octal', '0177.0.0.1'),
            ('wide', '4294967295'),
        )
        for label, host in inet_aton_hosts:
            files['clients/awg0-client-%s.conf' % label] = (
                '[Interface]\nPrivateKey = %s\nAddress = 10.66.66.5/32\n'
                '[Peer]\nPublicKey = %s\nEndpoint = %s:51820\nAllowedIPs = 0.0.0.0/0\n' % (KEY, PUB, host)
            ).encode()
        files['clients/awg0-client-dns.conf'] = (
            '[Interface]\nPrivateKey = %s\nAddress = 10.66.66.6/32\n'
            '[Peer]\nPublicKey = %s\nEndpoint = 1e100.net:51820\nAllowedIPs = 0.0.0.0/0\n' % (KEY, PUB)
        ).encode()
        make_tar(self.tar, files)
        inspected = self.run_helper('inspect')
        audit = json.loads(inspected.stdout)['endpoint_audit']
        self.assertEqual(audit['hostname'], 2)
        self.assertEqual(audit['ip_literal'], 7)
        kinds = {item['name']: item['kind'] for item in audit['clients']}
        self.assertEqual(kinds['awg0-client-phone'], 'hostname')
        self.assertEqual(kinds['awg0-client-dns'], 'hostname')
        self.assertEqual(kinds['awg0-client-literal'], 'ip_literal')
        for label, host in inet_aton_hosts:
            self.assertEqual(kinds['awg0-client-%s' % label], 'ip_literal')
            self.assertIn(('awg0-client-%s (%s)' % (label, host)).encode(), inspected.stderr)
        self.assertEqual(next(item['host'] for item in audit['clients'] if item['name'] == 'awg0-client-literal'), '203.0.113.7')
        self.assertIn(b'203.0.113.7', inspected.stderr)
        self.assertIn(b'2001:db8::5', inspected.stderr)
        self.assertIn(b'will need a new profile after an IP ban', inspected.stderr)
        self.assertNotIn(b'1e100.net', inspected.stderr)
        self.assertNotIn(KEY.encode(), inspected.stdout)
        stage = self.root / 'audit-stage'
        self.run_helper('unpack', self.tar, stage)
        prepared = self.run_helper('prepare', stage)
        self.assertIn(b'will need a new profile after an IP ban', prepared.stderr)
        summary = self.run_helper('endpoint-summary', stage)
        self.assertEqual(summary.stdout.splitlines()[:2], [b'2', b'7'])

    def test_endpoint_warning_precedes_encryption_and_count_failure_still_exports(self):
        source = self.root / 'source'
        (source / 'clients').mkdir(parents=True)
        (source / 'params').write_bytes(self.files['vpn/params'])
        (source / 'awg0.conf').write_bytes(self.files['vpn/server.conf'])
        literal = self.files['clients/awg0-client-phone.conf'].replace(
            b'Endpoint = vpn.example.test:51820', b'Endpoint = 203.0.113.7:51820')
        (source / 'clients/awg0-client-phone.conf').write_bytes(literal)
        (self.root / 'work/a').mkdir(parents=True)
        (self.root / 'work/b').mkdir()
        shell = r'''
set -uo pipefail
source "$1"
ROOT="$2"
AMNEZIAWG_DIR="$ROOT/source"
AWG_STATE_PROXY_CONFIG="$ROOT/not-installed-proxy"
acquireClientLifecycleLock() { return 0; }
releaseClientLifecycleLock() { :; }
awgStateTrustedPath() { return 0; }
isWebPanelInstalled() { return 1; }
collectAwgClientConfigCandidates() { local -n OUTPUT="$1"; OUTPUT=("$ROOT/source/clients/awg0-client-phone.conf"); }
awg() { printf 'fixture-tools\n'; }
age() {
    # Snapshot the log age can see. Appending to order.log from here would
    # be overwritten: the caller's stdout fd still owns that file's offset.
    cp -- "$ROOT/order.log" "$ROOT/at-age.log" || return 80
    grep -q 'Client endpoints in this archive: 0 hostname, 1 literal IP.' "$ROOT/at-age.log" || return 81
    grep -q 'will need a new profile after an IP ban' "$ROOT/at-age.log" || return 82
    grep -q 'Enter passphrase' "$ROOT/at-age.log" && return 83
    grep -q 'Encrypted state archive created' "$ROOT/at-age.log" && return 84
    printf 'AGE-STARTED\n' >"$ROOT/age-marker"
    cat >"$3"
}
awgStateExport "$ROOT/warned.tar.gz" "$ROOT/work/a" >"$ROOT/order.log" 2>&1 || {
    echo 'export-failed' >&2
    cat "$ROOT/order.log" >&2
    exit 10
}
[[ -f "$ROOT/age-marker" ]] || { echo 'age-did-not-start' >&2; cat "$ROOT/order.log" >&2; exit 11; }
grep -q 'Encrypted state archive created' "$ROOT/order.log" || { echo 'no-success-line' >&2; exit 12; }
# A broken counter does not change the exit status of an otherwise valid export.
awgStateArchive() {
    if [[ "$1" == endpoint-summary ]]; then return 9; fi
    python3 "$ROOT/helper.py" "${AWG_PARAMS_KEYS} ${AWG_PARAMS_BORINGTUN_KEYS}" "$@"
}
age() { cat >"$3"; }
awgStateExport "$ROOT/count-failed.tar.gz" "$ROOT/work/b" >"$ROOT/count.log" 2>&1 || exit 13
grep -q 'could not count client endpoints; export will continue' "$ROOT/count.log" || exit 14
[[ -f "$ROOT/count-failed.tar.gz" ]] || exit 15
'''
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)], capture_output=True)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        self.assertNotIn(KEY.encode(), (self.root / 'order.log').read_bytes())
        self.run_helper('verify', self.root / 'warned.tar.gz')
        self.run_helper('verify', self.root / 'count-failed.tar.gz')

    def test_client_profile_refusals_happen_before_encryption(self):
        source = self.root / 'source'
        (source / 'clients').mkdir(parents=True)
        (source / 'params').write_bytes(self.files['vpn/params'])
        (source / 'awg0.conf').write_bytes(self.files['vpn/server.conf'])
        client = source / 'clients/awg0-client-phone.conf'
        client.write_bytes(self.files['clients/awg0-client-phone.conf'])
        (self.root / 'work').mkdir()
        shell = r'''
set -uo pipefail
source "$1"
ROOT="$2"
KIND="$3"
AMNEZIAWG_DIR="$ROOT/source"
AWG_STATE_PROXY_CONFIG="$ROOT/not-installed-proxy"
acquireClientLifecycleLock() { return 0; }
releaseClientLifecycleLock() { :; }
awgStateTrustedPath() { return 0; }
isWebPanelInstalled() { return 1; }
collectAwgClientConfigCandidates() { local -n OUTPUT="$1"; OUTPUT=("$ROOT/source/clients/awg0-client-phone.conf"); }
awg() { printf 'fixture-tools\n'; }
age() { touch "$ROOT/age-ran"; cat >"$3"; }
rm -f "$ROOT/age-ran"
awgStateExport "$ROOT/refused-$KIND" "$ROOT/work/$KIND"
status=$?
[[ "$status" -ne 0 && ! -e "$ROOT/age-ran" && ! -e "$ROOT/refused-$KIND" ]] || exit 10
'''
        base = self.files['clients/awg0-client-phone.conf']
        cases = {
            'hook': (base.replace(b'[Interface]\n', b'[Interface]\nPreUp = touch /bad\n'),
                     b'client/peer hooks unsupported'),
            'listen-addr': (base.replace(b'Address = 10.66.66.2/32\n',
                                         b'Address = 10.66.66.2/32\nListenAddr = 127.0.0.1\n'),
                            b'ListenAddr is not accepted by amneziawg-tools'),
        }
        for kind, (payload, needle) in cases.items():
            with self.subTest(kind=kind):
                client.write_bytes(payload)
                (self.root / 'work' / kind).mkdir()
                result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root), kind],
                                        capture_output=True)
                combined = result.stdout + result.stderr
                self.assertEqual(result.returncode, 0, combined.decode())
                self.assertIn(needle, combined)
                self.assertNotIn(b'touch /bad', combined)
                self.assertNotIn(b'invalid or unsupported', combined)
                self.assertNotIn(KEY.encode(), combined)

    def test_staged_symlink_and_bad_client_name_refuse_before_passphrase(self):
        # export-check runs before age. A symlink, and any clients entry pack
        # would reject, must fail there rather than after the passphrase.
        good = self.files['clients/awg0-client-phone.conf']
        stage = self.root / 'check-stage'
        (stage / 'vpn').mkdir(parents=True)
        (stage / 'clients').mkdir()
        (stage / 'vpn/params').write_bytes(self.files['vpn/params'])
        (stage / 'vpn/server.conf').write_bytes(self.files['vpn/server.conf'])
        (stage / 'clients/awg0-client-phone.conf').write_bytes(good)
        link = stage / 'clients/awg0-client-x.conf'
        link.symlink_to(stage / 'clients/awg0-client-phone.conf')
        refused = self.run_helper('export-check', stage, ok=False)
        self.assertIn(b'symlink in staging tree', refused.stderr)
        self.assertNotIn(b'invalid or unsupported', refused.stderr)
        link.unlink()
        (stage / 'clients/bad name.conf').write_bytes(good)
        refused = self.run_helper('export-check', stage, ok=False)
        self.assertIn(b'unknown staging file', refused.stderr)
        (stage / 'clients/bad name.conf').unlink()
        (stage / 'clients/notes.txt').write_bytes(b'not a profile\n')
        refused = self.run_helper('export-check', stage, ok=False)
        self.assertIn(b'unknown staging file', refused.stderr)
        (stage / 'clients/notes.txt').unlink()
        self.run_helper('export-check', stage)

        source = self.root / 'source'
        (source / 'clients').mkdir(parents=True)
        (source / 'params').write_bytes(self.files['vpn/params'])
        (source / 'awg0.conf').write_bytes(self.files['vpn/server.conf'])
        (source / 'clients/awg0-client-phone.conf').write_bytes(good)
        (source / 'clients/bad name.conf').write_bytes(good)
        (source / 'clients/notes.txt').write_bytes(b'not a profile\n')
        shell = r'''
set -uo pipefail
source "$1"
ROOT="$2"
KIND="$3"
AMNEZIAWG_DIR="$ROOT/source"
AWG_STATE_PROXY_CONFIG="$ROOT/not-installed-proxy"
acquireClientLifecycleLock() { return 0; }
releaseClientLifecycleLock() { :; }
awgStateTrustedPath() { return 0; }
awg() { printf 'fixture-tools\n'; }
age() { touch "$ROOT/age-ran"; cat >"$3"; }
rm -f "$ROOT/age-ran"
case "$KIND" in
  symlink)
    isWebPanelInstalled() { return 0; }
    collectAwgClientConfigCandidates() { local -n OUTPUT="$1"; OUTPUT=("$ROOT/source/clients/awg0-client-phone.conf"); }
    awgStateSnapshotPanel() {
      ln -s "$ROOT/source/clients/awg0-client-phone.conf" "$1/clients/awg0-client-x.conf"
    }
    ;;
  bad-name)
    isWebPanelInstalled() { return 1; }
    collectAwgClientConfigCandidates() { local -n OUTPUT="$1"; OUTPUT=("$ROOT/source/clients/bad name.conf"); }
    ;;
  notes)
    isWebPanelInstalled() { return 1; }
    collectAwgClientConfigCandidates() { local -n OUTPUT="$1"; OUTPUT=("$ROOT/source/clients/notes.txt"); }
    ;;
  *) exit 9 ;;
esac
mkdir -p "$ROOT/work/$KIND"
awgStateExport "$ROOT/refused-$KIND" "$ROOT/work/$KIND" >"$ROOT/order-$KIND.log" 2>&1
status=$?
[[ "$status" -ne 0 && ! -e "$ROOT/age-ran" && ! -e "$ROOT/refused-$KIND" ]] || {
  echo "export-did-not-stop-before-age status=$status" >&2
  cat "$ROOT/order-$KIND.log" >&2
  exit 10
}
grep -q 'Enter passphrase' "$ROOT/order-$KIND.log" && exit 11
grep -q 'Encrypted state archive created' "$ROOT/order-$KIND.log" && exit 12
exit 0
'''
        cases = {
            'symlink': b'symlink in staging tree',
            'bad-name': b'unknown staging file',
            'notes': b'unknown staging file',
        }
        for kind, needle in cases.items():
            with self.subTest(kind=kind):
                result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root), kind],
                                        capture_output=True)
                combined = result.stdout + result.stderr + (self.root / ('order-%s.log' % kind)).read_bytes()
                self.assertEqual(result.returncode, 0, combined.decode())
                self.assertIn(needle, combined)
                self.assertNotIn(b'Enter passphrase', combined)
                self.assertNotIn(KEY.encode(), combined)

    def _stream_source(self):
        source = self.root / 'source'
        (source / 'clients').mkdir(parents=True, exist_ok=True)
        (source / 'params').write_bytes(self.files['vpn/params'])
        (source / 'awg0.conf').write_bytes(self.files['vpn/server.conf'])
        (source / 'clients/awg0-client-phone.conf').write_bytes(self.files['clients/awg0-client-phone.conf'])
        (self.root / 'work').mkdir(exist_ok=True)
        shell = r'''
set -uo pipefail
source "$1"
ROOT="$2"
AMNEZIAWG_DIR="$ROOT/source"
AWG_STATE_PROXY_CONFIG="$ROOT/not-installed-proxy"
acquireClientLifecycleLock() { CLIENT_LIFECYCLE_LOCK_FD=held; }
releaseClientLifecycleLock() { CLIENT_LIFECYCLE_LOCK_FD=""; printf released >"$ROOT/lock-released"; }
awgStateTrustedPath() { return 0; }
isWebPanelInstalled() { return 1; }
collectAwgClientConfigCandidates() { local -n OUTPUT="$1"; OUTPUT=("$ROOT/source/clients/awg0-client-phone.conf"); }
awg() { printf 'fixture-tools\n'; }
exec {pfd}<&0
awgStateExportStream "$ROOT/work" "$pfd" >"$ROOT/out.awgx"
exit $?
'''
        return shell

    def test_dependency_install_output_stays_off_stdout(self):
        # Streaming export publishes ciphertext on stdout. apt must not prefix it.
        shell = r'''
set -uo pipefail
source "$1"
ROOT="$2"
command() {
    if [[ "$1" == -v && "${2:-}" == age ]]; then
        return 1
    fi
    builtin command "$@"
}
apt-get() {
    printf 'APT-STDOUT-NOISE\n'
    printf 'APT-STDERR\n' >&2
    return 0
}
enable_apt_ipv4() { :; }
disable_apt_ipv4() { :; }
awgStateDependencies 1 >"$ROOT/dep.out" 2>"$ROOT/dep.err"
status=$?
[[ "$status" -eq 0 ]] || exit 10
[[ ! -s "$ROOT/dep.out" ]] || exit 11
grep -q APT-STDERR "$ROOT/dep.err" || exit 12
grep -q APT-STDOUT-NOISE "$ROOT/dep.err" || exit 13
'''
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)],
                                capture_output=True)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        self.assertFalse((self.root / 'dep.out').stat().st_size)
        self.assertNotIn(b'APT-STDOUT-NOISE', (self.root / 'dep.out').read_bytes())

    def _run_stream(self, secret, path_prefix=None, delay=0):
        env = os.environ.copy()
        if path_prefix:
            env['PATH'] = path_prefix + os.pathsep + env.get('PATH', '')
        # The secret is written to the pipe only. It is not part of argv or env.
        command = ['bash', '-c', self._stream_source(), 'test', str(SCRIPT), str(self.root)]
        if not delay:
            return subprocess.run(command, input=secret, capture_output=True, env=env)
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=env)
        time.sleep(delay)
        stdout, stderr = process.communicate(secret)
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)

    def test_stream_export_refuses_bad_passphrases_before_age(self):
        bindir = self.root / 'bin'
        bindir.mkdir()
        age = bindir / 'age'
        age.write_text('#!/bin/sh\ntouch %s\nexit 0\n' % (self.root / 'age-ran').as_posix())
        age.chmod(0o755)
        cases = {
            'empty': b'',
            'short': b'too-short',
            'newline': b'abcdefghijklmnop\nmore',
            'cr': b'abcdefghijklmnop\rmore',
            'nul': b'abcdefghijklmnop\x00more',
            'tab': b'0123456789abcdef\t',
            'ctrl-u': b'0123456789abcdef\x15',
            'ctrl-w': b'0123456789abcdef\x17',
            'ctrl-h': b'0123456789abcdef\x08',
            'del': b'0123456789abcdef\x7f',
            'ctrl-c': b'0123456789abcdef\x03',
            'ctrl-d': b'0123456789abcdef\x04',
            'ctrl-v': b'0123456789abcdef\x16',
        }
        self.assertLess(len(cases['short']), 16)
        for name, secret in cases.items():
            with self.subTest(name=name):
                marker = self.root / 'age-ran'
                if marker.exists():
                    marker.unlink()
                result = self._run_stream(secret, str(bindir))
                self.assertNotEqual(result.returncode, 0, result.stderr.decode())
                self.assertFalse(marker.exists())
                self.assertEqual((self.root / 'out.awgx').stat().st_size, 0)
                if secret:
                    self.assertNotIn(secret, result.stdout + result.stderr)
                self.assertNotIn(b'age-encryption.org', result.stdout)

    def _age_decrypt(self, archive, plain, secret):
        pid, fd = pty.fork()
        if pid == 0:
            try:
                settings = termios.tcgetattr(0)
                settings[3] &= ~termios.ECHO
                termios.tcsetattr(0, termios.TCSANOW, settings)
            except termios.error:
                os._exit(1)
            os.execvp('age', ['age', '--decrypt', '--output', str(plain), str(archive)])
        deadline = time.monotonic() + 30
        sent = False
        pending = b''
        transcript = b''
        try:
            while time.monotonic() < deadline:
                try:
                    ready, _, _ = select.select([fd], [], [], 0.2)
                except OSError:
                    ready = []
                if ready:
                    try:
                        data = os.read(fd, 4096)
                    except OSError as exc:
                        if exc.errno != errno.EIO:
                            raise
                        data = b''
                    if data:
                        transcript += data
                        pending = (pending + data)[-200:]
                        if (not sent) and b'passphrase' in pending.lower():
                            os.write(fd, secret + b'\n')
                            sent = True
                try:
                    ended, status = os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    break
                if ended:
                    self.assertEqual(os.waitstatus_to_exitcode(status), 0,
                                     transcript.decode(errors='replace'))
                    break
            else:
                os.kill(pid, 9)
                os.waitpid(pid, 0)
                self.fail('age decrypt timed out: ' + transcript.decode(errors='replace'))
        finally:
            os.close(fd)
        self.assertTrue(sent, transcript.decode(errors='replace'))

    @unittest.skipUnless(shutil.which('age'), 'age not installed')
    def test_sixteen_character_printable_passphrase_round_trips(self):
        secret = b'0123456789abcdef'
        self.assertEqual(len(secret), 16)
        result = self._run_stream(secret)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        archive = self.root / 'out.awgx'
        self.assertTrue(archive.read_bytes().startswith(b'age-encryption.org/v1\n'))
        self.assertNotIn(secret, result.stdout + result.stderr + archive.read_bytes())
        plain = self.root / 'plain-16.tar.gz'
        self._age_decrypt(archive, plain, secret)
        self.run_helper('verify', plain)

    def test_stream_export_sigterm_kills_age_and_pack(self):
        secret = b'0123456789abcdef-term'
        bindir = self.root / 'bin'
        bindir.mkdir()
        age = bindir / 'age'
        age.write_text(r'''#!/usr/bin/env python3
import os, time
root = __ROOT__

def read_line(fd):
    buf = b""
    while b"\n" not in buf:
        chunk = os.read(fd, 256)
        if not chunk:
            os._exit(3)
        buf += chunk
    return buf

tty = os.open("/dev/tty", os.O_RDWR)
os.write(tty, b"Enter passphrase (leave empty to autogenerate a secure one): ")
read_line(tty)
os.write(tty, b"\r\n\x1b[F\x1b[KConfirm passphrase: ")
read_line(tty)
os.write(tty, b"\r\n\x1b[F\x1b[K")
with open(root + "/age.pid", "w") as handle:
    handle.write(str(os.getpid()))
with open(root + "/driver.pid", "w") as handle:
    handle.write(str(os.getppid()))
time.sleep(60)
'''.replace('__ROOT__', repr(str(self.root))))
        age.chmod(0o755)
        env = os.environ.copy()
        env['PATH'] = str(bindir) + os.pathsep + env.get('PATH', '')
        process = subprocess.Popen(
            ['bash', '-c', self._stream_source(), 'test', str(SCRIPT), str(self.root)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        age_pid = None
        age_alive = True
        pack_alive = True
        stdout = b''
        stderr = b''
        try:
            process.stdin.write(secret)
            process.stdin.flush()
            process.stdin.close()
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and not (self.root / 'driver.pid').exists():
                if process.poll() is not None:
                    err = process.stderr.read().decode(errors='replace')
                    self.fail('export exited before age was ready: ' + err)
                time.sleep(0.05)
            self.assertTrue((self.root / 'driver.pid').exists(), 'driver pid was not recorded')
            driver = int((self.root / 'driver.pid').read_text())
            age_pid = int((self.root / 'age.pid').read_text())
            os.kill(driver, signal.SIGTERM)
            # stdin is already closed. communicate() would flush it again.
            process.wait(timeout=10)
            stdout = process.stdout.read() if process.stdout is not None else b''
            stderr = process.stderr.read() if process.stderr is not None else b''
            age_alive = self._pid_alive(age_pid)
            pack_alive = self._proc_cmdline_contains(b'awg-state-pack')
        finally:
            if process.poll() is None:
                process.kill()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            if age_pid is not None and self._pid_alive(age_pid):
                try:
                    os.kill(age_pid, signal.SIGKILL)
                except OSError:
                    pass
            self._kill_cmdline(b'awg-state-pack')
            for pipe in (process.stdout, process.stderr, process.stdin):
                if pipe is not None and not pipe.closed:
                    pipe.close()
        self.assertNotEqual(process.returncode, 0)
        self.assertFalse(age_alive)
        self.assertFalse(pack_alive)
        self.assertEqual((self.root / 'out.awgx').stat().st_size, 0)
        self.assertNotIn(secret, stdout + stderr)

    def _pid_alive(self, pid):
        if pid is None:
            return False
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        # A zombie still accepts kill 0. /proc/<pid>/stat state Z is not alive
        # for this test: the driver must have reaped age.
        try:
            stat = Path('/proc/%s/stat' % pid).read_text()
        except OSError:
            return False
        state = stat.rsplit(')', 1)[-1].split()
        return bool(state) and state[0] != 'Z'

    def _proc_cmdline_contains(self, needle):
        return any(needle in cmd for _pid, cmd in self._proc_cmds())

    def _kill_cmdline(self, needle):
        for pid, cmd in self._proc_cmds():
            if needle in cmd:
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass

    def _proc_cmds(self):
        found = []
        proc = Path('/proc')
        for entry in proc.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                found.append((int(entry.name), (entry / 'cmdline').read_bytes()))
            except (OSError, ValueError):
                continue
        return found

    def test_dispatcher_stream_stdout_is_only_the_ciphertext(self):
        if shutil.which('age') is None:
            self.skipTest('age not installed')
        secret = b'0123456789abcdef'
        text = SCRIPT.read_text()
        start = text.index('\t\t--export-state|--inspect-state|--import-state|--activate-state)')
        block = text[start:text.index('\t\t--reset-state-journal)')]
        shell = r'''
set -uo pipefail
source "$1"
ROOT="$2"
AMNEZIAWG_DIR="$ROOT/source"
AWG_STATE_PROXY_CONFIG="$ROOT/not-installed-proxy"
isRoot() { return 0; }
checkOS() { OS=debian; }
acquireClientLifecycleLock() { CLIENT_LIFECYCLE_LOCK_FD=held; }
releaseClientLifecycleLock() { CLIENT_LIFECYCLE_LOCK_FD=""; }
awgStateTrustedPath() { return 0; }
isWebPanelInstalled() { return 1; }
collectAwgClientConfigCandidates() { local -n OUTPUT="$1"; OUTPUT=("$ROOT/source/clients/awg0-client-phone.conf"); }
awg() { printf 'fixture-tools\n'; }
enable_apt_ipv4() { :; }
disable_apt_ipv4() { :; }
command() {
    if [[ "$1" == -v && "${2:-}" == age ]]; then
        return 1
    fi
    builtin command "$@"
}
apt-get() {
    printf 'APT-STDOUT-NOISE\n'
    printf 'APT-STDERR\n' >&2
    if [[ "$1" == install ]]; then
        unset -f command
    fi
    return 0
}
mkdir -p "$ROOT/source/clients"
# The case arm below is the real dispatcher, not a reimplementation.
set -- --export-state - --passphrase-fd 0
case "$1" in
''' + block + r'''
esac
'''
        source = self.root / 'source'
        (source / 'clients').mkdir(parents=True)
        (source / 'params').write_bytes(self.files['vpn/params'])
        (source / 'awg0.conf').write_bytes(self.files['vpn/server.conf'])
        (source / 'clients/awg0-client-phone.conf').write_bytes(
            self.files['clients/awg0-client-phone.conf'])
        result = subprocess.run(
            ['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)],
            input=secret, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        self.assertTrue(result.stdout.startswith(b'age-encryption.org/v1\n'), result.stdout[:80])
        self.assertNotIn(b'APT-STDOUT-NOISE', result.stdout)
        self.assertNotIn(b'APT-STDERR', result.stdout)
        self.assertIn(b'APT-STDOUT-NOISE', result.stderr)
        self.assertIn(b'APT-STDERR', result.stderr)
        self.assertNotIn(secret, result.stdout + result.stderr)
        archive = self.root / 'dispatcher.awgx'
        archive.write_bytes(result.stdout)
        plain = self.root / 'dispatcher-plain.tar.gz'
        self._age_decrypt(archive, plain, secret)
        self.run_helper('verify', plain)

    def test_stream_export_answers_tty_prompts_and_hides_the_passphrase(self):
        secret = b'stream-export-secret-value'
        bindir = self.root / 'bin'
        bindir.mkdir()
        age = bindir / 'age'
        # Token replacement, not %-formatting: the script itself contains %.
        # root is baked in because the driver gives age a clean environment.
        age.write_text(r'''#!/usr/bin/env python3
import os, stat
root = __ROOT__

def read_line(fd):
    buf = b""
    while b"\n" not in buf:
        chunk = os.read(fd, 256)
        if not chunk:
            os._exit(3)
        buf += chunk
    return buf

tty = os.open("/dev/tty", os.O_RDWR)
for fd in (0, 1):
    if stat.S_ISCHR(os.fstat(fd).st_mode):
        os._exit(2)
if not os.path.exists(root + "/lock-released"):
    os._exit(5)
os.write(tty, b"Enter passphrase (leave empty to autogenerate a secure one): ")
first = read_line(tty)
os.write(tty, b"\r\n\x1b[F\x1b[KConfirm passphrase: ")
second = read_line(tty)
os.write(tty, b"\r\n\x1b[F\x1b[K")
if first != second or not first.endswith(b"\n"):
    os._exit(4)
while True:
    chunk = os.read(0, 65536)
    if not chunk:
        break
blobs = []
for pid in os.listdir("/proc"):
    if not pid.isdigit():
        continue
    for leaf in ("cmdline", "environ"):
        try:
            with open("/proc/%s/%s" % (pid, leaf), "rb") as handle:
                blobs.append(handle.read().replace(b"\x00", b"\n"))
        except OSError:
            pass
with open(root + "/proc-dump", "wb") as handle:
    handle.write(b"\n".join(blobs))
with open(root + "/tty-ok", "w") as handle:
    handle.write("ok\n")
os.write(1, b"age-encryption.org/v1\nFAKE-CIPHERTEXT-PADDING\n")
os.close(tty)
os._exit(0)
'''.replace('__ROOT__', repr(str(self.root))))
        age.chmod(0o755)
        result = self._run_stream(secret, str(bindir))
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        archive = (self.root / 'out.awgx').read_bytes()
        self.assertTrue(archive.startswith(b'age-encryption.org/v1\n'))
        self.assertGreaterEqual(len(archive), 32)
        self.assertNotIn(secret, archive)
        self.assertNotIn(secret, result.stdout)
        self.assertNotIn(secret, result.stderr)
        self.assertNotIn(b'Encrypted state archive created', archive)
        self.assertIn(b'Client endpoints in this archive:', result.stderr)
        self.assertTrue((self.root / 'tty-ok').is_file())
        self.assertTrue((self.root / 'lock-released').is_file())
        dump = (self.root / 'proc-dump').read_bytes()
        self.assertNotIn(secret, dump)
        staged = b''.join(path.read_bytes() for path in (self.root / 'work').rglob('*') if path.is_file())
        self.assertNotIn(secret, staged)

    def test_stream_export_waits_for_a_late_passphrase(self):
        secret = b'stream-export-secret-value'
        bindir = self.root / 'bin'
        bindir.mkdir()
        age = bindir / 'age'
        age.write_text('''#!/usr/bin/env python3
import os
tty = os.open("/dev/tty", os.O_RDWR)
os.write(tty, b"Enter passphrase (leave empty to autogenerate a secure one): ")
buf = b""
while b"\\n" not in buf:
    buf += os.read(tty, 256)
os.write(tty, b"\\r\\n\\x1b[F\\x1b[KConfirm passphrase: ")
buf = b""
while b"\\n" not in buf:
    buf += os.read(tty, 256)
os.write(tty, b"\\r\\n\\x1b[F\\x1b[K")
while True:
    chunk = os.read(0, 65536)
    if not chunk:
        break
os.write(1, b"age-encryption.org/v1\\nFAKE-CIPHERTEXT-PADDING\\n")
os._exit(0)
''')
        age.chmod(0o755)
        result = self._run_stream(secret, str(bindir), delay=0.4)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertTrue((self.root / 'out.awgx').read_bytes().startswith(b'age-encryption.org/v1\n'))
        self.assertNotIn(secret, result.stdout + result.stderr)

    def test_stream_export_discards_output_when_pack_or_age_fails(self):
        secret = b'stream-export-secret-value'
        bindir = self.root / 'bin'
        bindir.mkdir()
        age = bindir / 'age'
        age.write_text('''#!/usr/bin/env python3
import os
tty = os.open("/dev/tty", os.O_RDWR)
os.write(tty, b"Enter passphrase (leave empty to autogenerate a secure one): ")
buf = b""
while b"\\n" not in buf:
    buf += os.read(tty, 256)
os.write(tty, b"\\r\\n\\x1b[F\\x1b[KConfirm passphrase: ")
buf = b""
while b"\\n" not in buf:
    buf += os.read(tty, 256)
os.write(tty, b"\\r\\n\\x1b[F\\x1b[K")
os.write(1, b"age-encryption.org/v1\\nPARTIAL")
os._exit(1)
''')
        age.chmod(0o755)
        result = self._run_stream(secret, str(bindir))
        self.assertNotEqual(result.returncode, 0, result.stderr.decode())
        # Age must have been prompted and then failed. A SIGHUP before the
        # prompts is a different bug and must not satisfy this test.
        self.assertIn(b'state encryption failed', result.stderr)
        self.assertNotIn(b'exited before the passphrase prompts', result.stderr)
        self.assertEqual((self.root / 'out.awgx').stat().st_size, 0)
        self.assertFalse((self.root / 'work' / 'encrypted').exists())
        self.assertNotIn(secret, result.stdout + result.stderr)
        # A stage pack cannot succeed when the staged tree is not a directory.
        shell = r'''
set -uo pipefail
source "$1"
ROOT="$2"
exec {pfd}<&0
if awgStatePassphraseAge "$pfd" "$ROOT/direct.awgx" "$ROOT/missing-stage" fixture deadbeef; then
    exit 10
fi
[[ ! -e "$ROOT/direct.awgx" ]] || exit 11
exit 0
'''
        direct = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)],
                                input=secret, capture_output=True)
        self.assertEqual(direct.returncode, 0, (direct.stdout + direct.stderr).decode())
        self.assertFalse((self.root / 'direct.awgx').exists())
        self.assertNotIn(secret, direct.stdout + direct.stderr)

    @unittest.skipUnless(shutil.which('age'), 'age not installed')
    def test_stream_export_decrypts_with_age_and_imports(self):
        secret = b'a-test-only-long-passphrase'
        result = self._run_stream(secret)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        archive = self.root / 'out.awgx'
        self.assertTrue(archive.read_bytes().startswith(b'age-encryption.org/v1\n'))
        self.assertNotIn(secret, result.stderr)
        plain = self.root / 'plain.tar.gz'
        pid, fd = pty.fork()
        if pid == 0:
            try:
                settings = termios.tcgetattr(0)
                settings[3] &= ~termios.ECHO
                termios.tcsetattr(0, termios.TCSANOW, settings)
            except termios.error:
                os._exit(1)
            os.execvp('age', ['age', '--decrypt', '--output', str(plain), str(archive)])
        deadline = time.monotonic() + 30
        sent = False
        pending = b''
        transcript = b''
        while time.monotonic() < deadline:
            try:
                ready, _, _ = select.select([fd], [], [], 0.2)
            except OSError:
                ready = []
            if ready:
                try:
                    data = os.read(fd, 4096)
                except OSError as exc:
                    # Linux reports a slave hangup as EIO. That is the child
                    # exiting, or a race before the slave is open, not a
                    # failed read of a prompt that was actually written.
                    if exc.errno != errno.EIO:
                        raise
                    data = b''
                if data:
                    transcript += data
                    pending = (pending + data)[-200:]
                    if (not sent) and b'passphrase' in pending.lower():
                        os.write(fd, secret + b'\n')
                        sent = True
            try:
                ended, status = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                break
            if ended:
                self.assertEqual(os.waitstatus_to_exitcode(status), 0,
                                 transcript.decode(errors='replace'))
                break
        else:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
            self.fail('age decrypt timed out: ' + transcript.decode(errors='replace'))
        os.close(fd)
        self.assertTrue(sent, transcript.decode(errors='replace'))
        try:
            ended, status = os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        else:
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        self.run_helper('verify', plain)
        unpacked = self.root / 'unpacked'
        self.run_helper('unpack', plain, unpacked)
        self.assertEqual((unpacked / 'clients/awg0-client-phone.conf').read_bytes(),
                         self.files['clients/awg0-client-phone.conf'])

    def test_direct_export_without_proxy_is_schema_1(self):
        result = self.export_source(51820, proxy=False)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        with tarfile.open(self.root / 'export.tar.gz') as archive:
            meta = json.load(archive.extractfile('manifest.json'))
        self.assertEqual(meta['schema_version'], 1)
        self.assertFalse(any(name.startswith('proxy/') for name in meta['files']))

    def test_import_preflight_checks_proxy_backend_port(self):
        result = subprocess.run(['bash', '-c', r"""
source "$1"; ROOT="$2"
AMNEZIAWG_DIR="$ROOT/none"; SERVER_AWG_NIC=awg0; SERVER_PORT=51820; AWG_STATE_AWG_PORT=51821
awgStateTrustedPath() { return 0; }
systemctl() { return 1; }
ip() { [[ "$*" != *awg0* ]]; }
ss() { [[ "$*" == *':51821'* ]] && echo busy; return 0; }
awgStateImportPreflight eth0 "$ROOT"; echo "rc=$?"
""", 'test', str(SCRIPT), str(self.root)], capture_output=True)
        self.assertIn(b'rc=1', result.stdout, result.stderr)
        self.assertIn(b'UDP port 51821 (AWG behind amneziawg-proxy) is already in use', result.stderr)

    def test_target_path_policy(self):
        # m1: archive-controlled install paths.
        code = CODE.split('\ntry:\n    main()', 1)[0]
        (self.root / 'real').mkdir()
        (self.root / 'link').symlink_to(self.root / 'real')
        result = subprocess.run(['python3', '-c', code + r"""
def outcome(path, default, kind, approved=''):
    try:
        target_dir_ok(path, default, kind, [approved] if approved else [])
        return 'ok'
    except StatePolicyError as error:
        return str(error)
import json
print(json.dumps([outcome(*case) for case in json.loads(sys.argv[2])]))
""", KEYS, json.dumps([
            ['/var/lib/amneziawg-web', '/var/lib/amneziawg-web', 'data', False],
            ['/var/lib/awg-test-new-%d' % os.getpid(), '/var/lib/amneziawg-web', 'data', False],
            ['/etc', '/var/lib/amneziawg-web', 'data', False],
            ['/var/lib', '/var/lib/amneziawg-web', 'data', False],
            ['/usr/bin', '/var/lib/amneziawg-web', 'data', False],
            ['/root/x', '/var/lib/amneziawg-web', 'data', False],
            ['/var/lib/dpkg', '/var/lib/amneziawg-web', 'data', False],
            ['/var/lib/../etc', '/var/lib/amneziawg-web', 'data', False],
            ['/tmp/x', '/var/lib/amneziawg-web', 'data', False],
            ['/etc', '/etc/amneziawg-proxy', 'config', False],
            ['/etc/awg-test-new-%d' % os.getpid(), '/etc/amneziawg-proxy', 'config', False],
            ['/usr/bin', '/usr/local/bin', 'install', False],
            ['/usr/local/bin', '/usr/local/bin', 'install', False],
            ['/opt/awg-test-new-%d/bin' % os.getpid(), '/usr/local/bin', 'install', False],
            [str(self.root / 'link/x'), str(self.root / 'link/x'), 'data', False],
            ['/var/lib/dpkg', '/var/lib/amneziawg-web', 'data', '/var/lib/dpkg'],
            ['/var/lib/dpkg', '/var/lib/amneziawg-web', 'data', '/var/lib/amneziawg-web'],
        ])], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        got = json.loads(result.stdout)
        ok = [o == 'ok' for o in got]
        self.assertEqual(ok, [True, True, False, False, False, False, False, False, False, False, True, False, True, True, False, True, False], got)
        self.assertIn('already exists', got[6])
        self.assertIn('already exists', got[16])
        self.assertIn('unsafe', got[7])
        self.assertIn('symlink', got[14])

    def test_custom_existing_proxy_paths_refused_at_restore(self):
        root = self.root / 'proxy-paths'
        root.mkdir()
        self.proxy_stage(root, meta=dict(config_path='/etc/proxy.toml', data_dir='/var/lib', install_dir='/usr/bin'))
        (root / 'defaults.sh').unlink()
        result = self.run_proxy(root, r"""
if awgStateRestoreProxy "$ROOT/stage" "$ROOT/journal" "$ROOT/work"; then exit 10; fi
[[ ! -e "$ROOT/installer.runs" ]] || exit 11
""")
        out = (result.stdout + result.stderr).decode()
        self.assertEqual(result.returncode, 0, out)
        self.assertIn('config path /etc is not the default', out)

    def test_existing_proxy_data_dir_stays_refused_when_installing_marker_is_left(self):
        # A leftover proxy-installing marker must not approve an existing directory.
        if not os.path.isdir('/var/lib/dpkg'):
            self.skipTest('needs the existing directory /var/lib/dpkg')
        root = self.root / 'proxy-dpkg-retry'
        root.mkdir()
        pid = os.getpid()
        self.proxy_stage(root, meta=dict(config_path='/etc/awg-state-newproxy-%d/proxy.toml' % pid,
                                          data_dir='/var/lib/dpkg',
                                          install_dir='/opt/awg-state-newproxy-%d' % pid))
        (root / 'defaults.sh').unlink()
        result = self.run_proxy(root, r"""
if awgStateRestoreProxy "$ROOT/stage" "$ROOT/journal" "$ROOT/work"; then exit 10; fi
[[ ! -e "$ROOT/journal/proxy-installing" && ! -e "$ROOT/journal/proxy-approved-dirs" ]] || exit 11
[[ ! -e "$ROOT/installer.runs" ]] || exit 12
: >"$ROOT/journal/proxy-installing"
if awgStateRestoreProxy "$ROOT/stage" "$ROOT/journal" "$ROOT/work"; then exit 13; fi
[[ ! -e "$ROOT/installer.runs" && ! -e "$ROOT/journal/proxy-approved-dirs" ]] || exit 14
""")
        out = (result.stdout + result.stderr).decode()
        self.assertEqual(result.returncode, 0, out)
        self.assertEqual(out.count('already exists'), 2, out)

    def test_custom_existing_panel_db_dir_refused(self):
        root = self.root / 'panel-etc'
        root.mkdir()
        self.panel_stage(root, env='AUTH_PASSWORD_HASH=$argon2id$v=19$x\nAWG_WEB_DB=/etc/awg-web.db\n')
        result = self.run_panel(root, r"""
if awgStateRestorePanel "$ROOT/stage" "$ROOT/journal" "$ROOT/work"; then exit 10; fi
[[ ! -e "$ROOT/installer.runs" ]] || exit 11
""")
        out = (result.stdout + result.stderr).decode()
        self.assertEqual(result.returncode, 0, out)
        self.assertIn('data path /etc is not the default', out)

    def test_dry_run_warnings_for_refused_proxy_and_bound_listen(self):
        root = self.root / 'warn'
        root.mkdir()
        self.proxy_stage(root, listen_port=51820, meta=dict(config_path=str(root / 'p/proxy.toml'), data_dir=str(root / 'd'),
                                                            install_dir=str(root / 'b')))
        result = self.run_proxy(root, 'awgStateProxyPlan "$ROOT/stage"')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b'WARNING: amneziawg-proxy: archived server ListenPort is not the proxy backend port', result.stderr)
        panel = self.root / 'warn-panel'
        panel.mkdir()
        self.panel_stage(panel, env='AUTH_PASSWORD_HASH=$argon2id$v=19$x\nAWG_WEB_LISTEN=203.0.113.7:8080\n')
        result = self.run_panel(panel, 'awgStatePanelPlan "$ROOT/stage"')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b'WARNING: AWG_WEB_LISTEN binds the old host address 203.0.113.7', result.stderr)
        for listen in ('127.0.0.1:8080', '0.0.0.0:8080', '[::]:8080', '[::1]:8080'):
            (panel / 'stage/web/env.conf').write_text('AUTH_PASSWORD_HASH=$argon2id$v=19$x\nAWG_WEB_LISTEN=%s\n' % listen)
            result = self.run_panel(panel, 'awgStatePanelPlan "$ROOT/stage"')
            self.assertNotIn(b'AWG_WEB_LISTEN binds', result.stderr, listen)
        # The VPN's own Interface addresses exist once the VPN (restored first) is up.
        (panel / 'stage/vpn').mkdir()
        (panel / 'stage/vpn/server.conf').write_bytes(self.files['vpn/server.conf'].replace(
            b'Address = 10.66.66.1/24', b'Address = 10.66.66.1/24, fd42:42:42::1/64'))
        for listen in ('10.66.66.1:8080', '[fd42:42:42::1]:8080'):
            (panel / 'stage/web/env.conf').write_text('AUTH_PASSWORD_HASH=$argon2id$v=19$x\nAWG_WEB_LISTEN=%s\n' % listen)
            result = self.run_panel(panel, 'awgStatePanelPlan "$ROOT/stage"')
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertNotIn(b'AWG_WEB_LISTEN binds', result.stderr, listen)
        (panel / 'stage/web/env.conf').write_text('AUTH_PASSWORD_HASH=$argon2id$v=19$x\nAWG_WEB_LISTEN=203.0.113.8:8080\n')
        result = self.run_panel(panel, 'awgStatePanelPlan "$ROOT/stage"')
        self.assertIn(b'AWG_WEB_LISTEN binds the old host address 203.0.113.8', result.stderr)

    def test_panel_health_ignores_http_proxy_env(self):
        # m3: an http_proxy pointing at a dead port must not break the local check.
        import http.server, threading
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200 if self.path == '/api/health' else 404)
                self.end_headers()
            def log_message(self, *a):
                pass
        server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        env_file = self.root / 'health.env'
        env_file.write_text('AWG_WEB_LISTEN=127.0.0.1:%d\n' % server.server_address[1])
        result = subprocess.run(['bash', '-c', 'source "$1"; awgStatePanelHealthy "$2"', 'test', str(SCRIPT), str(env_file)],
                                capture_output=True, timeout=60,
                                env=dict(os.environ, http_proxy='http://127.0.0.1:9', HTTP_PROXY='http://127.0.0.1:9', no_proxy='', NO_PROXY=''))
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_companion_lock_refuses_concurrent_runs_and_purge(self):
        # m4: second companion run and purge refuse while one holds the lock.
        journal = self.root / 'journal'
        journal.mkdir()
        result = subprocess.run(['bash', '-c', r"""
source "$1"; J="$2"
exec 9<"$J"; flock -x 9
awgStateRestorePanel() { echo panel-ran; }
awgStateRestoreProxy() { echo proxy-ran; }
( awgStateRestoreCompanions s "$J" w; echo "companions rc=$?" )
AWG_STATE_JOURNAL_DIR="${J%/*}"
isRoot() { return 0; }
acquireClientLifecycleLock() { :; }; releaseClientLifecycleLock() { :; }
awgStateTrustedPath() { return 0; }
D=$(printf '%064d' 0); mkdir -p "$AWG_STATE_JOURNAL_DIR/$D"; exec 8<"$AWG_STATE_JOURNAL_DIR/$D"; flock -x 8
( awgStatePurgeJournal "$D" --force ); echo "purge rc=$?"
[[ -d "$AWG_STATE_JOURNAL_DIR/$D" ]] && echo kept
exec 9>&- 8>&-
( awgStateRestoreCompanions s "$J" w; echo "companions rc=$?" )
( awgStatePurgeJournal "$D" --force >/dev/null ); echo "purge rc=$?"
[[ ! -e "$AWG_STATE_JOURNAL_DIR/$D" ]] && echo purged
""", 'test', str(SCRIPT), str(journal)], capture_output=True, text=True)
        self.assertEqual(result.stdout, 'companions rc=1\npurge rc=1\nkept\npanel-ran\nproxy-ran\ncompanions rc=0\npurge rc=0\npurged\n',
                         result.stderr)
        self.assertEqual(result.stderr.count('another panel/proxy restore'), 2)

    def test_purge_removes_approved_path_records_and_leftover_lock_file(self):
        journal = self.root / 'purge-approved'
        digest = 'ab' * 32
        jdir = journal / digest
        jdir.mkdir(parents=True)
        (jdir / 'panel-approved-dir').write_text('/var/lib/amneziawg-web\n')
        (jdir / 'proxy-approved-dirs').write_text('/etc/amneziawg-proxy\n/var/lib/amneziawg-proxy\n/usr/local/bin\n')
        (jdir / 'companions.lock').write_text('')
        result = subprocess.run(['bash', '-c', r"""
source "$1"
AWG_STATE_JOURNAL_DIR="$2"
isRoot() { return 0; }
acquireClientLifecycleLock() { :; }; releaseClientLifecycleLock() { :; }
awgStateTrustedPath() { return 0; }
awgStatePurgeJournal "$3" --force
""", 'test', str(SCRIPT), str(journal), digest], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(jdir.exists(), result.stdout)

    def test_finalized_purge_preserves_incomplete_companion_provenance(self):
        journals = self.root / 'journals'
        digest = 'cd' * 32
        jdir = journals / digest
        jdir.mkdir(parents=True)
        for name in ('finalized', 'panel-installing', 'panel-approved-dir',
                     'proxy-installing', 'proxy-approved-dirs', 'receipt'):
            (jdir / name).write_text('sentinel')
        result = subprocess.run(['bash', '-c', r"""
source "$1"
AWG_STATE_JOURNAL_DIR="$2"
isRoot() { return 0; }
acquireClientLifecycleLock() { :; }; releaseClientLifecycleLock() { :; }
awgStateTrustedPath() { return 0; }
awgStatePurgeJournal "$3"
""", 'test', str(SCRIPT), str(journals), digest], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((jdir / 'receipt').exists())
        for name in ('panel-installing', 'panel-approved-dir', 'proxy-installing', 'proxy-approved-dirs'):
            self.assertEqual((jdir / name).read_text(), 'sentinel')

    def test_failed_activation_cleanup_records_incomplete_rollback(self):
        result = subprocess.run(['bash', '-c', r"""
source "$1"
_AWG_STATE_ACTIVATION_UNIT=awg-quick@awg0
_AWG_STATE_ACTIVATION_JOURNAL="$2"
systemctl() {
    case "$1" in
        stop|disable) return 1 ;;
        show) [[ "$2" == --property=ActiveState ]] && printf 'active
' || printf 'enabled
' ;;
    esac
}
if awgStateActivationAbort; then exit 2; fi
test -f "$2/activation-rollback-incomplete"
""", 'test', str(SCRIPT), str(self.root)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('INCOMPLETE', result.stderr)

    def test_proxy_migration_requires_existing_backend_port_without_edit(self):
        installer = ROOT / 'amneziawg-proxy/scripts/amneziawg-proxy-install.sh'
        conf = self.root / 'awg0.conf'
        text = '[Interface]\nListenPort = 51821\n'
        conf.write_text(text)
        result = subprocess.run(['bash', '-c', r"""
source "$1"
AWG_CONF_FILE="$2"
BACKEND_PORT=51821
require_existing_awg_listen_port
""", 'test', str(installer), str(conf)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(conf.read_text(), text)

    def test_activation_takes_companion_lock_before_releasing_lifecycle_lock(self):
        text = SCRIPT.read_text()
        self.assertEqual(text.count('awgStateAcquireCompanionLock "${JOURNAL}" || return 1\n\t\t\treleaseClientLifecycleLock\n'
                                    '\t\t\tawgStateRestoreCompanions'), 2)
        self.assertEqual(text.count('releaseClientLifecycleLock\n\t\t\tawgStateRestoreCompanions'), 2)

    def test_web_installer_password_hash_file(self):
        # m2: --password-hash-file keeps the hash out of argv; --password-hash stays.
        web = ROOT / 'amneziawg-web/scripts/amneziawg-web-install.sh'
        shell = r"""
eval "$(sed -n '/^parse_args() {/,/^}/p;/^load_password_hash_file() {/,/^}/p' "$1")"
die() { echo "DIE $*"; exit 1; }; error() { echo "ERR $*"; }; usage() { :; }
PASSWORD_HASH="" PASSWORD_HASH_FILE="" BINARY_SRC="" SOURCE_DIR=""
shift; parse_args "$@"; printf 'hash=%s\n' "$PASSWORD_HASH"
"""
        good = self.root / 'hash'
        good.write_text('$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA\n')
        (self.root / 'hash-link').symlink_to(good)
        (self.root / 'bad').write_text('plain\n')
        def run(*args):
            return subprocess.run(['bash', '-c', shell, 'x', str(web), *args], capture_output=True, text=True).stdout
        self.assertEqual(run('--password-hash-file', str(good)), 'hash=$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA\n')
        self.assertEqual(run('--password-hash', '$argon2id$x'), 'hash=$argon2id$x\n')
        self.assertIn('mutually exclusive', run('--password-hash', '$argon2id$x', '--password-hash-file', str(good)))
        self.assertIn('regular file', run('--password-hash-file', str(self.root / 'hash-link')))
        self.assertIn('regular file', run('--password-hash-file', str(self.root / 'missing')))
        self.assertIn('Argon2 PHC hash', run('--password-hash-file', str(self.root / 'bad')))
        self.assertIn('--password-hash-file FILE', web.read_text())

    def test_proxy_plan_in_dry_run(self):
        root = self.root / 'proxy-plan'
        root.mkdir()
        self.proxy_stage(root)
        result = self.run_proxy(root, 'awgStateProxyPlan "$ROOT/stage"')
        out = result.stdout.decode()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn('"awg_matches_backend": true', out)
        self.assertIn('"listen": "0.0.0.0:51820"', out)
        self.assertIn('HTTPS/reverse proxy for the panel is operator-managed', out)


    def test_endpoint_plan_rewrites_only_the_host(self):
        secret = b'ENDPOINT-PLAN-SECRET-KEY'
        phone = self.root / 'awg0-client-phone.conf'
        # The old address also appears in a comment. Only the Endpoint host moves.
        phone_old = (
            b'# note 203.0.113.7 stays\n'
            b'[Interface]\nPrivateKey = ' + secret + b'\nAddress = 10.66.66.2/32\nMTU = 1280\n'
            b'Jc = 4\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 16\nS3 = 17\nS4 = 18\n'
            b'H1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n'
            b'[Peer]\nPublicKey = ' + PUB.encode() + b'\nPresharedKey = ' + KEY.encode() + b'\n'
            b'Endpoint = 203.0.113.7:51820\nAllowedIPs = 0.0.0.0/0,::/0\n'
        )
        phone.write_bytes(phone_old)
        v6 = self.root / 'awg0-client-v6.conf'
        v6_old = (
            b'[Interface]\r\nAddress = 10.66.66.4/32\r\nMTU = 1280\r\n'
            b'[Peer]\r\nPresharedKey = ' + secret + b'\r\n'
            b'Endpoint = [2001:db8::5]:51820\r\nAllowedIPs = 0.0.0.0/0\r\n'
        )
        v6.write_bytes(v6_old)
        plain = self.root / 'awg0-client-plain.conf'
        plain_old = b'[Peer]\nEndpoint = vpn.example.test:51820\n'
        plain.write_bytes(plain_old)
        out = self.root / 'out'
        out.mkdir()
        regular = self.root / 'regular'
        regular.write_bytes(b''.join(str(path).encode() + b'\0' for path in (phone, v6, plain)))
        (self.root / 'symlinks').write_bytes(b'')
        result = self.run_helper('endpoint-plan', regular, self.root / 'symlinks', out, 'rewrite',
                                 'vpn.example.test', '203.0.113.9')
        plan = json.loads(result.stdout)
        self.assertIsNone(plan['refused'])
        self.assertEqual(plan['ip_literal'], 2)
        self.assertEqual(plan['hostname'], 1)
        written = {row['path']: row for row in plan['files']}
        self.assertEqual(written[str(phone)]['status'], 'update')
        self.assertEqual(written[str(v6)]['status'], 'update')
        self.assertEqual(written[str(plain)]['status'], 'unchanged')
        phone_new = (out / written[str(phone)]['out']).read_bytes()
        v6_new = (out / written[str(v6)]['out']).read_bytes()
        self.assertEqual(phone_new, phone_old.replace(
            b'Endpoint = 203.0.113.7:51820', b'Endpoint = vpn.example.test:51820', 1))
        self.assertIn(b'203.0.113.7 stays', phone_new)
        self.assertEqual(v6_new, v6_old.replace(
            b'Endpoint = [2001:db8::5]:51820', b'Endpoint = vpn.example.test:51820', 1))
        self.assertNotIn(b'PrivateKey', v6_new)
        self.assertNotIn(secret, result.stdout + result.stderr)
        self.assertNotIn(KEY.encode(), result.stdout)
        # A second plan of the rewritten bytes changes nothing and writes nothing.
        phone.write_bytes(phone_new)
        v6.write_bytes(v6_new)
        again_out = self.root / 'out-again'
        again_out.mkdir()
        again = self.run_helper('endpoint-plan', regular, self.root / 'symlinks', again_out, 'rewrite',
                                'vpn.example.test', 'vpn.example.test')
        again_plan = json.loads(again.stdout)
        self.assertTrue(all(row['status'] == 'unchanged' for row in again_plan['files']))
        self.assertEqual(list(again_out.iterdir()), [])

    def test_endpoint_plan_refuses_symlink_conflict_and_ip_hostname(self):
        secret = b'ENDPOINT-PLAN-UNREAD-SECRET'
        target = self.root / 'target.conf'
        target.write_bytes(b'[Peer]\nPrivateKey = ' + secret + b'\nEndpoint = 203.0.113.7:51820\n')
        link = self.root / 'awg0-client-link.conf'
        link.symlink_to(self.root / 'missing-target.conf')
        regular_file = self.root / 'awg0-client-phone.conf'
        regular_file.write_bytes(b'[Peer]\nPrivateKey = ' + secret + b'\nEndpoint = 203.0.113.7:51820\n')
        out = self.root / 'out'
        out.mkdir()
        regular = self.root / 'regular'
        regular.write_bytes(str(regular_file).encode() + b'\0')
        symlinks = self.root / 'symlinks'
        symlinks.write_bytes(str(link).encode() + b'\0')
        refused = json.loads(self.run_helper(
            'endpoint-plan', regular, symlinks, out, 'rewrite', 'vpn.example.test', '203.0.113.9').stdout)
        self.assertEqual(refused['refused'], 'symlink')
        self.assertEqual(refused['symlinks'], [str(link)])
        self.assertEqual(list(out.iterdir()), [])
        self.assertNotIn(secret, json.dumps(refused).encode())
        # A symlink handed in as a regular path is still not opened.
        (self.root / 'empty-sym').write_bytes(b'')
        followed = self.run_helper('endpoint-plan', symlinks, self.root / 'empty-sym', out, 'rewrite',
                                   'vpn.example.test', '203.0.113.9', ok=False)
        self.assertIn(b'symlink client profile', followed.stderr)
        self.assertNotIn(b'not readable', followed.stderr)
        self.assertNotIn(secret, followed.stdout + followed.stderr)
        left = self.root / 'a' / 'awg0-client-phone.conf'
        right = self.root / 'b' / 'awg0-client-phone.conf'
        left.parent.mkdir()
        right.parent.mkdir()
        left.write_bytes(b'[Peer]\nEndpoint = 203.0.113.7:51820\nAllowedIPs = 0.0.0.0/0\n')
        right.write_bytes(left.read_bytes() + b'MTU = 1420\n')
        both = self.root / 'both'
        both.write_bytes(str(left).encode() + b'\0' + str(right).encode() + b'\0')
        conflict_out = self.root / 'conflict-out'
        conflict_out.mkdir()
        conflict = json.loads(self.run_helper(
            'endpoint-plan', both, self.root / 'empty-sym', conflict_out, 'rewrite',
            'vpn.example.test', '203.0.113.9').stdout)
        self.assertEqual(conflict['refused'], 'conflict')
        self.assertEqual(conflict['conflicts'][0]['files'], sorted([str(left), str(right)]))
        self.assertEqual(list(conflict_out.iterdir()), [])
        self.assertEqual(left.read_bytes(), b'[Peer]\nEndpoint = 203.0.113.7:51820\nAllowedIPs = 0.0.0.0/0\n')
        for bad in ('203.0.113.7', '2001:db8::1', '[2001:db8::1]', 'vpn.example.test:51820'):
            with self.subTest(bad=bad):
                denied = self.run_helper('endpoint-plan', both, self.root / 'empty-sym', conflict_out,
                                         'rewrite', bad, '203.0.113.9', ok=False)
                self.assertIn(b'hostname refused', denied.stderr)
                self.assertNotIn(secret, denied.stdout + denied.stderr)

    def test_endpoint_plan_preserves_malformed_duplicate_conflict_and_io_errors(self):
        left = self.root / 'a' / 'awg0-client-phone.conf'
        right = self.root / 'b' / left.name
        for path in (left, right):
            path.parent.mkdir()
        healthy = b'[Peer]\nEndpoint = 203.0.113.7:51820\n'
        malformed = healthy + b'# \xff\n'
        left.write_bytes(healthy)
        out = self.root / 'out'
        out.mkdir()
        regular = self.root / 'regular'
        regular.write_bytes(b''.join(str(path).encode() + b'\0' for path in (left, right)))
        symlinks = self.root / 'symlinks'
        symlinks.write_bytes(b'')

        def plan(ok=True):
            return self.run_helper('endpoint-plan', regular, symlinks, out, 'rewrite',
                                   'vpn.example.test', '203.0.113.9', ok=ok)

        missing = plan(ok=False)
        self.assertIn(b'client profile is not readable', missing.stderr)
        self.assertEqual(list(out.iterdir()), [])

        right.write_bytes(malformed)
        self.assertEqual(json.loads(plan().stdout)['refused'], 'conflict')
        self.assertEqual(list(out.iterdir()), [])

        left.write_bytes(malformed + b'# different copy\n')
        self.assertEqual(json.loads(plan().stdout)['refused'], 'conflict')
        self.assertEqual(list(out.iterdir()), [])

        left.write_bytes(malformed)
        skipped = json.loads(plan().stdout)
        self.assertIsNone(skipped['refused'])
        self.assertEqual([row['status'] for row in skipped['files']], ['skipped', 'skipped'])
        self.assertEqual(list(out.iterdir()), [])

    def test_endpoint_host_switch_command(self):
        # Search roots are mocked. The live /root and /home trees are not used.
        roots_fn = SOURCE.split('function awgStateClientConfigSearchRoots()', 1)[1].split('\nfunction ', 1)[0]
        for needle in ('${AMNEZIAWG_DIR}/clients', '"/root"', '/home/*', 'getHomeDirForClient', 'resolveWebPanelConfigDir'):
            self.assertIn(needle, roots_fn)
        collect = SOURCE.split('function collectAwgClientConfigCandidates()', 1)[1].split('\nfunction ', 1)[0]
        self.assertIn('awgStateClientConfigSearchRoots SEARCH_ROOTS', collect)
        command = SOURCE.split('function awgStateEndpointCommand()', 1)[1].split('\nfunction awgStateCommand()', 1)[0]
        self.assertNotIn('regenerateClients', command)
        secret = b'ENDPOINT-SWITCH-SECRET-KEY'
        tree = self.root / 'tree'
        clients = tree / 'clients'
        home = tree / 'home'
        panel = tree / 'panel'
        conflict_dir = tree / 'conflict'
        for directory in (clients, home, panel, conflict_dir):
            directory.mkdir(parents=True)
        phone_old = (
            b'# note 203.0.113.7 stays\n'
            b'[Interface]\nPrivateKey = ' + secret + b'\nAddress = 10.66.66.2/32\nMTU = 1280\n'
            b'Jc = 4\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 16\nS3 = 17\nS4 = 18\n'
            b'H1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n'
            b'PreUp = touch ' + str(self.root / 'pwned').encode() + b'\n'
            b'[Peer]\nPublicKey = ' + PUB.encode() + b'\nPresharedKey = ENDPOINT-SWITCH-PSK\n'
            b'Endpoint = 203.0.113.7:51820\nAllowedIPs = 0.0.0.0/0,::/0\nPersistentKeepalive = 25\n'
        )
        v6_old = (
            b'[Interface]\r\nAddress = 10.66.66.4/32\r\nMTU = 1280\r\n'
            b'Jc = 4\r\nJmin = 40\r\nJmax = 70\r\nS1 = 15\r\nS2 = 16\r\nS3 = 17\r\nS4 = 18\r\n'
            b'H1 = 1\r\nH2 = 2\r\nH3 = 3\r\nH4 = 4\r\n'
            b'[Peer]\r\nPublicKey = ' + PUB.encode() + b'\r\nPresharedKey = ENDPOINT-SWITCH-PSK\r\n'
            b'Endpoint = [2001:db8::5]:51820\r\nAllowedIPs = 0.0.0.0/0\r\n'
        )
        phone = clients / 'awg0-client-phone.conf'
        phone_home = home / 'awg0-client-phone.conf'
        v6 = panel / 'awg0-client-v6.conf'
        phone.write_bytes(phone_old)
        phone_home.write_bytes(phone_old)
        v6.write_bytes(v6_old)
        os.chmod(phone, 0o640)
        os.chmod(phone_home, 0o600)
        (conflict_dir / 'awg0-client-phone.conf').write_bytes(phone_old + b'MTU = 1420\n')
        (tree / 'awg0.conf').write_bytes(
            b'[Interface]\nListenPort = 51820\n'
            b'\n### Client phone\n[Peer]\nPublicKey = ' + PEER.encode() + b'\n'
            b'\n### Client v6\n[Peer]\nPublicKey = ' + PEER.encode() + b'\n'
            b'\n### Client extra\n[Peer]\nPublicKey = ' + PEER.encode() + b'\n'
            b'\n### Client odd\n[Peer]\nPublicKey = ' + PEER.encode() + b'\n'
            b'\n### Client nul\n[Peer]\nPublicKey = ' + PEER.encode() + b'\n'
        )
        (home / 'awg0-client-planted.conf').write_bytes(b'[Peer]\nEndpoint = 198.51.100.8:51820\n')
        odd = clients / 'awg0-client-odd.conf'
        odd_original = b'[Peer]\nEndpoint = 203.0.113.7:51820\n# \xff\n'
        odd.write_bytes(odd_original)
        nul = clients / 'awg0-client-nul.conf'
        nul_original = b'[Peer]\nEndpoint = 203.0.113.7:51820\n# \0\n'
        nul.write_bytes(nul_original)
        (tree / 'slash').mkdir()
        params = self.files['vpn/params'].replace(
            b"SERVER_PUB_IP='vpn.example.test'", b"SERVER_PUB_IP='203.0.113.9'")
        (tree / 'params').write_bytes(params)
        shell = r'''
set -uo pipefail
source "$1"
T="$2"
isRoot() { :; }
checkOS() { OS=debian; }
awgStateWorkDir() { printf '%s\n' "$T/work"; }
awgStateTrustedPath() { return 0; }
acquireClientLifecycleLock() { echo lock >>"$T/order"; return 0; }
releaseClientLifecycleLock() {
    if [[ ! -e "$T/released-once" ]]; then
        touch "$T/released-once"
        if [[ -n "${AWG_ENDPOINT_OUT:-}" && -s "${AWG_ENDPOINT_OUT}" ]]; then
            echo early-print >>"$T/order"
        fi
    fi
    echo release >>"$T/order"
}
regenerateClients() { echo regen >>"$T/called"; exit 99; }
awg() { echo awg >>"$T/called"; exit 99; }
# The third profile fails once, as root or not. The other profiles use the real rename.
eval "$(declare -f awgStateInstallRewrittenProfile | sed '1s/awgStateInstallRewrittenProfile/awgStateInstallRewrittenProfileReal/')"
awgStateInstallRewrittenProfile() {
    if [[ -f "$T/fail-v6" && "$2" == *awg0-client-v6.conf ]]; then
        return 1
    fi
    awgStateInstallRewrittenProfileReal "$@"
}
getHomeDirForClient() { echo getent >>"$T/called"; printf '%s\n' /root; }
resolveWebPanelConfigDir() { echo panel >>"$T/called"; printf '%s\n' /etc/amneziawg-panel; }
awgStateClientConfigSearchRoots() {
    local -n ROOTS_REF="$1"
    ROOTS_REF=("$T/tree/clients" "$T/tree/home" "$T/tree/panel" "$T/tree/slash/")
    if [[ -f "$T/include-conflict" ]]; then
        ROOTS_REF+=("$T/tree/conflict")
    fi
}
begin() {
    rm -rf -- "$T/work"
    mkdir -p -- "$T/work"
    rm -f -- "$T/released-once"
    : >"$T/order"
}
AMNEZIAWG_DIR="$T/tree"
begin
awgStateReadParams "$AMNEZIAWG_DIR/params" "$T/work/records" || { echo 'read-params-failed' >&2; exit 40; }
canon="$(mktemp -- "$T/params.canon.XXXXXX")"
serializeParams "$canon" || { echo 'serialize-failed' >&2; exit 41; }
mv -f -- "$canon" "$AMNEZIAWG_DIR/params"
cp -a -- "$AMNEZIAWG_DIR/params" "$T/params-canonical"
rm -rf -- "$T/work"
: >"$T/order"
for bad in 203.0.113.7 127.0.0.1 1.2.3.4 123 1.2.3 0x7f.1 0177.0.0.1 4294967295; do
    if awgStateEndpointCommand set "$bad" >"$T/ip.out" 2>"$T/ip.err"; then
        echo "accepted-ip $bad" >&2
        exit 30
    fi
    grep -q 'would be read as an IPv4 address' "$T/ip.err" || { echo "ip-message $bad" >&2; cat "$T/ip.err" >&2; exit 31; }
done
for bad in '2001:db8::1' '[2001:db8::1]'; do
    if awgStateEndpointCommand set "$bad" >"$T/ip.out" 2>"$T/ip.err"; then
        echo "accepted-ip $bad" >&2
        exit 30
    fi
    grep -q 'not an IP address' "$T/ip.err" || { echo "ip-message $bad" >&2; cat "$T/ip.err" >&2; exit 31; }
done
if awgStateEndpointCommand set 'not a host' >"$T/ip.out" 2>"$T/ip.err"; then
    echo 'accepted-bad-host' >&2
    exit 32
fi
grep -q 'DNS hostname' "$T/ip.err" || { cat "$T/ip.err" >&2; exit 33; }
got="$(awgStateEndpointRequireHostname 'Example.COM')" || { echo 'rejected-mixed-case' >&2; exit 35; }
[[ "${got}" == 'Example.COM' ]] || { printf 'spelling %s\n' "${got}" >&2; exit 36; }
for good in 1e100.net xn--bcher-kva.example a1.example 256.1.1.1; do
    awgStateEndpointRequireHostname "${good}" >/dev/null || { echo "rejected ${good}" >&2; exit 37; }
done
if awgStateEndpointRequireHostname 'vpn.example.test.' >/dev/null; then
    echo 'accepted-trailing-dot' >&2
    exit 38
fi
grep -q lock "$T/order" && { echo 'locked-on-refusal' >&2; exit 34; }
ln -s "$T/tree/missing-target.conf" "$T/tree/slash/awg0-client-extra.conf"
cand=()
collectAwgClientConfigCandidates cand || { echo 'collect-failed' >&2; exit 60; }
printf '%s\n' "${cand[@]}" >"$T/collected"
begin
AWG_ENDPOINT_OUT="$T/symlink.out"
: >"$AWG_ENDPOINT_OUT"
if awgStateEndpointCommand set vpn.example.test >"$AWG_ENDPOINT_OUT" 2>"$T/symlink.err"; then
    echo 'symlink-accepted' >&2
    exit 61
fi
grep -q 'symlink' "$T/symlink.err" || { cat "$T/symlink.err" >&2; exit 62; }
grep -q 'not readable' "$T/symlink.err" && { echo 'opened-symlink' >&2; exit 63; }
grep -F '//' "$T/symlink.err" && { echo 'double-slash' >&2; exit 67; }
rm -f -- "$T/tree/slash/awg0-client-extra.conf"
: >"$T/include-conflict"
begin
AWG_ENDPOINT_OUT="$T/conflict.out"
: >"$AWG_ENDPOINT_OUT"
if awgStateEndpointCommand set vpn.example.test --dry-run >"$AWG_ENDPOINT_OUT" 2>"$T/conflict.err"; then
    echo 'conflict-accepted' >&2
    exit 64
fi
grep -q 'disagree outside the Endpoint line' "$T/conflict.err" || { cat "$T/conflict.err" >&2; exit 65; }
cmp -s "$AMNEZIAWG_DIR/params" "$T/params-canonical" || { echo 'conflict-wrote-params' >&2; exit 66; }
rm -f -- "$T/include-conflict"
cp -a -- "$T/tree/clients/awg0-client-phone.conf" "$T/original-phone"
cp -a -- "$T/tree/panel/awg0-client-v6.conf" "$T/original-v6"
cp -a -- "$T/tree/home/awg0-client-phone.conf" "$T/original-home"
begin
AWG_ENDPOINT_OUT="$T/audit.json"
: >"$AWG_ENDPOINT_OUT"
awgStateEndpointCommand audit >"$AWG_ENDPOINT_OUT" 2>"$T/audit.err" || { echo 'audit-failed' >&2; cat "$T/audit.err" >&2; exit 50; }
grep -q early-print "$T/order" && { echo 'audit-printed-under-lock' >&2; exit 51; }
grep -q lock "$T/order" || { echo 'audit-no-lock' >&2; exit 52; }
grep -q release "$T/order" || { echo 'audit-no-release' >&2; exit 53; }
begin
AWG_ENDPOINT_OUT="$T/dry.out"
: >"$AWG_ENDPOINT_OUT"
awgStateEndpointCommand set vpn.example.test --dry-run >"$AWG_ENDPOINT_OUT" 2>"$T/dry.err" || { echo 'dry-run-failed' >&2; cat "$T/dry.err" >&2; exit 54; }
cmp -s "$AMNEZIAWG_DIR/params" "$T/params-canonical" || { echo 'dry-run-wrote-params' >&2; exit 55; }
cmp -s "$T/tree/clients/awg0-client-phone.conf" "$T/original-phone" || { echo 'dry-run-wrote-phone' >&2; exit 56; }
cmp -s "$T/tree/home/awg0-client-phone.conf" "$T/original-home" || exit 57
cmp -s "$T/tree/panel/awg0-client-v6.conf" "$T/original-v6" || exit 58
: >"$T/fail-v6"
begin
AWG_ENDPOINT_OUT="$T/partial.out"
: >"$AWG_ENDPOINT_OUT"
if awgStateEndpointCommand set vpn.example.test >"$AWG_ENDPOINT_OUT" 2>"$T/partial.err"; then
    echo 'partial-succeeded' >&2
    exit 70
fi
grep -q 'partial write' "$T/partial.err" || { cat "$T/partial.err" >&2; exit 71; }
cmp -s "$AMNEZIAWG_DIR/params" "$T/params-canonical" || { echo 'partial-wrote-params' >&2; exit 72; }
cmp -s "$T/tree/panel/awg0-client-v6.conf" "$T/original-v6" || { echo 'partial-wrote-v6' >&2; exit 73; }
cmp -s "$T/tree/clients/awg0-client-phone.conf" "$T/original-phone" && { echo 'partial-skipped-phone' >&2; exit 74; }
rm -f -- "$T/fail-v6"
begin
AWG_ENDPOINT_OUT="$T/apply.out"
: >"$AWG_ENDPOINT_OUT"
awgStateEndpointCommand set vpn.example.test >"$AWG_ENDPOINT_OUT" 2>"$T/apply.err" || { echo 'apply-failed' >&2; cat "$T/apply.err" >&2; exit 80; }
cp -a -- "$AMNEZIAWG_DIR/params" "$T/params-after"
cp -a -- "$T/tree/clients/awg0-client-phone.conf" "$T/phone-after"
cp -a -- "$T/tree/home/awg0-client-phone.conf" "$T/home-after"
cp -a -- "$T/tree/panel/awg0-client-v6.conf" "$T/v6-after"
begin
AWG_ENDPOINT_OUT="$T/rerun.out"
: >"$AWG_ENDPOINT_OUT"
awgStateEndpointCommand set vpn.example.test >"$AWG_ENDPOINT_OUT" 2>"$T/rerun.err" || { echo 'rerun-failed' >&2; cat "$T/rerun.err" >&2; exit 81; }
cmp -s "$AMNEZIAWG_DIR/params" "$T/params-after" || { echo 'rerun-wrote-params' >&2; exit 82; }
cmp -s "$T/tree/clients/awg0-client-phone.conf" "$T/phone-after" || exit 83
cmp -s "$T/tree/home/awg0-client-phone.conf" "$T/home-after" || exit 84
cmp -s "$T/tree/panel/awg0-client-v6.conf" "$T/v6-after" || exit 85
begin
AWG_ENDPOINT_OUT="$T/audit-after.json"
: >"$AWG_ENDPOINT_OUT"
awgStateEndpointCommand audit >"$AWG_ENDPOINT_OUT" 2>"$T/audit-after.err" || { echo 'audit-after-failed' >&2; cat "$T/audit-after.err" >&2; exit 86; }
begin
AWG_ENDPOINT_OUT="$T/dry-after.out"
: >"$AWG_ENDPOINT_OUT"
awgStateEndpointCommand set vpn.example.test --dry-run >"$AWG_ENDPOINT_OUT" 2>"$T/dry-after.err" || { echo 'dry-after-failed' >&2; cat "$T/dry-after.err" >&2; exit 87; }
[[ ! -e "$T/called" ]] || { echo 'regenerated-or-searched-live-roots' >&2; cat "$T/called" >&2; exit 88; }
[[ ! -e "$T/pwned" ]] || { echo 'executed-profile' >&2; exit 89; }
'''
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)], capture_output=True)
        combined = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, combined.decode())
        self.assertNotIn(secret, combined)
        self.assertNotIn(b'ENDPOINT-SWITCH-PSK', combined)
        self.assertNotIn(KEY.encode(), combined)
        collected = set((self.root / 'collected').read_text().splitlines())
        planted = home / 'awg0-client-planted.conf'
        # collectAwgClientConfigCandidates is not filtered to managed names.
        # The audit and the switch are. planted has no marker; odd does not parse.
        self.assertEqual(collected, {
            str(phone.resolve()),
            str(phone_home.resolve()),
            str(v6.resolve()),
            str(planted.resolve()),
            str(odd.resolve()),
            str(nul.resolve()),
        })
        audit = json.loads((self.root / 'audit.json').read_text())
        self.assertEqual(audit['hostname'], 0)
        self.assertEqual(audit['ip_literal'], 3)
        self.assertEqual(audit['symlinks'], [])
        self.assertEqual(audit['skipped'], sorted([str(odd), str(nul)]))
        by_name = {item['name']: item for item in audit['clients']}
        self.assertEqual(by_name['awg0-client-phone']['kind'], 'ip_literal')
        self.assertEqual(by_name['awg0-client-phone']['host'], '203.0.113.7')
        self.assertEqual(by_name['awg0-client-phone']['files'], sorted([str(phone.resolve()), str(phone_home.resolve())]))
        self.assertEqual(by_name['awg0-client-v6']['host'], '2001:db8::5')
        self.assertEqual(by_name['awg0-client-v6']['files'], [str(v6.resolve())])
        dry = (self.root / 'dry.out').read_text()
        self.assertIn('SERVER_PUB_IP 203.0.113.9 -> vpn.example.test\n', dry)
        self.assertIn('-Endpoint = 203.0.113.7:51820\n+Endpoint = vpn.example.test:51820\n', dry)
        self.assertIn('-Endpoint = [2001:db8::5]:51820\n+Endpoint = vpn.example.test:51820\n', dry)
        self.assertNotIn(secret.decode(), dry)
        self.assertNotIn('PrivateKey', dry)
        self.assertNotIn('PreUp', dry)
        phone_now = phone.read_bytes()
        home_now = phone_home.read_bytes()
        v6_now = v6.read_bytes()
        self.assertEqual(phone_now, phone_old.replace(
            b'Endpoint = 203.0.113.7:51820', b'Endpoint = vpn.example.test:51820', 1))
        self.assertEqual(home_now, phone_now)
        self.assertEqual(v6_now, v6_old.replace(
            b'Endpoint = [2001:db8::5]:51820', b'Endpoint = vpn.example.test:51820', 1))
        self.assertNotIn(b'PrivateKey', v6_now)
        self.assertIn(b'203.0.113.7 stays', phone_now)
        self.assertEqual(stat_mode(phone), 0o640)
        self.assertEqual(stat_mode(phone_home), 0o600)
        self.assertFalse((self.root / 'pwned').exists())
        params_text = (tree / 'params').read_text()
        self.assertIn("SERVER_PUB_IP='vpn.example.test'\n", params_text)
        self.assertNotIn('203.0.113.9', params_text)
        self.assertIn("SERVER_PRIV_KEY='" + KEY + "'\n", params_text)
        rerun = (self.root / 'rerun.out').read_text()
        self.assertIn('unchanged ' + str(phone.resolve()), rerun)
        self.assertIn('unchanged ' + str(v6.resolve()), rerun)
        self.assertNotIn('updated ', rerun)
        self.assertIn('SERVER_PUB_IP vpn.example.test\n', rerun)
        self.assertNotIn('->', rerun)
        after = json.loads((self.root / 'audit-after.json').read_text())
        self.assertEqual(after['hostname'], 3)
        self.assertEqual(after['ip_literal'], 0)
        self.assertTrue(all(item['kind'] == 'hostname' and item['host'] == 'vpn.example.test' for item in after['clients']))
        dry_after = (self.root / 'dry-after.out').read_text()
        self.assertIn('No Endpoint lines need to change.\n', dry_after)
        self.assertIn('skipped ' + str(odd.resolve()) + '\n', dry_after)
        self.assertIn('skipped ' + str(odd.resolve()), dry)
        self.assertEqual((home / 'awg0-client-planted.conf').read_bytes(), b'[Peer]\nEndpoint = 198.51.100.8:51820\n')
        self.assertNotIn('planted', (self.root / 'audit.json').read_text())
        self.assertNotIn('198.51.100.8', (self.root / 'audit.json').read_text())
        for profile, original in ((odd, odd_original), (nul, nul_original)):
            self.assertIn('skipped ' + str(profile) + '\n', dry)
            self.assertIn('skipped ' + str(profile) + '\n', rerun)
            self.assertEqual(profile.read_bytes(), original)
        self.assertNotIn('//', (self.root / 'symlink.err').read_text())
        self.assertFalse((self.root / 'work').exists())

    def test_endpoint_hostname_refuses_inet_aton_and_a_host_of_n(self):
        for value in ('123', '1.2.3', '0x7f.1', '0177.0.0.1', '4294967295', '0x7f000001'):
            with self.subTest(value=value):
                self.assertEqual(self.run_helper('endpoint-hostname', value).stdout, b'ipv4\n')
        for value in ('1e100.net', 'xn--bcher-kva.example', 'Example.COM', 'a1.example', '256.1.1.1'):
            with self.subTest(value=value):
                self.assertEqual(self.run_helper('endpoint-hostname', value).stdout, b'ok\n')
        self.assertEqual(self.run_helper('endpoint-hostname', 'vpn.example.test.').stdout, b'no\n')
        stage = self.root / 'aton'
        (stage / 'clients').mkdir(parents=True)
        expected_literal = 0
        expected_name = 0
        for name, endpoint, kind in (
            ('hex', '0x7f.1:51820', 'ip_literal'),
            ('short', '123:51820', 'ip_literal'),
            ('triple', '1.2.3:51820', 'ip_literal'),
            ('octal', '0177.0.0.1:51820', 'ip_literal'),
            ('dword', '4294967295:51820', 'ip_literal'),
            ('name', '1e100.net:51820', 'hostname'),
            ('notaton', '256.1.1.1:51820', 'hostname'),
        ):
            (stage / 'clients' / ('awg0-client-%s.conf' % name)).write_text('[Peer]\nEndpoint = %s\n' % endpoint)
            if kind == 'ip_literal':
                expected_literal += 1
            else:
                expected_name += 1
        summary = self.run_helper('endpoint-summary', stage)
        self.assertEqual(summary.stdout.splitlines()[:2], [str(expected_name).encode(), str(expected_literal).encode()])
        narrow = self.root / 'awg0-client-n.conf'
        narrow.write_bytes(b'[Peer]\nEndpoint = n:51820\n')
        regular = self.root / 'n-regular'
        regular.write_bytes(str(narrow).encode() + b'\0')
        (self.root / 'n-sym').write_bytes(b'')
        n_out = self.root / 'n-out'
        n_out.mkdir()
        plan = json.loads(self.run_helper(
            'endpoint-plan', regular, self.root / 'n-sym', n_out, 'rewrite',
            'vpn.example.test', '203.0.113.9').stdout)
        self.assertEqual(plan['files'][0]['status'], 'update')
        self.assertEqual((n_out / plan['files'][0]['out']).read_bytes(),
                         b'[Peer]\nEndpoint = vpn.example.test:51820\n')
        skipped_dir = self.root / 'skipped-profiles'
        skipped_dir.mkdir()
        bodies = {
            'semi': b'; Endpoint = 203.0.113.7:51820\n',
            'bom': b'\xef\xbb\xbf[Peer]\nEndpoint = 203.0.113.7:51820\n',
        }
        paths = []
        for name, body in bodies.items():
            path = skipped_dir / ('awg0-client-%s.conf' % name)
            path.write_bytes(body)
            paths.append(path)
        listed = self.root / 'skipped-list'
        listed.write_bytes(b''.join(str(path).encode() + b'\0' for path in paths))
        (self.root / 'skipped-sym').write_bytes(b'')
        skipped_out = self.root / 'skipped-out'
        skipped_out.mkdir()
        skipped_plan = json.loads(self.run_helper(
            'endpoint-plan', listed, self.root / 'skipped-sym', skipped_out, 'rewrite',
            'vpn.example.test', '203.0.113.9').stdout)
        self.assertTrue(all(row['status'] == 'skipped' for row in skipped_plan['files']))
        self.assertEqual(list(skipped_out.iterdir()), [])

    def test_endpoint_plan_uses_last_assignment_case_insensitively(self):
        stage = self.root / 'endpoint-case'
        clients = stage / 'clients'
        clients.mkdir(parents=True)
        profile = clients / 'awg0-client-phone.conf'
        body = (b'[pEeR]\r\nEndpoint = old.example.test:1000\r\n'
                b'\teNdPoInT\t=\t192.0.2.10:51820  # retained\r\n')
        profile.write_bytes(body)
        unsupported = clients / 'awg0-client-custom.conf'
        unsupported.write_bytes(b'[Peer]\nEndpoint = remote.example.test:service\n')
        rooted = clients / 'awg0-client-rooted.conf'
        rooted.write_bytes(b'[Peer]\nEndpoint = root.example.test.:51820\n')
        multi = clients / 'awg0-client-multi.conf'
        multi.write_bytes(b'[Peer]\nEndpoint = first.example.test:51820\n'
                          b'[Peer]\nEndpoint = other.example.test:51821\n')
        regular = stage / 'regular'
        regular.write_bytes(b''.join(os.fsencode(path) + b'\0' for path in (profile, unsupported, rooted, multi)))
        symlinks = stage / 'symlinks'
        symlinks.touch()
        out = stage / 'out'
        out.mkdir()
        summary = self.run_helper('endpoint-summary', stage)
        self.assertEqual(summary.stdout.splitlines()[:2], [b'1', b'1'])
        self.assertIn(b'2 client profile(s) could not be classified', summary.stdout)
        plan = json.loads(self.run_helper('endpoint-plan', regular, symlinks, out, 'rewrite',
                                         'new.example.test', 'old.example.test').stdout)
        self.assertEqual(plan['ip_literal'], 1)
        rows = {row['path']: row for row in plan['files']}
        self.assertEqual(rows[str(unsupported)]['status'], 'skipped')
        self.assertEqual(rows[str(multi)]['status'], 'skipped')
        self.assertEqual(rows[str(rooted)]['status'], 'update')
        rewritten = out / rows[str(profile)]['out']
        self.assertEqual(rewritten.read_bytes(), body.replace(b'192.0.2.10', b'new.example.test'))

    def test_endpoint_install_keeps_profile_access_acl(self):
        import struct

        original, updated = b'[Peer]\nEndpoint = old.example.test:51820\n', b'[Peer]\nEndpoint = new.example.test:51820\n'
        dest, before, rewrite = (self.root / name for name in ('profile.conf', 'before', 'rewrite'))
        dest.write_bytes(original)
        before.write_bytes(original)
        rewrite.write_bytes(updated)
        # POSIX ACL xattr v2: owner, named user, group, mask, other.
        acl = struct.pack('<I', 2) + b''.join(
            struct.pack('<HHI', tag, mode, ident)
            for tag, mode, ident in ((1, 6, 0xffffffff), (2, 4, os.getuid()),
                                     (4, 0, 0xffffffff), (16, 4, 0xffffffff), (32, 0, 0xffffffff)))
        try:
            os.setxattr(dest, 'system.posix_acl_access', acl)
        except OSError as error:
            if error.errno in (errno.ENOTSUP, errno.EPERM):
                self.skipTest('filesystem does not support testing POSIX ACLs')
            raise
        script = 'source "$1"; awgStateInstallRewrittenProfile "$2" "$3" "$4"'
        result = subprocess.run(['bash', '-c', script, 'test', str(SCRIPT),
                                 str(rewrite), str(dest), str(before)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(dest.read_bytes(), updated)
        self.assertIn('system.posix_acl_access', os.listxattr(dest))
        self.assertEqual(os.getxattr(dest, 'system.posix_acl_access'), acl)

    def test_endpoint_install_copies_acl_before_applying_mode(self):
        # Exercise the write ordering on filesystems that do not support ACLs.
        root = self.root
        dest, before, rewrite = (root / name for name in ('profile.conf', 'before', 'rewrite'))
        dest.write_bytes(b'[Peer]\nEndpoint = old.example.test:51820\n')
        before.write_bytes(dest.read_bytes())
        rewrite.write_bytes(dest.read_bytes().replace(b'old.example.test', b'new.example.test'))
        py = SOURCE.split("<<'AWG_ENDPOINT_INSTALL_PY'\n", 1)[1].split('\nAWG_ENDPOINT_INSTALL_PY', 1)[0]
        acl_calls = r'''
import errno, os, sys
original_inode = os.lstat(sys.argv[2]).st_ino
chmod = os.fchmod
copied = set()
def getxattr(fd, name):
    assert name == 'system.posix_acl_access'
    if os.fstat(fd).st_ino == original_inode:
        return b'test-acl-value'
    raise OSError(errno.ENODATA, 'no ACL')
def setxattr(fd, name, value):
    assert name == 'system.posix_acl_access'
    assert value == b'test-acl-value'
    copied.add(os.fstat(fd).st_ino)
def fchmod(fd, mode):
    assert os.fstat(fd).st_ino in copied
    chmod(fd, mode)
os.getxattr, os.setxattr, os.fchmod = getxattr, setxattr, fchmod
'''
        result = subprocess.run(['python3', '-I', '-c', acl_calls + py,
                                 str(rewrite), str(dest), str(before)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(dest.read_bytes(), rewrite.read_bytes())

    def test_endpoint_switch_stops_when_the_profile_changes_after_the_plan(self):
        tree = self.root / 'changed-tree'
        clients = tree / 'clients'
        clients.mkdir(parents=True)
        phone = clients / 'awg0-client-phone.conf'
        original = b'[Peer]\nEndpoint = 203.0.113.7:51820\n'
        phone.write_bytes(original)
        (tree / 'awg0.conf').write_bytes(
            b'[Interface]\nListenPort = 51820\n\n### Client phone\n[Peer]\nPublicKey = x\n')
        params = self.files['vpn/params'].replace(
            b"SERVER_PUB_IP='vpn.example.test'", b"SERVER_PUB_IP='203.0.113.9'")
        (tree / 'params').write_bytes(params)
        shell = r'''
set -uo pipefail
source "$1"
T="$2"
isRoot() { :; }
checkOS() { OS=debian; }
awgStateWorkDir() { printf '%s\n' "$T/work"; }
awgStateTrustedPath() { return 0; }
acquireClientLifecycleLock() { return 0; }
releaseClientLifecycleLock() { return 0; }
eval "$(declare -f awgStateInstallRewrittenProfile | sed '1s/awgStateInstallRewrittenProfile/awgStateInstallRewrittenProfileReal/')"
awgStateInstallRewrittenProfile() {
    if [[ ! -e "$T/tampered" ]]; then
        printf 'tampered\n' >"$2"
        touch "$T/tampered"
    fi
    awgStateInstallRewrittenProfileReal "$@"
}
awgStateClientConfigSearchRoots() {
    local -n ROOTS_REF="$1"
    ROOTS_REF=("$T/changed-tree/clients")
}
AMNEZIAWG_DIR="$T/changed-tree"
mkdir -p -- "$T/work"
if awgStateEndpointCommand set vpn.example.test >"$T/changed.out" 2>"$T/changed.err"; then
    echo 'changed-profile-succeeded' >&2
    exit 1
fi
grep -q 'profile changed since the plan; rerun' "$T/changed.err" || { cat "$T/changed.err" >&2; exit 2; }
'''
        result = subprocess.run(['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)], capture_output=True)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
        self.assertEqual((tree / 'params').read_bytes(), params)
        self.assertEqual(phone.read_bytes(), b'tampered\n')

    def test_endpoint_install_does_not_follow_a_swapped_temp_symlink(self):
        # A same-uid symlink at the temp path is enough. The old writer uses
        # cp -f, which follows that symlink and writes the sentinel.
        dest_dir = self.root / 'dest'
        dest_dir.mkdir()
        dest = dest_dir / 'awg0-client-phone.conf'
        original = b'[Peer]\nEndpoint = 203.0.113.7:51820\n'
        updated = b'[Peer]\nEndpoint = vpn.example.test:51820\n'
        dest.write_bytes(original)
        os.chmod(dest, 0o640)
        sentinel = self.root / 'sentinel'
        sentinel.write_bytes(b'SENTINEL-ORIGINAL\n')
        os.chmod(sentinel, 0o604)
        before = sentinel.stat()
        (self.root / 'src').write_bytes(updated)
        (self.root / 'before').write_bytes(original)
        stop = threading.Event()

        def swap():
            # fsync keeps the temp name visible longer than one tight scan, so
            # a pause between scans leaves room for a clean rename. A scan that
            # wins must still leave the sentinel untouched.
            while not stop.is_set():
                try:
                    names = os.listdir(dest_dir)
                except OSError:
                    time.sleep(0.002)
                    continue
                for name in names:
                    if not name.startswith('.awg-endpoint.'):
                        continue
                    path = dest_dir / name
                    try:
                        path.unlink()
                    except OSError:
                        pass
                    try:
                        path.symlink_to(sentinel)
                    except OSError:
                        pass
                time.sleep(0.002)

        thread = threading.Thread(target=swap, daemon=True)
        thread.start()
        shell = r'''
set -uo pipefail
source "$1"
T="$2"
isRoot() { :; }
checkOS() { OS=debian; }
ok=0
for _ in $(seq 1 50); do
    if [[ -L "$T/dest/awg0-client-phone.conf" ]]; then
        rm -f -- "$T/dest/awg0-client-phone.conf"
    fi
    cp -f -- "$T/original-dest" "$T/dest/awg0-client-phone.conf"
    chmod 640 "$T/dest/awg0-client-phone.conf"
    if awgStateInstallRewrittenProfile "$T/src" "$T/dest/awg0-client-phone.conf" "$T/before"; then
        ok=$((ok + 1))
    fi
done
printf '%s\n' "$ok"
'''
        try:
            (self.root / 'original-dest').write_bytes(original)
            result = subprocess.run(
                ['bash', '-c', shell, 'test', str(SCRIPT), str(self.root)],
                capture_output=True)
        finally:
            stop.set()
            thread.join(timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        after = sentinel.stat()
        self.assertEqual(sentinel.read_bytes(), b'SENTINEL-ORIGINAL\n')
        self.assertEqual(stat.S_IMODE(after.st_mode), stat.S_IMODE(before.st_mode))
        self.assertEqual((after.st_uid, after.st_gid), (before.st_uid, before.st_gid))
        self.assertGreater(int(result.stdout.strip() or b'0'), 0, result.stderr.decode())
        self.assertTrue(dest.is_file())
        self.assertFalse(dest.is_symlink())


PERMS_HARNESS = r"""
set -euo pipefail
ROOT="$1" PROXY_SH="$2" WEB_SH="$3"; shift 3
PROXY_DATA="$ROOT/var/lib/amneziawg-proxy"
mkdir -p "$ROOT/state"
step() { :; }; info() { :; }; warn() { echo "WARN $*" >&2; }
getent() { [[ "$1" == group && -e "$ROOT/group-$2" ]]; }
chown() { local p; for p in "${@:2}"; do printf '%s\n' "$1" >"$ROOT/state/$(printf %s "$p" | tr / _).owner"; done; }
chmod() { local p; for p in "${@:2}"; do printf '%s\n' "$1" >"$ROOT/state/$(printf %s "$p" | tr / _).mode"; done; }
eval "$(sed -n '/^setup_filesystem() {/,/^}/p' "$PROXY_SH")"
eval "web_proxy_share() { SERVICE_USER=awg-web
$(sed -n '/# If amneziawg-proxy is already installed/,/^    fi$/p' "$WEB_SH" | sed "s#/var/lib/amneziawg-proxy#$PROXY_DATA#g")
}"
grep -q "$PROXY_DATA" <(declare -f web_proxy_share)
grep -q 'awg-web' <(declare -f setup_filesystem)
CONFIG_DIR="$ROOT/etc/amneziawg-proxy" DATA_DIR="$PROXY_DATA"
proxy() { setup_filesystem; }
panel() { : >"$ROOT/group-awg-web"; web_proxy_share; }
for action in "$@"; do "$action"; done
key=$(printf %s "$PROXY_DATA" | tr / _)
printf '%s %s\n' "$(cat "$ROOT/state/$key.owner")" "$(cat "$ROOT/state/$key.mode")"
"""


def stat_mode(path):
    return path.stat().st_mode & 0o777


class CompanionPermissionTests(unittest.TestCase):
    """Panel-then-proxy (migration order) must end like a normal install where
    the proxy existed before the panel: both installers' own steps are run."""

    def perms(self, *actions):
        with tempfile.TemporaryDirectory(prefix='awg-perm-') as tmp:
            result = subprocess.run(
                ['bash', '-c', PERMS_HARNESS, 'perm', tmp,
                 str(ROOT / 'amneziawg-proxy/scripts/amneziawg-proxy-install.sh'),
                 str(ROOT / 'amneziawg-web/scripts/amneziawg-web-install.sh'), *actions],
                text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, '')
            return result.stdout.strip()

    def test_proxy_data_dir_matches_normal_install_in_every_order(self):
        normal = self.perms('proxy', 'panel')
        self.assertEqual(normal, 'root:awg-web 2750')
        self.assertEqual(self.perms('panel', 'proxy'), normal)
        # Retry where only the proxy step reruns, and a later panel rerun.
        self.assertEqual(self.perms('panel', 'proxy', 'proxy'), normal)
        self.assertEqual(self.perms('panel', 'proxy', 'panel'), normal)
        # Panel restore failed before creating its user: proxy alone is
        # root-only, and the panel retry fixes it exactly like a normal install.
        self.assertEqual(self.perms('proxy'), 'root:root 0750')
        self.assertEqual(self.perms('proxy', 'proxy', 'panel'), normal)

    def test_restore_order_keeps_proxy_installer_group_step(self):
        text = SCRIPT.read_text()
        body = text[text.index('function awgStateRestoreCompanions()'):]
        body = body[:body.index('\n}\n')]
        self.assertLess(body.index('awgStateRestorePanel'), body.index('awgStateRestoreProxy'))
        proxy = text[text.index('function awgStateRestoreProxy()'):]
        proxy = proxy[:proxy.index('\n}\n')]
        # The proxy data dir is left to the proxy installer (no chown/chmod here).
        self.assertNotIn('chown', proxy)
        self.assertNotIn('chmod', proxy)


class Awg1MigrationTests(unittest.TestCase):
    """Pre-2.0 AWG 1.0 kernel installations must export, import, retry
    activation, re-export, and keep working with amneziawg-web and
    amneziawg-proxy without being promoted to AWG 2.0."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='awg1-state-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.helper = self.root / 'helper.py'
        self.helper.write_text(CODE)

    def run_helper(self, mode, path, *args, ok=True):
        result = subprocess.run(['python3', str(self.helper), KEYS, mode, str(path),
                                 *map(str, args)], capture_output=True)
        if ok:
            self.assertEqual(result.returncode, 0, result.stderr.decode())
        else:
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(KEY.encode(), result.stderr)
        return result

    def legacy_fixture(self, include_dns2=True, proxy=True):
        lines = [
            'SERVER_PUB_IP=milan.example.test',
            'SERVER_PUB_NIC=eth0',
            'SERVER_AWG_NIC=awg0',
            'SERVER_AWG_IPV4=10.66.67.1',
            'SERVER_AWG_IPV6=fd42:42:43::1',
            'SERVER_PORT=64828',
            f'SERVER_PRIV_KEY={KEY}',
            f'SERVER_PUB_KEY={PUB}',
            'CLIENT_DNS_1=1.1.1.1',
        ]
        if include_dns2:
            lines.append('CLIENT_DNS_2=1.0.0.1')
        lines += [
            'ALLOWED_IPS=0.0.0.0/0,::/0',
            'SERVER_AWG_JC=10',
            'SERVER_AWG_JMIN=50',
            'SERVER_AWG_JMAX=1000',
            'SERVER_AWG_S1=84',
            'SERVER_AWG_S2=150',
            'SERVER_AWG_H1=1805140871',
            'SERVER_AWG_H2=1806515711',
            'SERVER_AWG_H3=434882725',
            'SERVER_AWG_H4=1715363230',
        ]
        listen_port = '64829' if proxy else '64828'
        conf = (
            '[Interface]\n'
            'Address = 10.66.67.1/24,fd42:42:43::1/64\n'
            f'ListenPort = {listen_port}\n'
            f'PrivateKey = {KEY}\n'
            'Jc = 10\nJmin = 50\nJmax = 1000\nS1 = 84\nS2 = 150\n'
            'H1 = 1805140871\nH2 = 1806515711\nH3 = 434882725\nH4 = 1715363230\n'
            'PostUp = iptables -w -I INPUT ! -i lo -p udp --dport 64829 -j DROP\n'
            f'\n### Client phone\n[Peer]\nPublicKey = {PEER}\nPresharedKey = {PUB}\n'
            'AllowedIPs = 10.66.67.2/32,fd42:42:43::2/128\n'
        )
        client = (
            f'[Interface]\nPrivateKey = {PEER}\nAddress = 10.66.67.2/32,fd42:42:43::2/128\n'
            'DNS = 1.1.1.1,1.0.0.1\n'
            'Jc = 10\nJmin = 50\nJmax = 1000\nS1 = 84\nS2 = 150\n'
            'H1 = 1805140871\nH2 = 1806515711\nH3 = 434882725\nH4 = 1715363230\n'
            f'\n[Peer]\nPublicKey = {PUB}\nPresharedKey = {PUB}\n'
            'Endpoint = milan.example.test:64828\nAllowedIPs = 0.0.0.0/0,::/0\n'
        )
        files = {
            'vpn/params': ('\n'.join(lines) + '\n').encode(),
            'vpn/server.conf': conf.encode(),
            'clients/awg0-client-phone.conf': client.encode(),
        }
        if proxy:
            files['proxy/proxy.toml'] = (
                'listen = "[::]:64828"\n'
                'backend = "127.0.0.1:64829"\n'
                'imitate_protocol = "auto"\n'
                'quic_certificate_domain = "milan.example.test"\n'
                'awg_config = "/etc/amnezia/amneziawg/awg0.conf"\n'
                'status_file = "/var/lib/amneziawg-proxy/sessions.json"\n'
                'status_interval_secs = 5\n'
            ).encode()
        return files

    def write_stage(self, name, files):
        stage = self.root / name
        for rel, data in files.items():
            path = stage / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        return stage

    def test_awg1_legacy_pack_inspect_and_rejections(self):
        files = self.legacy_fixture()
        stage = self.write_stage('stage-legacy', files)
        tar = self.root / 'legacy.tar.gz'
        self.run_helper('export-check', stage)
        self.run_helper('pack', stage, tar, 'awg-fixture')
        self.run_helper('verify', tar)
        info = json.loads(self.run_helper('inspect', tar).stdout.decode())
        self.assertEqual(info['protocol'], '1')
        self.assertEqual(info['backend'], 'kernel')
        self.assertEqual(info['proxy_plan']['topology'], 'proxy')
        self.assertTrue(info['proxy_plan']['awg_matches_backend'])
        self.assertIsNone(info['proxy_plan']['refusal'])
        self.assertEqual(info['endpoint_audit']['hostname'], 1)
        self.assertEqual(info['endpoint_audit']['ip_literal'], 0)

        # Explicit AWG_PROTOCOL_VERSION=1 / 1.0 with empty S3/S4 (post-import shape).
        for version in ('1', '1.0'):
            explicit = dict(files)
            explicit['vpn/params'] += f"AWG_PROTOCOL_VERSION='{version}'\nSERVER_AWG_S3=''\nSERVER_AWG_S4=''\n".encode()
            sdir = self.write_stage(f'stage-v-{version}', explicit)
            out_tar = self.root / f'explicit-{version}.tar.gz'
            self.run_helper('export-check', sdir)
            self.run_helper('pack', sdir, out_tar, 'awg-fixture')
            self.assertEqual(json.loads(self.run_helper('inspect', out_tar).stdout.decode())['protocol'], '1')

        # S3=0, S4=0 without AWG_PROTOCOL_VERSION stays AWG 2.0 (never inferred as 1.0).
        zero_v2 = self.legacy_fixture(proxy=False)
        zero_v2['vpn/params'] += b"SERVER_AWG_S3='0'\nSERVER_AWG_S4='0'\n"
        zero_v2['vpn/server.conf'] = zero_v2['vpn/server.conf'].replace(b'S2 = 150\n', b'S2 = 150\nS3 = 0\nS4 = 0\n')
        zdir = self.write_stage('stage-zero-v2', zero_v2)
        ztar = self.root / 'zero-v2.tar.gz'
        self.run_helper('pack', zdir, ztar, 'awg-fixture')
        self.assertEqual(json.loads(self.run_helper('inspect', ztar).stdout.decode())['protocol'], '2')

        # Standard headers 1..4, leading-zero scalar headers, and AWG 1.5 I1-I5 stay valid under AWG 1.0.
        special = self.legacy_fixture(proxy=False)
        special['vpn/params'] = (
            special['vpn/params']
            .replace(b'SERVER_AWG_H1=1805140871', b'SERVER_AWG_H1=00001')
            .replace(b'SERVER_AWG_H2=1806515711', b'SERVER_AWG_H2=2')
            .replace(b'SERVER_AWG_H3=434882725', b'SERVER_AWG_H3=3')
            .replace(b'SERVER_AWG_H4=1715363230', b'SERVER_AWG_H4=4')
        )
        special['vpn/server.conf'] = (
            special['vpn/server.conf']
            .replace(b'H1 = 1805140871', b'H1 = 00001')
            .replace(b'H2 = 1806515711', b'H2 = 2')
            .replace(b'H3 = 434882725', b'H3 = 3')
            .replace(b'H4 = 1715363230', b'H4 = 4')
            .replace(b'S2 = 150\n', b'S2 = 150\nI1 = <b 0xdeadbeef>\n')
        )
        special['clients/awg0-client-phone.conf'] = special['clients/awg0-client-phone.conf'].replace(
            b'S2 = 150\n', b'S2 = 150\nI1 = <b 0xdeadbeef>\n'
        )
        sp_tar = self.root / 'special.tar.gz'
        self.run_helper('pack', self.write_stage('stage-special', special), sp_tar, 'awg-fixture')
        self.assertEqual(json.loads(self.run_helper('inspect', sp_tar).stdout.decode())['protocol'], '1')

        # Legacy 2.0 and 3.0 aliases normalize cleanly in params().
        for raw, norm, extra_conf in (
            ('2.0', '2', b''),
            ('3.0', '3', f'HeaderProtectionKey = {KEY}\n'.encode()),
        ):
            aliased = self.legacy_fixture(proxy=False)
            aliased['vpn/params'] += f"SERVER_AWG_S3='15'\nSERVER_AWG_S4='16'\nAWG_PROTOCOL_VERSION='{raw}'\n".encode()
            if raw == '3.0':
                aliased['vpn/params'] += f"AWG_HEADER_PROTECTION_KEY='{KEY}'\n".encode()
            aliased['vpn/server.conf'] = aliased['vpn/server.conf'].replace(
                b'S2 = 150\n', b'S2 = 150\nS3 = 15\nS4 = 16\n' + extra_conf
            )
            a_tar = self.root / f'alias-{raw}.tar.gz'
            self.run_helper('pack', self.write_stage(f'stage-alias-{raw}', aliased), a_tar, 'awg-fixture')
            self.assertEqual(json.loads(self.run_helper('inspect', a_tar).stdout.decode())['protocol'], norm)

        # Tampered manifest protocol mismatches fail closed in both directions.
        for wrong_proto in ('2', '1.0'):
            bad_meta = manifest(files)
            bad_meta['protocol'] = wrong_proto
            bad_tar = self.root / f'bad-manifest-{wrong_proto}.tar.gz'
            make_tar(bad_tar, files, bad_meta)
            self.run_helper('verify', bad_tar, ok=False)
        v2_files = state_fixture()
        bad_v2_meta = manifest(v2_files)
        bad_v2_meta['protocol'] = '1'
        bad_v2_tar = self.root / 'bad-v2-as-v1.tar.gz'
        make_tar(bad_v2_tar, v2_files, bad_v2_meta)
        self.run_helper('verify', bad_v2_tar, ok=False)

        # Invalid AWG 1.0 / incomplete AWG 2.0 / kernel-imitation combinations must fail closed.
        bad_params = [
            ('boringtun', files['vpn/params'] + b"AWG_PROTOCOL_VERSION='1'\nAWG_BACKEND='boringtun'\n"),
            ('boringtun-inferred', files['vpn/params'] + b"AWG_BACKEND='boringtun'\n"),
            ('kernel-imitate-proto', files['vpn/params'] + b"AWG_BORINGTUN_IMITATE_PROTOCOL='quic'\n"),
            ('kernel-imitate-domain', files['vpn/params'] + b"AWG_BORINGTUN_IMITATE_DOMAIN='example.test'\n"),
            ('s3-set', files['vpn/params'] + b"AWG_PROTOCOL_VERSION='1'\nSERVER_AWG_S3='15'\n"),
            ('s4-zero-explicit-v1', files['vpn/params'] + b"AWG_PROTOCOL_VERSION='1'\nSERVER_AWG_S4='0'\n"),
            ('ranged-h1', files['vpn/params'].replace(b'SERVER_AWG_H1=1805140871', b'SERVER_AWG_H1=5-10') + b"AWG_PROTOCOL_VERSION='1'\n"),
            ('overflow-h1', files['vpn/params'].replace(b'SERVER_AWG_H1=1805140871', b'SERVER_AWG_H1=4294967296') + b"AWG_PROTOCOL_VERSION='1'\n"),
            ('awg3-key', files['vpn/params'] + f"AWG_PROTOCOL_VERSION='1'\nAWG_HEADER_PROTECTION_KEY='{KEY}'\n".encode()),
            ('awg3-trailers', files['vpn/params'] + b"AWG_PROTOCOL_VERSION='1'\nAWG_RANDOM_TRAILERS='on'\n"),
            ('awg3-rekey', files['vpn/params'] + b"AWG_PROTOCOL_VERSION='1'\nAWG_REKEY_AFTER_TIME='10'\n"),
            ('explicit-v2-missing-s3-s4', files['vpn/params'] + b"AWG_PROTOCOL_VERSION='2'\n"),
            ('explicit-v2-empty-s3-s4', files['vpn/params'] + b"AWG_PROTOCOL_VERSION='2'\nSERVER_AWG_S3=''\nSERVER_AWG_S4=''\n"),
            ('partial-s3-only', files['vpn/params'] + b"SERVER_AWG_S3='15'\n"),
        ]
        for label, payload in bad_params:
            with self.subTest(case=label):
                p = self.root / f'bad-{label}.params'
                p.write_bytes(payload)
                self.run_helper('params', p, ok=False)

        # Server config carrying S3, S4, or HeaderProtectionKey under AWG 1.0 must fail export-check.
        for label, extra in (
            ('s3', b'S3 = 15\n'),
            ('s4-zero', b'S4 = 0\n'),
            ('hpk', f'HeaderProtectionKey = {KEY}\n'.encode()),
        ):
            with self.subTest(bad_conf=label):
                bad_conf = dict(files)
                bad_conf['vpn/server.conf'] = bad_conf['vpn/server.conf'].replace(b'S2 = 150\n', b'S2 = 150\n' + extra)
                self.run_helper('export-check', self.write_stage(f'stage-bad-conf-{label}', bad_conf), ok=False)

    def test_awg1_roundtrip_import_local_identity_reexport_and_companions(self):
        # Omit CLIENT_DNS_2 too to prove set -u safety in serializeParams.
        files = self.legacy_fixture(include_dns2=False)
        source = self.root / 'source'
        (source / 'clients').mkdir(parents=True)
        (source / 'params').write_bytes(files['vpn/params'])
        (source / 'awg0.conf').write_bytes(files['vpn/server.conf'])
        (source / 'clients/awg0-client-phone.conf').write_bytes(files['clients/awg0-client-phone.conf'])
        proxy_dir = self.root / 'proxy-etc'
        proxy_dir.mkdir()
        (proxy_dir / 'proxy.toml').write_bytes(files['proxy/proxy.toml'])
        (self.root / 'work1').mkdir()
        (self.root / 'work2').mkdir()
        shell = r'''
set -euo pipefail
source "$1"
ROOT="$2"
WEB_HELPER="$3"
PROXY_SH="$4"
AMNEZIAWG_DIR="$ROOT/source"
AWG_STATE_PROXY_CONFIG="$ROOT/proxy-etc/proxy.toml"
AWG_STATE_PROXY_UNIT="$ROOT/no-proxy.service"
acquireClientLifecycleLock() { return 0; }
releaseClientLifecycleLock() { return 0; }
awgStateTrustedPath() { return 0; }
isWebPanelInstalled() { return 1; }
collectAwgClientConfigCandidates() { local -n OUTPUT="$1"; OUTPUT=("${AMNEZIAWG_DIR}/clients/awg0-client-phone.conf"); }
isRoot() { return 0; }
checkOS() { OS=ubuntu; }
awgStateWorkDir() { mktemp -d "$ROOT/tmpfs.XXXXXX"; }
awg() {
    case "$1" in
        --version) printf 'fixture-tools\n' ;;
        pubkey) printf '%s\n' "$SERVER_PUB_KEY" ;;
        *) return 1 ;;
    esac
}
age() { [[ "$1" == --passphrase && "$2" == --output && $# -eq 3 ]] || return 1; cat >"$3"; }

# 1. Export legacy AWG 1.0 server (no AWG_PROTOCOL_VERSION, no S3/S4).
awgStateExport "$ROOT/first.tar.gz" "$ROOT/work1"

# 2. Import onto a fresh target under set -euo pipefail.
awgStateArchive unpack "$ROOT/first.tar.gz" "$ROOT/stage"
awgStateReadParams "$ROOT/stage/vpn/params" "$ROOT/records"
[[ "$AWG_PROTOCOL_VERSION" == 1 ]]
awgStateArchive prepare "$ROOT/stage"
SERVER_PUB_NIC=ens99
ENABLE_IPV6=y
AMNEZIAWG_DIR="$ROOT/target"
AWG_SYSCTL_FILE="$ROOT/sysctl/awg.conf"
_AWG_STATE_IMPORT_DIR="$ROOT/stage"
writeFirewallRules() { printf 'PostUp = echo new-uplink-%s\n' "$SERVER_PUB_NIC"; }
writeAwgServerInstallState
awgParamsFileHasCanonicalKeys "$ROOT/target/params" kernel

# 2b. Reconcile, MTU budget warning, and proxy-prepare must all succeed on AWG 1.0.
awgStateArchive reconcile "$ROOT/target/awg0.conf" "$ROOT/stage" "$ROOT/reconciled.conf" >/dev/null
cmp -s "$ROOT/target/awg0.conf" "$ROOT/reconciled.conf"
freshOuterMtuBudget() { printf '1500\n'; }
awgStateWarnMtuBudget "$ROOT/target/awg0.conf" 2>"$ROOT/mtu.err"
[[ ! -s "$ROOT/mtu.err" ]]
awgStateArchive proxy-prepare "$ROOT/stage" "$ROOT/proxy-out" "$ROOT/target/awg0.conf" "" \
    "$AWG_STATE_PROXY_CONFIG" "/var/lib/amneziawg-proxy" "/usr/local/bin" >"$ROOT/proxy.fields"
grep -q 'awg_config = "'"$ROOT/target/awg0.conf"'"' "$ROOT/proxy-out/proxy.toml"

# 3. local-identity must succeed (needed for --activate-state companion retries).
awgStateArchive local-identity "$ROOT/stage/vpn/params" "$ROOT/target/params" "$ROOT/target/awg0.conf"

# 4. Bash awgStateEndpointSummary and a second export from the migrated AWG 1.0 host must succeed.
awgStateExport "$ROOT/second.tar.gz" "$ROOT/work2"
awgStateEndpointSummary >"$ROOT/summary.txt"

# 5. amneziawg-web-privileged must classify the migrated params as protocol 1 (kernel).
(
    # shellcheck disable=SC1090
    source <(sed -e '/^main "\$@"$/d' -e "s|^readonly AWG_PARAMS_PATH=.*|readonly AWG_PARAMS_PATH=\"$ROOT/target/params\"|" "$WEB_HELPER")
    require_root() { :; }
    validate_root_owned_file() { [[ "$1" == "$ROOT/target/params" && "$2" == false ]]; }
    validate_root_owned_directory() { return 0; }
    systemctl() { printf 'active\n'; }
    [[ "$(main protocol-status)" == 1 ]]
    main backend-status >"$ROOT/web-backend.txt"
)

# 6. amneziawg-proxy-install.sh must parse and accept the migrated params.
(
    eval "$(sed -n '/^awg_protocol_is_proxy_compatible() {/,/^}/p;/^awg_backend_is_proxy_compatible() {/,/^}/p;/^parse_params_file() {/,/^}/p' "$PROXY_SH")"
    parse_params_file "$ROOT/target/params"
    awg_backend_is_proxy_compatible "${PARAMS_VALUES[AWG_BACKEND]}"
    awg_protocol_is_proxy_compatible "${PARAMS_VALUES[AWG_PROTOCOL_VERSION]}"
)
'''
        result = subprocess.run(
            ['bash', '-c', shell, 'awg1-roundtrip', str(SCRIPT), str(self.root),
             str(ROOT / 'amneziawg-web/scripts/amneziawg-web-privileged'),
             str(ROOT / 'amneziawg-proxy/scripts/amneziawg-proxy-install.sh')],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        target_params = (self.root / 'target/params').read_text()
        self.assertIn("AWG_PROTOCOL_VERSION='1'\n", target_params)
        self.assertIn("SERVER_AWG_S3=''\n", target_params)
        self.assertIn("SERVER_AWG_S4=''\n", target_params)
        self.assertIn("SERVER_PUB_NIC='ens99'\n", target_params)
        target_conf = (self.root / 'target/awg0.conf').read_text()
        self.assertNotIn('S3 =', target_conf)
        self.assertNotIn('S4 =', target_conf)
        self.assertIn('ListenPort = 64829', target_conf)
        self.assertIn('new-uplink-ens99', target_conf)
        first_info = json.loads(self.run_helper('inspect', self.root / 'first.tar.gz').stdout.decode())
        second_info = json.loads(self.run_helper('inspect', self.root / 'second.tar.gz').stdout.decode())
        self.assertEqual(first_info['protocol'], '1')
        self.assertEqual(second_info['protocol'], '1')
        self.assertEqual((self.root / 'summary.txt').read_text().splitlines(), ['1', '0'])
        web_backend = (self.root / 'web-backend.txt').read_text()
        self.assertIn('backend=kernel\n', web_backend)
        self.assertIn('awg_protocol=1\n', web_backend)

    def test_awg1_cli_lifecycle_unmigrated_and_migrated(self):
        files = self.legacy_fixture(include_dns2=False, proxy=False)
        for variant in ('unmigrated', 'migrated'):
            with self.subTest(variant=variant):
                target = self.root / f'host-{variant}'
                (target / 'clients').mkdir(parents=True)
                params_bytes = files['vpn/params']
                if variant == 'migrated':
                    params_bytes += b"AWG_PROTOCOL_VERSION='1'\nSERVER_AWG_S3=''\nSERVER_AWG_S4=''\n"
                (target / 'params').write_bytes(params_bytes)
                (target / 'awg0.conf').write_bytes(files['vpn/server.conf'].replace(
                    b'S2 = 150\n', b'S2 = 150\n# S3 = 15 (not active)\n# S4 = 0 (not active)\n'))
                (target / 'clients/awg0-client-phone.conf').write_bytes(files['clients/awg0-client-phone.conf'])
                shell = r'''
set -euo pipefail
source "$1"
AMNEZIAWG_DIR="$2"
SERVER_AWG_CONF="$AMNEZIAWG_DIR/awg0.conf"
acquireClientLifecycleLock() { return 0; }
releaseClientLifecycleLock() { return 0; }
getHomeDirForClient() { printf '%s\n' "$AMNEZIAWG_DIR/clients"; }
ensureAwgBackendReady() { return 0; }
awgSyncInterfaceConfig() { return 0; }
copyToWebPanelDir() { return 0; }
removeFromWebPanelDir() { return 0; }
systemctl() {
    if [[ "${1:-}" == show ]]; then printf 'active\n'; return 0; fi
    return 1
}
awg() {
    case "$1" in
        genkey) printf '%s\n' "$3" ;;
        pubkey) printf '%s\n' "$4" ;;
        genpsk) printf '%s\n' "$4" ;;
        *) return 1 ;;
    esac
}
stat() {
    case "$2" in
        %u) printf '0\n' ;;
        %a) printf '600\n' ;;
        *) command stat "$@" ;;
    esac
}

# 1. Exported env vars must never leak into validateParamsFile.
(
    export SERVER_AWG_S3=15 SERVER_AWG_S4=20 CLIENT_DNS_2=8.8.8.8 SERVER_AWG_H1=999
    validateParamsFile 0
    [[ "$AWG_PROTOCOL_VERSION" == 1 ]]
    [[ -z "$SERVER_AWG_S3" && -z "$SERVER_AWG_S4" && -z "$CLIENT_DNS_2" ]]
    [[ "$SERVER_AWG_H1" == 1805140871 ]]
)
# Missing SERVER_AWG_H1 in params must not be satisfied by an exported env var.
(
    BAD_DIR="$AMNEZIAWG_DIR/missing-h1"
    mkdir -p "$BAD_DIR"
    grep -v '^SERVER_AWG_H1=' "$AMNEZIAWG_DIR/params" >"$BAD_DIR/params"
    printf "AWG_PROTOCOL_VERSION='1'\n" >>"$BAD_DIR/params"
    cp "$SERVER_AWG_CONF" "$BAD_DIR/awg0.conf"
    AMNEZIAWG_DIR="$BAD_DIR"
    export SERVER_AWG_H1=12345
    if validateParamsFile 0 >/dev/null 2>&1; then exit 18; fi
)
# Unmigrated legacy params with AWG_BACKEND=boringtun must fail closed.
(
    BT_DIR="$AMNEZIAWG_DIR/bt-legacy"
    mkdir -p "$BT_DIR"
    cp "$AMNEZIAWG_DIR/params" "$BT_DIR/params"
    printf "AWG_BACKEND='boringtun'\n" >>"$BT_DIR/params"
    cp "$SERVER_AWG_CONF" "$BT_DIR/awg0.conf"
    AMNEZIAWG_DIR="$BT_DIR"
    if validateParamsFile 0 >/dev/null 2>&1; then exit 19; fi
)

# 2. Validation, --backend-status, and changeAwgProtocolInteractively.
validateParamsFile 0
[[ "$AWG_PROTOCOL_VERSION" == 1 ]]
[[ "$(awgProtocolDisplayName "$AWG_PROTOCOL_VERSION")" == 1.0 ]]
printBackendStatus >"$AMNEZIAWG_DIR/backend-status.txt"
grep -qx 'backend=kernel' "$AMNEZIAWG_DIR/backend-status.txt"
grep -qx 'awg_protocol=1.0' "$AMNEZIAWG_DIR/backend-status.txt"
if changeAwgProtocolInteractively >"$AMNEZIAWG_DIR/menu.out" 2>&1 </dev/null; then exit 24; fi
grep -q 'AmneziaWG 1.0 must be migrated to AWG 2.0' "$AMNEZIAWG_DIR/menu.out"

if (AWG_BACKEND=boringtun validatePersistedAwgProtocolState) 2>/dev/null; then exit 20; fi
if (SERVER_AWG_S3=15 validatePersistedAwgProtocolState) 2>/dev/null; then exit 21; fi
if (SERVER_AWG_H1=5-10 validatePersistedAwgProtocolState) 2>/dev/null; then exit 22; fi
if (AWG_HEADER_PROTECTION_KEY="$SERVER_PUB_KEY" validatePersistedAwgProtocolState) 2>/dev/null; then exit 23; fi

# 3. Protocol mode changes (--enable-awg3, --enable-awg31, --disable-awg3) must refuse without mutating.
BEFORE="$(sha256sum "$AMNEZIAWG_DIR/params" "$SERVER_AWG_CONF")"
for target_mode in 2 3 3.1; do
    if setAwgProtocolMode "$target_mode" >"$AMNEZIAWG_DIR/out.$target_mode" 2>"$AMNEZIAWG_DIR/err.$target_mode"; then
        exit 30
    fi
    grep -q 'AmneziaWG 1.0.*AWG 2.0' "$AMNEZIAWG_DIR/err.$target_mode"
done
[[ "$(sha256sum "$AMNEZIAWG_DIR/params" "$SERVER_AWG_CONF")" == "$BEFORE" ]]

# 4. Non-interactive --list-clients, --add-client, --remove-client preserve AWG 1.0 (even with AUTO_INSTALL=y / EOF).
PARAMS_BEFORE="$(sha256sum "$AMNEZIAWG_DIR/params")"
LISTED="$(AUTO_INSTALL=y nonInteractiveListClients </dev/null)"
[[ "$LISTED" == phone ]]
ADDED_PATH="$(AUTO_INSTALL=y nonInteractiveAddClient laptop </dev/null)"
[[ "$ADDED_PATH" == "$AMNEZIAWG_DIR/clients/awg0-client-laptop.conf" ]]
[[ -f "$ADDED_PATH" ]]
! grep -q '^S3 =' "$ADDED_PATH"
! grep -q '^S4 =' "$ADDED_PATH"
grep -q '^S2 = 150$' "$ADDED_PATH"
grep -q '^H1 = 1805140871$' "$ADDED_PATH"
[[ "$(nonInteractiveListClients </dev/null | tr '\n' ' ')" == "phone laptop " ]]
REMOVED="$(AUTO_INSTALL=y nonInteractiveRemoveClient laptop </dev/null)"
[[ "$REMOVED" == OK ]]
[[ ! -e "$ADDED_PATH" ]]
[[ "$(nonInteractiveListClients </dev/null)" == phone ]]
[[ "$(sha256sum "$AMNEZIAWG_DIR/params")" == "$PARAMS_BEFORE" ]]
! grep -q '^S3 =' "$SERVER_AWG_CONF"
! grep -q '^S4 =' "$SERVER_AWG_CONF"

# 4b. AWG 2.0 with missing S3/S4 must fail closed in nonInteractiveAddClient (never emit empty S3 =).
(
    BAD2="$AMNEZIAWG_DIR/bad-v2"
    mkdir -p "$BAD2"
    grep -v '^AWG_PROTOCOL_VERSION=' "$AMNEZIAWG_DIR/params" >"$BAD2/params"
    printf "AWG_PROTOCOL_VERSION='2'\n" >>"$BAD2/params"
    cp "$SERVER_AWG_CONF" "$BAD2/awg0.conf"
    AMNEZIAWG_DIR="$BAD2"
    if nonInteractiveAddClient broken >"$BAD2/out" 2>"$BAD2/err" </dev/null; then exit 35; fi
    grep -q 'SERVER_AWG_S3 and SERVER_AWG_S4 must be set' "$BAD2/err"
    [[ ! -e "$BAD2/clients/awg0-client-broken.conf" ]]
)

# 5. Interactive AWG 1.0 -> 2.0 migration must promote AWG_PROTOCOL_VERSION to 2.
# (loadParams/migrateS3S4 are part of the non-errexit installer path.)
AUTO_INSTALL=y
set +e +o pipefail
loadParams 0 0 >"$AMNEZIAWG_DIR/migrate.out" 2>"$AMNEZIAWG_DIR/migrate.err"
RC=$?
set -euo pipefail
[[ "$RC" -eq 0 ]] || { cat "$AMNEZIAWG_DIR/migrate.out" "$AMNEZIAWG_DIR/migrate.err" >&2; exit 40; }
[[ "$AWG_PROTOCOL_VERSION" == 2 ]]
grep -q "^AWG_PROTOCOL_VERSION='2'$" "$AMNEZIAWG_DIR/params"
grep -q "^S3 = " "$SERVER_AWG_CONF"
grep -q "^S4 = " "$SERVER_AWG_CONF"
'''
                result = subprocess.run(
                    ['bash', '-c', shell, 'awg1-guard', str(SCRIPT), str(target), PEER, PUB],
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_awg1_cli_refuses_active_server_padding_before_profile_or_migration(self):
        files = self.legacy_fixture(proxy=False)
        shell = r'''
set -uo pipefail
source "$1"
AMNEZIAWG_DIR="$2"
SERVER_AWG_CONF="$AMNEZIAWG_DIR/stale.conf"
TEST_KEY="$4"
acquireClientLifecycleLock() { return 0; }
releaseClientLifecycleLock() { return 0; }
ensureAwgBackendReady() { return 0; }
awgSyncInterfaceConfig() { return 0; }
copyToWebPanelDir() { return 0; }
awg() {
    : >"$AMNEZIAWG_DIR/keygen-called"
    printf '%s\n' "$TEST_KEY"
}
stat() {
    if [[ "$2" == %u ]]; then printf '0\n'; else command stat "$@"; fi
}
AUTO_INSTALL=n
case "$3" in
    add) nonInteractiveAddClient laptop ;;
    menu) loadParamsForManagementMenu ;;
    action)
        create_client() { : >"$AMNEZIAWG_DIR/creation-called"; }
        if runLockedManagementOperation create_client; then exit 0; else exit 1; fi
        ;;
esac
'''
        for protocol, extra_params in (('inferred', b''), ('explicit', b"AWG_PROTOCOL_VERSION='1'\n")):
            for field, line in (('s3', b'S3 = 15\n'), ('s4', b'  s\t4 = 0 # active zero\n')):
                for entrypoint in ('add', 'menu', 'action'):
                    with self.subTest(protocol=protocol, field=field, entrypoint=entrypoint):
                        target = self.root / f'{protocol}-{field}-{entrypoint}'
                        target.mkdir()
                        params = target / 'params'
                        config = target / 'awg0.conf'
                        before_params = files['vpn/params'] + extra_params
                        before_config = files['vpn/server.conf'].replace(b'S2 = 150\n', b'S2 = 150\n' + line)
                        params.write_bytes(before_params)
                        params.chmod(0o600)
                        config.write_bytes(before_config)
                        result = subprocess.run(
                            ['bash', '-c', shell, 'awg1-conflict', str(SCRIPT), str(target), entrypoint, PUB],
                            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
                        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertIn('AmneziaWG 1.0', result.stderr)
                        self.assertIn(field.upper(), result.stderr)
                        self.assertNotIn(KEY, result.stderr)
                        self.assertEqual(params.read_bytes(), before_params)
                        self.assertEqual(config.read_bytes(), before_config)
                        self.assertEqual(sorted(p.name for p in target.iterdir()), ['awg0.conf', 'params'])

if __name__ == '__main__':
    unittest.main(verbosity=2)
