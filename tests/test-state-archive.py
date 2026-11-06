#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Vadim Smirnov (doing business as WireSock)
# SPDX-License-Identifier: MIT
"""Untrusted archive tests; no root, VPN, package manager or network required."""
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
    return dict(schema_version=1, backend='kernel', protocol='2', interface='awg0',
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
                with sqlite3.connect(dest / 'web/database.sqlite') as db:
                    db.execute('CREATE TABLE peers(public_key TEXT, disabled INTEGER, archived INTEGER, expires_at TEXT)')
                    db.execute('INSERT INTO peers VALUES(?,?,?,?)', (PEER, disabled, archived, expiry))
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
        with sqlite3.connect(dest / 'web/database.sqlite') as db:
            db.execute('CREATE TABLE peers(public_key TEXT, disabled INTEGER, archived INTEGER, expires_at TEXT)')
            db.execute('INSERT INTO peers VALUES(?,1,0,NULL)', (PEER,))
        self.run_helper('prepare', dest)
        clean = (dest / 'interface.conf').read_text() + (dest / 'peers.conf').read_text()
        self.assertNotIn('### Client phone', clean)
        self.assertIn('### Client tablet', clean)
        self.assertIn(other, clean)
        self.assertNotIn(PEER, clean)

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
awgStateCommand --import-state "$ROOT/state.tar.gz" --dry-run || exit 10
[[ ! -e "$AMNEZIAWG_DIR" && ! -e "$AWG_STATE_JOURNAL_DIR" && ! -e "$ROOT/install.log" ]] || exit 11
[[ "$(<"$AWG_SYSCTL_FILE")" == 'original sysctl' ]] || exit 12
FAIL_INSTALL=1
awgStateCommand --import-state "$ROOT/state.tar.gz"
[[ $? -ne 0 ]] || exit 13
[[ ! -e "$AMNEZIAWG_DIR" && ! -e "$AWG_SYSTEMD_UNIT_DIR/awg-quick@awg0.service.d" ]] || exit 14
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

    def test_invalid_arguments_never_enter_interactive_install(self):
        for args in (['--export-state'], ['--inspect-state', 'x', '--dry-run'],
                     ['--import-state', 'x', '--unknown'], ['--import-state', '--dry-run']):
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
