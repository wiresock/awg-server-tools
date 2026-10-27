"""Offline regressions for the anonymous public-download check, not signatures."""
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("adoption_fixtures", ROOT / "tests/test-boringtun-adopt.py")
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


class PublicContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.gh = fixtures.FakeGitHub()
        self.installer = (ROOT / "amneziawg-install.sh").read_text()
        patch = fixtures.adopt.installer_patch(self.installer, self.gh.descriptor)
        for added in (line[1:] for line in patch.splitlines() if line.startswith('+AWG_BT_RELEASE_')):
            key = added.split('=', 1)[0]
            self.installer = '\n'.join(added if line.startswith(key + '=') else line for line in self.installer.split('\n'))
        self.bin = self.path / 'bin'
        self.bin.mkdir()
        curl = self.bin / 'curl'
        curl.write_text('''#!/usr/bin/env python3
import os, pathlib, shutil, sys
from urllib.parse import urlsplit
args = sys.argv[1:]
source = pathlib.Path(os.environ['PUBLIC_FIXTURES']) / pathlib.PurePosixPath(urlsplit(args[-1]).path).name
if not source.is_file():
    sys.exit(22)
shutil.copyfile(source, args[args.index('-o') + 1])
''')
        curl.chmod(0o755)

    def run_check(self, success):
        assets = self.path / 'assets'
        assets.mkdir()
        for name, data in self.gh.files.items():
            (assets / name).write_bytes(data)
        installer = self.path / 'installer.sh'
        installer.write_text(self.installer)
        env = dict(os.environ, PATH=str(self.bin) + ':' + os.environ['PATH'], PUBLIC_FIXTURES=str(assets))
        result = subprocess.run(['bash', str(ROOT / 'tests/test-boringtun-public-release.sh'), str(installer)],
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)

    def test_five_platform_fork_release(self):
        self.run_check(True)

    def test_legacy_two_platform_release(self):
        self.installer = self.installer.replace('Wiresock-Foundation/wiresock-boringtun/releases/download',
                                                'wiresock/awg-server-tools/releases/download')
        for key in ('ASSET', 'ARCHIVE_SHA256', 'BINARY_SHA256'):
            self.installer = '\n'.join(f'AWG_BT_RELEASE_{key}_ARMV7=""' if line.startswith(f'AWG_BT_RELEASE_{key}_ARMV7=') else line for line in self.installer.split('\n'))
        entries = [item for item in self.gh.descriptor['archives'] if item['target'] in
                   ('x86_64-unknown-linux-musl', 'aarch64-unknown-linux-musl')]
        self.gh.files = {item['name']: self.gh.files[item['name']] for item in entries}
        self.gh.files['SHA256SUMS'] = ''.join(f"{item['sha256']}  {item['name']}\n" for item in sorted(entries, key=lambda i:i['name'])).encode()
        self.run_check(True)

    def test_missing_checksum_entry(self):
        self.gh.files['SHA256SUMS'] = b'\n'.join(self.gh.files['SHA256SUMS'].split(b'\n')[1:])
        self.run_check(False)

    def test_extra_checksum_entry(self):
        self.gh.files['SHA256SUMS'] += b'0' * 64 + b'  extra.tar.gz\n'
        self.run_check(False)

    def test_changed_checksum(self):
        self.gh.files['SHA256SUMS'] = b'0' * 64 + self.gh.files['SHA256SUMS'][64:]
        self.run_check(False)

    def test_wrong_descriptor_source(self):
        self.gh.descriptor['source_commit'] = 'd' * 40
        self.gh.files['RELEASE.json'] = fixtures.json.dumps(self.gh.descriptor).encode()
        self.run_check(False)

    def test_missing_descriptor(self):
        del self.gh.files['RELEASE.json']
        self.run_check(False)

    def test_missing_platform(self):
        self.gh.descriptor['archives'].pop(0)
        self.gh.files['RELEASE.json'] = fixtures.json.dumps(self.gh.descriptor).encode()
        self.run_check(False)

    def test_missing_macos_download(self):
        del self.gh.files[self.gh.descriptor['archives'][0]['name']]
        self.run_check(False)

    def test_changed_macos_download(self):
        self.gh.files[self.gh.descriptor['archives'][0]['name']] += b'changed'
        self.run_check(False)

    def test_changed_armv7_binary_pin(self):
        self.installer = '\n'.join('AWG_BT_RELEASE_BINARY_SHA256_ARMV7="' + '9' * 64 + '"' if line.startswith('AWG_BT_RELEASE_BINARY_SHA256_ARMV7=') else line for line in self.installer.split('\n'))
        self.run_check(False)

    def check_binary(self, changed=False, clear_pin=False):
        item = next(item for item in self.gh.descriptor['archives'] if item['target'] == 'aarch64-unknown-linux-musl')
        with tarfile.open(fileobj=io.BytesIO(self.gh.files[item['name']]), mode='r:gz') as archive:
            data = archive.extractfile(item['name'][:-7] + '/boringtun-cli').read()
        binary = self.path / 'candidate'
        binary.write_bytes(data + (b'changed' if changed else b''))
        if clear_pin:
            self.installer = self.installer.replace(item['binary_sha256'], '0' * 64)
        installer = self.path / 'installer.sh'
        installer.write_text(self.installer)
        return subprocess.run(['bash', '-c', 'source "$1"; btc_embedded_binary_matches "$2" "$3"', '_',
                               str(ROOT / 'tests/helpers/boringtun-contracts.sh'), str(installer), str(binary)],
                              capture_output=True).returncode

    def test_candidate_binary_gate_uses_current_installer_pin(self):
        self.assertEqual(self.check_binary(), 0)

    def test_candidate_binary_gate_rejects_changed_bytes(self):
        self.assertEqual(self.check_binary(changed=True), 1)

    def test_candidate_binary_gate_rejects_unpinned_binary(self):
        self.assertEqual(self.check_binary(clear_pin=True), 1)


if __name__ == '__main__':
    unittest.main()
