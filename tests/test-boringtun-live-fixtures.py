"""Offline checks of live-test fixtures; no root, binary execution or daemon."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
LIVE = (ROOT / 'tests/test-boringtun-host-live.sh').read_text()


class LiveFixtures(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)

    def run_bash(self, script, *arguments):
        return subprocess.run(['bash', '-c', script, '_', *map(str, arguments)],
                              capture_output=True, text=True)

    def live_identity(self, build, arch):
        # Exercise the live script's actual constant projection without its
        # root-only setup, installation or private configuration access.
        start = LIVE.index('RELEASE_TAG="$(installer_value AWG_BT_RELEASE_TAG)"')
        end = LIVE.index('STORE="', start)
        installer = (ROOT / 'amneziawg-install.sh').read_text()
        installer = re.sub(r'(-b)[0-9]+"$', rf'\g<1>{build}"', installer, flags=re.M)
        installer = re.sub(r'^AWG_BT_RELEASE_BUILD="[0-9]+"$',
                           f'AWG_BT_RELEASE_BUILD="{build}"', installer, flags=re.M)
        fixture = self.path / 'installer.sh'
        fixture.write_text(installer)
        script = '''set -euo pipefail
INSTALLER="$1" ARCH="$2" ARCH_KEY="${2^^}"
installer_value() { sed -n "s/^$1=\\\"\\(.*\\)\\\"$/\\1/p" "$INSTALLER"; }
'''
        result = self.run_bash(script + LIVE[start:end] + '\nprintf "%s\\n" "$RELEASE_ID" "$ASSET"', fixture, arch)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.splitlines()

    def test_current_build101_identity_for_both_native_linux_lanes(self):
        for arch in ('x86_64', 'aarch64'):
            with self.subTest(arch=arch):
                store, asset = self.live_identity(101, arch)
                self.assertEqual(store, f'boringtun-cli-0.7.1-ga92909c49920-b101-linux-{arch}-musl')
                self.assertEqual(asset, f'boringtun-cli-0.7.1-ga92909c49920-linux-{arch}-musl.tar.gz')

    def test_build1_preserves_original_archive_store_identity(self):
        store, asset = self.live_identity(1, 'x86_64')
        self.assertEqual(store, asset.removesuffix('.tar.gz'))

    def build2(self, build):
        pin = 'boringtun-cli-0.7.1-g111111111111' + (f'-b{build}' if build != 1 else '') + '-linux-x86_64-musl'
        source = self.path / pin
        source.mkdir()
        for name in ('LICENSE', 'MANIFEST', 'THIRD-PARTY-LICENSES', 'boringtun-cli'):
            (source / name).write_text('fixture bytes: ' + name)
        # Ownership requires root in the real disposable runner. This fixture
        # tests only naming, copies and no-overwrite behavior in a private dir.
        script = 'source "$1"; chown() { :; }; bt_fixture_build2 "$2" "$3"'
        result = self.run_bash(script, ROOT/'tests/helpers/boringtun-lifecycle-fixture.sh', self.path, pin)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'boringtun-cli-0.7.1-g111111111111-b2-linux-x86_64-musl')
        target = self.path / result.stdout.strip()
        for name in ('LICENSE', 'MANIFEST', 'THIRD-PARTY-LICENSES', 'boringtun-cli'):
            self.assertEqual((source/name).read_bytes(), (target/name).read_bytes())
        (target/'LICENSE').write_text('existing target must stay')
        repeat = self.run_bash(script, ROOT/'tests/helpers/boringtun-lifecycle-fixture.sh', self.path, pin)
        self.assertNotEqual(repeat.returncode, 0)
        self.assertEqual((target/'LICENSE').read_text(), 'existing target must stay')

    def test_build2_fixture_from_original_build1(self):
        self.build2(1)

    def test_build2_fixture_from_adopted_build101(self):
        self.build2(101)

    def test_fixture_installer_rewrites_adopted_build(self):
        line = next(line.strip() for line in LIVE.splitlines() if line.startswith('\tsed ') and 'AWG_BT_RELEASE_BUILD=' in line)
        source = self.path/'installer.sh'
        source.write_text('AWG_BT_RELEASE_BUILD="101"\n')
        target = self.path/'build2.sh'
        result = self.run_bash('INSTALLER="$1" B2_INSTALLER="$2"; ' + line, source, target)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(target.read_text(), 'AWG_BT_RELEASE_BUILD="2"\n')


if __name__ == '__main__':
    unittest.main()
