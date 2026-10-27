#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Vadim Smirnov (doing business as WireSock)
# SPDX-License-Identifier: MIT
"""Run deployment functions against disposable paths, never the host service."""
import os
import json
from pathlib import Path
import pwd
import re
import shlex
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "amneziawg-web/scripts/amneziawg-web-install.sh"
FUNCTIONS = "\n".join(re.findall(r"^\w+\(\) \{\n.*?^\}", INSTALLER.read_text(), re.M | re.S))


class PrivateStorage(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="awg-web-storage-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / "data"
        self.unit = self.root / "web.service"

    def run_installer(self, body):
        values = {
            "FIXTURE": str(self.root), "SERVICE_USER": pwd.getpwuid(os.getuid()).pw_name,
            "DATA_DIR": str(self.data), "ENV_DIR": str(self.root / "env"),
            "ENV_FILE": str(self.root / "env/env.conf"),
            "AWG_CONFIG_DIR": str(self.root / "clients"),
            "DEFAULT_AWG_CONFIG_DIR": str(self.root / "clients"),
            "AWG_DETECTED_HOME_DIR": "", "FORCE": "false",
            "SYSTEMD_UNIT_DEST": str(self.unit), "SERVICE_NAME": "amneziawg-web",
            "INSTALL_DIR": str(self.root / "bin"), "SCRIPT_DIR": str(INSTALLER.parent),
        }
        script = "set -euo pipefail\n" + FUNCTIONS + "\n"
        script += "\n".join(f"{k}={shlex.quote(v)}" for k, v in values.items())
        # The fixture owns its files; privileged operations cannot escape it.
        script += r'''
info() { :; }
step() { :; }
warn() { printf '%s\n' "$*"; }
die() { printf '%s\n' "$*" >&2; exit 1; }
chown() { [[ "${@: -1}" == "$FIXTURE/"* ]]; }
chmod() { [[ "${@: -1}" == "$FIXTURE/"* ]] && command chmod "$@"; }
setfacl() { return 1; }
systemctl() { [[ "$*" == daemon-reload ]]; }
'''
        result = subprocess.run(["bash"], input=script + body, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def test_new_and_existing_data_directory_is_private(self):
        for existing in (False, True):
            with self.subTest(existing=existing):
                if existing:
                    self.data.chmod(0o750)
                self.run_installer("setup_filesystem\n")
                self.assertEqual(stat.S_IMODE(self.data.stat().st_mode), 0o700)

    def test_packaged_inline_and_preserved_units_create_private_sqlite_files(self):
        for source in ("packaged", "inline", "preserved", "preserved-spaced"):
            with self.subTest(source=source):
                self.unit.unlink(missing_ok=True)
                if source.startswith("preserved"):
                    setting = " UMask = 0022 " if source.endswith("spaced") else "UMask=0022"
                    self.unit.write_text(f"[Service]\nExecStart=/fixture/web\n{setting}\n")
                body = ""
                if source == "inline":
                    body = "find_unit_template() { return 1; }\n"
                self.run_installer(body + "install_service_unit\n")
                masks = re.findall(r"^[ \t]*UMask[ \t]*=[ \t]*(\d+)[ \t]*$", self.unit.read_text(), re.M)
                mask = masks[-1] if masks else "0022"
                # SQLite creates WAL/SHM using the DB mode. Exercise actual
                # SQLite writes under the effective unit mask, not source text.
                directory = self.root / source
                directory.mkdir(mode=0o700)
                probe = '''import os, sqlite3, stat, sys
os.umask(int(sys.argv[2], 8))
db = sqlite3.connect(sys.argv[1])
db.execute("pragma journal_mode=wal")
db.execute("create table fixture(value text)")
db.execute("insert into fixture values ('fixture-only')")
db.commit()
for suffix in ('', '-wal', '-shm'):
    assert stat.S_IMODE(os.stat(sys.argv[1]+suffix).st_mode) == 0o600, suffix or 'database'
'''
                result = subprocess.run(["python3", "-c", probe, str(directory / "panel.db"), mask], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_reinstall_leaves_existing_database_and_sidecars_for_offline_repair(self):
        self.data.mkdir(mode=0o750)
        for suffix in ("", "-wal", "-shm", "-journal"):
            path = self.data / ("awg-web.db" + suffix)
            path.write_bytes(b"fixture-only")
            path.chmod(0o640)
        self.run_installer("setup_filesystem\n")
        for path in self.data.iterdir():
            self.assertEqual(path.read_bytes(), b"fixture-only")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)

    def test_docker_default_directory_and_launch_mask_are_private(self):
        dockerfile = (ROOT / "amneziawg-web/Dockerfile").read_text()
        directory_command = next(line[4:] for line in dockerfile.splitlines() if line.startswith("RUN ") and "/data" in line)
        directory_command = directory_command.replace("/data", shlex.quote(str(self.data)))
        directory_command = directory_command.replace("awg-web:awg-web", f"{os.getuid()}:{os.getgid()}")
        directory_command = directory_command.replace("-o awg-web", f"-o {os.getuid()}").replace("-g awg-web", f"-g {os.getgid()}")
        subprocess.run(["bash", "-c", "umask 022; " + directory_command], check=True)
        self.assertEqual(stat.S_IMODE(self.data.stat().st_mode), 0o700)
        entrypoint = json.loads(next(line[len("ENTRYPOINT "):] for line in dockerfile.splitlines() if line.startswith("ENTRYPOINT ")))
        # Substitute only the application executable: observe the real launch
        # wrapper's umask, argument forwarding and exit status without a server.
        probe = self.root / "probe"
        probe.write_text('#!/bin/sh\numask\nprintf "%s\\n" "$@"\nexit 17\n')
        probe.chmod(0o700)
        entrypoint = [arg.replace("/usr/local/bin/amneziawg-web", str(probe)) for arg in entrypoint]
        result = subprocess.run(entrypoint + ["one argument", "--version"], capture_output=True, text=True, umask=0o022)
        self.assertEqual(result.returncode, 17)
        self.assertEqual(result.stdout.splitlines(), ["0077", "one argument", "--version"])


if __name__ == "__main__":
    unittest.main()
