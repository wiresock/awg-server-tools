"""Pinned Bash source and version gates; no network or compiler invocation."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/boringtun-bash.py"
module = None
if SCRIPT.exists():
    spec = importlib.util.spec_from_file_location("bta_bash", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)


class BashToolchainTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(module, "pinned Bash installer is missing")
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT / "tests")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_policy_pins_source_and_twenty_ordered_patches(self):
        policy = module.read_policy()
        self.assertEqual(policy["version"], "5.3.20")
        self.assertEqual(len(policy["patches"]), 20)
        bad = dict(policy, patches=list(reversed(policy["patches"])))
        with self.assertRaises(ValueError):
            module.validate_policy(bad)
        with self.assertRaises(ValueError):
            module.validate_policy(dict(policy, extra=True))

    def test_mismatched_download_never_creates_input(self):
        entry = {"url": "https://ftp.gnu.org/gnu/bash/bash-5.3.tar.gz", "sha256": "a" * 64}
        target = self.root / "source.tar.gz"
        with patch.object(module.urllib.request, "urlopen", return_value=io.BytesIO(b"corrupt")):
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                module.verified_download(entry, target)
        self.assertFalse(target.exists())

    def test_verified_download_is_exact_and_cannot_overwrite(self):
        data = b"checked source input"
        entry = {"url": "https://ftp.gnu.org/gnu/bash/bash-5.3.tar.gz",
                 "sha256": hashlib.sha256(data).hexdigest()}
        target = self.root / "source.tar.gz"
        with patch.object(module.urllib.request, "urlopen", return_value=io.BytesIO(data)):
            module.verified_download(entry, target)
        self.assertEqual(target.read_bytes(), data)
        with self.assertRaises((ValueError, FileExistsError)):
            module.verified_download(entry, target)
        self.assertEqual(target.read_bytes(), data)

    def test_banner_and_internal_version_must_both_match(self):
        binary = self.root / "bash"
        binary.write_bytes(b"fixture shell")
        banner = "GNU bash, version 5.3.20(1)-release (aarch64-apple-darwin24.6.0)"
        for outputs in ((banner, "5.3.15(1)-release"),
                        (banner.replace("5.3.20", "5.3.15"), "5.3.20(1)-release"),
                        (banner, "5.3.200(1)-release")):
            with self.subTest(outputs=outputs), patch.object(module, "tool_output", side_effect=outputs):
                with self.assertRaises(ValueError):
                    module.verify_shell(binary)
        with patch.object(module, "tool_output", side_effect=(banner, "5.3.20(1)-release")):
            self.assertEqual(module.verify_shell(binary), {"banner": banner, "internal_version": "5.3.20(1)-release"})

    def test_source_extraction_rejects_traversal(self):
        archive = self.root / "source.tar.gz"
        with tarfile.open(archive, "w:gz") as handle:
            member = tarfile.TarInfo("../outside")
            member.size = 1
            handle.addfile(member, io.BytesIO(b"x"))
        destination = self.root / "source"
        destination.mkdir()
        with self.assertRaises(ValueError):
            module.extract_source(archive, destination)
        self.assertFalse((self.root / "outside").exists())

    def test_install_destination_must_be_new_and_under_runner_temp(self):
        runner = self.root / "runner"
        runner.mkdir()
        with patch.dict(os.environ, {"RUNNER_TEMP": str(runner)}):
            with self.assertRaises(ValueError):
                module.install_destination(self.root / "outside")
            existing = runner / "existing"
            existing.mkdir()
            with self.assertRaises(ValueError):
                module.install_destination(existing)
            self.assertEqual(module.install_destination(runner / "new"), (runner / "new").resolve())

    def test_receipt_rejects_changed_binary_or_source_manifest(self):
        binary = self.root / "bin/bash"
        binary.parent.mkdir()
        binary.write_bytes(b"changed binary")
        policy = module.read_policy()
        versions = {"banner": "GNU bash, version 5.3.20(1)-release (aarch64-apple-darwin24.6.0)",
                    "internal_version": "5.3.20(1)-release"}
        record = {"schema": 1, "version": "5.3.20", "source_manifest_sha256": module.digest(module.canonical(policy)),
                  "source_inputs": [policy["source"], *policy["patches"]], "configure_options": module.OPTIONS,
                  "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                  "xcode": "16.4", "xcode_build": "16F6", "sdk": "15.5", "deployment_target": "11.0",
                  "compiler": {"path": module.DEVELOPER + "/usr/bin/clang", "sha256": "c" * 64}, **versions}
        receipt = self.root / "BASH-TOOLCHAIN.json"
        receipt.write_text(json.dumps(record))
        with patch.object(module, "verify_shell", return_value=versions):
            self.assertEqual(module.verify_install(binary), record)
            for change in ({"binary_sha256": "b" * 64}, {"source_manifest_sha256": "a" * 64},
                           {"schema": True}, {"extra": "unknown"}):
                receipt.write_text(json.dumps(dict(record, **change)))
                with self.subTest(change=change), self.assertRaises(ValueError):
                    module.verify_install(binary)


if __name__ == "__main__":
    unittest.main()
