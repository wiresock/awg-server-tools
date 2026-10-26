#!/usr/bin/env python3
"""Behavioral regressions for complete, provenance-bound distribution notices."""
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NoticeChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("notices", ROOT / "scripts/boringtun-notices.py")
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / "config"
        self.config.mkdir()
        for name in ["notice-policy.json", "runtime-notices.txt", "fork-license.txt"]:
            (self.config / name).write_bytes((ROOT / "packaging/boringtun" / name).read_bytes())
        macos = ROOT / "packaging/boringtun/runtime-notices-macos.txt"
        if macos.exists():
            (self.config / macos.name).write_bytes(macos.read_bytes())
        self.third = self.root / "THIRD-PARTY-LICENSES"
        self.license = self.root / "LICENSE"
        self.third.write_bytes(b"THIRD-PARTY LICENSES FOR boringtun-cli\n\n" + (self.config / "runtime-notices.txt").read_bytes())
        self.license.write_bytes((self.config / "fork-license.txt").read_bytes())

    def check(self):
        self.module.check_files(self.config, "1.98.1", self.third, self.license)

    def test_complete_notices_pass(self):
        self.check()

    def test_removing_each_runtime_license_section_fails(self):
        original = self.third.read_bytes()
        # Delete each verbatim source-text section individually, keeping other
        # copyright strings. Full terms, not keyword presence, must be checked.
        sections = original.split(b"=" * 80 + b"\n")
        for index in range(1, min(46, len(sections))):
            with self.subTest(index=index):
                self.third.write_bytes((b"=" * 80 + b"\n").join(sections[:index] + sections[index + 1:]))
                with self.assertRaisesRegex(ValueError, "runtime notice bundle"):
                    self.check()

    def test_terms_tampering_and_duplicate_bundle_fail(self):
        original = self.third.read_bytes()
        for content in [original.replace(b"Permission is hereby granted", b"Permission has been removed", 1),
                        original + (self.config / "runtime-notices.txt").read_bytes()]:
            self.third.write_bytes(content)
            with self.assertRaisesRegex(ValueError, "runtime notice bundle"):
                self.check()

    def test_missing_fork_and_upstream_notices_or_terms_fail(self):
        original = self.license.read_bytes()
        for needle in [b"Copyright (c) 2019 Cloudflare, Inc. All rights reserved.",
                       b"Vadim Smirnov (doing business as WireSock)",
                       b"Redistribution and use in source and binary forms"]:
            with self.subTest(needle=needle):
                self.license.write_bytes(original.replace(needle, b"", 1))
                with self.assertRaisesRegex(ValueError, "fork LICENSE"):
                    self.check()

    def test_bundle_tampering_fails_even_if_archive_has_same_tamper(self):
        bundle = self.config / "runtime-notices.txt"
        bundle.write_bytes(bundle.read_bytes() + b"tampered\n")
        self.third.write_bytes(bundle.read_bytes())
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.check()

    def test_different_toolchain_requires_review(self):
        with self.assertRaisesRegex(ValueError, "toolchain"):
            self.module.check_files(self.config, "1.99.0", self.third, self.license)

    def test_missing_and_symlinked_inputs_fail(self):
        for path in [self.third, self.license, self.config / "runtime-notices.txt"]:
            original = path.read_bytes()
            path.unlink()
            with self.assertRaises(ValueError):
                self.check()
            target = self.root / "link-target"
            target.write_bytes(original)
            try:
                path.symlink_to(target)
            except OSError:
                path.write_bytes(original)
                continue
            with self.assertRaises(ValueError):
                self.check()
            path.unlink()
            path.write_bytes(original)

    def test_unreviewed_source_lock_fails(self):
        source = self.root / "source"
        source.mkdir()
        (source / "LICENSE.md").write_bytes(self.license.read_bytes())
        (source / "Cargo.lock").write_text("unreviewed native dependency graph\n")
        with self.assertRaisesRegex(ValueError, "Cargo.lock"):
            self.module.check_source(self.config, "1.98.1", source)

    def test_unknown_policy_fields_and_empty_lock_allowlist_fail(self):
        policy = self.config / "notice-policy.json"
        original = json.loads(policy.read_text())
        for data in [dict(original, unexpected=True), dict(original, source_lock_sha256=[])]:
            policy.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                self.check()

    def test_all_five_targets_select_the_reviewed_profile(self):
        for target in ["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl", "armv7-unknown-linux-musleabihf",
                       "aarch64-apple-darwin", "x86_64-apple-darwin"]:
            with self.subTest(target=target):
                _, bundle, _ = self.module.policy(self.config, "1.98.1", target)
                self.third.write_bytes(b"THIRD-PARTY LICENSES FOR boringtun-cli\n\n" + bundle)
                self.module.check_files(self.config, "1.98.1", self.third, self.license, target)

    def test_macos_does_not_accept_linux_musl_bundle(self):
        with self.assertRaisesRegex(ValueError, "runtime notice bundle"):
            self.module.check_files(self.config, "1.98.1", self.third, self.license, "aarch64-apple-darwin")
        _, macos, _ = self.module.policy(self.config, "1.98.1", "x86_64-apple-darwin")
        self.third.write_bytes(b"THIRD-PARTY LICENSES FOR boringtun-cli\n\n" + macos)
        with self.assertRaisesRegex(ValueError, "runtime notice bundle"):
            self.check()

    def test_unreviewed_target_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "target"):
            self.module.policy(self.config, "1.98.1", "arm-unknown-linux-musleabihf")

    def test_profile_mapping_is_exact_not_an_arbitrary_allowlist(self):
        path = self.config / "notice-policy.json"
        data = json.loads(path.read_text())
        data["profiles"]["macos-system"]["targets"].append("arm-unknown-linux-musleabihf")
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "profile"):
            self.check()

    def runtime_fixture(self):
        target = "armv7-unknown-linux-musleabihf"
        sysroot = self.root / "sysroot"
        name = target + "/lib/self-contained/libc.a"
        obj = sysroot / "lib/rustlib" / name
        obj.parent.mkdir(parents=True)
        obj.write_bytes(b"pinned runtime object")
        data = {"rust_toolchain": "1.98.1", "target_objects": {target: [name]},
                "target_object_sha256": {target: {name: hashlib.sha256(obj.read_bytes()).hexdigest()}}}
        path = self.config / "runtime-provenance.json"
        path.write_text(json.dumps(data))
        return target, sysroot, obj, path, data

    def test_installed_runtime_matches_distribution_bytes(self):
        target, sysroot, obj, _, _ = self.runtime_fixture()
        self.module.check_runtime(self.config, "1.98.1", sysroot, target)
        obj.write_bytes(b"modified runtime object")
        with self.assertRaisesRegex(ValueError, "pinned distribution"):
            self.module.check_runtime(self.config, "1.98.1", sysroot, target)
        obj.unlink()
        with self.assertRaises(ValueError):
            self.module.check_runtime(self.config, "1.98.1", sysroot, target)

    def test_runtime_inventory_cannot_omit_or_add_objects(self):
        target, sysroot, obj, path, data = self.runtime_fixture()
        data["target_objects"][target].append(target + "/lib/missing.rlib")
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "inventory"):
            self.module.check_runtime(self.config, "1.98.1", sysroot, target)
        data["target_objects"][target].pop()
        path.write_text(json.dumps(data))
        obj.with_name("unexpected.o").write_bytes(b"unreviewed runtime")
        with self.assertRaisesRegex(ValueError, "inventory"):
            self.module.check_runtime(self.config, "1.98.1", sysroot, target)

    def test_runtime_inventory_rejects_linked_parent_directory(self):
        target, sysroot, obj, _, _ = self.runtime_fixture()
        parent = obj.parent
        moved = self.root / "redirected"
        parent.rename(moved)
        try:
            parent.symlink_to(moved, target_is_directory=True)
        except OSError as error:
            self.skipTest(str(error))
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.module.check_runtime(self.config, "1.98.1", sysroot, target)


if __name__ == "__main__":
    unittest.main()
