#!/usr/bin/env python3
"""Binary-format tests. Hand-built objects test validation, not target execution."""
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/boringtun-platform.py"


def elf(bits=64, machine=62, flags=0, interp=False, needed=False):
    ident = b"\x7fELF" + bytes([1 if bits == 32 else 2, 1, 1]) + bytes(9)
    count = 1 + bool(interp) + bool(needed)
    if bits == 32:
        header = ident + struct.pack("<HHIIIIIHHHHHH", 2, machine, 1, 0x10100, 52, 0, flags, 52, 32, count, 0, 0, 0)
        ph = struct.pack("<IIIIIIII", 1, 0, 0x10000, 0x10000, 512, 512, 5, 0x1000)
        extra = lambda kind: struct.pack("<IIIIIIII", kind, 384, 0x10180, 0, 16, 16, 4, 4)
    else:
        header = ident + struct.pack("<HHIQQQIHHHHHH", 2, machine, 1, 0x40100, 64, 0, flags, 64, 56, count, 0, 0, 0)
        ph = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x40000, 0x40000, 512, 512, 0x1000)
        extra = lambda kind: struct.pack("<IIQQQQQQ", kind, 4, 384, 0x40180, 0, 32, 32, 8)
    data = bytearray((header + ph + (extra(3) if interp else b"") + (extra(2) if needed else b"")).ljust(512, b"\0"))
    if needed:
        data[384:384 + (8 if bits == 32 else 16)] = struct.pack("<II" if bits == 32 else "<QQ", 1, 1)
    return data


def string_command(cmd, text, dylib=False):
    offset = 24 if dylib else 12
    payload = text.encode() + b"\0"
    size = (offset + len(payload) + 7) & ~7
    return (struct.pack("<III", cmd, size, offset) + (bytes(12) if dylib else b"") + payload).ljust(size, b"\0")


def macho(arch="aarch64", dylib="/usr/lib/libSystem.B.dylib", minimum=0xB0000,
          platform=1, extra=b"", filetype=2):
    commands = [struct.pack("<II16sQQQQiiII", 0x19, 72, b"__TEXT", 0x100000000, 4096, 0, 512, 5, 5, 0, 0),
                struct.pack("<IIQQ", 0x80000028, 24, 448, 0),
                string_command(0xE, "/usr/lib/dyld"),
                string_command(0xC, dylib, True),
                struct.pack("<IIIIII", 0x32, 24, platform, minimum, 0xF0500, 0)]
    if extra:
        commands.append(extra)
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x100000C if arch == "aarch64" else 0x1000007,
                         0 if arch == "aarch64" else 3, filetype, len(commands), sum(map(len, commands)), 0x200000, 0)
    return bytearray((header + b"".join(commands)).ljust(512, b"\0"))


class PlatformTests(unittest.TestCase):
    def module(self):
        spec = importlib.util.spec_from_file_location("bta_platform", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_native_policy_rejects_wrong_clang_before_build(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as directory, patch.object(module.platform, "system", return_value="Linux"), \
                patch.object(module.shutil, "which", return_value=sys.executable), \
                patch.object(module, "tool_output", return_value="Ubuntu clang version 19.1.7"):
            with self.assertRaisesRegex(ValueError, "clang 18.1.3"):
                module.build_environment("armv7-unknown-linux-musleabihf", Path(directory))

    def test_macos_policy_requires_native_host(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as directory, patch.object(module.platform, "system", return_value="Linux"):
            with self.assertRaisesRegex(ValueError, "native macOS"):
                module.build_environment("aarch64-apple-darwin", Path(directory))

    def run_tool(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)], capture_output=True, text=True)

    def check(self, data, target, valid=True, error=None):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "binary"
            binary.write_bytes(data)
            result = self.run_tool("inspect", target, binary)
        if valid:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
            if error:
                self.assertIn(error, result.stderr)

    def test_five_exact_target_profiles(self):
        cases = {
            "x86_64-unknown-linux-musl": ["x86_64", "linux", "musl", "static", "linux-x86_64-musl"],
            "aarch64-unknown-linux-musl": ["aarch64", "linux", "musl", "static", "linux-aarch64-musl"],
            "armv7-unknown-linux-musleabihf": ["armv7", "linux", "musl", "static", "linux-armv7-musleabihf"],
            "x86_64-apple-darwin": ["x86_64", "macos", "libSystem", "dynamic-system", "macos-x86_64"],
            "aarch64-apple-darwin": ["aarch64", "macos", "libSystem", "dynamic-system", "macos-aarch64"],
        }
        for target, expected in cases.items():
            with self.subTest(target=target):
                result = self.run_tool("profile", target)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip().split("\t"), expected)
        self.assertNotEqual(self.run_tool("profile", "arm-unknown-linux-musleabihf").returncode, 0)

    def test_valid_linux_objects(self):
        self.check(elf(), "x86_64-unknown-linux-musl")
        self.check(elf(machine=183), "aarch64-unknown-linux-musl")
        self.check(elf(32, 40, 0x5000400), "armv7-unknown-linux-musleabihf")

    def test_elf_arch_class_endianness_and_file_type(self):
        self.check(elf(machine=183), "x86_64-unknown-linux-musl", False, "architecture")
        for offset, value in [(4, 1), (5, 2), (16, 1)]:
            data = elf(); data[offset] = value
            self.check(data, "x86_64-unknown-linux-musl", False)

    def test_arm_rejects_softfloat_or_wrong_eabi(self):
        for flags in [0x5000000, 0x5000200, 0x5000600, 0x4000400]:
            self.check(elf(32, 40, flags), "armv7-unknown-linux-musleabihf", False, "hard-float EABI5")

    def test_linux_rejects_runtime_dependencies(self):
        self.check(elf(interp=True), "x86_64-unknown-linux-musl", False, "program interpreter")
        self.check(elf(needed=True), "x86_64-unknown-linux-musl", False, "shared libraries")
        self.check(elf(32, 40, 0x5000400, needed=True), "armv7-unknown-linux-musleabihf", False, "shared libraries")

    def test_elf_rejects_truncated_tables_and_unmapped_entry(self):
        self.check(elf()[:80], "x86_64-unknown-linux-musl", False)
        data = elf(); struct.pack_into("<Q", data, 24, 0x999999)
        self.check(data, "x86_64-unknown-linux-musl", False, "entry")

    def test_macos_valid_both_architectures(self):
        for arch in ["aarch64", "x86_64"]:
            self.check(macho(arch), arch + "-apple-darwin")

    def test_macos_wrong_architecture_or_format(self):
        self.check(macho("x86_64"), "aarch64-apple-darwin", False, "architecture")
        self.check(elf(), "x86_64-apple-darwin", False, "Mach-O")
        self.check(macho(), "aarch64-unknown-linux-musl", False, "ELF")
        self.check(macho(filetype=6), "aarch64-apple-darwin", False, "executable")

    def test_macos_rejects_unsafe_dylibs(self):
        for name in ["@rpath/libSystem.B.dylib", "/tmp/libSystem.B.dylib", "/usr/local/lib/libfoo.dylib", "/usr/lib/libfoo.dylib"]:
            self.check(macho(dylib=name), "aarch64-apple-darwin", False, "system dylib")

    def test_macos_rejects_wrong_platform_and_deployment_target(self):
        self.check(macho(platform=2), "aarch64-apple-darwin", False, "macOS")
        for version in [0xA0C00, 0xC0000]:
            self.check(macho(minimum=version), "aarch64-apple-darwin", False, "11.0")

    def test_macos_rejects_rpath_environment_and_unknown_commands(self):
        for command in [0x8000001C, 0x27, 0xFFFFFFFF]:
            self.check(macho(extra=string_command(command, "/tmp")), "aarch64-apple-darwin", False)

    def test_macos_rejects_malformed_load_commands(self):
        data = macho(); struct.pack_into("<I", data, 36, 0)
        self.check(data, "aarch64-apple-darwin", False, "command")
        self.check(macho()[:100], "aarch64-apple-darwin", False)
        data = macho(); struct.pack_into("<I", data, 20, 8)
        self.check(data, "aarch64-apple-darwin", False)

    def test_macos_rejects_truncated_known_commands_and_external_tables(self):
        self.check(macho(extra=struct.pack("<II", 0x1B, 8)), "aarch64-apple-darwin", False, "command")
        self.check(macho(extra=struct.pack("<IIIIII", 0x2, 24, 500, 99999, 512, 1)), "aarch64-apple-darwin", False)

    def test_macos_rejects_duplicate_minimum_and_unmapped_entry(self):
        self.check(macho(extra=struct.pack("<IIII", 0x24, 16, 0xB0000, 0xF0500)), "aarch64-apple-darwin", False, "deployment")
        data = macho(); struct.pack_into("<Q", data, 112, 99999)
        self.check(data, "aarch64-apple-darwin", False, "entry")


if __name__ == "__main__":
    unittest.main()
