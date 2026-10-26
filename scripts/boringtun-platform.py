#!/usr/bin/env python3
"""Strict target identities and portable ELF/Mach-O inspection; never executes input."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys

PROFILES = {
    "x86_64-unknown-linux-musl": ("x86_64", "linux", "musl", "static", "linux-x86_64-musl"),
    "aarch64-unknown-linux-musl": ("aarch64", "linux", "musl", "static", "linux-aarch64-musl"),
    "armv7-unknown-linux-musleabihf": ("armv7", "linux", "musl", "static", "linux-armv7-musleabihf"),
    "x86_64-apple-darwin": ("x86_64", "macos", "libSystem", "dynamic-system", "macos-x86_64"),
    "aarch64-apple-darwin": ("aarch64", "macos", "libSystem", "dynamic-system", "macos-aarch64"),
}
SYSTEM_DYLIBS = {"/usr/lib/libSystem.B.dylib", "/usr/lib/libresolv.9.dylib", "/usr/lib/libiconv.2.dylib"}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def unpack(fmt, data, offset=0):
    require(0 <= offset <= len(data) - struct.calcsize(fmt), "truncated binary structure")
    return struct.unpack_from(fmt, data, offset)


def span(data, offset, size):
    require(0 <= offset <= len(data) and 0 <= size <= len(data) - offset, "binary range extends outside file")


def inspect_elf(data, target):
    bits, machine = {"x86_64": (64, 62), "aarch64": (64, 183), "armv7": (32, 40)}[PROFILES[target][0]]
    require(len(data) >= 16 and data[:4] == b"\x7fELF", "not an ELF executable")
    require(data[4:7] == bytes([2 if bits == 64 else 1, 1, 1]), "ELF class, endianness or version mismatch")
    fmt = "<HHIQQQIHHHHHH" if bits == 64 else "<HHIIIIIHHHHHH"
    kind, arch, version, entry, phoff, _, flags, ehsize, phsize, phnum, _, _, _ = unpack(fmt, data, 16)
    require(arch == machine, "ELF architecture mismatch")
    require(kind in (2, 3) and version == 1 and ehsize == (64 if bits == 64 else 52), "not a supported ELF executable")
    require(phsize == (56 if bits == 64 else 32) and 0 < phnum < 65535, "invalid ELF program table")
    span(data, phoff, phsize * phnum)
    if bits == 32:
        require(flags & 0xFF000000 == 0x05000000 and flags & 0x600 == 0x400, "ARM requires hard-float EABI5")
    executable = False
    for i in range(phnum):
        if bits == 64:
            ptype, pflags, offset, vaddr, _, size, memory, _ = unpack("<IIQQQQQQ", data, phoff + i * phsize)
        else:
            ptype, offset, vaddr, _, size, memory, pflags, _ = unpack("<IIIIIIII", data, phoff + i * phsize)
        span(data, offset, size)
        require(ptype != 3, "binary requests a program interpreter")
        if ptype == 1:
            require(size <= memory, "ELF load segment exceeds memory size")
            executable |= bool(pflags & 1 and vaddr <= entry < vaddr + size)
        if ptype == 2:
            width = 16 if bits == 64 else 8
            require(size % width == 0, "malformed ELF dynamic table")
            terminated = False
            for pos in range(offset, offset + size, width):
                tag, _ = unpack("<QQ" if bits == 64 else "<II", data, pos)
                require(tag != 1, "binary depends on shared libraries")
                if tag == 0:
                    terminated = True
                    break
            require(terminated, "unterminated ELF dynamic table")
    require(entry != 0 and executable, "ELF entry point is not mapped executable data")


def command_string(command, minimum):
    offset, = unpack("<I", command, 8)
    require(minimum <= offset < len(command), "invalid Mach-O string offset")
    end = command.find(b"\0", offset)
    require(end >= offset, "unterminated Mach-O command string")
    return command[offset:end].decode("ascii")


def inspect_macho(data, target):
    magic, cpu, subtype, kind, count, size, flags, reserved = unpack("<IIIIIIII", data)
    require(magic == 0xFEEDFACF, "not a little-endian 64-bit Mach-O executable")
    expected = (0x100000C, 0) if target.startswith("aarch64") else (0x1000007, 3)
    require((cpu, subtype & 0xFFFFFF) == expected, "Mach-O architecture mismatch")
    require(kind == 2 and reserved == 0 and flags & 0x200000, "Mach-O must be a PIE executable")
    require(0 < count <= size // 8, "invalid Mach-O command count")
    span(data, 32, size)
    pos, end = 32, 32 + size
    minima, entries, dylinkers, libraries, segments = [], [], [], set(), []
    # Commands emitted by Apple's linker for executable Rust binaries. Dynamic
    # search paths, injected environment, prebound dylibs and unknown commands
    # are deliberately excluded; a changed linker needs a reviewed policy update.
    accepted = {0x19, 0x2, 0xB, 0xE, 0xC, 0x80000018, 0x8000001F, 0x80000023,
                0x1B, 0x1D, 0x1E, 0x22, 0x80000022, 0x24, 0x26, 0x29, 0x2A,
                0x2B, 0x2E, 0x32, 0x80000028, 0x80000033, 0x80000034}
    for _ in range(count):
        cmd, length = unpack("<II", data, pos)
        require(cmd in accepted, "unsupported Mach-O load command")
        require(length >= 8 and length % 8 == 0 and pos + length <= end, "malformed Mach-O load command")
        command = data[pos:pos + length]
        fixed_sizes = {0x2: 24, 0xB: 80, 0x1B: 24, 0x22: 48, 0x80000022: 48, 0x2A: 16}
        require(cmd not in fixed_sizes or length == fixed_sizes[cmd], "malformed Mach-O fixed-size command")
        if cmd == 0x19:
            _, _, name, _, memory, offset, file_size, maximum, initial, nsects, _ = unpack("<II16sQQQQiiII", command)
            require(length == 72 + 80 * nsects and file_size <= memory, "malformed Mach-O segment")
            span(data, offset, file_size)
            require(initial & ~maximum == 0, "invalid Mach-O segment protections")
            for section in range(nsects):
                # Zerofill sections have memory but no file-backed bytes.
                section_size, section_offset = unpack("<QI", command, 72 + section * 80 + 40)
                section_flags, = unpack("<I", command, 72 + section * 80 + 64)
                if section_flags & 0xFF not in (1, 0xC, 0x12):
                    span(data, section_offset, section_size)
            if initial & 4:
                segments.append((offset, offset + file_size))
        elif cmd == 0x2:
            symbols, number, strings, string_size = unpack("<IIII", command, 8)
            span(data, symbols, 16 * number)
            span(data, strings, string_size)
        elif cmd == 0xB:
            values = unpack("<18I", command, 8)
            for index, width in [(6, 8), (8, 56), (10, 4), (12, 4), (14, 8), (16, 8)]:
                span(data, values[index], values[index + 1] * width)
        elif cmd in (0x22, 0x80000022):
            values = unpack("<10I", command, 8)
            for index in range(0, 10, 2):
                span(data, values[index], values[index + 1])
        elif cmd in (0xC, 0x80000018, 0x8000001F, 0x80000023):
            require(length >= 24, "truncated dylib command")
            name = command_string(command, 24)
            require(name in SYSTEM_DYLIBS, "unexpected system dylib dependency")
            libraries.add(name)
        elif cmd == 0xE:
            dylinkers.append(command_string(command, 12))
        elif cmd == 0x80000028:
            require(length == 24, "invalid Mach-O entry command")
            entries.append(unpack("<Q", command, 8)[0])
        elif cmd == 0x32:
            plat, minimum, sdk, tools = unpack("<IIII", command, 8)
            require(plat == 1, "Mach-O platform is not macOS")
            require(length == 24 + 8 * tools and sdk >= minimum, "invalid macOS build version")
            minima.append(minimum)
        elif cmd == 0x24:
            require(length == 16, "invalid macOS deployment command")
            minimum, sdk = unpack("<II", command, 8)
            require(sdk >= minimum, "invalid macOS SDK version")
            minima.append(minimum)
        elif cmd in (0x1D, 0x1E, 0x26, 0x29, 0x2B, 0x2E, 0x80000033, 0x80000034):
            require(length == 16, "invalid Mach-O linkedit command")
            offset, length_data = unpack("<II", command, 8)
            span(data, offset, length_data)
        pos += length
    require(pos == end, "Mach-O command sizes do not match header")
    require(minima == [0xB0000], "Mach-O deployment target must be exactly macOS 11.0")
    require(dylinkers == ["/usr/lib/dyld"], "Mach-O must use the system dynamic loader")
    require("/usr/lib/libSystem.B.dylib" in libraries, "Mach-O is missing required system dylib")
    require(len(entries) == 1 and entries[0] >= end and any(start <= entries[0] < stop for start, stop in segments),
            "Mach-O entry point is not mapped executable data")


def inspect(path, target):
    require(path.is_file() and not path.is_symlink(), "binary must be a regular file")
    require(0 < path.stat().st_size <= 256 * 1024 * 1024, "binary size is outside policy")
    data = path.read_bytes()
    (inspect_macho if PROFILES[target][1] == "macos" else inspect_elf)(data, target)


def tool_output(argv, environment=None):
    return subprocess.check_output(argv, text=True, stderr=subprocess.STDOUT, env=environment).strip()


def fingerprint(path):
    return {"path": str(path), "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest()}


def build_environment(target, directory):
    """Select reviewed native inputs; do not install tools or alter host settings.

    Hosted images are not immutable. Their selected compiler/SDK must match this
    policy and their actual binary hashes are retained for provenance. Native
    macOS execution and two-build equality are required before publication.
    """
    environment = {}
    record = {"target": target, "host": platform.platform(), "tools": {}}
    if target == "armv7-unknown-linux-musleabihf":
        require(platform.system() == "Linux", "ARMv7 cross builds require Linux")
        clang = shutil.which("clang-18")
        require(clang, "clang 18.1.3 (clang-18) is required")
        clang_version = tool_output([clang, "--version"])
        require(re.search(r"\bclang version 18\.1\.3(?:\s|$)", clang_version), "clang 18.1.3 is required")
        sysroot = Path(tool_output(["rustc", "--print", "sysroot"]))
        host = re.search(r"^host: ([a-zA-Z0-9_-]+)$", tool_output(["rustc", "-vV"]), re.M)
        require(host, "rustc did not report its host")
        linker = sysroot / "lib/rustlib" / host[1] / "bin/rust-lld"
        require(linker.is_file(), "pinned Rust rust-lld is unavailable")
        ar = shutil.which("llvm-ar-18")
        require(ar, "llvm-ar-18 is required")
        environment = {
            "CC_armv7_unknown_linux_musleabihf": clang,
            "AR_armv7_unknown_linux_musleabihf": ar,
            "CFLAGS_armv7_unknown_linux_musleabihf": "-march=armv7-a -mfpu=vfpv3-d16 -mfloat-abi=hard",
            "CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER": str(linker),
        }
        record["tools"] = {"clang": fingerprint(clang), "ar": fingerprint(ar), "linker": fingerprint(linker)}
        record["clang_version"] = clang_version
        record["linker_version"] = tool_output([str(linker), "-flavor", "gnu", "--version"])
        record["rust_link_flags"] = ["-Clinker-flavor=ld.lld", "-Clink-self-contained=yes"]
    elif target.endswith("-apple-darwin"):
        arch = "arm64" if target.startswith("aarch64") else "x86_64"
        require(platform.system() == "Darwin" and platform.machine() == arch, "build requires a native macOS host of the selected architecture")
        developer = "/Applications/Xcode_16.4.app/Contents/Developer"
        selected = dict(os.environ, DEVELOPER_DIR=developer)
        require(tool_output(["xcodebuild", "-version"], selected) == "Xcode 16.4\nBuild version 16F6", "Xcode 16.4 build 16F6 is required")
        require(tool_output(["xcrun", "--sdk", "macosx", "--show-sdk-version"], selected) == "15.5", "macOS SDK 15.5 is required")
        sdk = Path(tool_output(["xcrun", "--sdk", "macosx", "--show-sdk-path"], selected)).resolve()
        require(str(sdk).startswith(developer + "/"), "SDK must belong to the selected Xcode installation")
        clang = tool_output(["xcrun", "--sdk", "macosx", "--find", "clang"], selected)
        linker = tool_output(["xcrun", "--sdk", "macosx", "--find", "ld"], selected)
        key = target.replace("-", "_")
        environment = {"DEVELOPER_DIR": developer, "SDKROOT": str(sdk), "MACOSX_DEPLOYMENT_TARGET": "11.0",
                       "CC_" + key: clang, "CARGO_TARGET_" + key.upper() + "_LINKER": clang, "ZERO_AR_DATE": "1"}
        record["tools"] = {"clang": fingerprint(clang), "linker": fingerprint(linker), "sdk_settings": fingerprint(sdk / "SDKSettings.json")}
        record.update(xcode="16.4", xcode_build="16F6", sdk="15.5", deployment_target="11.0",
                      clang_version=tool_output([clang, "--version"], selected),
                      linker_version=tool_output([linker, "-version_details"], selected))
        tar = shutil.which("gtar")
        require(tar and tool_output([tar, "--version"]).splitlines()[0] == "tar (GNU tar) 1.35", "GNU tar 1.35 (gtar) is required")
        record["tools"]["gtar"] = fingerprint(tar)
        shell = os.environ.get("BTA_BUILD_SHELL") or shutil.which("bash")
        require(shell, "GNU Bash 5.3.20 is required on macOS")
        shell_version = tool_output([shell, "--version"]).splitlines()[0]
        require(shell_version.startswith("GNU bash, version 5.3.20("), "GNU Bash 5.3.20 is required on macOS")
        record["tools"]["bash"] = fingerprint(shell)
        record["bash_version"] = shell_version
    else:
        # Existing native Linux builds retain their original command and flags.
        require(platform.system() == "Linux", "Linux target requires native Linux")
        record["strategy"] = "native-linux-existing-toolchain"
    require(directory.is_dir(), "build directory is missing")
    destination = directory / "NATIVE-TOOLCHAIN.json"
    require(not destination.exists(), "native toolchain record already exists")
    for key, value in environment.items():
        require(not any(c in value for c in "\n\r\0"), "invalid native toolchain environment")
    record["environment"] = environment
    destination.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return environment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    profile = commands.add_parser("profile")
    profile.add_argument("target")
    check = commands.add_parser("inspect")
    check.add_argument("target")
    check.add_argument("binary", type=Path)
    reverse = commands.add_parser("target-for-suffix")
    reverse.add_argument("suffix")
    native = commands.add_parser("build-env")
    native.add_argument("target")
    native.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "target-for-suffix":
            matches = [target for target, values in PROFILES.items() if values[-1] == args.suffix]
            require(len(matches) == 1, "unsupported artifact suffix")
            print(matches[0])
        else:
            require(args.target in PROFILES, "unsupported target")
            if args.command == "profile":
                print("\t".join(PROFILES[args.target]))
            elif args.command == "build-env":
                for key, value in build_environment(args.target, args.directory).items():
                    print(key + "=" + value)
            else:
                inspect(args.binary, args.target)
    except (OSError, ValueError, UnicodeError, struct.error, subprocess.CalledProcessError) as error:
        print("ERROR: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
