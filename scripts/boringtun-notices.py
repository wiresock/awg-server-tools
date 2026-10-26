#!/usr/bin/env python3
"""Fail-closed checks for the reviewed full runtime and fork notice texts."""
import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

CONFIG = Path(os.environ.get("BORINGTUN_NOTICE_CONFIG", Path(__file__).resolve().parents[1] / "packaging/boringtun"))
BEGIN = b"BEGIN BORINGTUN RUNTIME AND NATIVE NOTICES\n"
END = b"END BORINGTUN RUNTIME AND NATIVE NOTICES\n"
DEFAULT_TARGET = "x86_64-unknown-linux-musl"
PROFILES = {
    "linux-musl": ("runtime-notices.txt", {"x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl", "armv7-unknown-linux-musleabihf"}),
    "macos-system": ("runtime-notices-macos.txt", {"aarch64-apple-darwin", "x86_64-apple-darwin"}),
}


def read_regular(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"missing or nonregular notice input: {path.name}")
    return path.read_bytes()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate policy key: {key}")
        result[key] = value
    return result


def policy(config, toolchain, target=DEFAULT_TARGET):
    data = json.loads(read_regular(config / "notice-policy.json"), object_pairs_hook=unique_object)
    keys = {"format", "rust_toolchain", "profiles", "fork_license_sha256", "source_lock_sha256"}
    if set(data) != keys or type(data["format"]) is not int or data["format"] != 2:
        raise ValueError("unknown notice policy format/fields")
    if data["rust_toolchain"] != toolchain:
        raise ValueError("runtime notice toolchain differs from the reviewed policy")
    locks = data["source_lock_sha256"]
    if not isinstance(locks, list) or not locks or len(set(locks)) != len(locks):
        raise ValueError("notice policy needs reviewed Cargo.lock checksums")
    if not isinstance(data["profiles"], dict) or set(data["profiles"]) != set(PROFILES):
        raise ValueError("unknown runtime notice profile")
    bundle = None
    for name, (filename, targets) in PROFILES.items():
        entry = data["profiles"][name]
        if (not isinstance(entry, dict) or set(entry) != {"targets", "runtime_file", "runtime_sha256"}
                or entry["runtime_file"] != filename or not isinstance(entry["targets"], list)
                or any(not isinstance(item, str) for item in entry["targets"])
                or len(entry["targets"]) != len(targets) or set(entry["targets"]) != targets):
            raise ValueError("unknown runtime notice profile mapping")
        value = entry["runtime_sha256"]
        if not isinstance(value, str) or not re.fullmatch("[0-9a-f]{64}", value):
            raise ValueError("invalid notice policy checksum")
        content = read_regular(config / filename)
        if sha(content) != value:
            raise ValueError("reviewed notice input checksum mismatch")
        if not content.startswith(BEGIN) or not content.endswith(END) or content.count(BEGIN) != 1:
            raise ValueError("invalid runtime notice bundle framing")
        if target in targets:
            bundle = content
    if bundle is None:
        raise ValueError("unreviewed runtime notice target")
    for value in [data["fork_license_sha256"], *locks]:
        if not isinstance(value, str) or not re.fullmatch("[0-9a-f]{64}", value):
            raise ValueError("invalid notice policy checksum")
    fork = read_regular(config / "fork-license.txt")
    if sha(fork) != data["fork_license_sha256"]:
        raise ValueError("reviewed notice input checksum mismatch")
    if not bundle.startswith(BEGIN) or not bundle.endswith(END) or bundle.count(BEGIN) != 1:
        raise ValueError("invalid runtime notice bundle framing")
    return data, bundle, fork


def check_files(config, toolchain, third_party, license_file=None, target=DEFAULT_TARGET):
    _, bundle, fork = policy(config, toolchain, target)
    content = read_regular(third_party)
    if content.count(BEGIN) != 1 or not content.endswith(bundle):
        raise ValueError("complete reviewed runtime notice bundle missing, duplicated or altered")
    if license_file is None or read_regular(license_file) != fork:
        raise ValueError("fork LICENSE differs from the complete reviewed upstream/fork notices")


def check_source(config, toolchain, source):
    data, _, fork = policy(config, toolchain)
    if sha(read_regular(source / "Cargo.lock")) not in data["source_lock_sha256"]:
        raise ValueError("Cargo.lock changed: review runtime/native notice coverage before building")
    # Source worktrees can use CRLF; archives must use the canonical LF text.
    if read_regular(source / "LICENSE.md").replace(b"\r\n", b"\n") != fork:
        raise ValueError("fork LICENSE differs from the complete reviewed upstream/fork notices")


def check_runtime(config, toolchain, sysroot, target=DEFAULT_TARGET):
    policy(config, toolchain, target)
    provenance = json.loads(read_regular(config / "runtime-provenance.json"), object_pairs_hook=unique_object)
    if provenance.get("rust_toolchain") != toolchain:
        raise ValueError("runtime provenance toolchain differs")
    entries = provenance.get("target_object_sha256", {}).get(target)
    if not isinstance(entries, dict) or not entries:
        raise ValueError("target runtime object inventory missing")
    inventory = provenance.get("target_objects", {}).get(target)
    if (not isinstance(inventory, list) or any(not isinstance(item, str) for item in inventory)
            or len(inventory) != len(set(inventory)) or set(inventory) != set(entries)):
        raise ValueError("target runtime object inventory differs from recorded distribution")
    base = Path(sysroot) / "lib/rustlib"
    target_root = base / target / "lib"
    for directory in [Path(sysroot), Path(sysroot) / "lib", base, base / target, target_root]:
        if directory.is_symlink():
            raise ValueError("symlink in target runtime inventory")
    found = set()
    for path in target_root.rglob("*"):
        if path.is_symlink():
            raise ValueError("symlink in target runtime inventory")
        if path.is_file():
            found.add(path.relative_to(base).as_posix())
        elif not path.is_dir():
            raise ValueError("nonregular object in target runtime inventory")
    if found != set(entries):
        raise ValueError("installed target runtime inventory differs from pinned distribution")
    for name, expected in entries.items():
        if (not isinstance(name, str) or not name.startswith(target + "/lib/") or "\\" in name
                or any(part in {"", ".", ".."} for part in name.split("/"))
                or not isinstance(expected, str) or not re.fullmatch("[0-9a-f]{64}", expected)):
            raise ValueError("unsafe runtime object inventory")
        if sha(read_regular(base / name)) != expected:
            raise ValueError(f"installed target runtime differs from pinned distribution: {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["check", "source", "bundle", "runtime"])
    parser.add_argument("toolchain")
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--target", default=DEFAULT_TARGET)
    args = parser.parse_args()
    try:
        if args.command == "check" and len(args.paths) in {1, 2}:
            check_files(CONFIG, args.toolchain, *map(Path, args.paths), target=args.target)
        elif args.command == "source" and len(args.paths) == 1:
            check_source(CONFIG, args.toolchain, Path(args.paths[0]))
        elif args.command == "bundle" and not args.paths:
            _, bundle, _ = policy(CONFIG, args.toolchain, args.target)
            sys.stdout.buffer.write(bundle)
        elif args.command == "runtime" and len(args.paths) == 1:
            check_runtime(CONFIG, args.toolchain, Path(args.paths[0]), args.target)
        else:
            parser.error("incorrect arguments")
    except (ValueError, OSError, TypeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
