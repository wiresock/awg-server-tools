#!/usr/bin/env python3
"""Build the reviewed GNU Bash inputs locally, or verify an installed receipt."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
VERSION = "5.3.20"
DEVELOPER = "/Applications/Xcode_16.4.app/Contents/Developer"
OPTIONS = ["--disable-readline", "--disable-nls", "--without-bash-malloc"]
MAX_DOWNLOAD = 32 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def validate_policy(value):
    require(type(value) is dict and set(value) == {"schema", "version", "checksum_source", "source", "patches"},
            "invalid Bash source policy")
    require(type(value["schema"]) is int and value["schema"] == 1 and value["version"] == VERSION,
            "unreviewed Bash source version")
    require(value["checksum_source"] == "https://github.com/Homebrew/homebrew-core/blob/9d390e8ea5618fde14eeb084d0da3eb5a4cce53c/Formula/b/bash.rb",
            "unexpected Bash checksum source")
    require(type(value["patches"]) is list and len(value["patches"]) == 20, "all twenty Bash patches are required")
    entries = [value["source"], *value["patches"]]
    urls = ["https://ftp.gnu.org/gnu/bash/bash-5.3.tar.gz"] + [
        f"https://ftp.gnu.org/gnu/bash/bash-5.3-patches/bash53-{number:03d}" for number in range(1, 21)]
    for entry, url in zip(entries, urls):
        require(type(entry) is dict and set(entry) == {"url", "sha256"} and entry["url"] == url and
                type(entry["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]),
                "invalid or out-of-order Bash source input")
    return value


def read_policy():
    return validate_policy(json.loads((ROOT / "packaging/boringtun/bash-toolchain.json").read_text()))


def verified_download(entry, destination):
    require(not destination.exists() and not destination.is_symlink(), "Bash input already exists")
    with urllib.request.urlopen(entry["url"], timeout=60) as response:
        data = response.read(MAX_DOWNLOAD + 1)
    require(len(data) <= MAX_DOWNLOAD, "Bash download exceeds the size limit")
    require(digest(data) == entry["sha256"], "Bash input SHA-256 mismatch: " + entry["url"])
    with destination.open("xb") as output:
        output.write(data)


def extract_source(archive, destination):
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        require(len(members) < 10000 and sum(item.size for item in members) < 128 * 1024 * 1024,
                "Bash source archive exceeds limits")
        for item in members:
            parts = Path(item.name).parts
            require(parts and parts[0] == "bash-5.3" and ".." not in parts and
                    (item.isdir() or item.isfile()), "unexpected Bash source archive member")
        source.extractall(destination, members=members, filter="data")


def tool_output(argv, environment=None):
    return subprocess.check_output(argv, text=True, stderr=subprocess.STDOUT, env=environment).strip()


def shell_environment():
    # Never let startup hooks make either version check execute caller content.
    return {key: value for key, value in os.environ.items()
            if key not in {"BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"} and not key.startswith("BASH_FUNC_")}


def verify_shell(binary):
    require(binary.is_file() and not binary.is_symlink(), "Bash must be a regular executable")
    environment = shell_environment()
    banner = tool_output([str(binary), "--version"], environment).splitlines()[0]
    internal = tool_output([str(binary), "--noprofile", "--norc", "-c", 'printf "%s" "$BASH_VERSION"'], environment)
    require(re.fullmatch(r"5\.3\.20\([0-9]+\)-release", internal) and
            banner.startswith("GNU bash, version " + internal + " (") and banner.endswith(")"),
            f"GNU Bash {VERSION} is required: banner={banner!r}, BASH_VERSION={internal!r}")
    return {"banner": banner, "internal_version": internal}


def install_destination(destination):
    require(os.environ.get("RUNNER_TEMP"), "RUNNER_TEMP is required")
    temporary = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    destination = destination.resolve()
    require(not any(char in str(destination) for char in "\r\n\0"), "invalid Bash installation path")
    require(destination.is_relative_to(temporary) and destination != temporary,
            "Bash installation must be below RUNNER_TEMP")
    require(not destination.exists(), "Bash installation destination already exists")
    return destination


def verify_install(binary):
    require(binary.is_file() and not binary.is_symlink(), "Bash must be a regular executable")
    binary = binary.resolve(strict=True)
    policy = read_policy()
    record = json.loads((binary.parent.parent / "BASH-TOOLCHAIN.json").read_text())
    expected_keys = {"schema", "version", "source_manifest_sha256", "source_inputs", "configure_options",
                     "binary_sha256", "xcode", "xcode_build", "sdk", "deployment_target", "compiler",
                     "banner", "internal_version"}
    require(type(record) is dict and set(record) == expected_keys and type(record["schema"]) is int and
            record["schema"] == 1 and record["version"] == VERSION and
            record.get("source_manifest_sha256") == digest(canonical(policy)) and
            record.get("source_inputs") == [policy["source"], *policy["patches"]] and
            record.get("configure_options") == OPTIONS and
            record.get("binary_sha256") == digest(binary.read_bytes()),
            "Bash installation receipt does not match the reviewed inputs and executable")
    require(record["xcode"] == "16.4" and record["xcode_build"] == "16F6" and record["sdk"] == "15.5" and
            record["deployment_target"] == "11.0" and type(record["compiler"]) is dict and
            set(record["compiler"]) == {"path", "sha256"} and
            type(record["compiler"]["path"]) is str and record["compiler"]["path"].startswith(DEVELOPER + "/") and
            type(record["compiler"]["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", record["compiler"]["sha256"]),
            "Bash compiler receipt does not match the reviewed native toolchain")
    versions = verify_shell(binary)
    require(all(record.get(key) == value for key, value in versions.items()), "Bash version receipt mismatch")
    return record


def install(destination):
    require(platform.system() == "Darwin" and platform.machine() in {"arm64", "x86_64"},
            "Bash toolchain installation requires native macOS")
    destination = install_destination(destination)
    policy = read_policy()
    environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(destination / "home"),
                   "TMPDIR": os.environ["RUNNER_TEMP"], "LC_ALL": "C", "DEVELOPER_DIR": DEVELOPER,
                   "MACOSX_DEPLOYMENT_TARGET": "11.0", "bash_cv_func_strchrnul_works": "no"}
    require(tool_output(["xcodebuild", "-version"], environment) == "Xcode 16.4\nBuild version 16F6",
            "Bash build requires Xcode 16.4 build 16F6")
    require(tool_output(["xcrun", "--sdk", "macosx", "--show-sdk-version"], environment) == "15.5",
            "Bash build requires macOS SDK 15.5")
    compiler = tool_output(["xcrun", "--sdk", "macosx", "--find", "clang"], environment)
    environment["CC"] = compiler
    environment["SDKROOT"] = tool_output(["xcrun", "--sdk", "macosx", "--show-sdk-path"], environment)
    destination.mkdir(parents=True)
    for name in ("home", "inputs", "work", "bin"):
        (destination / name).mkdir()
    entries = [policy["source"], *policy["patches"]]
    for entry in entries:
        verified_download(entry, destination / "inputs" / entry["url"].rsplit("/", 1)[1])
    extract_source(destination / "inputs/bash-5.3.tar.gz", destination / "work")
    source = destination / "work/bash-5.3"

    def run(argv):
        subprocess.run(argv, cwd=source, env=environment, check=True, stdout=sys.stderr, stderr=sys.stderr)

    for entry in policy["patches"]:
        run(["/usr/bin/patch", "-f", "-p0", "-i", str(destination / "inputs" / entry["url"].rsplit("/", 1)[1])])
    run(["/bin/sh", "./configure", "--prefix=" + str(destination), *OPTIONS])
    run(["/usr/bin/make", "-j2", "bash"])
    binary = destination / "bin/bash"
    shutil.copyfile(source / "bash", binary)
    binary.chmod(0o755)
    record = {"schema": 1, "version": VERSION, "source_manifest_sha256": digest(canonical(policy)),
              "source_inputs": entries, "configure_options": OPTIONS, "binary_sha256": digest(binary.read_bytes()),
              "xcode": "16.4", "xcode_build": "16F6", "sdk": "15.5", "deployment_target": "11.0",
              "compiler": {"path": compiler, "sha256": digest(Path(compiler).read_bytes())},
              **verify_shell(binary)}
    (destination / "BASH-TOOLCHAIN.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    verify_install(binary)
    return binary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("install").add_argument("destination", type=Path)
    commands.add_parser("verify").add_argument("binary", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "install":
            print(install(args.destination))
        else:
            print(json.dumps(verify_install(args.binary), sort_keys=True))
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError, tarfile.TarError) as error:
        print("Bash toolchain blocked: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
