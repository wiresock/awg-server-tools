#!/usr/bin/env python3
"""Reproduce the reviewed runtime/native notice bundle from hash-pinned inputs.

This is an offline maintainer tool, not part of release builds. Download the
inputs listed in packaging/boringtun/runtime-provenance.json into one directory,
then pass that directory. No archives are extracted to the filesystem.
"""
import argparse
import hashlib
import html.parser
import json
import re
import tarfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "packaging/boringtun"
BEGIN = "BEGIN BORINGTUN RUNTIME AND NATIVE NOTICES"
END = "END BORINGTUN RUNTIME AND NATIVE NOTICES"


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Text(html.parser.HTMLParser):
    """Retain every text node in the selected upstream inventory, in order."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)

    def handle_starttag(self, tag, attrs):
        if tag in {"p", "div", "h1", "h2", "h3", "li", "pre", "br"}:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in {"p", "div", "h1", "h2", "h3", "li", "pre"}:
            self.parts.append("\n")


def notice_blocks(data):
    """Conservative source-notice superset, including per-file native notices.

    Keep whole comment blocks, never paraphrase their terms. This deliberately
    includes source/generator notices for unused architectures as well.
    """
    text = data.decode("utf-8", errors="strict")
    blocks = re.findall(r"/\*.*?\*/|(?m:^(?:[ \t]*//[^\n]*\n)+)|(?m:^(?:[ \t]*\#[^\n]*\n)+)", text, re.S)
    return [b for b in blocks if re.search(r"copyright|permission|SPDX-License", b, re.I)]


def load_sources(inputs, config):
    """Stream each verified archive once, retaining only source/license text.

    Target binaries are hashed as they are read, not kept in memory. This also
    checks the object inventories against the actual five distributions.
    """
    sources = {}
    version = config["rust_toolchain"]
    lock_key = (f"rust-src-{version}.tar.xz", f"rust-src-{version}/rust-src/lib/rustlib/src/rust/library/Cargo.lock")
    exact = {(item["input"], item["path"]) for item in config["texts"]}
    exact.add((config["rust_inventory"]["input"], config["rust_inventory"]["path"]))
    exact.add(lock_key)
    for name, record in config["inputs"].items():
        p = inputs / name
        if not p.is_file() or p.is_symlink() or sha(p.read_bytes()) != record["sha256"]:
            raise ValueError(f"input checksum mismatch or nonregular file: {name}")
        if record.get("archive"):
            target = name.removeprefix(f"rust-std-{version}-").removesuffix(".tar.xz") if name.startswith(f"rust-std-{version}-") else None
            objects = {}
            with tarfile.open(p, "r|*") as archive:
                for member in archive:
                    if not member.isfile():
                        continue
                    path = member.name
                    needed = (name, path) in exact or any(
                        name == group["input"] and path.startswith(group["prefix"])
                        and Path(path).suffix in {".rs", ".c", ".h", ".S", ".s", ".pl", ".inc", ".inl"}
                        for group in config["source_notices"])
                    runtime_path = path.partition("/lib/rustlib/")[2]
                    is_runtime = target and runtime_path.startswith(target + "/lib/")
                    if needed or is_runtime:
                        data = archive.extractfile(member).read()
                        if needed:
                            if (name, path) in sources:
                                raise ValueError("duplicate source archive member")
                            sources[(name, path)] = data
                        if is_runtime:
                            if runtime_path in objects:
                                raise ValueError("duplicate target archive member")
                            objects[runtime_path] = sha(data)
            if target and (objects != config["target_object_sha256"].get(target)
                           or sorted(objects) != sorted(config["target_objects"].get(target, []))):
                raise ValueError(f"target object inventory differs: {target}")
        else:
            sources[(name, "")] = p.read_bytes()
    if sha(sources[lock_key]) != config["library_cargo_lock_sha256"]:
        raise ValueError("Rust library Cargo.lock differs from reviewed runtime graph")
    manifest = tomllib.loads(sources[(f"rust-{version}.toml", "")].decode())
    for target in config["target_objects"]:
        name = f"rust-std-{version}-{target}.tar.xz"
        if config["inputs"][name]["sha256"] != manifest["pkg"]["rust-std"]["target"][target]["xz_hash"]:
            raise ValueError(f"target digest differs from official distribution manifest: {target}")
    return sources


def generate(sources, config, profile="linux-musl"):
    if profile not in config["profiles"]:
        raise ValueError("unknown runtime notice profile")

    def read(name, path):
        return sources[(name, path)]

    out = [BEGIN + "\n", "Rust toolchain: " + config["rust_toolchain"] + "\n\n",
           "Reviewed runtime/native notices. Source versions, checksums and scope:\n",
           "https://github.com/wiresock/awg-server-tools/blob/main/docs/BORINGTUN_NOTICES.md\n",
           "This notice collection includes conservative source-notice supersets;\n",
           "it is not a claim that every listed source file is linked.\n\n"]
    records = []

    def emit(label, components, content, origin, transform="verbatim"):
        data = content if isinstance(content, bytes) else content.encode()
        records.append({"label": label, "source": origin, "transform": transform, "sha256": sha(data)})
        out.extend(["=" * 80 + "\n", label + "\n\nUsed by:\n",
                    "".join("  " + c + "\n" for c in components), "-" * 80 + "\n",
                    data.decode("utf-8"), "\n\n"])

    for item in config["texts"]:
        if profile not in item.get("profiles", config["profiles"]):
            continue
        emit(item["label"], item["components"], read(item["input"], item["path"]),
             item["input"] + ":" + item["path"])

    item = config["rust_inventory"]
    data = read(item["input"], item["path"]).decode()
    # The out-of-tree section includes tools, tests and non-Linux dependencies.
    # Exact runtime dependency licenses instead come from library/Cargo.lock's
    # vendored packages (texts above). Retain all in-tree attribution metadata.
    marker = '<h2 id="out-of-tree-dependencies">'
    if data.count(marker) != 1:
        raise ValueError("upstream Rust copyright inventory format changed")
    parser = Text()
    parser.feed(data.split(marker)[0])
    inventory = re.sub(r"\n[ \t]*\n(?:[ \t]*\n)+", "\n\n", "".join(parser.parts)).strip() + "\n"
    emit("Rust standard-library in-tree attribution inventory", ["rust-runtime " + config["rust_toolchain"]],
         inventory, item["input"] + ":" + item["path"], "HTML text nodes before out-of-tree-dependencies; blank-line compaction")

    for group in config["source_notices"]:
        if profile not in group.get("profiles", config["profiles"]):
            continue
        grouped = {}
        for name, path in sorted(sources):
            if name != group["input"] or not path.startswith(group["prefix"]):
                continue
            if Path(path or name).suffix not in {".rs", ".c", ".h", ".S", ".s", ".pl", ".inc", ".inl"}:
                continue
            for block in notice_blocks(read(name, path)):
                grouped.setdefault(block, []).append(path)
        for block, paths in grouped.items():
            emit(group["label"] + "\nFiles: " + ", ".join(paths), group["components"], block,
                 group["input"] + ":" + ",".join(paths), "whole copyright/license comment block")
    out.append(END + "\n")
    return "".join(out).encode(), records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", type=Path)
    parser.add_argument("--check", action="store_true", help="compare generated files without writing")
    args = parser.parse_args()
    config = json.loads((CONFIG / "runtime-provenance.json").read_text())
    sources = load_sources(args.inputs, config)
    for profile, output in config["profiles"].items():
        bundle, records = generate(sources, config, profile)
        provenance = (json.dumps(records, indent=2, ensure_ascii=False) + "\n").encode()
        outputs = {output["runtime_file"]: bundle, output["sections_file"]: provenance}
        for name, data in outputs.items():
            path = CONFIG / name
            if args.check:
                if path.read_bytes() != data:
                    raise ValueError(f"generated content differs: {name}")
            else:
                path.write_bytes(data)
        print(f"{profile}: {len(records)} sections; SHA256 {sha(bundle)}")


if __name__ == "__main__":
    main()
