#!/usr/bin/env python3
"""Verify an explicitly selected fork release and prepare a local adoption patch.

Requires Linux, Python 3.12+, bash/readelf and the checksum-pinned official gh
2.100.0 binary. All GitHub operations are reads. Nothing installs, executes an
archive binary, edits this checkout, opens a PR, or changes a release.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import difflib
import gzip
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import zlib

import boringtun_release_policy as policy

ROOT = Path(__file__).resolve().parents[1]
REPO = policy.REPOSITORY
GH_VERSION = "2.100.0"
# Extracted bin/gh hashes from the official checksum-verified release archives.
# Archive SHA-256 values and acquisition procedure are in BORINGTUN_ADOPTION.md.
GH_SHA256 = {
    "553949e2efa12842771efe6012aa4de21f1d591530ec17fc435f610f10e017ee": "linux_amd64",
    "28a037b967065aa314cb6d539943b55d27ef2f97c523ab2b6023ccf284e1828d": "linux_arm64",
}
TAG = re.compile(r"boringtun-cli-(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-g[0-9a-f]{12}-b[1-9][0-9]{0,8}\Z")
MAX_ASSET = 128 * 1024 * 1024
MEMBER_LIMITS = {"boringtun-cli": 64 * 1024 * 1024, "THIRD-PARTY-LICENSES": 8 * 1024 * 1024,
                 "LICENSE": 1024 * 1024, "MANIFEST": 64 * 1024}
MAX_TAR_PADDING = 64 * 1024
INSTALL_TARGETS = {"x86_64-unknown-linux-musl": "X86_64", "aarch64-unknown-linux-musl": "AARCH64",
                   "armv7-unknown-linux-musleabihf": "ARMV7"}


def require(ok, message):
    if not ok:
        raise policy.PolicyError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def regular(path):
    require(path.is_file() and not path.is_symlink(), f"missing or nonregular file: {path}")
    return path.read_bytes()


class GitHub:
    """Only read operations; argv is never passed through a shell."""
    def __init__(self, executable):
        self.executable = Path(executable).absolute()
        self.digest = sha(regular(self.executable))
        require(self.digest in GH_SHA256, "gh executable is not a pinned official 2.100.0 binary")
        self.env = os.environ.copy()
        self.env.update(GH_HOST="github.com", GH_PROMPT_DISABLED="1", GH_NO_UPDATE_NOTIFIER="1",
                        GH_NO_EXTENSION_UPDATE_NOTIFIER="1", GH_PAGER="cat")
        self.env.pop("GH_DEBUG", None)
        require(self.run(["--version"]).decode().splitlines()[0].startswith(f"gh version {GH_VERSION} "),
                "wrong gh version")

    def run(self, arguments):
        result = subprocess.run([str(self.executable), *arguments], env=self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        # Never print arbitrary stderr, which can contain authentication data.
        require(result.returncode == 0, f"read-only gh {arguments[0]} failed (exit {result.returncode})")
        return result.stdout

    def api(self, endpoint):
        return policy.load_json(self.run(["api", "--hostname", "github.com", "--method", "GET", endpoint]))

    def download(self, asset_id):
        require(type(asset_id) is int and asset_id > 0, "invalid asset ID")
        return self.run(["api", "--hostname", "github.com", "--method", "GET",
                         "--header", "Accept: application/octet-stream",
                         f"repos/{REPO}/releases/assets/{asset_id}"])

    def verify(self, path, descriptor):
        return policy.load_json(self.run(policy.attestation_arguments(str(path), descriptor)))


def asset_snapshot(release, tag):
    require(type(release) is dict and release.get("tag_name") == tag, "wrong release tag")
    require(type(release.get("id")) is int and release["id"] > 0, "invalid release ID")
    require(release.get("draft") is False and release.get("prerelease") is False,
            "only a published stable release can be adopted")
    require(release.get("html_url") == f"https://github.com/{REPO}/releases/tag/{tag}",
            "wrong release owner or URL")
    assets = release.get("assets")
    require(type(assets) is list and len(assets) == 7, "release must contain exactly seven assets")
    result = {}
    ids = set()
    for asset in assets:
        require(type(asset) is dict, "invalid release asset")
        name, ident, size = asset.get("name"), asset.get("id"), asset.get("size")
        require(type(name) is str and name not in result and "/" not in name and "\\" not in name,
                "unsafe or duplicate asset name")
        require(type(ident) is int and ident > 0 and ident not in ids, "invalid or duplicate asset ID")
        require(type(size) is int and 0 < size <= MAX_ASSET, "invalid asset size")
        require(asset.get("state") == "uploaded", "release asset upload is incomplete")
        result[name] = {"id": ident, "size": size}
        ids.add(ident)
    require("RELEASE.json" in result and "SHA256SUMS" in result, "release lacks descriptor or checksums")
    require(result["RELEASE.json"]["size"] <= 65536 and result["SHA256SUMS"]["size"] <= 4096,
            "oversize release metadata")
    return {"id": release["id"], "assets": result}


def tag_commit(gh, tag):
    ref = gh.api(f"repos/{REPO}/git/ref/tags/{tag}")
    require(ref.get("ref") == f"refs/tags/{tag}", "wrong tag reference")
    obj = ref.get("object", {})
    for _ in range(3):
        require(type(obj) is dict and re.fullmatch("[0-9a-f]{40}", str(obj.get("sha", ""))), "invalid tag object")
        if obj.get("type") == "commit":
            return obj["sha"]
        require(obj.get("type") == "tag", "tag does not resolve to a commit")
        obj = gh.api(f"repos/{REPO}/git/tags/{obj['sha']}").get("object", {})
    raise policy.PolicyError("excessively nested annotated tag")


def verify_attestation(results, descriptor, name, repo_identity):
    require(type(results) is list and results, "gh returned no verified attestations")
    expected = policy.release_assets(descriptor)
    del expected["SHA256SUMS"]
    for entry in results:
        if type(entry) is not dict or "verificationResult" not in entry:
            continue
        result = entry["verificationResult"]
        for subjects in ({name: expected[name]}, expected):
            try:
                checked = policy.check_verified_attestation(result, descriptor, subjects)
                cert = result["signature"]["certificate"]
                require(cert["sourceRepositoryIdentifier"] == str(repo_identity["id"]) and
                        cert["sourceRepositoryOwnerIdentifier"] == str(repo_identity["owner"]["id"]),
                        "attestation repository numeric identity mismatch")
                return checked
            except (policy.PolicyError, KeyError, TypeError):
                continue
    raise policy.PolicyError("no attestation matches the exact fork workflow, recipe, run, attempt and subjects")


def candidate_pin(descriptor):
    return (f"BORINGTUN_REPOSITORY=https://github.com/{REPO}\n"
            f"BORINGTUN_COMMIT={descriptor['source_commit']}\n"
            f"BORINGTUN_VERSION={descriptor['version']}\n"
            f"BORINGTUN_RUST_TOOLCHAIN={descriptor['rust_toolchain']}\n"
            "BORINGTUN_ARTIFACT_FORMAT=1\n")


def repository_evidence(value):
    """Project GitHub's full PR repo or minimal Actions association repo.

    Actions retains id/url/name, without full_name. Its exact API URL supplies
    the owner; never infer an owner from a display name or make a new lookup of
    a possibly deleted/renamed contributor repository.
    """
    require(type(value) is dict and type(value.get("id")) is int and value["id"] > 0,
            "missing retained contributor repository identity; provide reviewed immutable merge-event evidence before adoption")
    url = value.get("url")
    match = re.fullmatch(r"https://api\.github\.com/repos/([A-Za-z0-9][A-Za-z0-9-]*)/([A-Za-z0-9][A-Za-z0-9._-]*)", url) if type(url) is str else None
    require(match is not None, "repository identity must use an exact GitHub API repository URL")
    owner, name = match.groups()
    full_name = owner + "/" + name
    require(value.get("name") == name and ("full_name" not in value or value["full_name"] == full_name),
            "repository name disagrees with its exact API URL")
    return {"id": value["id"], "url": url, "name": name, "full_name": full_name}


def commit_prs(gh, source):
    """Read every commit association page, or fail without a partial result."""
    policy._sha(source)
    result, seen = [], set()
    for page in range(1, 12):
        entries = gh.api(f"repos/{REPO}/commits/{source}/pulls?per_page=100&page={page}")
        require(type(entries) is list and len(entries) <= 100, "invalid commit PR page")
        for pr in entries:
            require(type(pr) is dict, "invalid commit PR entry")
            number = policy._int(pr.get("number"), "commit PR number")
            require(number not in seen, "duplicate commit PR pagination entry")
            seen.add(number)
            result.append(pr)
        require(len(result) <= 1000, "commit PR discovery exceeds safe pagination bound")
        if len(entries) < 100:
            return result
    raise policy.PolicyError("commit PR discovery did not terminate")


def check_run_metadata(gh, descriptor, identity):
    """Independently resolve C to one merged PR and verify both exact attempts."""
    number = descriptor["pr"]
    source = descriptor["source_commit"]
    require(policy.merged_pr_number(commit_prs(gh, source), source) == number,
            "commit discovery differs from signed PR")
    pr = gh.api(f"repos/{REPO}/pulls/{number}")
    require(type(pr) is dict and type(pr.get("head")) is dict, "missing canonical merged PR metadata")
    build = descriptor["build_run"]
    build_run = gh.api(f"repos/{REPO}/actions/runs/{build['id']}/attempts/{build['run_attempt']}")
    require(type(build_run) is dict, "missing exact build attempt metadata")
    associations = build_run.get("pull_requests")
    require(type(associations) is list and len(associations) <= 1 and all(type(item) is dict for item in associations),
            "ambiguous exact build attempt PR associations")

    def project_ref(ref, kind):
        require(type(ref) is dict, f"missing run PR {kind} identity")
        repository = repository_evidence(ref.get("repo"))
        key = "sha" if kind == "head" else "ref"
        require(key in ref, f"missing run PR {kind} identity")
        return {key: ref[key], "repo": {"full_name": repository["full_name"]}}

    projected = {key: pr.get(key) for key in ("number", "state", "merged", "merge_commit_sha", "merged_at")}
    projected["base"] = project_ref(pr.get("base"), "base")
    current_base = repository_evidence(pr["base"]["repo"])
    require(current_base["id"] == identity["id"], "PR base repository numeric identity differs")
    # Deleting a contributor's repository can null PR.head.repo. Retain H from
    # the canonical merged PR, and use only the original exact build attempt's
    # recorded head repository. The policy below still matches PR number, H,
    # canonical base, source C, merge time and run/attempt; never infer a name.
    current_head = retained_head = retained_base = None
    if pr["head"].get("repo") is not None:
        current_head = repository_evidence(pr["head"]["repo"])
    projected_associations = []
    if associations:
        association = associations[0]
        associated_pr = {"number": association.get("number"), "head": project_ref(association.get("head"), "head"),
                         "base": project_ref(association.get("base"), "base")}
        projected_associations.append(associated_pr)
        retained_head = repository_evidence(association["head"]["repo"])
        retained_base = repository_evidence(association["base"]["repo"])
        require(retained_base["id"] == current_base["id"], "run PR base repository numeric identity differs")
        if current_head is not None:
            require(current_head["id"] == retained_head["id"], "run PR head repository numeric identity differs")
        projected["head"] = {"sha": pr["head"].get("sha"), "repo": associated_pr["head"]["repo"]}
    else:
        # Push attempts often have no PR associations. Fresh canonical PR data
        # supplies the contributor identity; a deleted repo without retained
        # evidence stays blocked rather than being guessed from a user name.
        projected["head"] = project_ref(pr["head"], "head")
    request = policy.merged_request(projected, number)
    require(request["source_commit"] == descriptor["source_commit"], "merged PR differs from signed source")
    comparison = gh.api(f"repos/{REPO}/compare/{source}...master")
    require(type(comparison) is dict and comparison.get("status") in ("ahead", "identical") and
            type(comparison.get("merge_base_commit")) is dict and comparison["merge_base_commit"].get("sha") == source,
            "signed source is not an ancestor of current master")
    evidence = {"merged_pr": projected, "current_head_repository": current_head,
                "retained_head_repository": retained_head, "retained_base_repository": retained_base}
    expected = [(descriptor["build_run"], "id", policy.BUILD_WORKFLOW, "push", descriptor["source_commit"], "build"),
                (descriptor["publisher"], "run_id", policy.PUBLISH_WORKFLOW, "workflow_run", descriptor["publisher"]["recipe_commit"], "publisher")]
    for recorded, id_key, path, event, commit, label in expected:
        workflow = gh.api(f"repos/{REPO}/actions/workflows/{path.rsplit('/', 1)[1]}")
        require(type(workflow.get("id")) is int and workflow["id"] == recorded["workflow_id"] and workflow.get("path") == path,
                f"{label} workflow identity differs")
        run = build_run if label == "build" else gh.api(f"repos/{REPO}/actions/runs/{recorded[id_key]}/attempts/{recorded['run_attempt']}")
        fields = {"id": recorded[id_key], "run_attempt": recorded["run_attempt"], "workflow_id": recorded["workflow_id"],
                  "path": path, "event": event, "head_sha": commit, "head_branch": "master"}
        fields.update({"status": "completed", "conclusion": "success"} if label == "build" else {"head_branch": "master"})
        require(type(run) is dict and all(run.get(key) == value and type(run.get(key)) is type(value) for key, value in fields.items()),
                f"{label} attempt is not the exact required recorded run")
        require(run.get("repository", {}).get("full_name") == REPO and type(run["repository"].get("id")) is int and run["repository"]["id"] == identity["id"],
                f"{label} attempt repository differs")
        if label == "build":
            created = run.get("created_at")
            require(type(created) is str and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", created), "missing original build creation time")
            require(datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ") >= datetime.strptime(request["merged_at"], "%Y-%m-%dT%H:%M:%SZ"),
                    "build attempt predates merged PR")
            projection = {key: run[key] for key in ("id", "run_attempt", "workflow_id", "path", "event", "status", "conclusion", "head_sha", "head_branch", "created_at")}
            projection["repository"] = {"full_name": run["repository"]["full_name"]}
            projection["pull_requests"] = projected_associations
            policy.check_build_run(projection, request, recorded["workflow_id"])
            evidence["build_attempt"] = projection
        else:
            # A publication/cleanup failure can follow successful validation and
            # signing. Immutable published bytes keep the original descriptor
            # and P even when a later attempt finishes publication. Check the
            # exact original attempt's security jobs, not its overall outcome.
            jobs = []
            total = None
            for page in range(1, 12):
                response = gh.api(f"repos/{REPO}/actions/runs/{recorded[id_key]}/attempts/{recorded['run_attempt']}/jobs?per_page=100&page={page}")
                require(type(response) is dict and type(response.get("total_count")) is int and 0 <= response["total_count"] <= 1000 and
                        type(response.get("jobs")) is list and len(response["jobs"]) <= 100, "invalid publisher attempt jobs response")
                require(total is None or total == response["total_count"], "publisher attempt jobs changed during pagination")
                total = response["total_count"]
                jobs.extend(response["jobs"])
                require(len(jobs) <= total, "duplicate or inconsistent publisher attempt jobs")
                if len(jobs) == total:
                    break
                require(response["jobs"], "publisher attempt job pagination ended early")
            selected = []
            for name in ("Validate completed build", "Attest verified content"):
                matches = [job for job in jobs if type(job) is dict and job.get("name") == name]
                require(len(matches) == 1, f"publisher attempt lacks exactly one {name} job")
                job = matches[0]
                require(type(job.get("run_id")) is int and job["run_id"] == recorded[id_key] and
                        job.get("status") == "completed" and job.get("conclusion") == "success",
                        f"publisher attempt security gate did not succeed: {name}")
                selected.append({key: job[key] for key in ("name", "run_id", "status", "conclusion")})
            evidence["publisher_attempt"] = fields
            evidence["publisher_gate_jobs"] = selected
    return evidence


def installer_patch(original, descriptor):
    descriptor = policy.check_descriptor(descriptor)
    values = {"TAG": descriptor["tag"], "BASE_URL": f"https://github.com/{REPO}/releases/download/{descriptor['tag']}",
              "VERSION": descriptor["version"], "SOURCE_REPOSITORY": f"https://github.com/{REPO}",
              "SOURCE_COMMIT": descriptor["source_commit"], "BUILD": str(descriptor["build"])}
    for archive in descriptor["archives"]:
        if archive["target"] not in INSTALL_TARGETS:
            continue
        suffix = INSTALL_TARGETS[archive["target"]]
        values[f"ASSET_{suffix}"] = archive["name"]
        values[f"ARCHIVE_SHA256_{suffix}"] = archive["sha256"]
        values[f"BINARY_SHA256_{suffix}"] = archive["binary_sha256"]
    previous = {}
    for name in values:
        matches = re.findall(rf'^AWG_BT_RELEASE_{name}="([^"\r\n]*)"$', original, flags=re.M)
        require(len(matches) == 1, f"installer must define AWG_BT_RELEASE_{name} exactly once")
        previous[name] = matches[0]
    # The installed-store key excludes repository/URL and uses only COMMIT12.
    # Changing bytes under the same key would leave existing hosts with a store
    # entry the new installer cannot use or safely overwrite.
    old_key = (previous["VERSION"], previous["SOURCE_COMMIT"][:12], previous["BUILD"])
    new_key = (values["VERSION"], values["SOURCE_COMMIT"][:12], values["BUILD"])
    if old_key == new_key:
        immutable = ["SOURCE_COMMIT", *[name for name in values if "SHA256" in name]]
        require(all(previous[name] == values[name] for name in immutable),
                "existing store identity has different source or bytes; select a release with a new build identity")
    changed = original
    for name, value in values.items():
        changed, count = re.subn(rf'^AWG_BT_RELEASE_{name}="[^"\r\n]*"$',
                                f'AWG_BT_RELEASE_{name}="{value}"', changed, flags=re.M)
        require(count == 1, f"installer must define AWG_BT_RELEASE_{name} exactly once")
    require(changed != original, "installer already selects this release")
    return "".join(difflib.unified_diff(original.splitlines(True), changed.splitlines(True),
                                       fromfile="a/amneziawg-install.sh", tofile="b/amneziawg-install.sh"))


def preinspect_archive(path, name):
    """Bound decompression using raw USTAR headers, before GNU tar sees input.

    Parsing raw headers rejects PAX/GNU extensions before a tar library can
    internally read their attacker-sized payloads. Only the format1 directory
    and four ordinary members are accepted, with fixed per-member byte bounds.
    No file from the archive is extracted during this pass.
    """
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_ASSET,
            "archive is missing, nonregular or exceeds compressed size limit")
    stem = name[:-7]
    expected = {stem, *(stem + "/" + filename for filename in MEMBER_LIMITS)}
    seen = set()
    try:
        with path.open("rb") as source, gzip.GzipFile(fileobj=source, mode="rb") as stream:
            while True:
                header = stream.read(512)
                require(len(header) == 512, "archive has a truncated USTAR header")
                if header == bytes(512):
                    require(stream.read(512) == bytes(512), "archive lacks two USTAR end blocks")
                    padding = stream.read(MAX_TAR_PADDING + 1)
                    require(len(padding) <= MAX_TAR_PADDING and not any(padding),
                            "archive exceeds trailing padding limit or contains hidden content")
                    break
                require(header[257:265] == b"ustar\x0000", "archive must use plain USTAR headers")
                member = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
                if member.type == tarfile.DIRTYPE:
                    require(member.name in (stem, stem + "/") and member.size == 0,
                            "archive has an unexpected directory")
                    key, limit = stem, 0
                else:
                    require(member.type in (tarfile.REGTYPE, tarfile.AREGTYPE),
                            "archive contains a link, sparse member, or metadata extension")
                    key = member.name
                    require(key in expected and key != stem, "archive contains an unexpected regular member")
                    limit = MEMBER_LIMITS[key.rsplit("/", 1)[1]]
                    require(0 < member.size <= limit, "archive member size exceeds reviewed bound")
                require(key not in seen, "archive contains duplicate members")
                seen.add(key)
                remaining = (member.size + 511) // 512 * 512
                while remaining:
                    chunk = stream.read(min(remaining, 65536))
                    require(chunk, "archive member is truncated")
                    remaining -= len(chunk)
            require(seen == expected, "archive lacks the exact four-member payload and directory")
    except (OSError, EOFError, UnicodeError, tarfile.HeaderError, zlib.error) as error:
        raise policy.PolicyError("invalid compressed USTAR archive") from error


def inspect_archives(directory, descriptor, root):
    """Use the production static gate; never run the downloaded executable."""
    config = root / "packaging/boringtun"
    provenance = regular(config / "runtime-provenance.json")
    require(sha(provenance) == descriptor["notice_provenance_sha256"], "unreviewed notice provenance; update local policy first")
    source = policy.load_json(provenance)
    toolchain = {key: source[key] for key in ("rust_toolchain", "rust_commit", "llvm_commit", "inputs")}
    # Same canonical object used by the fork publisher (no trailing LF).
    import json
    require(sha(json.dumps(toolchain, sort_keys=True, separators=(",", ":")).encode()) == descriptor["toolchain_sha256"],
            "unreviewed toolchain provenance")
    pin = directory / "candidate-pin.env"
    pin.write_text(candidate_pin(descriptor), encoding="utf-8", newline="\n")
    env = os.environ.copy()
    for key in ("BORINGTUN_NOTICE_CONFIG", "BORINGTUN_NOTICES_FILE", "BORINGTUN_RELEASE_FILE"):
        env.pop(key, None)
    env["BORINGTUN_PIN_FILE"] = str(pin)
    for archive in descriptor["archives"]:
        extract = directory / ("inspect-" + archive["target"])
        preinspect_archive(directory / archive["name"], archive["name"])
        result = subprocess.run(["bash", str(root / "scripts/boringtun-artifact.sh"), "verify-archive-static",
                                 str(directory / archive["name"]), str(extract)], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        require(result.returncode == 0, f"static archive/notice verification failed for {archive['target']}")
        stem = extract / archive["name"][:-7]
        require(sha(regular(stem / "boringtun-cli")) == archive["binary_sha256"], "signed binary checksum mismatch")
        require(sha(regular(stem / "THIRD-PARTY-LICENSES")) == archive["notice_sha256"], "signed notice checksum mismatch")


def adopt(tag, output, gh, root=ROOT):
    require(type(tag) is str and TAG.fullmatch(tag), "select an exact versioned fork release tag; latest is unsupported")
    output = Path(output).absolute()
    require(not output.exists(), "output must be a new directory")
    endpoint = f"repos/{REPO}/releases/tags/{tag}"
    snapshot = asset_snapshot(gh.api(endpoint), tag)
    identity = gh.api(f"repos/{REPO}")
    require(identity.get("full_name") == REPO and type(identity.get("id")) is int and identity["id"] > 0,
            "wrong canonical repository identity")
    require(type(identity.get("owner")) is dict and type(identity["owner"].get("id")) is int and identity["owner"]["id"] > 0,
            "missing canonical owner identity")
    output.mkdir(parents=True)
    assets = snapshot["assets"]
    raw = gh.download(assets["RELEASE.json"]["id"])
    require(len(raw) == assets["RELEASE.json"]["size"], "descriptor download size mismatch")
    descriptor = policy.check_descriptor(policy.load_json(raw))
    require(raw == policy.canonical_bytes(descriptor), "noncanonical RELEASE.json")
    require(descriptor["tag"] == tag, "descriptor names a different release")
    require(tag_commit(gh, tag) == descriptor["source_commit"], "tag target differs from signed source")
    expected = policy.release_assets(descriptor)
    require(set(assets) == set(expected), "unexpected or missing release assets")
    (output / "RELEASE.json").write_bytes(raw)
    receipt = {"schema": 2, "repository": REPO, "tag": tag, "release_id": snapshot["id"],
               "descriptor_sha256": sha(raw), "gh_version": GH_VERSION, "gh_sha256": gh.digest,
               "verified_attestations": {}, "gh_verification_results": {}, "assets": expected}
    result = gh.verify(output / "RELEASE.json", descriptor)
    receipt["verified_attestations"]["RELEASE.json"] = verify_attestation(result, descriptor, "RELEASE.json", identity)
    receipt["gh_verification_results"]["RELEASE.json"] = result
    receipt["run_evidence"] = check_run_metadata(gh, descriptor, identity)
    for name in sorted(set(expected) - {"RELEASE.json"}):
        data = gh.download(assets[name]["id"])
        require(len(data) == assets[name]["size"] and sha(data) == expected[name], f"asset checksum/size mismatch: {name}")
        (output / name).write_bytes(data)
        if name != "SHA256SUMS":
            result = gh.verify(output / name, descriptor)
            receipt["verified_attestations"][name] = verify_attestation(result, descriptor, name, identity)
            receipt["gh_verification_results"][name] = result
    inspect_archives(output, descriptor, root)
    require(asset_snapshot(gh.api(endpoint), tag) == snapshot and tag_commit(gh, tag) == descriptor["source_commit"],
            "release changed during verification")
    installer = regular(root / "amneziawg-install.sh")
    receipt["previous_installer_sha256"] = sha(installer)
    patch = installer_patch(installer.decode("utf-8").replace("\r\n", "\n"), descriptor)
    import json
    (output / "verification.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    (output / "adoption.patch").write_text(patch, encoding="utf-8", newline="\n")
    return output / "adoption.patch"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag", help="explicit published fork tag")
    parser.add_argument("--gh", required=True, type=Path, help="official checksum-pinned Linux gh executable")
    parser.add_argument("--output", required=True, type=Path, help="new local evidence directory")
    args = parser.parse_args()
    try:
        print(adopt(args.tag, args.output, GitHub(args.gh)))
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
