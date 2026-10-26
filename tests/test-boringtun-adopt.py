"""Offline adoption regressions; synthetic gh output is not signature evidence."""
import copy
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("adopt", ROOT / "scripts/boringtun-adopt.py")
adopt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adopt)
policy = adopt.policy
platform_spec = importlib.util.spec_from_file_location("platform_fixtures", ROOT / "tests/test-boringtun-platform.py")
platform_fixtures = importlib.util.module_from_spec(platform_spec)
platform_spec.loader.exec_module(platform_fixtures)
C, R = "c" * 40, "e" * 40
REPO = policy.REPOSITORY


def digest(data):
    return hashlib.sha256(data).hexdigest()


def repository(name, ident, minimal=False):
    # Raw Actions attempt 40239937252/1 retained this minimal id/url/name shape
    # (verified read-only from GitHub); it did not include full_name.
    value = {'id':ident,'url':'https://api.github.com/repos/' + name,'name':name.split('/')[1]}
    if not minimal:
        value['full_name'] = name
    return value


def archive(target, variant=""):
    arch = target.split("-")[0]
    name = policy.archive_name("0.7.1", C, target)
    macos = target.endswith("-apple-darwin")
    if macos:
        binary = bytes(platform_fixtures.macho(arch))
    elif arch == "armv7":
        binary = bytes(platform_fixtures.elf(32, 40, 0x5000400))
    else:
        binary = bytes(platform_fixtures.elf(machine={"x86_64":62,"aarch64":183}[arch]))
    prefix = ("THIRD-PARTY LICENSES FOR boringtun-cli\n" + "=" * 80 +
              "\nBSD-3-Clause\n\nUsed by:\n  curve25519-dalek 4.1.3 <https://example.invalid>\n" + "-" * 80 +
              "\nCopyright (c) 2016-2021 isis agora lovecruft. All rights reserved.\n"
              "Copyright (c) 2016-2021 Henry de Valence. All rights reserved.\n"
              "Copyright (c) 2012 The Go Authors. All rights reserved.\n")
    runtime_file = "runtime-notices-macos.txt" if macos else "runtime-notices.txt"
    if variant == "wrong-notice-profile":
        runtime_file = "runtime-notices.txt" if macos else "runtime-notices-macos.txt"
    notices = prefix.encode() + (ROOT / "packaging/boringtun" / runtime_file).read_bytes()
    if variant == "missing-notices":
        notices = prefix.encode()
    manifest = dict(artifact_format="1", name="boringtun-cli", version="0.7.1",
                    source_repository="https://github.com/" + REPO, source_commit=C,
                    source_date_epoch="1790285008", target=target, os="macos" if macos else "linux", arch=arch,
                    libc="libSystem" if macos else "musl", linkage="dynamic-system" if macos else "static", rust_toolchain="1.98.1", rustc="rustc 1.98.1",
                    cargo="cargo 1.98.1", build_command="cargo build --release --locked",
                    build_profile="release,strip=symbols", rustflags="remapped", binary="boringtun-cli",
                    binary_sha256=digest(binary), license="LICENSE (BSD-3-Clause)",
                    third_party_licenses="THIRD-PARTY-LICENSES")
    if variant == "wrong-arch":
        manifest["arch"] = "i686"
    files = {"boringtun-cli": binary, "MANIFEST": "".join(f"{k}={v}\n" for k, v in manifest.items()).encode(),
             "THIRD-PARTY-LICENSES": notices, "LICENSE": (ROOT / "packaging/boringtun/fork-license.txt").read_bytes()}
    if variant == "extra-member":
        files["README"] = b"unexpected\n"
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz", format=tarfile.USTAR_FORMAT) as tar:
        directory = tarfile.TarInfo(name[:-7])
        directory.type, directory.mode = tarfile.DIRTYPE, 0o755
        tar.addfile(directory)
        for filename, data in sorted(files.items()):
            member = tarfile.TarInfo(name[:-7] + "/" + filename)
            member.size = len(data)
            member.mode = 0o755 if filename == "boringtun-cli" else 0o644
            tar.addfile(member, io.BytesIO(data))
    data = raw.getvalue()
    if variant in ("oversized-member", "pax-bomb", "symlink"):
        member = tarfile.TarInfo(name[:-7] + "/boringtun-cli")
        member.size = 1024 * 1024 * 1024
        if variant == "pax-bomb":
            member.type = tarfile.XHDTYPE
        elif variant == "symlink":
            member.type, member.size, member.linkname = tarfile.SYMTYPE, 0, "/etc/passwd"
        data = gzip.compress(member.tobuf(format=tarfile.USTAR_FORMAT) + bytes(1024))
    elif variant == "padding-bomb":
        data = gzip.compress(gzip.decompress(data) + bytes(256 * 1024))
    return {"target": target, "name": name, "sha256": digest(data), "binary_sha256": digest(binary), "notice_sha256": digest(notices)}, data, notices


def verification(descriptor, subjects):
    """Schema fixture from gh2.100.0/sigstore-go1.3.0, never a signed bundle."""
    repo = "https://github.com/" + REPO
    signer = repo + "/" + policy.PUBLISH_WORKFLOW + "@refs/heads/master"
    invocation = repo + "/actions/runs/500/attempts/3"
    cert = dict(certificateIssuer="CN=sigstore-intermediate,O=sigstore.dev", subjectAlternativeName=signer,
                issuer="https://token.actions.githubusercontent.com", buildSignerURI=signer,
                buildSignerDigest=R, runnerEnvironment="github-hosted", sourceRepositoryURI=repo,
                sourceRepositoryDigest=R, sourceRepositoryRef="refs/heads/master", sourceRepositoryIdentifier="1234",
                sourceRepositoryOwnerURI="https://github.com/Wiresock-Foundation", sourceRepositoryOwnerIdentifier="5678",
                buildConfigURI=signer, buildConfigDigest=R, buildTrigger="workflow_run", runInvocationURI=invocation,
                sourceRepositoryVisibilityAtSigning="public")
    predicate = {"buildDefinition": {"buildType": "https://actions.github.io/buildtypes/workflow/v1",
                 "externalParameters": {"workflow": {"ref": "refs/heads/master", "repository": repo, "path": policy.PUBLISH_WORKFLOW}},
                 "internalParameters": {"github": {"event_name": "workflow_run", "repository_id": "1234",
                    "repository_owner_id": "5678", "runner_environment": "github-hosted"}},
                 "resolvedDependencies": [{"uri": "git+" + repo + "@refs/heads/master", "digest": {"gitCommit": R}}]},
                 "runDetails": {"builder": {"id": signer}, "metadata": {"invocationId": invocation}}}
    result = {"mediaType": "application/vnd.dev.sigstore.verificationresult+json;version=0.1", "signature": {"certificate": cert},
              "verifiedTimestamps": [{"type": "Tlog", "uri": "https://rekor.sigstore.dev", "timestamp": "2026-10-25T12:03:00Z"}],
              "verifiedIdentity": {"subjectAlternativeName": {"subjectAlternativeName": signer}, "issuer": {"issuer": "", "regexp": ".*"},
                                   "runnerEnvironment": "github-hosted"},
              "statement": {"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://slsa.dev/provenance/v1",
                "subject": [{"name": name, "digest": {"sha256": value}} for name, value in subjects.items()], "predicate": predicate}}
    return [{"verificationResult": result}]


class FakeGitHub:
    digest = next(iter(adopt.GH_SHA256))

    def __init__(self, variant=""):
        provenance = (ROOT / "packaging/boringtun/runtime-provenance.json").read_bytes()
        source = json.loads(provenance)
        toolchain = {key: source[key] for key in ("rust_toolchain", "rust_commit", "llvm_commit", "inputs")}
        records = [archive(target, variant) for target in policy.TARGETS]
        self.descriptor = dict(schema=2, repository=REPO, pr=42, source_commit=C, version="0.7.1", build=42,
            tag=policy.release_tag("0.7.1", C, 42), artifact_format=1, rust_toolchain="1.98.1",
            toolchain_sha256=digest(json.dumps(toolchain, sort_keys=True, separators=(",", ":")).encode()),
            notice_provenance_sha256=digest(provenance),
            build_run={"id": 100, "run_attempt": 2, "workflow_id": 200, "workflow_path": policy.BUILD_WORKFLOW, "recipe_commit": C},
            artifact={"id": 300, "name": "boringtun-100-2", "sha256": "1" * 64, "size_in_bytes": 1000},
            publisher={"workflow_id": 400, "workflow_path": policy.PUBLISH_WORKFLOW, "ref": "refs/heads/master",
                       "recipe_commit": R, "run_id": 500, "run_attempt": 3}, archives=[record[0] for record in records])
        self.files = {record[0]["name"]: record[1] for record in records}
        self.rebuild()
        self.wrong_tag = False
        self.attestation_edit = None
        self.combined = False
        self.publisher_status = "success"
        self.sign_status = "success"
        self.build_status = "success"
        self.build_created = "2026-10-25T12:00:01Z"
        self.deleted_head = False
        self.retained_head = True
        self.association_head = "a" * 40
        self.calls = []

    def rebuild(self):
        self.files["RELEASE.json"] = policy.canonical_bytes(self.descriptor)
        self.files["SHA256SUMS"] = "".join(f"{item['sha256']}  {item['name']}\n" for item in sorted(self.descriptor["archives"], key=lambda i:i["name"])).encode()
        self.assets = [{"id": i + 1, "name": name, "size": len(data), "state": "uploaded"} for i, (name, data) in enumerate(self.files.items())]
        self.release = {"id": 1000, "tag_name": self.descriptor["tag"], "draft": False, "prerelease": False,
                        "html_url": f"https://github.com/{REPO}/releases/tag/{self.descriptor['tag']}", "assets": self.assets}

    def api(self, endpoint):
        self.calls.append(endpoint)
        if endpoint == f"repos/{REPO}/pulls/42":
            return {"number":42,"state":"closed","merged":True,"merge_commit_sha":C,"merged_at":"2026-10-25T12:00:00Z",
                    "base":{"ref":"master","repo":repository(REPO,1234)},"head":{"sha":"a"*40,"repo":None if self.deleted_head else repository("contributor/fork",6789)}}
        if endpoint == f"repos/{REPO}/actions/workflows/boringtun-artifacts.yml":
            return {"id": 200, "path": policy.BUILD_WORKFLOW}
        if endpoint == f"repos/{REPO}/actions/runs/100/attempts/2":
            return {"id": 100, "run_attempt": 2, "workflow_id": 200,
                    "path": policy.BUILD_WORKFLOW, "event": "pull_request",
                    "status": "completed", "conclusion": self.build_status, "head_sha": C,
                    "repository": {"id": 1234, "full_name": REPO}, "created_at": self.build_created,
                    "pull_requests": [{"number":42,"base":{"ref":"master","repo":repository(REPO,1234,True)},
                                       "head":{"sha":self.association_head,"repo":repository("contributor/fork",6789,True) if self.retained_head else None}}]}
        if endpoint == f"repos/{REPO}/actions/workflows/boringtun-release.yml":
            return {"id": 400, "path": policy.PUBLISH_WORKFLOW}
        if endpoint == f"repos/{REPO}/actions/runs/500/attempts/3":
            return {"id": 500, "run_attempt": 3, "workflow_id": 400,
                    "path": policy.PUBLISH_WORKFLOW, "event": "workflow_run",
                    "status": "completed", "conclusion": self.publisher_status, "head_sha": R, "head_branch": "master",
                    "repository": {"id": 1234, "full_name": REPO}}
        if endpoint == f"repos/{REPO}/actions/runs/500/attempts/3/jobs?per_page=100&page=1":
            return {"total_count":2,"jobs":[{"name":"Validate completed build","run_id":500,"status":"completed","conclusion":"success"},
                                            {"name":"Attest verified content","run_id":500,"status":"completed","conclusion":self.sign_status}]}
        if endpoint.endswith("/git/ref/tags/" + self.descriptor["tag"]):
            return {"ref": "refs/tags/" + self.descriptor["tag"], "object": {"type": "commit", "sha": "a"*40 if self.wrong_tag else C}}
        if endpoint == f"repos/{REPO}":
            return {"full_name": REPO, "id": 1234, "owner": {"id": 5678}}
        return copy.deepcopy(self.release)

    def download(self, ident):
        name = next(a["name"] for a in self.assets if a["id"] == ident)
        return self.files[name]

    def verify(self, path, descriptor):
        subjects = policy.release_assets(descriptor)
        del subjects["SHA256SUMS"]
        result = verification(descriptor, subjects if self.combined else {path.name: subjects[path.name]})
        if self.attestation_edit:
            self.attestation_edit(result[0]["verificationResult"])
        return result


class AdoptionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.out = Path(self.temp.name) / "adoption"
        self.gh = FakeGitHub()
        self.tag = self.gh.descriptor["tag"]

    def run_adoption(self):
        return adopt.adopt(self.tag, self.out, self.gh)

    def test_complete_release_produces_patch_without_editing_checkout(self):
        before = (ROOT / "amneziawg-install.sh").read_bytes()
        result = self.run_adoption()
        self.assertTrue(result.is_file())
        self.assertIn(f'AWG_BT_RELEASE_TAG="{self.tag}"', result.read_text())
        self.assertIn(f"https://github.com/{REPO}/releases/download/", result.read_text())
        self.assertEqual(before, (ROOT / "amneziawg-install.sh").read_bytes())
        self.assertTrue((self.out / "candidate-pin.env").is_file())
        self.assertEqual(json.loads((self.out / "verification.json").read_text())["gh_version"], "2.100.0")

    def test_combined_six_subject_attestation_accepted(self):
        self.gh.combined = True
        self.assertTrue(self.run_adoption().is_file())

    def test_full_five_target_release_only_updates_three_linux_selections(self):
        result = self.run_adoption()
        self.assertEqual(len(self.gh.descriptor['archives']), 5)
        self.assertEqual(len(self.gh.assets), 7)
        self.assertEqual(len(json.loads((self.out / 'verification.json').read_text())['verified_attestations']), 6)
        additions = '\n'.join(line for line in result.read_text().splitlines() if line.startswith('+AWG_BT_RELEASE_'))
        for suffix, fragment in [('X86_64','linux-x86_64-musl'),('AARCH64','linux-aarch64-musl'),('ARMV7','linux-armv7-musleabihf')]:
            self.assertIn(f'AWG_BT_RELEASE_ASSET_{suffix}="boringtun-cli-0.7.1-gcccccccccccc-{fragment}.tar.gz"', additions)
        self.assertNotIn('macos-', additions)

    def test_missing_macos_asset_is_not_ignored_by_linux_consumer(self):
        self.gh.release['assets'] = [asset for asset in self.gh.assets if 'macos-aarch64' not in asset['name']]
        with self.assertRaisesRegex(policy.PolicyError, 'seven assets'):
            self.run_adoption()

    def test_arbitrary_extra_asset_is_rejected(self):
        self.gh.release['assets'].append({'id':99,'name':'README','size':1,'state':'uploaded'})
        with self.assertRaisesRegex(policy.PolicyError, 'seven assets'):
            self.run_adoption()

    def test_each_archive_has_its_own_signed_notice_hash(self):
        mac = next(item for item in self.gh.descriptor['archives'] if item['target'] == 'x86_64-apple-darwin')
        mac['notice_sha256'] = '9' * 64
        self.gh.rebuild()
        with self.assertRaisesRegex(policy.PolicyError, 'signed notice checksum'):
            self.run_adoption()

    def test_wrong_runtime_notice_profile_is_rejected_for_every_target(self):
        self.gh = FakeGitHub('wrong-notice-profile')
        with self.assertRaisesRegex(policy.PolicyError, 'archive/notice'):
            self.run_adoption()

    def test_no_latest_or_unsafe_tag(self):
        for tag in ("latest", "master", "v0.7.1", self.tag + "/../../x", self.tag + "\n", self.tag.replace("-b42", "-b0")):
            with self.subTest(tag=tag), self.assertRaises(policy.PolicyError):
                adopt.adopt(tag, self.out, self.gh)
        self.assertFalse(self.out.exists())

    def test_existing_output_is_never_overwritten(self):
        self.out.mkdir()
        with self.assertRaisesRegex(policy.PolicyError, "new directory"):
            self.run_adoption()

    def test_draft_prerelease_foreign_owner_and_missing_asset_rejected(self):
        for field, value in (("draft", True), ("prerelease", True), ("html_url", "https://github.com/attacker/fork"), ("assets", [])):
            self.gh = FakeGitHub()
            self.gh.release[field] = value
            with self.subTest(field=field), self.assertRaises(policy.PolicyError):
                self.run_adoption()
        self.assertFalse(self.out.exists())

    def test_wrong_tag_target_rejected(self):
        self.gh.wrong_tag = True
        with self.assertRaisesRegex(policy.PolicyError, "tag target"):
            self.run_adoption()

    def test_original_publisher_failure_after_signing_does_not_invalidate_release(self):
        self.gh.publisher_status = "failure"
        self.assertTrue(self.run_adoption().is_file())

    def test_failed_original_signing_job_cannot_be_adopted(self):
        self.gh.sign_status = "failure"
        with self.assertRaisesRegex(policy.PolicyError, "publisher attempt security gate"):
            self.run_adoption()

    def test_failed_build_attempt_cannot_be_adopted(self):
        self.gh.build_status = "failure"
        with self.assertRaisesRegex(policy.PolicyError, "build attempt"):
            self.run_adoption()

    def test_run_created_before_merge_cannot_be_adopted(self):
        self.gh.build_created = "2026-10-25T11:59:59Z"
        with self.assertRaisesRegex(policy.PolicyError, "predates merged"):
            self.run_adoption()

    def test_download_hash_or_size_tampering_rejected(self):
        name = self.gh.descriptor["archives"][0]["name"]
        self.gh.files[name] += b"tampered"
        with self.assertRaisesRegex(policy.PolicyError, "checksum/size"):
            self.run_adoption()
        self.assertFalse((self.out / "adoption.patch").exists())

    def test_noncanonical_descriptor_rejected(self):
        self.gh.files["RELEASE.json"] = json.dumps(self.gh.descriptor, indent=2).encode()
        next(a for a in self.gh.assets if a["name"] == "RELEASE.json")["size"] = len(self.gh.files["RELEASE.json"])
        with self.assertRaisesRegex(policy.PolicyError, "noncanonical"):
            self.run_adoption()

    def test_wrong_attestation_run_attempt_and_owner_rejected(self):
        for key, value in (("runInvocationURI", f"https://github.com/{REPO}/actions/runs/500/attempts/2"),
                           ("sourceRepositoryIdentifier", "999"), ("runnerEnvironment", "self-hosted"),
                           ("buildSignerDigest", "a" * 40)):
            self.gh.attestation_edit = lambda result, k=key, v=value: result["signature"]["certificate"].update({k:v})
            results = self.gh.verify(Path("RELEASE.json"), self.gh.descriptor)
            with self.subTest(key=key), self.assertRaisesRegex(policy.PolicyError, "no attestation"):
                adopt.verify_attestation(results, self.gh.descriptor, "RELEASE.json", {"id":1234,"owner":{"id":5678}})

    def test_signed_but_incomplete_notices_wrong_arch_extra_member_rejected(self):
        for variant in ("missing-notices", "wrong-arch", "extra-member"):
            self.gh = FakeGitHub(variant)
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as tmp, self.assertRaisesRegex(policy.PolicyError, "archive"):
                adopt.adopt(self.tag, Path(tmp) / "out", self.gh)

    def test_unsigned_verification_json_cannot_stand_in_for_gh_result(self):
        with self.assertRaises(policy.PolicyError):
            adopt.verify_attestation([{"statement": {}}], self.gh.descriptor, "RELEASE.json", {"id":1234,"owner":{"id":5678}})

    def test_unreviewed_runtime_policy_rejected(self):
        self.gh.descriptor["notice_provenance_sha256"] = "9" * 64
        self.gh.rebuild()
        with self.assertRaisesRegex(policy.PolicyError, "unreviewed notice provenance"):
            self.run_adoption()

    def test_binary_hash_must_match_signed_descriptor(self):
        self.gh.descriptor["archives"][0]["binary_sha256"] = "9" * 64
        self.gh.rebuild()
        with self.assertRaisesRegex(policy.PolicyError, "signed binary checksum"):
            self.run_adoption()

    def test_only_pinned_gh_binary_can_be_used(self):
        fake = Path(self.temp.name) / "gh"
        fake.write_bytes(b"#!/bin/sh\necho gh version 2.100.0\n")
        with self.assertRaisesRegex(policy.PolicyError, "not a pinned official"):
            adopt.GitHub(fake)

    def test_github_adapter_only_uses_get_and_exact_attestation_flags(self):
        client = adopt.GitHub.__new__(adopt.GitHub)
        commands = []
        client.run = lambda argv: commands.append(argv) or b"[]"
        client.api(f"repos/{REPO}")
        client.download(123)
        client.verify(Path("/tmp/RELEASE.json"), self.gh.descriptor)
        for argv in commands[:2]:
            self.assertEqual(argv[:6], ["api", "--hostname", "github.com", "--method", "GET", *argv[5:6]])
        verify = commands[2]
        self.assertEqual(verify[:2], ["attestation", "verify"])
        self.assertEqual(verify[verify.index("--repo") + 1], REPO)
        self.assertEqual(verify[verify.index("--signer-digest") + 1], R)
        self.assertEqual(verify[verify.index("--source-digest") + 1], R)
        self.assertIn("--deny-self-hosted-runners", verify)
        self.assertNotIn("--bundle", verify)

    def test_changing_release_on_readback_prevents_patch(self):
        original_api = self.gh.api
        calls = 0
        def changing(endpoint):
            nonlocal calls
            value = original_api(endpoint)
            if "/releases/tags/" in endpoint:
                calls += 1
                if calls == 2:
                    value["assets"][0]["id"] = 999
            return value
        self.gh.api = changing
        with self.assertRaisesRegex(policy.PolicyError, "changed during"):
            self.run_adoption()
        self.assertFalse((self.out / "adoption.patch").exists())

    def test_legacy_installers_remain_patchable_and_bad_duplicates_fail(self):
        original = (ROOT / "amneziawg-install.sh").read_text()
        for url in ("https://github.com/wiresock/awg-server-tools/releases/download", "https://github.com/wiresock/amneziawg-install/releases/download"):
            text = original.replace("https://github.com/wiresock/awg-server-tools/releases/download", url)
            self.assertIn(self.tag, adopt.installer_patch(text, self.gh.descriptor))
        with self.assertRaises(policy.PolicyError):
            adopt.installer_patch(original + '\nAWG_BT_RELEASE_BUILD="1"\n', self.gh.descriptor)

    def same_identity_installer(self):
        """Apply only generated constant additions to a local text fixture."""
        original = (ROOT / "amneziawg-install.sh").read_text()
        additions = [line[1:] for line in adopt.installer_patch(original, self.gh.descriptor).splitlines() if line.startswith('+AWG_BT_RELEASE_')]
        for added in additions:
            key = added.split('=', 1)[0]
            original = '\n'.join(added if line.startswith(key + '=') else line for line in original.split('\n'))
        return original

    def test_same_store_identity_cannot_change_bytes_across_release_owners(self):
        original = self.same_identity_installer()
        for owner in (REPO, 'wiresock/awg-server-tools', 'wiresock/amneziawg-install'):
            old = original.replace(f'https://github.com/{REPO}/releases/download/', f'https://github.com/{owner}/releases/download/')
            for field in ('sha256', 'binary_sha256'):
                changed = copy.deepcopy(self.gh.descriptor)
                linux = next(item for item in changed['archives'] if item['target'] == 'x86_64-unknown-linux-musl')
                linux[field] = '9' * 64
                with self.subTest(owner=owner, field=field), self.assertRaisesRegex(policy.PolicyError, 'store identity'):
                    adopt.installer_patch(old, changed)

    def test_identical_bytes_can_change_download_owner(self):
        original = self.same_identity_installer().replace(f'https://github.com/{REPO}/releases/download/',
                                                        'https://github.com/wiresock/awg-server-tools/releases/download/')
        self.assertIn(f'+AWG_BT_RELEASE_BASE_URL="https://github.com/{REPO}/', adopt.installer_patch(original, self.gh.descriptor))

    def test_full_commit_collision_under_same_store_prefix_is_rejected(self):
        original = self.same_identity_installer()
        changed = copy.deepcopy(self.gh.descriptor)
        changed['source_commit'] = C[:12] + 'd' * 28
        changed['build_run']['recipe_commit'] = changed['source_commit']
        with self.assertRaisesRegex(policy.PolicyError, 'store identity'):
            adopt.installer_patch(original, changed)

    def test_deleted_contributor_repository_uses_original_run_identity(self):
        self.gh.deleted_head = True
        self.assertTrue(self.run_adoption().is_file())

    def test_real_github_minimal_repo_association_shape_is_supported(self):
        self.assertTrue(self.run_adoption().is_file())
        proof = json.loads((self.out / 'verification.json').read_text())['run_evidence']
        self.assertEqual(proof['retained_head_repository']['id'], 6789)
        self.assertEqual(proof['retained_head_repository']['full_name'], 'contributor/fork')

    def test_repository_projection_rejects_ambiguous_urls_and_identity_changes(self):
        good = repository('contributor/fork',6789,True)
        for key,value in [('id',True),('id',0),('name','another'),('full_name','attacker/fork'),
                          ('url','https://api.github.com/repos/contributor/fork/'),
                          ('url','https://api.github.com/repos/contributor/fork?x=1'),
                          ('url','https://api.github.com/repos/contributor/fork#x'),
                          ('url','https://api.github.com/repos/contributor/%66ork'),
                          ('url','https://api.github.com@attacker.invalid/repos/contributor/fork')]:
            changed = dict(good)
            changed[key] = value
            with self.subTest(key=key,value=value), self.assertRaises(policy.PolicyError):
                adopt.repository_evidence(changed)

    def test_current_head_repository_id_must_match_retained_identity(self):
        original_api = self.gh.api
        def different_id(endpoint):
            result = original_api(endpoint)
            if endpoint.endswith('/pulls/42'):
                result['head']['repo']['id'] = 999
            return result
        self.gh.api = different_id
        with self.assertRaisesRegex(policy.PolicyError, 'head repository numeric identity differs'):
            self.run_adoption()

    def test_repository_rename_preserves_original_numeric_identity(self):
        original_api = self.gh.api
        def renamed(endpoint):
            result = original_api(endpoint)
            if endpoint.endswith('/pulls/42'):
                result['head']['repo'] = repository('contributor/renamed',6789)
            return result
        self.gh.api = renamed
        self.assertTrue(self.run_adoption().is_file())

    def test_missing_original_contributor_identity_has_actionable_error(self):
        self.gh.deleted_head = True
        self.gh.retained_head = False
        with self.assertRaisesRegex(policy.PolicyError, 'retained contributor repository identity.*reviewed immutable'):
            self.run_adoption()
        self.assertFalse((self.out / 'adoption.patch').exists())

    def test_deleted_repository_does_not_relax_exact_run_pr_head(self):
        self.gh.deleted_head = True
        self.gh.association_head = "b" * 40
        with self.assertRaisesRegex(policy.PolicyError, 'run PR head mismatch'):
            self.run_adoption()

    def test_archive_preinspection_rejects_large_headers_and_padding_bombs(self):
        name = self.gh.descriptor['archives'][0]['name']
        member = tarfile.TarInfo(name[:-7] + '/boringtun-cli')
        member.size = 1024 * 1024 * 1024
        raw = gzip.compress(member.tobuf(format=tarfile.USTAR_FORMAT) + bytes(1024))
        path = Path(self.temp.name) / name
        path.write_bytes(raw)
        with self.assertRaisesRegex(policy.PolicyError, 'member size'):
            adopt.preinspect_archive(path, name)
        path.write_bytes(gzip.compress(bytes(256 * 1024)))
        with self.assertRaisesRegex(policy.PolicyError, 'padding'):
            adopt.preinspect_archive(path, name)

    def test_archive_bombs_and_links_never_reach_extraction(self):
        for variant in ('oversized-member', 'pax-bomb', 'padding-bomb', 'symlink'):
            self.gh = FakeGitHub(variant)
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as tmp, patch.object(adopt.subprocess, 'run') as process:
                with self.assertRaisesRegex(policy.PolicyError, 'archive'):
                    adopt.adopt(self.tag, Path(tmp) / 'out', self.gh)
                process.assert_not_called()

    def test_publisher_job_evidence_is_paged_and_bound_to_original_attempt(self):
        original_api = self.gh.api
        prefix = f'repos/{REPO}/actions/runs/500/attempts/3/jobs?per_page=100&page='
        def paged(endpoint):
            if endpoint == prefix + '1':
                return {'total_count':101,'jobs':[{'name':'Validate completed build','run_id':500,'status':'completed','conclusion':'success'}] + [{'name':f'Other {n}'} for n in range(99)]}
            if endpoint == prefix + '2':
                return {'total_count':101,'jobs':[{'name':'Attest verified content','run_id':500,'status':'completed','conclusion':'success'}]}
            return original_api(endpoint)
        self.gh.api = paged
        self.assertTrue(self.run_adoption().is_file())

    def test_publisher_security_job_from_another_run_is_rejected(self):
        original_api = self.gh.api
        def wrong_run(endpoint):
            response = original_api(endpoint)
            if endpoint.endswith('/jobs?per_page=100&page=1'):
                response['jobs'][1]['run_id'] = 499
            return response
        self.gh.api = wrong_run
        with self.assertRaisesRegex(policy.PolicyError, 'security gate'):
            self.run_adoption()


if __name__ == "__main__":
    unittest.main()
