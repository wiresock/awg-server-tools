"""Pure, fail-closed policy for fork-owned BoringTun releases (Python 3.12+).

Inputs are exact JSON projections, not unrestricted REST objects. The trusted
caller fetches the PR and attempt-specific run, checks C's ancestry in master,
pins workflow IDs, validates the workflow at C, and hashes downloaded bytes.
This module does no I/O and cannot establish that evidence was fetched honestly.

PR projection: number/state/merged/merge_commit_sha/merged_at,
base={ref,repo:{full_name}}, head={sha,repo:{full_name}}.
Run projection: id/run_attempt/workflow_id/path/event/status/conclusion,
repository={full_name}, head_sha/head_branch/created_at, optional PR associations.
Artifact projection: id/name/digest/size_in_bytes/expired,
workflow_run={id,head_sha}. Its name is boringtun-<run ID>-<attempt>.

The descriptor schema is explicit in check_descriptor. It records C, B, R and P
separately. R may equal C; their roles are distinct, not necessarily their values.
Publication takes trusted readback state, including provenance_verified set ONLY
after independent verification, never from release prose or a downloaded field.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import math
import re


REPOSITORY = "Wiresock-Foundation/wiresock-boringtun"
BUILD_WORKFLOW = ".github/workflows/boringtun-artifacts.yml"
PUBLISH_WORKFLOW = ".github/workflows/boringtun-release.yml"
MASTER_REF = "refs/heads/master"
TARGETS = ("aarch64-apple-darwin", "aarch64-unknown-linux-musl", "armv7-unknown-linux-musleabihf",
           "x86_64-apple-darwin", "x86_64-unknown-linux-musl")
TARGET_SUFFIXES = {"x86_64-unknown-linux-musl": "linux-x86_64-musl",
                   "aarch64-unknown-linux-musl": "linux-aarch64-musl",
                   "armv7-unknown-linux-musleabihf": "linux-armv7-musleabihf",
                   "x86_64-apple-darwin": "macos-x86_64", "aarch64-apple-darwin": "macos-aarch64"}
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9._-]*\Z")


class PolicyError(ValueError):
    """Invalid/missing evidence or an immutable publication conflict."""


def _require(condition, message):
    if not condition:
        raise PolicyError(message)


def _keys(value, expected, label):
    _require(type(value) is dict, f"{label} must be an object")
    _require(set(value) == set(expected.split()), f"{label} has missing or unknown keys")


def _int(value, label):
    _require(type(value) is int and value > 0, f"{label} must be a positive integer")
    return value


def _match(value, pattern, label):
    _require(type(value) is str and pattern.fullmatch(value) is not None,
             f"invalid {label}")
    return value


def _sha(value):
    return _match(value, _SHA, "commit SHA")


def _digest(value):
    return _match(value, _DIGEST, "SHA-256")


def _repo(value, canonical=False):
    _match(value, _REPO, "repository")
    _require(not value.endswith(".git"), "repository must not end in .git")
    if canonical:
        _require(value == REPOSITORY, "noncanonical repository")
    return value


def _repository_object(value, canonical=False):
    _keys(value, "full_name", "repository")
    return _repo(value["full_name"], canonical)


def _date(value):
    _require(type(value) is str and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value),
             "timestamp must be a UTC REST timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise PolicyError("invalid timestamp") from exc


def load_json(raw):
    """Decode JSON with duplicate-key and nonfinite-number rejection."""
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def constant(_value):
        raise PolicyError("nonfinite JSON number")

    def finite_float(value):
        parsed = float(value)
        _require(math.isfinite(parsed), "nonfinite JSON number")
        return parsed

    _require(type(raw) in (str, bytes), "JSON must be text or bytes")
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant,
                          parse_float=finite_float)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise PolicyError("invalid JSON") from exc


def release_tag(version, source_commit, pr_number):
    """Return the deterministic release tag; PR number is the build identity."""
    _match(version, _VERSION, "CLI version")
    _sha(source_commit)
    _int(pr_number, "PR number")
    return f"boringtun-cli-{version}-g{source_commit[:12]}-b{pr_number}"


def archive_name(version, source_commit, target):
    """Preserve the existing format1 public archive filename (no build suffix)."""
    _match(version, _VERSION, "CLI version")
    _sha(source_commit)
    _require(type(target) is str and target in TARGETS, "unsupported target")
    return f"boringtun-cli-{version}-g{source_commit[:12]}-{TARGET_SUFFIXES[target]}.tar.gz"


def _base(value):
    _keys(value, "ref repo", "PR base")
    _require(value["ref"] == "master", "PR must target master")
    _repository_object(value["repo"], True)


def _head(value):
    _keys(value, "sha repo", "PR head")
    _sha(value["sha"])
    _repository_object(value["repo"])


def merged_request(pr, expected_number):
    """Validate a fresh merged-PR projection; use its POST-merge SHA for C.

    The REST API defines merge_commit_sha after merge for merge, squash and
    rebase alike: https://docs.github.com/en/rest/pulls/pulls#get-a-pull-request.
    Return schema/repository/pr/source_commit/pr_head_sha/pr_head_repository/
    merged_at. A fork head is legitimate; only the base must be canonical.
    """
    _keys(pr, "number state merged merge_commit_sha merged_at base head", "PR")
    _int(expected_number, "expected PR")
    _int(pr["number"], "PR number")
    _require(pr["number"] == expected_number, "wrong PR")
    _require(pr["state"] == "closed" and pr["merged"] is True, "PR is not merged and closed")
    _base(pr["base"])
    _head(pr["head"])
    _date(pr["merged_at"])
    return {"schema": 1, "repository": REPOSITORY, "pr": expected_number,
            "source_commit": _sha(pr["merge_commit_sha"]),
            "pr_head_sha": pr["head"]["sha"],
            "pr_head_repository": pr["head"]["repo"]["full_name"],
            "merged_at": pr["merged_at"]}


def _request(request):
    _keys(request, "schema repository pr source_commit pr_head_sha pr_head_repository merged_at", "request")
    _require(type(request["schema"]) is int and request["schema"] == 1, "unknown request schema")
    _repo(request["repository"], True)
    _int(request["pr"], "PR")
    _sha(request["source_commit"])
    _sha(request["pr_head_sha"])
    _repo(request["pr_head_repository"])
    _date(request["merged_at"])


def check_build_run(run, request, workflow_id):
    """Check attempt-specific API evidence and return a detached copy.

    The caller must also establish the trusted master-push workflow recipe at C;
    created_at is the original run creation time, never run_started_at on retry.
    Pin workflow_id from reviewed configuration, not from the run itself.
    Push run head_sha is the executed source C. PR-event head_sha is H instead;
    those runs are deliberately ineligible. C must independently identify one
    canonical merged-master PR; an unsigned artifact cannot establish that fact.
    """
    result = _check_build_identity(run, request, workflow_id)
    _require(run["status"] == "completed" and run["conclusion"] == "success", "build did not succeed")
    return result


def _check_build_identity(run, request, workflow_id):
    """Identity only, for read-only active-run inventory; never authorizes release."""
    _request(request)
    _keys(run, "id run_attempt workflow_id path event status conclusion repository head_sha head_branch created_at pull_requests", "build run")
    for key in ("id", "run_attempt", "workflow_id"):
        _int(run[key], key)
    _int(workflow_id, "expected workflow ID")
    _require(run["workflow_id"] == workflow_id and run["path"] == BUILD_WORKFLOW,
             "wrong build workflow")
    _repository_object(run["repository"], True)
    _require(run["event"] == "push" and run["head_branch"] == "master", "build must be a canonical master push")
    _sha(run["head_sha"])
    _require(run["head_sha"] == request["source_commit"], "build source differs from merged source")
    _require(_date(run["created_at"]) >= _date(request["merged_at"]), "run predates merge")
    prs = run["pull_requests"]
    _require(type(prs) is list and len(prs) <= 1, "ambiguous run PR associations")
    if prs:
        _keys(prs[0], "number head base", "run PR association")
        _int(prs[0]["number"], "run PR")
        _require(prs[0]["number"] == request["pr"], "wrong run PR")
        _base(prs[0]["base"])
        _head(prs[0]["head"])
        _require(prs[0]["head"]["sha"] == request["pr_head_sha"] and
                 prs[0]["head"]["repo"]["full_name"] == request["pr_head_repository"],
                 "run PR head mismatch")
    return deepcopy(run)


def merged_pr_number(pulls, source):
    """Select only an exact merged-master source from a fully paginated API list.

    This selects a candidate; the caller must independently GET that PR and
    validate merged_request. Commit association alone is not authorization.
    """
    _sha(source)
    _require(type(pulls) is list, "commit PR discovery must be a list")
    numbers = set()
    for pr in pulls:
        _require(type(pr) is dict, "invalid commit PR discovery entry")
        base = pr.get("base")
        _require(type(base) is dict and type(base.get("repo")) is dict,
                 "missing commit PR base identity")
        if (pr.get("state") == "closed" and pr.get("merged_at") is not None and
                pr.get("merge_commit_sha") == source and
                base.get("ref") == "master" and base["repo"].get("full_name") == REPOSITORY):
            number = _int(pr.get("number"), "discovered PR")
            _require(number not in numbers, "duplicate commit PR discovery entry")
            numbers.add(number)
    _require(len(numbers) == 1, "source must identify exactly one canonical merged-master PR")
    return next(iter(numbers))


def _artifact(artifact, run):
    _keys(artifact, "id name digest size_in_bytes expired workflow_run", "artifact")
    _int(artifact["id"], "artifact ID")
    _int(artifact["size_in_bytes"], "artifact size")
    _require(artifact["expired"] is False, "artifact expired")
    _require(artifact["name"] == f"boringtun-{run['id']}-{run['run_attempt']}", "wrong artifact attempt")
    _require(type(artifact["digest"]) is str and artifact["digest"].startswith("sha256:"),
             "artifact API digest required")
    _digest(artifact["digest"][7:])
    _keys(artifact["workflow_run"], "id head_sha", "artifact run")
    _int(artifact["workflow_run"]["id"], "artifact run ID")
    _require(artifact["workflow_run"] == {"id": run["id"], "head_sha": run["head_sha"]},
             "artifact run differs")
    return {"id": artifact["id"], "name": artifact["name"],
            "sha256": artifact["digest"][7:], "size_in_bytes": artifact["size_in_bytes"]}


def make_descriptor(request, run, artifact, publisher, archives):
    """Create RELEASE.json data from independently fetched/hashed evidence.

    publisher contains repository/workflow_id/workflow_path/ref/recipe_commit/
    run_id/run_attempt plus version/rust_toolchain/toolchain_sha256/
    notice_provenance_sha256 read from verified C/build inputs. archives is exactly
    five {target,name,sha256,binary_sha256,notice_sha256} records from trusted static inspection.
    This revalidates structure; the caller must pin run.workflow_id separately.
    """
    _request(request)
    _keys(publisher, "repository workflow_id workflow_path ref recipe_commit run_id run_attempt version rust_toolchain toolchain_sha256 notice_provenance_sha256", "publisher evidence")
    _repo(publisher["repository"], True)
    _require(type(run) is dict and "workflow_id" in run, "missing checked build run")
    run = check_build_run(run, request, run["workflow_id"])
    data = {"schema": 2, "repository": REPOSITORY, "pr": request["pr"],
            "source_commit": request["source_commit"], "version": publisher["version"],
            "build": request["pr"], "tag": release_tag(publisher["version"], request["source_commit"], request["pr"]),
            "artifact_format": 1, "build_run": {"id": run["id"], "run_attempt": run["run_attempt"],
            "workflow_id": run["workflow_id"], "workflow_path": run["path"],
            "recipe_commit": request["source_commit"]}, "artifact": _artifact(artifact, run),
            "publisher": {key: publisher[key] for key in
                          ("workflow_id", "workflow_path", "ref", "recipe_commit", "run_id", "run_attempt")},
            "archives": deepcopy(archives)}
    for key in ("rust_toolchain", "toolchain_sha256", "notice_provenance_sha256"):
        data[key] = publisher[key]
    return check_descriptor(data)


def check_descriptor(data):
    """Validate schema 2 signed descriptor; return a detached canonical-order copy.

    Validation is semantic, not cryptographic. Check the exact RELEASE.json bytes
    with gh before trusting its claims; reject noncanonical byte serialization.
    """
    _keys(data, "schema repository pr source_commit version build tag artifact_format rust_toolchain toolchain_sha256 notice_provenance_sha256 build_run artifact publisher archives", "descriptor")
    for key, version in (("schema", 2), ("artifact_format", 1)):
        _require(type(data[key]) is int and data[key] == version, f"unknown {key}")
    _repo(data["repository"], True)
    _sha(data["source_commit"])
    _int(data["pr"], "PR")
    _int(data["build"], "build")
    _require(data["build"] == data["pr"], "build identity must equal PR")
    _require(data["tag"] == release_tag(data["version"], data["source_commit"], data["pr"]), "wrong release tag")
    _match(data["rust_toolchain"], _VERSION, "Rust toolchain")
    for key in ("toolchain_sha256", "notice_provenance_sha256"):
        _digest(data[key])
    build = data["build_run"]
    _keys(build, "id run_attempt workflow_id workflow_path recipe_commit", "descriptor build")
    for key in ("id", "run_attempt", "workflow_id"):
        _int(build[key], key)
    _require(build["workflow_path"] == BUILD_WORKFLOW, "wrong build workflow path")
    _require(build["recipe_commit"] == data["source_commit"], "build recipe must be C")
    artifact = data["artifact"]
    _keys(artifact, "id name sha256 size_in_bytes", "descriptor artifact")
    _int(artifact["id"], "artifact ID")
    _int(artifact["size_in_bytes"], "artifact size")
    _digest(artifact["sha256"])
    _require(artifact["name"] == f"boringtun-{build['id']}-{build['run_attempt']}", "artifact attempt mismatch")
    publisher = data["publisher"]
    _keys(publisher, "workflow_id workflow_path ref recipe_commit run_id run_attempt", "descriptor publisher")
    for key in ("workflow_id", "run_id", "run_attempt"):
        _int(publisher[key], key)
    _require(publisher["workflow_path"] == PUBLISH_WORKFLOW and publisher["ref"] == MASTER_REF,
             "wrong promoter identity")
    _sha(publisher["recipe_commit"])
    archives = data["archives"]
    _require(type(archives) is list and len(archives) == len(TARGETS), "exactly five archives required")
    found = set()
    for item in archives:
        _keys(item, "target name sha256 binary_sha256 notice_sha256", "archive")
        _require(item["name"] == archive_name(data["version"], data["source_commit"], item["target"]), "wrong archive name")
        _require(item["target"] not in found, "duplicate target")
        found.add(item["target"])
        _digest(item["sha256"])
        _digest(item["binary_sha256"])
        _digest(item["notice_sha256"])
    _require(found == set(TARGETS), "archive target set differs")
    result = deepcopy(data)
    result["archives"].sort(key=lambda item: item["target"])
    return result


def canonical_bytes(descriptor):
    """The one supported RELEASE.json byte serialization, including trailing LF."""
    data = check_descriptor(descriptor)
    return (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def release_assets(descriptor):
    """Return exact seven release asset names -> SHA-256 digests."""
    data = check_descriptor(descriptor)
    assets = {item["name"]: item["sha256"] for item in data["archives"]}
    sums = "".join(f"{digest}  {name}\n" for name, digest in sorted(assets.items())).encode("ascii")
    assets["SHA256SUMS"] = hashlib.sha256(sums).hexdigest()
    assets["RELEASE.json"] = hashlib.sha256(canonical_bytes(data)).hexdigest()
    return assets


def publication_action(existing, desired):
    """Return create/resume/already-published, or raise PolicyError for conflict.

    existing=None means authenticated API absence, not a read error. Otherwise:
    {tag,target_commit,draft,descriptor,assets:{name:actual_readback_sha256},
    provenance_verified:bool}. The trusted caller verifies original provenance
    before setting that boolean. Existing published identities may have earlier
    B/P evidence; verify and retain their ORIGINAL descriptor/assets. For draft
    resume the caller must select exactly the original signed descriptor first.
    No deletion, replacement, upload or publication occurs in this function.
    """
    desired = check_descriptor(desired)
    if existing is None:
        return "create"
    _keys(existing, "tag target_commit draft descriptor assets provenance_verified", "existing release")
    _require(existing["provenance_verified"] is True, "original provenance not verified")
    _require(type(existing["draft"]) is bool, "draft must be boolean")
    original = check_descriptor(existing["descriptor"])
    _require(existing["tag"] == original["tag"] == desired["tag"], "release tag conflict")
    _require(existing["target_commit"] == original["source_commit"] == desired["source_commit"], "tag target conflict")
    stable = ("schema", "repository", "pr", "source_commit", "version", "build", "tag",
              "artifact_format", "rust_toolchain", "toolchain_sha256",
              "notice_provenance_sha256", "archives")
    _require(all(original[key] == desired[key] for key in stable), "release content conflict")
    assets = existing["assets"]
    _require(type(assets) is dict, "release assets must be an object")
    expected = release_assets(original)
    for name, digest in assets.items():
        _require(name in expected and digest == expected[name], "existing asset conflict")
    if existing["draft"]:
        _require(original == desired, "draft must reuse original descriptor")
        _require("RELEASE.json" in assets, "draft lacks signed release descriptor")
        return "resume"
    _require(assets == expected, "published release missing assets")
    return "already-published"


def attestation_arguments(path, descriptor):
    """Return gh argv (without executable); never execute or shell-quote it.

    Caller must pin gh 2.100.0 AND its distribution checksum, require exit zero,
    and consume only that process's stdout. A JSON file from a build artifact is
    not verified evidence. No --bundle override or user flags are accepted here.
    """
    data = check_descriptor(descriptor)
    _require(type(path) is str and path and "\x00" not in path, "invalid artifact path")
    signer = f"https://github.com/{REPOSITORY}/{PUBLISH_WORKFLOW}@{MASTER_REF}"
    recipe = data["publisher"]["recipe_commit"]
    return ["attestation", "verify", "--repo", REPOSITORY,
            "--cert-identity", signer, "--cert-oidc-issuer", "https://token.actions.githubusercontent.com",
            "--source-digest", recipe, "--signer-digest", recipe,
            "--source-ref", MASTER_REF, "--deny-self-hosted-runners",
            "--predicate-type", "https://slsa.dev/provenance/v1", "--format", "json", "--", path]


def check_verified_attestation(verification_result, descriptor, expected_subjects):
    """Validate untouched gh 2.100.0 JSON entry['verificationResult'].

    This is additional policy enforcement AFTER cryptographic verification by
    pinned gh, never a substitute for it. JSON cannot prove how it was obtained.
    The API reads the certificate's OIDC-derived invocation, not just the
    workflow-controlled predicate. Require exact subject names AND byte hashes;
    expected_subjects is a nonempty subset of the six signed release assets.
    A combined six-subject attestation must be checked against all six.

    Schema sources: cli/cli v2.100.0 pkg/cmd/attestation/verification/sigstore.go;
    sigstore/sigstore-go v1.3.0 pkg/verify/signed_entity.go, certificate_identity.go,
    pkg/fulcio/certificate/{summarize,extensions}.go; actions/toolkit provenance.
    Return {invocation, subjects:{name:sha256}, recipe_commit}.
    """
    data = check_descriptor(descriptor)
    result = verification_result
    _keys(result, "mediaType signature verifiedTimestamps verifiedIdentity statement", "verification result")
    _require(result["mediaType"] == "application/vnd.dev.sigstore.verificationresult+json;version=0.1",
             "unknown verification result schema")
    _keys(result["signature"], "certificate", "verified signature")
    cert = result["signature"]["certificate"]
    required = set(("certificateIssuer subjectAlternativeName issuer buildSignerURI buildSignerDigest "
                    "runnerEnvironment sourceRepositoryURI sourceRepositoryDigest sourceRepositoryRef "
                    "sourceRepositoryIdentifier sourceRepositoryOwnerURI sourceRepositoryOwnerIdentifier "
                    "buildConfigURI buildConfigDigest buildTrigger runInvocationURI "
                    "sourceRepositoryVisibilityAtSigning").split())
    legacy = set("githubWorkflowTrigger githubWorkflowSHA githubWorkflowName githubWorkflowRepository githubWorkflowRef".split())
    _require(type(cert) is dict and required <= set(cert) <= required | legacy,
             "certificate has missing or unknown fields")
    _require(all(type(value) is str and value for value in cert.values()), "invalid certificate field")
    repo_url = f"https://github.com/{REPOSITORY}"
    signer = f"{repo_url}/{PUBLISH_WORKFLOW}@{MASTER_REF}"
    publisher = data["publisher"]
    recipe = publisher["recipe_commit"]
    invocation = f"{repo_url}/actions/runs/{publisher['run_id']}/attempts/{publisher['run_attempt']}"
    required_values = {"subjectAlternativeName": signer, "issuer": "https://token.actions.githubusercontent.com",
                       "buildSignerURI": signer, "buildSignerDigest": recipe,
                       "runnerEnvironment": "github-hosted", "sourceRepositoryURI": repo_url,
                       "sourceRepositoryDigest": recipe, "sourceRepositoryRef": MASTER_REF,
                       "sourceRepositoryOwnerURI": "https://github.com/" + REPOSITORY.split("/")[0],
                       "buildConfigURI": signer, "buildConfigDigest": recipe,
                       "buildTrigger": "workflow_run", "runInvocationURI": invocation,
                       "sourceRepositoryVisibilityAtSigning": "public"}
    for key, expected in required_values.items():
        _require(cert[key] == expected, f"certificate {key} mismatch")
    for key in ("sourceRepositoryIdentifier", "sourceRepositoryOwnerIdentifier"):
        _require(re.fullmatch(r"[1-9][0-9]*", cert[key]) is not None, "invalid repository identifier")
    for key, expected in {"githubWorkflowTrigger": "workflow_run", "githubWorkflowSHA": recipe,
                          "githubWorkflowRepository": REPOSITORY, "githubWorkflowRef": MASTER_REF}.items():
        if key in cert:
            _require(cert[key] == expected, "legacy certificate field mismatch")

    identity = result["verifiedIdentity"]
    identity_required = {"subjectAlternativeName", "issuer"}
    _require(type(identity) is dict and identity_required <= set(identity) <=
             (required | legacy) - {"certificateIssuer"}, "unknown verified identity field")
    _keys(identity["subjectAlternativeName"], "subjectAlternativeName", "SAN matcher")
    # gh 2.100.0 intentionally uses an unrestricted Sigstore issuer matcher,
    # then verifies the exact issuer in its certificate-extension policy.
    # Source: cli/cli v2.100.0 pkg/cmd/attestation/verify/policy.go:101-121.
    # Match that precise output schema; the certificate issuer above and the
    # --cert-oidc-issuer argv remain exact, independent mandatory checks.
    _keys(identity["issuer"], "issuer regexp", "issuer matcher")
    _require(identity["subjectAlternativeName"]["subjectAlternativeName"] == signer and
             identity["issuer"] == {"issuer": "", "regexp": ".*"} and
             identity.get("runnerEnvironment") == "github-hosted", "unexpected pinned gh identity policy")
    for key in set(identity) - identity_required:
        _require(identity[key] == cert.get(key), "verified identity extension mismatch")
    timestamps = result["verifiedTimestamps"]
    _require(type(timestamps) is list and timestamps, "verified timestamp required")
    for timestamp in timestamps:
        _keys(timestamp, "type uri timestamp", "verified timestamp")
        _require(timestamp["type"] in ("Tlog", "TimestampAuthority"), "unknown timestamp type")
        _require(type(timestamp["uri"]) is str and timestamp["uri"], "missing timestamp URI")
        _require(type(timestamp["timestamp"]) is str, "invalid verified timestamp")
        try:
            parsed = datetime.fromisoformat(timestamp["timestamp"].replace("Z", "+00:00"))
        except ValueError as exc:
            raise PolicyError("invalid verified timestamp") from exc
        _require(parsed.tzinfo is not None, "verified timestamp lacks timezone")

    statement = result["statement"]
    _keys(statement, "_type subject predicateType predicate", "verified statement")
    _require(statement["_type"] == "https://in-toto.io/Statement/v1" and
             statement["predicateType"] == "https://slsa.dev/provenance/v1", "unknown statement schema")
    allowed_subjects = release_assets(data)
    del allowed_subjects["SHA256SUMS"]
    _require(type(expected_subjects) is dict and expected_subjects, "expected subjects required")
    for name, digest in expected_subjects.items():
        _require(name in allowed_subjects and digest == allowed_subjects[name], "expected subject conflicts with descriptor")
    _require(type(statement["subject"]) is list, "subjects must be a list")
    subjects = {}
    for subject in statement["subject"]:
        _keys(subject, "name digest", "subject")
        _keys(subject["digest"], "sha256", "subject digest")
        _require(type(subject["name"]) is str and subject["name"] not in subjects, "duplicate subject")
        subjects[subject["name"]] = _digest(subject["digest"]["sha256"])
    _require(subjects == expected_subjects, "attestation subject mismatch")

    predicate = statement["predicate"]
    _keys(predicate, "buildDefinition runDetails", "provenance predicate")
    definition = predicate["buildDefinition"]
    _keys(definition, "buildType externalParameters internalParameters resolvedDependencies", "build definition")
    _require(definition["buildType"] == "https://actions.github.io/buildtypes/workflow/v1", "unknown build type")
    _require(definition["externalParameters"] == {"workflow": {"ref": MASTER_REF, "repository": repo_url,
                                                              "path": PUBLISH_WORKFLOW}}, "predicate workflow mismatch")
    _require(definition["internalParameters"] == {"github": {"event_name": "workflow_run",
             "repository_id": cert["sourceRepositoryIdentifier"],
             "repository_owner_id": cert["sourceRepositoryOwnerIdentifier"],
             "runner_environment": "github-hosted"}}, "predicate GitHub identity mismatch")
    _require(definition["resolvedDependencies"] == [{"uri": f"git+{repo_url}@{MASTER_REF}",
                                                    "digest": {"gitCommit": recipe}}], "predicate recipe mismatch")
    _require(predicate["runDetails"] == {"builder": {"id": signer}, "metadata": {"invocationId": invocation}},
             "predicate invocation mismatch")
    return {"invocation": invocation, "subjects": subjects, "recipe_commit": recipe}
