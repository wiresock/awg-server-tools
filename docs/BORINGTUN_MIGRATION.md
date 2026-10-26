# Fork-owned BoringTun releases

## Current implementation status

The local patch implements the read-only five-platform build workflow, strict
release policy/orchestration and AWG adoption tooling. The fork's
`.github/workflows/boringtun-release.yml` is intentionally absent: local creation
of its future OIDC, attestation-write and release-write jobs awaits explicit
owner approval after an automatic approval review denial. End-to-end publisher
wiring is incomplete and unreviewed. `release-policy.json` remains disabled,
with attribution unresolved. Nothing in this patch activates publication or
changes existing releases or production.

The sections below describe the intended completed contract and the remaining
activation gates, not a claim that automatic publication already works.

The canonical producer moves to `Wiresock-Foundation/wiresock-boringtun`.
Each merged PR targeting its master branch has a distinct source-based tag:
`boringtun-cli-<CLI version>-g<source SHA first 12>-b<PR number>`. The complete
40-character source SHA is retained in MANIFEST and signed RELEASE.json.
The PR's merged result identifies the source for merge, squash and rebase
strategies; the PR head alone is not the release source. Direct pushes do not
request releases. AWG adoption remains an explicit, reviewed version/hash patch.

## Phased activation

1. Review both repository changes and resolve the source attribution gate.
   The fork's release-policy configuration starts disabled, with unresolved
   evidence listed. This implementation task does not activate or dispatch it.
2. Merge the AWG retirement change only with owner approval. Its current Release
   workflow has no publisher, and its Artifacts workflow runs consumer checks.
   The Runtime workflow tests the exact published installer release rather than
   building a separate artifact with placeholder notices. Historical releases,
   assets, tags and installer defaults remain unchanged.
3. With the owner's AWG access, audit all existing drafts and queued/running
   legacy publishers, record their disposition, and **disable the historical
   publishing workflow through GitHub**. A fork token or anonymous release list
   cannot prove drafts are absent. A current-YAML edit cannot prevent historical
   reruns. This repository does not change those settings or create credentials.
4. Record real merge/squash/rebase event and run-attempt fixtures, canonical
   repository/workflow IDs, and pinned-gh verified-attestation fixtures. Resolve
   every activation blocker through review before enabling the fork publisher.
5. Review the first eligible fork release and use `scripts/boringtun-adopt.py`
   to generate a local adoption patch. Review its exact tag, source, toolchain,
   notices, all five archive/binary hashes and the three Linux installer
   selections in a separate AWG PR.
   See the AWG repository's `docs/BORINGTUN_ADOPTION.md`.

## Artifact and trust contract

Five targets each compile/package twice and require identical bytes: Linux
x86_64/ARM64, Linux ARMv7 hard-float, and macOS Intel/Apple Silicon. Linux
x86_64/ARM64 and both Apple lanes are native; ARMv7 is cross-built and exercised
through QEMU, explicitly separate from physical Raspberry Pi validation.
Linux uses static ELF/TUN/interop gates; macOS uses Mach-O/system-library and
native utun gates. Binary archives keep four members. The seven release assets
are five archives, SHA256SUMS and schema-2 RELEASE.json; six subjects (the five
archives and descriptor) are attested. The descriptor binds source PR/commit, recipe commit, successful
build run/attempt and artifact digest, publisher workflow/run/attempt, toolchain
and notice provenance, including a per-archive notice hash. The promoter checks the exact selected attempt and
verified certificate/invocation identity. Downloaded binaries are never executed
in signing or publication jobs.

The descriptor's `toolchain_sha256` binds the reviewed Rust version, Rust/LLVM
source commits and pinned input manifest. Compiler/SDK receipts from each build
are supplemental CI artifacts; their bytes are not included in that digest.
Native compiler/SDK/Homebrew installation provenance therefore remains an
explicit activation gate. Do not describe this digest as attesting every host
tool or as establishing a fully hermetic build.

Builds have `contents: read`. Signing receives only the necessary OIDC and
attestation writes; publication receives content writes separately. Trusted
scripts come from the promoter's fixed workflow revision; source C executes
only in isolated read-only jobs. Existing maintainers' authentication can be
used for read-only local adoption; no new credentials are introduced.

Retries recover and verify the original signed descriptor rather than changing
its run IDs. The descriptor is uploaded first and its digest recorded in draft
metadata. Existing asset names are never overwritten. Conflicts and uncertain
writes require read-back and fail closed. Per-PR concurrency avoids replacing
unrelated pending merge runs; reconciliation exposes missing releases.

## Explicit platform limitations

GitHub can suppress merge-triggered workflows for merges made using
GITHUB_TOKEN. Reconciliation must expose the missing build; rerunning a
nonexistent run is not recovery. A reviewed recovery route and real event
fixtures remain activation prerequisites, not claimed implementation proof.

Creating a tag at an older merged commit whose workflow files differ from the
current default branch may require authorization beyond `contents: write`.
Such a publication remains blocked and visible. The owner must choose a
reviewed recovery procedure or authorize a changed tagging model. This change
does not broaden credentials, retarget the tag silently or skip that merge.

## Compatibility and rollback

The installer continues embedding its existing published AWG release,
`boringtun-cli-0.7.1-ge94c04f3f4fd-b1`, until a later adoption PR. Old AWG and
renamed-repository URLs remain accepted alongside the exact canonical fork URL.
The source repository, archive naming and four-member format stay compatible.
The installed cache key includes source/build but not publisher: adoption must
reject reuse of an existing source/build identity for different binary bytes.
Rollback uses the installed prior immutable release and configuration checks;
neither migration nor a fork release automatically upgrades production.

ARMv7 support requires ARMv7-A or later with VFPv3-D16 hard-float; original Pi 1
and original Pi Zero ARMv6 CPUs are excluded. AWG selects the ARMv7 archive for
compatible armhf hosts only after a reviewed adoption populates the currently
empty ARMv7 release fields. Existing runnable ARM64 stores on mixed-bitness
hosts remain valid rollback candidates. This does not establish ARM32 support
for the full web/proxy stack or validate a physical Pi.

Native ARM64 and macOS execution, ARMv7 emulation/interop, actual GitHub
event/attestation behavior and disposable host upgrade/rollback must be validated in their real environments before
activation. Local fixture tests are not substitutes for those checks.
