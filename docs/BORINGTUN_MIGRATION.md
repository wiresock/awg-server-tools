# Fork-owned BoringTun releases

## Current implementation status

The fork publisher is active for ordinary merged-PR pushes after explicit owner
approval. Its `.github/workflows/boringtun-release.yml` separates read-only
validation, attestation and publication jobs; privileged jobs independently
recheck live policy. The first release
[`ga92909c49920-b101`](https://github.com/Wiresock-Foundation/wiresock-boringtun/releases/tag/boringtun-cli-0.7.1-ga92909c49920-b101)
passed five-platform reproducibility, native macOS utun and three Linux interop
lanes in build `40409966150/1`. Publisher `40412814028/1` signed all six subjects.
The original draft was published with owner-approved recovery after a lookup
bug; all seven public files and six signatures were independently verified.
PR #102 added authenticated inventory and numeric-ID lookup. Its own canonical
build `40459788478/1` passed all 13 jobs, but publisher `40461864091/1` exposed
a remaining create/readback defect: it discards the returned draft ID and then
depends on the inventory immediately showing that draft. Signing passed; draft
`425104516` has no assets and is not public. No publication retry has been made.
AWG must not adopt this source until the existing draft is safely recovered and
its published files and original signatures are independently verified.

AWG workflow `369920301` was explicitly disabled and read back as
`disabled_manually`; its current YAML and scripts cannot publish. The owner-side
audit found no remaining legacy drafts or active publisher runs. Old releases
remain immutable. Existing historical workflows still require owner control;
current YAML alone cannot revoke every historical execution path.

The canonical producer moves to `Wiresock-Foundation/wiresock-boringtun`.
Each eligible ordinary merged-PR push to master has a distinct source-based tag:
`boringtun-cli-<CLI version>-g<source SHA first 12>-b<PR number>`. The complete
40-character source SHA is retained in MANIFEST and signed RELEASE.json.
The PR's merged result identifies the source for merge, squash and rebase
strategies; the PR head alone is not the release source. Direct pushes do not
request releases. AWG adoption remains an explicit, reviewed version/hash patch.

## Completed cutover and separate adoption

1. Both implementation PRs and the identity/transport repairs were independently
   reviewed and merged with publication disabled. Real canonical build evidence
   and one separately approved attestation-only run preceded activation.
2. The old AWG publisher was retired and disabled with owner approval before the
   fork publisher was enabled. No stored credentials or keys were created.
3. The owner stated that wgbooster/netlib existed before 2022 and identified the
   earlier archived fork. Existing 2024-2026 notices are retained assertions,
   not claims that the original components began in 2024. No exact origin year
   or other contributor's ownership was invented; see the fork's
   [attribution record](https://github.com/Wiresock-Foundation/wiresock-boringtun/blob/39d7bfc14f13a11a35122287ecdfa58c5ec1f218/docs/ATTRIBUTION.md).
4. The owner accepted GitHub-hosted toolchain trust and ordinary-event coverage
   and approved activation; exceptional missed events remain manual recovery.
5. Review an explicitly selected published fork release and use `scripts/boringtun-adopt.py`
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
The owner explicitly accepted the GitHub-hosted compiler/SDK/packaging-tool
trust boundary. Do not describe this digest as attesting every host tool or as
establishing a fully hermetic build.

Builds have `contents: read`. Signing receives only the necessary OIDC and
attestation writes; publication receives content writes separately. Trusted
scripts come from the promoter's fixed workflow revision; source C executes
only in isolated read-only jobs. Existing maintainers' authentication can be
used for read-only local adoption; no new credentials are introduced.

The publisher accepts only successful completed runs of the merged-PR build
workflow, then validates the exact event, repository, workflow ID, source and
attempt. It has no direct-push or manual publication trigger. A manually
dispatched maintenance build remains a dry run because its triggering event is
not eligible for promotion. Checkout, preparation upload and attestation actions
in the privileged workflow use immutable commit pins. Attestation receives the
descriptor and five archive paths derived from the revalidated prepared files.
Publication is serialized by validated PR number, leaving distinct merged PRs
in independent queues.

Retries recover and verify the original signed descriptor rather than changing
its run IDs. The descriptor is uploaded first and its digest recorded in draft
metadata. Existing asset names are never overwritten. Conflicts and uncertain
writes require read-back and fail closed. Per-PR concurrency avoids replacing
unrelated pending merge runs; reconciliation exposes missing releases.

## Explicit platform limitations

GitHub can suppress merge-triggered workflows for merges made using
GITHUB_TOKEN; batched or missed pushes can also lack one build per merge.
Read-only reconciliation exposes missing releases, but automatic catch-up is
not implemented. The owner accepted ordinary-event coverage for initial
activation. Recovery requires review; rerunning a nonexistent run is not
recovery. No `actions: write` dispatcher was authorized or added.

Creating a tag at an older merged commit whose workflow files differ from the
current default branch may require authorization beyond `contents: write`.
Such a publication remains blocked and visible. The owner must choose a
reviewed recovery procedure or authorize a changed tagging model. This change
does not broaden credentials, retarget the tag silently or skip that merge.

## Compatibility and rollback

The installer embeds the first verified public fork release,
`boringtun-cli-0.7.1-ga92909c49920-b101`, through the explicit
[adoption record](BORINGTUN_ADOPTION_2026-10-27.md). Old AWG and
renamed-repository URLs remain accepted alongside the exact canonical fork URL.
The source repository, archive naming and four-member format stay compatible.
The installed cache key includes source/build but not publisher: adoption must
reject reuse of an existing source/build identity for different binary bytes.
Rollback uses the installed prior immutable release and configuration checks;
neither migration nor a fork release automatically upgrades production.

Publisher retries retain the trusted workflow revision R. The live gate compares
current master policy bytes with that revision's policy; a code-only security fix
does not itself revoke an older R if the policy is unchanged. Future publisher
security fixes must also change the reviewed policy or introduce explicit recipe
revocation. Keep verification of an original signed release separate from
permission to execute an obsolete publisher.

ARMv7 support requires ARMv7-A or later with VFPv3-D16 hard-float; original Pi 1
and original Pi Zero ARMv6 CPUs are excluded. AWG selects the ARMv7 archive for
compatible armhf hosts using this release's verified ARMv7 pins. Existing runnable ARM64 stores on mixed-bitness
hosts remain valid rollback candidates. This does not establish ARM32 support
for the full web/proxy stack or validate a physical Pi.

Native ARM64/macOS execution, ARMv7 emulation/interop and actual GitHub
event/attestation behavior passed for the first fork release. Each new source
must pass again. Each AWG adoption separately runs disposable-host
upgrade/rollback checks; physical Pi and production deployment remain distinct
from those checks. Local fixtures are not substitutes for live evidence.

### Exact Bash for native macOS validation

Both macOS architectures build GNU Bash 5.3.20 below `RUNNER_TEMP` using
`scripts/boringtun-bash.py`. The reviewed
[`bash-toolchain.json`](../packaging/boringtun/bash-toolchain.json) pins the GNU
5.3 source archive and all twenty ordered upstream patches by SHA-256, with
checksums traced to the [immutable Homebrew formula](https://github.com/Homebrew/homebrew-core/blob/9d390e8ea5618fde14eeb084d0da3eb5a4cce53c/Formula/b/bash.rb).
Its canonical JSON digest is
`3bb13ba2ffc3096bbe7fe348a85f98e143c61c68072fd8b09be66b324543c73d`.
The build selects Xcode 16.4/16F6, SDK 15.5 and deployment target 11.0, and
disables readline and NLS so this shell needs no floating Homebrew libraries.
It installs no global files. The shared verifier checks both the version banner
and `BASH_VERSION`, the resulting executable hash, and the source receipt.

The original candidate job installed Homebrew Bash 5.3.15 and later failed the
production 5.3.20 gate. Its setup check ran under the macOS system Bash and did
not log either version representation. GNU Bash's shipped `CHANGES` records that
`[[` became subject to `set -e` after Bash 3.2; an unguarded comparison was
therefore insufficient there. Installation and verification now have explicit
failure exits and print the verified receipt. The initial local GNU-source
verification build was Linux-only. Both native macOS lanes subsequently passed
the exact Bash gate in canonical release CI.

`BASH-TOOLCHAIN.json` is copied into each `NATIVE-TOOLCHAIN.json` as supplemental
CI provenance. These receipt bytes and the Bash input manifest are not included
in the release descriptor's existing `toolchain_sha256` projection. This change
does not make the host toolchain hermetic; both native macOS CI lanes must pass
for every release.
