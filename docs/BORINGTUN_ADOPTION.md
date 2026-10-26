# Adopting a fork-owned BoringTun release

`scripts/boringtun-adopt.py` prepares an explicit, reviewed installer update from
a published release of `Wiresock-Foundation/wiresock-boringtun`. The command only
reads GitHub and writes a new local evidence directory. It does not edit the
checkout, publish a release, create a PR, or install anything. It never executes
a downloaded BoringTun binary. There is no `latest` mode.

The installer continues to use its existing AWG-hosted release until a separate
adoption patch is reviewed and merged. Existing release assets and historical
installer URLs stay untouched. The release identity remains
`boringtun-cli-VERSION-gCOMMIT12-bBUILD`; for new fork releases, BUILD is the
merged PR number. Existing Linux x86_64/aarch64 archive names and the four-member
archive format remain unchanged. New ARMv7 and macOS targets have their own
names. This preserves the existing store, upgrade, and rollback identifiers.
The local store key is independent of the download owner and contains only the
12-character commit prefix, version, build and architecture. Adoption rejects a
changed full source commit, archive hash or binary hash under that same key.
An owner/URL-only migration is permitted when all those values are identical.

## Prerequisites

Run on Linux x86_64 or aarch64 with Python 3.12 or later, Bash, `readelf`, GNU tar, gzip, and the
official GitHub CLI 2.100.0 binary. No new credential or persistent permission is
created. If authentication is needed, the command uses the operator's existing
GitHub CLI authentication for read-only API and attestation access.

The accepted CLI binaries come from the
[official v2.100.0 release](https://github.com/cli/cli/releases/tag/v2.100.0).
Verify the distribution before extracting its `bin/gh`. The command also checks
the extracted executable checksum and its exact version before invoking it.

| Distribution | Archive SHA-256 | Extracted `bin/gh` SHA-256 |
| --- | --- | --- |
| `gh_2.100.0_linux_amd64.tar.gz` | `e4d4bb4498e8d007abe545b6568926793ace1b6447da598294a610018cb164be` | `553949e2efa12842771efe6012aa4de21f1d591530ec17fc435f610f10e017ee` |
| `gh_2.100.0_linux_arm64.tar.gz` | `ea4e7a581a32ccad6cc7923cb1576ac5859ba4b9a16ab22eb8f8a96e78e2e961` | `28a037b967065aa314cb6d539943b55d27ef2f97c523ab2b6023ccf284e1828d` |

The archive hashes were checked against `gh_2.100.0_checksums.txt` in that release;
the binary hashes were computed from the verified archives. The command does
not download or install verification tools automatically.

## Prepare a review

Choose an actual published tag, then run:

```bash
python3 scripts/boringtun-adopt.py "$SELECTED_RELEASE_TAG" \
  --gh /absolute/path/to/gh_2.100.0_linux_amd64/bin/gh \
  --output /absolute/path/to/new-adoption-evidence
```

The output directory must not already exist. Schema 2 requires all seven
release assets: `RELEASE.json`, `SHA256SUMS`, and the five archives below. Each
archive has exactly four payload files: `boringtun-cli`, `LICENSE`,
`THIRD-PARTY-LICENSES`, and `MANIFEST`.

| Target | Archive suffix after `boringtun-cli-VERSION-gCOMMIT12-` | AWG installer selection |
| --- | --- | --- |
| `x86_64-unknown-linux-musl` | `linux-x86_64-musl.tar.gz` | `X86_64` |
| `aarch64-unknown-linux-musl` | `linux-aarch64-musl.tar.gz` | `AARCH64` |
| `armv7-unknown-linux-musleabihf` | `linux-armv7-musleabihf.tar.gz` | `ARMV7` |
| `x86_64-apple-darwin` | `macos-x86_64.tar.gz` | Verified; never installed by AWG |
| `aarch64-apple-darwin` | `macos-aarch64.tar.gz` | Verified; never installed by AWG |

Drafts, prereleases, extra assets, unknown descriptor fields, duplicate JSON
keys, noncanonical descriptor bytes, and tag-target disagreements fail closed.
The Linux consumer still verifies the full five-target matrix. Missing or
altered macOS assets fail adoption; they are not ignored because AWG uses Linux.
The signed schema 2 descriptor has exactly one archive record per target, each
containing its archive, binary and complete notice hashes. Schema 1 descriptors
are not accepted by this new fork-release adoption path; historical installed
AWG releases remain usable through their existing immutable installer pins.

For the descriptor and all five archives, pinned `gh` performs cryptographic
attestation verification. Additional checks require the exact fork publisher
workflow at `refs/heads/master`, its recipe commit, GitHub-hosted runner, numeric
repository and owner identities, and the certificate's exact run and attempt.
The workflow-controlled invocation must agree with the certificate. A signed
descriptor binds the source, PR, build attempt, toolchain inputs, notice
provenance, archive hashes, and binary hashes. The command independently reads
the merged PR, workflow IDs, and exact build and publication attempts. The
original build must have succeeded and postdate the merge. The original
publication attempt must have successful `Validate completed build` and `Attest
verified content` jobs, read through its attempt-specific paginated jobs API.
Its overall result may be failure if a later publication or cleanup step failed:
an immutable release keeps its original signed descriptor through retries.
Expired CI artifacts do not invalidate a published release; adoption uses the
published bytes and original verification evidence.

If a contributor deletes their repository after merge, the canonical PR may
return a null head repository. Adoption retains the PR's immutable head SHA and
uses the original build attempt's recorded contributor repository identity.
The exact PR number, head SHA, canonical base, merge source and time must still
agree. GitHub's minimal Actions repository objects contain `id`, `url`, and
`name`; the owner is read only from an exact `https://api.github.com/repos/OWNER/REPO`
URL, with the repository name and any optional `full_name` required to agree.
Numeric IDs must match the canonical base and, when available, the current
contributor repository. A renamed contributor repository therefore retains its
original identity. Both current and retained identities are saved in the receipt.
If that retained identity is also unavailable, adoption stops with an
explicit request for reviewed immutable merge-event evidence; it never guesses
a repository name from a display label or branch.

The local reviewed notice policy must match the release's full provenance hash.
The toolchain hash covers the canonical JSON object containing `rust_toolchain`,
`rust_commit`, `llvm_commit`, and `inputs` from that provenance file, using sorted
keys, compact separators, and no trailing newline. The unified provenance
covers the inputs for all five targets. Each archive record's `notice_sha256`
covers that archive's complete `THIRD-PARTY-LICENSES` bytes. There is no single
top-level notice hash: Linux musl and macOS system-runtime profiles differ, and
target-specific Cargo dependencies can also produce different notices.
The production `verify-archive-static` gate checks each archive and its full
runtime/native and upstream/fork notices. This path never invokes the binary.
Before invoking tar, a streaming raw-USTAR inspection admits only the expected
directory and four ordinary members. It rejects links, sparse files, GNU/PAX
metadata extensions, duplicate or unexpected members and hidden trailing data.
The binary is limited to 64 MiB, third-party notices to 8 MiB, LICENSE to 1 MiB,
MANIFEST to 64 KiB, and trailing zero padding to 64 KiB. These decompressed limits
apply in addition to the 128 MiB compressed asset limit, without extracting a
member or allocating its declared size. Any future larger artifact requires a
reviewed limit change.
A changed toolchain or notice policy needs a separate source review before the
adoption command will accept it.

After all checks and a second release/tag readback, the output contains:

- `adoption.patch`: proposed changes to the shared release identity and the
  three Linux installer selections only. The ARMv7 asset/hash fields stay empty
  in the current installer until a published release passes verification and
  its explicit adoption patch is reviewed. macOS assets never become installer
  selections.
- `candidate-pin.env`: the exact source/toolchain pin used for static inspection.
  This is evidence, not an automatic replacement of the historical build pin.
- `verification.json`: selected attestation identities, the full parsed output
  of successful pinned `gh` verification, release/asset hashes, tool version and
  checksum, and the previous installer checksum. The receipt uses schema 2 and
  includes all six signed subjects: the descriptor and all five archives.
- The signed descriptor, checksums, downloaded archives, and static inspection
  directories for review.

If a check fails, no adoption patch or success receipt is written. Downloaded
evidence may remain in the new directory for diagnosis; the command will not
overwrite it on retry. Use a new directory for a new verification attempt.

Review the patch and evidence in a separate AWG change. Run the installer
contract, host, upgrade, and rollback checks before approving adoption. Neither
the fork's automated releases nor this helper automatically upgrades servers.
Rollback continues to select an existing verified release/store identity.

## Implementation and remaining activation gates

`scripts/boringtun_release_policy.py` is a byte-for-byte vendored copy of the
fork's same-named pure policy module. Schema or identity changes must update both
copies together and rerun both repositories' tests. The adoption tests are
offline: they use synthetic REST/gh fixtures and real static archive checking.
Those fixtures are not cryptographic evidence of a live GitHub workflow run.

Before activation, capture and review live pinned-CLI verification output and
merged-PR run/attempt metadata for the supported merge strategies. The build
`head_sha == merged source` rule remains conservative until that evidence is
available; a missing association field must not be guessed. The publisher's
closed-event association checks bind the descriptor's build claim to its
trusted recipe. Adoption also independently checks the recorded attempt's
identity, status, source and original creation time.
The minimal `id`/`url`/`name` association schema was confirmed from the real
[fork run 40239937252, attempt 1](https://github.com/Wiresock-Foundation/wiresock-boringtun/actions/runs/40239937252/attempts/1).
That read establishes the repository-object schema; it does not establish the
closed-merged event's source-SHA semantics or satisfy the activation fixture gate.

The unresolved fork copyright years, publisher retirement/owner audit, and
first deployment approval remain release gates. This command does not resolve
them, disable historical workflow reruns, modify repository security settings,
or grant permission to publish. No fork release was created or adopted while
implementing this helper.
