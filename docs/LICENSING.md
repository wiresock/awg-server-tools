# Licensing

This page explains the licensing of AmneziaWG Server Tools for people who use,
redistribute, build on or contribute to it. It describes the licenses; it is
not legal advice, and where it summarises a license, the license text governs.

## Summary

- The repository's own code and documentation are licensed under the
  [MIT License](../LICENSES/MIT.txt). That covers the installer, the web panel
  (`amneziawg-web`), the proxy (`amneziawg-proxy`), the scripts, tests, CI and
  documentation.
- The installer contains code from three earlier MIT-licensed projects. Their
  authors keep their copyright, and their notices are kept in
  [`LICENSE`](../LICENSE) and in `amneziawg-install.sh`. See
  [`NOTICE.md`](../NOTICE.md) for the full origin.
- Third-party software that the project downloads, builds against or
  distributes keeps its own license. The project does not relicense it.
- The current development is by Vadim Smirnov, who does business as
  WireSock. WireSock is a trade name, not a separate legal entity, so his
  notices read `Copyright (c) 2026 Vadim Smirnov (doing business as WireSock)`.
- There is no Contributor License Agreement and no copyright assignment.
  Contributors keep their copyright and license their contributions under MIT
  ([`CONTRIBUTING.md`](../CONTRIBUTING.md)).

## Where the information is

| File | Contents |
| --- | --- |
| [`LICENSE`](../LICENSE) | The MIT License and holder notices for the repository's own code and inherited installer. Vendored notices retain their separately recorded terms. |
| [`amneziawg-web/LICENSE`](../amneziawg-web/LICENSE), [`amneziawg-proxy/LICENSE`](../amneziawg-proxy/LICENSE) | The same MIT terms for each Rust crate, so a crate copied on its own keeps its license. |
| [`LICENSES/`](../LICENSES) | SPDX license texts, plus the exact Linux and macOS runtime notice collections identified by their scoped `LicenseRef` identifiers ([REUSE](https://reuse.software)). |
| [`REUSE.toml`](../REUSE.toml) and SPDX headers | The copyright holders and license of every file, machine-readable. |
| [`NOTICE.md`](../NOTICE.md) | Origin of the project, the meaning of each notice and the third-party software. |
| [`docs/LICENSING_INVENTORY.md`](LICENSING_INVENTORY.md) | The audit behind these files: per-component evidence, confidence and open questions. |
| `THIRD-PARTY-LICENSES` in newly built BoringTun archives | Cargo dependency notices plus the reviewed runtime/native collection for the target profile (Linux musl or macOS system libraries). Existing published archives have the gaps listed below. |

`reuse spdx` prints a complete SPDX bill of materials for the repository.

## Using, modifying and redistributing this project

The MIT License permits anyone to use, copy, modify, merge, publish,
distribute, sublicense and sell copies of the software, including in
commercial and proprietary products, and to combine it with code under other
terms. Its one condition is that the copyright notices and the permission
notice are included in all copies or substantial portions of the software. It
comes without warranty.

In practice, when you redistribute this project's code, in source or as part
of another product:

- keep `LICENSE` (or, for code from a single crate, that crate's `LICENSE`)
  with it, including every copyright line;
- keep the SPDX headers and notices in the files you copy, in particular the
  upstream notices in `amneziawg-install.sh`;
- do not suggest that the authors endorse your product; the license grants no
  trademark rights, and the names AmneziaWG, WireGuard and BoringTun belong to
  their owners (see the README disclaimer);
- meet the obligations of any third-party component you also distribute, as
  described below. These come from those components' licenses, not from MIT.

You may license your own modifications and additions however you choose,
including under proprietary terms. The MIT-licensed parts you include remain
available under MIT from their authors.

## Third-party components and what distributing them requires

What a third-party license requires depends on whether and how its component
is distributed. Running a separate program does not change the license of the
program that runs it.

| Component | License | How the project uses it | Obligations for the project |
| --- | --- | --- | --- |
| WireSock BoringTun `boringtun-cli` | BSD-3-Clause (Cloudflare, Inc.; fork additions by Vadim Smirnov, doing business as WireSock) | Existing releases are **distributed** by this repository; fork-owned publication is being prepared. The installer downloads an explicitly selected release and runs it as a separate program. | Binary redistribution must reproduce BoringTun's notices and those of everything linked into it: each archive ships `LICENSE` and `THIRD-PARTY-LICENSES` (see below). BSD-3-Clause does not require source to be provided; the archive `MANIFEST` names the public source repository and commit anyway. |
| Rust crates linked into `boringtun-cli` | Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, MIT, Unicode-3.0 (gated by `packaging/boringtun/deny.toml`) | Statically linked into the distributed binary. | Reproduced in `THIRD-PARTY-LICENSES`. No crate in the graph may ship an Apache-2.0 `NOTICE` file: the build fails if one does, because that file would have to be reproduced too. |
| musl libc, Rust runtime and native support code | Per-component terms, including MIT, Apache-2.0 WITH LLVM-exception and upstream notices | Rust runtime is linked into `boringtun-cli`; Linux targets also use musl and self-contained native runtime objects, while macOS uses platform system libraries. | The reviewed target-specific runtime bundle is appended to newly generated notices; published archives still need replacement releases. See [Known gaps](#known-gaps). |
| Rust crates of `amneziawg-web` and `amneziawg-proxy` | Permissive, gated by `.github/licensing/deny.toml` | Downloaded from crates.io and built **on the server** by the install scripts. | None for the project, which distributes only its own source. Whoever distributes a built binary must include the crates' notices (see below). |
| SQLite (via `libsqlite3-sys`) | Public domain | Compiled into `amneziawg-web` on the server. | None. |
| AmneziaWG kernel module and `amneziawg-tools` (`awg`, `awg-quick`) | GPL-2.0 | Installed by the system package manager from Amnezia's package repository; run as separate programs. | None for the project, which does not distribute them. The packages carry their own license and source offers. |
| amneziawg-go, cargo-about, cargo-deny, reuse, the Rust toolchain | Their own licenses | CI, tests and build tools only; the toolchain is installed by rustup on request. | None; not distributed. |

### The BoringTun artifacts

`scripts/boringtun-artifact.sh licenses` gates the dependency graph of the
pinned BoringTun commit with cargo-deny (allowed licenses, crates.io only, no
`NOTICE` files) and generates `THIRD-PARTY-LICENSES` with cargo-about from the
crate sources in the lockfile. It then checks that the copyright notices listed
in `packaging/boringtun/required-notices` appear for their crates and that no
crate other than BoringTun is attributed only by a placeholder notice. The same
notice check runs again when an archive is verified, before it is published,
and `tests/test-boringtun-artifact.sh` tests it. Each archive contains exactly
`LICENSE`, `MANIFEST`, `THIRD-PARTY-LICENSES` and `boringtun-cli`, and the
installer keeps the notices next to the binary in
`/usr/local/lib/amneziawg-install/boringtun/<release>/`. See
[`BORINGTUN_ARTIFACTS.md`](BORINGTUN_ARTIFACTS.md).

The generator appends the reviewed runtime collection selected by the version-2
notice policy: `packaging/boringtun/runtime-notices.txt` for the three Linux musl
targets, or `runtime-notices-macos.txt` for the two macOS targets. The exact
checksum-pinned source inputs, five target distribution inventories and
transformations are recorded in `runtime-provenance.json`, `runtime-sections.json`
and `runtime-sections-macos.json`. The source lockfile and toolchain must match
the reviewed policy. Packaging and archive verification require the complete
bundle for the selected target and the complete upstream/fork `LICENSE` bytes.
Missing terms, altered text, an unsupported target or an unreviewed source
lockfile fail these checks.

These files are inputs to reproducible, attested release builds. Changing them
changes archive bytes and requires a new release; published assets stay intact.
The installer continues to use its explicitly selected published release until
a separate reviewed adoption update.

### Vendored notice texts and SPDX metadata

`packaging/boringtun/fork-license.txt` preserves Cloudflare's original notice and
BSD-3-Clause terms and the fork notice under the same terms. Its REUSE annotation
names both holders and retains the existing fork year range. The 2024 start is
unverified, and retaining it does not resolve the release gate below.

The two runtime files contain texts from several upstream projects, including
conservative source-notice supersets. Each portion retains the holders and terms
identified with it. Neither collection is attributed to Vadim Smirnov or
relicensed under the repository's MIT License.

| Packaging input | Profile | Exact `LICENSES/` copy |
| --- | --- | --- |
| `runtime-notices.txt` | Linux musl: x86_64, aarch64, armv7 | `LicenseRef-BoringTun-Runtime-Notices.txt` |
| `runtime-notices-macos.txt` | macOS system libraries: x86_64, aarch64 | `LicenseRef-BoringTun-Runtime-Notices-macOS.txt` |

Each copy's filename without `.txt` is the SPDX identifier for that collection.
The references identify the reproduced terms; they do not grant a new blanket
license or claim that every listed source is linked into a binary. The macOS
collection excludes the Linux musl and self-contained LLVM CRT/libunwind notice
sections. Both retain conservative common Rust and ring source-notice supersets.
The compiled component selection and exact source evidence remain in the
provenance records.

REUSE permits an identifying group descriptor for copyright holders. These two
annotations identify upstream holders through their notices in each file,
without inventing one aggregate owner or year range. The licensing check allows
that exact descriptor only for these two packaging inputs. It still rejects
accidental quoted fragments elsewhere, checks both `LicenseRef` copies byte for
byte, and validates the policy hashes and profile mappings for all five targets.
After regenerating the bundles, synchronize the copies with:

```bash
cp packaging/boringtun/runtime-notices.txt LICENSES/LicenseRef-BoringTun-Runtime-Notices.txt
cp packaging/boringtun/runtime-notices-macos.txt LICENSES/LicenseRef-BoringTun-Runtime-Notices-macOS.txt
bash scripts/check-licensing.sh --offline
```

### Distributing binaries of the web panel or the proxy

The project does not publish binaries or container images of `amneziawg-web` or
`amneziawg-proxy`. If you do (for example an image built from
`amneziawg-web/Dockerfile`, or a product that includes either binary), include
the crate's `LICENSE` and the notices of its Rust dependencies. The dependency
graph is limited to the licenses allowed in `.github/licensing/deny.toml`, and
none of its crates ships an Apache-2.0 `NOTICE` file as of this writing. A
third-party notice file can be generated the same way as for BoringTun, for
example with `cargo about generate` and a configuration modelled on
`packaging/boringtun/about.toml`. The binary also contains the Rust standard
library, and statically linked builds contain their C library.

The email feature adds two reviewed, version-specific allowances for Lettre's
dependencies. `quoted_printable` 0.5.2 uses [0BSD](https://spdx.org/licenses/0BSD.html);
its `LICENSE` names Kartikaya Gupta (2019). That license permits use and
redistribution without a notice-retention condition. `webpki-roots` 1.0.11
uses [CDLA-Permissive-2.0](https://cdla.dev/permissive-2-0/) for its bundled
trust-anchor data. Section 2.1 requires the agreement text to accompany shared
data: include that crate's complete `LICENSE` when distributing a binary
containing those roots, for example in its third-party notices. These findings
were checked against the exact crates' `LICENSE` files. No dependency source or
root data is vendored here; these allowances do not change the repository's MIT
license or the separate BoringTun policy.

## Known gaps

Implementation and publication are separate. These remaining gates do not
change the license of anything in this repository.

1. **Existing published BoringTun archives retain the notice gaps.** The local
   packaging fix adds checksum-pinned runtime/native notices and the complete
   fork notice, but does not modify any published archive. The corrected fork
   year range still needs owner evidence or an explicit correction: the 2024
   start has not been verified. New releases need the reviewed fork source,
   successful build and reproducibility gates on every supported target, verified
   attestations and authorized activation/publication. Installer adoption is
   a separate reviewed change. This work is tracked in
   [issue #175](https://github.com/wiresock/awg-server-tools/issues/175) and
   should be done before `boringtun-cli` is distributed in any other product.

The open legal questions found in the audit are listed in
[`LICENSING_INVENTORY.md`](LICENSING_INVENTORY.md#unresolved-questions).

## Automated checks

The **Licensing** workflow (`.github/workflows/licensing.yml`) runs
`scripts/check-licensing.sh` on every pull request and push to `main`. It
checks that:

- `reuse lint` passes, with no tag it cannot parse: every file has a valid SPDX
  license and copyright, and every license used has its text in `LICENSES/`;
- every copyright that `reuse spdx` resolves looks like a notice (no table
  bar or backtick, and a year or contact address), except the exact upstream
  holder descriptor for the two runtime collections described above;
- the Rust sources and the installed shell scripts carry their own SPDX
  header;
- `LICENSES/` contains only MIT, BSD-3-Clause and the two scoped runtime notice
  `LicenseRef` texts, each byte-identical to its reviewed profile bundle;
- `LICENSES/MIT.txt` is the unmodified SPDX text; `LICENSE` and the component
  `LICENSE` files carry its MIT terms and a copyright notice; and `LICENSE` and
  the installer keep the upstream notices, the installer also its named
  contributor;
- each crate's `Cargo.toml` declares the license that its `LICENSE` file and
  SPDX headers state;
- every `LICENSE` file names the maintainer as `Vadim Smirnov (doing business
  as WireSock)`; no copyright tag or notice names the trade name WireSock on
  its own; and each crate's SPDX years for the maintainer lie within the years
  of its `LICENSE` (a file from a later year needs that `LICENSE` to give a
  range such as `2026-2027`);
- the BoringTun cargo-about and cargo-deny configurations accept the same
  licenses;
- every Rust dependency of the web panel and the proxy is under a license
  allowed by `.github/licensing/deny.toml`. That policy allows Apache-2.0,
  BSD-3-Clause, ISC, MIT, Unicode-3.0 and Zlib, and only those licenses the
  current graphs need; a dual-licensed crate passes when one of its options is
  allowed. Package-specific exceptions additionally permit 0BSD for
  `quoted_printable` exactly 0.5.2 and CDLA-Permissive-2.0 for `webpki-roots`
  exactly 1.0.11, with the redistribution requirements described above. Other
  versions need review. A crate under any other license, or with no license
  metadata, fails the check until it is reviewed.

The BoringTun license gate keeps running in the BoringTun Artifacts workflow
with its own policy.

To run the checks locally, install the tools at the versions the workflow pins
and run the script from the repository root:

```bash
pipx install reuse==5.0.2
cargo install --locked cargo-deny@0.20.2
bash scripts/check-licensing.sh            # all checks
bash scripts/check-licensing.sh --offline  # without the dependency check
```

### Adding files and licenses

- A new Rust source or installed shell script starts with an
  `SPDX-FileCopyrightText` line naming its author and the
  `SPDX-License-Identifier` of its neighbours. Other files are covered by the
  globs in `REUSE.toml`, which attribute them to the maintainer; a file outside
  them makes `reuse lint` fail until it is annotated. A contributor's file
  carries the contributor's own copyright line (see `CONTRIBUTING.md`).
- Code copied from elsewhere keeps its original notice and license. Add its
  license text with `reuse download <SPDX-ID>`, give the file its original
  `SPDX-FileCopyrightText` and `SPDX-License-Identifier`, extend
  `EXPECTED_LICENSES` in `scripts/check-licensing.sh` and describe it in
  `NOTICE.md`. Never attribute third-party code to the maintainer, or mark it
  as MIT, unless it is.
- A new Rust dependency under a license not yet allowed fails the check. Add
  the license to `.github/licensing/deny.toml` only after confirming that it is
  permissive and that its notice requirements are understood.
