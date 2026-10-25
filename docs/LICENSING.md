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
| [`LICENSE`](../LICENSE) | The MIT License with every copyright notice that applies to the repository. |
| [`amneziawg-web/LICENSE`](../amneziawg-web/LICENSE), [`amneziawg-proxy/LICENSE`](../amneziawg-proxy/LICENSE) | The same MIT terms for each Rust crate, so a crate copied on its own keeps its license. |
| [`LICENSES/`](../LICENSES) | The standard text of each license used, as referenced by SPDX identifiers ([REUSE](https://reuse.software)). |
| [`REUSE.toml`](../REUSE.toml) and SPDX headers | The copyright holders and license of every file, machine-readable. |
| [`NOTICE.md`](../NOTICE.md) | Origin of the project, the meaning of each notice and the third-party software. |
| [`docs/LICENSING_INVENTORY.md`](LICENSING_INVENTORY.md) | The audit behind these files: per-component evidence, confidence and open questions. |
| `THIRD-PARTY-LICENSES` in each BoringTun archive | The licenses of the Rust crates linked into `boringtun-cli`. |

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
| WireSock BoringTun `boringtun-cli` | BSD-3-Clause (Cloudflare, Inc.; fork additions by Vadim Smirnov, doing business as WireSock) | Built in CI and **distributed** as release archives of this repository; the installer downloads and runs it as a separate program. | Binary redistribution must reproduce BoringTun's notices and those of everything linked into it: each archive ships `LICENSE` and `THIRD-PARTY-LICENSES` (see below). BSD-3-Clause does not require source to be provided; the archive `MANIFEST` names the public source repository and commit anyway. |
| Rust crates linked into `boringtun-cli` | Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, MIT, Unicode-3.0 (gated by `packaging/boringtun/deny.toml`) | Statically linked into the distributed binary. | Reproduced in `THIRD-PARTY-LICENSES`. No crate in the graph may ship an Apache-2.0 `NOTICE` file: the build fails if one does, because that file would have to be reproduced too. |
| musl libc and the Rust standard library | MIT (musl); MIT OR Apache-2.0 (Rust) | Statically linked into `boringtun-cli`. | Their notices are not yet in `THIRD-PARTY-LICENSES`; see [Known gaps](#known-gaps). |
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

These files are inputs to reproducible, attested release builds. Changing them
changes the archive bytes and needs a new release build, so the licensing
changes in this repository leave them as they are.

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

## Known gaps

These are known and not yet fixed. They do not change the license of anything
in this repository.

1. **BoringTun archives omit two sets of notices.** `boringtun-cli` is a static
   musl binary, so it contains the musl C library (MIT, "Copyright © 2005-2020
   Rich Felker, et al.") and the Rust standard library with its runtime
   components (mostly MIT OR Apache-2.0; the unwinder is LLVM's libunwind,
   Apache-2.0 WITH LLVM-exception). `THIRD-PARTY-LICENSES` lists only the crates of the
   BoringTun dependency graph, so their notices are missing. In addition, the
   archive `LICENSE` reproduces only Cloudflare's notice, while the files
   added by the fork carry "Copyright (c) 2024-2026 WireSock" under the same
   BSD-3-Clause terms, which should name Vadim Smirnov (doing business as
   WireSock). The fix ships in new, reproducible and attested release builds
   (a new build number or pin, as `packaging/boringtun/release.env` requires
   for any change of the archive bytes); published archives are never
   modified. It is tracked in
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
  bar or backtick, and a year or contact address), so a table row or heading
  quoted in a document is never taken for the document's own;
- the Rust sources and the installed shell scripts carry their own SPDX
  header;
- `LICENSES/` contains only the licenses the repository is meant to use (MIT),
  so adding a license is a deliberate change;
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
  allowed. A crate under any other license, or with no license metadata, fails
  the check until it is reviewed.

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
