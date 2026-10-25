# Notices and attribution

This file records where AmneziaWG Server Tools (`awg-server-tools`) comes from,
which copyright notices it carries and why, and which third-party software it
uses or distributes. It explains the notices; it does not change them. Adding,
keeping or rewording a notice here does not transfer copyright to anyone.

The license of the repository's own code is the MIT License: see
[`LICENSE`](LICENSE), and [`LICENSES/MIT.txt`](LICENSES/MIT.txt) for the
standard text that the SPDX headers refer to. Each file's copyright holders and
license are recorded machine-readably, inline as `SPDX-FileCopyrightText` and
`SPDX-License-Identifier` or in [`REUSE.toml`](REUSE.toml), and are checked by
`reuse lint`. [`docs/LICENSING.md`](docs/LICENSING.md) explains what this means
for users, redistributors and contributors.

## Origin of the project

The installer, `amneziawg-install.sh`, descends from three earlier MIT-licensed
projects. Each of them is the source of one of the notices in `LICENSE`.

| Project | Notice | What it contributed |
| --- | --- | --- |
| [angristan/wireguard-install](https://github.com/angristan/wireguard-install) | Copyright (c) 2019 angristan | The WireGuard installer that RomikB's AmneziaWG installer was based on ("initial release based on https://github.com/angristan/wireguard-install", RomikB commit `0bb9f77`, 2024-07-16). |
| [RomikB/amneziawg-install](https://github.com/RomikB/amneziawg-install) | Copyright (c) 2024 Roman Zakharchuk | The AmneziaWG adaptation of that installer. |
| [Varckin/amneziawg-install](https://github.com/Varckin/amneziawg-install) | Copyright (c) 2024 Markus Varckin | A copy of RomikB's installer at commit `9f831f3`, identical except for the project URLs. This repository's history starts with its commits (2024-08-14 to 2024-09-17). |

The notices of angristan and Roman Zakharchuk do not appear in the `LICENSE`
of Varckin/amneziawg-install, which names only Markus Varckin. Because code
from both earlier projects is still part of `amneziawg-install.sh`, all three
notices are reproduced here, in `LICENSE` and in the header of that script, as
their MIT licenses require.

Other people contributed to angristan/wireguard-install before RomikB's
adaptation and hold the copyright in their own contributions; the upstream
project publishes them under its single notice, which is reproduced here as it
stands.

## Copyright holder of the current development

WireSock is a trade name ("doing business as") used by **Vadim Smirnov**, an
individual. It is not a company or other separate legal entity and holds no
rights of its own. Wherever this repository names WireSock as a copyright
holder, the holder is Vadim Smirnov, and the notices say so:
`Copyright (c) 2026 Vadim Smirnov (doing business as WireSock)`.

Since January 2026 the project has been developed by Vadim Smirnov, operating
as WireSock, in
[wiresock/awg-server-tools](https://github.com/wiresock/awg-server-tools)
(formerly `wiresock/amneziawg-install`). That work extended the installer
(AmneziaWG 2.0, 3.0 and 3.1 support, the BoringTun backend, non-interactive
operation and many fixes) and added everything else in the repository:

- `amneziawg-web/`, the web management panel (Rust);
- `amneziawg-proxy/`, the UDP proxy with protocol imitation (Rust);
- the wrappers `amneziawg-web.sh` and `amneziawg-proxy.sh`, the build and
  release scripts in `scripts/`, the BoringTun packaging in
  `packaging/boringtun/`, the tests, the CI workflows and the documentation.

These files carry `SPDX-FileCopyrightText: 2026 Vadim Smirnov (doing business
as WireSock)`. The attribution rests on the git history, in which these files
were written by Vadim Smirnov or by automated coding agents that he directed on
his repository, with version-bump commits from GitHub Actions. Commit
authorship is evidence of who wrote a change, not proof of who owns it. The
questions this leaves open, including the status of agent-written code and any
agreement that could give someone else rights in this work, are listed in
[`docs/LICENSING_INVENTORY.md`](docs/LICENSING_INVENTORY.md#unresolved-questions).

If these rights are later transferred to another owner, the notices can name
that owner from then on. A transfer would not withdraw the MIT License already
granted for the published code, and nothing here anticipates one.

### Other contributors

- Denis Glotov contributed a one-line fix to `amneziawg-install.sh` (pull
  request #108, commit `f9af954`). He is named as a contributor in that file's
  header (`SPDX-FileContributor`). Vadim Smirnov claims no copyright in that
  change; whatever rights exist in it remain Denis Glotov's, and it is
  distributed under the MIT License like the rest of the file.

A contributor keeps the copyright in their contribution; see
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## Component notices

| Path | License | Copyright |
| --- | --- | --- |
| `amneziawg-install.sh` | MIT | 2019 angristan; 2024 Roman Zakharchuk; 2024 Markus Varckin; 2026 Vadim Smirnov (doing business as WireSock); contributor Denis Glotov |
| `amneziawg-web/` | MIT (`amneziawg-web/LICENSE`) | 2026 Vadim Smirnov (doing business as WireSock) |
| `amneziawg-proxy/` | MIT (`amneziawg-proxy/LICENSE`) | 2026 Vadim Smirnov (doing business as WireSock) |
| everything else | MIT (`LICENSE`) | 2026 Vadim Smirnov (doing business as WireSock) |

`amneziawg-web/LICENSE` previously gave the year as 2024. The component first
appears in this repository on 2026-03-25, as a single commit that already
contains that `LICENSE`, and no earlier development of it is known, so the year
is now 2026.

## Third-party software

The repository contains no copied or vendored third-party source code other
than the inherited installer code described above. The software below is used,
downloaded or distributed separately and keeps its own license; it is not
relicensed by this project.

### Distributed by this project: WireSock BoringTun (`boringtun-cli`)

The BoringTun backend runs `boringtun-cli`, built from
[WireSock BoringTun](https://github.com/Wiresock-Foundation/wiresock-boringtun),
a fork of [cloudflare/boringtun](https://github.com/cloudflare/boringtun), at
the commit pinned in `packaging/boringtun/pin.env`. Its archives are published
as releases of this repository and downloaded by the installer.

- License: BSD-3-Clause. Upstream notice: Copyright (c) 2019 Cloudflare, Inc.
  Files added by the fork carry "Copyright (c) 2024-2026 WireSock", the
  trade name of Vadim Smirnov; correcting that notice is tracked in
  [issue #175](https://github.com/wiresock/awg-server-tools/issues/175).
- Each archive contains `LICENSE` (BoringTun's license) and
  `THIRD-PARTY-LICENSES` (the licenses of every Rust crate linked into the
  binary, generated by cargo-about and gated by cargo-deny), and its `MANIFEST`
  names the exact source repository and commit. The installer keeps all three
  next to the binary in `/usr/local/lib/amneziawg-install/boringtun/`.
- The binary also links statically the musl C library and the Rust standard
  library, whose notices `THIRD-PARTY-LICENSES` does not yet include; see
  [`docs/LICENSING.md`](docs/LICENSING.md#known-gaps) and [issue #175](https://github.com/wiresock/awg-server-tools/issues/175).

### Built from source on the server: Rust crates of the web panel and proxy

`amneziawg-web` and `amneziawg-proxy` are built on the server by their install
scripts, which download their dependencies from crates.io as listed in each
`Cargo.lock`. This repository does not redistribute those crates or binaries
built from them. All of them are available under permissive licenses (MIT,
Apache-2.0, BSD-3-Clause, ISC, Unicode-3.0 or Zlib, many as alternatives), as
checked by cargo-deny with `.github/licensing/deny.toml`. `amneziawg-web`
includes SQLite (public domain) through `libsqlite3-sys`.

### Installed by the system package manager: AmneziaWG

The kernel backend uses the [AmneziaWG](https://docs.amnezia.org/documentation/amnezia-wg/)
kernel module and tools (`amneziawg`, `amneziawg-dkms`, `amneziawg-tools`,
including `awg` and `awg-quick`), which are licensed under GPL-2.0. The
installer has them installed by the system package manager from Amnezia's
package repository (`ppa:amnezia/ppa`); this project does not redistribute
them. The installer and the panel run `awg` and `awg-quick` as separate
programs. On Debian and Ubuntu, if the module's DKMS build fails, the installer
rewrites two compatibility macros in the module source on that server; see
[`docs/LICENSING_INVENTORY.md`](docs/LICENSING_INVENTORY.md#unresolved-questions).

### Other tools

The Rust toolchain (installed with rustup when requested), the distribution
packages the installer adds (for example `qrencode`, `iptables`, `nftables`)
and the tools used only by CI and tests (for example amneziawg-go, cargo-deny,
cargo-about, reuse) are separate programs under their own licenses and are not
distributed by this project.

## Trademarks

The project names (AmneziaWG, WireGuard, BoringTun and others) are used only to
identify the software they refer to; see the disclaimer in the
[README](README.md#disclaimer). The licenses above grant no trademark rights.
