# Licensing inventory

The audit behind [`NOTICE.md`](../NOTICE.md), [`LICENSE`](../LICENSE) and the
SPDX metadata, kept so that the attribution can be checked and maintained. It
records what the repository, its history and its upstreams show, how confident
each conclusion is, and what is still open. It is not legal advice.

Audited: `main` at `8d4ccee` (2026-10-22), full git history (195 commits), the
pull requests of `wiresock/awg-server-tools`, and the upstream repositories
listed below at the commits named.

**Confirmed** means shown directly by the repository, its history or the
upstream sources. **Assumed** means inferred and stated as such.

## Provenance

### Lineage of `amneziawg-install.sh`

| Step | Evidence | Status |
| --- | --- | --- |
| angristan/wireguard-install, MIT, "Copyright (c) 2019 angristan" | Its `LICENSE`. RomikB commit `0bb9f77` (2024-07-16): "initial release based on https://github.com/angristan/wireguard-install". Text specific to it (for example the LXC messages of `checkVirt`) is in RomikB's and in the current script. | Confirmed |
| RomikB/amneziawg-install, MIT, "Copyright (c) 2024 Roman Zakharchuk" | Its `LICENSE`. All 14 commits up to `9f831f3` (2024-07-15 to 2024-07-18) are by Roman Zakharchuk / RomikB. | Confirmed |
| Varckin/amneziawg-install, MIT, "Copyright (c) 2024 Markus Varckin" | Its first commit `d8528fc` (2024-08-14) adds a script identical to RomikB's `9f831f3` except for three URL lines; its later commits change only URLs and README text. It is a copy, not a GitHub fork, and its `LICENSE` names only Markus Varckin. | Confirmed |
| wiresock/awg-server-tools | Its history begins with Varckin's seven commits; WireSock's work starts with `ab182aa` (2026-01-31). | Confirmed |

Code from the upstreams that is still in the current script: about 155 of the
305 distinctive lines (longer than 25 characters) of RomikB's `9f831f3`, and
about 79 of the 262 of angristan's script at RomikB's base, appear unchanged.
`git blame -w -C` attributes 517 of the script's 14,000 lines to Varckin's
initial commit, that is to the copied RomikB code. Later RomikB or angristan
changes were not found in the script (only generic lines such as
`source /etc/os-release` match).

No other file contains a substantial amount of upstream code: the largest
overlaps elsewhere are two to four generic lines (configuration templates in
tests). The README's lines blamed to Varckin are blank lines and code fences.

### Authorship since 2026

| Author (git) | Commits | Scope |
| --- | --- | --- |
| Vadim Smirnov `<vadim@ntkernel.com>` (WireSock maintainer) | 116 | All components |
| Copilot coding agent (`copilot-swe-agent[bot]`), opened by the `wiresock` account, some co-authored by it | 27 | Initial `amneziawg-web` (#9, #14 and others), `amneziawg-proxy` crate (#15), installer and test changes (#10 to #48) |
| github-actions[bot] | 44 | Version bumps only (`chore(version)`) |
| Denis Glotov `<denis@glotov.org>` | 1 | `amneziawg-install.sh`, one line (#108, the only pull request from outside the `wiresock` account) |

Many later branches are named `claude/...` or `codex/...`, which indicates that
AI coding agents prepared those changes as well; their commits are authored by
Vadim Smirnov. (Assumed from branch names.)

## Inventory

| Path or component | License | Copyright (as recorded) | Origin | Evidence | Action | Confidence |
| --- | --- | --- | --- | --- | --- | --- |
| `LICENSE` | MIT | angristan 2019; Roman Zakharchuk 2024; Markus Varckin 2024; WireSock 2026 | Varckin's `LICENSE` | Lineage above | Restored the two upstream notices, added WireSock's | High |
| `amneziawg-install.sh` | MIT | same four notices; contributor Denis Glotov | Inherited and WireSock | Lineage above, blame | Inline SPDX header with all notices | High |
| `amneziawg-web/` (Rust, scripts, migrations, templates, docs, screenshots) | MIT | WireSock 2026 | WireSock, partly written by coding agents | History; `amneziawg-web/LICENSE` | Rust and shell sources: inline SPDX; rest: `REUSE.toml`; `LICENSE` kept unchanged | High (license); medium (holder, see questions 1 to 3) |
| `amneziawg-web/LICENSE` | MIT | "2024 WireSock" | WireSock | First commit of the component is 2026-03-25 | Kept; year flagged (question 4) | Medium |
| `amneziawg-proxy/` | MIT (`Cargo.toml`) | WireSock 2026 | WireSock (#15 by Copilot agent, then the maintainer) | History | Added `amneziawg-proxy/LICENSE`; inline SPDX in sources | High (license); medium (holder) |
| `amneziawg-web.sh`, `amneziawg-proxy.sh`, `scripts/amneziawg-cargo-build.sh` | MIT | WireSock 2026 | WireSock | History | Inline SPDX | High |
| `packaging/boringtun/**`, `scripts/boringtun-*.sh` | MIT | WireSock 2026 | WireSock | History | `REUSE.toml` only: these files feed attested, reproducible archives and are left byte for byte unchanged. `required-notices` quotes third-party notices as data, so its annotation uses `precedence = "override"` | High |
| `tests/**`, including `tests/fixtures/boringtun-auto-preludes/*.hex` | MIT | WireSock 2026 | WireSock; the fixtures are datagrams recorded from BoringTun releases | History | `REUSE.toml` | High (tests); medium (fixtures are program output, not authored code) |
| `docs/**`, `README.md`, `.github/**`, dotfiles | MIT | WireSock 2026 | WireSock | History | `REUSE.toml` | High |
| `amneziawg-*/Cargo.lock` | MIT | WireSock 2026 | Generated by Cargo | | `REUSE.toml` | High |
| `amneziawg-web/docs/screenshots/*` | MIT | WireSock 2026 | Screenshots of the panel with fictional data (#90, #170) | History, README | `REUSE.toml` | Medium (two of the `.png` files are JPEG data; no licensing effect) |

### Third-party code and dependencies

| Component | License | Relationship | Distributed by the project | Notes |
| --- | --- | --- | --- | --- |
| WireSock BoringTun `boringtun-cli` at `e94c04f3f4fd` | BSD-3-Clause (Cloudflare, Inc. 2019; WireSock 2024-2026 for files the fork added) | Separate program, downloaded by the installer | Yes, as release archives of this repository | Archive ships `LICENSE`, `THIRD-PARTY-LICENSES` (cargo-about), `MANIFEST` with source repository and commit. Gaps: question 9. |
| Crates linked into `boringtun-cli` | Apache-2.0, BSD-2/3-Clause, ISC, MIT, Unicode-3.0 | Static linking | Yes | Gated by `packaging/boringtun/deny.toml`; notices in `THIRD-PARTY-LICENSES`; curve25519-dalek's combined notice pinned by checksum. |
| musl libc, Rust standard library | MIT; MIT OR Apache-2.0 (libunwind: Apache-2.0 WITH LLVM-exception) | Static linking into `boringtun-cli` | Yes | Notices missing from the archives (question 9). |
| `amneziawg-web` crates (183 in the Linux graph) | Permissive; required by the graph: Apache-2.0, BSD-3-Clause, MIT, Unicode-3.0, Zlib | Compiled on the server | No | `.github/licensing/deny.toml`. The only copyleft option in the lockfile, `LGPL-2.1-or-later` in r-efi's "MIT OR Apache-2.0 OR LGPL-2.1-or-later", is for a target that is not built and is satisfied by MIT anyway. SQLite via `libsqlite3-sys` is public domain. No crate ships a `NOTICE` file. |
| `amneziawg-proxy` crates (90) | Same, plus ISC (ring, rustls, rustls-webpki, untrusted) | Compiled on the server | No | ring is "Apache-2.0 AND ISC". No crate ships a `NOTICE` file. |
| AmneziaWG kernel module, `amneziawg-tools` (`awg`, `awg-quick`) | GPL-2.0 | Installed by the package manager from `ppa:amnezia/ppa`; run as separate programs | No | No awg-quick code is copied: no line longer than 30 characters of `wg-quick/linux.bash` occurs in the repository. `tests/test-boringtun-runtime.sh` compares the installer's parser with awg-quick's functions, read from the installed script at test time. See question 8 for the DKMS patch. |
| amneziawg-go | MIT | Built in CI for interop tests | No | |
| Rust toolchain via rustup | MIT OR Apache-2.0 | Installed on request by the component install scripts | No | |

Code shared with WireSock BoringTun: `amneziawg-proxy` and WireSock BoringTun's
imitation modules share some idioms and small fragments. Both are WireSock's
own code, the proxy's dating from May and June 2026; WireSock BoringTun's
imitation files state they were ported from WireSock's own client code. No
third-party code was found in either direction. (Confirmed for the comparison
made; ownership of WireSock's client code is assumed to be WireSock's.)

## Unresolved questions

These need a decision by the maintainers or their counsel. None of them is
resolved by this repository's notices, and the existing permissions are kept
in every case.

1. **The legal entity behind "WireSock".** The notices use the name the project
   already used (`amneziawg-web/LICENSE`, WireSock BoringTun). The repository
   does not say which legal entity that is, or in which jurisdiction.
2. **Ownership of the maintainer's work.** The WireSock-era commits are by Vadim
   Smirnov. Whether his rights belong to the WireSock entity (by employment or
   assignment) or remain his, licensed under MIT, is not documented. It matters
   most for any use of this code under terms other than MIT.
3. **Code written by AI coding agents.** A large part of the code was produced
   by coding agents (the Copilot pull requests and, by branch name, later
   `claude/` and `codex/` work) under the maintainer's direction. How much of it
   is protected by copyright, and who holds that copyright, depends on the
   jurisdiction and on the human contribution to each change. The MIT license
   covers whatever rights exist; the question affects how much exclusive
   ownership WireSock can assert, not what users may do.
4. **The year in `amneziawg-web/LICENSE`.** "2024" predates the component's
   first commit (2026-03-25). Either the code existed before it was committed,
   or the year is a mistake to correct. The SPDX metadata says 2026.
5. **Varckin's notice.** Markus Varckin's changes were limited to URLs and
   README text, so his notice may cover little or nothing that is
   copyrightable. It is kept because it is an existing notice of the lineage,
   and removing it is not needed for any purpose.
6. **Contributors to angristan/wireguard-install.** That project has 38 distinct
   author names in its history before 2024-07-16 under its single "angristan" notice. The notice is
   reproduced as published; contributors' own rights are acknowledged in
   `NOTICE.md` without naming them, as upstream does.
7. **Denis Glotov's change.** One line (removing a `2>/dev/null`) is probably too
   small to be protected. He is named as a contributor; no ownership is claimed
   for WireSock.
8. **The DKMS compatibility patch.** `patchAwgDkmsUdpTunnelCompat` in the
   installer contains, as search keys, two one-line macro definitions that are
   verbatim from the GPL-2.0 AmneziaWG kernel module (commit `0bcc6dfaf9` by
   K900), and replaces them in the module source on the server with macros
   written for this project. The quoted lines are short, functional and needed
   for interoperability, so the risk is low, and the modified GPL source stays
   on the server; it is not distributed. Whether the MIT script should quote
   them is flagged rather than changed, because changing the matching would
   change installer behaviour.
9. **BoringTun archive notices.** The archives do not yet include the notices
   of the statically linked musl libc and Rust standard library, or WireSock's
   own BSD-3-Clause notice for the files its fork added (see
   [`LICENSING.md`](LICENSING.md#known-gaps)). WireSock is a copyright holder of
   the fork and the distributor, so its own notice matters mainly for people who
   redistribute the archives; the musl and Rust notices are owed by the
   distributor. Fixing this needs a new release build and is left to the next
   BoringTun pin change.
10. **Trademarks.** The project and component names use "AmneziaWG". The README
    disclaimer addresses affiliation; trademark use is outside the scope of the
    copyright licenses and of this audit.

## Considerations for proprietary derivative products

- The MIT License allows WireSock, and anyone else, to build a proprietary
  product from this code. The product must keep the notices of `LICENSE`
  (including angristan's, Roman Zakharchuk's and Markus Varckin's for any
  installer code it contains) and must not imply endorsement.
- The MIT-licensed code remains available to everyone under MIT. Rights beyond
  those MIT gives everyone exist only to the extent WireSock owns the code
  (questions 1 to 3). Code from contributors other than WireSock can be used in
  the product only under the license they contributed it under; the
  contribution policy grants no relicensing right.
- If the product redistributes AmneziaWG components (GPL-2.0), it takes on the
  GPL-2.0 obligations for those components, including offering their source.
  Keeping them as separately installed programs, as this project does, keeps
  those obligations with their distributors.
- If it ships `boringtun-cli`, the web panel or the proxy as binaries, it needs
  the third-party notices described in `LICENSING.md`, including the gaps of
  question 9.
- Before reusing the BoringTun fork code under non-BSD terms, the same
  ownership questions apply to it, and Cloudflare's upstream code stays under
  BSD-3-Clause.
