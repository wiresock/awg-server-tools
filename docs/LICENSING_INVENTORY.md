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
| wiresock/awg-server-tools | Its history begins with Varckin's seven commits; Vadim Smirnov's work, as WireSock, starts with `ab182aa` (2026-01-31). | Confirmed |

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

WireSock is a trade name ("doing business as") of Vadim Smirnov, an individual;
it is not a company or other separate legal entity. (Stated by the maintainer
on 2026-10-25.) The notices therefore name him: `Vadim Smirnov (doing business as WireSock)`.
They name the individual, so they do not depend on how or whether the trade
name is registered.

| Author (git) | Commits | Scope |
| --- | --- | --- |
| Vadim Smirnov `<vadim@ntkernel.com>`, the maintainer | 116 | All components |
| Copilot coding agent (`copilot-swe-agent[bot]`), opened by the `wiresock` account, some co-authored by it | 27 | Initial `amneziawg-web` (#9, #14 and others), `amneziawg-proxy` crate (#15), installer and test changes (#10 to #48) |
| github-actions[bot] | 44 | Version bumps only (`chore(version)`) |
| Denis Glotov `<denis@glotov.org>` | 1 | `amneziawg-install.sh`, one line (#108, the only pull request from outside the `wiresock` account) |

Many later branches are named `claude/...` or `codex/...`, which indicates that
AI coding agents prepared those changes as well; their commits are authored by
Vadim Smirnov. (Assumed from branch names.)

## Inventory

"VS" below stands for `2026 Vadim Smirnov (doing business as WireSock)`.

| Path or component | License | Copyright (as recorded) | Origin | Evidence | Action | Confidence |
| --- | --- | --- | --- | --- | --- | --- |
| `LICENSE` | MIT | angristan 2019; Roman Zakharchuk 2024; Markus Varckin 2024; VS | Varckin's `LICENSE` | Lineage above | Restored the two upstream notices, added VS | High |
| `amneziawg-install.sh` | MIT | same four notices; contributor Denis Glotov | Inherited, then Vadim Smirnov | Lineage above, blame | Inline SPDX header with all notices | High |
| `amneziawg-web/` (Rust, scripts, migrations, templates, docs, screenshots) | MIT | VS | Vadim Smirnov, partly written by coding agents he directed | History | Rust and shell sources: inline SPDX; rest: `REUSE.toml` | High (license); medium (extent of protection, questions 1 and 2) |
| `amneziawg-web/LICENSE` | MIT | VS (was "2024 WireSock") | Vadim Smirnov | The component's first commit, `c1e01ac` on 2026-03-25 (PR #9, by the Copilot agent), adds the whole panel together with this `LICENSE`. No earlier history in this repository and no separate earlier repository is known. | Year corrected to 2026; holder named | High |
| `amneziawg-proxy/` | MIT (`Cargo.toml`) | VS | Vadim Smirnov (#15 by the Copilot agent, then the maintainer) | History | Added `amneziawg-proxy/LICENSE`; inline SPDX in sources | High (license); medium (questions 1 and 2) |
| `amneziawg-web.sh`, `amneziawg-proxy.sh`, `scripts/amneziawg-cargo-build.sh` | MIT | VS | Vadim Smirnov | History | Inline SPDX | High |
| BoringTun packaging recipe, provenance metadata and scripts | MIT | VS | Vadim Smirnov | History | `REUSE.toml`; `required-notices` quotes notices as data with an override annotation. Vendored full notice texts are separate entries below. | High |
| `packaging/boringtun/fork-license.txt` | BSD-3-Clause | Cloudflare, Inc. 2019; Vadim Smirnov (doing business as WireSock), existing 2024-2026 range | BoringTun upstream/fork notices | Exact source license comparison and notice policy checksum | Explicit REUSE override; Cloudflare text preserved, 2024 remains unverified | High (preservation); unresolved fork start year |
| `packaging/boringtun/runtime-notices.txt` | `LicenseRef-BoringTun-Runtime-Notices`, retaining each portion's original terms | Upstream holders identified in the reproduced notices | Linux profile: exact pinned Rust, musl, ring and LLVM inputs | `runtime-provenance.json`, `runtime-sections.json`, notice policy and reproducible generator | Explicit REUSE override; exact collection also in `LICENSES/`; no aggregate MIT ownership claim | High (text provenance); release gates below remain |
| `packaging/boringtun/runtime-notices-macos.txt` | `LicenseRef-BoringTun-Runtime-Notices-macOS`, retaining each portion's original terms | Upstream holders identified in the reproduced notices | macOS profile: common Rust and ring notice supersets; excludes Linux musl and self-contained CRT/libunwind sections | `runtime-provenance.json`, `runtime-sections-macos.json`, policy v2 and reproducible generator; both macOS distribution inventories pinned | Explicit REUSE override; exact collection also in `LICENSES/`; no aggregate MIT ownership claim | High (text provenance); release gates below remain |
| `tests/**`, including `tests/fixtures/boringtun-auto-preludes/*.hex` | MIT | VS | Vadim Smirnov; the fixtures are datagrams recorded from BoringTun releases | History | `REUSE.toml` | High (tests); medium (fixtures are program output, not authored code) |
| `docs/**`, `README.md`, `.github/**`, dotfiles | MIT | VS | Vadim Smirnov | History | `REUSE.toml` | High |
| `amneziawg-*/Cargo.lock` | MIT | VS | Generated by Cargo | | `REUSE.toml` | High |
| `amneziawg-web/docs/screenshots/*` | MIT | VS | Screenshots of the panel with fictional data (#90, #170) | History, README | `REUSE.toml` | Medium (two of the `.png` files are JPEG data; no licensing effect) |

### Third-party code and dependencies

| Component | License | Relationship | Distributed by the project | Notes |
| --- | --- | --- | --- | --- |
| WireSock BoringTun `boringtun-cli` at `e94c04f3f4fd` | BSD-3-Clause (Cloudflare, Inc. 2019; files the fork added say "2024-2026 WireSock", that is Vadim Smirnov) | Separate program, downloaded by the installer | Yes, as release archives of this repository | Archive ships `LICENSE`, `THIRD-PARTY-LICENSES` (cargo-about), `MANIFEST` with source repository and commit. Gaps: question 6, [issue #175](https://github.com/wiresock/awg-server-tools/issues/175). |
| Crates linked into `boringtun-cli` | Apache-2.0, BSD-2/3-Clause, ISC, MIT, Unicode-3.0 | Static linking | Yes | Gated by `packaging/boringtun/deny.toml`; notices in `THIRD-PARTY-LICENSES`; curve25519-dalek's combined notice pinned by checksum. |
| musl libc, Rust standard library and native runtime objects | Per-component licenses, including MIT, Apache-2.0 and Apache-2.0 WITH LLVM-exception | Target-specific linking into `boringtun-cli`; Linux musl/self-contained native runtime and macOS system-library profiles are distinct | Yes | Reviewed notice collections added to packaging, with exact hashes for all five Rust target distributions; published archives remain unchanged and need replacement releases (question 6). |
| `amneziawg-web` crates (183 in the Linux graph) | Permissive; required by the graph: Apache-2.0, BSD-3-Clause, MIT, Unicode-3.0, Zlib | Compiled on the server | No | `.github/licensing/deny.toml`. The only copyleft option in the lockfile, `LGPL-2.1-or-later` in r-efi's "MIT OR Apache-2.0 OR LGPL-2.1-or-later", is for a target that is not built and is satisfied by MIT anyway. SQLite via `libsqlite3-sys` is public domain. No crate ships a `NOTICE` file. |
| `amneziawg-proxy` crates (90) | Same, plus ISC (ring, rustls, rustls-webpki, untrusted) | Compiled on the server | No | ring is "Apache-2.0 AND ISC". No crate ships a `NOTICE` file. |
| AmneziaWG kernel module, `amneziawg-tools` (`awg`, `awg-quick`) | GPL-2.0 | Installed by the package manager from `ppa:amnezia/ppa`; run as separate programs | No | No awg-quick code is copied: no line longer than 30 characters of `wg-quick/linux.bash` occurs in the repository. `tests/test-boringtun-runtime.sh` compares the installer's parser with awg-quick's functions, read from the installed script at test time. See question 5 for the DKMS patch. |
| amneziawg-go | MIT | Built in CI for interop tests | No | |
| Rust toolchain via rustup | MIT OR Apache-2.0 | Installed on request by the component install scripts | No | |

Code shared with WireSock BoringTun: `amneziawg-proxy` and WireSock BoringTun's
imitation modules share some idioms and small fragments. Both are Vadim
Smirnov's own code, the proxy's dating from May and June 2026; WireSock
BoringTun's imitation files state they were ported from his WireSock client
code. No third-party code was found in either direction. (Confirmed for the
comparison made; the ownership of that client code is assumed to be his and is
covered by question 1.)

## Resolved

- **Who "WireSock" is.** A trade name of Vadim Smirnov, not a separate legal
  entity (maintainer statement, 2026-10-25). The notices name him.
- **The year in `amneziawg-web/LICENSE`.** "2024" had no supporting evidence:
  the component, including that file, first appears on 2026-03-25 and no
  earlier development is known. It is now 2026.

## Unresolved questions

These need a decision by the maintainer or counsel. None of them is resolved
by this repository's notices, and the existing permissions are kept in every
case.

1. **Agreements that could affect ownership.** The notices assume that Vadim
   Smirnov owns the rights in his own work. The repository records no
   employment, contracting, client or funding agreement that could give someone
   else rights in it. For example, his commits use an `ntkernel.com` address,
   and the BoringTun fork lives in the `Wiresock-Foundation` GitHub
   organization. Whether any such agreement exists is for him to confirm. It
   matters most for any use of the code under terms other than MIT.
2. **Code written by AI coding agents.** A large part of the code was produced
   by coding agents (the Copilot pull requests and, by branch name, later
   `claude/` and `codex/` work) under the maintainer's direction. How much of
   it is protected by copyright depends on the jurisdiction and on the human
   contribution to each change. The terms of the tools used may also bear on
   it. The MIT license covers whatever rights exist; the question affects how
   much exclusive ownership can be asserted, not what users may do.
3. **Varckin's notice.** Markus Varckin's changes were limited to URLs and
   README text, so his notice may cover little or nothing that is
   copyrightable. It is kept because it is an existing notice of the lineage,
   and removing it is not needed for any purpose.
4. **Contributors to angristan/wireguard-install.** That project has 38
   distinct author names in its history before 2024-07-16 under its single
   "angristan" notice. The notice is reproduced as published; contributors' own
   rights are acknowledged in `NOTICE.md` without naming them, as upstream
   does.
5. **The DKMS compatibility patch.** `patchAwgDkmsUdpTunnelCompat` in the
   installer contains, as search keys, two one-line macro definitions that are
   verbatim from the GPL-2.0 AmneziaWG kernel module (commit `0bcc6dfaf9` by
   K900), and replaces them in the module source on the server with macros
   written for this project. The quoted lines are short, functional and needed
   for interoperability, so the risk is low, and the modified GPL source stays
   on the server; it is not distributed. Whether the MIT script should quote
   them is flagged rather than changed, because changing the matching would
   change installer behaviour.
6. **BoringTun replacement releases and fork years.** The packaging fix now
   includes reviewed runtime/native notices and a complete fork license, but
   existing published archives are unchanged. The fork's 2024 start is retained
   without being declared verified; owner evidence or an explicit correction is
   still needed. Build, reproducibility, provenance, publication and separate
   installer adoption gates remain before this correction reaches users (see
   [`LICENSING.md`](LICENSING.md#known-gaps)). Tracked in
   [issue #175](https://github.com/wiresock/awg-server-tools/issues/175), to be
   fixed in new, attested release builds before the binary is distributed in
   any other product.
7. **Denis Glotov's change.** One line (removing a `2>/dev/null`) is probably
   too small to be protected. He is named as a contributor; no ownership is
   claimed for the maintainer.
8. **Trademarks.** The project and component names use "AmneziaWG". The README
   disclaimer addresses affiliation; trademark use is outside the scope of the
   copyright licenses and of this audit.

## Considerations for proprietary derivative products

- The MIT License allows anyone to build a proprietary product from this code,
  including Vadim Smirnov under the WireSock name. The product must keep the
  notices of `LICENSE` (including angristan's, Roman Zakharchuk's and Markus
  Varckin's for any installer code it contains) and must not imply endorsement.
- The MIT-licensed code remains available to everyone under MIT. Rights beyond
  those MIT gives everyone exist only to the extent Vadim Smirnov owns the code
  (questions 1 and 2). Code from other contributors can be used in the product
  only under the license they contributed it under; the contribution policy
  grants no relicensing right.
- The rights in his own work can be transferred, for example to a legal entity
  formed later. Such a transfer should be recorded in writing, and the notices
  can then name the new owner from then on. It would not withdraw the MIT
  License already granted, and it could not include other contributors' rights
  without their own agreement. No such entity exists today, and none is
  assumed here.
- If the product redistributes AmneziaWG components (GPL-2.0), it takes on the
  GPL-2.0 obligations for those components, including offering their source.
  Keeping them as separately installed programs, as this project does, keeps
  those obligations with their distributors.
- If it ships `boringtun-cli`, the web panel or the proxy as binaries, it needs
  the third-party notices described in `LICENSING.md`, including the gaps of
  question 6.
- Before reusing the BoringTun fork code under non-BSD terms, the same
  ownership questions apply to it, and Cloudflare's upstream code stays under
  BSD-3-Clause.
