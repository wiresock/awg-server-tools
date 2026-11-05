# Proposed documentation site structure (mdBook)

Goal: shrink the root `README.md` (currently 1,113 lines) to a ~190-line landing
page (see draft `README.md`) and move the rest into an mdBook under `docs/`,
published to GitHub Pages. Component docs that already exist
(`amneziawg-web/docs/`, `amneziawg-proxy/doc/`) are **included** into the book
rather than duplicated, so each fact keeps one source.

## Site tree

```
docs/
├── book.toml
├── src/
│   ├── SUMMARY.md
│   ├── introduction.md            # What the toolkit is, components, choose-your-setup
│   ├── getting-started/
│   │   ├── requirements.md        # Distro matrix (from checkOS), BoringTun host reqs
│   │   ├── quick-start.md         # Download + install commands for all 3 scripts
│   │   ├── choose-setup.md        # Minimal vs VPN+panel vs proxy vs BoringTun
│   │   └── after-install.md       # Client config location, panel address, next steps
│   ├── installer/
│   │   ├── README.md              # How amneziawg-install.sh works (kernel backend)
│   │   ├── non-interactive.md     # Env vars, IPv4-only, MTU, automation
│   │   ├── clients.md             # --add/--remove/--list-client, interactive menu
│   │   ├── awg3.md                # AWG 3.0/3.1 mode, migration, proxy incompatibility
│   │   └── ubuntu-26.04-ppa.md    # Ubuntu 26.04 PPA compatibility
│   ├── boringtun/
│   │   ├── README.md              # Experimental userspace backend overview & install
│   │   ├── lifecycle.md           # Upgrade/rollback of the pinned binary
│   │   ├── imitation.md           # Built-in protocol imitation, auto mode, limits
│   │   ├── artifacts.md           # ← docs/BORINGTUN_ARTIFACTS.md
│   │   ├── migration.md           # ← docs/BORINGTUN_MIGRATION.md
│   │   └── notices.md             # ← docs/BORINGTUN_NOTICES.md
│   ├── web-panel/                 # {{#include}} wrappers around amneziawg-web/…
│   │   ├── README.md              # ← amneziawg-web/README.md
│   │   ├── install.md             # ← amneziawg-web/docs/INSTALL.md
│   │   ├── deployment.md          # ← amneziawg-web/docs/DEPLOYMENT.md
│   │   ├── email-delivery.md      # ← amneziawg-web/docs/EMAIL_DELIVERY.md
│   │   ├── maintenance.md         # upgrade / uninstall / purge (README "Maintenance")
│   │   └── architecture.md        # ← amneziawg-web/docs/ARCHITECTURE.md
│   ├── proxy/                     # {{#include}} wrappers around amneziawg-proxy/doc/…
│   │   ├── README.md              # Overview, install, examples, manage/uninstall
│   │   ├── usage.md               # ← amneziawg-proxy/doc/USAGE.md
│   │   ├── manual-deployment.md   # ← amneziawg-proxy/doc/MANUAL_DEPLOYMENT.md
│   │   ├── architecture.md        # ← amneziawg-proxy/doc/ARCHITECTURE.md
│   │   └── performance.md         # ← amneziawg-proxy/doc/PERFORMANCE.md
│   ├── reference/
│   │   ├── cli.md                 # All amneziawg-install.sh / -web.sh / -proxy.sh flags
│   │   ├── obfuscation-parameters.md  # Jc/Jmin/Jmax, S1–S4, H1–H4 …
│   │   └── versioning.md          # ← docs/VERSIONING.md
│   ├── project/
│   │   ├── background.md          # Project history (README "Background")
│   │   ├── repository-rename.md   # ← docs/REPOSITORY_RENAME.md
│   │   ├── contributing.md        # ← CONTRIBUTING.md (+ web CONTRIBUTING)
│   │   ├── licensing.md           # ← docs/LICENSING.md + License section
│   │   ├── licensing-inventory.md # ← docs/LICENSING_INVENTORY.md
│   │   ├── credits.md             # Credits + NOTICE.md pointer
│   │   └── disclaimer.md
│   └── images/                    # ← amneziawg-web/docs/screenshots/*.png
└── dev/                           # NOT in the published book (internal)
```

## Mapping: current root README → new location

| README lines | Section | Destination |
|---|---|---|
| 1–18 | Title, intro, rename note | `README.md` (kept, condensed) + `introduction.md` |
| 20–33 | 📖 Background | `project/background.md` |
| 35–53 | Web panel preview (screenshots) | `web-panel/README.md`; one screenshot may stay in README |
| 55–124 | 🚀 Quick Start | `README.md` (condensed) + `getting-started/quick-start.md` |
| 126–136 | 🧠 How It Works | `introduction.md` |
| 138–150 | 🤔 Choose Your Setup | `getting-started/choose-setup.md` |
| 152–161 | 🟢 Minimal Setup | `getting-started/choose-setup.md` |
| 163–200 | 🟡 VPN + Web Panel (incl. build prereqs) | `web-panel/install.md` (merge with INSTALL.md) |
| 202–267 | 🎭 Proxy intro + Install | `proxy/README.md` |
| 269–307 | Proxy: How It Works | `proxy/README.md` (or link to `proxy/architecture.md`) |
| 309–341 | Proxy: Traffic Examples | `proxy/usage.md` |
| 343–361 | Proxy: Manage / Uninstall | `proxy/README.md` |
| 363–374 | ⚙️ After Installation | `getting-started/after-install.md` + short README "Basic usage" |
| 376–400 | 🔄 Maintenance (web panel) | `web-panel/maintenance.md` |
| 402–538 | ⚡ Non-Interactive Install | `installer/non-interactive.md` |
| 540–555 | 🤖 Non-Interactive Client Management | `installer/clients.md` + `reference/cli.md` |
| 557–616 | 🔐 AWG 3.0 / 3.1 Mode | `installer/awg3.md` |
| 618–711 | 🧪 BoringTun backend | `boringtun/README.md` |
| 712–792 | BoringTun upgrade/rollback | `boringtun/lifecycle.md` |
| 793–910 | BoringTun built-in imitation | `boringtun/imitation.md` |
| 912–918 | 📦 Requirements | `getting-started/requirements.md` (**fix:** add Mint/Fedora/RHEL-family status from `checkOS`) |
| 919–986 | Ubuntu 26.04 PPA compatibility | `installer/ubuntu-26.04-ppa.md` |
| 988–1061 | Obfuscation Parameters | `reference/obfuscation-parameters.md` |
| 1063–1071 | Credits | `project/credits.md` (short version in README) |
| 1073–1084 | Disclaimer | `project/disclaimer.md` |
| 1086–1113 | License | `project/licensing.md` (short version in README) |

## Mapping: existing docs files

| Current file | Destination | Notes |
|---|---|---|
| `docs/BORINGTUN_ARTIFACTS.md` | `docs/src/boringtun/artifacts.md` | user/operator facing |
| `docs/BORINGTUN_MIGRATION.md` | `docs/src/boringtun/migration.md` | |
| `docs/BORINGTUN_NOTICES.md` | `docs/src/boringtun/notices.md` | |
| `docs/VERSIONING.md` | `docs/src/reference/versioning.md` | |
| `docs/LICENSING.md` | `docs/src/project/licensing.md` | keep README `#known-gaps` anchor working |
| `docs/LICENSING_INVENTORY.md` | `docs/src/project/licensing-inventory.md` | |
| `docs/REPOSITORY_RENAME.md` | `docs/src/project/repository-rename.md` | |
| `amneziawg-web/README.md`, `docs/INSTALL.md`, `DEPLOYMENT.md`, `EMAIL_DELIVERY.md`, `ARCHITECTURE.md` | stay in place; included via `{{#include}}` | keeps component docs next to code |
| `amneziawg-web/docs/RELEASE.md` | `docs/dev/web-release.md` (or include under project/) | maintainer process |
| `amneziawg-web/docs/MVP.md`, `PRODUCT_SPEC.md`, `ROADMAP.md` | `docs/dev/web/` | planning, not user docs |
| `amneziawg-proxy/doc/*.md` | stay in place; included via `{{#include}}` | `doc/README.md` becomes redundant index |
| `CONTRIBUTING.md`, `NOTICE.md` | stay at root (GitHub/REUSE expect them); included in book | |

## Internal planning files → `docs/dev/` (excluded from the book)

| Current file | Proposed location |
|---|---|
| `docs/BORINGTUN_BACKEND_DESIGN.md` (3,189 lines) | `docs/dev/design/boringtun-backend.md` |
| `docs/BORINGTUN_ADOPTION.md` | `docs/dev/design/boringtun-adoption.md` |
| `docs/BORINGTUN_ADOPTION_2026-10-27.md` | `docs/dev/records/2026-10-27-boringtun-adoption.md` |
| `docs/IMPLEMENTATION_PLAN_102_103.md` | `docs/dev/plans/implementation-102-103.md` |
| `docs/superpowers/plans/2026-10-26-boringtun-notices.md` | `docs/dev/plans/` |
| `docs/superpowers/plans/2026-10-27-mtu-budget-validation.md` | `docs/dev/plans/` |
| `docs/superpowers/plans/2026-10-27-email-storage-readiness.md` | `docs/dev/plans/` |
| `amneziawg-web/docs/COPILOT_TASK.md` | `docs/dev/plans/web-copilot-task.md` (or delete) |
| `amneziawg-web/docs/MVP.md`, `PRODUCT_SPEC.md`, `ROADMAP.md` | `docs/dev/web/` |

Before moving anything, update the tooling that references `docs/` paths. Verified by grep: `REUSE.toml`, `scripts/check-licensing.sh`,
`scripts/refresh-boringtun-notices.py`, `.github/workflows/licensing.yml` and
`.github/licensing/deny.toml` all name `docs/` files. Leave redirect stubs at old paths
for one release.

## Sample `docs/book.toml`

```toml
[book]
title = "WireSock AWG Server Tools"
authors = ["WireSock"]
language = "en"
src = "src"

[build]
build-dir = "book"
create-missing = false

[output.html]
git-repository-url = "https://github.com/wiresock/awg-server-tools"
edit-url-template = "https://github.com/wiresock/awg-server-tools/edit/main/docs/{path}"
site-url = "/awg-server-tools/"
no-section-label = true

[output.html.search]
enable = true

[output.linkcheck]   # requires mdbook-linkcheck; run in CI
follow-web-links = false
```

## Sample `docs/src/SUMMARY.md`

```markdown
# Summary

[Introduction](introduction.md)

# Getting started
- [Requirements](getting-started/requirements.md)
- [Quick start](getting-started/quick-start.md)
- [Choose your setup](getting-started/choose-setup.md)
- [After installation](getting-started/after-install.md)

# VPN installer
- [Overview](installer/README.md)
  - [Non-interactive install](installer/non-interactive.md)
  - [Managing clients](installer/clients.md)
  - [AWG 3.0 / 3.1 mode](installer/awg3.md)
  - [Ubuntu 26.04 PPA](installer/ubuntu-26.04-ppa.md)

# BoringTun backend (experimental)
- [Overview](boringtun/README.md)
  - [Upgrade and rollback](boringtun/lifecycle.md)
  - [Protocol imitation](boringtun/imitation.md)
  - [Release artifacts](boringtun/artifacts.md)
  - [Migration](boringtun/migration.md)
  - [Notices](boringtun/notices.md)

# Web panel
- [Overview](web-panel/README.md)
  - [Install](web-panel/install.md)
  - [Deployment](web-panel/deployment.md)
  - [Email delivery](web-panel/email-delivery.md)
  - [Maintenance](web-panel/maintenance.md)
  - [Architecture](web-panel/architecture.md)

# Obfuscation proxy
- [Overview](proxy/README.md)
  - [Usage](proxy/usage.md)
  - [Manual deployment](proxy/manual-deployment.md)
  - [Architecture](proxy/architecture.md)
  - [Performance](proxy/performance.md)

# Reference
- [CLI reference](reference/cli.md)
- [Obfuscation parameters](reference/obfuscation-parameters.md)
- [Versioning](reference/versioning.md)

---
[Background](project/background.md)
[Repository rename](project/repository-rename.md)
[Contributing](project/contributing.md)
[Licensing](project/licensing.md)
[Licensing inventory](project/licensing-inventory.md)
[Credits](project/credits.md)
[Disclaimer](project/disclaimer.md)
```

Example include wrapper (`docs/src/web-panel/install.md`):

```markdown
{{#include ../../../amneziawg-web/docs/INSTALL.md}}
```
Relative links inside included files are rewritten at build time by the
`include-map` preprocessor (`docs/mdbook-include-map.py`, hooked from
`book.toml`). It expands `{{#include}}` before mdBook's built-in `links`
preprocessor, maps known source files onto book chapters, reuses
`docs/src/images/` for web-panel screenshots, and turns other repo paths into
`https://github.com/wiresock/awg-server-tools/blob/main/...` links. Check with
`python3 docs/mdbook-include-map.py --check` from the repository root (same cwd as `mdbook build docs`). mdbook-linkcheck in CI remains a useful extra net.

## CI addition (sketch)

Add a `docs.yml` workflow: install mdbook (+ mdbook-linkcheck), run
`mdbook build docs`, and deploy `docs/book` to GitHub Pages on pushes to `main`.
