<!-- SPDX-FileCopyrightText: 2026 Vadim Smirnov (doing business as WireSock) -->
<!-- SPDX-License-Identifier: MIT -->
# Email storage readiness implementation plan

> Execute inline with systematic debugging and TDD; obtain independent whole-diff review before opening a draft PR.

Goal: align fresh deployment defaults with the existing private credential guard and explain unavailable persistence without exposing secrets.

Architecture: correct installer/systemd/Docker creation permissions. Keep the runtime guard and peer-only startup unchanged. Existing files and custom mounts require explicit offline operator repair, not automatic recursive permission changes.

Spec: authorized investigation of the installer/storage-readiness mismatch related to issue #171. The reporter's environment and cause remain unknown. Base: c150dee9ed38651d3fc3eeb1e0bbb67378b81e2a, including MTU PR #180.

Constraints: fixture-only testing; no live SMTP, deployment, merge, credential reads or real-server permission changes. No weakening of links, ownership or mode checks.

Review focus: preserved old units and systemd drop-ins; existing SQLite sidecars inherit the DB mode; Docker bind mounts hide image permissions; custom database paths; startup quarantine requires restart while env-only storage checks can refresh on Reload.

1. Write and run failing installer/unit/Docker fixtures and the successful-SMTP/disabled-Save browser regression. Expect directory0750 or0755, database0644, and insufficient repair guidance.
2. Set installer directory0700 and UMask0077 in packaged, inline and preserved installer units; Docker directory0700 and exec launch with umask077. Do not repair existing DB files automatically.
3. Explain disabled Save, directory0700/file0600, service ownership, SMTP/persistence distinction and reload/restart. Document offline repair for upgrades, manual deployments and bind mounts.
4. Run fixture suites, all browser tests and the web crate's complete cargo test suite on Linux. Confirm the original guard rejects permissive files, links and wrong ownership; verify new SQLx files/sidecars under the deployment mask.
5. Independently review, commit, push a separate draft PR, attach it, and monitor CI on the exact head. Do not post to issue #171.

Decision: default correction plus explicit offline repair is preferable to adding privileged credential-file migration. Ordinary binary upgrades may preserve old units and files and therefore remain save-disabled until repaired.
