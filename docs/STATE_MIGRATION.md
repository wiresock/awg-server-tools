<!-- SPDX-FileCopyrightText: 2026 Vadim Smirnov (doing business as WireSock) -->
<!-- SPDX-License-Identifier: MIT -->

# Server state archives (experimental CLI prototype)

This is the first CLI slice of [#185](https://github.com/wiresock/awg-server-tools/issues/185),
**not yet the complete panel-to-new-VPS migration workflow**. Do a restore drill
before relying on an archive. Debian/Ubuntu only, one server interface, same
AWG protocol and backend, installer-standard /24 IPv4 and optional /64 IPv6
subnets. Custom subnet prefixes fail closed. Import refuses to overwrite an existing installation.

## Commands

Run the installer as root. Use a trusted copy, not one carried in an archive.

```sh
bash amneziawg-install.sh --export-state /root/server.awgx
bash amneziawg-install.sh --inspect-state /root/server.awgx
SERVER_PUB_NIC=ens3 bash amneziawg-install.sh --import-state /root/server.awgx --dry-run
SERVER_PUB_NIC=ens3 bash amneziawg-install.sh --import-state /root/server.awgx
# After reviewing configuration and fencing/stopping the old server:
SERVER_PUB_NIC=ens3 bash amneziawg-install.sh --activate-state /root/server.awgx
```

`ens3` is an example: use the **new host's public network interface**, not its
VPN interface. If omitted, the installer uses the default-route interface. The
VPN interface name is retained from the archive. Neither server nor client keys
are regenerated. Client profiles and Endpoint values remain unchanged.

`age` prompts for the archive passphrase on the controlling terminal, confirming
it on export. There is no password flag, environment variable, stdin protocol,
or plaintext export mode. Use a real interactive terminal. Store the passphrase
separately from the archive. An archive grants full access to the VPN and can
also contain panel passwords and SMTP credentials.

Export/import install missing `age`, `python3`, and `sqlite3` with apt. Inspect,
dry-run and activation require them to be installed already and never install
packages.
The existing installer's distribution/version and signed AWG package handling
is reused. age availability is required; there is no unverified binary download
fallback.

## Timestamps and peer decisions

`--inspect-state` emits the manifest as JSON with a `peer_plan` object.
`--dry-run` prints a JSON plan before the host-install plan. Both show the
export timestamp, the destination evaluation time, per-peer **migrate/drop**
decisions (name, expiry, reason), and migrate/drop counts. Import, unchanged-
receipt reruns and activation log the same policy decisions. Inspection and
planning do not authorize traffic; activation always checks the clock again.

Archives older than **7 days** produce a warning, not a rejection. Export time
in the future relative to the destination clock fails closed: synchronize/check
both hosts' clocks before retrying. Missing, malformed or non-UTC export times
are rejected before extraction; timestamp-less archives from the earlier,
unreleased prototype must be **re-exported**, not assigned an invented time.
Peer expiry timestamps accept timezone-aware RFC3339 and are displayed in UTC.
No deadline is extended by the age of the archive or time spent quarantined.

## What is carried

The encrypted payload is a gzip tar containing only regular files:

- `manifest.json`: schema version 1, protocol, backend, interface, installer
  SHA-256, AWG tools version, per-file SHA-256 inventory, and mandatory
  `exported_at` (UTC ISO 8601, `YYYY-MM-DDTHH:MM:SSZ`, at snapshot packaging). The panel version is
  currently recorded as `not-probed`, not guessed.
- `vpn/params` and `vpn/server.conf`: exact source bytes, including server keys,
  PSKs, obfuscation and protocol fields. Imported params are parsed as literals
  against an allowlist, **never sourced**. Only validated values are serialized
  into new local params.
- `clients/*.conf`: discovered installer-managed profiles, byte for byte.
  Discovery reuses `collectAwgClientConfigCandidates`: managed clients directory,
  panel config directory, `/root`, `/home/*`, and managed users' resolved homes.
  Conflicting copies with the same basename and custom client shell hooks fail export. Copies are restored
  into the managed clients directory, not arbitrary archived home paths.
- `web/database.sqlite`: if the panel is installed, a consistent online
  `sqlite3 .backup` of the effective database location: `--database-url` takes
  precedence over `AWG_WEB_DB`; absent settings use `awg-web.db`. Relative paths
  use the service working directory.
  Unsupported SQLite URL/query formats fail export rather than silently omit
  the DB. Per-peer `expires_at` values remain in this snapshot; no remaining
  lifetime is reset on the destination. `web/env.conf` is copied from the existing env-file resolver.
- `proxy/proxy.toml`: the default `/etc/amneziawg-proxy/proxy.toml`, if present.

### Companion path inventory and deliberate gaps

The panel installer defines `/etc/amneziawg-web/env.conf` and
`/var/lib/amneziawg-web/awg-web.db`; `src/main.rs` supports `AWG_WEB_DB` and
`--database-url`. The actual Clap default is `awg-web.db`, relative to the
process/service working directory (not an unconditional `/var/lib` path).
The effective ExecStart `--database-url` overrides the environment; a resolver
error fails export rather than falling back to a different database. Only an
absent CLI setting falls back to `AWG_WEB_DB`, then the default. The existing
unit/env/working-directory resolvers are used for export.
Saved SMTP settings (including credentials) are in the panel DB's
`email_panel_settings` table (`src/delivery/settings.rs`). Environment-based
mail defaults may live in env.conf or unit settings; this prototype does not
flatten systemd Environment directives or merge multiple env files.

The proxy installer defaults to `/etc/amneziawg-proxy/proxy.toml`, and supports
custom `--config-file` paths. Custom proxy paths are **not discovered** yet.
`/var/lib/amneziawg-proxy/sessions.json` is runtime state and is excluded.

**Automatic panel/mail/proxy installation, path rebinding, DB migration, queue
scrubbing, ownership/ACL restoration and HTTPS setup remain TODO.** Companion
files are retained privately under the import journal's `recovery/` directory,
not copied into live service locations. Do not manually activate a recovered DB
without handling stale delivery jobs/grants and reviewing settings first. No
mail is sent or queued job replayed by the import. TLS keys, binaries, service
units, firewall dumps, sessions and arbitrary directory contents are excluded.
This is why this prototype does not yet meet issue #185's full phase-1 goal of
restoring a usable panel.

## Import safety and activation

1. Decrypt into private temporary staging. Verify schema, complete file
   inventory, checksums, params/config agreement, member names/types and size
   limits **before extraction**. Absolute paths, dot segments, duplicate
   members, symlinks, hardlinks, devices, directories and PAX overrides fail.
   JSON duplicate keys fail too. Checksums detect inconsistent payloads; they
   are not proof of the archive author's identity.
2. Preflight validates target paths, free UDP port, existing interface/unit and
   installation conflicts. The archive selects its original protocol/backend;
   this is not an in-place replacement or a backend/protocol conversion tool.
3. Exclude disabled, archived and **removal-pending** peers using the panel DB
   snapshot. Compare every expiry with the **destination host's current UTC
   clock**, not the export time: already expired (`expires_at <= now`) peers
   are dropped; future-expiry peers migrate normally, with their original
   deadline unchanged. A malformed/naive expiry is dropped rather than guessed.
   Decisions include the peer's name and expiry. A failed manual removal must
   not resurrect its peer. Required columns `public_key`, `disabled`, `archived`,
   `removal_pending`, `expires_at` must exist; incompatible schemas fail closed
   with a missing-column diagnostic. NULL policy flags are excluded too.
   Commented peers stay commented; profiles alone do not authorize traffic.
   **Ongoing expiry enforcement after activation depends on restoring the panel
   (or on the operator).** This prototype does not restore that enforcement or
   install a background expiry timer, but it does not block future-expiry users
   from migrating. Policy is only as recent as the snapshot: later bans or
   deadline changes are not magically known.
4. Reuse package/backend installation via an internal hook, preserving keys and
   protocol parameters. On BoringTun, reinstall and verify the pinned release.
   No initial client is generated. Temporary capability-probe keys are unrelated
   to the preserved server identity.
5. Discard **all** archived PreUp/PostUp/PreDown/PostDown commands. Regenerate
   firewall hooks for the target NIC/firewall stack. Keep the other server
   configuration fields and retained peers, and regenerate units/sysctl files.
   Forwarding sysctls are written but not applied during import.
6. Probe backend readiness and validate imported protocol fields with the
   installed tools using the existing scratch-interface validator (no peers).
   This is **not** a real client handshake test.
7. Leave the actual VPN stopped and disabled. This prototype's quarantine is an
   inactive service, not a live test-client firewall. Fence the old server and
   review the regenerated configuration. **Activate only with
   `--activate-state <same-archive>`**, not a manual `systemctl start/enable`.
   Activation decrypts/verifies the archive again, holds the lifecycle lock,
   verifies unchanged local receipts and **re-runs peer-policy reconciliation
   at activation and again after backend validation/sysctl application,
   immediately before startup**. Peers whose expiry passed during quarantine
   or validation are dropped then. It filters the current local config
   (removals only), never rebuilds peers from the old snapshot, and preserves
   receipt-verified generated host hooks. Import also refreshes expiry after
   package installation before recording its receipt. Only after that,
   verify a real client handshake before DNS cutover. Do not run both servers
   as active authorities for the same identity.
8. Activation does **not** enable the unit at boot. Use the same activation
   command after reboot until the full panel/enforcement workflow is restored.
   Reconciliation/activation refuses a running or enabled VPN: stop and disable
   it first. This is not a live config editor. Root can bypass the supported
   workflow with manual systemd commands; that is explicitly unsupported.

The journal is `/var/lib/amneziawg-install/state-imports/<manifest-digest>/`.
On ordinary failure/INT/TERM, newly created VPN config/instance units are removed
and previous sysctl/module-load/modprobe files restored. Packages, apt sources,
verified binaries/helpers, module load side effects and empty directories may
remain; this is **not full host rollback**. Power loss/SIGKILL needs operator
inspection. A successful reimport verifies its receipt and unchanged local config
hashes, then re-runs policy reconciliation even when those hashes are unchanged;
it does not reinstall or activate. A dry-run checks the reconciliation plan
without changing the config/receipt. Receipts are refreshed after safe,
removals-only reconciliation; a changed local installation is never overwritten.

Temporary decrypted files use mode 0600 within a 0700 directory and are removed
on ordinary exit. They are not securely erased; use encrypted storage. A hard
kill can leave staging behind. Streaming panel export and a no-plaintext-staging
mode are separate follow-up work. The encrypted destination is published with
mode 0600 without overwriting an existing path.

Clients using a hostname still depend on client DNS re-resolution behavior.
Literal-IP endpoints need a profile update. No DNS changes or endpoint rewrites
are done automatically.

## Tests and remaining acceptance work

`python3 tests/test-state-archive.py` checks literal parsing/injection, malicious
members/links, checksums/schema/protocol/backend mismatch, exact file roundtrip,
hook removal, snapshot CLI/env/default precedence, missing policy columns,
failed manual removal, UTC manifest timestamp/clock sanity and old-archive warnings,
per-peer inspection/dry-run counts, expired/future-expiry activation (including
deadlines passing in quarantine or backend validation), no-resurrection reruns,
dry-run, quarantine, rollback modes and idempotency using isolated host mocks.
With `age` installed it additionally
uses a real controlling TTY for passphrase roundtrip and wrong-passphrase tests.
CI installs age and runs this suite.

Still required: full two-container/VM install roundtrip with distinct uplinks,
real client datapath/handshake, DNS failover across representative clients,
BoringTun/kernel install drills, panel/mail/proxy restore and queue migration,
concurrent panel export stress, and power-loss recovery testing. The mock
roundtrip must not be described as those live tests.
