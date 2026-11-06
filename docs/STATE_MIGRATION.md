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
SERVER_PUB_NIC=ens3 bash amneziawg-install.sh --activate-state /root/server.awgx --enable-at-boot
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
   If a panel DB exists, a config peer absent from its `peers` table is dropped
   with reason `not_in_panel`; an absent panel DB preserves the config-only
   behavior. Commented peers stay commented; profiles alone do not authorize traffic.
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
   `--activate-state <same-archive> --enable-at-boot`**, not a manual
   `systemctl start/enable` before finalization.
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
8. With `--enable-at-boot`, successful activation enables the unit and records
   **finalized** in the journal (including a non-secret persistent marker).
   This is the normal completed migration: after reboot, systemd starts the
   local VPN without an archive, passphrase or migration-script invocation.
   Normal `systemctl` management and panel/operator configuration changes are
   supported after finalization. Subsequent archive import/activation calls
   are no-ops **only when the trusted local params/server config still exist
   and match the interface and server private key in the manifest-verified
   archived params**. Missing files after uninstall, malformed literal params or
   a different identity fail explicitly, without replaying policy or restoring anything.
   An intact finalized installation may be active/enabled and have ordinary
   port/address/peer edits; old receipts/policy are not replayed.
   Ongoing expiry enforcement remains the panel/operator's responsibility.
   Without the flag, activation is temporary testing only and leaves boot
   disabled. Stop/disable the test VPN, then repeat activation with
   `--enable-at-boot` to finalize. An enable/marker-publication failure attempts
   to stop/disable the unit and leaves the migration unfinalized. A power loss
   between enabling and recording the marker needs operator inspection.

The journal is `/var/lib/amneziawg-install/state-imports/<manifest-digest>/`.
On ordinary failure/INT/TERM, newly created VPN config/instance units are removed
and previous sysctl/module-load/modprobe files restored. Packages, apt sources,
verified binaries/helpers, module load side effects and empty directories may
remain; this is **not full host rollback**. Power loss/SIGKILL needs operator
inspection. A successful reimport verifies its receipt and unchanged local config
hashes, then re-runs policy reconciliation even when those hashes are unchanged;
it does not reinstall or activate. This applies **before finalization**; finalized
imports never replay the old snapshot. A dry-run checks the reconciliation plan
without changing the config/receipt. Receipts are refreshed after safe,
removals-only reconciliation; a changed local installation is never overwritten.

### Purging plaintext journal secrets

The journal's `recovery/` retains exact plaintext server params/keys, the panel
DB/env (potentially SMTP credentials), and proxy data. `before/` retains rollback
files. These are root-private but **remain until explicitly purged**; finalizing
prints a reminder and the exact manifest digest to use:

```sh
# Replace MANIFEST_SHA256 with the 64-character digest from the journal path:
bash amneziawg-install.sh --purge-state-journal MANIFEST_SHA256
# Only to abandon an unfinalized/failed import and its rollback/activation path:
bash amneziawg-install.sh --purge-state-journal MANIFEST_SHA256 --force
```

No archive/passphrase or age/sqlite dependency is needed for purge. It refuses
unfinalized journals without `--force`, validates the digest and trusted journal
path, takes the lifecycle lock, and rejects unexpected top-level entries. It
removes recovery/rollback files and receipts without following symlinks or
crossing filesystem boundaries. A finalized journal retains **only the non-secret
`finalized` interface-name tombstone**, so old archives cannot resurrect policy
after purge. Repeated purge is safe. Forced purge of an unfinalized journal
removes it entirely and abandons that import's recovery/reconciliation path;
it does not stop the VPN or remove the installed configuration.

### Lifecycle serialization (including a fresh standalone host)

All installer lifecycle operations use the persistent, root-private directory
inode `/var/lib/amneziawg-install/lifecycle`, opened read-only and locked with
non-blocking `flock`. It is **outside** the VPN/client installation tree, so
acquiring a lock for reset or a fresh import does not create `clients/` or make
fresh-target preflight reject its own side effects. Rollback, uninstall and
journal reset/purge retain this inode. Do not delete/recreate it while commands
may run; stop all older installer commands before upgrading the script.

When a panel is configured, the installer **also** acquires the existing panel
SQLite parent-directory inode lock, resolved with the panel's effective
`--database-url`/environment/working-directory rules. This preserves serialization
with native Rust creation/removal/expiry/DB updates and their privileged helper
calls, without changing the panel's locking protocol or permissions. The helper's
per-interface config lock remains unchanged. Installer locks are acquired in
root-private-then-panel order, both non-blockingly; a partial failure releases
the first immediately. No service-writable lock file is created or modified.

Normal fresh installation now takes the same lock and rechecks params under it,
so it cannot race a reset/import or another fresh installation. If params appear
before acquisition, rerun for management. Existing unrelated interface configs
remain supported by the existing free-NIC selection and no-overwrite checks.
Import reuses the underlying installation hook under its existing lock, not the
new interactive-entry wrapper, avoiding recursive acquisition.

### Restoring the same archive after uninstall (explicit reset)

Uninstall **retains** migration journals and finalized tombstones and prints a
reminder. Automatically deleting them would silently reopen old policy replay
and erase recovery/forensic data. A tombstone alone is not evidence of a live
installation: a later import/activation checks the interface name and private
key in local params against the manifest-verified archived params, and requires
the server config's `[Interface]` private key to match too. These private keys
and the interface are authoritative; equal private keys identify the same server
without needing a locally installed backend to derive a public key. A stale,
missing or malformed literal cached `SERVER_PUB_KEY` only produces a warning
**after all authoritative checks pass**; it is neither trusted nor repaired.
Unsafe literal syntax still fails, and normal archive/export params validation
remains strict. Missing/unsafe files or a different private key/interface return
non-zero with a recovery hint.
The guard does not compare mutable peer lists, ports or old receipt hashes, so
ordinary post-finalization management still works without stale policy replay.

For intentional recovery after **fully uninstalling/removing any conflicting
installation**, first preserve the encrypted archive and review its age/policy:

```sh
# Replace MANIFEST_SHA256 with the digest from the retained journal path.
bash amneziawg-install.sh --reset-state-journal MANIFEST_SHA256 --confirm-policy-replay
SERVER_PUB_NIC=ens3 bash amneziawg-install.sh --import-state /root/server.awgx --dry-run
SERVER_PUB_NIC=ens3 bash amneziawg-install.sh --import-state /root/server.awgx
# Fence the old server, review the fresh import, then finalize again:
SERVER_PUB_NIC=ens3 bash amneziawg-install.sh --activate-state /root/server.awgx --enable-at-boot
```

Reset is distinct from purge: it **removes that archive's finalized tombstone
and journal**, deliberately permitting a fresh import. It requires explicit
`--confirm-policy-replay`, a valid finalized journal/digest, no local params or
server `.conf` files, and a queryable inactive/failed, non-enabled VPN unit.
Reset takes the same exclusive client lifecycle lock as import/purge before
checking journal/installation state and holds it through deletion; a competing
lifecycle operation fails without changing the journal. Any blocking root
`.conf` files (including symlinks) are listed by byte-escaped filename using
`LC_ALL=C` shell quoting, not contents, so whitespace/control characters and
Unicode bidi controls cannot disguise the diagnostic.
Unknown service state, remaining installation files, unsafe paths or unexpected
journal entries fail closed. It never uninstalls/stops a service or overwrites a
live installation; normal fresh-import preflight still applies afterward.
No archive/passphrase or age/python/sqlite dependency is needed for reset.

**Warning:** this is explicit old-snapshot replay, not a continuation of the
finalized installation. Expiry is evaluated against the **current host clock**;
expired, disabled, removal-pending and absent-from-panel peers are excluded.
Local bans/removals or deadline changes made after export are not in the backup
and may be lost; previously locally removed peers can return if its policy
still permits them. Inspect/dry-run and review those decisions before importing.
The new import starts quarantined and must be finalized anew. Purge alone never
removes a finalized tombstone; there is no automatic reset on uninstall.

### Temporary staging and streaming encryption

Export streams gzip tar bytes **directly into age through a pipe**; no plaintext
`state.tar.gz` is written. Both pipeline statuses are checked (`pipefail`), and a
failed producer or encryption removes partial ciphertext rather than publishing
it. Individual-file snapshots (including SQLite `.backup`) still need staging.
All CLI modes prefer a private 0700 directory on `/dev/shm`, then `/run`, only
when that location is tmpfs/ramfs; if neither can create a staging directory,
there is a warned private `/tmp` fallback. Insufficient RAM/staging space aborts
rather than silently spilling an in-progress snapshot to disk. Import/inspect
still decrypt a bounded tarball inside their private staging directory.

Temporary plaintext files are mode 0600 and removed on ordinary exit. tmpfs may
be swapped: use encrypted swap/storage. Deletion/purge is **not secure erasure**;
a hard kill can leave staging, and prior disk, swap or backup copies may survive.
A fully no-plaintext-staging SQLite workflow remains follow-up work. The encrypted
destination is published with mode 0600 without overwriting an existing path.

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
It also covers authoritative panel membership, finalization/enable failure and
a simulated enabled-unit reboot (not a real host reboot), post-finalization
operator edits/purge, real-clock expiry crossing without mocking the comparison,
RAM staging, streaming export, and producer/consumer failure cleanup. Finalized
identity tests cover missing params/config after simulated uninstall, different
private keys or interface, cached-public-key warning-only handling after valid
private-key checks, normal mutable edits, reset safety and a fresh quarantined
import after explicit reset. Real `flock` contention tests verify reset holds the
lifecycle lock through preconditions/deletion and releases it on failure. Fresh
import/rollback and reset→fresh-import orchestration now use production lock
acquisition, not mocks. Tests cover ordinary fresh-install/reset contention,
under-lock params rechecks, retained standalone inodes and the panel database
lock compatibility/partial-failure release. Reset diagnostics cover multiple
filenames, spaces, control characters, Unicode bidi controls and symlinks.
With `age` installed it additionally
uses a real controlling TTY for passphrase roundtrip and wrong-passphrase tests.
CI installs age and runs this suite.

Still required: full two-container/VM install roundtrip with distinct uplinks,
real client datapath/handshake, DNS failover across representative clients,
BoringTun/kernel install drills, panel/mail/proxy restore and queue migration,
concurrent panel export stress, and power-loss recovery testing. The mock
roundtrip must not be described as those live tests.
