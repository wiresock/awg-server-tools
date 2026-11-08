<!-- SPDX-FileCopyrightText: 2026 Vadim Smirnov (doing business as WireSock) -->
<!-- SPDX-License-Identifier: MIT -->

# Server state archives (experimental CLI prototype)

This is the first CLI slice of [#185](https://github.com/wiresock/awg-server-tools/issues/185),
covering the VPN, the amneziawg-web panel and amneziawg-proxy (HTTPS for the
panel is operator-managed and not restored). Do a restore drill
before relying on an archive. Debian/Ubuntu only (including the derivatives the
installer already maps to them: Raspbian and Linux Mint), one server interface, same
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

`SERVER_PUB_IP=<hostname|IPv4|IPv6>` (no port; `host:port` is rejected, and a
value containing `:` must be a valid IPv6 address, bare or in one balanced
`[...]` pair — brackets are stripped because the installer adds them when it
builds `Endpoint`; all-digits-and-dots values must be a dotted quad with
octets 0-255 and no leading zeros; hostnames need 1-63-character labels with
alphanumeric ends; the unspecified `::`/`0.0.0.0`, loopback (`127.0.0.0/8`, `::1`) and multicast
(`224.0.0.0/4`, `ff00::/8`), including IPv4-mapped forms, are rejected) may be set at import, like `SERVER_PUB_NIC`, to change
the endpoint recorded in the new params (used for profiles generated after
cutover; restored profiles keep their own `Endpoint` lines). Import warns when
the effective value is an IP literal, because such profiles do not follow a DNS
switch. Import also warns when the restored client MTU or the server
`[Interface] MTU` exceeds the new host's outer MTU budget (uplink route/NIC MTU,
capped at 1500) with the archived S4; values are not rewritten automatically. Import
is **not** subject to fresh-install MTU admission: a deployed MTU/S4 pair is
restored as is (with the warning), while normal fresh installs still refuse it.

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

`--inspect-state` emits the manifest as JSON with a `peer_plan` object and a
`panel_plan` and a `proxy_plan` object (proxy listen/backend, AWG port match,
install paths; panel DB present, env/hash present — never the hash
itself —, archive vs. panel-source migration versions, mail jobs that would be
cancelled). `--dry-run` also prints the panel plan and how the panel would be
installed.
`--dry-run` prints a JSON plan before the host-install plan. Both show the
export timestamp, the destination evaluation time, per-peer **migrate/drop**
decisions (name, expiry, reason), and migrate/drop counts. Import, unchanged-
receipt reruns and activation log the same policy decisions. Inspection and
planning do not authorize traffic; activation always checks the clock again.

Archives older than **7 days** produce a warning, not a rejection. Export time
more than **5 minutes** in the future relative to the destination clock fails
closed (smaller skew is tolerated for NTP drift): synchronize/check both hosts'
clocks before retrying. Missing, malformed or non-UTC export times
are rejected before extraction; timestamp-less archives from the earlier,
unreleased prototype must be **re-exported**, not assigned an invented time.
Peer expiry timestamps accept timezone-aware RFC3339 and are displayed in UTC.
Fractional seconds (1–9 digits) are normalized to microseconds, so Python 3.9/3.10
and 3.11+ make the same decision.
No deadline is extended by the age of the archive or time spent quarantined.

## What is carried

The encrypted payload is a gzip tar containing only regular files:

- `manifest.json`: schema version 1, or 2 only when the archive carries
  `proxy/install.json` (both are importable; schema 1 may not carry it), protocol, backend, interface, installer
  SHA-256, AWG tools version, per-file SHA-256 inventory, and mandatory
  `exported_at` (UTC ISO 8601, `YYYY-MM-DDTHH:MM:SSZ`, at snapshot packaging). The panel version is
  currently recorded as `not-probed`, not guessed. `installer_sha256` is
  `unknown` when the installer does not run from a regular file (for example
  `bash <(curl ...)`), rather than a hash of consumed pipe input.
- `vpn/params` and `vpn/server.conf`: exact source bytes, including server keys,
  PSKs, obfuscation and protocol fields. Imported params are parsed as literals
  against an allowlist, **never sourced**. Only validated values are serialized
  into new local params.
- `clients/*.conf`: discovered installer-managed profiles, byte for byte.
  Discovery reuses `collectAwgClientConfigCandidates`: managed clients directory,
  panel config directory, `/root`, `/home/*`, and managed users' resolved homes.
  The first copy found (managed clients directory first) is exported; a later
  conflicting copy with the same basename (for example an edited copy in a
  user's home) is skipped with a warning naming it, instead of aborting export
  or replacing the root-owned copy. Custom client shell hooks fail export. Copies are restored
  into the managed clients directory, not arbitrary archived home paths.
- `web/database.sqlite`: if the panel is installed, a consistent online
  `sqlite3 .backup` of the effective database location: `--database-url` takes
  precedence over `AWG_WEB_DB`; absent settings use `awg-web.db`. Relative paths
  use the service working directory. The staged copy is converted to
  `journal_mode=DELETE` right after `.backup` (a WAL-mode panel DB would
  otherwise yield a WAL copy), export refuses if any `-wal`/`-shm`/`-journal`
  sidecar exists in staging, and every reader of a staged or unpacked DB opens
  it with `mode=ro&immutable=1`, so no sidecar is ever created or packed (also
  for older archives whose DB still has a WAL header).
  Unsupported SQLite URL/query formats fail export rather than silently omit
  the DB. Per-peer `expires_at` values remain in this snapshot; no remaining
  lifetime is reset on the destination. `web/env.conf` is copied from the existing env-file resolver.
- `proxy/proxy.toml` and `proxy/install.json`: the amneziawg-proxy config and
  its install paths (`config_path`, `data_dir`, `install_dir`), read from the
  real proxy unit's `ExecStart=<install-dir>/amneziawg-proxy <config>` and
  `WorkingDirectory=` (defaults when no unit exists); an unparsable `ExecStart`
  fails export instead of guessing.

Before the passphrase prompt, export validates the staged panel snapshot against
the schema import requires (`peers` table with `public_key`, `disabled`,
`archived`, `removal_pending`, `expires_at`) and parses the server config, so an
unimportable archive is refused at export time. The lifecycle locks are held
only while the private staging snapshot is taken and released before `age`
prompts, so panel and CLI operations are not blocked by a waiting prompt; the
staged copy is the consistent snapshot that gets encrypted.

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

The proxy installer defaults to `/etc/amneziawg-proxy/proxy.toml` and supports
custom `--config-file`/`--data-dir`/`--install-dir`; export discovers them from
the unit. `/var/lib/amneziawg-proxy/sessions.json` is runtime state and is excluded.

The panel DB/env are installed to their live locations only by the panel
restore step below, and the proxy config only by the proxy restore step. Import
never writes plaintext keys, panel DB/env or proxy data to the journal. TLS keys, binaries, service units, firewall
dumps, sessions and arbitrary directory contents are excluded.

### Panel restore

Design (from `amneziawg-web/scripts/amneziawg-web-install.sh` and
`amneziawg-web/src`):

- The panel installer builds `amneziawg-web` from the repository checkout with
  `cargo` (or takes `--binary-src`), installs it to `/usr/local/bin`, creates
  the `awg-web` system user, a 0700 `awg-web` data directory (`--data-dir`,
  default `/var/lib/amneziawg-web`), a root-only 0700 `/etc/amneziawg-web` with
  a 0600 `env.conf`, the privileged helper
  `/usr/local/libexec/amneziawg-web-privileged` with its sudoers entry, a copy of
  `amneziawg-install.sh`, and the `amneziawg-web.service` unit
  (`WorkingDirectory=<data dir>`, `EnvironmentFile=<env file>`,
  `ProtectSystem=strict` with `ReadWritePaths=` for the client config dir and
  data dir). `--non-interactive` needs `--password-hash`; an existing env file
  is kept unless `--force`. No TLS/reverse proxy is configured by it.
- The panel runs its embedded sqlx migrations at startup (`db.migrate()` in
  `src/main.rs`) before serving, and refuses a DB that has applied migrations
  it does not know. `GET /api/health` is public. Expiry enforcement is the
  panel's periodic `cleanup_expired_users` (`src/admin/mod.rs`).

Flow: after `--activate-state <archive> --enable-at-boot` has finalized the VPN
(and released the VPN lifecycle lock), or on a later rerun of
`--activate-state` on the finalized journal, if the archive has
`web/database.sqlite`:

1. Refuse if `amneziawg-web/scripts/amneziawg-web-install.sh` is not next to
   `amneziawg-install.sh` (run from a repository checkout), or if a panel env
   file or unit already exists and this migration did not start the install
   (an existing panel is never overwritten).
2. Prepare in private RAM staging: parse the archived `env.conf` as data (never
   sourced); require an Argon2 `AUTH_PASSWORD_HASH`; rebind `AWG_CONFIG_DIR` to
   the restored `${AMNEZIAWG_DIR}/clients` and keep an absolute `AWG_WEB_DB`
   (otherwise `/var/lib/amneziawg-web/awg-web.db`). Refuse when the archived
   `_sqlx_migrations` maximum is newer than the checkout's
   `amneziawg-web/migrations`. Copy the DB with SQLite backup, set
   `journal_mode=DELETE`, run `integrity_check`, and cancel queued mail jobs
   (`state='cancelled'`, `invalidation_code='state_migration'`) and mark
   in-flight `sending` jobs `unknown`, so no mail from the old host is replayed.
3. Install the env (root 0600), run the panel installer with
   `--non-interactive --username --password-hash-file --data-dir --env-file
   --config-dir --no-start --no-enable` (plus `--binary-src` when
   `AWG_STATE_PANEL_BINARY` is set; otherwise it builds from source and needs
   `cargo`), then install the DB as `awg-web` 0600 (stale `-wal/-shm/-journal`
   removed), start `amneziawg-web`, wait up to 30 s for `/api/health` on
   `AWG_WEB_LISTEN` (+`AWG_WEB_BASE_PATH`), and only then enable it at boot.
4. Journal: `panel-installing` while in progress, `panel-restored` when done,
   and audit steps in `steps`. On failure the panel is stopped (never enabled),
   the VPN keeps running finalized, the command exits non-zero with the cause,
   and rerunning `--activate-state <archive> --enable-at-boot` retries only the
   panel; a completed restore is a no-op.

`AWG_STATE_PANEL_BINARY=/path/to/amneziawg-web` is the only new input (an
environment variable, like `SERVER_PUB_IP`). The Argon2 hash reaches the panel
installer through `--password-hash-file` (a 0600 file in the RAM-backed work
directory), never on its command line; `--password-hash HASH` remains for
compatibility. `AWG_WEB_LISTEN` is restored verbatim: if it binds a specific
old-host address (not loopback, a wildcard, or an address on the archived
`[Interface] Address` line, which exists once the VPN is up), the panel cannot
bind on the new host and the restore fails its health check; dry-run and
`--inspect-state` warn about this, so change it on the old host before export
or edit the restored env.conf and rerun. Saved
SMTP settings travel inside the DB. Remaining TODO: merging multiple env files
or systemd `Environment=` directives, and restoring without the repository
checkout (the only checkout-less path, `amneziawg-web.sh`/`amneziawg-proxy.sh`,
clones the `main` branch at run time, which may not match the archive or this
installer, so it is not used automatically).

### amneziawg-proxy restore

`amneziawg-proxy` is the repository's **UDP obfuscation proxy** in front of
AWG (AWG 1.0/2.0 only), not an HTTP reverse proxy. Its installer
(`amneziawg-proxy/scripts/amneziawg-proxy-install.sh`) builds or takes
`--binary-src`, writes a 0600 root `proxy.toml`, rebinds AWG to the backend
port only if it is not already there, installs `amneziawg-proxy.service`
(`ExecStart=<install-dir>/amneziawg-proxy <config>`,
`WorkingDirectory=<data-dir>`), and keeps an existing config without `--force`.
The proxy has no certificate or key files (`quic_certificate_domain` is only an
SNI name).

**Topology.** With the proxy installer's defaults, the proxy listens on the
AWG port it detected (`SERVER_PORT` in params, the clients' Endpoint port) and
moves AWG's `ListenPort` to the backend port (51821); params are never edited.
The archive verifier therefore accepts either a direct setup (`ListenPort ==
SERVER_PORT`) or this proxy topology (archive has `proxy/proxy.toml`,
`ListenPort` == proxy backend port and `SERVER_PORT` == proxy listen port);
anything else fails export/verify with an explicit port error. That check
reads only `listen` and `backend` (double or single quotes). A `proxy.toml`
outside the installer's flat subset — integer underscores, an unknown key the
proxy would ignore — does not block VPN export, verify, prepare or reconcile.
`--inspect-state` and import `--dry-run` still show the VPN plan and warn
`amneziawg-proxy: <reason>; proxy restore would be refused`. The proxy restore
step still requires that subset and exits non-zero, naming the key it refused.
On import the server config keeps the backend `ListenPort`, the regenerated
firewall hooks open only `SERVER_PORT` (the proxy's public port, as on the old host; the
backend port is not opened, and the proxy installer adds no firewall rules),
and preflight checks that both UDP ports are free. Clients reach such a VPN
only once the proxy runs: if the proxy step is refused or fails (or the
archive is restored without its proxy), the VPN is up on the backend port but
unreachable on `SERVER_PORT` until the proxy is restored. Dry-run,
`--inspect-state` and the import plan warn about this.

**Install paths.** `proxy/install.json` paths and the panel's `AWG_WEB_DB`
directory are archive-controlled, and the installers chown/chmod those
directories. Restore accepts only the defaults, or a path that does not exist
yet below `/var/lib/`, `/srv/`, `/opt/` (data), `/etc/`, `/srv/`, `/opt/`
(proxy config directory) or `/opt/`, `/usr/local/` (proxy binary directory),
with no `..` components and no symlink anywhere on the path. A rerun accepts
an existing non-default directory only when the journal recorded that exact
path after an earlier check saw it absent (the installer may have created it
before failing). A directory that already existed stays refused, including
after `panel-installing` or `proxy-installing` is left behind.

After the panel step (independently of its outcome), when the archive has
`proxy/proxy.toml`:

1. Refuse if `amneziawg-proxy/scripts/amneziawg-proxy-install.sh` is not in
   this checkout, if a proxy config/unit exists that this migration did not
   install, if the config is not the flat `key = value` subset the installer
   writes, or if the archived server `ListenPort` is not the proxy backend port
   (the installer would then rewrite the finalized VPN config).
2. Run the proxy installer with `--non-interactive --listen-host --listen-port
   --backend-host --backend-port --protocol [--session-ttl --rate-limit
   --probe-reply-bytes --dns-forward --dns-upstream --quic-handshake
   --quic-domain] --config-file --data-dir --install-dir --awg-dir --no-start
   --no-enable` (values from the archived config and install paths; plus
   `--binary-src` when `AWG_STATE_PROXY_BINARY` is set).
3. Install the archived `proxy.toml` verbatim (root 0600) except `awg_config`,
   which points to the restored server config; start the service; require it
   to stay active and listen on its UDP port; then enable it at boot.
4. Journal `proxy-installing` / `proxy-restored` and steps
   (`proxy-restore-started`, `proxy-install`, `proxy-config-installed`,
   `proxy-restored` / `proxy-restore-failed`). A failure stops the proxy, never
   enables it, leaves the VPN and panel untouched, exits non-zero, and a rerun
   of `--activate-state <archive> --enable-at-boot` retries only the unfinished
   companion steps.

Companion lock: the panel and proxy steps run after the VPN lifecycle lock is
released (the panel installer and the panel take it themselves). Before that
release, activation takes a separate non-blocking flock on the journal
directory itself. Purge and reset take the same lock, so deleting a leftover
`companions.lock` file cannot drop it. A concurrent `--activate-state` rerun,
`--purge-state-journal` or `--reset-state-journal` for the same archive
refuses with a clear error.

Panel access to proxy status: the panel only reads
`AWG_PROXY_SESSIONS_FILE` (default `/var/lib/amneziawg-proxy/sessions.json`)
through its group; its unit has `ProtectSystem=strict` and
`ReadOnlyPaths=-/var/lib/amneziawg-proxy`, and there is no ACL or sudoers rule
for it. Both installers set the same state: the web installer makes an
existing `/var/lib/amneziawg-proxy` `root:awg-web 2750`, and the proxy installer
makes its data dir `root:awg-web 2750` when the `awg-web` group exists
(otherwise `root:root 0750`). The proxy unit's `UMask=0027` plus the setgid
directory give `sessions.json` mode 0640, group `awg-web`. Because the proxy
step runs after the panel step and always runs the proxy installer (also on a
retry), the result is the same as a normal install where the proxy was installed
first. If the panel step failed, the proxy dir stays `root:root 0750` until
the panel retry, which applies the web installer's own step. A custom proxy
`--data-dir` is not read by the panel in any install order (the panel's
default path and unit are fixed).

Clients that connect through the proxy reach the VPN only once it runs, so
keep the old server serving until the proxy step succeeds.

### HTTPS for the panel

This repository does not set up HTTPS: the panel installer binds plain HTTP
(default `127.0.0.1:8080`) and `amneziawg-web/docs/DEPLOYMENT.md` only gives
nginx/Caddy examples. There is no repo-managed reverse proxy, certificate,
ACME account or renewal timer whose paths could be discovered from real
configuration, so nothing HTTPS-related is archived or restored. Operators
re-create their reverse proxy on the new host; with Let's Encrypt HTTP-01
(certbot/Caddy defaults), switch DNS to the new host **before** issuing or
renewing there. `AUTH_SECURE_COOKIE` and `AWG_WEB_BASE_PATH` travel in the
restored env.conf.

## Import safety and activation

1. Decrypt into private temporary staging. Verify schema, complete file
   inventory, checksums, params/config agreement, member names/types and size
   limits **before extraction**. Absolute paths, dot segments, duplicate
   members, symlinks, hardlinks, devices, directories and PAX overrides fail.
   JSON duplicate keys fail too. The gzip stream is read to EOF, so a missing or corrupt
   trailer (CRC/length) or trailing garbage fails closed even when tar parsing ends early. Checksums detect inconsistent payloads; they
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
   **Ongoing expiry enforcement after activation is done by the restored panel**
   (see "Panel restore"): its periodic cleanup removes a peer when `expires_at`
   passes. If the archive has no panel, or panel restore failed/was refused,
   nothing removes a migrated peer at its deadline: use the `expires_at` values
   printed by `--inspect-state`/`--dry-run` to remove those clients on time
   (for example `--remove-client NAME`), or fix the cause and rerun
   `--activate-state <archive> --enable-at-boot`, which then retries only the
   panel restore. Policy is only as recent as the snapshot: later bans or
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
   Ongoing expiry enforcement is done by the restored panel (or the operator).
   Without the flag, activation is temporary testing only and leaves boot
   disabled. Stop/disable the test VPN, then repeat activation with
   `--enable-at-boot` to finalize. An enable/marker-publication failure attempts
   to stop/disable the unit and leaves the migration unfinalized. A power loss
   between enabling and recording the marker needs operator inspection.

The journal is `/var/lib/amneziawg-install/state-imports/<manifest-digest>/`.
Each import attempt takes a fresh `before/` image (a missing file is recorded as
absent) and swaps it in atomically, so a retry never restores a stale backup.
The `steps` file is an audit log only: after the VPN starts, a failed append
warns instead of aborting; real post-start failures (enable, finalized marker)
stop and disable the unit and leave the migration unfinalized.
INT/TERM/HUP during activation (from `systemctl start` until finalization, or
until a test activation completes) likewise stops and disables the unit and
leaves the import quarantined; rerun `--activate-state` to retry. Rollback
cleanup runs without errexit or re-entrant signals, attempts every step even if
logging fails, and reports an incomplete rollback explicitly. An INCOMPLETE
rollback also leaves a `rollback-incomplete` marker in the journal; while it
exists every attempt for that archive is refused — fresh import (before a new
before-image is taken, so the real image is kept), rerun/reconcile,
`--activate-state` and `--dry-run`. If the marker itself cannot be written, an
explicit warning says later attempts are NOT blocked automatically. Inspect/restore manually, then `--purge-state-journal <digest> --force`. Config and receipt
change together: if the receipt cannot be published, the previous config is
restored so a retry verifies and continues. If replacing the config itself
fails, the target is compared with the reconciled config and the previous
config is restored if the replacement had already landed; an interrupt and an
I/O failure get distinct messages. INT/TERM/HUP are deferred
while the config and its receipt are published, then honoured (before any
service start). Install and validation run in a nested subshell, so helper trap
scopes (such as the APT IPv4 override, which now also chains EXIT/HUP to the
previous handler) can never replace the import's rollback handler. In a
subshell that has not set traps yet, bash still *displays* the parent's
handlers; the APT helper drops that inherited display before saving, so it
never re-installs (and runs) a parent's EXIT/INT/TERM/HUP handler there.
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

### Journal contents and purge

The journal holds **no plaintext keys, panel DB/env or proxy data**: the
encrypted archive is the recovery copy. It keeps `before/` (previous
sysctl/module-load/modprobe files for rollback), `receipt` (SHA-256 hashes),
`nic`, `steps`, `panel-*`/`proxy-*` progress markers, a `rollback-incomplete` marker after a failed rollback and,
after finalization, the non-secret `finalized` marker.
Journals created by earlier prototype revisions may still contain a plaintext
`recovery/` directory; purge removes it. Finalizing prints the exact manifest
digest to use for optional cleanup:

```sh
# Replace MANIFEST_SHA256 with the 64-character digest from the journal path:
bash amneziawg-install.sh --purge-state-journal MANIFEST_SHA256
# Only to abandon an unfinalized/failed import and its rollback/activation path:
bash amneziawg-install.sh --purge-state-journal MANIFEST_SHA256 --force
```

No archive/passphrase or age/sqlite dependency is needed for purge. It refuses
unfinalized journals without `--force` (and `--reset-state-journal` on an
unfinalized journal points to `--purge-state-journal <digest> --force`), validates the digest and trusted journal
path, takes the lifecycle lock and the journal-directory companion lock (refusing
while a panel/proxy restore of that archive runs), and rejects unexpected
top-level entries. It
removes recovery/rollback files and receipts without following symlinks or
crossing filesystem boundaries. A finalized journal retains **only the non-secret
`finalized` interface-name tombstone**, so old archives cannot resurrect policy
after purge. Repeated purge is safe.

Finalization also records a **server-identity tombstone** in
`/var/lib/amneziawg-install/state-imports/identities/`, keyed by SHA-256 of the
VPN interface name and server public key, holding the archive's `exported_at`
and manifest digest. A later import of a *different* archive of the same server
whose `exported_at` is **not newer** fails with the exact
`--reset-state-journal <digest> --confirm-policy-replay` command to use; a newer
archive imports normally. It survives purge and uninstall; reset of that digest
removes it. Forced purge of an unfinalized journal
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

The panel's privileged helper runs the installer inside the panel service's
`ProtectSystem=strict` view, where `/var/lib` is read-only. Panel install and
upgrade therefore create this directory as root (outside the sandbox). On a host
whose panel has not been upgraded yet, when the directory is missing and cannot
be created in a read-only view **while a panel is configured**, the installer
warns and serializes on the panel database-directory lock alone; every root
caller also takes that lock while a panel exists, so mutual exclusion still
holds. Without a panel, failure to create the directory fails closed.

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

Uninstall **retains** migration journals, finalized and server-identity tombstones and prints a
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
when that location is tmpfs/ramfs; if neither is usable the command refuses
(there is no disk-backed `/tmp` fallback). Insufficient RAM/staging space aborts
rather than silently spilling an in-progress snapshot to disk. Import/inspect
still decrypt a bounded tarball inside their private staging directory.

Temporary plaintext files are mode 0600 and removed on ordinary exit. The
embedded Python verifier runs with `python3 -I`, so modules in the current
directory or `PYTHON*` variables cannot inject code into the root process. tmpfs may
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
Round-7 additions cover: a planted `tarfile.py` in the working directory not
being imported, the read-only lifecycle-directory fallback to the panel lock,
lock release before the prompt and early schema refusal at export, skipped
conflicting client copies, `installer_sha256` under `bash <(…)`, the
server-identity tombstone, the reset hint, the MTU warning, fractional-second
expiries and clock-skew tolerance, the `SERVER_PUB_IP` override/IP-literal
warning, and that journals hold no plaintext keys or panel DB. Round-12
additions use the real `sqlite3` CLI (skipped if absent; CI installs it) to
export a live WAL-mode panel DB and import a WAL-header DB without sidecars,
and cover the config-replace failure window, `host:port` rejection, inherited
subshell traps, refusal without RAM staging and the incomplete-rollback block.
The suite passes under Python 3.9, 3.10 and 3.13.
With `age` installed it additionally
uses a real controlling TTY for passphrase roundtrip and wrong-passphrase tests.
CI installs age and runs this suite.

Still required: full two-container/VM install roundtrip with distinct uplinks,
real client datapath/handshake, DNS failover across representative clients,
BoringTun/kernel install drills, a live panel restore (build, start, expiry
enforcement) and a live proxy restore — the panel/proxy tests here mock the installers/systemd —,
concurrent panel export stress, and power-loss recovery testing. The mock
roundtrip must not be described as those live tests.
