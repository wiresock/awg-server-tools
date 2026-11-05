# Non-interactive install

Skip all prompts and use sensible defaults:

```bash
sudo AUTO_INSTALL=y ./amneziawg-install.sh
```

Override specific defaults with environment variables:

| Variable | Default |
|----------|---------|
| `SERVER_PUB_IP` | Auto-detected |
| `SERVER_PUB_NIC` | Auto-detected |
| `SERVER_AWG_NIC` | `awg0`, or the first free `awgN` when `awg0` is in use |
| `SERVER_AWG_IPV4` | `10.66.66.1` |
| `SERVER_AWG_IPV6` | `fd42:42:42::1` |
| `ENABLE_IPV6` | `y` if the host has IPv6, otherwise `n` |
| `SERVER_PORT` | Random (49152–65535) |
| `CLIENT_DNS_1` | `1.1.1.1` |
| `CLIENT_DNS_2` | `1.0.0.1` |
| `CLIENT_MTU` | Generic final inner MTU: `min(1500, uplink MTU) - 80 - S4`; budgets below `1280` are refused. Empty omits MTU; see client compatibility below. |
| `ALLOWED_IPS` | `0.0.0.0/0, ::/0` (IPv4 only when `ENABLE_IPV6=n`) |
| `CREATE_INITIAL_CLIENT` | `yes` in `AUTO_INSTALL`; prompted interactively |

Set `ENABLE_IPV6=n` for an IPv4-only deployment: the server interface, firewall
rules, and all generated client configs omit IPv6 (no IPv6 address, no `::/0`
route), which avoids route-setup errors on hosts where IPv6 is disabled.

The installer manages one AmneziaWG interface per host and never takes over
one that already exists, such as the upstream tunnel of a two-hop server. An
interface name is in use when `/etc/amnezia/amneziawg/<name>.conf` or a network
link of that name exists. An explicit `SERVER_AWG_NIC` that is in use stops the
installation before anything is installed; without one, the installer picks
the first free `awgN` and says so. Later, every management action (adding,
removing or regenerating clients, protocol changes, the web panel) refuses to
change the config named by `SERVER_AWG_NIC` in params unless its
`[Interface] PrivateKey` is the installation's `SERVER_PRIV_KEY`. Uninstalling
removes only the installation's own files from `/etc/amnezia/amneziawg`
(params, the server config, client configs and their backups); other configs
there stay, and so does the directory then.

Example:

```bash
sudo AUTO_INSTALL=y SERVER_PORT=51820 CLIENT_DNS_1=8.8.8.8 ./amneziawg-install.sh

# IPv4-only server
sudo AUTO_INSTALL=y ENABLE_IPV6=n ./amneziawg-install.sh

# Persist an explicit MTU for new clients from the CLI and web panel
sudo AUTO_INSTALL=y CLIENT_MTU=1380 ./amneziawg-install.sh
```

AmneziaWG prepends `S4` junk bytes to every transport packet (`S1`–`S3` pad
the small handshake and cookie packets), and the automatic MTU of `awg-quick`,
the uplink MTU minus 80, does not allow for them: full-size transport packets
then exceed the path MTU and fragment. A new installation therefore writes
`MTU = min(1500, <uplink MTU>) - 80 - S4` into the server
`[Interface]`, using the smallest explicit MTU on the IPv4 and IPv6 default
routes through `SERVER_PUB_NIC`. If those routes do not specify a usable MTU,
it reads the NIC MTU from sysfs, falling back to 1500 when unavailable.
It refuses a result below 1280 before writing installation state: rounding
up does not create space on the path. It persists the same final inner value
as the default `CLIENT_MTU`. A known smaller uplink reduces both defaults;
a jumbo uplink does not establish a jumbo Internet path. The interactive
installer asks for the client MTU after `S4`, pre-filled with that value.
Omitting MTU remains supported for clients that account for S4 automatically,
including the inspected WireSock implementation. Linux `awg-quick` does not:
under a 1500-byte assumption its automatic 1420 value leaves room for only
20 bytes of S4 with outer IPv4, or zero with outer IPv6. The installer and
panel warn about this client-specific risk without rejecting omission for
padding-aware clients. An unknown endpoint or hostname receives the IPv6 warning.
Automatic MTU is derived on the client: reducing the server's local budget
does not communicate that limit to the client. Even a padding-aware client
may choose too large a value for a smaller server or remote path.

`CLIENT_MTU` syntax accepts decimal integers from **1280 to 65535**, without leading
zeros, so existing configurations remain readable. New profiles also require
`CLIENT_MTU + S4 + 80` to fit the assumed outer budget. Set it through the environment for an
automatic installation or at the prompt; an explicit `CLIENT_MTU=''` omits the
`MTU` line and leaves the client MTU automatic. Lower it when the path to the
clients carries less than 1500 bytes. The server interface MTU is written
once, at installation. Re-runs and upgrades never change it or an existing
`CLIENT_MTU`; when the pre-2.0 migration assigns a new `S4`, the installer
prints the recommended MTU instead of applying it.

For an existing installation, choose a final inner value that fits S4 and the
path budget, for example `CLIENT_MTU='1300'` with S4=120 and a 1500-byte budget,
in the root-owned
`/etc/amnezia/amneziawg/params` file. The CLI and web panel use that value for
subsequently generated clients, including explicit CLI regeneration. Existing
client files stay unchanged until regenerated. Remove the setting or use
`CLIENT_MTU=''` to omit the MTU line again. Old params files without this key
retain their current behavior, even if `CLIENT_MTU` is exported in the environment.
Web generation requires the updated web binary and privileged helper.

New profiles are refused when `1420 - S4 < 1280`, for IPv4,
IPv6, hostname and unknown endpoints alike, even if an explicit MTU was supplied. This prevents the observed
`S4=148` / effective MTU `1272` failure where WireSock rejected 1280-byte IP
packets. S4 has a hard maximum of 140; normal generation stops at 128 for headroom.
Known smaller budgets and caller-supplied final-inner MTUs further limit fresh
draws before random selection. The 1420 value here is already
an inner baseline after an 80-byte framing allowance; it is not a measured
outer PMTU. If the **outer** budget is 1420, the corresponding conservative
inner budget is `1420 − 80 − S4`, not `1420 − S4`.

Existing values and downloaded profiles remain unchanged. The CLI and peer
page warn about an unsafe budget and client-specific compatibility; listing, removal, startup and
upgrades continue. Creating or regenerating profiles that exceed the core budget is refused before
keys or client files are written. Coordinate the server, every generated
profile and copies already installed on devices before migrating settings.
Protocol changes and recovery retain existing S4/MTU settings; completing
those operations does not certify their packet-size budget.
Do not change H4 to adjust packet size: it is a fixed-size identifier, while
S4 is transport padding.

Generic/Linux `CLIENT_MTU` is a **final inner value**. The inspected older
WireSock source treats explicit `MTU` as a **pre-S4 baseline**: with
`MTU=1420` and `S4=128`, its effective inner MTU is 1292 before any smaller
transport-capacity clamp. Exporting 1292 directly to that client deducts S4
again, leaving 1164. The CLI and panel warn when this would leave less than
1280. Do not inflate generic profiles to 1420: Linux uses that number unchanged.
A change to WireSock's explicit-MTU semantics is proposed separately; this
update neither implements nor depends on an unreleased client fix. Verify
the installed client version and coordinate migration before importing an
explicit generic profile. No client-specific export format is introduced.
Fresh installation uses the known local uplink ceiling. Later CLI/web client
creation checks the nominal 1500-byte budget and stored client MTU; it does not
detect a subsequent reduction of the uplink or remote path MTU.
Remote PMTU is unmeasured. `RandomTrailers` uses a learned packet-size window:
an MTU edit alone does not shrink that window, and old or oversized peer
traffic can invalidate a nominal budget. Coordinate fresh tunnel state on
both ends and validate the actual path. No existing configuration is silently
rewritten by these diagnostics.

---
