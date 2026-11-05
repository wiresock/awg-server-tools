# BoringTun userspace backend (experimental)

> [!WARNING]
> **Experimental.** The kernel module stays the default and the recommended
> backend. BoringTun is chosen only by an explicit `AWG_BACKEND=boringtun` on a
> **fresh** install, and existing installations are never moved to it.

Instead of the AmneziaWG kernel module (built with DKMS), a server can run
[WireSock BoringTun](https://github.com/Wiresock-Foundation/wiresock-boringtun),
a userspace AmneziaWG implementation that serves the interface through a TUN
device. The VPN backend uses a prebuilt binary: no Rust toolchain, DKMS or
kernel headers are needed for BoringTun itself. The optional web panel has its
own Rust build prerequisites.

```bash
# Fresh install with the BoringTun backend
sudo AWG_BACKEND=boringtun AUTO_INSTALL=y ./amneziawg-install.sh

# Interactive install with the BoringTun backend
sudo AWG_BACKEND=boringtun ./amneziawg-install.sh
```

**Where it runs:** Debian 11+ and Ubuntu 22.04+ hosts (virtual machines or bare
metal) with systemd, on x86_64, aarch64 or ARMv7-A with VFPv3-D16 hard-float,
with `/dev/net/tun` and the IPv6 socket family available. ARMv7 requires an
`armhf` userspace; a 64-bit kernel with 32-bit armhf userspace selects that
ARMv7 binary. Original Pi 1 and Pi Zero ARMv6 CPUs are unsupported. ARMv7 release
validation uses emulation and interop tests, not physical Pi hardware; this does
not establish ARM32 support for the optional web/proxy stack. Containers and LXC
are not supported. Other architectures are refused before anything is changed.

**What it installs:**

- `amneziawg-tools` from the Amnezia PPA with `--no-install-recommends`, so the
  kernel module package (`amneziawg-dkms`) is not pulled in, plus `nftables`,
  `iptables` and `qrencode`. No `amneziawg`, DKMS, headers or `deb-src` sources.
- `boringtun-cli` from the fork's immutable public release
  [`boringtun-cli-0.7.1-ga92909c49920-b101`](https://github.com/Wiresock-Foundation/wiresock-boringtun/releases/tag/boringtun-cli-0.7.1-ga92909c49920-b101),
  built from WireSock BoringTun `a92909c49920e12de11fb0e066192b8f39b5b212`. The
  installer downloads the archive for its architecture from that exact URL and
  checks it against SHA-256 values embedded in the script before extracting
  anything; then it checks the archive's layout, its `MANIFEST`, the binary's
  SHA-256 and `boringtun-cli --version`. No "latest" lookup and no GitHub API.
  The release notes and [adoption evidence](../../BORINGTUN_ADOPTION_2026-10-27.md)
  describe the verified provenance and exact hashes.
- The binary into `/usr/local/lib/amneziawg-install/boringtun/`, and two
  generated helpers into `/usr/local/libexec/amneziawg-install/` that supervise
  the daemon inside the usual `awg-quick@<interface>` service.

Before any VPN configuration is written, a preflight starts a temporary
BoringTun instance with the chosen AWG 2.0 parameters and removes it again. If
the download, a check or the preflight fails, nothing is configured. If the
service does not start, the installer stops with BoringTun diagnostics; it
never falls back to the kernel module.

**Managing it:** everything else works as usual: clients, `--enable-awg3`,
`--enable-awg31`, `--disable-awg3` and uninstall. Use `systemctl` or this
script to start and stop the interface: a plain `awg-quick up awg0` does not
start BoringTun. A newer installer version never replaces an installed
BoringTun binary on its own: only `--upgrade-boringtun` does (see below). Exporting
`AWG_BACKEND` has no effect on an existing installation, whichever backend it
uses.

**Kernel module on the host:** if the AmneziaWG kernel module is loaded, the
install refuses and never unloads it. If the module is only installed (for
example `amneziawg-dkms` from an earlier kernel install), `awg-quick` would load
it instead of starting BoringTun, so the install asks before blocking it with
`/etc/modprobe.d/amneziawg-install-boringtun.conf`
(`install amneziawg /bin/false`); with `AUTO_INSTALL`, set
`AWG_BORINGTUN_BLOCK_KERNEL_MODULE=y` to agree. Uninstalling removes that file.
Kernel module packages that the BoringTun install did not install are never
removed, and neither is `/etc/modules-load.d/amneziawg.conf`.

**Uninstall:** it removes only what it can prove is this installation's: a
UAPI socket that a process may still serve, or a helper script changed after
the install, is left in place and reported. If a step fails, or the service's
teardown did not finish (for example PostDown hooks that may have run only in
part), the configuration in `/etc/amnezia/amneziawg` is kept, so running the
installer again offers the uninstall again once the cause is fixed.

**Not with the standalone proxy:** BoringTun cannot run behind
`amneziawg-proxy`, because it always listens on every address. The install
refuses while the proxy (or its `proxy.toml`) is present, and the proxy
installer refuses a BoringTun host. Keep the kernel backend for proxy setups.

**Web panel:** a BoringTun host needs a web panel whose copy of this script
(`/usr/local/bin/amneziawg-install.sh`) is at least this version; the install
refuses while an older copy is installed. Install or upgrade the panel and its
privileged helper together from the same checkout. The header reports the
configured protocol and verified running BoringTun release, without a proxy
status entry. The panel manages clients, AWG 2.0/3.1 transitions and native
imitation. Authentication and the default localhost binding apply to these
controls as well.
