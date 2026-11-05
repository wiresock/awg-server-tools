# Requirements

Supported Linux distributions (from the installer's `checkOS`):

| Distribution | Minimum version | Fresh install |
|---|---|---|
| Debian / Raspbian | 11 (Bullseye) | ✅ |
| Ubuntu | 22.04 (CI-tested on 22.04, 24.04, 26.04) | ✅ |
| Linux Mint | 21 | ✅ |
| Fedora | 39 | ❌ temporarily disabled |
| AlmaLinux / Rocky Linux | 9 | ❌ temporarily disabled |
| CentOS | 9 | ❌ untested, not recommended |

Fresh installs on Fedora, AlmaLinux and Rocky Linux are **temporarily
disabled** because verified AmneziaWG 2.0 packages are not currently available
for these RPM-based distributions; existing installs there can still run
non-install operations. CentOS 9 is accepted by the installer's OS check and
uses the same AmneziaWG COPR as other RPM-family hosts, but it is **not** a
tested install target and is not recommended (CI does not exercise CentOS).

The BoringTun backend requires a supported Debian/Ubuntu VM or bare-metal host
with systemd, TUN and IPv6 socket support, on x86_64, aarch64 or ARMv7
hard-float.

See also [Ubuntu 26.04 PPA compatibility](../installer/ubuntu-26.04-ppa.md).
