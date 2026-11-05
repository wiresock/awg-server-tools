# Install the web panel

> ⚠️ Requires VPN to be installed first (`amneziawg-install.sh`).

Use the **[Quick Start](../getting-started/quick-start.md)** commands above, or clone the repository (best for teams or repeated upgrades):

```bash
git clone https://github.com/wiresock/awg-server-tools.git
cd awg-server-tools
sudo ./amneziawg-install.sh
sudo ./amneziawg-web.sh install
```

The installer automatically downloads required files and builds the panel.
Add `--install-rust` if Rust is not already installed on the server.

For a **fresh BoringTun host**, replace the two installation commands above
with this sequence after cloning:

```bash
sudo AWG_BACKEND=boringtun AWG_BORINGTUN_IMITATE_PROTOCOL=none ./amneziawg-install.sh

# Panel build prerequisites on supported Debian/Ubuntu hosts
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev
sudo ./amneziawg-web.sh install --install-rust
```

Keep the default localhost binding and access the panel through an SSH tunnel.
The header separates the configured AWG version from the running backend and
panel version. The panel offers AWG **2.0** and **3.1**; a legacy 3.0 installation
is still recognized and can switch to either. On BoringTun hosts, the imitation
section shows configured and verified running settings separately and uses the
installer's compatibility checks and rollback when applying changes.

## Full installer reference

The complete web-panel install guide:

{{#include ../../../amneziawg-web/docs/INSTALL.md}}
