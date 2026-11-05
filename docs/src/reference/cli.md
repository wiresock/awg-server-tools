# CLI reference

Flags and commands documented in this repository's README and component docs.
This is not an exhaustive dump of every internal option.

## `amneziawg-install.sh`

```bash
sudo ./amneziawg-install.sh                  # interactive install / client menu
sudo AUTO_INSTALL=y ./amneziawg-install.sh   # non-interactive install

sudo ./amneziawg-install.sh --add-client <name>
sudo ./amneziawg-install.sh --remove-client <name>
sudo ./amneziawg-install.sh --list-clients

sudo ./amneziawg-install.sh --protocol-status
sudo ./amneziawg-install.sh --enable-awg3
sudo ./amneziawg-install.sh --enable-awg31
sudo ./amneziawg-install.sh --disable-awg3

sudo ./amneziawg-install.sh --backend-status
sudo ./amneziawg-install.sh --set-boringtun-imitation <none|dns|quic|sip|stun|auto> [hostname]
sudo ./amneziawg-install.sh --upgrade-boringtun
sudo ./amneziawg-install.sh --rollback-boringtun
```

See [non-interactive install](../installer/non-interactive.md) for environment
variables (`SERVER_PORT`, `ENABLE_IPV6`, `AWG_BACKEND`, …).

## `amneziawg-web.sh`

```bash
./amneziawg-web.sh status
sudo ./amneziawg-web.sh install
sudo ./amneziawg-web.sh upgrade
sudo ./amneziawg-web.sh uninstall --force
sudo ./amneziawg-web.sh uninstall --purge-config --purge-data --force
```

## `amneziawg-proxy.sh`

```bash
sudo ./amneziawg-proxy.sh    # install, or management menu when already installed
```

From a repository checkout:

```bash
sudo ./amneziawg-proxy/scripts/amneziawg-proxy-uninstall.sh --force
```
