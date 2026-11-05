# Choose your setup

| Goal | What to run |
|------|-------------|
| VPN server only | `amneziawg-install.sh` |
| VPN + web panel | `amneziawg-install.sh` then `amneziawg-web.sh install` |
| Userspace VPN without a kernel module | Fresh install with `sudo AWG_BACKEND=boringtun ./amneziawg-install.sh` |
| Userspace VPN + native imitation and web panel | Fresh BoringTun install, then `amneziawg-web.sh install`; configure imitation in the panel |
| VPN + DPI-resistant obfuscation | `amneziawg-install.sh` then `amneziawg-proxy.sh` *(AWG 1.0 or 2.0)* |
| Kernel VPN + panel + standalone proxy | `amneziawg-install.sh`, then `amneziawg-web.sh install`, then `amneziawg-proxy.sh` *(AWG 1.0 or 2.0)* |
| Advanced / development | Clone the repo, then run the scripts from the checkout |

---

## Minimal setup — VPN only (recommended)

> Most users should start here.

1. Update your system and reboot before installing.
2. Run the commands from **[Quick Start](quick-start.md)**.
3. Answer the prompts. The script installs AmneziaWG, configures the server, and generates a client config file.
4. **Run the script again at any time** to add or remove clients.

---

## Advanced setups

For the web panel, see [Web panel install](../web-panel/install.md).
For the obfuscation proxy, see [Proxy overview](../proxy/README.md).
For BoringTun, see [BoringTun backend](../boringtun/README.md).
