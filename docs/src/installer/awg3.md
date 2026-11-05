# AWG 3.0 / 3.1 mode

> [!WARNING]
> **Incompatible with amneziawg-proxy:**
> Do **not** enable AWG 3.0 or AWG 3.1 if you are using `amneziawg-proxy`. Because AmneziaWG 3.0+ incorporates the S1–S4 padding values as key material for header protection, the proxy's padding transformations corrupt header decryption and break packet classification.
>
> If you require `amneziawg-proxy`, keep your interface in AWG 2.0 mode (the default). If an interface was already migrated to AWG 3.0 or 3.1, revert it to AWG 2.0 using `sudo ./amneziawg-install.sh --disable-awg3` (or via the web panel under **AWG protocol**) before setting up or running the proxy.

Fresh installs and parameter files created by earlier releases use AWG 2.0 by
default. Installing or upgrading this project never changes an existing
interface's protocol mode. Existing AWG 3.0 installations stay on 3.0 until
you explicitly enable AWG 3.1.

```bash
# Missing protocol state is reported as 2
sudo ./amneziawg-install.sh --protocol-status

# Legacy AWG 3.0: probe the selected backend, then migrate the server and clients
sudo ./amneziawg-install.sh --enable-awg3

# Enable AWG 3.1 (AWG 3.0 plus RandomTrailers; DisableCookies stays off)
sudo ./amneziawg-install.sh --enable-awg31

# Atomically remove AWG 3.x-only fields and return every config to AWG 2.0
sudo ./amneziawg-install.sh --disable-awg3
```

AWG 3.0 header protection is interface-wide and cannot communicate with AWG
2.0 clients on the same interface. AWG 3.1 is AWG 3.0 plus `RandomTrailers`
(must match on every peer) and optional `DisableCookies` (server-sent Cookie
Reply / anti-DoS; default `off`). Enabling a mode creates or keeps one shared
header key, validates all generated configs, and updates the server plus every
recoverable client config as one transaction. If capability validation, file
replacement, service restart, or the process itself fails, the previous state
is restored. Redistribute every client config after a migration. The web panel
offers confirmed switches to AWG 2.0 and 3.1 under **AWG protocol**. Legacy
AWG 3.0 remains available through the CLI, but cannot be selected in the panel.

When `RandomTrailers` is on, upstream recommends identical `S1`–`S4` values to
reduce packet-type misdetection. The installer warns if they differ and does
not rewrite existing S-values.

**What this installer implements**

| Mode | Fields |
| --- | --- |
| AWG 2.0 | `Jc`, `Jmin`, `Jmax`, `S1`–`S4`, `H1`–`H4` |
| AWG 3.0 | AWG 2.0 plus `HeaderProtectionKey`, optional `ContentPaddingAddition`, `RekeyAfterTime`, `RekeyTimeout`, `RejectAfterTime`, `KeepaliveTimeout` |
| AWG 3.1 | AWG 3.0 plus `RandomTrailers` and `DisableCookies` |

Clients and the server must run AWG 3.1-capable implementations (`amneziawg-tools`
plus the running kernel module, or an equivalent 3.1 userspace stack). The
installer does not trust package version strings; it probes by applying the
fields to a temporary interface and reading them back. `I1`–`I5` (CPS) are
intentionally not generated, persisted, or migrated. Upstream also defines
optional `MaxHandshakeAttempts`; this installer does not manage that field
(same as the existing AWG 3.0 mode). Externally added `I1`–`I5` or
`MaxHandshakeAttempts` lines are left in place during protocol rewrites.

---
