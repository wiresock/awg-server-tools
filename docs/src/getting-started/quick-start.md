# Quick start

**VPN only (required):**

```bash
curl -fLO https://raw.githubusercontent.com/wiresock/awg-server-tools/main/amneziawg-install.sh
chmod +x amneziawg-install.sh
```

Choose **one** backend for a fresh installation:

**Kernel backend (default):**

```bash
sudo ./amneziawg-install.sh
```

**BoringTun userspace backend (experimental):**

```bash
sudo AWG_BACKEND=boringtun AWG_BORINGTUN_IMITATE_PROTOCOL=none ./amneziawg-install.sh
```

BoringTun uses a downloaded, verified prebuilt binary instead of a kernel
module. It requires a supported Debian/Ubuntu VM or bare-metal host with
systemd, TUN and IPv6 socket support, on x86_64, aarch64 or ARMv7 hard-float. This selects
BoringTun only on a fresh install; it does not migrate an existing kernel
installation. See [BoringTun requirements and lifecycle](../boringtun/README.md).

**Add the web panel (optional):**

```bash
curl -fLO https://raw.githubusercontent.com/wiresock/awg-server-tools/main/amneziawg-web.sh
chmod +x amneziawg-web.sh
sudo ./amneziawg-web.sh install
```

> **Note:** The web panel installer requires `git` to bootstrap the repository when run
> standalone. If `git` is not available, clone the repository manually or use `--binary-src`
> with a pre-built binary.

The panel is built from Rust source, including on BoringTun hosts. Install its
build prerequisites and use `--install-rust` if needed; BoringTun itself is
prebuilt. See [VPN + web panel](../web-panel/install.md).

BoringTun users can enable **Off / DNS / QUIC / SIP / STUN** directly under
**Protocol imitation · BoringTun** in the panel. No standalone proxy is needed.
**Auto** (per client, opt-in) is offered when the installed BoringTun binary
supports it; see
[native imitation and compatibility limits](../boringtun/imitation.md).

**Add the obfuscation proxy (optional, kernel backend with AWG 1.0 or 2.0):**

```bash
curl -fLO https://raw.githubusercontent.com/wiresock/awg-server-tools/main/amneziawg-proxy.sh
chmod +x amneziawg-proxy.sh
sudo ./amneziawg-proxy.sh
```

> Makes the VPN traffic look like QUIC/DNS/STUN/SIP to DPI. Compatible with
> **AmneziaWG 1.0 and 2.0** (not compatible with AWG 3.0+). See
> **[Traffic obfuscation proxy](../proxy/README.md)**.

✅ **After installation:**
- VPN server is running
- AWG 2.0 remains active by default; [AWG 3.1](../installer/awg3.md) requires an explicit migration after backend capability checks pass (do not enable AWG 3.x if using `amneziawg-proxy`)
- A client config file is generated at `~/awg0-client-<name>.conf`
- (If installed) Web panel listens on `127.0.0.1:8080` by default. From your computer, run `ssh -N -L 8080:127.0.0.1:8080 user@server`, then open `http://localhost:8080` and sign in.

---

> **TODO (future):** once signed releases with a `SHA256SUMS` file are
> published, prefer a pinned release URL and `sha256sum -c` over downloading
> from `main`. That path does **not** exist yet.
