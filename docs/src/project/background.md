# Background

This project started from the [RomikB/amneziawg-install](https://github.com/RomikB/amneziawg-install) installer (see [Credits](#credits) for its full lineage). I needed a reliable way to stand up **AmneziaWG 2.0** servers for testing [WireSock Secure Connect](https://www.wiresock.net/), and the upstream script predated the 2.0 release — so I took it and extended it to generate and manage the new 2.0 obfuscation parameters (S3/S4 padding and the H1–H4 header ranges). It now also supports an explicit, capability-checked migration to **AmneziaWG 3.1**, while retaining AWG 2.0 defaults and preserving the mode of existing installations.

Once the installer was solid, it was hard to stop:

1. **`amneziawg-install.sh`** — the original script, extended for AmneziaWG 2.0 (S3/S4, H1–H4, migration from pre-2.0 installs), optional AmneziaWG 3.0 header protection, and optional AmneziaWG 3.1 (`RandomTrailers` / `DisableCookies`).
2. **`amneziawg-web.sh`** — a web panel for managing clients, switching between AWG 2.0 and 3.1, and configuring BoringTun's native protocol imitation without touching the CLI.
3. **`amneziawg-proxy.sh`** — a UDP obfuscation proxy that takes traffic camouflage to the next level: it wraps AmneziaWG (AWG 1.0 or 2.0) so the datagrams on the wire look like a legitimate QUIC, DNS, STUN, or SIP service to Deep Packet Inspection (DPI).

> **⚠️ amneziawg-proxy is compatible only with AmneziaWG 1.0 and 2.0 and is most powerful with WireSock Secure Connect 3.5+.**
> The proxy is compatible **only with AmneziaWG 1.0 and 2.0** (it is **not compatible with AWG 3.0+** because AWG 3.0 uses S1–S4 padding as key material for header encryption). The proxy's full protocol-imitation feature set — coordinated client/server cover traffic, junk-packet shaping, and per-protocol padding — is only fully unleashed when paired with [WireSock Secure Connect](https://www.wiresock.net/) **3.5 or later** on the client side. Standard AmneziaWG clients still connect through the proxy and benefit from the server-side obfuscation, but the bidirectional imitation requires the WireSock client.

---
