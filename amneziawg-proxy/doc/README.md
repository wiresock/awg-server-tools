# amneziawg-proxy — Documentation

> [!IMPORTANT]
> **Compatibility: AmneziaWG 1.0 and 2.0**
> `amneziawg-proxy` is compatible **only with AmneziaWG 1.0 and 2.0**. It is **not compatible with AmneziaWG 3.0+** because AWG 3.0 incorporates the S1–S4 padding values into header protection key derivation (`HeaderProtectionKey`). Rewriting padding in flight breaks header decryption, and encrypted headers prevent packet classification.

AWG 1.0 configurations may omit both S3 and S4. The proxy treats them as zero:
handshake padding can be imitated, while cookie and transport packets pass
through unchanged. A partially specified S3/S4 pair is rejected.

| Document | Description |
|----------|-------------|
| [USAGE.md](USAGE.md) | Installation, configuration reference, running, logging, uninstallation, and troubleshooting. |
| [MANUAL_DEPLOYMENT.md](MANUAL_DEPLOYMENT.md) | Manual deployment scenarios, including Docker-hosted AWG, custom systemd units, firewall rules, and web-panel status integration. |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Internal design: module map, packet flows, protocol imitation details, session management, rate limiting, and worked packet-level examples. |
