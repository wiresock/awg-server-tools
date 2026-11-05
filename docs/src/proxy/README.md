# Traffic obfuscation proxy (`amneziawg-proxy`)

> ⚠️ Requires VPN to be installed first (`amneziawg-install.sh`).

> [!IMPORTANT]
> **Compatibility: AmneziaWG 1.0 and 2.0 (incompatible with AWG 3.0+)**
>
> `amneziawg-proxy` is compatible **only with AmneziaWG 1.0 and 2.0** and cannot be used when AWG 3.0 mode is enabled.
>
> In AmneziaWG 2.0, the S1–S4 padding prefix consists of arbitrary random bytes that the proxy safely replaces with cover-protocol filler bytes (QUIC, DNS, STUN, or SIP headers) while preserving the encrypted payload. Starting with AmneziaWG 3.0, the S1–S4 padding values are used as key material for header encryption (`HeaderProtectionKey`). Modifying or rewriting them in flight breaks header decryption on the peer, and the encrypted headers prevent the proxy from classifying packets.
>
> If you plan to use `amneziawg-proxy`, keep your interface in AWG 2.0 mode (the default). Do not enable AWG 3.0 on a proxied interface.

`amneziawg-proxy` is an async UDP proxy (written in Rust) that sits **in front of**
your AmneziaWG server and disguises the traffic so that, to Deep Packet
Inspection (DPI), the port appears to host an ordinary **QUIC, DNS, STUN, or
SIP** service. AmneziaWG's own obfuscation already hides the WireGuard
fingerprint; the proxy adds a second layer that makes the packets *positively
resemble* a known, allowed protocol instead of merely looking random.

> **💡 Best paired with WireSock Secure Connect 3.5+.** The proxy obfuscates
> the **server → client** direction on its own. Bidirectional imitation — where
> the **client → server** direction is camouflaged too — requires
> [WireSock Secure Connect](https://www.wiresock.net/) **3.5 or later**, which
> implements the matching client-side protocol imitation and junk-packet shaping.

### Install

The proxy installer detects the AWG interface, moves it to a separate backend
port, builds the binary, and installs a systemd service. It does **not** install
firewall rules or guarantee that the backend is loopback-only. Restrict access
to the backend port before running the installer; see the
[firewall checklist](manual-deployment.md#firewall-checklist).

```bash
curl -fLO https://raw.githubusercontent.com/wiresock/awg-server-tools/main/amneziawg-proxy.sh
chmod +x amneziawg-proxy.sh
sudo ./amneziawg-proxy.sh
```

Run with no arguments and it walks you through guided prompts. Run it again
later and it shows a management menu (status, logs, reconfigure, uninstall).

**Non-interactive examples.** `amneziawg-proxy.sh` forwards any flags to the
installer (cloning the helper scripts on the fly when run standalone), so the
one downloaded file is all you need:

```bash
# QUIC imitation (safest default) — public :51820 → loopback :51821
sudo ./amneziawg-proxy.sh \
  --non-interactive --listen-port 51820 --protocol quic

# DNS imitation that also answers real DNS queries (run on port 53)
sudo ./amneziawg-proxy.sh \
  --non-interactive --listen-port 53 --protocol dns \
  --dns-forward --dns-upstream 1.1.1.1:53

# STUN imitation (port 3478, WebRTC/NAT-permissive networks)
sudo ./amneziawg-proxy.sh \
  --non-interactive --listen-port 3478 --protocol stun
```

Full option reference, configuration keys, and troubleshooting live in
[amneziawg-proxy/doc/USAGE.md](usage.md). Internal design
and packet-level walkthroughs are in
[amneziawg-proxy/doc/ARCHITECTURE.md](architecture.md).

### How It Works

With client endpoints pointed at the proxy and the backend port protected by
firewall rules, VPN traffic follows this same-host path. The loopback address
below is the proxy's destination, not an exclusive AWG bind address:

```
                         ┌───────────────────────────────────┐
 VPN client ──── UDP ───►│  0.0.0.0:51820   amneziawg-proxy  │
 (DPI sees QUIC/DNS/     │            │                      │
  STUN/SIP)              │            ▼                      │
                         │  127.0.0.1:51821  awg0 (AmneziaWG)│
                         └───────────────────────────────────┘
```

The proxy does two complementary things:

1. **Probe response.** When a scanner or DPI box sends a protocol probe
   (a QUIC Initial, a DNS query, a STUN Binding Request, a SIP request), the
   proxy replies with a *valid* protocol response — a QUIC Version Negotiation,
   a DNS answer, a STUN Binding Success, a SIP `100 Trying`. The port therefore
   behaves exactly like the service it is pretending to be when actively
   probed.
2. **Padding transformation.** Every outgoing AmneziaWG 2.0 packet already carries a
   random S1–S4 padding prefix. The proxy overwrites that prefix with
   protocol-conformant bytes (a QUIC short header, a DNS/STUN header, SIP header
   text) so the *leading bytes and byte-distribution* of each datagram match the
   imitated protocol — while the encrypted WireGuard payload that follows is
   left untouched. (Note: this relies on AmneziaWG 2.0 protocol semantics where
   headers are plaintext and S1–S4 padding is unkeyed; in AWG 3.0+, S1–S4 padding
   serves as key material for header encryption, so rewriting it breaks compatibility).

| Mode | What DPI sees | Typical port | Good for |
|------|---------------|--------------|----------|
| `quic` | QUIC 1-RTT / Version Negotiation | 443 | QUIC/HTTP-3-heavy networks (safest default) |
| `dns`  | DNS query/response (optionally real) | 53 | DNS-filtered networks |
| `stun` | STUN Binding traffic | 3478 | WebRTC / NAT-traversal-permissive networks |
| `sip`  | SIP signaling | 5060 | VoIP-permissive networks |
| `auto` | Whatever the client probes for | — | Mixed-probe environments |

### Traffic Examples

**STUN mode — an outgoing server packet on the wire.** The padding prefix is
rewritten as a well-formed STUN message; a packet-capture tool dissects it as
STUN and leaves the encrypted AmneziaWG payload as trailing bytes:

```
01 01 00 1c 21 12 a4 42  4f 7a 1c …   ← STUN: Binding Success Response, msg length 0x1c, cookie 0x2112A442
00 20 00 08 00 01 …                    ← XOR-MAPPED-ADDRESS attribute (12 B)
80 22 00 0c …                          ← SOFTWARE attribute (16 B; fills the prefix) → 12 + 16 = 0x1c
… encrypted AmneziaWG payload …        ← opaque ciphertext (trails the message, not parsed)
```

**QUIC mode — a probe and its response.** A DPI box sends a QUIC Initial; the
proxy answers with a valid Version Negotiation packet, swapping the connection
IDs per RFC 9000:

```
→  c3 00000001 04 aabbccdd 00            QUIC Initial probe (DCID=AABBCCDD)
←  c3 00000000 00 04 aabbccdd 00000001   Version Negotiation (SCID echoes the DCID)
```

**DNS mode — a query answered for real.** With `--dns-forward`, a DNS probe is
forwarded to the upstream resolver and the genuine answer is returned, so the
port doubles as a working resolver while still tunneling VPN traffic.

To inspect it yourself, capture on the server's public port and open the capture
in Wireshark — frames decode cleanly as the imitated protocol, with no
"malformed" or WireGuard markers:

```bash
sudo tcpdump -i any -w awg-proxy.pcap udp port 51820
```

### Manage / Uninstall

Re-running `amneziawg-proxy.sh` on an installed host opens a management menu
(status, logs, reconfigure, uninstall) — the simplest path, and it works from
the single downloaded file:

```bash
sudo ./amneziawg-proxy.sh
```

From a repository checkout you can also drive the uninstaller non-interactively
(keeps config/data by default; add `--restore-awg` to rebind AWG to the public
port):

```bash
sudo ./amneziawg-proxy/scripts/amneziawg-proxy-uninstall.sh --force
```

---

## Deeper documentation

- [Usage](usage.md)
- [Manual deployment](manual-deployment.md)
- [Architecture](architecture.md)
- [Performance](performance.md)
