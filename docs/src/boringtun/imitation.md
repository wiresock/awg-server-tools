# Built-in protocol imitation (BoringTun only)

A BoringTun server can shape the S1–S4 prefixes of the packets it sends as
`dns`, `quic`, `sip` or `stun`, and answer probes of that service on its listen
port, or, with `auto`, choose one of those for each client. This uses
BoringTun's own imitation; it needs no proxy. The default is `none`, and the
kernel backend has no imitation at all.

```bash
# Choose it on a fresh BoringTun install (an interactive install asks)
sudo AWG_BACKEND=boringtun AWG_BORINGTUN_IMITATE_PROTOCOL=dns \
  AWG_BORINGTUN_IMITATE_DOMAIN=example.com AUTO_INSTALL=y ./amneziawg-install.sh

# Change it later: none, dns, quic, sip, stun or auto, and a hostname for dns, quic or sip
sudo ./amneziawg-install.sh --set-boringtun-imitation quic cdn.example.org
sudo ./amneziawg-install.sh --set-boringtun-imitation auto
sudo ./amneziawg-install.sh --set-boringtun-imitation none

# Show the backend, the imitation and the running daemon (key=value, no secrets)
sudo ./amneziawg-install.sh --backend-status
```

The management menu of a BoringTun host shows the imitation and offers
**7) Change BoringTun protocol imitation**. The hostname is optional: without
one, BoringTun chooses its own. It must be a plain host name of letters,
digits, hyphens and dots.

The web panel exposes the same transaction under **Protocol imitation ·
BoringTun**. Choose **Off**, **DNS**, **QUIC**, **SIP**, **STUN** or **Auto**,
optionally enter a hostname for DNS/QUIC/SIP, and confirm the brief VPN restart.
Saved and verified running settings are shown separately. Changing imitation
preserves the AWG version and client configurations.

**`auto` (opt-in).** BoringTun picks `dns`, `quic`, `sip` or `stun` separately
for each authenticated peer, from the imitation datagrams that peer's client
sends before its handshake, so clients with different imitation settings can
share one server and port. What to know:

- It is **best effort** and needs **recognizable client traffic**. A client
  that sends no DNS, QUIC, SIP or STUN pre-handshake datagrams (a standard
  AmneziaWG client, for example), or whose datagrams are lost, leaves its peer
  unresolved. Even a datagram that arrives may not count: one that also fits
  this server's AmneziaWG S/H framing, as a client's own imitation datagrams
  can depending on the S1–S4 and H1–H4 values, is tried as AmneziaWG traffic
  first. The release this installer pins
  (`boringtun-cli-0.7.1-ga92909c49920-b101`) still learns from it, but only when
  every such reading is refused for a reason that establishes nothing (a failed
  mac1, an unknown peer, index or session, no matching handshake, a failed
  decryption); after any other outcome it never counts as a hint, and the
  earlier release `boringtun-cli-0.7.1-gb94943906b11-b1` never does. Such a
  datagram is never answered as a probe. A peer for which nothing was learned is
  padded with random S padding, as with `none`; it may still be learned at a
  later handshake. A learned protocol is kept for the peer and survives roaming.
- A working tunnel, and `auto` configured and running, do not show that any
  peer is imitated. The status shows `auto` as configured and running, and
  nothing per peer: BoringTun does not report which protocol a peer learned.
- It does **not detect S1–S4, H1–H4** or any other AmneziaWG setting; clients
  still need this server's values. It takes no hostname (BoringTun uses its own
  generated ones), and the installer and panel refuse one.
- Probes: the listen port may answer DNS, QUIC and STUN probes as those
  imitations do; SIP gets no reply.
- **Header protection is not relaxed.** Under AWG 3.0/3.1 a learned `dns` or
  `stun` has the nonce trade-offs below, and a learned `sip` is not activated
  while any of S1–S4 is 31 bytes or more: that peer stays unresolved with random
  padding. Nothing is disabled and the S/H framing is never changed
  automatically, so `auto`, unlike `sip`, is accepted at any S size.
- It needs a BoringTun release that has it: the one this installer pins
  (`boringtun-cli-0.7.1-ga92909c49920-b101`) or the earlier
  `boringtun-cli-0.7.1-ge94c04f3f4fd-b1` and
  `boringtun-cli-0.7.1-gb94943906b11-b1`. Releases predating those report
  the same version but refuse `auto`; the installer asks the installed binary,
  and refuses `auto` before changing anything, pointing to
  `--upgrade-boringtun`. `--backend-status` reports this as
  `imitation_auto_support`.

A change is one transaction under the same lock as client changes. The new
settings are validated on a temporary BoringTun instance. The running service
is then restarted and checked: the verified daemon, its TUN link, its UAPI, the
same listen port, and the new imitation on its command line. If anything
fails, the previous files are restored exactly and the service is restarted
with the previous imitation. A stopped or failed service is only updated, not
started. Imitation is a server setting: **client configs do not change**, and it
is kept when you switch between AWG 2.0, 3.0 and 3.1.

What to expect:

- **Server side only.** Standard AmneziaWG clients keep sending plain
  AmneziaWG. Only the server's packets are shaped, unless the client imitates
  too (for example WireSock Secure Connect).
- **Probe replies.** DNS queries get `SERVFAIL`. STUN Binding Requests get a
  Binding Success about 2.6× their size, so the reply can be reflected at a
  spoofed source. QUIC Initials of 1200 bytes or more get Version Negotiation,
  but only when they offer a version real servers don't (QUIC v1 and v2 get no
  reply). SIP gets no reply. All replies share a 16 KiB/s budget, and loopback,
  link-local, multicast and broadcast sources are never answered.
- **The port stays the same.** The installer never moves it, because a new port
  needs new client configs. Imitation looks most plausible on the protocol's
  usual port.
- **AWG 3.0 / 3.1.** Header protection takes its nonce from the first 12 bytes
  of each S prefix, and imitation shapes those bytes:
  - `dns` leaves 16 random bits, so header masks repeat within a few hundred
    datagrams.
  - `stun` leaves 32 random bits.
  - `quic` keeps a random nonce.

  Payload encryption is unaffected. BoringTun refuses `sip` with header
  protection while any of S1–S4 is 31 bytes or more, and so does the installer,
  both when you choose `sip` and when you enable AWG 3.x under `sip`. Enabling an
  imitation under AWG 3.x from the menu asks for confirmation.
- **S sizes.** A short S prefix is only partly shaped. The thresholds are:
  - `dns`: 32 bytes, or the hostname's length + 33 for a query that names it;
  - `stun`: 20 bytes;
  - `sip`: 31 bytes;
  - `quic`: 1 byte.

  The installer warns about shorter prefixes but never changes S sizes.

---
