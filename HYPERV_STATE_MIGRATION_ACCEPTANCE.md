# Hyper-V live acceptance for PR #186

Date: 2026-11-09. Tester: local Hyper-V lab on this Windows host. No commits were pushed, the PR was not merged, and GitHub issues were not updated.

Product tree tested: `D:\projects\awg-state-export-import`, branch `feat/state-export-import`, commit `c2e773bf6843656b4a530a079b6c7c38dd1fcf05`. `git status` on that tree was clean at the end of the run. No product source was modified. The disposable guest copy of `amneziawg-install.sh` on Server B was patched only for the power-loss window, and only after that VM had been restored to `os-ready`. That patch is not in git. The `power-recovered` checkpoint still contains it.

Evidence directory: `D:\projects\awg-hyperv-lab\evidence`. Passphrases, private keys, preshared keys, and decrypted archives were not copied into this report. The Windows temp bundle used to move the encrypted archive was deleted when the power-loss script finished.

## Host and guests

| Item | Value |
|---|---|
| Host | Windows 11 Pro, build 10.0.26300 |
| Guests | Debian 12 bookworm, kernel `6.1.0-54-amd64` (6.1.190-1) |
| Hyper-V | Generation 2, Secure Boot off. Disks under `D:\projects\awg-hyperv-lab\vms` |
| Switch | Internal `awg-accept-lab`. Host vNIC `vEthernet (awg-accept-lab)` `172.31.250.1/24`, metric 400. No WinNAT |
| Outbound | DNS VM is dual-homed: lab `172.31.250.10` plus Default Switch DHCP, with iptables MASQUERADE. Lab VMs default-route via `.10` |
| DNS | dnsmasq on the DNS VM, `cache-size=0`, TTL 30, query log on. Name `vpn.awg-test.example`. Guests use only `172.31.250.10` |
| SSH | user `lab`, key `D:\projects\awg-hyperv-lab\keys\lab_ed25519` |
| Source on guests | `/opt/awg-src` from a git archive of `c2e773b` |

Default host route stayed `Ethernet` and `Wi-Fi` via `192.168.1.1` metric 0 for the whole run. Unrelated VMs and switches were not changed.

| VM | Role | vCPU | RAM | Lab address | Uplink name seen in the guest |
|---|---|---|---|---|---|
| `awg-accept-dns` | gateway and dnsmasq | 1 | 1 GB | `172.31.250.10` | `lab0` plus DHCP `wan0` |
| `awg-accept-a` | Server A | 2 | 4 GB | `172.31.250.11` | `wan0` |
| `awg-accept-b` | Server B | 2 | 4 GB | `172.31.250.12` | `migup0` |
| `awg-accept-c` | Linux client | 1 | 2 GB | `172.31.250.21` | `client0` |

`wan0` and `migup0` were read from `ip route` and `ip -br addr` inside the guests. They are not assumed names.

Checkpoints kept: `os-ready` on all four VMs; matrix `k20-fenced` / `k20-activated`, `bt20-fenced` / `bt20-activated`, `bt31-fenced` / `bt31-activated`, `k31-fenced` / `k31-activated`; `panel-fenced` / `panel-activated`; `proxy-fenced`, `proxy-before-reboot`, `proxy-rebooted`; `dns-fenced` (A), `dns-before-cut` (DNS VM), `dns-cutover` (B); `power-cut` and `power-recovered` (B).

Current power state: A is off (fenced). DNS, B, and C are running. B is on the `power-recovered` runtime, VPN active on the internal switch only.

## Result matrix

| Requirement | Result |
|---|---|
| Kernel, AWG 2.0, independent VM handshake, data, reboot | PASS |
| BoringTun, AWG 2.0, same | PASS |
| BoringTun, AWG 3.1, same | PASS |
| Kernel, AWG 3.1, same | PASS. The installed Debian module accepted `--enable-awg31` |
| Live `amneziawg-web` migration, expiry poller, mail not replayed | PASS |
| Panel export through the running systemd unit, sudoers, and sandbox | PASS. A mid-download interrupt was not a meaningful test |
| `ProtectHome=yes` excludes `/root` and `/home` | PASS |
| Proxy migration, kernel AWG 2.0, handshake and data through the proxy | PASS |
| Proxy with BoringTun or AWG 3.x | NOT RUN. The proxy does not support those combinations |
| `--audit-endpoints` / `--set-endpoint-host` dry-run, apply, idempotent | PASS |
| DNS cutover with a real resolver, Linux `awg-quick` client | PASS. Reconnect required an explicit tunnel restart |
| Second client implementation (official Amnezia or a real WireSock datapath) | BLOCKED on this host. See below |
| Abrupt Hyper-V power-off during quarantine, before the receipt | PASS for fail-closed behavior and a manual recovery. Not automatic recovery |
| Two real VPSs, public-IP cutover, mobile clients | NOT RUN. This lab does not provide them |

No confirmed product defect. Failures during the run were lab setup: client ARP after fencing, `/tmp` helpers disappearing on reboot, `python3-argon2-cffi` versus Debian `python3-argon2`, `AWG_STATE_PROXY_BINARY` pointed at the install destination, a shell redirect that did not run as root, `dnsmasq` SIGHUP not rereading `address=`, and WireSock's host configuration.

## Migration matrix

Each scenario installed Server A from this checkout, created client `linux1`, proved a handshake and ICMP from client C, exported with the installer, inspected and dry-ran, imported onto a fresh Server B, checked quarantine (`inactive`, `disabled`, no `awg0`), compared hashed material, fenced A, activated with `--enable-at-boot`, repeated the handshake and data transfer, rebooted B, and reconnected the same profile. Keys were not regenerated. The namespace harness in `tests/test-state-migration-live.sh` was not used as acceptance.

IP-literal profiles do not follow B's address. Those four scenarios added `172.31.250.11/24` on B's `migup0` only after A was fenced. That secondary address does not persist across reboot; the reboot check added it again. This is address takeover, not DNS. The DNS scenario did not do it.

BoringTun replies were sourced from `.12` even when the client sent to `.11`. Kernel replies were sourced from `.11`. BoringTun transfer counters often stayed at 336/336; ICMP and tcpdump were the datapath proof. The Linux client used the kernel `amneziawg` device for AWG 3.1 because `ip link add type amneziawg` succeeded. That is a real kernel datapath, not a BoringTun client and not Amnezia or WireSock.

Reconnect after fence or reboot was never spontaneous. Every success used `awg-quick down` and `up` on the unchanged profile. Client ARP for `.11` had to be flushed when it still pointed at the fenced VM.

| Scenario | Archive sha256 | Size | Profile sha256 | Data proof |
|---|---|---|---|---|
| BoringTun 2.0 | `d8b7a8a82dd986cc7c8ccfe4c9bb1d4ede246da0e820aa9c81c8608556862cc1` | 2055 | `fa3123b04fc4d89e5f401b86950e3f26506ce7db062e1c6cb5220515fbdf6c60` | ping 3/3 after activate and after reboot. boringtun-cli `0.7.1-ga92909c49920-b101` |
| BoringTun 3.1 | `6a251b94336030246db426158913976c9a5e71e9a82b9dc8e345977e841d42fa` | 2229 | `4085025b8079f27181588bdfdb420e3f5fd699096854a06f329616a1ed51f02b` | ping 3/3. Protocol 3.1, RandomTrailers on |
| Kernel 3.1 | `c2a1eb440cf3b887143460fa276c56e307c754f53ba13bdca4454f0c4f3b97c2` | 2202 | `091146b5a3a048171cab8d3a2809dee3a8bae030b2dbb001b0ac927bfee6b52e` | post-activate and post-reboot ping 3/3. Baseline ping was 1 of 3 with matching handshakes; treated as a first-packet race |
| Kernel 2.0 | recorded in the matrix run; reboot note is `evidence\k20-reboot.txt` | | | post-reboot ping 3/3, rtt 0.709/1.233/1.638 ms, both handshake timestamps `1794219565`, tcpdump `.21 -> .11:51820` |

Material comparison allowed only `SERVER_PUB_NIC` `wan0` to `migup0` and the matching uplink mentions. Obfuscation parameters compared equal within each scenario and differed across fresh installs.

## Web panel

`amneziawg-web` v0.1.42, built from this checkout, listened on `127.0.0.1:8080`. Unit: `User=awg-web`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`. Admin authentication was Argon2id. Debian package is `python3-argon2`.

Peers through the admin API: a permanent active peer, a peer then disabled, an already-expired peer, and a peer whose stored deadline was `2026-11-09T10:52:18Z`. The public API's shortest non-zero expiry is one day, so the short deadline was written into the database the poller reads. A queued `email_jobs` row was inserted while the service was stopped.

Installer export sha256 `ee047491f7c3196a7a88f8969028817bca07db5f32ad0fc20349bac51daa16fb`, mode 600, 12199 bytes. Import dropped the disabled and already-expired peers (source-only key hashes only). `linux1` profile sha256 `361ef9a1b83358a4fc045c7e15590280a58dcc3c5a2252b7851d2c0cae5a47bd` was unchanged. After activate: panel active, `/api/health` returned `{"status":"ok"}`, database integrity ok, disabled flag still set, expired peer absent, soon-expiry timestamp unchanged, queued mail `cancelled` with `state_migration`. Handshake ping 3/3, both timestamps `1794221217`.

The 15-second poller removed the soon-expired peer at `2026-11-09T10:52:27Z` without a manual config edit. Peer count went from 3 to 2. The journal line also contains the peer public key and is omitted here.

HTTP export through the running unit, loopback only:

| Request | Result |
|---|---|
| No session | 401, `Cache-Control: no-store` |
| Wrong password | 403 |
| Wrong CSRF | 403 |
| Authenticated export | 200, 12243 bytes, `Cache-Control: no-store`, sha256 `4208afcd335b8942512ca1f287eba19d59224a212ec319b4629c74ca6269b79d` |

`--inspect-state` succeeded. Audit events were `state.exported` and `state.export_failed` (`unauthenticated`, `reauth_failed`, `csrf_rejected`). No `.awgx` or `.age` file and no passphrase file remained under `/tmp`, `/var/tmp`, or `/home`. The archive is about 12 KB, so killing an in-flight download did not create a useful interrupt window. A following unauthorized request was still rejected.

ProtectHome proof on the restored panel: in the service mount namespace, `/root` and `/home` are inaccessible. Profiles placed at `/root/awg0-client-roof.conf` and `/home/lab/awg0-client-homed.conf` were in a root installer export and absent from the panel export. Panel export sha256 `a54fb8d6022cd311e9c8ea3e48a193e75c70c714ad1e0af745309e039ea6cc3e`, 17319 bytes, `Cache-Control: no-store`.

## Proxy

Kernel AWG 2.0 only. Proxy listen `0.0.0.0:51820`, backend `127.0.0.1:51821`. Client Endpoint stayed `:51820`. `proxy.toml` sha256 `60bd6d335efbec1acc5bbf1e49d02fbbe4ee0802b38be93cf8ded91938a5fed4`, mode 600, 3290 bytes, same before and after restore. The kernel socket is `0.0.0.0:51821` and `[::]:51821` because the installer does not add `ListenAddr`. nft accepts UDP 51820 only. The same bind existed on A and on restored B. Loopback tcpdump showed the proxy forwarding to `127.0.0.1:51821`. No uplink packet used 51821.

Archive sha256 `50ea74a9dac5367d205aa51413f9ff909051fcfff87dcb19a704f3fbc0fa5931`, mode 600, 3450 bytes. Quarantine inactive/disabled, `COMPARE_OK`.

The first activate failed with `install: ... are the same file` because `AWG_STATE_PROXY_BINARY` was `/usr/local/bin/amneziawg-proxy`. That is the install destination. The VPN was already finalized and the proxy unit was absent, which matches the documented failed companion step. Retry with a copy at `/opt/awg-proxy-bin/amneziawg-proxy` finished the proxy step. Proxy active and enabled. Post-restore ping 3/3, both timestamps `1794222403`. Post-reboot ping 3/3, both timestamps `1794222438`. Replies were sourced from `.12:51820`. An explicit tunnel restart was required. `.11` did not persist across reboot.

## Endpoint rewrite and DNS

On the kernel 2.0 Server A used for this scenario:

| Step | Result |
|---|---|
| `--audit-endpoints` | 1 IP-literal client, `awg0-client-linux1` |
| `--set-endpoint-host vpn.awg-test.example --dry-run` | no file change |
| apply | only the Endpoint host, that file's hash, and `SERVER_PUB_IP` |
| second apply | no further change |

Profile sha256 before `a80d64c8e1818ee656117ad96df8910ae1ed9abf1ceb00ac11da42c003094cc8`. After `d271dc3da54cab981e48a57d3049bb76f5e120967beeeb64f36a757cdc1e74ff`. Endpoint became `vpn.awg-test.example:51820`. A second client, `wiresock`, was created with the installer after that rewrite so it was born on the hostname. Its profile sha256 is `cfb534e36856f08bcda9e420af6591f70e036df90ed8e6632158faa044e0fe83`.

Linux client against A, resolved through dnsmasq: `dig` and `resolvectl` both `172.31.250.11`, ping 3/3, rtt 0.454/0.784/1.009 ms, both handshake timestamps `1794222782`, tcpdump `.21 <-> .11:51820`.

Export of that server: sha256 `1056c2aea6c40870b5a1e1e5f566251a7d12e3ed2855a876ea64ea862181060f`, 2247 bytes. Inspect reported backend kernel, protocol 2, two hostname endpoints, zero IP literals. Import quarantine on B: inactive, disabled, no link, `COMPARE_OK`. Restored profile hashes matched the two hashes above.

A was turned off with `Stop-VM -TurnOff`. B was activated with `SERVER_PUB_NIC=migup0` and was not given `.11`. `migup0` stayed `172.31.250.12/24`. While DNS still returned `.11`, the Linux tunnel endpoint stayed `.11:51820` and ping failed.

`systemctl reload dnsmasq` sent SIGHUP. dnsmasq does not reread `address=` on SIGHUP. The file already said `.12` and the process still answered `.11`. `systemctl restart dnsmasq` made `@127.0.0.1` and `@172.31.250.10` return `.12`. `dns-cut.sh` in the lab now restarts the service. That was a harness bug.

After the real change, before any tunnel restart:

- Windows `Resolve-DnsName` via a temporary NRPT rule for `.awg-test.example` to `172.31.250.10`, cache cleared, returned `172.31.250.12`. The NRPT rule was removed afterward.
- Client C `dig @172.31.250.10` and `resolvectl` returned `.12`.
- The live `awg` endpoint stayed `172.31.250.11:51820`, handshake 0, ping failed.

After `awg-quick down`/`up` of the same profile: resolved `.12`, endpoint `.12:51820`, ping 3/3, rtt 0.390/1.183/1.632 ms, both handshake timestamps `1794224158`, tcpdump `.21 <-> .12:51820` with 128-byte and 253-byte replies. Checkpoint `dns-cutover`.

The Linux client does not re-resolve an existing tunnel by itself. A tunnel restart was required. Profiles that already contained the hostname were the ones that moved; no new profile was imported on the client.

### WireSock and the second client

WireSock Secure Connect 3.5.8.1 is installed. CLI: `C:\Program Files\WireSock Secure Connect\command-line\wiresock-connect-cli.exe`. Existing profiles `praha.wiresock.net`, `us-hotspot`, and `wiresock.sshvpn.me` were not edited or deleted. No Amnezia Windows client is installed. No new Windows VM was created.

A lab profile `wiresock-safe` was imported from the server profile with `AllowedIPs` reduced to `10.66.66.0/24` and `DNS` removed, so a successful tunnel would not replace the host default route or host DNS. It was deleted at the end. NRPT for `.awg-test.example` was removed.

With the user's existing service settings (`OverrideJunkPacketsSettings=True`, `Jc=0`, protocol masking `github.com` / `quic` / `chrome`), WireSock sent handshakes to `172.31.250.11:51820` and logged `Awaiting response`. The server answered. Those settings were restored after every probe. The service-config sha256 before each edit and after restore was `032934908988DA30140AD49BFD53AEA478426A9765F2F31F1778EEB72A06B0A4`. Current settings are again override true and `Id=github.com`. Status is `Not connected`.

Turning the junk override off made the client use the profile's `Jc=5` and the matching Amnezia header ranges. The server still replied with UDP length 128, which is a WireGuard handshake response plus `S2=36`. WireSock in transparent mode still did not accept it.

`-lac` (virtual adapter) logged `Handshake response received from 172.31.250.11:51820`, and the server handshake timestamp advanced. ICMP and SSH to `10.66.66.1` then succeeded, but tcpdump on Server A showed cleartext TCP from `172.31.250.1` to `10.66.66.1:22` on `wan0`. AWG transfer counters did not move during that SSH. The virtual adapter also installed a `0.0.0.0/0` route with metric 65535, which did not outrank Ethernet metric 0, and that route disappeared on disconnect. The cleartext path is not a tunnel datapath, so WireSock is not counted as a passing client.

Two-client acceptance is not met. One real Linux `awg-quick` client passed the DNS move. Official Amnezia and a genuine WireSock tunnel were not demonstrated.

## Power loss

The cut used `Stop-VM -Name awg-accept-b -TurnOff -Force` while the import was inside a 90-second sleep. The sleep was inserted only in the guest copy of the installer, immediately after the `restore-complete-quarantined` step and before the NIC file, the sha256 receipt, and `committed`. The environment variable was `AWG_STATE_ACCEPTANCE_HOLD`. Stock code has no such hook; the real window is a few syscalls, which cannot be hit reliably from the host. The crash itself was a Hyper-V power-off, not `systemctl reboot` or a guest shutdown.

The hold marker was observed, then the VM was turned off. Checkpoint `power-cut` is that powered-off disk. After boot, uptime was 21 seconds.

| Check | Observed |
|---|---|
| `awg-quick@awg0` | inactive, disabled |
| `awg0` link | absent |
| UDP 51820 | not listening |
| receipt, finalized, nic, rollback-incomplete, proxy-restored | absent |
| steps | `install-packages`, `validate-installed-protocol`, `restore-complete-quarantined` |
| secret hashes versus the source material | `SECRET_MATCH` (0 only-source, 0 only-target) |

`--activate-state` exited 1: `this archive has no completed local import`. A second `--import-state` exited 1: `target configuration directory is not empty`. No rollback marker appeared, because a power cut does not run the EXIT trap. The refusals are the safe outcome.

Recovery, only after `SECRET_MATCH` and a stopped VPN with no `rollback-incomplete`:

1. Remove `/etc/amnezia/amneziawg` and any instance unit drop-in for `awg-quick@awg0`. The packaged template unit was left in place.
2. `amneziawg-install.sh --purge-state-journal <manifest-sha256> --force`. Journal id `e72caf261d5bf423a2d9dbb2d4f60a165990777cb3d124ebd3c65221ede50b79`. The tool printed that the unfinalized journal was purged.
3. Import again. `COMPARE_OK`. Quarantine inactive/disabled.
4. `--activate-state --enable-at-boot`. Active and enabled. `migup0` remained `172.31.250.12/24`.
5. Same Linux profile, explicit tunnel restart. Ping 3/3, rtt 0.468/1.211/1.678 ms, both handshake timestamps `1794224384`, tcpdump `.21 <-> .12:51820`.

Checkpoint `power-recovered`. A fresh import re-evaluates peer policy against the current clock. This archive had no panel expiry rows. The crashed journal is not an automatic resume, and the test did not weaken the preflight or the rollback marker.

## Bugs and local code

No product defect was confirmed, and the feature branch has no local code change.

Lab-only notes:

- Proxy activate must be given a binary path that is not the install destination.
- `dnsmasq` needs a restart, not a reload, before an `address=` change is served.
- Panel password hashing on bookworm uses `python3-argon2`.
- Guest helpers must live outside `/tmp` if they are needed after reboot.
- After fencing, flush the client's ARP entry for the old address before the next handshake when the test still uses that address.

## What this lab does not prove

Hyper-V gave real kernels, systemd, independent virtual machines, a real DNS server, and a real power cut. It does not stand in for two public VPS hosts, a public-IP or public-DNS cutover, NAT in front of a VPS, or an official mobile or desktop Amnezia client. WireSock on this Windows host did not produce an encrypted datapath without disturbing the user's global DPI settings, and with the virtual adapter it leaked the inner session onto the lab NIC.

## Recommendation

Keep PR #186 experimental.

The migration, quarantine, panel restore, panel export sandbox, proxy restore, endpoint rewrite, lab DNS move, and power-loss fail-closed behavior all worked on this commit. The open conditions for leaving experimental status are the runbook's two real VPS hosts and a second real client implementation. The power-loss result should be described as a safe refusal plus an operator cleanup, not as automatic resume.
