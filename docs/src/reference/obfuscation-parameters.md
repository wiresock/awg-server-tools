# Obfuscation parameters

AmneziaWG 2.0 adds S3/S4 and H1–H4 range parameters for enhanced traffic obfuscation. The installer generates all values automatically.

| Parameter | Range | Constraint |
|-----------|-------|------------|
| Jc | 1–128 | — |
| Jmin | 1–1280 | Jmin ≤ Jmax |
| Jmax | 1–1280 | Jmin ≤ Jmax |
| S1 | 15–150 | S1 + 56 ≠ S2 and S2 + 56 ≠ S1 |
| S2 | 15–150 | S1 + 56 ≠ S2 and S2 + 56 ≠ S1 |
| S3 | 15–150 | S3 + 56 ≠ S4 and S4 + 56 ≠ S3 |
| S4 | 15–150 (15–140 behind an IPv6 endpoint or a hostname) | S3 + 56 ≠ S4 and S4 + 56 ≠ S3 |
| H1–H4 | 5–2147483647 | Ranges must not overlap |

H parameters accept a range (`min-max`) or a single value.

These are the ranges the installer generates and accepts at install time.
When it loads an existing installation it also keeps two kinds of values set
by hand in `params` (keep `awg0.conf` matching, then regenerate the clients):

- `S3` and `S4` from 0 upwards (still at most 150, with the same `+ 56`
  rules). The protocol allows padding below 15, and a small `S4` saves MTU.
- The standard WireGuard headers `H1=1`, `H2=2`, `H3=3`, `H4=4`, exactly in
  that order. These turn off header obfuscation, so the installer never
  generates them and prints a warning on every run. Any other value below 5
  is rejected.

Hand-set values outside these rules are reported by name before the
installer offers to replace them; answer `N` to keep the files unchanged.

`S4` is prepended to every transport packet. Fresh installs generate15–128,
and manual selection allows at most140. A smaller known uplink or explicit
generic client MTU further limits the range. The server and generic client
default to `min(1500, uplink MTU) - 80 - S4`, without rounding below1280.
Linux automatic MTU leaves room for S4 up to 20 behind an IPv4 endpoint and zero
behind an IPv6 endpoint or hostname under the nominal 1500-byte budget;
omission remains allowed with a warning because padding-aware clients use
different calculations. S3 and S4 input is interpreted as decimal, including
values with leading zeros; `S4=0120` therefore means 120 bytes and recommends
an MTU of 1300 on a 1500-byte path. See
[Non-Interactive Install](../installer/non-interactive.md).

</details>

<details>
<summary>🔁 Migration from Pre-2.0</summary>

Run the installer on an existing pre-2.0 installation. It detects the need for migration and prompts before proceeding.

**Important:** All existing client configs become incompatible after migration. Regenerate them using option 1 (Add a new user) in the management menu.

Migration steps:
1. Creates `.bak` backup files before making any changes.
2. Generates new S3/S4 values with bidirectional constraint validation.
3. Converts single H values to range format (or regenerates if overlapping).
4. Updates server config and params file atomically.
5. Renames outdated client configs with `.old` suffix.
6. Reloads the running VPN service (if active).

Backups are restored automatically if migration fails.

</details>

<details>
<summary>🔒 Security Notes</summary>

- **Shell injection prevention** — params file values are safely shell-quoted.
- **Atomic writes** — config updates use a temp file + rename to prevent corruption on interruption.
- **Filesystem boundary protection** — client config search uses `-xdev` to stay within the config filesystem.

</details>

---
