# First public fork-release adoption

The installer selects
[`boringtun-cli-0.7.1-ga92909c49920-b101`](https://github.com/Wiresock-Foundation/wiresock-boringtun/releases/tag/boringtun-cli-0.7.1-ga92909c49920-b101),
release ID `424839667`. This is the first public fork release. The later
`39d7bfc14f13` source and its unpublished draft are not adoption inputs.
Historical AWG release assets, `pin.env` and `release.env` remain unchanged.

## Verification evidence

On 2026-10-27 the read-only `scripts/boringtun-adopt.py` command freshly
downloaded and checked all seven public assets with the checksum-pinned official
GitHub CLI 2.100.0. It cryptographically verified the descriptor and all five
archives, then checked exact source/recipe/run/attempt identity, merged-PR
evidence, notice/toolchain provenance, static binary format and complete notices
for all five targets. No downloaded BoringTun binary was executed. A second
release/tag readback confirmed that the identity did not change during checking.

| Identity | Verified value |
| --- | --- |
| Source and publisher recipe | `a92909c49920e12de11fb0e066192b8f39b5b212` |
| Merged fork PR | [#101](https://github.com/Wiresock-Foundation/wiresock-boringtun/pull/101) |
| Build | [40409966150, attempt 1](https://github.com/Wiresock-Foundation/wiresock-boringtun/actions/runs/40409966150/attempts/1) |
| Publisher | [40412814028, attempt 1](https://github.com/Wiresock-Foundation/wiresock-boringtun/actions/runs/40412814028/attempts/1) |
| `RELEASE.json` SHA-256 | `72cdbcfffa577f499672a8f05a337797c1665889df384d5174f0ff0986966047` |
| `SHA256SUMS` SHA-256 | `6b5ba22869e34927305ff3f569e32413f22a64c9d5abdda3e451fd43a596fe9c` |
| Notice provenance SHA-256 | `387a1832f8d4ee4376af84fa92b637ce6a2f7afc34a2bb866b56ee40e4ea268e` |
| Toolchain projection SHA-256 | `1c3e5f4da3aafb13cd60b35c37168169a22b71eb52a5ed0be90100af709968ac` |
| Local adoption `verification.json` SHA-256 | `8725222292e8138e4ffe7105080f4f8932ffd91e721a31e690e077ae63b6d9f0` |

The local receipt, full successful `gh` verification output, downloaded assets,
static inspection outputs and generated installer patch were retained in
`provenance/adoption-a929-b101-verified-20261027` in the maintainer's workspace.
That local evidence directory is not a public repository artifact. The public
release files, attestations and linked run identities allow independent checks;
a fresh receipt may differ as GitHub metadata changes.

| Linux target | Archive SHA-256 | Binary SHA-256 |
| --- | --- | --- |
| x86_64 musl | `d7dbd5019540fb0c9c451b41b8b16830cb5d5923afec20a61ce4edf2c513358f` | `8b0bbb4897d4ccce34b89025374f97476cd6505b4f8bf2346ebd21126f797b8a` |
| aarch64 musl | `3171278b375c2e5b3c55f288c1db34513c78b0cbba6165244264f7efb4b51dd4` | `c49f5f1501885aaabd787e5ab24f18e4070d1bf2e1b21ff255211d0f20428f94` |
| ARMv7 musleabihf | `bd724ea1d8ad12a0b2185b0f361add9bb1cadccb39df8ebcccfac3fe1d0847b9` | `bd19a5957e78c875b1f8ec75ef2296cddce19ba8869c7ca6d3697f8b206a35c0` |

Both macOS archive hashes and their signatures were also checked against the
same descriptor. They never become AWG installer selections. The four-member
archive format and explicit source/build store identities are preserved.
ARMv7 installation requires ARMv7-A/VFPv3-D16 hard-float; ARMv6 Pi models are
unsupported, and this adoption does not claim physical Raspberry Pi testing.

## Adoption and operational gates

The adoption patch changes the exact installer URL, source/build identity and
three Linux asset/archive/binary pins. The anonymous public-release check also
validates the signed descriptor's full five-target contract and all downloaded
archive hashes. Signature and CI identity checks occur in the adoption command;
the anonymous check establishes public availability and consistency with pins.

The host workflow includes an x86_64 upgrade/rollback lane from the last
AWG-owned `e94c04f3` release, alongside the older compatibility lanes. The
`b94943906b11` behavioral model remains limited to that old binary; candidate
collision tests require the actual installed binary to match the adopted pins.
Disposable-runner checks are separate from production rollout and physical Pi
validation. Their current outcome belongs to the adoption PR's checks.

Existing installations do not upgrade automatically. Before any production
cutover, retain independent administrative access and make a verified root-only
backup of configurations, helpers, units, current/previous release stores and
symlinks. Keep secret material on the host. Preserve the old installer and both
store targets before the upgrade can prune an older target. An upgrade restarts
the active tunnel service and can interrupt traffic. Verify services, binary
identity, unchanged configuration hashes and authorized client connectivity;
use the supported rollback transaction on regression. This adoption performs
no production backup, upgrade or rollback itself.
