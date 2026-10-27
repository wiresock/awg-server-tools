<!-- SPDX-FileCopyrightText: 2026 Vadim Smirnov (doing business as WireSock) -->
<!-- SPDX-License-Identifier: MIT -->
# MTU budget validation implementation plan

> Execute with superpowers:executing-plans and TDD; obtain an independent whole-diff review before opening the draft PR.

Goal: prevent the confirmed automatic-client failure (1420 minus S4=148 gives 1272, which rejects a 1280-byte IP packet) before creating configurations or keys. Existing configurations remain readable and operable.

Architecture: keep syntax parsing separate from new-configuration admission. Generic/Linux MTU remains a final inner value. WireSock uses an explicit pre-S4 baseline, as confirmed by the authorized native-source audit. The fallback outer budget1500 is an assumption, not measured remote PMTU. Do not silently compensate generic exports.

Owner-approved policy, 2026-10-27: hard S4 maximum140 on the1420 baseline,
normal generated maximum128, reduced limits for smaller known budgets. The
proposed universal70 cap was withdrawn: it only arose from imposing one
numeric export on clients with different MTU meanings. Separate WireSock
exports were also withdrawn. The owner requested a native client proposal
for explicit final-inner semantics; native implementation is not authorized.
AWG exports keep their existing meaning and warn about older clients.

Fresh generic policy: P=min(1500, observed uplink MTU); default final-inner
MTU=P-80-S4. Generated S4 is bounded by min(128,P-1360), and additionally
P-80-CLIENT_MTU when a final-inner override is supplied. Manual selection
may reach140 subject to that budget. The server uses P-80-S4 separately.
Later CLI/web creation checks nominal1500 and the persisted MTU, not current
uplink/remote PMTU. Omitted MTU remains allowed for padding-aware clients;
Linux awg-quick's omission risk is warning-only. Legacy reads and downloads
retain their bytes.

## Constraints and review focus

- Work only on fix/mtu-budget-validation, based on 4c1593ac29336ae6824cbf31484612915d3efe2a. No Lisbon mutations, merges, release changes, or old PR edits.
- Unknown PMTU and RandomTrailers high-water state must never be described as verified safe.
- Legacy reads, downloads, deletion, metadata edits, polling and startup must not acquire a new hard validation failure.
- New admission must run before key generation, file writes, peer append, or runtime sync.
- Keep generic explicit exports final-inner; no WireSock compensation or target UI. A passing numeric parser does not prove client packet-size safety.

## Tasks

- [x] Bash RED: tests/test-mtu-budget.sh exercises the impossible floor, boundary, integer overflow, endpoint families, explicit-export preservation and refusal before side effects.
- [x] Bash GREEN: make recommendedMtuForS4 reject impossible/overflowing budgets; add automatic-client admission at generation boundaries; bound fresh S4 selection using the same budget; add nonblocking legacy diagnostics. Keep validateClientMtu syntax-only.
- [x] Rust RED/GREEN: add a separate automatic-budget assessment to admin/client_manager.rs; invoke before native creation side effects and in rendering. Preserve parse_params and legacy exports. Add a typed safe creation error and nonblocking panel warning.
- [x] Regression: update tests that intentionally asserted the old unsafe floor/selection. Retain legacy syntax/export assertions; add shared boundary cases and assert warning-only legacy operation.
- [x] Local verification: focused Bash/Rust tests, installer unit suite, relevant protocol/generation/UI suites, cargo test, formatting, Clippy with denied warnings, shell lint and offline licensing checks.
- [x] Independent review and regression fixes. Native client changes remain a separate proposal.
- [ ] Push the coherent update and monitor exact-head nonpublishing CI for draft PR180.

## Padding evidence

At deployed BoringTun a92909c49920e12de11fb0e066192b8f39b5b212, RandomTrailers transport padding is min(random configured addition, learned window minus S4 minus32 minus plaintext). With the actual 10-100 range it is not an unconditional extra100. The window starts500, grows on transport observations, and does not shrink on MTU edits. Handshake trailers can reach window minus1. Fresh coordinated peers with MTU1280 and S4=128 bound UDP payload1440; stale or oversized peer traffic invalidates that conditional proof. No static configuration check substitutes for client coordination, fresh tunnel state and actual path validation.

## Earlier automatic-only verification (pushed b326290)

The focused Bash regression failed before implementation (12 failures) and
passed afterward. Independent review exposed two further fresh-install paths
that did not stop before side effects; four added assertions reproduced those
failures before the ordering and return-propagation fix. The final focused
suite passes 27 checks. Existing suites pass 1016 installer, 657 BoringTun host,
95 protocol, 168 backend and 37 mutation-engine checks. The full web Rust
suite passes 690 tests; formatting, Clippy with denied warnings, Bash syntax
and ShellCheck pass.

The initial remote native-source read was inaccessible. The owner then
provided D:/projects/wiresock/wiresock-vpn-client, inspected read-only at
626914289f2dcb75e1e6c25c04b5b2cc195a9ee7. wg_tunnel_base.h:3343-3360
subtracts S4 from explicit MTU; :2249-2263 does so for automatic MTU after
the80-byte framing allowance. The older SDK commit a5183451c62b42abe0a5fb67be215bb5a9375603
has the same explicit subtraction. Neither source revision was matched to
the installed screenshot build. Linux amneziawg-tools at
ee0f0a9aa34ff0a0da4b3433b9512781cfe02843, src/wg-quick/linux.bash:125-141,
uses explicit MTU unchanged. Protocol changes and
recovery keep existing S4/MTU and only warn, so inherited settings do not
prevent recovery. There is no general S4/MTU edit or upload API in the current
web panel; root-owned hand edits remain an operator responsibility.

## Independent core extension, not yet pushed

Focused Bash RED reproduced double deduction and missing fresh bounds
(35 passed/10 failed), then passed45 checks. Review added a real sysfs-read
path regression: a known NIC MTU1200 incorrectly became1500 (46 passed/1
failed); preserving positive observed MTUs made all47 pass. Rust RED
confirmed generic1292/S4=128 was incorrectly reduced to1164. The focused
MTU group then passed10. An interim policy incorrectly rejected omitted
MTU/S4=95 fixtures by applying Linux automatic semantics to all clients;
that policy is withdrawn. Review also reproduced Rust accepting signed S4 `+20`
while Bash refused it; admission now checks ASCII digits without hardening
legacy parsing. Full final validation remains pending. The native proposal
is separate and no target-export design is planned.

## Corrected core policy verification

Omitted-MTU RED tests reproduced the overbroad rejection; allowing omission
and retaining Linux warnings made the focused groups pass. Independent review
then found missing AUTO_INSTALL compatibility diagnostics. Three regressions
failed before the warning call and passed after it, including the fact that
client-derived automatic MTU does not inherit a smaller server budget.

Final local results: 54 MTU assertions, 1067 installer assertions, 657
BoringTun host assertions, 95 protocol tests, 168 backend tests, 37 mutation
engine assertions and 693 Rust tests pass. Formatting, Clippy with denied
warnings, Bash syntax, ShellCheck and diff checks pass. REUSE and offline
licensing policy pass on the staged tree export; dependency-license checks
and container/live checks remain for exact-head CI. Independent review has
no remaining actionable core findings. The earlier stalled installer run
was a synthetic input fixture exhausting its answers after the new budget
rejection; corrected inputs and prompt-only EOF handling retain all coverage.
