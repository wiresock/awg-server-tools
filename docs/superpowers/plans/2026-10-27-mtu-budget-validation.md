<!-- SPDX-FileCopyrightText: 2026 Vadim Smirnov (doing business as WireSock) -->
<!-- SPDX-License-Identifier: MIT -->
# MTU budget validation implementation plan

> Execute with superpowers:executing-plans and TDD; obtain an independent whole-diff review before opening the draft PR.

Goal: prevent the confirmed automatic-client failure (1420 minus S4=148 gives 1272, which rejects a 1280-byte IP packet) before creating configurations or keys. Existing configurations remain readable and operable.

Architecture: keep syntax parsing separate from new-configuration admission. Bash and Rust use the same conservative 80-byte outer framing allowance and minimum effective inner MTU1280. The fallback outer budget1500 is an assumption, not measured remote PMTU. Explicit client MTU interpretation is pending owner confirmation; preserve its existing exported bytes and do not compensate it.

## Constraints and review focus

- Work only on fix/mtu-budget-validation, based on 4c1593ac29336ae6824cbf31484612915d3efe2a. No Lisbon mutations, merges, release changes, or old PR edits.
- Unknown PMTU and RandomTrailers high-water state must never be described as verified safe.
- Legacy reads, downloads, deletion, metadata edits, polling and startup must not acquire a new hard validation failure.
- New admission must run before key generation, file writes, peer append, or runtime sync.
- Preserve explicit client MTU exports until their WireSock interpretation is confirmed. A passing numeric parser does not prove client packet-size safety.

## Tasks

- [x] Bash RED: tests/test-mtu-budget.sh exercises the impossible floor, boundary, integer overflow, endpoint families, explicit-export preservation and refusal before side effects.
- [x] Bash GREEN: make recommendedMtuForS4 reject impossible/overflowing budgets; add automatic-client admission at generation boundaries; bound fresh S4 selection using the same budget; add nonblocking legacy diagnostics. Keep validateClientMtu syntax-only.
- [x] Rust RED/GREEN: add a separate automatic-budget assessment to admin/client_manager.rs; invoke before native creation side effects and in rendering. Preserve parse_params and legacy exports. Add a typed safe creation error and nonblocking panel warning.
- [x] Regression: update tests that intentionally asserted the old unsafe floor/selection. Retain legacy syntax/export assertions; add shared boundary cases and assert warning-only legacy operation.
- [ ] Verification: focused Bash/Rust tests, installer unit suite, relevant protocol/generation/UI suites, cargo test, cargo fmt --check, cargo clippy -- -D warnings, shell lint and licensing checks. Run nonpublishing CI for the reviewed draft.
- [ ] Independent review, fix substantiated findings with regressions, commit and open a draft PR. Explicit client export work remains pending if the owner has not answered.

## Padding evidence

At deployed BoringTun a92909c49920e12de11fb0e066192b8f39b5b212, RandomTrailers transport padding is min(random configured addition, learned window minus S4 minus32 minus plaintext). With the actual 10-100 range it is not an unconditional extra100. The window starts500, grows on transport observations, and does not shrink on MTU edits. Handshake trailers can reach window minus1. Fresh coordinated peers with MTU1280 and S4=128 bound UDP payload1440; stale or oversized peer traffic invalidates that conditional proof. No static configuration check substitutes for client coordination, fresh tunnel state and actual path validation.

## Verification and scope record

The focused Bash regression failed before implementation (12 failures) and
passed afterward. Independent review exposed two further fresh-install paths
that did not stop before side effects; four added assertions reproduced those
failures before the ordering and return-propagation fix. The final focused
suite passes 27 checks. Existing suites pass 1016 installer, 657 BoringTun host,
95 protocol, 168 backend and 37 mutation-engine checks. The full web Rust
suite passes 690 tests; formatting, Clippy with denied warnings, Bash syntax
and ShellCheck pass.

Explicit MTU handling remains outside this patch's safety guarantee. The
inspected WireSock UI passes the profile filename to a native engine; the
referenced native repository was not accessible through the connected
account. No explicit export compensation was inferred. Protocol changes and
recovery keep existing S4/MTU and only warn, so inherited settings do not
prevent recovery. There is no general S4/MTU edit or upload API in the current
web panel; root-owned hand edits remain an operator responsibility.
