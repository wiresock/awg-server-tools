# BoringTun runtime notices implementation plan

> **For agentic workers:** Use superpowers:executing-plans. The user requested implementation after the audit checkpoint and an independent final review.

**Goal:** Complete issue #175's local packaging implementation and document the remaining publication/adoption gates.

**Architecture:** Preserve the four-file archive. Append a reviewed, checksum-pinned runtime/native notice bundle to Cargo notices, bind it to the exact Rust version, and verify complete notice bytes as well as component-specific attribution. Require the fork's complete BSD license at generation, packaging and archive verification.

**Tech Stack:** Bash, Python 3, Rust distribution/source manifests, Git, existing shell regression suites.

**Spec:** https://github.com/wiresock/awg-server-tools/issues/175 and the task's explicit restrictions.

## Global constraints

- Fresh AWG branch from main and fork branch from its default master; no prior worktree edits.
- Preserve Cloudflare's original notice verbatim; substantiate ownership and years, documenting unresolved provenance.
- No releases, assets, tags, installer constants, deployments, issue closure or merges.
- No memory updates. Current pin remains until a reviewed fork commit is available for adoption.

## Review focus

- Missing individual native/runtime notices and license terms must fail, including static archive verification.
- A changed toolchain or dependency must not silently reuse a stale notice bundle.
- Missing, modified, duplicated or symlinked notice inputs must fail closed.
- Synthetic test archives must stay isolated from production verification.
- Existing release contracts and installer adoption are distinct from local packaging preparation.

## Task 1: Establish provenance and fork attribution

- [ ] Verify Rust 1.98.1 distribution/source checksums, library dependencies, musl and LLVM sources, and ring native notices.
- [ ] Audit fork-added files and source history, preserving upstream notices and recording unresolved ported-code years.
- [ ] Update substantiated attribution and add a check proving upstream LICENSE preservation.

## Task 2: Complete notice generation and fail-closed validation

- [ ] Add regression cases in tests/test-boringtun-artifact.sh for absent fork/runtime notices, altered terms and stale toolchain provenance; observe expected failures.
- [ ] Add reviewed notice inputs and provenance under packaging/boringtun; implement exact bundle validation in scripts/boringtun-artifact.sh, extend required-notices and append the bundle in licenses.
- [ ] Require both LICENSE and THIRD-PARTY-LICENSES at production gates; retain four archive members.
- [ ] Update fixtures, CI paths if needed and licensing documentation/REUSE metadata.

## Task 3: Verify and prepare delivery

- [ ] Run artifact, release, licensing and relevant shell suites; run real license generation and local native reproducibility where available.
- [ ] Obtain independent review of final changes and resolve findings.
- [ ] Commit local branches and report exact commits, passed/unrun checks, unresolved provenance and release/adoption gates.
