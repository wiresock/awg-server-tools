# BoringTun distribution notices

Format-1 archives still contain exactly `boringtun-cli`, `LICENSE`,
`THIRD-PARTY-LICENSES` and `MANIFEST` under their versioned directory.
`LICENSE` contains the unchanged Cloudflare BSD-3-Clause text followed by the
fork holder's notice and complete BSD terms. `THIRD-PARTY-LICENSES` contains the
Cargo dependency notices followed by the reviewed runtime/native collection.

## Reproducible inputs

`packaging/boringtun/runtime-provenance.json` records exact upstream URLs and
SHA-256 digests. Rust 1.98.1 comes from the dated 2026-09-03 distribution and
commit `48a229ceaefd4985c50990b14116b6d856af0985`. The source archive and all five
target distributions were downloaded and checked against the pinned official
Rust distribution manifest. Exact per-file SHA-256 inventories cover 70 objects
for x86_64 Linux, 66 for ARM64 Linux, 63 for ARMv7 Linux, and 59 each for Intel
and Apple Silicon macOS. Linux inventories include the self-contained CRT
objects and libc/libunwind; Apple inventories contain the shipped Rust runtime.
An inventory lists shipped objects; it does not claim that every object is linked.

The collection uses exact vendored versions in Rust's `library/Cargo.lock`,
Rust's in-tree attribution inventory, and complete license texts from that
source archive. It excludes the compiler inventory's out-of-tree tooling/test
dependency section, whose versions differ from the standard-library lockfile.
The reviewed runtime dependency selection is explicit in the provenance file.
Pinned `std`, `unwind` and `panic_unwind` manifests select the same covered Unix
dependencies for these Linux and Apple targets. Rust compiler-builtins/libm
source notices are included conservatively.

Notice policy v2 maps exactly three Linux musl targets to `runtime-notices.txt`
and two Apple targets to `runtime-notices-macos.txt`. The Linux collection retains
286 sections; the Apple collection has 232. Apple artifacts use dynamic macOS
system libraries: they do not redistribute musl, Linux CRT objects or static
LLVM libunwind, so those sections are not assigned to the Apple profile. Rust
and ring source notices remain conservative supersets. The application Cargo
license collection covers the union of all five targets; it does not imply that
every listed crate is linked on each platform.

Pinned Rust's `src/ci/docker/scripts/musl.sh` identifies musl 1.2.5 and its
patches. Its complete `COPYRIGHT` and per-file notice blocks are retained.
The pinned LLVM submodule is
`52ed14fcd56afc30f9cccd8ca8ce237c2eef7e04`: libunwind and compiler-rt each have
their own complete license text, with compiler-rt credits preserved separately.
Rust bootstrap's `CrtBeginEnd` implementation compiles compiler-rt's
`crtbegin.c`/`crtend.c`; `copy_self_contained_objects` places those outputs in
the musl distribution. Both source files and bootstrap evidence are hash-pinned.
These CRT objects are not attributed to GCC by inference from the C compiler.

ring 0.17.14's crate checksum is pinned to the application's Cargo.lock.
Its license mapping, BoringSSL/other-bit license texts and native per-file
notice blocks are included. Source/generator notices for unused architectures
may also be present; this conservative collection does not relicense the
binary under every source tool's license.

Download the listed inputs into one directory, then run:

```sh
python3 scripts/refresh-boringtun-notices.py /path/to/inputs --check
```

The generator verifies all input digests before reading them, preserves full
license text, and records each emitted section's origin, transformation and
digest in `runtime-sections.json` and `runtime-sections-macos.json`. HTML conversion retains ordered text nodes;
source extraction retains complete copyright/license comment blocks. A change
to any input, source selection, toolchain or Cargo.lock needs review and a new
notice-policy digest. Do not update a hash merely to silence a failed gate.

## Enforced checks and remaining evidence

`boringtun-notices.py` requires the exact approved runtime bundle and fork
license bytes for the selected target. Source validation also binds Cargo.lock
to reviewed checksums. Before compilation, the installed target runtime must
match every distribution object's bytes and the exact inventory; missing or
extra files and symlinked runtime paths fail closed.
Packaging, license generation and production archive verification all invoke
these checks. Cargo notices must still identify their holders; literal
placeholders inside the separately byte-verified upstream runtime texts do not
weaken Cargo's placeholder check. Removing a copyright line, terms, a runtime
section, or the fork notice fails verification.

Linux static ELF checks and macOS Mach-O/system-link checks are distinct. Native
macOS compilation, SDK/link receipts, two-build equality and utun behavior still
require real macOS execution before release activation; fixtures do not establish
those results. No Developer ID or notarization credentials are introduced.

The fork's existing 2024–2026 year assertions are retained, **not independently
verified**. The 33 affected paths and source-port evidence are listed in the
fork's `docs/ATTRIBUTION.md`; six 2026-only notices remain 2026. Publication is
blocked pending owner evidence or an explicit correction. Other contributors'
authorship is preserved. A locally passing notice check does not resolve that
historical ownership question or authorize release publication.

The migration is described in [BORINGTUN_MIGRATION.md](BORINGTUN_MIGRATION.md).
