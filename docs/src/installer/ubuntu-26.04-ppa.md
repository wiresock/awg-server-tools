# Ubuntu 26.04 PPA compatibility

When the Amnezia PPA does not publish a `resolute` suite, the Ubuntu 26.04
(Resolute) installer uses the PPA's signed Ubuntu 24.04 (`noble`) suite as a
temporary, narrowly scoped fallback:

- The native `resolute` suite is checked first on every install or management
  run. Once it is published, the installer automatically stops using the
  fallback.
- Network failures and unexpected HTTP responses do **not** trigger the
  fallback. Both native PPA metadata endpoints must explicitly report that the
  suite is absent.
- Normal APT signature verification remains enabled. The installer does not
  add `trusted=yes` or allow insecure repositories.
- The fallback is allowed on `amd64`, `arm64`, `armhf`, `ppc64el`, `riscv64`,
  and `s390x`, where the required package indexes are published. It is rejected
  on `i386`, which lacks `amneziawg-tools`.
- Runtime module loading is continuously tested on the GitHub-hosted Ubuntu
  26.04 `amd64` image. Other listed architectures have package-index coverage
  but are not runtime-tested by this repository's CI.

Uninstalling AmneziaWG removes only source entries that exactly match the
Amnezia PPA, including a fallback entry left by an interrupted older install.
Unrelated APT sources in the same file are preserved.

Ubuntu kernels such as `7.0.0-1017-azure` backport UDP tunnel API changes that
the upstream AmneziaWG module's version checks do not recognize. During Debian
and Ubuntu kernel-backend installation or module repair, the installer replaces
the two known compatibility macros in the installed DKMS source with checks of
the actual function signatures. This supports both older and backported APIs.
If package configuration failed before the fix was applied, the same package
transaction is retried once. Rerunning an interrupted install patches existing
source before prerequisite package operations. The patched source also supports
later kernel rebuilds; replacing the DKMS package can replace that source.
Unrecognized or newer upstream macros are left unchanged. CI builds against both
the running kernel and the latest Azure headers.

Temporarily disabled:

- Fedora (RPM-based)
- AlmaLinux (RPM-based)
- Rocky Linux (RPM-based)

Reason: verified AmneziaWG 2.0 packages are not currently available for these RPM-based distributions. Please watch this repository's releases and README for support status updates.

Source builds require approximately 2 GiB of free space for `amneziawg-web`
and 1 GiB for `amneziawg-proxy`. Their install and upgrade scripts inspect the
Cargo target filesystem, free inodes, CPU count, and available memory before
building. On constrained hosts they use one Cargo job and, when the source
filesystem is too small, place build artifacts on a suitable disk-backed
filesystem automatically.

To select a specific build filesystem, create a writable directory on an
executable mount and pass it explicitly:

```bash
sudo env AMNEZIAWG_BUILD_ROOT=/path/with/free-space ./amneziawg-web.sh upgrade
sudo env AMNEZIAWG_BUILD_ROOT=/path/with/free-space ./amneziawg-proxy.sh upgrade
```

An explicit `CARGO_TARGET_DIR` is also supported, but is treated as strict: the
operation fails with a diagnostic if that target does not meet the build
requirements.

---

<details>
<summary>⚙️ AmneziaWG 2.0 Parameters</summary>
