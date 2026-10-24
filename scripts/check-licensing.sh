#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 WireSock
# SPDX-License-Identifier: MIT
#
# Licensing checks for this repository. See docs/LICENSING.md.
#
# Usage: scripts/check-licensing.sh [--offline]
#
# Checks that:
#   - the repository is REUSE compliant (`reuse lint`): every file has an SPDX
#     license and copyright, and every license used has its text in LICENSES/;
#   - LICENSES/ holds only the licenses this repository is meant to use, so a
#     new license is a reviewed decision and not a side effect;
#   - LICENSE, each component LICENSE and LICENSES/MIT.txt carry the same MIT
#     terms, and LICENSE and the installer keep the inherited upstream notices;
#   - the Cargo manifests declare the license their LICENSE files and SPDX
#     headers state, and each crate has its own LICENSE file;
#   - the BoringTun cargo-about and cargo-deny policies accept the same
#     licenses, as packaging/boringtun/about.toml requires;
#   - the Rust dependencies of the web panel and the proxy are all under
#     licenses allowed by .github/licensing/deny.toml (cargo-deny).
#
# The BoringTun THIRD-PARTY-LICENSES generation and its required-notices check
# are separate: scripts/boringtun-artifact.sh runs them in the BoringTun
# Artifacts workflow, and tests/test-boringtun-artifact.sh tests them.
#
# --offline skips cargo-deny, which needs the crate sources (it runs
# `cargo fetch` unless they are already in the Cargo home).
#
# Needs: reuse, and cargo with cargo-deny unless --offline. CI pins their
# versions in .github/workflows/licensing.yml.

set -euo pipefail

ROOT="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "${ROOT}"

OFFLINE=0
case "${1:-}" in
    "") ;;
    --offline) OFFLINE=1 ;;
    *) echo "usage: $0 [--offline]" >&2; exit 2 ;;
esac

# Licenses whose texts may be in LICENSES/. Extend only together with the
# documentation in NOTICE.md and docs/LICENSING.md.
EXPECTED_LICENSES="MIT"
# Crate directory and the SPDX license its Cargo.toml must declare.
CRATES="amneziawg-web:MIT amneziawg-proxy:MIT"
# Built from parts so that `reuse lint` does not read this script's patterns
# as license or copyright tags of the script itself.
LICENSE_TAG="SPDX-License""-Identifier:"
COPYRIGHT_TAG="SPDX-File""CopyrightText:"
NOTICE_PREFIX="Copy""right (c)"

FAILED=0
fail() {
    printf 'FAIL: %s\n' "$*" >&2
    FAILED=1
}
pass() {
    printf 'ok:   %s\n' "$*"
}

# The MIT terms of a license file: everything from "Permission is hereby
# granted" on, with whitespace normalised so that line wrapping differs freely.
mit_terms() {
    sed -n '/^Permission is hereby granted/,$p' "$1" | tr -s '[:space:]' ' ' | sed 's/^ //; s/ $//'
}

check_reuse() {
    if ! command -v reuse >/dev/null 2>&1; then
        fail "reuse is not installed (pip install reuse; see docs/LICENSING.md)"
        return
    fi
    if reuse lint >/dev/null 2>&1; then
        pass "reuse lint: the repository is REUSE compliant"
    else
        reuse lint >&2 || true
        fail "reuse lint reported problems (see above)"
    fi
}

check_license_dir() {
    local found
    found="$(find LICENSES -maxdepth 1 -type f -name '*.txt' -printf '%f\n' | sed 's/\.txt$//' | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')"
    if [[ "${found}" == "${EXPECTED_LICENSES}" ]]; then
        pass "LICENSES/ holds exactly: ${found}"
    else
        fail "LICENSES/ holds '${found}', expected '${EXPECTED_LICENSES}'; a new license needs review (docs/LICENSING.md)"
    fi
}

check_license_files() {
    local reference file notice lost=0
    reference="$(mit_terms LICENSES/MIT.txt)"
    [[ -n "${reference}" ]] || { fail "LICENSES/MIT.txt has no MIT terms"; return; }
    for file in LICENSE amneziawg-web/LICENSE amneziawg-proxy/LICENSE; do
        if [[ ! -f "${file}" ]]; then
            fail "${file} is missing"
        elif [[ "$(head -n 1 "${file}")" != "MIT License" || "$(mit_terms "${file}")" != "${reference}" ]]; then
            fail "${file} does not carry the MIT terms of LICENSES/MIT.txt"
        elif ! grep -Eq "^${NOTICE_PREFIX/(c)/\\(c\\)} [0-9]{4}" "${file}"; then
            fail "${file} has no copyright notice"
        else
            pass "${file} carries the MIT terms and a copyright notice"
        fi
    done
    for file in NOTICE.md REUSE.toml CONTRIBUTING.md docs/LICENSING.md; do
        [[ -s "${file}" ]] || fail "${file} is missing or empty"
    done
    # The inherited notices (NOTICE.md, "Origin of the project") must not be
    # dropped from LICENSE or from the installer that contains their code.
    while IFS= read -r notice; do
        if ! grep -qxF "${NOTICE_PREFIX} ${notice}" LICENSE; then
            fail "LICENSE lost the notice '${NOTICE_PREFIX} ${notice}'"
            lost=1
        fi
        if ! grep -qxF "# ${COPYRIGHT_TAG} ${notice}" amneziawg-install.sh; then
            fail "amneziawg-install.sh lost the notice '${notice}'"
            lost=1
        fi
    done <<'EOF'
2019 angristan
2024 Roman Zakharchuk
2024 Markus Varckin
EOF
    if [[ "${lost}" -eq 0 ]]; then
        pass "LICENSE and amneziawg-install.sh keep the upstream notices"
    fi
}

check_crates() {
    local entry dir expected declared bad
    for entry in ${CRATES}; do
        dir="${entry%%:*}"
        expected="${entry#*:}"
        declared="$(sed -n 's/^license[[:space:]]*=[[:space:]]*"\(.*\)"[[:space:]]*$/\1/p' "${dir}/Cargo.toml")"
        if [[ "${declared}" != "${expected}" ]]; then
            fail "${dir}/Cargo.toml declares license '${declared}', expected '${expected}'"
            continue
        fi
        if grep -q '^license-file[[:space:]]*=' "${dir}/Cargo.toml"; then
            fail "${dir}/Cargo.toml sets license-file; the SPDX license field is the single source"
            continue
        fi
        # Every inline SPDX license tag in the crate must agree with Cargo.toml.
        bad="$(git ls-files -z -- "${dir}" | xargs -0 grep -I -h -o "${LICENSE_TAG} .*" 2>/dev/null |
            sed "s/^${LICENSE_TAG} //; s/[[:space:]]*$//" | LC_ALL=C sort -u | grep -vxF "${expected}" || true)"
        if [[ -n "${bad}" ]]; then
            fail "${dir} has files licensed '${bad//$'\n'/, }', but Cargo.toml declares '${expected}'"
            continue
        fi
        pass "${dir}: Cargo.toml, LICENSE and SPDX headers agree on ${expected}"
    done
}

# packaging/boringtun/about.toml: "deny.toml gates the same graph plus build
# dependencies; both must accept the same licenses."
check_boringtun_policies() {
    local about deny
    about="$(sed -n '/^accepted = \[/,/^\]/p' packaging/boringtun/about.toml | grep -o '"[^"]*"' | LC_ALL=C sort | tr '\n' ' ')"
    deny="$(sed -n '/^allow = \[/,/^\]/p' packaging/boringtun/deny.toml | grep -o '"[^"]*"' | LC_ALL=C sort | tr '\n' ' ')"
    if [[ -n "${about}" && "${about}" == "${deny}" ]]; then
        pass "BoringTun cargo-about and cargo-deny accept the same licenses"
    else
        fail "packaging/boringtun/about.toml accepts [${about}] but deny.toml allows [${deny}]"
    fi
}

check_dependencies() {
    local entry dir
    if [[ "${OFFLINE}" -eq 1 ]]; then
        echo "skip: cargo-deny dependency licenses (--offline)"
        return
    fi
    if ! cargo deny --version >/dev/null 2>&1; then
        fail "cargo-deny is not installed (cargo install --locked cargo-deny; see docs/LICENSING.md)"
        return
    fi
    for entry in ${CRATES}; do
        dir="${entry%%:*}"
        if (cd "${dir}" && cargo deny --locked --config "${ROOT}/.github/licensing/deny.toml" check licenses); then
            pass "${dir}: every dependency is under an allowed license"
        else
            fail "${dir}: cargo-deny rejected a dependency license (see above)"
        fi
    done
}

check_reuse
check_license_dir
check_license_files
check_crates
check_boringtun_policies
check_dependencies

if [[ "${FAILED}" -ne 0 ]]; then
    echo "Licensing checks failed; see docs/LICENSING.md." >&2
    exit 1
fi
echo "All licensing checks passed."
