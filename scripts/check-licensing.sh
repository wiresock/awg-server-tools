#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Vadim Smirnov (doing business as WireSock)
# SPDX-License-Identifier: MIT
#
# Licensing checks for this repository. See docs/LICENSING.md.
#
# Usage: scripts/check-licensing.sh [--offline]
#
# Checks that:
#   - the repository is REUSE compliant (`reuse lint`): every file has an SPDX
#     license and copyright, and every license used has its text in LICENSES/;
#     and every copyright that `reuse spdx` resolves looks like a notice, so a
#     quoted table row or heading is never taken for a file's own;
#   - the Rust sources and the installed shell scripts carry their own SPDX
#     copyright and license header;
#   - LICENSES/ holds only the licenses this repository is meant to use, so a
#     new license is a reviewed decision and not a side effect;
#   - LICENSES/MIT.txt is the unmodified SPDX text, LICENSE and each component
#     LICENSE carry the same MIT terms, and LICENSE and the installer keep the
#     inherited upstream notices and the installer its named contributor;
#   - the Cargo manifests declare the license their LICENSE files and SPDX
#     headers state, and each crate has its own LICENSE file;
#   - the maintainer is named as the individual behind the WireSock trade name
#     (MAINTAINER below) in every LICENSE file and copyright tag that mentions
#     WireSock, and each crate's SPDX years for him lie within its LICENSE's;
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
EXPECTED_LICENSES="BSD-3-Clause LicenseRef-BoringTun-Runtime-Notices LicenseRef-BoringTun-Runtime-Notices-macOS MIT"
# Crate directory and the SPDX license its Cargo.toml must declare.
CRATES="amneziawg-web:MIT amneziawg-proxy:MIT"
# Built from parts so that `reuse lint` does not read this script's patterns
# as license or copyright tags of the script itself.
LICENSE_TAG="SPDX-License""-Identifier:"
COPYRIGHT_TAG="SPDX-File""CopyrightText:"
NOTICE_PREFIX="Copy""right (c)"
NOTICE_PREFIX_RE="Copy""right \\(c\\)"
CONTRIBUTOR_TAG="SPDX-File""Contributor:"
# sha256 of the SPDX MIT text as downloaded by `reuse download MIT`.
MIT_TEXT_SHA256="b05785f9f18e6716bab63424b11454513b9943a222595b70411009202fc592b5"
# WireSock is a trade name of Vadim Smirnov, not a separate legal entity, so a
# notice never names WireSock alone (NOTICE.md).
MAINTAINER="Vadim Smirnov (doing business as WireSock)"
MAINTAINER_RE="${MAINTAINER//(/\\(}"
MAINTAINER_RE="${MAINTAINER_RE//)/\\)}"

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
    local output rc=0
    output="$(reuse lint 2>&1)" || rc=$?
    # reuse logs a tag it cannot parse as an ERROR and skips that file's own
    # header, which can still leave the summary compliant: treat it as failure.
    if [[ "${rc}" -eq 0 ]] && ! grep -q ' - ERROR - ' <<<"${output}"; then
        pass "reuse lint: the repository is REUSE compliant"
    else
        printf '%s\n' "${output}" >&2
        fail "reuse lint reported problems (see above)"
        return
    fi
    # Under precedence = "closest", reuse prefers anything in a file that looks
    # like a copyright notice over REUSE.toml. A document that quotes notices
    # in a table or shows a heading would then be credited to the wrong holder
    # while lint still passes. A resolved copyright is taken for such a
    # fragment when it contains a table bar or backtick, or names neither a
    # year nor an e-mail address. Real notices, including verbatim third-party
    # ones such as "2019 Cloudflare, Inc. All rights reserved.", pass.
    local spdx odd rc=0
    spdx="$(reuse spdx 2>/dev/null)" || rc=$?
    if [[ "${rc}" -ne 0 || -z "${spdx}" ]]; then
        fail "reuse spdx failed (exit ${rc})"
        return
    fi
    odd="$(awk '
        /^FileName: / { name = $2 }
        /^FileCopyrightText: <text>/ { t = 1; sub(/^FileCopyrightText: <text>/, "") }
        t {
            line = $0; done = sub(/<\/text>.*/, "", line)
            # These two aggregates identify holders by their verbatim source
            # notices, without assigning all portions to one owner. REUSE
            # permits an identifying group descriptor without a year.
            if ((name == "./packaging/boringtun/runtime-notices.txt" ||
                 name == "./packaging/boringtun/runtime-notices-macos.txt") &&
                line == "Upstream copyright holders identified in the source notices reproduced in this file") {
                if (done) t = 0
                next
            }
            if (line != "" && (line ~ /[|`]/ || (line !~ /[0-9][0-9][0-9][0-9]/ && line !~ /<[^>]+@[^>]+>/)))
                print name " :: " line
            if (done) t = 0
        }' <<<"${spdx}")"
    if [[ -n "${odd}" ]]; then
        fail "reuse resolves text that does not look like a copyright notice. If the file quotes notices or shows example tags as documentation or data, add it to the override annotation at the end of REUSE.toml; if it is a real notice, it needs a year or a contact address. Never use the override for a file whose own notice belongs to someone else:"$'\n'"${odd}"
    else
        pass "every copyright reuse resolves looks like a notice"
    fi
}

# Files that are installed or copied on their own carry their notice inline
# (REUSE.toml): the Rust sources and the shell scripts outside the tests, CI
# and the BoringTun release pipeline.
check_inline_headers() {
    local file header missing=""
    while IFS= read -r file; do
        header="$(sed -n '1,40p' -- "${file}")"
        if ! grep -q "${COPYRIGHT_TAG} " <<<"${header}" || ! grep -q "${LICENSE_TAG} " <<<"${header}"; then
            missing+="${file}"$'\n'
        fi
    done < <(git ls-files -- '*.rs' '*.sh' amneziawg-web/scripts/amneziawg-web-privileged |
        grep -vE '^(tests/|\.github/|scripts/boringtun-)')
    if [[ -n "${missing}" ]]; then
        fail "these files need an inline ${COPYRIGHT_TAG} and ${LICENSE_TAG} header:"$'\n'"${missing%$'\n'}"
    else
        pass "Rust sources and installed shell scripts carry SPDX headers"
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
    if [[ "$(sha256sum LICENSES/MIT.txt | cut -d' ' -f1)" != "${MIT_TEXT_SHA256}" ]]; then
        fail "LICENSES/MIT.txt is not the unmodified SPDX MIT text"
    fi
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
    if ! grep -qxF "# ${CONTRIBUTOR_TAG} Denis Glotov" amneziawg-install.sh; then
        fail "amneziawg-install.sh lost its contributor line for Denis Glotov"
        lost=1
    fi
    if [[ "${lost}" -eq 0 ]]; then
        pass "LICENSE and amneziawg-install.sh keep the upstream notices and contributor"
    fi
}

# The heterogeneous runtime collections are stored as LicenseRef texts so SPDX
# consumers receive the actual per-section terms, not a blanket MIT grant.
# Each copy must remain byte-identical to its packaging input, whose digest and
# platform mapping are checked by the version-2 policy. No other files get the
# aggregate-holder exemption in check_reuse.
check_boringtun_notice_metadata() {
    local bundle reference target toolchain
    while read -r bundle reference; do
        if [[ ! -f "${bundle}" || -L "${bundle}" || ! -f "${reference}" || -L "${reference}" ]] || \
            ! cmp -s -- "${bundle}" "${reference}"; then
            fail "${reference} must be an exact copy of the reviewed runtime notice bundle"
            return
        fi
    done <<'EOF'
packaging/boringtun/runtime-notices.txt LICENSES/LicenseRef-BoringTun-Runtime-Notices.txt
packaging/boringtun/runtime-notices-macos.txt LICENSES/LicenseRef-BoringTun-Runtime-Notices-macOS.txt
EOF
    toolchain="$(sed -n 's/^BORINGTUN_RUST_TOOLCHAIN=//p' packaging/boringtun/pin.env)"
    for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl armv7-unknown-linux-musleabihf \
        x86_64-apple-darwin aarch64-apple-darwin; do
        if ! BORINGTUN_NOTICE_CONFIG="${ROOT}/packaging/boringtun" python3 scripts/boringtun-notices.py bundle \
            "${toolchain}" --target "${target}" >/dev/null; then
            fail "the BoringTun runtime and fork notice inputs differ from the reviewed policy for ${target}"
            return
        fi
    done
    pass "BoringTun notice metadata preserves both reviewed upstream collections for all five targets"
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

check_holders() {
    local file entry dir bare license_years bad=0
    for file in LICENSE amneziawg-web/LICENSE amneziawg-proxy/LICENSE; do
        if ! grep -qxE "${NOTICE_PREFIX_RE} [0-9]{4}(-[0-9]{4})? ${MAINTAINER_RE}" "${file}"; then
            fail "${file} has no '${NOTICE_PREFIX} <year> ${MAINTAINER}' notice"
            bad=1
        fi
    done
    # Copyright tags (inline or in REUSE.toml) and LICENSE notices that name
    # WireSock without the individual behind it.
    # Case-insensitive, after any comment prefix, with or without "(c)" or ©.
    bare="$(git ls-files -z | xargs -0 grep -I -n -i -E \
        "(SPDX-FileCopyrightText[[:space:]]*[:=]|^[[:space:]#/*;!-]*copyright[[:space:]]).*wiresock" 2>/dev/null |
        grep -vF "${MAINTAINER}" || true)"
    if [[ -n "${bare}" ]]; then
        fail "copyright lines name WireSock without '${MAINTAINER}':"$'\n'"${bare}"
        bad=1
    fi
    # A file's years for the maintainer must lie within the years its crate's
    # LICENSE gives him: a 2027 file needs LICENSE to say 2026-2027, after which
    # the 2026 files stay valid.
    local first last years from to outside malformed
    for entry in ${CRATES}; do
        dir="${entry%%:*}"
        license_years="$(sed -E -n "s/^${NOTICE_PREFIX_RE} ([0-9]{4}(-[0-9]{4})?) ${MAINTAINER_RE}\$/\1/p" "${dir}/LICENSE")"
        if [[ -z "${license_years}" ]]; then
            fail "${dir}/LICENSE has no notice for ${MAINTAINER}"
            bad=1
            continue
        fi
        # Tags naming the maintainer must have the form the years are read from.
        malformed="$(git ls-files -z -- "${dir}" | xargs -0 grep -I -h -o -E "${COPYRIGHT_TAG} .*${MAINTAINER_RE}.*" 2>/dev/null |
            grep -vxE "${COPYRIGHT_TAG} (© )?[0-9]{4}(-[0-9]{4})? ${MAINTAINER_RE}" || true)"
        if [[ -n "${malformed}" ]]; then
            fail "${dir}: write the maintainer's tags as '${COPYRIGHT_TAG} <year>[-<year>] ${MAINTAINER}':"$'\n'"${malformed}"
            bad=1
        fi
        first="${license_years%%-*}"
        last="${license_years##*-}"
        outside=""
        while IFS= read -r years; do
            [[ -n "${years}" ]] || continue
            from="${years%%-*}"
            to="${years##*-}"
            if (( from < first || to > last || from > to )); then
                outside+="${years} "
            fi
        done < <(git ls-files -z -- "${dir}" |
            xargs -0 grep -I -h -o -E "${COPYRIGHT_TAG} (© )?[0-9]{4}(-[0-9]{4})? ${MAINTAINER_RE}\$" 2>/dev/null |
            sed -E "s/^${COPYRIGHT_TAG} (© )?([0-9-]+) .*/\2/" | LC_ALL=C sort -u)
        if [[ -n "${outside}" ]]; then
            fail "${dir}: SPDX headers give the year(s) ${outside% } for ${MAINTAINER}, outside the '${license_years}' of ${dir}/LICENSE"
            bad=1
        fi
    done
    if [[ "${bad}" -eq 0 ]]; then
        pass "LICENSE files and copyright tags name ${MAINTAINER} consistently"
    fi
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
check_inline_headers
check_license_dir
check_license_files
check_boringtun_notice_metadata
check_crates
check_holders
check_boringtun_policies
check_dependencies

if [[ "${FAILED}" -ne 0 ]]; then
    echo "Licensing checks failed; see docs/LICENSING.md." >&2
    exit 1
fi
echo "All licensing checks passed."
