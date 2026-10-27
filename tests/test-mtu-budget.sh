#!/bin/bash
# SPDX-FileCopyrightText: 2026 Vadim Smirnov (doing business as WireSock)
# SPDX-License-Identifier: MIT
# Configuration admission, not a claim that an Internet path was measured.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT}/amneziawg-install.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
PASSED=0 FAILED=0
expect() {
    if [[ "$1" == "$2" ]]; then PASSED=$((PASSED + 1));
    else printf 'FAIL: %s: expected <%s>, got <%s>\n' "$3" "$1" "$2"; FAILED=$((FAILED + 1)); fi
}
recommend() (
    local rc=0 out
    out="$(recommendedMtuForS4 "$1" "$2" 2>/dev/null)" || rc=$?
    printf '%s|%s' "${rc}" "${out}"
)
expect '0|1280' "$(recommend 140 1500)" '1280 fits exactly at the conservative boundary'
expect '0|1292' "$(recommend 128 1500)" 'S4 is deducted exactly once'
expect '1|' "$(recommend 148 1500)" '1420 minus 148 is 1272, never rounded up'
expect '1|' "$(recommend 141 1500)" 'one byte below the minimum is rejected'
expect '0|1280' "$(recommend 60 1420)" 'an actual outer budget of 1420 is distinct from a baseline'
expect '1|' "$(recommend 148 1420)" 'a smaller outer budget cannot be treated as 1500'
expect '1|' "$(recommend 999999999999999999999 1500)" 'S4 cannot overflow arithmetic'
expect '1|' "$(recommend 20 999999999999999999999)" 'path budget cannot overflow arithmetic'
for endpoint in 198.51.100.1 2001:db8::1 '[2001:db8::1]' vpn.example.com ''; do
    result="$(
        SERVER_PUB_IP="${endpoint}" SERVER_AWG_S4=148 CLIENT_MTU=''
        rc=0
        out="$(renderClientMtu 2>/dev/null)" || rc=$?
        printf '%s|%s' "${rc}" "${out}"
    )"
    expect '1|' "${result}" "unsafe automatic client admission: ${endpoint:-unknown endpoint}"
done
# Explicit WireSock MTU semantics are awaiting owner confirmation. Do not
# rewrite exports or add a second S4 deduction while that fact is unknown.
expect $'\nMTU = 1280' "$(CLIENT_MTU=1280 SERVER_AWG_S4=148 renderClientMtu)" 'explicit export remains byte compatible'
expect '' "$(CLIENT_MTU='' SERVER_AWG_S4=128 renderClientMtu)" 'existing safe automatic export is preserved'
(
    SERVER_AWG_S4=148 CLIENT_MTU=''
    ensureAwgBackendReady() { touch "${TMP}/backend-touched"; exit 77; }
    newClient
) >"${TMP}/new.out" 2>"${TMP}/new.err"
rc=$?
expect 1 "${rc}" 'new client refusal precedes backend/key/file work'
expect absent "$(if [[ -e "${TMP}/backend-touched" ]]; then echo present; else echo absent; fi)" 'rejected creation has no backend side effect'
(
    SERVER_AWG_S4=148 CLIENT_MTU=''
    AMNEZIAWG_DIR="${TMP}/must-not-be-created"
    writeAwgServerInstallState
) >"${TMP}/install.out" 2>"${TMP}/install.err"
expect 1 "$?" 'fresh installation refuses before creating its state directory'
expect absent "$(if [[ -e "${TMP}/must-not-be-created" ]]; then echo present; else echo absent; fi)" 'rejected install leaves no state files'
(
    SERVER_AWG_S4=148 CLIENT_MTU=''
    AMNEZIAWG_DIR="${TMP}/existing"
    regenerateClients
) >"${TMP}/regenerate.out" 2>"${TMP}/regenerate.err"
expect 1 "$?" 'regeneration refuses unsafe automatic export before modifying profiles'
(
    SERVER_AWG_S4=148 CLIENT_MTU='' AWG_RANDOM_TRAILERS=on
    warnIfAutomaticClientMtuUnsafe
    printf '%s|%s|%s' "$?" "${SERVER_AWG_S4}" "${CLIENT_MTU}"
) >"${TMP}/legacy.out" 2>"${TMP}/legacy.err"
expect '0|148|' "$(cat "${TMP}/legacy.out")" 'legacy diagnostics succeed without changing values'
expect 1 "$(grep -c 'Existing settings were preserved' "${TMP}/legacy.err")" 'legacy warning explains preservation'
expect 1 "$(grep -c 'Changing MTU does not reset it' "${TMP}/legacy.err")" 'random trailer warning covers stale learned state'
for install in installBoringtunHost installAmneziaWG; do
    (
        ensureSupportedInstallDistro() { :; }
        selectFreshInstallBackend() { AWG_BACKEND=kernel; }
        selectFreshInstallImitation() { :; }
        checkBoringtunHostSupport() { :; }
        installQuestions() { SERVER_AWG_S4=148; CLIENT_MTU=''; SERVER_PUB_NIC=mock0; }
        uplinkMtu() { echo 1500; }
        enable_apt_ipv4() { touch "${TMP}/${install}-side-effect"; exit 77; }
        OS=unused
        "${install}"
    ) >"${TMP}/${install}.out" 2>"${TMP}/${install}.err"
    expect 1 "$?" "${install} refuses before package, scratch-interface or key work"
    expect absent "$(if [[ -e "${TMP}/${install}-side-effect" ]]; then echo present; else echo absent; fi)" "${install} never reaches side effects for an unsafe candidate"
done
printf 'MTU budget: %s passed, %s failed\n' "${PASSED}" "${FAILED}"
(( FAILED == 0 ))
