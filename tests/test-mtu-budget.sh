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
# Generic profiles use a final inner MTU. They must fit framing plus S4,
# and an explicit value must not bypass the owner's S4 maximum.
for candidate in 148:1280 148:1420 120:1380 140:1281; do
    IFS=: read -r s4 mtu <<<"${candidate}"
    result="$(
        SERVER_AWG_S4="${s4}" CLIENT_MTU="${mtu}"
        rc=0
        out="$(renderClientMtu 2>/dev/null)" || rc=$?
        printf '%s|%s' "${rc}" "${out}"
    )"
    expect '1|' "${result}" "generic MTU ${mtu} with S4 ${s4} exceeds the budget"
done
expect $'\nMTU = 1292' "$(CLIENT_MTU=1292 SERVER_AWG_S4=128 renderClientMtu)" 'generic final-inner MTU is not reduced a second time'
expect $'\nMTU = 1280' "$(CLIENT_MTU=1280 SERVER_AWG_S4=140 renderClientMtu)" 'manual S4 boundary140 preserves generic MTU1280'
result="$(CLIENT_MTU=1351 SERVER_AWG_S4=70 renderClientMtu 2>/dev/null)"; rc=$?
expect '1|' "${rc}|${result}" 'generic final-inner value must fit Linux framing'
for candidate in '198.51.100.1:20:0' '198.51.100.1:120:0' 'vpn.example.com:0:0' 'vpn.example.com:128:0'; do
    IFS=: read -r endpoint s4 want <<<"${candidate}"
    result="$(SERVER_PUB_IP="${endpoint}" CLIENT_MTU='' SERVER_AWG_S4="${s4}" renderClientMtu 2>/dev/null)"; rc=$?
    expect "${want}|" "${rc}|${result}" 'omission remains supported for clients that deduct S4 automatically'
done
warning="$(SERVER_PUB_IP=198.51.100.1 CLIENT_MTU='' SERVER_AWG_S4=120 warnIfClientMtuUnsafe 2>&1)"
expect 1 "$(grep -c 'Linux awg-quick' <<<"${warning}")" 'supported omission still warns about Linux automatic MTU'
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
    warnIfClientMtuUnsafe
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
# Fresh draws must fit the operator's requested value deterministically,
# rather than fail at random after choosing an incompatible S4.
fresh_limit() (
    SERVER_PUB_IP="$1" SERVER_PUB_NIC=mock0
    if [[ "$2" == unset ]]; then unset CLIENT_MTU; else CLIENT_MTU="$2"; fi
    # Capture the budget outside the stub's positional parameter scope.
    local path="$3" rc=0 out
    uplinkMtu() { printf '%s' "${path}"; }
    out="$(s4LimitForFreshInstall 2>/dev/null)" || rc=$?
    printf '%s|%s' "${rc}" "${out}"
)
expect '0|128' "$(fresh_limit vpn.example.com unset 1500)" 'fresh generation leaves12 bytes below the hard limit'
expect '0|40' "$(fresh_limit vpn.example.com 1380 1500)" 'supplied MTU limits every random draw'
expect '0|128' "$(fresh_limit 198.51.100.1 '' 1500)" 'explicit omission keeps the supported automatic calculation'
expect '0|128' "$(fresh_limit vpn.example.com '' 1500)" 'hostname omission is not rejected by assuming a Linux client'
expect '0|128' "$(fresh_limit vpn.example.com 1280 1500)" 'generic1280 is a final inner value'
expect '0|60' "$(fresh_limit vpn.example.com unset 1420)" 'known smaller uplink constrains fresh S4'
expect '1|' "$(fresh_limit vpn.example.com unset 1360)" 'known uplink with no S4 budget is rejected'
expect '0|128' "$(fresh_limit vpn.example.com unset 9000)" 'jumbo uplink does not inflate the assumed remote budget'
expect '0|1280' "$(recommend 140 1500)" 'hard140 is distinct from the generated128 ceiling'
expect '0|60' "$(fresh_limit 198.51.100.1 '' 1420)" 'omission still respects the known server outer budget'
# Exercise the actual sysfs fallback branch, not a replacement uplinkMtu.
# Only the value returned by read for the real loopback MTU file is substituted.
nic_budget="$(
    ip() { :; }
    read() {
        local rc=0
        builtin read "$@" || rc=$?
        if [[ "${*: -1}" == MTU ]]; then MTU=1200; fi
        return "${rc}"
    }
    uplinkMtu lo
)"
expect 1200 "${nic_budget}" 'a known low NIC MTU must not become an assumed1500'
fresh_warnings() (
    local path="$2"
    AUTO_INSTALL=y SERVER_PUB_IP=198.51.100.1 SERVER_PUB_NIC=mock0
    SERVER_AWG_NIC=awg0 SERVER_AWG_IPV4=10.66.66.1 SERVER_PORT=51820 ENABLE_IPV6=n
    AMNEZIAWG_DIR="${TMP}/fresh"
    if [[ "$1" == unset ]]; then unset CLIENT_MTU; else CLIENT_MTU="$1"; fi
    ip() { [[ "$1" != link ]] || return 1; }
    uplinkMtu() { printf '%s' "${path}"; }
    generateS1AndS2() { RANDOM_AWG_S1=30; RANDOM_AWG_S2=100; }
    generateS3AndS4() { RANDOM_AWG_S3=45; RANDOM_AWG_S4="$1"; }
    installQuestions
)
fresh_warnings unset 1500 >"${TMP}/auto-default.out" 2>"${TMP}/auto-default.err"
expect 0 "$?" 'automatic default still installs a valid generic budget'
expect 1 "$(grep -c 'Older WireSock' "${TMP}/auto-default.err")" 'automatic default warns before old-client import'
fresh_warnings '' 1500 >"${TMP}/auto-omitted.out" 2>"${TMP}/auto-omitted.err"
expect 0 "$?" 'automatic omitted MTU remains supported'
expect 1 "$(grep -c 'Linux awg-quick' "${TMP}/auto-omitted.err")" 'automatic omission emits the Linux warning'
fresh_warnings '' 1420 >"${TMP}/auto-smaller.out" 2>"${TMP}/auto-smaller.err"
expect 0 "$?" 'automatic omission can retain a known smaller server budget'
expect 1 "$(grep -c 'client-derived' "${TMP}/auto-smaller.err")" 'omission warning does not imply the server budget reaches the client'
printf 'MTU budget: %s passed, %s failed\n' "${PASSED}" "${FAILED}"
(( FAILED == 0 ))
