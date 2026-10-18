#!/usr/bin/env bash
# Exercise the real transaction through the privileged helper. Only network,
# service and config-rendering operations are replaced; hook evaluation keeps
# awg-quick's command echo and arbitrary hook stdout/stderr behavior.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT
export ROOT WORK TMPDIR="$WORK"
# shellcheck disable=SC1090
source <(sed '/^main "\$@"$/d' "$ROOT/amneziawg-web/scripts/amneziawg-web-privileged")
require_root() { :; }
emit_protocol_status() { printf '2\n'; }
resolve_awg_install_script() { printf '%s\n' "$WORK/installer"; }

mkdir "$WORK/config"
printf '[Interface]\n' > "$WORK/config/awg0.conf"
printf 'SERVER_AWG_NIC=awg0\n' > "$WORK/config/params"
cat > "$WORK/installer" <<'INSTALLER'
#!/usr/bin/env bash
AWG_INSTALLER_CAPABILITY_PROTOCOL_DIAGNOSTICS="protocol-diagnostics-v1"
source "$ROOT/amneziawg-install.sh"
AMNEZIAWG_DIR="$WORK/config"
SERVER_AWG_CONF="$WORK/config/awg0.conf"
SERVER_AWG_NIC=awg0
renderAwgProtocolFields() { :; }
collectActiveAwgClientConfigs() { :; }
rewriteAwgProtocolConfig() { cp -- "$1" "$2"; }
serializeParams() { cp -- "$AMNEZIAWG_DIR/params" "$1"; }
if [[ "${TEST_VALIDATION:-0}" == 0 ]]; then
    validateStagedAwgConfigs() { return 0; }
fi
awgBackendCreateScratchInterface() { return 0; }
awgBackendDestroyScratchInterface() { return 0; }
awg() {
    [[ "$1" == setconf ]] || return 2
    printf 'Unable to modify interface: Invalid argument\n' >&2
    printf 'PrivateKey = short-secret-key\n' >&2
    return 1
}
systemctl() { return 1; }
ip() { return 0; }
awg-quick() {
    if [[ "$1" == strip ]]; then cat -- "$2"; else "$WORK/quick" "$@"; fi
}
awgBackendQuickUp() { "$WORK/quick" up "$@"; }
applyAwgProtocolTransaction
INSTALLER
cat > "$WORK/quick" <<'QUICK'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == "$HOOK_PHASE" ]] || exit 0
hook="$(cat "$WORK/hook")"
# awg-quick prints hooks before evaluating them. The shell started here also
# exposes any incorrectly inherited diagnostic descriptor to the hook.
echo "[#] $hook" >&2
(eval "$hook")
QUICK
chmod +x "$WORK/installer" "$WORK/quick"

FAILURES=0
for HOOK_PHASE in down up; do
    export HOOK_PHASE
    for mode in echo stderr spoofed descriptor; do
        case "$mode" in
            echo) printf '%s\n' 'API_TOKEN=review-dummy-secret false' > "$WORK/hook" ;;
            stderr) printf '%s\n' 'printf "arbitrary-hook-secret\n" >&2; false' > "$WORK/hook" ;;
            spoofed) printf '%s\n' 'printf "installer: ERROR: spoofed-hook-secret\n" >&2; false' > "$WORK/hook" ;;
            descriptor) printf '%s\n' 'printf "inherited-descriptor-secret\n" >&3; false' > "$WORK/hook" ;;
        esac
        rc=0
        (trap cleanup EXIT; main enable-awg31) > "$WORK/stdout" 2> "$WORK/stderr" || rc=$?
        if [[ "$rc" != 2 ]] || [[ -s "$WORK/stdout" ]]; then
            printf 'FAIL: %s/%s did not fail privately (exit %s)\n' "$HOOK_PHASE" "$mode" "$rc"
            FAILURES=$((FAILURES + 1))
        elif grep -Eq 'dummy-secret|hook-secret|descriptor-secret|\[#\]' "$WORK/stderr"; then
            printf 'FAIL: %s/%s leaked a hook command or secret through the helper\n' "$HOOK_PHASE" "$mode"
            cat "$WORK/stderr"
            FAILURES=$((FAILURES + 1))
        elif ! grep -q '^installer: ERROR: .*' "$WORK/stderr"; then
            printf 'FAIL: %s/%s lost the trusted transaction failure diagnostic\n' "$HOOK_PHASE" "$mode"
            FAILURES=$((FAILURES + 1))
        else
            printf 'PASS: %s/%s preserves the failure reason and withholds hook output\n' "$HOOK_PHASE" "$mode"
        fi
        if [[ -n "$(find "$WORK" -maxdepth 1 -name 'amneziawg-web-migration.*' -print -quit)" ]]; then
            printf 'FAIL: %s/%s left a private diagnostic file behind\n' "$HOOK_PHASE" "$mode"
            FAILURES=$((FAILURES + 1))
        fi
    done
done

# A real validator failure must keep the failed step, original config path
# and useful tool message, while its key-bearing line stays redacted.
export TEST_VALIDATION=1
rc=0
(trap cleanup EXIT; main enable-awg31) > "$WORK/stdout" 2> "$WORK/stderr" || rc=$?
if [[ "$rc" != 2 ]] ||
    ! grep -Fq "awg setconf rejected the server configuration ($WORK/config/awg0.conf)" "$WORK/stderr" ||
    ! grep -Fq 'Unable to modify interface: Invalid argument' "$WORK/stderr" ||
    grep -q 'short-secret-key' "$WORK/stderr"; then
    printf 'FAIL: validation diagnostic lost its step/file/tool message or exposed a key\n'
    cat "$WORK/stderr"
    FAILURES=$((FAILURES + 1))
else
    printf 'PASS: real validation preserves step/file/tool message and withholds keys\n'
fi
((FAILURES == 0))
