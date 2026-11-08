#!/usr/bin/env bash
# export-state is the only privileged-helper subcommand that writes a secret,
# and that secret is age ciphertext. The passphrase stays on the stdin pipe.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT
mkdir -p "$WORK/tmp"
export TMPDIR="$WORK/tmp"
# shellcheck disable=SC1090
source <(sed '/^main "\$@"$/d' "$ROOT/amneziawg-web/scripts/amneziawg-web-privileged")
require_root() { :; }
resolve_awg_install_script() { printf '%s\n' "$WORK/mock-installer.sh"; }
# Export refuses to start unless age, python3 and sqlite3 resolve on the
# helper PATH. The mock installer never executes them. When this machine does
# not have one, report a trusted path so the other tests still reach the mock.
if [[ -z "$(resolve_system_command age)" || -z "$(resolve_system_command python3)" || -z "$(resolve_system_command sqlite3)" ]]; then
    eval "$(declare -f resolve_system_command | sed '1s/^resolve_system_command/_resolve_system_command_real/')"
    resolve_system_command() {
        local found
        found="$(_resolve_system_command_real "$1")"
        if [[ -z "${found}" ]]; then
            case "$1" in
                age|python3|sqlite3)
                    printf '/usr/bin/%s\n' "$1"
                    return 0
                    ;;
            esac
        fi
        printf '%s\n' "${found}"
    }
fi

fail_test() {
    echo "FAIL: $1"
    [[ ! -e "$WORK/stderr" ]] || cat "$WORK/stderr" >&2
    exit 1
}

SECRET='stream-export-secret-value'
KEY='A/b+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
LONG="$(printf 'x%.0s' {1..400})"
UNIT="$ROOT/amneziawg-web/packaging/amneziawg-web.service"

grep -qxF 'AWG_INSTALLER_CAPABILITY_STATE_EXPORT_STREAM="state-export-stream-v1"' \
    "$ROOT/amneziawg-install.sh" \
    || fail_test 'installer is missing the streaming-export capability marker'
[[ "$(grep -c -- '--export-state - --passphrase-fd 0' \
    "$ROOT/amneziawg-web/scripts/amneziawg-web-privileged")" == 1 ]] \
    || fail_test 'streaming export must be invoked from exactly one helper site'
grep -q 'Only subcommand that emits a secret' \
    "$ROOT/amneziawg-web/scripts/amneziawg-web-privileged" \
    || fail_test 'helper does not record that export-state is the secret output'

# ProtectSystem=strict keeps the /dev API mount, including /dev/shm, and does
# not enable PrivateDevices. /run is not excluded, so it is read-only there.
# Checked against systemd.exec and this unit; this is not a live namespace.
# The unit file is stored with CR LF, so the carriage return is optional.
unit_line() {
    grep -q -E "^${1}"$'\r?$' "$UNIT"
}
unit_line 'ProtectSystem=strict' || fail_test 'panel service is not ProtectSystem=strict'
unit_line 'ProtectHome=yes' || fail_test 'panel service does not set ProtectHome'
unit_line 'PrivateTmp=yes' || fail_test 'panel service does not set PrivateTmp'
if grep -q -E $'^PrivateDevices=' "$UNIT"; then
    fail_test 'PrivateDevices would hide /dev and break sudo'
fi
unit_line 'ReadWritePaths=/var/lib/amneziawg-web' \
    || fail_test 'panel database directory is not writable in the sandbox'
unit_line 'ReadWritePaths=/etc/amnezia/amneziawg' \
    || fail_test 'AWG config directory is not writable in the sandbox'
grep -q 'for BASE in /dev/shm /run' "$ROOT/amneziawg-install.sh" \
    || fail_test 'state staging does not prefer /dev/shm'
grep -q 'ensure_installer_lifecycle_lock_dir' \
    "$ROOT/amneziawg-web/scripts/amneziawg-web-install.sh" \
    || fail_test 'panel installer does not pre-create the lifecycle lock directory'
grep -q 'lifecycle-lock-fallback=panel' "$ROOT/amneziawg-install.sh" \
    || fail_test 'installer has no panel-lock fallback for a read-only /var/lib'

run_export() {
    local rc=0
    printf '%s' "$SECRET" | (trap cleanup EXIT; main export-state) \
        >"$WORK/stdout" 2>"$WORK/stderr" || rc=$?
    printf '%s' "$rc"
}

cat > "$WORK/mock-installer.sh" <<MOCK
#!/bin/bash
AWG_INSTALLER_CAPABILITY_STATE_EXPORT_STREAM="state-export-stream-v1"
printf '%s\n' "\$@" > "${WORK}/argv"
tr '\\0' '\\n' < /proc/self/cmdline > "${WORK}/self-cmdline" || true
tr '\\0' '\\n' < /proc/self/environ > "${WORK}/self-environ" || true
tr '\\0' '\\n' < /proc/\$PPID/cmdline > "${WORK}/parent-cmdline" || true
tr '\\0' '\\n' < /proc/\$PPID/environ > "${WORK}/parent-environ" || true
sha256sum | awk '{print \$1}' > "${WORK}/stdin-sha"
printf 'age-encryption.org/v1\nCIPHERTEXT-ONLY\n'
printf 'PrivateKey = ${KEY}\n' >&2
printf 'stderr is dropped when export succeeds\n' >&2
exit 0
MOCK
chmod 0755 "$WORK/mock-installer.sh"
expected="$(printf '%s' "$SECRET" | sha256sum | awk '{print $1}')"
rc="$(run_export)"
[[ "$rc" == 0 ]] || fail_test "expected exit 0, got $rc"
[[ "$(head -n 1 "$WORK/stdout")" == 'age-encryption.org/v1' ]] \
    || fail_test 'stdout is not an age ciphertext header'
[[ ! -s "$WORK/stderr" ]] || fail_test 'successful export relayed installer stderr'
[[ "$(cat "$WORK/stdin-sha")" == "$expected" ]] || fail_test 'installer did not receive the passphrase on stdin'
[[ "$(cat "$WORK/argv")" == $'--export-state\n-\n--passphrase-fd\n0' ]] \
    || fail_test "installer argv was not the streaming mode: $(cat "$WORK/argv")"
for recorded in argv self-cmdline self-environ parent-cmdline parent-environ stdout stderr; do
    [[ -f "$WORK/$recorded" ]] || continue
    if grep -q -F -- "$SECRET" "$WORK/$recorded"; then
        fail_test "passphrase leaked into $recorded"
    fi
done
if grep -q -F -- "$KEY" "$WORK/stdout" "$WORK/stderr"; then
    fail_test 'a private key reached helper stdout or stderr'
fi
[[ -z "$(find "$WORK/tmp" -type f -print -quit)" ]] \
    || fail_test 'helper created a file in TMPDIR'

cat > "$WORK/mock-installer.sh" <<MOCK
#!/bin/bash
AWG_INSTALLER_CAPABILITY_STATE_EXPORT_STREAM="state-export-stream-v1"
i=0
while (( i < 20 )); do
    printf 'line %02d\n' "\$i" >&2
    i=\$((i + 1))
done
printf 'PrivateKey = ${KEY}\n' >&2
printf 'public key ${KEY} was rejected\n' >&2
printf '%s\n' '${LONG}' >&2
exit 1
MOCK
chmod 0755 "$WORK/mock-installer.sh"
rc="$(run_export)"
[[ "$rc" == 2 ]] || fail_test "expected exit 2 from a failed export, got $rc"
[[ ! -s "$WORK/stdout" ]] || fail_test 'failed export wrote ciphertext to stdout'
[[ "$(head -n 1 "$WORK/stderr")" == 'amneziawg-web-privileged: state export failed' ]] \
    || fail_test 'failure line is not the fixed helper message'
[[ "$(grep -c '^installer: ' "$WORK/stderr")" == 12 ]] \
    || fail_test "expected 12 relayed lines, got $(grep -c '^installer: ' "$WORK/stderr" || true)"
if grep -q -F -- "$SECRET" "$WORK/stderr" || grep -q -F -- "$KEY" "$WORK/stderr"; then
    fail_test 'failure diagnostics contained the passphrase or a key'
fi
grep -q '\[redacted\]' "$WORK/stderr" || fail_test 'key-shaped stderr was not redacted'
grep -q '\[truncated\]' "$WORK/stderr" || fail_test 'long diagnostic line was not truncated'
if grep -q -F -- "$SECRET" "$WORK/stdout"; then
    fail_test 'passphrase leaked into failed export stdout'
fi

printf '#!/bin/bash\ntouch %s\nexit 0\n' "$WORK/ran" > "$WORK/mock-installer.sh"
chmod 0755 "$WORK/mock-installer.sh"
rc="$(run_export)"
[[ "$rc" == 2 ]] || fail_test "expected exit 2 when the installer lacks the marker, got $rc"
[[ ! -e "$WORK/ran" ]] || fail_test 'helper executed an installer without the streaming marker'
grep -q 'cannot stream a state archive' "$WORK/stderr" \
    || fail_test 'missing marker did not produce the fixed error'

rc=0
(trap cleanup EXIT; main export-state) </dev/null >"$WORK/stdout" 2>"$WORK/stderr" || rc=$?
[[ "$rc" == 2 ]] || fail_test "expected exit 2 for a non-pipe passphrase, got $rc"
grep -q 'requires the passphrase on a pipe' "$WORK/stderr" \
    || fail_test 'non-pipe stdin was not refused'
[[ ! -s "$WORK/stdout" ]] || fail_test 'non-pipe refusal wrote stdout'

rc=0
printf '%s' "$SECRET" | (trap cleanup EXIT; main export-state extra) \
    >"$WORK/stdout" 2>"$WORK/stderr" || rc=$?
[[ "$rc" == 2 ]] || fail_test "expected exit 2 for an extra argument, got $rc"
grep -q 'expects 0 argument' "$WORK/stderr" || fail_test 'extra argument was not refused'

if command -v sqlite3 >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
    live="$WORK/live.db"
    sqlite3 "$live" 'PRAGMA journal_mode=WAL; CREATE TABLE peers(name TEXT); INSERT INTO peers VALUES ("phone");'
    python3 - "$live" <<'PY' &
import sqlite3, sys, time
connection = sqlite3.connect(sys.argv[1])
connection.execute('BEGIN')
connection.execute('SELECT * FROM peers')
time.sleep(20)
PY
    holder=$!
    sleep 0.3
    sqlite3 -readonly "$live" ".timeout 10000" ".backup '${WORK}/copy.db'" \
        || fail_test 'sqlite3 .backup failed while the database was open'
    kill "$holder" 2>/dev/null || true
    wait "$holder" 2>/dev/null || true
    [[ "$(sqlite3 "$WORK/copy.db" 'SELECT name FROM peers')" == phone ]] \
        || fail_test 'backup of the open database did not contain the row'
fi

cat > "$WORK/summary-installer.sh" <<MOCK
#!/bin/bash
AWG_INSTALLER_CAPABILITY_ENDPOINT_SUMMARY="endpoint-summary-v1"
printf '%s\n' "\$@" > "$WORK/summary-argv"
printf '4\n1\n'
printf 'PrivateKey = should-not-be-on-stdout\n' >&2
exit 0
MOCK
chmod 700 "$WORK/summary-installer.sh"
resolve_awg_install_script() { printf '%s\n' "$WORK/summary-installer.sh"; }
rc=0
# exit 2 inside the helper must not abort this script.
(trap cleanup EXIT; main endpoint-summary) >"$WORK/summary-out" 2>"$WORK/summary-err" || rc=$?
[[ "$rc" == 0 ]] || fail_test "endpoint-summary failed: $rc"
[[ "$(cat "$WORK/summary-out")" == $'4\n1' ]] || fail_test 'endpoint-summary did not print two counts'
[[ ! -s "$WORK/summary-err" ]] || fail_test 'successful endpoint-summary wrote stderr'
[[ "$(cat "$WORK/summary-argv")" == '--endpoint-summary' ]] \
    || fail_test 'endpoint-summary argv was not the read-only flag'
grep -q 'PrivateKey' "$WORK/summary-out" && fail_test 'endpoint count included a key'

cat > "$WORK/summary-installer.sh" <<MOCK
#!/bin/bash
AWG_INSTALLER_CAPABILITY_ENDPOINT_SUMMARY="endpoint-summary-v1"
printf 'PrivateKey = ${KEY}\n' >&2
printf 'public key ${KEY} was rejected\n' >&2
printf 'not counts\n'
exit 1
MOCK
rc=0
(trap cleanup EXIT; main endpoint-summary) >"$WORK/summary-out" 2>"$WORK/summary-err" || rc=$?
[[ "$rc" == 2 ]] || fail_test "bad endpoint-summary should exit 2, got $rc"
[[ ! -s "$WORK/summary-out" ]] || fail_test 'failed endpoint-summary wrote stdout'
grep -q 'PrivateKey' "$WORK/summary-err" && fail_test 'endpoint-summary stderr kept a key'
grep -q '\[redacted\]' "$WORK/summary-err" || fail_test 'endpoint-summary stderr was not redacted'

cat > "$WORK/summary-installer.sh" <<'MOCK'
#!/bin/bash
printf '1\n2\n'
exit 0
MOCK
rm -f "$WORK/summary-ran"
rc=0
(trap cleanup EXIT; main endpoint-summary) >"$WORK/summary-out" 2>"$WORK/summary-err" || rc=$?
[[ "$rc" == 2 ]] || fail_test 'missing endpoint marker should fail'
grep -q 'cannot summarize endpoints' "$WORK/summary-err" \
    || fail_test 'missing endpoint marker did not produce the fixed error'
[[ ! -s "$WORK/summary-out" ]] || fail_test 'missing marker wrote stdout'

# A missing age must fail before the installer starts. The installer is a
# capable mock; the capability check must not hide the missing-tool error.
# Command substitution strips the newline resolve_system_command prints
# when the tool is absent.
(
    resolve_awg_install_script() { printf '%s\n' "$WORK/mock-installer.sh"; }
    cat > "$WORK/mock-installer.sh" <<MOCK
#!/bin/bash
AWG_INSTALLER_CAPABILITY_STATE_EXPORT_STREAM="state-export-stream-v1"
touch "$WORK/ran"
printf '%s\n' "\$@" > "$WORK/argv"
exit 0
MOCK
    chmod 0755 "$WORK/mock-installer.sh"
    resolve_system_command() {
        if [[ "$1" == age ]]; then
            printf '\n'
        else
            printf '/usr/bin/%s\n' "$1"
        fi
    }
    rm -f "$WORK/argv" "$WORK/ran"
    rc=0
    printf '%s' "$SECRET" | (trap cleanup EXIT; main export-state) \
        >"$WORK/stdout" 2>"$WORK/stderr" || rc=$?
    [[ "$rc" == 2 ]] || fail_test "missing age should exit 2, got $rc"
    grep -q 'export-state requires age; rerun the panel upgrade' "$WORK/stderr" \
        || fail_test 'missing age did not produce the fixed message'
    [[ ! -e "$WORK/argv" && ! -e "$WORK/ran" ]] || fail_test 'missing age started the installer'
    [[ ! -s "$WORK/stdout" ]] || fail_test 'missing age wrote stdout'
)
resolve_awg_install_script() { printf '%s\n' "$WORK/mock-installer.sh"; }

cat > "$WORK/mock-installer.sh" <<MOCK
#!/bin/bash
AWG_INSTALLER_CAPABILITY_STATE_EXPORT_STREAM="state-export-stream-v1"
printf '%s\\n' "\$\$" > "$WORK/installer.pid"
sleep 60 &
printf '%s\\n' "\$!" > "$WORK/sleep.pid"
sleep 60
MOCK
chmod 0755 "$WORK/mock-installer.sh"
rm -f "$WORK/installer.pid" "$WORK/sleep.pid"
printf '%s' "$SECRET" | (trap cleanup EXIT; main export-state) \
    >"$WORK/stdout" 2>"$WORK/stderr" &
helper_pid=$!
ready=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if [[ -s "$WORK/installer.pid" && -s "$WORK/sleep.pid" ]]; then
        ready=1
        break
    fi
    sleep 0.1
done
[[ "$ready" == 1 ]] || fail_test 'installer did not record its process group'
kill -s TERM -- "$helper_pid" || true
wait "$helper_pid" 2>/dev/null || true
installer_pid="$(cat "$WORK/installer.pid")"
sleep_pid="$(cat "$WORK/sleep.pid")"
gone=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if ! kill -0 "$installer_pid" 2>/dev/null && ! kill -0 "$sleep_pid" 2>/dev/null; then
        gone=1
        break
    fi
    sleep 0.1
done
[[ "$gone" == 1 ]] || fail_test "SIGTERM left installer ${installer_pid} or sleep ${sleep_pid} running"

install_sh="$ROOT/amneziawg-web/scripts/amneziawg-web-install.sh"
upgrade_sh="$ROOT/amneziawg-web/scripts/amneziawg-web-upgrade.sh"
diff -q <(sed -n '/^ensure_state_export_dependencies()/,/^}/p' "$install_sh") \
    <(sed -n '/^ensure_state_export_dependencies()/,/^}/p' "$upgrade_sh") \
    || fail_test 'install and upgrade state-export dependency functions differ'
grep -q 'ensure_state_export_dependencies$' <(sed -n '/^main()/,/^}/p' "$install_sh") \
    || fail_test 'panel install does not install age'
grep -q 'ensure_state_export_dependencies$' <(sed -n '/^main()/,/^}/p' "$upgrade_sh") \
    || fail_test 'panel upgrade does not install age'

(
    body="$(sed -n '/^ensure_state_export_dependencies()/,/^}/p' "$install_sh")"
    body="${body//\/etc\/os-release/${WORK}/os-release}"
    body="${body//\/etc\/apt\/apt.conf.d\/99amneziawg-force-ipv4/${WORK}/force-ipv4.conf}"
    info() { printf 'INFO %s\n' "$*"; }
    warn() { printf 'WARN %s\n' "$*" >&2; }
    command() {
        if [[ "$1" == -v ]]; then
            case "${2:-}" in
                apt-get) return 0 ;;
                age|python3|sqlite3) return 1 ;;
            esac
            return 1
        fi
        builtin command "$@"
    }
    apt-get() {
        printf '%s\n' "$*" >>"$WORK/apt-args"
        if [[ "$1" == install ]]; then
            grep -q 'Acquire::ForceIPv4 "true";' "$WORK/force-ipv4.conf" || return 9
            printf 'APT-STDOUT\n'
        fi
        return 0
    }
    printf 'ID=debian\n' >"$WORK/os-release"
    # shellcheck disable=SC1090
    eval "$body"
    ensure_state_export_dependencies >"$WORK/dep-out" 2>"$WORK/dep-err"
    if grep -q APT-STDOUT "$WORK/dep-out"; then
        fail_test 'apt stdout was not captured'
    fi
    grep -q 'install -y -qq age python3 sqlite3' "$WORK/apt-args" \
        || fail_test 'age was not installed with apt-get'
    [[ ! -e "$WORK/force-ipv4.conf" ]] || fail_test 'temporary ForceIPv4 config was left behind'
    rm -f "$WORK/apt-args"
    printf 'ID=linuxmint\nID_LIKE=ubuntu\n' >"$WORK/os-release"
    ensure_state_export_dependencies >/dev/null
    grep -q install "$WORK/apt-args" || fail_test 'Linux Mint did not install age'
    rm -f "$WORK/apt-args" "$WORK/force-ipv4.conf"
    printf 'ID=fedora\nID_LIKE=\n' >"$WORK/os-release"
    ensure_state_export_dependencies >"$WORK/dep-out" 2>"$WORK/dep-err"
    [[ ! -e "$WORK/apt-args" ]] || fail_test 'a non-Debian OS tried to install age'
    grep -q 'Skipping age' "$WORK/dep-err" || fail_test 'non-Debian skip was not explained'
)

echo 'OK: export-state streams ciphertext and keeps the passphrase off argv, env, and stderr'
