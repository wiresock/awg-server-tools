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

echo 'OK: export-state streams ciphertext and keeps the passphrase off argv, env, and stderr'
