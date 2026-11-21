#!/usr/bin/env bash
# Opt-in check that closing an export stops age under real sudo.
# Enable with AWG_TEST_REAL_SUDO=1 and run as root in a disposable container.
# It creates a throwaway user and a sudoers drop-in and removes both on exit.
set -euo pipefail

if [[ "${AWG_TEST_REAL_SUDO:-}" != 1 ]]; then
    echo "skip: set AWG_TEST_REAL_SUDO=1 to run the real sudo export shutdown test"
    exit 0
fi
[[ "$(id -u)" -eq 0 ]] || { echo "real sudo export test must run as root" >&2; exit 1; }
[[ ! -e /etc/amnezia/amneziawg/params ]] || {
    echo "refusing to run: /etc/amnezia/amneziawg/params already exists" >&2
    exit 1
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
USER_NAME=awg-export-test
HELPER=/usr/local/libexec/amneziawg-web-privileged
INSTALLER=/usr/local/bin/amneziawg-install.sh
SUDOERS=/etc/sudoers.d/awg-export-test
UNIT=/etc/systemd/system/amneziawg-web.service
WEB_ROOT=/etc/amneziawg-web
OUTER_PID=""

cleanup() {
    if [[ -n "${OUTER_PID}" ]]; then
        kill -s TERM -- "${OUTER_PID}" 2>/dev/null || true
        wait "${OUTER_PID}" 2>/dev/null || true
        OUTER_PID=""
    fi
    pkill -TERM -x age 2>/dev/null || true
    pkill -TERM -f "${INSTALLER}" 2>/dev/null || true
    rm -f -- "${SUDOERS}" "${UNIT}" "${INSTALLER}" "${HELPER}"
    rm -rf -- /etc/amnezia /dev/shm/awg-state.* /run/awg-state.* "${WEB_ROOT}"
    if id "${USER_NAME}" >/dev/null 2>&1; then
        userdel "${USER_NAME}"
    fi
}
trap cleanup EXIT

echo "sudo: $(sudo -V | head -n 1)"
if grep -n 'use_pty' /etc/sudoers; then
    echo "sudoers: Defaults use_pty is present"
else
    echo "sudoers: Defaults use_pty is not set"
fi

install -d -m 755 /usr/local/libexec /etc/amnezia/amneziawg/clients "${WEB_ROOT}"
install -m 755 "${ROOT}/amneziawg-install.sh" "${INSTALLER}"
install -m 755 "${ROOT}/amneziawg-web/scripts/amneziawg-web-privileged" "${HELPER}"
printf '%s\n' "${INSTALLER}" >"${WEB_ROOT}/installed-awg-script.path"
chmod 644 "${WEB_ROOT}/installed-awg-script.path"
cat >"${UNIT}" <<'UNIT'
[Service]
EnvironmentFile=/etc/amneziawg-web/awg-web.env
ExecStart=/opt/amneziawg-web/bin/amneziawg-web
UNIT
chmod 644 "${UNIT}"
python3 - <<'PY'
import base64
import sqlite3
from pathlib import Path

key = base64.b64encode(b"A" * 32).decode()
pub = base64.b64encode(b"B" * 32).decode()
peer = base64.b64encode(b"C" * 32).decode()
names = (
    "SERVER_PUB_IP SERVER_PUB_NIC SERVER_AWG_NIC SERVER_AWG_IPV4 SERVER_AWG_IPV6 "
    "SERVER_PORT SERVER_PRIV_KEY SERVER_PUB_KEY CLIENT_DNS_1 CLIENT_DNS_2 CLIENT_MTU "
    "ALLOWED_IPS ENABLE_IPV6 SERVER_AWG_JC SERVER_AWG_JMIN SERVER_AWG_JMAX "
    "SERVER_AWG_S1 SERVER_AWG_S2 SERVER_AWG_S3 SERVER_AWG_S4 SERVER_AWG_H1 "
    "SERVER_AWG_H2 SERVER_AWG_H3 SERVER_AWG_H4 AWG_BACKEND AWG_PROTOCOL_VERSION "
    "AWG_HEADER_PROTECTION_KEY AWG_CONTENT_PADDING_ADDITION AWG_REKEY_AFTER_TIME "
    "AWG_REKEY_TIMEOUT AWG_REJECT_AFTER_TIME AWG_KEEPALIVE_TIMEOUT AWG_RANDOM_TRAILERS "
    "AWG_DISABLE_COOKIES AWG_BORINGTUN_IMITATE_PROTOCOL AWG_BORINGTUN_IMITATE_DOMAIN"
).split()
values = {name: "" for name in names}
values.update(
    SERVER_PUB_IP="vpn.example.test",
    SERVER_PUB_NIC="eth0",
    SERVER_AWG_NIC="awg0",
    SERVER_AWG_IPV4="10.66.66.1",
    SERVER_AWG_IPV6="fd42:42:42::1",
    SERVER_PORT="51820",
    SERVER_PRIV_KEY=key,
    SERVER_PUB_KEY=pub,
    CLIENT_DNS_1="1.1.1.1",
    ALLOWED_IPS="0.0.0.0/0,::/0",
    ENABLE_IPV6="n",
    AWG_BACKEND="kernel",
    AWG_PROTOCOL_VERSION="2",
    AWG_BORINGTUN_IMITATE_PROTOCOL="none",
)
for suffix, value in (
    ("JC", "4"), ("JMIN", "40"), ("JMAX", "70"),
    ("S1", "15"), ("S2", "16"), ("S3", "17"), ("S4", "18"),
    ("H1", "1"), ("H2", "2"), ("H3", "3"), ("H4", "4"),
):
    values["SERVER_AWG_" + suffix] = value
root = Path("/etc/amnezia/amneziawg")
(root / "params").write_text("".join("%s='%s'\n" % (name, values[name]) for name in names))
conf = "[Interface]\nAddress = 10.66.66.1/24\nPrivateKey = %s\nListenPort = 51820\n" % key
for suffix, field in (
    ("JC", "Jc"), ("JMIN", "Jmin"), ("JMAX", "Jmax"),
    ("S1", "S1"), ("S2", "S2"), ("S3", "S3"), ("S4", "S4"),
    ("H1", "H1"), ("H2", "H2"), ("H3", "H3"), ("H4", "H4"),
):
    conf += "%s = %s\n" % (field, values["SERVER_AWG_" + suffix])
conf += "\n### Client phone\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = 10.66.66.2/32\n" % (peer, pub)
(root / "awg0.conf").write_text(conf)
client = (
    "[Interface]\nPrivateKey = %s\nAddress = 10.66.66.2/32\n"
    "[Peer]\nPublicKey = %s\nEndpoint = vpn.example.test:51820\nAllowedIPs = 0.0.0.0/0\n"
) % (peer, pub)
(root / "clients" / "awg0-client-phone.conf").write_text(client)
db = Path("/etc/amneziawg-web/awg-web.db")
connection = sqlite3.connect(db)
connection.execute(
    "CREATE TABLE peers ("
    "public_key TEXT PRIMARY KEY, disabled INTEGER NOT NULL, "
    "archived INTEGER NOT NULL, removal_pending INTEGER NOT NULL, expires_at TEXT)"
)
connection.commit()
connection.close()
Path("/etc/amneziawg-web/awg-web.env").write_text("AWG_WEB_DB=/etc/amneziawg-web/awg-web.db\n")
PY
chmod 700 /etc/amnezia /etc/amnezia/amneziawg /etc/amnezia/amneziawg/clients "${WEB_ROOT}"
chmod 600 /etc/amnezia/amneziawg/params /etc/amnezia/amneziawg/awg0.conf \
    /etc/amnezia/amneziawg/clients/awg0-client-phone.conf \
    "${WEB_ROOT}/awg-web.db" "${WEB_ROOT}/awg-web.env"
chown -R root:root /etc/amnezia /etc/amneziawg-web /etc/systemd/system/amneziawg-web.service \
    "${INSTALLER}" "${HELPER}"

if ! id "${USER_NAME}" >/dev/null 2>&1; then
    useradd --system --create-home --shell /usr/sbin/nologin "${USER_NAME}"
fi

write_sudoers() {
    local pty_line="$1"
    {
        if [[ -n "${pty_line}" ]]; then
            printf '%s\n' "${pty_line}"
        fi
        printf '%s\n' "${USER_NAME} ALL=(root) NOPASSWD: ${HELPER}"
    } >"${SUDOERS}"
    chmod 440 "${SUDOERS}"
    visudo -cf "${SUDOERS}" >/dev/null
}

assert_stopped() {
    local label="$1"
    local deadline=$((SECONDS + 8))
    local staging
    while (( SECONDS < deadline )); do
        if ! pgrep -x age >/dev/null 2>&1 \
            && ! pgrep -f "${INSTALLER}" >/dev/null 2>&1 \
            && ! pgrep -f "${HELPER}" >/dev/null 2>&1; then
            staging="$(find /dev/shm /run -maxdepth 1 -name 'awg-state.*' -print 2>/dev/null || true)"
            if [[ -z "${staging}" ]]; then
                echo "${label}: age, installer and staging are gone"
                return 0
            fi
        fi
        sleep 0.2
    done
    echo "${label}: export did not stop within the grace period" >&2
    ps -ef | grep -E 'age|amneziawg' | grep -v grep >&2 || true
    find /dev/shm /run -maxdepth 1 -name 'awg-state.*' -print >&2 || true
    return 1
}

run_case() {
    local label="$1"
    local work pass_fifo out_fifo err_file
    work="$(mktemp -d /dev/shm/awg-sudo-test.XXXXXXXX)"
    pass_fifo="${work}/pass"
    out_fifo="${work}/out"
    err_file="${work}/err"
    mkfifo "${pass_fifo}" "${out_fifo}"
    : >"${err_file}"
    # Redirects stay in this root shell. sudo must not own the fifo opens.
    # shellcheck disable=SC2024
    sudo -u "${USER_NAME}" /usr/bin/sudo -n "${HELPER}" export-state \
        <"${pass_fifo}" >"${out_fifo}" 2>"${err_file}" &
    OUTER_PID=$!
    # Unblock the fifo open, then close our reader so the panel's disconnect
    # is the close plus SIGTERM to sudo, not a stuck writer.
    # Open both fifo ends before writing. The helper's shell opens stdin,
    # then stdout, and only then execs. Writing earlier can deadlock.
    exec 3>"${pass_fifo}"
    exec 4<"${out_fifo}"
    printf '%s' '0123456789abcdef' >&3
    exec 3>&-
    local seen=0 sudo_pid user_uid
    local deadline=$((SECONDS + 20))
    while (( SECONDS < deadline )); do
        if pgrep -x age >/dev/null 2>&1; then
            seen=1
            break
        fi
        if ! kill -0 "${OUTER_PID}" 2>/dev/null; then
            echo "${label}: helper exited before age started" >&2
            cat "${err_file}" >&2 || true
            return 1
        fi
        sleep 0.02
    done
    [[ "${seen}" == 1 ]] || {
        echo "${label}: age did not start" >&2
        cat "${err_file}" >&2 || true
        return 1
    }
    # The panel signals the sudo it spawned. That process keeps the invoking
    # user's real uid, so the user can signal it, and sudo relays TERM.
    # Matching the helper path with pgrep also hits the outer root sudo -u
    # and can walk up to pid 1. Select the test user's sudo instead.
    user_uid="$(id -u "${USER_NAME}")"
    sudo_pid="$(ps -eo pid=,ruid=,args= | awk -v uid="${user_uid}" -v helper="${HELPER}" '
        $2 == uid && index($0, "sudo") && index($0, helper) { print $1; exit }
    ')"
    if [[ -z "${sudo_pid}" || "${sudo_pid}" == 1 ]]; then
        echo "${label}: could not find the test user's sudo" >&2
        ps -eo pid,ppid,ruid,euid,args >&2 || true
        return 1
    fi
    if ! pgrep -x age >/dev/null 2>&1; then
        echo "${label}: age exited before the disconnect" >&2
        ps -eo pid,ppid,ruid,euid,args >&2 || true
        return 1
    fi
    echo "${label}: signaling sudo pid ${sudo_pid} as ${USER_NAME}"
    ps -o pid,ppid,ruid,euid,args -p "${sudo_pid}" || true
    # Close the reader the way a disconnected panel does, then SIGTERM sudo.
    exec 4<&-
    if ! sudo -u "${USER_NAME}" kill -s TERM -- "${sudo_pid}"; then
        echo "${label}: the test user could not signal sudo ${sudo_pid}" >&2
        ps -eo pid,ppid,ruid,euid,args >&2 || true
        return 1
    fi
    assert_stopped "${label}"
    wait "${OUTER_PID}" 2>/dev/null || true
    OUTER_PID=""
    rm -rf -- "${work}"
}

write_sudoers ""
run_case "use_pty-default"
write_sudoers "Defaults:${USER_NAME} !use_pty"
run_case "use_pty-disabled"
echo "OK: real sudo disconnect stops age, the installer and staging"
