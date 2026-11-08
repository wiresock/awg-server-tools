#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Vadim Smirnov (doing business as WireSock)
# SPDX-License-Identifier: MIT
# Disposable-host BoringTun migration. Not a substitute for the manual
# checklist in docs/STATE_MIGRATION.md.
#
# source: install BoringTun, add one client, export to ${AWG_MIGRATION_OUT}.
# target: rename the default-route NIC to migup0, import, activate with
#         --enable-at-boot, compare material, handshake from a namespace.
#
# The client Endpoint is 192.0.2.1, the same TEST-NET-1 address
# tests/test-boringtun-host-live.sh puts on its veth. The target places that
# address on a veth and handshakes with the exported profile bytes. CI has no
# physical client; this is that namespace handshake, not a phone or WireSock.
#
# The passphrase file path is AWG_MIGRATION_PASSPHRASE_FILE. The passphrase is
# never placed in argv or in the environment. age reads it from the
# controlling terminal only (age 1.1.1 on Debian 12 prompts "Enter passphrase"
# and "Confirm passphrase").
set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }
[[ "${AWG_DISPOSABLE_HOST_TEST:-}" == 1 ]] || die "set AWG_DISPOSABLE_HOST_TEST=1 on a disposable host"
[[ "${EUID}" -eq 0 ]] || die "must run as root"
[[ -d /run/systemd/system ]] || die "systemd must be PID 1"
ROLE="${1:-}"
OUT="${AWG_MIGRATION_OUT:-}"
PASSFILE="${AWG_MIGRATION_PASSPHRASE_FILE:-}"
# The path is not a secret, but children do not need it. age must not see a
# passphrase in the environment; this variable is only a path, and it is
# dropped before any installer process starts.
unset AWG_MIGRATION_PASSPHRASE_FILE
[[ "${ROLE}" == source || "${ROLE}" == target ]] || die "usage: $0 source|target"
[[ -n "${OUT}" && -d "${OUT}" && ! -L "${OUT}" ]] || die "AWG_MIGRATION_OUT must be a directory"
[[ -f "${PASSFILE}" && ! -L "${PASSFILE}" && -s "${PASSFILE}" ]] || die "passphrase file must be a non-empty regular file"
[[ "$(stat -c %a "${PASSFILE}")" == 600 ]] || die "passphrase file must be mode 0600"
INSTALLER="${AWG_MIGRATION_INSTALLER:-/workspace/amneziawg-install.sh}"
[[ -f "${INSTALLER}" && ! -L "${INSTALLER}" ]] || die "installer not found"
command -v python3 >/dev/null || die "python3 is required"
command -v age >/dev/null || die "age is required"
command -v ip >/dev/null || die "ip is required"

# Feed age's tty prompts from the passphrase file. Count is 2 for export
# (entry and confirmation) and 1 for decrypt. Echo is disabled before exec so
# the passphrase is not written back to the transcript. Deadline is long
# because import installs packages and the BoringTun release after the prompt.
tty_run() {
	local COUNT="$1"
	shift
	python3 -I - "${COUNT}" "${PASSFILE}" "$@" <<'PY'
import os, select, sys, termios, time
try:
    import pty
except ImportError:
    sys.stderr.write("python3 pty is required\n")
    raise SystemExit(1)
count = int(sys.argv[1])
with open(sys.argv[2], "rb") as handle:
    secret = handle.read().splitlines()[0] + b"\n"
argv = sys.argv[3:]
pid, fd = pty.fork()
if pid == 0:
    try:
        settings = termios.tcgetattr(0)
        settings[3] &= ~termios.ECHO
        termios.tcsetattr(0, termios.TCSANOW, settings)
    except termios.error:
        os._exit(1)
    os.execvp(argv[0], argv)
sent = 0
pending = b""
deadline = time.monotonic() + 1500
hangup = False
try:
    while time.monotonic() < deadline:
        if not hangup:
            try:
                ready, _, _ = select.select([fd], [], [], 0.2)
            except (OSError, ValueError):
                hangup = True
                ready = []
            if ready:
                try:
                    data = os.read(fd, 4096)
                except OSError:
                    data = b""
                if not data:
                    # The slave can hang up as the child exits. That is the
                    # child's status, not a timed-out prompt.
                    hangup = True
                else:
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                    pending = (pending + data.lower())[-200:]
                    while sent < count and b"passphrase" in pending:
                        try:
                            os.write(fd, secret)
                        except OSError:
                            hangup = True
                            break
                        sent += 1
                        pending = pending.replace(b"passphrase", b"", 1)
        ended, status = os.waitpid(pid, os.WNOHANG)
        if ended:
            code = os.waitstatus_to_exitcode(status)
            if code == 0 and sent < count:
                sys.stderr.write("age exited before every passphrase prompt\n")
                raise SystemExit(1)
            raise SystemExit(code)
        if hangup:
            time.sleep(0.05)
    os.kill(pid, 9)
    os.waitpid(pid, 0)
    raise SystemExit("tty interaction timed out")
finally:
    os.close(fd)
PY
}

field() { # <file> <KEY>
	sed -n "s/^${2}='\\(.*\\)'\$/\\1/p" "$1" | head -n 1
}

default_nic() {
	ip -4 route show default | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}'
}

default_via() {
	ip -4 route show default | awk '{for (i = 1; i < NF; i++) if ($i == "via") { print $(i + 1); exit }}'
}

# Hashes only. The file is mode 0600 and is not a config.
material() { # <params> <server.conf> <client.conf> <outfile>
	local PARAMS="$1" CONF="$2" CLIENT="$3" DEST="$4" LINE
	{
		printf 'priv %s\n' "$(printf %s "$(field "${PARAMS}" SERVER_PRIV_KEY)" | sha256sum | cut -d' ' -f1)"
		printf 'pub %s\n' "$(printf %s "$(field "${PARAMS}" SERVER_PUB_KEY)" | sha256sum | cut -d' ' -f1)"
		for LINE in JC JMIN JMAX S1 S2 S3 S4 H1 H2 H3 H4; do
			printf 'obf %s %s\n' "${LINE}" "$(field "${PARAMS}" "SERVER_AWG_${LINE}")"
		done
		awk '
			/^[[:space:]]*PublicKey[[:space:]]*=/ { print "peer", $3 }
			/^[[:space:]]*PresharedKey[[:space:]]*=/ { print "psk", $3 }
		' "${CONF}" | while read -r KIND VALUE; do
			printf '%s %s\n' "${KIND}" "$(printf %s "${VALUE}" | sha256sum | cut -d' ' -f1)"
		done
		printf 'client %s\n' "$(sha256sum "${CLIENT}" | cut -d' ' -f1)"
	} >"${DEST}"
	chmod 600 "${DEST}"
}

NS=awgcli
VETH_HOST=awgvh0
VETH_CLIENT=awgvc0
HOST_ADDR=192.0.2.1
CLIENT_ADDR=192.0.2.2
CLIENT_IF=awgc0
IF=awg0
PORT=51820
CPID=""

cleanup_handshake() {
	if [[ -n "${CPID}" ]]; then
		kill "${CPID}" 2>/dev/null || true
		wait "${CPID}" 2>/dev/null || true
		CPID=""
	fi
	ip netns delete "${NS}" 2>/dev/null || true
	ip link delete "${VETH_HOST}" 2>/dev/null || true
	rm -f "/tmp/${CLIENT_IF}.conf" "/tmp/${CLIENT_IF}.setconf" /tmp/awg-mig-client-bin /tmp/mig-client.log
}
trap cleanup_handshake EXIT

if [[ "${ROLE}" == source ]]; then
	[[ ! -e /etc/amnezia/amneziawg/params ]] || die "AmneziaWG is already installed"
	NIC="$(default_nic)"
	[[ -n "${NIC}" && "${NIC}" != migup0 ]] || die "source uplink must exist and must not already be migup0"
	printf '%s\n' "${NIC}" >"${OUT}/source-nic"
	chmod 600 "${OUT}/source-nic"
	AWG_BACKEND=boringtun AUTO_INSTALL=y SERVER_PUB_IP="${HOST_ADDR}" SERVER_PUB_NIC="${NIC}" \
		SERVER_AWG_NIC="${IF}" SERVER_AWG_IPV4=10.66.66.1 SERVER_PORT="${PORT}" ENABLE_IPV6=n \
		CREATE_INITIAL_CLIENT=n bash "${INSTALLER}" </dev/null
	# --add-client prints the profile and a QR code. Keep that off the log.
	bash "${INSTALLER}" --add-client migrate1 >/dev/null
	CLIENT="/etc/amnezia/amneziawg/clients/${IF}-client-migrate1.conf"
	[[ -f "${CLIENT}" && ! -L "${CLIENT}" ]] || die "client profile was not written"
	install -m 600 "${CLIENT}" "${OUT}/client.conf"
	material /etc/amnezia/amneziawg/params "/etc/amnezia/amneziawg/${IF}.conf" "${OUT}/client.conf" "${OUT}/source.material"
	tty_run 2 bash "${INSTALLER}" --export-state "${OUT}/state.awgx"
	[[ -f "${OUT}/state.awgx" && ! -L "${OUT}/state.awgx" ]] || die "export did not write the archive"
	echo "source export complete"
	exit 0
fi

[[ -f "${OUT}/state.awgx" && -f "${OUT}/source.material" && -f "${OUT}/client.conf" && -f "${OUT}/source-nic" ]] || die "source outputs are missing"
[[ ! -e /etc/amnezia/amneziawg/params ]] || die "target must be a fresh host"
SRC_NIC="$(<"${OUT}/source-nic")"
UPLINK="$(default_nic)"
GATEWAY="$(default_via)"
[[ -n "${UPLINK}" && -n "${GATEWAY}" ]] || die "target has no IPv4 default route with a gateway"
# Renaming an up interface fails on these kernels. Taking it down drops the
# default route; the address stays, and the connected route returns on up.
# docker exec is by pid, not by the interface name.
if [[ "${UPLINK}" != migup0 ]]; then
	ip link set dev "${UPLINK}" down
	ip link set dev "${UPLINK}" name migup0
	ip link set dev migup0 up
	ip route replace default via "${GATEWAY}" dev migup0
fi
[[ -d /sys/class/net/migup0 ]] || die "failed to name the uplink migup0"
[[ "$(default_nic)" == migup0 ]] || die "default route is not via migup0 after the rename"
ip -4 addr show dev migup0 | grep -q 'inet ' || die "uplink lost its address during rename"
[[ "${SRC_NIC}" != migup0 ]] || die "source and target uplink names are both migup0"
export AUTO_INSTALL=y SERVER_PUB_NIC=migup0
tty_run 1 bash "${INSTALLER}" --import-state "${OUT}/state.awgx"
tty_run 1 bash "${INSTALLER}" --activate-state "${OUT}/state.awgx" --enable-at-boot
RESTORED="/etc/amnezia/amneziawg/clients/${IF}-client-migrate1.conf"
[[ -f "${RESTORED}" && ! -L "${RESTORED}" ]] || die "restored client profile is missing"
material /etc/amnezia/amneziawg/params "/etc/amnezia/amneziawg/${IF}.conf" "${RESTORED}" "${OUT}/target.material"
cmp -s "${OUT}/source.material" "${OUT}/target.material" || die "restored key, obfuscation, peer or client hash differs"
grep -q "^Endpoint = ${HOST_ADDR}:${PORT}\$" "${RESTORED}" || die "restored client profile Endpoint changed"
grep -qx "SERVER_PUB_NIC='migup0'" /etc/amnezia/amneziawg/params || die "restored params did not record migup0"
systemctl is-active --quiet "awg-quick@${IF}" || die "restored VPN is not active"

# Handshake. awg-quick strip takes the interface name from the file name, as
# in tests/test-boringtun-host-live.sh. The UAPI socket is created in the
# host mount namespace; awg setconf runs there, not in the netns.
ip netns add "${NS}"
ip link add "${VETH_HOST}" type veth peer name "${VETH_CLIENT}"
ip link set "${VETH_CLIENT}" netns "${NS}"
ip addr add "${HOST_ADDR}/24" dev "${VETH_HOST}"
ip link set "${VETH_HOST}" up
ip -n "${NS}" addr add "${CLIENT_ADDR}/24" dev "${VETH_CLIENT}"
ip -n "${NS}" link set "${VETH_CLIENT}" up
ip -n "${NS}" link set lo up
SERVER_PID="$(systemctl show -p MainPID --value "awg-quick@${IF}.service")"
[[ "${SERVER_PID}" =~ ^[1-9][0-9]*$ ]] || die "restored BoringTun is not running"
SERVER_EXE="$(readlink -f "/proc/${SERVER_PID}/exe")"
[[ "${SERVER_EXE##*/}" == boringtun-cli ]] || die "awg-quick MainPID is not boringtun-cli"
cp -f -- "/proc/${SERVER_PID}/exe" /tmp/awg-mig-client-bin
chmod 755 /tmp/awg-mig-client-bin
install -m 600 "${OUT}/client.conf" "/tmp/${CLIENT_IF}.conf"
awg-quick strip "/tmp/${CLIENT_IF}.conf" >"/tmp/${CLIENT_IF}.setconf"
CLIENT_TUNNEL="$(sed -n 's/^Address = \([0-9.]*\)\/32.*/\1/p' "${OUT}/client.conf" | head -n 1)"
SERVER_TUNNEL="$(field /etc/amnezia/amneziawg/params SERVER_AWG_IPV4)"
[[ -n "${CLIENT_TUNNEL}" && -n "${SERVER_TUNNEL}" ]] || die "could not read tunnel addresses"
ip netns exec "${NS}" env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin /tmp/awg-mig-client-bin \
	--foreground --disable-drop-privileges --verbosity error "${CLIENT_IF}" >/tmp/mig-client.log 2>&1 &
CPID=$!
READY=0
for _ in $(seq 1 50); do
	if [[ -S "/var/run/wireguard/${CLIENT_IF}.sock" ]]; then
		READY=1
		break
	fi
	sleep 0.2
done
if [[ "${READY}" != 1 ]]; then
	echo "client log:" >&2
	sed 's/^/    /' /tmp/mig-client.log >&2 || true
	die "namespace client socket did not appear"
fi
awg setconf "${CLIENT_IF}" "/tmp/${CLIENT_IF}.setconf"
ip -n "${NS}" addr add "${CLIENT_TUNNEL}/32" dev "${CLIENT_IF}"
ip -n "${NS}" link set "${CLIENT_IF}" up
ip -n "${NS}" route add "${SERVER_TUNNEL}/32" dev "${CLIENT_IF}"
ok=0
for _ in $(seq 1 40); do
	if ip netns exec "${NS}" ping -c 1 -W 1 "${SERVER_TUNNEL}" >/dev/null 2>&1; then
		ok=1
		break
	fi
	sleep 0.5
done
[[ "${ok}" == 1 ]] || die "client namespace did not reach the restored server"
awg show "${IF}" latest-handshakes | awk '{ if ($2 > 0) found = 1 } END { exit !found }' || die "server recorded no handshake"
echo "target restore and handshake complete"
