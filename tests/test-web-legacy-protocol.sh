#!/usr/bin/env bash
# Run the real helper with only its params path redirected to a fixture.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT
# Load helper definitions with the params path redirected to the fixture.
# shellcheck disable=SC1090
source <(sed -e '/^main "\$@"$/d' -e "s|^readonly AWG_PARAMS_PATH=.*|readonly AWG_PARAMS_PATH=\"$WORK/params\"|" "$ROOT/amneziawg-web/scripts/amneziawg-web-privileged")
require_root() { :; }
# Fixture ownership stands in for the production root-owned params file.
validate_root_owned_file() { [[ "$1" == "$WORK/params" && "$2" == false ]]; }
validate_root_owned_directory() { [[ "$1" == "$AWG_CONFIG_ROOT" ]]; }
systemctl() {
    [[ "$*" == 'show -p ActiveState --value awg-quick@awg0.service' ]] || return 99
    printf 'active\n'
}
printf '%s\n' 'SERVER_AWG_NIC=awg0' 'SERVER_AWG_S1=84' 'SERVER_AWG_S2=150' 'SERVER_AWG_H1=1805140871' 'SERVER_AWG_H2=1806515711' 'SERVER_AWG_H3=434882725' 'SERVER_AWG_H4=1715363230' > "$WORK/legacy"
for version in absent 1 1.0; do
    cp "$WORK/legacy" "$WORK/params"
    [[ "$version" == absent ]] || printf "AWG_PROTOCOL_VERSION='%s'\n" "$version" >> "$WORK/params"
    [[ "$(main protocol-status)" == 1 ]]
done
# A legacy installer may treat unknown flags as mutations; AWG1 status must
# not execute it, including when params explicitly name version 1 or 1.0.
resolve_awg_install_script() {
    touch "$WORK/installer-resolved"
    printf '%s\n' "$WORK/installer"
}
cat > "$WORK/installer" <<'EOF'
#!/usr/bin/env bash
exit 99
EOF
chmod 700 "$WORK/installer"
before="$(sha256sum "$WORK/params")"
module=not-loaded
[[ ! -d /sys/module/amneziawg ]] || module=loaded
for version in absent 1 1.0; do
    cp "$WORK/legacy" "$WORK/params"
    [[ "$version" == absent ]] || printf "AWG_PROTOCOL_VERSION='%s'\n" "$version" >> "$WORK/params"
    before="$(sha256sum "$WORK/params")"
    [[ "$(main backend-status)" == "$(printf 'backend=kernel\nawg_protocol=1\nservice_state=active\nmodule_state=%s' "$module")" ]]
    [[ "$(sha256sum "$WORK/params")" == "$before" ]]
done
[[ "$(sha256sum "$WORK/params")" == "$before" ]]
for version in absent 1 1.0; do
    cp "$WORK/legacy" "$WORK/params"
    [[ "$version" == absent ]] || printf "AWG_PROTOCOL_VERSION='%s'\n" "$version" >> "$WORK/params"
    for operation in enable-awg31 disable-awg3; do
        if (main "$operation") > "$WORK/output" 2> "$WORK/error"; then
            echo 'FAIL: legacy protocol migration was accepted'; exit 1
        fi
        if [[ -e "$WORK/installer-resolved" ]]; then
            echo 'FAIL: legacy protocol migration reached installer resolution'; exit 1
        fi
        [[ ! -s "$WORK/output" ]]
        grep -q 'AWG 1.0.*installer' "$WORK/error"
    done
done
for backend in boringtun other 'kernel;touch /tmp/unexpected'; do
    cp "$WORK/legacy" "$WORK/params"
    printf "AWG_BACKEND='%s'\n" "$backend" >> "$WORK/params"
    if (main backend-status) > "$WORK/output" 2>/dev/null; then exit 1; fi
    [[ ! -s "$WORK/output" ]]
done
cp "$WORK/legacy" "$WORK/params"
printf "SERVER_AWG_S3='0'\nSERVER_AWG_S4='0'\n" >> "$WORK/params"
[[ "$(main protocol-status)" == 2 ]]
for version in 2 2.0 3 3.0 3.1; do
    printf "  AWG_PROTOCOL_VERSION='%s'\n" "$version" > "$WORK/params"
    expected="$version"
    [[ "$version" != *.0 ]] || expected="${version%.0}"
    [[ "$(main protocol-status)" == "$expected" ]]
done
printf "AWG_PROTOCOL_VERSION='4'\n" > "$WORK/params"
if (main protocol-status) >/dev/null 2>&1; then exit 1; fi
echo 'PASS: AWG 1.0 detection, explicit versions, migration rejection, and no params mutation'
