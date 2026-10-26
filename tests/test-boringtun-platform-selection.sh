#!/usr/bin/env bash
# shellcheck disable=SC2034 # fixtures set globals read by the sourced installer
# Platform-selection and retained-store regressions. Host identity is simulated;
# fixture executables are shell scripts, not evidence of native ARM execution.
# All filesystem writes remain in a private temporary directory.
set -uo pipefail
SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd -P)"
# shellcheck source=../amneziawg-install.sh
source "${PROJECT_ROOT}/amneziawg-install.sh"
# shellcheck source=helpers/boringtun-contracts.sh
source "${SCRIPT_DIR}/helpers/boringtun-contracts.sh"
T="$(mktemp -d "${TMPDIR:-/tmp}/boringtun-platform-tests.XXXXXX")"
trap 'rm -rf -- "${T}"' EXIT
chmod 0755 "${T}"
mkdir -p "${T}/bin" "${T}/store"
for NAME in uname dpkg; do
	printf '#!/bin/bash\ncat %q\n' "${T}/${NAME}" >"${T}/bin/${NAME}"
	chmod 0755 "${T}/bin/${NAME}"
done
PATH="${T}/bin:${PATH}"
AWG_BT_PATH="${PATH}"
AWG_BT_HOST_ARCH=""
AWG_BT_TRUST_ANCHOR="${T}"
AWG_BT_TRUSTED_UID="$(id -u)"
AWG_BT_STORE_DIR="${T}/store"
PASS=0 FAIL=0
check() {
	local WANT="$1" LABEL="$2" RC=0
	shift 2
	"$@" >"${T}/out" 2>"${T}/err" || RC=$?
	if [[ "${RC}" == "${WANT}" ]]; then
		printf '  OK: %s\n' "${LABEL}"; PASS=$((PASS + 1))
	else
		printf '  FAIL: %s (expected %s, got %s)\n' "${LABEL}" "${WANT}" "${RC}"
		cat "${T}/err"; FAIL=$((FAIL + 1))
	fi
}
equal() { [[ "$1" == "$2" ]]; }
host() { printf '%s\n' "$1" >"${T}/dpkg"; printf '%s\n' "$2" >"${T}/uname"; }
preferred() { equal "$1" "$(_awgBtHostArch)"; }

host amd64 x86_64
check 0 'native amd64 selects x86_64' preferred x86_64
host arm64 aarch64
check 0 'native arm64 selects aarch64' preferred aarch64
host armhf armv7l
check 0 'native ARMv7 hard-float selects armv7' preferred armv7
host armhf armv8l
check 0 'AArch32 ARMv8 hard-float selects armv7' preferred armv7
host armhf aarch64
check 0 '32-bit userland on a 64-bit kernel selects armv7' preferred armv7
host armhf armv6l
check 1 'Raspberry Pi ARMv6 armhf is rejected' _awgBtHostArch
host armel armv7l
check 1 'soft-float userland is rejected' _awgBtHostArch
host i386 x86_64
check 1 'a 64-bit kernel alone does not select a new 64-bit userland install' _awgBtHostArch
host unknown aarch64
check 1 'unknown userland fails closed' _awgBtHostArch

host armhf aarch64
_awgBtSelectRelease x86_64
check 1 'unpublished ARMv7 release cannot be selected' _awgBtSelectRelease armv7
SELECTION_ERROR="$(cat "${T}/err")"
check 0 'failed selection clears the previous release asset' equal '' "${_AWG_BT_REL_ASSET}"
contains() { [[ "$2" == *"$1"* ]]; }
check 0 'unpublished target reports why it cannot install' contains 'not yet been published and adopted' "${SELECTION_ERROR}"
check 0 'ARMv7 uses its hard-float target triple' equal armv7-unknown-linux-musleabihf "$(_awgBtTarget armv7 2>/dev/null)"
check 0 'ARMv7 store uses its distinct ABI suffix' equal \
	boringtun-cli-0.7.1-g123456789abc-b2-linux-armv7-musleabihf \
	"$(_awgBtReleaseStoreId 0.7.1 123456789abcdef0123456789abcdef0123456789a 2 armv7)"
check 0 'ARMv7 store identity is accepted' _awgBtReleaseIdValid boringtun-cli-0.7.1-g123456789abc-linux-armv7-musleabihf
check 1 'ambiguous ARMv7 musl-only identity is rejected' _awgBtReleaseIdValid boringtun-cli-0.7.1-g123456789abc-linux-armv7-musl
check 1 'ARM64 cannot claim the ARMv7 ABI suffix' _awgBtReleaseIdValid boringtun-cli-0.7.1-g123456789abc-linux-aarch64-musleabihf

fixture() { # <id> <arch> <target> <commit>
	local DIR="${AWG_BT_STORE_DIR}/$1" ARCH="$2" TARGET="$3" COMMIT="$4" KEY VALUE HASH
	mkdir -p "${DIR}"
	printf '#!/bin/sh\nprintf "boringtun 0.7.1\\n"\n' >"${DIR}/boringtun-cli"
	chmod 0755 "${DIR}" "${DIR}/boringtun-cli"
	printf 'fixture license\n' >"${DIR}/LICENSE"
	printf 'fixture notices\n' >"${DIR}/THIRD-PARTY-LICENSES"
	HASH="$(sha256sum "${DIR}/boringtun-cli" | cut -d' ' -f1)"
	for KEY in ${AWG_BT_MANIFEST_KEYS}; do
		VALUE=fixture
		case "${KEY}" in
			artifact_format) VALUE=1 ;; name | binary) VALUE=boringtun-cli ;;
			version) VALUE=0.7.1 ;; source_repository) VALUE="${AWG_BT_RELEASE_SOURCE_REPOSITORY}" ;;
			source_commit) VALUE="${COMMIT}" ;; target) VALUE="${TARGET}" ;; arch) VALUE="${ARCH}" ;;
			os) VALUE=linux ;; libc) VALUE=musl ;; linkage) VALUE=static ;;
			binary_sha256) VALUE="${HASH}" ;; license) VALUE=LICENSE ;; third_party_licenses) VALUE=THIRD-PARTY-LICENSES ;;
		esac
		printf '%s=%s\n' "${KEY}" "${VALUE}"
	done >"${DIR}/MANIFEST"
	chmod 0644 "${DIR}/LICENSE" "${DIR}/THIRD-PARTY-LICENSES" "${DIR}/MANIFEST"
}
OLD=boringtun-cli-0.7.1-g111111111111-linux-aarch64-musl
ARM=boringtun-cli-0.7.1-g222222222222-linux-armv7-musleabihf
fixture "${OLD}" aarch64 aarch64-unknown-linux-musl 1111111111111111111111111111111111111111
fixture "${ARM}" armv7 armv7-unknown-linux-musleabihf 2222222222222222222222222222222222222222
ln -s "${OLD}" "${AWG_BT_STORE_DIR}/current"
check 0 'mixed-bitness host retains a verified static ARM64 store' _awgBtVerifyStore
check 0 'mixed-bitness host also accepts a verified ARMv7 store' _awgBtVerifyRelease "${ARM}"
host armhf armv7l
check 1 '32-bit kernel rejects the retained ARM64 store' _awgBtVerifyStore
check 0 '32-bit kernel accepts the ARMv7 store' _awgBtVerifyRelease "${ARM}"
host arm64 aarch64
check 1 'ARM64 userland does not imply kernel AArch32 support' _awgBtVerifyRelease "${ARM}"
host armhf aarch64

check_arm_candidate() (
	AWG_BT_RELEASE_SOURCE_COMMIT=2222222222222222222222222222222222222222
	_AWG_BT_REL_BINARY_SHA256="$(sha256sum "${AWG_BT_STORE_DIR}/${ARM}/boringtun-cli" | cut -d' ' -f1)"
	_AWG_BT_REL_ID="${ARM}"
	_awgBtCheckReleaseDir "${AWG_BT_STORE_DIR}/${ARM}" armv7
)
check 0 'ARMv7 candidate accepts the explicit hard-float target triple' check_arm_candidate
cp "${AWG_BT_STORE_DIR}/${ARM}/MANIFEST" "${T}/arm.manifest"
sed -i 's/target=armv7-unknown-linux-musleabihf/target=armv7-unknown-linux-musl/' "${AWG_BT_STORE_DIR}/${ARM}/MANIFEST"
check 1 'ARMv7 runtime rejects a manifest with the wrong ABI' _awgBtVerifyRelease "${ARM}"
check 1 'ARMv7 candidate rejects a manifest with the wrong ABI' check_arm_candidate
cp "${T}/arm.manifest" "${AWG_BT_STORE_DIR}/${ARM}/MANIFEST"
printf '# changed bytes under the same identity\n' >>"${AWG_BT_STORE_DIR}/${ARM}/boringtun-cli"
check 1 'ARMv7 store rejects different binary bytes under the same identity' _awgBtVerifyRelease "${ARM}"
fixture "${ARM}" armv7 armv7-unknown-linux-musleabihf 2222222222222222222222222222222222222222

# Exercise the real emitted helper definitions in a fresh shell. Only its
# command-line entry point is removed so this focused test invokes verification.
for KIND in launch ctl; do
	_awgBtRenderHelper "${KIND}" | head -n -2 >"${T}/${KIND}"
	printf '\n_awgBtVerifyStore || exit $?\n_awgBtVerifyRelease %q\n' "${ARM}" >>"${T}/${KIND}"
	check 0 "generated ${KIND} helper preserves both compatible stores" bash "${T}/${KIND}"
done

# Real lifecycle/store operations with systemd, tunnel validation and config IO
# replaced at their external boundaries. The stopped service must stay stopped.
rollback() (
	acquireClientLifecycleLock() { return 0; }
	loadParams() { AWG_BACKEND=boringtun; SERVER_AWG_NIC=awg0; AWG_PROTOCOL_VERSION=2; AWG_BORINGTUN_IMITATE_PROTOCOL=none; AWG_BORINGTUN_IMITATE_DOMAIN=''; }
	normalizeAwgProtocolVersion() { return 0; }
	systemctl() { [[ "$1" == show ]] || return 1; echo inactive; }
	_awgBtReconcileLifecycleHelpers() { return 0; }
	_awgBtLifecycleConfigHashes() { echo unchanged-config-fixture; }
	_awgBtValidateReleaseCandidate() { return 0; }
	boringtunBinaryLifecycle "$1"
)
rm -- "${AWG_BT_STORE_DIR}/current"
ln -s "${ARM}" "${AWG_BT_STORE_DIR}/current"
ln -s "${OLD}" "${AWG_BT_STORE_DIR}/previous"
check 0 'rollback to compatible ARM64 does not need a published ARMv7 pin' rollback rollback
check 0 'rollback selects the actual previous ARM64 store' equal "${OLD}" "$(readlink "${AWG_BT_STORE_DIR}/current")"
check 1 'upgrade waits for a published ARMv7 pin' rollback upgrade
check 0 'unpublished upgrade preserves the selected ARM64 store' equal "${OLD}" "$(readlink "${AWG_BT_STORE_DIR}/current")"

# A full adoption supplies all three constants. A partial or malformed contract
# must never reuse stale state or become an installable release.
AWG_BT_RELEASE_ASSET_ARMV7="boringtun-cli-${AWG_BT_RELEASE_VERSION}-g${AWG_BT_RELEASE_SOURCE_COMMIT:0:12}-linux-armv7-musleabihf.tar.gz"
AWG_BT_RELEASE_ARCHIVE_SHA256_ARMV7="$(printf a%.0s {1..64})"
AWG_BT_RELEASE_BINARY_SHA256_ARMV7=""
check 1 'partially adopted ARMv7 contract is rejected' _awgBtSelectRelease armv7
AWG_BT_RELEASE_BINARY_SHA256_ARMV7="$(printf b%.0s {1..64})"
check 0 'complete verified ARMv7 constants make it selectable' _awgBtSelectRelease armv7
check 0 'selected archive keeps hard-float naming' equal "${AWG_BT_RELEASE_ASSET_ARMV7%.tar.gz}" "${_AWG_BT_REL_ID}"

sed '/^AWG_BT_RELEASE_\(ASSET\|ARCHIVE_SHA256\|BINARY_SHA256\)_ARMV7=/d' \
	"${PROJECT_ROOT}/amneziawg-install.sh" >"${T}/legacy.sh"
check 0 'historical two-target installer contract remains valid' equal '' "$(btc_embedded_release_problems "${T}/legacy.sh")"
cp "${T}/legacy.sh" "${T}/adopted.sh"
for NAME in ASSET ARCHIVE_SHA256 BINARY_SHA256; do
	VAR="AWG_BT_RELEASE_${NAME}_ARMV7"
	printf '%s="%s"\n' "${VAR}" "${!VAR}" >>"${T}/adopted.sh"
done
check 0 'three-target adoption contract is internally valid' equal '' "$(btc_embedded_release_problems "${T}/adopted.sh")"
sed 's/^AWG_BT_RELEASE_BINARY_SHA256_ARMV7=.*/AWG_BT_RELEASE_BINARY_SHA256_ARMV7=""/' "${T}/adopted.sh" >"${T}/partial.sh"
check 1 'partial ARMv7 adoption contract is reported' equal '' "$(btc_embedded_release_problems "${T}/partial.sh")"
sed 's/linux-armv7-musleabihf/linux-armv7-musl/g' "${T}/adopted.sh" >"${T}/wrong-abi.sh"
check 1 'wrong ARMv7 asset ABI is reported' equal '' "$(btc_embedded_release_problems "${T}/wrong-abi.sh")"
sed 's/^AWG_BT_RELEASE_BINARY_SHA256_ARMV7=.*/AWG_BT_RELEASE_BINARY_SHA256_ARMV7="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"/' "${T}/adopted.sh" >"${T}/duplicate-hash.sh"
check 1 'ARMv7 archive and binary hashes must differ' equal '' "$(btc_embedded_release_problems "${T}/duplicate-hash.sh")"
cp "${T}/legacy.sh" "${T}/malformed-empty.sh"
printf 'AWG_BT_RELEASE_ASSET_ARMV7=not-a-literal\nAWG_BT_RELEASE_ARCHIVE_SHA256_ARMV7=""\nAWG_BT_RELEASE_BINARY_SHA256_ARMV7=""\n' >>"${T}/malformed-empty.sh"
check 1 'malformed optional fields cannot appear to be an empty release' equal '' "$(btc_embedded_release_problems "${T}/malformed-empty.sh")"

printf '\nPlatform selection: %s passed, %s failed\n' "${PASS}" "${FAIL}"
((FAIL == 0))
