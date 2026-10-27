#!/usr/bin/env bash

# Live check that the BoringTun release an installer embeds is public, with
# exactly the embedded bytes. It downloads the release assets and SHA256SUMS
# anonymously from the exact URLs the installer uses, and checks each archive's
# SHA-256, its layout, the SHA-256 of the boringtun-cli inside it and its
# MANIFEST, all against the installer's AWG_BT_RELEASE_* constants alone.
#
# It never reads packaging/boringtun/pin.env or release.env: those describe the
# release being built, prepared or published, which an installer adopts only in
# a later, separate change of its constants. Until then this proves that the
# earlier release the installer still embeds stays downloadable; after that
# change it proves the adopted one.
#
# Fork releases additionally require the complete five-platform schema-2
# checksum set and RELEASE.json; all three Linux selections match the installer.
# Adoption separately verifies signatures/provenance; this checks public bytes.
# Requirements: curl, tar, sha256sum, Python 3 and network access to GitHub.
#
# Usage: bash tests/test-boringtun-public-release.sh [installer]
#        (default: amneziawg-install.sh of this checkout)

set -uo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd -P)"
INSTALLER="${1:-${PROJECT_ROOT}/amneziawg-install.sh}"
# shellcheck source=helpers/boringtun-contracts.sh
source "${SCRIPT_DIR}/helpers/boringtun-contracts.sh"

for TOOL in curl tar sha256sum; do
	command -v "${TOOL}" >/dev/null 2>&1 || { echo "ERROR: ${TOOL} is required" >&2; exit 2; }
done
[[ -f "${INSTALLER}" ]] || { echo "ERROR: no installer at ${INSTALLER}" >&2; exit 2; }

PASSED=0
FAILED=0
ok() {
	echo "  OK: $1"
	PASSED=$((PASSED + 1))
}
bad() {
	echo "  FAIL: $1"
	FAILED=$((FAILED + 1))
}
check() { # <message> <command...>
	local MESSAGE="$1"
	shift
	if "$@"; then ok "${MESSAGE}"; else bad "${MESSAGE}"; fi
}
value() { btc_embedded_value "${INSTALLER}" "$1"; }
sha_of() { sha256sum -- "$1" 2>/dev/null | cut -d' ' -f1; }
MANIFEST=""
manifest_has() { grep -qxF -- "$1" <<<"${MANIFEST}"; }
# The download of an exact URL as the installer does it: no credentials, HTTPS
# only, redirects included.
download() { # <url> <file>
	curl --proto '=https' --proto-redir '=https' -fsSL --retry 3 -o "$2" "$1"
}

WORK="$(mktemp -d "${TMPDIR:-/tmp}/boringtun-public-release.XXXXXX")"
trap 'rm -rf -- "${WORK}"' EXIT

TAG="$(value TAG)"
BASE="$(value BASE_URL)"
VERSION="$(value VERSION)"
REPOSITORY="$(value SOURCE_REPOSITORY)"
COMMIT="$(value SOURCE_COMMIT)"
echo "=== The installer's embedded release ${TAG}"
PROBLEMS="$(btc_embedded_release_problems "${INSTALLER}")"
if [[ -z "${PROBLEMS}" ]]; then
	ok "the embedded release is internally consistent"
else
	bad "the embedded release is internally consistent:"
	sed 's/^/      /' <<<"${PROBLEMS}"
	echo "BoringTun public release: ${PASSED} passed, ${FAILED} failed"
	exit 1
fi

ARCHES=(x86_64 aarch64)
FORK=0
if [[ "${BASE}" == "${BTC_FORK_RELEASE_DOWNLOAD_URL}/${TAG}" ]]; then
	FORK=1
	ARCHES+=(armv7)
	if ! download "${BASE}/RELEASE.json" "${WORK}/RELEASE.json" ||
		! python3 "${SCRIPT_DIR}/helpers/boringtun-public-contract.py" "${INSTALLER}" "${WORK}/RELEASE.json" >"${WORK}/expected-sums"; then
		bad "the public fork descriptor matches all adopted Linux pins and the five-platform contract"
		exit 1
	fi
	ok "the public fork descriptor matches all adopted Linux pins and the five-platform contract"
	# Names come only from the validated descriptor, never arbitrary checksum input.
	while read -r HASH ASSET; do
		if download "${BASE}/${ASSET}" "${WORK}/${ASSET}"; then
			check "${ASSET} matches its public descriptor hash" test "$(sha_of "${WORK}/${ASSET}")" = "${HASH}"
		else
			bad "${ASSET} is downloadable anonymously"
		fi
	done <"${WORK}/expected-sums"
else
	printf '%s  %s\n%s  %s\n' "$(value ARCHIVE_SHA256_AARCH64)" "$(value ASSET_AARCH64)" \
		"$(value ARCHIVE_SHA256_X86_64)" "$(value ASSET_X86_64)" >"${WORK}/expected-sums"
fi

for ARCH in "${ARCHES[@]}"; do
	KEY="${ARCH^^}"
	ASSET="$(value "ASSET_${KEY}")"
	ARCHIVE_SHA256="$(value "ARCHIVE_SHA256_${KEY}")"
	BINARY_SHA256="$(value "BINARY_SHA256_${KEY}")"
	STEM="${ASSET%.tar.gz}"
	echo "=== ${BASE}/${ASSET}"
	if { ((FORK)) && [[ ! -f "${WORK}/${ASSET}" ]]; } ||
		{ ((!FORK)) && ! download "${BASE}/${ASSET}" "${WORK}/${ASSET}"; }; then
		bad "${ASSET} is downloadable anonymously"
		continue
	fi
	ok "${ASSET} is downloadable anonymously"
	check "it has the embedded archive SHA-256 ${ARCHIVE_SHA256}" test "$(sha_of "${WORK}/${ASSET}")" = "${ARCHIVE_SHA256}"
	check "it holds exactly ${STEM}/ with LICENSE, MANIFEST, THIRD-PARTY-LICENSES and boringtun-cli" \
		test "$(tar -tzf "${WORK}/${ASSET}" 2>/dev/null | tr '\n' ' ')" = \
		"${STEM}/ ${STEM}/LICENSE ${STEM}/MANIFEST ${STEM}/THIRD-PARTY-LICENSES ${STEM}/boringtun-cli "
	check "its boringtun-cli has the embedded binary SHA-256 ${BINARY_SHA256}" \
		test "$(tar -xzOf "${WORK}/${ASSET}" "${STEM}/boringtun-cli" 2>/dev/null | sha256sum | cut -d' ' -f1)" = "${BINARY_SHA256}"
	MANIFEST="$(tar -xzOf "${WORK}/${ASSET}" "${STEM}/MANIFEST" 2>/dev/null)"
	check "its MANIFEST names the embedded source commit ${COMMIT}" manifest_has "source_commit=${COMMIT}"
	check "  the embedded source repository" manifest_has "source_repository=${REPOSITORY}"
	check "  the embedded version" manifest_has "version=${VERSION}"
	TARGET="${ARCH}-unknown-linux-musl"
	[[ "${ARCH}" != armv7 ]] || TARGET=armv7-unknown-linux-musleabihf
	check "  the architecture ${ARCH}" manifest_has "target=${TARGET}"
	check "  and the embedded binary SHA-256" manifest_has "binary_sha256=${BINARY_SHA256}"
done

echo "=== ${BASE}/SHA256SUMS"
if download "${BASE}/SHA256SUMS" "${WORK}/SHA256SUMS"; then
	ok "SHA256SUMS is downloadable anonymously"
	if cmp -s "${WORK}/SHA256SUMS" "${WORK}/expected-sums"; then
		ok "it lists exactly the expected platform assets and hashes"
		check "and the downloaded archives match it" bash -c 'cd "$1" && sha256sum --quiet -c SHA256SUMS' _ "${WORK}"
	else
		bad "it lists exactly the expected platform assets and hashes"
	fi
	echo "    SHA256SUMS $(sha_of "${WORK}/SHA256SUMS")"
else
	bad "SHA256SUMS is downloadable anonymously"
fi

echo "BoringTun public release ${TAG}: ${PASSED} passed, ${FAILED} failed"
((FAILED == 0))
