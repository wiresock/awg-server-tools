# shellcheck shell=bash
# SPDX-FileCopyrightText: 2026 Vadim Smirnov (doing business as WireSock)
# SPDX-License-Identifier: MIT
# Run only in a disposable-host test. Historical installers chose S4 up to150;
# their upgrade tests need a stable valid starting budget, not random rejection
# when the current installer later creates a client. Installer bytes stay intact.
bt_live_initial_install() ( # <installer> <fresh|historical>
    case "$2" in
        fresh) ;;
        historical)
            AWG_HOST_FIXTURE_REAL_SHUF="$(type -P shuf)" || return 1
            [[ -x "${AWG_HOST_FIXTURE_REAL_SHUF}" ]] || return 1
            export AWG_HOST_FIXTURE_REAL_SHUF
            shuf() {
                if [[ "$#" -eq 2 && "$1" == -i15-150 && "$2" == -n1 ]]; then
                    printf '120\n'
                else
                    "${AWG_HOST_FIXTURE_REAL_SHUF}" "$@"
                fi
            }
            export -f shuf
            ;;
        *) return 2;;
    esac
    bash "$1"
)
